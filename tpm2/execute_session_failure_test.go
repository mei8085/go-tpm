package tpm2

import (
	"encoding/binary"
	"strings"
	"testing"

	"github.com/google/go-tpm/tpm2/transport"
)

// errFakeValidation is a sentinel returned by the fake session's Validate.
var errFakeValidation = &validationError{"incorrect authorization HMAC"}

type validationError struct{ msg string }

func (e *validationError) Error() string { return e.msg }

// scriptedTransport serves canned responses, recording every command sent.
type scriptedTransport struct {
	responses [][]byte
	errs      []error
	commands  [][]byte
}

var _ transport.TPM = (*scriptedTransport)(nil)

func (s *scriptedTransport) Send(input []byte) ([]byte, error) {
	s.commands = append(s.commands, append([]byte(nil), input...))
	i := len(s.commands) - 1
	if i < len(s.errs) && s.errs[i] != nil {
		return nil, s.errs[i]
	}
	if i < len(s.responses) {
		return s.responses[i], nil
	}
	return nil, nil
}

// fakeSession is a Session that also implements authUpdater/authReader,
// recording every auth update and cleanup so execute's rollback behavior can
// be asserted directly.
type fakeSession struct {
	handle      TPMHandle
	auth        []byte
	updates     [][]byte
	cleanups    int
	validateErr error
}

var (
	_ Session     = (*fakeSession)(nil)
	_ authUpdater = (*fakeSession)(nil)
	_ authReader  = (*fakeSession)(nil)
)

func (f *fakeSession) Init(_ transport.TPM) error           { return nil }
func (f *fakeSession) CleanupFailure(_ transport.TPM) error { f.cleanups++; return nil }
func (f *fakeSession) NonceTPM() TPM2BNonce                 { return TPM2BNonce{} }
func (f *fakeSession) NewNonceCaller() error                { return nil }
func (f *fakeSession) Authorize(TPMCC, []byte, []byte, []TPM2BName, int) (*TPMSAuthCommand, error) {
	return &TPMSAuthCommand{Handle: f.handle}, nil
}
func (f *fakeSession) Validate(TPMRC, TPMCC, []byte, []TPM2BName, int, *TPMSAuthResponse) error {
	return f.validateErr
}
func (f *fakeSession) IsEncryption() bool   { return false }
func (f *fakeSession) IsDecryption() bool   { return false }
func (f *fakeSession) Encrypt([]byte) error { return nil }
func (f *fakeSession) Decrypt([]byte) error { return nil }
func (f *fakeSession) Handle() TPMHandle    { return f.handle }
func (f *fakeSession) updateAuth(auth []byte) {
	f.auth = append([]byte(nil), auth...)
	f.updates = append(f.updates, append([]byte(nil), auth...))
}
func (f *fakeSession) authValue() []byte { return append([]byte(nil), f.auth...) }

// buildAuthResponse builds a syntactically complete successful response for a
// no-parameter, single-session command such as HierarchyChangeAuth.
//
// Wire layout after the 10-byte header: a 4-byte parameter-area size, then
// the authorization area as the concatenated TPMSAuthResponse structs with
// no size prefix of their own (verified against a real simulator response).
func buildAuthResponse(wellFormed bool) []byte {
	// A minimal TPMSAuthResponse (verified against tpm2.Marshal):
	//   Nonce TPM2BNonce: 2-byte zero size;
	//   Attributes TPMASession: 1 zero byte;
	//   Authorization TPM2BData: 2-byte zero size.
	// Total: 5 bytes.
	authArea := []byte{
		0x00, 0x00, // Nonce: empty
		0x00,       // Attributes: none (irrelevant to the fake session)
		0x00, 0x00, // Authorization: empty
	}
	if !wellFormed {
		// Truncate the auth area so unmarshalling the mandatory
		// TPMSAuthResponse fails.
		authArea = authArea[:2]
	}
	parmAreaSize := uint32(0)
	total := 10 + 4 + len(authArea)
	rsp := make([]byte, 0, total)
	hdr := make([]byte, 10)
	binary.BigEndian.PutUint16(hdr[0:2], uint16(TPMSTSessions))
	binary.BigEndian.PutUint32(hdr[2:6], uint32(total))
	// response code stays zero (TPM_RC_SUCCESS).
	rsp = append(rsp, hdr...)
	tmp := make([]byte, 4)
	binary.BigEndian.PutUint32(tmp, parmAreaSize)
	rsp = append(rsp, tmp...)
	rsp = append(rsp, authArea...)
	return rsp
}

func changeAuthCommand(s Session) HierarchyChangeAuth {
	return HierarchyChangeAuth{
		AuthHandle: AuthHandle{
			Handle: TPMRHOwner,
			Name:   HandleName(TPMRHOwner),
			Auth:   s,
		},
		NewAuth: TPM2BAuth{Buffer: []byte("new-auth")},
	}
}

// assertFailureContract verifies the public failure contract for a response
// that fails session validation:
//   - a clear error containing wantErrSub is returned;
//   - the command was still sent (the TPM acted; only the response is
//     rejected);
//   - the session's cached auth is rolled back to its pre-command value;
//   - the auth update sequence is apply-new then restore-old;
//   - failure cleanup runs exactly once.
func assertFailureContract(t *testing.T, sess *fakeSession, tr *scriptedTransport, wantErrSub string) {
	t.Helper()
	_, err := changeAuthCommand(sess).Execute(tr)
	if err == nil {
		t.Fatal("expected validation failure, got nil")
	}
	if !strings.Contains(err.Error(), wantErrSub) {
		t.Fatalf("expected error containing %q, got: %v", wantErrSub, err)
	}
	if len(tr.commands) != 1 {
		t.Fatalf("expected the command to be sent once, got %d sends", len(tr.commands))
	}
	if string(sess.auth) != "old-auth" {
		t.Errorf("cached auth not rolled back: got %q, want %q", sess.auth, "old-auth")
	}
	got := make([]string, len(sess.updates))
	for i, u := range sess.updates {
		got[i] = string(u)
	}
	want := []string{"new-auth", "old-auth"}
	if len(got) != len(want) {
		t.Fatalf("update sequence = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("update sequence = %v, want %v", got, want)
		}
	}
	if sess.cleanups != 1 {
		t.Errorf("expected exactly one failure cleanup, got %d", sess.cleanups)
	}
}

func TestExecuteRollsBackCachedAuthOnResponseValidationFailure(t *testing.T) {
	t.Run("malformed auth area", func(t *testing.T) {
		sess := &fakeSession{handle: 0x020000AA, auth: []byte("old-auth")}
		tr := &scriptedTransport{responses: [][]byte{buildAuthResponse(false)}}
		assertFailureContract(t, sess, tr, "reading auth session")
	})

	t.Run("rejected response HMAC", func(t *testing.T) {
		sess := &fakeSession{
			handle:      0x020000AB,
			auth:        []byte("old-auth"),
			validateErr: errFakeValidation,
		}
		tr := &scriptedTransport{responses: [][]byte{buildAuthResponse(true)}}
		assertFailureContract(t, sess, tr, "validating auth session")
	})
}

// TestExecuteCommitsCachedAuthOnSuccessfulResponse is the compatibility
// half: when validation succeeds the new cached auth is retained and no
// failure cleanup runs.
func TestExecuteCommitsCachedAuthOnSuccessfulResponse(t *testing.T) {
	sess := &fakeSession{
		handle: 0x020000AC,
		auth:   []byte("old-auth"),
	}
	tr := &scriptedTransport{responses: [][]byte{buildAuthResponse(true)}}

	if _, err := changeAuthCommand(sess).Execute(tr); err != nil {
		t.Fatalf("expected success, got: %v", err)
	}
	if string(sess.auth) != "new-auth" {
		t.Errorf("cached auth not committed: got %q, want %q", sess.auth, "new-auth")
	}
	if len(sess.updates) != 1 || string(sess.updates[0]) != "new-auth" {
		t.Errorf("unexpected update sequence: %v", sess.updates)
	}
	if sess.cleanups != 0 {
		t.Errorf("failure cleanup ran on success path: %d time(s)", sess.cleanups)
	}
}
