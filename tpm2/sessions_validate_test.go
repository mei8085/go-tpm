package tpm2

import (
	"bytes"
	"testing"
)

// validHMACResponseAuth builds a TPMSAuthResponse whose HMAC is correct for
// the given hmacSession/command parameters, so that Validate succeeds.
func validHMACResponseAuth(t *testing.T, s *hmacSession, rc TPMRC, cc TPMCC, parms []byte, names []TPM2BName, authIndex int, attrs TPMASession) TPMSAuthResponse {
	t.Helper()
	newNonce := TPM2BNonce{Buffer: []byte("fresh-nonceTPM!!")} // 16 bytes
	var hmacKey []byte
	hmacKey = append(hmacKey, s.sessionKey...)
	if len(s.bindName.Buffer) == 0 || authIndex >= len(names) || !bytes.Equal(names[authIndex].Buffer, s.bindName.Buffer) {
		hmacKey = append(hmacKey, hmacKeyFromAuthValue(s.auth)...)
	}
	rph, err := rpHash(s.hash, rc, cc, parms)
	if err != nil {
		t.Fatalf("rpHash: %v", err)
	}
	mac, err := computeHMAC(s.hash, hmacKey, rph, newNonce.Buffer, s.nonceCaller.Buffer, nil, attrs)
	if err != nil {
		t.Fatalf("computeHMAC: %v", err)
	}
	return TPMSAuthResponse{
		Nonce:         newNonce,
		Attributes:    attrs,
		Authorization: TPM2BData{Buffer: mac},
	}
}

func newTestHMACSession(handle TPMHandle) *hmacSession {
	return &hmacSession{
		sessionOptions: sessionOptions{
			attrs: TPMASession{ContinueSession: true},
		},
		hash:       TPMAlgSHA256,
		nonceSize:  16,
		handle:     handle,
		sessionKey: []byte("session-key-bytes"),
		nonceCaller: TPM2BNonce{
			Buffer: []byte("caller-nonce!!12"), // 16 bytes
		},
		nonceTPM: TPM2BNonce{
			Buffer: []byte("old-nonceTPM!!!!"), // 16 bytes
		},
	}
}

// TestHMACSessionValidateFailureDoesNotCommitState verifies that a failed
// response validation leaves the cached session state untouched, so that a
// later independent use of the session is not polluted.
func TestHMACSessionValidateFailureDoesNotCommitState(t *testing.T) {
	const handle TPMHandle = 0x02000001
	s := newTestHMACSession(handle)
	s.auth = []byte("entity-auth")

	cc := TPMCCUnseal
	parms := []byte{0x00, 0x00}
	var names []TPM2BName

	attrs := TPMASession{ContinueSession: true}
	auth := validHMACResponseAuth(t, s, TPMRCSuccess, cc, parms, names, 0, attrs)
	// Corrupt the HMAC so that validation must fail.
	auth.Authorization.Buffer[0] ^= 0xFF

	oldNonceTPM := append([]byte(nil), s.nonceTPM.Buffer...)
	err := s.Validate(TPMRCSuccess, cc, parms, names, 0, &auth)
	if err == nil {
		t.Fatal("expected validation error for corrupted HMAC, got nil")
	}

	if !bytes.Equal(s.nonceTPM.Buffer, oldNonceTPM) {
		t.Errorf("nonceTPM committed despite failed validation: got %x, want %x",
			s.nonceTPM.Buffer, oldNonceTPM)
	}
	if s.handle != handle {
		t.Errorf("handle changed despite failed validation: got %#x, want %#x", s.handle, handle)
	}
}

// TestHMACSessionValidateFailureWithFlushKeepsHandle verifies that even when
// the (untrusted) response says the session was flushed, a failed HMAC check
// does not reset the cached handle to TPM_RH_NULL.
func TestHMACSessionValidateFailureWithFlushKeepsHandle(t *testing.T) {
	const handle TPMHandle = 0x02000002
	s := newTestHMACSession(handle)

	cc := TPMCCUnseal
	var parms []byte
	var names []TPM2BName

	// ContinueSession == false means a valid response would flush the session.
	attrs := TPMASession{}
	auth := validHMACResponseAuth(t, s, TPMRCSuccess, cc, parms, names, 0, attrs)
	auth.Authorization.Buffer[0] ^= 0xFF

	err := s.Validate(TPMRCSuccess, cc, parms, names, 0, &auth)
	if err == nil {
		t.Fatal("expected validation error for corrupted HMAC, got nil")
	}
	if s.handle != handle {
		t.Errorf("handle reset to %#x despite failed validation, want %#x", s.handle, handle)
	}
}

// TestHMACSessionValidateSuccessCommitsState verifies the success path keeps
// the original behavior: the new nonceTPM (and any handle change) are
// committed after a fully validated response.
func TestHMACSessionValidateSuccessCommitsState(t *testing.T) {
	const handle TPMHandle = 0x02000003
	s := newTestHMACSession(handle)

	cc := TPMCCUnseal
	var parms []byte
	var names []TPM2BName

	t.Run("continue session", func(t *testing.T) {
		attrs := TPMASession{ContinueSession: true}
		auth := validHMACResponseAuth(t, s, TPMRCSuccess, cc, parms, names, 0, attrs)
		if err := s.Validate(TPMRCSuccess, cc, parms, names, 0, &auth); err != nil {
			t.Fatalf("Validate: %v", err)
		}
		if !bytes.Equal(s.nonceTPM.Buffer, auth.Nonce.Buffer) {
			t.Errorf("nonceTPM not committed: got %x, want %x", s.nonceTPM.Buffer, auth.Nonce.Buffer)
		}
		if s.handle != handle {
			t.Errorf("handle changed unexpectedly: got %#x, want %#x", s.handle, handle)
		}
	})

	t.Run("flushed session", func(t *testing.T) {
		attrs := TPMASession{} // ContinueSession == false
		auth := validHMACResponseAuth(t, s, TPMRCSuccess, cc, parms, names, 0, attrs)
		if err := s.Validate(TPMRCSuccess, cc, parms, names, 0, &auth); err != nil {
			t.Fatalf("Validate: %v", err)
		}
		if !bytes.Equal(s.nonceTPM.Buffer, auth.Nonce.Buffer) {
			t.Errorf("nonceTPM not committed: got %x, want %x", s.nonceTPM.Buffer, auth.Nonce.Buffer)
		}
		if s.handle != TPMRHNull {
			t.Errorf("handle not reset after validated flush: got %#x, want %#x", s.handle, TPMRHNull)
		}
	})
}

// TestHMACSessionValidateNilAuth is the boundary case: a nil response auth
// must return an error without touching the session state.
func TestHMACSessionValidateNilAuth(t *testing.T) {
	const handle TPMHandle = 0x02000004
	s := newTestHMACSession(handle)
	oldNonceTPM := append([]byte(nil), s.nonceTPM.Buffer...)

	if err := s.Validate(TPMRCSuccess, TPMCCUnseal, nil, nil, 0, nil); err == nil {
		t.Fatal("expected error for nil auth, got nil")
	}
	if !bytes.Equal(s.nonceTPM.Buffer, oldNonceTPM) {
		t.Errorf("nonceTPM changed on nil auth: got %x, want %x", s.nonceTPM.Buffer, oldNonceTPM)
	}
	if s.handle != handle {
		t.Errorf("handle changed on nil auth: got %#x, want %#x", s.handle, handle)
	}
}

// TestPolicySessionValidateFailureDoesNotCommitState mirrors the HMAC session
// test for policy sessions.
func TestPolicySessionValidateFailureDoesNotCommitState(t *testing.T) {
	const handle TPMHandle = 0x03000001
	s := &policySession{
		sessionOptions: sessionOptions{
			attrs: TPMASession{ContinueSession: true},
		},
		hash:       TPMAlgSHA256,
		nonceSize:  16,
		handle:     handle,
		sessionKey: []byte("policy-session-key"),
		nonceCaller: TPM2BNonce{
			Buffer: []byte("policy-caller!!1"), // 16 bytes
		},
		nonceTPM: TPM2BNonce{
			Buffer: []byte("policy-old-nonce"), // 17 bytes
		},
	}

	newNonce := TPM2BNonce{Buffer: []byte("policy-new-nonce")} // 16 bytes
	var hmacKey []byte
	hmacKey = append(hmacKey, s.sessionKey...)
	hmacKey = append(hmacKey, hmacKeyFromAuthValue(s.auth)...)
	rph, err := rpHash(s.hash, TPMRCSuccess, TPMCCPolicyGetDigest, nil)
	if err != nil {
		t.Fatalf("rpHash: %v", err)
	}
	mac, err := computeHMAC(s.hash, hmacKey, rph, newNonce.Buffer, s.nonceCaller.Buffer, nil, s.attrs)
	if err != nil {
		t.Fatalf("computeHMAC: %v", err)
	}
	auth := TPMSAuthResponse{
		Nonce:         newNonce,
		Attributes:    s.attrs,
		Authorization: TPM2BData{Buffer: mac},
	}
	auth.Authorization.Buffer[0] ^= 0xFF

	oldNonceTPM := append([]byte(nil), s.nonceTPM.Buffer...)
	if err := s.Validate(TPMRCSuccess, TPMCCPolicyGetDigest, nil, nil, 0, &auth); err == nil {
		t.Fatal("expected validation error for corrupted HMAC, got nil")
	}
	if !bytes.Equal(s.nonceTPM.Buffer, oldNonceTPM) {
		t.Errorf("nonceTPM committed despite failed validation: got %x, want %x",
			s.nonceTPM.Buffer, oldNonceTPM)
	}
	if s.handle != handle {
		t.Errorf("handle changed despite failed validation: got %#x, want %#x", s.handle, handle)
	}

	// Nil auth boundary case.
	if err := s.Validate(TPMRCSuccess, TPMCCPolicyGetDigest, nil, nil, 0, nil); err == nil {
		t.Fatal("expected error for nil auth, got nil")
	}
	if s.handle != handle {
		t.Errorf("handle changed on nil auth: got %#x, want %#x", s.handle, handle)
	}
}

// TestPWSessionValidateNilAuth checks the password pseudo-session's boundary
// handling.
func TestPWSessionValidateNilAuth(t *testing.T) {
	s := &pwSession{auth: []byte("pw")}
	if err := s.Validate(TPMRCSuccess, TPMCCUnseal, nil, nil, 0, nil); err == nil {
		t.Fatal("expected error for nil auth, got nil")
	}
}

// recordingTransport records the commands it receives and serves scripted
// responses.
type recordingTransport struct {
	commands  [][]byte
	responses [][]byte
	errs      []error
	flushSeen int
}

func (r *recordingTransport) Send(input []byte) ([]byte, error) {
	cmd := append([]byte(nil), input...)
	r.commands = append(r.commands, cmd)
	// A FlushContext command has command code TPMCCFlushContext.
	if len(cmd) >= 10 {
		cc := TPMCC(be32(cmd[6:10]))
		if cc == TPMCCFlushContext {
			r.flushSeen++
		}
	}
	i := len(r.commands) - 1
	var rsp []byte
	if i < len(r.responses) {
		rsp = r.responses[i]
	}
	var err error
	if i < len(r.errs) {
		err = r.errs[i]
	}
	return rsp, err
}

func be32(b []byte) uint32 {
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func flushResponse() []byte {
	// tag(2)=no sessions, size(4)=10, code(4)=success
	return []byte{
		0x80, 0x01,
		0x00, 0x00, 0x00, 0x0A,
		0x00, 0x00, 0x00, 0x00,
	}
}

// TestCleanupFailureIsReentrySafe verifies that CleanupFailure is a safe
// no-op on an uninitialized session and on repeated calls, instead of issuing
// a flush of TPM_RH_NULL.
func TestCleanupFailureIsReentrySafe(t *testing.T) {
	tr := &recordingTransport{responses: [][]byte{flushResponse()}}

	t.Run("uninitialized HMAC session", func(t *testing.T) {
		s := &hmacSession{
			sessionOptions: sessionOptions{attrs: TPMASession{}}, // one-off, not ContinueSession
			handle:         TPMRHNull,
		}
		if err := s.CleanupFailure(tr); err != nil {
			t.Fatalf("first CleanupFailure: %v", err)
		}
		if err := s.CleanupFailure(tr); err != nil {
			t.Fatalf("second CleanupFailure: %v", err)
		}
		if tr.flushSeen != 0 {
			t.Errorf("expected no flush for uninitialized session, saw %d", tr.flushSeen)
		}
	})

	t.Run("initialized one-off HMAC session flushes once", func(t *testing.T) {
		const handle TPMHandle = 0x02000010
		s := &hmacSession{
			sessionOptions: sessionOptions{attrs: TPMASession{}},
			handle:         handle,
		}
		if err := s.CleanupFailure(tr); err != nil {
			t.Fatalf("first CleanupFailure: %v", err)
		}
		if s.handle != TPMRHNull {
			t.Errorf("handle not cleared after cleanup: %#x", s.handle)
		}
		if err := s.CleanupFailure(tr); err != nil {
			t.Fatalf("second CleanupFailure: %v", err)
		}
		if tr.flushSeen != 1 {
			t.Errorf("expected exactly one flush, saw %d", tr.flushSeen)
		}
	})

	t.Run("reusable session is never cleaned up", func(t *testing.T) {
		const handle TPMHandle = 0x02000011
		s := &hmacSession{
			sessionOptions: sessionOptions{attrs: TPMASession{ContinueSession: true}},
			handle:         handle,
		}
		if err := s.CleanupFailure(tr); err != nil {
			t.Fatalf("CleanupFailure: %v", err)
		}
		if tr.flushSeen != 1 { // unchanged from previous subtest
			t.Errorf("reusable session must not be flushed, saw %d flushes", tr.flushSeen)
		}
		if s.handle != handle {
			t.Errorf("reusable session handle changed: %#x", s.handle)
		}
	})

	t.Run("uninitialized policy session", func(t *testing.T) {
		s := &policySession{
			sessionOptions: sessionOptions{attrs: TPMASession{}},
			handle:         TPMRHNull,
		}
		if err := s.CleanupFailure(tr); err != nil {
			t.Fatalf("CleanupFailure: %v", err)
		}
		if tr.flushSeen != 1 {
			t.Errorf("expected no new flush for uninitialized policy session, saw %d", tr.flushSeen)
		}
	})
}

// TestAuthValueSnapshotIsCopy verifies that the authReader snapshot cannot be
// aliased by later session updates.
func TestAuthValueSnapshotIsCopy(t *testing.T) {
	s := newTestHMACSession(0x02000020)
	s.auth = []byte("original")
	snap := s.authValue()
	s.updateAuth([]byte("changed"))
	if string(snap) != "original" {
		t.Errorf("snapshot aliased session auth: got %q, want %q", snap, "original")
	}

	ps := &policySession{
		sessionOptions: sessionOptions{auth: []byte("policy-original"), authSet: true},
	}
	psnap := ps.authValue()
	ps.updateAuth([]byte("policy-changed"))
	if string(psnap) != "policy-original" {
		t.Errorf("policy snapshot aliased session auth: got %q, want %q", psnap, "policy-original")
	}
}
