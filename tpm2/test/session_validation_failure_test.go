package tpm2test

import (
	"bytes"
	"strings"
	"testing"

	. "github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/testhelper"
)

// corruptingTransport wraps a TPM transport and, while corrupt is armed,
// flips the last byte of responses to commands whose code is in targetCCs.
// The last byte of a response carrying an authorization area is inside the
// response HMAC, so corrupting it forces host-side response validation to
// fail without affecting session-management commands such as
// TPM2_StartAuthSession or TPM2_FlushContext.
type corruptingTransport struct {
	transport.TPM
	corruptNext int
	targetCCs   map[TPMCC]bool
}

func (c *corruptingTransport) Send(input []byte) ([]byte, error) {
	rsp, err := c.TPM.Send(input)
	if err == nil && c.corruptNext > 0 && len(input) >= 10 && len(rsp) > 0 {
		cc := TPMCC(binaryBigEndianUint32(input[6:10]))
		if c.targetCCs[cc] {
			rsp[len(rsp)-1] ^= 0xFF
			c.corruptNext--
		}
	}
	return rsp, err
}

func binaryBigEndianUint32(b []byte) uint32 {
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

// createSealedObject creates an SRK plus a sealed keyed-hash object protected
// by the given auth value, returning the loaded object's handle and name and
// a cleanup function.
func createSealedObject(t *testing.T, thetpm transport.TPM, auth []byte) (TPMHandle, TPM2BName, func()) {
	t.Helper()
	srkRsp, err := CreatePrimary{
		PrimaryHandle: TPMRHOwner,
		InPublic:      New2B(ECCSRKTemplate),
	}.Execute(thetpm)
	if err != nil {
		t.Fatalf("CreatePrimary: %v", err)
	}
	createRsp, err := Create{
		ParentHandle: AuthHandle{
			Handle: srkRsp.ObjectHandle,
			Name:   srkRsp.Name,
			Auth:   PasswordAuth(nil),
		},
		InSensitive: TPM2BSensitiveCreate{
			Sensitive: &TPMSSensitiveCreate{
				UserAuth: TPM2BAuth{Buffer: auth},
				Data: NewTPMUSensitiveCreate(&TPM2BSensitiveData{
					Buffer: []byte("top-secret"),
				}),
			},
		},
		InPublic: New2B(TPMTPublic{
			Type:    TPMAlgKeyedHash,
			NameAlg: TPMAlgSHA256,
			ObjectAttributes: TPMAObject{
				FixedTPM:     true,
				FixedParent:  true,
				UserWithAuth: true,
				NoDA:         true,
			},
		}),
	}.Execute(thetpm)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	loadRsp, err := Load{
		ParentHandle: AuthHandle{
			Handle: srkRsp.ObjectHandle,
			Name:   srkRsp.Name,
			Auth:   PasswordAuth(nil),
		},
		InPrivate: createRsp.OutPrivate,
		InPublic:  createRsp.OutPublic,
	}.Execute(thetpm)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	cleanup := func() {
		if _, err := (FlushContext{FlushHandle: loadRsp.ObjectHandle}).Execute(thetpm); err != nil {
			t.Errorf("flush object: %v", err)
		}
		if _, err := (FlushContext{FlushHandle: srkRsp.ObjectHandle}).Execute(thetpm); err != nil {
			t.Errorf("flush SRK: %v", err)
		}
	}
	return loadRsp.ObjectHandle, loadRsp.Name, cleanup
}

// TestReusableSessionRollsBackCachedStateOnValidationFailure verifies the
// public contract for response validation failures: Execute returns a clear
// error, and the reusable HMAC session's host-side cached state (NonceTPM and
// handle) is not committed from the untrusted response. Independent
// operations using other auth paths keep working.
func TestReusableSessionRollsBackCachedStateOnValidationFailure(t *testing.T) {
	thetpm := testhelper.Open(t)
	defer thetpm.Close()

	auth := []byte("object-auth")
	handle, name, cleanup := createSealedObject(t, thetpm, auth)
	defer cleanup()

	sess, closeSess, err := HMACSession(thetpm, TPMAlgSHA256, 16, Auth(auth))
	if err != nil {
		t.Fatalf("HMACSession: %v", err)
	}
	defer closeSess()

	unsealWith := func(t transport.TPM, s Session) error {
		_, err := Unseal{
			ItemHandle: AuthHandle{
				Handle: handle,
				Name:   name,
				Auth:   s,
			},
		}.Execute(t)
		return err
	}

	// Sanity: the session works before the failure.
	if err := unsealWith(thetpm, sess); err != nil {
		t.Fatalf("baseline Unseal failed: %v", err)
	}
	// Snapshot the host-side cached state established by the successful call.
	goodNonce := append([]byte(nil), sess.NonceTPM().Buffer...)
	goodHandle := sess.Handle()

	// Corrupt the next Unseal response so that its authorization HMAC fails
	// host-side validation. Only Unseal responses are targeted, so internal
	// session management traffic is left untouched.
	corrupt := &corruptingTransport{
		TPM:         thetpm,
		corruptNext: 1,
		targetCCs:   map[TPMCC]bool{TPMCCUnseal: true},
	}
	err = unsealWith(corrupt, sess)
	if err == nil {
		t.Fatal("expected response validation error, got nil")
	}
	if !strings.Contains(err.Error(), "validating auth session") {
		t.Fatalf("expected a session validation error, got: %v", err)
	}

	// The failed response must not have committed its untrusted nonce/handle
	// into the session cache.
	if !bytes.Equal(sess.NonceTPM().Buffer, goodNonce) {
		t.Errorf("NonceTPM committed from failed response: got %x, want %x",
			sess.NonceTPM().Buffer, goodNonce)
	}
	if sess.Handle() != goodHandle {
		t.Errorf("handle changed after failed validation: got %#x, want %#x",
			sess.Handle(), goodHandle)
	}

	// Independent operations must not be polluted by the failed call:
	// password auth and a freshly created HMAC session both keep working.
	if err := unsealWith(thetpm, PasswordAuth(auth)); err != nil {
		t.Fatalf("independent password-auth command failed after validation failure: %v", err)
	}
	freshSess, freshClose, err := HMACSession(thetpm, TPMAlgSHA256, 16, Auth(auth))
	if err != nil {
		t.Fatalf("creating a fresh HMAC session after failure: %v", err)
	}
	defer freshClose()
	if err := unsealWith(thetpm, freshSess); err != nil {
		t.Fatalf("independent fresh-session command failed after validation failure: %v", err)
	}
}

// TestJustInTimeSessionCleanedUpAfterValidationFailure verifies that a
// one-off HMAC() session is flushed on the TPM after a response validation
// failure, instead of being leaked.
func TestJustInTimeSessionCleanedUpAfterValidationFailure(t *testing.T) {
	thetpm := testhelper.Open(t)
	defer thetpm.Close()

	auth := []byte("jit-object-auth")
	handle, name, cleanup := createSealedObject(t, thetpm, auth)
	defer cleanup()

	// Count loaded sessions before the failed command.
	before := loadedSessionHandles(t, thetpm)

	corrupt := &corruptingTransport{
		TPM:         thetpm,
		corruptNext: 1,
		targetCCs:   map[TPMCC]bool{TPMCCUnseal: true},
	}
	jitSess := HMAC(TPMAlgSHA256, 16, Auth(auth))
	_, err := Unseal{
		ItemHandle: AuthHandle{
			Handle: handle,
			Name:   name,
			Auth:   jitSess,
		},
	}.Execute(corrupt)
	if err == nil {
		t.Fatal("expected response validation error, got nil")
	}
	if !strings.Contains(err.Error(), "validating auth session") {
		t.Fatalf("expected a session validation error, got: %v", err)
	}

	// The just-in-time session must have been flushed during failure cleanup.
	after := loadedSessionHandles(t, thetpm)
	if len(after) != len(before) {
		t.Errorf("session leak after validation failure: had %d loaded sessions, now have %d (%v)",
			len(before), len(after), after)
	}
}

// truncatingTransport truncates scripted responses to commands whose code is
// in targetCCs, producing a structurally invalid response that fails while
// parsing the parameter/session areas.
type truncatingTransport struct {
	transport.TPM
	truncateNext int
	targetCCs    map[TPMCC]bool
}

func (c *truncatingTransport) Send(input []byte) ([]byte, error) {
	rsp, err := c.TPM.Send(input)
	if err == nil && c.truncateNext > 0 && len(input) >= 10 {
		cc := TPMCC(binaryBigEndianUint32(input[6:10]))
		if c.targetCCs[cc] && len(rsp) > 10 {
			rsp = rsp[:10]
			c.truncateNext--
		}
	}
	return rsp, err
}

// TestMalformedResponseCleansUpJustInTimeSession verifies that a response
// which fails structural parsing (not just HMAC validation) also triggers
// failure cleanup of just-in-time sessions and returns a clear error.
func TestMalformedResponseCleansUpJustInTimeSession(t *testing.T) {
	thetpm := testhelper.Open(t)
	defer thetpm.Close()

	auth := []byte("malformed-object-auth")
	handle, name, cleanup := createSealedObject(t, thetpm, auth)
	defer cleanup()

	before := loadedSessionHandles(t, thetpm)

	trunc := &truncatingTransport{
		TPM:          thetpm,
		truncateNext: 1,
		targetCCs:    map[TPMCC]bool{TPMCCUnseal: true},
	}
	_, err := Unseal{
		ItemHandle: AuthHandle{
			Handle: handle,
			Name:   name,
			Auth:   HMAC(TPMAlgSHA256, 16, Auth(auth)),
		},
	}.Execute(trunc)
	if err == nil {
		t.Fatal("expected error for truncated response, got nil")
	}
	if !strings.Contains(err.Error(), "unmarshalling TPM response") &&
		!strings.Contains(err.Error(), "reading auth session") &&
		!strings.Contains(err.Error(), "parameter area") {
		t.Fatalf("expected a response parsing error, got: %v", err)
	}

	after := loadedSessionHandles(t, thetpm)
	if len(after) != len(before) {
		t.Errorf("session leak after malformed response: had %d loaded sessions, now have %d (%v)",
			len(before), len(after), after)
	}
}

// loadedSessionHandles returns the handles of all loaded HMAC and policy
// sessions visible via TPM2_GetCapability.
func loadedSessionHandles(t *testing.T, thetpm transport.TPM) []TPMHandle {
	t.Helper()
	query := func(prop TPMHT) []TPMHandle {
		rsp, err := GetCapability{
			Capability:    TPMCapHandles,
			Property:      uint32(prop),
			PropertyCount: 100,
		}.Execute(thetpm)
		if err != nil {
			t.Fatalf("GetCapability(%v): %v", prop, err)
		}
		handles, err := rsp.CapabilityData.Data.Handles()
		if err != nil {
			t.Fatalf("decoding handles for %v: %v", prop, err)
		}
		return handles.Handle
	}
	return append(query(TPMHTHMACSession), query(TPMHTPolicySession)...)
}
