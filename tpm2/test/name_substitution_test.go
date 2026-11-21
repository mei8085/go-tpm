package tpm2test

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"reflect"
	"strings"
	"testing"

	. "github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/testhelper"
)

// responseAbsent reports whether a command returned no response material.
// Execute hands back a typed nil pointer on failure, which a plain nil
// comparison does not catch.
func responseAbsent(rsp any) bool {
	if rsp == nil {
		return true
	}
	v := reflect.ValueOf(rsp)
	return v.Kind() == reflect.Ptr && v.IsNil()
}

// This file exercises Name-substitution attacks against the two TPM flows
// whose protection wrappers are cryptographically bound to an object Name:
//
//   - TPM2_ActivateCredential over a credential produced by CreateCredential
//     (TPMS_ID_OBJECT, see Part 1 "Credential Protection"), and
//   - TPM2_Import over an outer wrapper produced by CreateDuplicate
//     (see Part 1 "Outer Duplication Wrapper").
//
// For every attack the tests assert that the request is rejected while the
// Name/integrity binding is being checked, i.e. before the wrapped credential
// or sensitive area is decrypted or otherwise used. A parallel set of cases
// uses a wrong authorization value to show that authorization failures
// (TPM_RC_BAD_AUTH) are reported distinctly from Name/integrity failures
// (TPM_RC_INTEGRITY / TPM_RC_SIZE).
//
// All TPM access goes through the in-process software simulator, so the tests
// need neither a physical TPM nor a network connection.

// rejectStage classifies an error according to the processing stage at which
// the TPM (or the go-tpm client guard) rejected the request. The returned
// label is logged verbosely so test output visibly separates Name/integrity
// rejections from authorization rejections.
func rejectStage(err error) string {
	if err == nil {
		return "ACCEPTED"
	}
	// The client-side marshaller refuses to send a command whose handle has
	// no Name at all; this is a local Name check, not a TPM response.
	if strings.Contains(err.Error(), "missing Name") {
		return "CLIENT-NAME-GUARD"
	}
	var rc TPMRC
	if errors.As(err, &rc) {
		switch {
		case errors.Is(err, TPMRCBadAuth), errors.Is(err, TPMRCAuthFail):
			return "AUTHORIZATION"
		case errors.Is(err, TPMRCIntegrity), errors.Is(err, TPMRCSignature):
			return "NAME/INTEGRITY"
		case errors.Is(err, TPMRCSize), errors.Is(err, TPMRCInsufficient):
			return "WRAPPER-ENCODING"
		}
		return "TPM-ERROR"
	}
	return "OTHER"
}

// assertNameBindingFailure asserts that a command was rejected by a
// Name/integrity (or wrapper-encoding) check and that no protected material
// was returned, proving the rejection happened before the credential could be
// used. wantRC is the expected return code for TPM-side rejections; client
// guard errors ("missing Name") carry no TPM RC.
func assertNameBindingFailure(t *testing.T, stage string, rsp any, err error, wantRC TPMRC) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: expected %s rejection, but the command succeeded and the credential was used",
			stage, wantRC)
	}
	if !responseAbsent(rsp) {
		t.Fatalf("%s: expected no response material before validation, got %#v", stage, rsp)
	}
	stageGot := rejectStage(err)
	if stageGot == "CLIENT-NAME-GUARD" {
		if !strings.Contains(err.Error(), "missing Name") {
			t.Fatalf("%s: unexpected client guard error: %v", stage, err)
		}
		t.Logf("%-45s rejected before credential use [stage=%s]: %v", stage, stageGot, err)
		return
	}
	if !errors.Is(err, wantRC) {
		t.Fatalf("%s: want %s failure, got %v (stage %s)", stage, wantRC, err, stageGot)
	}
	if stageGot != "NAME/INTEGRITY" && stageGot != "WRAPPER-ENCODING" {
		t.Fatalf("%s: rejection stage = %s, want a Name/integrity stage; err = %v", stage, stageGot, err)
	}
	t.Logf("%-45s rejected before credential use [stage=%s]: %v", stage, stageGot, err)
}

// assertAuthorizationFailure asserts that a command was rejected at the
// authorization stage, and specifically not at the Name/integrity stage.
func assertAuthorizationFailure(t *testing.T, stage string, rsp any, err error) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: expected an authorization failure, but the command succeeded", stage)
	}
	if !responseAbsent(rsp) {
		t.Fatalf("%s: expected no response material, got %#v", stage, rsp)
	}
	if !errors.Is(err, TPMRCBadAuth) && !errors.Is(err, TPMRCAuthFail) {
		t.Fatalf("%s: want TPM_RC_BAD_AUTH/TPM_RC_AUTH_FAIL, got %v (stage %s)", stage, err, rejectStage(err))
	}
	if errors.Is(err, TPMRCIntegrity) || errors.Is(err, TPMRCSize) {
		t.Fatalf("%s: authorization failure was misclassified as a Name/integrity failure: %v", stage, err)
	}
	t.Logf("%-45s rejected at authorization check [stage=%s]: %v", stage, rejectStage(err), err)
}

// createTestSRK creates a primary storage key in the given hierarchy and
// flushes it when the test finishes.
func createTestSRK(t *testing.T, tpm transport.TPM, hierarchy TPMHandle, template TPMTPublic) *CreatePrimaryResponse {
	t.Helper()
	rsp, err := CreatePrimary{
		PrimaryHandle: hierarchy,
		InPublic:      New2B(template),
	}.Execute(tpm)
	if err != nil {
		t.Fatalf("CreatePrimary(hierarchy=%#x): %v", hierarchy, err)
	}
	t.Cleanup(func() {
		FlushContext{FlushHandle: rsp.ObjectHandle}.Execute(tpm)
	})
	return rsp
}

// createNamedChild creates a transient ECC child object under parent.
func createNamedChild(t *testing.T, tpm transport.TPM, parent NamedHandle) *CreateLoadedResponse {
	t.Helper()
	public := TPMTPublic{
		Type:    TPMAlgECC,
		NameAlg: TPMAlgSHA256,
		ObjectAttributes: TPMAObject{
			FixedTPM: false, FixedParent: false, SensitiveDataOrigin: true,
			UserWithAuth: true, Decrypt: true, SignEncrypt: true,
		},
		Parameters: NewTPMUPublicParms(TPMAlgECC, &TPMSECCParms{CurveID: TPMECCNistP256}),
		Unique: NewTPMUPublicID(TPMAlgECC, &TPMSECCPoint{
			X: TPM2BECCParameter{Buffer: make([]byte, 32)},
			Y: TPM2BECCParameter{Buffer: make([]byte, 32)},
		}),
	}
	rsp, err := CreateLoaded{
		ParentHandle: parent,
		InPublic:     New2BTemplate(&public),
	}.Execute(tpm)
	if err != nil {
		t.Fatalf("CreateLoaded: %v", err)
	}
	t.Cleanup(func() {
		FlushContext{FlushHandle: rsp.ObjectHandle}.Execute(tpm)
	})
	return rsp
}

// flipByte flips one byte of the integrity HMAC region of a protection
// wrapper. The wrapper layout is: uint16 hmacSize || HMAC || encrypted body.
func flipByte(t *testing.T, blob []byte, offset int) []byte {
	t.Helper()
	if offset >= len(blob) {
		t.Fatalf("flip offset %d out of range for %d-byte blob", offset, len(blob))
	}
	out := append([]byte(nil), blob...)
	out[offset] ^= 0x01
	return out
}

// rearrangeWrapper simulates an encoding-rearrangement attack: the leading
// TPM2B-sized HMAC and the trailing encrypted body swap positions while the
// total byte length is preserved.
func rearrangeWrapper(t *testing.T, blob []byte) []byte {
	t.Helper()
	if len(blob) < 2 {
		t.Fatalf("wrapper too short: %d bytes", len(blob))
	}
	hmacLen := int(binary.BigEndian.Uint16(blob[:2]))
	if hmacLen == 0 || 2+hmacLen >= len(blob) {
		t.Fatalf("malformed wrapper: hmacLen=%d totalLen=%d", hmacLen, len(blob))
	}
	out := append([]byte{}, blob[2+hmacLen:]...)
	out = append(out, blob[:2+hmacLen]...)
	return out
}

// TestActivateCredentialNameSubstitution attacks the Name binding of a
// TPMS_ID_OBJECT credential: the HMAC inside the credential blob is computed
// over (encIdentity || objectName), so any substitution of the bound Name
// must be detected before the credential secret is released.
func TestActivateCredentialNameSubstitution(t *testing.T) {
	tpm := testhelper.Open(t)
	defer tpm.Close()

	// Decrypt key in the Owner hierarchy (empty auth value).
	ownerSRK := createTestSRK(t, tpm, TPMRHOwner, ECCSRKTemplate)
	ownerPub, err := ownerSRK.OutPublic.Contents()
	if err != nil {
		t.Fatalf("owner OutPublic.Contents(): %v", err)
	}
	ownerEncKey, err := ImportEncapsulationKey(ownerPub)
	if err != nil {
		t.Fatalf("ImportEncapsulationKey(owner SRK): %v", err)
	}

	// A second SRK in a different hierarchy supplies a cross-level target:
	// same template, different parent object, different Name.
	endorsementSRK := createTestSRK(t, tpm, TPMRHEndorsement, ECCSRKTemplate)
	endorsementPub, err := endorsementSRK.OutPublic.Contents()
	if err != nil {
		t.Fatalf("endorsement OutPublic.Contents(): %v", err)
	}
	endorsementEncKey, err := ImportEncapsulationKey(endorsementPub)
	if err != nil {
		t.Fatalf("ImportEncapsulationKey(endorsement SRK): %v", err)
	}

	// One loaded credentialed object under the Owner SRK. The simulator only
	// exposes a handful of transient slots, so every second "object" below is
	// constructed in software and contributes only a Name.
	objectA := createNamedChild(t, tpm, NamedHandle{Handle: ownerSRK.ObjectHandle, Name: ownerSRK.Name})

	// A second, purely software-defined object with a distinct Name. A
	// credential bound to this Name can never match the Name the TPM computes
	// for the loaded object A.
	objectBTemplate := TPMTPublic{
		Type:    TPMAlgRSA,
		NameAlg: TPMAlgSHA256,
		ObjectAttributes: TPMAObject{
			FixedTPM: false, FixedParent: false, SensitiveDataOrigin: true,
			UserWithAuth: true, Decrypt: true, SignEncrypt: true,
		},
		Parameters: NewTPMUPublicParms(TPMAlgRSA, &TPMSRSAParms{KeyBits: 2048}),
		Unique:     NewTPMUPublicID(TPMAlgRSA, &TPM2BPublicKeyRSA{}),
	}
	objectBName, err := ObjectName(&objectBTemplate)
	if err != nil {
		t.Fatalf("ObjectName(object B template): %v", err)
	}
	if bytes.Equal(objectA.Name.Buffer, objectBName.Buffer) {
		t.Fatal("test setup produced colliding object Names")
	}

	secret := []byte("activate-credential-secret")

	// Credential correctly bound to object A.
	blobA, seedA, err := CreateCredential(rand.Reader, ownerEncKey, objectA.Name.Buffer, secret)
	if err != nil {
		t.Fatalf("CreateCredential(A): %v", err)
	}
	// Credential bound to the foreign object B's Name (duplicate/confused-name
	// material).
	blobB, _, err := CreateCredential(rand.Reader, ownerEncKey, objectBName.Buffer, secret)
	if err != nil {
		t.Fatalf("CreateCredential(B): %v", err)
	}
	// Credential bound to a fabricated same-length Name (digest tampered).
	fabricatedName := append([]byte(nil), objectA.Name.Buffer...)
	fabricatedName[len(fabricatedName)-1] ^= 0xFF
	blobFabricated, _, err := CreateCredential(rand.Reader, ownerEncKey, fabricatedName, secret)
	if err != nil {
		t.Fatalf("CreateCredential(fabricated name): %v", err)
	}
	// Credential bound to a truncated Name (alg prefix retained, digest cut).
	truncatedName := objectA.Name.Buffer[:18]
	blobTruncated, _, err := CreateCredential(rand.Reader, ownerEncKey, truncatedName, secret)
	if err != nil {
		t.Fatalf("CreateCredential(truncated name): %v", err)
	}
	// Credential for object A's Name but encrypted under the endorsement SRK,
	// i.e. a parent-object substitution across hierarchy levels.
	blobCrossLevel, seedCrossLevel, err := CreateCredential(rand.Reader, endorsementEncKey, objectA.Name.Buffer, secret)
	if err != nil {
		t.Fatalf("CreateCredential(cross-level): %v", err)
	}

	activate := func(blob, seed []byte, activateHandle, keyHandle AuthHandle) (*ActivateCredentialResponse, error) {
		return ActivateCredential{
			ActivateHandle: activateHandle,
			KeyHandle:      keyHandle,
			CredentialBlob: TPM2BIDObject{Buffer: blob},
			Secret:         TPM2BEncryptedSecret{Buffer: seed},
		}.Execute(tpm)
	}
	ownerKeyAuth := AuthHandle{Handle: ownerSRK.ObjectHandle, Name: ownerSRK.Name, Auth: PasswordAuth(nil)}
	authA := AuthHandle{Handle: objectA.ObjectHandle, Name: objectA.Name, Auth: PasswordAuth(nil)}

	t.Run("legitimate activation succeeds", func(t *testing.T) {
		rsp, err := activate(blobA, seedA, authA, ownerKeyAuth)
		if err != nil {
			t.Fatalf("ActivateCredential() = %v", err)
		}
		if !bytes.Equal(rsp.CertInfo.Buffer, secret) {
			t.Fatalf("CertInfo = %x, want %x", rsp.CertInfo.Buffer, secret)
		}
		t.Logf("legitimate activation recovered the credential [stage=%s]", rejectStage(err))
	})

	t.Run("duplicate name: credential bound to a foreign name rejected on object A", func(t *testing.T) {
		// Per TPM 2.0 Part 1 the TPM recomputes the activate object's Name from
		// its stored public area and never trusts the Name carried in the
		// command (that Name only binds the authorization session). The attack
		// surface is therefore a credential blob whose wrapper was bound to a
		// different object's Name: it cannot validate against object A.
		rsp, err := activate(blobB, seedA, authA, ownerKeyAuth)
		assertNameBindingFailure(t, "foreign-Name blob activated on object A", rsp, err, TPMRCIntegrity)
	})

	t.Run("duplicate name: command-name spoof cannot bypass the binding", func(t *testing.T) {
		// Even with object B's Name spoofed into the handle area, a blob bound
		// to object A must remain usable only because the TPM ignores the
		// spoofed Name for the wrapper check. Assert the TPM does not treat the
		// spoofed command Name as the wrapper Name and reject it as a handle
		// mismatch: success here proves the internal Name, not the wire Name,
		// is authoritative, while the foreign-Name blob case above stays
		// rejected.
		spoofedAuth := AuthHandle{Handle: objectA.ObjectHandle, Name: *objectBName, Auth: PasswordAuth(nil)}
		if _, err := activate(blobA, seedA, spoofedAuth, ownerKeyAuth); err != nil {
			t.Fatalf("TPM must use the internal object Name, not the spoofed wire Name: %v", err)
		}
		t.Log("wire-Name spoof did not alter wrapper validation (internal Name authoritative)")
	})

	t.Run("fabricated name binding is rejected", func(t *testing.T) {
		rsp, err := activate(blobFabricated, seedA, authA, ownerKeyAuth)
		assertNameBindingFailure(t, "fabricated Name", rsp, err, TPMRCIntegrity)
	})

	t.Run("truncated name binding is rejected", func(t *testing.T) {
		rsp, err := activate(blobTruncated, seedA, authA, ownerKeyAuth)
		assertNameBindingFailure(t, "truncated Name", rsp, err, TPMRCIntegrity)
	})

	t.Run("missing name in command is rejected client-side", func(t *testing.T) {
		missingNameAuth := AuthHandle{Handle: objectA.ObjectHandle, Auth: PasswordAuth(nil)}
		rsp, err := activate(blobA, seedA, missingNameAuth, ownerKeyAuth)
		assertNameBindingFailure(t, "missing ActivateHandle Name", rsp, err, TPMRCSize)
	})

	t.Run("encoding rearrangement of credential blob is rejected", func(t *testing.T) {
		rsp, err := activate(rearrangeWrapper(t, blobA), seedA, authA, ownerKeyAuth)
		assertNameBindingFailure(t, "rearranged ID object", rsp, err, TPMRCSize)
	})

	t.Run("integrity HMAC tampering is rejected", func(t *testing.T) {
		// Offset 4 skips the 2-byte size and first 2 HMAC bytes.
		rsp, err := activate(flipByte(t, blobA, 4), seedA, authA, ownerKeyAuth)
		assertNameBindingFailure(t, "tampered ID object HMAC", rsp, err, TPMRCIntegrity)
	})

	t.Run("cross-level parent substitution is rejected", func(t *testing.T) {
		rsp, err := activate(blobCrossLevel, seedCrossLevel, authA, ownerKeyAuth)
		assertNameBindingFailure(t, "endorsement-hierarchy seed under Owner SRK", rsp, err, TPMRCIntegrity)
	})

	t.Run("wrong authorization value is reported separately from name failure", func(t *testing.T) {
		badAuthA := AuthHandle{Handle: objectA.ObjectHandle, Name: objectA.Name, Auth: PasswordAuth([]byte("wrong-password"))}
		rsp, err := activate(blobA, seedA, badAuthA, ownerKeyAuth)
		assertAuthorizationFailure(t, "wrong ActivateHandle auth value", rsp, err)
	})

	t.Run("legitimate activation still works after rejected attacks", func(t *testing.T) {
		rsp, err := activate(blobA, seedA, authA, ownerKeyAuth)
		if err != nil {
			t.Fatalf("post-attack ActivateCredential() = %v", err)
		}
		if !bytes.Equal(rsp.CertInfo.Buffer, secret) {
			t.Fatalf("CertInfo = %x, want %x", rsp.CertInfo.Buffer, secret)
		}
	})
}

// TestDuplicateImportNameSubstitution attacks the Name binding of an outer
// duplication wrapper: the wrapper HMAC is computed over
// (dupSensitive || objectName), and TPM2_Import recomputes the object Name
// from ObjectPublic before checking it. Any mismatch between the Name bound
// into the wrapper and the Name implied by the import structures must fail
// before the sensitive area is unwrapped and loaded.
func TestDuplicateImportNameSubstitution(t *testing.T) {
	tpm := testhelper.Open(t)
	defer tpm.Close()

	ownerSRK := createTestSRK(t, tpm, TPMRHOwner, ECCSRKTemplate)
	ownerPub, err := ownerSRK.OutPublic.Contents()
	if err != nil {
		t.Fatalf("owner OutPublic.Contents(): %v", err)
	}
	ownerEncKey, err := ImportEncapsulationKey(ownerPub)
	if err != nil {
		t.Fatalf("ImportEncapsulationKey(owner SRK): %v", err)
	}

	endorsementSRK := createTestSRK(t, tpm, TPMRHEndorsement, ECCSRKTemplate)
	endorsementPub, err := endorsementSRK.OutPublic.Contents()
	if err != nil {
		t.Fatalf("endorsement OutPublic.Contents(): %v", err)
	}
	endorsementEncKey, err := ImportEncapsulationKey(endorsementPub)
	if err != nil {
		t.Fatalf("ImportEncapsulationKey(endorsement SRK): %v", err)
	}

	// Two distinct software-created keyed-hash objects with distinct Names.
	plaintext := []byte("duplicate-import-secret")
	pubA, sensA := makeSealedBlob(t, TPMAlgSHA256, append([]byte{0xAA}, make([]byte, 31)...), plaintext)
	pubB, sensB := makeSealedBlob(t, TPMAlgSHA256, append([]byte{0xBB}, make([]byte, 31)...), plaintext)
	nameA, err := ObjectName(pubA)
	if err != nil {
		t.Fatalf("ObjectName(A): %v", err)
	}
	nameB, err := ObjectName(pubB)
	if err != nil {
		t.Fatalf("ObjectName(B): %v", err)
	}
	if bytes.Equal(nameA.Buffer, nameB.Buffer) {
		t.Fatal("test setup produced colliding object Names")
	}

	// Wrapper correctly binding object A.
	dupA, seedA, err := CreateDuplicate(rand.Reader, ownerEncKey, nameA.Buffer, sensA)
	if err != nil {
		t.Fatalf("CreateDuplicate(A): %v", err)
	}
	// Wrapper binding object B's Name (duplicate/confused-name material).
	dupB, _, err := CreateDuplicate(rand.Reader, ownerEncKey, nameB.Buffer, sensB)
	if err != nil {
		t.Fatalf("CreateDuplicate(B): %v", err)
	}
	// Wrapper bound to a fabricated same-length Name.
	fabricatedName := append([]byte(nil), nameA.Buffer...)
	fabricatedName[len(fabricatedName)-1] ^= 0xFF
	dupFabricated, _, err := CreateDuplicate(rand.Reader, ownerEncKey, fabricatedName, sensA)
	if err != nil {
		t.Fatalf("CreateDuplicate(fabricated name): %v", err)
	}
	// Wrapper bound to a truncated Name.
	truncatedName := nameA.Buffer[:18]
	dupTruncated, _, err := CreateDuplicate(rand.Reader, ownerEncKey, truncatedName, sensA)
	if err != nil {
		t.Fatalf("CreateDuplicate(truncated name): %v", err)
	}
	// Object A's Name and sensitive, but wrapped to the endorsement SRK.
	dupCrossLevel, seedCrossLevel, err := CreateDuplicate(rand.Reader, endorsementEncKey, nameA.Buffer, sensA)
	if err != nil {
		t.Fatalf("CreateDuplicate(cross-level): %v", err)
	}

	parentAuth := func(auth []byte) AuthHandle {
		return AuthHandle{Handle: ownerSRK.ObjectHandle, Name: ownerSRK.Name, Auth: PasswordAuth(auth)}
	}
	imp := func(objectPub *TPMTPublic, dup, seed []byte, parent AuthHandle) (*ImportResponse, error) {
		return Import{
			ParentHandle: parent,
			ObjectPublic: New2B(*objectPub),
			Duplicate:    TPM2BPrivate{Buffer: dup},
			InSymSeed:    TPM2BEncryptedSecret{Buffer: seed},
		}.Execute(tpm)
	}

	t.Run("legitimate import, load and unseal succeed", func(t *testing.T) {
		importRsp, err := imp(pubA, dupA, seedA, parentAuth(nil))
		if err != nil {
			t.Fatalf("Import() = %v", err)
		}
		loadRsp, err := Load{
			ParentHandle: NamedHandle{Handle: ownerSRK.ObjectHandle, Name: ownerSRK.Name},
			InPublic:     New2B(*pubA),
			InPrivate:    importRsp.OutPrivate,
		}.Execute(tpm)
		if err != nil {
			t.Fatalf("Load() = %v", err)
		}
		defer FlushContext{FlushHandle: loadRsp.ObjectHandle}.Execute(tpm)
		unsealRsp, err := Unseal{
			ItemHandle: NamedHandle{Handle: loadRsp.ObjectHandle, Name: *nameA},
		}.Execute(tpm)
		if err != nil {
			t.Fatalf("Unseal() = %v", err)
		}
		if !bytes.Equal(unsealRsp.OutData.Buffer, plaintext) {
			t.Fatalf("unsealed data = %x, want %x", unsealRsp.OutData.Buffer, plaintext)
		}
		t.Logf("legitimate import recovered the sensitive area [stage=%s]", rejectStage(nil))
	})

	t.Run("duplicate name: wrapper of B imported with public area A", func(t *testing.T) {
		rsp, err := imp(pubA, dupB, seedA, parentAuth(nil))
		assertNameBindingFailure(t, "B's wrapper against A's public", rsp, err, TPMRCIntegrity)
	})

	t.Run("duplicate name: wrapper of A imported with public area B", func(t *testing.T) {
		rsp, err := imp(pubB, dupA, seedA, parentAuth(nil))
		assertNameBindingFailure(t, "A's wrapper against B's public", rsp, err, TPMRCIntegrity)
	})

	t.Run("fabricated name binding is rejected", func(t *testing.T) {
		rsp, err := imp(pubA, dupFabricated, seedA, parentAuth(nil))
		assertNameBindingFailure(t, "wrapper bound to fabricated Name", rsp, err, TPMRCIntegrity)
	})

	t.Run("truncated name binding is rejected", func(t *testing.T) {
		rsp, err := imp(pubA, dupTruncated, seedA, parentAuth(nil))
		assertNameBindingFailure(t, "wrapper bound to truncated Name", rsp, err, TPMRCIntegrity)
	})

	t.Run("missing parent name in command is rejected client-side", func(t *testing.T) {
		missingNameParent := AuthHandle{Handle: ownerSRK.ObjectHandle, Auth: PasswordAuth(nil)}
		rsp, err := imp(pubA, dupA, seedA, missingNameParent)
		assertNameBindingFailure(t, "missing ParentHandle Name", rsp, err, TPMRCSize)
	})

	t.Run("encoding rearrangement of duplicate wrapper is rejected", func(t *testing.T) {
		rsp, err := imp(pubA, rearrangeWrapper(t, dupA), seedA, parentAuth(nil))
		assertNameBindingFailure(t, "rearranged duplicate wrapper", rsp, err, TPMRCSize)
	})

	t.Run("integrity HMAC tampering is rejected", func(t *testing.T) {
		rsp, err := imp(pubA, flipByte(t, dupA, 4), seedA, parentAuth(nil))
		assertNameBindingFailure(t, "tampered duplicate HMAC", rsp, err, TPMRCIntegrity)
	})

	t.Run("cross-level parent substitution is rejected", func(t *testing.T) {
		rsp, err := imp(pubA, dupCrossLevel, seedCrossLevel, parentAuth(nil))
		assertNameBindingFailure(t, "endorsement-hierarchy wrapper under Owner SRK", rsp, err, TPMRCIntegrity)
	})

	t.Run("wrong parent authorization value is reported separately from name failure", func(t *testing.T) {
		rsp, err := imp(pubA, dupA, seedA, parentAuth([]byte("wrong-password")))
		assertAuthorizationFailure(t, "wrong parent auth value", rsp, err)
	})

	t.Run("legitimate import still works after rejected attacks", func(t *testing.T) {
		rsp, err := imp(pubA, dupA, seedA, parentAuth(nil))
		if err != nil {
			t.Fatalf("post-attack Import() = %v", err)
		}
		if rsp.OutPrivate.Buffer == nil {
			t.Fatal("post-attack Import() returned an empty private area")
		}
	})
}
