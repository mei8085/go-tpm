package tpm2

import (
	"bytes"
	"reflect"
	"testing"
)

// This file exercises the reflection-based TPM structure deserializer through
// its public entry points (Unmarshal, UnmarshalCommand, UnmarshalResponse) and
// through the internal TPM2B decoder. It deliberately uses only in-memory byte
// slices: no TPM device or simulator is involved.
//
// Two invariants are checked throughout:
//
//  1. Structural equivalence of accepted input. If Unmarshal accepts a byte
//     slice, marshalling the decoded value and decoding it again must produce a
//     deeply equal value, and a second marshalling pass must produce the same
//     bytes. Canonical encodings (the output of Marshal) must also survive a
//     byte-for-byte round trip, including when padded with trailing bytes.
//
//  2. No usable half-parsed state on rejection. Every failing entry point
//     returns a nil pointer or the zero value of the command type; the internal
//     TPM2B decoder resets its receiver to the zero value.

// unmarshalRoundTrip decodes data as T and verifies the structural-equivalence
// invariant. It returns nil when the data was rejected.
//
// Failure messages include the offending input in hex so that fuzz and test
// failures are reproducible without rerunning.
func unmarshalRoundTrip[T Marshallable, P interface {
	*T
	Unmarshallable
}](t *testing.T, data []byte) *T {
	t.Helper()

	got, err := Unmarshal[T, P](data)
	if err != nil {
		if got != nil {
			t.Fatalf("Unmarshal(%x) returned a non-nil value together with error %v", data, err)
		}
		return nil
	}

	enc := Marshal(any(*got).(Marshallable))
	again, err := Unmarshal[T, P](enc)
	if err != nil {
		t.Fatalf("re-decoding own encoding of (%x) failed: %x: %v", data, enc, err)
	}
	enc2 := Marshal(any(*again).(Marshallable))
	if !bytes.Equal(enc, enc2) {
		t.Fatalf("marshalling is not stable for (%x): %x then %x", data, enc, enc2)
	}
	if !reflect.DeepEqual(got, again) {
		t.Fatalf("decode is not idempotent for (%x):\nfirst:  %+v\nsecond: %+v", data, got, again)
	}
	return got
}

func mustMarshal(t *testing.T, v Marshallable) []byte {
	t.Helper()
	return Marshal(v)
}

// nestedPublic samples exercise unions inside unions: TPMT_PUBLIC selects
// TPMU_PUBLIC_PARMS which itself embeds TPMT_SYM_DEF_OBJECT, whose fields are
// tagged unions (TPMU_SYM_KEY_BITS, TPMU_SYM_MODE, TPMU_SYM_DETAILS).
func nestedPublic() map[string]Marshallable {
	return map[string]Marshallable{
		"keyedhash": &TPMTPublic{
			Type:    TPMAlgKeyedHash,
			NameAlg: TPMAlgSHA256,
			ObjectAttributes: TPMAObject{
				FixedTPM: true, FixedParent: true, UserWithAuth: true, NoDA: true,
			},
		},
		"ecc-with-sym-and-kdf": &TPMTPublic{
			Type:    TPMAlgECC,
			NameAlg: TPMAlgSHA256,
			AuthPolicy: TPM2BDigest{
				Buffer: bytes.Repeat([]byte{0xa5}, 32),
			},
			Parameters: NewTPMUPublicParms(TPMAlgECC, &TPMSECCParms{
				Symmetric: TPMTSymDefObject{
					Algorithm: TPMAlgAES,
					KeyBits:   NewTPMUSymKeyBits(TPMAlgAES, TPMKeyBits(256)),
					Mode:      NewTPMUSymMode(TPMAlgAES, TPMAlgCFB),
				},
				Scheme: TPMTECCScheme{
					Scheme:  TPMAlgECDSA,
					Details: NewTPMUAsymScheme(TPMAlgECDSA, &TPMSSigSchemeECDSA{HashAlg: TPMAlgSHA256}),
				},
				CurveID: TPMECCNistP384,
				KDF: TPMTKDFScheme{
					Scheme:  TPMAlgKDF2,
					Details: NewTPMUKDFScheme(TPMAlgKDF2, &TPMSKDFSchemeKDF2{HashAlg: TPMAlgSHA512}),
				},
			}),
			Unique: NewTPMUPublicID(TPMAlgECC, &TPMSECCPoint{
				X: TPM2BECCParameter{Buffer: bytes.Repeat([]byte{0x11}, 48)},
				Y: TPM2BECCParameter{Buffer: bytes.Repeat([]byte{0x22}, 48)},
			}),
		},
		"rsa": &TPMTPublic{
			Type:    TPMAlgRSA,
			NameAlg: TPMAlgSHA384,
			Parameters: NewTPMUPublicParms(TPMAlgRSA, &TPMSRSAParms{
				Symmetric: TPMTSymDefObject{Algorithm: TPMAlgNull},
				Scheme: TPMTRSAScheme{
					Scheme:  TPMAlgRSAPSS,
					Details: NewTPMUAsymScheme(TPMAlgRSAPSS, &TPMSSigSchemeRSAPSS{HashAlg: TPMAlgSHA384}),
				},
				KeyBits:  TPMKeyBits(2048),
				Exponent: 65537,
			}),
			Unique: NewTPMUPublicID(TPMAlgRSA, &TPM2BPublicKeyRSA{
				Buffer: bytes.Repeat([]byte{0x5a}, 256),
			}),
		},
		"symcipher": &TPMTPublic{
			Type:    TPMAlgSymCipher,
			NameAlg: TPMAlgSHA1,
			Parameters: NewTPMUPublicParms(TPMAlgSymCipher, &TPMSSymCipherParms{
				Sym: TPMTSymDefObject{
					Algorithm: TPMAlgAES,
					KeyBits:   NewTPMUSymKeyBits(TPMAlgAES, TPMKeyBits(128)),
					Mode:      NewTPMUSymMode(TPMAlgAES, TPMAlgCFB),
				},
			}),
			Unique: NewTPMUPublicID(TPMAlgSymCipher, &TPM2BDigest{Buffer: []byte{0x01}}),
		},
	}
}

// nestedAttest covers every member of the TPMU_ATTEST tagged union. Several
// members contain their own variable-length and list fields.
func nestedAttest() map[string]Marshallable {
	return map[string]Marshallable{
		"quote": &TPMSAttest{
			Magic:           TPMGeneratedValue,
			Type:            TPMSTAttestQuote,
			QualifiedSigner: TPM2BName{Buffer: []byte{0x00, 0x0b, 0xaa}},
			ExtraData:       TPM2BData{Buffer: []byte{0xde, 0xad}},
			ClockInfo:       TPMSClockInfo{Clock: 42, Safe: true},
			FirmwareVersion: 0x00010002,
			Attested: NewTPMUAttest(TPMSTAttestQuote, &TPMSQuoteInfo{
				PCRSelect: TPMLPCRSelection{PCRSelections: []TPMSPCRSelection{
					{Hash: TPMAlgSHA256, PCRSelect: []byte{0x01}},
					{Hash: TPMAlgSHA1, PCRSelect: []byte{0xff, 0xff, 0xff}},
				}},
				PCRDigest: TPM2BDigest{Buffer: bytes.Repeat([]byte{0x33}, 32)},
			}),
		},
		"certify": &TPMSAttest{
			Magic:    TPMGeneratedValue,
			Type:     TPMSTAttestCertify,
			Attested: NewTPMUAttest(TPMSTAttestCertify, &TPMSCertifyInfo{Name: TPM2BName{Buffer: []byte{0x00, 0x0b, 0x01}}, QualifiedName: TPM2BName{Buffer: []byte{0x00, 0x0b, 0x02}}}),
		},
		"creation": &TPMSAttest{
			Magic:    TPMGeneratedValue,
			Type:     TPMSTAttestCreation,
			Attested: NewTPMUAttest(TPMSTAttestCreation, &TPMSCreationInfo{ObjectName: TPM2BName{}, CreationHash: TPM2BDigest{Buffer: []byte{0x04}}}),
		},
		"time": &TPMSAttest{
			Magic:    TPMGeneratedValue,
			Type:     TPMSTAttestTime,
			Attested: NewTPMUAttest(TPMSTAttestTime, &TPMSTimeAttestInfo{Time: TPMSTimeInfo{Time: 7, ClockInfo: TPMSClockInfo{Clock: 8}}, FirmwareVersion: 9}),
		},
		"nv": &TPMSAttest{
			Magic:    TPMGeneratedValue,
			Type:     TPMSTAttestNV,
			Attested: NewTPMUAttest(TPMSTAttestNV, &TPMSNVCertifyInfo{IndexName: TPM2BName{Buffer: []byte{0x40, 0, 0, 1}}, Offset: 5, NVContents: TPM2BData{Buffer: []byte{1, 2, 3}}}),
		},
		"nvdigest": &TPMSAttest{
			Magic:    TPMGeneratedValue,
			Type:     TPMSTAttestNVDigest,
			Attested: NewTPMUAttest(TPMSTAttestNVDigest, &TPMSNVDigestCertifyInfo{IndexName: TPM2BName{}, NVDigest: TPM2BDigest{Buffer: []byte{7}}}),
		},
		"commandaudit": &TPMSAttest{
			Magic:    TPMGeneratedValue,
			Type:     TPMSTAttestCommandAudit,
			Attested: NewTPMUAttest(TPMSTAttestCommandAudit, &TPMSCommandAuditInfo{AuditCounter: 3, DigestAlg: TPMAlgSHA256, AuditDigest: TPM2BDigest{}, CommandDigest: TPM2BDigest{Buffer: []byte{9}}}),
		},
		"sessionaudit": &TPMSAttest{
			Magic:    TPMGeneratedValue,
			Type:     TPMSTAttestSessionAudit,
			Attested: NewTPMUAttest(TPMSTAttestSessionAudit, &TPMSSessionAuditInfo{ExclusiveSession: true, SessionDigest: TPM2BDigest{Buffer: []byte{1}}}),
		},
	}
}

func TestUnmarshalNestedStructures(t *testing.T) {
	for name, v := range nestedPublic() {
		t.Run("public/"+name, func(t *testing.T) {
			enc := mustMarshal(t, v)
			got := unmarshalRoundTrip[TPMTPublic](t, enc)
			if got == nil {
				t.Fatalf("canonical TPMTPublic encoding was rejected: %x", enc)
			}
			if reenc := Marshal(got); !bytes.Equal(enc, reenc) {
				t.Fatalf("TPMTPublic (%s) did not round trip byte-for-byte:\nwant %x\ngot  %x", name, enc, reenc)
			}
		})
	}
	for name, v := range nestedAttest() {
		t.Run("attest/"+name, func(t *testing.T) {
			enc := mustMarshal(t, v)
			got := unmarshalRoundTrip[TPMSAttest](t, enc)
			if got == nil {
				t.Fatalf("canonical TPMSAttest encoding was rejected: %x", enc)
			}
			if reenc := Marshal(got); !bytes.Equal(enc, reenc) {
				t.Fatalf("TPMSAttest (%s) did not round trip byte-for-byte:\nwant %x\ngot  %x", name, enc, reenc)
			}
		})
	}
	t.Run("nvpublic", func(t *testing.T) {
		v := &TPMSNVPublic{
			NVIndex:    TPMRHOwner,
			NameAlg:    TPMAlgSHA256,
			Attributes: TPMANV{OwnerRead: true, OwnerWrite: true, NT: TPMNTOrdinary},
			AuthPolicy: TPM2BDigest{Buffer: bytes.Repeat([]byte{0xc3}, 32)},
			DataSize:   64,
		}
		enc := mustMarshal(t, v)
		got := unmarshalRoundTrip[TPMSNVPublic](t, enc)
		if got == nil || !bytes.Equal(enc, Marshal(got)) {
			t.Fatalf("TPMSNVPublic round trip failed: %x", enc)
		}
	})
}

func TestUnmarshalVariableLengthRegions(t *testing.T) {
	t.Run("tpm2b", func(t *testing.T) {
		// 0x7fff (32767) is the largest size a TPM2B may legally declare; see
		// Part 2, Section 10.3.1.
		for _, size := range []int{0, 1, 2, 255, 256, 4096, 32767} {
			payload := bytes.Repeat([]byte{0x7e}, size)
			enc := mustMarshal(t, &TPM2BData{Buffer: payload})
			got := unmarshalRoundTrip[TPM2BData](t, enc)
			if got == nil {
				t.Fatalf("TPM2BData of size %d was rejected", size)
			}
			if !bytes.Equal(got.Buffer, payload) {
				t.Fatalf("TPM2BData of size %d decoded to %d bytes", size, len(got.Buffer))
			}
			if reenc := Marshal(got); !bytes.Equal(enc, reenc) {
				t.Fatalf("TPM2BData of size %d did not round trip", size)
			}
		}
		// Sizes above the 32767 maximum must be rejected even when the bytes
		// are present.
		for _, size := range []int{32768, 65535} {
			enc := mustMarshal(t, &TPM2BData{Buffer: bytes.Repeat([]byte{0x7e}, size)})
			if v, err := Unmarshal[TPM2BData](enc); err == nil {
				t.Fatalf("TPM2BData of illegal size %d was accepted (%d bytes)", size, len(v.Buffer))
			}
		}
	})
	t.Run("sized8", func(t *testing.T) {
		for _, size := range []int{0, 1, 3, 32, 255} {
			v := &TPMSPCRSelection{Hash: TPMAlgSHA256, PCRSelect: bytes.Repeat([]byte{0x01}, size)}
			enc := mustMarshal(t, v)
			got := unmarshalRoundTrip[TPMSPCRSelection](t, enc)
			if got == nil {
				t.Fatalf("sized8 region of size %d was rejected", size)
			}
			if len(got.PCRSelect) != size {
				t.Fatalf("sized8 region of size %d decoded to %d bytes", size, len(got.PCRSelect))
			}
		}
	})
	t.Run("list", func(t *testing.T) {
		for _, n := range []int{0, 1, 2, 16} {
			sel := make([]TPMSPCRSelection, n)
			for i := range sel {
				sel[i] = TPMSPCRSelection{Hash: TPMAlgSHA256, PCRSelect: []byte{byte(i)}}
			}
			enc := mustMarshal(t, &TPMLPCRSelection{PCRSelections: sel})
			got := unmarshalRoundTrip[TPMLPCRSelection](t, enc)
			if got == nil {
				t.Fatalf("list of %d elements was rejected", n)
			}
			if len(got.PCRSelections) != n {
				t.Fatalf("list of %d elements decoded to %d", n, len(got.PCRSelections))
			}
		}
	})
}

func TestUnmarshalEmptyCollections(t *testing.T) {
	t.Run("empty list", func(t *testing.T) {
		enc := mustMarshal(t, &TPMLCC{CommandCodes: nil})
		if !bytes.Equal(enc, []byte{0, 0, 0, 0}) {
			t.Fatalf("empty TPMLCC encoded as %x, want 00000000", enc)
		}
		got := unmarshalRoundTrip[TPMLCC](t, enc)
		if got == nil || len(got.CommandCodes) != 0 {
			t.Fatalf("empty list did not decode to an empty list: %+v", got)
		}
	})
	t.Run("empty 2B", func(t *testing.T) {
		enc := mustMarshal(t, &TPM2BData{Buffer: nil})
		got := unmarshalRoundTrip[TPM2BData](t, enc)
		if got == nil || len(got.Buffer) != 0 {
			t.Fatalf("empty TPM2B did not decode to an empty buffer: %+v", got)
		}
	})
	t.Run("empty sized8", func(t *testing.T) {
		enc := mustMarshal(t, &TPMSPCRSelection{Hash: TPMAlgNull})
		got := unmarshalRoundTrip[TPMSPCRSelection](t, enc)
		if got == nil || len(got.PCRSelect) != 0 {
			t.Fatalf("empty sized8 did not decode to an empty slice: %+v", got)
		}
	})
	t.Run("empty digest in public", func(t *testing.T) {
		enc := mustMarshal(t, &TPMTPublic{Type: TPMAlgKeyedHash, NameAlg: TPMAlgSHA256})
		got := unmarshalRoundTrip[TPMTPublic](t, enc)
		if got == nil || len(got.AuthPolicy.Buffer) != 0 {
			t.Fatalf("empty AuthPolicy did not decode empty: %+v", got)
		}
	})
}

// trailingByteTrailers are suffixes appended to canonical encodings to verify
// that the deserializer stops after the structure it wants.
var trailingByteTrailers = map[string][]byte{
	"one zero":         {0x00},
	"one nonzero":      {0xff},
	"zero run":         make([]byte, 16),
	"another encoding": Marshal(&TPMTPublic{Type: TPMAlgKeyedHash, NameAlg: TPMAlgSHA256}),
}

// assertTrailingIgnored decodes enc with every trailer appended and requires
// that the result is accepted and re-encodes to exactly enc.
func assertTrailingIgnored[T Marshallable, P interface {
	*T
	Unmarshallable
}](t *testing.T, name string, enc []byte) {
	t.Helper()
	for tname, trailer := range trailingByteTrailers {
		padded := append(append([]byte{}, enc...), trailer...)
		got, err := Unmarshal[T, P](padded)
		if err != nil {
			t.Fatalf("%s + trailing %q: rejected: %v", name, tname, err)
		}
		if reenc := Marshal(any(*got).(Marshallable)); !bytes.Equal(reenc, enc) {
			t.Fatalf("%s + trailing %q: re-encoded to %x, want %x", name, tname, reenc, enc)
		}
	}
}

func TestUnmarshalTrailingBytes(t *testing.T) {
	for name, v := range nestedPublic() {
		assertTrailingIgnored[TPMTPublic](t, "public/"+name, mustMarshal(t, v))
	}
	for name, v := range nestedAttest() {
		assertTrailingIgnored[TPMSAttest](t, "attest/"+name, mustMarshal(t, v))
	}
	assertTrailingIgnored[TPMLPCRSelection](t, "list", mustMarshal(t,
		&TPMLPCRSelection{PCRSelections: []TPMSPCRSelection{{Hash: TPMAlgSHA256, PCRSelect: []byte{1, 2}}}}))
	assertTrailingIgnored[TPM2BData](t, "2B", mustMarshal(t, &TPM2BData{Buffer: []byte{1, 2, 3}}))
}

// assertTruncationRejected requires every proper prefix of enc to be rejected,
// with no value returned alongside the error.
func assertTruncationRejected[T Marshallable, P interface {
	*T
	Unmarshallable
}](t *testing.T, name string, enc []byte) {
	t.Helper()
	for n := 0; n < len(enc); n++ {
		v, err := Unmarshal[T, P](enc[:n])
		if err == nil {
			t.Fatalf("%s truncated to %d/%d bytes was accepted: %+v (full encoding %x)", name, n, len(enc), v, enc)
		}
		if v != nil {
			t.Fatalf("%s truncated to %d/%d bytes returned a value together with error %v", name, n, len(enc), err)
		}
	}
}

func TestUnmarshalTruncationRejected(t *testing.T) {
	for name, v := range nestedPublic() {
		assertTruncationRejected[TPMTPublic](t, "public/"+name, mustMarshal(t, v))
	}
	for name, v := range nestedAttest() {
		assertTruncationRejected[TPMSAttest](t, "attest/"+name, mustMarshal(t, v))
	}
	assertTruncationRejected[TPMSNVPublic](t, "nvpublic",
		mustMarshal(t, &TPMSNVPublic{NVIndex: TPMRHOwner, NameAlg: TPMAlgSHA256}))
	assertTruncationRejected[TPM2BData](t, "2B", mustMarshal(t, &TPM2BData{Buffer: []byte{1, 2, 3}}))
	assertTruncationRejected[TPMSPCRSelection](t, "sized8",
		mustMarshal(t, &TPMSPCRSelection{Hash: TPMAlgSHA256, PCRSelect: []byte{1, 2, 3}}))
	assertTruncationRejected[TPMLPCRSelection](t, "list",
		mustMarshal(t, &TPMLPCRSelection{PCRSelections: []TPMSPCRSelection{{Hash: TPMAlgSHA256, PCRSelect: []byte{1}}}}))
	assertTruncationRejected[TPMSClockInfo](t, "clock",
		mustMarshal(t, &TPMSClockInfo{Clock: 1, ResetCount: 2, RestartCount: 3, Safe: true}))
	assertTruncationRejected[TPMACC](t, "bitfield", mustMarshal(t, &TPMACC{CommandIndex: 0x1234, NV: true}))
	assertTruncationRejected[TPMSAuthCommand](t, "auth-command",
		mustMarshal(t, &TPMSAuthCommand{Nonce: TPM2BNonce{Buffer: []byte{1}}, Authorization: TPM2BData{Buffer: []byte{2}}}))
}

func TestUnmarshalNumericOverflowRejected(t *testing.T) {
	be32 := func(v uint32) []byte {
		return []byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}
	}
	t.Run("list count over int32", func(t *testing.T) {
		if v, err := Unmarshal[TPMLCC](be32(0xFFFFFFFF)); err == nil {
			t.Fatalf("list count 0xffffffff was accepted: %+v", v)
		}
	})
	t.Run("list count over max list length", func(t *testing.T) {
		if v, err := Unmarshal[TPMLCC](be32(0x8000)); err == nil {
			t.Fatalf("list count 0x8000 was accepted: %+v", v)
		}
	})
	t.Run("list count at max but truncated", func(t *testing.T) {
		// 0x7fff is the largest permitted count, but the elements are absent.
		if v, err := Unmarshal[TPMLCC](be32(0x7FFF)); err == nil {
			t.Fatalf("list count 0x7fff with no elements was accepted: %+v", v)
		}
	})
	t.Run("2B size beyond input", func(t *testing.T) {
		if v, err := Unmarshal[TPM2BData]([]byte{0xff, 0xff, 0x00}); err == nil {
			t.Fatalf("TPM2B size 0xffff with 1 byte of data was accepted: %x", v.Buffer)
		}
	})
	t.Run("sized16 size beyond input", func(t *testing.T) {
		// TPM2BData is a sized16 region; claim 0xffff bytes with none present.
		if v, err := Unmarshal[TPM2BData]([]byte{0xff, 0xff}); err == nil {
			t.Fatalf("sized16 region of 0xffff bytes with no data was accepted: %x", v.Buffer)
		}
	})
	t.Run("sized8 size beyond input", func(t *testing.T) {
		// TPMSPCRSelection: hash algorithm then a sized8 region claiming 0xff.
		if v, err := Unmarshal[TPMSPCRSelection]([]byte{0x00, 0x0b, 0xff}); err == nil {
			t.Fatalf("sized8 region of 0xff bytes with no data was accepted: %+v", v)
		}
	})
	t.Run("truncated uint64", func(t *testing.T) {
		// TPMSClockInfo starts with a uint64 Clock field.
		if v, err := Unmarshal[TPMSClockInfo]([]byte{0, 0, 0, 0, 0, 0, 0}); err == nil {
			t.Fatalf("truncated uint64 was accepted: %+v", v)
		}
	})
}

func TestUnmarshalUnknownUnionSelectorRejected(t *testing.T) {
	enc := mustMarshal(t, &TPMTPublic{Type: TPMAlgKeyedHash, NameAlg: TPMAlgSHA256})
	// Overwrite the algorithm selector with AES, which has no TPMU_PUBLIC_PARMS
	// member, while leaving the rest of the encoding intact.
	mutated := append([]byte{}, enc...)
	mutated[0], mutated[1] = 0x00, 0x06
	if v, err := Unmarshal[TPMTPublic](mutated); err == nil {
		t.Fatalf("unknown union selector was accepted: %+v (%x)", v, mutated)
	} else if v != nil {
		t.Fatalf("unknown union selector returned non-nil value with error %v", err)
	}
}

// TestRejectedInputLeavesNoUsableState pins down the "no half-parsed state"
// contract for every public decoding entry point.
func TestRejectedInputLeavesNoUsableState(t *testing.T) {
	t.Run("Unmarshal", func(t *testing.T) {
		// A TPMTPublic whose payload ends midway through a sized region.
		enc := mustMarshal(t, &TPMTPublic{Type: TPMAlgKeyedHash, NameAlg: TPMAlgSHA256})
		for n := 0; n < len(enc); n++ {
			if v, err := Unmarshal[TPMTPublic](enc[:n]); err == nil || v != nil {
				t.Fatalf("truncation to %d bytes: got (%+v, %v), want (nil, non-nil error)", n, v, err)
			}
		}
	})
	t.Run("UnmarshalCommand", func(t *testing.T) {
		cmd := GetCapability{Capability: TPMCapAlgs, Property: 1, PropertyCount: 2}
		enc, err := MarshalCommand(cmd)
		if err != nil {
			t.Fatalf("MarshalCommand: %v", err)
		}
		for n := 0; n < len(enc); n++ {
			got, err := UnmarshalCommand[GetCapability](enc[:n])
			if err == nil {
				t.Fatalf("truncation to %d bytes was accepted: %+v", n, got)
			}
			if !reflect.DeepEqual(got, GetCapability{}) {
				t.Fatalf("truncation to %d bytes left partial command %+v (err %v)", n, got, err)
			}
		}
	})
	t.Run("UnmarshalResponse", func(t *testing.T) {
		enc, err := MarshalResponse(GetCapability{}, &GetCapabilityResponse{
			CapabilityData: TPMSCapabilityData{
				Capability: TPMCapAlgs,
				Data:       NewTPMUCapabilities(TPMCapAlgs, &TPMLAlgProperty{}),
			},
		})
		if err != nil {
			t.Fatalf("MarshalResponse: %v", err)
		}
		for n := 0; n < len(enc); n++ {
			got, err := UnmarshalResponse[GetCapabilityResponse](enc[:n])
			if err == nil || got != nil {
				t.Fatalf("truncation to %d bytes: got (%+v, %v), want (nil, non-nil error)", n, got, err)
			}
		}
	})
	t.Run("TPM2B receiver is zeroed", func(t *testing.T) {
		// Pre-populate the receiver, then feed a truncated TPM2B. The internal
		// decoder must not leave the old or partially read contents behind.
		value := New2B(TPMTPublic{Type: TPMAlgKeyedHash, NameAlg: TPMAlgSHA256})
		value.buffer = []byte{0x01, 0x02}
		if err := value.unmarshal(bytes.NewBuffer([]byte{0x00, 0x10, 0xaa})); err == nil {
			t.Fatal("truncated TPM2B was accepted")
		}
		if value.buffer != nil || value.contents != nil {
			t.Fatalf("failed TPM2B decode left state: buffer=%x contents=%+v", value.buffer, value.contents)
		}
		// A failed 2-byte size prefix must also reset the receiver.
		value = New2B(TPMTPublic{Type: TPMAlgKeyedHash, NameAlg: TPMAlgSHA256})
		if err := value.unmarshal(bytes.NewBuffer([]byte{0x00})); err == nil {
			t.Fatal("TPM2B with a partial size field was accepted")
		}
		if value.buffer != nil || value.contents != nil {
			t.Fatalf("failed TPM2B size decode left state: buffer=%x contents=%+v", value.buffer, value.contents)
		}
	})
	t.Run("Contents does not cache a failure", func(t *testing.T) {
		value := BytesAs2B[TPMTPublic]([]byte{0x00}) // one byte: too short
		if _, err := value.Contents(); err == nil {
			t.Fatal("Contents accepted a truncated buffer")
		}
		if value.contents != nil {
			t.Fatalf("Contents cached a value after a failure: %+v", value.contents)
		}
	})
}

func TestUnmarshalDoesNotMutateInput(t *testing.T) {
	for name, v := range nestedPublic() {
		enc := mustMarshal(t, v)
		orig := append([]byte{}, enc...)
		if _, err := Unmarshal[TPMTPublic](enc); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !bytes.Equal(orig, enc) {
			t.Fatalf("%s: Unmarshal mutated its input: %x -> %x", name, orig, enc)
		}
	}
}

// TestUnmarshalResponseRejectsMissingParameters covers responses with an
// optional parameter: an empty optional region must not let the decoder skip
// the required parameters that follow it.
func TestUnmarshalResponseRejectsMissingParameters(t *testing.T) {
	full, err := MarshalResponse(CreateLoaded{}, &CreateLoadedResponse{
		ObjectHandle: TPMHandle(0x80000001),
		OutPublic:    New2B(TPMTPublic{Type: TPMAlgKeyedHash, NameAlg: TPMAlgSHA256}),
		Name:         TPM2BName{Buffer: []byte{0x00, 0x0b, 0xaa}},
	})
	if err != nil {
		t.Fatalf("MarshalResponse: %v", err)
	}
	if _, err := UnmarshalResponse[CreateLoadedResponse](full); err != nil {
		t.Fatalf("canonical response was rejected: %v", err)
	}
	// Any prefix of the response must be rejected, including the one that
	// ends immediately after the zero-length optional region.
	for n := 0; n < len(full); n++ {
		if got, err := UnmarshalResponse[CreateLoadedResponse](full[:n]); err == nil || got != nil {
			t.Fatalf("truncation to %d/%d bytes: got (%+v, %v), want (nil, non-nil error)", n, len(full), got, err)
		}
	}
}

// TestUnmarshalResponseWithoutParameters covers a response struct that has no
// parameters at all; its canonical preimage is exactly the 8-byte header.
func TestUnmarshalResponseWithoutParameters(t *testing.T) {
	enc, err := MarshalResponse(NVReadLock{}, &NVReadLockResponse{})
	if err != nil {
		t.Fatalf("MarshalResponse: %v", err)
	}
	if len(enc) != 8 {
		t.Fatalf("parameterless response encoded to %d bytes (%x), want 8", len(enc), enc)
	}
	if _, err := UnmarshalResponse[NVReadLockResponse](enc); err != nil {
		t.Fatalf("parameterless response was rejected: %v", err)
	}
}

// TestUnmarshalCommandResponseTrailingBytes documents that the cpHash/rpHash
// preimage decoders consume the leading structure and ignore any suffix. This
// mirrors Unmarshal's behavior, which is required for callers that decode a
// structure from the front of a larger buffer.
func TestUnmarshalCommandResponseTrailingBytes(t *testing.T) {
	cmd := GetCapability{Capability: TPMCapAlgs, Property: 1, PropertyCount: 2}
	cmdEnc, err := MarshalCommand(cmd)
	if err != nil {
		t.Fatalf("MarshalCommand: %v", err)
	}
	rspEnc, err := MarshalResponse(GetCapability{}, &GetCapabilityResponse{
		CapabilityData: TPMSCapabilityData{
			Capability: TPMCapAlgs,
			Data:       NewTPMUCapabilities(TPMCapAlgs, &TPMLAlgProperty{}),
		},
	})
	if err != nil {
		t.Fatalf("MarshalResponse: %v", err)
	}
	for _, n := range []int{1, 2, 3, 16} {
		suffix := bytes.Repeat([]byte{0xde}, n)

		gotCmd, err := UnmarshalCommand[GetCapability](append(append([]byte{}, cmdEnc...), suffix...))
		if err != nil {
			t.Fatalf("command + %d trailing bytes was rejected: %v", n, err)
		}
		if !reflect.DeepEqual(gotCmd, cmd) {
			t.Fatalf("command + %d trailing bytes decoded to %+v, want %+v", n, gotCmd, cmd)
		}

		gotRsp, err := UnmarshalResponse[GetCapabilityResponse](append(append([]byte{}, rspEnc...), suffix...))
		if err != nil {
			t.Fatalf("response + %d trailing bytes was rejected: %v", n, err)
		}
		if reenc, err := MarshalResponse(GetCapability{}, gotRsp); err != nil {
			t.Fatalf("re-marshalling response + %d trailing bytes: %v", n, err)
		} else if !bytes.Equal(reenc, rspEnc) {
			t.Fatalf("response + %d trailing bytes re-encoded to %x, want %x", n, reenc, rspEnc)
		}
	}
}
