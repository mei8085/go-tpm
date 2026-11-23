package tpm2

import (
	"bytes"
	"crypto/sha256"
	"testing"
)

// policyExtend reproduces the chaining rule of PolicyCalculator from the TPM
// specification (Part 3, 23.2.3) so tests can check it independently.
func policyExtend(t *testing.T, state []byte, parts ...[]byte) []byte {
	t.Helper()
	h := sha256.New()
	h.Write(state)
	for _, p := range parts {
		h.Write(p)
	}
	return h.Sum(nil)
}

func newSHA256Policy(t *testing.T) *PolicyCalculator {
	t.Helper()
	p, err := NewPolicyCalculator(TPMAlgSHA256)
	if err != nil {
		t.Fatalf("NewPolicyCalculator() = %v", err)
	}
	return p
}

func be16(v uint16) []byte { return []byte{byte(v >> 8), byte(v)} }
func be32(v uint32) []byte {
	return []byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}
}

// TestPolicyCalculatorsAreIndependent checks that separate calculators do not
// share state, so that one object's policy cannot leak into another's.
func TestPolicyCalculatorsAreIndependent(t *testing.T) {
	a := newSHA256Policy(t)
	b := newSHA256Policy(t)

	zero := make([]byte, sha256.Size)
	if !bytes.Equal(a.Hash().Digest, zero) || !bytes.Equal(b.Hash().Digest, zero) {
		t.Fatalf("fresh calculators are not zeroed: a=%x b=%x", a.Hash().Digest, b.Hash().Digest)
	}

	if err := (PolicyPhysicalPresence{}).Update(a); err != nil {
		t.Fatalf("PolicyPhysicalPresence.Update() = %v", err)
	}
	if bytes.Equal(a.Hash().Digest, zero) {
		t.Errorf("a was not updated")
	}
	if !bytes.Equal(b.Hash().Digest, zero) {
		t.Errorf("updating a changed b to %x", b.Hash().Digest)
	}

	// Reset on a must not touch b either.
	if err := (PolicyRestart{}).Update(a); err != nil {
		t.Fatalf("PolicyRestart.Update() = %v", err)
	}
	if !bytes.Equal(a.Hash().Digest, zero) {
		t.Errorf("a after restart = %x, want zeros", a.Hash().Digest)
	}
	if !bytes.Equal(b.Hash().Digest, zero) {
		t.Errorf("b after restarting a = %x, want zeros", b.Hash().Digest)
	}
}

// TestPolicyRestartResetsOnlyPolicyState checks that PolicyRestart clears the
// digest rather than extending it, matching the session reset performed by the
// TPM (Part 3, 23.2).
func TestPolicyRestartResetsOnlyPolicyState(t *testing.T) {
	p := newSHA256Policy(t)
	for _, cmd := range []PolicyCommand{
		PolicyPhysicalPresence{},
		PolicyPassword{},
		PolicyNameHash{NameHash: TPM2BDigest{Buffer: make([]byte, sha256.Size)}},
	} {
		if err := cmd.Update(p); err != nil {
			t.Fatalf("%T.Update() = %v", cmd, err)
		}
	}
	if bytes.Equal(p.Hash().Digest, make([]byte, sha256.Size)) {
		t.Fatalf("policy is zeroed before restart")
	}
	if err := (PolicyRestart{}).Update(p); err != nil {
		t.Fatalf("PolicyRestart.Update() = %v", err)
	}
	if !bytes.Equal(p.Hash().Digest, make([]byte, sha256.Size)) {
		t.Errorf("after PolicyRestart digest = %x, want zeros", p.Hash().Digest)
	}
}

func TestPolicyLocalityPreimage(t *testing.T) {
	p := newSHA256Policy(t)
	locality := TPMALocality{TPMLocZero: true, TPMLocThree: true}
	if err := (PolicyLocality{Locality: locality}).Update(p); err != nil {
		t.Fatalf("PolicyLocality.Update() = %v", err)
	}
	want := policyExtend(t, make([]byte, sha256.Size),
		be32(uint32(TPMCCPolicyLocality)),
		[]byte{0x09}, // bits 0 and 3
	)
	if !bytes.Equal(p.Hash().Digest, want) {
		t.Errorf("PolicyLocality digest = %x, want %x", p.Hash().Digest, want)
	}
}

func TestPolicyNameHashPreimage(t *testing.T) {
	p := newSHA256Policy(t)
	nameHash := bytes.Repeat([]byte{0xAB}, sha256.Size)
	if err := (PolicyNameHash{NameHash: TPM2BDigest{Buffer: nameHash}}).Update(p); err != nil {
		t.Fatalf("PolicyNameHash.Update() = %v", err)
	}
	want := policyExtend(t, make([]byte, sha256.Size),
		be32(uint32(TPMCCPolicyNameHash)),
		nameHash,
	)
	if !bytes.Equal(p.Hash().Digest, want) {
		t.Errorf("PolicyNameHash digest = %x, want %x", p.Hash().Digest, want)
	}
}

// TestPolicyNameHashSizeValidation checks the size check the TPM applies even
// to trial sessions (Part 3, 23.14).
func TestPolicyNameHashSizeValidation(t *testing.T) {
	for _, alg := range []TPMIAlgHash{TPMAlgSHA1, TPMAlgSHA256, TPMAlgSHA384, TPMAlgSHA512} {
		h, err := alg.Hash()
		if err != nil {
			t.Fatalf("%v.Hash() = %v", alg, err)
		}
		p, err := NewPolicyCalculator(alg)
		if err != nil {
			t.Fatalf("NewPolicyCalculator(%v) = %v", alg, err)
		}
		if err := (PolicyNameHash{NameHash: TPM2BDigest{Buffer: make([]byte, h.Size())}}).Update(p); err != nil {
			t.Errorf("%v: correct-size nameHash rejected: %v", alg, err)
		}
		if err := (PolicyNameHash{NameHash: TPM2BDigest{Buffer: make([]byte, h.Size()+1)}}).Update(p); err == nil {
			t.Errorf("%v: oversize nameHash accepted", alg)
		}
	}
}

func TestPolicyCounterTimerPreimage(t *testing.T) {
	p := newSHA256Policy(t)
	operand := []byte{0x01, 0x02, 0x03, 0x04}
	offset := uint16(8)
	op := TPMEOUnsignedGE
	if err := (PolicyCounterTimer{OperandB: TPM2BOperand{Buffer: operand}, Offset: offset, Operation: op}).Update(p); err != nil {
		t.Fatalf("PolicyCounterTimer.Update() = %v", err)
	}

	argHash := sha256.New()
	argHash.Write(operand)
	argHash.Write(be16(offset))
	argHash.Write(be16(uint16(op)))

	want := policyExtend(t, make([]byte, sha256.Size),
		be32(uint32(TPMCCPolicyCounterTimer)),
		argHash.Sum(nil),
	)
	if !bytes.Equal(p.Hash().Digest, want) {
		t.Errorf("PolicyCounterTimer digest = %x, want %x", p.Hash().Digest, want)
	}
}

// TestPolicyCounterTimerTimeInfoSize checks that the bounds used by the
// calculator match the canonical encoding of TPMS_TIME_INFO.
func TestPolicyCounterTimerTimeInfoSize(t *testing.T) {
	if got := len(Marshal(&TPMSTimeInfo{})); got != tpmTimeInfoSize {
		t.Errorf("TPMS_TIME_INFO marshals to %d bytes, want %d", got, tpmTimeInfoSize)
	}
}

// TestPolicyCounterTimerBounds checks the bounds that the TPM enforces on the
// reference into TPMS_TIME_INFO even for a trial session (Part 3, 23.10).
func TestPolicyCounterTimerBounds(t *testing.T) {
	tests := []struct {
		name    string
		offset  uint16
		operand int
		wantErr bool
	}{
		// TPMS_TIME_INFO is 25 bytes: Time(8) + Clock(8) + resetCount(4) +
		// restartCount(4) + Safe(1).
		{"StartOfTime", 0, 8, false},
		{"EndOfSafe", 24, 1, false},
		{"EmptyOperandAtEnd", 25, 0, false},
		{"OffsetPastEnd", 26, 0, true},
		{"FullStructure", 0, 25, false},
		{"OperandRunsPastEnd", 20, 6, true},
	}
	for _, tt := range tests {
		p := newSHA256Policy(t)
		cmd := PolicyCounterTimer{
			OperandB:  TPM2BOperand{Buffer: make([]byte, tt.operand)},
			Offset:    tt.offset,
			Operation: TPMEOEq,
		}
		err := cmd.Update(p)
		if tt.wantErr && err == nil {
			t.Errorf("%s: Update() succeeded, want error", tt.name)
		}
		if !tt.wantErr && err != nil {
			t.Errorf("%s: Update() = %v", tt.name, err)
		}
	}
}

// TestPolicyCounterTimerOperations checks that every comparison constant is
// accepted and that undefined values are rejected, mirroring the unmarshalling
// check of TPM_EO (Part 2, 6.8).
func TestPolicyCounterTimerOperations(t *testing.T) {
	for op := TPMEOEq; op <= TPMEOBitClear; op++ {
		p := newSHA256Policy(t)
		if err := (PolicyCounterTimer{OperandB: TPM2BOperand{Buffer: []byte{0}}, Operation: op}).Update(p); err != nil {
			t.Errorf("operation %#04x rejected: %v", uint16(op), err)
		}
	}
	for _, op := range []TPMEO{TPMEOBitClear + 1, 0x00FF, 0xFFFF} {
		p := newSHA256Policy(t)
		if err := (PolicyCounterTimer{OperandB: TPM2BOperand{Buffer: []byte{0}}, Operation: op}).Update(p); err == nil {
			t.Errorf("operation %#04x accepted", uint16(op))
		}
	}
}

func TestPolicyTemplatePreimage(t *testing.T) {
	p := newSHA256Policy(t)
	templateHash := bytes.Repeat([]byte{0x5A}, sha256.Size)
	if err := (PolicyTemplate{TemplateHash: TPM2BDigest{Buffer: templateHash}}).Update(p); err != nil {
		t.Fatalf("PolicyTemplate.Update() = %v", err)
	}
	want := policyExtend(t, make([]byte, sha256.Size),
		be32(uint32(TPMCCPolicyTemplate)),
		templateHash,
	)
	if !bytes.Equal(p.Hash().Digest, want) {
		t.Errorf("PolicyTemplate digest = %x, want %x", p.Hash().Digest, want)
	}
}

// TestPolicyPasswordMatchesAuthValue checks that PolicyPassword extends the
// digest with TPM_CC_PolicyAuthValue, as specified in Part 3, 23.18. The two
// commands therefore commit to the same policy; they differ only in the session
// attribute that they set.
func TestPolicyPasswordMatchesAuthValue(t *testing.T) {
	pwPol := newSHA256Policy(t)
	if err := (PolicyPassword{}).Update(pwPol); err != nil {
		t.Fatalf("PolicyPassword.Update() = %v", err)
	}
	want := policyExtend(t, make([]byte, sha256.Size), be32(uint32(TPMCCPolicyAuthValue)))
	if !bytes.Equal(pwPol.Hash().Digest, want) {
		t.Errorf("PolicyPassword digest = %x, want %x", pwPol.Hash().Digest, want)
	}

	authPol := newSHA256Policy(t)
	if err := (PolicyAuthValue{}).Update(authPol); err != nil {
		t.Fatalf("PolicyAuthValue.Update() = %v", err)
	}
	if !bytes.Equal(pwPol.Hash().Digest, authPol.Hash().Digest) {
		t.Errorf("PolicyPassword digest = %x, PolicyAuthValue digest = %x; want equal",
			pwPol.Hash().Digest, authPol.Hash().Digest)
	}
}

func TestPolicyPhysicalPresencePreimage(t *testing.T) {
	p := newSHA256Policy(t)
	if err := (PolicyPhysicalPresence{}).Update(p); err != nil {
		t.Fatalf("PolicyPhysicalPresence.Update() = %v", err)
	}
	want := policyExtend(t, make([]byte, sha256.Size), be32(uint32(TPMCCPolicyPhysicalPresence)))
	if !bytes.Equal(p.Hash().Digest, want) {
		t.Errorf("PolicyPhysicalPresence digest = %x, want %x", p.Hash().Digest, want)
	}
}

// TestPolicyTicketMatchesAuthorization checks that a ticket reproduces the
// digest of the authorization it stands in for, which is how the TPM applies a
// ticket (Part 3, 23.5 and the reference implementation's PolicyContextUpdate
// with TPM_CC_PolicySigned or TPM_CC_PolicySecret selected by the ticket tag).
func TestPolicyTicketMatchesAuthorization(t *testing.T) {
	name := TPM2BName{Buffer: bytes.Repeat([]byte{0x11}, 34)}
	policyRef := TPM2BNonce{Buffer: []byte{0x22, 0x33}}

	for _, tt := range []struct {
		name  string
		tag   TPMST
		cc    TPMCC
		other PolicyCommand
	}{
		{
			name:  "AuthSigned",
			tag:   TPMSTAuthSigned,
			cc:    TPMCCPolicySigned,
			other: PolicySigned{AuthObject: NamedHandle{Name: name}, PolicyRef: policyRef},
		},
		{
			name:  "AuthSecret",
			tag:   TPMSTAuthSecret,
			cc:    TPMCCPolicySecret,
			other: PolicySecret{AuthHandle: AuthHandle{Name: name}, PolicyRef: policyRef},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ticketPol := newSHA256Policy(t)
			ticket := PolicyTicket{
				PolicyRef: policyRef,
				AuthName:  name,
				Ticket:    TPMTTKAuth{Tag: tt.tag},
			}
			if err := ticket.Update(ticketPol); err != nil {
				t.Fatalf("PolicyTicket.Update() = %v", err)
			}

			// Independently compute the two-step update of
			// PolicyContextUpdate.
			first := policyExtend(t, make([]byte, sha256.Size), be32(uint32(tt.cc)), name.Buffer)
			want := policyExtend(t, first, policyRef.Buffer)
			if !bytes.Equal(ticketPol.Hash().Digest, want) {
				t.Errorf("PolicyTicket digest = %x, want %x", ticketPol.Hash().Digest, want)
			}

			otherPol := newSHA256Policy(t)
			if err := tt.other.Update(otherPol); err != nil {
				t.Fatalf("%T.Update() = %v", tt.other, err)
			}
			if !bytes.Equal(ticketPol.Hash().Digest, otherPol.Hash().Digest) {
				t.Errorf("PolicyTicket digest = %x, %T digest = %x; want equal",
					ticketPol.Hash().Digest, tt.other, otherPol.Hash().Digest)
			}
		})
	}
}

func TestPolicyTicketRejectsNonAuthTickets(t *testing.T) {
	for _, tag := range []TPMST{TPMSTVerified, TPMSTHashCheck, 0} {
		p := newSHA256Policy(t)
		if err := (PolicyTicket{Ticket: TPMTTKAuth{Tag: tag}}).Update(p); err == nil {
			t.Errorf("tag %#04x accepted, want error", uint16(tag))
		}
	}
}

// TestPolicyLocalityValidation checks the constraint the TPM applies to the
// locality byte: it may not be zero (Part 3, 23.8).
func TestPolicyLocalityValidation(t *testing.T) {
	p := newSHA256Policy(t)
	if err := (PolicyLocality{Locality: TPMALocality{}}).Update(p); err == nil {
		t.Errorf("empty locality accepted, want error")
	}
	for _, l := range []TPMALocality{
		{TPMLocZero: true},
		{TPMLocFour: true},
		{TPMLocZero: true, TPMLocOne: true, TPMLocTwo: true, TPMLocThree: true, TPMLocFour: true},
		{Extended: 1},
		{Extended: 7},
	} {
		p := newSHA256Policy(t)
		if err := (PolicyLocality{Locality: l}).Update(p); err != nil {
			t.Errorf("locality %+v rejected: %v", l, err)
		}
	}
}

// TestPolicyTemplateSizeValidation checks the digest size constraint.
func TestPolicyTemplateSizeValidation(t *testing.T) {
	p := newSHA256Policy(t)
	if err := (PolicyTemplate{TemplateHash: TPM2BDigest{Buffer: make([]byte, sha256.Size)}}).Update(p); err != nil {
		t.Errorf("correct-size templateHash rejected: %v", err)
	}
	if err := (PolicyTemplate{TemplateHash: TPM2BDigest{Buffer: make([]byte, 3)}}).Update(p); err == nil {
		t.Errorf("short templateHash accepted")
	}
}

// TestPolicyACSendSelectPreimage checks the name-binding digest of
// TPM2_Policy_AC_SendSelect, including the conditional object Name.
func TestPolicyACSendSelectPreimage(t *testing.T) {
	objectName := []byte{0x00, 0x0B, 1, 2, 3}
	authHandleName := []byte{0x40, 0x00, 0x00, 0x01}
	acName := []byte{0x00, 0x0B, 9, 9}

	tests := []struct {
		name          string
		includeObject bool
	}{
		{"ExcludeObject", false},
		{"IncludeObject", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := newSHA256Policy(t)
			cmd := PolicyACSendSelect{
				ObjectName:     TPM2BName{Buffer: objectName},
				AuthHandleName: TPM2BName{Buffer: authHandleName},
				ACName:         TPM2BName{Buffer: acName},
				IncludeObject:  tt.includeObject,
			}
			if err := cmd.Update(p); err != nil {
				t.Fatalf("PolicyACSendSelect.Update() = %v", err)
			}

			parts := [][]byte{be32(uint32(TPMCCPolicyACSendSelect))}
			if tt.includeObject {
				parts = append(parts, objectName)
			}
			var include []byte
			if tt.includeObject {
				include = []byte{1}
			} else {
				include = []byte{0}
			}
			parts = append(parts, authHandleName, acName, include)
			want := policyExtend(t, make([]byte, sha256.Size), parts...)
			if !bytes.Equal(p.Hash().Digest, want) {
				t.Errorf("PolicyACSendSelect digest = %x, want %x", p.Hash().Digest, want)
			}
		})
	}
}
