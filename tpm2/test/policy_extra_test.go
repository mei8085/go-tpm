package tpm2test

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"testing"

	. "github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/testhelper"
)

// policyDigests runs the given policy commands against a trial policy session
// and returns both the digest that the TPM reports and the digest that
// PolicyCalculator computes locally. The returned errors are the errors of the
// Update calls, so callers can check calculator-side validation.
//
// Each element of build must be a command value whose PolicySession is set from
// the handle it is given.
func policyDigests(t *testing.T, thetpm transport.TPM, build ...func(TPMHandle) PolicyCommand) (want, got []byte, updateErrs []error) {
	t.Helper()

	sess, cleanup, err := PolicySession(thetpm, TPMAlgSHA256, 16, Trial())
	if err != nil {
		t.Fatalf("setting up trial session: %v", err)
	}
	defer func() {
		if err := cleanup(); err != nil {
			t.Errorf("cleaning up trial session: %v", err)
		}
	}()

	cmds := make([]PolicyCommand, 0, len(build))
	for i, b := range build {
		cmd := b(sess.Handle())
		if err := executePolicyCommand(t, thetpm, cmd); err != nil {
			t.Fatalf("executing policy command %d (%T): %v", i, cmd, err)
		}
		cmds = append(cmds, cmd)
	}

	pgd, err := PolicyGetDigest{PolicySession: sess.Handle()}.Execute(thetpm)
	if err != nil {
		t.Fatalf("executing PolicyGetDigest: %v", err)
	}

	pol, err := NewPolicyCalculator(TPMAlgSHA256)
	if err != nil {
		t.Fatalf("creating policy calculator: %v", err)
	}
	for _, cmd := range cmds {
		updateErrs = append(updateErrs, cmd.Update(pol))
	}
	return pgd.PolicyDigest.Buffer, pol.Hash().Digest, updateErrs
}

// executePolicyCommand executes a policy command whose PolicySession is already
// set.
func executePolicyCommand(t *testing.T, thetpm transport.TPM, cmd PolicyCommand) error {
	t.Helper()
	var err error
	switch c := cmd.(type) {
	case PolicyLocality:
		_, err = c.Execute(thetpm)
	case PolicyNameHash:
		_, err = c.Execute(thetpm)
	case PolicyCounterTimer:
		_, err = c.Execute(thetpm)
	case PolicyTemplate:
		_, err = c.Execute(thetpm)
	case PolicyPassword:
		_, err = c.Execute(thetpm)
	case PolicyPhysicalPresence:
		_, err = c.Execute(thetpm)
	case PolicyRestart:
		_, err = c.Execute(thetpm)
	case PolicyACSendSelect:
		_, err = c.Execute(thetpm)
	default:
		t.Fatalf("unhandled policy command type %T", cmd)
	}
	return err
}

// assertPolicyRejected checks that both the TPM and PolicyCalculator reject the
// command. This is the case for inputs that the TPM validates even in a trial
// session, where the calculator is meant to be an equivalent.
func assertPolicyRejected(t *testing.T, thetpm transport.TPM, build func(TPMHandle) PolicyCommand) {
	t.Helper()

	sess, cleanup, err := PolicySession(thetpm, TPMAlgSHA256, 16, Trial())
	if err != nil {
		t.Fatalf("setting up trial session: %v", err)
	}
	defer cleanup()

	cmd := build(sess.Handle())
	if err := executePolicyCommand(t, thetpm, cmd); err == nil {
		t.Errorf("%T.Execute() succeeded, want error", cmd)
	}

	pol, err := NewPolicyCalculator(TPMAlgSHA256)
	if err != nil {
		t.Fatalf("creating policy calculator: %v", err)
	}
	if err := cmd.Update(pol); err == nil {
		t.Errorf("%T.Update() succeeded, want error", cmd)
	}
}

func TestPolicyLocalityUpdate(t *testing.T) {
	thetpm := testhelper.Open(t)
	defer thetpm.Close()

	locality := TPMALocality{TPMLocZero: true, TPMLocOne: true, TPMLocTwo: true}
	want, got, errs := policyDigests(t, thetpm, func(h TPMHandle) PolicyCommand {
		return PolicyLocality{PolicySession: h, Locality: locality}
	})
	if err := errs[0]; err != nil {
		t.Fatalf("PolicyLocality.Update() = %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("PolicyLocality digest = %x,\nwant %x", got, want)
	}
}

func TestPolicyLocalityUpdateExtended(t *testing.T) {
	thetpm := testhelper.Open(t)
	defer thetpm.Close()

	locality := TPMALocality{Extended: 1}
	want, got, errs := policyDigests(t, thetpm, func(h TPMHandle) PolicyCommand {
		return PolicyLocality{PolicySession: h, Locality: locality}
	})
	if err := errs[0]; err != nil {
		t.Fatalf("PolicyLocality.Update() = %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("PolicyLocality digest = %x,\nwant %x", got, want)
	}
}

func TestPolicyLocalityUpdateMaxExtended(t *testing.T) {
	thetpm := testhelper.Open(t)
	defer thetpm.Close()

	// Extended localities occupy bits 7:5, so Extended == 7 is the largest
	// encoded value (0xE0).
	locality := TPMALocality{Extended: 7}
	want, got, errs := policyDigests(t, thetpm, func(h TPMHandle) PolicyCommand {
		return PolicyLocality{PolicySession: h, Locality: locality}
	})
	if err := errs[0]; err != nil {
		t.Fatalf("PolicyLocality.Update() = %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("PolicyLocality digest = %x,\nwant %x", got, want)
	}
}

func TestPolicyLocalityUpdateInvalid(t *testing.T) {
	thetpm := testhelper.Open(t)
	defer thetpm.Close()

	for _, tt := range []struct {
		name     string
		locality TPMALocality
	}{
		{"Empty", TPMALocality{}},
		{"EmptyExtended", TPMALocality{Extended: 0}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			assertPolicyRejected(t, thetpm, func(h TPMHandle) PolicyCommand {
				return PolicyLocality{PolicySession: h, Locality: tt.locality}
			})
		})
	}
}

func TestPolicyNameHashUpdate(t *testing.T) {
	thetpm := testhelper.Open(t)
	defer thetpm.Close()

	nameHash := TPM2BDigest{Buffer: sha256.New().Sum(nil)}
	want, got, errs := policyDigests(t, thetpm, func(h TPMHandle) PolicyCommand {
		return PolicyNameHash{PolicySession: h, NameHash: nameHash}
	})
	if err := errs[0]; err != nil {
		t.Fatalf("PolicyNameHash.Update() = %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("PolicyNameHash digest = %x,\nwant %x", got, want)
	}
}

func TestPolicyNameHashUpdateWrongSize(t *testing.T) {
	thetpm := testhelper.Open(t)
	defer thetpm.Close()

	shortHash := TPM2BDigest{Buffer: []byte{1, 2, 3}}
	assertPolicyRejected(t, thetpm, func(h TPMHandle) PolicyCommand {
		return PolicyNameHash{PolicySession: h, NameHash: shortHash}
	})
}

func TestPolicyCounterTimerUpdate(t *testing.T) {
	thetpm := testhelper.Open(t)
	defer thetpm.Close()

	// Time is the first uint64 of TPMS_TIME_INFO, so an 8-byte operand at
	// offset 0 is in bounds.
	operand := TPM2BOperand{Buffer: make([]byte, 8)}
	want, got, errs := policyDigests(t, thetpm, func(h TPMHandle) PolicyCommand {
		return PolicyCounterTimer{
			PolicySession: h,
			OperandB:      operand,
			Offset:        0,
			Operation:     TPMEOUnsignedGE,
		}
	})
	if err := errs[0]; err != nil {
		t.Fatalf("PolicyCounterTimer.Update() = %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("PolicyCounterTimer digest = %x,\nwant %x", got, want)
	}
}

func TestPolicyCounterTimerUpdateInvalid(t *testing.T) {
	thetpm := testhelper.Open(t)
	defer thetpm.Close()

	tests := []struct {
		name string
		cmd  PolicyCounterTimer
	}{
		{
			name: "OffsetBeyondTimeInfo",
			cmd:  PolicyCounterTimer{OperandB: TPM2BOperand{Buffer: []byte{1}}, Offset: 25},
		},
		{
			name: "OperandRunsPastTimeInfo",
			cmd:  PolicyCounterTimer{OperandB: TPM2BOperand{Buffer: make([]byte, 8)}, Offset: 20},
		},
		{
			name: "InvalidOperation",
			cmd:  PolicyCounterTimer{OperandB: TPM2BOperand{Buffer: []byte{1}}, Offset: 0, Operation: TPMEO(0xFFFF)},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := tt.cmd
			assertPolicyRejected(t, thetpm, func(h TPMHandle) PolicyCommand {
				cmd.PolicySession = h
				return cmd
			})
		})
	}
}

func TestPolicyTemplateUpdate(t *testing.T) {
	thetpm := testhelper.Open(t)
	defer thetpm.Close()

	templateHash := TPM2BDigest{Buffer: sha256.New().Sum(nil)}
	want, got, errs := policyDigests(t, thetpm, func(h TPMHandle) PolicyCommand {
		return PolicyTemplate{PolicySession: h, TemplateHash: templateHash}
	})
	if err := errs[0]; err != nil {
		t.Fatalf("PolicyTemplate.Update() = %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("PolicyTemplate digest = %x,\nwant %x", got, want)
	}
}

func TestPolicyTemplateUpdateWrongSize(t *testing.T) {
	thetpm := testhelper.Open(t)
	defer thetpm.Close()

	shortHash := TPM2BDigest{Buffer: []byte{1, 2}}
	assertPolicyRejected(t, thetpm, func(h TPMHandle) PolicyCommand {
		return PolicyTemplate{PolicySession: h, TemplateHash: shortHash}
	})
}

func TestPolicyPasswordUpdate(t *testing.T) {
	thetpm := testhelper.Open(t)
	defer thetpm.Close()

	want, got, errs := policyDigests(t, thetpm, func(h TPMHandle) PolicyCommand {
		return PolicyPassword{PolicySession: h}
	})
	if err := errs[0]; err != nil {
		t.Fatalf("PolicyPassword.Update() = %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("PolicyPassword digest = %x,\nwant %x", got, want)
	}

	// Part 3, section 23.18: PolicyPassword extends the digest exactly as
	// PolicyAuthValue does.
	authPol, err := NewPolicyCalculator(TPMAlgSHA256)
	if err != nil {
		t.Fatalf("creating policy calculator: %v", err)
	}
	if err := (PolicyAuthValue{}).Update(authPol); err != nil {
		t.Fatalf("PolicyAuthValue.Update() = %v", err)
	}
	if !bytes.Equal(authPol.Hash().Digest, got) {
		t.Errorf("PolicyPassword digest = %x, PolicyAuthValue digest = %x; want equal",
			got, authPol.Hash().Digest)
	}
}

func TestPolicyPhysicalPresenceUpdate(t *testing.T) {
	thetpm := testhelper.Open(t)
	defer thetpm.Close()

	want, got, errs := policyDigests(t, thetpm, func(h TPMHandle) PolicyCommand {
		return PolicyPhysicalPresence{PolicySession: h}
	})
	if err := errs[0]; err != nil {
		t.Fatalf("PolicyPhysicalPresence.Update() = %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("PolicyPhysicalPresence digest = %x,\nwant %x", got, want)
	}
}

// TestPolicyRestartUpdate checks that restarting a policy session discards the
// accumulated digest, both in the TPM and in the calculator.
func TestPolicyRestartUpdate(t *testing.T) {
	thetpm := testhelper.Open(t)
	defer thetpm.Close()

	want, got, errs := policyDigests(t, thetpm,
		func(h TPMHandle) PolicyCommand { return PolicyPhysicalPresence{PolicySession: h} },
		func(h TPMHandle) PolicyCommand { return PolicyRestart{PolicySession: h} },
	)
	for i, err := range errs {
		if err != nil {
			t.Fatalf("Update() for command %d = %v", i, err)
		}
	}
	if !bytes.Equal(want, make([]byte, len(want))) {
		t.Errorf("TPM digest after PolicyRestart = %x, want all zeros", want)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("PolicyRestart digest = %x,\nwant %x", got, want)
	}
}

// TestPolicyTicketUpdate checks that a ticket carries the same policy digest as
// the authorization it stands in for. PolicyTicket cannot be executed in a
// trial session, so this compares digests computed locally.
func TestPolicyTicketUpdate(t *testing.T) {
	name := TPM2BName{Buffer: []byte{1, 2, 3, 4, 5, 6, 7, 8}}
	policyRef := TPM2BNonce{Buffer: []byte{9, 10, 11, 12}}

	tests := []struct {
		name string
		tag  TPMST
		cc   TPMCC
		sign func(TPM2BName, TPM2BNonce) PolicyCommand
	}{
		{"AuthSigned", TPMSTAuthSigned, TPMCCPolicySigned, func(n TPM2BName, r TPM2BNonce) PolicyCommand {
			return PolicySigned{AuthObject: NamedHandle{Name: n}, PolicyRef: r}
		}},
		{"AuthSecret", TPMSTAuthSecret, TPMCCPolicySecret, func(n TPM2BName, r TPM2BNonce) PolicyCommand {
			return PolicySecret{AuthHandle: AuthHandle{Name: n}, PolicyRef: r}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ticketPol, err := NewPolicyCalculator(TPMAlgSHA256)
			if err != nil {
				t.Fatalf("creating policy calculator: %v", err)
			}
			ticket := PolicyTicket{
				PolicyRef: policyRef,
				AuthName:  name,
				Ticket:    TPMTTKAuth{Tag: tt.tag},
			}
			if err := ticket.Update(ticketPol); err != nil {
				t.Fatalf("PolicyTicket.Update() = %v", err)
			}

			authPol, err := NewPolicyCalculator(TPMAlgSHA256)
			if err != nil {
				t.Fatalf("creating policy calculator: %v", err)
			}
			if err := tt.sign(name, policyRef).Update(authPol); err != nil {
				t.Fatalf("computing reference digest: %v", err)
			}

			if !bytes.Equal(ticketPol.Hash().Digest, authPol.Hash().Digest) {
				t.Errorf("PolicyTicket digest = %x, want %x (from %s)",
					ticketPol.Hash().Digest, authPol.Hash().Digest, tt.name)
			}
		})
	}
}

func TestPolicyTicketUpdateInvalidTag(t *testing.T) {
	pol, err := NewPolicyCalculator(TPMAlgSHA256)
	if err != nil {
		t.Fatalf("creating policy calculator: %v", err)
	}
	if err := (PolicyTicket{Ticket: TPMTTKAuth{Tag: TPMSTVerified}}).Update(pol); err == nil {
		t.Fatalf("PolicyTicket.Update() with a verification ticket succeeded, want error")
	}
}

// TestPolicyCounterTimerRealSession checks that the TPM actually evaluates the
// time condition in a non-trial session, while a trial session skips it.
func TestPolicyCounterTimerRealSession(t *testing.T) {
	thetpm := testhelper.Open(t)
	defer thetpm.Close()

	sess, cleanup, err := PolicySession(thetpm, TPMAlgSHA256, 16)
	if err != nil {
		t.Fatalf("setting up policy session: %v", err)
	}
	defer cleanup()

	// Offset 0 is the low end of Time (a uint64). Comparing it against
	// 2^64-1 with ">=" can never succeed, while "<" always does, regardless
	// of how far the clock has advanced.
	allOnes := TPM2BOperand{Buffer: bytes.Repeat([]byte{0xFF}, 8)}
	unsatisfied := PolicyCounterTimer{
		PolicySession: sess.Handle(),
		OperandB:      allOnes,
		Offset:        0,
		Operation:     TPMEOUnsignedGE,
	}
	if _, err := unsatisfied.Execute(thetpm); !errors.Is(err, TPMRCPolicy) {
		t.Errorf("PolicyCounterTimer with an unsatisfied condition = %v, want %v", err, TPMRCPolicy)
	}

	// The same comparison with "<" holds, so the TPM must accept it.
	satisfied := PolicyCounterTimer{
		PolicySession: sess.Handle(),
		OperandB:      allOnes,
		Offset:        0,
		Operation:     TPMEOUnsignedLT,
	}
	if _, err := satisfied.Execute(thetpm); err != nil {
		t.Errorf("PolicyCounterTimer with a satisfied condition = %v", err)
	}
}

// TestPolicyLocalityRealSession checks the locality accumulation rules that the
// TPM applies in a non-trial session: an unset accumulated locality starts as
// all regular localities, and successive regular localities are intersected.
func TestPolicyLocalityRealSession(t *testing.T) {
	thetpm := testhelper.Open(t)
	defer thetpm.Close()

	sess, cleanup, err := PolicySession(thetpm, TPMAlgSHA256, 16)
	if err != nil {
		t.Fatalf("setting up policy session: %v", err)
	}
	defer cleanup()

	// With nothing accumulated, any non-empty regular locality is accepted.
	if _, err := (PolicyLocality{
		PolicySession: sess.Handle(),
		Locality:      TPMALocality{TPMLocOne: true},
	}).Execute(thetpm); err != nil {
		t.Fatalf("PolicyLocality(locality 1) = %v", err)
	}

	// The accumulated locality is now {1}; intersecting it with {2} leaves
	// the empty set and has to fail.
	if _, err := (PolicyLocality{
		PolicySession: sess.Handle(),
		Locality:      TPMALocality{TPMLocTwo: true},
	}).Execute(thetpm); !errors.Is(err, TPMRCRange) {
		t.Errorf("PolicyLocality(locality 2) after locality 1 = %v, want %v", err, TPMRCRange)
	}

	// Intersecting with a set that still contains locality 1 succeeds.
	if _, err := (PolicyLocality{
		PolicySession: sess.Handle(),
		Locality:      TPMALocality{TPMLocOne: true, TPMLocTwo: true},
	}).Execute(thetpm); err != nil {
		t.Errorf("PolicyLocality(localities 1 and 2) after locality 1 = %v", err)
	}
}

// TestPolicyRestartRealSession checks that PolicyRestart clears the policy
// digest of a non-trial session.
func TestPolicyRestartRealSession(t *testing.T) {
	thetpm := testhelper.Open(t)
	defer thetpm.Close()

	sess, cleanup, err := PolicySession(thetpm, TPMAlgSHA256, 16)
	if err != nil {
		t.Fatalf("setting up policy session: %v", err)
	}
	defer cleanup()

	if _, err := (PolicyPhysicalPresence{PolicySession: sess.Handle()}).Execute(thetpm); err != nil {
		t.Fatalf("PolicyPhysicalPresence() = %v", err)
	}
	before, err := PolicyGetDigest{PolicySession: sess.Handle()}.Execute(thetpm)
	if err != nil {
		t.Fatalf("PolicyGetDigest() = %v", err)
	}
	if bytes.Equal(before.PolicyDigest.Buffer, make([]byte, len(before.PolicyDigest.Buffer))) {
		t.Fatalf("policy digest before restart is all zeros")
	}

	if _, err := (PolicyRestart{PolicySession: sess.Handle()}).Execute(thetpm); err != nil {
		t.Fatalf("PolicyRestart() = %v", err)
	}
	after, err := PolicyGetDigest{PolicySession: sess.Handle()}.Execute(thetpm)
	if err != nil {
		t.Fatalf("PolicyGetDigest() = %v", err)
	}
	if !bytes.Equal(after.PolicyDigest.Buffer, make([]byte, len(after.PolicyDigest.Buffer))) {
		t.Errorf("policy digest after restart = %x, want all zeros", after.PolicyDigest.Buffer)
	}
}

// TestPolicyRestartRecovery checks the restore condition of TPM2_PolicyRestart:
// after a restart, the session behaves exactly like a freshly created one, so
// the same subsequent commands produce the same digest as on a new session.
func TestPolicyRestartRecovery(t *testing.T) {
	thetpm := testhelper.Open(t)
	defer thetpm.Close()

	// Build a reference digest on a session that never saw the discarded
	// commands.
	reference, _, errs := policyDigests(t, thetpm, func(h TPMHandle) PolicyCommand {
		return PolicyPhysicalPresence{PolicySession: h}
	})
	if err := errs[0]; err != nil {
		t.Fatalf("PolicyPhysicalPresence.Update() = %v", err)
	}

	// Now build a session that first accumulates unrelated state, restarts,
	// and only then applies the same command.
	sess, cleanup, err := PolicySession(thetpm, TPMAlgSHA256, 16)
	if err != nil {
		t.Fatalf("setting up policy session: %v", err)
	}
	defer cleanup()

	for _, cmd := range []PolicyCommand{
		PolicyPassword{PolicySession: sess.Handle()},
		PolicyLocality{PolicySession: sess.Handle(), Locality: TPMALocality{TPMLocZero: true}},
		PolicyRestart{PolicySession: sess.Handle()},
		PolicyPhysicalPresence{PolicySession: sess.Handle()},
	} {
		if err := executePolicyCommand(t, thetpm, cmd); err != nil {
			t.Fatalf("%T.Execute() = %v", cmd, err)
		}
	}

	got, err := PolicyGetDigest{PolicySession: sess.Handle()}.Execute(thetpm)
	if err != nil {
		t.Fatalf("PolicyGetDigest() = %v", err)
	}
	if !bytes.Equal(got.PolicyDigest.Buffer, reference) {
		t.Errorf("digest after restart and re-application = %x, want %x (fresh session)",
			got.PolicyDigest.Buffer, reference)
	}
}

// TestPolicySessionIsolation checks that concurrent policy sessions do not
// affect each other's digest.
func TestPolicySessionIsolation(t *testing.T) {
	thetpm := testhelper.Open(t)
	defer thetpm.Close()

	first, cleanupFirst, err := PolicySession(thetpm, TPMAlgSHA256, 16)
	if err != nil {
		t.Fatalf("setting up first policy session: %v", err)
	}
	defer cleanupFirst()

	second, cleanupSecond, err := PolicySession(thetpm, TPMAlgSHA256, 16)
	if err != nil {
		t.Fatalf("setting up second policy session: %v", err)
	}
	defer cleanupSecond()

	if _, err := (PolicyPhysicalPresence{PolicySession: first.Handle()}).Execute(thetpm); err != nil {
		t.Fatalf("PolicyPhysicalPresence(first) = %v", err)
	}
	// Restarting one session must not clear the other.
	if _, err := (PolicyRestart{PolicySession: second.Handle()}).Execute(thetpm); err != nil {
		t.Fatalf("PolicyRestart(second) = %v", err)
	}

	firstDigest, err := PolicyGetDigest{PolicySession: first.Handle()}.Execute(thetpm)
	if err != nil {
		t.Fatalf("PolicyGetDigest(first) = %v", err)
	}
	if bytes.Equal(firstDigest.PolicyDigest.Buffer, make([]byte, sha256.Size)) {
		t.Errorf("restarting the second session cleared the first")
	}

	secondDigest, err := PolicyGetDigest{PolicySession: second.Handle()}.Execute(thetpm)
	if err != nil {
		t.Fatalf("PolicyGetDigest(second) = %v", err)
	}
	if !bytes.Equal(secondDigest.PolicyDigest.Buffer, make([]byte, sha256.Size)) {
		t.Errorf("second session digest = %x, want zeros", secondDigest.PolicyDigest.Buffer)
	}
}

// TestPolicyTicketMatchesTPM checks the PolicyTicket digest against the digest
// that a trial TPM computes for the authorization it substitutes. A ticket
// cannot be applied to a trial session, so the reference has to come from the
// underlying command.
func TestPolicyTicketMatchesTPM(t *testing.T) {
	thetpm := testhelper.Open(t)
	defer thetpm.Close()

	sk, cleanup := signingKey(t, thetpm)
	defer cleanup()

	policyRef := TPM2BNonce{Buffer: []byte{5, 6, 7, 8}}

	// The TPM's view: execute PolicySigned on a trial session.
	sess, cleanupSess, err := PolicySession(thetpm, TPMAlgSHA256, 16, Trial())
	if err != nil {
		t.Fatalf("setting up trial session: %v", err)
	}
	defer cleanupSess()
	if _, err := (PolicySigned{
		AuthObject:    sk,
		PolicySession: sess.Handle(),
		PolicyRef:     policyRef,
		Auth: TPMTSignature{
			SigAlg: TPMAlgECDSA,
			Signature: NewTPMUSignature(
				TPMAlgECDSA,
				&TPMSSignatureECC{Hash: TPMAlgSHA256},
			),
		},
	}).Execute(thetpm); err != nil {
		t.Fatalf("PolicySigned.Execute() = %v", err)
	}
	want, err := PolicyGetDigest{PolicySession: sess.Handle()}.Execute(thetpm)
	if err != nil {
		t.Fatalf("PolicyGetDigest() = %v", err)
	}

	// The calculator's view: apply the ticket that would carry that
	// authorization.
	ticketPol, err := NewPolicyCalculator(TPMAlgSHA256)
	if err != nil {
		t.Fatalf("creating policy calculator: %v", err)
	}
	if err := (PolicyTicket{
		PolicyRef: policyRef,
		AuthName:  sk.Name,
		Ticket:    TPMTTKAuth{Tag: TPMSTAuthSigned},
	}).Update(ticketPol); err != nil {
		t.Fatalf("PolicyTicket.Update() = %v", err)
	}

	if !bytes.Equal(ticketPol.Hash().Digest, want.PolicyDigest.Buffer) {
		t.Errorf("PolicyTicket digest = %x, TPM PolicySigned digest = %x",
			ticketPol.Hash().Digest, want.PolicyDigest.Buffer)
	}
}

// TestPolicyACSendSelectUpdate checks the policy digest of the name-binding
// command for both values of includeObject against a trial TPM.
func TestPolicyACSendSelectUpdate(t *testing.T) {
	thetpm := testhelper.Open(t)
	defer thetpm.Close()

	objectName := TPM2BName{Buffer: []byte{0x00, 0x0B, 1, 2, 3}}
	authHandleName := TPM2BName{Buffer: []byte{0x40, 0x00, 0x00, 0x01}}
	acName := TPM2BName{Buffer: []byte{0x00, 0x0B, 9, 9}}

	for _, includeObject := range []bool{false, true} {
		name := "ExcludeObject"
		if includeObject {
			name = "IncludeObject"
		}
		t.Run(name, func(t *testing.T) {
			want, got, errs := policyDigests(t, thetpm, func(h TPMHandle) PolicyCommand {
				return PolicyACSendSelect{
					PolicySession:  h,
					ObjectName:     objectName,
					AuthHandleName: authHandleName,
					ACName:         acName,
					IncludeObject:  includeObject,
				}
			})
			if err := errs[0]; err != nil {
				t.Fatalf("PolicyACSendSelect.Update() = %v", err)
			}
			if !bytes.Equal(got, want) {
				t.Errorf("PolicyACSendSelect digest = %x,\nwant %x", got, want)
			}
		})
	}
}
