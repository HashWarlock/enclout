package verify

import (
	"context"
	"errors"
	"testing"
)

type fakeDCAP struct {
	result DCAPResult
	err    error
}

func (f fakeDCAP) Verify(_ context.Context, _ string) (DCAPResult, error) {
	if f.err != nil {
		return DCAPResult{}, f.err
	}
	return f.result, nil
}

func TestVerifyFailClosedOnDependencyError(t *testing.T) {
	v := NewStrictVerifier(fakeDCAP{err: errors.New("pccs timeout")}, NewStaticPolicy(nil, nil))
	_, err := v.Verify(context.Background(), Bundle{})
	if err == nil {
		t.Fatalf("expected error")
	}
	var verr VerificationError
	if !errors.As(err, &verr) || verr.Code != ReasonAttestationDependencyFailure {
		t.Fatalf("expected %s, got %v", ReasonAttestationDependencyFailure, err)
	}
}

func TestVerifyFailsOnReportDataMismatch(t *testing.T) {
	v := NewStrictVerifier(fakeDCAP{
		result: DCAPResult{
			QuoteValid:      true,
			QEIdentityValid: true,
			TCBValid:        true,
		},
	}, NewStaticPolicy([]string{"mrtd"}, []string{"rtmr3"}))

	_, err := v.Verify(context.Background(), Bundle{
		SSHPublicKey: "ssh-ed25519 AAAATEST connector@tee",
		QuoteHex:     "abcd",
		MRTD:         "mrtd",
		RTMR0:        "rtmr0",
		RTMR1:        "rtmr1",
		RTMR2:        "rtmr2",
		RTMR3:        "rtmr3",
	})
	if err == nil {
		t.Fatalf("expected mismatch error")
	}

	var verr VerificationError
	if !errors.As(err, &verr) {
		t.Fatalf("expected verification error, got %v", err)
	}
	if verr.Code != ReasonReportDataMismatch {
		t.Fatalf("expected %s, got %s", ReasonReportDataMismatch, verr.Code)
	}
}

func TestVerifySuccess(t *testing.T) {
	pub := "ssh-ed25519 AAAATEST connector@tee"
	expected := ComputeExpectedReportData(pub)
	v := NewStrictVerifier(fakeDCAP{
		result: DCAPResult{
			QuoteValid:      true,
			QEIdentityValid: true,
			TCBValid:        true,
			ReportData:      expected,
		},
	}, NewStaticPolicy([]string{"mrtd"}, []string{"rtmr3"}))

	decision, err := v.Verify(context.Background(), Bundle{
		SSHPublicKey: pub,
		QuoteHex:     "abcd",
		MRTD:         "mrtd",
		RTMR0:        "rtmr0",
		RTMR1:        "rtmr1",
		RTMR2:        "rtmr2",
		RTMR3:        "rtmr3",
	})
	if err != nil {
		t.Fatalf("unexpected verify error: %v", err)
	}
	if !decision.Trusted {
		t.Fatalf("expected trusted decision")
	}
}
