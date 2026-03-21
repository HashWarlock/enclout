package attestation

import (
	"context"
	"errors"
	"testing"
)

// fakeDCAP is a configurable test double for DCAPVerifier.
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

func TestStrictVerifier_AllChecksPass(t *testing.T) {
	pub := "ssh-ed25519 AAAATEST connector@tee"
	expected := ComputeExpectedReportData(pub)

	v := NewStrictVerifier(
		fakeDCAP{result: DCAPResult{
			QuoteValid:      true,
			QEIdentityValid: true,
			TCBValid:        true,
			ReportData:      expected,
		}},
		NewStaticPolicy([]string{"mrtd-ok"}, []string{"rtmr3-ok"}),
	)

	decision, err := v.Verify(context.Background(), Bundle{
		SSHPublicKey: pub,
		QuoteHex:     "abcd",
		MRTD:         "mrtd-ok",
		RTMR0:        "r0",
		RTMR1:        "r1",
		RTMR2:        "r2",
		RTMR3:        "rtmr3-ok",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !decision.Trusted {
		t.Fatalf("expected trusted decision")
	}
}

func TestStrictVerifier_QuoteInvalid(t *testing.T) {
	v := NewStrictVerifier(
		fakeDCAP{result: DCAPResult{
			QuoteValid:      false,
			QEIdentityValid: true,
			TCBValid:        true,
		}},
		NewStaticPolicy(nil, nil),
	)

	_, err := v.Verify(context.Background(), Bundle{
		SSHPublicKey: "key",
		QuoteHex:     "abcd",
		MRTD:         "m",
		RTMR0:        "r0",
		RTMR1:        "r1",
		RTMR2:        "r2",
		RTMR3:        "r3",
	})
	if err == nil {
		t.Fatalf("expected error for invalid quote")
	}
	var verr VerificationError
	if !errors.As(err, &verr) || verr.Code != ReasonQuoteInvalid {
		t.Fatalf("expected %s, got %v", ReasonQuoteInvalid, err)
	}
}

func TestStrictVerifier_MeasurementMismatch(t *testing.T) {
	pub := "ssh-ed25519 AAAATEST connector@tee"
	expected := ComputeExpectedReportData(pub)

	v := NewStrictVerifier(
		fakeDCAP{result: DCAPResult{
			QuoteValid:      true,
			QEIdentityValid: true,
			TCBValid:        true,
			ReportData:      expected,
		}},
		NewStaticPolicy([]string{"mrtd-allowed"}, nil),
	)

	_, err := v.Verify(context.Background(), Bundle{
		SSHPublicKey: pub,
		QuoteHex:     "abcd",
		MRTD:         "mrtd-wrong",
		RTMR0:        "r0",
		RTMR1:        "r1",
		RTMR2:        "r2",
		RTMR3:        "r3",
	})
	if err == nil {
		t.Fatalf("expected measurement mismatch error")
	}
	var verr VerificationError
	if !errors.As(err, &verr) || verr.Code != ReasonMeasurementMismatch {
		t.Fatalf("expected %s, got %v", ReasonMeasurementMismatch, err)
	}
}

func TestStrictVerifier_ReportDataMismatch(t *testing.T) {
	v := NewStrictVerifier(
		fakeDCAP{result: DCAPResult{
			QuoteValid:      true,
			QEIdentityValid: true,
			TCBValid:        true,
			// ReportData is zero-valued, won't match any real SSH key hash.
		}},
		NewStaticPolicy([]string{"mrtd"}, []string{"rtmr3"}),
	)

	_, err := v.Verify(context.Background(), Bundle{
		SSHPublicKey: "ssh-ed25519 AAAATEST connector@tee",
		QuoteHex:     "abcd",
		MRTD:         "mrtd",
		RTMR0:        "r0",
		RTMR1:        "r1",
		RTMR2:        "r2",
		RTMR3:        "rtmr3",
	})
	if err == nil {
		t.Fatalf("expected report data mismatch error")
	}
	var verr VerificationError
	if !errors.As(err, &verr) || verr.Code != ReasonReportDataMismatch {
		t.Fatalf("expected %s, got %v", ReasonReportDataMismatch, err)
	}
}

func TestStrictVerifier_DCAPUnavailable(t *testing.T) {
	v := NewStrictVerifier(
		fakeDCAP{err: errors.New("pccs timeout")},
		NewStaticPolicy(nil, nil),
	)

	_, err := v.Verify(context.Background(), Bundle{})
	if err == nil {
		t.Fatalf("expected error for DCAP unavailability")
	}
	var verr VerificationError
	if !errors.As(err, &verr) || verr.Code != ReasonAttestationDependencyFailure {
		t.Fatalf("expected %s, got %v", ReasonAttestationDependencyFailure, err)
	}
}
