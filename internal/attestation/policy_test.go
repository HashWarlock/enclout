package attestation

import (
	"errors"
	"testing"
)

func TestStaticPolicy_AllowedMeasurements(t *testing.T) {
	p := NewStaticPolicy([]string{"mrtd-good"}, []string{"rtmr3-good"})
	err := p.CheckMeasurements(Bundle{
		MRTD:  "mrtd-good",
		RTMR0: "r0",
		RTMR1: "r1",
		RTMR2: "r2",
		RTMR3: "rtmr3-good",
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestStaticPolicy_DisallowedMRTD(t *testing.T) {
	p := NewStaticPolicy([]string{"mrtd-good"}, []string{"rtmr3-good"})
	err := p.CheckMeasurements(Bundle{
		MRTD:  "mrtd-bad",
		RTMR0: "r0",
		RTMR1: "r1",
		RTMR2: "r2",
		RTMR3: "rtmr3-good",
	})
	if err == nil {
		t.Fatalf("expected error for disallowed MRTD")
	}
	var verr VerificationError
	if !errors.As(err, &verr) || verr.Code != ReasonMeasurementMismatch {
		t.Fatalf("expected %s, got %v", ReasonMeasurementMismatch, err)
	}
}

func TestStaticPolicy_DisallowedRTMR3(t *testing.T) {
	p := NewStaticPolicy([]string{"mrtd-good"}, []string{"rtmr3-good"})
	err := p.CheckMeasurements(Bundle{
		MRTD:  "mrtd-good",
		RTMR0: "r0",
		RTMR1: "r1",
		RTMR2: "r2",
		RTMR3: "rtmr3-bad",
	})
	if err == nil {
		t.Fatalf("expected error for disallowed RTMR3")
	}
	var verr VerificationError
	if !errors.As(err, &verr) || verr.Code != ReasonMeasurementMismatch {
		t.Fatalf("expected %s, got %v", ReasonMeasurementMismatch, err)
	}
}

func TestStaticPolicy_EmptyAllowlistAllowsAll(t *testing.T) {
	p := NewStaticPolicy(nil, nil)
	err := p.CheckMeasurements(Bundle{
		MRTD:  "anything",
		RTMR0: "r0",
		RTMR1: "r1",
		RTMR2: "r2",
		RTMR3: "anything",
	})
	if err != nil {
		t.Fatalf("empty allowlists should be permissive, got %v", err)
	}
}

func TestStaticPolicy_BothChecked(t *testing.T) {
	p := NewStaticPolicy([]string{"mrtd-good"}, []string{"rtmr3-good"})

	// Both bad: MRTD fails first.
	err := p.CheckMeasurements(Bundle{
		MRTD:  "mrtd-bad",
		RTMR0: "r0",
		RTMR1: "r1",
		RTMR2: "r2",
		RTMR3: "rtmr3-bad",
	})
	if err == nil {
		t.Fatalf("expected error when both MRTD and RTMR3 are disallowed")
	}
	var verr VerificationError
	if !errors.As(err, &verr) || verr.Code != ReasonMeasurementMismatch {
		t.Fatalf("expected %s, got %v", ReasonMeasurementMismatch, err)
	}

	// MRTD good but RTMR3 bad.
	err = p.CheckMeasurements(Bundle{
		MRTD:  "mrtd-good",
		RTMR0: "r0",
		RTMR1: "r1",
		RTMR2: "r2",
		RTMR3: "rtmr3-bad",
	})
	if err == nil {
		t.Fatalf("expected error when RTMR3 is disallowed")
	}
	if !errors.As(err, &verr) || verr.Code != ReasonMeasurementMismatch {
		t.Fatalf("expected %s, got %v", ReasonMeasurementMismatch, err)
	}
}
