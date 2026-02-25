package verify

import (
	"bytes"
	"context"
	"fmt"
)

type VerificationError struct {
	Code string
	Err  error
}

func (e VerificationError) Error() string {
	if e.Err == nil {
		return e.Code
	}
	return fmt.Sprintf("%s: %v", e.Code, e.Err)
}

func (e VerificationError) Unwrap() error {
	return e.Err
}

type StrictVerifier struct {
	dcap   DCAPVerifier
	policy MeasurementPolicy
}

func NewStrictVerifier(dcap DCAPVerifier, policy MeasurementPolicy) StrictVerifier {
	return StrictVerifier{
		dcap:   dcap,
		policy: policy,
	}
}

func (v StrictVerifier) Verify(ctx context.Context, bundle Bundle) (Decision, error) {
	result, err := v.dcap.Verify(ctx, bundle.QuoteHex)
	if err != nil {
		return Decision{}, VerificationError{Code: ReasonAttestationDependencyFailure, Err: err}
	}
	if !result.QuoteValid || !result.QEIdentityValid || !result.TCBValid {
		return Decision{}, VerificationError{Code: ReasonQuoteInvalid, Err: fmt.Errorf("strict quote checks failed")}
	}

	if err := v.policy.CheckMeasurements(bundle); err != nil {
		return Decision{}, err
	}

	expected := ComputeExpectedReportData(bundle.SSHPublicKey)
	if !bytes.Equal(result.ReportData[:], expected[:]) {
		return Decision{}, VerificationError{Code: ReasonReportDataMismatch, Err: fmt.Errorf("report data mismatch")}
	}

	return Decision{
		Trusted: true,
	}, nil
}
