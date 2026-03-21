package attestation

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
)

// StrictVerifier performs fail-closed attestation verification: DCAP quote
// validity, measurement policy, and report-data binding must all pass.
type StrictVerifier struct {
	dcap   DCAPVerifier
	policy MeasurementPolicy
}

// NewStrictVerifier creates a verifier that checks DCAP results, measurement
// policy, and report-data binding.
func NewStrictVerifier(dcap DCAPVerifier, policy MeasurementPolicy) StrictVerifier {
	return StrictVerifier{
		dcap:   dcap,
		policy: policy,
	}
}

// Verify runs all attestation checks and returns a trusted decision only when
// every check passes. Any single failure is terminal (fail-closed).
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

// ComputeExpectedReportData derives the 64-byte report data from an SSH
// public key string. The first 32 bytes are the SHA-256 hash of the key;
// the remaining 32 bytes are zeros.
func ComputeExpectedReportData(sshPublicKey string) [64]byte {
	var out [64]byte
	sum := sha256.Sum256([]byte(sshPublicKey))
	copy(out[:32], sum[:])
	return out
}
