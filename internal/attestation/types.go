package attestation

import (
	"context"
	"fmt"
)

// Reason codes for verification failures.
const (
	ReasonAttestationDependencyFailure = "AttestationDependencyFailure"
	ReasonBundleInvalid                = "BundleInvalid"
	ReasonQuoteInvalid                 = "QuoteInvalid"
	ReasonMeasurementMismatch          = "MeasurementMismatch"
	ReasonReportDataMismatch           = "ReportDataMismatch"
)

// Bundle holds the attestation evidence provided by a TEE connector.
type Bundle struct {
	ConnectorID              string
	SSHPublicKey             string
	QuoteHex                 string
	MRTD                     string
	RTMR0                    string
	RTMR1                    string
	RTMR2                    string
	RTMR3                    string
	ReportDataExpectedSHA256 string
	PolicyVersion            string
}

// Decision is the outcome of attestation verification.
type Decision struct {
	Trusted    bool
	ReasonCode string
}

// VerificationError carries a machine-readable reason code alongside the
// underlying error.
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

func (e VerificationError) Unwrap() error { return e.Err }

// DCAPResult holds the parsed output of a DCAP quote verification.
type DCAPResult struct {
	QuoteValid      bool
	QEIdentityValid bool
	TCBValid        bool
	ReportData      [64]byte
}

// DCAPVerifier verifies a DCAP quote and returns the parsed result.
type DCAPVerifier interface {
	Verify(ctx context.Context, quoteHex string) (DCAPResult, error)
}

// MeasurementPolicy decides whether a bundle's measurements are acceptable.
type MeasurementPolicy interface {
	CheckMeasurements(bundle Bundle) error
}
