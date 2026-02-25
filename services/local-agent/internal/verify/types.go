package verify

import "context"

const (
	ReasonAttestationDependencyFailure = "AttestationDependencyFailure"
	ReasonBundleInvalid                = "BundleInvalid"
	ReasonQuoteInvalid                 = "QuoteInvalid"
	ReasonMeasurementMismatch          = "MeasurementMismatch"
	ReasonReportDataMismatch           = "ReportDataMismatch"
)

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

type Decision struct {
	Trusted    bool
	ReasonCode string
}

type DCAPResult struct {
	QuoteValid      bool
	QEIdentityValid bool
	TCBValid        bool
	ReportData      [64]byte
}

type DCAPVerifier interface {
	Verify(ctx context.Context, quoteHex string) (DCAPResult, error)
}

type MeasurementPolicy interface {
	CheckMeasurements(bundle Bundle) error
}
