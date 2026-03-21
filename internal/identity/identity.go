package identity

import "context"

// ConnectorIdentity holds the derived cryptographic identity for a connector.
type ConnectorIdentity struct {
	ConnectorID       string
	SSHPublicKey      string
	PublicKeyHex      string
	FingerprintSHA256 string
}

// Attestation holds TEE attestation data bound to the connector identity.
type Attestation struct {
	QuoteHex                 string
	MRTD                     string
	RTMR0                    string
	RTMR1                    string
	RTMR2                    string
	RTMR3                    string
	EventLog                 string
	ReportDataExpectedSHA256 string
	PolicyVersion            string
}

// DstackInfo holds dstack application metadata.
type DstackInfo struct {
	AppID      string
	InstanceID string
	AppName    string
	TCBInfo    string
}

// Deriver is the extension point for identity derivation.
// DstackDeriver (real TEE) and EnvDeriver (dev/testing) both implement it.
type Deriver interface {
	DeriveIdentity(ctx context.Context, connectorID string) (ConnectorIdentity, Attestation, error)
}
