package signing

import "time"

const DefaultSigningKID = "v1"

// BundlePayload contains the attestation data to be signed.
type BundlePayload struct {
	RequestID                string    `json:"request_id"`
	ConnectorID              string    `json:"connector_id"`
	SSHPublicKey             string    `json:"ssh_public_key"`
	QuoteHex                 string    `json:"quote_hex"`
	EventLog                 string    `json:"event_log"`
	MRTD                     string    `json:"mrtd"`
	RTMR0                    string    `json:"rtmr0"`
	RTMR1                    string    `json:"rtmr1"`
	RTMR2                    string    `json:"rtmr2"`
	RTMR3                    string    `json:"rtmr3"`
	ReportDataExpectedSHA256 string    `json:"report_data_expected_sha256"`
	PolicyVersion            string    `json:"policy_version"`
	IssuedAt                 time.Time `json:"issued_at"`
	ExpiresAt                time.Time `json:"expires_at"`
	Nonce                    string    `json:"nonce"`
}

// SignedBundle wraps a payload with its cryptographic signature.
type SignedBundle struct {
	Payload   BundlePayload `json:"payload"`
	Signature string        `json:"signature"`
	Alg       string        `json:"alg"`
	KID       string        `json:"kid"`
}

// PublicKeyInfo describes a single public key in a keyset.
type PublicKeyInfo struct {
	KID          string `json:"kid"`
	Alg          string `json:"alg"`
	PublicKeyB64 string `json:"public_key_b64"`
}

// SigningKeyset lists all public keys and identifies the active signing key.
type SigningKeyset struct {
	ActiveKID string          `json:"active_kid"`
	Keys      []PublicKeyInfo `json:"keys"`
}

// BundleSigner abstracts single-key and multi-key signing.
type BundleSigner interface {
	SignBundle(payload BundlePayload) (SignedBundle, error)
	Keyset() SigningKeyset
}
