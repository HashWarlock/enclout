package signing

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

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

type SignedBundle struct {
	Payload   BundlePayload `json:"payload"`
	Signature string        `json:"signature"`
	Alg       string        `json:"alg"`
}

type Ed25519Signer struct {
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
}

func NewEd25519SignerFromSeedB64(seedB64 string) (*Ed25519Signer, error) {
	seed, err := base64.StdEncoding.DecodeString(seedB64)
	if err != nil {
		return nil, fmt.Errorf("decode signing seed: %w", err)
	}
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("signing seed must be %d bytes", ed25519.SeedSize)
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	return &Ed25519Signer{privateKey: privateKey, publicKey: publicKey}, nil
}

func (s *Ed25519Signer) SignBundle(payload BundlePayload) (SignedBundle, error) {
	raw, err := marshalCanonical(payload)
	if err != nil {
		return SignedBundle{}, err
	}
	sig := ed25519.Sign(s.privateKey, raw)
	return SignedBundle{
		Payload:   payload,
		Signature: base64.StdEncoding.EncodeToString(sig),
		Alg:       "ed25519",
	}, nil
}

func (s *Ed25519Signer) PublicKeyB64() string {
	return base64.StdEncoding.EncodeToString(s.publicKey)
}

func VerifyBundle(payload BundlePayload, signatureB64 string, publicKeyB64 string) (bool, error) {
	raw, err := marshalCanonical(payload)
	if err != nil {
		return false, err
	}
	pub, err := base64.StdEncoding.DecodeString(publicKeyB64)
	if err != nil {
		return false, fmt.Errorf("decode pubkey: %w", err)
	}
	if len(pub) != ed25519.PublicKeySize {
		return false, errors.New("invalid ed25519 public key length")
	}
	sig, err := base64.StdEncoding.DecodeString(signatureB64)
	if err != nil {
		return false, fmt.Errorf("decode signature: %w", err)
	}
	return ed25519.Verify(ed25519.PublicKey(pub), raw, sig), nil
}

func ReportDataHashFromSSHPublicKey(sshPublicKey string) string {
	sum := sha256.Sum256([]byte(sshPublicKey))
	return fmt.Sprintf("%x", sum[:])
}

func marshalCanonical(payload BundlePayload) ([]byte, error) {
	return json.Marshal(payload)
}
