package signing

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// VerifyBundle checks that signatureB64 is a valid Ed25519 signature over the
// canonical JSON of payload, using the given base64-encoded public key.
func VerifyBundle(payload BundlePayload, signatureB64, publicKeyB64 string) (bool, error) {
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

// VerifySignedBundleWithKeyset verifies a signed bundle against a trusted
// keyset. payloadRaw must be the exact bytes that were signed (canonical JSON).
func VerifySignedBundleWithKeyset(payloadRaw []byte, signatureB64, alg, kid string, keyset map[string]string) error {
	alg = strings.TrimSpace(alg)
	if alg != "ed25519" {
		return fmt.Errorf("unsupported bundle signature algorithm: %s", alg)
	}
	if len(payloadRaw) == 0 {
		return fmt.Errorf("missing bundle payload")
	}
	kid = strings.TrimSpace(kid)
	if kid == "" {
		return fmt.Errorf("missing bundle kid")
	}

	publicKeyB64, ok := keyset[kid]
	if !ok {
		return fmt.Errorf("unknown bundle kid %q", kid)
	}

	pub, err := base64.StdEncoding.DecodeString(strings.TrimSpace(publicKeyB64))
	if err != nil {
		return fmt.Errorf("decode public key: %w", err)
	}
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("public key must be %d bytes", ed25519.PublicKeySize)
	}

	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(signatureB64))
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}

	if !ed25519.Verify(ed25519.PublicKey(pub), payloadRaw, sig) {
		return fmt.Errorf("invalid bundle signature")
	}
	return nil
}

// ReportDataHashFromSSHPublicKey returns the hex-encoded SHA-256 hash of the
// SSH public key string.
func ReportDataHashFromSSHPublicKey(sshPublicKey string) string {
	sum := sha256.Sum256([]byte(sshPublicKey))
	return fmt.Sprintf("%x", sum[:])
}
