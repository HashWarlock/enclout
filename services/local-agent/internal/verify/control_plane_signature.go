package verify

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"strings"
)

func VerifySignedBundle(payloadRaw []byte, signatureB64 string, alg string, publicKeyB64 string) error {
	if strings.TrimSpace(alg) != "ed25519" {
		return VerificationError{Code: ReasonBundleInvalid, Err: fmt.Errorf("unsupported bundle signature algorithm")}
	}
	if len(payloadRaw) == 0 {
		return VerificationError{Code: ReasonBundleInvalid, Err: fmt.Errorf("missing bundle payload")}
	}

	publicKey, err := decodePublicKey(publicKeyB64)
	if err != nil {
		return VerificationError{Code: ReasonBundleInvalid, Err: err}
	}
	signature, err := decodeSignature(signatureB64)
	if err != nil {
		return VerificationError{Code: ReasonBundleInvalid, Err: err}
	}

	if !ed25519.Verify(publicKey, payloadRaw, signature) {
		return VerificationError{Code: ReasonBundleInvalid, Err: fmt.Errorf("invalid bundle signature")}
	}
	return nil
}

func decodePublicKey(publicKeyB64 string) (ed25519.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(publicKeyB64))
	if err != nil {
		return nil, fmt.Errorf("decode control-plane public key: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("control-plane public key must be %d bytes", ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(raw), nil
}

func decodeSignature(signatureB64 string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(signatureB64))
	if err != nil {
		return nil, fmt.Errorf("decode bundle signature: %w", err)
	}
	if len(raw) != ed25519.SignatureSize {
		return nil, fmt.Errorf("bundle signature must be %d bytes", ed25519.SignatureSize)
	}
	return raw, nil
}
