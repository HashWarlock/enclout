package verify

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"testing"
)

func TestVerifySignedBundleValid(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate test keypair: %v", err)
	}

	payloadRaw := []byte(`{"connector_id":"conn_1","quote_hex":"abcd"}`)
	signatureB64 := base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, payloadRaw))
	publicKeyB64 := base64.StdEncoding.EncodeToString(publicKey)

	if err := VerifySignedBundle(payloadRaw, signatureB64, "ed25519", publicKeyB64); err != nil {
		t.Fatalf("expected valid signature, got error: %v", err)
	}
}

func TestVerifySignedBundleInvalidSignature(t *testing.T) {
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate test keypair: %v", err)
	}

	payloadRaw := []byte(`{"connector_id":"conn_1","quote_hex":"abcd"}`)
	signatureB64 := base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
	publicKeyB64 := base64.StdEncoding.EncodeToString(publicKey)

	err = VerifySignedBundle(payloadRaw, signatureB64, "ed25519", publicKeyB64)
	if err == nil {
		t.Fatalf("expected invalid signature error")
	}

	var verr VerificationError
	if !errors.As(err, &verr) {
		t.Fatalf("expected VerificationError, got %v", err)
	}
	if verr.Code != ReasonBundleInvalid {
		t.Fatalf("expected reason %q, got %q", ReasonBundleInvalid, verr.Code)
	}
}
