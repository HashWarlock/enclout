package signing

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"testing"
)

func TestVerifyBundle_ValidSignature(t *testing.T) {
	signer, err := NewEd25519SignerFromSeedB64(seedB64(t))
	if err != nil {
		t.Fatal(err)
	}

	payload := samplePayload()
	bundle, err := signer.SignBundle(payload)
	if err != nil {
		t.Fatal(err)
	}

	ok, err := VerifyBundle(payload, bundle.Signature, signer.PublicKeyB64())
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !ok {
		t.Fatal("expected valid signature")
	}
}

func TestVerifyBundle_TamperedSignature(t *testing.T) {
	signer, err := NewEd25519SignerFromSeedB64(seedB64(t))
	if err != nil {
		t.Fatal(err)
	}

	payload := samplePayload()
	bundle, err := signer.SignBundle(payload)
	if err != nil {
		t.Fatal(err)
	}

	// Decode, flip a byte, re-encode
	sigBytes, _ := base64.StdEncoding.DecodeString(bundle.Signature)
	sigBytes[0] ^= 0xff
	tampered := base64.StdEncoding.EncodeToString(sigBytes)

	ok, err := VerifyBundle(payload, tampered, signer.PublicKeyB64())
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if ok {
		t.Fatal("expected invalid signature for tampered data")
	}
}

func TestVerifyBundle_WrongKey(t *testing.T) {
	signer, err := NewEd25519SignerFromSeedB64(seedB64(t))
	if err != nil {
		t.Fatal(err)
	}

	otherSigner, err := NewEd25519SignerFromSeedB64(seedB64(t))
	if err != nil {
		t.Fatal(err)
	}

	payload := samplePayload()
	bundle, err := signer.SignBundle(payload)
	if err != nil {
		t.Fatal(err)
	}

	ok, err := VerifyBundle(payload, bundle.Signature, otherSigner.PublicKeyB64())
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if ok {
		t.Fatal("expected invalid signature with wrong key")
	}
}

func TestVerifySignedBundleWithKeyset(t *testing.T) {
	signer, err := NewEd25519SignerWithKIDFromSeedB64(seedB64(t), "k1")
	if err != nil {
		t.Fatal(err)
	}

	payload := samplePayload()
	bundle, err := signer.SignBundle(payload)
	if err != nil {
		t.Fatal(err)
	}

	// Marshal the payload to get the raw bytes that were signed
	raw, err := marshalCanonical(payload)
	if err != nil {
		t.Fatal(err)
	}

	keyset := map[string]string{
		"k1": signer.PublicKeyB64(),
	}

	err = VerifySignedBundleWithKeyset(raw, bundle.Signature, bundle.Alg, bundle.KID, keyset)
	if err != nil {
		t.Fatalf("verify with keyset: %v", err)
	}
}

func TestReportDataHashFromSSHPublicKey(t *testing.T) {
	key := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKey"
	got := ReportDataHashFromSSHPublicKey(key)

	sum := sha256.Sum256([]byte(key))
	want := fmt.Sprintf("%x", sum[:])

	if got != want {
		t.Errorf("hash = %q, want %q", got, want)
	}

	// Verify it is a 64-character hex string
	if len(got) != 64 {
		t.Errorf("hash length = %d, want 64", len(got))
	}
}
