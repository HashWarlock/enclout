package identity

import (
	"bytes"
	"crypto/ed25519"
	"testing"
)

func TestDeriveEd25519_Deterministic(t *testing.T) {
	seed := bytes.Repeat([]byte{0x42}, ed25519.SeedSize)

	pub1, priv1, err := DeriveEd25519(seed)
	if err != nil {
		t.Fatalf("first derivation failed: %v", err)
	}

	pub2, priv2, err := DeriveEd25519(seed)
	if err != nil {
		t.Fatalf("second derivation failed: %v", err)
	}

	if !bytes.Equal(pub1, pub2) {
		t.Error("same seed produced different public keys")
	}
	if !bytes.Equal(priv1, priv2) {
		t.Error("same seed produced different private keys")
	}
}

func TestDeriveEd25519_DifferentSeeds(t *testing.T) {
	seed1 := bytes.Repeat([]byte{0x42}, ed25519.SeedSize)
	seed2 := bytes.Repeat([]byte{0x43}, ed25519.SeedSize)

	pub1, _, err := DeriveEd25519(seed1)
	if err != nil {
		t.Fatalf("first derivation failed: %v", err)
	}

	pub2, _, err := DeriveEd25519(seed2)
	if err != nil {
		t.Fatalf("second derivation failed: %v", err)
	}

	if bytes.Equal(pub1, pub2) {
		t.Error("different seeds produced same public key")
	}
}

func TestDeriveEd25519_InvalidSeedLength(t *testing.T) {
	tests := []struct {
		name string
		seed []byte
	}{
		{"too short", bytes.Repeat([]byte{0x42}, 16)},
		{"too long", bytes.Repeat([]byte{0x42}, 64)},
		{"empty", []byte{}},
		{"one byte off", bytes.Repeat([]byte{0x42}, 31)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := DeriveEd25519(tt.seed)
			if err == nil {
				t.Errorf("expected error for seed length %d, got nil", len(tt.seed))
			}
		})
	}
}

func TestDeriveEd25519_SignVerify(t *testing.T) {
	seed := bytes.Repeat([]byte{0x42}, ed25519.SeedSize)

	pub, priv, err := DeriveEd25519(seed)
	if err != nil {
		t.Fatalf("derivation failed: %v", err)
	}

	message := []byte("hello, TEE identity")
	sig := ed25519.Sign(priv, message)

	if !ed25519.Verify(pub, message, sig) {
		t.Error("signature verification failed")
	}

	// Tampered message should not verify.
	tampered := []byte("hello, TEE identity!")
	if ed25519.Verify(pub, tampered, sig) {
		t.Error("verification should fail for tampered message")
	}
}
