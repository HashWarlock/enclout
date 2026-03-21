package identity

import (
	"bytes"
	"crypto/ed25519"
	"os"
	"strings"
	"testing"
)

func TestSSHPublicKeyString_Format(t *testing.T) {
	seed := bytes.Repeat([]byte{0x42}, ed25519.SeedSize)
	pub, _, err := DeriveEd25519(seed)
	if err != nil {
		t.Fatalf("DeriveEd25519 failed: %v", err)
	}

	sshKey, err := SSHPublicKeyString(pub)
	if err != nil {
		t.Fatalf("SSHPublicKeyString failed: %v", err)
	}

	if !strings.HasPrefix(sshKey, "ssh-ed25519 ") {
		t.Errorf("expected prefix 'ssh-ed25519 ', got %q", sshKey)
	}
}

func TestSSHPublicKeyString_Deterministic(t *testing.T) {
	seed := bytes.Repeat([]byte{0x42}, ed25519.SeedSize)
	pub, _, err := DeriveEd25519(seed)
	if err != nil {
		t.Fatalf("DeriveEd25519 failed: %v", err)
	}

	key1, err := SSHPublicKeyString(pub)
	if err != nil {
		t.Fatalf("first call failed: %v", err)
	}

	key2, err := SSHPublicKeyString(pub)
	if err != nil {
		t.Fatalf("second call failed: %v", err)
	}

	if key1 != key2 {
		t.Errorf("same key produced different strings:\n  %s\n  %s", key1, key2)
	}
}

func TestSSHPublicKeyString_GoldenMatch(t *testing.T) {
	seed := bytes.Repeat([]byte{0x42}, ed25519.SeedSize)
	pub, _, err := DeriveEd25519(seed)
	if err != nil {
		t.Fatalf("DeriveEd25519 failed: %v", err)
	}

	sshKey, err := SSHPublicKeyString(pub)
	if err != nil {
		t.Fatalf("SSHPublicKeyString failed: %v", err)
	}

	goldenBytes, err := os.ReadFile("../../testdata/golden_ssh_key.txt")
	if err != nil {
		t.Fatalf("failed to read golden file: %v", err)
	}
	golden := strings.TrimSpace(string(goldenBytes))

	// Compare only the key type + base64 portion (first two space-separated fields),
	// ignoring any trailing comment which may differ between implementations.
	goFields := strings.Fields(sshKey)
	goldenFields := strings.Fields(golden)

	if len(goFields) < 2 || len(goldenFields) < 2 {
		t.Fatalf("unexpected format: go=%q golden=%q", sshKey, golden)
	}

	goKeyPart := goFields[0] + " " + goFields[1]
	goldenKeyPart := goldenFields[0] + " " + goldenFields[1]

	if goKeyPart != goldenKeyPart {
		t.Errorf("golden mismatch:\n  go:     %s\n  golden: %s", goKeyPart, goldenKeyPart)
	}
}

func TestSSHFingerprint(t *testing.T) {
	seed := bytes.Repeat([]byte{0x42}, ed25519.SeedSize)
	pub, _, err := DeriveEd25519(seed)
	if err != nil {
		t.Fatalf("DeriveEd25519 failed: %v", err)
	}

	sshKey, err := SSHPublicKeyString(pub)
	if err != nil {
		t.Fatalf("SSHPublicKeyString failed: %v", err)
	}

	fingerprint := SSHFingerprint(sshKey)

	// SHA256 hex digest is always 64 hex characters.
	if len(fingerprint) != 64 {
		t.Errorf("expected 64 hex chars, got %d: %s", len(fingerprint), fingerprint)
	}

	// Must be valid hex.
	for _, c := range fingerprint {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Errorf("non-hex character %q in fingerprint", c)
			break
		}
	}

	// Deterministic: same input produces same fingerprint.
	fp2 := SSHFingerprint(sshKey)
	if fingerprint != fp2 {
		t.Errorf("fingerprint not deterministic: %s vs %s", fingerprint, fp2)
	}
}
