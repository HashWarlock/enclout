package signing

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"
	"time"
)

func seedB64(t *testing.T) string {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(seed)
}

func samplePayload() BundlePayload {
	now := time.Now().UTC().Truncate(time.Second)
	return BundlePayload{
		RequestID:                "req-1",
		ConnectorID:              "conn-1",
		SSHPublicKey:             "ssh-ed25519 AAAA...",
		QuoteHex:                 "abcd",
		EventLog:                 "log",
		MRTD:                     "mrtd-hex",
		RTMR0:                    "rtmr0-hex",
		RTMR1:                    "rtmr1-hex",
		RTMR2:                    "rtmr2-hex",
		RTMR3:                    "rtmr3-hex",
		ReportDataExpectedSHA256: "sha256hex",
		PolicyVersion:            "v1",
		IssuedAt:                 now,
		ExpiresAt:                now.Add(time.Hour),
		Nonce:                    "nonce-abc",
	}
}

func TestEd25519Signer_SignBundle_RoundTrip(t *testing.T) {
	seed := seedB64(t)
	signer, err := NewEd25519SignerFromSeedB64(seed)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}

	payload := samplePayload()
	bundle, err := signer.SignBundle(payload)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	if bundle.Alg != "ed25519" {
		t.Errorf("alg = %q, want ed25519", bundle.Alg)
	}
	if bundle.KID != DefaultSigningKID {
		t.Errorf("kid = %q, want %q", bundle.KID, DefaultSigningKID)
	}
	if bundle.Signature == "" {
		t.Fatal("signature is empty")
	}

	ok, err := VerifyBundle(payload, bundle.Signature, signer.PublicKeyB64())
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !ok {
		t.Fatal("signature should be valid")
	}
}

func TestSignerSet_SignBundle_UsesActiveKID(t *testing.T) {
	seeds := map[string]string{
		"k1": seedB64(t),
		"k2": seedB64(t),
	}
	ss, err := NewSignerSetFromSeedMap(seeds, "k2")
	if err != nil {
		t.Fatalf("new signer set: %v", err)
	}

	bundle, err := ss.SignBundle(samplePayload())
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if bundle.KID != "k2" {
		t.Errorf("kid = %q, want k2", bundle.KID)
	}
}

func TestSignerSet_Keyset_ListsAllKeys(t *testing.T) {
	seeds := map[string]string{
		"alpha": seedB64(t),
		"beta":  seedB64(t),
	}
	ss, err := NewSignerSetFromSeedMap(seeds, "alpha")
	if err != nil {
		t.Fatalf("new signer set: %v", err)
	}

	ks := ss.Keyset()
	if ks.ActiveKID != "alpha" {
		t.Errorf("active kid = %q, want alpha", ks.ActiveKID)
	}
	if len(ks.Keys) != 2 {
		t.Fatalf("keys count = %d, want 2", len(ks.Keys))
	}
	// Keys should be sorted by KID
	if ks.Keys[0].KID != "alpha" || ks.Keys[1].KID != "beta" {
		t.Errorf("keys not sorted: %v, %v", ks.Keys[0].KID, ks.Keys[1].KID)
	}
}

func TestNewSignerSetFromSeedMap_MissingActiveKID(t *testing.T) {
	seeds := map[string]string{
		"k1": seedB64(t),
	}
	_, err := NewSignerSetFromSeedMap(seeds, "missing")
	if err == nil {
		t.Fatal("expected error for missing active KID")
	}
}

func TestNewEd25519SignerFromSeedB64_InvalidSeed(t *testing.T) {
	// bad base64
	_, err := NewEd25519SignerFromSeedB64("not-valid-base64!!!")
	if err == nil {
		t.Fatal("expected error for bad base64")
	}

	// wrong length (16 bytes instead of 32)
	short := base64.StdEncoding.EncodeToString(make([]byte, 16))
	_, err = NewEd25519SignerFromSeedB64(short)
	if err == nil {
		t.Fatal("expected error for wrong seed length")
	}
}
