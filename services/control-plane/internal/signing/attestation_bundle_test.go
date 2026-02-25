package signing

import (
	"encoding/base64"
	"testing"
	"time"
)

func TestSignAndVerifyBundle(t *testing.T) {
	seed := []byte("12345678901234567890123456789012")
	seedB64 := base64.StdEncoding.EncodeToString(seed)

	signer, err := NewEd25519SignerFromSeedB64(seedB64)
	if err != nil {
		t.Fatalf("unexpected signer error: %v", err)
	}

	payload := BundlePayload{
		RequestID:                "req_1",
		ConnectorID:              "conn_1",
		SSHPublicKey:             "ssh-ed25519 AAAATEST connector@tee",
		QuoteHex:                 "abcd",
		EventLog:                 "[]",
		MRTD:                     "mrtd",
		RTMR0:                    "rtmr0",
		RTMR1:                    "rtmr1",
		RTMR2:                    "rtmr2",
		RTMR3:                    "rtmr3",
		ReportDataExpectedSHA256: "deadbeef",
		PolicyVersion:            "v1",
		IssuedAt:                 time.Date(2026, 2, 24, 17, 0, 0, 0, time.UTC),
		ExpiresAt:                time.Date(2026, 2, 24, 17, 5, 0, 0, time.UTC),
		Nonce:                    "nonce",
	}

	signed, err := signer.SignBundle(payload)
	if err != nil {
		t.Fatalf("unexpected sign error: %v", err)
	}
	if signed.KID != DefaultSigningKID {
		t.Fatalf("expected default kid %q, got %q", DefaultSigningKID, signed.KID)
	}

	ok, err := VerifyBundle(payload, signed.Signature, signer.PublicKeyB64())
	if err != nil {
		t.Fatalf("unexpected verify error: %v", err)
	}
	if !ok {
		t.Fatal("expected signature verification to pass")
	}
}

func TestReportDataHashFromSSHPublicKey(t *testing.T) {
	got := ReportDataHashFromSSHPublicKey("ssh-ed25519 AAAATEST connector@tee")
	if len(got) != 64 {
		t.Fatalf("expected 64 hex chars, got %d", len(got))
	}
}
