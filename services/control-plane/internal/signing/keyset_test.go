package signing

import (
	"encoding/base64"
	"testing"
	"time"
)

func TestSignerSetSignsWithActiveKID(t *testing.T) {
	seedA := base64.StdEncoding.EncodeToString([]byte("12345678901234567890123456789012"))
	seedB := base64.StdEncoding.EncodeToString([]byte("abcdefghijklmnopqrstuvwxzy123456"))

	set, err := NewSignerSetFromSeedMap(map[string]string{
		"v1": seedA,
		"v2": seedB,
	}, "v2")
	if err != nil {
		t.Fatalf("unexpected signer set error: %v", err)
	}

	signed, err := set.SignBundle(BundlePayload{
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
	})
	if err != nil {
		t.Fatalf("unexpected sign error: %v", err)
	}
	if signed.KID != "v2" {
		t.Fatalf("expected active kid v2, got %q", signed.KID)
	}

	keyset := set.Keyset()
	if keyset.ActiveKID != "v2" {
		t.Fatalf("expected keyset active kid v2, got %q", keyset.ActiveKID)
	}
	if len(keyset.Keys) != 2 {
		t.Fatalf("expected 2 keys, got %d", len(keyset.Keys))
	}
}
