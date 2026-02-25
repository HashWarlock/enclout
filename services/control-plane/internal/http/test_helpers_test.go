package handlers

import (
	"encoding/base64"
	"testing"
	"time"

	"enclout/services/control-plane/internal/requests"
	"enclout/services/control-plane/internal/signing"
)

func newTestHandler(t *testing.T) (*Handler, *requests.InMemoryStore) {
	t.Helper()
	store := requests.NewInMemoryStoreWithClock(realTestClock{
		now: time.Date(2026, 2, 24, 17, 0, 0, 0, time.UTC),
	})

	seed := []byte("12345678901234567890123456789012")
	signer, err := signing.NewEd25519SignerFromSeedB64(base64.StdEncoding.EncodeToString(seed))
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}

	source := NewStaticBundleSource(map[string]BundleTemplate{
		"conn_1": {
			ConnectorID:  "conn_1",
			SSHPublicKey: "ssh-ed25519 AAAATEST connector@tee",
			QuoteHex:     "abcd",
			EventLog:     "[]",
			MRTD:         "mrtd",
			RTMR0:        "rtmr0",
			RTMR1:        "rtmr1",
			RTMR2:        "rtmr2",
			RTMR3:        "rtmr3",
		},
	})

	h := NewHandler(store, signer, source)
	h.SetNow(func() time.Time {
		return time.Date(2026, 2, 24, 17, 0, 0, 0, time.UTC)
	})
	return h, store
}

type realTestClock struct {
	now time.Time
}

func (c realTestClock) Now() time.Time {
	return c.now
}

func createInput(deviceID string) requests.CreateInput {
	return requests.CreateInput{
		OpenClawUserID: "usr_1",
		DeviceID:       deviceID,
		ConnectorID:    "conn_1",
		SourceChannel:  "telegram",
		TTL:            5 * time.Minute,
	}
}
