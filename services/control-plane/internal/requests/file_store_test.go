package requests

import (
	"path/filepath"
	"testing"
	"time"
)

func TestFileStorePersistsAcrossReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "requests.json")

	store, err := NewFileStore(path)
	if err != nil {
		t.Fatalf("unexpected NewFileStore error: %v", err)
	}

	created, err := store.Create(CreateInput{
		OpenClawUserID: "usr_1",
		DeviceID:       "dev_1",
		ConnectorID:    "conn_1",
		SourceChannel:  "telegram",
		TTL:            5 * time.Minute,
	})
	if err != nil {
		t.Fatalf("unexpected create error: %v", err)
	}
	_, err = store.SetLocalDecision(created.ID, true)
	if err != nil {
		t.Fatalf("unexpected local decision error: %v", err)
	}

	reopened, err := NewFileStore(path)
	if err != nil {
		t.Fatalf("unexpected reopen error: %v", err)
	}

	got, err := reopened.Get(created.ID)
	if err != nil {
		t.Fatalf("unexpected get error after reopen: %v", err)
	}
	if got.Status != StatusApproved {
		t.Fatalf("expected persisted status %q, got %q", StatusApproved, got.Status)
	}
}
