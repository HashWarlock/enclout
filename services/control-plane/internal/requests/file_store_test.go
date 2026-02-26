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

func TestFileStorePersistsInstallSessionsAndTokensAcrossReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "requests.json")

	store, err := NewFileStore(path)
	if err != nil {
		t.Fatalf("unexpected NewFileStore error: %v", err)
	}

	created, token, err := store.CreateInstallSession(CreateInstallInput{
		OpenClawUserID: "usr_1",
		DeviceID:       "dev_1",
		ConnectorID:    "conn_1",
		SourceChannel:  "telegram",
		TTL:            10 * time.Minute,
	})
	if err != nil {
		t.Fatalf("unexpected create install session error: %v", err)
	}

	_, err = store.SetInstallApproval(created.ID, true)
	if err != nil {
		t.Fatalf("unexpected approval error: %v", err)
	}

	reopened, err := NewFileStore(path)
	if err != nil {
		t.Fatalf("unexpected reopen error: %v", err)
	}

	redeemed, err := reopened.RedeemInstallToken(token)
	if err != nil {
		t.Fatalf("unexpected redeem error after reopen: %v", err)
	}
	if redeemed.ID != created.ID {
		t.Fatalf("expected same session id, got %q want %q", redeemed.ID, created.ID)
	}

	updated, err := reopened.SetInstallResult(created.ID, InstallStatusInstalled, "")
	if err != nil {
		t.Fatalf("unexpected install result error: %v", err)
	}
	if updated.Status != InstallStatusInstalled {
		t.Fatalf("expected installed status, got %q", updated.Status)
	}
}
