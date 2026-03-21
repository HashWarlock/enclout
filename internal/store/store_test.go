package store_test

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"enclout/internal/access"
	"enclout/internal/store"
	"enclout/migrations"
)

func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := store.OpenMemory(migrations.FS)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestOpenMemory(t *testing.T) {
	db, err := store.OpenMemory(migrations.FS)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()

	tables := []string{"connection_requests", "install_sessions", "audit_log", "connector_bundles"}
	for _, table := range tables {
		var name string
		err := db.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name=?", table).Scan(&name)
		if err != nil {
			t.Fatalf("table %s not found: %v", table, err)
		}
	}
}

func TestOpenMemory_WALMode(t *testing.T) {
	db, err := store.OpenMemory(migrations.FS)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()

	var mode string
	if err := db.QueryRow("PRAGMA journal_mode").Scan(&mode); err != nil {
		t.Fatalf("query journal_mode: %v", err)
	}
	// In-memory databases may report "memory" instead of "wal"
	if mode != "wal" && mode != "memory" {
		t.Fatalf("expected wal or memory journal mode, got %s", mode)
	}
}

// --- SessionRepository tests ---

func TestSessionRepository_Create_Get(t *testing.T) {
	db, err := store.OpenMemory(migrations.FS)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()

	repo := store.NewSessionRepository(db)
	ctx := context.Background()

	session, _ := access.NewInstallSession("requester-1", "cli", 10*time.Minute)

	if err := repo.Create(ctx, session); err != nil {
		t.Fatalf("create: %v", err)
	}

	got, err := repo.Get(ctx, session.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}

	if got.ID != session.ID {
		t.Errorf("ID: got %q, want %q", got.ID, session.ID)
	}
	if got.RequesterID != session.RequesterID {
		t.Errorf("RequesterID: got %q, want %q", got.RequesterID, session.RequesterID)
	}
	if got.DeviceID != session.DeviceID {
		t.Errorf("DeviceID: got %q, want %q", got.DeviceID, session.DeviceID)
	}
	if got.ConnectorID != session.ConnectorID {
		t.Errorf("ConnectorID: got %q, want %q", got.ConnectorID, session.ConnectorID)
	}
	if got.Source != session.Source {
		t.Errorf("Source: got %q, want %q", got.Source, session.Source)
	}
	if got.Status != session.Status {
		t.Errorf("Status: got %q, want %q", got.Status, session.Status)
	}
	if got.TokenDigest != session.TokenDigest {
		t.Errorf("TokenDigest: got %q, want %q", got.TokenDigest, session.TokenDigest)
	}
	if got.ReasonCode != session.ReasonCode {
		t.Errorf("ReasonCode: got %q, want %q", got.ReasonCode, session.ReasonCode)
	}
	// RFC3339 truncates sub-second precision, so compare truncated times
	if !got.CreatedAt.Equal(session.CreatedAt.Truncate(time.Second)) {
		t.Errorf("CreatedAt: got %v, want %v", got.CreatedAt, session.CreatedAt.Truncate(time.Second))
	}
	if !got.ExpiresAt.Equal(session.ExpiresAt.Truncate(time.Second)) {
		t.Errorf("ExpiresAt: got %v, want %v", got.ExpiresAt, session.ExpiresAt.Truncate(time.Second))
	}
}

func TestSessionRepository_Update(t *testing.T) {
	db, err := store.OpenMemory(migrations.FS)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()

	repo := store.NewSessionRepository(db)
	ctx := context.Background()

	session, _ := access.NewInstallSession("requester-2", "web", 10*time.Minute)

	if err := repo.Create(ctx, session); err != nil {
		t.Fatalf("create: %v", err)
	}

	// Transition status via domain method
	if err := session.Approve(); err != nil {
		t.Fatalf("approve: %v", err)
	}

	if err := repo.Update(ctx, session); err != nil {
		t.Fatalf("update: %v", err)
	}

	got, err := repo.Get(ctx, session.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}

	if got.Status != access.InstallStatusApproved {
		t.Errorf("Status after update: got %q, want %q", got.Status, access.InstallStatusApproved)
	}
}

func TestSessionRepository_RedeemToken(t *testing.T) {
	db, err := store.OpenMemory(migrations.FS)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()

	repo := store.NewSessionRepository(db)
	ctx := context.Background()

	session, rawToken := access.NewInstallSession("requester-3", "cli", 10*time.Minute)
	digest := access.DigestToken(rawToken)

	if err := repo.Create(ctx, session); err != nil {
		t.Fatalf("create: %v", err)
	}

	// First redemption should succeed
	got, err := repo.RedeemToken(ctx, digest)
	if err != nil {
		t.Fatalf("first redeem: %v", err)
	}
	if got.ID != session.ID {
		t.Errorf("redeemed session ID: got %q, want %q", got.ID, session.ID)
	}
	if got.TokenDigest != "" {
		t.Errorf("token digest after redeem should be empty, got %q", got.TokenDigest)
	}

	// Second redemption of the same digest should return ErrNotFound
	_, err = repo.RedeemToken(ctx, digest)
	if !errors.Is(err, access.ErrNotFound) {
		t.Fatalf("second redeem: got %v, want %v", err, access.ErrNotFound)
	}
}

func TestSessionRepository_RedeemToken_NotFound(t *testing.T) {
	db, err := store.OpenMemory(migrations.FS)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()

	repo := store.NewSessionRepository(db)
	ctx := context.Background()

	_, err = repo.RedeemToken(ctx, "nonexistent-digest")
	if !errors.Is(err, access.ErrNotFound) {
		t.Fatalf("redeem unknown digest: got %v, want %v", err, access.ErrNotFound)
	}
}
