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

// --- RequestRepository tests ---

func TestRequestRepository_Create_Get(t *testing.T) {
	db := openTestDB(t)
	repo := store.NewRequestRepository(db)
	ctx := context.Background()

	req := access.NewConnectionRequest("user-1", "dev-1", "conn-1", "cli", 5*time.Minute)
	if err := repo.Create(ctx, req); err != nil {
		t.Fatalf("create: %v", err)
	}

	got, err := repo.Get(ctx, req.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.ID != req.ID {
		t.Fatalf("expected %s, got %s", req.ID, got.ID)
	}
	if got.RequesterID != "user-1" {
		t.Fatalf("expected user-1, got %s", got.RequesterID)
	}
	if got.Status != access.StatusPendingLocalConfirm {
		t.Fatalf("expected pending, got %s", got.Status)
	}
}

func TestRequestRepository_Update(t *testing.T) {
	db := openTestDB(t)
	repo := store.NewRequestRepository(db)
	ctx := context.Background()

	req := access.NewConnectionRequest("user-1", "dev-1", "conn-1", "cli", 5*time.Minute)
	repo.Create(ctx, req)
	req.Approve()
	repo.Update(ctx, req)

	got, _ := repo.Get(ctx, req.ID)
	if got.Status != access.StatusApproved {
		t.Fatalf("expected approved, got %s", got.Status)
	}
}

func TestRequestRepository_Transition(t *testing.T) {
	db := openTestDB(t)
	repo := store.NewRequestRepository(db)
	ctx := context.Background()

	req := access.NewConnectionRequest("user-1", "dev-1", "conn-1", "cli", 5*time.Minute)
	if err := repo.Create(ctx, req); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := req.Approve(); err != nil {
		t.Fatalf("approve: %v", err)
	}
	if err := repo.Update(ctx, req); err != nil {
		t.Fatalf("update approved: %v", err)
	}

	updated, err := repo.Transition(ctx, req.ID, []access.Status{access.StatusApproved}, access.StatusRevoked, "")
	if err != nil {
		t.Fatalf("transition: %v", err)
	}
	if updated.Status != access.StatusRevoked {
		t.Fatalf("expected revoked, got %s", updated.Status)
	}
}

func TestRequestRepository_Transition_ConflictsOnStaleStatus(t *testing.T) {
	db := openTestDB(t)
	repo := store.NewRequestRepository(db)
	ctx := context.Background()

	req := access.NewConnectionRequest("user-1", "dev-1", "conn-1", "cli", 5*time.Minute)
	if err := repo.Create(ctx, req); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := req.Approve(); err != nil {
		t.Fatalf("approve: %v", err)
	}
	if err := repo.Update(ctx, req); err != nil {
		t.Fatalf("update approved: %v", err)
	}

	if _, err := repo.Transition(ctx, req.ID, []access.Status{access.StatusApproved}, access.StatusRevoked, ""); err != nil {
		t.Fatalf("revoke transition: %v", err)
	}

	_, err := repo.Transition(ctx, req.ID, []access.Status{access.StatusApproved}, access.StatusConnected, "")
	if !errors.Is(err, access.ErrInvalidTransition) {
		t.Fatalf("expected ErrInvalidTransition, got %v", err)
	}

	got, err := repo.Get(ctx, req.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Status != access.StatusRevoked {
		t.Fatalf("expected status to remain revoked, got %s", got.Status)
	}
}

func TestRequestRepository_ListPending(t *testing.T) {
	db := openTestDB(t)
	repo := store.NewRequestRepository(db)
	ctx := context.Background()

	r1 := access.NewConnectionRequest("u1", "dev-A", "conn-1", "cli", 5*time.Minute)
	r2 := access.NewConnectionRequest("u2", "dev-A", "conn-2", "cli", 5*time.Minute)
	r3 := access.NewConnectionRequest("u3", "dev-B", "conn-3", "cli", 5*time.Minute)
	repo.Create(ctx, r1)
	repo.Create(ctx, r2)
	repo.Create(ctx, r3)

	pending, err := repo.ListPending(ctx, "dev-A")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(pending) != 2 {
		t.Fatalf("expected 2, got %d", len(pending))
	}
}

func TestRequestRepository_List_FilterAndPagination(t *testing.T) {
	db := openTestDB(t)
	repo := store.NewRequestRepository(db)
	ctx := context.Background()

	r1 := access.NewConnectionRequest("u1", "dev-A", "conn-1", "cli", 5*time.Minute)
	r2 := access.NewConnectionRequest("u1", "dev-A", "conn-2", "cli", 5*time.Minute)
	r3 := access.NewConnectionRequest("u2", "dev-B", "conn-3", "cli", 5*time.Minute)
	if err := repo.Create(ctx, r1); err != nil {
		t.Fatalf("create r1: %v", err)
	}
	if err := repo.Create(ctx, r2); err != nil {
		t.Fatalf("create r2: %v", err)
	}
	if err := repo.Create(ctx, r3); err != nil {
		t.Fatalf("create r3: %v", err)
	}

	if _, err := repo.Transition(ctx, r1.ID, []access.Status{access.StatusPendingLocalConfirm}, access.StatusApproved, ""); err != nil {
		t.Fatalf("approve r1: %v", err)
	}

	filtered, err := repo.List(ctx, store.RequestListOptions{
		DeviceID: "dev-A",
		Status:   access.StatusApproved,
		Limit:    10,
		Offset:   0,
	})
	if err != nil {
		t.Fatalf("list filtered: %v", err)
	}
	if len(filtered) != 1 {
		t.Fatalf("expected 1 filtered item, got %d", len(filtered))
	}
	if filtered[0].ID != r1.ID {
		t.Fatalf("expected approved request %s, got %s", r1.ID, filtered[0].ID)
	}

	paged, err := repo.List(ctx, store.RequestListOptions{
		Limit:  2,
		Offset: 1,
	})
	if err != nil {
		t.Fatalf("list paged: %v", err)
	}
	if len(paged) != 2 {
		t.Fatalf("expected 2 paged items, got %d", len(paged))
	}
}

func TestRequestRepository_Get_NotFound(t *testing.T) {
	db := openTestDB(t)
	repo := store.NewRequestRepository(db)

	_, err := repo.Get(context.Background(), "nonexistent")
	if err != access.ErrNotFound {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

// --- BundleRepository tests ---

func TestBundleRepository_Register_Get(t *testing.T) {
	db := openTestDB(t)
	repo := store.NewBundleRepository(db)
	ctx := context.Background()

	b := store.ConnectorBundle{
		ConnectorID:   "conn-1",
		SSHPublicKey:  "ssh-ed25519 AAAA...",
		QuoteHex:      "deadbeef",
		EventLog:      "log-data",
		MRTD:          "mrtd-val",
		RTMR0:         "rtmr0-val",
		RTMR1:         "rtmr1-val",
		RTMR2:         "rtmr2-val",
		RTMR3:         "rtmr3-val",
		PolicyVersion: "v2",
		Info:          `{"cpu":"x86"}`,
	}

	if err := repo.Register(ctx, b); err != nil {
		t.Fatalf("register: %v", err)
	}

	got, err := repo.Get(ctx, "conn-1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}

	if got.ConnectorID != b.ConnectorID {
		t.Errorf("ConnectorID: got %q, want %q", got.ConnectorID, b.ConnectorID)
	}
	if got.SSHPublicKey != b.SSHPublicKey {
		t.Errorf("SSHPublicKey: got %q, want %q", got.SSHPublicKey, b.SSHPublicKey)
	}
	if got.QuoteHex != b.QuoteHex {
		t.Errorf("QuoteHex: got %q, want %q", got.QuoteHex, b.QuoteHex)
	}
	if got.EventLog != b.EventLog {
		t.Errorf("EventLog: got %q, want %q", got.EventLog, b.EventLog)
	}
	if got.MRTD != b.MRTD {
		t.Errorf("MRTD: got %q, want %q", got.MRTD, b.MRTD)
	}
	if got.RTMR0 != b.RTMR0 {
		t.Errorf("RTMR0: got %q, want %q", got.RTMR0, b.RTMR0)
	}
	if got.RTMR1 != b.RTMR1 {
		t.Errorf("RTMR1: got %q, want %q", got.RTMR1, b.RTMR1)
	}
	if got.RTMR2 != b.RTMR2 {
		t.Errorf("RTMR2: got %q, want %q", got.RTMR2, b.RTMR2)
	}
	if got.RTMR3 != b.RTMR3 {
		t.Errorf("RTMR3: got %q, want %q", got.RTMR3, b.RTMR3)
	}
	if got.PolicyVersion != b.PolicyVersion {
		t.Errorf("PolicyVersion: got %q, want %q", got.PolicyVersion, b.PolicyVersion)
	}
	if got.Info != b.Info {
		t.Errorf("Info: got %q, want %q", got.Info, b.Info)
	}
	if got.RegisteredAt.IsZero() {
		t.Error("RegisteredAt should not be zero")
	}
}

func TestBundleRepository_Register_Upsert(t *testing.T) {
	db := openTestDB(t)
	repo := store.NewBundleRepository(db)
	ctx := context.Background()

	b1 := store.ConnectorBundle{
		ConnectorID:   "conn-upsert",
		SSHPublicKey:  "key-1",
		QuoteHex:      "quote-1",
		PolicyVersion: "v1",
		Info:          "{}",
	}
	if err := repo.Register(ctx, b1); err != nil {
		t.Fatalf("register first: %v", err)
	}

	b2 := store.ConnectorBundle{
		ConnectorID:   "conn-upsert",
		SSHPublicKey:  "key-2",
		QuoteHex:      "quote-2",
		PolicyVersion: "v2",
		Info:          `{"updated":true}`,
	}
	if err := repo.Register(ctx, b2); err != nil {
		t.Fatalf("register second: %v", err)
	}

	got, err := repo.Get(ctx, "conn-upsert")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.SSHPublicKey != "key-2" {
		t.Errorf("SSHPublicKey after upsert: got %q, want %q", got.SSHPublicKey, "key-2")
	}
	if got.QuoteHex != "quote-2" {
		t.Errorf("QuoteHex after upsert: got %q, want %q", got.QuoteHex, "quote-2")
	}
	if got.PolicyVersion != "v2" {
		t.Errorf("PolicyVersion after upsert: got %q, want %q", got.PolicyVersion, "v2")
	}
}

func TestBundleRepository_Get_NotFound(t *testing.T) {
	db := openTestDB(t)
	repo := store.NewBundleRepository(db)
	ctx := context.Background()

	_, err := repo.Get(ctx, "nonexistent-connector")
	if err == nil {
		t.Fatal("expected error for unknown connector, got nil")
	}
}

func TestBundleRepository_List(t *testing.T) {
	db := openTestDB(t)
	repo := store.NewBundleRepository(db)
	ctx := context.Background()

	bundles := []store.ConnectorBundle{
		{ConnectorID: "alpha", SSHPublicKey: "key-a", QuoteHex: "qa", PolicyVersion: "v1", Info: "{}"},
		{ConnectorID: "beta", SSHPublicKey: "key-b", QuoteHex: "qb", PolicyVersion: "v1", Info: "{}"},
	}
	for _, b := range bundles {
		if err := repo.Register(ctx, b); err != nil {
			t.Fatalf("register %s: %v", b.ConnectorID, err)
		}
	}

	got, err := repo.List(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("list length: got %d, want 2", len(got))
	}
	// Ordered by connector_id
	if got[0].ConnectorID != "alpha" {
		t.Errorf("first connector: got %q, want %q", got[0].ConnectorID, "alpha")
	}
	if got[1].ConnectorID != "beta" {
		t.Errorf("second connector: got %q, want %q", got[1].ConnectorID, "beta")
	}
}

// --- AuditLogger tests ---

func TestAuditLogger_Log(t *testing.T) {
	db := openTestDB(t)
	logger := store.NewAuditLogger(db)
	ctx := context.Background()

	if err := logger.Log(ctx, "connector", "conn-1", "registered", "system", "initial registration"); err != nil {
		t.Fatalf("log: %v", err)
	}

	entries, err := logger.QueryByEntity(ctx, "connector", "conn-1")
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("entries length: got %d, want 1", len(entries))
	}

	e := entries[0]
	if e.EntityType != "connector" {
		t.Errorf("EntityType: got %q, want %q", e.EntityType, "connector")
	}
	if e.EntityID != "conn-1" {
		t.Errorf("EntityID: got %q, want %q", e.EntityID, "conn-1")
	}
	if e.Action != "registered" {
		t.Errorf("Action: got %q, want %q", e.Action, "registered")
	}
	if e.Actor != "system" {
		t.Errorf("Actor: got %q, want %q", e.Actor, "system")
	}
	if e.Detail != "initial registration" {
		t.Errorf("Detail: got %q, want %q", e.Detail, "initial registration")
	}
	if e.CreatedAt.IsZero() {
		t.Error("CreatedAt should not be zero")
	}
	if e.ID == 0 {
		t.Error("ID should be set (autoincrement)")
	}
}

func TestAuditLogger_QueryByEntity(t *testing.T) {
	db := openTestDB(t)
	logger := store.NewAuditLogger(db)
	ctx := context.Background()

	// 3 entries for 2 different entities
	if err := logger.Log(ctx, "connector", "c1", "registered", "sys", ""); err != nil {
		t.Fatalf("log 1: %v", err)
	}
	if err := logger.Log(ctx, "connector", "c1", "verified", "sys", "ok"); err != nil {
		t.Fatalf("log 2: %v", err)
	}
	if err := logger.Log(ctx, "connector", "c2", "registered", "sys", ""); err != nil {
		t.Fatalf("log 3: %v", err)
	}

	// Query for c1 should return 2
	c1Entries, err := logger.QueryByEntity(ctx, "connector", "c1")
	if err != nil {
		t.Fatalf("query c1: %v", err)
	}
	if len(c1Entries) != 2 {
		t.Fatalf("c1 entries: got %d, want 2", len(c1Entries))
	}
	if c1Entries[0].Action != "registered" {
		t.Errorf("c1 first action: got %q, want %q", c1Entries[0].Action, "registered")
	}
	if c1Entries[1].Action != "verified" {
		t.Errorf("c1 second action: got %q, want %q", c1Entries[1].Action, "verified")
	}

	// Query for c2 should return 1
	c2Entries, err := logger.QueryByEntity(ctx, "connector", "c2")
	if err != nil {
		t.Fatalf("query c2: %v", err)
	}
	if len(c2Entries) != 1 {
		t.Fatalf("c2 entries: got %d, want 1", len(c2Entries))
	}
}

func TestAuditLogger_List_FilterAndPagination(t *testing.T) {
	db := openTestDB(t)
	logger := store.NewAuditLogger(db)
	ctx := context.Background()

	if err := logger.Log(ctx, "connector", "c1", "registered", "sys", ""); err != nil {
		t.Fatalf("log 1: %v", err)
	}
	if err := logger.Log(ctx, "request", "r1", "created", "user", ""); err != nil {
		t.Fatalf("log 2: %v", err)
	}
	if err := logger.Log(ctx, "connector", "c1", "verified", "sys", "ok"); err != nil {
		t.Fatalf("log 3: %v", err)
	}

	filtered, err := logger.List(ctx, store.AuditListOptions{
		EntityType: "connector",
		EntityID:   "c1",
		Limit:      10,
		Offset:     0,
	})
	if err != nil {
		t.Fatalf("list filtered: %v", err)
	}
	if len(filtered) != 2 {
		t.Fatalf("expected 2 filtered entries, got %d", len(filtered))
	}

	paged, err := logger.List(ctx, store.AuditListOptions{
		Limit:  2,
		Offset: 1,
	})
	if err != nil {
		t.Fatalf("list paged: %v", err)
	}
	if len(paged) != 2 {
		t.Fatalf("expected 2 paged entries, got %d", len(paged))
	}

	since := time.Now().UTC().Add(1 * time.Minute)
	none, err := logger.List(ctx, store.AuditListOptions{
		Since: &since,
		Limit: 10,
	})
	if err != nil {
		t.Fatalf("list since: %v", err)
	}
	if len(none) != 0 {
		t.Fatalf("expected 0 entries for future since, got %d", len(none))
	}
}
