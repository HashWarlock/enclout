package store_test

import (
	"testing"

	"enclout/internal/store"
	"enclout/migrations"
)

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
