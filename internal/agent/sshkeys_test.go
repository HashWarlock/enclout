package agent

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSSHKeyManager_InstallForConnector_ReplacesExistingConnectorKey(t *testing.T) {
	m := NewSSHKeyManager(t.TempDir())

	if err := m.InstallForConnector("alice", "conn-1", "ssh-ed25519 AAAAold connector@tee"); err != nil {
		t.Fatalf("install old key: %v", err)
	}
	if err := m.InstallForConnector("alice", "conn-1", "ssh-ed25519 AAAAnew connector@tee"); err != nil {
		t.Fatalf("install new key: %v", err)
	}

	keys, err := m.ListManaged("alice")
	if err != nil {
		t.Fatalf("list managed: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("expected 1 managed key, got %d", len(keys))
	}
	if keys[0].ConnectorID != "conn-1" {
		t.Fatalf("expected connector conn-1, got %s", keys[0].ConnectorID)
	}
	if keys[0].PublicKey != "ssh-ed25519 AAAAnew connector@tee" {
		t.Fatalf("expected latest key to replace previous key, got %q", keys[0].PublicKey)
	}

	authorizedPath := filepath.Join(m.baseDir, "alice", "authorized_keys")
	content, err := os.ReadFile(authorizedPath)
	if err != nil {
		t.Fatalf("read authorized_keys: %v", err)
	}
	if string(content) != "ssh-ed25519 AAAAnew connector@tee\n" {
		t.Fatalf("unexpected authorized_keys content: %q", string(content))
	}
}

func TestSSHKeyManager_CleanupStale_RemovesOutdatedConnectorKeys(t *testing.T) {
	m := NewSSHKeyManager(t.TempDir())

	if err := m.InstallForConnector("alice", "conn-old", "ssh-ed25519 AAAAold connector@tee"); err != nil {
		t.Fatalf("install old key: %v", err)
	}
	if err := m.InstallForConnector("alice", "conn-new", "ssh-ed25519 AAAAnew connector@tee"); err != nil {
		t.Fatalf("install new key: %v", err)
	}

	if err := m.CleanupStale("alice", "conn-new"); err != nil {
		t.Fatalf("cleanup stale: %v", err)
	}

	keys, err := m.ListManaged("alice")
	if err != nil {
		t.Fatalf("list managed: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("expected 1 key after cleanup, got %d", len(keys))
	}
	if keys[0].ConnectorID != "conn-new" {
		t.Fatalf("expected connector conn-new, got %s", keys[0].ConnectorID)
	}

	authorizedPath := filepath.Join(m.baseDir, "alice", "authorized_keys")
	content, err := os.ReadFile(authorizedPath)
	if err != nil {
		t.Fatalf("read authorized_keys: %v", err)
	}
	if string(content) != "ssh-ed25519 AAAAnew connector@tee\n" {
		t.Fatalf("unexpected authorized_keys content after cleanup: %q", string(content))
	}
}

func TestSSHKeyManager_CleanupStale_NoOpWhenAlreadyCurrent(t *testing.T) {
	m := NewSSHKeyManager(t.TempDir())
	if err := m.InstallForConnector("alice", "conn-1", "ssh-ed25519 AAAA connector@tee"); err != nil {
		t.Fatalf("install key: %v", err)
	}

	if err := m.CleanupStale("alice", "conn-1"); err != nil {
		t.Fatalf("cleanup no-op: %v", err)
	}

	keys, err := m.ListManaged("alice")
	if err != nil {
		t.Fatalf("list managed: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(keys))
	}
}
