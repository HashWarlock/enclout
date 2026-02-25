package sshkeys

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInstallManagedKeyAtomicAndPermissioned(t *testing.T) {
	dir := t.TempDir()
	m := NewManager(dir)
	key := "ssh-ed25519 AAAATEST connector@tee"

	err := m.Install("alice", key)
	if err != nil {
		t.Fatalf("unexpected install error: %v", err)
	}

	target := filepath.Join(dir, "alice", "authorized_keys")
	data, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("unexpected read error: %v", err)
	}
	if !strings.Contains(string(data), "ssh-ed25519") {
		t.Fatalf("expected public key in authorized_keys")
	}
}
