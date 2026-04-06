package agent

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// SSHKeyManager installs SSH public keys using atomic write-then-rename.
type SSHKeyManager struct {
	baseDir string
}

// NewSSHKeyManager creates a manager that writes authorized_keys files
// under baseDir/<username>/authorized_keys. A leading "~" in baseDir is
// expanded to the current user's home directory.
func NewSSHKeyManager(baseDir string) SSHKeyManager {
	if strings.HasPrefix(baseDir, "~/") {
		home, err := os.UserHomeDir()
		if err == nil {
			baseDir = filepath.Join(home, baseDir[2:])
		}
	}
	return SSHKeyManager{baseDir: baseDir}
}

// Install writes the given SSH public key to <baseDir>/<username>/authorized_keys
// using an atomic write-then-rename pattern.
func (m SSHKeyManager) Install(username string, pubKey string) error {
	pubKey = strings.TrimSpace(pubKey)
	if username == "" || pubKey == "" {
		return fmt.Errorf("username and public key are required")
	}

	userDir := filepath.Join(m.baseDir, username)
	if err := os.MkdirAll(userDir, 0o755); err != nil {
		return err
	}

	finalPath := filepath.Join(userDir, "authorized_keys")
	tmpPath := finalPath + ".tmp"
	if err := os.WriteFile(tmpPath, []byte(pubKey+"\n"), 0o644); err != nil {
		return err
	}
	return os.Rename(tmpPath, finalPath)
}
