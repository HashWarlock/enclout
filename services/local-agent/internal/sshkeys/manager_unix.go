package sshkeys

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type Manager struct {
	baseDir string
}

func NewManager(baseDir string) Manager {
	return Manager{baseDir: baseDir}
}

func (m Manager) Install(username string, pubKey string) error {
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
