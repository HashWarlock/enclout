package agent

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// SSHKeyManager installs SSH public keys using atomic write-then-rename.
type SSHKeyManager struct {
	baseDir string
}

// ManagedKey describes one managed connector key installed on the endpoint.
type ManagedKey struct {
	ConnectorID string    `json:"connector_id"`
	PublicKey   string    `json:"public_key"`
	InstalledAt time.Time `json:"installed_at"`
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

// InstallForConnector installs or replaces a managed key for a specific
// connector and rewrites authorized_keys from managed inventory.
func (m SSHKeyManager) InstallForConnector(username, connectorID, pubKey string) error {
	pubKey = strings.TrimSpace(pubKey)
	connectorID = strings.TrimSpace(connectorID)
	if username == "" || connectorID == "" || pubKey == "" {
		return fmt.Errorf("username, connectorID, and public key are required")
	}

	userDir := filepath.Join(m.baseDir, username)
	if err := os.MkdirAll(userDir, 0o755); err != nil {
		return err
	}
	managedDir := filepath.Join(userDir, "managed")
	if err := os.MkdirAll(managedDir, 0o755); err != nil {
		return err
	}

	rec := managedKeyRecord{
		ConnectorID: connectorID,
		PublicKey:   pubKey,
		InstalledAt: time.Now().UTC().Format(time.RFC3339),
	}
	data, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	recordPath := filepath.Join(managedDir, safeConnectorFilename(connectorID))
	if err := writeAtomic(recordPath, data, 0o644); err != nil {
		return err
	}
	return m.rewriteAuthorizedKeysFromManaged(userDir)
}

// CleanupStale removes managed connector keys that do not match
// activeConnectorID and rewrites authorized_keys.
func (m SSHKeyManager) CleanupStale(username, activeConnectorID string) error {
	if username == "" || activeConnectorID == "" {
		return nil
	}
	userDir := filepath.Join(m.baseDir, username)
	managedDir := filepath.Join(userDir, "managed")
	entries, err := os.ReadDir(managedDir)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		path := filepath.Join(managedDir, entry.Name())
		rec, err := readManagedRecord(path)
		if err != nil {
			return err
		}
		if rec.ConnectorID == activeConnectorID {
			continue
		}
		if err := os.Remove(path); err != nil {
			return err
		}
	}
	return m.rewriteAuthorizedKeysFromManaged(userDir)
}

// ListManaged returns all managed connector keys for username.
func (m SSHKeyManager) ListManaged(username string) ([]ManagedKey, error) {
	if username == "" {
		return []ManagedKey{}, nil
	}
	managedDir := filepath.Join(m.baseDir, username, "managed")
	entries, err := os.ReadDir(managedDir)
	if os.IsNotExist(err) {
		return []ManagedKey{}, nil
	}
	if err != nil {
		return nil, err
	}

	out := make([]ManagedKey, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		rec, err := readManagedRecord(filepath.Join(managedDir, entry.Name()))
		if err != nil {
			return nil, err
		}
		installedAt, _ := time.Parse(time.RFC3339, rec.InstalledAt)
		out = append(out, ManagedKey{
			ConnectorID: rec.ConnectorID,
			PublicKey:   rec.PublicKey,
			InstalledAt: installedAt,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].ConnectorID < out[j].ConnectorID
	})
	return out, nil
}

type managedKeyRecord struct {
	ConnectorID string `json:"connector_id"`
	PublicKey   string `json:"public_key"`
	InstalledAt string `json:"installed_at"`
}

func (m SSHKeyManager) rewriteAuthorizedKeysFromManaged(userDir string) error {
	keys, err := m.ListManaged(filepath.Base(userDir))
	if err != nil {
		return err
	}
	finalPath := filepath.Join(userDir, "authorized_keys")
	if len(keys) == 0 {
		if err := os.Remove(finalPath); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}

	var lines []string
	for _, k := range keys {
		lines = append(lines, strings.TrimSpace(k.PublicKey))
	}
	content := strings.Join(lines, "\n") + "\n"
	return writeAtomic(finalPath, []byte(content), 0o644)
}

func readManagedRecord(path string) (managedKeyRecord, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return managedKeyRecord{}, err
	}
	var rec managedKeyRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return managedKeyRecord{}, err
	}
	if strings.TrimSpace(rec.ConnectorID) == "" || strings.TrimSpace(rec.PublicKey) == "" {
		return managedKeyRecord{}, fmt.Errorf("invalid managed key record: %s", path)
	}
	return rec, nil
}

func safeConnectorFilename(connectorID string) string {
	replacer := strings.NewReplacer("/", "_", "\\", "_", ":", "_", "..", "_")
	return replacer.Replace(connectorID) + ".json"
}

func writeAtomic(path string, data []byte, perm os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
