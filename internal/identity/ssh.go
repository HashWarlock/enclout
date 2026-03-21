package identity

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"golang.org/x/crypto/ssh"
)

// SSHPublicKeyString encodes an Ed25519 public key in SSH authorized_keys format.
// The output matches the Node.js implementation's ssh-ed25519 encoding.
func SSHPublicKeyString(pub ed25519.PublicKey) (string, error) {
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub))), nil
}

// SSHFingerprint computes a SHA-256 hex fingerprint of the SSH public key string.
// This matches the Node.js: createHash("sha256").update(sshPublicKey).digest("hex").
func SSHFingerprint(sshPublicKey string) string {
	sum := sha256.Sum256([]byte(sshPublicKey))
	return hex.EncodeToString(sum[:])
}
