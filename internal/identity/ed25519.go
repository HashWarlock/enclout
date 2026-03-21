package identity

import (
	"crypto/ed25519"
	"fmt"
)

// DeriveEd25519 deterministically derives an Ed25519 key pair from a 32-byte seed.
// This is byte-compatible with the Node.js implementation which uses the same
// seed-to-key derivation via PKCS8/SPKI DER encoding.
func DeriveEd25519(seed []byte) (ed25519.PublicKey, ed25519.PrivateKey, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, nil, fmt.Errorf("seed must be %d bytes, got %d", ed25519.SeedSize, len(seed))
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	return pub, priv, nil
}
