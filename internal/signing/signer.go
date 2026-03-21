package signing

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// Ed25519Signer signs bundles with a single Ed25519 key pair.
type Ed25519Signer struct {
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
	kid        string
}

// NewEd25519SignerFromSeedB64 creates a signer from a base64-encoded 32-byte
// seed using the default key ID ("v1").
func NewEd25519SignerFromSeedB64(seedB64 string) (*Ed25519Signer, error) {
	return NewEd25519SignerWithKIDFromSeedB64(seedB64, DefaultSigningKID)
}

// NewEd25519SignerWithKIDFromSeedB64 creates a signer from a base64-encoded
// seed with a specific key ID.
func NewEd25519SignerWithKIDFromSeedB64(seedB64, kid string) (*Ed25519Signer, error) {
	seed, err := base64.StdEncoding.DecodeString(seedB64)
	if err != nil {
		return nil, fmt.Errorf("decode signing seed: %w", err)
	}
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("signing seed must be %d bytes", ed25519.SeedSize)
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	kid = strings.TrimSpace(kid)
	if kid == "" {
		kid = DefaultSigningKID
	}
	return &Ed25519Signer{privateKey: privateKey, publicKey: publicKey, kid: kid}, nil
}

// SignBundle signs the payload and returns a SignedBundle.
func (s *Ed25519Signer) SignBundle(payload BundlePayload) (SignedBundle, error) {
	raw, err := marshalCanonical(payload)
	if err != nil {
		return SignedBundle{}, err
	}
	sig := ed25519.Sign(s.privateKey, raw)
	return SignedBundle{
		Payload:   payload,
		Signature: base64.StdEncoding.EncodeToString(sig),
		Alg:       "ed25519",
		KID:       s.kid,
	}, nil
}

// PublicKeyB64 returns the base64-encoded public key.
func (s *Ed25519Signer) PublicKeyB64() string {
	return base64.StdEncoding.EncodeToString(s.publicKey)
}

// Keyset returns a SigningKeyset containing only this signer's key.
func (s *Ed25519Signer) Keyset() SigningKeyset {
	return SigningKeyset{
		ActiveKID: s.kid,
		Keys: []PublicKeyInfo{
			{
				KID:          s.kid,
				Alg:          "ed25519",
				PublicKeyB64: s.PublicKeyB64(),
			},
		},
	}
}

// SignerSet manages multiple Ed25519 signers and signs with the active one.
type SignerSet struct {
	activeKID string
	signers   map[string]*Ed25519Signer
}

// NewSignerSetFromSeedMap creates a SignerSet from a map of kid->base64Seed
// pairs. The activeKID must exist in the map.
func NewSignerSetFromSeedMap(seedByKID map[string]string, activeKID string) (*SignerSet, error) {
	if len(seedByKID) == 0 {
		return nil, fmt.Errorf("no signing keys configured")
	}

	activeKID = strings.TrimSpace(activeKID)
	if activeKID == "" {
		activeKID = DefaultSigningKID
	}

	signers := make(map[string]*Ed25519Signer, len(seedByKID))
	for kid, seedB64 := range seedByKID {
		kid = strings.TrimSpace(kid)
		if kid == "" {
			return nil, fmt.Errorf("signing key kid cannot be empty")
		}
		signer, err := NewEd25519SignerWithKIDFromSeedB64(seedB64, kid)
		if err != nil {
			return nil, fmt.Errorf("invalid signing key %q: %w", kid, err)
		}
		signers[kid] = signer
	}

	if _, ok := signers[activeKID]; !ok {
		return nil, fmt.Errorf("active signing kid %q not found", activeKID)
	}

	return &SignerSet{
		activeKID: activeKID,
		signers:   signers,
	}, nil
}

// SignBundle signs the payload using the active key.
func (s *SignerSet) SignBundle(payload BundlePayload) (SignedBundle, error) {
	signer := s.signers[s.activeKID]
	return signer.SignBundle(payload)
}

// Keyset returns a SigningKeyset with all registered keys, sorted by KID.
func (s *SignerSet) Keyset() SigningKeyset {
	keys := make([]PublicKeyInfo, 0, len(s.signers))
	for _, signer := range s.signers {
		keys = append(keys, PublicKeyInfo{
			KID:          signer.kid,
			Alg:          "ed25519",
			PublicKeyB64: signer.PublicKeyB64(),
		})
	}

	sort.Slice(keys, func(i, j int) bool {
		return keys[i].KID < keys[j].KID
	})

	return SigningKeyset{
		ActiveKID: s.activeKID,
		Keys:      keys,
	}
}

// marshalCanonical produces deterministic JSON for signature stability.
func marshalCanonical(payload BundlePayload) ([]byte, error) {
	return json.Marshal(payload)
}
