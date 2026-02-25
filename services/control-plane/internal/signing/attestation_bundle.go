package signing

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

const DefaultSigningKID = "v1"

type BundlePayload struct {
	RequestID                string    `json:"request_id"`
	ConnectorID              string    `json:"connector_id"`
	SSHPublicKey             string    `json:"ssh_public_key"`
	QuoteHex                 string    `json:"quote_hex"`
	EventLog                 string    `json:"event_log"`
	MRTD                     string    `json:"mrtd"`
	RTMR0                    string    `json:"rtmr0"`
	RTMR1                    string    `json:"rtmr1"`
	RTMR2                    string    `json:"rtmr2"`
	RTMR3                    string    `json:"rtmr3"`
	ReportDataExpectedSHA256 string    `json:"report_data_expected_sha256"`
	PolicyVersion            string    `json:"policy_version"`
	IssuedAt                 time.Time `json:"issued_at"`
	ExpiresAt                time.Time `json:"expires_at"`
	Nonce                    string    `json:"nonce"`
}

type SignedBundle struct {
	Payload   BundlePayload `json:"payload"`
	Signature string        `json:"signature"`
	Alg       string        `json:"alg"`
	KID       string        `json:"kid"`
}

type Ed25519Signer struct {
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
	kid        string
}

type PublicKeyInfo struct {
	KID          string `json:"kid"`
	Alg          string `json:"alg"`
	PublicKeyB64 string `json:"public_key_b64"`
}

type SigningKeyset struct {
	ActiveKID string          `json:"active_kid"`
	Keys      []PublicKeyInfo `json:"keys"`
}

type BundleSigner interface {
	SignBundle(payload BundlePayload) (SignedBundle, error)
	Keyset() SigningKeyset
}

type SignerSet struct {
	activeKID string
	signers   map[string]*Ed25519Signer
}

func NewEd25519SignerFromSeedB64(seedB64 string) (*Ed25519Signer, error) {
	return NewEd25519SignerWithKIDFromSeedB64(seedB64, DefaultSigningKID)
}

func NewEd25519SignerWithKIDFromSeedB64(seedB64 string, kid string) (*Ed25519Signer, error) {
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

func (s *Ed25519Signer) PublicKeyB64() string {
	return base64.StdEncoding.EncodeToString(s.publicKey)
}

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

func (s *SignerSet) SignBundle(payload BundlePayload) (SignedBundle, error) {
	signer := s.signers[s.activeKID]
	return signer.SignBundle(payload)
}

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

func VerifyBundle(payload BundlePayload, signatureB64 string, publicKeyB64 string) (bool, error) {
	raw, err := marshalCanonical(payload)
	if err != nil {
		return false, err
	}
	pub, err := base64.StdEncoding.DecodeString(publicKeyB64)
	if err != nil {
		return false, fmt.Errorf("decode pubkey: %w", err)
	}
	if len(pub) != ed25519.PublicKeySize {
		return false, errors.New("invalid ed25519 public key length")
	}
	sig, err := base64.StdEncoding.DecodeString(signatureB64)
	if err != nil {
		return false, fmt.Errorf("decode signature: %w", err)
	}
	return ed25519.Verify(ed25519.PublicKey(pub), raw, sig), nil
}

func ReportDataHashFromSSHPublicKey(sshPublicKey string) string {
	sum := sha256.Sum256([]byte(sshPublicKey))
	return fmt.Sprintf("%x", sum[:])
}

func marshalCanonical(payload BundlePayload) ([]byte, error) {
	return json.Marshal(payload)
}
