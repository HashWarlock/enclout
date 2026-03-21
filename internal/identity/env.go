package identity

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
)

// EnvDeriver implements Deriver for dev/testing by reading seed and
// attestation values from environment variables.
type EnvDeriver struct{}

// DeriveIdentity derives a connector identity from environment variables.
//
// Required env vars:
//   - TEE_SEED_B64: base64-encoded 32-byte seed for Ed25519 derivation
//
// Optional env vars (for attestation):
//   - TEE_QUOTE_HEX: hex-encoded attestation quote
//   - TEE_MRTD, TEE_RTMR0, TEE_RTMR1, TEE_RTMR2, TEE_RTMR3: measurement registers
//   - TEE_EVENT_LOG: JSON event log
//   - TEE_POLICY_VERSION: attestation policy version
func (d *EnvDeriver) DeriveIdentity(ctx context.Context, connectorID string) (ConnectorIdentity, Attestation, error) {
	if connectorID == "" {
		return ConnectorIdentity{}, Attestation{}, fmt.Errorf("connectorID must not be empty")
	}

	seedB64 := os.Getenv("TEE_SEED_B64")
	if seedB64 == "" {
		return ConnectorIdentity{}, Attestation{}, fmt.Errorf("TEE_SEED_B64 environment variable is required")
	}

	seed, err := base64.StdEncoding.DecodeString(seedB64)
	if err != nil {
		return ConnectorIdentity{}, Attestation{}, fmt.Errorf("TEE_SEED_B64: invalid base64: %w", err)
	}

	pub, _, err := DeriveEd25519(seed)
	if err != nil {
		return ConnectorIdentity{}, Attestation{}, fmt.Errorf("derive ed25519: %w", err)
	}

	sshKey, err := SSHPublicKeyString(pub)
	if err != nil {
		return ConnectorIdentity{}, Attestation{}, fmt.Errorf("ssh public key: %w", err)
	}

	fingerprint := SSHFingerprint(sshKey)

	identity := ConnectorIdentity{
		ConnectorID:       connectorID,
		SSHPublicKey:      sshKey,
		PublicKeyHex:      hex.EncodeToString(pub),
		FingerprintSHA256: fingerprint,
	}

	attestation := Attestation{
		QuoteHex:      os.Getenv("TEE_QUOTE_HEX"),
		MRTD:          os.Getenv("TEE_MRTD"),
		RTMR0:         os.Getenv("TEE_RTMR0"),
		RTMR1:         os.Getenv("TEE_RTMR1"),
		RTMR2:         os.Getenv("TEE_RTMR2"),
		RTMR3:         os.Getenv("TEE_RTMR3"),
		EventLog:      os.Getenv("TEE_EVENT_LOG"),
		PolicyVersion: os.Getenv("TEE_POLICY_VERSION"),
	}

	return identity, attestation, nil
}
