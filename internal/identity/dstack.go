package identity

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	dstacksdk "github.com/Dstack-TEE/dstack/sdk/go/dstack"
)

// DstackDeriver implements Deriver using the official dstack Go SDK.
// It reads DSTACK_SIMULATOR_ENDPOINT from the environment automatically;
// in a Phala Cloud CVM the SDK falls back to /var/run/dstack.sock.
type DstackDeriver struct {
	client     *dstacksdk.DstackClient
	keyPath    string
	keySubject string
}

const (
	defaultKeyPath    = "ssh/connector/v1"
	defaultKeySubject = "ed25519"
	defaultKeyAlg     = "ed25519"
)

// NewDstackDeriver creates a DstackDeriver using the dstack SDK default client.
// The SDK reads DSTACK_SIMULATOR_ENDPOINT; if unset it connects via
// /var/run/dstack.sock (the standard path inside a Phala Cloud CVM).
func NewDstackDeriver() *DstackDeriver {
	return &DstackDeriver{
		client:     dstacksdk.NewDstackClient(),
		keyPath:    defaultKeyPath,
		keySubject: defaultKeySubject,
	}
}

// DeriveIdentity derives a connector identity from the dstack TEE.
func (d *DstackDeriver) DeriveIdentity(ctx context.Context, connectorID string) (ConnectorIdentity, Attestation, error) {
	if connectorID == "" {
		return ConnectorIdentity{}, Attestation{}, fmt.Errorf("connectorID must not be empty")
	}

	// Step 1: Get deterministic Ed25519 seed from dstack.
	keyResp, err := d.client.GetKey(ctx, d.keyPath, d.keySubject, defaultKeyAlg)
	if err != nil {
		return ConnectorIdentity{}, Attestation{}, fmt.Errorf("get key: %w", err)
	}
	seed, err := keyResp.DecodeKey()
	if err != nil {
		return ConnectorIdentity{}, Attestation{}, fmt.Errorf("decode key: %w", err)
	}

	// Step 2: Derive Ed25519 identity from seed.
	pub, _, err := DeriveEd25519(seed)
	if err != nil {
		return ConnectorIdentity{}, Attestation{}, fmt.Errorf("derive ed25519: %w", err)
	}

	sshKey, err := SSHPublicKeyString(pub)
	if err != nil {
		return ConnectorIdentity{}, Attestation{}, fmt.Errorf("ssh public key: %w", err)
	}

	fingerprint := SSHFingerprint(sshKey)

	// Step 3: Bind the SSH public key into the attestation quote.
	// GetQuote accepts at most 64 raw bytes, so we SHA256-hash the key string
	// (32 bytes) — this preserves the binding while fitting the limit.
	keyHash := sha256.Sum256([]byte(sshKey))
	quoteResp, err := d.client.GetQuote(ctx, keyHash[:])
	if err != nil {
		return ConnectorIdentity{}, Attestation{}, fmt.Errorf("get quote: %w", err)
	}

	// Step 4: Fetch TCB info for measurement registers (MRTD, RTMR0-3).
	infoResp, err := d.client.Info(ctx)
	if err != nil {
		return ConnectorIdentity{}, Attestation{}, fmt.Errorf("get info: %w", err)
	}

	tcb, err := infoResp.DecodeTcbInfo()
	if err != nil {
		return ConnectorIdentity{}, Attestation{}, fmt.Errorf("decode tcb info: %w", err)
	}

	identity := ConnectorIdentity{
		ConnectorID:       connectorID,
		SSHPublicKey:      sshKey,
		PublicKeyHex:      hex.EncodeToString(pub),
		FingerprintSHA256: fingerprint,
	}

	attestation := Attestation{
		QuoteHex:                 quoteResp.Quote,
		EventLog:                 quoteResp.EventLog,
		MRTD:                     tcb.Mrtd,
		RTMR0:                    tcb.Rtmr0,
		RTMR1:                    tcb.Rtmr1,
		RTMR2:                    tcb.Rtmr2,
		RTMR3:                    tcb.Rtmr3,
		ReportDataExpectedSHA256: hex.EncodeToString(keyHash[:]),
	}

	return identity, attestation, nil
}
