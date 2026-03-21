package identity

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// DstackClient communicates with the dstack TEE runtime to derive keys,
// get attestation quotes, and retrieve app metadata.
type DstackClient struct {
	httpClient *http.Client
	endpoint   string
}

// NewDstackClient creates a dstack client pointing at the given endpoint.
// The endpoint is typically "http://localhost:8090" or a Unix socket path.
func NewDstackClient(endpoint string) *DstackClient {
	return &DstackClient{
		httpClient: &http.Client{},
		endpoint:   endpoint,
	}
}

// getKeyRequest is the JSON body for /GetKey.
type getKeyRequest struct {
	Path    string `json:"path"`
	Purpose string `json:"purpose"`
}

// getKeyResponse is the JSON response from /GetKey.
type getKeyResponse struct {
	Key            string   `json:"key"`
	SignatureChain []string `json:"signature_chain"`
}

// GetKey requests deterministic key derivation from dstack.
// The returned bytes are the raw key material (decoded from hex).
func (c *DstackClient) GetKey(ctx context.Context, path, subject string) ([]byte, error) {
	req := getKeyRequest{Path: path, Purpose: subject}
	var resp getKeyResponse
	if err := c.post(ctx, "/GetKey", req, &resp); err != nil {
		return nil, fmt.Errorf("dstack GetKey: %w", err)
	}
	key, err := hex.DecodeString(resp.Key)
	if err != nil {
		return nil, fmt.Errorf("dstack GetKey: invalid hex key: %w", err)
	}
	return key, nil
}

// getQuoteRequest is the JSON body for /GetQuote.
type getQuoteRequest struct {
	ReportData string `json:"report_data"`
}

// getQuoteResponse is the JSON response from /GetQuote.
type getQuoteResponse struct {
	Quote    string `json:"quote"`
	EventLog string `json:"event_log"`
	Error    string `json:"error,omitempty"`
}

// GetQuote gets an attestation quote binding to reportData.
// reportData is the raw string to bind into the quote; it is hex-encoded
// before sending to the dstack API (matching the Node.js SDK's to_hex behavior).
func (c *DstackClient) GetQuote(ctx context.Context, reportData string) (quoteHex, eventLog string, err error) {
	hexData := hex.EncodeToString([]byte(reportData))
	req := getQuoteRequest{ReportData: hexData}
	var resp getQuoteResponse
	if err := c.post(ctx, "/GetQuote", req, &resp); err != nil {
		return "", "", fmt.Errorf("dstack GetQuote: %w", err)
	}
	if resp.Error != "" {
		return "", "", fmt.Errorf("dstack GetQuote: %s", resp.Error)
	}
	return resp.Quote, resp.EventLog, nil
}

// infoResponse is the JSON response from /Info.
type infoResponse struct {
	AppID      string `json:"app_id"`
	InstanceID string `json:"instance_id"`
	AppName    string `json:"app_name"`
	TCBInfo    string `json:"tcb_info"`
}

// Info returns dstack app metadata.
func (c *DstackClient) Info(ctx context.Context) (DstackInfo, error) {
	var resp infoResponse
	if err := c.post(ctx, "/Info", struct{}{}, &resp); err != nil {
		return DstackInfo{}, fmt.Errorf("dstack Info: %w", err)
	}
	return DstackInfo{
		AppID:      resp.AppID,
		InstanceID: resp.InstanceID,
		AppName:    resp.AppName,
		TCBInfo:    resp.TCBInfo,
	}, nil
}

// post sends a JSON POST request to the dstack endpoint.
func (c *DstackClient) post(ctx context.Context, path string, body any, result any) error {
	payload, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}

	url := c.endpoint + path
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("send request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(respBody))
	}

	if err := json.Unmarshal(respBody, result); err != nil {
		return fmt.Errorf("unmarshal response: %w", err)
	}
	return nil
}

// DstackDeriver implements Deriver using the dstack TEE runtime.
type DstackDeriver struct {
	Client    *DstackClient
	KeyPath   string
	KeySubject string
}

const (
	defaultKeyPath    = "ssh/connector/v1"
	defaultKeySubject = "ed25519"
)

// NewDstackDeriver creates a DstackDeriver with default key path and subject.
func NewDstackDeriver(client *DstackClient) *DstackDeriver {
	return &DstackDeriver{
		Client:     client,
		KeyPath:    defaultKeyPath,
		KeySubject: defaultKeySubject,
	}
}

// DeriveIdentity derives a connector identity from the dstack TEE.
func (d *DstackDeriver) DeriveIdentity(ctx context.Context, connectorID string) (ConnectorIdentity, Attestation, error) {
	if connectorID == "" {
		return ConnectorIdentity{}, Attestation{}, fmt.Errorf("connectorID must not be empty")
	}

	// Step 1: Get deterministic seed from dstack.
	seed, err := d.Client.GetKey(ctx, d.KeyPath, d.KeySubject)
	if err != nil {
		return ConnectorIdentity{}, Attestation{}, fmt.Errorf("get key: %w", err)
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

	// Step 3: Get attestation quote bound to the SSH public key.
	quoteHex, eventLog, err := d.Client.GetQuote(ctx, sshKey)
	if err != nil {
		return ConnectorIdentity{}, Attestation{}, fmt.Errorf("get quote: %w", err)
	}

	// Step 4: Get dstack info (not used in identity, but for attestation metadata).
	_, err = d.Client.Info(ctx)
	if err != nil {
		return ConnectorIdentity{}, Attestation{}, fmt.Errorf("get info: %w", err)
	}

	// Compute the expected SHA256 of report_data (the SSH public key hex-encoded).
	reportDataHex := hex.EncodeToString([]byte(sshKey))
	rdHash := sha256.Sum256([]byte(reportDataHex))

	identity := ConnectorIdentity{
		ConnectorID:       connectorID,
		SSHPublicKey:      sshKey,
		PublicKeyHex:      hex.EncodeToString(pub),
		FingerprintSHA256: fingerprint,
	}

	attestation := Attestation{
		QuoteHex:                 quoteHex,
		EventLog:                 eventLog,
		ReportDataExpectedSHA256: hex.EncodeToString(rdHash[:]),
	}

	return identity, attestation, nil
}
