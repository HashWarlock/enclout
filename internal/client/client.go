package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// APIError represents an HTTP error from the server, wrapping the status code
// and any error message returned in the JSON body.
type APIError struct {
	StatusCode int
	Message    string
}

func (e *APIError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("api: HTTP %d: %s", e.StatusCode, e.Message)
	}
	return fmt.Sprintf("api: HTTP %d", e.StatusCode)
}

// RequestResponse mirrors access.ConnectionRequest as serialized by the server.
// Field names match Go's default JSON encoding (no json tags on the struct).
type RequestResponse struct {
	ID          string    `json:"ID"`
	RequesterID string    `json:"RequesterID"`
	DeviceID    string    `json:"DeviceID"`
	ConnectorID string    `json:"ConnectorID"`
	Source      string    `json:"Source"`
	Status      string    `json:"Status"`
	CreatedAt   time.Time `json:"CreatedAt"`
	ExpiresAt   time.Time `json:"ExpiresAt"`
	Nonce       string    `json:"Nonce"`
	ReasonCode  string    `json:"ReasonCode"`
}

// SessionResponse mirrors access.InstallSession as serialized by the server.
type SessionResponse struct {
	ID          string    `json:"ID"`
	RequesterID string    `json:"RequesterID"`
	DeviceID    string    `json:"DeviceID"`
	ConnectorID string    `json:"ConnectorID"`
	Source      string    `json:"Source"`
	Status      string    `json:"Status"`
	TokenDigest string    `json:"TokenDigest"`
	CreatedAt   time.Time `json:"CreatedAt"`
	ExpiresAt   time.Time `json:"ExpiresAt"`
	ReasonCode  string    `json:"ReasonCode"`
}

// SessionCreateResponse is the response from POST /v1/sessions.
type SessionCreateResponse struct {
	Session      SessionResponse `json:"session"`
	InstallToken string          `json:"install_token"`
	InstallURL   string          `json:"install_url"`
}

// SigningKeyset describes the server's signing keys.
type SigningKeyset struct {
	ActiveKID string          `json:"active_kid"`
	Keys      []PublicKeyInfo `json:"keys"`
}

// PublicKeyInfo describes a single public key.
type PublicKeyInfo struct {
	KID          string `json:"kid"`
	Alg          string `json:"alg"`
	PublicKeyB64 string `json:"public_key_b64"`
}

// ConnectorResponse mirrors store.ConnectorBundle as serialized by the server.
type ConnectorResponse struct {
	ConnectorID   string    `json:"ConnectorID"`
	SSHPublicKey  string    `json:"SSHPublicKey"`
	QuoteHex      string    `json:"QuoteHex"`
	EventLog      string    `json:"EventLog"`
	MRTD          string    `json:"MRTD"`
	RTMR0         string    `json:"RTMR0"`
	RTMR1         string    `json:"RTMR1"`
	RTMR2         string    `json:"RTMR2"`
	RTMR3         string    `json:"RTMR3"`
	PolicyVersion string    `json:"PolicyVersion"`
	Info          string    `json:"Info"`
	RegisteredAt  time.Time `json:"RegisteredAt"`
}

// ListRequestsOptions specifies optional filters and pagination for request history.
type ListRequestsOptions struct {
	DeviceID    string
	RequesterID string
	Status      string
	Limit       int
	Offset      int
}

// AuditEntryResponse mirrors store.AuditEntry as serialized by the server.
type AuditEntryResponse struct {
	ID         int64     `json:"ID"`
	EntityType string    `json:"EntityType"`
	EntityID   string    `json:"EntityID"`
	Action     string    `json:"Action"`
	Actor      string    `json:"Actor"`
	Detail     string    `json:"Detail"`
	CreatedAt  time.Time `json:"CreatedAt"`
}

// ListAuditOptions specifies optional filters and pagination for audit queries.
type ListAuditOptions struct {
	EntityType string
	EntityID   string
	Since      string
	Until      string
	Limit      int
	Offset     int
}

// Client is a typed HTTP client for the enclout API.
type Client struct {
	baseURL    string
	token      string
	httpClient *http.Client
}

// New creates a new Client targeting the given baseURL with the given auth token.
func New(baseURL, token string) *Client {
	return &Client{
		baseURL: trimRightSlash(baseURL),
		token:   token,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// --- Request operations ---

// CreateRequest creates a new connection request.
func (c *Client) CreateRequest(ctx context.Context, requesterID, deviceID, connectorID, source string, ttl time.Duration) (RequestResponse, error) {
	body := map[string]string{
		"requester_id": requesterID,
		"device_id":    deviceID,
		"connector_id": connectorID,
		"source":       source,
	}
	var resp RequestResponse
	if err := c.doJSON(ctx, http.MethodPost, "/v1/requests", body, &resp); err != nil {
		return RequestResponse{}, err
	}
	return resp, nil
}

// GetRequest retrieves a connection request by ID.
func (c *Client) GetRequest(ctx context.Context, id string) (RequestResponse, error) {
	var resp RequestResponse
	if err := c.doJSON(ctx, http.MethodGet, "/v1/requests/"+url.PathEscape(id), nil, &resp); err != nil {
		return RequestResponse{}, err
	}
	return resp, nil
}

// ListRequests retrieves connection requests with optional filters and pagination.
func (c *Client) ListRequests(ctx context.Context, opts *ListRequestsOptions) ([]RequestResponse, error) {
	path := "/v1/requests"
	if opts != nil {
		values := url.Values{}
		if opts.DeviceID != "" {
			values.Set("device_id", opts.DeviceID)
		}
		if opts.RequesterID != "" {
			values.Set("requester_id", opts.RequesterID)
		}
		if opts.Status != "" {
			values.Set("status", opts.Status)
		}
		if opts.Limit > 0 {
			values.Set("limit", fmt.Sprintf("%d", opts.Limit))
		}
		if opts.Offset > 0 {
			values.Set("offset", fmt.Sprintf("%d", opts.Offset))
		}
		if encoded := values.Encode(); encoded != "" {
			path += "?" + encoded
		}
	}

	var resp []RequestResponse
	if err := c.doJSON(ctx, http.MethodGet, path, nil, &resp); err != nil {
		return nil, err
	}
	return resp, nil
}

// PostDecision sends an approval or denial decision for a connection request.
func (c *Client) PostDecision(ctx context.Context, id string, approved bool) error {
	body := map[string]bool{"approved": approved}
	return c.doJSON(ctx, http.MethodPost, "/v1/requests/"+url.PathEscape(id)+"/decision", body, nil)
}

// RevokeRequest revokes a connection request by ID.
func (c *Client) RevokeRequest(ctx context.Context, id string) error {
	return c.doJSON(ctx, http.MethodPost, "/v1/requests/"+url.PathEscape(id)+"/revoke", nil, nil)
}

// PostResult sets the final result status for an approved connection request.
func (c *Client) PostResult(ctx context.Context, id, status, reasonCode string) error {
	body := map[string]string{
		"status":      status,
		"reason_code": reasonCode,
	}
	return c.doJSON(ctx, http.MethodPost, "/v1/requests/"+url.PathEscape(id)+"/result", body, nil)
}

// GetBundle retrieves the signed attestation bundle for an approved request.
func (c *Client) GetBundle(ctx context.Context, id string) (json.RawMessage, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/v1/requests/"+url.PathEscape(id)+"/bundle", nil)
	if err != nil {
		return nil, err
	}
	c.setAuth(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, parseAPIError(resp)
	}

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(raw), nil
}

// ListPending retrieves all pending connection requests for a device.
func (c *Client) ListPending(ctx context.Context, deviceID string) ([]RequestResponse, error) {
	var resp []RequestResponse
	if err := c.doJSON(ctx, http.MethodGet, "/v1/devices/"+url.PathEscape(deviceID)+"/pending", nil, &resp); err != nil {
		return nil, err
	}
	return resp, nil
}

// ListAudit retrieves audit entries with optional filters and pagination.
func (c *Client) ListAudit(ctx context.Context, opts *ListAuditOptions) ([]AuditEntryResponse, error) {
	path := "/v1/audit"
	if opts != nil {
		values := url.Values{}
		if opts.EntityType != "" {
			values.Set("entity_type", opts.EntityType)
		}
		if opts.EntityID != "" {
			values.Set("entity_id", opts.EntityID)
		}
		if opts.Since != "" {
			values.Set("since", opts.Since)
		}
		if opts.Until != "" {
			values.Set("until", opts.Until)
		}
		if opts.Limit > 0 {
			values.Set("limit", fmt.Sprintf("%d", opts.Limit))
		}
		if opts.Offset > 0 {
			values.Set("offset", fmt.Sprintf("%d", opts.Offset))
		}
		if encoded := values.Encode(); encoded != "" {
			path += "?" + encoded
		}
	}

	var resp []AuditEntryResponse
	if err := c.doJSON(ctx, http.MethodGet, path, nil, &resp); err != nil {
		return nil, err
	}
	return resp, nil
}

// --- Session operations ---

// CreateSession creates a new install session.
func (c *Client) CreateSession(ctx context.Context, requesterID, source string, ttl time.Duration) (SessionCreateResponse, error) {
	body := map[string]string{
		"requester_id": requesterID,
		"source":       source,
	}
	var resp SessionCreateResponse
	if err := c.doJSON(ctx, http.MethodPost, "/v1/sessions", body, &resp); err != nil {
		return SessionCreateResponse{}, err
	}
	return resp, nil
}

// GetSession retrieves an install session by ID.
func (c *Client) GetSession(ctx context.Context, id string) (SessionResponse, error) {
	var resp SessionResponse
	if err := c.doJSON(ctx, http.MethodGet, "/v1/sessions/"+url.PathEscape(id), nil, &resp); err != nil {
		return SessionResponse{}, err
	}
	return resp, nil
}

// ApproveSession approves an install session.
func (c *Client) ApproveSession(ctx context.Context, id string) error {
	body := map[string]bool{"approved": true}
	return c.doJSON(ctx, http.MethodPost, "/v1/sessions/"+url.PathEscape(id)+"/approve", body, nil)
}

// RegisterIdentity registers a connector identity on an install session.
func (c *Client) RegisterIdentity(ctx context.Context, id, connectorID, deviceID string) error {
	body := map[string]string{
		"connector_id": connectorID,
		"device_id":    deviceID,
	}
	return c.doJSON(ctx, http.MethodPost, "/v1/sessions/"+url.PathEscape(id)+"/register", body, nil)
}

// SessionResult sets the final result status on an install session.
func (c *Client) SessionResult(ctx context.Context, id, status, reason string) error {
	body := map[string]string{
		"status":      status,
		"reason_code": reason,
	}
	return c.doJSON(ctx, http.MethodPost, "/v1/sessions/"+url.PathEscape(id)+"/result", body, nil)
}

// RedeemToken redeems an install token digest and returns the associated session.
func (c *Client) RedeemToken(ctx context.Context, tokenDigest string) (SessionResponse, error) {
	body := map[string]string{
		"token_digest": tokenDigest,
	}
	var resp SessionResponse
	if err := c.doJSON(ctx, http.MethodPost, "/v1/sessions/redeem", body, &resp); err != nil {
		return SessionResponse{}, err
	}
	return resp, nil
}

// --- Signing keys ---

// GetSigningKeys returns the server's signing keyset.
func (c *Client) GetSigningKeys(ctx context.Context) (SigningKeyset, error) {
	var resp SigningKeyset
	if err := c.doJSON(ctx, http.MethodGet, "/v1/signing-keys", nil, &resp); err != nil {
		return SigningKeyset{}, err
	}
	return resp, nil
}

// --- Connector registration ---

// RegisterConnector registers a connector bundle with the server.
func (c *Client) RegisterConnector(ctx context.Context, bundle interface{}) error {
	return c.doJSON(ctx, http.MethodPost, "/v1/connectors/register", bundle, nil)
}

// ListConnectors lists all registered connectors.
func (c *Client) ListConnectors(ctx context.Context) ([]ConnectorResponse, error) {
	var resp []ConnectorResponse
	if err := c.doJSON(ctx, http.MethodGet, "/v1/connectors", nil, &resp); err != nil {
		return nil, err
	}
	return resp, nil
}

// GetConnector returns a registered connector by ID.
func (c *Client) GetConnector(ctx context.Context, id string) (ConnectorResponse, error) {
	var resp ConnectorResponse
	if err := c.doJSON(ctx, http.MethodGet, "/v1/connectors/"+url.PathEscape(id), nil, &resp); err != nil {
		return ConnectorResponse{}, err
	}
	return resp, nil
}

// --- internals ---

// doJSON performs an HTTP request, optionally encoding reqBody as JSON, and
// optionally decoding the JSON response into respBody.
func (c *Client) doJSON(ctx context.Context, method, path string, reqBody, respBody any) error {
	var bodyReader io.Reader
	if reqBody != nil {
		data, err := json.Marshal(reqBody)
		if err != nil {
			return fmt.Errorf("marshal request body: %w", err)
		}
		bodyReader = bytes.NewReader(data)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bodyReader)
	if err != nil {
		return err
	}
	c.setAuth(req)
	if reqBody != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return parseAPIError(resp)
	}

	if respBody != nil {
		if err := json.NewDecoder(resp.Body).Decode(respBody); err != nil {
			return fmt.Errorf("decode response: %w", err)
		}
	}
	return nil
}

func (c *Client) setAuth(req *http.Request) {
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
}

func parseAPIError(resp *http.Response) *APIError {
	ae := &APIError{StatusCode: resp.StatusCode}
	var errBody struct {
		Error string `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&errBody); err == nil && errBody.Error != "" {
		ae.Message = errBody.Error
	}
	return ae
}

func trimRightSlash(v string) string {
	return strings.TrimRight(v, "/")
}
