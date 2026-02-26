package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

type Request struct {
	ID             string `json:"id"`
	ConnectorID    string `json:"connector_id"`
	DeviceID       string `json:"device_id"`
	OpenClawUserID string `json:"openclaw_user_id"`
}

type Bundle struct {
	Payload    map[string]any `json:"payload"`
	PayloadRaw []byte         `json:"-"`
	Signature  string         `json:"signature"`
	Alg        string         `json:"alg"`
	KID        string         `json:"kid"`
}

type SigningKeyInfo struct {
	KID          string `json:"kid"`
	Alg          string `json:"alg"`
	PublicKeyB64 string `json:"public_key_b64"`
}

type SigningKeyset struct {
	ActiveKID string           `json:"active_kid"`
	Keys      []SigningKeyInfo `json:"keys"`
}

type Client struct {
	baseURL string
	token   string
	http    *http.Client
}

func NewClient(baseURL string, token string) *Client {
	return &Client{
		baseURL: stringsTrimRightSlash(baseURL),
		token:   token,
		http: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

func (c *Client) PollPending(ctx context.Context, deviceID string) ([]Request, error) {
	escaped := url.PathEscape(deviceID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/v1/devices/"+escaped+"/pending-requests", nil)
	if err != nil {
		return nil, err
	}
	c.addHeaders(req)

	res, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("poll failed with status %d", res.StatusCode)
	}

	var out []Request
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *Client) PostLocalDecision(ctx context.Context, requestID string, approved bool) error {
	body := map[string]bool{"approved": approved}
	return c.postJSON(ctx, "/v1/connection-requests/"+url.PathEscape(requestID)+"/local-decision", body)
}

func (c *Client) GetAttestationBundle(ctx context.Context, requestID string) (Bundle, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/v1/connection-requests/"+url.PathEscape(requestID)+"/attestation-bundle", nil)
	if err != nil {
		return Bundle{}, err
	}
	c.addHeaders(req)

	res, err := c.http.Do(req)
	if err != nil {
		return Bundle{}, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return Bundle{}, fmt.Errorf("bundle fetch failed with status %d", res.StatusCode)
	}
	var raw struct {
		Payload   json.RawMessage `json:"payload"`
		Signature string          `json:"signature"`
		Alg       string          `json:"alg"`
		KID       string          `json:"kid"`
	}
	if err := json.NewDecoder(res.Body).Decode(&raw); err != nil {
		return Bundle{}, err
	}

	var payload map[string]any
	if err := json.Unmarshal(raw.Payload, &payload); err != nil {
		return Bundle{}, err
	}

	return Bundle{
		Payload:    payload,
		PayloadRaw: append([]byte(nil), raw.Payload...),
		Signature:  raw.Signature,
		Alg:        raw.Alg,
		KID:        raw.KID,
	}, nil
}

func (c *Client) GetSigningKeyset(ctx context.Context) (SigningKeyset, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/v1/signing-keys", nil)
	if err != nil {
		return SigningKeyset{}, err
	}
	c.addHeaders(req)

	res, err := c.http.Do(req)
	if err != nil {
		return SigningKeyset{}, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return SigningKeyset{}, fmt.Errorf("signing keys fetch failed with status %d", res.StatusCode)
	}

	var out SigningKeyset
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		return SigningKeyset{}, err
	}
	return out, nil
}

func (c *Client) PostResult(ctx context.Context, requestID string, status string, reasonCode string) error {
	body := map[string]string{
		"status":      status,
		"reason_code": reasonCode,
	}
	return c.postJSON(ctx, "/v1/connection-requests/"+url.PathEscape(requestID)+"/result", body)
}

func (c *Client) postJSON(ctx context.Context, path string, body any) error {
	raw, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	c.addHeaders(req)
	req.Header.Set("Content-Type", "application/json")

	res, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK && res.StatusCode != http.StatusCreated {
		return fmt.Errorf("request failed with status %d", res.StatusCode)
	}
	return nil
}

func (c *Client) addHeaders(req *http.Request) {
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
}

func stringsTrimRightSlash(v string) string {
	for len(v) > 0 && v[len(v)-1] == '/' {
		v = v[:len(v)-1]
	}
	return v
}
