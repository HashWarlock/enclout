package attestation

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const maxErrorBodyBytes = 4096

// HTTPDCAPVerifier calls a remote DCAP verification service over HTTP.
type HTTPDCAPVerifier struct {
	endpoint string
	token    string
	client   *http.Client
}

type dcapVerifyRequest struct {
	QuoteHex string `json:"quote_hex"`
}

type dcapVerifyResponse struct {
	QuoteValid      bool                `json:"quote_valid"`
	QEIdentityValid bool                `json:"qe_identity_valid"`
	TCBValid        bool                `json:"tcb_valid"`
	ReportDataHex   string              `json:"report_data_hex"`
	ReportData      string              `json:"report_data"`
	NestedResult    *dcapVerifyResponse `json:"result"`
}

// NewHTTPDCAPVerifier creates a verifier that POSTs quote data to the given
// endpoint. A zero or negative timeout defaults to 10 seconds.
func NewHTTPDCAPVerifier(endpoint string, token string, timeout time.Duration) (HTTPDCAPVerifier, error) {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return HTTPDCAPVerifier{}, fmt.Errorf("missing DCAP verifier endpoint")
	}
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return HTTPDCAPVerifier{
		endpoint: endpoint,
		token:    strings.TrimSpace(token),
		client: &http.Client{
			Timeout: timeout,
		},
	}, nil
}

// Verify sends the quote hex to the DCAP verifier service and parses the
// response into a DCAPResult.
func (v HTTPDCAPVerifier) Verify(ctx context.Context, quoteHex string) (DCAPResult, error) {
	if strings.TrimSpace(quoteHex) == "" {
		return DCAPResult{}, fmt.Errorf("missing quote_hex")
	}

	rawBody, err := json.Marshal(dcapVerifyRequest{QuoteHex: quoteHex})
	if err != nil {
		return DCAPResult{}, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, v.endpoint, bytes.NewReader(rawBody))
	if err != nil {
		return DCAPResult{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	if v.token != "" {
		req.Header.Set("Authorization", "Bearer "+v.token)
	}

	res, err := v.client.Do(req)
	if err != nil {
		return DCAPResult{}, err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(res.Body, maxErrorBodyBytes))
		return DCAPResult{}, fmt.Errorf("dcap verifier returned status %d: %s", res.StatusCode, strings.TrimSpace(string(body)))
	}

	var decoded dcapVerifyResponse
	if err := json.NewDecoder(res.Body).Decode(&decoded); err != nil {
		return DCAPResult{}, err
	}

	src := decoded
	if decoded.NestedResult != nil {
		src = *decoded.NestedResult
	}

	reportDataHex := src.ReportDataHex
	if strings.TrimSpace(reportDataHex) == "" {
		reportDataHex = src.ReportData
	}
	reportData, err := parseReportDataHex(reportDataHex)
	if err != nil {
		return DCAPResult{}, err
	}

	return DCAPResult{
		QuoteValid:      src.QuoteValid,
		QEIdentityValid: src.QEIdentityValid,
		TCBValid:        src.TCBValid,
		ReportData:      reportData,
	}, nil
}

func parseReportDataHex(raw string) ([64]byte, error) {
	var out [64]byte

	raw = strings.TrimSpace(raw)
	raw = strings.TrimPrefix(raw, "0x")
	raw = strings.TrimPrefix(raw, "0X")
	if raw == "" {
		return out, fmt.Errorf("missing report_data_hex")
	}

	decoded, err := hex.DecodeString(raw)
	if err != nil {
		return out, fmt.Errorf("decode report_data_hex: %w", err)
	}

	switch len(decoded) {
	case 32:
		// Some verifier APIs return only the SHA-256 portion of REPORT_DATA.
		copy(out[:32], decoded)
	case 64:
		copy(out[:], decoded)
	default:
		return out, fmt.Errorf("report_data length must be 32 or 64 bytes, got %d", len(decoded))
	}

	return out, nil
}
