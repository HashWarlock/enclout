package verify

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestHTTPDCAPVerifierVerifySuccess(t *testing.T) {
	expected := ComputeExpectedReportData("ssh-ed25519 AAAATEST connector@tee")
	expectedHex := hex.EncodeToString(expected[:])

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST, got %s", r.Method)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer token-123" {
			t.Fatalf("unexpected auth header: %q", got)
		}

		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("failed to decode request body: %v", err)
		}
		if body["quote_hex"] != "abcd" {
			t.Fatalf("expected quote_hex abcd, got %v", body["quote_hex"])
		}

		_ = json.NewEncoder(w).Encode(map[string]any{
			"quote_valid":       true,
			"qe_identity_valid": true,
			"tcb_valid":         true,
			"report_data_hex":   expectedHex,
		})
	}))
	defer srv.Close()

	verifier, err := NewHTTPDCAPVerifier(srv.URL, "token-123", 2*time.Second)
	if err != nil {
		t.Fatalf("unexpected constructor error: %v", err)
	}

	got, err := verifier.Verify(context.Background(), "abcd")
	if err != nil {
		t.Fatalf("unexpected verify error: %v", err)
	}
	if !got.QuoteValid || !got.QEIdentityValid || !got.TCBValid {
		t.Fatalf("expected all strict checks true, got %+v", got)
	}
	if got.ReportData != expected {
		t.Fatalf("report_data mismatch")
	}
}

func TestHTTPDCAPVerifierSupportsNestedAnd32ByteReportData(t *testing.T) {
	seedOnly := make([]byte, 32)
	for i := 0; i < 32; i++ {
		seedOnly[i] = byte(i + 1)
	}
	seedHex := hex.EncodeToString(seedOnly)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"result": map[string]any{
				"quote_valid":       true,
				"qe_identity_valid": true,
				"tcb_valid":         true,
				"report_data_hex":   seedHex,
			},
		})
	}))
	defer srv.Close()

	verifier, err := NewHTTPDCAPVerifier(srv.URL, "", 2*time.Second)
	if err != nil {
		t.Fatalf("unexpected constructor error: %v", err)
	}

	got, err := verifier.Verify(context.Background(), "abcd")
	if err != nil {
		t.Fatalf("unexpected verify error: %v", err)
	}
	if got.ReportData[0] != 1 || got.ReportData[31] != 32 {
		t.Fatalf("unexpected first 32 bytes in report data")
	}
	for i := 32; i < 64; i++ {
		if got.ReportData[i] != 0 {
			t.Fatalf("expected zero padding at byte %d", i)
		}
	}
}

func TestHTTPDCAPVerifierVerifyNon200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "backend unavailable", http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	verifier, err := NewHTTPDCAPVerifier(srv.URL, "", 2*time.Second)
	if err != nil {
		t.Fatalf("unexpected constructor error: %v", err)
	}

	_, err = verifier.Verify(context.Background(), "abcd")
	if err == nil {
		t.Fatalf("expected non-200 error")
	}
	if !strings.Contains(err.Error(), "status 503") {
		t.Fatalf("expected status code in error, got %v", err)
	}
}

func TestNewHTTPDCAPVerifierRequiresEndpoint(t *testing.T) {
	_, err := NewHTTPDCAPVerifier("", "", time.Second)
	if err == nil {
		t.Fatalf("expected missing endpoint error")
	}
}
