package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSigningKeysReturnsActiveKeyset(t *testing.T) {
	handler, _ := newTestHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/v1/signing-keys", nil)
	rr := httptest.NewRecorder()
	handler.SigningKeys(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), `"active_kid":"v1"`) {
		t.Fatalf("expected active kid in response, got %s", rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), `"public_key_b64"`) {
		t.Fatalf("expected public key in response, got %s", rr.Body.String())
	}
}
