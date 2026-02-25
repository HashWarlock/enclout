package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRequireBearerTokenRejectsMissingToken(t *testing.T) {
	nextCalled := false
	handler := RequireBearerToken("secret-token", func(_ http.ResponseWriter, _ *http.Request) {
		nextCalled = true
	})

	req := httptest.NewRequest(http.MethodGet, "/v1/example", nil)
	rr := httptest.NewRecorder()
	handler(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for missing auth, got %d", rr.Code)
	}
	if nextCalled {
		t.Fatalf("expected protected handler to not execute")
	}
}

func TestRequireBearerTokenAllowsValidToken(t *testing.T) {
	nextCalled := false
	handler := RequireBearerToken("secret-token", func(w http.ResponseWriter, _ *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/v1/example", nil)
	req.Header.Set("Authorization", "Bearer secret-token")
	rr := httptest.NewRecorder()
	handler(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 for valid auth, got %d", rr.Code)
	}
	if !nextCalled {
		t.Fatalf("expected protected handler to execute")
	}
}
