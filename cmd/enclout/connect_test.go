package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"enclout/internal/client"
)

func TestPollUntilTerminal_RevokedIsTerminal(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatalf("expected GET, got %s", r.Method)
		}
		if r.URL.Path != "/v1/requests/req_1" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"ID":"req_1",
			"RequesterID":"user_1",
			"DeviceID":"dev_1",
			"ConnectorID":"conn_1",
			"Source":"cli",
			"Status":"revoked",
			"CreatedAt":"2026-04-08T00:00:00Z",
			"ExpiresAt":"2026-04-08T00:05:00Z",
			"Nonce":"n1",
			"ReasonCode":""
		}`))
	}))
	defer server.Close()

	c := client.New(server.URL, "")

	start := time.Now()
	req, err := pollUntilTerminal(context.Background(), c, "req_1")
	if err != nil {
		t.Fatalf("pollUntilTerminal: %v", err)
	}

	if req.Status != "revoked" {
		t.Fatalf("expected status revoked, got %q", req.Status)
	}

	// pollUntilTerminal currently polls every 2s; this guards against accidental non-terminal loops.
	if time.Since(start) > 4*time.Second {
		t.Fatalf("poll took too long, revoked may not be treated as terminal")
	}
}

