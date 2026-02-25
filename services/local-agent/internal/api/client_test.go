package api

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPollPendingRequests(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `[{"id":"req_1","connector_id":"conn_1","device_id":"dev_1","openclaw_user_id":"usr_1"}]`)
	}))
	defer srv.Close()

	client := NewClient(srv.URL, "token")
	items, err := client.PollPending(context.Background(), "dev_1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("expected 1 item, got %d", len(items))
	}
	if items[0].ID != "req_1" {
		t.Fatalf("unexpected request id %q", items[0].ID)
	}
}

func TestPostLocalDecision(t *testing.T) {
	var gotPath string
	var gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		raw, _ := io.ReadAll(r.Body)
		gotBody = string(raw)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := NewClient(srv.URL, "token")
	err := client.PostLocalDecision(context.Background(), "req_7", true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotPath != "/v1/connection-requests/req_7/local-decision" {
		t.Fatalf("unexpected path: %s", gotPath)
	}
	if !strings.Contains(gotBody, `"approved":true`) {
		t.Fatalf("unexpected body: %s", gotBody)
	}
}
