package handlers

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"enclout/services/control-plane/internal/openclaw"
)

func TestInstallSessionStatusProgressionViaIntentAndPolling(t *testing.T) {
	api, store := newTestHandler(t)
	intentHandler := openclaw.NewIntentHandler(store)

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/openclaw/intents", intentHandler.Handle)
	mux.HandleFunc("/v1/install-sessions/", func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && !strings.Contains(strings.TrimPrefix(r.URL.Path, "/v1/install-sessions/"), "/"):
			api.GetInstallSession(w, r)
		case strings.HasSuffix(r.URL.Path, "/result") && r.Method == http.MethodPost:
			api.InstallSessionResult(w, r)
		default:
			http.NotFound(w, r)
		}
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	client := server.Client()

	create := doJSON(t, client, http.MethodPost, server.URL+"/v1/openclaw/intents", map[string]any{
		"intent":           "request_connector_install",
		"openclaw_user_id": "usr_1",
		"connector_id":     "conn_1",
		"device_id":        "dev_1",
		"source_channel":   "signal",
	})
	if create.status != http.StatusCreated {
		t.Fatalf("expected create status 201, got %d body=%s", create.status, string(create.body))
	}
	var createOut map[string]any
	if err := json.Unmarshal(create.body, &createOut); err != nil {
		t.Fatalf("decode create body: %v", err)
	}
	sessionID, _ := createOut["install_session_id"].(string)
	if sessionID == "" {
		t.Fatalf("expected install_session_id in create response")
	}

	requested := doJSON(t, client, http.MethodGet, server.URL+"/v1/install-sessions/"+sessionID, nil)
	if requested.status != http.StatusOK {
		t.Fatalf("expected requested poll status 200, got %d body=%s", requested.status, string(requested.body))
	}
	var requestedOut map[string]any
	if err := json.Unmarshal(requested.body, &requestedOut); err != nil {
		t.Fatalf("decode requested body: %v", err)
	}
	if requestedOut["status"] != "requested" {
		t.Fatalf("expected requested state, got %#v", requestedOut["status"])
	}

	approve := doJSON(t, client, http.MethodPost, server.URL+"/v1/openclaw/intents", map[string]any{
		"intent":             "approve_install_session",
		"install_session_id": sessionID,
		"approved":           true,
	})
	if approve.status != http.StatusOK {
		t.Fatalf("expected approve status 200, got %d body=%s", approve.status, string(approve.body))
	}

	approved := doJSON(t, client, http.MethodGet, server.URL+"/v1/install-sessions/"+sessionID, nil)
	if approved.status != http.StatusOK {
		t.Fatalf("expected approved poll status 200, got %d body=%s", approved.status, string(approved.body))
	}
	var approvedOut map[string]any
	if err := json.Unmarshal(approved.body, &approvedOut); err != nil {
		t.Fatalf("decode approved body: %v", err)
	}
	if approvedOut["status"] != "approved" {
		t.Fatalf("expected approved state, got %#v", approvedOut["status"])
	}

	result := doJSON(t, client, http.MethodPost, server.URL+"/v1/install-sessions/"+sessionID+"/result", map[string]any{
		"status": "installed",
	})
	if result.status != http.StatusOK {
		t.Fatalf("expected result status 200, got %d body=%s", result.status, string(result.body))
	}

	installed := doJSON(t, client, http.MethodGet, server.URL+"/v1/install-sessions/"+sessionID, nil)
	if installed.status != http.StatusOK {
		t.Fatalf("expected installed poll status 200, got %d body=%s", installed.status, string(installed.body))
	}
	var installedOut map[string]any
	if err := json.Unmarshal(installed.body, &installedOut); err != nil {
		t.Fatalf("decode installed body: %v", err)
	}
	if installedOut["status"] != "installed" {
		t.Fatalf("expected installed state, got %#v", installedOut["status"])
	}
}

type jsonResponse struct {
	status int
	body   []byte
}

func doJSON(t *testing.T, client *http.Client, method string, url string, body map[string]any) jsonResponse {
	t.Helper()

	var raw []byte
	if body != nil {
		var err error
		raw, err = json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
	}

	req, err := http.NewRequest(method, url, bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request %s %s: %v", method, url, err)
	}
	defer resp.Body.Close()

	out := jsonResponse{status: resp.StatusCode}
	out.body, err = io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return out
}
