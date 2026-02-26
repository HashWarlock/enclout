package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"enclout/services/local-agent/internal/install"
)

func TestDefaultPlistPath(t *testing.T) {
	got := defaultPlistPath("/Users/alice", "ai.enclout.agent")
	want := "/Users/alice/Library/LaunchAgents/ai.enclout.agent.plist"
	if got != want {
		t.Fatalf("unexpected plist path: got %q want %q", got, want)
	}
}

func TestDefaultSystemdUnitPath(t *testing.T) {
	got := defaultSystemdUnitPath("/home/alice", "ai.enclout.agent")
	want := "/home/alice/.config/systemd/user/ai.enclout.agent.service"
	if got != want {
		t.Fatalf("unexpected unit path: got %q want %q", got, want)
	}
}

func TestBuildInstallEnvIncludesRequiredAndOptional(t *testing.T) {
	env := map[string]string{
		"AGENT_TOKEN":                     "tok",
		"DCAP_VERIFIER_TIMEOUT":           "15s",
		"CONTROL_PLANE_SIGNING_KEYS_JSON": `{"v1":"AAAA"}`,
		"SIGNING_KEYSET_CACHE_TTL":        "5m",
	}

	got := buildInstallEnv("alice", "http://127.0.0.1:8080", "http://127.0.0.1:9000", func(key string) string {
		return env[key]
	})

	if got["CONTROL_PLANE_URL"] != "http://127.0.0.1:8080" {
		t.Fatalf("missing CONTROL_PLANE_URL")
	}
	if got["LOCAL_USERNAME"] != "alice" {
		t.Fatalf("missing LOCAL_USERNAME")
	}
	if got["DCAP_VERIFIER_URL"] != "http://127.0.0.1:9000" {
		t.Fatalf("missing DCAP_VERIFIER_URL")
	}
	if got["AGENT_TOKEN"] != "tok" {
		t.Fatalf("missing optional AGENT_TOKEN")
	}
	if got["SIGNING_KEYSET_CACHE_TTL"] != "5m" {
		t.Fatalf("missing optional SIGNING_KEYSET_CACHE_TTL")
	}
}

type fakeLaunchdInstaller struct {
	mu    sync.Mutex
	calls int
	last  install.ServiceConfig
}

func (f *fakeLaunchdInstaller) InstallAndStart(_ context.Context, cfg install.ServiceConfig) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.last = cfg
	return nil
}

type installSessionState struct {
	ID             string `json:"id"`
	OpenClawUserID string `json:"openclaw_user_id"`
	DeviceID       string `json:"device_id"`
	ConnectorID    string `json:"connector_id"`
	SourceChannel  string `json:"source_channel"`
	Status         string `json:"status"`
	ReasonCode     string `json:"reason_code,omitempty"`
}

type fakeControlPlaneInstallAPI struct {
	mu       sync.Mutex
	nextID   int
	nextTok  int
	sessions map[string]installSessionState
	tokens   map[string]string
}

func newFakeControlPlaneInstallAPI() *fakeControlPlaneInstallAPI {
	return &fakeControlPlaneInstallAPI{
		sessions: map[string]installSessionState{},
		tokens:   map[string]string{},
	}
}

func (f *fakeControlPlaneInstallAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/v1/openclaw/intents":
		f.handleIntent(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/v1/install-sessions/redeem":
		f.handleRedeem(w, r)
	case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/v1/install-sessions/") && strings.HasSuffix(r.URL.Path, "/result"):
		f.handleResult(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (f *fakeControlPlaneInstallAPI) handleIntent(w http.ResponseWriter, r *http.Request) {
	var body map[string]any
	_ = json.NewDecoder(r.Body).Decode(&body)
	intent, _ := body["intent"].(string)

	switch intent {
	case "request_connector_install":
		f.mu.Lock()
		defer f.mu.Unlock()
		f.nextID++
		f.nextTok++
		id := fmt.Sprintf("ins_%d", f.nextID)
		tok := fmt.Sprintf("tok_%d", f.nextTok)
		session := installSessionState{
			ID:             id,
			OpenClawUserID: stringFromMap(body, "openclaw_user_id"),
			DeviceID:       stringFromMap(body, "device_id"),
			ConnectorID:    stringFromMap(body, "connector_id"),
			SourceChannel:  stringFromMap(body, "source_channel"),
			Status:         "requested",
		}
		f.sessions[id] = session
		f.tokens[tok] = id
		writeJSON(w, http.StatusCreated, map[string]any{
			"id":               session.ID,
			"openclaw_user_id": session.OpenClawUserID,
			"device_id":        session.DeviceID,
			"connector_id":     session.ConnectorID,
			"source_channel":   session.SourceChannel,
			"status":           session.Status,
			"install_token":    tok,
		})
	case "approve_install_session":
		id := stringFromMap(body, "install_session_id")
		approved, _ := body["approved"].(bool)
		f.mu.Lock()
		defer f.mu.Unlock()
		session, ok := f.sessions[id]
		if !ok {
			http.Error(w, "not_found", http.StatusNotFound)
			return
		}
		if approved {
			session.Status = "approved"
		} else {
			session.Status = "failed"
			session.ReasonCode = "Denied"
		}
		f.sessions[id] = session
		writeJSON(w, http.StatusOK, session)
	default:
		http.Error(w, "unsupported_intent", http.StatusBadRequest)
	}
}

func (f *fakeControlPlaneInstallAPI) handleRedeem(w http.ResponseWriter, r *http.Request) {
	var body map[string]any
	_ = json.NewDecoder(r.Body).Decode(&body)
	token := stringFromMap(body, "token")

	f.mu.Lock()
	defer f.mu.Unlock()
	id, ok := f.tokens[token]
	if !ok {
		http.Error(w, "not_found", http.StatusNotFound)
		return
	}
	session := f.sessions[id]
	if session.Status != "approved" {
		http.Error(w, "invalid_transition", http.StatusConflict)
		return
	}
	delete(f.tokens, token)
	writeJSON(w, http.StatusOK, session)
}

func (f *fakeControlPlaneInstallAPI) handleResult(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/install-sessions/"), "/result")
	var body map[string]any
	_ = json.NewDecoder(r.Body).Decode(&body)

	f.mu.Lock()
	defer f.mu.Unlock()
	session, ok := f.sessions[id]
	if !ok {
		http.Error(w, "not_found", http.StatusNotFound)
		return
	}
	session.Status = stringFromMap(body, "status")
	session.ReasonCode = stringFromMap(body, "reason_code")
	f.sessions[id] = session
	writeJSON(w, http.StatusOK, session)
}

func (f *fakeControlPlaneInstallAPI) session(id string) installSessionState {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.sessions[id]
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func stringFromMap(m map[string]any, key string) string {
	v, _ := m[key].(string)
	return v
}

func postJSON(t *testing.T, client *http.Client, url string, body string) map[string]any {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewBufferString(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("post %s: %v", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		t.Fatalf("unexpected status %d from %s", resp.StatusCode, url)
	}
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return out
}

func TestRunEndToEndInstallFlowFromIntentToInstalled(t *testing.T) {
	apiState := newFakeControlPlaneInstallAPI()
	server := httptest.NewServer(apiState)
	defer server.Close()

	client := server.Client()
	createResp := postJSON(t, client, server.URL+"/v1/openclaw/intents", `{
		"intent":"request_connector_install",
		"openclaw_user_id":"usr_1",
		"connector_id":"conn_1",
		"device_id":"dev_1",
		"source_channel":"telegram"
	}`)
	sessionID := createResp["id"].(string)
	installToken := createResp["install_token"].(string)

	_ = postJSON(t, client, server.URL+"/v1/openclaw/intents", `{
		"intent":"approve_install_session",
		"install_session_id":"`+sessionID+`",
		"approved":true
	}`)

	fakeInstaller := &fakeLaunchdInstaller{}
	err := runWithDeps(
		context.Background(),
		[]string{
			"-token", installToken,
			"-agent-bin", "/usr/local/bin/enclout-agent",
			"-control-plane-url", server.URL,
			"-dcap-verifier-url", "http://127.0.0.1:9000",
			"-local-username", "alice",
			"-plist-path", filepath.Join(t.TempDir(), "ai.enclout.agent.plist"),
		},
		func(_ string) (string, bool) { return "", false },
		"darwin",
		func() install.ServiceInstaller { return fakeInstaller },
		install.Run,
	)
	if err != nil {
		t.Fatalf("unexpected run error: %v", err)
	}

	if fakeInstaller.calls != 1 {
		t.Fatalf("expected install call once, got %d", fakeInstaller.calls)
	}
	got := apiState.session(sessionID)
	if got.Status != "installed" {
		t.Fatalf("expected installed session status, got %q", got.Status)
	}
	if got.ReasonCode != "" {
		t.Fatalf("expected empty reason code on success, got %q", got.ReasonCode)
	}
}

func TestRunEndToEndInstallFlowLinuxSystemd(t *testing.T) {
	apiState := newFakeControlPlaneInstallAPI()
	server := httptest.NewServer(apiState)
	defer server.Close()

	client := server.Client()
	createResp := postJSON(t, client, server.URL+"/v1/openclaw/intents", `{
		"intent":"request_connector_install",
		"openclaw_user_id":"usr_1",
		"connector_id":"conn_1",
		"device_id":"dev_1",
		"source_channel":"slack"
	}`)
	sessionID := createResp["id"].(string)
	installToken := createResp["install_token"].(string)

	_ = postJSON(t, client, server.URL+"/v1/openclaw/intents", `{
		"intent":"approve_install_session",
		"install_session_id":"`+sessionID+`",
		"approved":true
	}`)

	fakeInstaller := &fakeLaunchdInstaller{}
	err := runWithDeps(
		context.Background(),
		[]string{
			"-token", installToken,
			"-agent-bin", "/usr/local/bin/enclout-agent",
			"-control-plane-url", server.URL,
			"-dcap-verifier-url", "http://127.0.0.1:9000",
			"-local-username", "alice",
			"-service-path", filepath.Join(t.TempDir(), "ai.enclout.agent.service"),
		},
		func(_ string) (string, bool) { return "", false },
		"linux",
		func() install.ServiceInstaller { return fakeInstaller },
		install.Run,
	)
	if err != nil {
		t.Fatalf("unexpected run error: %v", err)
	}

	if fakeInstaller.calls != 1 {
		t.Fatalf("expected install call once, got %d", fakeInstaller.calls)
	}
	got := apiState.session(sessionID)
	if got.Status != "installed" {
		t.Fatalf("expected installed session status, got %q", got.Status)
	}
}
