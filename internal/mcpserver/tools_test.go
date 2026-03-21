package mcpserver_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/fstest"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	mcpgoserver "github.com/mark3labs/mcp-go/server"

	"enclout/internal/client"
	"enclout/internal/mcpserver"
	"enclout/internal/server"
	"enclout/internal/signing"
	"enclout/internal/store"
)

const testAuthToken = "test-secret-token"

const migrationSQL = `
CREATE TABLE IF NOT EXISTS connection_requests (
    id            TEXT PRIMARY KEY,
    requester_id  TEXT NOT NULL,
    device_id     TEXT NOT NULL,
    connector_id  TEXT NOT NULL,
    source        TEXT NOT NULL DEFAULT '',
    status        TEXT NOT NULL DEFAULT 'pending_local_confirm',
    nonce         TEXT NOT NULL,
    reason_code   TEXT NOT NULL DEFAULT '',
    created_at    TEXT NOT NULL,
    expires_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_requests_device_status ON connection_requests(device_id, status);

CREATE TABLE IF NOT EXISTS install_sessions (
    id            TEXT PRIMARY KEY,
    requester_id  TEXT NOT NULL,
    device_id     TEXT NOT NULL DEFAULT '',
    connector_id  TEXT NOT NULL DEFAULT '',
    source        TEXT NOT NULL DEFAULT '',
    status        TEXT NOT NULL DEFAULT 'requested',
    token_digest  TEXT NOT NULL DEFAULT '',
    reason_code   TEXT NOT NULL DEFAULT '',
    created_at    TEXT NOT NULL,
    expires_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_install_token ON install_sessions(token_digest) WHERE token_digest != '';

CREATE TABLE IF NOT EXISTS audit_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    entity_type TEXT NOT NULL,
    entity_id   TEXT NOT NULL,
    action      TEXT NOT NULL,
    actor       TEXT NOT NULL DEFAULT '',
    detail      TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_entity ON audit_log(entity_type, entity_id);
CREATE INDEX IF NOT EXISTS idx_audit_time ON audit_log(created_at);

CREATE TABLE IF NOT EXISTS connector_bundles (
    connector_id   TEXT PRIMARY KEY,
    ssh_public_key TEXT NOT NULL,
    quote_hex      TEXT NOT NULL,
    event_log      TEXT NOT NULL DEFAULT '',
    mrtd           TEXT NOT NULL DEFAULT '',
    rtmr0          TEXT NOT NULL DEFAULT '',
    rtmr1          TEXT NOT NULL DEFAULT '',
    rtmr2          TEXT NOT NULL DEFAULT '',
    rtmr3          TEXT NOT NULL DEFAULT '',
    policy_version TEXT NOT NULL DEFAULT 'v1',
    info           TEXT NOT NULL DEFAULT '{}',
    registered_at  TEXT NOT NULL
);
`

type testEnv struct {
	mcpServer *mcpserver.Server
	apiClient *client.Client
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()

	migrationFS := fstest.MapFS{
		"001_initial.sql": &fstest.MapFile{Data: []byte(migrationSQL)},
	}
	db, err := store.OpenMemory(migrationFS)
	if err != nil {
		t.Fatalf("open memory db: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	requests := store.NewRequestRepository(db)
	sessions := store.NewSessionRepository(db)
	bundles := store.NewBundleRepository(db)
	audit := store.NewAuditLogger(db)

	seed := base64.StdEncoding.EncodeToString([]byte("12345678901234567890123456789012"))
	signer, err := signing.NewEd25519SignerFromSeedB64(seed)
	if err != nil {
		t.Fatalf("create signer: %v", err)
	}

	deps := server.Deps{
		DB:       db,
		Requests: requests,
		Sessions: sessions,
		Bundles:  bundles,
		Audit:    audit,
		Signer:   signer,
	}

	h := server.NewHandlers(deps)
	auth := func(next http.Handler) http.Handler {
		return server.BearerAuth(testAuthToken, next)
	}
	router := server.NewRouter(h, auth)
	ts := httptest.NewServer(router)
	t.Cleanup(ts.Close)

	c := client.New(ts.URL, testAuthToken)
	mcpSrv := mcpserver.New(c, ts.URL)

	return &testEnv{
		mcpServer: mcpSrv,
		apiClient: c,
	}
}

// callTool is a helper that invokes a tool handler directly via the MCP server
// by constructing a CallToolRequest with the given arguments.
func callTool(t *testing.T, env *testEnv, toolName string, args map[string]any) *mcp.CallToolResult {
	t.Helper()
	ctx := context.Background()

	// Create an MCPServer from the mcp-go library, register our tools, then
	// dispatch via HandleMessage so the full MCP tool-call path is exercised.
	srv := mcpgoserver.NewMCPServer("enclout-test", "0.0.0")
	env.mcpServer.Register(srv)

	reqBytes, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "tools/call",
		"params": map[string]any{
			"name":      toolName,
			"arguments": args,
		},
	})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}

	respMsg := srv.HandleMessage(ctx, reqBytes)
	respBytes, err := json.Marshal(respMsg)
	if err != nil {
		t.Fatalf("marshal response: %v", err)
	}

	// Parse the JSON-RPC response
	var rpcResp struct {
		Result *mcp.CallToolResult `json:"result"`
		Error  *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(respBytes, &rpcResp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if rpcResp.Error != nil {
		t.Fatalf("RPC error: code=%d message=%s", rpcResp.Error.Code, rpcResp.Error.Message)
	}
	if rpcResp.Result == nil {
		t.Fatal("expected result, got nil")
	}
	return rpcResp.Result
}

// getTextContent extracts the text from the first TextContent in a CallToolResult.
func getTextContent(t *testing.T, result *mcp.CallToolResult) string {
	t.Helper()
	if len(result.Content) == 0 {
		t.Fatal("expected at least one content item")
	}
	tc, ok := result.Content[0].(mcp.TextContent)
	if !ok {
		t.Fatalf("expected TextContent, got %T", result.Content[0])
	}
	return tc.Text
}

// --- Tests ---

func TestConnect_CreatesRequest(t *testing.T) {
	env := newTestEnv(t)

	result := callTool(t, env, "enclout_connect", map[string]any{
		"requester_id": "user1",
		"device_id":    "dev1",
		"connector_id": "conn1",
		"source":       "telegram",
	})

	if result.IsError {
		t.Fatalf("expected success, got error: %s", getTextContent(t, result))
	}

	text := getTextContent(t, result)
	var resp client.RequestResponse
	if err := json.Unmarshal([]byte(text), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}

	if resp.ID == "" {
		t.Error("expected non-empty request ID")
	}
	if resp.RequesterID != "user1" {
		t.Errorf("expected requester_id user1, got %s", resp.RequesterID)
	}
	if resp.DeviceID != "dev1" {
		t.Errorf("expected device_id dev1, got %s", resp.DeviceID)
	}
	if resp.ConnectorID != "conn1" {
		t.Errorf("expected connector_id conn1, got %s", resp.ConnectorID)
	}
	if resp.Source != "telegram" {
		t.Errorf("expected source telegram, got %s", resp.Source)
	}
	if resp.Status != "pending_local_confirm" {
		t.Errorf("expected status pending_local_confirm, got %s", resp.Status)
	}
}

func TestInstallStart_ReturnsCommands(t *testing.T) {
	env := newTestEnv(t)

	result := callTool(t, env, "enclout_install_start", map[string]any{
		"requester_id": "user1",
		"source":       "web",
	})

	if result.IsError {
		t.Fatalf("expected success, got error: %s", getTextContent(t, result))
	}

	text := getTextContent(t, result)
	var resp struct {
		Session         client.SessionResponse `json:"session"`
		InstallToken    string                 `json:"install_token"`
		InstallURL      string                 `json:"install_url"`
		InstallCommands map[string]string      `json:"install_commands"`
	}
	if err := json.Unmarshal([]byte(text), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}

	if resp.Session.ID == "" {
		t.Error("expected non-empty session ID")
	}
	if resp.InstallToken == "" {
		t.Error("expected non-empty install token")
	}
	if resp.InstallURL == "" {
		t.Error("expected non-empty install URL")
	}
	if resp.Session.Status != "requested" {
		t.Errorf("expected status requested, got %s", resp.Session.Status)
	}
	if resp.Session.RequesterID != "user1" {
		t.Errorf("expected requester_id user1, got %s", resp.Session.RequesterID)
	}

	linuxCmd, ok := resp.InstallCommands["linux_macos"]
	if !ok {
		t.Fatal("expected install_commands to contain linux_macos key")
	}
	if linuxCmd == "" {
		t.Error("expected non-empty linux_macos install command")
	}
	// The command should be a curl pipe
	if len(linuxCmd) < 10 {
		t.Errorf("install command seems too short: %s", linuxCmd)
	}
}

func TestRequestStatus_ReturnsStatus(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()

	// Create a request via the API client first
	created, err := env.apiClient.CreateRequest(ctx, "user1", "dev1", "conn1", "", 5*time.Minute)
	if err != nil {
		t.Fatalf("CreateRequest: %v", err)
	}

	// Check its status via the MCP tool
	result := callTool(t, env, "enclout_request_status", map[string]any{
		"request_id": created.ID,
	})

	if result.IsError {
		t.Fatalf("expected success, got error: %s", getTextContent(t, result))
	}

	text := getTextContent(t, result)
	var resp client.RequestResponse
	if err := json.Unmarshal([]byte(text), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}

	if resp.ID != created.ID {
		t.Errorf("expected ID %s, got %s", created.ID, resp.ID)
	}
	if resp.Status != "pending_local_confirm" {
		t.Errorf("expected status pending_local_confirm, got %s", resp.Status)
	}
}

func TestListPending_ReturnsArray(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()

	// Create two requests for dev1 and one for dev2
	for _, devID := range []string{"dev1", "dev1", "dev2"} {
		if _, err := env.apiClient.CreateRequest(ctx, "user1", devID, "conn1", "", 5*time.Minute); err != nil {
			t.Fatalf("CreateRequest: %v", err)
		}
	}

	result := callTool(t, env, "enclout_list_pending", map[string]any{
		"device_id": "dev1",
	})

	if result.IsError {
		t.Fatalf("expected success, got error: %s", getTextContent(t, result))
	}

	text := getTextContent(t, result)
	var items []client.RequestResponse
	if err := json.Unmarshal([]byte(text), &items); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}

	if len(items) != 2 {
		t.Errorf("expected 2 pending for dev1, got %d", len(items))
	}

	// Verify all items belong to dev1
	for _, item := range items {
		if item.DeviceID != "dev1" {
			t.Errorf("expected device_id dev1, got %s", item.DeviceID)
		}
	}
}

func TestInstallApprove_Succeeds(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()

	// Create a session first
	session, err := env.apiClient.CreateSession(ctx, "user1", "web", 10*time.Minute)
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	// Approve via MCP tool
	result := callTool(t, env, "enclout_install_approve", map[string]any{
		"session_id": session.Session.ID,
	})

	if result.IsError {
		t.Fatalf("expected success, got error: %s", getTextContent(t, result))
	}

	text := getTextContent(t, result)
	if text == "" {
		t.Error("expected non-empty success message")
	}

	// Verify via API that session is now approved
	got, err := env.apiClient.GetSession(ctx, session.Session.ID)
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if got.Status != "approved" {
		t.Errorf("expected status approved, got %s", got.Status)
	}
}

func TestInstallStatus_ReturnsStatus(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()

	// Create a session first
	session, err := env.apiClient.CreateSession(ctx, "user1", "cli", 10*time.Minute)
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	// Check status via MCP tool
	result := callTool(t, env, "enclout_install_status", map[string]any{
		"session_id": session.Session.ID,
	})

	if result.IsError {
		t.Fatalf("expected success, got error: %s", getTextContent(t, result))
	}

	text := getTextContent(t, result)
	var resp client.SessionResponse
	if err := json.Unmarshal([]byte(text), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}

	if resp.ID != session.Session.ID {
		t.Errorf("expected ID %s, got %s", session.Session.ID, resp.ID)
	}
	if resp.Status != "requested" {
		t.Errorf("expected status requested, got %s", resp.Status)
	}
}
