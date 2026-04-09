package server_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/fstest"

	"enclout/internal/access"
	"enclout/internal/server"
	"enclout/internal/signing"
	"enclout/internal/store"
)

const testAuthToken = "test-secret-token"

// migrationSQL is the DDL for in-memory test databases.
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
	ts       *httptest.Server
	requests *store.RequestRepository
	sessions *store.SessionRepository
	bundles  *store.BundleRepository
	audit    *store.AuditLogger
	signer   signing.BundleSigner
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

	return &testEnv{
		ts:       ts,
		requests: requests,
		sessions: sessions,
		bundles:  bundles,
		audit:    audit,
		signer:   signer,
	}
}

func (e *testEnv) doRequest(t *testing.T, method, path string, body any, withAuth bool) *http.Response {
	t.Helper()
	var bodyReader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
		bodyReader = bytes.NewReader(data)
	}
	req, err := http.NewRequest(method, e.ts.URL+path, bodyReader)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if withAuth {
		req.Header.Set("Authorization", "Bearer "+testAuthToken)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	return resp
}

func decodeJSON[T any](t *testing.T, resp *http.Response) T {
	t.Helper()
	defer resp.Body.Close()
	var v T
	if err := json.NewDecoder(resp.Body).Decode(&v); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return v
}

// --- Tests ---

func TestAuth_MissingToken(t *testing.T) {
	env := newTestEnv(t)

	resp := env.doRequest(t, "GET", "/v1/signing-keys", nil, false)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", resp.StatusCode)
	}
}

func TestAuth_WrongToken(t *testing.T) {
	env := newTestEnv(t)

	req, _ := http.NewRequest("GET", env.ts.URL+"/v1/signing-keys", nil)
	req.Header.Set("Authorization", "Bearer wrong-token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", resp.StatusCode)
	}
}

func TestHealthz(t *testing.T) {
	env := newTestEnv(t)

	// healthz does not require auth
	resp := env.doRequest(t, "GET", "/healthz", nil, false)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "ok" {
		t.Errorf("expected 'ok', got %q", string(body))
	}
}

func TestCreateRequest(t *testing.T) {
	env := newTestEnv(t)

	body := map[string]string{
		"requester_id": "user1",
		"device_id":    "dev1",
		"connector_id": "conn1",
		"source":       "telegram",
	}
	resp := env.doRequest(t, "POST", "/v1/requests", body, true)
	if resp.StatusCode != http.StatusCreated {
		respBody, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("expected 201, got %d: %s", resp.StatusCode, string(respBody))
	}

	var result access.ConnectionRequest
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		resp.Body.Close()
		t.Fatalf("decode: %v", err)
	}
	resp.Body.Close()

	if result.ID == "" {
		t.Error("expected non-empty ID")
	}
	if result.Status != access.StatusPendingLocalConfirm {
		t.Errorf("expected status pending_local_confirm, got %s", result.Status)
	}
	if result.RequesterID != "user1" {
		t.Errorf("expected requester_id user1, got %s", result.RequesterID)
	}
}

func TestGetRequest(t *testing.T) {
	env := newTestEnv(t)

	// Create a request first
	body := map[string]string{
		"requester_id": "user1",
		"device_id":    "dev1",
		"connector_id": "conn1",
	}
	createResp := env.doRequest(t, "POST", "/v1/requests", body, true)
	created := decodeJSON[access.ConnectionRequest](t, createResp)

	// Get it back
	getResp := env.doRequest(t, "GET", "/v1/requests/"+created.ID, nil, true)
	if getResp.StatusCode != http.StatusOK {
		getResp.Body.Close()
		t.Fatalf("expected 200, got %d", getResp.StatusCode)
	}
	got := decodeJSON[access.ConnectionRequest](t, getResp)

	if got.ID != created.ID {
		t.Errorf("expected ID %s, got %s", created.ID, got.ID)
	}
	if got.DeviceID != "dev1" {
		t.Errorf("expected device_id dev1, got %s", got.DeviceID)
	}
}

func TestGetRequest_NotFound(t *testing.T) {
	env := newTestEnv(t)

	resp := env.doRequest(t, "GET", "/v1/requests/nonexistent", nil, true)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404, got %d", resp.StatusCode)
	}
}

func TestPostDecision_Approve(t *testing.T) {
	env := newTestEnv(t)

	// Create request
	createBody := map[string]string{
		"requester_id": "user1",
		"device_id":    "dev1",
		"connector_id": "conn1",
	}
	createResp := env.doRequest(t, "POST", "/v1/requests", createBody, true)
	created := decodeJSON[access.ConnectionRequest](t, createResp)

	// Approve it
	decisionBody := map[string]bool{"approved": true}
	decResp := env.doRequest(t, "POST", "/v1/requests/"+created.ID+"/decision", decisionBody, true)
	if decResp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(decResp.Body)
		decResp.Body.Close()
		t.Fatalf("expected 200, got %d: %s", decResp.StatusCode, string(respBody))
	}
	updated := decodeJSON[access.ConnectionRequest](t, decResp)

	if updated.Status != access.StatusApproved {
		t.Errorf("expected status approved, got %s", updated.Status)
	}
}

func TestPostDecision_Deny(t *testing.T) {
	env := newTestEnv(t)

	createBody := map[string]string{
		"requester_id": "user1",
		"device_id":    "dev1",
		"connector_id": "conn1",
	}
	createResp := env.doRequest(t, "POST", "/v1/requests", createBody, true)
	created := decodeJSON[access.ConnectionRequest](t, createResp)

	decisionBody := map[string]bool{"approved": false}
	decResp := env.doRequest(t, "POST", "/v1/requests/"+created.ID+"/decision", decisionBody, true)
	if decResp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(decResp.Body)
		decResp.Body.Close()
		t.Fatalf("expected 200, got %d: %s", decResp.StatusCode, string(respBody))
	}
	updated := decodeJSON[access.ConnectionRequest](t, decResp)

	if updated.Status != access.StatusDeniedLocal {
		t.Errorf("expected status denied_local, got %s", updated.Status)
	}
}

func TestPostRevoke(t *testing.T) {
	env := newTestEnv(t)

	createBody := map[string]string{
		"requester_id": "user1",
		"device_id":    "dev1",
		"connector_id": "conn1",
	}
	createResp := env.doRequest(t, "POST", "/v1/requests", createBody, true)
	created := decodeJSON[access.ConnectionRequest](t, createResp)

	decisionBody := map[string]bool{"approved": true}
	decResp := env.doRequest(t, "POST", "/v1/requests/"+created.ID+"/decision", decisionBody, true)
	if decResp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(decResp.Body)
		decResp.Body.Close()
		t.Fatalf("expected 200, got %d: %s", decResp.StatusCode, string(respBody))
	}
	decResp.Body.Close()

	revokeResp := env.doRequest(t, "POST", "/v1/requests/"+created.ID+"/revoke", nil, true)
	if revokeResp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(revokeResp.Body)
		revokeResp.Body.Close()
		t.Fatalf("expected 200, got %d: %s", revokeResp.StatusCode, string(respBody))
	}
	updated := decodeJSON[access.ConnectionRequest](t, revokeResp)

	if updated.Status != access.StatusRevoked {
		t.Errorf("expected status revoked, got %s", updated.Status)
	}
}

func TestPostRevoke_InvalidTransition(t *testing.T) {
	env := newTestEnv(t)

	createBody := map[string]string{
		"requester_id": "user1",
		"device_id":    "dev1",
		"connector_id": "conn1",
	}
	createResp := env.doRequest(t, "POST", "/v1/requests", createBody, true)
	created := decodeJSON[access.ConnectionRequest](t, createResp)

	decisionBody := map[string]bool{"approved": true}
	decResp := env.doRequest(t, "POST", "/v1/requests/"+created.ID+"/decision", decisionBody, true)
	if decResp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(decResp.Body)
		decResp.Body.Close()
		t.Fatalf("expected 200, got %d: %s", decResp.StatusCode, string(respBody))
	}
	decResp.Body.Close()

	resultBody := map[string]string{
		"status":      "connected",
		"reason_code": "",
	}
	resultResp := env.doRequest(t, "POST", "/v1/requests/"+created.ID+"/result", resultBody, true)
	if resultResp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resultResp.Body)
		resultResp.Body.Close()
		t.Fatalf("expected 200, got %d: %s", resultResp.StatusCode, string(respBody))
	}
	resultResp.Body.Close()

	revokeResp := env.doRequest(t, "POST", "/v1/requests/"+created.ID+"/revoke", nil, true)
	defer revokeResp.Body.Close()
	if revokeResp.StatusCode != http.StatusConflict {
		respBody, _ := io.ReadAll(revokeResp.Body)
		t.Fatalf("expected 409, got %d: %s", revokeResp.StatusCode, string(respBody))
	}

	var errBody map[string]string
	if err := json.NewDecoder(revokeResp.Body).Decode(&errBody); err != nil {
		t.Fatalf("decode error response: %v", err)
	}
	if errBody["error"] != "invalid_transition" {
		t.Fatalf("expected invalid_transition error, got %q", errBody["error"])
	}
}

func TestListPending(t *testing.T) {
	env := newTestEnv(t)

	// Create two requests for dev1 and one for dev2
	for _, devID := range []string{"dev1", "dev1", "dev2"} {
		body := map[string]string{
			"requester_id": "user1",
			"device_id":    devID,
			"connector_id": "conn1",
		}
		resp := env.doRequest(t, "POST", "/v1/requests", body, true)
		resp.Body.Close()
	}

	resp := env.doRequest(t, "GET", "/v1/devices/dev1/pending", nil, true)
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	items := decodeJSON[[]access.ConnectionRequest](t, resp)

	if len(items) != 2 {
		t.Errorf("expected 2 pending items for dev1, got %d", len(items))
	}
}

func TestListPending_Empty(t *testing.T) {
	env := newTestEnv(t)

	resp := env.doRequest(t, "GET", "/v1/devices/nodevice/pending", nil, true)
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	items := decodeJSON[[]access.ConnectionRequest](t, resp)

	if len(items) != 0 {
		t.Errorf("expected 0 items, got %d", len(items))
	}
}

func TestCreateSession(t *testing.T) {
	env := newTestEnv(t)

	body := map[string]string{
		"requester_id": "user1",
		"source":       "web",
	}
	resp := env.doRequest(t, "POST", "/v1/sessions", body, true)
	if resp.StatusCode != http.StatusCreated {
		respBody, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("expected 201, got %d: %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		Session      access.InstallSession `json:"session"`
		InstallToken string                `json:"install_token"`
		InstallURL   string                `json:"install_url"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		resp.Body.Close()
		t.Fatalf("decode: %v", err)
	}
	resp.Body.Close()

	if result.Session.ID == "" {
		t.Error("expected non-empty session ID")
	}
	if result.InstallToken == "" {
		t.Error("expected non-empty install_token")
	}
	if result.InstallURL == "" {
		t.Error("expected non-empty install_url")
	}
	if result.Session.Status != access.InstallStatusRequested {
		t.Errorf("expected status requested, got %s", result.Session.Status)
	}
}

func TestRedeemToken(t *testing.T) {
	env := newTestEnv(t)

	// Create session to get raw token
	createBody := map[string]string{
		"requester_id": "user1",
		"source":       "web",
	}
	createResp := env.doRequest(t, "POST", "/v1/sessions", createBody, true)
	var createResult struct {
		Session      access.InstallSession `json:"session"`
		InstallToken string                `json:"install_token"`
	}
	json.NewDecoder(createResp.Body).Decode(&createResult)
	createResp.Body.Close()

	// Compute digest from raw token
	tokenDigest := access.DigestToken(createResult.InstallToken)

	// First redeem should succeed
	redeemBody := map[string]string{"token_digest": tokenDigest}
	resp := env.doRequest(t, "POST", "/v1/sessions/redeem", redeemBody, true)
	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("expected 200 on first redeem, got %d: %s", resp.StatusCode, string(respBody))
	}
	redeemed := decodeJSON[access.InstallSession](t, resp)
	if redeemed.ID != createResult.Session.ID {
		t.Errorf("redeemed session ID mismatch: %s != %s", redeemed.ID, createResult.Session.ID)
	}

	// Second redeem should fail
	resp2 := env.doRequest(t, "POST", "/v1/sessions/redeem", redeemBody, true)
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404 on second redeem, got %d", resp2.StatusCode)
	}
}

func TestSigningKeys(t *testing.T) {
	env := newTestEnv(t)

	resp := env.doRequest(t, "GET", "/v1/signing-keys", nil, true)
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	keyset := decodeJSON[signing.SigningKeyset](t, resp)
	if keyset.ActiveKID == "" {
		t.Error("expected non-empty active_kid")
	}
	if len(keyset.Keys) == 0 {
		t.Error("expected at least one key")
	}
	if keyset.Keys[0].PublicKeyB64 == "" {
		t.Error("expected non-empty public_key_b64")
	}
}

func TestRegisterConnector(t *testing.T) {
	env := newTestEnv(t)

	body := map[string]string{
		"connector_id":   "conn1",
		"ssh_public_key": "ssh-ed25519 AAAATEST connector@tee",
		"quote_hex":      "abcd",
	}
	resp := env.doRequest(t, "POST", "/v1/connectors/register", body, true)
	if resp.StatusCode != http.StatusCreated {
		respBody, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("expected 201, got %d: %s", resp.StatusCode, string(respBody))
	}
	result := decodeJSON[map[string]string](t, resp)
	if result["status"] != "registered" {
		t.Errorf("expected status=registered, got %s", result["status"])
	}
}

func TestGetBundle(t *testing.T) {
	env := newTestEnv(t)

	// Register a connector bundle first
	regBody := map[string]string{
		"connector_id":   "conn1",
		"ssh_public_key": "ssh-ed25519 AAAATEST connector@tee",
		"quote_hex":      "abcd",
		"event_log":      "[]",
		"mrtd":           "mrtd",
		"rtmr0":          "rtmr0",
		"rtmr1":          "rtmr1",
		"rtmr2":          "rtmr2",
		"rtmr3":          "rtmr3",
	}
	regResp := env.doRequest(t, "POST", "/v1/connectors/register", regBody, true)
	regResp.Body.Close()

	// Create a request
	createBody := map[string]string{
		"requester_id": "user1",
		"device_id":    "dev1",
		"connector_id": "conn1",
	}
	createResp := env.doRequest(t, "POST", "/v1/requests", createBody, true)
	created := decodeJSON[access.ConnectionRequest](t, createResp)

	// Approve it
	decisionBody := map[string]bool{"approved": true}
	decResp := env.doRequest(t, "POST", "/v1/requests/"+created.ID+"/decision", decisionBody, true)
	decResp.Body.Close()

	// Get the bundle
	bundleResp := env.doRequest(t, "GET", "/v1/requests/"+created.ID+"/bundle", nil, true)
	if bundleResp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(bundleResp.Body)
		bundleResp.Body.Close()
		t.Fatalf("expected 200, got %d: %s", bundleResp.StatusCode, string(respBody))
	}
	bundle := decodeJSON[signing.SignedBundle](t, bundleResp)

	if bundle.Payload.ConnectorID != "conn1" {
		t.Errorf("expected connector_id conn1, got %s", bundle.Payload.ConnectorID)
	}
	if bundle.Signature == "" {
		t.Error("expected non-empty signature")
	}
	if bundle.Alg != "ed25519" {
		t.Errorf("expected alg ed25519, got %s", bundle.Alg)
	}
}

func TestGetBundle_NotApproved(t *testing.T) {
	env := newTestEnv(t)

	createBody := map[string]string{
		"requester_id": "user1",
		"device_id":    "dev1",
		"connector_id": "conn1",
	}
	createResp := env.doRequest(t, "POST", "/v1/requests", createBody, true)
	created := decodeJSON[access.ConnectionRequest](t, createResp)

	// Try to get bundle without approving -- should fail
	bundleResp := env.doRequest(t, "GET", "/v1/requests/"+created.ID+"/bundle", nil, true)
	defer bundleResp.Body.Close()
	if bundleResp.StatusCode != http.StatusConflict {
		t.Errorf("expected 409, got %d", bundleResp.StatusCode)
	}
}

func TestInstallLanding(t *testing.T) {
	env := newTestEnv(t)

	resp := env.doRequest(t, "GET", "/install", nil, false)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
	ct := resp.Header.Get("Content-Type")
	if ct != "text/html; charset=utf-8" {
		t.Errorf("expected text/html content type, got %s", ct)
	}
}

func TestPostResult(t *testing.T) {
	env := newTestEnv(t)

	// Create and approve a request
	createBody := map[string]string{
		"requester_id": "user1",
		"device_id":    "dev1",
		"connector_id": "conn1",
	}
	createResp := env.doRequest(t, "POST", "/v1/requests", createBody, true)
	created := decodeJSON[access.ConnectionRequest](t, createResp)

	decisionBody := map[string]bool{"approved": true}
	decResp := env.doRequest(t, "POST", "/v1/requests/"+created.ID+"/decision", decisionBody, true)
	decResp.Body.Close()

	// Set result to connected
	resultBody := map[string]string{
		"status":      "connected",
		"reason_code": "",
	}
	resultResp := env.doRequest(t, "POST", "/v1/requests/"+created.ID+"/result", resultBody, true)
	if resultResp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resultResp.Body)
		resultResp.Body.Close()
		t.Fatalf("expected 200, got %d: %s", resultResp.StatusCode, string(respBody))
	}
	updated := decodeJSON[access.ConnectionRequest](t, resultResp)

	if updated.Status != access.StatusConnected {
		t.Errorf("expected status connected, got %s", updated.Status)
	}
}
