package client_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/fstest"
	"time"

	"enclout/internal/access"
	"enclout/internal/client"
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
	client   *client.Client
	requests *store.RequestRepository
	sessions *store.SessionRepository
	bundles  *store.BundleRepository
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

	return &testEnv{
		client:   c,
		requests: requests,
		sessions: sessions,
		bundles:  bundles,
	}
}

func TestClient_CreateRequest(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()

	resp, err := env.client.CreateRequest(ctx, "user1", "dev1", "conn1", "telegram", 5*time.Minute)
	if err != nil {
		t.Fatalf("CreateRequest: %v", err)
	}
	if resp.ID == "" {
		t.Error("expected non-empty ID")
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
	if resp.Status != "pending_local_confirm" {
		t.Errorf("expected status pending_local_confirm, got %s", resp.Status)
	}
	if resp.Source != "telegram" {
		t.Errorf("expected source telegram, got %s", resp.Source)
	}
}

func TestClient_GetRequest(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()

	created, err := env.client.CreateRequest(ctx, "user1", "dev1", "conn1", "", 5*time.Minute)
	if err != nil {
		t.Fatalf("CreateRequest: %v", err)
	}

	got, err := env.client.GetRequest(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetRequest: %v", err)
	}
	if got.ID != created.ID {
		t.Errorf("expected ID %s, got %s", created.ID, got.ID)
	}
	if got.DeviceID != "dev1" {
		t.Errorf("expected device_id dev1, got %s", got.DeviceID)
	}
}

func TestClient_PostDecision(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()

	created, err := env.client.CreateRequest(ctx, "user1", "dev1", "conn1", "", 5*time.Minute)
	if err != nil {
		t.Fatalf("CreateRequest: %v", err)
	}

	if err := env.client.PostDecision(ctx, created.ID, true); err != nil {
		t.Fatalf("PostDecision: %v", err)
	}

	// Verify the request is now approved
	got, err := env.client.GetRequest(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetRequest: %v", err)
	}
	if got.Status != "approved" {
		t.Errorf("expected status approved, got %s", got.Status)
	}
}

func TestClient_PostResult(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()

	created, err := env.client.CreateRequest(ctx, "user1", "dev1", "conn1", "", 5*time.Minute)
	if err != nil {
		t.Fatalf("CreateRequest: %v", err)
	}
	if err := env.client.PostDecision(ctx, created.ID, true); err != nil {
		t.Fatalf("PostDecision: %v", err)
	}

	if err := env.client.PostResult(ctx, created.ID, "connected", ""); err != nil {
		t.Fatalf("PostResult: %v", err)
	}

	got, err := env.client.GetRequest(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetRequest: %v", err)
	}
	if got.Status != "connected" {
		t.Errorf("expected status connected, got %s", got.Status)
	}
}

func TestClient_RevokeRequest(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()

	created, err := env.client.CreateRequest(ctx, "user1", "dev1", "conn1", "", 5*time.Minute)
	if err != nil {
		t.Fatalf("CreateRequest: %v", err)
	}
	if err := env.client.PostDecision(ctx, created.ID, true); err != nil {
		t.Fatalf("PostDecision: %v", err)
	}

	if err := env.client.RevokeRequest(ctx, created.ID); err != nil {
		t.Fatalf("RevokeRequest: %v", err)
	}

	got, err := env.client.GetRequest(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetRequest: %v", err)
	}
	if got.Status != "revoked" {
		t.Errorf("expected status revoked, got %s", got.Status)
	}
}

func TestClient_RevokeRequest_InvalidTransition(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()

	created, err := env.client.CreateRequest(ctx, "user1", "dev1", "conn1", "", 5*time.Minute)
	if err != nil {
		t.Fatalf("CreateRequest: %v", err)
	}
	if err := env.client.PostDecision(ctx, created.ID, true); err != nil {
		t.Fatalf("PostDecision: %v", err)
	}
	if err := env.client.PostResult(ctx, created.ID, "connected", ""); err != nil {
		t.Fatalf("PostResult: %v", err)
	}

	err = env.client.RevokeRequest(ctx, created.ID)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	apiErr, ok := err.(*client.APIError)
	if !ok {
		t.Fatalf("expected *APIError, got %T: %v", err, err)
	}
	if apiErr.StatusCode != http.StatusConflict {
		t.Errorf("expected 409, got %d", apiErr.StatusCode)
	}
	if apiErr.Message != "invalid_transition" {
		t.Errorf("expected message 'invalid_transition', got %q", apiErr.Message)
	}
}

func TestClient_ListPending(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()

	// Create two requests for dev1
	for i := 0; i < 2; i++ {
		if _, err := env.client.CreateRequest(ctx, "user1", "dev1", "conn1", "", 5*time.Minute); err != nil {
			t.Fatalf("CreateRequest: %v", err)
		}
	}
	// Create one for dev2
	if _, err := env.client.CreateRequest(ctx, "user1", "dev2", "conn1", "", 5*time.Minute); err != nil {
		t.Fatalf("CreateRequest: %v", err)
	}

	items, err := env.client.ListPending(ctx, "dev1")
	if err != nil {
		t.Fatalf("ListPending: %v", err)
	}
	if len(items) != 2 {
		t.Errorf("expected 2 pending for dev1, got %d", len(items))
	}

	// Empty list for unknown device
	empty, err := env.client.ListPending(ctx, "nodevice")
	if err != nil {
		t.Fatalf("ListPending: %v", err)
	}
	if len(empty) != 0 {
		t.Errorf("expected 0 items, got %d", len(empty))
	}
}

func TestClient_CreateSession(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()

	resp, err := env.client.CreateSession(ctx, "user1", "web", 5*time.Minute)
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
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
}

func TestClient_GetSession(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()

	created, err := env.client.CreateSession(ctx, "user1", "web", 5*time.Minute)
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	got, err := env.client.GetSession(ctx, created.Session.ID)
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if got.ID != created.Session.ID {
		t.Errorf("expected ID %s, got %s", created.Session.ID, got.ID)
	}
}

func TestClient_ApproveSession(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()

	created, err := env.client.CreateSession(ctx, "user1", "web", 5*time.Minute)
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	if err := env.client.ApproveSession(ctx, created.Session.ID); err != nil {
		t.Fatalf("ApproveSession: %v", err)
	}

	got, err := env.client.GetSession(ctx, created.Session.ID)
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if got.Status != "approved" {
		t.Errorf("expected status approved, got %s", got.Status)
	}
}

func TestClient_RegisterIdentity(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()

	created, err := env.client.CreateSession(ctx, "user1", "web", 5*time.Minute)
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	if err := env.client.RegisterIdentity(ctx, created.Session.ID, "conn1", "dev1"); err != nil {
		t.Fatalf("RegisterIdentity: %v", err)
	}

	got, err := env.client.GetSession(ctx, created.Session.ID)
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if got.ConnectorID != "conn1" {
		t.Errorf("expected connector_id conn1, got %s", got.ConnectorID)
	}
	if got.DeviceID != "dev1" {
		t.Errorf("expected device_id dev1, got %s", got.DeviceID)
	}
}

func TestClient_SessionResult(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()

	created, err := env.client.CreateSession(ctx, "user1", "web", 5*time.Minute)
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if err := env.client.ApproveSession(ctx, created.Session.ID); err != nil {
		t.Fatalf("ApproveSession: %v", err)
	}
	if err := env.client.RegisterIdentity(ctx, created.Session.ID, "conn1", "dev1"); err != nil {
		t.Fatalf("RegisterIdentity: %v", err)
	}

	if err := env.client.SessionResult(ctx, created.Session.ID, "installed", ""); err != nil {
		t.Fatalf("SessionResult: %v", err)
	}

	got, err := env.client.GetSession(ctx, created.Session.ID)
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if got.Status != "installed" {
		t.Errorf("expected status installed, got %s", got.Status)
	}
}

func TestClient_RedeemToken(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()

	created, err := env.client.CreateSession(ctx, "user1", "web", 5*time.Minute)
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	tokenDigest := access.DigestToken(created.InstallToken)

	// First redeem succeeds
	redeemed, err := env.client.RedeemToken(ctx, tokenDigest)
	if err != nil {
		t.Fatalf("RedeemToken: %v", err)
	}
	if redeemed.ID != created.Session.ID {
		t.Errorf("expected session ID %s, got %s", created.Session.ID, redeemed.ID)
	}

	// Second redeem fails (token consumed)
	_, err = env.client.RedeemToken(ctx, tokenDigest)
	if err == nil {
		t.Fatal("expected error on second redeem, got nil")
	}
	apiErr, ok := err.(*client.APIError)
	if !ok {
		t.Fatalf("expected *APIError, got %T: %v", err, err)
	}
	if apiErr.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404, got %d", apiErr.StatusCode)
	}
}

func TestClient_GetSigningKeys(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()

	keyset, err := env.client.GetSigningKeys(ctx)
	if err != nil {
		t.Fatalf("GetSigningKeys: %v", err)
	}
	if keyset.ActiveKID == "" {
		t.Error("expected non-empty active_kid")
	}
	if len(keyset.Keys) == 0 {
		t.Error("expected at least one key")
	}
	if keyset.Keys[0].PublicKeyB64 == "" {
		t.Error("expected non-empty public_key_b64")
	}
	if keyset.Keys[0].Alg != "ed25519" {
		t.Errorf("expected alg ed25519, got %s", keyset.Keys[0].Alg)
	}
}

func TestClient_AuthHeader(t *testing.T) {
	// Stand up a tiny server that checks for the Bearer token
	var gotAuth string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"active_kid":"v1","keys":[]}`))
	}))
	defer ts.Close()

	c := client.New(ts.URL, "my-secret-token")
	_, err := c.GetSigningKeys(context.Background())
	if err != nil {
		t.Fatalf("GetSigningKeys: %v", err)
	}
	if gotAuth != "Bearer my-secret-token" {
		t.Errorf("expected 'Bearer my-secret-token', got %q", gotAuth)
	}
}

func TestClient_RegisterConnector(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()

	bundle := map[string]string{
		"connector_id":   "conn1",
		"ssh_public_key": "ssh-ed25519 AAAATEST connector@tee",
		"quote_hex":      "abcd",
	}
	if err := env.client.RegisterConnector(ctx, bundle); err != nil {
		t.Fatalf("RegisterConnector: %v", err)
	}

	// Verify the connector is registered by creating a request, approving, and getting the bundle
	created, err := env.client.CreateRequest(ctx, "user1", "dev1", "conn1", "", 5*time.Minute)
	if err != nil {
		t.Fatalf("CreateRequest: %v", err)
	}
	if err := env.client.PostDecision(ctx, created.ID, true); err != nil {
		t.Fatalf("PostDecision: %v", err)
	}

	raw, err := env.client.GetBundle(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetBundle: %v", err)
	}

	// Parse the bundle to verify it contains the connector info
	var signed struct {
		Payload struct {
			ConnectorID string `json:"connector_id"`
		} `json:"payload"`
		Signature string `json:"signature"`
	}
	if err := json.Unmarshal(raw, &signed); err != nil {
		t.Fatalf("unmarshal bundle: %v", err)
	}
	if signed.Payload.ConnectorID != "conn1" {
		t.Errorf("expected connector_id conn1, got %s", signed.Payload.ConnectorID)
	}
	if signed.Signature == "" {
		t.Error("expected non-empty signature")
	}
}

func TestClient_GetBundle(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()

	// Register connector
	bundle := map[string]string{
		"connector_id":   "conn1",
		"ssh_public_key": "ssh-ed25519 AAAATEST connector@tee",
		"quote_hex":      "abcd",
	}
	if err := env.client.RegisterConnector(ctx, bundle); err != nil {
		t.Fatalf("RegisterConnector: %v", err)
	}

	// Create and approve request
	created, err := env.client.CreateRequest(ctx, "user1", "dev1", "conn1", "", 5*time.Minute)
	if err != nil {
		t.Fatalf("CreateRequest: %v", err)
	}
	if err := env.client.PostDecision(ctx, created.ID, true); err != nil {
		t.Fatalf("PostDecision: %v", err)
	}

	raw, err := env.client.GetBundle(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetBundle: %v", err)
	}

	if !json.Valid(raw) {
		t.Error("expected valid JSON from GetBundle")
	}
}

func TestClient_ListConnectors(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()

	for _, connectorID := range []string{"conn-a", "conn-b"} {
		bundle := map[string]string{
			"connector_id":   connectorID,
			"ssh_public_key": "ssh-ed25519 AAAATEST connector@tee",
			"quote_hex":      "abcd",
		}
		if err := env.client.RegisterConnector(ctx, bundle); err != nil {
			t.Fatalf("RegisterConnector(%s): %v", connectorID, err)
		}
	}

	items, err := env.client.ListConnectors(ctx)
	if err != nil {
		t.Fatalf("ListConnectors: %v", err)
	}
	if len(items) != 2 {
		t.Fatalf("expected 2 connectors, got %d", len(items))
	}
	if items[0].ConnectorID != "conn-a" || items[1].ConnectorID != "conn-b" {
		t.Fatalf("expected sorted connector IDs [conn-a conn-b], got [%s %s]", items[0].ConnectorID, items[1].ConnectorID)
	}
}

func TestClient_GetConnector(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()

	bundle := map[string]string{
		"connector_id":   "conn-1",
		"ssh_public_key": "ssh-ed25519 AAAATEST connector@tee",
		"quote_hex":      "abcd",
		"mrtd":           "mrtd-1",
	}
	if err := env.client.RegisterConnector(ctx, bundle); err != nil {
		t.Fatalf("RegisterConnector: %v", err)
	}

	got, err := env.client.GetConnector(ctx, "conn-1")
	if err != nil {
		t.Fatalf("GetConnector: %v", err)
	}
	if got.ConnectorID != "conn-1" {
		t.Fatalf("expected connector_id conn-1, got %s", got.ConnectorID)
	}
	if got.MRTD != "mrtd-1" {
		t.Fatalf("expected mrtd-1, got %s", got.MRTD)
	}
}

func TestClient_GetConnector_NotFound(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()

	_, err := env.client.GetConnector(ctx, "missing")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	apiErr, ok := err.(*client.APIError)
	if !ok {
		t.Fatalf("expected *APIError, got %T: %v", err, err)
	}
	if apiErr.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", apiErr.StatusCode)
	}
	if apiErr.Message != "not_found" {
		t.Fatalf("expected not_found, got %q", apiErr.Message)
	}
}

func TestClient_APIError(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()

	// Attempt to get a nonexistent request
	_, err := env.client.GetRequest(ctx, "nonexistent")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	apiErr, ok := err.(*client.APIError)
	if !ok {
		t.Fatalf("expected *APIError, got %T: %v", err, err)
	}
	if apiErr.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404, got %d", apiErr.StatusCode)
	}
	if apiErr.Message != "not_found" {
		t.Errorf("expected message 'not_found', got %q", apiErr.Message)
	}
}

func TestClient_ListRequests_FilterAndPagination(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()

	r1, err := env.client.CreateRequest(ctx, "user1", "dev1", "conn1", "", 5*time.Minute)
	if err != nil {
		t.Fatalf("CreateRequest r1: %v", err)
	}
	if _, err := env.client.CreateRequest(ctx, "user1", "dev1", "conn2", "", 5*time.Minute); err != nil {
		t.Fatalf("CreateRequest r2: %v", err)
	}
	if _, err := env.client.CreateRequest(ctx, "user2", "dev2", "conn3", "", 5*time.Minute); err != nil {
		t.Fatalf("CreateRequest r3: %v", err)
	}
	if err := env.client.PostDecision(ctx, r1.ID, true); err != nil {
		t.Fatalf("PostDecision: %v", err)
	}

	filtered, err := env.client.ListRequests(ctx, &client.ListRequestsOptions{
		DeviceID: "dev1",
		Status:   "approved",
		Limit:    10,
		Offset:   0,
	})
	if err != nil {
		t.Fatalf("ListRequests filtered: %v", err)
	}
	if len(filtered) != 1 {
		t.Fatalf("expected 1 filtered item, got %d", len(filtered))
	}
	if filtered[0].ID != r1.ID {
		t.Fatalf("expected approved request %s, got %s", r1.ID, filtered[0].ID)
	}

	paged, err := env.client.ListRequests(ctx, &client.ListRequestsOptions{
		Limit:  2,
		Offset: 1,
	})
	if err != nil {
		t.Fatalf("ListRequests paged: %v", err)
	}
	if len(paged) != 2 {
		t.Fatalf("expected 2 paged items, got %d", len(paged))
	}
}

func TestClient_ListRequests_InvalidStatus(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()

	_, err := env.client.ListRequests(ctx, &client.ListRequestsOptions{Status: "bogus"})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	apiErr, ok := err.(*client.APIError)
	if !ok {
		t.Fatalf("expected *APIError, got %T: %v", err, err)
	}
	if apiErr.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", apiErr.StatusCode)
	}
	if apiErr.Message != "invalid_status" {
		t.Fatalf("expected invalid_status, got %q", apiErr.Message)
	}
}

func TestClient_ListAudit_FilterAndPagination(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()

	if err := env.requests.Create(ctx, access.NewConnectionRequest("user1", "dev1", "conn1", "", 5*time.Minute)); err != nil {
		t.Fatalf("seed request: %v", err)
	}
	if err := env.client.RegisterConnector(ctx, map[string]string{
		"connector_id":   "c1",
		"ssh_public_key": "ssh-ed25519 AAAATEST connector@tee",
		"quote_hex":      "abcd",
	}); err != nil {
		t.Fatalf("register connector: %v", err)
	}

	filtered, err := env.client.ListAudit(ctx, &client.ListAuditOptions{
		EntityType: "connector",
		EntityID:   "c1",
		Limit:      10,
		Offset:     0,
	})
	if err != nil {
		t.Fatalf("ListAudit filtered: %v", err)
	}
	if len(filtered) == 0 {
		t.Fatal("expected at least one filtered audit entry")
	}

	paged, err := env.client.ListAudit(ctx, &client.ListAuditOptions{
		Limit:  1,
		Offset: 0,
	})
	if err != nil {
		t.Fatalf("ListAudit paged: %v", err)
	}
	if len(paged) != 1 {
		t.Fatalf("expected 1 paged entry, got %d", len(paged))
	}
}

func TestClient_ListAudit_InvalidSince(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()

	_, err := env.client.ListAudit(ctx, &client.ListAuditOptions{Since: "nope"})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	apiErr, ok := err.(*client.APIError)
	if !ok {
		t.Fatalf("expected *APIError, got %T: %v", err, err)
	}
	if apiErr.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", apiErr.StatusCode)
	}
	if apiErr.Message != "invalid_since" {
		t.Fatalf("expected invalid_since, got %q", apiErr.Message)
	}
}
