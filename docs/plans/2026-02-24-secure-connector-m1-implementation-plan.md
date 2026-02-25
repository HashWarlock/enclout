# Secure Connector M1 Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build M1 of Secure Connector with strict fail-closed local attestation verification, channel-agnostic chat-triggered access requests, and Linux/macOS local confirmation on every request.

**Architecture:** Use a split design. The control plane orchestrates channel requests and publishes signed attestation bundles, while the local Go agent is the trust anchor and enforces strict verification before enabling SSH trust. A TEE connector service derives deterministic identity material and publishes quote-bound metadata.

**Tech Stack:** Go 1.23 (`chi`, `ed25519`, `httptest`), TypeScript 5 / Node 22 (`@phala/dstack-sdk`, `@noble/ed25519`, `vitest`), JSON-over-HTTPS APIs, WebSocket/polling device notify.

---

## Execution Preconditions

- Create and use a dedicated worktree before coding (`@using-git-worktrees`).
- Execute tasks with strict TDD discipline (`@test-driven-development`).
- If test failures are unclear, pause and use `@systematic-debugging`.
- Before declaring completion, run full verification (`@verification-before-completion`).

## Task 1: Bootstrap Control Plane Config Loading

**Files:**
- Create: `services/control-plane/go.mod`
- Create: `services/control-plane/internal/config/config.go`
- Test: `services/control-plane/internal/config/config_test.go`

**Step 1: Write the failing test**

```go
func TestLoadConfigRequired(t *testing.T) {
	t.Setenv("BIND_ADDR", "127.0.0.1:8080")
	t.Setenv("SIGNING_KEY_B64", "")
	_, err := Load()
	require.Error(t, err)
	require.Contains(t, err.Error(), "SIGNING_KEY_B64")
}
```

**Step 2: Run test to verify it fails**

Run: `cd services/control-plane && go test ./internal/config -run TestLoadConfigRequired -v`  
Expected: FAIL with `undefined: Load`

**Step 3: Write minimal implementation**

```go
type Config struct {
	BindAddr     string
	SigningKeyB64 string
}

func Load() (Config, error) {
	cfg := Config{
		BindAddr:      os.Getenv("BIND_ADDR"),
		SigningKeyB64: os.Getenv("SIGNING_KEY_B64"),
	}
	if cfg.SigningKeyB64 == "" {
		return Config{}, fmt.Errorf("missing SIGNING_KEY_B64")
	}
	if cfg.BindAddr == "" {
		cfg.BindAddr = "127.0.0.1:8080"
	}
	return cfg, nil
}
```

**Step 4: Run test to verify it passes**

Run: `cd services/control-plane && go test ./internal/config -v`  
Expected: PASS

**Step 5: Commit**

```bash
git add services/control-plane/go.mod services/control-plane/internal/config/config.go services/control-plane/internal/config/config_test.go
git commit -m "feat(control-plane): add env config loader"
```

### Task 2: Add Connection Request State Machine + TTL/Nonce Store

**Files:**
- Create: `services/control-plane/internal/requests/model.go`
- Create: `services/control-plane/internal/requests/store.go`
- Test: `services/control-plane/internal/requests/store_test.go`

**Step 1: Write the failing test**

```go
func TestCreateAndExpireRequest(t *testing.T) {
	store := NewInMemoryStore(clock.NewMock())
	req, err := store.Create(CreateInput{
		OpenClawUserID: "usr_1",
		DeviceID:       "dev_1",
		ConnectorID:    "conn_1",
		SourceChannel:  "telegram",
		TTL:            5 * time.Minute,
	})
	require.NoError(t, err)
	require.Equal(t, StatusPendingLocalConfirm, req.Status)
}
```

**Step 2: Run test to verify it fails**

Run: `cd services/control-plane && go test ./internal/requests -run TestCreateAndExpireRequest -v`  
Expected: FAIL with `undefined: NewInMemoryStore`

**Step 3: Write minimal implementation**

```go
type Status string

const (
	StatusPendingLocalConfirm Status = "pending_local_confirm"
	StatusDeniedLocal         Status = "denied_local"
	StatusApproved            Status = "approved"
	StatusExpired             Status = "expired"
	StatusVerificationFailed  Status = "verification_failed"
	StatusConnected           Status = "connected"
)
```

```go
func (s *InMemoryStore) Create(in CreateInput) (ConnectionRequest, error) {
	nonce := uuid.NewString()
	now := s.clock.Now().UTC()
	req := ConnectionRequest{
		ID:             uuid.NewString(),
		OpenClawUserID: in.OpenClawUserID,
		DeviceID:       in.DeviceID,
		ConnectorID:    in.ConnectorID,
		SourceChannel:  in.SourceChannel,
		Status:         StatusPendingLocalConfirm,
		CreatedAt:      now,
		ExpiresAt:      now.Add(in.TTL),
		Nonce:          nonce,
	}
	s.items[req.ID] = req
	return req, nil
}
```

**Step 4: Run test to verify it passes**

Run: `cd services/control-plane && go test ./internal/requests -v`  
Expected: PASS

**Step 5: Commit**

```bash
git add services/control-plane/internal/requests/model.go services/control-plane/internal/requests/store.go services/control-plane/internal/requests/store_test.go
git commit -m "feat(control-plane): add connection request store with ttl"
```

### Task 3: Implement `POST /v1/connection-requests`

**Files:**
- Create: `services/control-plane/internal/http/create_request_handler.go`
- Modify: `services/control-plane/cmd/api/main.go`
- Test: `services/control-plane/internal/http/create_request_handler_test.go`

**Step 1: Write the failing test**

```go
func TestCreateRequestHandler(t *testing.T) {
	body := `{"openclaw_user_id":"usr_1","device_id":"dev_1","connector_id":"conn_1","source_channel":"slack"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/connection-requests", strings.NewReader(body))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	require.Equal(t, http.StatusCreated, rr.Code)
	require.Contains(t, rr.Body.String(), `"status":"pending_local_confirm"`)
}
```

**Step 2: Run test to verify it fails**

Run: `cd services/control-plane && go test ./internal/http -run TestCreateRequestHandler -v`  
Expected: FAIL with `nil pointer` or `handler not implemented`

**Step 3: Write minimal implementation**

```go
func (h *Handler) CreateRequest(w http.ResponseWriter, r *http.Request) {
	var in CreateRequestBody
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		http.Error(w, "invalid_json", http.StatusBadRequest)
		return
	}
	req, err := h.store.Create(requests.CreateInput{
		OpenClawUserID: in.OpenClawUserID,
		DeviceID:       in.DeviceID,
		ConnectorID:    in.ConnectorID,
		SourceChannel:  in.SourceChannel,
		TTL:            5 * time.Minute,
	})
	if err != nil {
		http.Error(w, "create_failed", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(req)
}
```

**Step 4: Run test to verify it passes**

Run: `cd services/control-plane && go test ./internal/http -run TestCreateRequestHandler -v`  
Expected: PASS

**Step 5: Commit**

```bash
git add services/control-plane/internal/http/create_request_handler.go services/control-plane/cmd/api/main.go services/control-plane/internal/http/create_request_handler_test.go
git commit -m "feat(control-plane): add create connection request endpoint"
```

### Task 4: Implement Local Decision + Status Result Endpoints

**Files:**
- Create: `services/control-plane/internal/http/local_decision_handler.go`
- Create: `services/control-plane/internal/http/result_handler.go`
- Modify: `services/control-plane/internal/requests/store.go`
- Test: `services/control-plane/internal/http/local_decision_handler_test.go`
- Test: `services/control-plane/internal/http/result_handler_test.go`

**Step 1: Write the failing tests**

```go
func TestLocalDecisionApproveTransition(t *testing.T) {
	// create pending request, call approve endpoint
	// expect status == approved
}
```

```go
func TestResultVerificationFailedTransition(t *testing.T) {
	// set approved request, post verification_failed result
	// expect status == verification_failed
}
```

**Step 2: Run tests to verify they fail**

Run: `cd services/control-plane && go test ./internal/http -run 'Test(LocalDecision|Result)' -v`  
Expected: FAIL with transition/state function missing

**Step 3: Write minimal implementation**

```go
func (s *InMemoryStore) SetLocalDecision(id string, approved bool) (ConnectionRequest, error) {
	req := s.items[id]
	if req.Status != StatusPendingLocalConfirm {
		return ConnectionRequest{}, ErrInvalidTransition
	}
	if approved {
		req.Status = StatusApproved
	} else {
		req.Status = StatusDeniedLocal
	}
	s.items[id] = req
	return req, nil
}
```

```go
func (s *InMemoryStore) SetResult(id string, status Status) (ConnectionRequest, error) {
	req := s.items[id]
	if req.Status != StatusApproved {
		return ConnectionRequest{}, ErrInvalidTransition
	}
	req.Status = status
	s.items[id] = req
	return req, nil
}
```

**Step 4: Run tests to verify they pass**

Run: `cd services/control-plane && go test ./internal/http -run 'Test(LocalDecision|Result)' -v`  
Expected: PASS

**Step 5: Commit**

```bash
git add services/control-plane/internal/http/local_decision_handler.go services/control-plane/internal/http/result_handler.go services/control-plane/internal/requests/store.go services/control-plane/internal/http/local_decision_handler_test.go services/control-plane/internal/http/result_handler_test.go
git commit -m "feat(control-plane): add local decision and result transitions"
```

### Task 5: Implement Signed Attestation Bundle Endpoint

**Files:**
- Create: `services/control-plane/internal/signing/attestation_bundle.go`
- Create: `services/control-plane/internal/http/attestation_bundle_handler.go`
- Test: `services/control-plane/internal/signing/attestation_bundle_test.go`
- Test: `services/control-plane/internal/http/attestation_bundle_handler_test.go`

**Step 1: Write the failing test**

```go
func TestSignAndVerifyBundle(t *testing.T) {
	signer := NewEd25519Signer(testPrivateKey)
	raw, sig := signer.SignBundle(sampleBundle)
	require.True(t, VerifyBundle(raw, sig, testPublicKey))
}
```

**Step 2: Run test to verify it fails**

Run: `cd services/control-plane && go test ./internal/signing -run TestSignAndVerifyBundle -v`  
Expected: FAIL with signer functions undefined

**Step 3: Write minimal implementation**

```go
func (s *Ed25519Signer) SignBundle(b BundlePayload) ([]byte, []byte, error) {
	raw, err := json.Marshal(b)
	if err != nil {
		return nil, nil, err
	}
	sig := ed25519.Sign(s.privateKey, raw)
	return raw, sig, nil
}
```

**Step 4: Run tests to verify they pass**

Run: `cd services/control-plane && go test ./internal/signing ./internal/http -run 'Test(SignAndVerifyBundle|GetAttestationBundle)' -v`  
Expected: PASS

**Step 5: Commit**

```bash
git add services/control-plane/internal/signing/attestation_bundle.go services/control-plane/internal/http/attestation_bundle_handler.go services/control-plane/internal/signing/attestation_bundle_test.go services/control-plane/internal/http/attestation_bundle_handler_test.go
git commit -m "feat(control-plane): sign and serve attestation bundles"
```

### Task 6: Add Channel-Agnostic OpenClaw Intent Adapter

**Files:**
- Create: `services/control-plane/internal/openclaw/intent_handler.go`
- Test: `services/control-plane/internal/openclaw/intent_handler_test.go`
- Modify: `services/control-plane/cmd/api/main.go`

**Step 1: Write the failing test**

```go
func TestIntentMapsToCreateRequest(t *testing.T) {
	body := `{"intent":"request_connector_access","openclaw_user_id":"usr_1","connector_id":"conn_1","device_id":"dev_1","source_channel":"telegram"}`
	// expect created request; source channel stored as metadata only
}
```

**Step 2: Run test to verify it fails**

Run: `cd services/control-plane && go test ./internal/openclaw -run TestIntentMapsToCreateRequest -v`  
Expected: FAIL with route/handler missing

**Step 3: Write minimal implementation**

```go
if payload.Intent != "request_connector_access" {
	http.Error(w, "unsupported_intent", http.StatusBadRequest)
	return
}
_, err := h.requests.Create(requests.CreateInput{
	OpenClawUserID: payload.OpenClawUserID,
	DeviceID:       payload.DeviceID,
	ConnectorID:    payload.ConnectorID,
	SourceChannel:  payload.SourceChannel,
	TTL:            5 * time.Minute,
})
```

**Step 4: Run test to verify it passes**

Run: `cd services/control-plane && go test ./internal/openclaw -v`  
Expected: PASS

**Step 5: Commit**

```bash
git add services/control-plane/internal/openclaw/intent_handler.go services/control-plane/internal/openclaw/intent_handler_test.go services/control-plane/cmd/api/main.go
git commit -m "feat(control-plane): add channel-agnostic openclaw intent adapter"
```

### Task 7: Build Local Agent API Client + Request Polling

**Files:**
- Create: `services/local-agent/go.mod`
- Create: `services/local-agent/internal/api/client.go`
- Test: `services/local-agent/internal/api/client_test.go`

**Step 1: Write the failing test**

```go
func TestPollPendingRequests(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `[{"id":"req_1","status":"pending_local_confirm"}]`)
	}))
	client := NewClient(srv.URL, "token")
	items, err := client.PollPending(context.Background(), "dev_1")
	require.NoError(t, err)
	require.Len(t, items, 1)
}
```

**Step 2: Run test to verify it fails**

Run: `cd services/local-agent && go test ./internal/api -run TestPollPendingRequests -v`  
Expected: FAIL with `undefined: NewClient`

**Step 3: Write minimal implementation**

```go
type Client struct {
	baseURL string
	token   string
	http    *http.Client
}

func (c *Client) PollPending(ctx context.Context, deviceID string) ([]Request, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/v1/devices/"+deviceID+"/pending-requests", nil)
	req.Header.Set("Authorization", "Bearer "+c.token)
	res, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	var out []Request
	err = json.NewDecoder(res.Body).Decode(&out)
	return out, err
}
```

**Step 4: Run test to verify it passes**

Run: `cd services/local-agent && go test ./internal/api -v`  
Expected: PASS

**Step 5: Commit**

```bash
git add services/local-agent/go.mod services/local-agent/internal/api/client.go services/local-agent/internal/api/client_test.go
git commit -m "feat(local-agent): add control-plane client and request polling"
```

### Task 8: Add Local Confirmation (Native Prompt + CLI Fallback)

**Files:**
- Create: `services/local-agent/internal/approval/prompter.go`
- Create: `services/local-agent/internal/approval/native_darwin.go`
- Create: `services/local-agent/internal/approval/native_linux.go`
- Create: `services/local-agent/internal/approval/cli_fallback.go`
- Test: `services/local-agent/internal/approval/prompter_test.go`

**Step 1: Write the failing test**

```go
func TestPromptFallsBackToCLI(t *testing.T) {
	p := NewPrompter(fakeNative{err: errors.New("unavailable")}, fakeCLI{decision: true})
	ok, err := p.Confirm(context.Background(), RequestSummary{ID: "req_1"})
	require.NoError(t, err)
	require.True(t, ok)
}
```

**Step 2: Run test to verify it fails**

Run: `cd services/local-agent && go test ./internal/approval -run TestPromptFallsBackToCLI -v`  
Expected: FAIL with constructor/method missing

**Step 3: Write minimal implementation**

```go
type Prompter struct {
	native DecisionSource
	cli    DecisionSource
}

func (p Prompter) Confirm(ctx context.Context, req RequestSummary) (bool, error) {
	ok, err := p.native.Confirm(ctx, req)
	if err == nil {
		return ok, nil
	}
	return p.cli.Confirm(ctx, req)
}
```

**Step 4: Run test to verify it passes**

Run: `cd services/local-agent && go test ./internal/approval -v`  
Expected: PASS

**Step 5: Commit**

```bash
git add services/local-agent/internal/approval/prompter.go services/local-agent/internal/approval/native_darwin.go services/local-agent/internal/approval/native_linux.go services/local-agent/internal/approval/cli_fallback.go services/local-agent/internal/approval/prompter_test.go
git commit -m "feat(local-agent): add native confirmation with cli fallback"
```

### Task 9: Implement Strict Verifier Pipeline + Fail-Closed Semantics

**Files:**
- Create: `services/local-agent/internal/verify/types.go`
- Create: `services/local-agent/internal/verify/verifier.go`
- Create: `services/local-agent/internal/verify/report_data.go`
- Test: `services/local-agent/internal/verify/verifier_test.go`
- Test: `services/local-agent/internal/verify/report_data_test.go`

**Step 1: Write the failing tests**

```go
func TestVerifyFailClosedOnDependencyError(t *testing.T) {
	v := NewStrictVerifier(fakeDCAP{err: errors.New("pccs timeout")})
	_, err := v.Verify(context.Background(), sampleBundle())
	require.Error(t, err)
	require.Contains(t, err.Error(), "AttestationDependencyFailure")
}
```

```go
func TestReportDataBinding(t *testing.T) {
	got := ComputeExpectedReportData(sampleSSHPublicKey)
	require.Equal(t, expected64BytesHex, hex.EncodeToString(got))
}
```

**Step 2: Run tests to verify they fail**

Run: `cd services/local-agent && go test ./internal/verify -run 'Test(VerifyFailClosedOnDependencyError|ReportDataBinding)' -v`  
Expected: FAIL with undefined verifier/report-data functions

**Step 3: Write minimal implementation**

```go
func ComputeExpectedReportData(sshPublicKey string) [64]byte {
	var out [64]byte
	sum := sha256.Sum256([]byte(sshPublicKey))
	copy(out[:32], sum[:])
	return out
}
```

```go
func (v *StrictVerifier) Verify(ctx context.Context, b Bundle) (Decision, error) {
	res, err := v.dcap.Verify(ctx, b.QuoteHex)
	if err != nil {
		return Decision{}, fmt.Errorf("AttestationDependencyFailure: %w", err)
	}
	if !res.QuoteValid || !res.QEIdentityValid || !res.TCBValid {
		return Decision{}, errors.New("QuoteInvalid")
	}
	if err := v.policy.CheckMeasurements(b); err != nil {
		return Decision{}, err
	}
	if !bytes.Equal(res.ReportData[:], ComputeExpectedReportData(b.SSHPublicKey)[:]) {
		return Decision{}, errors.New("ReportDataMismatch")
	}
	return Decision{Trusted: true}, nil
}
```

**Step 4: Run tests to verify they pass**

Run: `cd services/local-agent && go test ./internal/verify -v`  
Expected: PASS

**Step 5: Commit**

```bash
git add services/local-agent/internal/verify/types.go services/local-agent/internal/verify/verifier.go services/local-agent/internal/verify/report_data.go services/local-agent/internal/verify/verifier_test.go services/local-agent/internal/verify/report_data_test.go
git commit -m "feat(local-agent): add strict fail-closed attestation verifier"
```

### Task 10: Add Managed SSH Key Installation With Atomic Writes

**Files:**
- Create: `services/local-agent/internal/sshkeys/manager_unix.go`
- Test: `services/local-agent/internal/sshkeys/manager_unix_test.go`

**Step 1: Write the failing test**

```go
func TestInstallManagedKeyAtomicAndPermissioned(t *testing.T) {
	dir := t.TempDir()
	m := NewManager(dir)
	err := m.Install("alice", "ssh-ed25519 AAAATEST connector@tee")
	require.NoError(t, err)
	data, err := os.ReadFile(filepath.Join(dir, "alice", "authorized_keys"))
	require.NoError(t, err)
	require.Contains(t, string(data), "ssh-ed25519")
}
```

**Step 2: Run test to verify it fails**

Run: `cd services/local-agent && go test ./internal/sshkeys -run TestInstallManagedKeyAtomicAndPermissioned -v`  
Expected: FAIL with manager missing

**Step 3: Write minimal implementation**

```go
func (m *Manager) Install(username, pubKey string) error {
	userDir := filepath.Join(m.baseDir, username)
	if err := os.MkdirAll(userDir, 0o755); err != nil {
		return err
	}
	finalPath := filepath.Join(userDir, "authorized_keys")
	tmpPath := finalPath + ".tmp"
	if err := os.WriteFile(tmpPath, []byte(pubKey+"\n"), 0o644); err != nil {
		return err
	}
	return os.Rename(tmpPath, finalPath)
}
```

**Step 4: Run test to verify it passes**

Run: `cd services/local-agent && go test ./internal/sshkeys -v`  
Expected: PASS

**Step 5: Commit**

```bash
git add services/local-agent/internal/sshkeys/manager_unix.go services/local-agent/internal/sshkeys/manager_unix_test.go
git commit -m "feat(local-agent): add atomic managed authorized_keys installer"
```

### Task 11: Implement Agent Connection Flow Orchestrator

**Files:**
- Create: `services/local-agent/internal/flow/runner.go`
- Test: `services/local-agent/internal/flow/runner_test.go`
- Modify: `services/local-agent/cmd/agent/main.go`

**Step 1: Write the failing test**

```go
func TestRunnerHappyPath(t *testing.T) {
	r := NewRunner(fakeAPI{}, fakePrompter{approved: true}, fakeVerifier{trusted: true}, fakeKeys{})
	err := r.Process(context.Background(), sampleRequest())
	require.NoError(t, err)
	// assert local decision posted, bundle fetched, result posted connected
}
```

**Step 2: Run test to verify it fails**

Run: `cd services/local-agent && go test ./internal/flow -run TestRunnerHappyPath -v`  
Expected: FAIL with `undefined: NewRunner`

**Step 3: Write minimal implementation**

```go
func (r *Runner) Process(ctx context.Context, req api.Request) error {
	approved, err := r.prompter.Confirm(ctx, approval.RequestSummary{ID: req.ID, ConnectorID: req.ConnectorID})
	if err != nil {
		return err
	}
	if err := r.api.PostLocalDecision(ctx, req.ID, approved); err != nil || !approved {
		return err
	}
	bundle, err := r.api.GetAttestationBundle(ctx, req.ID)
	if err != nil {
		return err
	}
	decision, err := r.verifier.Verify(ctx, bundle)
	if err != nil || !decision.Trusted {
		_ = r.api.PostResult(ctx, req.ID, "verification_failed", "QuoteInvalid")
		return err
	}
	if err := r.keys.Install(req.LocalUser, bundle.SSHPublicKey); err != nil {
		_ = r.api.PostResult(ctx, req.ID, "verification_failed", "TransportFailure")
		return err
	}
	return r.api.PostResult(ctx, req.ID, "connected", "")
}
```

**Step 4: Run test to verify it passes**

Run: `cd services/local-agent && go test ./internal/flow -v`  
Expected: PASS

**Step 5: Commit**

```bash
git add services/local-agent/internal/flow/runner.go services/local-agent/internal/flow/runner_test.go services/local-agent/cmd/agent/main.go
git commit -m "feat(local-agent): orchestrate confirm-verify-connect flow"
```

### Task 12: Implement TEE Connector Identity + Metadata Publisher

**Files:**
- Create: `services/connector-tee/package.json`
- Create: `services/connector-tee/tsconfig.json`
- Create: `services/connector-tee/src/identity.ts`
- Create: `services/connector-tee/src/publish.ts`
- Create: `services/connector-tee/src/main.ts`
- Test: `services/connector-tee/src/__tests__/identity.test.ts`
- Test: `services/connector-tee/src/__tests__/publish.test.ts`

**Step 1: Write the failing tests**

```ts
it("derives deterministic ssh-ed25519 public key from 32-byte seed", async () => {
  const out = deriveEd25519Identity(Buffer.alloc(32, 7));
  expect(out.sshPublicKey.startsWith("ssh-ed25519 ")).toBe(true);
});
```

```ts
it("builds attestation payload with quote and report-data hash", async () => {
  const payload = buildAttestationPayload(sampleKey, sampleQuote, sampleMeasurements);
  expect(payload.report_data_expected_sha256).toMatch(/^[a-f0-9]{64}$/);
});
```

**Step 2: Run tests to verify they fail**

Run: `cd services/connector-tee && pnpm test`  
Expected: FAIL with missing functions/files

**Step 3: Write minimal implementation**

```ts
export function deriveEd25519Identity(seed: Uint8Array) {
  if (seed.length !== 32) throw new Error("seed must be 32 bytes");
  const publicKey = ed.getPublicKey(seed);
  const blob = Buffer.concat([encodeSSHString(Buffer.from("ssh-ed25519")), encodeSSHString(Buffer.from(publicKey))]);
  return { publicKey, sshPublicKey: `ssh-ed25519 ${blob.toString("base64")} connector@tee` };
}
```

```ts
export function buildAttestationPayload(sshPublicKey: string, quoteHex: string, m: Measurements) {
  const hash = createHash("sha256").update(sshPublicKey).digest("hex");
  return { ssh_public_key: sshPublicKey, quote_hex: quoteHex, report_data_expected_sha256: hash, ...m };
}
```

**Step 4: Run tests to verify they pass**

Run: `cd services/connector-tee && pnpm test`  
Expected: PASS

**Step 5: Commit**

```bash
git add services/connector-tee/package.json services/connector-tee/tsconfig.json services/connector-tee/src/identity.ts services/connector-tee/src/publish.ts services/connector-tee/src/main.ts services/connector-tee/src/__tests__/identity.test.ts services/connector-tee/src/__tests__/publish.test.ts
git commit -m "feat(connector-tee): publish deterministic identity and attestation metadata"
```

### Task 13: Add Cross-Component Integration Test (Strict Success + Strict Failure)

**Files:**
- Create: `tests/integration/strict_flow_test.go`
- Create: `tests/integration/testdata/valid_bundle.json`
- Create: `tests/integration/testdata/mismatched_report_data_bundle.json`

**Step 1: Write the failing tests**

```go
func TestStrictFlowSuccess(t *testing.T) {
	// fake orchestrator + fake dcap verifier(valid)
	// expect terminal status connected
}

func TestStrictFlowFailsOnReportDataMismatch(t *testing.T) {
	// fake orchestrator + fake dcap verifier(valid quote but mismatched report_data)
	// expect verification_failed with ReportDataMismatch
}
```

**Step 2: Run tests to verify they fail**

Run: `go test ./tests/integration -v`  
Expected: FAIL with harness missing

**Step 3: Write minimal implementation**

```go
// Build httptest control-plane server with in-memory store.
// Run local-agent runner against valid and invalid bundle fixtures.
// Assert posted status transitions and reason codes.
```

**Step 4: Run tests to verify they pass**

Run: `go test ./tests/integration -v`  
Expected: PASS

**Step 5: Commit**

```bash
git add tests/integration/strict_flow_test.go tests/integration/testdata/valid_bundle.json tests/integration/testdata/mismatched_report_data_bundle.json
git commit -m "test(integration): add strict success and report-data mismatch flows"
```

### Task 14: Add Operator Docs + Verification Scripts

**Files:**
- Create: `docs/runbooks/connector-access-flow.md`
- Create: `docs/runbooks/attestation-failure-codes.md`
- Create: `scripts/verify-m1.sh`
- Modify: `README.md`

**Step 1: Write failing verification script check**

```bash
#!/usr/bin/env bash
set -euo pipefail
go test ./... >/dev/null
pnpm --dir services/connector-tee test >/dev/null
```

**Step 2: Run script to verify it fails before docs/README wiring**

Run: `bash scripts/verify-m1.sh`  
Expected: FAIL until all modules/tests are wired correctly

**Step 3: Write minimal docs and script wiring**

```md
# Connector Access Flow
1. Chat request
2. Local prompt
3. Strict verification
4. Connected or reason-coded failure
```

**Step 4: Run script to verify it passes**

Run: `bash scripts/verify-m1.sh`  
Expected: PASS

**Step 5: Commit**

```bash
git add docs/runbooks/connector-access-flow.md docs/runbooks/attestation-failure-codes.md scripts/verify-m1.sh README.md
git commit -m "docs: add runbooks and m1 verification script"
```

## Definition of Done

- Chat-triggered connector requests are channel-agnostic and mapped to OpenClaw user identity.
- Local confirmation is required on every request (native prompt with CLI fallback).
- Local agent enforces strict fail-closed verification before trust/connection.
- Attestation bundle signature, nonce, expiry, measurement policy, and report-data binding are all validated.
- Linux/macOS key installation uses managed authorized keys path with atomic updates.
- Unit + integration tests pass via `scripts/verify-m1.sh`.
