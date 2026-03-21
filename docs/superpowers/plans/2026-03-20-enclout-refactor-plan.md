# Enclout Single Binary Refactor — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Consolidate three services (Go control-plane, Go local-agent, Node.js connector-tee) into a single Go binary (`enclout`) with CLI subcommands, SQLite persistence, and an MCP server layer.

**Architecture:** Domain-driven packages under `internal/` with thin CLI and MCP entry points. SQLite replaces file-backed JSON. TEE identity ported from Node.js to Go. All OpenClaw coupling removed.

**Tech Stack:** Go 1.23, Cobra (CLI), modernc.org/sqlite, golang.org/x/crypto/ssh, mcp-go (MCP server), slog (structured logging)

**Spec:** `docs/superpowers/specs/2026-03-20-enclout-refactor-design.md`

---

## File Map

### New files to create

```
cmd/enclout/main.go           — Cobra root command + version
cmd/enclout/serve.go           — enclout serve subcommand
cmd/enclout/agent.go           — enclout agent subcommand
cmd/enclout/connect.go         — enclout connect subcommand
cmd/enclout/install.go         — enclout install subcommand
cmd/enclout/status.go          — enclout status subcommand
cmd/enclout/mcp.go             — enclout mcp subcommand

internal/access/request.go     — ConnectionRequest model + state transitions
internal/access/request_test.go
internal/access/session.go     — InstallSession model + state transitions
internal/access/session_test.go
internal/access/id.go          — random ID + token digest helpers
internal/access/errors.go      — shared domain errors (ErrNotFound, ErrInvalidTransition, ErrExpired)

internal/signing/bundle.go     — BundlePayload, SignedBundle, ConnectorBundle types
internal/signing/signer.go     — Ed25519Signer, SignerSet, keyset rotation
internal/signing/verify.go     — signature verification, report data hash
internal/signing/signer_test.go
internal/signing/verify_test.go

internal/identity/ed25519.go   — deterministic Ed25519 derivation from seed
internal/identity/ssh.go       — SSH authorized_keys format encoding
internal/identity/dstack.go    — dstack SDK Go client (HTTP over Unix socket)
internal/identity/env.go       — EnvDeriver for dev/testing
internal/identity/identity.go  — Deriver interface + ConnectorIdentity/Attestation types
internal/identity/ed25519_test.go
internal/identity/ssh_test.go
internal/identity/dstack_test.go

internal/attestation/verifier.go — StrictVerifier (DCAP + measurements + report-data)
internal/attestation/dcap.go     — HTTP DCAP client
internal/attestation/policy.go   — measurement allowlist policy
internal/attestation/types.go    — Bundle, Decision, VerificationError types
internal/attestation/verifier_test.go
internal/attestation/policy_test.go

internal/store/sqlite.go       — DB connection, WAL mode, migration runner (embed.FS passed in)

migrations/migrations.go       — top-level embed.FS for SQL files (Go embed cannot use '..' paths)
internal/store/requests.go     — RequestRepository (SQLite)
internal/store/sessions.go     — SessionRepository (SQLite)
internal/store/bundles.go      — BundleRepository (SQLite)
internal/store/audit.go        — AuditLogger (SQLite)
internal/store/store_test.go

internal/server/router.go      — Go 1.23 stdlib mux with path patterns
internal/server/handlers.go    — request/session/bundle/signing-keys handlers
internal/server/middleware.go   — auth, request ID, structured logging
internal/server/server.go      — Server struct with graceful shutdown
internal/server/server_test.go

internal/client/client.go      — typed HTTP client (agent -> server)
internal/client/client_test.go

internal/agent/daemon.go       — poll loop with jitter + backoff
internal/agent/approval.go     — Prompter interface + native/CLI implementations
internal/agent/sshkeys.go      — authorized_keys manager
internal/agent/runner.go       — request processing orchestrator (flow)
internal/agent/daemon_test.go
internal/agent/runner_test.go

internal/mcpserver/tools.go    — MCP tool schemas + handlers
internal/mcpserver/tools_test.go

internal/config/config.go      — unified config (flags + env + TOML file)
internal/config/config_test.go

migrations/001_initial.sql     — full SQLite schema

testdata/golden_ssh_key.txt    — SSH key golden fixture from Node.js

go.mod
go.sum
Makefile
.github/workflows/ci.yml
```

### Files to delete (final cleanup)

```
services/control-plane/        — entire directory
services/local-agent/          — entire directory
services/connector-tee/        — entire directory
skills/enclout-openclaw-agent/ — entire directory
```

---

## Task Dependency Graph

```
Task 1 (scaffolding)
  ├── Task 2 (access/request) ──┐
  ├── Task 3 (access/session) ──┤
  ├── Task 4 (signing) ─────────┤
  ├── Task 5 (identity) ────────┤
  ├── Task 6 (attestation) ─────┤
  │                              │
  │                              ▼
  │                         Task 7 (store: foundation)
  │                           ├── Task 8 (store: requests)
  │                           ├── Task 9 (store: sessions)
  │                           └── Task 10 (store: bundles + audit)
  │                                      │
  │                                      ▼
  ├── Task 11 (config) ──────────► Task 12 (HTTP server)
  │                                      │
  │                                      ▼
  │                               Task 13 (HTTP client)
  │                                 │          │
  │                                 ▼          ▼
  │                         Task 14 (agent) Task 17 (MCP server)
  │                                 │          │
  │                                 ▼          ▼
  └── Task 15 (CLI: main+serve+agent)  Task 18 (CLI: mcp)
              │
              ▼
      Task 16 (CLI: connect+install+status)
              │
              ▼
      Task 19 (CI + Makefile)
              │
              ▼
      Task 20 (cleanup old code)
```

Tasks 2-6 are independent of each other and can be parallelized.
Tasks 8-10 are independent of each other and can be parallelized.

---

### Task 1: Project Scaffolding

**Files:**
- Create: `go.mod`
- Create: `Makefile`
- Create: `migrations/001_initial.sql`
- Create: `cmd/enclout/main.go` (stub)

- [ ] **Step 1: Initialize Go module**

**Important:** The old `go.mod` files live inside `services/control-plane/` and `services/local-agent/`. Do NOT delete them yet — they stay until Task 20 (cleanup). The new root `go.mod` uses the same module name `enclout`. Go tooling will prefer the root module for new code under `cmd/` and `internal/`. The old service directories keep their own modules and continue to compile independently until cleanup.

```bash
cd /Users/hashwarlock/Projects/AI/enclout
go mod init enclout
```

- [ ] **Step 2: Add dependencies**

```bash
go get github.com/spf13/cobra@latest
go get modernc.org/sqlite@latest
go get golang.org/x/crypto@latest
```

- [ ] **Step 3: Create directory structure**

```bash
mkdir -p cmd/enclout
mkdir -p internal/{access,signing,identity,attestation,store,server,client,agent,mcpserver,config}
mkdir -p migrations testdata
```

- [ ] **Step 4: Write SQL migration**

Create `migrations/001_initial.sql` with the full schema from the spec:
- `connection_requests` table with `idx_requests_device_status` index
- `install_sessions` table with `idx_install_token` partial unique index
- `audit_log` table with entity and time indexes
- `connector_bundles` table with `info` JSON column

```sql
-- migrations/001_initial.sql

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
```

- [ ] **Step 5: Write stub main.go**

Create `cmd/enclout/main.go`:

```go
package main

import (
    "fmt"
    "os"

    "github.com/spf13/cobra"
)

var version = "dev"

func main() {
    root := &cobra.Command{
        Use:   "enclout",
        Short: "Secure connector with TEE-attested SSH key derivation",
    }

    root.AddCommand(&cobra.Command{
        Use:   "version",
        Short: "Print version",
        Run: func(cmd *cobra.Command, args []string) {
            fmt.Println(version)
        },
    })

    if err := root.Execute(); err != nil {
        os.Exit(1)
    }
}
```

- [ ] **Step 6: Write Makefile**

```makefile
.PHONY: build test lint clean

build:
	go build -o bin/enclout ./cmd/enclout

test:
	go test ./... -race -count=1

lint:
	go vet ./...

clean:
	rm -rf bin/
```

- [ ] **Step 7: Verify build compiles**

```bash
make build
./bin/enclout version
```

Expected: prints `dev`

- [ ] **Step 8: Commit**

```bash
git add cmd/ internal/ migrations/ testdata/ go.mod Makefile
git commit -m "feat: scaffold single-binary project structure"
```

---

### Task 2: Domain Model — ConnectionRequest

**Files:**
- Create: `internal/access/id.go`
- Create: `internal/access/request.go`
- Create: `internal/access/request_test.go`

**Reference:** `services/control-plane/internal/requests/model.go` (existing model), spec section "ConnectionRequest"

- [ ] **Step 1: Write shared errors and id helpers**

Create `internal/access/errors.go`:

```go
package access

import "errors"

var (
    ErrNotFound          = errors.New("not found")
    ErrInvalidTransition = errors.New("invalid status transition")
    ErrExpired           = errors.New("expired")
)
```

Create `internal/access/id.go` with `RandomID()` (UUID-like) and `DigestToken(token string) string` (SHA256 hex). Port from existing `services/control-plane/internal/requests/id.go`.

```go
package access

import (
    "crypto/rand"
    "crypto/sha256"
    "encoding/hex"
    "fmt"
    "strings"
)

func RandomID() string {
    b := make([]byte, 16)
    _, _ = rand.Read(b)
    return fmt.Sprintf("%x", b)
}

func DigestToken(token string) string {
    sum := sha256.Sum256([]byte(strings.TrimSpace(token)))
    return hex.EncodeToString(sum[:])
}
```

- [ ] **Step 2: Write failing tests for ConnectionRequest**

Create `internal/access/request_test.go`:

```go
package access_test

import (
    "testing"
    "time"

    "enclout/internal/access"
)

func TestNewConnectionRequest(t *testing.T) {
    req := access.NewConnectionRequest("req-1", "dev-1", "conn-1", "cli", 5*time.Minute)
    if req.Status != access.StatusPendingLocalConfirm {
        t.Fatalf("expected pending_local_confirm, got %s", req.Status)
    }
    if req.RequesterID != "req-1" {
        t.Fatalf("expected req-1, got %s", req.RequesterID)
    }
}

func TestConnectionRequest_Approve(t *testing.T) {
    req := access.NewConnectionRequest("req-1", "dev-1", "conn-1", "cli", 5*time.Minute)
    if err := req.Approve(); err != nil {
        t.Fatalf("unexpected error: %v", err)
    }
    if req.Status != access.StatusApproved {
        t.Fatalf("expected approved, got %s", req.Status)
    }
}

func TestConnectionRequest_Approve_WrongState(t *testing.T) {
    req := access.NewConnectionRequest("req-1", "dev-1", "conn-1", "cli", 5*time.Minute)
    _ = req.Approve()
    if err := req.Approve(); err == nil {
        t.Fatal("expected error for double approve")
    }
}

func TestConnectionRequest_Deny(t *testing.T) {
    req := access.NewConnectionRequest("req-1", "dev-1", "conn-1", "cli", 5*time.Minute)
    if err := req.Deny(); err != nil {
        t.Fatalf("unexpected error: %v", err)
    }
    if req.Status != access.StatusDeniedLocal {
        t.Fatalf("expected denied_local, got %s", req.Status)
    }
}

func TestConnectionRequest_SetResult_Connected(t *testing.T) {
    req := access.NewConnectionRequest("req-1", "dev-1", "conn-1", "cli", 5*time.Minute)
    _ = req.Approve()
    if err := req.SetResult(access.StatusConnected, ""); err != nil {
        t.Fatalf("unexpected error: %v", err)
    }
    if req.Status != access.StatusConnected {
        t.Fatalf("expected connected, got %s", req.Status)
    }
}

func TestConnectionRequest_SetResult_VerificationFailed(t *testing.T) {
    req := access.NewConnectionRequest("req-1", "dev-1", "conn-1", "cli", 5*time.Minute)
    _ = req.Approve()
    if err := req.SetResult(access.StatusVerificationFailed, "MeasurementMismatch"); err != nil {
        t.Fatalf("unexpected error: %v", err)
    }
    if req.ReasonCode != "MeasurementMismatch" {
        t.Fatalf("expected MeasurementMismatch, got %s", req.ReasonCode)
    }
}

func TestConnectionRequest_Expire(t *testing.T) {
    req := access.NewConnectionRequest("req-1", "dev-1", "conn-1", "cli", 5*time.Minute)
    if err := req.Expire(); err != nil {
        t.Fatalf("unexpected error: %v", err)
    }
    if req.Status != access.StatusExpired {
        t.Fatalf("expected expired, got %s", req.Status)
    }
}
```

- [ ] **Step 3: Run tests to verify they fail**

```bash
go test ./internal/access/... -v
```

Expected: FAIL — types not defined yet.

- [ ] **Step 4: Implement ConnectionRequest**

Create `internal/access/request.go`:

```go
package access

import "time"

type Status string

const (
    StatusPendingLocalConfirm Status = "pending_local_confirm"
    StatusApproved            Status = "approved"
    StatusDeniedLocal         Status = "denied_local"
    StatusExpired             Status = "expired"
    StatusVerificationFailed  Status = "verification_failed"
    StatusConnected           Status = "connected"
)

type ConnectionRequest struct {
    ID          string
    RequesterID string
    DeviceID    string
    ConnectorID string
    Source      string
    Status      Status
    CreatedAt   time.Time
    ExpiresAt   time.Time
    Nonce       string
    ReasonCode  string
}

func NewConnectionRequest(requesterID, deviceID, connectorID, source string, ttl time.Duration) ConnectionRequest {
    now := time.Now().UTC()
    return ConnectionRequest{
        ID:          RandomID(),
        RequesterID: requesterID,
        DeviceID:    deviceID,
        ConnectorID: connectorID,
        Source:      source,
        Status:      StatusPendingLocalConfirm,
        CreatedAt:   now,
        ExpiresAt:   now.Add(ttl),
        Nonce:       RandomID(),
    }
}

func (r *ConnectionRequest) Approve() error {
    if r.Status != StatusPendingLocalConfirm {
        return ErrInvalidTransition
    }
    r.Status = StatusApproved
    return nil
}

func (r *ConnectionRequest) Deny() error {
    if r.Status != StatusPendingLocalConfirm {
        return ErrInvalidTransition
    }
    r.Status = StatusDeniedLocal
    return nil
}

func (r *ConnectionRequest) Expire() error {
    if r.Status != StatusPendingLocalConfirm && r.Status != StatusApproved {
        return ErrInvalidTransition
    }
    r.Status = StatusExpired
    return nil
}

func (r *ConnectionRequest) SetResult(status Status, reasonCode string) error {
    if r.Status != StatusApproved {
        return ErrInvalidTransition
    }
    if status != StatusConnected && status != StatusVerificationFailed {
        return ErrInvalidTransition
    }
    r.Status = status
    r.ReasonCode = reasonCode
    return nil
}
```

- [ ] **Step 5: Run tests to verify they pass**

```bash
go test ./internal/access/... -v -run TestConnectionRequest
```

Expected: all PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/access/
git commit -m "feat(access): add ConnectionRequest domain model with state transitions"
```

---

### Task 3: Domain Model — InstallSession

**Files:**
- Create: `internal/access/session.go`
- Modify: `internal/access/request_test.go` (add session tests, or create separate file)

**Reference:** Spec section "InstallSession", existing `services/control-plane/internal/requests/store.go:173-358`

- [ ] **Step 1: Write failing tests for InstallSession**

Add to `internal/access/session_test.go`:

Test cases:
- `TestNewInstallSession` — creates with status `requested`, sets token digest
- `TestInstallSession_Approve` — requested -> approved
- `TestInstallSession_Deny` — requested -> failed with reason "Denied"
- `TestInstallSession_Register` — sets connectorID + deviceID from requested or approved
- `TestInstallSession_Register_TerminalState` — fails from installed/failed
- `TestInstallSession_Complete` — approved (with identity) -> installed
- `TestInstallSession_Complete_NoIdentity` — fails if connectorID/deviceID empty
- `TestInstallSession_Fail` — approved -> failed with reason
- `TestInstallSession_Expire` — requested|approved -> failed with reason "Expired"

- [ ] **Step 2: Run tests to verify they fail**

```bash
go test ./internal/access/... -v -run TestInstallSession
```

- [ ] **Step 3: Implement InstallSession**

Create `internal/access/session.go` with:
- `InstallStatus` type and constants (Requested, Approved, Installed, Failed)
- `InstallSession` struct matching spec
- `NewInstallSession(requesterID, source string, ttl time.Duration) (InstallSession, string)` — returns session + raw token
- All transition methods: `Approve()`, `Deny()`, `Register()`, `Complete()`, `Fail()`, `Expire()`

- [ ] **Step 4: Run tests to verify they pass**

```bash
go test ./internal/access/... -v
```

- [ ] **Step 5: Commit**

```bash
git add internal/access/session.go internal/access/session_test.go
git commit -m "feat(access): add InstallSession domain model with state transitions"
```

---

### Task 4: Signing Package

**Files:**
- Create: `internal/signing/bundle.go`
- Create: `internal/signing/signer.go`
- Create: `internal/signing/verify.go`
- Create: `internal/signing/signer_test.go`
- Create: `internal/signing/verify_test.go`

**Reference:** `services/control-plane/internal/signing/attestation_bundle.go` (port directly)

- [ ] **Step 1: Write bundle types**

Create `internal/signing/bundle.go` with `BundlePayload`, `SignedBundle`, `PublicKeyInfo`, `SigningKeyset`, `BundleSigner` interface. Direct port from existing code.

- [ ] **Step 2: Write failing signer tests**

Create `internal/signing/signer_test.go`:
- `TestEd25519Signer_SignBundle` — sign + verify round-trip
- `TestSignerSet_SignBundle` — multi-key set signs with active KID
- `TestSignerSet_Keyset` — returns correct keyset structure
- `TestNewSignerSetFromSeedMap_ActiveKIDRequired` — errors if active KID missing

- [ ] **Step 3: Run tests to verify they fail**

```bash
go test ./internal/signing/... -v
```

- [ ] **Step 4: Implement signer.go**

Port `Ed25519Signer`, `SignerSet`, `NewEd25519SignerFromSeedB64`, `NewEd25519SignerWithKIDFromSeedB64`, `NewSignerSetFromSeedMap`, `marshalCanonical` from existing `services/control-plane/internal/signing/attestation_bundle.go`.

- [ ] **Step 5: Run tests to verify they pass**

```bash
go test ./internal/signing/... -v -run TestEd25519Signer
go test ./internal/signing/... -v -run TestSignerSet
```

- [ ] **Step 6: Write failing verify tests**

Create `internal/signing/verify_test.go`:
- `TestVerifyBundle_ValidSignature` — sign then verify returns true
- `TestVerifyBundle_InvalidSignature` — tampered signature returns false
- `TestVerifyBundle_WrongKey` — different key returns false
- `TestReportDataHash` — SHA256 of SSH public key matches expected hex

- [ ] **Step 7: Implement verify.go**

Port `VerifyBundle`, `VerifySignedBundleWithKeyset`, `ReportDataHashFromSSHPublicKey` from existing code. The keyset verification logic currently lives in `services/local-agent/internal/verify/control_plane_signature.go`.

- [ ] **Step 8: Run all signing tests**

```bash
go test ./internal/signing/... -v
```

- [ ] **Step 9: Commit**

```bash
git add internal/signing/
git commit -m "feat(signing): port Ed25519 bundle signing and verification"
```

---

### Task 5: Identity Package (TEE Port)

**Files:**
- Create: `internal/identity/identity.go` — types + Deriver interface
- Create: `internal/identity/ed25519.go`
- Create: `internal/identity/ssh.go`
- Create: `internal/identity/dstack.go`
- Create: `internal/identity/env.go`
- Create: `internal/identity/ed25519_test.go`
- Create: `internal/identity/ssh_test.go`
- Create: `internal/identity/dstack_test.go`
- Create: `testdata/golden_ssh_key.txt`

**Reference:** `services/connector-tee/src/identity.js`, `services/connector-tee/src/tee.js`

- [ ] **Step 1: Generate golden test fixture**

Run the existing Node.js code with a known seed to capture expected output:

```bash
cd services/connector-tee
node --input-type=module -e "
import {deriveEd25519Identity} from './src/identity.js';
const seed = Buffer.alloc(32, 0x42);
const id = deriveEd25519Identity(seed);
console.log(id.sshPublicKey);
"
```

Save output to `testdata/golden_ssh_key.txt`.

- [ ] **Step 2: Write identity types**

Create `internal/identity/identity.go`:

```go
package identity

import "context"

type ConnectorIdentity struct {
    ConnectorID       string
    SSHPublicKey      string
    PublicKeyHex      string
    FingerprintSHA256 string
}

type Attestation struct {
    QuoteHex                 string
    MRTD                     string
    RTMR0                    string
    RTMR1                    string
    RTMR2                    string
    RTMR3                    string
    EventLog                 string
    ReportDataExpectedSHA256 string
    PolicyVersion            string
}

type DstackInfo struct {
    AppID      string
    InstanceID string
    AppName    string
    TCBInfo    string
}

type Deriver interface {
    DeriveIdentity(ctx context.Context, connectorID string) (ConnectorIdentity, Attestation, error)
}
```

- [ ] **Step 3: Write failing Ed25519 tests**

Create `internal/identity/ed25519_test.go`:
- `TestDeriveEd25519_Deterministic` — same seed produces same key pair
- `TestDeriveEd25519_InvalidSeedLength` — non-32-byte seed errors
- `TestDeriveEd25519_SignVerify` — derived key can sign and verify

- [ ] **Step 4: Implement ed25519.go**

```go
package identity

import (
    "crypto/ed25519"
    "fmt"
)

func DeriveEd25519(seed []byte) (ed25519.PublicKey, ed25519.PrivateKey, error) {
    if len(seed) != ed25519.SeedSize {
        return nil, nil, fmt.Errorf("seed must be %d bytes, got %d", ed25519.SeedSize, len(seed))
    }
    priv := ed25519.NewKeyFromSeed(seed)
    pub := priv.Public().(ed25519.PublicKey)
    return pub, priv, nil
}
```

- [ ] **Step 5: Run Ed25519 tests**

```bash
go test ./internal/identity/... -v -run TestDeriveEd25519
```

- [ ] **Step 6: Write failing SSH tests (including golden test)**

Create `internal/identity/ssh_test.go`:
- `TestSSHPublicKeyString_Format` — output starts with `ssh-ed25519 `
- `TestSSHPublicKeyString_GoldenMatch` — output matches `testdata/golden_ssh_key.txt`
- `TestSSHFingerprint` — SHA256 fingerprint is 64 hex chars

- [ ] **Step 7: Implement ssh.go**

```go
package identity

import (
    "crypto/ed25519"
    "crypto/sha256"
    "encoding/hex"
    "strings"

    "golang.org/x/crypto/ssh"
)

func SSHPublicKeyString(pub ed25519.PublicKey) (string, error) {
    sshPub, err := ssh.NewPublicKey(pub)
    if err != nil {
        return "", err
    }
    // MarshalAuthorizedKey returns "ssh-ed25519 AAAA...\n"
    return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub))), nil
}

func SSHFingerprint(sshPublicKey string) string {
    sum := sha256.Sum256([]byte(sshPublicKey))
    return hex.EncodeToString(sum[:])
}
```

- [ ] **Step 8: Run SSH tests (golden test must pass)**

```bash
go test ./internal/identity/... -v -run TestSSH
```

Expected: golden test PASSES — Go output matches Node.js output byte-for-byte.

**Note:** If `ssh.MarshalAuthorizedKey` produces a different comment suffix than the Node.js code (which appends `connector@tee`), the golden test may need adjustment. The SSH key material (base64 blob) must match; the trailing comment is cosmetic. Adjust the test to compare only the key type + base64 portion if needed.

- [ ] **Step 9: Write dstack client + EnvDeriver**

Create `internal/identity/dstack.go` with `DstackClient` struct:
- HTTP client configured for Unix socket transport (or simulator HTTP endpoint)
- `GetKey(ctx, path, subject)` -> `[]byte` (32-byte seed)
- `GetQuote(ctx, reportData)` -> `(quoteHex, eventLog string, err error)`
- `Info(ctx)` -> `(DstackInfo, error)`

Create `internal/identity/env.go` with `EnvDeriver`:
- Reads `TEE_SEED_B64` and `TEE_QUOTE_HEX` from environment
- Implements `Deriver` interface

Create `internal/identity/dstack_test.go` with `httptest.Server` simulating dstack responses.

- [ ] **Step 10: Run all identity tests**

```bash
go test ./internal/identity/... -v
```

- [ ] **Step 11: Commit**

```bash
git add internal/identity/ testdata/
git commit -m "feat(identity): port TEE Ed25519 derivation and SSH encoding from Node.js"
```

---

### Task 6: Attestation Package

**Files:**
- Create: `internal/attestation/types.go`
- Create: `internal/attestation/verifier.go`
- Create: `internal/attestation/dcap.go`
- Create: `internal/attestation/policy.go`
- Create: `internal/attestation/verifier_test.go`
- Create: `internal/attestation/policy_test.go`

**Reference:** `services/local-agent/internal/verify/verifier.go`, `dcap.go`, `policy.go`

- [ ] **Step 1: Write types**

Create `internal/attestation/types.go`: `Bundle`, `Decision`, `VerificationError`, `DCAPResult`, reason code constants. Direct port from existing `services/local-agent/internal/verify/`.

- [ ] **Step 2: Write failing policy tests**

Create `internal/attestation/policy_test.go`:
- `TestStaticPolicy_AllowedMeasurements` — matching MRTD/RTMR3 passes
- `TestStaticPolicy_DisallowedMRTD` — mismatched MRTD fails
- `TestStaticPolicy_EmptyAllowlistAllowsAll` — empty list is permissive

- [ ] **Step 3: Implement policy.go**

Port `MeasurementPolicy`, `StaticPolicy`, `CheckMeasurements` from existing `services/local-agent/internal/verify/policy.go`.

- [ ] **Step 4: Run policy tests**

```bash
go test ./internal/attestation/... -v -run TestStaticPolicy
```

- [ ] **Step 5: Write failing verifier tests**

Create `internal/attestation/verifier_test.go`:
- `TestStrictVerifier_AllChecksPass` — returns Trusted decision
- `TestStrictVerifier_QuoteInvalid` — DCAP returns invalid -> VerificationError
- `TestStrictVerifier_MeasurementMismatch` — policy rejects -> VerificationError
- `TestStrictVerifier_ReportDataMismatch` — report data doesn't match SSH key hash
- `TestStrictVerifier_DCAPUnavailable` — DCAP client error -> AttestationDependencyFailure

Use a fake `DCAPVerifier` interface implementation for tests.

- [ ] **Step 6: Implement verifier.go and dcap.go**

Port `StrictVerifier`, `ComputeExpectedReportData` from existing `verifier.go`.
Port `HTTPDCAPVerifier` from existing `services/local-agent/internal/verify/dcap.go`.

- [ ] **Step 7: Run all attestation tests**

```bash
go test ./internal/attestation/... -v
```

- [ ] **Step 8: Commit**

```bash
git add internal/attestation/
git commit -m "feat(attestation): port strict DCAP verification and measurement policy"
```

---

### Task 7: Store — SQLite Foundation

**Files:**
- Create: `internal/store/sqlite.go`

**Reference:** Spec section "Storage Layer"

- [ ] **Step 1: Create migrations embed package**

Go's `//go:embed` does not support `..` paths. Create a top-level embed file at `migrations/migrations.go`:

```go
package migrations

import "embed"

//go:embed *.sql
var FS embed.FS
```

- [ ] **Step 2: Write sqlite.go**

Create `internal/store/sqlite.go`. It receives the embedded FS as a parameter:

```go
package store

import (
    "database/sql"
    "fmt"
    "io/fs"
    "sort"
    "strings"

    _ "modernc.org/sqlite"
)

func Open(dbPath string, migrationFS fs.FS) (*sql.DB, error) {
    db, err := sql.Open("sqlite", dbPath)
    if err != nil {
        return nil, fmt.Errorf("open database: %w", err)
    }
    if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
        db.Close()
        return nil, fmt.Errorf("enable WAL: %w", err)
    }
    if _, err := db.Exec("PRAGMA foreign_keys=ON"); err != nil {
        db.Close()
        return nil, fmt.Errorf("enable foreign keys: %w", err)
    }
    if err := migrate(db, migrationFS); err != nil {
        db.Close()
        return nil, fmt.Errorf("migrate: %w", err)
    }
    return db, nil
}

func OpenMemory(migrationFS fs.FS) (*sql.DB, error) {
    return Open(":memory:", migrationFS)
}

func migrate(db *sql.DB, migrationFS fs.FS) error {
    entries, err := fs.ReadDir(migrationFS, ".")
    if err != nil {
        return fmt.Errorf("read migrations: %w", err)
    }
    sort.Slice(entries, func(i, j int) bool {
        return entries[i].Name() < entries[j].Name()
    })
    for _, entry := range entries {
        if !strings.HasSuffix(entry.Name(), ".sql") {
            continue
        }
        content, err := fs.ReadFile(migrationFS, entry.Name())
        if err != nil {
            return fmt.Errorf("read %s: %w", entry.Name(), err)
        }
        if _, err := db.Exec(string(content)); err != nil {
            return fmt.Errorf("execute %s: %w", entry.Name(), err)
        }
    }
    return nil
}
```

Callers (e.g., `cmd/enclout/serve.go`) pass `migrations.FS` to `store.Open()`.

- [ ] **Step 2: Write test verifying DB opens and tables exist**

Add to `internal/store/store_test.go`:

```go
func TestOpenMemory(t *testing.T) {
    db, err := store.OpenMemory()
    if err != nil {
        t.Fatalf("open: %v", err)
    }
    defer db.Close()

    // Verify tables exist
    tables := []string{"connection_requests", "install_sessions", "audit_log", "connector_bundles"}
    for _, table := range tables {
        var name string
        err := db.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name=?", table).Scan(&name)
        if err != nil {
            t.Fatalf("table %s not found: %v", table, err)
        }
    }
}
```

- [ ] **Step 3: Run test**

```bash
go test ./internal/store/... -v -run TestOpenMemory
```

- [ ] **Step 4: Commit**

```bash
git add internal/store/sqlite.go internal/store/store_test.go migrations/
git commit -m "feat(store): SQLite foundation with WAL mode and migration runner"
```

---

### Task 8: Store — RequestRepository

**Files:**
- Create: `internal/store/requests.go`
- Modify: `internal/store/store_test.go` (add request tests)

- [ ] **Step 1: Write failing tests**

Add to `internal/store/store_test.go`:
- `TestRequestRepository_Create_Get` — round-trip create + get
- `TestRequestRepository_Update` — create, modify status, update, re-get
- `TestRequestRepository_ListPending` — creates 3 requests (2 pending for device A, 1 pending for device B), asserts `ListPending("A")` returns 2
- `TestRequestRepository_Get_NotFound` — returns error for missing ID

- [ ] **Step 2: Run tests to verify they fail**

```bash
go test ./internal/store/... -v -run TestRequestRepository
```

- [ ] **Step 3: Implement requests.go**

```go
package store

import (
    "context"
    "database/sql"
    "time"

    "enclout/internal/access"
)

type RequestRepository struct {
    db *sql.DB
}

func NewRequestRepository(db *sql.DB) *RequestRepository {
    return &RequestRepository{db: db}
}

func (r *RequestRepository) Create(ctx context.Context, req access.ConnectionRequest) error {
    now := time.Now().UTC().Format(time.RFC3339)
    _, err := r.db.ExecContext(ctx,
        `INSERT INTO connection_requests (id, requester_id, device_id, connector_id, source, status, nonce, reason_code, created_at, expires_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        req.ID, req.RequesterID, req.DeviceID, req.ConnectorID, req.Source,
        string(req.Status), req.Nonce, req.ReasonCode,
        req.CreatedAt.Format(time.RFC3339), req.ExpiresAt.Format(time.RFC3339), now,
    )
    return err
}

func (r *RequestRepository) Get(ctx context.Context, id string) (access.ConnectionRequest, error) {
    var req access.ConnectionRequest
    var status, createdAt, expiresAt, updatedAt string
    err := r.db.QueryRowContext(ctx,
        `SELECT id, requester_id, device_id, connector_id, source, status, nonce, reason_code, created_at, expires_at
         FROM connection_requests WHERE id = ?`, id,
    ).Scan(&req.ID, &req.RequesterID, &req.DeviceID, &req.ConnectorID, &req.Source,
        &status, &req.Nonce, &req.ReasonCode, &createdAt, &expiresAt,
    )
    if err == sql.ErrNoRows {
        return access.ConnectionRequest{}, access.ErrNotFound
    }
    if err != nil {
        return access.ConnectionRequest{}, err
    }
    req.Status = access.Status(status)
    req.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
    req.ExpiresAt, _ = time.Parse(time.RFC3339, expiresAt)
    _ = updatedAt
    return req, nil
}

func (r *RequestRepository) Update(ctx context.Context, req access.ConnectionRequest) error {
    now := time.Now().UTC().Format(time.RFC3339)
    _, err := r.db.ExecContext(ctx,
        `UPDATE connection_requests SET status = ?, reason_code = ?, updated_at = ? WHERE id = ?`,
        string(req.Status), req.ReasonCode, now, req.ID,
    )
    return err
}

func (r *RequestRepository) ListPending(ctx context.Context, deviceID string) ([]access.ConnectionRequest, error) {
    rows, err := r.db.QueryContext(ctx,
        `SELECT id, requester_id, device_id, connector_id, source, status, nonce, reason_code, created_at, expires_at
         FROM connection_requests WHERE device_id = ? AND status = ?`,
        deviceID, string(access.StatusPendingLocalConfirm),
    )
    if err != nil {
        return nil, err
    }
    defer rows.Close()

    var out []access.ConnectionRequest
    for rows.Next() {
        var req access.ConnectionRequest
        var status, createdAt, expiresAt string
        if err := rows.Scan(&req.ID, &req.RequesterID, &req.DeviceID, &req.ConnectorID, &req.Source,
            &status, &req.Nonce, &req.ReasonCode, &createdAt, &expiresAt,
        ); err != nil {
            return nil, err
        }
        req.Status = access.Status(status)
        req.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
        req.ExpiresAt, _ = time.Parse(time.RFC3339, expiresAt)
        out = append(out, req)
    }
    return out, rows.Err()
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
go test ./internal/store/... -v -run TestRequestRepository
```

- [ ] **Step 5: Commit**

```bash
git add internal/store/requests.go internal/store/store_test.go
git commit -m "feat(store): add RequestRepository with SQLite CRUD"
```

---

### Task 9: Store — SessionRepository

**Files:**
- Create: `internal/store/sessions.go`
- Modify: `internal/store/store_test.go`

- [ ] **Step 1: Write failing tests**

- `TestSessionRepository_Create_Get` — round-trip
- `TestSessionRepository_Update` — update status
- `TestSessionRepository_RedeemToken` — redeem returns session, second redeem fails
- `TestSessionRepository_RedeemToken_NotFound` — unknown token errors

- [ ] **Step 2: Run tests to verify they fail**

- [ ] **Step 3: Implement sessions.go**

Same pattern as RequestRepository. `Create` reads `TokenDigest` from the session struct. `RedeemToken` looks up by token digest and clears it atomically.

- [ ] **Step 4: Run tests to verify they pass**

- [ ] **Step 5: Commit**

```bash
git add internal/store/sessions.go internal/store/store_test.go
git commit -m "feat(store): add SessionRepository with token redemption"
```

---

### Task 10: Store — BundleRepository + AuditLogger

**Files:**
- Create: `internal/store/bundles.go`
- Create: `internal/store/audit.go`
- Modify: `internal/store/store_test.go`

- [ ] **Step 1: Write failing bundle tests**

- `TestBundleRepository_Register_Get` — register and retrieve
- `TestBundleRepository_Register_Upsert` — re-register updates existing
- `TestBundleRepository_Get_NotFound` — missing connector errors
- `TestBundleRepository_List` — returns all registered bundles

- [ ] **Step 2: Implement bundles.go**

`Register` uses `INSERT OR REPLACE` (upsert). `Get` returns a single bundle by connector ID. `List` returns all.

- [ ] **Step 3: Write failing audit tests**

- `TestAuditLogger_Log` — writes audit entry
- `TestAuditLogger_QueryByEntity` — filters by entity_type + entity_id

- [ ] **Step 4: Implement audit.go**

```go
type AuditLogger struct {
    db *sql.DB
}

func (a *AuditLogger) Log(ctx context.Context, entityType, entityID, action, actor, detail string) error {
    _, err := a.db.ExecContext(ctx,
        `INSERT INTO audit_log (entity_type, entity_id, action, actor, detail, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
        entityType, entityID, action, actor, detail, time.Now().UTC().Format(time.RFC3339),
    )
    return err
}
```

- [ ] **Step 5: Run all store tests**

```bash
go test ./internal/store/... -v
```

- [ ] **Step 6: Commit**

```bash
git add internal/store/bundles.go internal/store/audit.go internal/store/store_test.go
git commit -m "feat(store): add BundleRepository and AuditLogger"
```

---

### Task 11: Config Package

**Files:**
- Create: `internal/config/config.go`
- Create: `internal/config/config_test.go`

**Reference:** Spec section "Config resolution" and TOML schema

- [ ] **Step 1: Write config struct and loader**

Create `internal/config/config.go`:

```go
package config

import "time"

type ServeConfig struct {
    Bind            string
    DB              string
    ConnectorID     string
    AuthToken       string
    SigningKeyB64   string
    SigningKeysJSON string
    SigningActiveKID string
    LogFormat       string
}

type AgentConfig struct {
    Server          string
    DeviceID        string
    Username        string
    Token           string
    PollInterval    time.Duration
    KeysDir         string
    DCAPUrl         string
    DCAPToken       string
    DCAPTimeout     time.Duration
    AllowMRTD       []string
    AllowRTMR3      []string
    SigningKeysJSON  string
    SigningPubkeyB64 string
    SigningCacheTTL time.Duration
    LogFormat       string
}
```

Config loading deferred to Cobra flag binding in the CLI commands — no TOML parser needed in v1. Env var binding via `cobra.Command.Flags().StringVar()` + `viper.BindEnv()` or manual `os.Getenv` fallback.

**Known spec deviation:** The spec defines a full TOML config file schema. This is intentionally deferred to a follow-up task. For v1, all config comes from flags and env vars. The TOML file support can be added later by integrating `github.com/spf13/viper` with Cobra.

- [ ] **Step 2: Write tests**

- `TestServeConfig_Validate` — missing auth token returns error
- `TestServeConfig_Validate_SigningKeyRequired` — at least one signing key required
- `TestAgentConfig_Validate` — missing server/device-id/username returns error

- [ ] **Step 3: Implement Validate methods**

- [ ] **Step 4: Run tests**

```bash
go test ./internal/config/... -v
```

- [ ] **Step 5: Commit**

```bash
git add internal/config/
git commit -m "feat(config): add config types with validation"
```

---

### Task 12: HTTP Server

**Files:**
- Create: `internal/server/server.go`
- Create: `internal/server/router.go`
- Create: `internal/server/handlers.go`
- Create: `internal/server/middleware.go`
- Create: `internal/server/server_test.go`

**Reference:** Spec section "HTTP API", existing `services/control-plane/internal/http/`

This task is split into sub-steps that follow TDD: tests first for each handler group.

- [ ] **Step 1: Write middleware + server struct + router skeleton**

Create `internal/server/middleware.go`:

```go
package server

import (
    "context"
    "crypto/rand"
    "encoding/hex"
    "log/slog"
    "net/http"
    "strings"
    "time"
)

type contextKey string

const requestIDKey contextKey = "request_id"

func BearerAuth(token string, next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        auth := r.Header.Get("Authorization")
        if !strings.HasPrefix(auth, "Bearer ") || strings.TrimPrefix(auth, "Bearer ") != token {
            http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
            return
        }
        next.ServeHTTP(w, r)
    })
}

func RequestID(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        id := r.Header.Get("X-Request-ID")
        if id == "" {
            b := make([]byte, 8)
            _, _ = rand.Read(b)
            id = hex.EncodeToString(b)
        }
        w.Header().Set("X-Request-ID", id)
        ctx := context.WithValue(r.Context(), requestIDKey, id)
        next.ServeHTTP(w, r.WithContext(ctx))
    })
}

func RequestLogger(logger *slog.Logger, next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        start := time.Now()
        rw := &responseWriter{ResponseWriter: w, status: http.StatusOK}
        next.ServeHTTP(rw, r)
        logger.Info("request",
            "method", r.Method,
            "path", r.URL.Path,
            "status", rw.status,
            "duration", time.Since(start),
            "request_id", r.Context().Value(requestIDKey),
        )
    })
}

type responseWriter struct {
    http.ResponseWriter
    status int
}

func (rw *responseWriter) WriteHeader(code int) {
    rw.status = code
    rw.ResponseWriter.WriteHeader(code)
}
```

Create `internal/server/server.go`:

```go
package server

import (
    "context"
    "database/sql"
    "log/slog"
    "net/http"
    "time"

    "enclout/internal/signing"
    "enclout/internal/store"
)

type Server struct {
    httpServer *http.Server
    db         *sql.DB
    logger     *slog.Logger
}

type Config struct {
    Bind      string
    AuthToken string
    Logger    *slog.Logger
}

type Deps struct {
    DB       *sql.DB
    Requests *store.RequestRepository
    Sessions *store.SessionRepository
    Bundles  *store.BundleRepository
    Audit    *store.AuditLogger
    Signer   signing.BundleSigner
}

func New(cfg Config, deps Deps) *Server {
    h := NewHandlers(deps)
    auth := func(next http.Handler) http.Handler {
        return BearerAuth(cfg.AuthToken, next)
    }
    router := NewRouter(h, auth)
    handler := RequestID(RequestLogger(cfg.Logger, router))
    return &Server{
        httpServer: &http.Server{Addr: cfg.Bind, Handler: handler},
        db:         deps.DB,
        logger:     cfg.Logger,
    }
}

func (s *Server) Start() error { return s.httpServer.ListenAndServe() }

func (s *Server) Shutdown(ctx context.Context) error {
    return s.httpServer.Shutdown(ctx)
}

func (s *Server) StartExpiration(ctx context.Context) {
    go func() {
        ticker := time.NewTicker(30 * time.Second)
        defer ticker.Stop()
        for {
            select {
            case <-ctx.Done():
                return
            case <-ticker.C:
                now := time.Now().UTC().Format(time.RFC3339)
                _, _ = s.db.ExecContext(ctx,
                    `UPDATE connection_requests SET status = 'expired', updated_at = ? WHERE expires_at < ? AND status IN ('pending_local_confirm', 'approved')`,
                    now, now,
                )
                _, _ = s.db.ExecContext(ctx,
                    `UPDATE install_sessions SET status = 'failed', reason_code = 'Expired', updated_at = ? WHERE expires_at < ? AND status IN ('requested', 'approved')`,
                    now, now,
                )
            }
        }
    }()
}
```

Create `internal/server/router.go`:

```go
package server

import "net/http"

func NewRouter(h *Handlers, auth func(http.Handler) http.Handler) http.Handler {
    mux := http.NewServeMux()

    // Connection requests
    mux.Handle("POST /v1/requests", auth(http.HandlerFunc(h.CreateRequest)))
    mux.Handle("GET /v1/requests/{id}", auth(http.HandlerFunc(h.GetRequest)))
    mux.Handle("POST /v1/requests/{id}/decision", auth(http.HandlerFunc(h.PostDecision)))
    mux.Handle("POST /v1/requests/{id}/result", auth(http.HandlerFunc(h.PostResult)))
    mux.Handle("GET /v1/requests/{id}/bundle", auth(http.HandlerFunc(h.GetBundle)))

    // Install sessions
    mux.Handle("POST /v1/sessions", auth(http.HandlerFunc(h.CreateSession)))
    mux.Handle("GET /v1/sessions/{id}", auth(http.HandlerFunc(h.GetSession)))
    mux.Handle("POST /v1/sessions/{id}/approve", auth(http.HandlerFunc(h.ApproveSession)))
    mux.Handle("POST /v1/sessions/{id}/register", auth(http.HandlerFunc(h.RegisterIdentity)))
    mux.Handle("POST /v1/sessions/{id}/result", auth(http.HandlerFunc(h.SessionResult)))
    mux.Handle("POST /v1/sessions/redeem", auth(http.HandlerFunc(h.RedeemToken)))

    // Device queries
    mux.Handle("GET /v1/devices/{deviceID}/pending", auth(http.HandlerFunc(h.ListPending)))

    // Signing keys + connector registration
    mux.Handle("GET /v1/signing-keys", auth(http.HandlerFunc(h.SigningKeys)))
    mux.Handle("POST /v1/connectors/register", auth(http.HandlerFunc(h.RegisterConnector)))

    // Operational
    mux.Handle("GET /install", http.HandlerFunc(h.InstallLanding))
    mux.Handle("GET /healthz", http.HandlerFunc(h.Healthz))

    return mux
}
```

- [ ] **Step 2: Write failing auth + healthz tests**

Create `internal/server/server_test.go` with test helpers:

```go
package server_test

import (
    "net/http"
    "net/http/httptest"
    "testing"

    "enclout/internal/server"
    "enclout/internal/store"
    "enclout/internal/signing"
    "enclout/migrations"
)

const testToken = "test-token"

func testServer(t *testing.T) (*httptest.Server, *store.RequestRepository, *store.SessionRepository) {
    t.Helper()
    db, err := store.OpenMemory(migrations.FS)
    if err != nil {
        t.Fatal(err)
    }
    t.Cleanup(func() { db.Close() })

    signer, _ := signing.NewEd25519SignerFromSeedB64("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
    requests := store.NewRequestRepository(db)
    sessions := store.NewSessionRepository(db)
    bundles := store.NewBundleRepository(db)
    audit := store.NewAuditLogger(db)
    deps := server.Deps{DB: db, Requests: requests, Sessions: sessions, Bundles: bundles, Audit: audit, Signer: signer}
    cfg := server.Config{Bind: ":0", AuthToken: testToken, Logger: slog.Default()}
    h := server.NewHandlers(deps)
    auth := func(next http.Handler) http.Handler { return server.BearerAuth(testToken, next) }
    router := server.NewRouter(h, auth)
    ts := httptest.NewServer(router)
    t.Cleanup(ts.Close)
    return ts, requests, sessions
}

func TestAuth_MissingToken(t *testing.T) {
    ts, _, _ := testServer(t)
    resp, _ := http.Get(ts.URL + "/v1/signing-keys")
    if resp.StatusCode != 401 { t.Fatalf("expected 401, got %d", resp.StatusCode) }
}

func TestHealthz(t *testing.T) {
    ts, _, _ := testServer(t)
    resp, _ := http.Get(ts.URL + "/healthz")
    if resp.StatusCode != 200 { t.Fatalf("expected 200, got %d", resp.StatusCode) }
}
```

- [ ] **Step 3: Write Handlers struct + Healthz + stub handlers**

Create `internal/server/handlers.go` with all handler methods as stubs returning 501. Implement `Healthz` and `SigningKeys` first since they are simplest.

- [ ] **Step 4: Run tests — auth + healthz should pass, others fail**

```bash
go test ./internal/server/... -v -run "TestAuth|TestHealthz"
```

- [ ] **Step 5: Write failing request handler tests + implement**

Add tests for `CreateRequest`, `GetRequest`, `PostDecision`, `PostResult`, `GetBundle`, `ListPending`. Each test: create httptest request, call handler, assert status code and response body.

Then implement each handler:
- `CreateRequest`: parse JSON body -> `access.NewConnectionRequest()` -> `requests.Create()` -> `audit.Log()` -> return 201
- `GetRequest`: `r.PathValue("id")` -> `requests.Get()` -> return 200
- `PostDecision`: get request -> `req.Approve()` or `req.Deny()` -> `requests.Update()` -> `audit.Log()` -> return 200
- `PostResult`: get request -> `req.SetResult()` -> `requests.Update()` -> `audit.Log()` -> return 200
- `GetBundle`: get request -> `bundles.Get(req.ConnectorID)` -> build `BundlePayload` -> `signer.SignBundle()` -> return 200
- `ListPending`: `r.PathValue("deviceID")` -> `requests.ListPending()` -> return 200

Port JSON shapes from existing `services/control-plane/internal/http/create_request_handler.go`, `local_decision_handler.go`, `result_handler.go`, `attestation_bundle_handler.go`.

Run request tests:
```bash
go test ./internal/server/... -v -run "TestCreateRequest|TestGetRequest|TestPostDecision|TestGetBundle|TestListPending"
```

- [ ] **Step 6: Write failing session handler tests + implement**

Add tests for `CreateSession`, `GetSession`, `ApproveSession`, `RegisterIdentity`, `SessionResult`, `RedeemToken`.

Then implement each handler. Port from `services/control-plane/internal/http/install_session_handler.go`.

`CreateSession` must return `install_token` and `install_url` in the response.

`InstallLanding` renders a minimal HTML page with the install command, port from existing `serveInstallLanding` in `cmd/api/main.go:110-157`.

`RegisterConnector` accepts a `ConnectorBundle` JSON body and calls `bundles.Register()`.

Run session tests:
```bash
go test ./internal/server/... -v -run "TestCreateSession|TestRedeemToken|TestApproveSession"
```

- [ ] **Step 7: Run all server tests**

```bash
go test ./internal/server/... -v
```

- [ ] **Step 8: Commit**

```bash
git add internal/server/
git commit -m "feat(server): HTTP API with Go 1.23 stdlib mux, middleware, and handlers"
```

---

### Task 13: HTTP Client

**Files:**
- Create: `internal/client/client.go`
- Create: `internal/client/client_test.go`

**Reference:** `services/local-agent/internal/api/client.go`

- [ ] **Step 1: Write client interface and implementation**

```go
package client

type Client struct {
    baseURL    string
    token      string
    httpClient *http.Client
}

func New(baseURL, token string) *Client { ... }

// Request operations
func (c *Client) CreateRequest(ctx, input) (ConnectionRequest, error)
func (c *Client) GetRequest(ctx, id) (ConnectionRequest, error)
func (c *Client) PostDecision(ctx, id, approved) error
func (c *Client) PostResult(ctx, id, status, reasonCode) error
func (c *Client) GetBundle(ctx, id) (SignedBundle, error)
func (c *Client) ListPending(ctx, deviceID) ([]ConnectionRequest, error)

// Session operations
func (c *Client) CreateSession(ctx, input) (SessionResponse, error)
func (c *Client) GetSession(ctx, id) (InstallSession, error)
func (c *Client) ApproveSession(ctx, id) error
func (c *Client) RegisterIdentity(ctx, id, connectorID, deviceID) error
func (c *Client) SessionResult(ctx, id, status, reason) error
func (c *Client) RedeemToken(ctx, token) (InstallSession, error)

// Signing keys
func (c *Client) GetSigningKeys(ctx) (SigningKeyset, error)
```

- [ ] **Step 2: Write tests using httptest.Server**

Create `internal/client/client_test.go`:
- `TestClient_CreateRequest` — sends correct JSON, parses response
- `TestClient_PostDecision` — sends approved=true
- `TestClient_ListPending` — parses array response
- `TestClient_RedeemToken` — sends token, gets session back
- `TestClient_AuthHeader` — every request includes Bearer token

Wire up `internal/server` as the test backend — this is effectively an integration test of client + server.

- [ ] **Step 3: Run tests**

```bash
go test ./internal/client/... -v
```

- [ ] **Step 4: Commit**

```bash
git add internal/client/
git commit -m "feat(client): typed HTTP client for control plane API"
```

---

### Task 14: Agent Package

**Files:**
- Create: `internal/agent/daemon.go`
- Create: `internal/agent/runner.go`
- Create: `internal/agent/approval.go`
- Create: `internal/agent/sshkeys.go`
- Create: `internal/agent/daemon_test.go`
- Create: `internal/agent/runner_test.go`

**Reference:** `services/local-agent/cmd/agent/main.go`, `services/local-agent/internal/flow/runner.go`, `services/local-agent/internal/approval/`, `services/local-agent/internal/sshkeys/`

- [ ] **Step 1: Port approval.go**

Port `Prompter` interface, `NativePrompter` (darwin/linux), `CLIPrompter`, and composite `Prompter` from existing `services/local-agent/internal/approval/`.

Files:
- `internal/agent/approval.go` — interface + composite `Prompter` (tries native, falls back to CLI)
- `internal/agent/approval_darwin.go` — macOS: uses `osascript` to show a confirmation dialog. Build constraint: `//go:build darwin`
- `internal/agent/approval_linux.go` — Linux: tries `zenity --question`, falls back to `kdialog --yesno`. Build constraint: `//go:build linux`
- `internal/agent/approval_cli.go` — CLI fallback: prints to stdout, reads y/n from stdin. No build constraints.

Port directly from:
- `services/local-agent/internal/approval/prompter.go` (interface + composite)
- `services/local-agent/internal/approval/native_darwin.go` (osascript)
- `services/local-agent/internal/approval/native_linux.go` (zenity/kdialog)
- `services/local-agent/internal/approval/cli_fallback.go` (stdin)

**Testing note:** Native prompters are untestable in CI (no display server). Tests use a fake `Prompter` implementation that returns a preconfigured response. The `Prompter` interface is defined in `approval.go` and all tests mock it.

- [ ] **Step 2: Port sshkeys.go**

Port `Manager` from `services/local-agent/internal/sshkeys/manager_unix.go`. Same atomic write-then-rename pattern.

- [ ] **Step 3: Write failing runner tests**

Create `internal/agent/runner_test.go`:
- `TestRunner_Process_FullFlow` — happy path: approve -> verify -> install key -> connected
- `TestRunner_Process_UserDenied` — user denies -> denied_local
- `TestRunner_Process_VerificationFailed` — verifier returns untrusted -> verification_failed
- `TestRunner_Process_SignatureInvalid` — bundle signature fails -> verification_failed

Use fake implementations for `client.Client`, `Prompter`, `Verifier`, `KeyInstaller`, `TrustedSigningKeys`.

- [ ] **Step 4: Implement runner.go**

Port from `services/local-agent/internal/flow/runner.go`. Same structure but using the new `internal/client` and `internal/attestation` packages.

- [ ] **Step 5: Run runner tests**

```bash
go test ./internal/agent/... -v -run TestRunner
```

- [ ] **Step 6: Write KeysetSource (trusted signing key cache)**

Create `internal/agent/keyset.go`. Port from `services/local-agent/internal/trust/keyset_source.go`:

```go
package agent

import (
    "context"
    "sync"
    "time"
)

type KeysetSource struct {
    client       KeysetFetcher
    bootstrap    map[string]string // kid -> pubkey_b64, from config
    cache        map[string]string
    cacheTTL     time.Duration
    lastRefresh  time.Time
    mu           sync.RWMutex
}

type KeysetFetcher interface {
    GetSigningKeys(ctx context.Context) (map[string]string, error)
}

func NewKeysetSource(client KeysetFetcher, bootstrap map[string]string, cacheTTL time.Duration) *KeysetSource {
    return &KeysetSource{
        client:    client,
        bootstrap: bootstrap,
        cache:     bootstrap,
        cacheTTL:  cacheTTL,
    }
}

func (k *KeysetSource) TrustedKeys(ctx context.Context) (map[string]string, error) {
    k.mu.RLock()
    if time.Since(k.lastRefresh) < k.cacheTTL && len(k.cache) > 0 {
        defer k.mu.RUnlock()
        return k.cache, nil
    }
    k.mu.RUnlock()

    // Refresh from server
    k.mu.Lock()
    defer k.mu.Unlock()
    keys, err := k.client.GetSigningKeys(ctx)
    if err != nil {
        if len(k.cache) > 0 {
            return k.cache, nil // use stale cache on error
        }
        return nil, err
    }
    k.cache = keys
    k.lastRefresh = time.Now()
    return keys, nil
}
```

Write tests in `internal/agent/keyset_test.go`:
- `TestKeysetSource_BootstrapKeys` — returns bootstrap keys before TTL
- `TestKeysetSource_RefreshAfterTTL` — fetches fresh keys after TTL expires
- `TestKeysetSource_FallbackToCache` — returns stale cache on fetch error

- [ ] **Step 7: Write failing daemon tests**

Create `internal/agent/daemon_test.go`:
- `TestDaemon_PollsOnInterval` — verifies poll calls at expected intervals
- `TestDaemon_BackoffOnError` — after N failures, interval increases
- `TestDaemon_ResetBackoffOnSuccess` — interval returns to base after success
- `TestDaemon_GracefulShutdown` — context cancel stops the loop

Use a fake client that records poll calls with timestamps.

- [ ] **Step 8: Implement daemon.go**

Port from `services/local-agent/cmd/agent/main.go`, adding:
- Jittered base interval (±20%)
- Exponential backoff (cap 60s)
- Health file writes
- `slog` structured logging

- [ ] **Step 9: Run all agent tests**

```bash
go test ./internal/agent/... -v
```

- [ ] **Step 10: Commit**

```bash
git add internal/agent/
git commit -m "feat(agent): daemon with jitter, backoff, runner, approval, and SSH keys"
```

---

### Task 15: CLI — main + serve + agent

**Files:**
- Modify: `cmd/enclout/main.go`
- Create: `cmd/enclout/serve.go`
- Create: `cmd/enclout/agent.go`

- [ ] **Step 1: Write serve command**

Create `cmd/enclout/serve.go`:
- Cobra command with all flags from spec (`--bind`, `--db`, `--connector-id`, `--auth-token`, `--signing-key`, etc.)
- `RunE` function: load config -> open SQLite -> build dependencies -> create server -> start with graceful shutdown
- Env var binding for each flag (ENCLOUT_ prefix)
- Optional: if dstack socket detected and `--connector-id` set, derive identity and register connector bundle on startup

- [ ] **Step 2: Write agent command**

Create `cmd/enclout/agent.go`:
- Cobra command with all flags from spec (`--server`, `--device-id`, `--username`, `--dcap-url`, etc.)
- `RunE` function: load config -> build client -> build verifier -> build runner -> start daemon
- Env var binding for each flag

- [ ] **Step 3: Wire into main.go**

```go
root.AddCommand(serveCmd())
root.AddCommand(agentCmd())
```

- [ ] **Step 4: Verify build and help output**

```bash
make build
./bin/enclout serve --help
./bin/enclout agent --help
```

Expected: both show all flags with descriptions.

- [ ] **Step 5: Integration smoke test**

```bash
# Start server in background
ENCLOUT_AUTH_TOKEN=test-token ENCLOUT_SIGNING_KEY_B64=$(openssl rand -base64 32) ./bin/enclout serve --db :memory: &
SERVER_PID=$!
sleep 1

# Health check
curl -s http://127.0.0.1:8080/healthz
# Expected: ok

kill $SERVER_PID
```

- [ ] **Step 6: Commit**

```bash
git add cmd/enclout/
git commit -m "feat(cli): add serve and agent subcommands"
```

---

### Task 16: CLI — connect + install + status

**Files:**
- Create: `cmd/enclout/connect.go`
- Create: `cmd/enclout/install.go`
- Create: `cmd/enclout/status.go`

- [ ] **Step 1: Write connect command**

Create `cmd/enclout/connect.go`:
- Flags: `--server`, `--device-id`, `--connector-id`, `--requester`, `--token`, `--wait`, `--json`
- `RunE`: create client -> CreateRequest -> if `--wait`, poll GetRequest until terminal state -> print result
- Exit codes: 0=connected, 1=denied/failed, 2=expired, 3=error

- [ ] **Step 2: Write install command**

Create `cmd/enclout/install.go`:
- Flags: `--server`, `--install-token`, `--username`, `--keys-dir`
- `RunE`: create client -> RedeemToken -> RegisterIdentity (generate device ID) -> configure OS service -> SessionResult
- Port launchd/systemd installer from `services/local-agent/internal/install/`

- [ ] **Step 3: Write status command**

Create `cmd/enclout/status.go`:
- Flags: `--server`, `--request-id`, `--device-id`, `--json`
- `RunE`: create client -> GetRequest or ListPending -> format output

- [ ] **Step 4: Verify help output**

```bash
make build
./bin/enclout connect --help
./bin/enclout install --help
./bin/enclout status --help
```

- [ ] **Step 5: Commit**

```bash
git add cmd/enclout/connect.go cmd/enclout/install.go cmd/enclout/status.go
git commit -m "feat(cli): add connect, install, and status subcommands"
```

---

### Task 17: MCP Server

**Files:**
- Create: `internal/mcpserver/tools.go`
- Create: `internal/mcpserver/tools_test.go`

**Reference:** Spec section "MCP Server Layer"

- [ ] **Step 1: Add mcp-go dependency**

```bash
go get github.com/mark3labs/mcp-go@latest
```

- [ ] **Step 2: Write tool definitions**

Create `internal/mcpserver/tools.go`:

```go
package mcpserver

type Server struct {
    client *client.Client
    serverURL string
}

func New(client *client.Client, serverURL string) *Server { ... }

// Register all tools with the MCP server
func (s *Server) Register(mcpServer *mcp.Server) {
    // enclout_connect
    // enclout_install_start
    // enclout_install_approve
    // enclout_install_status
    // enclout_request_status
    // enclout_list_pending
}
```

Each tool handler: validate params -> call `s.client.Method()` -> format response.

The `enclout_install_start` handler builds `install_commands` (platform-specific shell snippets) from the returned `install_url` and `install_token`.

- [ ] **Step 3: Write failing tests**

Create `internal/mcpserver/tools_test.go`:
- `TestConnect_CallsCreateRequest` — verifies correct API call
- `TestInstallStart_ReturnsCommands` — verifies install_commands in response
- `TestRequestStatus_ReturnsStatus` — verifies status passthrough
- `TestListPending_ReturnsArray` — verifies array formatting

Use `httptest.Server` running the real `internal/server` as backend.

- [ ] **Step 4: Run tests**

```bash
go test ./internal/mcpserver/... -v
```

- [ ] **Step 5: Commit**

```bash
git add internal/mcpserver/
git commit -m "feat(mcp): MCP tool server with 6 tools wrapping HTTP client"
```

---

### Task 18: CLI — mcp command

**Files:**
- Create: `cmd/enclout/mcp.go`

- [ ] **Step 1: Write mcp command**

Create `cmd/enclout/mcp.go`:
- Flags: `--server`, `--token`
- `RunE`: create client -> create MCP server -> register tools -> serve over stdio

```go
func mcpCmd() *cobra.Command {
    var serverURL, token string
    cmd := &cobra.Command{
        Use:   "mcp",
        Short: "Start MCP tool server (stdio)",
        RunE: func(cmd *cobra.Command, args []string) error {
            c := client.New(serverURL, token)
            mcpSrv := mcpserver.New(c, serverURL)
            s := mcp.NewServer("enclout", version)
            mcpSrv.Register(s)
            return s.ServeStdio()
        },
    }
    cmd.Flags().StringVar(&serverURL, "server", "", "Control plane URL (required)")
    cmd.Flags().StringVar(&token, "token", "", "Bearer token")
    cmd.MarkFlagRequired("server")
    return cmd
}
```

- [ ] **Step 2: Wire into main.go**

```go
root.AddCommand(mcpCmd())
```

- [ ] **Step 3: Verify build**

```bash
make build
./bin/enclout mcp --help
```

- [ ] **Step 4: Commit**

```bash
git add cmd/enclout/mcp.go cmd/enclout/main.go
git commit -m "feat(cli): add mcp subcommand for stdio tool server"
```

---

### Task 19: CI + Makefile

**Files:**
- Create: `.github/workflows/ci.yml` (replace existing)
- Modify: `Makefile` (finalize)

- [ ] **Step 1: Write CI workflow**

Create `.github/workflows/ci.yml`:

```yaml
name: CI

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: '1.23'
      - run: go test ./... -race -count=1
      - run: go vet ./...
      - run: go build ./cmd/enclout
```

- [ ] **Step 2: Finalize Makefile**

Add `install` target:

```makefile
install: build
	cp bin/enclout /usr/local/bin/enclout
```

- [ ] **Step 3: Run full test suite**

```bash
make test
make build
```

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/ci.yml Makefile
git commit -m "ci: replace multi-module CI with single Go binary workflow"
```

---

### Task 20: Cleanup Old Code

**Files:**
- Delete: `services/control-plane/` (entire directory)
- Delete: `services/local-agent/` (entire directory)
- Delete: `services/connector-tee/` (entire directory)
- Delete: `skills/enclout-openclaw-agent/` (entire directory)
- Delete: `scripts/verify-m1.sh` (references old structure)
- Delete: `tests/integration/` (replaced by in-package tests)

- [ ] **Step 1: Verify no references to old paths**

```bash
grep -r "services/control-plane" --include="*.go" .
grep -r "services/local-agent" --include="*.go" .
grep -r "connector-tee" --include="*.go" .
```

Expected: no matches in new code.

- [ ] **Step 2: Delete old directories**

```bash
rm -rf services/
rm -rf skills/
rm -rf scripts/verify-m1.sh
rm -rf tests/integration/
```

- [ ] **Step 3: Run full test suite one last time**

```bash
make test
make build
./bin/enclout version
```

Expected: all tests pass, binary builds, version prints.

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "refactor: remove old multi-service code replaced by single binary"
```

---

## Summary

| Task | Package | Depends On | Parallelizable With |
|------|---------|------------|---------------------|
| 1 | scaffolding | — | — |
| 2 | access/request | 1 | 3, 4, 5, 6 |
| 3 | access/session | 1 | 2, 4, 5, 6 |
| 4 | signing | 1 | 2, 3, 5, 6 |
| 5 | identity | 1 | 2, 3, 4, 6 |
| 6 | attestation | 1 | 2, 3, 4, 5 |
| 7 | store foundation | 1 | — |
| 8 | store/requests | 2, 7 | 9, 10 |
| 9 | store/sessions | 3, 7 | 8, 10 |
| 10 | store/bundles | 7 | 8, 9 |
| 11 | config | 1 | 2-10 |
| 12 | server | 2, 3, 4, 7-10, 11 | — |
| 13 | client | 12 | — |
| 14 | agent | 5, 6, 13 | 17 |
| 15 | CLI serve+agent | 12, 14 | — |
| 16 | CLI connect+install+status | 13, 15 | 17 |
| 17 | MCP server | 13 | 14, 16 |
| 18 | CLI mcp | 17 | 16 |
| 19 | CI | 15-18 | — |
| 20 | cleanup | 19 | — |
