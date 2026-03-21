# Enclout Refactor: Single Binary with CLI + MCP Server

**Date:** 2026-03-20
**Status:** Approved (pending spec review)

## Overview

Refactor enclout from three separate services (Go control-plane, Go local-agent, Node.js connector-tee) into a single Go binary (`enclout`) with CLI subcommands and an MCP server layer. The TEE SSH key generation transforms from an OpenClaw-specific skill into a harness-agnostic plugin compatible with any MCP-speaking agent (OpenClaw, Pi Agent Harness, Claude Code).

## Goals

1. **Single binary** — one `enclout` executable replaces three services and two languages
2. **Harness-agnostic** — no OpenClaw coupling in the core; MCP server works with any harness
3. **Production persistence** — SQLite replaces the file-backed JSON store
4. **Observability** — structured logging, audit log table, request tracing
5. **CLI-first** — humans and agent harnesses both use the same operations

## Non-Goals

- Universal SSH proxy (proxying arbitrary machines without TEE)
- Multi-tenancy or RBAC (single-tenant, single API token auth)
- Real-time push notifications (polling stays, with improvements)

---

## Architecture

```
CLI (enclout connect/install/status)    MCP Server (enclout mcp, stdio)
               │                                      │
               └──────────────┬───────────────────────┘
                              │
                    ┌─────────▼─────────┐
                    │   Core Library     │
                    │   (internal/*)     │
                    └─────────┬─────────┘
                              │
               ┌──────────────┼──────────────┐
               │              │              │
        ┌──────▼──────┐ ┌────▼────┐  ┌──────▼──────┐
        │  HTTP API   │ │  SQLite │  │ TEE Identity│
        │  (server/)  │ │ (store/)│  │ (identity/) │
        └─────────────┘ └─────────┘  └─────────────┘
```

Entry points (CLI subcommands and MCP tools) are thin wrappers over shared domain packages. The HTTP API is the communication layer between `enclout serve` (server-side) and `enclout agent`/`enclout connect` (client-side).

---

## Project Structure

```
enclout/
├── cmd/enclout/
│   ├── main.go              # cobra root command
│   ├── serve.go             # enclout serve (control plane API)
│   ├── agent.go             # enclout agent (polling daemon)
│   ├── connect.go           # enclout connect (request access)
│   ├── install.go           # enclout install (bootstrap agent)
│   ├── mcp.go               # enclout mcp (MCP tool server, stdio)
│   ├── status.go            # enclout status (query state)
│   └── version.go           # enclout version
│
├── internal/
│   ├── access/              # request lifecycle state machine
│   │   ├── request.go       # ConnectionRequest model + transitions
│   │   ├── session.go       # InstallSession model + transitions
│   │   └── access_test.go
│   │
│   ├── identity/            # TEE key derivation (Go port)
│   │   ├── ed25519.go       # deterministic Ed25519 from 32-byte seed
│   │   ├── ssh.go           # SSH wire format encoding
│   │   ├── dstack.go        # dstack SDK client (HTTP over Unix socket)
│   │   └── identity_test.go
│   │
│   ├── attestation/         # verification logic
│   │   ├── verifier.go      # StrictVerifier
│   │   ├── dcap.go          # HTTP DCAP client
│   │   ├── policy.go        # measurement allowlist
│   │   └── attestation_test.go
│   │
│   ├── signing/             # bundle signing + keyset management
│   │   ├── signer.go        # Ed25519Signer, SignerSet, rotation
│   │   ├── bundle.go        # BundlePayload, SignedBundle types
│   │   ├── verify.go        # signature verification
│   │   └── signing_test.go
│   │
│   ├── agent/               # daemon logic
│   │   ├── daemon.go        # poll loop with jitter + backoff
│   │   ├── approval.go      # native + CLI prompter
│   │   ├── sshkeys.go       # authorized_keys management
│   │   └── agent_test.go
│   │
│   ├── store/               # SQLite persistence
│   │   ├── sqlite.go        # connection, migrations, schema
│   │   ├── requests.go      # RequestRepository implementation
│   │   ├── sessions.go      # SessionRepository implementation
│   │   ├── audit.go         # audit log writes
│   │   └── store_test.go
│   │
│   ├── server/              # HTTP API
│   │   ├── router.go        # Go 1.22+ stdlib mux with path patterns
│   │   ├── handlers.go      # request handlers
│   │   ├── middleware.go     # auth, logging, request ID
│   │   └── server_test.go
│   │
│   ├── mcpserver/           # MCP tool definitions
│   │   ├── tools.go         # tool schemas + handlers
│   │   └── mcpserver_test.go
│   │
│   ├── client/              # HTTP client (agent -> server)
│   │   ├── client.go        # typed API client
│   │   └── client_test.go
│   │
│   └── config/              # unified config
│       ├── config.go        # env + file + flags resolution
│       └── config_test.go
│
├── migrations/
│   └── 001_initial.sql
│
├── go.mod
├── go.sum
└── Makefile
```

---

## Domain Model

### ConnectionRequest (access/request.go)

```go
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
    RequesterID string    // generic — not OpenClaw-specific
    DeviceID    string
    ConnectorID string
    Source      string    // "openclaw", "pi", "cli", etc.
    Status      Status
    CreatedAt   time.Time
    ExpiresAt   time.Time
    Nonce       string
    ReasonCode  string
}
```

**Key change:** `OpenClawUserID` becomes `RequesterID`, `SourceChannel` becomes `Source`.

State transitions are methods on the type, not in the store:

```go
func (r *ConnectionRequest) Approve() error  // pending_local_confirm -> approved
func (r *ConnectionRequest) Deny() error     // pending_local_confirm -> denied_local
func (r *ConnectionRequest) Expire() error   // pending/approved -> expired
func (r *ConnectionRequest) SetResult(status Status, reason string) error
```

### InstallSession (access/session.go)

Same pattern — `RequesterID` + `Source`, transitions on the type.

### ConnectorIdentity (identity/)

```go
type ConnectorIdentity struct {
    ConnectorID       string
    SSHPublicKey      string
    PublicKeyHex      string
    FingerprintSHA256 string
}

type Attestation struct {
    QuoteHex                 string
    MRTD                     string
    RTMR0, RTMR1, RTMR2, RTMR3 string
    EventLog                 string
    ReportDataExpectedSHA256 string
    PolicyVersion            string
}

type Deriver interface {
    DeriveIdentity(ctx context.Context, connectorID string) (ConnectorIdentity, Attestation, error)
}
```

Two implementations: `DstackDeriver` (real TEE) and `EnvDeriver` (dev/testing).

---

## Storage Layer

### SQLite with WAL mode

Replace in-memory + file-backed JSON store with SQLite via `modernc.org/sqlite` (pure Go, no CGo).

### Schema (migrations/001_initial.sql)

```sql
CREATE TABLE connection_requests (
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
CREATE INDEX idx_requests_device_status ON connection_requests(device_id, status);

CREATE TABLE install_sessions (
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
CREATE UNIQUE INDEX idx_install_token ON install_sessions(token_digest) WHERE token_digest != '';

CREATE TABLE audit_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    entity_type TEXT NOT NULL,
    entity_id   TEXT NOT NULL,
    action      TEXT NOT NULL,
    actor       TEXT NOT NULL DEFAULT '',
    detail      TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL
);
CREATE INDEX idx_audit_entity ON audit_log(entity_type, entity_id);
CREATE INDEX idx_audit_time ON audit_log(created_at);
```

### Repository interfaces

```go
type RequestRepository interface {
    Create(ctx context.Context, req access.ConnectionRequest) error
    Get(ctx context.Context, id string) (access.ConnectionRequest, error)
    Update(ctx context.Context, req access.ConnectionRequest) error
    ListPending(ctx context.Context, deviceID string) ([]access.ConnectionRequest, error)
}

type SessionRepository interface {
    Create(ctx context.Context, session access.InstallSession, tokenDigest string) error
    Get(ctx context.Context, id string) (access.InstallSession, error)
    Update(ctx context.Context, session access.InstallSession) error
    RedeemToken(ctx context.Context, tokenDigest string) (access.InstallSession, error)
}
```

### Expiration

Background goroutine in `enclout serve` runs every 30 seconds:

```sql
UPDATE connection_requests SET status = 'expired', updated_at = ?
WHERE expires_at < ? AND status IN ('pending_local_confirm', 'approved');
```

No more side-effects on read (`expireIfNeeded` pattern removed).

---

## CLI Subcommands

### Command tree

```
enclout
├── serve       Start the control plane API server
├── agent       Run the local agent daemon
├── connect     Request access to a device
├── install     Bootstrap agent on a device (redeem token)
├── status      Show request/session/agent state
├── mcp         Start MCP tool server (stdio)
└── version     Print version and build info
```

### enclout serve

```
enclout serve [flags]
  --bind          Listen address (default: 127.0.0.1:8080)
  --db            SQLite database path (default: ./enclout.db)
  --config        Config file path (optional)
  --log-format    "text" or "json" (default: text)
```

Graceful shutdown via `signal.NotifyContext` + `server.Shutdown(ctx)`.

### enclout agent

```
enclout agent [flags]
  --server        Control plane URL (required)
  --device-id     Device ID (required)
  --username      Local SSH username (required)
  --token         Bearer token
  --poll-interval Poll interval (default: 5s)
  --keys-dir      SSH keys directory (default: ~/.enclout/keys)
  --log-format    "text" or "json" (default: text)
```

Jittered polling (+-20%), exponential backoff on error (max 60s), health file at `~/.enclout/agent.health`.

### enclout connect

```
enclout connect [flags]
  --server        Control plane URL (required)
  --device-id     Target device (required)
  --connector-id  Connector ID (required)
  --requester     Requester identity (default: OS user)
  --token         Bearer token
  --wait          Block until terminal state (default: true)
  --json          JSON output
```

Exit codes: 0=connected, 1=denied/failed, 2=expired, 3=error.

### enclout install

```
enclout install [flags]
  --server        Control plane URL (required)
  --install-token One-time token (required)
  --username      Local SSH username (default: current user)
  --keys-dir      Managed keys directory
```

Redeems token, registers identity, configures OS service (`launchd`/`systemd`), starts agent.

### enclout mcp

```
enclout mcp [flags]
  --server        Control plane URL (required)
  --token         Bearer token
```

MCP server over stdio.

### enclout status

```
enclout status [flags]
  --server        Control plane URL
  --request-id    Show specific request
  --device-id     Show all for device
  --json          JSON output
```

### Config resolution

Flags -> env vars -> config file (`~/.enclout/config.toml` or `./enclout.toml`) -> defaults.

---

## MCP Server Layer

### Tools

| Tool | Description | Inputs | Returns |
|------|-------------|--------|---------|
| `enclout_connect` | Request SSH access | device_id, connector_id, requester_id, source | request_id, status, message |
| `enclout_install_start` | Create install session | requester_id, source | session_id, install_url, install_token |
| `enclout_install_approve` | Approve install session | session_id | session_id, status |
| `enclout_install_status` | Check install progress | session_id | session_id, status, connector_id, device_id |
| `enclout_request_status` | Check request progress | request_id | request_id, status, reason_code |
| `enclout_list_pending` | List pending for device | device_id | requests[] |

### Architecture

MCP server (stdio) -> client.Client (HTTP) -> enclout serve (HTTP API) -> SQLite.

Each tool handler is ~15 lines: validate input, call HTTP client, format response.

### Harness consumption

Any MCP-compatible harness connects to `enclout mcp`:

```json
{
  "mcpServers": {
    "enclout": {
      "command": "enclout",
      "args": ["mcp", "--server", "https://control-plane.example.com"]
    }
  }
}
```

The entire `skills/enclout-openclaw-agent/` directory is replaced by this configuration.

---

## TEE Identity Port

### Ed25519 derivation (identity/ed25519.go)

Go's `crypto/ed25519.NewKeyFromSeed()` takes a 32-byte seed directly. No PKCS8 DER prefix manipulation needed (unlike the Node.js version).

### SSH wire format (identity/ssh.go)

`golang.org/x/crypto/ssh.MarshalAuthorizedKey()` replaces manual wire encoding.

### dstack client (identity/dstack.go)

HTTP calls over Unix socket (`/var/run/dstack.sock`) or simulator HTTP endpoint:
- `GetKey(path, subject)` -> 32-byte seed
- `GetQuote(reportData)` -> quote hex + event log
- `Info()` -> app metadata

### Deriver interface

```go
type Deriver interface {
    DeriveIdentity(ctx context.Context, connectorID string) (ConnectorIdentity, Attestation, error)
}
```

Two implementations:
- `DstackDeriver` — real TEE via dstack SDK
- `EnvDeriver` — reads `TEE_SEED_B64` + `TEE_QUOTE_HEX` from env (dev/testing)

### Validation

Golden test: same seed as current Node.js test fixtures must produce identical SSH public keys.

---

## HTTP API

### Route table

Go 1.22+ stdlib mux with path patterns. Replaces manual `strings.HasSuffix` routing.

```
POST /v1/requests                    Create connection request
GET  /v1/requests/{id}               Get request
POST /v1/requests/{id}/decision      Post local decision
POST /v1/requests/{id}/result        Post final result
GET  /v1/requests/{id}/bundle        Get signed attestation bundle

POST /v1/sessions                    Create install session
GET  /v1/sessions/{id}               Get session
POST /v1/sessions/{id}/approve       Approve session
POST /v1/sessions/{id}/register      Register identity
POST /v1/sessions/{id}/result        Post session result
POST /v1/sessions/redeem             Redeem install token

GET  /v1/devices/{deviceID}/pending  List pending requests
GET  /v1/signing-keys                Public signing keyset

GET  /install                        Install landing page
GET  /healthz                        Health check
```

### Changes from current API

- `/v1/connection-requests` -> `/v1/requests` (shorter)
- `/v1/install-sessions` -> `/v1/sessions` (shorter)
- `/v1/openclaw/intents` removed (harnesses use MCP or CLI)
- Path parameters via `r.PathValue("id")` (stdlib, no string hacking)

### Middleware

Request ID injection, structured request logging (method, path, status, duration), bearer token auth.

### Error format

Standardized JSON:
```json
{
    "error": "invalid_transition",
    "message": "request status is 'expired', cannot transition to 'approved'",
    "request_id": "abc-123"
}
```

---

## Agent Daemon

### Poll loop improvements

- Jittered polling: base interval +-20% random jitter
- Exponential backoff on error: doubles per failure, caps at 60s, resets on success
- Health file: `~/.enclout/agent.health` with last poll timestamp

### Structured logging

`slog` with text (human) or JSON (machine) output format.

### Service installation

`enclout install` configures launchd (macOS) or systemd (Linux) to run `enclout agent` with the appropriate flags. One binary, one service definition.

---

## Testing Strategy

### Three layers

1. **Domain unit tests** — pure logic, no I/O. State transitions, crypto derivation, SSH key golden tests (byte-compatibility with Node.js output).

2. **Store integration tests** — real SQLite (`:memory:`), no mocks. Tests actual SQL queries, constraints, index behavior.

3. **Flow integration tests** — full request lifecycle in-process with real SQLite, real signing, real verification. Only external dependencies (DCAP verifier, dstack SDK, OS prompter, filesystem) are faked.

### Fake boundaries

| Component | In tests | Reason |
|-----------|----------|--------|
| SQLite | Real (`:memory:`) | Tests actual queries |
| State machine | Real | Core logic |
| Signing/verification | Real | Crypto correctness |
| DCAP verifier | Fake | External HTTP service |
| dstack SDK | Fake | Requires TEE hardware |
| OS prompter | Fake | Requires terminal |
| SSH key writer | Fake | Filesystem side effect |

### CI

```yaml
test:
  runs-on: ubuntu-latest
  steps:
    - uses: actions/setup-go@v5
      with: { go-version: '1.23' }
    - run: go test ./... -race -count=1
    - run: go vet ./...
    - run: go build ./cmd/enclout
```

No more Node.js setup or multi-module test orchestration.

---

## What Gets Deleted

- `services/control-plane/` — folded into `internal/` packages
- `services/local-agent/` — folded into `internal/` packages
- `services/connector-tee/` — ported to Go in `internal/identity/`
- `skills/enclout-openclaw-agent/` — replaced by MCP server configuration
- All `package.json`, `tsconfig.json`, Node.js dependencies

## Dependencies

- `github.com/spf13/cobra` — CLI framework
- `modernc.org/sqlite` — pure Go SQLite driver
- `golang.org/x/crypto/ssh` — SSH wire format
- `github.com/mark3labs/mcp-go` (or equivalent) — MCP server SDK
- Standard library for everything else (crypto, net/http, slog, embed)
