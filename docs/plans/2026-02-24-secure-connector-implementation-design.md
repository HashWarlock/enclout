# Secure Connector TEE Implementation Design (M1)

Date: 2026-02-24
Status: Validated in brainstorming session
Scope: M1 architecture and contracts for secure, chat-triggered connector access

## Locked Decisions

- Verification mode: `strict` in production
- Failure policy: `fail-closed`
- Trust anchor: local agent performs final verification
- Initial OS targets: Linux + macOS
- Local agent language: Go
- Metadata source: control plane API
- Chat trigger model: channel-agnostic, mapped to OpenClaw user identity
- Local confirmation policy: required on every new connection request
- Local confirmation UX: native desktop prompt with CLI fallback

## Goals

- Provide a clean implementation path to full strict TDX attestation verification.
- Allow users to request connector access from any paired chat channel.
- Ensure server-side orchestration cannot bypass local trust checks.
- Keep flow seamless while preserving explicit user intent on-device.

## Non-Goals (M1)

- Windows support
- Long-lived unattended approvals
- Channel-specific custom trust policies
- Alternative trust anchors outside the local machine

## Architecture (M1)

M1 uses a split architecture:

- Control plane/OpenClaw handles channel intake and request orchestration.
- Local Go agent is the sole trust decision point.

The control plane is not trusted to decide whether a connector is safe. It only coordinates request lifecycle and delivers signed metadata. Any paired channel (Telegram, Slack, etc.) can initiate a connection request under a single OpenClaw user identity. Each request must still be confirmed locally on the target device.

### Components

- Channel Adapters
- Access Orchestrator API
- Connector Metadata Service
- Local Agent (Go, Linux/macOS)
- TEE Connector

### Trust Boundary

- Local agent enforces strict attestation policy before enabling connection.
- Control plane compromise should not allow silent access because local confirmation + local strict verification are both mandatory.

### High-Level Flow

1. User requests access from a paired chat channel.
2. Orchestrator creates a short-lived request and notifies local agent.
3. Local agent prompts user for on-device confirmation.
4. On approval, agent fetches signed attestation bundle.
5. Agent performs strict verification (`fail-closed`).
6. If verification passes, agent enables trust window and connector SSH path.
7. Connection status is reported back to orchestrator and relayed to chat.

## Contracts and APIs

## Data Model: `ConnectionRequest`

- `id`
- `openclaw_user_id`
- `device_id`
- `connector_id`
- `source_channel` (informational)
- `status`:
  - `pending_local_confirm`
  - `denied_local`
  - `approved`
  - `expired`
  - `verification_failed`
  - `connected`
- `created_at`
- `expires_at` (recommended TTL: 5 minutes)
- `nonce`

## Core APIs

1. `POST /v1/connection-requests`
   - Created by channel adapter after OpenClaw auth.
2. `POST /v1/connection-requests/{id}/notify-device`
   - Pushes request to local agent (WebSocket preferred, polling fallback).
3. `POST /v1/connection-requests/{id}/local-decision`
   - Local agent reports `approve|deny` after native/CLI confirmation.
4. `GET /v1/connection-requests/{id}/attestation-bundle`
   - Available only after local approval; returns signed verification bundle.
5. `POST /v1/connection-requests/{id}/result`
   - Local agent reports terminal outcome + reason code.

## Attestation Bundle

- `connector_id`
- `ssh_public_key`
- `quote_hex`
- `event_log`
- `mrtd`
- `rtmr0`
- `rtmr1`
- `rtmr2`
- `rtmr3`
- `report_data_expected_sha256`
- `policy_version`
- `issued_at`
- `expires_at`
- `nonce`
- `signature`

## OpenClaw Skill Contract

- Unified intent: `request_connector_access(connector_id, device_id?)`
- Skill triggers orchestration and relays status.
- Skill does not perform trust verification.

## Verification and Security Pipeline

Local agent pipeline (`strict`, `fail-closed`):

1. Validate request ID, nonce, and expiry.
2. Verify bundle signature from control plane.
3. Run strict DCAP checks (certificate chain, CRL, TCB, QE identity).
4. Enforce measurement policy (`MRTD`, `RTMR0..3`) against allowlist.
5. Compute `sha256(ssh_public_key)` and require exact `REPORT_DATA` match.
6. Only then mark key/request as trusted and proceed.

## Error Model

- `UserDenied`
- `RequestExpired`
- `BundleInvalid`
- `AttestationDependencyFailure`
- `QuoteInvalid`
- `MeasurementMismatch`
- `ReportDataMismatch`
- `TransportFailure`

Each error is returned as a clear reason code to orchestrator/chat without exposing sensitive internals.

## Testing Strategy

- Unit tests:
  - signature/nonce/TTL validation
  - `REPORT_DATA` binding logic
  - measurement policy matcher
- Integration tests:
  - mocked orchestrator + local approval flow + strict verifier fixtures
- Adversarial tests:
  - replayed bundle
  - key/quote swap
  - stale CRL
  - downgraded TCB
  - RTMR mismatch
- End-to-end smoke tests (Linux/macOS):
  - chat request -> local confirm -> strict verify -> connected status

## Rollout Notes

- Implement a stable `Verifier` interface in M1 so strict and baseline modes share contracts.
- Keep strict policy default in production; baseline may exist for controlled non-prod validation only.
- Maintain request TTL and one-time nonce semantics to limit replay windows.

## Next Step

Convert this design into a concrete implementation plan (work packages, sequencing, acceptance criteria, and test gates), then execute in an isolated worktree.
