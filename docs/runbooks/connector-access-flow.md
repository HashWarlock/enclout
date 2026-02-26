# Connector Access Flow Runbook

## Purpose

Describe the operator sequence for channel-initiated connector access with local trust enforcement.

## Preconditions

- Control plane is reachable over HTTPS.
- Local agent is running on Linux or macOS.
- Local agent has `DCAP_VERIFIER_URL` configured to a strict DCAP verification service.
- Connector metadata is published for the requested `connector_id`.
- Device has active OpenClaw pairing for at least one chat channel.

## Flow

1. User requests access from a paired channel using the OpenClaw intent:
   - `request_connector_access(connector_id, device_id?)`
2. Control plane creates a `pending_local_confirm` request with short TTL and nonce.
3. Local agent receives request and prompts user on-device (native prompt; CLI fallback).
4. Local agent posts local decision:
   - `approve` -> request moves to `approved`
   - `deny` -> request moves to `denied_local`
5. On approval, local agent fetches signed attestation bundle.
6. Local agent verifies strictly (fail-closed):
   - Bundle signature and freshness
   - Quote validity, QE identity, TCB status
   - Measurement policy (`MRTD`, `RTMR*`)
   - `REPORT_DATA` binding to SSH public key hash
7. If verification passes, local agent installs managed SSH key and posts `connected`.
8. If verification fails, local agent posts `verification_failed` with reason code.
9. Channel receives final state from orchestrator.

## Install Bootstrap Flow (macOS Launchd First)

1. User requests install from a paired channel:
   - `request_connector_install(connector_id, device_id?)`
2. Control plane creates install session (`requested`) and returns one-time `install_token`.
3. OpenClaw agent approves install session:
   - `approve_install_session(install_session_id, approved=true)`
4. On device, user runs local installer with token (`cmd/install`).
5. Installer redeems token once:
   - valid + approved -> session details returned
   - invalid/replayed/expired -> fail closed
6. Installer writes `launchd` plist and starts local agent service.
7. Installer posts install result:
   - `installed` on success
   - `failed` with reason code on failure
8. Channel receives install outcome and can proceed with normal `request_connector_access`.

## Operational Checks

- Check `/healthz` on control plane.
- Inspect local agent logs for:
  - decision prompt outcomes
  - verifier reason codes
  - SSH key install result
- Verify request lifecycle transitions in control-plane store/logs.

## Security Invariants

- No connection without local confirmation for that request ID.
- No trust without strict local verification.
- Control plane orchestration does not replace local trust evaluation.
