# enclout

`enclout` = enclave + outbound SSH to connect to end devices.

This repository contains M1 scaffolding for a secure connector system that combines:

- Channel-agnostic access requests through OpenClaw identity.
- Local on-device confirmation for each connection request.
- Strict fail-closed attestation verification in the local agent.
- Signed attestation bundle delivery from control plane.

## Project Layout

- `services/control-plane`: request orchestration API and signed attestation bundle endpoint.
- `services/local-agent`: Linux/macOS agent for prompt, verification, and managed SSH key installation.
- `services/connector-tee`: deterministic identity + attestation payload publisher.
- `tests/integration`: strict-flow fixture tests.
- `docs/plans`: validated design and implementation plan.
- `docs/runbooks`: operator flow and failure-code references.

## Verification

Run:

```bash
./scripts/verify-m1.sh
```

The script requires both `go` and `node` toolchains.

## Connector TEE Runtime Env

Required:

- `CONNECTOR_ID`

TEE mode (default):

- `DSTACK_SIMULATOR_ENDPOINT` (optional; set for local simulator instead of unix socket)
- `DSTACK_KEY_PATH` (optional; default `ssh/connector/v1`)
- `DSTACK_KEY_SUBJECT` (optional; default `ed25519`)

Measurements:

- `MRTD`, `RTMR0`, `RTMR1`, `RTMR2`, `RTMR3`
- `EVENT_LOG` (optional; default `[]`)
- `POLICY_VERSION` (optional; default `v1`)

Legacy local fallback mode (for non-TEE development only):

- `TEE_SEED_B64`
- `TEE_QUOTE_HEX`

## Local Agent Runtime Env

Required:

- `CONTROL_PLANE_URL`
- `DEVICE_ID`
- `LOCAL_USERNAME`
- `DCAP_VERIFIER_URL`

Optional:

- `AGENT_TOKEN`
- `DCAP_VERIFIER_TOKEN`
- `DCAP_VERIFIER_TIMEOUT` (seconds or duration string, default `10s`)
- `MANAGED_KEYS_DIR` (default `/var/lib/connector-agent/keys`)
- `ALLOW_MRTD` (comma-separated allowlist)
- `ALLOW_RTMR3` (comma-separated allowlist)
