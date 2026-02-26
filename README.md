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
  - `docs/runbooks/signing-key-rotation.md` covers safe `kid` rotation.

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

## Control Plane Runtime Env

Required:

- `API_AUTH_TOKEN`

Signing key configuration (choose one):

- Single key mode:
  - `SIGNING_KEY_B64`
  - Optional `SIGNING_ACTIVE_KID` (default `v1`)
- Rotation/keyset mode:
  - `SIGNING_KEYS_JSON` (JSON object of `kid -> seed_b64`)
  - `SIGNING_ACTIVE_KID` (must exist in `SIGNING_KEYS_JSON`)

Optional:

- `BIND_ADDR` (default `127.0.0.1:8080`)
- `STORE_PATH` (default `./var/control-plane-requests.json`)
- `CONNECTOR_BUNDLE_TEMPLATES_JSON`

## Local Agent Runtime Env

Required:

- `CONTROL_PLANE_URL`
- `DEVICE_ID`
- `LOCAL_USERNAME`
- `DCAP_VERIFIER_URL`

Control-plane signing trust bootstrap (optional):

- Keyset bootstrap:
  - `CONTROL_PLANE_SIGNING_KEYS_JSON` (JSON object of `kid -> public_key_b64`)
- Single key bootstrap (backward compatible):
  - `CONTROL_PLANE_SIGNING_PUBKEY_B64`
  - Optional `CONTROL_PLANE_SIGNING_KID` (default `v1`)

Runtime keyset refresh:

- Local agent fetches `GET /v1/signing-keys` and caches trusted keys.
- `SIGNING_KEYSET_CACHE_TTL` (seconds or duration string, default `5m`)

Optional:

- `AGENT_TOKEN`
- `DCAP_VERIFIER_TOKEN`
- `DCAP_VERIFIER_TIMEOUT` (seconds or duration string, default `10s`)
- `MANAGED_KEYS_DIR` (default `/var/lib/connector-agent/keys`)
- `ALLOW_MRTD` (comma-separated allowlist)
- `ALLOW_RTMR3` (comma-separated allowlist)

## Install Bootstrap (macOS + Linux)

For install bootstrap from any paired channel:

1. Request install from any paired chat channel through OpenClaw intent `request_connector_install`.
2. Use the returned one-time `install_token` and run the installer.

macOS (`launchd`):

```bash
CONTROL_PLANE_URL=http://127.0.0.1:8080 \
DCAP_VERIFIER_URL=http://127.0.0.1:9000 \
go run ./services/local-agent/cmd/install -- \
  -token "<install_token>" \
  -agent-bin "/usr/local/bin/enclout-agent"
```

Linux (`systemd --user`):

```bash
CONTROL_PLANE_URL=http://127.0.0.1:8080 \
DCAP_VERIFIER_URL=http://127.0.0.1:9000 \
go run ./services/local-agent/cmd/install -- \
  -token "<install_token>" \
  -agent-bin "/usr/local/bin/enclout-agent"
```

3. Installer redeems token, configures OS service (`launchd` or `systemd --user`), starts the agent, and posts install result (`installed` or `failed`) back to control plane.
