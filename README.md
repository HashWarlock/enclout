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
  - `docs/runbooks/openclaw-skill-contract.md` defines the channel-agnostic agent intent contract.
  - `docs/runbooks/signing-key-rotation.md` covers safe `kid` rotation.
- `skills/enclout-openclaw-agent`: reusable skill package for OpenClaw/Codex chat agents.

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

## OpenClaw Agent Skill

Install the bundled `enclout` skill package into your agent skill directory:

```bash
./scripts/install-enclout-skill.sh "$HOME/.agents/skills"
```

Default install target (if omitted) is `~/.agents/skills`.
Skill contents live at `skills/enclout-openclaw-agent`.

### Docker Compose (CVM) Quickstart

Use this flow when your OpenClaw agent runs in a Docker Compose service.

1. Update the repo on the CVM host:

```bash
cd ~/enclout
git checkout main
git pull origin main
```

2. Install the `enclout` skill on the CVM host:

```bash
cd ~/enclout
./scripts/install-enclout-skill.sh "$HOME/.agents/skills"
```

3. Mount host skills into the agent container (adjust service/path names):

```yaml
services:
  openclaw-agent:
    volumes:
      - ${HOME}/.agents/skills:/home/app/.agents/skills:ro
```

4. Recreate the agent container:

```bash
docker compose up -d --force-recreate openclaw-agent
```

5. Verify the skill exists inside the container:

```bash
docker compose exec openclaw-agent \
  sh -lc 'find /home/app/.agents/skills/enclout-openclaw-agent -maxdepth 2 -type f | sort'
```

6. Run a chat smoke test from any paired channel:

```text
Install enclout connector <connector_id> on device <device_id> from this channel.
```

Expected flow:

1. Agent calls `request_connector_install`.
2. Agent calls `approve_install_session`.
3. You run the returned `enclout install` command on the target device.
4. Agent polls `GET /v1/install-sessions/{id}` until terminal state.
5. Agent proceeds with `request_connector_access` after `installed`.
