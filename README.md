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

For URL-first connect bootstrap from any paired channel:

1. Request connect through OpenClaw intent `request_connector_connect`.
2. Share/click the returned `install_url`.
3. Run installer with the one-time `install_token` (direct command or landing page instruction).

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

4. Installer redeems token, auto-registers `connector_id` + `device_id`, configures OS service (`launchd` or `systemd --user`), starts the agent, and posts install result (`installed` or `failed`) back to control plane.

## OpenClaw Agent Skill (Dynamic, Optional)

You do not need to pre-bake the `enclout` skill into your OpenClaw image.
Recommended path is dynamic install when needed.

Recommended (Agentskills-compatible, explicit skill selector):

```bash
npx skills add HashWarlock/enclout --skill enclout-openclaw-agent -a openclaw -g -y
```

Most reliable fallback (direct GitHub skill URL):

```bash
npx skills add https://github.com/HashWarlock/enclout/tree/main/skills/enclout-openclaw-agent -a openclaw -g -y
```

Do not use this older syntax (can fail to resolve skill correctly):

```text
HashWarlock/enclout@enclout-openclaw-agent
```

### Chat-Channel Bootstrap (Copy/Paste)

Use this as the first operator message in the paired chat channel:

```text
Install skill from https://github.com/HashWarlock/enclout/tree/main/skills/enclout-openclaw-agent for the openclaw agent.
Then confirm enclout-openclaw-agent is loaded.
After that, for connect requests, run URL-first flow:
request_connector_connect -> send install_url -> approve_install_session -> poll install session -> request_connector_access.
Never ask end users for API_AUTH_TOKEN, CONTROL_PLANE_URL, openclaw_user_id, source_channel, connector_id (before install), or device_id (before install).
Derive control-plane base URL from the active OpenClaw gateway/session origin.
Use gateway session auth by default; if explicit bearer is required, generate a short-lived bearer via deterministic key generator capability.
If gateway URL/auth context cannot be resolved, return exactly:
"Operator action needed: OpenClaw gateway auth context unavailable (cannot resolve gateway URL or generate session bearer). End user does not need to provide tokens or URLs."
```

User experience note:

- The skill should not ask for `connector_id`/`device_id` up front.
- OpenClaw identity/channel context must be runtime-resolved.
- Control-plane URL/auth must be derived dynamically from gateway/session context.
- If gateway URL/auth context is missing, return operator error; do not ask the end user for tokens or URLs.

### Agent Prompt Contract (Important)

When using `enclout-openclaw-agent`, the chat agent must follow this behavior:

1. Never ask the end user for runtime/operator values:
   `API_AUTH_TOKEN`, `CONTROL_PLANE_URL`, `openclaw_user_id`, `source_channel`,
   `connector_id` (before install), or `device_id` (before install).
2. Start with URL-first flow:
   `request_connector_connect` -> `install_url` -> approval -> polling.
3. Derive control-plane URL/auth from active gateway/session context; do not require static env values in chat flow.
4. If gateway URL/auth context is unavailable, return an operator-facing error instead of a user prompt.

Expected operator-facing error style:

```text
Operator action needed: OpenClaw gateway auth context unavailable (cannot resolve gateway URL or generate session bearer). End user does not need to provide tokens or URLs.
```

Local fallback (when running from checked-out repo):

```bash
./scripts/install-enclout-skill.sh "$HOME/.agents/skills"
```

### Docker Compose (CVM) Quickstart

Use this flow when your OpenClaw agent runs in a Docker Compose service.

1. Update the repo on the CVM host:

```bash
cd ~/enclout
git checkout main
git pull origin main
```

2. Install skill dynamically in the running agent container:

```bash
docker compose exec openclaw-agent \
  sh -lc 'npx skills add https://github.com/HashWarlock/enclout/tree/main/skills/enclout-openclaw-agent -a openclaw -g -y'
```

3. Optional but recommended: persist installed skills with a volume mount:

```yaml
services:
  openclaw-agent:
    volumes:
      - /path/on/host/agent-skills:/home/app/.agents/skills
```

4. Restart/recreate the agent service:

```bash
docker compose up -d --force-recreate openclaw-agent
```

5. Ask the agent to confirm skill load:

```text
List installed skills and confirm enclout-openclaw-agent is available.
```

6. Run a chat smoke test from any paired channel:

```text
Connect me to this device.
```

If the agent still asks the user for env vars or IDs, send this correction prompt once:

```text
Stop requesting runtime/operator values from end users.
Use enclout-openclaw-agent URL-first flow only.
Derive gateway URL/auth context dynamically; do not require static token/URL env vars.
If gateway URL/auth context is missing, return operator-action error only.
```

Expected flow:

1. Agent calls `request_connector_connect`.
2. Agent sends clickable `install_url`.
3. Agent calls `approve_install_session`.
4. You run the returned `enclout install` command on the target device.
5. Agent polls `GET /v1/install-sessions/{id}` until terminal state.
6. Agent reads `connector_id` + `device_id` from install session and proceeds with `request_connector_access`.
