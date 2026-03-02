# OpenClaw Skill Contract for enclout

## Purpose

Define the chat-agent contract for invoking `enclout` flows through OpenClaw intents.
This contract is channel-agnostic: any paired channel can use it by setting `source_channel`.

Skill distribution:

- Recommended dynamic install: `npx skills add HashWarlock/enclout --skill enclout-openclaw-agent -a openclaw -g -y`
- Reliable fallback: `npx skills add https://github.com/HashWarlock/enclout/tree/main/skills/enclout-openclaw-agent -a openclaw -g -y`
- Repository skill source: `skills/enclout-openclaw-agent`
- Local fallback installer: `scripts/install-enclout-skill.sh`

## Transport

- Endpoint: `POST /v1/openclaw/intents` on the active OpenClaw gateway/session origin
- Auth: use gateway session auth by default; if explicit bearer is required, mint a short-lived bearer with the runtime deterministic key generator capability
- Content type: `application/json`

Agent UX rule:

- End users should start with a connect request and install link flow.
- Do not ask for `connector_id`/`device_id` up front.
- Derive `openclaw_user_id` and `source_channel` from agent/runtime context.
- Derive control-plane URL/auth context from the gateway/session dynamically; do not require static `API_AUTH_TOKEN` or `CONTROL_PLANE_URL` in paired-channel chat flow.

## Intents

### 1) `request_connector_connect` (URL-First)

Use when a user asks to connect and connector install may be required.

Request:

```json
{
  "intent": "request_connector_connect",
  "openclaw_user_id": "usr_1",
  "source_channel": "telegram"
}
```

Response `201 Created`:

```json
{
  "install_session_id": "ins_1",
  "install_token": "tok_1",
  "install_url": "https://control-plane.example/install?token=tok_1",
  "status": "requested",
  "expires_at": "2026-02-24T17:05:00Z",
  "install_commands": {
    "darwin": "CONTROL_PLANE_URL=\"<control_plane_url>\" DCAP_VERIFIER_URL=\"<dcap_verifier_url>\" enclout install -token \"tok_1\" -agent-bin \"/usr/local/bin/enclout-agent\"",
    "linux": "CONTROL_PLANE_URL=\"<control_plane_url>\" DCAP_VERIFIER_URL=\"<dcap_verifier_url>\" enclout install -token \"tok_1\" -agent-bin \"/usr/local/bin/enclout-agent\""
  }
}
```

Notes:

- `install_token` is one-time and short-lived; do not log it in plaintext.
- Prefer `install_url` as primary UX.
- Use `install_commands.darwin` or `.linux` based on user device OS.

### 2) `request_connector_install` (Backward-Compatible)

Supported for direct install flow when `connector_id` and `device_id` are already known.

### 3) `approve_install_session`

Use after user confirms they want to proceed.

Request:

```json
{
  "intent": "approve_install_session",
  "install_session_id": "ins_1",
  "approved": true
}
```

Response `200 OK`:

```json
{
  "id": "ins_1",
  "openclaw_user_id": "usr_1",
  "device_id": "dev_1",
  "connector_id": "conn_1",
  "source_channel": "telegram",
  "status": "approved",
  "reason_code": "",
  "created_at": "2026-02-24T17:00:00Z",
  "expires_at": "2026-02-24T17:05:00Z"
}
```

If `approved` is `false`, status transitions to `failed` with `reason_code` `Denied`.

### 4) `install_session_result`

Used by the installer/local agent to report terminal install outcome.

Request:

```json
{
  "intent": "install_session_result",
  "install_session_id": "ins_1",
  "status": "installed",
  "reason_code": ""
}
```

Allowed `status` values:

- `installed`
- `failed`

Response `200 OK`: updated install session object.

### 5) `request_connector_access`

Use after install succeeds and install session now contains `connector_id` + `device_id`.

Request:

```json
{
  "intent": "request_connector_access",
  "openclaw_user_id": "usr_1",
  "connector_id": "conn_1",
  "device_id": "dev_1",
  "source_channel": "telegram"
}
```

Response `201 Created`: connection request object with status `pending_local_confirm`.

## Install Status Polling

Endpoint:

- `GET /v1/install-sessions/{install_session_id}`

Auth:

- Use gateway session auth by default.
- If explicit bearer is required, mint a short-lived bearer using the runtime deterministic key generator capability.

Response `200 OK` returns current install session state.

States:

- `requested`
- `approved`
- `installed` (terminal success)
- `failed` (terminal failure)

## Recommended Agent Flow (Any Paired Channel)

1. Receive user connect request from paired channel.
2. Call `request_connector_connect`.
3. Send `install_url` to user and approve session.
4. Call `approve_install_session`.
5. Poll `GET /v1/install-sessions/{id}` every 2-3 seconds.
6. Stop polling on `installed` or `failed`, then report result to user.
7. On `installed`, read `connector_id` and `device_id` from session.
8. Call `request_connector_access` with these bound IDs.

## Error Handling

Common response codes:

- `400`: `invalid_json`, `unsupported_intent`, `create_failed`, `update_failed`
- `404`: `not_found`
- `409`: `invalid_transition`
- `410`: `install_session_expired`

Agent behavior:

- Treat `install_session_expired` and terminal `failed` as hard stop.
- Never reuse an `install_token`.
- Do not continue to access flow unless install status is `installed` or install was already complete.
- If gateway URL/auth context cannot be resolved, return operator-facing gateway-context error (do not ask end user for tokens/URLs).
