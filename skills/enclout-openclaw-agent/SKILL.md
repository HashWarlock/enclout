---
name: enclout-openclaw-agent
description: Use when a user asks to connect from any paired channel and you need a URL-first enclout install flow with install-session polling and automatic connector/device identity binding.
---

# enclout OpenClaw Agent Skill

## Purpose

Run a channel-agnostic URL-first connect flow for `enclout` through OpenClaw intents.

## User-Facing Inputs (Ask Only These)

- None required up front.
- Optional clarification only if user asks to target a specific device/group.

Do not ask for `connector_id` or `device_id` before install completes.

## Runtime-Resolved Inputs (Do Not Ask End User)

- `CONTROL_PLANE_URL` from runtime config
- `API_AUTH_TOKEN` from runtime secrets
- `openclaw_user_id` from chat identity/session context
- `source_channel` from current channel metadata

## Connect + Install Workflow

1. Create connect/install session via `request_connector_connect`.
2. Send the returned clickable `install_url` to the user.
3. Approve session with `approve_install_session` (`approved=true`).
4. Poll `GET /v1/install-sessions/{id}` every 2-3 seconds.
5. Stop polling on terminal state:
   - `installed`: read `connector_id` + `device_id` from session and continue to access request flow.
   - `failed`: report `reason_code` and stop.

## Access Workflow

1. After successful install, send `request_connector_access` with bound `connector_id` and `device_id`.
2. Return resulting request status to the user.

## API Templates

Use templates in `templates/`:

- `request_connector_connect.json`
- `request_connector_install.json`
- `approve_install_session.json`
- `request_connector_access.json`
- `install_session_result.json`
- `user-install-response.md`

## Guardrails

- Never print or persist `install_token` beyond active install flow.
- Never reuse a token after redemption attempt.
- Treat `install_session_expired` and terminal `failed` as hard-stop errors.
- Keep `source_channel` as the channel where the request originated.
- Never ask end users for `API_AUTH_TOKEN`, `CONTROL_PLANE_URL`, or raw `openclaw_user_id`.
- If runtime config/secrets are missing, return a short operator-facing error instead of requesting those values from the user.
- If install reaches `installed` but `connector_id`/`device_id` is missing, stop and report operator error (do not ask end user for IDs).
