---
name: enclout-openclaw-agent
description: Use when a user wants to install or request enclout connector access from any paired chat channel and you need to orchestrate OpenClaw intents with install-session polling.
---

# enclout OpenClaw Agent Skill

## Purpose

Run a channel-agnostic install and access flow for `enclout` through OpenClaw intents.

## User-Facing Inputs (Ask Only These)

- `connector_id`
- Optional `device_id`

If `connector_id` is missing, ask one short question for it.
If `device_id` is missing, proceed with your paired/default device logic.

## Runtime-Resolved Inputs (Do Not Ask End User)

- `CONTROL_PLANE_URL` from runtime config
- `API_AUTH_TOKEN` from runtime secrets
- `openclaw_user_id` from chat identity/session context
- `source_channel` from current channel metadata

## Install Workflow

1. Create install session via `request_connector_install`.
2. Present the OS-specific command from `install_commands.darwin` or `install_commands.linux`.
3. Approve session with `approve_install_session` (`approved=true`).
4. Poll `GET /v1/install-sessions/{id}` every 2-3 seconds.
5. Stop polling on terminal state:
   - `installed`: continue to access request flow.
   - `failed`: report `reason_code` and stop.

## Access Workflow

1. After successful install (or when already installed), send `request_connector_access`.
2. Return resulting request status to the user.

## API Templates

Use templates in `templates/`:

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
