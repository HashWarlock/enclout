# OpenClaw Skill Contract (Canonical)

This runbook defines how a channel agent should call enclout's **current canonical API**.

## Control Plane Auth

- Use `Authorization: Bearer <token>` for all `/v1/*` endpoints.
- Resolve URL/auth from operator/runtime context; do not request raw tokens from end users.

## Canonical Endpoint Mapping

Connect flow:

1. Create request: `POST /v1/requests`
2. Poll/request status: `GET /v1/requests/{id}`
3. Endpoint local decision: `POST /v1/requests/{id}/decision`
4. Optional revoke: `POST /v1/requests/{id}/revoke`
5. Connector fetches signed bundle: `GET /v1/requests/{id}/bundle`
6. Connector reports result: `POST /v1/requests/{id}/result`

Install flow:

1. Create install session: `POST /v1/sessions`
2. Poll session: `GET /v1/sessions/{id}`
3. Approve/deny session: `POST /v1/sessions/{id}/approve`
4. Redeem install token digest: `POST /v1/sessions/redeem`
5. Register connector/device identity: `POST /v1/sessions/{id}/register`
6. Report install outcome: `POST /v1/sessions/{id}/result`

Observability:

- Pending by device: `GET /v1/devices/{deviceID}/pending`
- Request history: `GET /v1/requests`
- Connector inventory: `GET /v1/connectors`, `GET /v1/connectors/{id}`
- Audit history: `GET /v1/audit`

## Recommended Agent Behavior

- Default to URL-first install UX by creating install sessions.
- Do not ask for `connector_id`/`device_id` before install registration completes.
- Treat terminal request statuses (`connected`, `denied_local`, `verification_failed`, `expired`, `revoked`) as final.
- Treat terminal install statuses (`installed`, `failed`) as final.

## Query Contracts

Request listing (`GET /v1/requests`) supports:

- `device_id`
- `requester_id`
- `status`
- `limit`
- `offset`

Audit listing (`GET /v1/audit`) supports:

- `entity_type`
- `entity_id`
- `since` (RFC3339)
- `until` (RFC3339)
- `limit`
- `offset`

## Compatibility Note

Legacy OpenClaw intent transports are not canonical implementation surfaces in this repository. If a compatibility adapter exists externally, it should translate into the above `/v1/*` routes.
