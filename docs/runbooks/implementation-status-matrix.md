# Enclout Implementation Status Matrix

Legend:

- `Implemented`: present in current Go codebase.
- `Planned`: intentionally deferred in canonical phase model.
- `Deprecated`: legacy naming/paths not authoritative.

## Platform Capabilities

| Capability | Phase | Status | Notes |
|---|---|---|---|
| Request lifecycle (`/v1/requests/*`) | A | Implemented | Includes revoke and terminal statuses. |
| Install session lifecycle (`/v1/sessions/*`) | A | Implemented | Includes token redeem + identity register + result. |
| Connector registration + signed bundle delivery | A | Implemented | `POST /v1/connectors/register`, `GET /v1/requests/{id}/bundle`. |
| Signing keyset endpoint | A | Implemented | `GET /v1/signing-keys`. |
| Pending device query | A | Implemented | `GET /v1/devices/{deviceID}/pending`. |
| Connector inventory query | A | Implemented | `GET /v1/connectors`, `GET /v1/connectors/{id}`. |
| Request history query | A | Implemented | `GET /v1/requests` with filters/pagination. |
| Audit history query | A | Implemented | `GET /v1/audit` with filters/pagination. |
| MRTD/RTMR3 allowlist enforcement flags | A | Implemented | `ENCLOUT_ALLOW_MRTD`, `ENCLOUT_ALLOW_RTMR3`. |
| Audit sink fail-closed gate | A | Implemented | Agent blocks connect when sink is unhealthy. |
| Managed key rotation + stale cleanup | A | Implemented | Connector-scoped key metadata + cleanup. |
| CVM reverse tunnel connector runtime | B | Planned | Not yet implemented in this repo. |
| Live shell + remote port-forward transport | B | Planned | Depends on Phase B runtime. |
| Full terminal/file-op encrypted forensic log | C | Planned | Requires endpoint-owned key design and capture pipeline. |

## Contract Surface Status

| Surface | Status |
|---|---|
| `/v1/requests`, `/v1/sessions`, `/v1/connectors`, `/v1/audit`, `/v1/signing-keys` | Implemented |
| `/v1/openclaw/intents` as canonical control-plane route | Deprecated |
| `/v1/install-sessions/*` naming | Deprecated |
| `/v1/connection-requests/*` naming | Deprecated |
