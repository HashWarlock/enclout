# Drift-Closure Release Notes

Date: 2026-04-08

## Summary

This release closes the major architecture/implementation drift for Phase A (Trust Plane).

Delivered:

- Revocation semantics with terminal `revoked` handling across API + CLI wait path.
- Atomic request transitions to prevent `revoke`/`result` race overwrite.
- Connector inventory APIs: `GET /v1/connectors`, `GET /v1/connectors/{id}`.
- Request history API: `GET /v1/requests` with filters/pagination.
- Audit history API: `GET /v1/audit` with filters/pagination.
- Managed key rotation workflow on endpoint:
  - connector-scoped key metadata
  - stale-key cleanup after connector rotation
  - status output includes local key inventory and stale detection.
- Documentation convergence to canonical routes and phase model.

## API Additions

- `POST /v1/requests/{id}/revoke`
- `GET /v1/connectors`
- `GET /v1/connectors/{id}`
- `GET /v1/requests`
- `GET /v1/audit`

## Behavior Changes

- `connect --wait` now treats `revoked` as terminal and exits non-zero.
- Request state transitions are enforced atomically at the repository layer.
- Runner checks request approval in-flight and refuses to continue on revocation.

## Operator Migration Notes

- Update downstream integrations to canonical endpoints:
  - use `/v1/sessions/*` (not `/v1/install-sessions/*`)
  - use `/v1/requests/*` (not `/v1/connection-requests/*`)
- If using local key management automation, expect connector-scoped managed metadata under the configured keys dir.
- Use the implementation matrix for current capability status:
  - `docs/runbooks/implementation-status-matrix.md`

## Verification Snapshot

- `go test ./...` passed.
- Route grep audit confirms required routes are present in `internal/server/router.go`.
