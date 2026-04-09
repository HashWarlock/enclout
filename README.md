# enclout

`enclout` is a Go-based control plane + endpoint agent for TEE-attested connector access.

## Scope

Current implementation aligns to **Phase A (Trust Plane)**:

- Request/session lifecycle APIs.
- Endpoint local approval and attestation verification.
- Signed connector bundle delivery.
- Managed SSH key installation with rotation cleanup.
- Query APIs for connectors, request history, and audit metadata.

Planned:

- **Phase B (Transport Plane):** CVM-side reverse connector runtime and live shell/port-forward transport.
- **Phase C (Forensics Plane):** full terminal/file-op capture with endpoint-only encryption and tamper-evident chaining.

## Commands

- `enclout serve`: start control plane HTTP API.
- `enclout agent`: run endpoint polling/verification/key-install daemon.
- `enclout connect`: create a connection request.
- `enclout install`: redeem an install token and register device/connector identity.
- `enclout status`: inspect request/device status and local managed key inventory.
- `enclout mcp`: run MCP server.

## Canonical API Surface

- `POST /v1/requests`
- `GET /v1/requests`
- `GET /v1/requests/{id}`
- `POST /v1/requests/{id}/decision`
- `POST /v1/requests/{id}/revoke`
- `POST /v1/requests/{id}/result`
- `GET /v1/requests/{id}/bundle`
- `POST /v1/sessions`
- `GET /v1/sessions/{id}`
- `POST /v1/sessions/{id}/approve`
- `POST /v1/sessions/{id}/register`
- `POST /v1/sessions/{id}/result`
- `POST /v1/sessions/redeem`
- `GET /v1/devices/{deviceID}/pending`
- `POST /v1/connectors/register`
- `GET /v1/connectors`
- `GET /v1/connectors/{id}`
- `GET /v1/audit`
- `GET /v1/signing-keys`

Operational endpoints:

- `GET /healthz`
- `GET /install`

## Runtime Configuration (Current)

Serve (`enclout serve`):

- `ENCLOUT_BIND`
- `ENCLOUT_DB`
- `ENCLOUT_CONNECTOR_ID`
- `ENCLOUT_AUTH_TOKEN`
- `ENCLOUT_SIGNING_KEY_B64` or `ENCLOUT_SIGNING_KEYS_JSON`
- `ENCLOUT_SIGNING_ACTIVE_KID`

Agent (`enclout agent`):

- `ENCLOUT_SERVER`
- `ENCLOUT_DEVICE_ID`
- `ENCLOUT_USERNAME`
- `ENCLOUT_TOKEN`
- `ENCLOUT_DCAP_URL`
- `ENCLOUT_DCAP_TOKEN`
- `ENCLOUT_DCAP_TIMEOUT`
- `ENCLOUT_KEYS_DIR`
- `ENCLOUT_AUDIT_DIR`
- `ENCLOUT_ALLOW_MRTD`
- `ENCLOUT_ALLOW_RTMR3`

## Verification

Run full test suite:

```bash
go test ./...
```

## Canonical References

- Architecture baseline: `docs/superpowers/specs/2026-04-08-enclout-canonical-architecture-design.md`
- Drift-closure execution plan: `docs/superpowers/plans/2026-04-08-enclout-drift-closure-implementation-plan.md`
- Capability status matrix: `docs/runbooks/implementation-status-matrix.md`
