# Signing Key Rotation Runbook

## Purpose

Rotate control-plane attestation signing keys without breaking local-agent verification.

## Preconditions

- Control plane and local agents are running versions that support bundle `kid` and keysets.
- Current and next signing seeds are prepared securely.
- You can update environment variables on control plane and local agents.

## Data Model

- Control plane signs bundles with `kid`.
- Control plane exposes trusted keyset at `GET /v1/signing-keys`.
- Local agent verifies bundle signature by `kid` against trusted key map.

## Required Configuration

Control plane:

- `SIGNING_KEYS_JSON` as `{"v1":"<seed_b64>","v2":"<seed_b64>"...}`
- `SIGNING_ACTIVE_KID` as active key id

Local agent:

- `CONTROL_PLANE_SIGNING_KEYS_JSON` as `{"v1":"<pubkey_b64>","v2":"<pubkey_b64>"...}`

## Safe Rotation Procedure (N to N+1)

1. Generate new keypair offline and assign new `kid` (example: `v2`).
2. Keep current key (`v1`) active on control plane.
3. Update control plane `SIGNING_KEYS_JSON` to include both `v1` and `v2`.
4. Keep `SIGNING_ACTIVE_KID=v1`.
5. Deploy control plane config and verify `GET /v1/signing-keys` returns both keys.
6. Update local agents with both public keys in `CONTROL_PLANE_SIGNING_KEYS_JSON`.
7. Confirm local agents are healthy and verifying bundles.
8. Switch control plane to `SIGNING_ACTIVE_KID=v2`.
9. Verify new bundles contain `"kid":"v2"` and local agents accept them.
10. Keep overlap window (recommended 24 hours minimum).
11. Remove `v1` from local agents after overlap window and verification.
12. Remove `v1` from control plane keyset after all agents are updated.

## Verification Checklist

1. `GET /v1/signing-keys` shows expected `active_kid` and all overlap keys.
2. Bundle responses include expected `kid`.
3. Local-agent logs show no `BundleInvalid` during overlap.
4. Requests still complete as `connected` with the new active `kid`.

## Rollback Procedure

1. Revert control plane `SIGNING_ACTIVE_KID` to previous key.
2. Keep both keys present in control plane and agents.
3. Re-deploy control plane.
4. Confirm bundles are signed with previous `kid` and local-agent errors clear.

## Failure Modes

- Unknown `kid` on agent:
  - Cause: control plane switched to new key before agents received keyset.
  - Fix: add missing `kid` public key to agents or roll back active `kid`.
- Signature mismatch:
  - Cause: wrong key material, payload tampering, or malformed key map.
  - Fix: validate key mapping and signer source, then redeploy.

## Emergency Notes

- Never remove old key before all agents trust new key.
- Never switch active `kid` without overlap.
- Treat signing seed exposure as incident: rotate immediately and invalidate old key.
