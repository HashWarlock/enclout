# Attestation Failure Codes

## Purpose

Reference for local-agent failure reasons returned to control plane and chat channels.

## Codes

- `AttestationDependencyFailure`
  - Meaning: strict verification dependency (PCCS/Intel endpoint/verifier backend) failed.
  - Behavior: fail-closed; request must not continue.
- `QuoteInvalid`
  - Meaning: quote cryptographic checks, QE identity, or TCB validation failed.
  - Behavior: reject request.
- `MeasurementMismatch`
  - Meaning: measured values (`MRTD`, `RTMR*`) are not allowlisted by current policy.
  - Behavior: reject request.
- `ReportDataMismatch`
  - Meaning: quote `REPORT_DATA` does not match expected hash of received SSH public key.
  - Behavior: reject request.
- `TransportFailure`
  - Meaning: trust succeeded but SSH key installation or connection preparation failed.
  - Behavior: request marked failed; operator action required.

## Triage Sequence

1. Confirm request ID and connector ID.
2. Confirm decision was locally approved for the same request.
3. Inspect local-agent verification logs for specific failure code.
4. If dependency/availability issue, restore verifier dependencies first.
5. If cryptographic/policy issue, compare attestation bundle fields with expected policy.
6. Retry only with new request ID and fresh local confirmation.
