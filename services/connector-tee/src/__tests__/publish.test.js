import test from "node:test";
import assert from "node:assert/strict";
import { buildAttestationPayload } from "../publish.js";

test("builds attestation payload with quote and report-data hash", () => {
  const payload = buildAttestationPayload("ssh-ed25519 AAAATEST connector@tee", "abcd", {
    mrtd: "mrtd",
    rtmr0: "rtmr0",
    rtmr1: "rtmr1",
    rtmr2: "rtmr2",
    rtmr3: "rtmr3",
    eventLog: "[]",
    policyVersion: "v1",
  });

  assert.match(payload.report_data_expected_sha256, /^[a-f0-9]{64}$/);
  assert.equal(payload.quote_hex, "abcd");
  assert.equal(payload.mrtd, "mrtd");
});
