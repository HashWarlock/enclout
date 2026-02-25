import { createHash } from "node:crypto";

export function buildAttestationPayload(sshPublicKey, quoteHex, measurements) {
  if (!sshPublicKey || !quoteHex) {
    throw new Error("sshPublicKey and quoteHex are required");
  }

  const reportDataHash = createHash("sha256").update(sshPublicKey).digest("hex");
  return {
    ssh_public_key: sshPublicKey,
    quote_hex: quoteHex,
    event_log: measurements.eventLog ?? "[]",
    mrtd: measurements.mrtd,
    rtmr0: measurements.rtmr0,
    rtmr1: measurements.rtmr1,
    rtmr2: measurements.rtmr2,
    rtmr3: measurements.rtmr3,
    report_data_expected_sha256: reportDataHash,
    policy_version: measurements.policyVersion ?? "v1",
  };
}
