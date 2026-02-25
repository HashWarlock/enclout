import { createHash } from "node:crypto";
import { deriveEd25519Identity } from "./identity.js";
import { buildAttestationPayload } from "./publish.js";

function requireEnv(name) {
  const value = process.env[name];
  if (!value) {
    throw new Error(`missing ${name}`);
  }
  return value;
}

function loadSeed() {
  const seedB64 = requireEnv("TEE_SEED_B64");
  const seed = Buffer.from(seedB64, "base64");
  if (seed.length !== 32) {
    throw new Error("TEE_SEED_B64 must decode to 32 bytes");
  }
  return seed;
}

function run() {
  const seed = loadSeed();
  const quoteHex = requireEnv("TEE_QUOTE_HEX");
  const connectorId = requireEnv("CONNECTOR_ID");
  const identity = deriveEd25519Identity(seed);
  const payload = buildAttestationPayload(identity.sshPublicKey, quoteHex, {
    mrtd: process.env.MRTD ?? "",
    rtmr0: process.env.RTMR0 ?? "",
    rtmr1: process.env.RTMR1 ?? "",
    rtmr2: process.env.RTMR2 ?? "",
    rtmr3: process.env.RTMR3 ?? "",
    eventLog: process.env.EVENT_LOG ?? "[]",
    policyVersion: process.env.POLICY_VERSION ?? "v1",
  });

  const output = {
    connector_id: connectorId,
    identity_fingerprint_sha256: createHash("sha256").update(identity.sshPublicKey).digest("hex"),
    attestation: payload,
  };

  process.stdout.write(`${JSON.stringify(output)}\n`);
}

run();
