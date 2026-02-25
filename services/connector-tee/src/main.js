import { createHash } from "node:crypto";
import { DstackClient } from "@phala/dstack-sdk";
import { deriveEd25519Identity } from "./identity.js";
import { buildAttestationPayload } from "./publish.js";
import { buildConnectorOutputFromTEE } from "./tee.js";

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

function loadMeasurements() {
  return {
    mrtd: process.env.MRTD ?? "",
    rtmr0: process.env.RTMR0 ?? "",
    rtmr1: process.env.RTMR1 ?? "",
    rtmr2: process.env.RTMR2 ?? "",
    rtmr3: process.env.RTMR3 ?? "",
    eventLog: process.env.EVENT_LOG ?? "[]",
    policyVersion: process.env.POLICY_VERSION ?? "v1",
  };
}

function runLegacyEnvMode(connectorId) {
  const seed = loadSeed();
  const quoteHex = requireEnv("TEE_QUOTE_HEX");
  const identity = deriveEd25519Identity(seed);
  const payload = buildAttestationPayload(identity.sshPublicKey, quoteHex, loadMeasurements());

  return {
    connector_id: connectorId,
    identity_fingerprint_sha256: createHash("sha256").update(identity.sshPublicKey).digest("hex"),
    identity: {
      ssh_public_key: identity.sshPublicKey,
      public_key_hex: Buffer.from(identity.publicKey).toString("hex"),
    },
    attestation: payload,
    dstack_info: {
      app_id: "",
      instance_id: "",
      app_name: "",
      tcb_info: "",
    },
  };
}

async function run() {
  const connectorId = requireEnv("CONNECTOR_ID");
  const useLegacyEnvMode = process.env.TEE_SEED_B64 || process.env.TEE_QUOTE_HEX;
  if (useLegacyEnvMode) {
    const output = runLegacyEnvMode(connectorId);
    process.stdout.write(`${JSON.stringify(output)}\n`);
    return;
  }

  const endpoint = process.env.DSTACK_SIMULATOR_ENDPOINT;
  const client = endpoint ? new DstackClient(endpoint) : new DstackClient();
  const output = await buildConnectorOutputFromTEE({
    client,
    connectorId,
    measurements: loadMeasurements(),
    keyPath: process.env.DSTACK_KEY_PATH ?? "ssh/connector/v1",
    keySubject: process.env.DSTACK_KEY_SUBJECT ?? "ed25519",
  });
  process.stdout.write(`${JSON.stringify(output)}\n`);
}

run().catch((err) => {
  process.stderr.write(`${String(err?.stack ?? err)}\n`);
  process.exit(1);
});
