import { createHash } from "node:crypto";
import { deriveEd25519Identity } from "./identity.js";
import { buildAttestationPayload } from "./publish.js";

const DEFAULT_KEY_PATH = "ssh/connector/v1";
const DEFAULT_KEY_SUBJECT = "ed25519";

function requireString(value, name) {
  const str = String(value ?? "").trim();
  if (!str) {
    throw new Error(`missing ${name}`);
  }
  return str;
}

function extractSeed32(getKeyResponse) {
  if (getKeyResponse?.key) {
    const seed = Buffer.from(getKeyResponse.key);
    if (seed.length === 32) {
      return seed;
    }
  }

  if (typeof getKeyResponse?.asUint8Array === "function") {
    const seed = Buffer.from(getKeyResponse.asUint8Array());
    if (seed.length === 32) {
      return seed;
    }
  }

  throw new Error("dstack getKey returned invalid key material; expected 32 bytes");
}

export async function buildConnectorOutputFromTEE({
  client,
  connectorId,
  measurements,
  keyPath = DEFAULT_KEY_PATH,
  keySubject = DEFAULT_KEY_SUBJECT,
}) {
  if (!client || typeof client.getKey !== "function" || typeof client.getQuote !== "function" || typeof client.info !== "function") {
    throw new Error("client must implement getKey, getQuote, and info");
  }

  const resolvedConnectorId = requireString(connectorId, "connectorId");
  const keyResponse = await client.getKey(keyPath, keySubject);
  const seed = extractSeed32(keyResponse);
  const identity = deriveEd25519Identity(seed);

  // REPORT_DATA must bind directly to the key material trusted by the client.
  const quoteResponse = await client.getQuote(identity.sshPublicKey);
  const dstackInfo = await client.info();

  const payload = buildAttestationPayload(identity.sshPublicKey, quoteResponse.quote, {
    mrtd: measurements.mrtd ?? "",
    rtmr0: measurements.rtmr0 ?? "",
    rtmr1: measurements.rtmr1 ?? "",
    rtmr2: measurements.rtmr2 ?? "",
    rtmr3: measurements.rtmr3 ?? "",
    eventLog: measurements.eventLog ?? quoteResponse.event_log ?? "[]",
    policyVersion: measurements.policyVersion ?? "v1",
  });

  return {
    connector_id: resolvedConnectorId,
    identity_fingerprint_sha256: createHash("sha256").update(identity.sshPublicKey).digest("hex"),
    identity: {
      ssh_public_key: identity.sshPublicKey,
      public_key_hex: Buffer.from(identity.publicKey).toString("hex"),
    },
    attestation: payload,
    dstack_info: {
      app_id: dstackInfo.app_id ?? "",
      instance_id: dstackInfo.instance_id ?? "",
      app_name: dstackInfo.app_name ?? "",
      tcb_info: dstackInfo.tcb_info ?? "",
    },
  };
}
