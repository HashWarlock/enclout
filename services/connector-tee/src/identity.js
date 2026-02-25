import { createPrivateKey, createPublicKey } from "node:crypto";

const ED25519_PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

function encodeSSHString(data) {
  const buf = Buffer.alloc(4);
  buf.writeUInt32BE(data.length, 0);
  return Buffer.concat([buf, data]);
}

export function deriveEd25519Identity(seedInput) {
  const seed = Buffer.from(seedInput);
  if (seed.length !== 32) {
    throw new Error("seed must be 32 bytes");
  }

  const pkcs8Der = Buffer.concat([ED25519_PKCS8_PREFIX, seed]);
  const privateKey = createPrivateKey({
    key: pkcs8Der,
    format: "der",
    type: "pkcs8",
  });

  const spkiDer = createPublicKey(privateKey).export({
    format: "der",
    type: "spki",
  });
  const spki = Buffer.from(spkiDer);
  if (spki.length !== ED25519_SPKI_PREFIX.length + 32 || !spki.slice(0, ED25519_SPKI_PREFIX.length).equals(ED25519_SPKI_PREFIX)) {
    throw new Error("unexpected ed25519 spki encoding");
  }
  const publicKey = spki.slice(ED25519_SPKI_PREFIX.length);

  const keyType = Buffer.from("ssh-ed25519");
  const blob = Buffer.concat([encodeSSHString(keyType), encodeSSHString(publicKey)]);
  const sshPublicKey = `ssh-ed25519 ${blob.toString("base64")} connector@tee`;

  const privateKeyPem = privateKey.export({
    format: "pem",
    type: "pkcs8",
  });

  return {
    publicKey,
    sshPublicKey,
    privateKeyPem: String(privateKeyPem),
  };
}
