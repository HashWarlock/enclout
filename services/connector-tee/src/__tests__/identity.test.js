import test from "node:test";
import assert from "node:assert/strict";
import { deriveEd25519Identity } from "../identity.js";

test("derives deterministic ssh-ed25519 public key from 32-byte seed", () => {
  const seed = Buffer.alloc(32, 7);
  const outA = deriveEd25519Identity(seed);
  const outB = deriveEd25519Identity(seed);

  assert.equal(outA.sshPublicKey.startsWith("ssh-ed25519 "), true);
  assert.equal(outA.sshPublicKey, outB.sshPublicKey);
  assert.equal(outA.publicKey.length, 32);
});
