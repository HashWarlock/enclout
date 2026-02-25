import test from "node:test";
import assert from "node:assert/strict";
import { buildConnectorOutputFromTEE } from "../tee.js";

test("builds connector output from dstack client key+quote+info", async () => {
  const calls = {
    keyPath: "",
    keySubject: "",
    quoteInput: "",
    infoCalled: false,
  };

  const fakeClient = {
    async getKey(path, subject) {
      calls.keyPath = path;
      calls.keySubject = subject;
      return { key: Buffer.alloc(32, 7) };
    },
    async getQuote(data) {
      calls.quoteInput = String(data);
      return { quote: "aabbccdd", event_log: '[{"label":"compose-hash"}]' };
    },
    async info() {
      calls.infoCalled = true;
      return {
        app_id: "app_1",
        instance_id: "inst_1",
        app_name: "enclout",
        tcb_info: "{}",
      };
    },
  };

  const out = await buildConnectorOutputFromTEE({
    client: fakeClient,
    connectorId: "conn_1",
    measurements: {
      mrtd: "mrtd",
      rtmr0: "rtmr0",
      rtmr1: "rtmr1",
      rtmr2: "rtmr2",
      rtmr3: "rtmr3",
      policyVersion: "v1",
    },
  });

  assert.equal(calls.keyPath, "ssh/connector/v1");
  assert.equal(calls.keySubject, "ed25519");
  assert.equal(calls.infoCalled, true);
  assert.equal(calls.quoteInput, out.attestation.ssh_public_key);

  assert.equal(out.connector_id, "conn_1");
  assert.equal(out.attestation.quote_hex, "aabbccdd");
  assert.equal(out.attestation.report_data_expected_sha256.length, 64);
  assert.equal(out.dstack_info.app_id, "app_1");
});

test("throws when dstack key material is not 32 bytes", async () => {
  const fakeClient = {
    async getKey() {
      return { key: Buffer.alloc(16, 1) };
    },
    async getQuote() {
      return { quote: "aa", event_log: "[]" };
    },
    async info() {
      return { app_id: "a", instance_id: "i", app_name: "n", tcb_info: "{}" };
    },
  };

  await assert.rejects(
    () =>
      buildConnectorOutputFromTEE({
        client: fakeClient,
        connectorId: "conn_1",
        measurements: {
          mrtd: "mrtd",
          rtmr0: "rtmr0",
          rtmr1: "rtmr1",
          rtmr2: "rtmr2",
          rtmr3: "rtmr3",
        },
      }),
    /32 bytes/,
  );
});
