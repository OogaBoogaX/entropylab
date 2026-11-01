// Security contract: preview UR text accepts only complete bounded PSBT payloads;
// incomplete, conflicting and wrong-type data must never reach the PSBT parser.
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { psbtBytesFromText } from "../src/js/psbt-editor.js";
import { loadAppFunctions } from "./app-slice-harness.mjs";
import { hodlUrEncodePsbt } from "../src/js/psbt-ur.js";

const base64 = readFileSync(new URL("./fixtures/psbt/p2wpkh-1in-2out.b64", import.meta.url), "utf8").trim();
const expected = new Uint8Array(Buffer.from(base64, "base64"));

test("preview text transports a complete UR without changing the PSBT bytes", () => {
  globalThis.__ENTROPYLAB_PREVIEW__ = true;
  try {
    const parts = hodlUrEncodePsbt(expected, { maxBytes: 80 });
    assert.deepEqual(psbtBytesFromText(parts.toReversed().join("\n")), expected);
    assert.deepEqual(psbtBytesFromText(hodlUrEncodePsbt(expected, { maxBytes: 10000 })[0]), expected);
    assert.throws(() => psbtBytesFromText(parts[0]), /partial/);
    assert.throws(() => psbtBytesFromText(parts[0].replace("crypto-psbt", "bytes")), /wrong-type/);
    assert.deepEqual(psbtBytesFromText(base64), expected);
    // The shared text decoder also serves Inspector raw transactions.
    assert.deepEqual(psbtBytesFromText("02000000000000000000"), Uint8Array.from([2,0,0,0,0,0,0,0,0,0]));
  } finally {
    delete globalThis.__ENTROPYLAB_PREVIEW__;
  }
});

test("release text handling does not enable preview UR transport", () => {
  assert.throws(() => psbtBytesFromText(hodlUrEncodePsbt(expected)[0]));
});

test("Inspector readiness does not replay untrusted UR fragments on each input", async () => {
  const fields = { "psbt-text": { value: "ur:crypto-psbt/1-1000/invalid" } };
  let assemblies = 0;
  const enabled = {};
  const app = await loadAppFunctions(["hodlSyncPsbtControls"], { stubs: {
    __ENTROPYLAB_PREVIEW__: true,
    document: { getElementById: (id) => fields[id] ?? { value: "", hidden: false, classList: { toggle() {} } } },
    hodlSetButtonEnabled: (id, value) => { enabled[id] = value; },
    hodlPsbtBytes: () => { assemblies++; throw new Error("refused"); },
    hodlStationPassphraseStamp: () => "",
    hodlPsbtPriv: null,
    hodlPsbtHd: null,
    hodlPsbtSessionSpec: { key: "No session key. Inspect-only mode." },
    hodlPsbtNonceHistory: [],
  } });
  for (let i = 0; i < 10; i++) app.hodlSyncPsbtControls();
  assert.equal(assemblies, 0);
  assert.equal(enabled["psbt-go"], true);
});
