// Security contract: released UR/BBQr text accepts only complete bounded PSBTs;
// incomplete, conflicting and wrong-type data must never reach the PSBT parser.
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { psbtBytesFromText } from "../src/js/psbt-editor.js";
import { loadAppFunctions } from "./app-slice-harness.mjs";
import { hodlUrEncodePsbt } from "../src/js/psbt-ur.js";

const base64 = readFileSync(new URL("./fixtures/psbt/p2wpkh-1in-2out.b64", import.meta.url), "utf8").trim();
const expected = new Uint8Array(Buffer.from(base64, "base64"));

const qrFixture = (name) => readFileSync(new URL(`./fixtures/psbt-qr/${name}.txt`, import.meta.url), "utf8").trim().split(/\s+/);
const referenceUr = qrFixture("p2wpkh-1in-2out-systematic-high");
const referenceSingleUr = qrFixture("p2wpkh-1in-2out-single-ur");
const referenceBbqr = qrFixture("bbqr/p2wpkh-1in-2out-h-single");
const differentUr = qrFixture("p2tr-taproot-single-ur");
const differentBbqr = qrFixture("bbqr/bip370-minimal-h-single");

for (const [name, parts] of [
  ["UR single", referenceSingleUr],
  ["UR multipart", referenceUr],
  ...["h", "2", "z"].flatMap((encoding) => ["single", "multipart"].map((mode) => [
    `BBQr ${encoding} ${mode}`, qrFixture(`bbqr/p2wpkh-1in-2out-${encoding}-${mode}`),
  ])),
]) {
  test(`text ${name} accepts whitespace and duplicates only before completion`, () => {
    const frames = parts.length > 1 ? [parts[0], parts[0], ...parts.slice(1)] : parts;
    assert.deepEqual(psbtBytesFromText(` \t${frames.join(" \r\n\t")}\n `), expected);
  });
}

for (const [name, parts] of [
  ["UR single", referenceSingleUr],
  ["UR multipart", referenceUr],
  ["BBQr h multipart", qrFixture("bbqr/p2wpkh-1in-2out-h-multipart")],
]) {

  for (const [tailName, tail] of [
    ["an identical completed frame", parts.at(-1)],
    ["a different complete PSBT", name.startsWith("UR") ? differentUr[0] : differentBbqr[0]],
    ["malformed text", "not-a-frame"],
    ["another transport", name.startsWith("UR") ? referenceBbqr[0] : referenceSingleUr[0]],
    ["static base64", base64],
    ["static hex", Buffer.from(expected).toString("hex")],
  ]) {
    test(`text ${name} rejects ${tailName} after completion`, () => {
      assert.throws(() => psbtBytesFromText([...parts, tail].join("\n")), /\(done\)/);
    });
  }
}

test("text rejection wipes the already completed PSBT bytes", () => {
  const fill = Uint8Array.prototype.fill;
  const retained = [];
  Uint8Array.prototype.fill = function (...args) {
    if (args[0] === 0 && this.length === expected.length && this.every((byte, index) => byte === expected[index])) retained.push(this);
    return Reflect.apply(fill, this, args);
  };
  try {
    assert.throws(() => psbtBytesFromText([...referenceSingleUr, "not-a-frame"].join("\n")), /\(done\)/);
  } finally {
    Uint8Array.prototype.fill = fill;
  }
  assert.ok(retained.length > 0, "the completed PSBT buffer must be wiped on rejection");
  for (const bytes of retained) assert.ok(bytes.every((byte) => byte === 0));
});

test("released text transports complete UR without changing PSBT bytes", () => {
  const parts = hodlUrEncodePsbt(expected, { maxBytes: 80 });
  assert.deepEqual(psbtBytesFromText([...parts].reverse().join("\n")), expected);
  assert.deepEqual(psbtBytesFromText(hodlUrEncodePsbt(expected, { maxBytes: 10000 })[0]), expected);
  assert.throws(() => psbtBytesFromText(parts[0]), /partial/);
  assert.throws(() => psbtBytesFromText(parts[0].replace("crypto-psbt", "bytes")), /wrong-type/);
});

test("shared text decoding preserves released base64, hex and raw transaction decoding", () => {
  assert.deepEqual(psbtBytesFromText(base64), expected);
  assert.deepEqual(psbtBytesFromText(Buffer.from(expected).toString("hex")), expected);
  const transaction = Uint8Array.from([2, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
  assert.deepEqual(psbtBytesFromText("02000000000000000000"), transaction);
  assert.deepEqual(psbtBytesFromText(Buffer.from(transaction).toString("base64")), transaction);
});

for (const encoding of ["h", "2", "z"]) {
  test(`released text accepts independent BBQr ${encoding} in Editor and Inspector`, async () => {
    const app = await loadAppFunctions(["hodlPsbtBytes"], { stubs: {
      hodlPsbtBytesFromText: psbtBytesFromText,
    } });
    for (const mode of ["single", "multipart"]) {
      const parts = readFileSync(new URL(`./fixtures/psbt-qr/bbqr/p2wpkh-1in-2out-${encoding}-${mode}.txt`, import.meta.url), "utf8").trim().split("\n");
      const text = [...parts].reverse().join("\n");
      assert.deepEqual(psbtBytesFromText(text), expected);
      assert.deepEqual(app.hodlPsbtBytes(text), expected);
      if (parts.length > 1) assert.throws(() => psbtBytesFromText(parts[0]), /partial/);
      assert.throws(() => psbtBytesFromText(parts[0].slice(0, 3) + "T" + parts[0].slice(4)), /wrong-type/);
    }
  });
}

test("text QR reassembly keeps its 1 MiB budget even though ordinary paste permits larger PSBTs", () => {
  const oversized = `B$HP0100${"00".repeat(2145)}`;
  assert.throws(() => psbtBytesFromText(oversized), /too-large/);
});

test("Inspector readiness does not replay untrusted QR fragments on each input", async () => {
  const fields = { "psbt-text": { value: "ur:crypto-psbt/1-1000/invalid" } };
  let assemblies = 0;
  const enabled = {};
  const app = await loadAppFunctions(["hodlSyncPsbtControls"], { stubs: {
    document: { getElementById: (id) => fields[id] ?? { value: "", hidden: false, classList: { toggle() {} } } },
    hodlSetButtonEnabled: (id, value) => { enabled[id] = value; },
    hodlPsbtBytes: () => { assemblies++; throw new Error("refused"); },
    hodlStationPassphraseStamp: () => "",
    hodlPsbtPriv: null,
    hodlPsbtHd: null,
    hodlPsbtSessionSpec: { key: "No session key. Inspect-only mode." },
    hodlPsbtNonceHistory: [],
  } });
  for (const value of ["ur:crypto-psbt/1-1000/invalid", "B$ZP0200INVALID"]) {
    fields["psbt-text"].value = value;
    for (let i = 0; i < 10; i++) app.hodlSyncPsbtControls();
    assert.equal(assemblies, 0);
    assert.equal(enabled["psbt-go"], true);
  }
});
