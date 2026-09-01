// PSBT script metadata must be committed by the advertised previous output.
import { createHash } from "node:crypto";
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const app = readFileSync(join(root, "src/js/app.js"), "utf8");

function loadSlice(name) {
  const start = app.indexOf(`function ${name}(`);
  assert.ok(start >= 0, name);
  let depth = 0;
  for (let index = app.indexOf("{", start); index < app.length; index++) {
    if (app[index] === "{") depth++;
    else if (app[index] === "}" && --depth === 0) return app.slice(start, index + 1);
  }
  throw new Error(`Could not extract ${name}`);
}

const concat = (...parts) => {
  const output = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let offset = 0;
  for (const part of parts) { output.set(part, offset); offset += part.length; }
  return output;
};
const sha256 = (bytes) => new Uint8Array(createHash("sha256").update(bytes).digest());
const hash160 = (bytes) => new Uint8Array(createHash("ripemd160").update(sha256(bytes)).digest());
const p2wpkh = (hash = new Uint8Array(20).fill(3)) => concat(Uint8Array.of(0, 20), hash);
const p2wsh = (script) => concat(Uint8Array.of(0, 32), sha256(script));
const p2sh = (script) => concat(Uint8Array.of(0xa9, 0x14), hash160(script), Uint8Array.of(0x87));

const hodlInputScriptCode = new Function(
  "hodlFind", "hodlEq", "p2shScript", "hodlConcatBytes", "p2wshScript",
  `${loadSlice("hodlInputScriptCode")}; return hodlInputScriptCode;`,
)(
  (entries, type) => entries.filter((entry) => entry.type === type),
  (left, right) => Boolean(left && right && left.length === right.length && left.every((byte, index) => byte === right[index])),
  (script) => p2sh(script),
  concat,
  (script) => p2wsh(script),
);

const entry = (type, val) => ({ type, keydata: new Uint8Array(0), val });

test("direct and correctly nested P2WPKH metadata produces its BIP143 scriptCode", () => {
  const witnessProgram = p2wpkh();
  const expected = concat(Uint8Array.of(0x76, 0xa9, 0x14), witnessProgram.slice(2), Uint8Array.of(0x88, 0xac));
  assert.deepEqual(hodlInputScriptCode([], { script: witnessProgram }), expected);
  assert.deepEqual(hodlInputScriptCode([entry(4, witnessProgram)], { script: p2sh(witnessProgram) }), expected);
});

test("a nested redeem script that does not hash to the P2SH output is rejected", () => {
  const advertised = p2wpkh(new Uint8Array(20).fill(4));
  const supplied = p2wpkh(new Uint8Array(20).fill(5));
  assert.equal(hodlInputScriptCode([entry(4, supplied)], { script: p2sh(advertised) }), null);
});

test("P2WSH metadata is accepted only when SHA256(witnessScript) matches the witness program", () => {
  const witnessScript = Uint8Array.of(0x51, 0x21, 0x02, 0xac);
  assert.deepEqual(hodlInputScriptCode([entry(5, witnessScript)], { script: p2wsh(witnessScript) }), witnessScript);
  const wrongProgram = p2wsh(Uint8Array.of(0x51));
  assert.equal(hodlInputScriptCode([entry(5, witnessScript)], { script: wrongProgram }), null);
});

test("nested P2WSH requires both the P2SH and P2WSH commitments to match", () => {
  const witnessScript = Uint8Array.of(0x52, 0x21, 0x03, 0xae);
  const redeem = p2wsh(witnessScript);
  assert.deepEqual(hodlInputScriptCode([entry(4, redeem), entry(5, witnessScript)], { script: p2sh(redeem) }), witnessScript);
  assert.equal(hodlInputScriptCode([entry(4, redeem), entry(5, witnessScript)], { script: p2sh(p2wpkh()) }), null);
});
