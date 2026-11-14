// Unified anti-exfil transcript reader: adapters and orchestrator.
// Run with: npm test
import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { secp256k1 as noble } from "@noble/curves/secp256k1.js";

import { readAntiExfil, checkAntiExfilSignature } from "../src/js/anti-exfil.js";
import * as jade from "../src/js/anti-exfil-adapters/jade.js";
import * as bitbox02 from "../src/js/anti-exfil-adapters/bitbox02.js";
import * as aexb from "../src/js/anti-exfil-adapters/aexb.js";
import { hodlParseBitboxTranscript } from "../src/js/psbt-bitbox.js";
import { aexbVerify } from "../src/js/aexb.js";
import { secp256k1Ready } from "../src/js/secp256k1.js";
import { hashesReady } from "../src/js/hashes.js";

await secp256k1Ready;
await hashesReady;

const root = dirname(fileURLToPath(import.meta.url));
const read = (path) => readFileSync(join(root, path), "utf8");

const app = read("../src/js/app.js");
function loadSlice(name) {
  const start = app.indexOf(`function ${name}(`);
  assert.ok(start >= 0, name);
  let depth = 0;
  let end = -1;
  for (let i = app.indexOf("{", start); i < app.length; i++) {
    if (app[i] === "{") depth++;
    else if (app[i] === "}") {
      depth--;
      if (depth === 0) {
        end = i + 1;
        break;
      }
    }
  }
  assert.ok(end > start, name);
  return app.slice(start, end);
}
const hodlHex = {
  encode: (bytes) => Buffer.from(bytes).toString("hex"),
  decode: (hex) => Uint8Array.from(Buffer.from(hex, "hex")),
};
const hodlParseAntiExfil = new Function(
  "hodlHex",
  `${loadSlice("hodlParseAntiExfil")}; return hodlParseAntiExfil;`,
)(hodlHex);

const hexDecode = (text) => Uint8Array.from(Buffer.from(text, "hex"));
const toHex = (bytes) => Buffer.from(bytes).toString("hex");
const sha256 = (bytes) => new Uint8Array(createHash("sha256").update(Buffer.from(bytes)).digest());
const concat = (...arrays) => {
  const out = new Uint8Array(arrays.reduce((sum, arr) => sum + arr.length, 0));
  let offset = 0;
  for (const arr of arrays) {
    out.set(arr, offset);
    offset += arr.length;
  }
  return out;
};
const taggedHash = (tag, ...chunks) => {
  const tagHash = sha256(new TextEncoder().encode(tag));
  return sha256(concat(tagHash, tagHash, ...chunks));
};
const bigOf = (bytes) => BigInt(`0x${toHex(bytes)}`);

// From test/psbt-anti-exfil.test.mjs, "parses host nonce and compressed opening as separate hex".
const jadeHost = "11".repeat(32);
const jadeOpening = "02466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f27";

// From test/psbt-bitbox-s2c.test.mjs, "one 32-byte field is the revealed host nonce, not the SHA256 commitment".
const bitboxHost = "11".repeat(32);
const bitboxOpening = "02466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f27";
const bitboxCommitment = toHex(sha256(hexDecode(bitboxHost)));

const aexbFixtures = join(root, "fixtures", "aexb");
const positive = JSON.parse(readFileSync(join(aexbFixtures, "protocol-v1-multislot-vectors.json"), "utf8"));

const JADE_BITBOX_WARNING =
  "This reads as a Jade host nonce \u03C1 or a BitBox02 host nonce. Both are checked the same way. From a BitBox02, paste the host nonce, not its SHA-256 commitment.";

test("Jade vectors agree with hodlParseAntiExfil", () => {
  const inputs = [
    `${jadeHost}\n${jadeOpening}`,
    `${jadeHost}${jadeOpening}`,
    `host ${jadeHost}\nopening ${jadeOpening}`,
  ];
  for (const input of inputs) {
    const expected = hodlParseAntiExfil(input);
    const result = readAntiExfil(input);
    assert.equal(result.kind, "jade");
    assert.deepEqual(result.transcript, expected);
    assert.deepEqual(result.candidates, ["jade", "bitbox02"]);
    assert.equal(result.warning, JADE_BITBOX_WARNING);
    assert.equal(result.warningCode, "jade-or-bitbox02");
  }
});

test("BitBox vectors agree with hodlParseBitboxTranscript", () => {
  const inputs = [
    `${bitboxHost} ${bitboxCommitment} ${bitboxOpening}`,
    `${bitboxCommitment} ${bitboxOpening} ${bitboxHost}`,
  ];
  for (const input of inputs) {
    const expected = hodlParseBitboxTranscript(input, hexDecode, sha256);
    const result = readAntiExfil(input);
    assert.equal(result.kind, "bitbox02");
    assert.equal(toHex(result.transcript.host), toHex(expected.hostNonce));
    assert.equal(result.transcript.openings.length, 1);
    assert.equal(toHex(result.transcript.openings[0]), toHex(expected.opening));
    assert.equal(toHex(result.transcript.commitment), toHex(expected.commitment));
    assert.equal(result.transcript.commitmentMatches, expected.commitmentMatches);
    assert.equal(result.warningCode, null);
  }
});

test("AEXB vectors decode and verify", () => {
  const byStage = new Map();
  for (const vector of positive.messages) {
    const result = readAntiExfil(vector.message_hex);
    assert.equal(result.kind, "aexb");
    assert.equal(result.warningCode, null);
    assert.equal(result.transcript.decoded.stage, vector.stage);
    byStage.set(vector.stage, result.transcript.decoded);

    const packageResult = readAntiExfil(vector.package_hex);
    assert.equal(packageResult.kind, "aexb");
    assert.equal(packageResult.transcript.decoded.stage, vector.stage);
  }

  const stage2 = byStage.get(2);
  const reveal = byStage.get(3);
  const signatures = byStage.get(4);
  const revealResult = aexbVerify(reveal, null, stage2);
  assert.equal(revealResult.ok, true);
  assert.equal(revealResult.verdict, "ok");
  const signatureResult = aexbVerify(signatures, reveal, stage2);
  assert.equal(signatureResult.ok, true);
  assert.equal(signatureResult.verdict, "ok");
});

test("AEXB messages split on whitespace and keep paste order", () => {
  const stage2 = positive.messages.find((vector) => vector.stage === 2);
  const stage3 = positive.messages.find((vector) => vector.stage === 3);
  const result = readAntiExfil(`${stage2.message_hex}\n${stage3.message_hex}`);
  assert.equal(result.kind, "aexb");
  assert.equal(result.transcript.messages.length, 2);
  assert.equal(result.transcript.messages[0].stage, 2);
  assert.equal(result.transcript.messages[1].stage, 3);
  assert.equal(result.transcript.decoded.stage, 2);
});

test("a line-wrapped AEXB message decodes as one message", () => {
  const stage4 = positive.messages.find((vector) => vector.stage === 4);
  const wrapped = stage4.message_hex.match(/.{1,64}/g).join("\n");
  const result = readAntiExfil(wrapped);
  assert.equal(result.kind, "aexb");
  assert.equal(result.transcript.messages.length, 1);
  assert.equal(result.transcript.decoded.stage, 4);
});

test("a bad second AEXB message reports its position", () => {
  const stage2 = positive.messages.find((vector) => vector.stage === 2);
  const result = readAntiExfil(`${stage2.message_hex}\n41455842`);
  assert.equal(result.kind, null);
  assert.match(result.error, /^Message 2: /);
});

test("a single truncated AEXB message keeps today's error text", () => {
  const result = readAntiExfil("41455842" + "00".repeat(10));
  assert.equal(result.kind, null);
  assert.equal(result.error, "message is shorter than the AEXB header");
});

test("a line-wrapped truncated AEXB message reports the AEXB error", () => {
  const result = readAntiExfil("41455842\n" + "00".repeat(10));
  assert.equal(result.kind, null);
  assert.match(result.error, /AEXB/);
  assert.doesNotMatch(result.error, /Jade/);
});

test("a Jade host nonce that starts with the AEXB magic still reads as Jade", () => {
  for (const magic of ["41455842", "41455854"]) {
    const host = magic + "11".repeat(28);
    const result = readAntiExfil(`${host}\n${jadeOpening}`);
    assert.equal(result.kind, "jade");
    assert.equal(Buffer.from(result.transcript.host).toString("hex"), host);
    assert.equal(Buffer.from(result.transcript.openings[0]).toString("hex"), jadeOpening);
  }
});

test("a BitBox commitment pasted as rho reads as Jade with the warning and fails the check", () => {
  const host = hexDecode(jadeHost);
  const opening = hexDecode(jadeOpening);
  const tweak = bigOf(taggedHash("s2c/ecdsa/point", opening, host));
  const committed = noble.Point.fromBytes(opening).add(noble.Point.BASE.multiply(tweak)).toBytes(true);
  const r = committed.slice(1);

  const real = readAntiExfil(`${jadeHost} ${jadeOpening}`);
  assert.equal(real.kind, "jade");
  assert.equal(checkAntiExfilSignature(r, real.transcript), true);

  const commitment = toHex(sha256(host));
  const trap = readAntiExfil(`${commitment} ${jadeOpening}`);
  assert.equal(trap.kind, "jade");
  assert.equal(trap.warning, JADE_BITBOX_WARNING);
  assert.equal(checkAntiExfilSignature(r, trap.transcript), false);

  const bitbox = readAntiExfil(`${jadeHost} ${commitment} ${jadeOpening}`);
  assert.equal(bitbox.kind, "bitbox02");
  assert.equal(checkAntiExfilSignature(r, bitbox.transcript), true);
});

test("a signature whose r does not commit to the opening gives false", () => {
  const host = hexDecode(jadeHost);
  const opening = hexDecode(jadeOpening);
  const tweak = bigOf(taggedHash("s2c/ecdsa/point", opening, host));
  const committed = noble.Point.fromBytes(opening).add(noble.Point.BASE.multiply(tweak)).toBytes(true);
  const r = committed.slice(1);
  const tampered = Uint8Array.from(r);
  tampered[31] ^= 1;
  const transcript = readAntiExfil(`${jadeHost} ${jadeOpening}`).transcript;
  assert.equal(checkAntiExfilSignature(tampered, transcript), false);
});

test("checkAntiExfilSignature refuses AEXB transcripts", () => {
  const result = readAntiExfil(positive.messages[0].message_hex);
  assert.equal(result.kind, "aexb");
  assert.throws(
    () => checkAntiExfilSignature(new Uint8Array(32), result.transcript),
    /AEXB transcripts are verified with aexbVerify/,
  );
});

test("bad input returns kind null with an error and never throws", () => {
  const inputs = [
    "not hex at all",
    jadeHost,
    "aa".repeat(40),
    `${jadeHost} ${"04" + "aa".repeat(32)}`,
    `${jadeHost} ${"22".repeat(32)} ${"33".repeat(32)} ${jadeOpening}`,
    "zz".repeat(32),
  ];
  for (const input of inputs) {
    const result = readAntiExfil(input);
    assert.equal(result.kind, null, input);
    assert.ok(result.error, input);
    assert.equal(result.transcript, null);
    assert.deepEqual(result.candidates, []);
    assert.equal(result.warning, null);
    assert.equal(result.warningCode, null);
  }
});

test("a truncated AEXB or AEXT message reports its own decode error first", () => {
  const cases = [
    ["41455842" + "00".repeat(10), /AEXB/],
    ["AEXB" + "00".repeat(10), /AEXB/],
    ["41455854" + "00".repeat(10), /AEXT/],
  ];
  for (const [input, pattern] of cases) {
    const result = readAntiExfil(input);
    assert.equal(result.kind, null, input);
    assert.match(result.error, pattern, input);
    assert.doesNotMatch(result.error, /Jade/, input);
  }
});

test("detect never throws", () => {
  const inputs = [
    "",
    "   ",
    "not hex at all",
    jadeHost,
    "aa".repeat(40),
    `${jadeHost} ${"04" + "aa".repeat(32)}`,
    `${jadeHost} ${"22".repeat(32)} ${"33".repeat(32)} ${jadeOpening}`,
    "zz".repeat(32),
    `${jadeHost} ${jadeOpening}`,
    `${jadeHost}${jadeOpening}`,
    `${bitboxHost} ${bitboxCommitment} ${bitboxOpening}`,
    positive.messages[0].message_hex,
    positive.messages[0].package_hex,
  ];
  const adapters = [["jade", jade], ["bitbox02", bitbox02], ["aexb", aexb]];
  for (const input of inputs) {
    for (const [name, adapter] of adapters) {
      assert.doesNotThrow(() => adapter.detect(input), `${name} on ${input}`);
    }
  }
});
