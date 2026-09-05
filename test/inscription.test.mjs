import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  parseEnvelopes,
  parseWitness,
  scriptsFromPsbtInput,
  inspectPsbtInscriptions,
  describeEnvelope,
  inscriptionIdFromBytes,
  concatBytes,
  bytesToHex,
} from "../src/js/inscription.js";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const app = readFileSync(join(root, "src/js/app.js"), "utf8");
const template = readFileSync(join(root, "src/index.html"), "utf8");
const shell = readFileSync(join(root, "src/shell.html"), "utf8");
const utf8 = (text) => new TextEncoder().encode(text);
const push = (data) => {
  const bytes = typeof data === "string" ? utf8(data) : data;
  if (bytes.length === 0) return Uint8Array.of(0x00);
  if (bytes.length <= 0x4b) return concatBytes(Uint8Array.of(bytes.length), bytes);
  if (bytes.length <= 0xff) return concatBytes(Uint8Array.of(0x4c, bytes.length), bytes);
  const lo = bytes.length & 0xff, hi = bytes.length >> 8;
  return concatBytes(Uint8Array.of(0x4d, lo, hi), bytes);
};
const envelope = ({ contentType = "text/plain;charset=utf-8", body = "Hello, world!", fields = [], usePushnum = false, close = true } = {}) => {
  const parts = [Uint8Array.of(0x00, 0x63), push("ord")];
  if (usePushnum) parts.push(Uint8Array.of(0x51));
  else parts.push(push(Uint8Array.of(1)));
  parts.push(push(contentType));
  for (const [tag, value] of fields) {
    parts.push(push(typeof tag === "number" ? Uint8Array.of(tag) : tag));
    parts.push(push(value));
  }
  parts.push(Uint8Array.of(0x00));
  const bodyBytes = typeof body === "string" ? utf8(body) : body;
  for (let offset = 0; offset < bodyBytes.length; offset += 520) parts.push(push(bodyBytes.slice(offset, offset + 520)));
  if (close) parts.push(Uint8Array.of(0x68));
  return concatBytes(...parts);
};

test("docs hello-world envelope parses content-type and body", () => {
  const script = envelope();
  const { envelopes } = parseEnvelopes(script);
  assert.equal(envelopes.length, 1);
  assert.equal(envelopes[0].contentType, "text/plain;charset=utf-8");
  assert.equal(envelopes[0].bodyBytes, 13);
  assert.equal(new TextDecoder().decode(envelopes[0].body), "Hello, world!");
  assert.equal(envelopes[0].unrecognizedEven, false);
});

test("OP_1 pushnum tags are accepted and flagged", () => {
  const { envelopes } = parseEnvelopes(envelope({ usePushnum: true }));
  assert.equal(envelopes.length, 1);
  assert.equal(envelopes[0].contentType, "text/plain;charset=utf-8");
  assert.equal(envelopes[0].pushnum, true);
});

test("body chunks larger than 520 bytes are concatenated", () => {
  const body = utf8("x".repeat(600));
  const { envelopes } = parseEnvelopes(envelope({ body }));
  assert.equal(envelopes[0].bodyBytes, 600);
  assert.equal(envelopes[0].body[0], 0x78);
  assert.equal(envelopes[0].body[599], 0x78);
});

test("scripts without an ord protocol id are not inscriptions", () => {
  const script = concatBytes(Uint8Array.of(0x00, 0x63), push("nope"), Uint8Array.of(0x68));
  assert.equal(parseEnvelopes(script).envelopes.length, 0);
  assert.equal(parseEnvelopes(Uint8Array.of(0x51, 0xac)).envelopes.length, 0);
});

test("unclosed envelopes are ignored", () => {
  assert.equal(parseEnvelopes(envelope({ close: false })).envelopes.length, 0);
});

test("parent and pointer fields decode", () => {
  const parentTxid = new Uint8Array(32).fill(0xab);
  const parent = concatBytes(parentTxid, Uint8Array.of(2));
  const { envelopes } = parseEnvelopes(envelope({
    fields: [
      [3, parent],
      [2, Uint8Array.of(7)],
    ],
  }));
  assert.equal(envelopes[0].pointer, 7n);
  assert.equal(envelopes[0].parent, `${"ab".repeat(32)}i2`);
});

test("inscription id omits a trailing zero index", () => {
  const txid = new Uint8Array(32).fill(1);
  assert.equal(inscriptionIdFromBytes(txid), `${"01".repeat(32)}i0`);
});

test("unrecognized even tags are unbound", () => {
  const { envelopes } = parseEnvelopes(envelope({ fields: [[4, Uint8Array.of(1)]] }));
  assert.equal(envelopes[0].unrecognizedEven, true);
});

test("known even pointer tag is not unbound", () => {
  const { envelopes } = parseEnvelopes(envelope({ fields: [[2, Uint8Array.of(1)]] }));
  assert.equal(envelopes[0].unrecognizedEven, false);
  assert.equal(envelopes[0].pointer, 1n);
});

test("duplicate content-type is flagged", () => {
  const { envelopes } = parseEnvelopes(envelope({
    fields: [
      [1, utf8("image/png")],
    ],
  }));
  assert.equal(envelopes[0].duplicate, true);
});

test("image bodies are described without being rendered", () => {
  const { envelopes } = parseEnvelopes(envelope({ contentType: "image/png", body: Uint8Array.of(0x89, 0x50, 0x4e, 0x47) }));
  const text = describeEnvelope(envelopes[0]).join("\n");
  assert.match(text, /image\/png/);
  assert.match(text, /not rendered/);
  assert.doesNotMatch(text, /text:/);
});

test("two envelopes in one script are both found", () => {
  const script = concatBytes(envelope({ body: "one" }), envelope({ body: "two" }));
  const { envelopes } = parseEnvelopes(script);
  assert.equal(envelopes.length, 2);
  assert.equal(new TextDecoder().decode(envelopes[0].body), "one");
  assert.equal(new TextDecoder().decode(envelopes[1].body), "two");
});

test("tap-leaf scripts are read from PSBT type 0x15", () => {
  const script = envelope();
  const leaf = concatBytes(script, Uint8Array.of(0xc0));
  const found = scriptsFromPsbtInput([{ type: 21, val: leaf, keydata: new Uint8Array(33) }]);
  assert.equal(found.length, 1);
  assert.equal(found[0].source, "tap-leaf");
  assert.equal(parseEnvelopes(found[0].script).envelopes.length, 1);
});

test("final scriptwitness yields the tapscript", () => {
  const script = envelope();
  const control = new Uint8Array(33).fill(0xc0);
  const encodeVarInt = (n) => Uint8Array.of(n);
  const item = (bytes) => concatBytes(encodeVarInt(bytes.length), bytes);
  const witness = concatBytes(encodeVarInt(3), item(new Uint8Array(64)), item(script), item(control));
  const stack = parseWitness(witness);
  assert.equal(stack.length, 3);
  const found = scriptsFromPsbtInput([{ type: 8, val: witness, keydata: new Uint8Array() }]);
  assert.ok(found.some((row) => parseEnvelopes(row.script).envelopes.length === 1));
});

test("inspectPsbtInscriptions numbers envelopes across inputs and survives junk", () => {
  const script = envelope({ body: "a" });
  const leaf = concatBytes(script, Uint8Array.of(0xc0));
  const psbt = {
    inputs: [
      [{ type: 21, val: leaf, keydata: new Uint8Array(33) }],
      [{ type: 8, val: Uint8Array.of(0xff), keydata: new Uint8Array() }],
      [{ type: 21, val: concatBytes(envelope({ body: "b" }), Uint8Array.of(0xc0)), keydata: new Uint8Array(33) }],
    ],
  };
  const report = inspectPsbtInscriptions(psbt);
  assert.equal(report.envelopes.length, 2);
  assert.equal(report.envelopes[0].envelopeIndex, 0);
  assert.equal(report.envelopes[1].envelopeIndex, 1);
  assert.equal(report.envelopes[1].input, 2);
});

test("PSBT inspector wires envelope detection into the report", () => {
  assert.match(app, /inspectPsbtInscriptions/);
  assert.match(app, /Inscription envelope/);
  assert.match(app, /does not number sats/);
  for (const markup of [shell]) {
    assert.match(markup, /inscription envelope/);
  }
});
