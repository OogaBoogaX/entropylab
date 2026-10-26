// Tests for the RBF fee-bump check in the PSBT Inspector: the
// hodlPsbtPrependRbfCheck wiring in src/js/app.js over the real
// checkRbfReplacement from src/js/psbt-rbf-check.js. The screen defends
// against Electrum GHSA-6jp4-8v48-cc5v — a malicious server handing the
// wallet a modified "unconfirmed" transaction so the fee bump signs the
// attacker's version — so it must fail closed, never green, on anything it
// cannot prove.
// Run with: node --test test/psbt-rbf-ui.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import vm from "node:vm";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { checkRbfReplacement } from "../src/js/psbt-rbf-check.js";
import { hex as hodlHex } from "../src/js/coders.js";
import { serializeTx as realSerializeTx, parseRawTx as realParseRawTx } from "../src/js/tx.js";
import { psbtBytesFromUpload as realPsbtBytesFromUpload } from "../src/js/psbt-editor.js";
import { applyPreviewBlocks } from "../scripts/preview-blocks.mjs";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const read = (path) => readFileSync(join(root, path), "utf8");
const app = read("src/js/app.js");
const shell = read("src/shell.html");

// --- Independent boundary doubles ---------------------------------------
// The extracted app functions reach the inspector's parsers and hashers as
// free variables. These doubles are written straight from BIP-174 and the
// Bitcoin transaction serialization rules, so the app's normalization is
// graded against the specifications, not against the app's own parsing.
const sha256 = (bytes) => new Uint8Array(createHash("sha256").update(bytes).digest());
const bytesToHex = (bytes) => [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
const bytesFromHex = (hex) => new Uint8Array(hex.match(/../g).map((pair) => parseInt(pair, 16)));
const read32 = (bytes, at) => (bytes[at] | bytes[at + 1] << 8 | bytes[at + 2] << 16 | bytes[at + 3] << 24) >>> 0;
const concat = (...parts) => {
  const out = new Uint8Array(parts.reduce((total, part) => total + part.length, 0));
  let at = 0;
  for (const part of parts) {
    out.set(part, at);
    at += part.length;
  }
  return out;
};
const le32 = (value) => Uint8Array.of(value & 255, value >> 8 & 255, value >> 16 & 255, value >>> 24);
const le64 = (value) => {
  const bytes = new Uint8Array(8);
  new DataView(bytes.buffer).setBigUint64(0, BigInt(value), true);
  return bytes;
};
const writeVarint = (value) => {
  if (value < 0xfd) return Uint8Array.of(value);
  if (value <= 0xffff) return Uint8Array.of(0xfd, value & 255, value >> 8);
  throw new Error("test builder: varint too large");
};
const readVarint = (bytes, at) => {
  const first = bytes[at];
  if (first < 0xfd) return [first, at + 1];
  if (first === 0xfd) return [bytes[at + 1] | bytes[at + 2] << 8, at + 3];
  throw new Error("test double: varint too large");
};

// Canonical non-witness transaction builder (the form BIP-174 requires for
// the unsigned transaction, and the form a txid commits to).
const buildRawTx = ({ version = 2, locktime = 0, inputs, outputs }) => concat(
  le32(version),
  writeVarint(inputs.length),
  ...inputs.map((input) => concat(input.txid, le32(input.vout), writeVarint(0), le32(input.sequence ?? 0xfffffffd))),
  writeVarint(outputs.length),
  ...outputs.map((output) => concat(le64(output.amount), writeVarint(output.script.length), output.script)),
  le32(locktime),
);

// Witness-tolerant parser, in the shape the inspector's parser reports:
// input txids keep wire byte order, output amounts are bigints.
const parseRawTx = (bytes) => {
  let at = 0;
  const version = read32(bytes, at);
  at += 4;
  const segwit = bytes[at] === 0 && bytes[at + 1] !== 0;
  if (segwit) at += 2;
  let inputCount;
  [inputCount, at] = readVarint(bytes, at);
  const inputs = [];
  for (let i = 0; i < inputCount; i++) {
    const txid = bytes.slice(at, at + 32);
    at += 32;
    const vout = read32(bytes, at);
    at += 4;
    let scriptLength;
    [scriptLength, at] = readVarint(bytes, at);
    const script = bytes.slice(at, at + scriptLength);
    at += scriptLength;
    const sequence = read32(bytes, at);
    at += 4;
    inputs.push({ txid, vout, script, sequence, witness: [] });
  }
  let outputCount;
  [outputCount, at] = readVarint(bytes, at);
  const outputs = [];
  for (let i = 0; i < outputCount; i++) {
    const amount = new DataView(bytes.buffer, bytes.byteOffset + at, 8).getBigUint64(0, true);
    at += 8;
    let scriptLength;
    [scriptLength, at] = readVarint(bytes, at);
    const script = bytes.slice(at, at + scriptLength);
    at += scriptLength;
    outputs.push({ amount, script });
  }
  if (segwit) {
    for (let i = 0; i < inputCount; i++) {
      let itemCount;
      [itemCount, at] = readVarint(bytes, at);
      for (let j = 0; j < itemCount; j++) {
        let length;
        [length, at] = readVarint(bytes, at);
        inputs[i].witness.push(bytes.slice(at, at + length));
        at += length;
      }
    }
  }
  const locktime = read32(bytes, at);
  at += 4;
  if (at !== bytes.length) throw new Error("test double: trailing bytes");
  return { version, inputs, outputs, locktime };
};

// Canonical serializer; withWitness=false is the serialization a txid
// commits to (BIP-144: no marker, flag or witness stacks).
const serializeTx = (tx, withWitness) => {
  const segwit = withWitness === true && tx.inputs.some((input) => (input.witness || []).length > 0);
  const parts = [le32(tx.version)];
  if (segwit) parts.push(Uint8Array.of(0, 1));
  parts.push(writeVarint(tx.inputs.length));
  for (const input of tx.inputs) {
    parts.push(concat(input.txid, le32(input.vout), writeVarint(input.script.length), input.script, le32(input.sequence)));
  }
  parts.push(writeVarint(tx.outputs.length));
  for (const output of tx.outputs) {
    parts.push(concat(le64(output.amount), writeVarint(output.script.length), output.script));
  }
  if (segwit) {
    for (const input of tx.inputs) {
      parts.push(writeVarint(input.witness.length));
      for (const item of input.witness) parts.push(writeVarint(item.length), item);
    }
  }
  parts.push(le32(tx.locktime));
  return concat(...parts);
};

// Minimal BIP-174 PSBT builder and parser; entries are {type, keydata, val}
// exactly as the inspector's hodlParsePsbt reports them.
const PSBT_MAGIC = Uint8Array.of(0x70, 0x73, 0x62, 0x74, 0xff);
const isPsbtMagic = (bytes) => bytes.length >= 5 && PSBT_MAGIC.every((byte, index) => bytes[index] === byte);
const psbtEntry = (type, val, keydata = new Uint8Array(0)) => ({ type, keydata, val });
const writeMap = (entries) => concat(
  ...entries.map((entry) => concat(writeVarint(1 + entry.keydata.length), Uint8Array.of(entry.type), entry.keydata, writeVarint(entry.val.length), entry.val)),
  Uint8Array.of(0),
);
const buildPsbt = (unsignedTxBytes, inputMaps, outputMaps) => {
  const tx = parseRawTx(unsignedTxBytes);
  const maps = (given, count) => given ?? Array.from({ length: count }, () => []);
  return concat(
    PSBT_MAGIC,
    writeMap([psbtEntry(0, unsignedTxBytes)]),
    ...maps(inputMaps, tx.inputs.length).map(writeMap),
    ...maps(outputMaps, tx.outputs.length).map(writeMap),
  );
};
const readMap = (bytes, at) => {
  const entries = [];
  for (;;) {
    let keyLength;
    [keyLength, at] = readVarint(bytes, at);
    if (keyLength === 0) return { entries, next: at };
    const type = bytes[at];
    const keydata = bytes.slice(at + 1, at + keyLength);
    at += keyLength;
    let valLength;
    [valLength, at] = readVarint(bytes, at);
    const val = bytes.slice(at, at + valLength);
    at += valLength;
    entries.push({ type, keydata, val });
  }
};
const parsePsbt = (bytes) => {
  if (!isPsbtMagic(bytes)) throw new Error("test double: not a PSBT");
  let at = 5;
  const global = readMap(bytes, at);
  at = global.next;
  const unsigned = global.entries.filter((entry) => entry.type === 0 && entry.keydata.length === 0);
  if (unsigned.length !== 1) throw new Error("test double: exactly one unsigned transaction");
  const tx = parseRawTx(unsigned[0].val);
  const inputs = [];
  const outputs = [];
  for (let i = 0; i < tx.inputs.length; i++) {
    const map = readMap(bytes, at);
    at = map.next;
    inputs.push(map.entries);
  }
  for (let i = 0; i < tx.outputs.length; i++) {
    const map = readMap(bytes, at);
    at = map.next;
    outputs.push(map.entries);
  }
  if (at !== bytes.length) throw new Error("test double: trailing bytes");
  return { tx, global: global.entries, inputs, outputs, raw: bytes };
};

// The inspector's text intake accepts hex or base64; the double keeps that
// contract (hex wins on an even-length hex paste, else base64).
const psbtBytesFromText = (raw) => {
  const compact = String(raw).trim().replace(/\s/g, "");
  if (!compact) throw new Error("test double: empty");
  if (/^[0-9a-fA-F]+$/.test(compact) && compact.length % 2 === 0) return bytesFromHex(compact.toLowerCase());
  const bytes = new Uint8Array(Buffer.from(compact, "base64"));
  if (bytes.length === 0) throw new Error("test double: not base64");
  return bytes;
};
const b64 = (bytes) => Buffer.from(bytes).toString("base64");

const escapeHtml = (text) => String(text).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
const interpolate = (text, params) => text.replace(/\{([a-z]+)\}/g, (whole, name) => {
  if (!params || !(name in params)) throw new Error(`missing interpolation ${name} in "${text}"`);
  return String(params[name]);
});
// hodlT is the HTML-escaping translator, hodlTText the plain-text one: the
// doubles keep that split, so a line routed through the wrong one shows.
const hodlT = (text, params) => escapeHtml(interpolate(text, params));
const hodlTText = (text, params) => interpolate(text, params);

// --- Harness: extract the app functions, run them against the doubles ---
const extract = (name) => {
  const match = app.match(new RegExp(`^function ${name}\\([^]*?^}`, "m"));
  assert.ok(match, `src/js/app.js defines ${name}`);
  return match[0];
};

const rbfHarness = (sessionScripts = []) => {
  const session = new Map(sessionScripts.map((hex) => [hex, true]));
  const elements = { "psbt-rbf-original": { value: "" } };
  const context = vm.createContext({
    hodlT,
    hodlTText,
    bytesToHex,
    hodlHex,
    hodlSha256: sha256,
    hodlR32: read32,
    serializeTx: realSerializeTx,
    parseRawTx: realParseRawTx,
    hodlParsePsbt: parsePsbt,
    isPsbtMagic,
    hodlPsbtBytesFromText: psbtBytesFromText,
    hodlCheckRbfReplacement: checkRbfReplacement,
    hodlSessionOwnership: () => session,
    matchOwnership: (map, script) => ({ state: map.has(bytesToHex(script)) ? "ours" : "theirs" }),
    document: { getElementById: (id) => elements[id] ?? null },
  });
  for (const name of [
    "hodlPsbtRbfAmount",
    "hodlPsbtRbfBtc",
    "hodlPsbtRbfShowScript",
    "hodlPsbtRbfNormalizeTx",
    "hodlPsbtRbfNormalizePsbt",
    "hodlPsbtRbfItemLine",
    "hodlPsbtRbfNote",
    "hodlPsbtPrependRbfCheck",
  ]) {
    vm.runInContext(extract(name), context);
  }
  return { context, elements };
};

const fakeOutput = (initial = "") => ({
  html: initial,
  insertAdjacentHTML(position, html) {
    assert.equal(position, "afterbegin", "the RBF note is always prepended");
    this.html = html + this.html;
  },
});

const runRbf = ({ session = [], originalText, replacementBytes, kind = "psbt", outputHtml = "" }) => {
  const { context, elements } = rbfHarness(session);
  elements["psbt-rbf-original"].value = originalText;
  const output = fakeOutput(outputHtml);
  const result = context.hodlPsbtPrependRbfCheck(output, replacementBytes, kind, "mainnet");
  return { result, html: output.html, context };
};

// --- Fixtures ------------------------------------------------------------
const TXID_A = bytesFromHex("aa".repeat(32));
const TXID_B = bytesFromHex("bb".repeat(32));
const OURS = bytesFromHex(`0014${"11".repeat(20)}`);
const THEIRS = bytesFromHex(`0014${"22".repeat(20)}`);
const ATTACKER = bytesFromHex(`0014${"33".repeat(20)}`);
const OURS_HEX = bytesToHex(OURS);
const THEIRS_HEX = bytesToHex(THEIRS);

const psbtPair = (originalOutputs, replacementOutputs) => ({
  original: buildPsbt(buildRawTx({ inputs: [{ txid: TXID_A, vout: 0 }], outputs: originalOutputs })),
  replacement: buildPsbt(buildRawTx({ inputs: [{ txid: TXID_A, vout: 0 }], outputs: replacementOutputs })),
});

const CLEAN = psbtPair(
  [{ amount: 100000n, script: THEIRS }, { amount: 50000n, script: OURS }],
  [{ amount: 100000n, script: THEIRS }, { amount: 49000n, script: OURS }],
);

test("a clean bump with a session key is green and carries the standing caveat", () => {
  const { result, html } = runRbf({ session: [OURS_HEX], originalText: b64(CLEAN.original), replacementBytes: CLEAN.replacement });
  assert.equal(result.verdict, "green");
  assert.match(html, /data-rbf-verdict="green"/);
  assert.match(html, /Payments preserved; fee increased\./);
  assert.match(html, /data-rbf-item="change-decreased"/);
  assert.match(html, /This compares the supplied transactions\. It does not confirm that the network will accept the replacement\./);
});

test("the Electrum attack — a recipient swapped for an attacker output — is red with payment-removed", () => {
  const { original, replacement } = psbtPair(
    [{ amount: 100000n, script: THEIRS }, { amount: 50000n, script: OURS }],
    [{ amount: 100000n, script: ATTACKER }, { amount: 49000n, script: OURS }],
  );
  const { result, html } = runRbf({ session: [OURS_HEX], originalText: b64(original), replacementBytes: replacement });
  assert.equal(result.verdict, "red");
  assert.match(html, /data-rbf-verdict="red"/);
  assert.match(html, /A payment was changed or removed\./);
  assert.match(html, /data-rbf-item="payment-removed"/);
  assert.match(html, /0\.00100000 BTC/, "amounts render in BTC with 8 decimals");
  assert.match(html, /This compares the supplied transactions\./, "the standing caveat shows even on red");
});

test("a change decrease beside a new underivable output is a redirected change (red)", () => {
  const { original, replacement } = psbtPair(
    [{ amount: 100000n, script: THEIRS }, { amount: 50000n, script: OURS }],
    [{ amount: 100000n, script: THEIRS }, { amount: 40000n, script: OURS }, { amount: 9000n, script: ATTACKER }],
  );
  const { result, html } = runRbf({ session: [OURS_HEX], originalText: b64(original), replacementBytes: replacement });
  assert.equal(result.verdict, "red");
  assert.ok(result.items.some((item) => item.code === "change-redirected"));
  assert.match(html, /data-rbf-item="change-redirected"/);
  assert.match(html, /Your change was redirected: your own output went down or disappeared while a new output this key cannot derive appeared\./);
});

test("with no session key a decrease is amber and asks the user to confirm their change", () => {
  const { result, html } = runRbf({ session: [], originalText: b64(CLEAN.original), replacementBytes: CLEAN.replacement });
  assert.equal(result.verdict, "amber");
  assert.match(html, /data-rbf-verdict="amber"/);
  assert.match(html, /Additional review needed\./);
  assert.match(html, /data-rbf-item="output-decreased-unverified"/);
  assert.match(html, /One output decreased\. Check that it is your change\./);
});

test("a raw-transaction original gives null, unverified input amounts", () => {
  const { context } = rbfHarness();
  const raw = buildRawTx({ inputs: [{ txid: TXID_A, vout: 1 }], outputs: [{ amount: 42000n, script: THEIRS }] });
  const normalized = context.hodlPsbtRbfNormalizeTx(parseRawTx(raw));
  assert.equal(normalized.inputs.length, 1);
  assert.equal(normalized.inputs[0].amount, null);
  assert.equal(normalized.inputs[0].amountVerified, false);
  assert.equal(normalized.inputs[0].sighash, null);
  assert.equal(normalized.outputs[0].amount, 42000n);
  assert.equal(normalized.outputs[0].script, THEIRS_HEX);
});

test("a non_witness_utxo amount is verified only when the recomputed txid matches the outpoint", () => {
  const { context } = rbfHarness();
  const buildPrev = (amount) => buildRawTx({ inputs: [{ txid: TXID_B, vout: 0 }], outputs: [{ amount, script: OURS }] });
  const prevTx = buildPrev(77000n);
  const prevTxid = sha256(sha256(serializeTx(parseRawTx(prevTx), false)));
  const unsigned = buildRawTx({ inputs: [{ txid: prevTxid, vout: 0 }], outputs: [{ amount: 76000n, script: THEIRS }] });
  const normalize = (prevBytes) => context.hodlPsbtRbfNormalizePsbt(parsePsbt(buildPsbt(unsigned, [[psbtEntry(0, prevBytes)]])));
  const verified = normalize(prevTx);
  assert.equal(verified.inputs[0].amount, 77000n);
  assert.equal(verified.inputs[0].amountVerified, true);
  const tampered = normalize(buildPrev(78000n));
  assert.equal(tampered.inputs[0].amount, 78000n, "the claimed amount is still read");
  assert.equal(tampered.inputs[0].amountVerified, false, "but a swapped previous transaction does not verify");
});

test("a bare witness_utxo amount is read but stays unverified", () => {
  const { context } = rbfHarness();
  const witnessUtxo = concat(le64(66000n), writeVarint(OURS.length), OURS);
  const unsigned = buildRawTx({ inputs: [{ txid: TXID_A, vout: 2 }], outputs: [{ amount: 65000n, script: THEIRS }] });
  const normalized = context.hodlPsbtRbfNormalizePsbt(parsePsbt(buildPsbt(unsigned, [[psbtEntry(1, witnessUtxo)]])));
  assert.equal(normalized.inputs[0].amount, 66000n);
  assert.equal(normalized.inputs[0].amountVerified, false);
});

test("a PSBT sighash-type entry is carried into the comparison", () => {
  const { context } = rbfHarness();
  const unsigned = buildRawTx({ inputs: [{ txid: TXID_A, vout: 0 }], outputs: [{ amount: 1000n, script: THEIRS }] });
  const normalized = context.hodlPsbtRbfNormalizePsbt(parsePsbt(buildPsbt(unsigned, [[psbtEntry(3, le32(1))]])));
  assert.equal(normalized.inputs[0].sighash, 1);
});

test("the verdict renders above the signer audit and the inspection", () => {
  const audit = "<div data-signer-audit>audit</div>";
  const inspection = "<div data-inspection>inspection</div>";
  const { html } = runRbf({ session: [OURS_HEX], originalText: b64(CLEAN.original), replacementBytes: CLEAN.replacement, outputHtml: audit + inspection });
  assert.ok(html.indexOf("data-rbf-verdict") >= 0, "the verdict rendered");
  assert.ok(html.indexOf("data-rbf-verdict") < html.indexOf("data-signer-audit"), "the RBF verdict sits above the signer audit");
  assert.ok(html.indexOf("data-signer-audit") < html.indexOf("data-inspection"), "the audit stays above the inspection");
  const runStart = app.indexOf("function hodlRunPsbt(");
  const run = app.slice(runStart, app.indexOf("\nfunction ", runStart));
  assert.ok(run.indexOf("hodlPsbtPrependSignerAudit(") < run.indexOf("hodlPsbtPrependRbfCheck("), "the run prepends the audit first so the RBF note lands above it");
});

test("an empty original field renders nothing", () => {
  const { context } = rbfHarness([OURS_HEX]);
  const output = fakeOutput("<div>inspection</div>");
  const result = context.hodlPsbtPrependRbfCheck(output, CLEAN.replacement, "psbt", "mainnet");
  assert.equal(result, null);
  assert.equal(output.html, "<div>inspection</div>");
});

test("inspecting a raw transaction instead of the bump PSBT is amber, never green", () => {
  const rawReplacement = buildRawTx({ inputs: [{ txid: TXID_A, vout: 0 }], outputs: [{ amount: 100000n, script: THEIRS }, { amount: 49000n, script: OURS }] });
  const { result, html } = runRbf({ session: [OURS_HEX], originalText: b64(CLEAN.original), replacementBytes: rawReplacement, kind: "transaction" });
  assert.equal(result, null);
  assert.match(html, /data-rbf-verdict="amber"/);
  assert.match(html, /Inspect the fee-bump PSBT, not a raw transaction\./);
  assert.match(html, /This compares the supplied transactions\./);
});

test("an unreadable original fails closed to amber, never green", () => {
  const { result, html } = runRbf({ session: [OURS_HEX], originalText: "02000000", replacementBytes: CLEAN.replacement });
  assert.equal(result, null);
  assert.match(html, /data-rbf-verdict="amber"/);
  assert.match(html, /The original transaction could not be read\./);
});

test("no shared inputs is neutral and says it is not a direct replacement", () => {
  const original = buildPsbt(buildRawTx({ inputs: [{ txid: TXID_A, vout: 0 }], outputs: [{ amount: 100000n, script: THEIRS }] }));
  const replacement = buildPsbt(buildRawTx({ inputs: [{ txid: TXID_B, vout: 1 }], outputs: [{ amount: 99000n, script: THEIRS }] }));
  const { result, html } = runRbf({ session: [OURS_HEX], originalText: b64(original), replacementBytes: replacement });
  assert.equal(result.verdict, "neutral");
  assert.match(html, /data-rbf-verdict="neutral"/);
  assert.match(html, /No shared inputs\./);
  assert.match(html, /This does not directly replace the supplied transaction\./);
  assert.match(html, /This compares the supplied transactions\./);
});

test("scripts render as addresses when they decode for the network, else as hex", () => {
  const { context } = rbfHarness();
  context.hodlAddressFromScript = (script, network) => {
    assert.equal(network, "mainnet");
    return bytesToHex(script) === OURS_HEX ? "bc1qexample" : null;
  };
  assert.equal(context.hodlPsbtRbfShowScript(OURS_HEX, "mainnet"), "bc1qexample");
  assert.equal(context.hodlPsbtRbfShowScript(THEIRS_HEX, "mainnet"), THEIRS_HEX, "a script the decoder cannot place stays hex");
  context.hodlAddressFromScript = () => {
    throw new Error("not an address");
  };
  assert.equal(context.hodlPsbtRbfShowScript(OURS_HEX, "mainnet"), OURS_HEX, "a decoder failure falls back to hex");
});

test("the screen and its wiring ship in every build", () => {
  const runStart = app.indexOf("function hodlRunPsbt(");
  const run = app.slice(runStart, app.indexOf("\nfunction ", runStart));
  const callAt = run.indexOf("hodlPsbtPrependRbfCheck(");
  assert.ok(callAt >= 0, "the call in hodlRunPsbt exists");
  assert.doesNotMatch(run.slice(Math.max(0, callAt - 200), callAt), /__ENTROPYLAB_PREVIEW__/, "the call in hodlRunPsbt is ungated");
  const uploadAt = app.indexOf('const rbfFile = document.getElementById("psbt-rbf-file");');
  assert.ok(uploadAt >= 0, "the upload wiring exists");
  assert.doesNotMatch(app.slice(Math.max(0, uploadAt - 200), uploadAt), /__ENTROPYLAB_PREVIEW__/, "the upload wiring is ungated");
  assert.match(app, /document\.getElementById\("psbt-rbf-original"\)\?\.addEventListener\("input", hodlPsbtClearRbfVerdict\)/, "editing the original retires the verdict");
  const optionsAt = shell.indexOf('id="psbt-rbf-options"');
  assert.ok(optionsAt > 0, "the RBF options block exists in the shell");
  const before = shell.slice(0, optionsAt);
  const open = before.lastIndexOf("<!-- preview -->");
  const close = before.lastIndexOf("<!-- /preview -->");
  assert.ok(open === -1 || open < close, "no preview marker opens the block");
  const release = applyPreviewBlocks(shell, false);
  assert.match(release, /id="psbt-rbf-options"/, "a release build keeps the RBF section");
  for (const id of ["psbt-rbf-original", "psbt-rbf-upload", "psbt-rbf-file"]) {
    assert.match(release, new RegExp(`id="${id}"`), `a release build keeps #${id}`);
  }
  assert.match(release, /<summary>Check a fee bump \(RBF\) \(optional\)<\/summary>/);
});

test("the RBF upload fills #psbt-rbf-original from a File-like object with arrayBuffer()", async () => {
  const elements = { "psbt-rbf-original": { value: "" } };
  let cleared = 0;
  // Uint8Array is the test realm's: the real psbtBytesFromUpload checks
  // `instanceof Uint8Array`, and a vm-realm array would fail that check for
  // a reason that has nothing to do with the app.
  const context = vm.createContext({
    hodlPsbtRbfUploadGeneration: 0,
    document: { getElementById: (id) => elements[id] || null },
    hodlBytesToB64: (bytes) => Buffer.from(bytes).toString("base64"),
    hodlSetPsbtError: () => {},
    psbtBytesFromUpload: realPsbtBytesFromUpload,
    hodlPsbtClearRbfVerdict: () => { cleared += 1; },
    Uint8Array,
  });
  vm.runInContext(extract("hodlPsbtLoadRbfUpload"), context);
  const bytes = Uint8Array.of(0x70, 0x73, 0x62, 0x74, 0xff, 0x00);
  context.hodlPsbtLoadRbfUpload({ arrayBuffer: async () => bytes.buffer });
  await new Promise((resolve) => setTimeout(resolve, 0));
  assert.equal(elements["psbt-rbf-original"].value, Buffer.from(bytes).toString("base64"));
  assert.equal(cleared, 1, "the upload retires a shown verdict");
});

test("a later RBF-original pick wins over an earlier read that finishes last", async () => {
  const elements = { "psbt-rbf-original": { value: "" } };
  const context = vm.createContext({
    hodlPsbtRbfUploadGeneration: 0,
    document: { getElementById: (id) => elements[id] || null },
    hodlBytesToB64: (bytes) => Buffer.from(bytes).toString("base64"),
    hodlSetPsbtError: () => {},
    psbtBytesFromUpload: realPsbtBytesFromUpload,
    hodlPsbtClearRbfVerdict: () => {},
    Uint8Array,
  });
  vm.runInContext(extract("hodlPsbtLoadRbfUpload"), context);
  let releaseA;
  const slowA = { arrayBuffer: () => new Promise((resolve) => { releaseA = () => resolve(Uint8Array.of(0x70, 0x73, 0x62, 0x74, 0xff, 0xaa).buffer); }) };
  const fastB = { arrayBuffer: async () => Uint8Array.of(0x70, 0x73, 0x62, 0x74, 0xff, 0xbb).buffer };
  context.hodlPsbtLoadRbfUpload(slowA);
  context.hodlPsbtLoadRbfUpload(fastB);
  await new Promise((resolve) => setTimeout(resolve, 0));
  assert.equal(elements["psbt-rbf-original"].value, Buffer.from([0x70, 0x73, 0x62, 0x74, 0xff, 0xbb]).toString("base64"));
  releaseA();
  await new Promise((resolve) => setTimeout(resolve, 0));
  assert.equal(elements["psbt-rbf-original"].value, Buffer.from([0x70, 0x73, 0x62, 0x74, 0xff, 0xbb]).toString("base64"), "the stale read does not overwrite the newer pick");
});

test("editing the RBF original retires the rendered verdict", () => {
  let removed = 0;
  const verdict = { remove: () => { removed += 1; } };
  const out = { querySelector: (selector) => (selector === "[data-rbf-verdict]" ? verdict : null) };
  const context = vm.createContext({
    document: { getElementById: (id) => (id === "psbt-out" ? out : null) },
  });
  vm.runInContext(extract("hodlPsbtClearRbfVerdict"), context);
  context.hodlPsbtClearRbfVerdict();
  assert.equal(removed, 1);
});

test("retiring the signer audit also retires the RBF verdict", () => {
  let cleared = 0;
  const context = vm.createContext({
    document: { getElementById: () => null },
    hodlPsbtLast: null,
    hodlPsbtInspected: {},
    hodlSyncPsbtControls: () => {},
    hodlPsbtClearRbfVerdict: () => { cleared += 1; },
  });
  vm.runInContext(extract("hodlPsbtClearSignerAudit"), context);
  context.hodlPsbtClearSignerAudit();
  assert.equal(cleared, 1, "the verdict goes even when no audit section is on screen");
});

test("finding lines are HTML-escaped, never raw text", () => {
  const { context } = rbfHarness();
  context.hodlAddressFromScript = () => '<img src=x onerror="alert(1)">';
  const line = context.hodlPsbtRbfItemLine({ code: "payment-removed", script: THEIRS_HEX, before: 100000n }, "mainnet");
  assert.doesNotMatch(line, /<img/);
  assert.match(line, /&lt;img/);
});

test("a replacement PSBT that does not normalize is amber without blaming the original", () => {
  const { result, html } = runRbf({ session: [OURS_HEX], originalText: b64(CLEAN.original), replacementBytes: Uint8Array.of(0x70, 0x73, 0x62, 0x74, 0xff, 0x00) });
  assert.equal(result, null);
  assert.match(html, /data-rbf-verdict="amber"/);
  assert.doesNotMatch(html, /The original transaction could not be read\./);
});
