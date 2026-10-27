// End-to-end: a P2WPKH PSBT signed with ECDSA sign-to-contract, the AEXB
// stages 2-4 of that session, and the render's per-signature verdicts.
// Run with: npm run test:ci
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { loadAppFunctions } from "./app-slice-harness.mjs";
import { readAntiExfil } from "../src/js/anti-exfil.js";
import { aexbDecode, aexbEncode, aexbVerify } from "../src/js/aexb.js";
import { s2cCommittedNonce, s2cHostCommitment, s2cSignatureMatches } from "../src/js/s2c.js";
import { secp256k1Ready } from "../src/js/secp256k1.js";
import { hashesReady } from "../src/js/hashes.js";

await secp256k1Ready;
await hashesReady;

// @noble/hashes moved ripemd160 to legacy.js in v1.4; accept either layout.
let ripemd160;
try {
  ({ ripemd160 } = await import("@noble/hashes/legacy.js"));
} catch {
  ({ ripemd160 } = await import("@noble/hashes/ripemd160"));
}

const root = dirname(fileURLToPath(import.meta.url));
const app = readFileSync(join(root, "..", "src/js/app.js"), "utf8");

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

// --- deterministic bytes ---------------------------------------------------
const sha256 = (bytes) => new Uint8Array(createHash("sha256").update(bytes).digest());
const dsha256 = (bytes) => sha256(sha256(bytes));
const concat = (...parts) => {
  const out = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
};
const le32 = (value) => {
  const bytes = new Uint8Array(4);
  new DataView(bytes.buffer).setUint32(0, value, true);
  return bytes;
};
const le64 = (value) => {
  const bytes = new Uint8Array(8);
  new DataView(bytes.buffer).setBigUint64(0, BigInt(value), true);
  return bytes;
};
const varint = (value) => {
  if (value < 0xfd) return Uint8Array.of(value);
  if (value <= 0xffff) return Uint8Array.of(0xfd, value & 0xff, (value >>> 8) & 0xff);
  throw new Error("varint too large for this fixture");
};
const bytesToNum = (bytes) => BigInt("0x" + (Buffer.from(bytes).toString("hex") || "0"));
const numToBytes = (value) => Uint8Array.from(Buffer.from(value.toString(16).padStart(64, "0"), "hex"));
const N = secp256k1.Point.CURVE().n;
const mod = (value, m) => ((value % m) + m) % m;
const invert = (value) => {
  let [oldR, r] = [mod(value, N), N];
  let [oldS, s] = [1n, 0n];
  while (r !== 0n) {
    const q = oldR / r;
    [oldR, r] = [r, oldR - q * r];
    [oldS, s] = [s, oldS - q * s];
  }
  return mod(oldS, N);
};
// BIP340-style tagged hash, the construction s2c.js uses for its tweak.
const taggedHash = (tag, ...parts) => {
  const tagHash = sha256(new TextEncoder().encode(tag));
  return sha256(concat(tagHash, tagHash, ...parts));
};
const derInt = (value) => {
  let bytes = numToBytes(value);
  let start = 0;
  while (start < bytes.length - 1 && bytes[start] === 0) start++;
  bytes = bytes.slice(start);
  if (bytes[0] & 0x80) bytes = concat(Uint8Array.of(0), bytes);
  return concat(Uint8Array.of(0x02, bytes.length), bytes);
};
const der = (r, s) => {
  const body = concat(derInt(r), derInt(s));
  return concat(Uint8Array.of(0x30, body.length), body);
};

// --- the PSBT --------------------------------------------------------------
const signerSecret = bytesToNum(Uint8Array.from(Buffer.from("11".repeat(32), "hex")));
const signerPubkey = secp256k1.getPublicKey(numToBytes(signerSecret), true);
const pubkeyHash = ripemd160(sha256(signerPubkey));
const witnessScript = concat(Uint8Array.of(0x00, 0x14), pubkeyHash); // P2WPKH output
const scriptCode = concat(Uint8Array.of(0x76, 0xa9, 0x14), pubkeyHash, Uint8Array.of(0x88, 0xac));
const prevTxid = new Uint8Array(32).fill(0x22);
const prevVout = 0;
const sequence = 0xfffffffd;
const inputAmount = 100000n;
const outputAmount = 90000n;
const outputScript = Uint8Array.of(0x51);

// BIP143 SIGHASH_ALL digest for input 0, from the specification.
const hashPrevouts = dsha256(concat(prevTxid, le32(prevVout)));
const hashSequence = dsha256(le32(sequence));
const hashOutputs = dsha256(concat(le64(outputAmount), varint(outputScript.length), outputScript));
const sighash = dsha256(concat(
  le32(2),
  hashPrevouts,
  hashSequence,
  prevTxid,
  le32(prevVout),
  varint(scriptCode.length),
  scriptCode,
  le64(inputAmount),
  le32(sequence),
  hashOutputs,
  le32(0),
  le32(1),
));

// --- sign-to-contract ------------------------------------------------------
const rho = new Uint8Array(32).fill(0x33);
const k0 = bytesToNum(Uint8Array.from(Buffer.from("22".repeat(32), "hex")));
const R0 = secp256k1.getPublicKey(numToBytes(k0), true);
const tweak = bytesToNum(taggedHash("s2c/ecdsa/point", R0, rho));
const k = mod(k0 + tweak, N);
const committed = secp256k1.getPublicKey(numToBytes(k), true);
const r = mod(bytesToNum(committed.slice(1)), N);
const z = bytesToNum(sighash);
let s = mod(invert(k) * (z + r * signerSecret), N);
if (s > N / 2n) s = N - s;
const signature64 = concat(numToBytes(r), numToBytes(s));
const partialSignature = concat(der(r, s), Uint8Array.of(1));

test("the fixture is a genuine sign-to-contract signature", () => {
  assert.deepEqual(committed, s2cCommittedNonce(R0, rho), "the test's tweak matches s2c.js");
  assert.ok(s2cSignatureMatches(numToBytes(r), R0, rho));
});

// --- the AEXB session ------------------------------------------------------
const sessionId = new Uint8Array(32).fill(0x44);
const psbtDigest = new Uint8Array(32).fill(0x55);
const commitment = s2cHostCommitment(rho);

function aexbSession(signature, inputIndex = 0) {
  const shared = { inputIndex, sighashType: 1, signerPubkey, messageHash: sighash, commitment, opening: R0 };
  const base = { network: 0, sessionId, psbtDigest };
  return {
    stage2: aexbEncode({ ...base, stage: 2, slots: [{ ...shared, rho: null, signature: null }] }),
    stage3: aexbEncode({ ...base, stage: 3, slots: [{ ...shared, rho, signature: null }] }),
    stage4: aexbEncode({ ...base, stage: 4, slots: [{ ...shared, rho: null, signature }] }),
  };
}
const transcript = (session) =>
  [session.stage2, session.stage3, session.stage4].map((message) => Buffer.from(message).toString("hex")).join("\n");

const witnessUtxo = concat(le64(inputAmount), varint(witnessScript.length), witnessScript);
const psbtFor = (signature) => ({
  tx: {
    version: 2, locktime: 0, segwit: false,
    inputs: [{ txid: prevTxid, vout: prevVout, sequence, scriptSig: new Uint8Array() }],
    outputs: [{ amount: outputAmount, script: outputScript }],
  },
  inputs: [[
    { type: 1, keydata: new Uint8Array(), val: witnessUtxo },
    { type: 2, keydata: signerPubkey, val: signature },
  ]],
  outputs: [[]],
});

// The render reads the transcript through hodlReadNonceTranscript
// unconditionally; the reader detects the format. The harness's `settable`
// path does not reach the top-level `var PREVIEW`, so the flag is supplied as
// a stub (and written through __set when the harness exposes it) to prove a
// release build (PREVIEW false) takes the same path.
const baseStubs = {
  document: { getElementById: () => null },
  readAntiExfil,
  aexbVerify,
  hodlSessionOwnership: () => new Map(),
  hodlRenderOutputHtml: () => "",
  hodlOwnershipWarning: () => "",
  hodlPublicInlineHtml: (text) => text,
  hodlPsbtReferenceVerdict: () => ({ state: "incomplete" }),
  hodlPrivForPub: () => null,
  hodlPrivFromPath: () => null,
  hodlPsbtMasterFingerprint: () => null,
  hodlPsbtRecordNonceInspection: () => {},
};
const releaseApi = await loadAppFunctions(["hodlRenderPsbt"], { settable: ["PREVIEW"], stubs: { ...baseStubs, PREVIEW: false } });
if (releaseApi.__set) releaseApi.__set.PREVIEW = false;

function renderNonce(signature, raw) {
  return releaseApi.hodlRenderPsbt(psbtFor(signature), undefined, undefined, "nonce", { network: "mainnet", transcript: raw, record: false });
}

test("a sign-to-contract signature matches its AEXB transcript slot", () => {
  const session = aexbSession(signature64);
  assert.equal(aexbVerify(aexbDecode(session.stage4), aexbDecode(session.stage3), aexbDecode(session.stage2)).ok, true, "the fixture verifies on its own");
  const html = renderNonce(partialSignature, transcript(session));
  assert.match(html, /data-aexb-verdict='match'/);
  assert.match(html, /data-aexb-summary='covered'/);
});

test("an ordinary nonce does not match the transcript", () => {
  const session = aexbSession(signature64);
  const ordinary = bytesToNum(Uint8Array.from(Buffer.from("44".repeat(32), "hex")));
  const ordinaryR = mod(bytesToNum(secp256k1.getPublicKey(numToBytes(ordinary), true).slice(1)), N);
  let ordinaryS = mod(invert(ordinary) * (z + ordinaryR * signerSecret), N);
  if (ordinaryS > N / 2n) ordinaryS = N - ordinaryS;
  const html = renderNonce(concat(der(ordinaryR, ordinaryS), Uint8Array.of(1)), transcript(session));
  assert.match(html, /data-aexb-verdict='mismatch'/);
  assert.match(html, /data-aexb-summary='partial'/);
});

test("a transcript slot for another input covers no signature", () => {
  const session = aexbSession(signature64, 1);
  const html = renderNonce(partialSignature, transcript(session));
  assert.match(html, /data-aexb-verdict='no-slot'/);
});

test("a flipped signature byte fails the transcript", () => {
  const flipped = signature64.slice();
  flipped[16] ^= 0x01;
  const session = aexbSession(flipped);
  const html = renderNonce(partialSignature, transcript(session));
  assert.match(html, /data-aexb-summary='fail'/);
  assert.doesNotMatch(html, /data-aexb-verdict=/);
});

test("a release render (PREVIEW false) verifies the AEXB transcript too", () => {
  const session = aexbSession(signature64);
  const html = renderNonce(partialSignature, transcript(session));
  assert.match(html, /data-aexb-verdict='match'/);
  assert.match(html, /data-aexb-summary='covered'/);
});

// --- the markup ------------------------------------------------------------
test("the shell carries the unified anti-exfil strings on their ids", () => {
  const shell = readFileSync(join(root, "..", "src/shell.html"), "utf8");
  const start = shell.indexOf('id="nonce-jade-options"');
  assert.ok(start >= 0, "#nonce-jade-options is no longer in the shell");
  const block = shell.slice(start, shell.indexOf("</details>", start));
  assert.ok(block.includes('id="psbt-ax-transcript-help"'), "the help paragraph keeps its id");
  assert.ok(block.includes('id="psbt-ax-transcript"'), "the field keeps its id");
  assert.ok(block.includes("Anti-exfil transcript (Jade, BitBox02 or AEXB, optional)"), "the summary names all three formats");
  assert.ok(block.includes("Paste a Jade or BitBox02 host nonce and opening, or the AEXB/AEXT messages of one session as hex, stages 2 to 4. The format is detected automatically."), "the help text describes the unified field");
  assert.ok(block.includes('aria-label="Anti-exfil transcript"'), "the field's accessible name is the unified one");
  assert.ok(block.includes('placeholder="Host nonce and opening, or AEXB messages, as hex"'), "the placeholder describes both formats");
});
