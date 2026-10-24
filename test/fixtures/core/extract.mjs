// Extracts the Bitcoin Core transaction vectors that pin how a signature's
// scriptCode is built — OP_CODESEPARATOR position, FindAndDelete, the
// SIGHASH_SINGLE bug, non-standard hash types and high-S signatures — from
// Core's src/test/data/tx_valid.json and tx_invalid.json into
// tx-scriptcode-vectors.json next to this script.
//
//   node test/fixtures/core/extract.mjs <bitcoin-core-checkout>/src/test/data
//
// Nothing is computed here: each vector's transaction and prevouts are copied
// verbatim, its scriptPubKeys are assembled from Core's test-script notation,
// and the annotations below only say which scriptSig pushes or witness items
// are the signature and public key a PSBT's partial-signature field would
// carry. Those pairings follow from the script (CHECKSIG consumes the top
// two stack items; CHECKMULTISIG pairs signatures and keys top-down), and
// each is stated next to its vector. "valid" means Core accepts the spend,
// so every annotated signature verified inside it; "invalid" means Core
// rejects the spend because the annotated signature does not verify under
// the scriptCode consensus builds for it. The sha256 of each source file is
// recorded so a re-extraction from another Core tag is visible in review.
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const SOURCE = { repository: "https://github.com/bitcoin/bitcoin", tag: "v31.1", commit: "9be056a8a72b624dae9623b2f7bded92c2a21c91" };

const dataDir = process.argv[2];
if (!dataDir) throw new Error("usage: node test/fixtures/core/extract.mjs <bitcoin-core>/src/test/data");
const read = (name) => readFileSync(join(dataDir, name), "utf8");
const files = { "tx_valid.json": read("tx_valid.json"), "tx_invalid.json": read("tx_invalid.json") };

// --- Core's test-script notation (src/core_read.cpp ParseScript), the subset
// these vectors use: opcode names with or without OP_, small decimal numbers,
// and 0x-prefixed raw bytes inserted verbatim.
const OPS = {
  "0": 0x00, FALSE: 0x00, PUSHDATA1: 0x4c, PUSHDATA2: 0x4d, PUSHDATA4: 0x4e, "1NEGATE": 0x4f,
  NOP: 0x61, IF: 0x63, NOTIF: 0x64, ELSE: 0x67, ENDIF: 0x68, VERIFY: 0x69, RETURN: 0x6a,
  DROP: 0x75, DUP: 0x76, SWAP: 0x7c, EQUAL: 0x87, EQUALVERIFY: 0x88, HASH160: 0xa9,
  CODESEPARATOR: 0xab, CHECKSIG: 0xac, CHECKSIGVERIFY: 0xad, CHECKMULTISIG: 0xae, CHECKMULTISIGVERIFY: 0xaf,
};
const assemble = (notation) =>
  notation.trim().split(/\s+/).map((token) => {
    if (/^0x[0-9a-f]*$/i.test(token)) return token.slice(2).toLowerCase();
    if (/^([1-9]|1[0-6])$/.test(token)) return (0x50 + Number(token)).toString(16);
    const op = OPS[token.replace(/^OP_/, "")];
    if (op === undefined) throw new Error(`notation token ${token} is outside the subset this extractor reads`);
    return op.toString(16).padStart(2, "0");
  }).join("");

// --- transactions and scripts
const parseTx = (hex) => {
  const b = Buffer.from(hex, "hex");
  let o = 0;
  const u32 = () => { const v = b.readUInt32LE(o); o += 4; return v; };
  const varint = () => {
    const first = b[o++];
    if (first < 0xfd) return first;
    if (first === 0xfd) { const v = b.readUInt16LE(o); o += 2; return v; }
    if (first === 0xfe) return u32();
    throw new Error("64-bit compact size");
  };
  const take = (n) => { const r = b.subarray(o, o + n); o += n; return r; };
  u32();
  const segwit = b[o] === 0 && b[o + 1] === 1;
  if (segwit) o += 2;
  const inputs = [];
  for (let n = varint(); n--;) {
    take(36); // prevout
    inputs.push({ scriptSig: take(varint()), sequence: u32(), witness: [] });
  }
  for (let n = varint(); n--;) { take(8); take(varint()); }
  if (segwit) for (const input of inputs) for (let n = varint(); n--;) input.witness.push(take(varint()));
  return inputs;
};
// The data pushes of a push-only scriptSig (OP_0 and OP_1..OP_16 as their
// values), in order.
const pushes = (script) => {
  const out = [];
  for (let pc = 0; pc < script.length;) {
    const op = script[pc];
    let header = 0, length = 0;
    if (op >= 0x01 && op <= 0x4b) length = op;
    else if (op === 0x4c) { header = 1; length = script[pc + 1]; }
    else if (op === 0x4d) { header = 2; length = script.readUInt16LE(pc + 1); }
    else if (op === 0x00) length = 0;
    else if (op >= 0x51 && op <= 0x60) { out.push(Buffer.from([op - 0x50]).toString("hex")); pc += 1; continue; }
    else throw new Error(`scriptSig is not push-only (0x${op.toString(16)})`);
    out.push(Buffer.from(script.subarray(pc + 1 + header, pc + 1 + header + length)).toString("hex"));
    pc += 1 + header + length;
  }
  return out;
};
// The 33- and 65-byte pushes of a script, in order: a multisig script's keys.
const keysIn = (hex) => {
  const script = Buffer.from(hex, "hex"), keys = [];
  for (let pc = 0; pc < script.length;) {
    const op = script[pc];
    if (op >= 0x01 && op <= 0x4b) {
      if (op === 33 || op === 65) keys.push(Buffer.from(script.subarray(pc + 1, pc + 1 + op)).toString("hex"));
      pc += 1 + op;
    } else pc += 1;
  }
  return keys;
};

// --- selection
// A vector is named by its file, the first prevout's txid, and which
// occurrence of that txid it is; the comment lines above it must contain
// `anchor`, so a moved or rewritten vector fails the extraction.
const find = (file, txid, nth, anchor) => {
  // A comment block describes every vector up to the next comment block.
  let seen = 0, comments = [], afterVector = false;
  for (const entry of JSON.parse(files[file])) {
    if (typeof entry[0] === "string") {
      if (afterVector) comments = [];
      comments.push(entry[0]);
      afterVector = false;
      continue;
    }
    afterVector = true;
    if (entry[0][0][0] === txid && seen++ === nth) {
      const text = comments.join(" ");
      if (!text.includes(anchor)) throw new Error(`${file} ${txid}#${nth}: comment does not contain "${anchor}"`);
      return { entry, comments };
    }
  }
  throw new Error(`${file} ${txid}#${nth} not found`);
};

// Item references: ["ss", n] is scriptSig push n, ["wit", n] witness item n,
// ["hex", "..."] a literal (a signature embedded in the script itself), and
// ["key", n] the n-th public key pushed by the spend's script.
const CASES = [
  // --- tx_valid.json: OP_CODESEPARATOR in legacy scripts
  { file: "tx_valid.json", txid: "bc7fd132fcf817918334822ee6d9bd95c889099c96e07ca2c1eb2cc70db63224", nth: 0, anchor: "removes OP_CODESEPARATOR",
    checks: [{ input: 0, why: "a separator ahead of the only CHECKSIG: the scriptCode is the rest of the script", sigs: [[["key", 0], ["ss", 0]]] }] },
  { file: "tx_valid.json", txid: "83e194f90b6ef21fa2e3a365b63794fb5daa844bdc9b25de30899fcfe7b01047", nth: 0, anchor: "removes OP_CODESEPARATOR",
    checks: [{ input: 0, why: "two separators ahead of the CHECKSIG", sigs: [[["key", 0], ["ss", 0]]] }] },
  { file: "tx_valid.json", txid: "326882a7f22b5191f1a0cc9962ca4b878cd969cf3b3a70887aece4d801a0ba5e", nth: 0, anchor: "Hashed data starts at the CODESEPARATOR",
    checks: [{ input: 0, why: "the separator sits between the key push and CHECKSIG: only CHECKSIG itself is hashed", sigs: [[["key", 0], ["ss", 0]]] }] },
  { file: "tx_valid.json", txid: "a955032f4d6b0c9bfe8cad8f00a8933790b9c1dc28c82e0f48e75b35da0e4944", nth: 0, anchor: "But only if execution has reached it",
    checks: [
      // The top push (ss 1) meets the first CHECKSIGVERIFY, before any separator ran.
      { input: 0, why: "first CHECKSIGVERIFY: no separator has executed, the whole script is hashed", sigs: [[["key", 0], ["ss", 1]]] },
      { input: 0, why: "second CHECKSIGVERIFY: hashed from the separator that executed before it", sigs: [[["key", 1], ["ss", 0]]] },
    ] },
  { file: "tx_valid.json", txid: "a955032f4d6b0c9bfe8cad8f00a8933790b9c1dc28c82e0f48e75b35da0e4944", nth: 1, anchor: "unexecuted IF block does not change what is hashed",
    checks: [{ input: 0, why: "IF not taken: the separator inside it never runs", sigs: [[["key", 0], ["ss", 0]]] }] },
  { file: "tx_valid.json", txid: "a955032f4d6b0c9bfe8cad8f00a8933790b9c1dc28c82e0f48e75b35da0e4944", nth: 2, anchor: "with the IF block executed",
    checks: [{ input: 0, why: "IF taken: hashed from the separator inside it", sigs: [[["key", 0], ["ss", 0]]] }] },
  // --- tx_valid.json: FindAndDelete, the SIGHASH_SINGLE bug, hash type 0, high S
  { file: "tx_valid.json", txid: "cf016927962ec028964c186043d48e465b3d4672f758953b00d3c4682f71cad6", nth: 0, anchor: "shortest valid DER encoded signature",
    checks: [{ input: 0, why: "the redeem script pushes its own signature (r=1, s=1); FindAndDelete removes it before hashing", sigs: [[["ss", 0], ["hex", "300602010102010101"]]] }] },
  { file: "tx_valid.json", txid: "406b2b06bcd34d3c8733e6b79f7a394c8a431fbf4ff5ac705c93f4076bb77602", nth: 0, anchor: "SIGHASH type 0",
    checks: [{ input: 0, why: "hash type 0 is committed to as 0, and the signature is high-S (LOW_S is policy)", sigs: [[["ss", 1], ["ss", 0]]] }] },
  { file: "tx_valid.json", txid: "f18783ace138abac5d3a7a5cf08e88fe6912f267ef936452e0c27d090621c169", nth: 0, anchor: "correct sighash (with FindAndDelete)",
    checks: [{ input: 0, why: "P2SH redeem script CHECKSIGVERIFY <sig>: FindAndDelete removes the signature", sigs: [[["ss", 1], ["ss", 0]]] }] },
  { file: "tx_valid.json", txid: "f18783ace138abac5d3a7a5cf08e88fe6912f267ef936452e0c27d090621c169", nth: 1, anchor: "correct sighash (without FindAndDelete)",
    checks: [{ input: 0, why: "the same script as P2WSH: BIP143 does not FindAndDelete", sigs: [[["wit", 1], ["wit", 0]]] }] },
  { file: "tx_valid.json", txid: "9628667ad48219a169b41b020800162287d2c0f713c04157e95c484a8dcb7592", nth: 0, anchor: "correct sighash (with FindAndDelete)",
    // 0 <sig1> <sig2> 2 <key1> <key2> | 2 CHECKMULTISIGVERIFY: sig2 meets key2 first, then sig1 key1.
    checks: [{ input: 0, why: "CHECKMULTISIG removes every signature it is given from the scriptCode", sigs: [[["ss", 4], ["ss", 1]], [["ss", 5], ["ss", 2]]] }] },
  { file: "tx_valid.json", txid: "9628667ad48219a169b41b020800162287d2c0f713c04157e95c484a8dcb7592", nth: 1, anchor: "correct sighash (without FindAndDelete)",
    checks: [{ input: 0, why: "the same multisig as P2WSH: nothing is removed", sigs: [[["wit", 4], ["wit", 1]], [["wit", 5], ["wit", 2]]] }] },
  { file: "tx_valid.json", txid: "b5b598de91787439afd5938116654e0b16b7a0d0f82742ba37564219c5afcbf9", nth: 0, anchor: "within a P2SH redeemScript",
    // 0 <sigA> <sigB> | 2 <sigA> <K> <K> 3 CHECKMULTISIG: sigB meets K first; sigA (SINGLE, input 1 of 1 output) the second K.
    checks: [
      { input: 0, why: "plain P2PKH", sigs: [[["ss", 1], ["ss", 0]]] },
      { input: 1, why: "the redeem script embeds the other signature; CHECKMULTISIG removes it, then this one verifies", sigs: [[["key", 1], ["ss", 2]]] },
      { input: 1, why: "SIGHASH_SINGLE past the last output signs the digest 1", sigs: [[["key", 1], ["ss", 1]]] },
    ] },
  { file: "tx_valid.json", txid: "ceafe58e0f6e7d67c0409fbbf673c84c166e3c5d3c24af58f7175b18df3bb3db", nth: 0, anchor: "bare CHECKMULTISIG",
    checks: [
      { input: 0, why: "plain P2PKH", sigs: [[["ss", 1], ["ss", 0]]] },
      { input: 1, why: "bare multisig, SIGHASH_SINGLE bug signature also embedded in the script", sigs: [[["key", 0], ["ss", 1]]] },
    ] },
  // --- tx_valid.json: BIP143 examples
  { file: "tx_valid.json", txid: "6eb316926b1c5d567cd6f5e6a84fec606fc53d7b474526d1fff3948020c93dfe", nth: 0, anchor: "P2WSH with OP_CODESEPARATOR and out-of-range SIGHASH_SINGLE",
    // witness <sigB> <sigA> <K1 CHECKSIGVERIFY CODESEPARATOR K2 CHECKSIG>: sigA meets K1.
    checks: [
      { input: 0, why: "P2PK", sigs: [[["key", 0], ["ss", 0]]] },
      { input: 1, why: "BIP143 first CHECKSIGVERIFY: the whole witness script, separator included", sigs: [[["key", 0], ["wit", 1]]] },
      { input: 1, why: "BIP143 CHECKSIG after the separator: hashed from the separator", sigs: [[["key", 1], ["wit", 0]]] },
    ] },
  { file: "tx_valid.json", txid: "01c0cf7fba650638e55eb91261b183251fbb466f90dff17f10086817c542b5e9", nth: 0, anchor: "unexecuted OP_CODESEPARATOR and SINGLE|ANYONECANPAY",
    checks: [
      { input: 0, why: "0 IF CODESEPARATOR ENDIF: not taken, the whole witness script is hashed", sigs: [[["key", 0], ["wit", 0]]] },
      { input: 1, why: "1 IF CODESEPARATOR ENDIF: taken, hashed from the separator", sigs: [[["key", 0], ["wit", 0]]] },
    ] },
  { file: "tx_valid.json", txid: "1b2a9a426ba603ba357ce7773cb5805cb9c7c2b386d100d1fc9263513188e680", nth: 0, anchor: "input-output pairs swapped",
    checks: [
      { input: 0, why: "separator taken, other input order", sigs: [[["key", 0], ["wit", 0]]] },
      { input: 1, why: "separator not taken, other input order", sigs: [[["key", 0], ["wit", 0]]] },
    ] },
  { file: "tx_valid.json", txid: "6eb98797a21c6c10aa74edf29d618be109f48a8e94c694f3701e08ca69186436", nth: 0, anchor: "6 different SIGHASH types",
    checks: [{ input: 0, why: "6-of-6: signature n meets key n", sigs: [1, 2, 3, 4, 5, 6].map((n) => [["key", n - 1], ["wit", n]]) }] },
  // --- tx_invalid.json: the annotated signature does not verify
  { file: "tx_invalid.json", txid: "0000000000000000000000000000000000000000000000000000000000000100", nth: 0, anchor: "same pushdata prefix as is standard",
    checks: [{ input: 0, expect: "invalid", why: "the embedded copy uses a non-standard push, so FindAndDelete leaves it in the scriptCode", sigs: [[["ss", 1], ["ss", 0]]] }] },
  { file: "tx_invalid.json", txid: "0000000000000000000000000000000000000000000000000000000000000100", nth: 2, anchor: "including the hash type, matches",
    checks: [{ input: 0, expect: "invalid", why: "the embedded copy has another hash type byte, so FindAndDelete leaves it", sigs: [[["ss", 1], ["ss", 0]]] }] },
  { file: "tx_invalid.json", txid: "f18783ace138abac5d3a7a5cf08e88fe6912f267ef936452e0c27d090621c169", nth: 0, anchor: "wrong sighash (without FindAndDelete)",
    checks: [{ input: 0, expect: "invalid", why: "the key was recovered from the digest without FindAndDelete", sigs: [[["ss", 1], ["ss", 0]]] }] },
  { file: "tx_invalid.json", txid: "f18783ace138abac5d3a7a5cf08e88fe6912f267ef936452e0c27d090621c169", nth: 1, anchor: "wrong sighash (with FindAndDelete)",
    checks: [{ input: 0, expect: "invalid", why: "P2WSH key recovered from a FindAndDelete digest; BIP143 never removes", sigs: [[["wit", 1], ["wit", 0]]] }] },
  { file: "tx_invalid.json", txid: "9628667ad48219a169b41b020800162287d2c0f713c04157e95c484a8dcb7592", nth: 0, anchor: "wrong sighash (without FindAndDelete)",
    checks: [{ input: 0, expect: "invalid", why: "multisig keys recovered without FindAndDelete", sigs: [[["ss", 4], ["ss", 1]], [["ss", 5], ["ss", 2]]] }] },
  { file: "tx_invalid.json", txid: "9628667ad48219a169b41b020800162287d2c0f713c04157e95c484a8dcb7592", nth: 1, anchor: "wrong sighash (with FindAndDelete)",
    checks: [{ input: 0, expect: "invalid", why: "P2WSH multisig keys recovered from a FindAndDelete digest", sigs: [[["wit", 4], ["wit", 1]], [["wit", 5], ["wit", 2]]] }] },
];

const cases = CASES.map(({ file, txid, nth, anchor, checks }) => {
  const { entry, comments } = find(file, txid, nth, anchor);
  const [prevouts, tx] = entry;
  const inputs = parseTx(tx);
  return {
    source: `${file} (${txid.slice(0, 16)}…, occurrence ${nth})`,
    comment: comments.join(" "),
    tx,
    prevouts: prevouts.map(([id, vout, notation, amount]) => ({ txid: id, vout, scriptPubKey: assemble(notation), amount: amount ?? 0 })),
    checks: checks.map(({ input, expect = "valid", why, sigs }) => {
      const spk = assemble(prevouts[input][2]);
      const scriptSig = pushes(inputs[input].scriptSig);
      const witness = inputs[input].witness.map((item) => Buffer.from(item).toString("hex"));
      const isP2sh = /^a914[0-9a-f]{40}87$/.test(spk);
      const redeemScript = isP2sh ? scriptSig[scriptSig.length - 1] : undefined;
      const program = isP2sh ? redeemScript : spk;
      const isP2wsh = /^0020[0-9a-f]{64}$/.test(program);
      const witnessScript = isP2wsh ? witness[witness.length - 1] : undefined;
      const signing = witnessScript ?? redeemScript ?? spk;
      const item = ([from, n]) => (from === "ss" ? scriptSig[n] : from === "wit" ? witness[n] : from === "hex" ? n : keysIn(signing)[n]);
      const partialSigs = sigs.map(([key, sig]) => {
        const [pubkey, signature] = [item(key), item(sig)];
        if (!pubkey || !signature) throw new Error(`${txid}: unresolved pairing ${JSON.stringify([key, sig])}`);
        return { pubkey, signature };
      });
      return { input, expect, why, ...(redeemScript && { redeemScript }), ...(witnessScript && { witnessScript }), partialSigs };
    }),
  };
});

const out = {
  about: "Bitcoin Core tx_valid/tx_invalid vectors that pin the ECDSA scriptCode rules; written by extract.mjs, do not edit by hand.",
  source: { ...SOURCE, sha256: Object.fromEntries(Object.entries(files).map(([name, text]) => [name, createHash("sha256").update(text).digest("hex")])) },
  cases,
};
const target = join(dirname(fileURLToPath(import.meta.url)), "tx-scriptcode-vectors.json");
writeFileSync(target, `${JSON.stringify(out, null, 2)}\n`);
console.log(`wrote ${cases.length} vectors, ${cases.reduce((n, c) => n + c.checks.length, 0)} checks to ${target}`);
