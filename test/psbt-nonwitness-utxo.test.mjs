// Issue #350: the inspector's fee must not rest on witness-UTXO claims alone.
// A non-witness UTXO embeds the previous transaction, so its txid is checked
// against the input's outpoint and its amount read from the transaction's own
// output; the two declarations are resolved as a set and a disagreement is
// flagged instead of summed.
// Run with `npm test` (part of the default suite).
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { parseRawTx, serializeTx } from "../src/js/tx.js";
import { sha256 } from "../src/js/hashes.js";
import { secp256k1 } from "../src/js/secp256k1.js";
import { psbtInspectDoc } from "../src/js/psbt-wasm.js";

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

const hodlEq = new Function(`${loadSlice("hodlEq")}; return hodlEq;`)();
const hodlFind = new Function(`${loadSlice("hodlFind")}; return hodlFind;`)();
const hodlNonWitUtxo = new Function(
  "hodlFind",
  "parseRawTx",
  "hodlSha256",
  "hodlEq",
  "serializeTx",
  `${loadSlice("hodlNonWitUtxo")}; return hodlNonWitUtxo;`,
)(hodlFind, parseRawTx, sha256, hodlEq, serializeTx);

// A minimal previous transaction paying `sats` to `script` on output `vout`.
const le32 = (n) => new Uint8Array(new Uint32Array([n >>> 0]).buffer);
const le64 = (n) => new Uint8Array(new BigUint64Array([BigInt(n)]).buffer);
const prevTx = (sats, script = [0x51]) =>
  new Uint8Array([
    ...le32(2), 1, ...new Uint8Array(32), ...le32(0xffffffff), 0, ...le32(0xffffffff),
    1, ...le64(sats), script.length, ...script,
    ...le32(0),
  ]);
// The same transaction witness-serialized (BIP-144 marker/flag plus a
// one-item stack): legal inside a non-witness UTXO and common from non-Core
// wallets. Its fields are identical to prevTx's, so prevTx(sats, script) is
// exactly its witness-stripped form.
const segwitPrevTx = (sats, script = [0x51]) =>
  new Uint8Array([
    ...le32(2), 0, 1,
    1, ...new Uint8Array(32), ...le32(0xffffffff), 0, ...le32(0xffffffff),
    1, ...le64(sats), script.length, ...script,
    1, 1, 0x10,
    ...le32(0),
  ]);
const txidOf = (bytes) => createHash("sha256").update(createHash("sha256").update(bytes).digest()).digest();
const entry = (type, val) => ({ type, keydata: new Uint8Array(0), val });

test("a non-witness UTXO resolves to its own embedded output's amount", () => {
  const prev = prevTx(42000);
  const input = { txid: new Uint8Array(txidOf(prev)), vout: 0 };
  const claim = hodlNonWitUtxo([entry(0, prev)], input);
  assert.equal(claim.amount, 42000n);
  assert.deepEqual([...claim.script], [0x51]);
  // No type-0 entry, no claim.
  assert.equal(hodlNonWitUtxo([], input), null);
});

test("a non-witness UTXO whose txid differs from the spent outpoint claims nothing (issue #350)", () => {
  const prev = prevTx(42000);
  const other = prevTx(1);
  const input = { txid: new Uint8Array(txidOf(other)), vout: 0 };
  assert.throws(() => hodlNonWitUtxo([entry(0, prev)], input), /does not match the input's previous output/);
});

test("a non-witness UTXO missing the spent output claims nothing", () => {
  const prev = prevTx(42000);
  const input = { txid: new Uint8Array(txidOf(prev)), vout: 3 };
  assert.throws(() => hodlNonWitUtxo([entry(0, prev)], input), /does not contain the spent output/);
});

test("a witness-serialized non-witness UTXO matches by txid, never by wtxid (issue #350)", () => {
  const prev = segwitPrevTx(42000);
  const stripped = prevTx(42000);
  // The two serializations hash differently: hashing the raw bytes is the wtxid.
  assert.notDeepEqual(txidOf(prev), txidOf(stripped));
  assert.deepEqual(parseRawTx(prev).segwit, true);
  // The outpoint names the txid, so the witness-carrying field verifies…
  const input = { txid: new Uint8Array(txidOf(stripped)), vout: 0 };
  const claim = hodlNonWitUtxo([entry(0, prev)], input);
  assert.equal(claim.amount, 42000n);
  assert.deepEqual([...claim.script], [0x51]);
  // …and a field whose bytes only hash to the outpoint with the witness
  // included is the lie the check exists to catch.
  const byWtxid = { txid: new Uint8Array(txidOf(prev)), vout: 0 };
  assert.throws(() => hodlNonWitUtxo([entry(0, prev)], byWtxid), /does not match the input's previous output/);
});

// The reference-layer cross-check behind the inspector's validity banner
// (audit C3-6): the JS parser is throw-or-render, so a file that is invalid
// per BIP-174 but structurally readable used to render as an ordinary report.
const hodlPsbtReferenceVerdict = new Function(
  "psbtInspectDoc",
  `${loadSlice("hodlPsbtReferenceVerdict")}; return hodlPsbtReferenceVerdict;`,
)(psbtInspectDoc);

// A crafted file can evict every error from the reference crate's problem
// list: the list caps at 64 entries in collection order while the severity
// counts are taken before truncation (the producer's pinned fixture is
// test/psbt-wasm.test.mjs's "a truncated problem list still reports its true
// severity totals"). `warningSigs` junk partial signatures on input 0
// (warning-severity, collected first) pad the list; `badWitnesses` further
// inputs each carry a malformed final witness for a P2WPKH claim
// (error-severity, collected last).
const evictionFixture = (warningSigs, badWitnesses) => {
  const vi = (n) => (n < 0xfd ? [n] : [0xfd, n & 0xff, n >> 8]);
  const bytes = [];
  const push = (...chunks) => { for (const chunk of chunks.flat(2)) bytes.push(chunk); };
  // Unsigned transaction: 1 + badWitnesses inputs, one 1000-sat OP_TRUE output.
  const tx = [2, 0, 0, 0, 1 + badWitnesses];
  for (let i = 1 + badWitnesses; i > 0; i--) tx.push(...new Array(32).fill(0xa0 + i), 0, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff);
  tx.push(1, 0xe8, 0x03, 0, 0, 0, 0, 0, 0, 1, 0x51, 0, 0, 0, 0);
  push([0x70, 0x73, 0x62, 0x74, 0xff], [0x01, 0x00], vi(tx.length), tx, 0x00);
  const witnessUtxo = (fill) => [0x50, 0xc3, 0, 0, 0, 0, 0, 0, 0x16, 0x00, 0x14, ...new Array(20).fill(fill)];
  // Input 0's map: the witness-UTXO claim plus well-formed partial
  // signatures under distinct *valid* junk keys (small scalar multiples, so
  // rust-bitcoin parses the file and the severities are left to the
  // signature check, which fails them as warnings).
  push(vi(1), [0x01], vi(31), witnessUtxo(0x11));
  for (let i = 0; i < warningSigs; i++) {
    const priv = new Uint8Array(32);
    priv[30] = (i >> 8) & 0xff;
    priv[31] = 1 + (i & 0xff);
    push(vi(34), [0x02, ...secp256k1.getPublicKey(priv, true)], vi(9), [0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x01]);
  }
  push(0x00);
  // One input per error: same claim shape, plus a three-item final witness.
  const badWitness = [0x03, 0x01, 0xaa, 0x01, 0xbb, 0x01, 0xcc];
  for (let input = 1; input <= badWitnesses; input++) {
    push(vi(1), [0x01], vi(31), witnessUtxo(0x20 + input));
    push(vi(1), [0x08], vi(badWitness.length), badWitness, 0x00);
  }
  push(0x00); // the one output's (empty) map
  return Uint8Array.from(bytes);
};

test("truncation-evicted errors still fail the reference cross-check (audit C2-C)", () => {
  const raw = evictionFixture(65, 1);
  // The doc is the pinned attack shape: the kept list is warnings-only while
  // an error sits behind the display cap. The cross-check verdict must read
  // the pre-truncation errorCount, not the truncated list, or the banner
  // and the report's cross-check row read as clean.
  const doc = psbtInspectDoc(raw);
  assert.equal(doc.problemsTruncated, true);
  assert.ok(doc.problems.every((problem) => problem.severity === "warning"), "the kept entries are all warnings");
  assert.equal(doc.errorCount, 1);
  assert.equal(doc.problemCount, 66);
  const verdict = hodlPsbtReferenceVerdict({ raw });
  assert.equal(verdict.state, "problem");
  assert.deepEqual(verdict.problems.length, 1, "evicted errors surface as a named row, not silence");
  assert.match(verdict.problems[0], /1 error-severity problem\(s\) hidden by the .*display cap/);
  assert.equal(verdict.unlisted, 0, "the placeholder names the hidden errors, so they are not counted twice");
});

test("an error that survived the cap is listed and the evicted one stays counted (audit C2-C)", () => {
  const raw = evictionFixture(63, 2);
  const doc = psbtInspectDoc(raw);
  assert.equal(doc.problemsTruncated, true);
  assert.equal(doc.errorCount, 2);
  assert.equal(doc.problems.filter((problem) => problem.severity === "error").length, 1, "one error survived the cap");
  const verdict = hodlPsbtReferenceVerdict({ raw });
  assert.equal(verdict.state, "problem");
  assert.equal(verdict.unlisted, 1, "the evicted error is counted for the banner's continuation line");
  assert.ok(verdict.problems.some((problem) => /final witness/.test(problem)), "the surviving error is listed");
  assert.ok(!verdict.problems.some((problem) => /display cap/.test(problem)), "listed errors need no placeholder");
});

test("the reference cross-check flags a BIP-174-invalid file the JS parser renders (audit C3-6)", () => {
  const varint = (n) => (n < 0xfd ? [n] : [0xfd, n & 0xff, n >> 8]);
  const psbtOf = (outpointTxid, nonWitness) => {
    const unsigned = [
      ...le32(2), 1, ...outpointTxid, ...le32(0), 0, ...le32(0xffffffff),
      1, ...le64(1000), 1, 0x51,
      ...le32(0),
    ];
    return new Uint8Array([
      0x70, 0x73, 0x62, 0x74, 0xff,
      1, 0, ...varint(unsigned.length), ...unsigned, 0,
      1, 0, ...varint(nonWitness.length), ...nonWitness, 0,
      0, // the one output's (empty) map
    ]);
  };
  const prev = prevTx(42000);
  // The non-witness UTXO's txid does not match the spent outpoint: BIP-174
  // makes that an invalid PSBT (its first signer check fails).
  const invalid = psbtOf(new Uint8Array(32).fill(0x11), prev);
  const verdict = hodlPsbtReferenceVerdict({ raw: invalid });
  assert.equal(verdict.state, "problem");
  assert.ok(verdict.problems.some((problem) => /txid|previous output/i.test(problem)), verdict.problems.join(" | "));
  // The same file with a matching claim cross-checks clean.
  const valid = psbtOf(new Uint8Array(txidOf(prev)), prev);
  assert.equal(hodlPsbtReferenceVerdict({ raw: valid }).state, "complete");
});

test("the report resolves claims as a set and flags conflicts (issue #350)", () => {
  // The wiring in hodlRenderPsbt: both declaration kinds read per input, the
  // verified non-witness claim preferred, disagreement routed to a conflict
  // list that voids the fee.
  assert.match(app, /nonWitnessUtxo = hodlNonWitUtxo\(entries, tx\.inputs\[index\]\)/);
  assert.match(app, /witnessUtxo\.amount === nonWitnessUtxo\.amount/);
  assert.match(app, /conflictedInputs\.push\(index\)/);
  assert.match(app, /Fee unknown<\/strong> — input\(s\) /);
  assert.match(app, /Conflicting previous-output claims:/);
  // The disclaimer must no longer claim non-witness amounts go unchecked.
  assert.match(app, /non-witness UTXO amounts are cross-checked against the embedded previous transaction/);
  assert.doesNotMatch(app, /does not check them against previous transactions or the blockchain/);
});
