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
import { parseRawTx } from "../src/js/tx.js";
import { sha256 } from "../src/js/hashes.js";

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
  `${loadSlice("hodlNonWitUtxo")}; return hodlNonWitUtxo;`,
)(hodlFind, parseRawTx, sha256, hodlEq);

// A minimal previous transaction paying `sats` to `script` on output `vout`.
const le32 = (n) => new Uint8Array(new Uint32Array([n >>> 0]).buffer);
const le64 = (n) => new Uint8Array(new BigUint64Array([BigInt(n)]).buffer);
const prevTx = (sats, script = [0x51]) =>
  new Uint8Array([
    ...le32(2), 1, ...new Uint8Array(32), ...le32(0xffffffff), 0, ...le32(0xffffffff),
    1, ...le64(sats), script.length, ...script,
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
