// Seeded fuzzing of the PSBT editor's input/output editing path
// (src/js/psbt-editor.js driving src/js/psbt-wasm.js).
//
// Where psbt-editor-tx.test.mjs pins the fixed happy paths of the Add input /
// Add output controls and the row delete buttons, this suite sweeps the space
// around them: a deterministic PRNG walks random operation sequences over the
// committed PSBT fixtures — adding and deleting inputs and outputs, typing
// valid and adversarial text into their fields (txid, vout, sequence, value,
// scriptPubKey, version, locktime), and adding and removing key-value pairs —
// each step pushed through the exact functions the editor calls
// (psbtEditorBuildDoc -> psbtBuildBytes -> psbtInspectDoc), with the edit
// semantics mirrored from the handlers, rebuild() included:
//
//   - structural edits (add/delete element, add/delete pair) apply to a clone
//     and are kept only when rust-bitcoin accepts the rebuild — the editor's
//     mutate() backup/restore;
//   - field edits write the trimmed text into the document and live-rebuild,
//     keeping the typed text when the build fails (typing never loses state);
//   - any edit that changes the transaction section drops the signing pairs
//     first (the real dropSigningPairs, issues #325/#360): a rebuilt PSBT must
//     never look signed with stale material.
//
// The walk stays on PSBT v0 documents (the fixtures are v0; v2 conversion via
// the version pair is covered by psbt-v2.test.mjs).
//
// Oracles checked on every step:
//
//   Safety:  a rejected build throws a clean Error with a message — never a
//            WebAssembly.RuntimeError (a Rust panic escaping the boundary) —
//            and the WASM instance is proven healthy after every rejection by
//            rebuilding a known-good fixture. A rejected structural edit
//            leaves the working document byte-identical; a rejected field
//            edit keeps the typed text and changes nothing else (beyond the
//            signing-pair drop the editor itself performs); a document whose
//            fields do not build blocks structural edits exactly like the
//            editor's mutate() does, unless the edit removes the poisoned
//            element; and any invalid field can always be repaired by typing
//            a valid value again.
//   Correct: every accepted build starts with the psbt\xff magic, inspects
//            back, and is a byte-exact fixpoint — build ∘ inspect = id (the
//            build gate's consensus check keeps every accepted amount below
//            MAX_MONEY, so the JSON number round-trip is always exact). Adds
//            append the documented default slot with an empty key-value map;
//            deletes keep every surviving element in order WITH its map
//            (minus dropped signing pairs); the unsigned-transaction pair is
//            always regenerated as the first global pair; valid numeric text
//            normalizes ("007" -> 7, "+5" -> 5) and hex to lowercase. The
//            boundary rejects what the UI guards against: zero inputs, zero
//            outputs, and amounts past MAX_MONEY all fail with clean errors.
//
// The seed below is fixed, so a failure reproduces exactly; the assertion
// messages name the failing iteration and operation. Never reseed from the
// clock — a red run must reproduce byte-for-byte.
//
// Run with `npm test` (part of the default suite).
import { test } from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { psbtEditorBuildDoc, dropSigningPairs } from "../src/js/psbt-editor.js";
import { psbtBuildBytes, psbtInspectDoc } from "../src/js/psbt-wasm.js";

const root = dirname(dirname(fileURLToPath(import.meta.url)));

// Every committed PSBT fixture is a fuzz base — except no-outputs.b64: the
// build gate's consensus check rejects a zero-output transaction, so that
// fixture is loadable but not rebuildable (pinned in a guard below).
const fixtureDoc = (name) =>
  psbtInspectDoc(Uint8Array.from(atob(readFileSync(join(root, "test/fixtures/psbt", name), "utf8").trim()), (char) => char.charCodeAt(0)));
const NON_REBUILDABLE = new Set(["no-outputs.b64"]);
const FIXTURES = readdirSync(join(root, "test/fixtures/psbt"))
  .filter((name) => name.endsWith(".b64") && !NON_REBUILDABLE.has(name))
  .sort()
  .map((name) => ({ name, doc: fixtureDoc(name) }));
assert.ok(FIXTURES.length >= 8, `expected the committed PSBT fixtures, found ${FIXTURES.length}`);
const HEALTHY = FIXTURES.find((fixture) => fixture.name === "p2wpkh-1in-2out.b64");

// --- deterministic randomness (same fixed-seed policy as wallet-export-fuzz) --
const FUZZ_SEED = 0x5eed0240;
const ITERATIONS = 240;
const mulberry32 = (seed) => {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
};
const rand = mulberry32(FUZZ_SEED);
const rint = (n) => Math.floor(rand() * n);
const pick = (items) => items[rint(items.length)];
const chance = (p) => rand() < p;
const randomHex = (chars) => Array.from({ length: chars }, () => "0123456789abcdef"[rint(16)]).join("");

// --- coverage + volume accounting (the non-vacuity guards live at the end) ---
const flavors = new Map();
const note = (flavor) => flavors.set(flavor, (flavors.get(flavor) ?? 0) + 1);
const counts = { builds: 0, rejections: 0, fixpoints: 0, health: 0 };

// --- the rebuild pipeline with the oracles every accepted build must satisfy -
const PSBT_MAGIC = [0x70, 0x73, 0x62, 0x74, 0xff];
const bytesEqual = (a, b) => a.length === b.length && a.every((byte, index) => byte === b[index]);
const MAX_MONEY = 2_100_000_000_000_000n;
const U32_MAX = 4294967295n, U64_MAX = 18446744073709551615n, I32_MIN = -2147483648n, I32_MAX = 2147483647n;

// One editor rebuild step: build the draft document, decode the result, and
// prove the decode rebuilds to the same bytes (twice, so a non-fixpoint can
// never hide behind a single re-decode). Throws the boundary's Error when the
// draft does not build; any assertion failure inside is an oracle violation
// and must never be swallowed as a "rejection" by the callers.
const rebuildPipeline = (draft, label) => {
  const bytes1 = psbtBuildBytes(psbtEditorBuildDoc(draft));
  counts.builds += 1;
  for (const [index, byte] of PSBT_MAGIC.entries()) assert.equal(bytes1[index], byte, `${label}: built PSBT lost its magic`);
  const fresh1 = psbtInspectDoc(bytes1); // a build the inspector cannot read back is a bug
  const bytes2 = psbtBuildBytes(psbtEditorBuildDoc(fresh1));
  const bytes3 = psbtBuildBytes(psbtEditorBuildDoc(psbtInspectDoc(bytes2)));
  assert.ok(bytesEqual(bytes1, bytes2), `${label}: build/inspect is not a fixpoint`);
  assert.ok(bytesEqual(bytes2, bytes3), `${label}: repeated build/inspect never stabilizes`);
  counts.fixpoints += 1;
  assert.equal(fresh1.inputs.length, fresh1.tx.inputs.length, `${label}: input maps misaligned with the transaction`);
  assert.equal(fresh1.outputs.length, fresh1.tx.outputs.length, `${label}: output maps misaligned with the transaction`);
  assert.equal(fresh1.globals[0]?.key, "00", `${label}: the unsigned-transaction pair was not regenerated first`);
  return { bytes: bytes1, fresh: fresh1 };
};

// AssertionErrors are oracle violations; anything else out of the boundary is
// an application-level rejection. The catchers below must never confuse them.
const isOracleFailure = (err) => err instanceof assert.AssertionError;

// The safety contract of a rejection: a plain Error with a message, never a
// WASM trap (a Rust panic crossing the boundary reads as "unreachable
// executed"); afterwards a known-good fixture must still build — an error
// must never leave the instance or its linear memory poisoned.
const cleanError = (err, label) => {
  assert.ok(err instanceof Error, `${label}: a non-Error escaped: ${String(err)}`);
  assert.ok(!(err instanceof WebAssembly.RuntimeError), `${label}: a WASM trap escaped the boundary: ${err.message}`);
  assert.ok(typeof err.message === "string" && err.message.length > 0, `${label}: rejection with an empty message`);
  assert.doesNotMatch(err.message, /unreachable executed|panicked at/i, `${label}: looks like a Rust panic: ${err.message}`);
};
const healthy = (label) => {
  try {
    psbtInspectDoc(psbtBuildBytes(psbtEditorBuildDoc(structuredClone(HEALTHY.doc))));
    counts.health += 1;
  } catch (err) {
    assert.fail(`${label}: the WASM instance is unhealthy after a rejection: ${err.message}`);
  }
};

// Runs the pipeline on a draft that must be ACCEPTED.
const mustBuild = (draft, label) => {
  try {
    return rebuildPipeline(draft, label);
  } catch (err) {
    if (isOracleFailure(err)) throw err;
    assert.fail(`${label}: a meant-valid edit was rejected: ${err.message}`);
  }
};

// Runs the pipeline on a draft that must be CLEANLY REJECTED.
const mustReject = (draft, label, pattern) => {
  let err = null;
  try {
    rebuildPipeline(draft, label);
  } catch (caught) {
    if (isOracleFailure(caught)) throw caught;
    err = caught;
  }
  assert.ok(err, `${label}: a meant-invalid edit built successfully`);
  cleanError(err, label);
  if (pattern) assert.match(err.message, pattern, `${label}: unexpected rejection`);
  counts.rejections += 1;
  healthy(label);
  return err;
};

// --- the edit semantics, mirrored from psbt-editor.js --------------------------
// state.anchor mirrors rebuild()'s pristineTx: the JSON of the transaction the
// current signing pairs commit to, refreshed after every successful build. Any
// rebuild with a changed transaction first drops the signing pairs (the real
// dropSigningPairs); mutate() applies it to the draft (a rejection restores
// them), liveRebuild() applies it to the working document (a rejection keeps
// them dropped).
const dropIfTxChanged = (state, doc) => {
  if (state.anchor !== null && JSON.stringify(doc.tx) !== state.anchor) {
    const dropped = dropSigningPairs(doc);
    if (dropped) note("ok:signing-pairs-dropped");
  }
};
const accept = (state, fresh) => {
  state.doc = fresh;
  state.poisoned = null;
  state.anchor = JSON.stringify(fresh.tx);
};

// Mirrors mutate(): the change applies to a clone and is kept only when
// rust-bitcoin accepts the rebuild; otherwise the working document is
// restored untouched. Returns { before, fresh } on acceptance, null on
// rejection. On a building document a structural edit must never be
// rejected; on a poisoned one it must bounce off and change nothing —
// unless the edit itself removed the poisoned element (deleting the input
// whose field does not build is exactly how a user recovers), in which case
// the document builds again and the poison is gone.
const mutate = (state, label, fn) => {
  const before = state.doc;
  const draft = structuredClone(before);
  fn(draft);
  dropIfTxChanged(state, draft);
  let fresh = null;
  try {
    ({ fresh } = rebuildPipeline(draft, label));
  } catch (err) {
    if (isOracleFailure(err)) throw err;
    assert.ok(state.poisoned, `${label}: a structural edit on a building document was rejected: ${err.message}`);
    cleanError(err, label);
    counts.rejections += 1;
    healthy(label);
    assert.deepEqual(state.doc, before, `${label}: a rejected structural edit changed the document`);
    note("reject:poisoned-blocks-structural");
    return null;
  }
  if (state.poisoned) note("poison-cleared-by-structural-edit");
  accept(state, fresh);
  return { before, fresh };
};

// Same, for a structural change that is meant to be rejected on its own
// (duplicate key, bad hex, zero inputs, …). On a poisoned document the
// rejection is the poisoned field's, so the specific message is only checked
// when the document otherwise builds.
const mutateExpectReject = (state, label, fn, pattern) => {
  const before = state.doc;
  const draft = structuredClone(before);
  fn(draft);
  dropIfTxChanged(state, draft);
  mustReject(draft, label, state.poisoned ? null : pattern);
  assert.deepEqual(state.doc, before, `${label}: a rejected structural edit changed the document`);
};

// Mirrors the input handlers: the trimmed text lands in the working document
// and a live rebuild is attempted; on rejection the typed text stays (the
// user is mid-edit) and every other field is untouched.
const writeField = (state, label, target, text) => {
  const stored = typeof text === "string" ? text.trim() : text;
  const before = state.doc;
  target.write(state.doc, stored);
  dropIfTxChanged(state, state.doc);
  const repairsPoison = state.poisoned && state.poisoned.kind === target.kind && state.poisoned.index === target.index;
  const valid = target.ok(stored, state.doc);
  const expectOk = repairsPoison ? valid : !state.poisoned && valid;
  let outcome = null;
  try {
    outcome = rebuildPipeline(state.doc, label);
  } catch (err) {
    if (isOracleFailure(err)) throw err;
    assert.ok(!expectOk, `${label}: ${target.name} rejected valid ${JSON.stringify(stored)}: ${err.message}`);
    cleanError(err, label);
    counts.rejections += 1;
    healthy(label);
    if (!state.poisoned) state.poisoned = { kind: target.kind, index: target.index };
    note(`reject:${target.kind}`);
    const expected = structuredClone(before);
    target.write(expected, stored);
    dropIfTxChanged(state, expected);
    assert.deepEqual(state.doc, expected, `${label}: a rejected field edit disturbed other fields`);
    return;
  }
  assert.ok(expectOk, `${label}: ${target.name} accepted ${JSON.stringify(stored)} — expected a rejection`);
  accept(state, outcome.fresh);
  assert.deepEqual(target.read(outcome.fresh), target.normalize(stored), `${label}: ${target.name} did not decode to its normalized form`);
  note(`field:${target.kind}:ok`);
  if (repairsPoison) note("repair-ok");
  if (typeof stored === "string" && stored !== text) note("normalize:trimmed");
  if (typeof stored === "string" && target.hex && /[A-F]/.test(stored)) note("normalize:case");
  if (typeof stored === "string" && /^0+\d|^\+/.test(stored)) note("normalize:leading-zeros-or-plus");
};

// --- field targets and their text pools --------------------------------------
// target.ok(text, doc) must EXACTLY predict the boundary's acceptance: when
// it mispredicts, the walk fails loudly — that is the fuzzer doing its job.

const integerText = (text) => /^[+-]?\d+$/.test(String(text));
const inRange = (text, min, max) => integerText(text) && BigInt(text) >= min && BigInt(text) <= max;
const asStoredNumber = (text) => Number(text); // the JSON decode shape for u32/i32 fields
// Amounts decode as decimal strings (exact past 2^53); the canonical form
// drops leading zeros and a leading plus.
const asStoredAmount = (text) => BigInt(String(text)).toString();

// The build gate's consensus check: every output amount is at most MAX_MONEY
// and so is their total (bad-txns-vout-toolarge / bad-txns-txouttotal-toolarge).
const valueOk = (text, doc, index) => {
  if (!inRange(text, 0n, U64_MAX)) return false;
  const value = BigInt(String(text));
  if (value > MAX_MONEY) return false;
  let total = value;
  for (const [at, output] of doc.tx.outputs.entries()) {
    if (at === index) continue;
    const sibling = String(output.value);
    if (!integerText(sibling)) continue; // a mid-edit poison on another field: the build rejects there anyway
    total += BigInt(sibling);
  }
  return total <= MAX_MONEY;
};

// …and prevouts must be unique (bad-txns-inputs-duplicate): an edit that
// points a second input at an existing outpoint is rejected. The candidate
// values are passed explicitly — the doc may still hold the invalid text the
// candidate would replace, so comparing against the doc's current value could
// never see the candidate (a repair loop would spin forever on it).
const outpointFree = (doc, index, txid, vout) => {
  const candidateTxid = String(txid).toLowerCase();
  if (!integerText(String(vout))) return true; // moot on an unbuildable doc
  const candidateVout = String(Number(BigInt(String(vout))));
  for (const [at, other] of doc.tx.inputs.entries()) {
    if (at === index || !integerText(String(other.vout))) continue; // a mid-edit poison compares as no duplicate
    if (String(other.txid).toLowerCase() === candidateTxid && String(Number(BigInt(String(other.vout)))) === candidateVout) return false;
  }
  return true;
};

const txidPool = [
  () => randomHex(64),
  () => randomHex(64).toUpperCase(),
  () => "0".repeat(64),
  () => "f".repeat(64),
  () => randomHex(pick([2, 62, 66])), // wrong length
  () => "zz" + randomHex(62), // non-hex
  () => "",
  () => "0x" + randomHex(64), // carries a prefix
  () => " " + randomHex(64) + "\t", // trims to valid
];
const u32Pool = [
  () => String(rint(4294967296)),
  () => pick(["0", "1", "4294967295"]),
  () => "007",
  () => "  " + String(rint(1000)) + " ", // trims to valid
  () => "+" + String(rint(1000)), // rust-bitcoin's parser accepts a leading plus
  () => rint(4294967296), // number-typed (the inspect output's own shape)
  () => String(4294967296 + rint(1000)), // too large
  () => pick(["-1", "", "1.5", "abc", "1e3", "0x10", "٧"]), // rejected
];
const satsPool = [
  () => String(rint(1_000_000_000_000)), // valid, leaves total headroom
  () => pick(["0", "1", "546", "100000000"]),
  () => "007",
  () => "2100000000000001", // past MAX_MONEY: consensus-invalid, clean rejection
  () => "18446744073709551615", // u64 max, same gate
  () => "18446744073709551616", // not even u64
  () => pick(["-1", "", "1.5", "abc", "1e3"]),
];
const scriptPool = [
  () => "",
  () => randomHex(2 * rint(40)),
  () => "0014" + randomHex(40),
  () => "6a" + randomHex(2 * rint(20)),
  () => "5120" + randomHex(64),
  () => "a914" + randomHex(40) + "87",
  () => ("0014" + randomHex(40)).toUpperCase(),
  () => randomHex(1 + 2 * rint(20)), // odd length
  () => "zz" + randomHex(8),
  () => "0x6a",
];
const versionPool = [
  () => pick(["0", "1", "2", "-1", "2147483647", "-2147483648"]),
  () => rint(3), // number-typed
  () => String(2147483648 + rint(1000)),
  () => "-2147483649",
  () => pick(["", "1.5", "abc"]),
];

const fieldTargets = (state) => {
  const targets = [];
  state.doc.tx.inputs.forEach((input, index) => {
    targets.push(
      {
        kind: "txid", index, name: `input ${index} txid`, hex: true, pool: txidPool,
        write: (doc, text) => { doc.tx.inputs[index].txid = text; },
        read: (doc) => doc.tx.inputs[index].txid,
        ok: (text, doc) => /^[0-9a-f]{64}$/i.test(String(text)) && outpointFree(doc, index, text, doc.tx.inputs[index].vout),
        normalize: (text) => String(text).toLowerCase(),
      },
      {
        kind: "vout", index, name: `input ${index} vout`, hex: false, pool: u32Pool,
        write: (doc, text) => { doc.tx.inputs[index].vout = text; },
        read: (doc) => doc.tx.inputs[index].vout,
        ok: (text, doc) => inRange(text, 0n, U32_MAX) && outpointFree(doc, index, doc.tx.inputs[index].txid, text),
        normalize: asStoredNumber,
      },
      {
        kind: "sequence", index, name: `input ${index} sequence`, hex: false, pool: u32Pool,
        write: (doc, text) => { doc.tx.inputs[index].sequence = text; },
        read: (doc) => doc.tx.inputs[index].sequence,
        ok: (text) => inRange(text, 0n, U32_MAX),
        normalize: asStoredNumber,
      },
    );
  });
  state.doc.tx.outputs.forEach((output, index) => {
    targets.push(
      {
        kind: "value", index, name: `output ${index} value`, hex: false, pool: satsPool,
        write: (doc, text) => { doc.tx.outputs[index].value = text; },
        read: (doc) => doc.tx.outputs[index].value,
        ok: (text, doc) => valueOk(text, doc, index),
        normalize: asStoredAmount,
      },
      {
        kind: "scriptPubKey", index, name: `output ${index} scriptPubKey`, hex: true, pool: scriptPool,
        write: (doc, text) => { doc.tx.outputs[index].scriptPubKey = text; },
        read: (doc) => doc.tx.outputs[index].scriptPubKey,
        ok: (text) => /^(?:[0-9a-f]{2})*$/i.test(String(text)),
        normalize: (text) => String(text).toLowerCase(),
      },
    );
  });
  targets.push(
    {
      kind: "version", index: undefined, name: "version", hex: false, pool: versionPool,
      write: (doc, text) => { doc.tx.version = text; },
      read: (doc) => doc.tx.version,
      ok: (text) => inRange(text, I32_MIN, I32_MAX),
      normalize: asStoredNumber,
    },
    {
      kind: "locktime", index: undefined, name: "locktime", hex: false, pool: u32Pool,
      write: (doc, text) => { doc.tx.locktime = text; },
      read: (doc) => doc.tx.locktime,
      ok: (text) => inRange(text, 0n, U32_MAX),
      normalize: asStoredNumber,
    },
  );
  return targets;
};

// --- structural handlers, mirrored from psbt-editor.js -------------------------

// Mirrors the [data-tx-add] click handler.
const addElement = (doc, kind) => {
  if (kind === "input") {
    doc.tx.inputs.push({ txid: "0".repeat(64), vout: 0, scriptSig: "", sequence: 4294967295 });
    doc.inputs.push([]);
  } else {
    doc.tx.outputs.push({ value: "0", scriptPubKey: "" });
    doc.outputs.push([]);
  }
};

// Mirrors the [data-txin-del] / [data-txout-del] click handlers.
const removeElement = (doc, kind, index) => {
  doc.tx[kind === "input" ? "inputs" : "outputs"].splice(index, 1);
  doc[kind === "input" ? "inputs" : "outputs"].splice(index, 1);
};

const txView = {
  input: (input) => ({ txid: input.txid, vout: input.vout, scriptSig: input.scriptSig, sequence: input.sequence }),
  output: (output) => ({ value: output.value, scriptPubKey: output.scriptPubKey }),
};
const pairsOf = (map) => map.map((pair) => [pair.key, pair.value]);
const mapListOf = (kind) => (kind === "global" ? "globals" : kind === "input" ? "inputs" : "outputs");
const mapAt = (doc, kind, index) => (kind === "global" ? doc.globals : doc[mapListOf(kind)][index]);
// A transaction-changing edit drops the signing pairs (rebuild()'s
// dropSigningPairs), so survivors of an add/delete keep their maps MINUS the
// transaction-committing types. Input maps only: the same type bytes are
// unrelated output-map fields (02 is PSBT_OUT_BIP32_DERIVATION there).
const SIGNING_TYPES = new Set(["02", "07", "08", "13", "14"]);
const expectedSurvivorPairs = (map, kind) => (kind === "input" ? pairsOf(map).filter(([key]) => !SIGNING_TYPES.has(key.slice(0, 2))) : pairsOf(map));

const MAX_ELEMENTS = 12; // bounded growth keeps the walk fast; alignment is scale-free

const addElementOp = (state, label, kind) => {
  const list = kind === "input" ? "inputs" : "outputs";
  if (state.doc.tx[list].length >= MAX_ELEMENTS) return;
  // A second Add input before the first one's txid is edited duplicates the
  // zero outpoint — the consensus gate rejects it cleanly and the working
  // document is kept (mutate() restores).
  if (kind === "input" && state.doc.tx.inputs.some((input) => input.txid === "0".repeat(64) && Number(input.vout) === 0)) {
    mutateExpectReject(state, label, (draft) => addElement(draft, "input"), /inputs-duplicate|consensus-invalid/);
    if (!state.poisoned) note("reject:duplicate-outpoint");
    return;
  }
  const applied = mutate(state, label, (draft) => addElement(draft, kind));
  if (!applied) return;
  const { before, fresh } = applied;
  const n = before.tx[list].length;
  assert.equal(fresh.tx[list].length, n + 1, `${label}: the added ${kind} is missing`);
  assert.equal(fresh[list].length, n + 1, `${label}: the added ${kind}'s key-value map is missing`);
  for (let index = 0; index < n; index++) {
    assert.deepEqual(txView[kind](fresh.tx[list][index]), txView[kind](before.tx[list][index]), `${label}: adding a ${kind} disturbed element ${index}`);
    assert.deepEqual(pairsOf(fresh[list][index]), expectedSurvivorPairs(before[list][index], kind), `${label}: adding a ${kind} disturbed map ${index}`);
  }
  const defaults = kind === "input" ? { txid: "0".repeat(64), vout: 0, scriptSig: "", sequence: 4294967295 } : { value: "0", scriptPubKey: "" };
  assert.deepEqual(txView[kind](fresh.tx[list][n]), defaults, `${label}: the added ${kind} is not the documented default`);
  assert.deepEqual(fresh[list][n], [], `${label}: the added ${kind}'s map is not empty`);
  note(`ok:add-${kind}`);
};

const deleteElementOp = (state, label, kind) => {
  const list = kind === "input" ? "inputs" : "outputs";
  // The UI withholds the delete control on the last input; the boundary's
  // rejection of a bypass is covered by zeroInputOp. The last OUTPUT keeps
  // its button — the consensus gate rejects that delete cleanly (probed
  // below), and the working document must survive untouched.
  if (state.doc.tx[list].length < (kind === "input" ? 2 : 1)) return;
  if (kind === "output" && state.doc.tx.outputs.length === 1) {
    mutateExpectReject(state, label, (draft) => removeElement(draft, "output", 0), /vout-empty|consensus-invalid/);
    if (!state.poisoned) note("reject:del-last-output");
    return;
  }
  const floor = 1;
  // Sometimes the user deletes rows one after another down to the floor.
  do {
    const index = rint(state.doc.tx[list].length);
    const applied = mutate(state, `${label} delete ${kind} ${index}`, (draft) => removeElement(draft, kind, index));
    if (!applied) return; // poisoned document: the delete bounced, covered by mutate()
    const { before, fresh } = applied;
    assert.equal(fresh.tx[list].length, before.tx[list].length - 1, `${label}: the ${kind} was not deleted`);
    assert.equal(fresh[list].length, fresh.tx[list].length, `${label}: maps misaligned after deleting ${kind} ${index}`);
    for (let at = 0; at < fresh.tx[list].length; at++) {
      const from = at < index ? at : at + 1;
      assert.deepEqual(txView[kind](fresh.tx[list][at]), txView[kind](before.tx[list][from]), `${label}: deleting ${kind} ${index} misaligned element ${at} (was ${from})`);
      assert.deepEqual(pairsOf(fresh[list][at]), expectedSurvivorPairs(before[list][from], kind), `${label}: deleting ${kind} ${index} lost the map of element ${from}`);
    }
    note(`ok:del-${kind}`);
    if (fresh.tx[list].length === floor) note(`ok:del-${kind}-to-floor`);
  } while (chance(0.25) && state.doc.tx[list].length > floor);
};

// --- pair operations -----------------------------------------------------------

let pairSerial = 0;
// Unique keydata per added pair keeps the must-succeed cases free of
// accidental duplicate keys.
const uniqueSerial = () => (pairSerial++).toString(16).padStart(8, "0");

const validPair = () => {
  const serial = uniqueSerial();
  if (chance(0.5)) {
    // A well-formed proprietary key: <prefix compactsize><prefix><subtype><keydata>.
    const prefix = [...`fz${serial}`].map((char) => char.charCodeAt(0).toString(16).padStart(2, "0")).join("");
    return { key: `fc${(prefix.length / 2).toString(16).padStart(2, "0")}${prefix}00${randomHex(2 * rint(8))}`, value: randomHex(2 * rint(40)), expect: "ok" };
  }
  // Unknown type bytes are stored raw by every implementation. Sometimes the
  // key or the value crosses a compact-size (252/253) length boundary.
  const key = pick(["30", "31", "77"]) + serial + randomHex(2 * rint(8));
  const value = chance(0.06) ? randomHex(2 * pick([252, 253, 254, 300])) : randomHex(2 * rint(40));
  return { key: chance(0.04) ? "30" + randomHex(2 * 250) + serial : key, value, expect: "ok" };
};

// Known type bytes with arbitrary byte shapes: rust-bitcoin parses several
// pair types during Psbt::deserialize (xpubs, partial signatures, derivation
// keys), so these either build or reject cleanly — both are fine, a trap or
// a hang is not. (Signing types 02/13 land in input maps; a later
// transaction edit drops them again — the drop is part of the model.)
const MAYFAIL_TYPES = { global: ["01"], input: ["00", "01", "02", "03", "06", "13", "15", "16"], output: ["00", "01", "02", "06"] };
const mayFailPair = (kind) => ({ key: pick(MAYFAIL_TYPES[kind]) + randomHex(2 * rint(34)), value: randomHex(2 * rint(60)), expect: "either" });

const addPairOp = (state, label) => {
  const kind = pick(["global", "input", "output"]);
  const list = mapListOf(kind);
  if (kind !== "global" && state.doc[list].length === 0) return; // no map to add to (zero outputs)
  const mapIndex = kind === "global" ? 0 : rint(state.doc[list].length);
  const pair = chance(0.6) ? validPair() : mayFailPair(kind);
  const before = state.doc;
  const draft = structuredClone(before);
  mapAt(draft, kind, mapIndex).push({ key: pair.key, value: pair.value });
  dropIfTxChanged(state, draft); // a no-op for pair adds (tx untouched); kept for symmetry with rebuild()
  if (state.poisoned) {
    mustReject(draft, label);
    assert.deepEqual(state.doc, before, `${label}: a rejected pair add changed the document`);
    note("reject:poisoned-blocks-structural");
    return;
  }
  if (pair.expect === "either") {
    let fresh = null;
    try {
      ({ fresh } = rebuildPipeline(draft, label));
    } catch (err) {
      if (isOracleFailure(err)) throw err;
      cleanError(err, label);
      counts.rejections += 1;
      healthy(label);
      note("reject:typed-pair");
      return;
    }
    accept(state, fresh);
    note("ok:typed-pair");
  } else {
    accept(state, mustBuild(draft, label).fresh);
    note("ok:add-pair");
  }
  assert.deepEqual(pairsOf(mapAt(state.doc, kind, mapIndex)), [...pairsOf(mapAt(before, kind, mapIndex)), [pair.key, pair.value]], `${label}: the added pair is not appended verbatim`);
};

const deletePairOp = (state, label) => {
  const candidates = [];
  if (state.doc.globals.length) candidates.push(["global", 0]);
  state.doc.inputs.forEach((map, index) => map.length && candidates.push(["input", index]));
  state.doc.outputs.forEach((map, index) => map.length && candidates.push(["output", index]));
  if (!candidates.length) return;
  const [kind, mapIndex] = pick(candidates);
  const map = mapAt(state.doc, kind, mapIndex);
  const pairIndex = rint(map.length);
  const removedKey = map[pairIndex].key;
  const applied = mutate(state, label, (draft) => mapAt(draft, kind, mapIndex).splice(pairIndex, 1));
  if (!applied) return;
  const { before, fresh } = applied;
  // The locked unsigned-transaction pair is regenerated by the build even
  // when the document drops it — deleting key 00 changes nothing.
  const expected =
    kind === "global" && removedKey === "00"
      ? pairsOf(mapAt(before, kind, mapIndex))
      : pairsOf(mapAt(before, kind, mapIndex)).filter((_, at) => at !== pairIndex);
  assert.deepEqual(pairsOf(mapAt(fresh, kind, mapIndex)), expected, `${label}: deleting pair ${pairIndex} misaligned its map`);
  note("ok:del-pair");
  if (kind === "global" && removedKey === "00") note("ok:del-unsigned-tx-pair");
};

const duplicatePairOp = (state, label) => {
  const candidates = [];
  if (state.doc.globals.length) candidates.push(["global", 0]);
  state.doc.inputs.forEach((map, index) => map.length && candidates.push(["input", index]));
  state.doc.outputs.forEach((map, index) => map.length && candidates.push(["output", index]));
  if (!candidates.length) {
    if (state.poisoned) return;
    addPairOp(state, `${label} (seeding a pair)`);
    return duplicatePairOp(state, label);
  }
  const [kind, mapIndex] = pick(candidates);
  const pair = mapAt(state.doc, kind, mapIndex)[0];
  mutateExpectReject(state, label, (draft) => mapAt(draft, kind, mapIndex).push({ key: pair.key, value: randomHex(2) }), /duplicate key/);
  if (!state.poisoned) note("reject:duplicate-key");
};

// Deliberately bypasses the add control's isHex pre-check: the boundary
// itself must reject bad hex cleanly (defense in depth).
const badHexPairOp = (state, label) => {
  const kind = pick(["global", "input", "output"]);
  const list = mapListOf(kind);
  if (kind !== "global" && state.doc[list].length === 0) return;
  const mapIndex = kind === "global" ? 0 : rint(state.doc[list].length);
  const pair = chance(0.5)
    ? { key: pick(["", "zz", "0", "0x30", randomHex(3)]), value: "" }
    : { key: "30aa", value: pick(["zz", "abc", "0x12"]) };
  mutateExpectReject(state, label, (draft) => mapAt(draft, kind, mapIndex).push(pair), /hex|type byte/);
  if (!state.poisoned) note("reject:pair-hex");
};

const globalVersionOp = (state, label) => {
  if (state.doc.globals.some((pair) => pair.key === "fb")) return; // one version pair only
  // v0 documents only: 02000000 would convert the document to PSBT v2 (a
  // different document shape; psbt-v2.test.mjs covers the v2 path).
  const variant = pick([
    { value: "00000000", ok: true },
    { value: "01000000", ok: false, pattern: /only PSBT v0 and v2/ },
    { value: "03000000", ok: false, pattern: /only PSBT v0 and v2/ },
    { value: "00", ok: false, pattern: /4-byte value/ },
    { value: "", ok: false, pattern: /4-byte value/ },
  ]);
  if (variant.ok) {
    const applied = mutate(state, label, (draft) => draft.globals.push({ key: "fb", value: variant.value }));
    if (!applied) return;
    assert.equal(applied.fresh.psbtVersion, 0, `${label}: a zero global version must stay v0`);
    assert.ok(applied.fresh.globals.some((pair) => pair.key === "fb"), `${label}: the version pair vanished`);
    note("ok:global-version");
    return;
  }
  mutateExpectReject(state, label, (draft) => draft.globals.push({ key: "fb", value: variant.value }), variant.pattern);
  if (!state.poisoned) note("reject:global-version");
};

// The UI withholds the delete control on the last input; bypassing it (a
// hand-edited document) must still be rejected cleanly by the build gate.
const zeroInputOp = (state, label) => {
  mutateExpectReject(state, label, (draft) => {
    draft.tx.inputs = [];
    draft.inputs = [];
  }, /vin-empty|consensus-invalid|does not parse/);
  if (!state.poisoned) note("reject:zero-input");
};

// Whole-document corruption, applied to a throwaway clone: the editor only
// ever holds inspector-produced documents, but the boundary must reject a
// malformed one cleanly (a console-poked object, a future schema change).
const CORRUPTIONS = [
  (draft) => { delete draft.tx; },
  (draft) => { draft.tx = []; },
  (draft) => { draft.tx.inputs = {}; },
  (draft) => { draft.globals = null; },
  (draft) => { draft.inputs = "x"; },
  (draft) => { draft.outputs = [7]; },
  (draft) => { draft.tx.outputs = [7]; },
  (draft) => { draft.globals = [{ key: 5, value: "" }]; },
];
const garbageDocOp = (state, label) => {
  const draft = structuredClone(state.doc);
  pick(CORRUPTIONS)(draft);
  mustReject(draft, label);
  note("reject:garbage-doc");
};

const fieldEditOp = (state, label) => {
  const targets = fieldTargets(state);
  const target = pick(targets);
  let text = pick(target.pool)();
  // While another field does not build, only valid text goes to the other
  // fields — a second poison would muddy the expectation; the typed text
  // still sticks and the rebuild still fails on the poisoned field.
  if (state.poisoned && (state.poisoned.kind !== target.kind || state.poisoned.index !== target.index)) {
    while (!target.ok(typeof text === "string" ? text.trim() : text, state.doc)) text = pick(target.pool)();
  }
  writeField(state, label, target, text);
};

// Typing a valid value over the invalid one must always recover — the live
// editor depends on it (its error state clears on the next good keystroke).
const repairOp = (state, label) => {
  const target = fieldTargets(state).find((t) => t.kind === state.poisoned.kind && t.index === state.poisoned.index);
  let text = pick(target.pool)();
  while (!target.ok(typeof text === "string" ? text.trim() : text, state.doc)) text = pick(target.pool)();
  writeField(state, label, target, text);
};

const OPS = [
  [4, (state, label) => addElementOp(state, label, "input")],
  [4, (state, label) => addElementOp(state, label, "output")],
  [2, (state, label) => deleteElementOp(state, label, "input")],
  [2, (state, label) => deleteElementOp(state, label, "output")],
  [8, fieldEditOp],
  [3, addPairOp],
  [2, deletePairOp],
  [1, duplicatePairOp],
  [1, badHexPairOp],
  [1, globalVersionOp],
  [1, zeroInputOp],
  [1, garbageDocOp],
];
const OP_BAG = OPS.flatMap(([weight, fn]) => Array.from({ length: weight }, () => fn));

test("seeded random walks: adding/removing inputs and outputs stays safe and correct", () => {
  for (let i = 0; i < ITERATIONS; i++) {
    const fixture = FIXTURES[i % FIXTURES.length];
    note(`fixture:${fixture.name}`);
    // The editor anchors the signing pairs to the loaded transaction; the
    // first edit that moves the transaction drops them.
    const state = { doc: structuredClone(fixture.doc), poisoned: null, anchor: JSON.stringify(fixture.doc.tx) };
    const opCount = 3 + rint(10);
    for (let j = 0; j < opCount; j++) {
      const label = `iteration ${i} (${fixture.name}) op ${j}`;
      // A field edit that left the document unbuildable is usually followed
      // by the repair keystroke — or by the user trying a structural edit
      // anyway, which must bounce off. Both are forced here so the walk
      // exercises them instead of wandering off.
      if (state.poisoned && chance(0.6)) {
        repairOp(state, label);
        continue;
      }
      if (state.poisoned && chance(0.43)) {
        pick([(s, l) => addElementOp(s, l, pick(["input", "output"])), (s, l) => deleteElementOp(s, l, pick(["input", "output"])), addPairOp, deletePairOp])(state, label);
        continue;
      }
      pick(OP_BAG)(state, label);
    }
    // Every walk ends on a building document: repair any poisoned field and
    // rebuild once more.
    if (state.poisoned) repairOp(state, `iteration ${i} (${fixture.name}) final repair`);
    mustBuild(structuredClone(state.doc), `iteration ${i} (${fixture.name}) final rebuild`);
    note("walk-complete");
  }
});

// --- deterministic guards: the properties above, proven without the PRNG -----

// Marker pairs must follow THEIR element across adds and deletes — the exact
// alignment property the editor's paired push/splice exists for. Signing
// pairs ride the drop instead: a transaction edit strips them on purpose.
test("key-value maps follow their elements across adds and deletes (marker walk)", () => {
  let doc = structuredClone(HEALTHY.doc);
  const state = { doc, poisoned: null, anchor: JSON.stringify(doc.tx) };
  const apply = (fn) => {
    const applied = mutate(state, "marker walk", fn);
    assert.ok(applied, "marker walk step rejected");
    return applied.fresh;
  };
  const pushPair = (kind, index, key, value) => apply((draft) => mapAt(draft, kind, index).push({ key, value }));

  // The fixture's own input map carries a partial signature (type 02).
  assert.ok(HEALTHY.doc.inputs[0].some((pair) => pair.key.startsWith("02")), "fixture lost its partial sig");
  pushPair("input", 0, "30aa000001", "01");
  pushPair("output", 1, "30bb000001", "02");
  let fresh = apply((draft) => addElement(draft, "input"));
  // The transaction changed: the partial sig is dropped, the markers stay.
  assert.ok(!fresh.inputs[0].some((pair) => pair.key.startsWith("02")), "the stale partial sig survived a transaction edit");
  assert.ok(fresh.inputs[0].some((pair) => pair.key === "30aa000001"), "the marker pair was dropped with it");
  pushPair("input", 1, "30aa000002", "03");
  fresh = apply((draft) => addElement(draft, "output"));
  pushPair("output", 2, "30bb000002", "04");
  assert.equal(fresh.tx.inputs.length, 2);
  assert.equal(fresh.tx.outputs.length, 3);

  // Deleting the original input moves the ADDED input — with its marker — to 0.
  const addedInputMap = pairsOf(fresh.inputs[1]);
  fresh = apply((draft) => removeElement(draft, "input", 0));
  assert.equal(fresh.tx.inputs.length, 1);
  assert.equal(fresh.tx.inputs[0].txid, "0".repeat(64), "the survivor is not the added input");
  assert.deepEqual(pairsOf(fresh.inputs[0]), addedInputMap, "the added input's map did not follow it");

  // Deleting original output 0 shifts the other outputs — with their maps.
  const survivingTx = [txView.output(fresh.tx.outputs[1]), txView.output(fresh.tx.outputs[2])];
  const survivingMaps = [pairsOf(fresh.outputs[1]), pairsOf(fresh.outputs[2])];
  fresh = apply((draft) => removeElement(draft, "output", 0));
  assert.equal(fresh.tx.outputs.length, 2);
  assert.deepEqual([txView.output(fresh.tx.outputs[0]), txView.output(fresh.tx.outputs[1])], survivingTx, "outputs misaligned by the delete");
  assert.deepEqual([pairsOf(fresh.outputs[0]), pairsOf(fresh.outputs[1])], survivingMaps, "output maps did not follow their outputs");
});

// The rejection contract, pinned value by value: every adversarial field text
// throws a clean Error (never a WASM trap) and the instance stays healthy.
test("adversarial field and pair values reject cleanly, pinned", () => {
  const cases = [];
  const onInput = (field, text) => (draft) => { draft.tx.inputs[0][field] = text; };
  const onOutput = (field, text) => (draft) => { draft.tx.outputs[0][field] = text; };
  for (const text of ["z".repeat(64), "0".repeat(63), "0".repeat(66), ""]) cases.push([onInput("txid", text), /txid/]);
  for (const text of ["4294967296", "-1", "1.5", "", "abc"]) cases.push([onInput("vout", text), /vout/]);
  for (const text of ["4294967296", "-1"]) cases.push([onInput("sequence", text), /sequence/]);
  for (const text of ["18446744073709551616", "-1", "1.5", "", "abc"]) cases.push([onOutput("value", text), /value/]);
  for (const text of ["2100000000000001", "18446744073709551615"]) cases.push([onOutput("value", text), /toolarge|consensus-invalid/]);
  for (const text of ["0", "zz", "0x6a"]) cases.push([onOutput("scriptPubKey", text), /scriptPubKey/]);
  for (const text of ["2147483648", "", "abc"]) cases.push([(draft) => { draft.tx.version = text; }, /version/]);
  for (const text of ["4294967296", "-1"]) cases.push([(draft) => { draft.tx.locktime = text; }, /locktime/]);
  cases.push(
    [(draft) => { draft.inputs[0].push({ key: draft.inputs[0][0].key, value: "" }); }, /duplicate key/],
    [(draft) => { draft.inputs[0].push({ key: "", value: "" }); }, /type byte/],
    [(draft) => { draft.inputs[0].push({ key: "30aa", value: "abc" }); }, /odd number of digits/],
    [(draft) => { draft.inputs[0].push({ key: "zz", value: "" }); }, /non-hex/],
    [(draft) => { draft.tx.inputs = []; draft.inputs = []; }, /vin-empty|consensus-invalid/],
    [(draft) => { draft.tx.outputs = []; draft.outputs = []; }, /vout-empty|consensus-invalid/],
    [(draft) => { draft.globals.push({ key: "fb", value: "03000000" }); }, /only PSBT v0 and v2/],
  );
  for (const [index, [corrupt, pattern]] of cases.entries()) {
    const draft = structuredClone(HEALTHY.doc);
    corrupt(draft);
    mustReject(draft, `pinned rejection ${index}`, pattern);
  }
});

// The boundary pins the UI guards: the last input's delete control is
// withheld because a zero-input transaction cannot round-trip, and the last
// output's delete is rejected by the consensus gate. no-outputs.b64 stays
// loadable-but-not-rebuildable: inspect parses it, the build gate refuses it.
test("the build gate rejects zero-input and zero-output transactions cleanly", () => {
  mustReject((() => { const draft = structuredClone(HEALTHY.doc); draft.tx.inputs = []; draft.inputs = []; return draft; })(), "zero inputs", /vin-empty/);
  mustReject((() => { const draft = structuredClone(HEALTHY.doc); draft.tx.outputs = []; draft.outputs = []; return draft; })(), "zero outputs", /vout-empty/);
  const noOutputs = fixtureDoc("no-outputs.b64");
  assert.equal(noOutputs.tx.outputs.length, 0, "the no-outputs fixture must keep zero outputs");
  mustReject(noOutputs, "no-outputs fixture rebuild", /vout-empty/);
  // …and a total past MAX_MONEY, even with each output inside the cap.
  const draft = structuredClone(HEALTHY.doc);
  draft.tx.outputs[0].value = "1500000000000000";
  draft.tx.outputs[1].value = "1500000000000000";
  mustReject(draft, "total past MAX_MONEY", /txouttotal-toolarge/);
});

// Two consensus-gate rejections a user actually meets: clicking Add input
// twice without editing the first added input duplicates the zero outpoint,
// and the last output keeps its delete button but the build refuses the
// removal. Both leave the working document untouched — and giving the first
// added input a real txid unblocks the add, proving the model.
test("duplicate zero-outpoint add and last-output delete reject cleanly, pinned", () => {
  const doc = structuredClone(HEALTHY.doc);
  const state = { doc, poisoned: null, anchor: JSON.stringify(doc.tx) };
  assert.ok(mutate(state, "first add input", (draft) => addElement(draft, "input")), "the first add was rejected");
  mutateExpectReject(state, "second add input with a zero outpoint", (draft) => addElement(draft, "input"), /inputs-duplicate/);
  note("reject:duplicate-outpoint");
  // Editing the added input's txid clears the duplicate; the next add builds.
  writeField(state, "real txid for the added input", fieldTargets(state).find((target) => target.kind === "txid" && target.index === 1), "0123456789abcdef".repeat(4));
  assert.equal(state.poisoned, null, "the txid edit did not build");
  assert.ok(mutate(state, "add after unblocking", (draft) => addElement(draft, "input")), "the unblocked add was rejected");
  assert.equal(state.doc.tx.inputs.length, 3);

  const oneOutput = { doc: structuredClone(fixtureDoc("locktime-rbf.b64")), poisoned: null, anchor: null };
  oneOutput.anchor = JSON.stringify(oneOutput.doc.tx);
  assert.equal(oneOutput.doc.tx.outputs.length, 1, "fixture drifted: locktime-rbf must keep one output");
  mutateExpectReject(oneOutput, "delete the last output", (draft) => removeElement(draft, "output", 0), /vout-empty/);
  note("reject:del-last-output");
  assert.equal(oneOutput.doc.tx.outputs.length, 1, "the last output was deleted despite the rejection");
});

// A field that does not build blocks structural edits (mutate keeps the
// working document) until a valid keystroke repairs it — the live editor's
// exact semantics. Deleting the poisoned element is the other way out.
test("an unbuildable field blocks structural edits until repaired", () => {
  const doc = structuredClone(HEALTHY.doc);
  const state = { doc, poisoned: null, anchor: JSON.stringify(doc.tx) };
  writeField(state, "poison vout", fieldTargets(state).find((target) => target.kind === "vout"), "not-a-number");
  assert.equal(state.poisoned?.kind, "vout", "the invalid text did not poison the document");
  assert.equal(state.doc.tx.inputs[0].vout, "not-a-number", "the typed text was lost");
  const inputsBefore = state.doc.tx.inputs.length;
  addElementOp(state, "structural edit while poisoned", "input");
  assert.equal(state.doc.tx.inputs.length, inputsBefore, "the structural edit stuck despite the poisoned field");
  assert.equal(state.doc.tx.inputs[0].vout, "not-a-number", "the working document was disturbed");
  repairOp(state, "repair keystroke");
  assert.equal(state.poisoned, null, "the document did not recover");
  addElementOp(state, "structural edit after repair", "input");
  assert.equal(state.doc.tx.inputs.length, inputsBefore + 1, "structural edits did not resume after the repair");

  // The other way out of a poisoned document: delete the element whose field
  // does not build. (Needs two inputs — the last one's delete is withheld.)
  writeField(state, "poison txid", fieldTargets(state).find((target) => target.kind === "txid" && target.index === 0), "zz");
  assert.equal(state.poisoned?.kind, "txid", "the txid text did not poison the document");
  const recovered = mutate(state, "delete the poisoned input", (draft) => removeElement(draft, "input", 0));
  assert.ok(recovered, "deleting the poisoned element was rejected");
  assert.equal(state.poisoned, null, "deleting the poisoned element did not recover the document");
  assert.equal(state.doc.tx.inputs.length, inputsBefore, "the poisoned input survived its own delete");
});

// The fuzzer guards itself: with a dead pool or a swallowed oracle these
// flavors and volumes would silently vanish.
test("the walk covered every flavor and volume floor", () => {
  const required = [
    ...FIXTURES.map((fixture) => `fixture:${fixture.name}`),
    "ok:add-input", "ok:add-output", "ok:del-input", "ok:del-output", "ok:del-input-to-floor", "ok:del-output-to-floor",
    "field:txid:ok", "field:vout:ok", "field:sequence:ok", "field:value:ok", "field:scriptPubKey:ok", "field:version:ok", "field:locktime:ok",
    "reject:txid", "reject:vout", "reject:sequence", "reject:value", "reject:scriptPubKey", "reject:version", "reject:locktime",
    "ok:add-pair", "ok:del-pair", "reject:duplicate-key", "reject:pair-hex",
    "ok:global-version", "reject:global-version", "reject:zero-input", "reject:garbage-doc",
    "reject:poisoned-blocks-structural", "reject:duplicate-outpoint", "reject:del-last-output", "repair-ok", "ok:signing-pairs-dropped", "walk-complete",
  ];
  for (const flavor of required) assert.ok((flavors.get(flavor) ?? 0) > 0, `the walk never exercised ${flavor}`);
  // Floors sit well below the observed volumes (1412/670/1412) so a dead
  // pool or a swallowed oracle trips them, not PRNG drift.
  assert.ok(counts.builds >= 1100, `suspiciously few accepted builds: ${counts.builds}`);
  assert.ok(counts.rejections >= 500, `suspiciously few rejections: ${counts.rejections}`);
  assert.ok(counts.fixpoints >= 1100, `suspiciously few byte-exact fixpoints: ${counts.fixpoints}`);
  assert.equal(counts.health, counts.rejections, "not every rejection was followed by a health check");
});
