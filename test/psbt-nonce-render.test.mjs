import { test } from "node:test";
import assert from "node:assert/strict";
import { schnorr, secp256k1 } from "@noble/curves/secp256k1.js";
import { loadAppFunctions } from "./app-slice-harness.mjs";

const pubkey = Uint8Array.from(Buffer.from("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", "hex"));
// Readable DER r/s with SIGHASH_ALL, deliberately without prevouts: these
// fixtures establish a possible repeat, not a verified signature/key leak.
const signature = (r) => Uint8Array.of(0x30, 6, 2, 1, r, 2, 1, 1, 1);
const recorded = [];
const app = await loadAppFunctions(["hodlRenderPsbt", "hodlRenderRawTx"], { stubs: {
  document: { getElementById: () => null },
  hodlSessionOwnership: () => new Map(),
  hodlRenderOutputHtml: () => "",
  hodlOwnershipWarning: () => "",
  hodlPublicInlineHtml: (text) => text,
  hodlPsbtReferenceVerdict: () => ({ state: "incomplete" }),
  hodlPrivForPub: () => null,
  hodlPrivFromPath: () => null,
  hodlPsbtMasterFingerprint: () => null,
  hodlPsbtRecordNonceInspection: (kind, records, tag, verdict) => recorded.push({ kind, records, verdict }),
} });

function fixture(nonces) {
  const tx = {
    version: 2, locktime: 0, segwit: false,
    inputs: nonces.map((r, vout) => ({
      txid: new Uint8Array(32).fill(0x11), vout, sequence: 0xffffffff,
      scriptSig: Uint8Array.of(9, ...signature(r), 33, ...pubkey),
    })),
    outputs: [{ amount: 1000n, script: Uint8Array.of(0x51) }],
  };
  const psbt = {
    tx: { ...tx, inputs: tx.inputs.map((input) => ({ ...input, scriptSig: new Uint8Array() })) },
    inputs: nonces.map((r) => [{ type: 2, keydata: pubkey, val: signature(r) }]),
    outputs: [[]],
  };
  return { tx, psbt };
}

for (const kind of ["psbt", "transaction"]) test(`${kind} nonce report cannot contradict a repeated-r warning with a clean line`, () => {
  // Contract: same-key repeated r must warn and must never also say no r was
  // repeated; distinct readable r values may report no repeated r.
  const render = (nonces) => {
    const { tx, psbt } = fixture(nonces);
    return kind === "psbt" ? app.hodlRenderPsbt(psbt, undefined, undefined, "nonce") : app.hodlRenderRawTx(tx, undefined, undefined, "nonce");
  };
  const distinct = render([1, 2]);
  assert.match(distinct, /No repeated ECDSA nonce/);
  const repeated = render([1, 1]);
  assert.equal(recorded.at(-1).verdict, "possible");
  // This safety-critical substring pins the absence of a false assurance,
  // without asserting styles, markup, or the full user-facing sentence.
  assert.doesNotMatch(repeated, /No repeated ECDSA nonce/);
});

test("both inspectors clear prior output and report collision-budget refusal without recording a verdict", async () => {
  // Coverage of the existing error contract: real renderers/comparator with
  // only input acquisition and unrelated UI/session services substituted.
  const fields = new Map();
  const element = (id) => {
    if (!fields.has(id)) fields.set(id, { value: "", innerHTML: "" });
    return fields.get(id);
  };
  const errors = [], events = [];
  let kind = "psbt";
  const { tx, psbt } = fixture(Array(257).fill(1));
  const handlers = await loadAppFunctions(["hodlRunPsbt", "hodlRunNonce"], { stubs: {
    document: { getElementById: element },
    hodlSetPsbtError: (error) => errors.push(error),
    hodlSetNonceError: (error) => errors.push(error),
    hodlPsbtResetNonceInspection: () => {},
    hodlPaintPsbtSession: () => {},
    hodlLoadPsbtKey: () => {},
    hodlStationPassphraseBytes: () => null,
    hodlClearStationPassphrase: () => {},
    hodlPsbtBytes: () => new Uint8Array(),
    isPsbtMagic: () => kind === "psbt",
    hodlParsePsbt: () => psbt,
    parseRawTx: () => tx,
    hodlRenderPsbt: app.hodlRenderPsbt,
    hodlRenderRawTx: app.hodlRenderRawTx,
    hodlJournalLog: (event) => events.push(event),
  } });
  for (kind of ["psbt", "transaction"]) for (const station of ["psbt", "nonce"]) {
    element(`${station}-out`).innerHTML = "prior result";
    const recordsBefore = recorded.length;
    handlers[station === "psbt" ? "hodlRunPsbt" : "hodlRunNonce"]();
    assert.equal(element(`${station}-out`).innerHTML, "");
    assert.match(errors.at(-1).raw, /nonce comparison limit/i);
    assert.equal(events.at(-1), "inspect-error");
    assert.equal(recorded.length, recordsBefore);
  }
});

test("a language switch paints both inspectors' last runs again, with the inputs those runs read", async () => {
  // The inspector output is built from filled-in strings no catalog key
  // matches, so the static sweep cannot carry it across a switch; the last
  // run is painted again. It must be the same analysis: the run's network
  // and Jade transcript, not whatever the page holds now, and no second
  // nonce-history record. A session change drops the stored runs, so a
  // switch can never re-read a PSBT under another key.
  const outputs = { "psbt-out": { innerHTML: "inspect result" }, "nonce-out": { innerHTML: "nonce result" } };
  const calls = [];
  const refresh = await loadAppFunctions(["hodlRefreshPsbtLocale", "hodlPsbtWipeMem"], { settable: ["hodlPsbtLast", "hodlNonceLast"], stubs: {
    document: { getElementById: (id) => outputs[id] ?? null },
    hodlPaintPsbtSession: () => {},
    hodlPaintPsbtKeyNotes: () => {},
    hodlSetPsbtError: () => {},
    hodlSetNonceError: () => {},
    hodlPsbtSyncNonceHistoryControls: () => {},
    hodlPsbtResetNonceInspection: () => {},
    hodlRenderPsbt: (...args) => (calls.push(["psbt", ...args]), "repainted psbt " + args[3]),
    hodlRenderRawTx: (...args) => (calls.push(["transaction", ...args]), "repainted transaction " + args[3]),
  } });
  const psbt = { psbt: true }, tx = { tx: true }, tag = new Uint8Array([1]);
  refresh.__set.hodlPsbtLast({ kind: "psbt", parsed: psbt, sourceTag: tag, checkedAt: "t1", network: "testnet" });
  refresh.__set.hodlNonceLast({ kind: "transaction", parsed: tx, sourceTag: tag, checkedAt: "t2", network: "signet", transcript: "" });
  refresh.hodlRefreshPsbtLocale();
  assert.equal(outputs["psbt-out"].innerHTML, "repainted psbt inspect");
  assert.equal(outputs["nonce-out"].innerHTML, "repainted transaction nonce");
  assert.deepEqual(calls, [
    ["psbt", psbt, tag, "t1", "inspect", { network: "testnet", transcript: undefined, record: false }],
    ["transaction", tx, tag, "t2", "nonce", { network: "signet", transcript: "", record: false }],
  ]);

  refresh.hodlPsbtWipeMem();
  outputs["psbt-out"].innerHTML = outputs["nonce-out"].innerHTML = "kept";
  refresh.hodlRefreshPsbtLocale();
  assert.equal(calls.length, 2, "a wiped session leaves nothing to paint again");
  assert.equal(outputs["psbt-out"].innerHTML, "kept");
});

test("every line the inspectors write goes through the translator", async () => {
  // A marking translator stands in for a page language: what is left outside
  // its marks once the markup is stripped is English no language reaches.
  // Data stays as it is: hex (txids, r values, sequence), amounts, the BTC
  // unit, and the "script …" form an address takes for a bare script.
  const mark = (key, vars) => "⟦" + key.replace(/\{(\w+)\}/g, (whole, name) => (vars?.[name] == null ? whole : String(vars[name]))) + "⟧";
  const pseudo = await loadAppFunctions(["hodlRenderPsbt", "hodlRenderRawTx"], { stubs: {
    document: { getElementById: () => null },
    hodlT: mark,
    hodlTText: mark,
    hodlTAttr: mark,
    hodlSessionOwnership: () => new Map(),
    hodlPublicInlineHtml: (text) => text,
    hodlPsbtReferenceVerdict: () => ({ state: "complete" }),
    hodlPrivForPub: () => null,
    hodlPrivFromPath: () => null,
    hodlPsbtMasterFingerprint: () => null,
    hodlPsbtRecordNonceInspection: () => {},
  } });
  const english = (html) => html.replace(/<[^>]*>/g, " ").replace(/⟦[^⟧]*⟧/g, " ").split(/[\s·:()#,]+/)
    .filter((word) => /[A-Za-z]/.test(word) && !/^(?:BTC|script|0x[0-9a-f]+|[0-9a-f]+)$/.test(word));
  for (const nonces of [[1, 2], [1, 1], [1]]) {
    const { tx, psbt } = fixture(nonces);
    for (const view of ["inspect", "nonce", "all"]) {
      assert.deepEqual(english(pseudo.hodlRenderPsbt(psbt, undefined, undefined, view)), [], `PSBT ${view} view, r values ${nonces}`);
      assert.deepEqual(english(pseudo.hodlRenderRawTx(tx, undefined, undefined, view)), [], `transaction ${view} view, r values ${nonces}`);
    }
  }
});

// "Show more" in the Inspector (the owner, 2026-10-22).
test("a raw transaction in the Inspector shows 2,000 inputs, then a Show-more button naming the rest", () => {
  const tx = {
    version: 2, locktime: 0, segwit: false,
    inputs: Array.from({ length: 2100 }, (_, vout) => ({ txid: new Uint8Array(32).fill(0x11), vout, scriptSig: new Uint8Array(), sequence: 0xffffffff })),
    outputs: [{ amount: 1000n, script: Uint8Array.of(0x51) }],
  };
  const limits = { inputs: 2000, outputs: 2000, step: 2000, format: (n) => n.toLocaleString("en-US") };
  const html = app.hodlRenderRawTx(tx, undefined, undefined, "inspect", { network: "mainnet", limits });
  assert.equal((html.match(/<strong>Input \d+<\/strong>/g) || []).length, 2000);
  assert.ok(html.includes("100 more inputs not shown, still included in this transaction."));
  assert.match(html, /<button[^>]*data-psbt-more='inputs'[^>]*>Show 100 more inputs<\/button>/);
  const all = app.hodlRenderRawTx(tx, undefined, undefined, "inspect", { network: "mainnet", limits: { ...limits, inputs: 4000 } });
  assert.equal((all.match(/<strong>Input \d+<\/strong>/g) || []).length, 2100);
  assert.doesNotMatch(all, /data-psbt-more/);
});

test("a Show-more click grows that list by one step, paints the last run again and moves focus to the next button", async () => {
  const renders = [];
  let focused = null, html = "";
  const next = { focus: () => { focused = "next"; } };
  const output = {
    set innerHTML(value) { html = value; },
    get innerHTML() { return html; },
    querySelector: (selector) => (selector === "[data-psbt-more='inputs']" && html.includes("more") ? next : null),
    hasAttribute: () => false,
    setAttribute: () => {},
    focus: () => { focused = "output"; },
  };
  const last = { kind: "psbt", parsed: { psbt: true }, sourceTag: new Uint8Array(1), checkedAt: "t1", network: "testnet", limits: { inputs: 2000, outputs: 2000, step: 2000 } };
  const ui = await loadAppFunctions(["hodlPsbtShowMore"], { stubs: {
    document: { getElementById: (id) => (id === "psbt-out" ? output : null) },
    hodlPsbtLast: last,
    hodlRenderPsbt: (...args) => { renders.push(args); return renders.length === 1 ? "…and 1 more" : "done"; },
    hodlRenderRawTx: () => { throw new Error("not a transaction"); },
  } });
  const click = (kind) => ui.hodlPsbtShowMore({ target: { closest: () => ({ dataset: { psbtMore: kind } }) } });
  click("inputs");
  assert.deepEqual(renders[0].slice(2, 4), ["t1", "inspect"]);
  assert.deepEqual({ ...renders[0][4].limits }, { inputs: 4000, outputs: 2000, step: 2000 }, "inputs grew by one step; outputs did not");
  assert.equal(renders[0][4].network, "testnet");
  assert.equal(focused, "next", "focus moves to the list's next button");
  click("inputs");
  assert.equal(renders[1][4].limits.inputs, 6000);
  assert.equal(focused, "output", "with the list complete, focus moves to the output");
  ui.hodlPsbtShowMore({ target: { closest: () => null } });
  assert.equal(renders.length, 2, "a click elsewhere in the output paints nothing");
});

test("appending raw-transaction inputs gives exactly the page a full render of the grown window gives", () => {
  const tx = {
    version: 2, locktime: 0, segwit: false,
    inputs: Array.from({ length: 4100 }, (_, vout) => ({ txid: new Uint8Array(32).fill(0x11), vout, scriptSig: new Uint8Array(), sequence: 0xffffffff })),
    outputs: [{ amount: 1000n, script: Uint8Array.of(0x51) }],
  };
  const limits = { inputs: 4000, outputs: 2000, step: 2000, format: (n) => n.toLocaleString("en-US") };
  const opts = (extra) => ({ network: "mainnet", limits: { ...limits, inputs: 2000 }, ...extra });
  const page = app.hodlRenderRawTx(tx, undefined, undefined, "inspect", opts());
  const before = app.hodlRenderRawTx(tx, undefined, undefined, "inspect", opts({ only: { kind: "inputs", from: 2000 } }));
  const part = app.hodlRenderRawTx(tx, undefined, undefined, "inspect", { network: "mainnet", limits, only: { kind: "inputs", from: 2000 } });
  const open = "<div data-psbt-tail='inputs'>", old = open + before.tail + "</div>";
  assert.equal(page.split(old).length, 2);
  assert.equal((part.chunk.match(/<strong>Input \d+<\/strong>/g) || []).length, 2000);
  assert.equal(page.replace(old, part.chunk + open + part.tail + "</div>"), app.hodlRenderRawTx(tx, undefined, undefined, "inspect", { network: "mainnet", limits }));
});

test("a Show-more click inserts only the new block above the list's tail, or repaints when the render declines", async () => {
  let html = "full page", focused = null;
  const inserted = [], renders = [];
  const tail = { innerHTML: "old tail", insertAdjacentHTML: (where, text) => inserted.push([where, text]) };
  const output = {
    set innerHTML(value) { html = value; },
    get innerHTML() { return html; },
    querySelector: (selector) => (selector === "[data-psbt-tail='inputs']" ? tail : selector === "[data-psbt-more='inputs']" ? { focus: () => { focused = "next"; } } : null),
    hasAttribute: () => true,
    setAttribute: () => {},
    focus: () => { focused = "output"; },
  };
  let decline = false;
  const ui = await loadAppFunctions(["hodlPsbtShowMore"], { stubs: {
    document: { getElementById: (id) => (id === "psbt-out" ? output : null) },
    hodlPsbtLast: { kind: "psbt", parsed: {}, sourceTag: new Uint8Array(1), checkedAt: "t1", network: "mainnet", limits: { inputs: 2000, outputs: 2000, step: 2000 } },
    hodlRenderPsbt: (...args) => { renders.push(args[4]); return args[4].only ? (decline ? null : { chunk: "<new block>", tail: "<new tail>" }) : "repainted"; },
    hodlRenderRawTx: () => { throw new Error("not a transaction"); },
  } });
  const click = () => ui.hodlPsbtShowMore({ target: { closest: () => ({ dataset: { psbtMore: "inputs" } }) } });
  click();
  assert.deepEqual(renders[0].only, { kind: "inputs", from: 2000 }, "only the block past the 2,000 already shown");
  assert.equal(renders[0].limits.inputs, 4000);
  assert.deepEqual(inserted, [["beforebegin", "<new block>"]], "inserted above the tail");
  assert.equal(tail.innerHTML, "<new tail>");
  assert.equal(html, "full page", "the rest of the page is untouched");
  assert.equal(focused, "next");
  decline = true;
  click();
  assert.deepEqual(renders[1].only, { kind: "inputs", from: 4000 });
  assert.equal(renders[2].only, undefined, "a declined block repaints the whole run");
  assert.equal(html, "repainted");
});

// --- BIP340 (Taproot/Schnorr) nonce reuse ----------------------------------
// Genuine BIP340 signatures built with @noble/curves. The nonce is fixed to a
// chosen k so two different messages are signed with the same R — the key
// leak the inspector must catch (s1 - s2 = (e1 - e2)*d reveals the key).
const curveN = secp256k1.Point.CURVE().n;
const bytesToNum = (bytes) => BigInt("0x" + Buffer.from(bytes).toString("hex"));
const numToBytes = (value) => Uint8Array.from(Buffer.from(value.toString(16).padStart(64, "0"), "hex"));
const signWithNonce = (message, secret, k) => {
  // BIP340 with a fixed nonce: R = k*G, e is the tagged challenge hash,
  // s = k + e*d mod n. The key and the nonce are negated when P or R has an
  // odd y; trying both parities and keeping the signature that verifies
  // avoids depending on point decoding.
  const px = schnorr.getPublicKey(numToBytes(secret));
  const rx = schnorr.getPublicKey(numToBytes(k));
  const e = bytesToNum(schnorr.utils.taggedHash("BIP0340/challenge", rx, px, message)) % curveN;
  for (const d of [secret, curveN - secret]) {
    for (const kEven of [k, curveN - k]) {
      const sig = Uint8Array.from([...rx, ...numToBytes((kEven + e * d) % curveN)]);
      if (schnorr.verify(sig, message, px)) return sig;
    }
  }
  throw new Error("no parity combination produced a valid signature");
};
const tapSecret = bytesToNum(new Uint8Array(32).fill(0x42));
const tapKey = schnorr.getPublicKey(numToBytes(tapSecret)); // x-only output key Q
const tapMsgA = new Uint8Array(32).fill(0x01);
const tapMsgB = new Uint8Array(32).fill(0x02);
const tapSigA = signWithNonce(tapMsgA, tapSecret, bytesToNum(new Uint8Array(32).fill(0xaa)));
const tapSigB = signWithNonce(tapMsgB, tapSecret, bytesToNum(new Uint8Array(32).fill(0xaa))); // same k as A: same R
const tapSigC = signWithNonce(tapMsgA, tapSecret, bytesToNum(new Uint8Array(32).fill(0xbb))); // different k: different R
const p2trScript = Uint8Array.from([0x51, 0x20, ...tapKey]); // OP_1 PUSH32 <Q>
const witnessUtxoEntry = () => {
  // PSBT_IN_WITNESS_UTXO: the previous output, amount then script (BIP-174).
  const val = new Uint8Array(8 + 1 + p2trScript.length);
  new DataView(val.buffer).setBigUint64(0, 1000n, true);
  val[8] = p2trScript.length;
  val.set(p2trScript, 9);
  return { type: 1, keydata: new Uint8Array(), val };
};
const tapKeySigEntry = (val) => ({ type: 19, keydata: new Uint8Array(), val });
const witnessStack = (items) => Uint8Array.from([items.length, ...items.flatMap((item) => [item.length, ...item])]);
const tapPsbt = (inputEntries) => ({
  tx: {
    version: 2, locktime: 0, segwit: false,
    inputs: inputEntries.map((_, vout) => ({ txid: new Uint8Array(32).fill(0x11), vout, sequence: 0xffffffff, scriptSig: new Uint8Array() })),
    outputs: [{ amount: 1000n, script: Uint8Array.of(0x51) }],
  },
  inputs: inputEntries,
  outputs: [[]],
});

test("two key-path signatures sharing R under one key are a key leak: warning, summary problem, reuse verdict", () => {
  // The fixtures are genuine: both signatures verify, and the forced shared
  // nonce makes them share R while signing different messages.
  assert.ok(schnorr.verify(tapSigA, tapMsgA, tapKey) && schnorr.verify(tapSigB, tapMsgB, tapKey), "fixtures are genuine BIP340 signatures");
  assert.deepEqual(tapSigA.slice(0, 32), tapSigB.slice(0, 32), "forced nonce reuse: both signatures share R");
  const psbt = tapPsbt([
    [witnessUtxoEntry(), tapKeySigEntry(tapSigA)],
    [witnessUtxoEntry(), tapKeySigEntry(tapSigB)],
  ]);
  const html = app.hodlRenderPsbt(psbt, undefined, undefined, "all");
  assert.match(html, /Reused Schnorr nonce detected for the same key/);
  assert.match(html, /Two Taproot signatures reuse a nonce under the same key/);
  assert.doesNotMatch(html, /No repeated BIP340 nonces/, "a reuse warning must never come with a clean line");
  assert.equal(recorded.at(-1).verdict, "reuse");
});

test("two key-path signatures with different R are a clean result", () => {
  assert.notDeepEqual(tapSigA.slice(0, 32), tapSigC.slice(0, 32));
  const psbt = tapPsbt([
    [witnessUtxoEntry(), tapKeySigEntry(tapSigA)],
    [witnessUtxoEntry(), tapKeySigEntry(tapSigC)],
  ]);
  const html = app.hodlRenderPsbt(psbt, undefined, undefined, "all");
  assert.match(html, /No repeated BIP340 nonces were found among them/);
  assert.doesNotMatch(html, /Reused Schnorr nonce/);
  assert.equal(recorded.at(-1).verdict, "clean");
});

test("a key-path signature whose previous output is not in the file is incomplete, never clean", () => {
  const psbt = tapPsbt([
    [witnessUtxoEntry(), tapKeySigEntry(tapSigA)],
    [tapKeySigEntry(tapSigC)], // no witness UTXO: the key Q is missing (C's own R, so only the key is in question)
  ]);
  const html = app.hodlRenderPsbt(psbt, undefined, undefined, "all");
  assert.match(html, /Some could not be checked for a repeated nonce/);
  assert.doesNotMatch(html, /No repeated BIP340 nonces/);
  assert.equal(recorded.at(-1).verdict, "incomplete");
});

test("key path and script path signatures on one input under one key with one R are reuse", () => {
  const leafHash = new Uint8Array(32).fill(0x77);
  const psbt = tapPsbt([
    [witnessUtxoEntry(), tapKeySigEntry(tapSigA), { type: 20, keydata: Uint8Array.from([...tapKey, ...leafHash]), val: tapSigB }],
  ]);
  const html = app.hodlRenderPsbt(psbt, undefined, undefined, "all");
  assert.match(html, /Reused Schnorr nonce detected for the same key/);
  assert.equal(recorded.at(-1).verdict, "reuse");
});

test("a finalized P2TR key-path input joins the nonce comparison", () => {
  const psbt = tapPsbt([
    [witnessUtxoEntry(), { type: 8, keydata: new Uint8Array(), val: witnessStack([tapSigA]) }],
    [witnessUtxoEntry(), tapKeySigEntry(tapSigB)],
  ]);
  const html = app.hodlRenderPsbt(psbt, undefined, undefined, "all");
  assert.match(html, /Reused Schnorr nonce detected for the same key/);
  assert.equal(recorded.at(-1).verdict, "reuse");
});

test("a crafted PSBT with 20,000 same-R Taproot signatures is refused by the comparison cap", () => {
  const entries = [witnessUtxoEntry()];
  for (let count = 0; count < 20000; count++) entries.push(tapKeySigEntry(tapSigA));
  const before = recorded.length;
  assert.throws(() => app.hodlRenderPsbt(tapPsbt([entries]), undefined, undefined, "all"), /Nonce comparison limit exceeded/);
  assert.equal(recorded.length, before, "a refused inspection records no verdict");
});

test("the analysis summary row reports Schnorr reuse as a problem, ECDSA reuse text first", async () => {
  const { hodlPsbtNonceCheck } = await loadAppFunctions(["hodlPsbtNonceCheck"]);
  const sameKey = Object.assign([{}, {}], { sameKey: true });
  const schnorrOnly = hodlPsbtNonceCheck([], [], false, [sameKey]);
  assert.equal(schnorrOnly.state, "problem");
  assert.match(schnorrOnly.detail, /Two Taproot signatures reuse a nonce under the same key/);
  const crossKey = hodlPsbtNonceCheck([], [], false, [[{}, {}]]);
  assert.equal(crossKey.state, "problem");
  assert.match(crossKey.detail, /Two Taproot signatures share a nonce under different keys/, "a pair not marked same-key is cross-key");
  const both = hodlPsbtNonceCheck([{}], [], false, [sameKey]);
  assert.equal(both.state, "problem");
  assert.match(both.detail, /repeated ECDSA nonce/, "ECDSA reuse text wins when both exist");
  assert.equal(hodlPsbtNonceCheck([], [], false, []).state, "complete", "no Schnorr records, no change");
});

test("the same Taproot signature copied onto two inputs is not reported as a key leak", () => {
  const psbt = tapPsbt([
    [witnessUtxoEntry(), tapKeySigEntry(tapSigA)],
    [witnessUtxoEntry(), tapKeySigEntry(tapSigA)],
  ]);
  const html = app.hodlRenderPsbt(psbt, undefined, undefined, "all");
  assert.doesNotMatch(html, /Reused Schnorr nonce/);
  assert.match(html, /No repeated BIP340 nonces were found among them/);
  assert.notEqual(recorded.at(-1).verdict, "reuse");
});

// DeepSeek's red-team of #1051 (c6ad892). F1 (mixed families) is tested in
// psbt-codeseparator.test.mjs, whose control PSBT has two checked ECDSA
// signatures.

test("a single Taproot signature is not read as clean (F5)", () => {
  const html = app.hodlRenderPsbt(tapPsbt([[witnessUtxoEntry(), tapKeySigEntry(tapSigA)]]), undefined, undefined, "all");
  assert.match(html, /Only one Taproot signature is present, so nonce reuse cannot be judged from this file alone/);
  assert.doesNotMatch(html, /No repeated BIP340 nonces/);
  assert.equal(recorded.at(-1).verdict, "incomplete");
});

test("a final witness beside a 0x13 is compared too, and an identical copy counts once (F2)", () => {
  // Input 0 keeps a 0x13 (C) beside a different final witness (A); A and
  // input 1's B share R under one key.
  const hidden = app.hodlRenderPsbt(tapPsbt([
    [witnessUtxoEntry(), tapKeySigEntry(tapSigC), { type: 8, keydata: new Uint8Array(), val: witnessStack([tapSigA]) }],
    [witnessUtxoEntry(), tapKeySigEntry(tapSigB)],
  ]), undefined, undefined, "all");
  assert.match(hidden, /Reused Schnorr nonce detected for the same key/);
  assert.equal(recorded.at(-1).verdict, "reuse");
  // The same signature in the 0x13 and the final witness is one signature.
  const copied = app.hodlRenderPsbt(tapPsbt([
    [witnessUtxoEntry(), tapKeySigEntry(tapSigA), { type: 8, keydata: new Uint8Array(), val: witnessStack([tapSigA]) }],
    [witnessUtxoEntry(), tapKeySigEntry(tapSigC)],
  ]), undefined, undefined, "all");
  assert.match(copied, /This PSBT also contains 2 Taproot \/ Schnorr signature\(s\)/);
  assert.match(copied, /No repeated BIP340 nonces were found among them/);
  assert.equal(recorded.at(-1).verdict, "clean");
});

test("the completed nonce line names the signatures that were compared (F4)", async () => {
  const { hodlPsbtNonceCheck } = await loadAppFunctions(["hodlPsbtNonceCheck"]);
  assert.match(hodlPsbtNonceCheck([], [], false, [], 0, 2).detail, /^All Taproot signatures in this PSBT/);
  assert.match(hodlPsbtNonceCheck([], [], false, [], 2, 2).detail, /^All ECDSA and Taproot signatures in this PSBT/);
  assert.match(hodlPsbtNonceCheck([], [], false, [], 2, 0).detail, /^All ECDSA signatures in this PSBT/);
  assert.match(hodlPsbtNonceCheck([], [], false).detail, /^All ECDSA signatures in this PSBT/, "callers without counts keep the ECDSA line");
});

// --- finalized script path, raw transactions (#1051 round 3) ---------------
const leafKey = new Uint8Array(32).fill(0x44);
const pkLeaf = Uint8Array.of(0x20, ...leafKey, 0xac);
const controlBlock = Uint8Array.of(0xc0, ...new Uint8Array(32).fill(0x55));
const rawSig = (r, s) => Uint8Array.of(...new Uint8Array(32).fill(r), ...new Uint8Array(32).fill(s));
const finalScriptPath = (sig) => ({ type: 8, keydata: new Uint8Array(), val: witnessStack([sig, pkLeaf, controlBlock]) });

test("finalized script-path signatures join the comparison: a shared R under the leaf key is reuse", () => {
  const reuse = app.hodlRenderPsbt(tapPsbt([[witnessUtxoEntry(), finalScriptPath(rawSig(0xa1, 0x01))], [witnessUtxoEntry(), finalScriptPath(rawSig(0xa1, 0x02))]]), undefined, undefined, "all");
  assert.match(reuse, /Reused Schnorr nonce detected for the same key/);
  assert.equal(recorded.at(-1).verdict, "reuse");
  const distinct = app.hodlRenderPsbt(tapPsbt([[witnessUtxoEntry(), finalScriptPath(rawSig(0xa1, 0x01))], [witnessUtxoEntry(), finalScriptPath(rawSig(0xb2, 0x02))]]), undefined, undefined, "all");
  assert.match(distinct, /No repeated BIP340 nonces were found among them/);
  assert.equal(recorded.at(-1).verdict, "clean");
});

test("a finalized Taproot spend the check cannot read is an unchecked Taproot input, not an ECDSA one", () => {
  const unknownLeaf = { type: 8, keydata: new Uint8Array(), val: witnessStack([rawSig(0xa1, 0x01), Uint8Array.of(0x51), controlBlock]) };
  const html = app.hodlRenderPsbt(tapPsbt([[witnessUtxoEntry(), unknownLeaf], [witnessUtxoEntry(), tapKeySigEntry(tapSigA)], [witnessUtxoEntry(), tapKeySigEntry(tapSigC)]]), undefined, undefined, "all");
  assert.match(html, /Some finalized Taproot inputs could not be read/);
  assert.doesNotMatch(html, /Some ECDSA signatures could not be inspected/);
  assert.doesNotMatch(html, /No repeated BIP340 nonces/);
  assert.equal(recorded.at(-1).verdict, "incomplete");
});

test("a Taproot signature starting 0x30 is not mistaken for an uninspected ECDSA signature", () => {
  // hodlFinalSigs' DER test is a first byte of 0x30 and a length up to 73,
  // which a 64-byte Schnorr signature passes one time in 256.
  const keyPath = (sig) => ({ type: 8, keydata: new Uint8Array(), val: witnessStack([sig]) });
  const html = app.hodlRenderPsbt(tapPsbt([[witnessUtxoEntry(), keyPath(rawSig(0x30, 0x01))], [witnessUtxoEntry(), keyPath(rawSig(0x31, 0x02))]]), undefined, undefined, "all");
  assert.doesNotMatch(html, /Some ECDSA signatures could not be inspected/);
  assert.equal(recorded.at(-1).verdict, "clean");
});

test("a 0x13 or 0x14 field with malformed keydata counts as incomplete, never dropped (Kimi K3's review)", () => {
  const html = app.hodlRenderPsbt(tapPsbt([
    [witnessUtxoEntry(), tapKeySigEntry(tapSigA), { type: 19, keydata: Uint8Array.of(0xaa), val: tapSigB }],
    [witnessUtxoEntry(), tapKeySigEntry(tapSigC)],
  ]), undefined, undefined, "all");
  assert.doesNotMatch(html, /No repeated BIP340 nonces/);
  assert.equal(recorded.at(-1).verdict, "incomplete");
  app.hodlRenderPsbt(tapPsbt([[witnessUtxoEntry(), tapKeySigEntry(tapSigA), { type: 20, keydata: new Uint8Array(31), val: tapSigB }], [witnessUtxoEntry(), tapKeySigEntry(tapSigC)]]), undefined, undefined, "all");
  assert.equal(recorded.at(-1).verdict, "incomplete", "a 0x14 whose keydata is not key + leaf hash");
});

const rawTx = (witnesses, legacy = []) => ({
  version: 2, locktime: 0, segwit: true,
  inputs: [
    ...legacy.map((r, vout) => ({ txid: new Uint8Array(32).fill(0x11), vout, sequence: 0xffffffff, scriptSig: Uint8Array.of(9, ...signature(r), 33, ...pubkey), witness: [] })),
    ...witnesses.map((witness, k) => ({ txid: new Uint8Array(32).fill(0x22), vout: k, sequence: 0xffffffff, scriptSig: new Uint8Array(), witness })),
  ],
  outputs: [{ amount: 1000n, script: Uint8Array.of(0x51) }],
});

test("raw transaction: script-path signatures are compared; a shared R under the leaf key is reuse", () => {
  const reuse = app.hodlRenderRawTx(rawTx([[rawSig(0xa1, 0x01), pkLeaf, controlBlock], [rawSig(0xa1, 0x02), pkLeaf, controlBlock]]), undefined, undefined, "nonce");
  assert.match(reuse, /Reused Schnorr nonce detected for the same key/);
  assert.equal(recorded.at(-1).verdict, "reuse");
  const distinct = app.hodlRenderRawTx(rawTx([[rawSig(0xa1, 0x01), pkLeaf, controlBlock], [rawSig(0xb2, 0x02), pkLeaf, controlBlock]]), undefined, undefined, "nonce");
  assert.match(distinct, /This transaction also contains 2 Taproot \/ Schnorr signature\(s\) in script-path spends/);
  assert.equal(recorded.at(-1).verdict, "clean");
  app.hodlRenderRawTx(rawTx([[rawSig(0xa1, 0x01), pkLeaf, controlBlock]]), undefined, undefined, "nonce");
  assert.equal(recorded.at(-1).verdict, "incomplete", "one script-path signature cannot be judged");
});

test("raw transaction: a Taproot key-path input is unchecked, so two clean ECDSA signatures are no longer a clean result", () => {
  app.hodlRenderRawTx(rawTx([], [1, 2]), undefined, undefined, "nonce");
  assert.equal(recorded.at(-1).verdict, "clean", "control: two distinct ECDSA signatures");
  const html = app.hodlRenderRawTx(rawTx([[rawSig(0xa1, 0x01)]], [1, 2]), undefined, undefined, "nonce");
  assert.match(html, /Some Taproot signatures in this transaction could not be checked for a repeated nonce/);
  assert.equal(recorded.at(-1).verdict, "incomplete");
});

// Nemotron 3 Ultra's review of #1051 (7e87de9): Taproot signatures are keyed
// by the input's resolved previous output, not the witness UTXO alone.
test("a P2TR input whose previous output is only in its non-witness UTXO is keyed from it", async () => {
  const { createHash } = await import("node:crypto");
  const sha256d = (bytes) => new Uint8Array(createHash("sha256").update(createHash("sha256").update(bytes).digest()).digest());
  const le64 = (value) => { const bytes = new Uint8Array(8); new DataView(bytes.buffer).setBigUint64(0, value, true); return bytes; };
  const prevTx = (amount) => Uint8Array.of(2, 0, 0, 0, 1, ...new Uint8Array(32), 0, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 1, ...le64(amount), 34, 0x51, 0x20, ...tapKey, 0, 0, 0, 0);
  const prevs = [prevTx(1000n), prevTx(2000n)];
  const psbt = {
    tx: { version: 2, locktime: 0, segwit: false, inputs: prevs.map((prev) => ({ txid: sha256d(prev), vout: 0, sequence: 0xffffffff, scriptSig: new Uint8Array() })), outputs: [{ amount: 1000n, script: Uint8Array.of(0x51) }] },
    inputs: [[{ type: 0, keydata: new Uint8Array(), val: prevs[0] }, tapKeySigEntry(tapSigA)], [{ type: 0, keydata: new Uint8Array(), val: prevs[1] }, tapKeySigEntry(tapSigB)]],
    outputs: [[]],
  };
  const html = app.hodlRenderPsbt(psbt, undefined, undefined, "all");
  assert.match(html, /Reused Schnorr nonce detected for the same key/);
  assert.equal(recorded.at(-1).verdict, "reuse");
});

test("a finalized key-path input with no previous output is an unchecked Taproot input, not an ECDSA one", () => {
  const keyPathOnly = { type: 8, keydata: new Uint8Array(), val: witnessStack([tapSigA]) };
  const html = app.hodlRenderPsbt(tapPsbt([[keyPathOnly], [witnessUtxoEntry(), tapKeySigEntry(tapSigB)], [witnessUtxoEntry(), tapKeySigEntry(tapSigC)]]), undefined, undefined, "all");
  assert.match(html, /Some finalized Taproot inputs could not be read/);
  assert.doesNotMatch(html, /Some ECDSA signatures could not be inspected/);
  assert.equal(recorded.at(-1).verdict, "incomplete");
});

// DeepSeek's red-team of #1051 (89360c2), F1/F2: a real Taproot output key
// is the tweaked internal key, so a key-path signature (under Q) and a
// script-path signature (under P) never share a key, yet a shared nonce
// leaks P's secret: s1 - s2 = (e1 - e2)*d + e1*t with t public.
test("a key-path signature under the tweaked output key and a script-path signature under its internal key that share R are reuse", () => {
  const P = tapKey;
  const leaf = Uint8Array.of(0x20, ...P, 0xac);
  const leafHash = schnorr.utils.taggedHash("TapLeaf", Uint8Array.of(0xc0, leaf.length, ...leaf));
  const t = bytesToNum(schnorr.utils.taggedHash("TapTweak", P, leafHash)) % curveN;
  const dEven = secp256k1.getPublicKey(numToBytes(tapSecret), true)[0] === 0x03 ? curveN - tapSecret : tapSecret;
  const q = (dEven + t) % curveN;
  const Q = schnorr.getPublicKey(numToBytes(q));
  assert.notDeepEqual(Q, P, "a real output key is the tweaked internal key");
  const k = bytesToNum(new Uint8Array(32).fill(0xcc));
  const keyPathSig = signWithNonce(tapMsgA, q, k);
  const scriptPathSig = signWithNonce(tapMsgB, tapSecret, k);
  assert.ok(schnorr.verify(keyPathSig, tapMsgA, Q) && schnorr.verify(scriptPathSig, tapMsgB, P), "both signatures are genuine");
  assert.deepEqual(keyPathSig.slice(0, 32), scriptPathSig.slice(0, 32), "one nonce, one R");
  const utxoQ = () => {
    const val = new Uint8Array(8 + 1 + 34);
    new DataView(val.buffer).setBigUint64(0, 1000n, true);
    val.set([34, 0x51, 0x20, ...Q], 8);
    return { type: 1, keydata: new Uint8Array(), val };
  };
  const html = app.hodlRenderPsbt(tapPsbt([
    [utxoQ(), tapKeySigEntry(keyPathSig)],
    [utxoQ(), { type: 20, keydata: Uint8Array.of(...P, ...leafHash), val: scriptPathSig }],
  ]), undefined, undefined, "all");
  assert.match(html, /Reused Schnorr nonce across different keys/);
  assert.match(html, /Two Taproot signatures share a nonce under different keys/);
  assert.doesNotMatch(html, /No repeated BIP340 nonces/);
  assert.equal(recorded.at(-1).verdict, "reuse");
});

test("a keyless key-path signature that shares R with another is still reported", () => {
  const html = app.hodlRenderPsbt(tapPsbt([[witnessUtxoEntry(), tapKeySigEntry(tapSigA)], [tapKeySigEntry(tapSigB)]]), undefined, undefined, "all");
  assert.match(html, /Reused Schnorr nonce across different keys/);
  assert.equal(recorded.at(-1).verdict, "reuse");
});

// Kimi K3's review of #1031 (3fba4cd).
test("a Show-more click whose render throws keeps the window where the page is", async () => {
  const last = { kind: "psbt", parsed: {}, sourceTag: new Uint8Array(1), checkedAt: "t1", network: "mainnet", limits: { inputs: 2000, outputs: 2000, step: 2000 } };
  const output = { innerHTML: "", querySelector: () => null, hasAttribute: () => true, setAttribute: () => {}, focus: () => {} };
  const ui = await loadAppFunctions(["hodlPsbtShowMore"], { stubs: {
    document: { getElementById: (id) => (id === "psbt-out" ? output : null) },
    hodlPsbtLast: last,
    hodlRenderPsbt: () => { throw new Error("render failed"); },
    hodlRenderRawTx: () => { throw new Error("not a transaction"); },
  } });
  assert.throws(() => ui.hodlPsbtShowMore({ target: { closest: () => ({ dataset: { psbtMore: "inputs" } }) } }), /render failed/);
  assert.equal(last.limits.inputs, 2000, "the window did not grow past what the page shows");
});

test("the Show-more count falls back to plain digits when the locale tag is malformed", async () => {
  const { hodlFormatCount } = await loadAppFunctions(["hodlFormatCount"], { stubs: { hodlGetLocale: () => "en_US" } });
  assert.equal(hodlFormatCount(2000), "2000");
  const good = await loadAppFunctions(["hodlFormatCount"], { stubs: { hodlGetLocale: () => "en" } });
  assert.equal(good.hodlFormatCount(2000), "2,000");
});

test("when the other list's tail refresh throws after the block is in, the window has grown with the page", async () => {
  // Muse Spark's review of #1052: the block is inserted by the first render;
  // a throw in the second (the other tail) must not leave the window behind.
  const last = { kind: "psbt", parsed: {}, sourceTag: new Uint8Array(1), checkedAt: "t1", network: "mainnet", limits: { inputs: 2000, outputs: 2000, step: 2000 } };
  const tail = { innerHTML: "old", insertAdjacentHTML: () => {} };
  const output = { innerHTML: "", querySelector: (selector) => (selector.includes("data-psbt-tail") ? tail : null), hasAttribute: () => true, setAttribute: () => {}, focus: () => {} };
  let calls = 0;
  const ui = await loadAppFunctions(["hodlPsbtShowMore"], { stubs: {
    document: { getElementById: (id) => (id === "psbt-out" ? output : null) },
    hodlPsbtLast: last,
    hodlRenderPsbt: () => { if (++calls === 1) return { chunk: "<block>", tail: "<tail>" }; throw new Error("tail render failed"); },
    hodlRenderRawTx: () => { throw new Error("not a transaction"); },
  } });
  assert.throws(() => ui.hodlPsbtShowMore({ target: { closest: () => ({ dataset: { psbtMore: "inputs" } }) } }), /tail render failed/);
  assert.equal(last.limits.inputs, 4000, "the inserted block's window is kept");
});
