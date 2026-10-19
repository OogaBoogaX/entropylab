import { test } from "node:test";
import assert from "node:assert/strict";
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
