// The Journal nonce verdict (recorded by the PSBT / raw-tx inspector) must
// never disagree with the on-screen nonce checks in the dangerous direction:
// it cannot read "clean" while the summary says coverage is incomplete, and a
// stale verdict must not survive a failed re-inspect or a wipe.
//
// These tests run the live hodlJournalNonceVerdict function extracted from
// src/js/app.js (same loadSlice technique as psbt-nonce-reuse.test.mjs), with
// the journal log and verdict state intercepted in a scoped scope.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { snapshotSession } from "../src/js/journal.js";

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

const journalVerdictSlice = loadSlice("hodlJournalNonceVerdict");

// Run the real helper with the journal log and the two module-level verdict
// vars provided as parameters, so each test observes exactly the state and the
// log entries a real caller would produce.
function runVerdict(kind, reused, possible, incomplete, comparable) {
  const events = [];
  const hodlJournalLog = (action, detail, tool) => events.push({ action, detail, tool });
  const result = new Function(
    "hodlJournalLog",
    `let hodlPsbtNonceVerdict = "", hodlPsbtNonceVerdictKind = "";
     ${journalVerdictSlice}
     return (kind, reused, possible, incomplete, comparable) => {
       hodlJournalNonceVerdict(kind, reused, possible, incomplete, comparable);
       return { verdict: hodlPsbtNonceVerdict, kind: hodlPsbtNonceVerdictKind };
     };`,
  )(hodlJournalLog)(kind, reused, possible, incomplete, comparable);
  return { verdict: result.verdict, kind: result.kind, events };
}

const REUSED = [["a", "b"]];
const POSSIBLE = [["a", "b"]];

test("reuse is recorded and logged, and never claims clean", () => {
  const { verdict, kind, events } = runVerdict("psbt", REUSED, [], 0, 3);
  assert.equal(verdict, "reuse");
  assert.equal(kind, "psbt");
  assert.equal(events.length, 1);
  assert.equal(events[0].action, "inspect-nonce-reuse");
  assert.match(events[0].detail, /^psbt · 3 comparable · 1 reuse · 0 possible · 0 unreadable$/);
});

test("possible reuse (digest not rebuilt) is logged separately, not as reuse", () => {
  const { verdict, events } = runVerdict("psbt", [], POSSIBLE, 0, 3);
  assert.equal(verdict, "possible");
  assert.equal(events.length, 1);
  assert.equal(events[0].action, "inspect-nonce-possible");
  assert.match(events[0].detail, /0 reuse · 1 possible/);
});

test("incomplete coverage never yields clean, even with two comparable sigs", () => {
  for (const incomplete of [1, 2]) {
    const { verdict, events } = runVerdict("psbt", [], [], incomplete, 2);
    assert.equal(verdict, "incomplete");
    assert.equal(events.length, 1);
    assert.equal(events[0].action, "inspect-nonce-incomplete");
  }
});

test("fewer than two comparable signatures is incomplete and not logged", () => {
  const { verdict, events } = runVerdict("psbt", [], [], 0, 1);
  assert.equal(verdict, "incomplete");
  assert.equal(events.length, 0);
});

test("clean only when coverage is full and at least two sigs compare", () => {
  const { verdict, events } = runVerdict("psbt", [], [], 0, 2);
  assert.equal(verdict, "clean");
  assert.equal(events.length, 0);
});

test("raw-transaction kind is carried through to the verdict detail", () => {
  const { verdict, kind, events } = runVerdict("transaction", [], POSSIBLE, 0, 2);
  assert.equal(verdict, "possible");
  assert.equal(kind, "transaction");
  assert.match(events[0].detail, /^transaction · /);
});

// Snapshot gating: a nonce verdict is only meaningful while a payload is
// loaded, and a raw-transaction verdict must not be worded as a PSBT verdict.
function snap(psbt) {
  return snapshotSession({
    capturedAt: "2026-09-02 10:00:00",
    version: "v0.1.3",
    commit: "abc1234",
    includePrivate: false,
    keys: [],
    msigs: [],
    bip85: [],
    sp: { derived: false },
    psbt,
  });
}

test("no verdict line when the inspector is empty", () => {
  const text = snap({ loaded: false, nonce: "reuse", nonceKind: "psbt" });
  assert.match(text, /inspector empty/);
  assert.doesNotMatch(text, /nonce verdict/);
});

test("no verdict line when the nonce verdict is empty", () => {
  const text = snap({ loaded: true, nonce: "", nonceKind: "" });
  assert.doesNotMatch(text, /nonce verdict/);
});

test("a raw-transaction verdict is labeled as a raw transaction, not a PSBT", () => {
  const text = snap({ loaded: true, nonce: "possible", nonceKind: "transaction" });
  assert.match(text, /nonce verdict: possible reuse in this raw transaction/);
});

test("a clean verdict states ECDSA-only coverage and the Schnorr caveat", () => {
  const text = snap({ loaded: true, nonce: "clean", nonceKind: "psbt" });
  assert.match(text, /nonce verdict: no repeated ECDSA r for the same key in this PSBT/);
  assert.match(text, /Taproot\/Schnorr nonces are not analyzed/);
});

// Stale-state invariants in app.js: the verdict is cleared wherever the
// inspector result is discarded, so a later snapshot cannot report a verdict
// produced by a previous payload.
test("the verdict is cleared on every path that discards the inspector result", () => {
  const wipe = loadSlice("hodlPsbtWipeMem");
  assert.match(wipe, /hodlPsbtNonceVerdict = ""/);
  assert.match(wipe, /hodlPsbtNonceVerdictKind = ""/);
  const run = loadSlice("hodlRunPsbt");
  // cleared at entry (before parsing the new payload) and again in the
  // catch, so a failed re-inspect leaves no stale verdict.
  assert.equal((run.match(/hodlPsbtNonceVerdict = ""/g) || []).length >= 2, true);
});

// The hooks are invoked only after the on-screen banners are pushed, so the
// journal can never record a verdict for a render whose warnings were cut off.
test("both hooks run after the nonce warning banners", () => {
  const psbt = loadSlice("hodlRenderPsbt");
  assert.ok(psbt.indexOf("Reused nonce detected") < psbt.indexOf("hodlJournalNonceVerdict("));
  const raw = loadSlice("hodlRenderRawTx");
  assert.ok(raw.indexOf("Repeated nonce r for the same public key") < raw.indexOf("hodlJournalNonceVerdict("));
});


