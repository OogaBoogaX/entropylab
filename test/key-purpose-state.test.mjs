// The purpose toggle commits one consistent result to the same key only after
// success. Failure, cancellation, deletion or switching keys must leave the
// previous result/settings and other keys alone. Cryptographic outputs are
// covered independently in key-purpose-match.test.mjs and the browser suite.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import vm from "node:vm";

const source = readFileSync(new URL("../src/js/app.js", import.meta.url), "utf8");
const extract = (name) => {
  const match = source.match(new RegExp(`^(?:async )?function ${name}\\([^]*?^}`, "m"));
  assert.ok(match, name);
  return match[0];
};
const clone = value => JSON.parse(JSON.stringify(value));
function harness() {
  const previous = { eligible: true, accounts: [{ accountPath: "m/100/0'/3'" }], masterIdentity: "root-A" };
  const state = { id: 7, name: "Personal key", accountId: "bip86", fields: { derivationPath: "m/100/0'/3'/0/7" }, result: previous };
  const other = { id: 8, fields: { derivationPath: "m/42'/0'/0'/0/0" }, result: { masterIdentity: "root-B" } };
  let resolve, reject, calls = [], restored = 0, disposed = 0, captured = 0;
  const pending = new Promise((yes, no) => { resolve = yes; reject = no; });
  const control = { cancelled: false };
  const context = vm.createContext({
    hodlKeys: [state, other], hodlActiveKey: 0, hodlWalletResult: previous,
    hodlDerivationGeneration: 0, hodlActiveDerivation: control,
    hodlCommittedResults: new Set([previous]), hodlWalletDatBirthday: "now",
    HodlDerivationCancelledError: class extends Error {},
    hodlCanMatchPurpose: wallet => Boolean(wallet?.eligible),
    hodlParseCustomDerivationPath: () => ({ components: [{ index: 100, hardened: false }] }),
    hodlWalletWithPurposeMatch: async (wallet, enabled, original, tracker) => {
      calls.push({ wallet, enabled, original: clone(original), tracker });
      tracker.step();
      return pending;
    },
    hodlRestoreKey: () => { restored++; },
    hodlJournalCaptureDerivedKey: () => { captured++; },
    hodlDisposeDroppedWallets: () => { disposed++; },
    hodlErrorSpecFrom: error => ({ raw: error.message }),
    hodlFormatErrorSpec: spec => spec?.raw || "",
    hodlSetWorkspaceError() {},
  });
  vm.runInContext(["hodlAssertDerivationActive", "hodlApplyPurposeMatch"].map(extract).join("\n"), context);
  const progress = { setTotal() {}, step() {} };
  return { context, state, other, previous, control, resolve, reject, calls, start: enabled => context.hodlApplyPurposeMatch(state, enabled, progress), counters: () => ({ restored, disposed, captured }) };
}

test("purpose changes commit atomically to the existing key without changing another key", async () => {
  const ui = harness(), before = clone(ui.state), otherBefore = clone(ui.other), operation = ui.start(true);
  assert.deepEqual(clone(ui.state), before, "settings moved while the old keys were still shown");
  assert.equal(ui.context.hodlWalletResult, ui.previous);
  const replacement = { ...ui.previous, purposeMatch: true, originalPurpose: { index: 100, hardened: false }, accounts: [{ accountPath: "m/86'/0'/3'" }] };
  ui.resolve(replacement);
  assert.equal(await operation, true);
  assert.equal(ui.context.hodlKeys[0], ui.state);
  assert.equal(ui.state.id, 7);
  assert.equal(ui.state.name, "Personal key");
  assert.equal(ui.state.accountId, "bip86");
  assert.equal(ui.state.result, replacement);
  assert.equal(ui.context.hodlWalletResult, replacement);
  assert.ok(ui.context.hodlCommittedResults.has(replacement));
  assert.equal(ui.context.hodlWalletDatBirthday, "now", "purpose matching changed another export's birthday preference");
  assert.deepEqual(clone(ui.other), otherBefore);
  assert.deepEqual(ui.counters(), { restored: 1, disposed: 1, captured: 1 });
});

test("unchecking uses the remembered original even though the live path is standard", async () => {
  const ui = harness();
  ui.previous.purposeMatch = true;
  ui.previous.originalPurpose = { index: 100, hardened: false };
  ui.previous.accounts[0].accountPath = "m/86'/0'/3'";
  ui.context.hodlParseCustomDerivationPath = () => { throw new Error("must use saved original"); };
  const operation = ui.start(false);
  assert.deepEqual(ui.calls[0].original, { index: 100, hardened: false });
  assert.equal(ui.calls[0].enabled, false);
  ui.resolve({ ...ui.previous, purposeMatch: false });
  assert.equal(await operation, true);
});

test("failed derivation leaves the previous result, script and path usable", async () => {
  const ui = harness(), fields = clone(ui.state.fields), operation = ui.start(true);
  ui.reject(new Error("fixture derivation failed"));
  assert.equal(await operation, false);
  assert.equal(ui.state.result, ui.previous);
  assert.equal(ui.context.hodlWalletResult, ui.previous);
  assert.deepEqual(clone(ui.state.fields), fields);
  assert.equal(ui.state.accountId, "bip86");
  assert.ok(ui.state.errorSpec);
  assert.deepEqual(ui.counters(), { restored: 0, disposed: 0, captured: 0 });
});

for (const reason of ["cancel", "generation", "switch", "delete", "replace"]) test(`${reason} during purpose derivation cannot commit stale results`, async () => {
  const ui = harness(), operation = ui.start(true), fields = clone(ui.state.fields);
  if (reason === "cancel") ui.control.cancelled = true;
  if (reason === "generation") ui.context.hodlDerivationGeneration++;
  if (reason === "switch") ui.context.hodlActiveKey = 1;
  if (reason === "delete") ui.context.hodlKeys.splice(0, 1);
  if (reason === "replace") ui.state.result = { masterIdentity: "new-result" };
  const current = ui.state.result;
  assert.throws(() => ui.calls[0].tracker.step(), ui.context.HodlDerivationCancelledError);
  ui.resolve({ purposeMatch: true });
  await assert.rejects(operation, ui.context.HodlDerivationCancelledError);
  assert.equal(ui.state.result, current);
  assert.equal(ui.context.hodlWalletResult, ui.previous);
  assert.deepEqual(clone(ui.state.fields), fields);
  assert.deepEqual(ui.counters(), { restored: 0, disposed: 0, captured: 0 });
});

test("unsupported sources and the input station never invoke purpose derivation", async () => {
  for (const lab of [false, true]) {
    const ui = harness();
    ui.state.isLab = lab;
    ui.previous.eligible = lab;
    assert.equal(await ui.start(true), false);
    assert.equal(ui.calls.length, 0);
    assert.equal(ui.state.result, ui.previous);
  }
});

test("ordinary derivation completion unlocks the result controls after clearing the active run", async () => {
  const states = [], context = vm.createContext({
    document: { getElementById: () => null }, hodlActiveDerivation: null,
    hodlDerivationProgressTimers: {}, setTimeout: () => 1,
    hodlDerivationPause: async () => {},
    hodlCreateDerivationTracker: () => ({ complete() {} }),
    hodlResetDerivationProgress() {}, hodlSetDerivationButtonState() {},
    hodlSyncDeriveButton() {}, hodlSyncMsigDeriveButton() {}, hodlSettleDerivationKeys() {},
    hodlSyncPurposeMatchControls: () => states.push(Boolean(context.hodlActiveDerivation)),
    HodlDerivationCancelledError: class extends Error {},
  });
  vm.runInContext(extract("hodlDeriveWithProgress"), context);
  await context.hodlDeriveWithProgress("key", async () => true);
  assert.equal(context.hodlActiveDerivation, null);
  assert.equal(states.at(-1), false, "result controls never learned that derivation finished");
});
