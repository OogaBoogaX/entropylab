import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import vm from "node:vm";
import { KEY_VAULT_MAX_KEYS, keyVaultIdentity } from "../src/js/keymanager.js";

const app = readFileSync(new URL("../src/js/app.js", import.meta.url), "utf8");
const originalFields = { seed: "published BIP39 vector 1", pass: "", derivationPath: "m/84'/0'/0'/{0-1}/{0-9}" };
const copy = value => JSON.parse(JSON.stringify(value));

function harness() {
  const original = { id: 1, number: 1, name: "Family savings", fields: copy(originalFields), result: { masterIdentity: "wallet-A", masterFingerprint: "aabbccdd" } };
  const lab = { id: 0, number: 0, name: "Key Station", isLab: true, fields: {}, result: null };
  let nextId = 3;
  const context = vm.createContext({
    hodlPassphraseVaultField: null, hodlPassphraseShown: false, TextEncoder, TextDecoder,
    hodlVanityApplying: false, hodlJournalUnlocked: () => false,
    hodlKeys: [lab, original], hodlActiveKey: 1,
    hodlNewKeyState: () => ({ id: nextId, number: nextId++, name: "New key", fields: {}, result: null }),
    hodlNewLabState: () => ({ id: 0, number: 0, name: "Key Station", isLab: true, fields: {}, result: null }),
    hodlCaptureKey() {}, hodlRenderKeyTabs() {}, hodlRestoreKey() {},
    hodlZeroKeyPassphrase(state) { if (ArrayBuffer.isView(state?.fields?.pass)) state.fields.pass.fill(0); },
    hodlReleaseKeyConsumers() {},
    // Secure entry stays off here; its wiring is covered in secure-entry-wiring.test.mjs.
    hodlSecureEntryHasData: () => false, hodlSecureKeyOf: () => null,
    hodlSelectKey: index => { context.hodlActiveKey = index; },
    hodlSelectLab: () => { context.hodlActiveKey = 0; },
    hodlKeyManagerPending: [], hodlKeyManagerIgnored: [], hodlKeyManagerIds: new Set(), hodlKeyManagerActiveId: "",
    hodlKeyVaultMaxKeys: KEY_VAULT_MAX_KEYS, keyVaultIdentity,
    hodlTText: (value, vars) => value.replace("{name}", String(vars?.name ?? "")),
    hodlT: (value, vars) => value.replace("{n}", String(vars?.n ?? "")).replace("{suffix}", String(vars?.suffix ?? "")),
  });
  for (const name of ["hodlNormalizeKeyName", "hodlKeyNameTaken", "hodlDefaultKeyName", "hodlCloneDerivedKey", "hodlKeyWalletIdentity", "hodlKeyManagerStates", "hodlKeyManagerHasInputs", "hodlKeyManagerCapacityError", "hodlCommitDerivedKey", "hodlFillLabFromKey", "hodlEditKeyInputs", "hodlStoredPassphraseBytes"]) {
    const source = app.match(new RegExp(`^function ${name}\\([^]*?^}`, "m"));
    assert.ok(source, name);
    vm.runInContext(source[0], context);
  }
  return { context, original };
}

test("Edit Input copies inputs; Derive New keeps the original even for identical wallet identity", () => {
  const { context, original } = harness();
  const before = copy(original);
  context.hodlEditKeyInputs();
  const draft = context.hodlKeys[0];
  assert.equal(draft.isLab, true);
  assert.equal(draft.result, null);
  assert.notEqual(draft.fields, original.fields);
  assert.deepEqual(copy(draft.fields), originalFields);
  draft.result = { ...original.result };
  context.hodlCommitDerivedKey();
  assert.equal(context.hodlKeys.length, 3);
  assert.equal(context.hodlKeys[1], original);
  assert.deepEqual(copy(original), before);
  assert.notEqual(context.hodlKeys[2].id, original.id);
  assert.equal(context.hodlKeys[0].editSourceId, undefined);
});

test("Derive New does not overwrite another wallet after edited inputs match it", () => {
  const { context, original } = harness();
  const other = { ...copy(original), id: 2, number: 2, name: "Other", result: { masterIdentity: "wallet-B", masterFingerprint: "bbccddee" } };
  context.hodlKeys.push(other);
  context.hodlEditKeyInputs();
  context.hodlKeys[0].result = { ...other.result };
  context.hodlCommitDerivedKey();
  assert.equal(context.hodlKeys.length, 4);
  assert.equal(context.hodlKeys[1], original);
  assert.equal(context.hodlKeys[2], other);
});

test("Update Existing replaces only the remembered source after it moves or its identity changes", () => {
  const { context, original } = harness();
  const other = { ...copy(original), id: 2, number: 2, name: "Other", result: { masterIdentity: "wallet-B", masterFingerprint: "bbccddee" } };
  context.hodlKeys.push(other);
  context.hodlEditKeyInputs();
  const draft = context.hodlKeys[0];
  draft.result = { ...other.result };
  context.hodlKeys = [draft, other, original];
  context.hodlCommitDerivedKey("update");
  assert.equal(context.hodlKeys.length, 3);
  assert.equal(context.hodlActiveKey, 2);
  assert.equal(context.hodlKeys[2].id, original.id);
  assert.equal(context.hodlKeys[2].name, original.name);
  assert.equal(context.hodlKeys[2].result.masterIdentity, "wallet-B");
  assert.equal(context.hodlKeys[1], other);
  assert.equal(context.hodlKeys[0].editSourceId, undefined);
});

test("Update refuses a deleted source, but Derive New remains available", () => {
  const { context, original } = harness();
  context.hodlEditKeyInputs();
  const draft = context.hodlKeys[0];
  context.hodlKeys.splice(1, 1);
  draft.result = { ...original.result };
  assert.throws(() => context.hodlCommitDerivedKey("update"));
  assert.equal(context.hodlKeys.length, 1);
  assert.equal(context.hodlKeys[0], draft);
  context.hodlCommitDerivedKey();
  assert.equal(context.hodlKeys.length, 2);
});

test("Update refuses a fresh station with no source", () => {
  const { context, original } = harness();
  context.hodlActiveKey = 0;
  context.hodlKeys[0].result = { ...original.result };
  assert.throws(() => context.hodlCommitDerivedKey("update"));
  assert.equal(context.hodlKeys[1], original);
});

test("loading external unverified inputs is not an edit of a station key", () => {
  const { context, original } = harness();
  const imported = { ...copy(original), id: 99, name: "Imported inputs" };
  const labIndex = context.hodlFillLabFromKey(imported);
  assert.equal(context.hodlKeys[labIndex].editSourceId, null);
  context.hodlActiveKey = labIndex;
  context.hodlKeys[labIndex].result = { ...original.result };
  context.hodlCommitDerivedKey();
  assert.equal(context.hodlKeys.length, 2);
  assert.equal(context.hodlKeys[1].id, original.id);
});

test("a derivation without a result keeps its source and the edit context", () => {
  const { context, original } = harness();
  context.hodlEditKeyInputs();
  context.hodlCommitDerivedKey("update");
  assert.equal(context.hodlKeys[1], original);
  assert.equal(context.hodlKeys[0].editSourceId, original.id);
});

test("ordinary fresh-station derivation keeps identity-based replacement and a saved name", () => {
  const { context, original } = harness();
  context.hodlActiveKey = 0;
  context.hodlKeys[0].result = { ...original.result };
  context.hodlCommitDerivedKey();
  assert.equal(context.hodlKeys.length, 2);
  assert.equal(context.hodlKeys[1].id, original.id);
  assert.equal(context.hodlKeys[1].name, original.name);
});

test("an automatic fingerprint tab label follows a changed underlying key", () => {
  const { context, original } = harness();
  original.name = "aabbccdd";
  context.hodlEditKeyInputs();
  context.hodlKeys[0].result = { masterIdentity: "wallet-B", masterFingerprint: "bbccddee" };
  context.hodlCommitDerivedKey("update");
  assert.equal(context.hodlKeys[1].name, "bbccddee");
});

test("Derive New numbers duplicate fingerprint labels from one", () => {
  const { context, original } = harness();
  original.name = original.result.masterFingerprint;
  for (const suffix of [1, 2]) {
    context.hodlActiveKey = 1;
    context.hodlEditKeyInputs();
    context.hodlKeys[0].result = { ...original.result };
    context.hodlCommitDerivedKey();
    assert.equal(context.hodlKeys[1 + suffix].name, `${original.result.masterFingerprint} (${suffix})`);
    assert.equal(context.hodlKeys[1], original);
  }
});

test("an invalid or missing edit context keeps Update unavailable and uses text-only status", () => {
  const { context, original } = harness();
  const elements = Object.fromEntries(["go", "key-update", "key-edit-note"].map(id => [id, {
    id, hidden: true, disabled: true, dataset: {}, attributes: {}, style: { removeProperty() {} },
    getBoundingClientRect: () => ({ width: 100 }),
    setAttribute(name, value) { this.attributes[name] = value; },
    removeAttribute(name) { delete this.attributes[name]; },
    set innerHTML(_) { assert.fail("Edit status must not become an HTML sink"); },
  }]));
  context.document = { getElementById: id => elements[id] || null };
  context.hodlActiveDerivation = null;
  context.hodlCanDeriveCurrentKey = () => true;
  for (const name of ["hodlDerivationButton", "hodlSetDerivationButtonState", "hodlSyncDeriveButton"]) {
    vm.runInContext(app.match(new RegExp(`^function ${name}\\([^]*?^}`, "m"))[0], context);
  }
  context.hodlEditKeyInputs();
  original.name = "<img src=x onerror=alert(1)>";
  context.hodlSyncDeriveButton();
  assert.equal(elements["key-edit-note"].hidden, false);
  assert.ok(elements["key-edit-note"].textContent);
  assert.equal(elements["key-update"].disabled, false);
  assert.equal(elements.go.disabled, false);
  context.hodlCanDeriveCurrentKey = () => false;
  context.hodlSyncDeriveButton();
  assert.equal(elements["key-update"].disabled, true);
  assert.equal(elements.go.disabled, true);
  context.hodlCanDeriveCurrentKey = () => true;
  context.hodlKeys.splice(1, 1);
  context.hodlSyncDeriveButton();
  assert.equal(elements["key-update"].disabled, true);
  assert.equal(elements.go.disabled, false);
});

test("a running key edit action owns Stop and disables its peer", () => {
  const { context } = harness();
  const elements = Object.fromEntries(["go", "key-update", "key-edit-note"].map(id => [id, {
    id, hidden: true, disabled: true, dataset: {}, style: { removeProperty() {} },
    getBoundingClientRect: () => ({ width: 100 }),
    setAttribute() {}, removeAttribute() {},
  }]));
  context.document = { getElementById: id => elements[id] || null };
  context.hodlCanDeriveCurrentKey = () => true;
  context.hodlEditKeyInputs();
  for (const name of ["hodlDerivationButton", "hodlSetDerivationButtonState", "hodlSyncDeriveButton"]) {
    vm.runInContext(app.match(new RegExp(`^function ${name}\\([^]*?^}`, "m"))[0], context);
  }
  for (const buttonId of ["go", "key-update"]) {
    context.hodlActiveDerivation = { kind: "key", buttonId, cancelled: false };
    context.hodlSyncDeriveButton();
    assert.equal(elements[buttonId].dataset.derivationState, "running");
    assert.equal(elements[buttonId].disabled, false);
    assert.equal(elements[buttonId === "go" ? "key-update" : "go"].disabled, true);
    context.hodlActiveDerivation.cancelled = true;
    context.hodlSyncDeriveButton();
    assert.equal(elements[buttonId].dataset.derivationState, "stopping");
    assert.equal(elements[buttonId].disabled, true);
    context.hodlActiveDerivation = null;
    context.hodlSyncDeriveButton();
    assert.equal(elements.go.disabled, false);
    assert.equal(elements["key-update"].disabled, false);
  }
});

test("low-entropy confirmation retains the Update action's button identity", () => {
  const { context } = harness();
  let continueDerive, invoked;
  context.hodlActiveDerivation = null;
  context.hodlLowEntropyWarning = () => ({ bits: 1 });
  context.hodlLowEntropyConfirm = { isAcknowledged: () => false, open: (_warning, callback) => { continueDerive = callback; } };
  context.hodlDeriveWithProgress = (...args) => { invoked = args; };
  vm.runInContext(app.match(/^function hodlHandleDerivationButton\([^]*?^}/m)[0], context);
  context.hodlHandleDerivationButton("key", () => {}, "key-update");
  assert.ok(continueDerive);
  continueDerive();
  assert.equal(invoked[2], "key-update");
});
