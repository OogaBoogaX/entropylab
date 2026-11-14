import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import vm from "node:vm";

const app = readFileSync(new URL("../src/js/app.js", import.meta.url), "utf8");
const fields = {
  m: "2", n: "3", script: "p2wsh", keyOrder: "sorted", network: "mainnet",
  xpubs: ["cosigner-a", "cosigner-b", "cosigner-c"], specs: ["bip48", "bip48", "bip48"],
  branchStart: "0", branchRange: "2", addressStart: "11", addressRange: "5",
  descriptor: "", thresholdLocked: false, reuseSessionKeys: true,
};
const json = (value) => JSON.parse(JSON.stringify(value));

function harness() {
  const original = { id: 1, number: 1, name: "Original", fields: json(fields), result: { kind: "msig", m: 2, n: 3, script: "p2wsh" }, createdPolicy: "2-of-3" };
  const lab = { id: 0, number: 0, isLab: true, fields: {}, result: null };
  let nextId = 3;
  const context = vm.createContext({
    hodlMsigs: [lab, original], hodlActiveMsig: 1,
    hodlNewMsigState: () => ({ id: nextId, number: nextId++, name: "New", fields: {} }),
    hodlNewMsigLabState: () => ({ id: 0, number: 0, isLab: true, fields: {}, result: null }),
    hodlMsigNameTaken: () => false, hodlMsigPolicyName: () => "2-of-3",
    hodlTText: (text, vars) => text.replace(/\{(\w+)\}/g, (whole, name) => (vars?.[name] == null ? whole : String(vars[name]))),
    hodlCaptureMsig() {}, hodlRenderMsigTabs() {}, hodlRestoreMsig() {}, hodlSelectMsigLab() {},
    hodlSelectMsig: (index) => { context.hodlActiveMsig = index; },
  });
  for (const name of ["hodlMsigHasResult", "hodlCloneDerivedMsig", "hodlMsigIdentity", "hodlCommitDerivedMsig", "hodlFillMsigLabFromWallet", "hodlEditMsigInputs"]) {
    const source = app.match(new RegExp(`^function ${name}\\([^]*?^}`, "m"));
    if (source) vm.runInContext(source[0], context);
  }
  return { context, original };
}

test("Edit Input copies all inputs; Derive New creates a separate tab even for identical inputs", () => {
  const { context, original } = harness();
  const before = json(original);
  context.hodlEditMsigInputs();
  const draft = context.hodlMsigs[context.hodlActiveMsig];
  assert.equal(draft.isLab, true);
  assert.equal(draft.result, null);
  assert.deepEqual(json(draft.fields), fields);
  assert.notEqual(draft.fields.xpubs, original.fields.xpubs);
  assert.notEqual(draft.fields.specs, original.fields.specs);
  draft.result = { ...original.result };
  context.hodlCommitDerivedMsig();
  assert.equal(context.hodlMsigs.length, 3);
  assert.equal(context.hodlMsigs[1], original);
  assert.deepEqual(json(original), before);
  assert.notEqual(context.hodlMsigs[context.hodlActiveMsig].id, original.id);
  assert.equal(context.hodlMsigs[0].editSourceId, undefined);
});

test("Derive New with changed inputs never replaces another matching wallet", () => {
  const { context, original } = harness();
  const other = { ...original, id: 2, number: 2, fields: { ...json(fields), m: "1" } };
  context.hodlMsigs.push(other);
  context.hodlEditMsigInputs();
  const draft = context.hodlMsigs[context.hodlActiveMsig];
  draft.fields.m = "1";
  draft.result = { ...original.result, m: 1 };
  context.hodlCommitDerivedMsig();
  assert.equal(context.hodlMsigs.length, 4);
  assert.equal(context.hodlMsigs[1], original);
  assert.equal(context.hodlMsigs[2], other);
});

test("Update Existing replaces the source by stable id after its policy changes to match another wallet", () => {
  const { context, original } = harness();
  const other = { ...original, id: 2, number: 2, fields: { ...json(fields), m: "1" } };
  context.hodlMsigs.push(other);
  context.hodlEditMsigInputs();
  const draft = context.hodlMsigs[context.hodlActiveMsig];
  draft.fields.m = "1";
  draft.fields.keyOrder = "listed";
  draft.result = { kind: "msig", m: 1, n: 3, script: "p2wsh" };
  // Moving a tab must not change which wallet Update targets.
  context.hodlMsigs = [draft, other, original];
  context.hodlCommitDerivedMsig("update");
  assert.equal(context.hodlMsigs.length, 3);
  assert.equal(context.hodlActiveMsig, 2);
  assert.equal(context.hodlMsigs[2].id, original.id);
  assert.equal(context.hodlMsigs[2].number, original.number);
  assert.equal(context.hodlMsigs[2].name, original.name);
  assert.equal(context.hodlMsigs[2].fields.m, "1");
  assert.equal(context.hodlMsigs[2].fields.keyOrder, "listed");
  assert.equal(context.hodlMsigs[1], other);
  assert.equal(context.hodlMsigs[0].editSourceId, undefined);
});

test("an unsuccessful derive keeps the source and its edit context", () => {
  const { context, original } = harness();
  const before = json(original);
  context.hodlEditMsigInputs();
  context.hodlCommitDerivedMsig("update");
  assert.equal(context.hodlMsigs.length, 2);
  assert.equal(context.hodlMsigs[1], original);
  assert.deepEqual(json(original), before);
  assert.equal(context.hodlMsigs[0].editSourceId, original.id);
});

test("Update refuses a deleted source; Derive New can still commit the copied inputs", () => {
  const { context, original } = harness();
  context.hodlEditMsigInputs();
  const draft = context.hodlMsigs[0];
  context.hodlMsigs.splice(1, 1);
  draft.result = { ...original.result };
  assert.throws(() => context.hodlCommitDerivedMsig("update"));
  assert.equal(context.hodlMsigs.length, 1);
  assert.equal(context.hodlMsigs[0], draft);
  context.hodlCommitDerivedMsig();
  assert.equal(context.hodlMsigs.length, 2);
  assert.notEqual(context.hodlMsigs[1].id, original.id);
});

test("Update refuses a fresh station with no source even when its inputs match a wallet", () => {
  const { context, original } = harness();
  context.hodlActiveMsig = 0;
  Object.assign(context.hodlMsigs[0], { fields: json(fields), result: { ...original.result } });
  assert.throws(() => context.hodlCommitDerivedMsig("update"));
  assert.equal(context.hodlMsigs[1], original);
  assert.equal(context.hodlMsigs.length, 2);
});

test("editing a different wallet replaces the previous source context", () => {
  const { context, original } = harness();
  const other = { ...original, id: 2, number: 2, fields: { ...json(fields), m: "1" } };
  context.hodlMsigs.push(other);
  context.hodlEditMsigInputs();
  context.hodlActiveMsig = 2;
  context.hodlEditMsigInputs();
  assert.equal(context.hodlMsigs[0].editSourceId, other.id);
  assert.equal(context.hodlMsigs[0].fields.m, "1");
});

test("ordinary station derivation retains existing identity-based replacement", () => {
  const { context, original } = harness();
  context.hodlActiveMsig = 0;
  Object.assign(context.hodlMsigs[0], { fields: json(fields), result: { ...original.result } });
  context.hodlCommitDerivedMsig();
  assert.equal(context.hodlMsigs.length, 2);
  assert.equal(context.hodlActiveMsig, 1);
  assert.equal(context.hodlMsigs[1].id, original.id);
  assert.equal(context.hodlMsigs[1].name, original.name);
});

test("a multisig tab displays its stored name even when it has a saved quorum", () => {
  const { context, original } = harness();
  context.document = { createElement: () => ({
    children: [], dataset: {}, attributes: {},
    append(...children) { this.children.push(...children); },
    setAttribute(name, value) { this.attributes[name] = value; },
  }) };
  context.hodlCreateMsigTabMark = () => ({});
  vm.runInContext(app.match(/^function hodlCreateMsigTab\([^]*?^}/m)[0], context);
  for (const name of ["Family savings", "Travel fund", "<b>Literal name</b>"]) {
    original.name = name;
    const button = context.hodlCreateMsigTab(1);
    assert.equal(button.children[1].textContent, name);
    assert.ok(button.attributes["aria-label"].includes(name));
  }
});

function actionHarness() {
  const { context, original } = harness();
  const elements = Object.fromEntries(["msig-go", "msig-update", "msig-edit-note"].map((id) => [id, {
    id, hidden: true, disabled: true, dataset: {}, attributes: {}, style: { removeProperty() {} },
    getBoundingClientRect: () => ({ width: 100 }),
    setAttribute(name, value) { this.attributes[name] = value; },
    removeAttribute(name) { delete this.attributes[name]; },
    set innerHTML(_) { assert.fail("An edit status must not become an HTML sink"); },
  }]));
  Object.assign(context, {
    document: { getElementById: (id) => elements[id] || null },
    hodlActiveDerivation: null,
    hodlValidatedMsigInputs() {},
  });
  for (const name of ["hodlDerivationButton", "hodlSetDerivationButtonState", "hodlSyncMsigDeriveButton"]) {
    vm.runInContext(app.match(new RegExp(`^function ${name}\\([^]*?^}`, "m"))[0], context);
  }
  context.hodlEditMsigInputs();
  return { context, elements, original };
}

test("both edit actions share validation; a missing source disables only Update", () => {
  const { context, elements, original } = actionHarness();
  original.name = "<img src=x onerror=alert(1)>";
  context.hodlSyncMsigDeriveButton();
  assert.equal(elements["msig-edit-note"].hidden, false);
  assert.ok(elements["msig-edit-note"].textContent);
  assert.equal(elements["msig-update"].hidden, false);
  assert.equal(elements["msig-update"].disabled, false);
  assert.equal(elements["msig-go"].disabled, false);
  context.hodlValidatedMsigInputs = () => { throw new Error("Invalid inputs"); };
  context.hodlSyncMsigDeriveButton();
  for (const id of ["msig-update", "msig-go"]) {
    assert.equal(elements[id].disabled, true);
    assert.equal(elements[id].attributes["aria-disabled"], "true");
  }
  context.hodlValidatedMsigInputs = () => {};
  context.hodlMsigs.splice(1, 1);
  context.hodlSyncMsigDeriveButton();
  assert.equal(elements["msig-update"].disabled, true);
  assert.equal(elements["msig-go"].disabled, false);
  context.hodlMsigs[0] = context.hodlNewMsigLabState();
  context.hodlSyncMsigDeriveButton();
  assert.equal(elements["msig-update"].hidden, true);
  assert.equal(elements["msig-edit-note"].hidden, true);
});

test("each running edit action owns Stop and disables its peer until idle", () => {
  for (const id of ["msig-update", "msig-go"]) {
    const { context, elements } = actionHarness();
    const peer = elements[id === "msig-update" ? "msig-go" : "msig-update"];
    context.hodlActiveDerivation = { kind: "msig", buttonId: id, cancelled: false };
    context.hodlSyncMsigDeriveButton();
    assert.equal(elements[id].dataset.derivationState, "running");
    assert.equal(elements[id].disabled, false);
    assert.equal(peer.disabled, true);
    context.hodlActiveDerivation.cancelled = true;
    context.hodlSyncMsigDeriveButton();
    assert.equal(elements[id].dataset.derivationState, "stopping");
    assert.equal(elements[id].disabled, true);
    context.hodlActiveDerivation = null;
    context.hodlSyncMsigDeriveButton();
    assert.equal(elements[id].dataset.derivationState, undefined);
    assert.equal(elements[id].disabled, false);
    assert.equal(peer.disabled, false);
  }
});

test("a running key derivation disables both multisig actions", () => {
  const { context, elements } = actionHarness();
  context.hodlActiveDerivation = { kind: "key", cancelled: false };
  context.hodlSyncMsigDeriveButton();
  for (const id of ["msig-update", "msig-go"]) {
    assert.equal(elements[id].disabled, true);
    assert.equal(elements[id].attributes["aria-disabled"], "true");
  }
});
