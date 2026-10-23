import { test } from "node:test";
import assert from "node:assert/strict";
import { loadAppFunctions } from "./app-slice-harness.mjs";
import { MiniDocument } from "./mini-dom.mjs";

const inputState = (id, name = `Input ${id}`) => ({
  id, number: id, name, mode: "seed", needsDerivation: true, result: null,
  fields: { network: "testnet", derivationPath: "m/84'/1'/0'/0/0" },
});

async function keyUi(t, { pending = [], keys = [], archived = [] } = {}) {
  const page = new MiniDocument(), previousDocument = globalThis.document;
  globalThis.document = page;
  t.after(() => { globalThis.document = previousDocument; });
  const create = page.createElement.bind(page);
  page.createElement = (tag) => {
    const element = create(tag);
    element.contains = (target) => {
      for (let node = target; node; node = node.parentNode) if (node === element) return true;
      return false;
    };
    element.focus = () => { if (!element.disabled && element.isConnected) page.activeElement = element; };
    element.setSelectionRange = (start, end, direction = "none") => {
      element.selectionStart = start; element.selectionEnd = end; element.selectionDirection = direction;
    };
    Object.defineProperty(element, "firstElementChild", { get: () => element.children[0] || null });
    return element;
  };
  for (const [id, tag] of [
    ["journal-keymanager-tab", "button"], ["journal-keymanager-tabs", "div"],
    ["journal-keymanager-panel", "div"], ["journal-keymanager-status", "p"],
    ["journal-keymanager-derive", "button"], ["journal-keymanager-download", "button"],
    ["journal-keymanager-add-all", "button"],
    ["journal-keymanager-upload", "button"], ["journal-keymanager-file", "input"],
    ["journal-keymanager-ignored-list", "div"], ["outside", "button"],
  ]) {
    const element = page.createElement(tag);
    element.id = id;
    page.body.append(element);
  }
  const calls = { log: [], reveal: [], use: [] };
  const variables = ["hodlKeys", "hodlKeyManagerPending", "hodlKeyManagerIgnored", "hodlKeyManagerActiveId", "hodlActiveDerivation", "hodlJournalKeyDerivation"];
  const api = await loadAppFunctions([
    "hodlKeyManagerRender", "hodlKeyManagerRename", "hodlKeyManagerDetails", "hodlKeyManagerSyncDerivationUI",
    "hodlDeriveWithProgress", "hodlDerivationProgressTimers", ...variables,
  ], {
    stubs: {
      hodlNewLabState: () => ({ isLab: true }), hodlKeyManagerRenderIgnored() {}, hodlRenderKeyTabs() {},
      hodlFillKeyTabLifehash() {}, hodlKeyManagerIgnore() {}, hodlKeyManagerDeriveInputs() {}, hodlKeyManagerReviewInputs() {},
      hodlKeyManagerUseInStation: (state) => calls.use.push(state),
      hodlRevealTab: (tabs, index) => calls.reveal.push(tabs.children[index]),
      hodlKeySummaryMethod: (state) => state.mode,
      hodlJournalLog: (...args) => calls.log.push(args),
      hodlResetDerivationProgress() {}, hodlSetDerivationButtonState() {}, hodlSyncDeriveButton() {},
      hodlSyncMsigDeriveButton() {}, hodlSyncPurposeMatchControls() {}, hodlSettleDerivationKeys() {},
      hodlDerivationPause: async () => {}, hodlCreateDerivationTracker: () => ({ complete() {} }),
      HodlDerivationCancelledError: class extends Error {},
    }, settable: variables,
  });
  api.__set.hodlKeys(keys);
  api.__set.hodlKeyManagerPending(pending);
  api.__set.hodlKeyManagerIgnored(archived);
  api.__set.hodlKeyManagerActiveId("");
  api.__set.hodlActiveDerivation(null);
  api.__set.hodlJournalKeyDerivation(null);
  t.after(() => { for (const timer of Object.values(api.hodlDerivationProgressTimers)) clearTimeout(timer); });
  return { api, page, calls, el: (id) => page.getElementById(`journal-keymanager-${id}`) };
}

test("Keys toolbar availability follows pending work and exportable inventory", async (t) => {
  const { api, el } = await keyUi(t);
  for (const { pending = [], archived = [], running = null, other = null, hidden, disabled, downloadDisabled } of [
    { hidden: true, disabled: true, downloadDisabled: true },
    { archived: [inputState(3)], hidden: true, disabled: true, downloadDisabled: false },
    { pending: [inputState(1)], hidden: false, disabled: false, downloadDisabled: false },
    { pending: [inputState(1)], other: {}, hidden: false, disabled: true, downloadDisabled: false },
    { running: {}, hidden: false, disabled: false, downloadDisabled: true },
  ]) {
    api.__set.hodlKeyManagerPending(pending);
    api.__set.hodlKeyManagerIgnored(archived);
    api.__set.hodlJournalKeyDerivation(running);
    api.__set.hodlActiveDerivation(other);
    api.hodlKeyManagerRender();
    assert.equal(el("derive").hidden, hidden);
    assert.equal(el("derive").disabled, disabled);
    assert.equal(el("download").disabled, downloadDisabled);
    assert.equal(el("upload").disabled, Boolean(running || other));
    assert.equal(el("file").disabled, Boolean(running || other));
  }
});

test("bulk reopening appears only for multiple verified detached keys and respects both busy controllers", async (t) => {
  const first = { ...inputState(1), needsDerivation: false, result: {} }, second = { ...inputState(2), needsDerivation: false, result: {} };
  const { api, el } = await keyUi(t);
  for (const { pending = [], keys = [], archived = [], busy = null, batch = null, hidden, disabled } of [
    { hidden: true, disabled: true },
    { pending: [first], hidden: true, disabled: true },
    { pending: [inputState(3), inputState(4)], archived: [first, second], hidden: true, disabled: true },
    { pending: [first, { ...second, result: null }], hidden: true, disabled: true },
    { pending: [first, second], keys: [first], hidden: true, disabled: true },
    { pending: [first, { ...first, name: "same entry" }], hidden: true, disabled: true },
    { pending: [first, second, inputState(3)], hidden: false, disabled: false },
    { pending: [first, second], busy: {}, hidden: false, disabled: true },
    { pending: [first, second], batch: {}, hidden: false, disabled: true },
  ]) {
    api.__set.hodlKeys(keys);
    api.__set.hodlKeyManagerPending(pending);
    api.__set.hodlKeyManagerIgnored(archived);
    api.__set.hodlActiveDerivation(busy);
    api.__set.hodlJournalKeyDerivation(batch);
    api.hodlKeyManagerSyncDerivationUI();
    assert.equal(el("add-all").hidden, hidden);
    assert.equal(el("add-all").disabled, disabled);
  }
});

test("station derivation blocks Journal import until idle while Journal batch Stop remains available", async (t) => {
  const { api, el } = await keyUi(t, { pending: [inputState(1)] });
  api.__set.hodlActiveDerivation({ kind: "key" });
  api.hodlKeyManagerSyncDerivationUI();
  assert.equal(el("upload").disabled, true, "Import must not offer a batch that cannot start during station derivation");
  assert.equal(el("file").disabled, true, "the file picker must share Import's busy guard");
  assert.equal(el("derive").disabled, true);
  api.__set.hodlActiveDerivation(null);
  api.hodlKeyManagerSyncDerivationUI();
  assert.equal(el("upload").disabled, false);
  assert.equal(el("file").disabled, false);
  assert.equal(el("derive").disabled, false);
  api.__set.hodlJournalKeyDerivation({});
  api.__set.hodlActiveDerivation({ kind: "key" });
  api.__set.hodlKeyManagerPending([]);
  api.hodlKeyManagerSyncDerivationUI();
  assert.equal(el("upload").disabled, true);
  assert.equal(el("file").disabled, true);
  assert.equal(el("derive").hidden, false, "batch Stop must survive the last pending input");
  assert.equal(el("derive").disabled, false, "the active batch must remain stoppable");
});

test("starting station derivation immediately updates the Journal toolbar", async (t) => {
  const { api, el } = await keyUi(t, { pending: [inputState(1)] });
  api.hodlKeyManagerRender();
  const operation = api.hodlDeriveWithProgress("key", async () => false, "derive");
  try {
    assert.equal(el("upload").disabled, true, "derivation started without disabling Import");
    assert.equal(el("file").disabled, true);
    assert.equal(el("derive").disabled, true);
  } finally {
    await operation;
  }
});

for (const outcome of ["success", "rejected", "error", "cancelled"]) {
  test(`ending station derivation restores the Journal toolbar after ${outcome}`, async (t) => {
    const { api, el } = await keyUi(t, { pending: [inputState(1)] });
    api.hodlKeyManagerRender();
    const failure = new Error("fixture derivation failure");
    const operation = api.hodlDeriveWithProgress("key", async () => {
      if (outcome === "error") throw failure;
      return outcome !== "rejected";
    }, "derive");
    if (outcome === "cancelled") api.hodlActiveDerivation.cancelled = true;
    api.hodlKeyManagerSyncDerivationUI();
    assert.equal(el("upload").disabled, true);
    if (outcome === "error") await assert.rejects(operation, error => error === failure);
    else await operation;
    assert.equal(api.hodlActiveDerivation, null);
    assert.equal(el("upload").disabled, false, "finished derivation left Import disabled");
    assert.equal(el("file").disabled, false);
    assert.equal(el("derive").disabled, false);
  });
}

test("derivation availability refreshes existing entry actions and archived Restore without rebuilding them", async (t) => {
  const pending = inputState(1), live = { ...inputState(2), needsDerivation: false, result: {} };
  const { api, page, el } = await keyUi(t, { pending: [pending], keys: [live] });
  api.__set.hodlKeyManagerActiveId("1");
  api.hodlKeyManagerRender();
  const actions = ["open", "archive", "review"].map(action => el("panel").querySelector(`[data-keymanager-action="${action}"]`));
  const restore = page.createElement("button");
  restore.dataset.keymanagerAction = "restore";
  el("ignored-list").append(restore);
  for (const kind of ["station", "journal"]) {
    api.__set.hodlActiveDerivation(kind === "station" ? { kind: "key" } : null);
    api.__set.hodlJournalKeyDerivation(kind === "journal" ? {} : null);
    api.hodlKeyManagerSyncDerivationUI();
    for (const action of [...actions, restore]) assert.equal(action.disabled, true, `${kind} derivation left a conflicting action enabled`);
    api.__set.hodlActiveDerivation(null);
    api.__set.hodlJournalKeyDerivation(null);
    api.hodlKeyManagerSyncDerivationUI();
    for (const action of [...actions, restore]) {
      assert.equal(action.disabled, false, "finished derivation left an action disabled");
      assert.equal(action.isConnected, true, "availability changes replaced the existing action");
    }
  }
  api.__set.hodlKeyManagerActiveId("2");
  api.hodlKeyManagerRender();
  const archiveLive = el("panel").querySelector('[data-keymanager-action="archive"]');
  api.__set.hodlActiveDerivation({ kind: "key" });
  api.hodlKeyManagerSyncDerivationUI();
  api.__set.hodlActiveDerivation(null);
  api.hodlKeyManagerSyncDerivationUI();
  assert.equal(archiveLive.disabled, true, "a key still in Key Station cannot be archived");
});

test("an emptied Keys panel never retains a removed tab as its accessible label", async (t) => {
  const { api, page, el } = await keyUi(t, { pending: [inputState(1)] });
  api.hodlKeyManagerRender();
  assert.ok(page.getElementById(el("panel").getAttribute("aria-labelledby")));
  api.__set.hodlKeyManagerPending([]);
  api.__set.hodlKeyManagerIgnored([inputState(1)]);
  api.hodlKeyManagerRender();
  const label = el("panel").getAttribute("aria-labelledby");
  assert.ok(!label || page.getElementById(label), "the empty panel references a removed tab");
  assert.equal(el("tabs").children.length, 0);
  assert.ok(el("panel").textContent.trim(), "the empty panel needs guidance");
  assert.equal(el("download").disabled, false, "archived inputs remain exportable");
});

test("pending input details include the saved network without inventing a verified identity", async (t) => {
  const pending = inputState(1);
  const { api, el } = await keyUi(t, { pending: [pending] });
  api.hodlKeyManagerRender();
  assert.equal(el("panel").querySelector('[data-keymanager-detail="network"]')?.textContent, pending.fields.network);
  assert.equal(el("panel").querySelector('[data-keymanager-detail="path"]')?.textContent, pending.fields.derivationPath);
  assert.equal(el("panel").querySelector('[data-keymanager-detail="fingerprint"]'), null);
});

test("single private keys receive the same private-material guidance as other private results", async (t) => {
  const { api } = await keyUi(t);
  const details = (result) => api.hodlKeyManagerDetails({ ...inputState(1), needsDerivation: false, result });
  const guidance = (result) => details(result).find((row) => row[3] === "private-material")?.[1];
  const hd = guidance({ rootNode: {} }), single = guidance({ privateKey: Uint8Array.of(1) });
  assert.ok(hd && single);
  assert.equal(single, hd, "a single private key was classified as lacking private output");
  assert.notEqual(single, guidance({}), "private and public-only results need distinct recovery guidance");
});

test("renaming updates the current key without replacing the next pointer action", async (t) => {
  const state = { ...inputState(1), needsDerivation: false, result: {} };
  const { api, page, calls, el } = await keyUi(t, { pending: [state] });
  api.hodlKeyManagerRender();
  const rename = el("panel").querySelector('[data-keymanager-action="rename"]');
  const open = el("panel").querySelector('[data-keymanager-action="open"]');
  rename.focus();
  rename.value = "  New   name  ";
  rename.dispatchEvent({ type: "change", target: rename });
  assert.equal(state.name, "New name");
  assert.equal(rename.value, state.name);
  assert.equal(rename.isConnected, true);
  assert.equal(open.isConnected, true, "committing on blur removed the pending pointer target");
  assert.equal(page.activeElement, rename);
  assert.equal(el("tabs").querySelector("[data-keymanager-label]").textContent, state.name);
  assert.equal(el("panel").querySelector("[data-keymanager-name]").textContent, state.name);
  open.click();
  assert.deepEqual(calls.use, [state]);
  assert.equal(calls.log.length, 1);
  rename.dispatchEvent({ type: "change", target: rename });
  assert.equal(calls.log.length, 1, "an unchanged name was logged as another mutation");
});

test("key rename handles Enter, Escape and invalid names without losing the editing control", async (t) => {
  const state = inputState(1), other = inputState(2, "Existing");
  const { api, page, calls, el } = await keyUi(t, { pending: [state, other] });
  api.hodlKeyManagerRender();
  const rename = el("panel").querySelector('[data-keymanager-action="rename"]');
  rename.focus();
  const key = (value, options = {}) => {
    let prevented = false;
    rename.dispatchEvent({ type: "keydown", key: value, target: rename, preventDefault() { prevented = true; }, ...options });
    return prevented;
  };
  rename.value = "Renamed";
  assert.equal(key("Enter", { isComposing: true }), false);
  assert.equal(state.name, "Input 1");
  assert.equal(key("Enter"), true);
  assert.equal(state.name, "Renamed");
  assert.equal(page.activeElement, rename);
  for (const invalid of ["", " existing "]) {
    rename.value = invalid;
    key("Enter");
    assert.equal(state.name, "Renamed");
    assert.equal(rename.getAttribute("aria-invalid"), "true");
    assert.ok(el("status").textContent.trim());
    assert.equal(el("status").dataset.state, "error");
    assert.equal(rename.isConnected, true);
  }
  rename.value = "Cancelled";
  assert.equal(key("Escape"), true);
  assert.equal(rename.value, state.name);
  assert.notEqual(rename.getAttribute("aria-invalid"), "true");
  assert.equal(page.activeElement, rename);
  rename.dispatchEvent({ type: "change", target: rename });
  assert.equal(state.name, "Renamed");
  assert.equal(calls.log.length, 1, "cancelled or rejected edits mutated the journal");
});

test("Keys rerenders preserve owned focus and reveal the selection without stealing outside focus", async (t) => {
  const first = inputState(1), second = inputState(2);
  const { api, page, calls, el } = await keyUi(t, { pending: [first, second] });
  api.__set.hodlKeyManagerActiveId("2");
  api.hodlKeyManagerRender();
  const rename = el("panel").querySelector('[data-keymanager-action="rename"]');
  rename.focus();
  rename.value = "Still editing";
  rename.setSelectionRange(2, 6, "backward");
  api.hodlKeyManagerRender();
  const replacement = el("panel").querySelector('[data-keymanager-action="rename"]');
  assert.equal(page.activeElement, replacement);
  assert.equal(replacement.value, "Still editing");
  assert.equal(replacement.selectionStart, 2);
  assert.equal(replacement.selectionEnd, 6);
  assert.equal(replacement.selectionDirection, "backward");
  assert.equal(calls.reveal.at(-1), el("tabs").querySelector('[data-keymanager-id="2"]'));
  const outside = page.getElementById("outside");
  outside.focus();
  api.hodlKeyManagerRender();
  assert.equal(page.activeElement, outside);
  const selected = el("tabs").querySelector('[data-keymanager-id="2"]');
  selected.focus();
  selected.dispatchEvent({ type: "keydown", key: "ArrowLeft", preventDefault() {} });
  assert.equal(page.activeElement, el("tabs").querySelector('[data-keymanager-id="1"]'));
  assert.equal(calls.reveal.at(-1), page.activeElement);
});
