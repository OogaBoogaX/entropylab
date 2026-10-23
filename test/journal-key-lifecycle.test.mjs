import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { runInNewContext } from "node:vm";
import { KEY_VAULT_MAX_KEYS, keyVaultIdentity } from "../src/js/keymanager.js";
import { MiniDocument } from "./mini-dom.mjs";
import { HDKey } from "../src/js/hdkey.js";

// Security contract: reviewed inputs retain their chosen chain and fresh
// setup decision after their source moves; stale/busy actions cannot move
// recovery inputs, and reuse cannot consume inputs without preserving them.
const app = readFileSync(new URL("../src/js/app.js", import.meta.url), "utf8");
const WORDS = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
function source(name) {
  const start = app.indexOf(`function ${name}(`);
  assert.ok(start >= 0, name);
  let depth = 0;
  for (let i = app.indexOf(") {", start) + 2; i < app.length; i++) {
    if (app[i] === "{") depth++;
    else if (app[i] === "}" && --depth === 0) return (app.slice(start - 6, start) === "async " ? "async " : "") + app.slice(start, i + 1);
  }
  assert.fail(`unterminated ${name}`);
}
function harness() {
  const document = new MiniDocument(), events = [], derived = [], decisions = [];
  const create = document.createElement.bind(document);
  document.createElement = tag => {
    const element = create(tag);
    element.focus = () => { document.activeElement = element; };
    return element;
  };
  for (const [tag, id] of [["section", "journal-keymanager-ignored"], ["div", "journal-keymanager-ignored-list"], ["div", "journal-keymanager-tabs"], ["button", "journal-keymanager-derive"], ["div", "key-tabs"], ["p", "key-import-context"]]) {
    const element = document.createElement(tag); element.id = id; document.body.append(element);
  }
  const c = {
    document, keyVaultIdentity, TextEncoder, TextDecoder, Uint8Array, ArrayBuffer,
    hodlPrivateKeyKinds: ["wif", "hex-key", "minikey", "brain"],
    hodlTypedText: value => new TextDecoder().decode(value),
    HodlDerivationCancelledError: class extends Error {},
    hodlKeyVaultMaxKeys: KEY_VAULT_MAX_KEYS, hodlNextKeyId: 1, hodlNextKeyNumber: 1,
    hodlKeys: [], hodlKeyManagerPending: [], hodlKeyManagerIgnored: [], hodlKeyManagerIds: new Set(), hodlKeyManagerActiveId: "", hodlActiveKey: 0,
    hodlActiveDerivation: null, hodlJournalKeyDerivation: null, hodlJournalGeneration: 0, hodlDerivationGeneration: 0,
    hodlWorkspace: "journal", hodlWalletResult: null, hodlOutEl: { innerHTML: "" }, hodlCommittedResults: new Set(),
    hodlJournalUnlocked: () => true, hodlDefaultCoinType: () => 1, hodlNetworkDefault: "testnet", hodlNetworkChoice: "testnet",
    hodlDefaultKeyName: id => `Key ${id}`, hodlKeyColor: id => String(id), hodlVanityApplying: false,
    hodlTText: (text, vars = {}) => text.replace(/\{(\w+)\}/g, (_, key) => String(vars[key] ?? "")),
    hodlKeyManagerStatus: (...args) => events.push(["status", ...args]), hodlJournalLog: (...args) => events.push(["log", ...args]),
    hodlRenderKeyTabs() {}, hodlRestoreKey() {}, hodlInvalidateDerivation() {}, hodlDisposeDroppedWallets() {}, hodlReleaseKeyConsumers() {}, hodlWipeUnsharedWalletRows() {},
    hodlShowWorkspace: workspace => { c.hodlWorkspace = workspace; },
    hodlCaptureKey: () => { c.hodlKeys[c.hodlActiveKey].result = c.hodlWalletResult; },
    hodlKeyManagerDeriveInputs: async states => { derived.push(states); return false; },
    hodlKeySummaryMethodText: () => "Seed words", hodlKeySummaryPath: state => state.fields.derivationPath,
    hodlPublicInlineHtml: () => { throw new Error("Archived metadata must not be an HTML sink"); },
    hodlKeyMode: "seed", hodlSeedMethod: "words", hodlTargetWordCount: 12,
    hodlReadDerivationPlan: () => ({ network: "testnet", coinType: 1, purpose: 84, accountIndex: 0, hardening: { purpose: true } }),
    hodlNetworkFamily: value => value === "mainnet" ? "mainnet" : "testnet",
    hodlReadAddressWindow: () => ({ start: 0, range: 1 }), hodlReadBranchWindow: () => ({ start: 0, range: 1 }),
    hodlPassphraseFieldBytes: () => new Uint8Array(), hodlSelectedScriptType: () => "bip84", hodlScriptDefinition: id => ({ purpose: 84, label: id }),
    hodlPassphraseBip39Enabled: () => false, hodlSelectedSeedInput: () => ({ value: WORDS }),
    hodlValidateTargetMnemonic: value => ({ words: value.split(" ") }), hodlThrowIfFailed() {},
    hodlMnemonicWalletWithProgress: async (_words, _passphrase, network) => ({ network, masterIdentity: "published-vector-root", masterFingerprint: "73c5da0a" }),
    hodlAssertDerivationActive() {}, hodlConfirmKeyFingerprint: async () => true,
    hodlSetWorkspaceError: (_scope, error) => { if (error) events.push(["error", error]); },
    hodlError: text => new Error(text), hodlErrorSpecFrom: error => error.message,
    hodlSetSelectedScriptType() {}, hodlSnapshotKeySummary() {}, hodlFocusWalletResult() {},
    hodlKeyManagerDecideCommit: async (_transaction, input, result) => { decisions.push({ input, result }); return { kind: "skip" }; },
  };
  for (const name of ["hodlNewKeyState", "hodlNewLabState", "hodlStoredPassphraseBytes", "hodlPassphraseText", "hodlZeroKeyPassphrase", "hodlKeyManagerEntry", "hodlKeyManagerHasInputs", "hodlPrivateKeyValues", "hodlNormalizePrivateKeyKind", "hodlDetectPrivateKeyKind", "hodlKeyManagerArchiveEntry", "hodlKeyManagerStates", "hodlKeyManagerCapacityError", "hodlKeyManagerImportedState", "hodlKeyManagerIgnore", "hodlKeyManagerRestoreIgnored", "hodlKeyManagerRenderIgnored", "hodlKeyManagerUseInStation", "hodlKeyManagerReviewInputs", "hodlKeyManagerDiscardInputs", "hodlCloneDerivedKey", "hodlFillLabFromKey", "hodlKeyLogLabel", "hodlKeyWalletIdentity", "hodlKeyNameTaken", "hodlNormalizeKeyName", "hodlCommitDerivedKey", "hodlCalculateKey"])
    runInNewContext(source(name), c);
  c.hodlKeyManagerRender = () => {
    const tabs = document.getElementById("journal-keymanager-tabs"); tabs.replaceChildren();
    for (const state of c.hodlKeyManagerStates()) {
      const tab = document.createElement("button"); tab.dataset.keymanagerId = keyVaultIdentity(state); tab.setAttribute("aria-selected", String(tab.dataset.keymanagerId === c.hodlKeyManagerActiveId)); tabs.append(tab);
    }
    c.hodlKeyManagerRenderIgnored();
  };
  c.hodlKeys.push(c.hodlNewLabState());
  const input = (name = "Imported source") => {
    const state = c.hodlNewKeyState(name);
    Object.assign(state, { mode: "seed", seedMethod: "words", needsDerivation: true });
    Object.assign(state.fields, { seed: WORDS, network: "regtest", derivationPath: "m/84'/1'/0'/0/0", pass: new Uint8Array([19, 23]) });
    return state;
  };
  const review = state => {
    c.hodlKeyManagerPending.push(state); c.hodlKeyManagerUseInStation(state); return c.hodlKeys[c.hodlActiveKey];
  };
  return { c, document, events, derived, decisions, input, review };
}

for (const removedBy of ["archive", "clear"]) test(`reviewed inputs retain their saved chain and setup decision after ${removedBy}`, async () => {
  const h = harness(), state = h.input(), lab = h.review(state);
  if (removedBy === "archive") h.c.hodlKeyManagerIgnore(state);
  else { h.c.hodlKeyManagerPending = []; h.c.hodlJournalGeneration++; h.c.hodlJournalUnlocked = () => false; }
  assert.equal(await h.c.hodlCalculateKey({}), false, "the setup decision must be able to decline without committing");
  assert.equal(h.decisions.length, 1, "moving a source must not bypass fresh setup matching");
  assert.equal(h.decisions[0].result.network, "regtest", "reviewed inputs must not silently use the global testnet picker");
  assert.equal(h.c.hodlKeys[0], lab);
  assert.equal(lab.fields.seed, WORDS);
});

test("orphaned reviewed inputs refuse a saved chain that conflicts with their derivation path", async () => {
  const h = harness(), state = h.input(), lab = h.review(state);
  h.c.hodlKeyManagerPending = []; lab.importedNetworkChoice = "mainnet";
  let derived = 0; h.c.hodlMnemonicWalletWithProgress = async () => { derived++; return { network: "testnet" }; };
  assert.equal(await h.c.hodlCalculateKey({}), false);
  assert.equal(derived, 0, "a mainnet override with a testnet derivation must be refused before derivation");
  assert.ok(h.events.some(event => event[0] === "error"));
});

test("archive and restore refuse busy or stale actions without moving inputs", async () => {
  const h = harness(), pending = h.input("Pending"), archived = h.input("Archived");
  h.c.hodlKeyManagerPending.push(pending); h.c.hodlKeyManagerIgnored.push(archived);
  h.c.hodlActiveDerivation = {};
  h.c.hodlKeyManagerIgnore(pending); await h.c.hodlKeyManagerRestoreIgnored(archived);
  assert.equal(h.c.hodlKeyManagerPending[0], pending);
  assert.equal(h.c.hodlKeyManagerIgnored[0], archived);
  assert.equal(h.derived.length, 0);
  h.c.hodlActiveDerivation = null;
  const stale = h.input("No longer archived");
  await h.c.hodlKeyManagerRestoreIgnored(stale);
  assert.equal(h.c.hodlKeyManagerPending.length, 1, "a detached stale Restore callback must not resurrect an input");
});

test("Restore and derive queues fresh unverified inputs once and leaves failed or stopped inputs pending", async () => {
  const h = harness(), archived = h.input("Restored inputs");
  archived.result = { masterFingerprint: "forged cached fingerprint" };
  h.c.hodlKeyManagerIgnored.push(archived);
  await h.c.hodlKeyManagerRestoreIgnored(archived);
  assert.equal(h.derived.length, 1);
  const restored = h.c.hodlKeyManagerPending[0];
  assert.equal(h.derived[0][0], restored);
  assert.equal(restored.result, null);
  assert.equal(restored.needsDerivation, true);
  assert.equal(restored.fields.seed, WORDS);
  assert.deepEqual([...restored.fields.pass], [19, 23]);
  assert.equal(h.c.hodlKeyManagerIgnored.length, 0);
  await h.c.hodlKeyManagerRestoreIgnored(archived);
  assert.equal(h.derived.length, 1, "the removed source's old handler cannot queue it twice");
});

test("Restore releases the old archive's secret bytes before waiting for derivation", async () => {
  const h = harness(), source = h.input(), oldPass = source.fields.pass;
  h.c.hodlKeyManagerIgnored.push(source);
  let finish;
  h.c.hodlKeyManagerDeriveInputs = () => new Promise(resolve => { finish = resolve; });
  const restoring = h.c.hodlKeyManagerRestoreIgnored(source), fresh = h.c.hodlKeyManagerPending[0];
  assert.deepEqual([...oldPass], [0, 0], "the removed entry must not retain bytes outside End Session's ownership roots");
  assert.deepEqual([...fresh.fields.pass], [19, 23]);
  assert.equal(fresh.fields.seed, WORDS);
  assert.equal(source.fields.seed, "");
  h.c.hodlKeyManagerDiscardInputs(fresh); h.c.hodlJournalGeneration++;
  finish(false); await restoring;
  assert.deepEqual([...oldPass], [0, 0]);
});

test("archiving and restoring a verified key preserves signet/regtest beyond its coin-type family", async () => {
  for (const network of ["signet", "regtest"]) {
    const h = harness(), state = h.input();
    state.needsDerivation = false; state.fields.network = "testnet";
    state.result = { network, masterIdentity: "fresh-derived-root" };
    h.c.hodlKeyManagerPending.push(state); h.c.hodlKeyManagerIgnore(state);
    const archived = h.c.hodlKeyManagerIgnored[0];
    assert.equal(archived.fields.network, network);
    await h.c.hodlKeyManagerRestoreIgnored(archived);
    assert.equal(h.derived[0][0].fields.network, network);
    assert.equal(h.derived[0][0].result, null);
  }
});

test("archiving unverified inputs never promotes cached network claims", () => {
  const h = harness(), state = h.input();
  state.result = { network: "mainnet", masterIdentity: "untrusted cache" };
  h.c.hodlKeyManagerPending.push(state); h.c.hodlKeyManagerIgnore(state);
  assert.equal(h.c.hodlKeyManagerIgnored[0].fields.network, "regtest");
});

test("archived input controls describe literal public metadata and cannot restore while deriving", () => {
  const h = harness(), archived = h.input("<img src=x onerror=alert(1)>");
  archived.fields.derivationPath = "m/<svg>/0";
  h.c.hodlKeyManagerIgnored.push(archived); h.c.hodlActiveDerivation = {};
  h.c.hodlKeyManagerRenderIgnored();
  const list = h.document.getElementById("journal-keymanager-ignored-list"), button = list.querySelector("[data-keymanager-action='restore']");
  for (const value of [archived.name, "Seed words", "regtest", archived.fields.derivationPath]) assert.ok(list.textContent.includes(value), value);
  assert.equal(list.querySelectorAll("img, svg").length, 0);
  assert.ok(button.getAttribute("aria-label").includes(archived.name));
  assert.equal(button.disabled, true);
});

function exactReuse(h) {
  const source = h.input("Original archived source"), lab = h.review(source), existing = h.input("Existing station key");
  existing.needsDerivation = false; existing.result = { masterIdentity: "same-root", network: "regtest" };
  h.c.hodlKeys.push(existing); h.c.hodlKeyManagerIgnore(source);
  lab.fields.seed = "edited recovery inputs"; lab.result = { ...existing.result };
  return { lab, existing, decision: { kind: "reuse", state: existing, previousResult: existing.result } };
}
test("orphaned reviewed exact reuse preserves the edited inputs without replacing the old archive", () => {
  const h = harness(), { lab, existing, decision } = exactReuse(h), original = h.c.hodlKeyManagerIgnored[0];
  lab.fields.network = "testnet"; // Capturing the coin-type field records its encoding family.
  h.c.hodlCommitDerivedKey("derive", decision);
  assert.equal(h.c.hodlKeys[h.c.hodlActiveKey], existing);
  assert.equal(h.c.hodlKeyManagerIgnored.length, 2);
  assert.equal(h.c.hodlKeyManagerIgnored[0], original);
  assert.equal(original.fields.seed, WORDS);
  assert.equal(h.c.hodlKeyManagerIgnored[1].fields.seed, "edited recovery inputs");
  assert.equal(h.c.hodlKeyManagerIgnored[1].fields.network, "regtest", "the snapshot must preserve the freshly derived chain");
  assert.notEqual(keyVaultIdentity(original), keyVaultIdentity(h.c.hodlKeyManagerIgnored[1]), "preserved inputs need an independent archive identity");
});
test("a full archive refuses orphaned exact reuse without consuming its reviewed draft", () => {
  const h = harness(), { lab, decision } = exactReuse(h);
  while (h.c.hodlKeyManagerIgnored.length < KEY_VAULT_MAX_KEYS) h.c.hodlKeyManagerIgnored.push(h.input());
  assert.throws(() => h.c.hodlCommitDerivedKey("derive", decision), { name: "Error" });
  assert.equal(h.c.hodlKeys[0], lab);
  assert.equal(lab.fields.seed, "edited recovery inputs");
  assert.deepEqual([...lab.fields.pass], [19, 23]);
});
test("after Journal Clear, exact reuse retains the reviewed draft and focuses the existing key", () => {
  const h = harness(), { lab, existing, decision } = exactReuse(h), previous = existing.result;
  const freshBytes = new Uint8Array([41, 43]), existingBytes = new Uint8Array([47, 53]);
  lab.result.seed = freshBytes; previous.seed = existingBytes;
  h.c.hodlWalletResult = lab.result;
  h.c.hodlRestoreKey = () => { h.c.hodlWalletResult = h.c.hodlKeys[h.c.hodlActiveKey].result; };
  for (const name of ["hodlLiveWalletResults", "hodlResultSecretBytes", "hodlSettleDerivationKeys"]) runInNewContext(source(name), h.c);
  h.c.hodlKeyManagerIgnored = []; h.c.hodlJournalUnlocked = () => false;
  h.c.hodlCommitDerivedKey("derive", decision);
  assert.equal(h.c.hodlKeys.length, 2, "reusing a key must not create a duplicate wallet tab");
  assert.equal(h.c.hodlKeys[0], lab);
  assert.equal(lab.result, null, "the uncommitted fresh result must leave the ownership roots");
  assert.equal(lab.fields.seed, "edited recovery inputs");
  assert.deepEqual([...lab.fields.pass], [19, 23]);
  assert.equal(lab.importedNetworkChoice, "regtest");
  assert.equal(h.c.hodlKeys[1], existing);
  assert.equal(existing.result, previous);
  assert.equal(h.c.hodlActiveKey, 1);
  assert.equal(h.c.hodlKeyManagerIgnored.length, 0);
  h.c.hodlSettleDerivationKeys({ rowKeys: [freshBytes, existingBytes], nodes: [] });
  assert.deepEqual([...freshBytes], [0, 0]);
  assert.deepEqual([...existingBytes], [47, 53]);
  assert.deepEqual([...lab.fields.pass], [19, 23]);
});

test("reviewed exact reuse preserves corrected inputs as well as its still-pending original", () => {
  const h = harness(), source = h.input(), lab = h.review(source), existing = h.input("Existing wallet");
  existing.needsDerivation = false; existing.result = { masterIdentity: "same-root", network: "regtest" }; h.c.hodlKeys.push(existing);
  lab.fields.pass = new Uint8Array([29, 31]); lab.result = { ...existing.result };
  h.c.hodlCommitDerivedKey("derive", { kind: "reuse", state: existing, previousResult: existing.result });
  assert.equal(h.c.hodlKeyManagerIgnored.length, 2);
  assert.deepEqual(h.c.hodlKeyManagerIgnored.map(entry => [...new TextEncoder().encode(entry.fields.pass)]), [[19, 23], [29, 31]]);
  assert.equal(h.c.hodlKeyManagerPending.length, 0);
  assert.equal(h.c.hodlKeys[h.c.hodlActiveKey], existing);
});

test("preserving original and corrected inputs requires two archive slots before consuming either", () => {
  const h = harness(), source = h.input(), lab = h.review(source), existing = h.input("Existing wallet");
  existing.needsDerivation = false; existing.result = { masterIdentity: "same-root", network: "regtest" }; h.c.hodlKeys.push(existing);
  lab.fields.pass = new Uint8Array([29, 31]); lab.result = { ...existing.result };
  while (h.c.hodlKeyManagerIgnored.length < KEY_VAULT_MAX_KEYS - 1) h.c.hodlKeyManagerIgnored.push(h.input());
  assert.throws(() => h.c.hodlCommitDerivedKey("derive", { kind: "reuse", state: existing, previousResult: existing.result }), { name: "Error" });
  assert.equal(h.c.hodlKeyManagerPending[0], source);
  assert.equal(h.c.hodlKeys[0], lab);
  assert.deepEqual([...source.fields.pass], [19, 23]); assert.deepEqual([...lab.fields.pass], [29, 31]);
});

test("unchanged reviewed inputs need only one archive record", () => {
  const h = harness(), source = h.input(), lab = h.review(source), existing = h.input("Existing wallet");
  existing.needsDerivation = false; existing.result = { masterIdentity: "same-root", network: "regtest" }; h.c.hodlKeys.push(existing);
  lab.result = { ...existing.result };
  h.c.hodlCommitDerivedKey("derive", { kind: "reuse", state: existing, previousResult: existing.result });
  assert.equal(h.c.hodlKeyManagerIgnored.length, 1);
});

test("a new batch source does not inherit the parked reviewed draft's label or chain", () => {
  const h = harness(), old = h.input("Older reviewed source"); h.review(old);
  const next = h.input("New batch source"); next.fields.network = "signet"; h.c.hodlKeyManagerPending.push(next);
  h.c.hodlActiveKey = h.c.hodlFillLabFromKey(next);
  const lab = h.c.hodlKeys[h.c.hodlActiveKey];
  lab.importedKeyId = next.id; lab.result = { masterIdentity: "different-root", network: "signet" };
  assert.ok(lab.importedName == null);
  assert.ok(lab.importedNetworkChoice == null);
  h.c.hodlCommitDerivedKey("derive", { kind: "append" });
  assert.equal(h.c.hodlKeys[h.c.hodlActiveKey].name, next.name);
});

test("reviewed context exposes only literal public labels and the current saved network", () => {
  const h = harness(), state = h.input("<svg onload=alert(1)>");
  runInNewContext(source("hodlKeyManagerSyncReviewedContext"), h.c);
  const lab = h.review(state), status = h.document.getElementById("key-import-context");
  h.c.hodlKeyManagerSyncReviewedContext();
  assert.equal(status.hidden, false);
  assert.ok(status.textContent.includes(state.name));
  assert.ok(status.textContent.includes("regtest"));
  assert.ok(!status.textContent.includes(WORDS));
  assert.equal(status.children.length, 0);
  lab.importedNetworkChoice = "signet"; h.c.hodlKeyManagerSyncReviewedContext();
  assert.ok(status.textContent.includes("signet"));
  h.c.hodlKeys[0] = h.c.hodlNewLabState(); h.c.hodlKeyManagerSyncReviewedContext();
  assert.equal(status.hidden, true); assert.equal(status.textContent, "");
});

test("archive and restore put focus on the moved entry, without stealing it after Clear", async () => {
  const h = harness(), source = h.input();
  h.c.hodlKeyManagerPending.push(source); h.c.hodlKeyManagerIgnore(source);
  assert.equal(h.document.activeElement?.dataset.keymanagerAction, "restore");
  h.c.hodlWorkspace = "journal";
  await h.c.hodlKeyManagerRestoreIgnored(h.c.hodlKeyManagerIgnored[0]);
  assert.equal(h.document.activeElement?.dataset.keymanagerId, keyVaultIdentity(h.c.hodlKeyManagerPending[0]));
  const next = h.input(); h.c.hodlKeyManagerIgnored.push(next);
  let finish;
  h.c.hodlKeyManagerDeriveInputs = () => new Promise(resolve => { finish = resolve; });
  const restoring = h.c.hodlKeyManagerRestoreIgnored(next);
  assert.equal(h.document.activeElement, h.document.getElementById("journal-keymanager-derive"));
  h.c.hodlJournalGeneration++;
  const elsewhere = h.document.createElement("button"); h.document.body.append(elsewhere); elsewhere.focus();
  finish(false); await restoring;
  assert.equal(h.document.activeElement, elsewhere);
});

test("restore focuses the selected entry when completed progress loses focus", async () => {
  const h = harness(), source = h.input();
  h.c.hodlKeyManagerIgnored.push(source);
  let finish;
  h.c.hodlKeyManagerDeriveInputs = () => new Promise(resolve => { finish = resolve; });
  const restoring = h.c.hodlKeyManagerRestoreIgnored(source);
  h.document.activeElement = h.document.body; // A hidden progress control loses browser focus.
  finish(false); await restoring;
  assert.equal(h.document.activeElement?.dataset.keymanagerId, h.c.hodlKeyManagerActiveId);
});

test("reviewed pending inputs keep their chain and an in-flight Clear cancels orphaned completion", async () => {
  const h = harness(), source = h.input(); h.review(source);
  assert.equal(await h.c.hodlCalculateKey({}), false);
  assert.equal(h.decisions[0].result.network, "regtest");
  h.c.hodlKeyManagerPending = [];
  let finish;
  h.c.hodlMnemonicWalletWithProgress = () => new Promise(resolve => { finish = resolve; });
  const deriving = h.c.hodlCalculateKey({}); h.c.hodlJournalGeneration++;
  finish({ network: "regtest", masterIdentity: "fresh-result" });
  await assert.rejects(deriving, h.c.HodlDerivationCancelledError);
  assert.equal(h.decisions.length, 1, "stale completion must not open another setup decision");
});

// External review: a local archive must contain inputs, never JSON-shaped
// HDKey instances that cannot be wiped or used as fresh derivation evidence.
test("restoring locally archived HD inputs reaches fresh derivation without serialized nodes", async () => {
  const h = harness(), state = h.input();
  const root = HDKey.fromMasterSeed(Uint8Array.from(Buffer.from("000102030405060708090a0b0c0d0e0f", "hex")));
  state.needsDerivation = false;
  state.result = { kind: "hd", network: "regtest", rootNode: root, accounts: [] };
  h.c.hodlKeyManagerPending.push(state);
  for (const name of ["hodlResultSecretBytes", "hodlWipeWalletKeys", "hodlLiveWalletResults", "hodlWipeUnsharedWalletRows"])
    runInNewContext(source(name), h.c);
  h.c.hodlKeyManagerIgnore(state);
  const archived = h.c.hodlKeyManagerIgnored[0];
  assert.equal(archived.result, null, "an archive must not keep serialized runtime nodes or output claims");
  assert.equal(archived.needsDerivation, true);
  await assert.doesNotReject(h.c.hodlKeyManagerRestoreIgnored(archived));
  assert.equal(h.derived.length, 1);
  assert.equal(h.derived[0][0].result, null);
  assert.equal(h.derived[0][0].needsDerivation, true);
  assert.equal(h.derived[0][0].fields.seed, WORDS);
  assert.equal(h.derived[0][0].fields.network, "regtest");
  assert.deepEqual([...h.derived[0][0].fields.pass], [19, 23]);
  root.wipePrivateData();
});

test("pending rename updates the reviewed draft and its eventual key name", () => {
  const h = harness(), state = h.input("Before rename"), lab = h.review(state);
  for (const name of ["hodlKeyManagerNameTaken", "hodlKeyManagerRename", "hodlKeyManagerSyncReviewedContext"])
    runInNewContext(source(name), h.c);
  const input = h.document.createElement("input"); input.value = "After rename";
  h.c.hodlKeyManagerRename(state, input);
  assert.equal(lab.importedName, state.name);
  h.c.hodlKeyManagerSyncReviewedContext();
  assert.ok(h.document.getElementById("key-import-context").textContent.includes(state.name));
  lab.result = { network: "regtest", masterIdentity: "fresh-root" };
  h.c.hodlCommitDerivedKey("derive", { kind: "append" });
  assert.equal(h.c.hodlKeys[h.c.hodlActiveKey].name, "After rename");
});


test("unchanged legacy private-key field migration does not create a reviewed archive duplicate", () => {
  const h = harness(), state = h.input("Legacy WIF");
  const wif = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ";
  state.mode = "key"; state.fields.seed = ""; state.fields.key = wif; state.fields.network = "mainnet";
  state.fields.keyKind = "wif-or-hex";
  const lab = h.review(state), existing = h.input("Existing wallet");
  existing.needsDerivation = false; existing.result = { masterIdentity: "same-root", network: "mainnet" };
  h.c.hodlKeys.push(existing);
  h.c.hodlPrivateKeyKinds = ["wif", "hex-key", "minikey", "brain"];
  for (const name of ["hodlDetectPrivateKeyKind", "hodlNormalizePrivateKeyKind", "hodlPrivateKeyValues"])
    runInNewContext(source(name), h.c);
  // The real RestoreFormFields migration; no user edits occurred.
  const privateKeys = h.c.hodlPrivateKeyValues(lab.fields);
  lab.fields.keyKind = h.c.hodlNormalizePrivateKeyKind(lab.fields.keyKind, privateKeys[lab.fields.keyKind] || "");
  lab.result = { ...existing.result };
  h.c.hodlCommitDerivedKey("derive", { kind: "reuse", state: existing, previousResult: existing.result });
  assert.equal(h.c.hodlKeyManagerIgnored.length, 1, "moving the same input between legacy and current fields is not a recovery-input edit");
  assert.equal(h.c.hodlKeyManagerIgnored[0].fields.key, wif, "the original portable source remains preserved");
});


test("a resultless station input exposes verification guidance and opens its original tab", () => {
  const h = harness(), state = h.input("Withdrawn result"); delete state.needsDerivation;
  h.c.hodlKeys.push(state);
  h.c.hodlKeySummaryMethod = () => "Seed words";
  runInNewContext(source("hodlKeyManagerDetails"), h.c);
  const details = h.c.hodlKeyManagerDetails(state).map(([, , , key]) => key);
  assert.ok(details.includes("verification"));
  assert.ok(!details.includes("fingerprint") && !details.includes("public-key"));
  h.c.hodlKeyManagerUseInStation(state);
  assert.equal(h.c.hodlKeys[h.c.hodlActiveKey], state);
  assert.equal(h.c.hodlWorkspace, "calc");
  assert.equal(h.c.hodlKeyManagerPending.length, 0);
  assert.equal(state.result, null);
});
