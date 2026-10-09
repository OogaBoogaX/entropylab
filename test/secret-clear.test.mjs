// Lifecycle clearing must discard application state, not only visible fields.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import vm from "node:vm";
import { HDKey as ScureHDKey } from "@scure/bip32";
import { createJournal, wipeJournal } from "../src/js/journal.js";
import { createBase58check, hex } from "@scure/base";
import { sha256 } from "@noble/hashes/sha2.js";
import { loadAppFunctions } from "./app-slice-harness.mjs";
import { HDKey } from "../src/js/hdkey.js";
import { hex as appHex } from "../src/js/coders.js";
import { keyVaultIdentity } from "../src/js/keymanager.js";

// The helpers that zero address-row key bytes (#546 B2). The lifecycle
// harness loads whichever of them app.js defines, so a source without them
// fails the byte-wiping tests on the bytes, not on a missing function.
const rowWipeHelpers = ["hodlZeroWalletRows", "hodlResultSecretBytes", "hodlWipeWalletKeys", "hodlLiveWalletResults", "hodlWipeUnsharedWalletRows", "hodlSettleDerivationKeys", "hodlDisposeDroppedWallets"];

function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}

// Execute the real controller functions, with delayed crypto and a small DOM.
function functionSource(name) {
  const start = app.indexOf(`function ${name}(`);
  assert.ok(start >= 0, name);
  const next = app.indexOf("\nfunction ", start + 1);
  const asyncNext = app.indexOf("\nasync function ", start + 1);
  const end = Math.min(...[next, asyncNext].filter(value => value >= 0));
  return (app.slice(start - 6, start) === "async " ? "async " : "") + app.slice(start, end);
}

// Every context gets the passphrase vault's helpers (passphrase-vault.js)
// with no vault bound, so they read the field's own text, as these harnesses
// model it, and the encoders a VM context lacks.
const passphraseHelpers = ["hodlPassphraseVaultActive", "hodlPassphraseFieldBytes", "hodlStoredPassphraseBytes", "hodlPassphraseText", "hodlStorePassphrase", "hodlShowStoredPassphrase", "hodlClearPassphraseField", "hodlClearStationPassphrase"];
function createContext(sandbox) {
  const context = vm.createContext({ hodlPassphraseVaultField: null, hodlPassphraseShown: false, hodlStationPassphraseFields: null, TextEncoder, TextDecoder, ...sandbox });
  for (const name of passphraseHelpers) vm.runInContext(functionSource(name), context);
  return context;
}

function raceHarness() {
  const pending = deferred(), decryptStarted = deferred(), events = {}, effects = [];
  const fields = new Map();
  const mirrors = [".dice-input-highlight", ".dice-word-grid", "#last-words", "#brain-lab-hex"]
    .map(selector => ({ selector, textContent: "secret mnemonic" }));
  const context = createContext({
    // Synthetic commit results have no markers; the notice call on the
    // derive path must see "no private material" rather than throw.
    hodlResultHasSeed: () => false, hodlResultHasRoot: () => false,
    hodlResultHasSingleKey: () => false, hodlResultHasImportedPrivate: () => false,
    document: {
      getElementById: id => fields.get(id) ?? null,
      querySelectorAll: selector => mirrors.filter(el => selector.split(", ").includes(el.selector)),
    },
    addEventListener: (type, callback) => { events[type] = callback; },
    hodlActiveDerivation: { kind: "key", cancelled: false }, hodlDerivationGeneration: 0, hodlCommittedResults: new Set(),
    hodlJournalGeneration: 0, hodlJournalKeys: {}, hodlJournal: {},
    hodlKeys: [{ id: 1, number: 1, fields: {}, result: null }], hodlActiveKey: 0, hodlKeyManagerPending: [],
    hodlMsigs: [], hodlActiveMsig: -1,
    hodlNewMsigState: (name, id, number) => ({ name, id, number, fields: { descriptor: "", xpubs: ["", "", ""] }, result: null }),
    hodlNewMsigLabState: () => ({ isLab: true, fields: { descriptor: "", xpubs: ["", "", ""] }, result: null }),
    hodlKeyMode: "hex", hodlTargetWordCount: 24, hodlNetworkChoice: "mainnet",
    hodlWalletResult: null, hodlOutEl: { innerHTML: "" }, hodlLastWordCache: new Map(),
    hodlBip85Note: "", hodlSpNote: "",
    hodlReadDerivationPlan: () => ({ network: "mainnet", coinType: 0 }),
    hodlNetworkFamily: value => value,
    hodlReadAddressWindow: () => ({ start: 0, range: 1 }),
    hodlReadBranchWindow: () => ({ start: 0, range: 2 }),
    hodlSelectedScriptType: () => "bip84", hodlDefaultHardening: () => ({}),
    hodlPassphraseBip39Enabled: () => false, hodlSelectedEntropy: () => ({}),
    hodlEntropyWalletWithProgress: () => pending.promise,
    hodlNewKeyState: () => ({ fields: {}, result: null }),
    hodlRestoreKey: () => { context.hodlWalletResult = null; },
    hodlJournalUnlocked: () => true,
    hodlConfirmKeyFingerprint: () => Promise.resolve(true),
    hodlJournalOpenExport: () => { decryptStarted.resolve(); return pending.promise; },
    hodlJournalWipeMem: () => { context.hodlJournalGeneration++; },
    hodlErrorSpecFrom: error => error.message,
  });
  fields.set("pass", { value: "private passphrase", dataset: {} });
  fields.set("dice", { value: "1 2 3 4 5 6", dataset: { previousValue: "1 2 3 4 5 6" } });
  for (const name of ["hodlThrowIfFailed", "hodlSetSelectedScriptType", "hodlCaptureKey",
    "hodlSnapshotKeySummary", "hodlCommitDerivedKey", "hodlJournalCaptureDerivedKey",
    "hodlFocusWalletResult", "hodlJournalLog", "hodlSetWorkspaceError", "hodlJournalSetStatus",
    "hodlKeyManagerStatus", "hodlPsbtWipeMem", "hodlBip85WipeMem", "hodlSpWipeMem",
    "hodlLnWipeMem", "hodlRenderBip85Tabs", "hodlSyncBip85View", "hodlVanityCancel",
    "hodlVanitySyncSource", "hodlVanitySyncControls", "hodlRefreshStationKeyPickers", "hodlRefreshMsigSessionPickers", "hodlSyncPsbtControls",
    "hodlRestoreMsig"])
    context[name] = (...args) => { effects.push([name, ...args]); };
  vm.runInContext('class HodlDerivationCancelledError extends Error {}', context);
  for (const name of ["hodlInvalidateDerivation", "hodlAssertDerivationActive", "hodlCalculateKey",
    "hodlWipeActiveKey", "hodlJournalImportFile", "hodlKeyManagerImportFile", "hodlInitSecretFieldAutoClear",
    "hodlAccountAddressBranches", ...rowWipeHelpers.filter((name) => app.includes(`function ${name}(`))])
    vm.runInContext(functionSource(name), context);
  context.hodlInitSecretFieldAutoClear();
  return { context, pending, decryptStarted, events, effects, mirrors, fields };
}

for (const teardown of ["clear", "pagehide", "pageshow", "stop"]) {
  for (const rejects of [false, true]) test(`${teardown} discards a late derivation ${rejects ? "error" : "result"}`, async () => {
    const { context, pending, events, effects } = raceHarness();
    const calculation = context.hodlCalculateKey({});
    const rejected = assert.rejects(calculation, error => error.constructor.name === "HodlDerivationCancelledError");
    if (teardown === "clear") context.hodlWipeActiveKey();
    else if (teardown === "stop") context.hodlActiveDerivation.cancelled = true;
    else events[teardown]({ persisted: true });
    effects.length = 0;
    if (rejects) pending.reject(new Error("late crypto failure"));
    else pending.resolve({ network: "mainnet", privateKey: "secret" });
    await rejected;
    assert.equal(context.hodlWalletResult, null);
    assert.deepEqual(effects, []);
  });
}

test("an uninterrupted derivation still commits its result", async () => {
  const { context, pending, effects } = raceHarness();
  const calculation = context.hodlCalculateKey({});
  const result = { network: "mainnet", privateKey: "secret" };
  pending.resolve(result);
  assert.equal(await calculation, true);
  assert.equal(context.hodlWalletResult, result);
  assert.ok(effects.some(([name]) => name === "hodlCommitDerivedKey"));
});

test("Multisig Clear prevents a suspended derivation from committing", async () => {
  const { context, pending, effects } = raceHarness();
  Object.assign(context, {
    hodlActiveMsig: 0, hodlMsigs: [{ id: 2, number: 1 }],
    hodlNewMsigState: () => ({ result: null }), hodlRestoreMsig: () => {},
    hodlValidatedMsigInputs: () => ({
      count: 1, addressStart: 0, branchStart: 0, branchRange: 1,
      kind: "p2wsh", keyTokens: ["key"], accountSummary: {},
    }),
    hodlMsigKeysSorted: () => true, hodlMsigInnerDescriptor: () => "descriptor",
    descriptorDerive: () => ({ address: "test address", pubkeys: [] }),
    hodlHex: { decode: value => value, encode: value => value },
    hodlAddressBranchRole: () => "receive", hodlAddressBranchLabel: () => "Receive",
    hodlDescriptorWithChecksum: value => value,
  });
  vm.runInContext(functionSource("hodlBuildMsig"), context);
  vm.runInContext(functionSource("hodlMsigBranchDescriptor"), context);
  vm.runInContext(functionSource("hodlMsigAddressRow"), context);
  vm.runInContext(functionSource("hodlWipeActiveMsig"), context);
  const operation = context.hodlBuildMsig({ setTotal() {}, step: () => pending.promise });
  const rejected = assert.rejects(operation, error => error.constructor.name === "HodlDerivationCancelledError");
  context.hodlWipeActiveMsig();
  effects.length = 0;
  pending.resolve();
  await rejected;
  assert.equal(context.hodlWalletResult, null);
  assert.deepEqual(effects, []);
});

test("pagehide and persisted pageshow erase rendered word copies", () => {
  const { events, mirrors } = raceHarness();
  for (const type of ["pagehide", "pageshow"]) {
    mirrors.forEach(el => { el.textContent = "secret mnemonic"; });
    events[type]({ persisted: true });
    assert.ok(mirrors.every(el => el.textContent === ""));
  }
});

test("pagehide and persisted pageshow erase transcript-render panels and progress lines", () => {
  // The dealt-cards strip, the worked word/number calculations and the die
  // fairness panel each render the typed transcript back (dealt faces,
  // per-word BIP39 indices, roll counts), and the progress lines quote a
  // rejected word or token in an error cue. Clearing the field alone leaves
  // those rendered copies behind.
  const panels = ["dealt-cards", "dice-manual-calculations", "cards-manual-calculations", "number-base-calculations", "dice-fairness"];
  const metas = ["dice-meta", "cards-meta", "entropy-meta", "seed-meta", "seed-number-meta", "private-key-meta"];
  for (const type of ["pagehide", "pageshow"]) {
    const { events, fields } = raceHarness();
    // The panel containers hold child nodes; in a real DOM a textContent
    // assignment removes them all, so the stub models rendered content as
    // textContent.
    for (const id of [...panels, ...metas]) fields.set(id, { textContent: `rendered transcript fragment for ${id}`, dataset: {} });
    events[type]({ persisted: true });
    for (const id of [...panels, ...metas]) assert.equal(fields.get(id).textContent, "", `${type} left #${id} rendered`);
  }
});

test("pagehide and persisted pageshow drop the dice previousValue leftover", () => {
  // #423 leftover: the wipe blanked dice.value and left dataset.previousValue
  // holding the rolls. That is the raw entropy the visible field just lost.
  const { context, events } = raceHarness();
  const dice = context.document.getElementById("dice");
  for (const type of ["pagehide", "pageshow"]) {
    dice.value = "1 2 3 4 5 6";
    dice.dataset.previousValue = "1 2 3 4 5 6";
    events[type]({ persisted: true });
    assert.equal(dice.value, "");
    assert.equal(dice.dataset.previousValue, undefined);
  }
});

for (const name of ["hodlJournalImportFile", "hodlKeyManagerImportFile"]) {
  for (const phase of ["read", "decrypt"]) {
    for (const rejects of [false, true]) test(`${name} discards stale ${phase} ${rejects ? "failure" : "completion"}`, async () => {
      const { context, pending, decryptStarted, effects } = raceHarness();
      const read = deferred();
      const operation = context[name]({ size: 1, name: "notes.elkeys", text: () => read.promise });
      if (phase === "decrypt") {
        read.resolve('{"entropylabJournalExport":true}');
        await decryptStarted.promise;
      }
      context.hodlJournalWipeMem();
      effects.length = 0;
      const gate = phase === "read" ? read : pending;
      if (rejects) gate.reject(new Error("late import failure"));
      else gate.resolve(phase === "read" ? '{}' : { kind: "key-manager", content: "private" });
      await operation;
      assert.deepEqual(effects, []);
      assert.deepEqual(context.hodlJournal, {});
    });
  }
}

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const app = readFileSync(join(root, "src/js/app.js"), "utf8");
const start = app.indexOf("function hodlInitSecretFieldAutoClear()");
const end = app.indexOf("\nfunction hodlBoot()", start);
const lifecycle = app.slice(start, end);

// A key tab keeps its BIP39 passphrase as UTF-8 bytes (the passphrase
// vault): leaving the page zeroes them, rather than dropping them for the
// collector, and empties the field.
test("pagehide clears a station passphrase vault, not only its field", () => {
  const { context, events, fields } = raceHarness();
  let cleared = false;
  const field = { value: "\u2022\u2022\u2022\u2022\u2022\u2022", dataset: {} };
  fields.set("sp-pass", field);
  context.hodlStationPassphraseFields = { "sp-pass": { api: { clear() { cleared = true; field.value = ""; } } } };
  events.pagehide({ persisted: false });
  assert.equal(cleared, true, "pagehide left the SP passphrase vault in place");
  assert.equal(field.value, "", "pagehide left the SP passphrase field filled");
});

test("pagehide zeroes each key tab's stored passphrase bytes", () => {
  const { context, events, fields } = raceHarness();
  const stored = new TextEncoder().encode("private passphrase");
  context.hodlKeys[0].fields.pass = stored;
  events.pagehide({ persisted: false });
  assert.ok(stored.every((byte) => byte === 0), "the tab's passphrase bytes survived pagehide");
  assert.equal(fields.get("pass").value, "");
});

test("page lifecycle clearing replaces every cached key and clears PSBT private state", () => {
  assert.match(lifecycle, /hodlPsbtWipeMem\(\)/);
  assert.match(lifecycle, /hodlBip85WipeMem\(\)/);
  assert.match(lifecycle, /hodlSpWipeMem\(\)/);
  assert.match(lifecycle, /hodlJournalWipeMem\(\)/);
  assert.match(lifecycle, /hodlKeys\s*=\s*hodlKeys\.map\(\(state\)\s*=>\s*\{/);
  assert.match(lifecycle, /privateKeys\[kind\]\s*=\s*""/);
  assert.match(lifecycle, /if \(id === "privateKeys"\) return;\s*if \(ArrayBuffer\.isView\(fields\[id\]\)\) fields\[id\]\.fill\(0\);\s*fields\[id\] = ""/);
  assert.match(lifecycle, /state\.result\s*=\s*null/);
  assert.match(lifecycle, /return state\.isLab \? hodlNewLabState\(\) : hodlNewKeyState\(state\.name, state\.id, state\.number\)/);
  assert.match(lifecycle, /hodlWalletResult\s*=\s*null[\s\S]*hodlRevealPrivate\s*=\s*false[\s\S]*hodlPickedLastWord\s*=\s*""[\s\S]*hodlDiceCoinPositions\s*=\s*\[\]/);
  assert.match(lifecycle, /addEventListener\("pagehide", clearSecretFields\)/);
  assert.match(lifecycle, /event\.persisted\) clearSecretFields\(\)/);
});

test("PSBT key and passphrase fields are explicitly cleared", () => {
  assert.match(lifecycle, /getElementById\("psbt-key"\)/);
  assert.match(lifecycle, /getElementById\("psbt-pass"\)/);
  assert.match(lifecycle, /psbtKey\.value\s*=\s*""/);
  assert.match(lifecycle, /psbtPass\.value\s*=\s*""/);
});

test("PSBT text and anti-exfil transcript fields are explicitly cleared", () => {
  // #psbt-text can carry xprvs in proprietary fields; #psbt-ax-transcript
  // holds the anti-exfil host nonce.
  assert.match(lifecycle, /getElementById\("psbt-text"\)/);
  assert.match(lifecycle, /getElementById\("psbt-ax-transcript"\)/);
  assert.match(lifecycle, /psbtText\.value\s*=\s*""/);
  assert.match(lifecycle, /psbtAxTranscript\.value\s*=\s*""/);
});

// The Nonce Inspector loads the shared session key from its own fields, and
// its input can carry xprvs in proprietary PSBT fields, so page teardown has
// to empty all three the same way it empties the PSBT Inspector's.
test("pagehide and persisted pageshow empty the Nonce Inspector's key, passphrase and input", () => {
  const ids = ["nonce-key", "nonce-pass", "nonce-text"];
  for (const [type, event] of [["pagehide", {}], ["pageshow", { persisted: true }]]) {
    const { events, fields } = raceHarness();
    for (const id of ids) fields.set(id, { value: "xprv9s21ZrQH143K secret material", dataset: {} });
    events[type](event);
    for (const id of ids) assert.equal(fields.get(id).value, "", `${type} left #${id} filled`);
  }
});

test("BIP-85 parent and derived-child fields are explicitly cleared", () => {
  assert.match(lifecycle, /getElementById\("bip85-key"\)/);
  assert.match(lifecycle, /bip85Key\.value\s*=\s*""/);
  assert.match(lifecycle, /bip85Out\.innerHTML\s*=\s*""/);
});

test("Lightning seed, passphrase, and derived output are explicitly cleared", () => {
  assert.match(lifecycle, /hodlLnWipeMem\(\)/);
  assert.match(lifecycle, /getElementById\("ln-seed"\)/);
  assert.match(lifecycle, /getElementById\("ln-pass"\)/);
  assert.match(lifecycle, /lnSeed\.value\s*=\s*""/);
  assert.match(lifecycle, /lnPass\.value\s*=\s*""/);
  assert.match(lifecycle, /lnOut\.innerHTML\s*=\s*""/);
  assert.match(lifecycle, /lnError\.textContent\s*=\s*""/);
});

test("Entropy Journal password, entries, and encrypted session are explicitly cleared", () => {
  // The lifecycle's hodlJournalWipeMem clears both the session notepad and the
  // encrypted notebook (keys, document, and every notebook field).
  assert.match(lifecycle, /hodlJournalWipeMem\(\)/);
  assert.match(app, /function hodlJournalWipeMem\(\) \{[\s\S]*?hodlJournalWipeNotebook\(\)[\s\S]*?hodlJournalClearFields\(\)/);
  assert.match(app, /journal-create-password/);
  assert.match(app, /journal-input/);
  assert.match(app, /journal-phrase/);
  assert.match(app, /journal-entry-notes/);
});

test("Silent Payments session key and passphrase fields are explicitly cleared", () => {
  assert.match(lifecycle, /getElementById\("sp-key"\)/);
  assert.match(lifecycle, /getElementById\("sp-pass"\)/);
  assert.match(lifecycle, /spKey\.value\s*=\s*""/);
  assert.match(lifecycle, /spPass\.value\s*=\s*""/);
});

test("Silent Payments private-bearing inputs and revealed output are cleared", () => {
  // #sp-send-vins carries per-input derivation paths into the session's keys;
  // #sp-out renders revealed scan/spend private material. Both must go when
  // the page lifecycle clears.
  assert.match(lifecycle, /getElementById\("sp-send-vins"\)/);
  assert.match(lifecycle, /spVins\.value\s*=\s*""/);
  assert.match(lifecycle, /getElementById\("sp-out"\)/);
  assert.match(lifecycle, /spOut\.innerHTML\s*=\s*""/);
  assert.match(lifecycle, /spError\.textContent\s*=\s*""/);
  assert.match(lifecycle, /spSession\.textContent\s*=\s*hodlSpNote/);
});

test("Silent Payments recipient, verify, and label fields are explicitly cleared", () => {
  assert.match(lifecycle, /getElementById\("sp-recipients"\)/);
  assert.match(lifecycle, /spRecipients\.value\s*=\s*""/);
  assert.match(lifecycle, /getElementById\("sp-verify-vins"\)/);
  assert.match(lifecycle, /spVerifyVins\.value\s*=\s*""/);
  assert.match(lifecycle, /getElementById\("sp-verify-outputs"\)/);
  assert.match(lifecycle, /spVerifyOutputs\.value\s*=\s*""/);
  assert.match(lifecycle, /getElementById\("sp-label"\)/);
  assert.match(lifecycle, /spLabel\.value\s*=\s*""/);
  assert.match(lifecycle, /getElementById\("sp-payname"\)/);
  assert.match(lifecycle, /spPayname\.value\s*=\s*""/);
});

test("highlight mirrors, copy-button phrases, the last-word cache, and the PSBT editor are cleared", () => {
  // The .dice-input-highlight <pre> behind each input holds a second live
  // copy of the typed secret; copy buttons keep the phrase in data-phrase;
  // hodlLastWordCache retains partial mnemonics; the editor holds the loaded
  // PSBT (which can carry xprvs in proprietary fields).
  assert.match(lifecycle, /querySelectorAll\("\.dice-input-highlight, \.dice-word-grid, #last-words, #brain-lab-hex"\)/);
  assert.match(lifecycle, /highlight\.textContent\s*=\s*""/);
  assert.match(lifecycle, /querySelectorAll\("\[data-phrase\]"\)/);
  assert.match(lifecycle, /removeAttribute\("data-phrase"\)/);
  assert.match(lifecycle, /hodlLastWordCache\.clear\(\)/);
  assert.match(lifecycle, /getElementById\("psbted-wipe"\)/);
  assert.match(lifecycle, /psbtEditorWipe\.click\(\)/);
});

test("Vanity grinder salt, matches, and running workers are cleared", () => {
  // The imported/typed salt prefixes every candidate passphrase, and a found
  // passphrase is private key material — both go on pagehide/bfcache, and the
  // worker pool is cancelled so nothing keeps grinding (or holding the salt
  // in a worker's WASM heap) after the page hides.
  assert.match(lifecycle, /hodlVanityCancel\(\)/);
  assert.match(lifecycle, /hodlVanityMatches\s*=\s*\[\]/);
  assert.match(lifecycle, /hodlVanityFound\s*=\s*0/);
  assert.match(lifecycle, /hodlVanityReveal\s*=\s*false/);
  assert.match(lifecycle, /hodlVanitySource\s*=\s*""/);
  assert.match(lifecycle, /hodlVanityRun\s*=\s*null/);
  assert.match(lifecycle, /getElementById\("vanity-pass"\)/);
  assert.match(lifecycle, /vanityPass\.textContent\s*=\s*""/);
  assert.match(lifecycle, /getElementById\("vanity-out"\)/);
  assert.match(lifecycle, /vanityOut\.innerHTML\s*=\s*""/);
  // The masked column is sized from the passphrase lengths; that width goes
  // with the matches, on the wipe and when results are cleared.
  assert.match(lifecycle, /vanityOut\.style\.removeProperty\("--vanity-pass-width"\)/);
  const renderStart = app.indexOf("function hodlRenderVanityOut()");
  const render = app.slice(renderStart, app.indexOf("\nfunction ", renderStart + 1));
  assert.match(render, /box\.style\.removeProperty\("--vanity-pass-width"\)/);
  assert.match(lifecycle, /getElementById\("vanity-error"\)/);
  assert.match(lifecycle, /vanityError\.textContent\s*=\s*""/);
  // The grinder itself goes too: its callbacks close over the run's words and
  // passphrase, so cancelling alone keeps them reachable (audit A35-1).
  assert.match(lifecycle, /hodlVanityGrinder\s*=\s*null/);
});

test("pagehide drops the vanity grinder, not only the visible matches", () => {
  // A stopped or finished grind keeps the run's seed words and passphrase
  // alive through the grinder's callbacks; Clear Results drops it for the
  // same reason (#546 B3), and the page lifecycle sweep must as well.
  const { context, events } = raceHarness();
  context.hodlVanityGrinder = { cancelled: false, cancel() { this.cancelled = true; }, secrets: "run words and passphrase" };
  events.pagehide({});
  assert.equal(context.hodlVanityGrinder, null, "pagehide left the vanity grinder (and its retained run secrets) reachable");
});

test("dropping the vanity key pick clears the passphrase the source block showed", () => {
  // #vanity-pass shows the picked key's BIP39 passphrase verbatim. Hiding the
  // block when the pick is dropped (chip toggle, wipe, station change) must
  // not leave the passphrase parked in the hidden panel.
  const elements = new Map();
  for (const id of ["vanity-source-block", "vanity-session-note", "vanity-source-name", "vanity-source-kind", "vanity-pass", "vanity-pass-note", "vanity-source-path", "vanity-source-lifehash"])
    elements.set(id, { textContent: "hunter2", hidden: false, disabled: false, dataset: {} });
  const context = createContext({
    document: {
      getElementById: id => elements.get(id) ?? null,
      querySelector: () => null,
      querySelectorAll: () => [],
    },
    hodlVanitySource: "1",
    hodlVanitySourceState: () => null,
    hodlVanitySourceKeys: () => [],
    hodlTText: (text) => text,
    hodlKeyStationMarker: "Keys",
    hodlPaintKeyStationNote() {},
    hodlVanitySyncMethod() {},
    hodlVanitySyncControls() {},
  });
  vm.runInContext(`${functionSource("hodlVanitySyncSource")}\nhodlVanitySyncSource();`, context);
  assert.equal(elements.get("vanity-source-block").hidden, true, "an unpicked source block must hide");
  assert.equal(elements.get("vanity-pass").textContent, "", "unpicking left the shown passphrase behind");
  assert.equal(elements.get("vanity-pass-note").textContent, "", "unpicking left the passphrase note behind");
});

test("journal Lock empties the snapshot, the notepad and the session log", () => {
  // With #journal-state-private ticked, #journal-state-text holds the whole
  // session's recovery texts — seed words, xprvs, WIFs. And the notepad plus
  // the session log are free text the user pasted keystrokes into. #522:
  // a locked journal keeps none of it (#625 review follow-up).
  const elements = new Map([
    ["journal-state-text", { value: "24 seed words and xprvs", dataset: {} }],
    ["journal-state-private", { checked: true, dataset: {} }],
    ["journal-status-note", { textContent: "", dataset: {} }],
    ["journal-notes-text", { value: "dice rolls and brain text", dataset: {} }],
    ["journal-log-out", { textContent: "journal-unlock 12:00", dataset: {} }],
  ]);
  const journal = createJournal();
  journal.pages[0].notesText = "dice rolls and brain text";
  journal.log.push({ kind: "journal-unlock" });
  journal.stateText = "snapshot text";
  const context = createContext({
    document: { getElementById: id => elements.get(id) ?? null },
    hodlJournal: journal,
    wipeJournal,
    hodlKeyManagerReset() {}, hodlJournalWipeNotebook() {}, hodlJournalClearFields() {},
    hodlJournalHideEditor() {}, hodlJournalSetGate() {}, hodlJournalShowWork() {},
    hodlSyncJournalTool() {}, hodlJournalLog() {}, hodlRenderJournalPageTabs() {},
    hodlJournalApplyPageStyle() {}, hodlJournalResetPendingNote(field, label) { field.dataset.pendingNote = label; },
    hodlJournalTool: "book",
  });
  vm.runInContext(`${functionSource("hodlJournalLock")}\nhodlJournalLock();`, context);
  assert.equal(elements.get("journal-state-text").value, "", "Lock left the session snapshot filled");
  assert.equal(elements.get("journal-state-private").checked, false, "Lock left the private toggle ticked");
  assert.equal(elements.get("journal-notes-text").value, "", "Lock left the notepad filled");
  assert.equal(elements.get("journal-log-out").textContent, "No events yet.", "Lock left the session log rendered");
  assert.equal(journal.pages.length, 1, "Lock left notepad pages behind");
  assert.equal(journal.pages[0].notesText, "", "Lock left notepad text behind");
  assert.equal(journal.log.length, 0, "Lock left the session log in memory");
  assert.equal(journal.stateText, "", "Lock left the snapshot's in-memory text");
});

test("pagehide and persisted pageshow end the PSBT session, reports included", () => {
  // The paste fields and the session key go on page hide, but the parsed
  // report state (hodlPsbtLast — the typed decode the inspector re-renders
  // from) and the rendered #psbt-out/#nonce-out views stayed: a bfcache
  // restore re-showed an inspection whose fields were already empty. The
  // lifecycle handler inside hodlInitPsbt must end the session, not only
  // drop the key.
  const start = app.indexOf("function hodlInitPsbt(");
  const init = app.slice(start, app.indexOf("\nfunction ", start + 1));
  const sweep = init.slice(init.indexOf("let clearSecretFields"));
  assert.match(sweep, /hodlEndPsbtSession\(\)/, "the PSBT lifecycle sweep must end the whole session");

  const elements = new Map();
  for (const id of ["psbt-out", "nonce-out"]) elements.set(id, { innerHTML: "<table>report</table>", dataset: {} });
  for (const id of ["psbt-key", "psbt-pass", "psbt-text", "psbt-ax-transcript", "nonce-key", "nonce-pass", "nonce-text"]) elements.set(id, { value: "session material", dataset: {} });
  const errors = [];
  const context = createContext({
    document: { getElementById: id => elements.get(id) ?? null },
    hodlPsbtWipeMem() {}, hodlPsbtClearNonceHistory() {},
    hodlPsbtLast: { rvalues: ["deadbeef"] }, hodlPsbtInspected: { psbt: "stamp" },
    hodlPsbtSessionSpec: { key: "Session key" },
    hodlSetPsbtError: () => errors.push("psbt"), hodlSetNonceError: () => errors.push("nonce"),
    hodlPaintPsbtSession() {}, hodlRefreshStationKeyPickers() {}, hodlSyncPsbtControls() {},
  });
  vm.runInContext(`${functionSource("hodlEndPsbtSession")}\nhodlEndPsbtSession();`, context);
  assert.equal(context.hodlPsbtLast, null, "session end left the parsed report state");
  // (vm realms: assert.keys rather than deepEqual against a home-realm {}.)
  assert.equal(Object.keys(context.hodlPsbtInspected || {}).length, 0, "session end left run stamps");
  assert.equal(elements.get("psbt-out").innerHTML, "", "session end left the PSBT report rendered");
  assert.equal(elements.get("nonce-out").innerHTML, "", "session end left the nonce report rendered");
  assert.deepEqual(errors.sort(), ["nonce", "psbt"], "session end left an error line");
  for (const id of ["psbt-key", "psbt-pass", "psbt-text", "psbt-ax-transcript", "nonce-key", "nonce-pass", "nonce-text"])
    assert.equal(elements.get(id).value, "", `session end left #${id} filled`);
});

test("pagehide and persisted pageshow reset every multisig tab", () => {
  // The station is watch-only — the descriptor import refuses private keys —
  // but a bfcache restore must not bring the session's form back: the
  // lifecycle resets every tab the way the station's own Clear does, and
  // re-renders the (empty) active one.
  assert.match(lifecycle, /hodlMsigs\s*=\s*hodlMsigs\.map\(\(state\)\s*=>/);
  assert.match(lifecycle, /state\.isLab \? hodlNewMsigLabState\(\) : hodlNewMsigState\(state\.name, state\.id, state\.number\)/);
  assert.match(lifecycle, /hodlRestoreMsig\(\)/);
  for (const type of ["pagehide", "pageshow"]) {
    const { context, events } = raceHarness();
    context.hodlMsigs = [{ isLab: false, name: "Vault", id: 7, number: 3, fields: { descriptor: "wsh(sortedmulti(1,xprv9s21ZrQH143K…/0/*))", xpubs: ["xpub661MyMwAqRbc…"] }, result: { mark: 1 } }];
    events[type]({ persisted: type === "pageshow" });
    const state = context.hodlMsigs[0];
    assert.equal(state.name, "Vault", "the tab's name may not change on lifecycle reset");
    assert.equal(state.id, 7, "the tab's id may not change on lifecycle reset");
    assert.equal(state.fields.descriptor, "", `${type} left the descriptor in the tab state`);
    assert.deepEqual(state.fields.xpubs, ["", "", ""], `${type} left cosigner keys in the tab state`);
    assert.equal(state.result, null, `${type} left the derived multisig result`);
  }
});

test("the key Wipe button drops the cached partial mnemonics", () => {
  // Runs the real hodlWipeActiveKey. The cache keys are near-complete seeds,
  // so the wipe must clear them itself rather than wait for pagehide, and it
  // must do so even when no key slot is active.
  for (const activeKey of [-1, 0]) {
    const cache = new Map([["24:abandon abandon abandon", { candidates: [] }]]);
    const context = createContext({
      hodlLastWordCache: cache,
      hodlInvalidateDerivation() {},
      hodlActiveKey: activeKey,
      hodlKeys: [{ name: "Key 1", id: 1, number: 1, isLab: false }],
      hodlNewKeyState: () => ({}),
      hodlNewLabState: () => ({}),
      hodlRestoreKey() {},
      hodlJournalLog() {},
      hodlWipeUnsharedWalletRows() {},
      hodlRefreshStationKeyPickers() {},
      hodlRefreshMsigSessionPickers() {},
    });
    vm.runInContext(`${functionSource("hodlWipeActiveKey")}\nhodlWipeActiveKey();`, context);
    assert.equal(cache.size, 0, `Wipe (active key ${activeKey}) left partial mnemonics in the last-word cache`);
  }
});

test("the key Wipe clears the partial-phrase cache after the form restore refills it", async () => {
  // The clear above pins that the cache goes; this pins the order. Restoring
  // the fresh key state re-renders the form, dropping the seed field while it
  // still holds the typed words; the blur that fires re-runs the final-word
  // analysis, which caches the partial phrase (audit A35-2). The restore stub
  // re-enters through the app's own hodlSeedFinalWordContext — the same call
  // the blur's update() makes — so only a clear after the restore passes.
  let slice;
  const partial = Array(11).fill("abandon").join(" ");
  const inert = new Proxy(function () {}, { get: (target, key) => key === Symbol.toPrimitive ? () => "" : key === "then" ? undefined : inert, apply: () => inert, construct: () => inert });
  // The slice's load-time form-element lookups need a document to call into.
  Object.assign(globalThis, { __ENTROPYLAB_TEST_HOOKS__: false, document: inert, window: inert });
  try {
    slice = await loadAppFunctions(["hodlWipeActiveKey", "hodlSeedFinalWordContext", "hodlLastWordCache"], {
      stubs: {
        hodlInvalidateDerivation() {},
        hodlNewKeyState: (name, id, number) => ({ name, id, number, fields: {}, result: null }),
        hodlNewLabState: () => ({ isLab: true, fields: {}, result: null }),
        hodlRestoreKey: () => { slice.hodlSeedFinalWordContext(partial, 12); },
        hodlWipeUnsharedWalletRows() {},
        hodlRefreshStationKeyPickers() {},
        hodlRefreshMsigSessionPickers() {},
        hodlJournalLog() {},
      },
      settable: ["hodlKeys", "hodlActiveKey"],
    });
  } finally {
    delete globalThis.document;
    delete globalThis.window;
  }
  slice.__set.hodlKeys([{ name: "Key 1", id: 1, number: 1, isLab: false }]);
  slice.__set.hodlActiveKey(0);
  slice.hodlWipeActiveKey();
  assert.equal(slice.hodlLastWordCache.size, 0, "Wipe left the restore's re-cached partial phrase in the last-word cache");
});

// #546 B2: an address row keeps its private key as wipeable bytes, and the
// WIF text exists only while it is shown, copied or exported. Strings cannot
// be erased, so no string in a derived row may carry the key. Expected keys
// come from @scure/bip32 on BIP32 test vector 1 and the WIFs from an
// independent Base58Check encoder, not from app.js.
const vectorSeed = hex.decode("000102030405060708090a0b0c0d0e0f");
const wifOf = (key, network) => createBase58check(sha256).encode(Uint8Array.from([network === "testnet" ? 0xef : 0x80, ...key, 0x01]));
const stringsIn = (value, out = []) => {
  if (typeof value === "string") out.push(value);
  else if (value && typeof value === "object" && !ArrayBuffer.isView(value)) Object.values(value).forEach((entry) => stringsIn(entry, out));
  return out;
};
const vectorRows = (hodlDeriveAddressRows, network, role, count = 3) => {
  const coin = network === "testnet" ? 1 : 0, branch = role === "receive" ? 0 : 1;
  const account = HDKey.fromMasterSeed(vectorSeed).derive(`m/84'/${coin}'/0'`);
  return hodlDeriveAddressRows(account, `m/84h/${coin}h/0h`, "p2wpkh", network, count, role, 0).map((row, index) => ({
    row, key: ScureHDKey.fromMasterSeed(vectorSeed).derive(`m/84'/${coin}'/0'/${branch}/${index}`).privateKey,
  }));
};

test("derived address rows hold their private keys as bytes, never as text", async () => {
  const { hodlDeriveAddressRows } = await loadAppFunctions(["hodlDeriveAddressRows"]);
  for (const network of ["mainnet", "testnet"]) for (const role of ["receive", "change"]) {
    for (const [index, { row, key }] of vectorRows(hodlDeriveAddressRows, network, role).entries()) {
      const secrets = [wifOf(key, network), hex.encode(key)];
      assert.ok(!stringsIn(row).some((text) => secrets.some((secret) => text.includes(secret))), `${network} ${role}/${index}: the row holds its private key as text`);
      assert.deepEqual(row.privateKey, key, `${network} ${role}/${index}: the row's key bytes`);
    }
  }
});

test("a row's WIF is encoded only on request and matches an independent encoder", async () => {
  const { hodlDeriveAddressRows, hodlRowWif, hodlCompressedWifLength } = await loadAppFunctions(["hodlDeriveAddressRows", "hodlRowWif", "hodlCompressedWifLength"]);
  for (const network of ["mainnet", "testnet"]) for (const role of ["receive", "change"]) {
    for (const { row, key } of vectorRows(hodlDeriveAddressRows, network, role)) assert.equal(hodlRowWif(row), wifOf(key, network));
  }
  assert.equal(hodlRowWif({ privateKey: null, network: "mainnet" }), null, "a watch-only row has no WIF");
  // The hidden table masks a row's WIF by its fixed length instead of encoding
  // it: every compressed WIF, at the smallest and largest keys, on both
  // networks, is that long.
  const n1 = hex.decode("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140"), one = new Uint8Array(32);
  one[31] = 1;
  for (const key of [one, n1]) for (const network of ["mainnet", "testnet"]) assert.equal(wifOf(key, network).length, hodlCompressedWifLength);
});

// A result's rows, the shape key results carry (accounts → addressBranches →
// rows); receive/change alias the same row objects.
const walletWithRows = (Bytes = Uint8Array) => {
  const rows = [0, 1].map((index) => ({ index, privateKey: new Bytes(32).fill(index + 7) }));
  return { rows, result: { accounts: [{ addressBranches: [{ branch: 0, rows }], receive: rows, change: [] }] } };
};
const zeroed = (rows) => rows.every((row) => row.privateKey.every((byte) => byte === 0));

test("Wipe zeroes a wallet's row key bytes unless another key tab still shows the wallet", () => {
  for (const shared of [false, true]) {
    const { rows, result } = walletWithRows();
    const active = { name: "Key 1", id: 1, number: 1, isLab: false, result };
    const context = createContext({
      hodlLastWordCache: new Map(), hodlInvalidateDerivation() {}, hodlActiveKey: 0,
      hodlKeys: shared ? [active, { isLab: true, result }] : [active], hodlKeyManagerPending: [], hodlWalletResult: result,
      hodlNewKeyState: () => ({ result: null }), hodlNewLabState: () => ({ result: null }),
      hodlRestoreKey() { context.hodlWalletResult = context.hodlKeys[context.hodlActiveKey]?.result ?? null; }, hodlJournalLog() {},
      hodlRefreshStationKeyPickers() {}, hodlRefreshMsigSessionPickers() {},
    });
    for (const name of ["hodlAccountAddressBranches", ...rowWipeHelpers.filter((name) => app.includes(`function ${name}(`))]) vm.runInContext(functionSource(name), context);
    vm.runInContext(`${functionSource("hodlWipeActiveKey")}\nhodlWipeActiveKey();`, context);
    if (shared) assert.ok(rows.every((row) => row.privateKey.some((byte) => byte !== 0)), "Wipe zeroed keys another tab still shows");
    else assert.ok(zeroed(rows), "Wipe left the wallet's row key bytes in memory");
  }
});

test("pagehide and persisted pageshow zero every derived wallet's row key bytes", () => {
  for (const event of ["pagehide", "pageshow"]) {
    const { context, events } = raceHarness();
    context.hodlNewLabState = () => ({ fields: {}, result: null });
    const station = walletWithRows(), lab = walletWithRows(), pending = walletWithRows(), shown = walletWithRows();
    context.hodlKeys = [{ id: 1, number: 1, fields: {}, result: station.result }, { id: 2, number: 2, isLab: true, fields: {}, result: lab.result }];
    context.hodlKeyManagerPending = [{ result: pending.result }];
    context.hodlWalletResult = shown.result;
    events[event]({ persisted: true });
    for (const [name, wallet] of Object.entries({ station, lab, pending, shown })) assert.ok(zeroed(wallet.rows), `${event}: the ${name} wallet's row key bytes survived`);
  }
});

test("an ignored key's saved copy carries no key bytes", async () => {
  const { rows, result } = walletWithRows();
  result.masterFingerprint = "73c5da0a";
  const { hodlKeyManagerEntry } = await loadAppFunctions(["hodlKeyManagerEntry"]);
  const entry = hodlKeyManagerEntry({ id: 1, name: "Key 1", isLab: false, fields: {}, result });
  const copied = entry.result.accounts[0].addressBranches[0].rows;
  assert.ok(copied.every((row) => row.privateKey === undefined), "the copy kept the rows' key bytes");
  assert.equal(entry.result.masterFingerprint, "73c5da0a", "the copy keeps what identifies the key");
  assert.ok(rows.every((row) => row.privateKey instanceof Uint8Array), "copying must not touch the live rows");
});

// A key detached from a station moves, result and all, into the Key Manager's
// pending list, and the Key Station can still show that same result. The Key
// Manager's reset (Journal lock, unlock, create, wipe) zeroes every byte array
// its pending keys reach; it must not reach rows a station still shows.
test("a Key Manager reset leaves the row key bytes of a wallet a station still shows", () => {
  const context = createContext({
    hodlKeyManagerIgnored: [], hodlKeyManagerIds: new Set(), hodlKeyManagerActiveId: "",
    document: { getElementById: () => null }, hodlKeyManagerStatus() {}, hodlKeyManagerRender() {},
    hodlRefreshStationKeyPickers() {}, hodlRefreshMsigSessionPickers() {},
  });
  // The wipe tests bytes with instanceof, so they must come from the context's
  // own realm, as they do in the page.
  const Bytes = vm.runInContext("Uint8Array", context), shared = walletWithRows(Bytes), alone = walletWithRows(Bytes);
  Object.assign(context, {
    hodlKeyManagerPending: [{ id: 1, result: shared.result }, { id: 2, result: alone.result }],
    hodlKeys: [{ isLab: true, result: shared.result }], hodlWalletResult: shared.result,
  });
  for (const name of ["hodlKeyManagerWipeValue", "hodlKeyManagerReset", "hodlAccountAddressBranches", ...rowWipeHelpers.filter((name) => app.includes(`function ${name}(`))]) vm.runInContext(functionSource(name), context);
  vm.runInContext("hodlKeyManagerReset();", context);
  assert.ok(shared.rows.every((row) => row.privateKey.some((byte) => byte !== 0)), "the reset zeroed keys the Key Station still shows");
  assert.ok(zeroed(alone.rows), "the reset left a pending-only wallet's row key bytes in memory");
});

// A derivation that never commits must not leave the row keys it made in
// memory either: stopped, wiped, hidden, failed, or declined at the
// fingerprint confirmation, before or after its rows are complete (Astra's
// review of #588). This runs the real derivation controller, progress
// tracker and address-row builder on BIP32 test vector 1, holding each
// progress pause until the test releases it. The stubbed wallet builder only
// strings the real rows together. Every key the row builder takes from a
// child node is recorded, so the assertions read the exact buffers the rows
// kept, and the expected keys come from @scure/bip32.
const vectorRowKey = (branch, index) => ScureHDKey.fromMasterSeed(vectorSeed).derive(`m/84'/0'/0'/${branch}/${index}`).privateKey;
const vectorFingerprint = ScureHDKey.fromMasterSeed(vectorSeed).fingerprint.toString(16).padStart(8, "0");
const vectorRowKeys = [[0, 0], [0, 1], [1, 0], [1, 1]].map(([branch, index]) => vectorRowKey(branch, index));
const allZero = (keys) => keys.every((key) => key.every((byte) => byte === 0));
const noneZero = (keys) => keys.every((key) => key.some((byte) => byte !== 0));

// The real account and wallet builders' collaborators, loaded once. The
// builders themselves run in each harness context, so the key material they
// keep registers with that harness's derivation (#546 B2 step 2b).
const walletBuilderParts = loadAppFunctions(["hodlAccountExportFamily", "hodlSerializeExtendedKey", "hodlExtendedKeyVersions", "hodlNetworkFamily",
  "hodlDescriptorWithChecksum", "hodlScriptDescriptor", "hodlWatchOnlyMultipathDescriptor", "hodlOriginPathComponent", "hodlAddressBranchLabel",
  "hodlDeriveAddressRows", "hodlBuildMultisigCosignerExports", "hodlCoinTypeFromNetwork", "hodlNote"]);
const walletKeepers = ["hodlCopyPrivateNode", "hodlKeepPrivateNode", "hodlNodeHasPrivateKey"].filter((name) => app.includes(`function ${name}(`));
const bip84Definition = { id: "bip84", label: "Native SegWit", bip: "BIP84", script: "p2wpkh", purpose: 84, purposeHardened: true };

async function derivationHarness({ failAtAddress = 0, identity = () => "bip32-vector-1", single = false, seedWords = false } = {}) {
  const harness = raceHarness(), { context } = harness, keys = [], pauses = [];
  const real = await loadAppFunctions(["hodlPathComponent", "hodlAddressBranchRole", "hodlAddressOrThrow"]);
  let clock = 0, addresses = 0;
  Object.assign(context, await walletBuilderParts, { hodlHDKey: HDKey });
  Object.assign(context, {
    hodlActiveDerivation: null, hodlDerivationProgressTimers: {}, hodlHex: appHex,
    hodlPathComponent: real.hodlPathComponent, hodlAddressBranchRole: real.hodlAddressBranchRole,
    hodlAddressOrThrow(...args) {
      if (++addresses === failAtAddress) throw new Error("address failure");
      return real.hodlAddressOrThrow(...args);
    },
    // Every progress step yields, and each yield waits for the test.
    performance: { now: () => (clock += 20) }, setTimeout: () => 0, clearTimeout() {},
    hodlDerivationPause() { const gate = deferred(); pauses.push(gate); return gate.promise; },
    hodlResetDerivationProgress() {}, hodlSetDerivationButtonState() {}, hodlSyncDeriveButton() {}, hodlSyncMsigDeriveButton() {}, hodlSyncPurposeMatchControls() {},
    // The rows come from the real row builder; the real account and wallet
    // builders then assemble them into the result a derivation commits.
    async hodlEntropyWalletWithProgress(entropy, passphrase, network, count, accountIndex, addressStart, tracker) {
      // A single-key result from the real builder, which records its key
      // bytes with this harness's derivation (#546 B2 step 2c-1).
      if (single) {
        const builder = await singleKeyBuilder;
        builder.__set.hodlActiveDerivation(context.hodlActiveDerivation);
        return builder.hodlSingleKeyWallet(singleKeyWif, "mainnet", "wif");
      }
      // A seed wallet from the real builder, which records its seed material
      // with this harness's derivation (#546 B2 step 2c-2).
      if (seedWords) {
        const builder = await seedWalletBuilder;
        builder.__set.hodlActiveDerivation(context.hodlActiveDerivation);
        return Object.assign(await builder.hodlMnemonicWalletWithProgress(seedVector.words, seedVector.pass, "mainnet", 2, undefined, 0, 0, tracker, 84, 0), { masterIdentity: identity() });
      }
      const root = HDKey.fromMasterSeed(vectorSeed), account = root.derive("m/84'/0'/0'"), watched = {
        derive(path) {
          const child = account.derive(path);
          return { get publicKey() { return child.publicKey; }, get privateKey() { const key = child.privateKey; keys.push(key); return key; }, wipePrivateData: () => child.wipePrivateData() };
        },
      }, addressBranches = [];
      try {
        for (const branch of [0, 1]) addressBranches.push({ branch, rows: await context.hodlAddressRowsWithProgress(watched, "m/84h/0h/0h", "p2wpkh", "mainnet", 2, branch, 0, tracker) });
        const fingerprint = vectorFingerprint, source = { mnemonic: null, passphraseUsed: false, passphrase: "", entropyHex: null, seedHex: null, notes: [], warnings: [] };
        const accountResult = context.hodlAccountResult(account, bip84Definition, "mainnet", 2, { accountPath: "m/84h/0h/0h", accountIndex: 0, masterFingerprint: fingerprint, originFingerprint: fingerprint, originPath: "84h/0h/0h", addressBranches, branchStart: 0, branchRange: 2 });
        return Object.assign(context.hodlRootWalletResult(root, "mainnet", source, 0, fingerprint, [accountResult], 0), { masterIdentity: identity() });
      } finally {
        account.wipePrivateData();
        root.wipePrivateData();
      }
    },
  });
  for (const name of ["hodlDeriveWithProgress", "hodlCreateDerivationTracker", "hodlStopDerivation", "hodlAddressRowsWithProgress", "hodlDerivedAddressRow",
    "hodlAccountResult", "hodlRootWalletResult", ...walletKeepers])
    vm.runInContext(functionSource(name), context);
  // Releases held pauses until `done` holds; fails if the derivation stalls.
  const driveUntil = async (done) => {
    for (let spins = 0; !done(); spins++) {
      assert.ok(spins < 1000, "the derivation stalled");
      if (pauses.length) pauses.shift().resolve();
      else await new Promise((resolve) => setImmediate(resolve));
    }
  };
  const start = () => {
    const run = { settled: false };
    run.promise = context.hodlDeriveWithProgress("key", context.hodlCalculateKey).finally(() => { run.settled = true; });
    return run;
  };
  return { ...harness, keys, pauses, driveUntil, start };
}

for (const teardown of ["Wipe", "pagehide", "persisted pageshow", "Stop"]) {
  test(`${teardown} during a derivation's progress pause zeroes the rows it has built`, async () => {
    const { context, events, keys, pauses, driveUntil, start } = await derivationHarness();
    const run = start();
    await driveUntil(() => keys.length === 1 && pauses.length === 1);
    assert.deepEqual(keys[0], vectorRowKeys[0], "the first row holds its real key");
    if (teardown === "Wipe") context.hodlWipeActiveKey();
    else if (teardown === "Stop") context.hodlStopDerivation("key");
    else events[teardown.split(" ").pop()]({ persisted: true });
    // A hidden page can stay suspended mid-derivation: Wipe and page teardown
    // must not wait for it to unwind. Stop lets it unwind at the next pause.
    if (teardown !== "Stop") assert.ok(allZero(keys), `${teardown} left the partial rows' key bytes in memory`);
    await driveUntil(() => run.settled);
    await run.promise;
    assert.equal(context.hodlWalletResult, null, `${teardown}: the stopped derivation committed`);
    assert.equal(keys.length, 1, `${teardown}: the derivation kept deriving`);
    assert.ok(allZero(keys), `${teardown} left the partial rows' key bytes in memory`);
  });
}

test("a derivation that fails part-way zeroes the rows it had built", async () => {
  const { context, keys, driveUntil, start } = await derivationHarness({ failAtAddress: 3 });
  const run = start();
  await driveUntil(() => run.settled);
  assert.equal(await run.promise, undefined);
  assert.equal(context.hodlWalletResult, null);
  assert.equal(keys.length, 3, "the third row failed after taking its key");
  assert.ok(allZero(keys), "a failed derivation left its rows' key bytes in memory");
});

test("declining the fingerprint confirmation zeroes the finished result's row keys", async () => {
  const { context, keys, driveUntil, start } = await derivationHarness(), confirm = deferred();
  let asked = false;
  context.hodlConfirmKeyFingerprint = () => { asked = true; return confirm.promise; };
  const run = start();
  await driveUntil(() => asked);
  assert.deepEqual(keys, vectorRowKeys, "the finished result holds its real keys");
  confirm.resolve(false);
  await driveUntil(() => run.settled);
  await run.promise;
  assert.equal(context.hodlWalletResult, null, "the declined result committed");
  assert.ok(allZero(keys), "the declined result's row key bytes stayed in memory");
});

test("pagehide while the fingerprint confirmation is open zeroes the pending result's row keys", async () => {
  const { context, events, keys, driveUntil, start } = await derivationHarness(), confirm = deferred();
  let asked = false;
  context.hodlConfirmKeyFingerprint = () => { asked = true; return confirm.promise; };
  const run = start();
  await driveUntil(() => asked);
  assert.ok(noneZero(keys));
  events.pagehide({});
  assert.ok(allZero(keys), "pagehide left the pending result's row key bytes in memory");
  // Confirming after the page comes back must not revive the result.
  confirm.resolve(true);
  await driveUntil(() => run.settled);
  await run.promise;
  assert.equal(context.hodlWalletResult, null, "the confirmation committed a result the page had already wiped");
  assert.ok(allZero(keys));
});

test("a committed derivation keeps its row keys, and a later stopped one zeroes only its own", async () => {
  const { context, keys, pauses, driveUntil, start } = await derivationHarness();
  const first = start();
  await driveUntil(() => first.settled);
  await first.promise;
  const committed = keys.splice(0);
  assert.ok(context.hodlWalletResult, "the derivation committed");
  assert.deepEqual(committed, vectorRowKeys, "committing zeroed the keys the station now shows");
  const second = start();
  await driveUntil(() => keys.length === 1 && pauses.length === 1);
  context.hodlStopDerivation("key");
  await driveUntil(() => second.settled);
  await second.promise;
  assert.ok(allZero(keys), "the stopped derivation left its row key bytes in memory");
  assert.deepEqual(committed, vectorRowKeys, "stopping a derivation zeroed the keys of the wallet the station shows");
});

// The account node a wallet derives its rows from holds the account private
// key. A derivation that stops part-way must wipe it as a finished one does.
test("a stopped derivation wipes the account nodes it derived", async () => {
  const { hodlRootWalletWithProgress } = await loadAppFunctions(["hodlRootWalletWithProgress"]);
  const root = HDKey.fromMasterSeed(vectorSeed), derive = root.derive.bind(root), nodes = [];
  root.derive = (path) => { const node = derive(path); nodes.push(node); return node; };
  let steps = 0;
  const tracker = { setTotal() {}, step() { if (++steps === 3) throw new Error("stopped"); return null; } };
  await assert.rejects(hodlRootWalletWithProgress(root, "mainnet", 2, {}, 0, 0, tracker, 84, 0), /stopped/);
  assert.equal(nodes.length, 1);
  assert.ok(nodes.every((node) => node.privateKey === null), "the stopped derivation left the account private key in memory");
});

test("a stopped import of an account key wipes the imported node", async () => {
  // BIP32 test vector 1, chain m/0H/1/2H: a depth-3 extended private key.
  const xprv = "xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM";
  const { hodlParseExtendedKey } = await loadAppFunctions(["hodlParseExtendedKey"]), nodes = [];
  const { hodlImportedWalletWithProgress } = await loadAppFunctions(["hodlImportedWalletWithProgress"], {
    stubs: {
      hodlParseExtendedKey(value) { const parsed = hodlParseExtendedKey(value); nodes.push(parsed.node); return parsed; },
      hodlSelectedScriptType: () => "bip84",
    },
  });
  let steps = 0;
  const tracker = { setTotal() {}, step() { if (++steps === 3) throw new Error("stopped"); return null; } };
  await assert.rejects(hodlImportedWalletWithProgress(xprv, "mainnet", 2, 0, 0, tracker, 84, 0), /stopped/);
  assert.equal(nodes.length, 1);
  assert.ok(nodes[0].privateKey === null, "the stopped import left the imported private key in memory");
});

// #546 B2 step 2a: a wallet the Key Station stops holding cannot come back,
// so its row keys are zeroed when it goes rather than left for the collector.
// A station drops a wallet when an edit clears it, a re-derive replaces it,
// a failed re-derive loses it, its tab is deleted or ignored, or a revoked
// brain-wallet acknowledgement retracts it. These run the real derivation
// (as above) and commit it through the real hodlCommitDerivedKey; the two
// bookkeeping stand-ins do only what the real ones do with results:
// hodlCaptureKey files the shown result on the active tab, and
// hodlRestoreKey shows the active tab's result.
async function stationHarness(options = {}) {
  let identity = "bip32-vector-1", nextId = 1;
  const harness = await derivationHarness({ ...options, identity: () => identity }), { context } = harness;
  const lab = () => ({ id: 0, number: 0, isLab: true, fields: {}, result: null });
  Object.assign(context, {
    hodlKeys: [lab()], hodlActiveKey: 0, hodlNextKeyNumber: 1, hodlWorkspace: "calc",
    hodlKeyManagerIds: new Set(), hodlKeyManagerActiveId: "", hodlKeyManagerIgnored: [], keyVaultIdentity,
    hodlCaptureKey() { const state = context.hodlKeys[context.hodlActiveKey]; if (state) state.result = context.hodlWalletResult; },
    hodlRestoreKey() { context.hodlWalletResult = context.hodlKeys[context.hodlActiveKey]?.result ?? null; },
    hodlNewLabState: lab, hodlNewKeyState: () => { const id = nextId++; return { id, number: id, fields: {}, result: null }; },
    hodlRenderKeyTabs() {}, hodlElement: () => ({ children: [] }), hodlSyncKeyDeleteButton() {}, hodlSyncKeyAddButton() {},
    hodlSpDropAddressesFrom() {}, hodlKeyManagerRender() {}, hodlKeyLogLabel: () => "key", hodlSetWorkspaceError() {},
    hodlJournalUnlocked: () => false,
    // The rows' key bytes come from this realm (the real HDKey), as they
    // do in the page, so the page code's instanceof must see this realm's.
    Uint8Array,
    hodlJournalWipeNotebook() {}, hodlJournalClearFields() {}, hodlJournalHideEditor() {}, hodlJournalSetGate() {},
    hodlJournalShowWork() {}, hodlSyncJournalTool() {}, hodlJournalTool: "notes",
    // Journal Lock wipes the session notepad/log (with the real wipeJournal
    // on a real journal object); the DOM sides are absent elements here.
    hodlJournal: createJournal(), wipeJournal,
    hodlRenderJournalPageTabs() {}, hodlJournalApplyPageStyle() {}, hodlJournalResetPendingNote() {},
  });
  context.document.getElementById = ((byId, note = { textContent: "" }) => (id) => id === "journal-status-note" ? note : byId(id))(context.document.getElementById);
  for (const name of ["hodlCommitDerivedKey", "hodlCloneDerivedKey", "hodlKeyWalletIdentity", "hodlInvalidateLiveKeyResult",
    "hodlInvalidateActiveKeyOutput", "hodlRetractBrainWalletResults", "hodlDeleteActiveKey", "hodlKeyManagerIgnore",
    "hodlKeyManagerEntry", "hodlKeyManagerDetachFromStation", "hodlKeyManagerReset", "hodlKeyManagerWipeValue", "hodlJournalLock"])
    vm.runInContext(functionSource(name), context);
  // Derives BIP32 test vector 1 on the active tab and commits it, returning
  // the key buffers the committed rows hold.
  const derive = async (wallet = identity) => {
    identity = wallet;
    const from = harness.keys.length, run = harness.start();
    await harness.driveUntil(() => run.settled);
    await run.promise;
    return harness.keys.slice(from);
  };
  const selectLab = () => { context.hodlActiveKey = context.hodlKeys.findIndex((state) => state.isLab); context.hodlRestoreKey(); };
  // What hodlShowWorkspace does to the key state: capture the active tab on
  // leaving Keys and clear the shown wallet; restore the active tab on return.
  const leaveKeys = (workspace) => { context.hodlCaptureKey(); context.hodlWorkspace = workspace; context.hodlWalletResult = null; };
  const returnToKeys = () => { context.hodlWorkspace = "calc"; context.hodlRestoreKey(); };
  // Whether the Key Station still keeps a reference to a wallet. A dropped
  // wallet must be forgotten, not only zeroed: its seed material is still
  // text until B2 step 2c.
  const held = (result) => [...context.hodlCommittedResults].includes(result);
  const active = () => context.hodlKeys[context.hodlActiveKey];
  return { ...harness, derive, selectLab, leaveKeys, returnToKeys, held, active, setIdentity: (value) => { identity = value; } };
}

test("an edit that clears a derived wallet zeroes its row keys", async () => {
  for (const clear of ["hodlInvalidateLiveKeyResult", "hodlInvalidateActiveKeyOutput"]) {
    const { context, derive, held } = await stationHarness();
    const keys = await derive(), result = context.hodlWalletResult;
    assert.deepEqual(keys, vectorRowKeys, `${clear}: the committed wallet holds its real keys`);
    assert.ok(result && held(result), `${clear}: the derivation committed`);
    context[clear]();
    assert.equal(context.hodlKeys[context.hodlActiveKey].result, null);
    assert.ok(allZero(keys), `${clear} dropped the wallet and left its row key bytes in memory`);
    assert.ok(!held(result), `${clear}: the Key Station still references the dropped wallet`);
  }
});

test("re-deriving a key tab zeroes the wallet it replaces", async () => {
  const { context, derive, held } = await stationHarness();
  const replaced = await derive(), tab = context.hodlActiveKey, old = context.hodlKeys[tab].result;
  assert.equal(context.hodlKeys[tab].isLab, false, "the first derivation filed a key tab");
  const current = await derive();
  assert.equal(context.hodlActiveKey, tab);
  assert.ok(allZero(replaced), "the replaced wallet's row key bytes stayed in memory");
  assert.ok(!held(old) && held(context.hodlKeys[tab].result), "the Key Station references the wrong wallet");
  assert.deepEqual(current, vectorRowKeys, "the wallet the tab now shows lost its keys");
});

test("re-deriving an open wallet from the Key Station zeroes the tab's old copy", async () => {
  const { context, derive, selectLab, held, active } = await stationHarness();
  const replaced = await derive(), old = active().result;
  selectLab();
  const current = await derive();
  assert.equal(context.hodlKeys.filter((state) => !state.isLab).length, 1, "the same wallet opened a second tab");
  assert.ok(allZero(replaced), "the tab's old copy kept its row key bytes");
  assert.ok(!held(old), "the Key Station still references the tab's old copy");
  assert.deepEqual(current, vectorRowKeys);
});

test("a failed re-derive zeroes the wallet the tab loses", async () => {
  // The first derivation builds rows 1 to 4; the second fails on its second row.
  const { context, derive, held, active } = await stationHarness({ failAtAddress: 6 });
  const lost = await derive(), old = active().result;
  await derive();
  assert.equal(context.hodlKeys[context.hodlActiveKey].result, null, "the failed re-derive left the old wallet on the tab");
  assert.ok(allZero(lost), "the lost wallet's row key bytes stayed in memory");
  assert.ok(!held(old), "the Key Station still references the lost wallet");
});

test("deleting a key tab zeroes its wallet; with the journal open it moves to the Key Manager intact", async () => {
  for (const journalOpen of [false, true]) {
    const { context, derive, selectLab, held, active } = await stationHarness();
    const deleted = await derive("wallet-a"), deletedResult = active().result;
    selectLab();
    const other = await derive("wallet-b");
    context.hodlActiveKey = context.hodlKeys.findIndex((state) => state.result?.masterIdentity === "wallet-a");
    context.hodlRestoreKey();
    context.hodlJournalUnlocked = () => journalOpen;
    context.hodlDeleteActiveKey();
    assert.ok(!context.hodlKeys.some((state) => state.result?.masterIdentity === "wallet-a"), "the tab is still in the station");
    if (journalOpen) {
      assert.equal(context.hodlKeyManagerPending.length, 1, "the key did not move to the Key Manager");
      // Another wallet dropping afterwards must not reach the one the Key Manager holds.
      context.hodlActiveKey = context.hodlKeys.findIndex((state) => state.result?.masterIdentity === "wallet-b");
      context.hodlRestoreKey();
      context.hodlInvalidateLiveKeyResult();
      assert.deepEqual(deleted, vectorRowKeys, "the Key Manager's key lost its row key bytes");
      assert.ok(held(deletedResult), "the Key Manager's wallet was forgotten while it still holds it");
    } else {
      assert.ok(allZero(deleted), "the deleted tab's row key bytes stayed in memory");
      assert.ok(!held(deletedResult), "the Key Station still references the deleted tab's wallet");
    }
    if (!journalOpen) assert.deepEqual(other, vectorRowKeys, "deleting one tab zeroed another tab's wallet");
  }
});

// The Key Manager lives in the Journal workspace. Leaving Keys captures the
// active tab and clears the shown wallet (hodlShowWorkspace), so anything
// that runs there must not capture again: that would file the cleared value
// over the selected tab's wallet, and the next sweep would zero it.
test("ignoring a key from the Journal zeroes its wallet and leaves the selected wallet intact", async () => {
  for (const [ignored, from] of [["a", "station"], ["b", "station"], ["a", "pending"]]) {
    const { context, derive, selectLab, leaveKeys, returnToKeys, held } = await stationHarness();
    const keys = { a: await derive("wallet-a") };
    selectLab();
    keys.b = await derive("wallet-b");
    const tab = (wallet) => context.hodlKeys.find((state) => state.result?.masterIdentity === `wallet-${wallet}`);
    const states = { a: tab("a"), b: tab("b") }, kept = ignored === "a" ? "b" : "a", keptResult = states[kept].result, ignoredResult = states[ignored].result;
    if (from === "pending") {
      // Deleting a tab with the journal open moves it to the Key Manager.
      context.hodlActiveKey = context.hodlKeys.indexOf(states.a);
      context.hodlRestoreKey();
      context.hodlJournalUnlocked = () => true;
      context.hodlDeleteActiveKey();
      assert.deepEqual(context.hodlKeyManagerPending, [states.a]);
    }
    const label = `ignoring ${ignored} from ${from} with b selected`;
    leaveKeys("journal");
    context.hodlKeyManagerIgnore(states[ignored]);
    assert.equal(context.hodlKeyManagerIgnored.length, 1);
    assert.ok(allZero(keys[ignored]), `${label}: the ignored wallet kept its row key bytes`);
    assert.ok(!held(ignoredResult) && held(keptResult), `${label}: the Key Station references the wrong wallet`);
    assert.equal(states[kept].result, keptResult, `${label}: the other wallet's tab lost its wallet`);
    assert.deepEqual(keys[kept], vectorRowKeys, `${label}: the other wallet's row keys were zeroed`);
    returnToKeys();
    assert.notEqual(context.hodlWalletResult, states[ignored].result, `${label}: Keys shows the ignored wallet`);
  }
});

test("changing the language outside Keys keeps the selected key's wallet", async () => {
  for (const shown of [null, { kind: "msig" }]) {
    const { context, derive, leaveKeys, returnToKeys } = await stationHarness();
    const keys = await derive(), state = context.hodlKeys[context.hodlActiveKey], result = state.result;
    Object.assign(context, {
      Event: class { constructor(type) { this.type = type; } }, hodlWorkspaceTabs: [], hodlKeyModeLabels: {},
      hodlKeyModeSelectEl: { options: [], dispatchEvent() {} }, hodlNetworkPickerRender: null, hodlReadThemeMode: () => "system",
    });
    for (const name of ["hodlRenderKeyForm", "hodlRestoreFormFields", "hodlUpdateSeedLengthControl", "hodlUpdateAddressEstimate",
      "hodlUpdateCoinTypeHelp", "hodlUpdateDerivationPathPreview", "hodlUpdateMsigScriptDetection",
      "hodlUpdateMsigAccount", "hodlShowMsig", "hodlRefreshKeyResult", "hodlRefreshPsbtLocale", "hodlApplyTheme", "hodlRefreshWorkspaceErrors"])
      context[name] = () => {};
    let logRefreshes = 0, guideRefreshes = 0;
    context.hodlSecurityLog = { refresh: () => logRefreshes++ };
    context.hodlFeatureGuide = { refresh: () => guideRefreshes++ };
    vm.runInContext(functionSource("hodlApplyLocale"), context);
    leaveKeys("msig");
    // The Multisig workspace shows its own result, or none.
    context.hodlWalletResult = shown;
    context.hodlApplyLocale();
    assert.equal(logRefreshes, 1, "the security log must refresh with the locale");
    assert.equal(guideRefreshes, 1, "the guide must refresh with the locale without dropping wallet state");
    assert.equal(state.result, result, `${shown ? "with" : "without"} a multisig result: the language change dropped the key's wallet`);
    context.hodlDisposeDroppedWallets();
    assert.deepEqual(keys, vectorRowKeys, "the language change got the selected wallet zeroed");
    returnToKeys();
    assert.equal(context.hodlWalletResult, result);
  }
});

test("revoking the brain-wallet acknowledgement zeroes every wallet it retracts, and no other", async () => {
  const { context, derive, selectLab, held } = await stationHarness();
  const brainA = await derive("brain-a"), retracted = [context.hodlWalletResult];
  context.hodlKeys[context.hodlActiveKey].result.brainWalletOutput = "hd";
  selectLab();
  const brainB = await derive("brain-b");
  retracted.push(context.hodlWalletResult);
  context.hodlKeys[context.hodlActiveKey].result.brainWalletOutput = "hd";
  selectLab();
  const plain = await derive("plain");
  context.hodlRetractBrainWalletResults("hd");
  assert.ok(allZero(brainA) && allZero(brainB), "a retracted brain wallet kept its row key bytes");
  assert.ok(!retracted.some(held), "the Key Station still references a retracted brain wallet");
  assert.deepEqual(plain, vectorRowKeys, "the retraction zeroed a wallet it did not retract");
});

test("a wallet another tab still shows keeps its row keys when one tab drops it", async () => {
  const { context, derive } = await stationHarness();
  const keys = await derive(), shown = context.hodlKeys[context.hodlActiveKey];
  context.hodlKeys.push({ id: 99, number: 99, isLab: false, fields: {}, result: shown.result });
  context.hodlInvalidateLiveKeyResult();
  assert.equal(shown.result, null);
  assert.deepEqual(keys, vectorRowKeys, "dropping a shared wallet from one tab zeroed the keys the other tab shows");
});

test("saving a vanity passphrase match to its key zeroes the wallet the key had", async () => {
  // A passphrase match is a new wallet (new fingerprint): the Keys tab files
  // it as a new tab, then the match folds it back into the key it came from,
  // which drops that key's previous wallet.
  const { context, derive, setIdentity, driveUntil, held } = await stationHarness();
  const previous = await derive("before-vanity"), source = context.hodlKeys[context.hodlActiveKey], previousResult = source.result;
  const run = { sourceKind: "key", sourceId: source.id, sourceLabel: "key", method: "passphrase", script: "p2wpkh", path: [84, 0, 0, 0, 0], pathText: "m/84'/0'/0'/0/0" };
  Object.assign(context, {
    hodlScriptTypes: (await loadAppFunctions(["hodlScriptTypes"])).hodlScriptTypes,
    hodlVanityMatches: [{ passphrase: "vanity passphrase", index: null, savedTo: "" }], hodlVanityRun: run, hodlVanityApplying: false,
    hodlVanityPlan: () => ({ node: null, pathPrefix: [], path: run.path }), hodlWorkspace: "vanity", hodlSpSource: "", hodlBip85Source: "",
    hodlRenderVanityOut() {}, hodlVanitySyncControls() {}, hodlVanityKeyLabel: () => "key", hodlVanitySetStatus() {}, hodlVanitySyncSource() {},
    hodlPickSpSessionKey() {}, hodlPickBip85SessionKey() {},
  });
  const page = { "calc-card": { hidden: false }, "vanity-error": { textContent: "" } }, byId = context.document.getElementById;
  context.document.getElementById = (id) => page[id] ?? byId(id);
  for (const name of ["hodlVanityApplyMatch", "hodlFillLabFromKey"]) vm.runInContext(functionSource(name), context);
  setIdentity("after-vanity");
  let settled = false;
  const applied = context.hodlVanityApplyMatch(0).finally(() => { settled = true; });
  await driveUntil(() => settled);
  await applied;
  const saved = context.hodlKeys.find((state) => state.id === source.id);
  assert.equal(page["vanity-error"].textContent, "", "saving the match failed");
  assert.equal(saved?.result?.masterIdentity, "after-vanity", "the match was not saved to its key");
  assert.equal(context.hodlKeys.filter((state) => !state.isLab).length, 1, "the new wallet stayed in a second tab");
  assert.ok(allZero(previous), "the key's previous wallet kept its row key bytes");
  assert.ok(!held(previousResult), "the Key Station still references the key's previous wallet");
  // Spread into this realm's array: the result's arrays come from the harness context.
  const shown = [...saved.result.accounts[0].addressBranches.flatMap((branch) => branch.rows.map((row) => row.privateKey))];
  assert.deepEqual(shown, vectorRowKeys, "saving zeroed the wallet the key now shows");
});

test("pagehide also zeroes a dropped wallet no drop site has zeroed yet", async () => {
  const { context, events, derive } = await stationHarness();
  const keys = await derive();
  // A drop that skipped the zeroing: the result is gone from every station.
  context.hodlKeys[context.hodlActiveKey].result = null;
  context.hodlWalletResult = null;
  assert.deepEqual(keys, vectorRowKeys);
  events.pagehide({});
  assert.ok(allZero(keys), "pagehide left a dropped wallet's row key bytes in memory");
  assert.equal(context.hodlCommittedResults.size, 0, "pagehide left wallets referenced by the Key Station");
});

// Locking the journal (and unlocking, creating or wiping it) resets the Key
// Manager: its pending keys are zeroed and dropped. The Key Station must
// forget those wallets too, or its record keeps each whole result, root xprv
// included, reachable after the lock (Codex, #590). A wallet a station still
// shows stays zeroed-free and held.
test("locking the journal forgets the Key Manager's wallets and keeps the ones a station shows", async () => {
  const { context, derive, selectLab, leaveKeys, returnToKeys, held, active } = await stationHarness();
  context.hodlJournalUnlocked = () => true;
  const detachedKeys = await derive("detached"), detached = active().result;
  context.hodlDeleteActiveKey();
  assert.equal(context.hodlKeyManagerPending[0]?.result, detached, "deleting the tab did not move it to the Key Manager");
  selectLab();
  const sharedKeys = await derive("shared"), sharedTab = active(), shared = sharedTab.result;
  // A Key Manager entry that still shares its wallet with a station tab.
  context.hodlKeyManagerPending.push({ id: 77, number: 77, fields: {}, result: shared });
  leaveKeys("journal");
  context.hodlJournalLock();
  assert.equal(context.hodlKeyManagerPending.length, 0);
  assert.ok(!held(detached), "Lock left the Key Manager's wallet referenced by the Key Station");
  assert.ok(allZero(detachedKeys), "Lock left the Key Manager's wallet's row key bytes in memory");
  assert.ok(held(shared), "Lock forgot a wallet a station still shows");
  assert.equal(sharedTab.result, shared);
  assert.deepEqual(sharedKeys, vectorRowKeys, "Lock zeroed a wallet a station still shows");
  // It is still disposed of once the station drops it.
  returnToKeys();
  context.hodlInvalidateLiveKeyResult();
  assert.ok(allZero(sharedKeys) && !held(shared), "the shared wallet escaped disposal after the lock");
});

// #546 B2 step 2b: the extended private keys a wallet result keeps (its root
// and account keys, and the descriptors and SLIP-132 exports built from
// them) go wherever its row keys go. Before this step they were strings for
// the whole session, so no Wipe could reach them.
// Which of the wallet's extended private keys a result still makes usable:
// the root's or the BIP84 account's, found as text anywhere in it (the xprv,
// or the account's SLIP-132 yprv/zprv) or as a key node that still holds that
// private key.
const vectorKeys = (() => {
  const b58check = createBase58check(sha256), withVersion = (text, version) => {
    const raw = Uint8Array.from(b58check.decode(text));
    new DataView(raw.buffer).setUint32(0, version);
    return b58check.encode(raw);
  };
  const root = ScureHDKey.fromMasterSeed(vectorSeed), account = root.derive("m/84'/0'/0'");
  // SLIP-0132 mainnet private versions: xprv, yprv, zprv.
  return [
    { name: "account", privateKey: hex.encode(account.privateKey), texts: [0x0488ade4, 0x049d7878, 0x04b2430c].map((version) => withVersion(account.privateExtendedKey, version)) },
    { name: "root", privateKey: hex.encode(root.privateKey), texts: [root.privateExtendedKey] },
  ];
})();
const usableKeyMaterial = (result) => {
  const found = new Set(), seen = new Set(), walk = (value) => {
    if (typeof value === "string") {
      for (const key of vectorKeys) if (key.texts.some((secret) => value.includes(secret))) found.add(key.name);
    } else if (value && typeof value === "object" && !ArrayBuffer.isView(value) && !seen.has(value)) {
      seen.add(value);
      const privateKey = value instanceof HDKey ? value.privateKey : null;
      if (privateKey) for (const key of vectorKeys) if (key.privateKey === hex.encode(privateKey)) found.add(key.name);
      for (const key of Object.keys(value)) walk(value[key]);
    }
  };
  walk(result);
  return vectorKeys.map((key) => key.name).filter((name) => found.has(name));
};
const bothKeys = ["account", "root"];

test("a wallet's extended private keys stay usable while it is held and are gone once it is dropped or the page goes", async () => {
  for (const drop of ["Wipe", "edit", "re-derive", "delete", "journal lock", "pagehide"]) {
    const { context, events, derive, selectLab, leaveKeys, active } = await stationHarness();
    context.hodlJournalUnlocked = () => drop === "journal lock";
    await derive("dropped");
    const dropped = active().result;
    selectLab();
    await derive("kept");
    const kept = active().result;
    assert.deepEqual(usableKeyMaterial(dropped), bothKeys, `${drop}: a committed wallet lost its keys`);
    assert.deepEqual(usableKeyMaterial(kept), bothKeys, `${drop}: a committed wallet lost its keys`);
    context.hodlActiveKey = context.hodlKeys.findIndex((state) => state.result === dropped);
    context.hodlRestoreKey();
    if (drop === "Wipe") context.hodlWipeActiveKey();
    else if (drop === "edit") context.hodlInvalidateLiveKeyResult();
    else if (drop === "re-derive") await derive("dropped");
    else if (drop === "delete") context.hodlDeleteActiveKey();
    else if (drop === "journal lock") {
      context.hodlDeleteActiveKey();
      leaveKeys("journal");
      context.hodlJournalLock();
    } else events.pagehide({});
    assert.deepEqual(usableKeyMaterial(dropped), [], `${drop}: the dropped wallet's extended private keys are still usable`);
    if (drop === "pagehide") assert.deepEqual(usableKeyMaterial(kept), [], "pagehide left a shown wallet's extended private keys usable");
    else assert.deepEqual(usableKeyMaterial(kept), bothKeys, `${drop}: dropping one wallet took another wallet's keys`);
  }
});

test("a wallet another tab still shows keeps its extended private keys when one tab drops it", async () => {
  const { context, derive, active } = await stationHarness();
  await derive();
  const result = active().result;
  context.hodlKeys.push({ id: 99, number: 99, isLab: false, fields: {}, result });
  context.hodlInvalidateLiveKeyResult();
  assert.deepEqual(usableKeyMaterial(result), bothKeys, "dropping a shared wallet from one tab took the keys the other tab shows");
});

// The Ignored list keeps a JSON copy of the key for its identity. JSON drops
// byte arrays, so with the keys held as nodes the copy keeps none of them;
// text would have been copied whole.
test("an ignored key's saved copy carries none of its wallet's extended private keys", async () => {
  const { context, derive, active } = await stationHarness();
  await derive();
  const state = active(), entry = context.hodlKeyManagerEntry(state);
  assert.deepEqual(usableKeyMaterial(entry), [], "the Ignored copy kept an extended private key");
  assert.equal(keyVaultIdentity(entry), keyVaultIdentity(state), "the copy keeps what identifies the key");
  assert.deepEqual(usableKeyMaterial(state.result), bothKeys, "copying must not touch the live wallet");
});

test("a derivation declined at the fingerprint confirmation, or hidden while it asks, leaves no usable extended private key", async () => {
  for (const ending of ["declined", "pagehide"]) {
    const { context, events, driveUntil, start } = await derivationHarness(), confirm = deferred();
    let pending = null;
    context.hodlConfirmKeyFingerprint = (result) => { pending = result; return confirm.promise; };
    const run = start();
    await driveUntil(() => pending);
    assert.deepEqual(usableKeyMaterial(pending), bothKeys, `${ending}: the finished result carries no keys to wipe`);
    if (ending === "pagehide") events.pagehide({});
    confirm.resolve(ending === "pagehide");
    await driveUntil(() => run.settled);
    await run.promise;
    assert.equal(context.hodlWalletResult, null);
    assert.deepEqual(usableKeyMaterial(pending), [], `${ending}: the uncommitted result's extended private keys are still usable`);
  }
});

// #546 B2 step 2c-1: a single key (WIF, hex, mini key or brain wallet) holds
// its private key as bytes, which go wherever a wallet's keys go. Before this
// step its WIFs and hex were strings for the whole session.
// Bitcoin wiki, "Wallet import format": this key's uncompressed mainnet WIF.
const singleKeyWif = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ";
const singleKeyBytes = hex.decode("0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d");
const singleKeyBuilder = loadAppFunctions(["hodlSingleKeyWallet", "hodlActiveDerivation"], { settable: ["hodlActiveDerivation"] });
// Whether a result still makes the key usable: its WIFs or hex as text
// anywhere in it, or bytes that still hold it.
const usableSingleKey = (result) => {
  const b58check = createBase58check(sha256), texts = [
    b58check.encode(Uint8Array.from([0x80, ...singleKeyBytes])), b58check.encode(Uint8Array.from([0x80, ...singleKeyBytes, 1])), hex.encode(singleKeyBytes),
  ];
  let found = false;
  const seen = new Set(), walk = (value) => {
    if (typeof value === "string") found ||= texts.some((secret) => value.toLowerCase().includes(secret.toLowerCase()));
    else if (value instanceof Uint8Array || (ArrayBuffer.isView(value) && value.BYTES_PER_ELEMENT === 1)) found ||= hex.encode(Uint8Array.from(value)) === hex.encode(singleKeyBytes);
    else if (value && typeof value === "object" && !seen.has(value)) {
      seen.add(value);
      for (const key of Object.keys(value)) walk(value[key]);
    }
  };
  walk(result);
  return found;
};

test("a single key stays usable while it is held and is zeroed once it is dropped or the page goes", async () => {
  for (const drop of ["Wipe", "edit", "re-derive", "delete", "journal lock", "pagehide"]) {
    const { context, events, derive, selectLab, leaveKeys, active } = await stationHarness({ single: true });
    context.hodlJournalUnlocked = () => drop === "journal lock";
    await derive();
    const dropped = active().result;
    selectLab();
    await derive();
    const kept = active().result;
    assert.equal(dropped.kind, "single");
    assert.notEqual(dropped, kept);
    assert.ok(usableSingleKey(dropped) && usableSingleKey(kept), `${drop}: a committed single key lost its key`);
    context.hodlActiveKey = context.hodlKeys.findIndex((state) => state.result === dropped);
    context.hodlRestoreKey();
    if (drop === "Wipe") context.hodlWipeActiveKey();
    else if (drop === "edit") context.hodlInvalidateLiveKeyResult();
    else if (drop === "re-derive") await derive();
    else if (drop === "delete") context.hodlDeleteActiveKey();
    else if (drop === "journal lock") {
      context.hodlDeleteActiveKey();
      leaveKeys("journal");
      context.hodlJournalLock();
    } else events.pagehide({});
    assert.equal(usableSingleKey(dropped), false, `${drop}: the dropped single key is still usable`);
    if (drop === "pagehide") assert.equal(usableSingleKey(kept), false, "pagehide left a shown single key usable");
    else assert.ok(usableSingleKey(kept), `${drop}: dropping one key took another key's bytes`);
  }
});

test("a single key another tab still shows keeps its bytes when one tab drops it", async () => {
  const { context, derive, active } = await stationHarness({ single: true });
  await derive();
  const result = active().result;
  context.hodlKeys.push({ id: 99, number: 99, isLab: false, fields: {}, result });
  context.hodlInvalidateLiveKeyResult();
  assert.ok(usableSingleKey(result), "dropping a shared single key from one tab zeroed the key the other tab shows");
});

test("a single key declined at the fingerprint confirmation, or hidden while it asks, is zeroed", async () => {
  for (const ending of ["declined", "pagehide"]) {
    const { context, events, driveUntil, start } = await derivationHarness({ single: true }), confirm = deferred();
    let pending = null;
    context.hodlConfirmKeyFingerprint = (result) => { pending = result; return confirm.promise; };
    const run = start();
    await driveUntil(() => pending);
    assert.ok(usableSingleKey(pending), `${ending}: the finished result carries no key to zero`);
    if (ending === "pagehide") events.pagehide({});
    confirm.resolve(ending === "pagehide");
    await driveUntil(() => run.settled);
    await run.promise;
    assert.equal(context.hodlWalletResult, null);
    assert.equal(usableSingleKey(pending), false, `${ending}: the uncommitted single key is still usable`);
  }
});

// #546 B2 step 2c-2: a seed wallet holds its BIP39 entropy and seed as bytes,
// which go wherever a wallet's keys go. Before this step its words, entropy
// hex and seed hex were strings for the whole session.
// BIP39 test vector (trezor/python-mnemonic vectors.json), passphrase "TREZOR".
const seedVector = {
  words: "legal winner thank year wave sausage worth useful legal winner thank yellow", pass: "TREZOR", entropy: "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
  seed: "2e8905819b8723fe2c1d161860e5ee1830318dbf49a83bd451cfb8440c28bd6fa457fe1296106559a3c80937a1c1069be3a3a5bd381ee6260e8d9739fce1f607",
};
// Its slice carries page-boot statements that run once at load; they get
// inert stand-ins for the page there.
const seedWalletBuilder = (async () => {
  const inert = new Proxy(function () {}, { get: (target, key) => key === Symbol.toPrimitive ? () => "" : key === "then" ? undefined : inert, apply: () => inert, construct: () => inert });
  Object.assign(globalThis, { __ENTROPYLAB_TEST_HOOKS__: false, document: inert, window: inert });
  try {
    return await loadAppFunctions(["hodlMnemonicWalletWithProgress", "hodlActiveDerivation"], { stubs: { hodlSelectedScriptType: () => "bip84" }, settable: ["hodlActiveDerivation"] });
  } finally {
    delete globalThis.document;
    delete globalThis.window;
  }
})();
// Which seed material a result still makes usable: the words or entropy hex
// as text, or entropy bytes ("entropy"); the seed hex as text, or seed bytes
// ("seed"); the typed passphrase as text or as its UTF-8 bytes ("passphrase",
// #546 B2 step 2c-3).
const usableSeedMaterial = (result) => {
  const found = new Set(), seen = new Set(), passphrase = hex.encode(new TextEncoder().encode(seedVector.pass)), walk = (value) => {
    if (typeof value === "string") {
      const text = value.toLowerCase();
      if (text.includes(seedVector.words) || text.includes(seedVector.entropy)) found.add("entropy");
      if (text.includes(seedVector.seed)) found.add("seed");
      if (value.includes(seedVector.pass)) found.add("passphrase");
    } else if (ArrayBuffer.isView(value) && value.BYTES_PER_ELEMENT === 1) {
      const bytes = hex.encode(Uint8Array.from(value));
      if (bytes === seedVector.entropy) found.add("entropy");
      if (bytes === seedVector.seed) found.add("seed");
      if (bytes === passphrase) found.add("passphrase");
    } else if (value && typeof value === "object" && !seen.has(value)) {
      seen.add(value);
      for (const key of Object.keys(value)) walk(value[key]);
    }
  };
  walk(result);
  return ["entropy", "passphrase", "seed"].filter((name) => found.has(name));
};
const bothSeeds = ["entropy", "passphrase", "seed"];

test("a seed wallet's seed material stays usable while it is held and is zeroed once it is dropped or the page goes", async () => {
  for (const drop of ["Wipe", "edit", "re-derive", "delete", "journal lock", "pagehide"]) {
    const { context, events, derive, selectLab, leaveKeys, active } = await stationHarness({ seedWords: true });
    context.hodlJournalUnlocked = () => drop === "journal lock";
    await derive("dropped");
    const dropped = active().result;
    selectLab();
    await derive("kept");
    const kept = active().result;
    assert.deepEqual(usableSeedMaterial(dropped), bothSeeds, `${drop}: a committed wallet lost its seed material`);
    assert.deepEqual(usableSeedMaterial(kept), bothSeeds, `${drop}: a committed wallet lost its seed material`);
    context.hodlActiveKey = context.hodlKeys.findIndex((state) => state.result === dropped);
    context.hodlRestoreKey();
    if (drop === "Wipe") context.hodlWipeActiveKey();
    else if (drop === "edit") context.hodlInvalidateLiveKeyResult();
    else if (drop === "re-derive") await derive("dropped");
    else if (drop === "delete") context.hodlDeleteActiveKey();
    else if (drop === "journal lock") {
      context.hodlDeleteActiveKey();
      leaveKeys("journal");
      context.hodlJournalLock();
    } else events.pagehide({});
    assert.deepEqual(usableSeedMaterial(dropped), [], `${drop}: the dropped wallet's seed material is still usable`);
    if (drop === "pagehide") assert.deepEqual(usableSeedMaterial(kept), [], "pagehide left a shown wallet's seed material usable");
    else assert.deepEqual(usableSeedMaterial(kept), bothSeeds, `${drop}: dropping one wallet took another wallet's seed material`);
  }
});

test("a seed wallet another tab still shows keeps its seed material when one tab drops it", async () => {
  const { context, derive, active } = await stationHarness({ seedWords: true });
  await derive();
  const result = active().result;
  context.hodlKeys.push({ id: 99, number: 99, isLab: false, fields: {}, result });
  context.hodlInvalidateLiveKeyResult();
  assert.deepEqual(usableSeedMaterial(result), bothSeeds, "dropping a shared wallet from one tab zeroed the seed material the other tab shows");
});

test("an ignored seed wallet's saved copy carries none of its seed material", async () => {
  const { context, derive, active } = await stationHarness({ seedWords: true });
  await derive();
  const state = active(), entry = context.hodlKeyManagerEntry(state);
  assert.deepEqual(usableSeedMaterial(entry), [], "the Ignored copy kept seed material");
  assert.deepEqual(usableSeedMaterial(state.result), bothSeeds, "copying must not touch the live wallet");
});

test("a seed wallet declined at the fingerprint confirmation, or hidden while it asks, leaves no usable seed material", async () => {
  for (const ending of ["declined", "pagehide"]) {
    const { context, events, driveUntil, start } = await derivationHarness({ seedWords: true }), confirm = deferred();
    let pending = null;
    context.hodlConfirmKeyFingerprint = (result) => { pending = result; return confirm.promise; };
    const run = start();
    await driveUntil(() => pending);
    assert.deepEqual(usableSeedMaterial(pending), bothSeeds, `${ending}: the finished result carries no seed material to zero`);
    if (ending === "pagehide") events.pagehide({});
    confirm.resolve(ending === "pagehide");
    await driveUntil(() => run.settled);
    await run.promise;
    assert.equal(context.hodlWalletResult, null);
    assert.deepEqual(usableSeedMaterial(pending), [], `${ending}: the uncommitted wallet's seed material is still usable`);
  }
});
