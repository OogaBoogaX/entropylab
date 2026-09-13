// Lifecycle clearing must discard application state, not only visible fields.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import vm from "node:vm";

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

function raceHarness() {
  const pending = deferred(), decryptStarted = deferred(), events = {}, effects = [];
  const fields = new Map();
  const mirrors = [".dice-input-highlight", ".dice-word-grid", "#last-words", "#brain-lab-hex"]
    .map(selector => ({ selector, textContent: "secret mnemonic" }));
  const context = vm.createContext({
    document: {
      getElementById: id => fields.get(id) ?? null,
      querySelectorAll: selector => mirrors.filter(el => selector.split(", ").includes(el.selector)),
    },
    addEventListener: (type, callback) => { events[type] = callback; },
    hodlActiveDerivation: { kind: "key", cancelled: false }, hodlDerivationGeneration: 0,
    hodlJournalGeneration: 0, hodlJournalKeys: {}, hodlJournal: {},
    hodlKeys: [{ id: 1, number: 1, fields: {}, result: null }], hodlActiveKey: 0,
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
    hodlJournalOpenExport: () => { decryptStarted.resolve(); return pending.promise; },
    hodlJournalWipeMem: () => { context.hodlJournalGeneration++; },
    hodlErrorSpecFrom: error => error.message,
  });
  fields.set("pass", { value: "private passphrase" });
  for (const name of ["hodlThrowIfFailed", "hodlSetSelectedScriptType", "hodlCaptureKey",
    "hodlSnapshotKeySummary", "hodlCommitDerivedKey", "hodlJournalCaptureDerivedKey",
    "hodlFocusWalletResult", "hodlJournalLog", "hodlSetWorkspaceError", "hodlJournalSetStatus",
    "hodlKeyManagerStatus", "hodlPsbtWipeMem", "hodlBip85WipeMem", "hodlSpWipeMem",
    "hodlLnWipeMem", "hodlRenderBip85Tabs", "hodlSyncBip85View", "hodlVanityCancel",
    "hodlVanitySyncSource", "hodlVanitySyncControls", "hodlRefreshStationKeyPickers"])
    context[name] = (...args) => { effects.push([name, ...args]); };
  vm.runInContext('class HodlDerivationCancelledError extends Error {}', context);
  for (const name of ["hodlInvalidateDerivation", "hodlAssertDerivationActive", "hodlCalculateKey",
    "hodlWipeActiveKey", "hodlJournalImportFile", "hodlKeyManagerImportFile", "hodlInitSecretFieldAutoClear"])
    vm.runInContext(functionSource(name), context);
  context.hodlInitSecretFieldAutoClear();
  return { context, pending, decryptStarted, events, effects, mirrors };
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

test("page lifecycle clearing replaces every cached key and clears PSBT private state", () => {
  assert.match(lifecycle, /hodlPsbtWipeMem\(\)/);
  assert.match(lifecycle, /hodlBip85WipeMem\(\)/);
  assert.match(lifecycle, /hodlSpWipeMem\(\)/);
  assert.match(lifecycle, /hodlJournalWipeMem\(\)/);
  assert.match(lifecycle, /hodlKeys\s*=\s*hodlKeys\.map\(\(state\)\s*=>\s*\{/);
  assert.match(lifecycle, /privateKeys\[kind\]\s*=\s*""/);
  assert.match(lifecycle, /if \(id !== "privateKeys"\) fields\[id\] = ""/);
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
  assert.match(lifecycle, /vanityPass\.value\s*=\s*""/);
  assert.match(lifecycle, /getElementById\("vanity-out"\)/);
  assert.match(lifecycle, /vanityOut\.innerHTML\s*=\s*""/);
  assert.match(lifecycle, /getElementById\("vanity-error"\)/);
  assert.match(lifecycle, /vanityError\.textContent\s*=\s*""/);
});
