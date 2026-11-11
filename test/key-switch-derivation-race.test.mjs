// Key-switch / derivation race: switching the active key or multisig tab
// must cancel an in-flight derivation. Archiving a live station key is
// refused, so that attempt must leave the originating tab and its derivation
// intact.
//
// Security contract: a derivation started from one tab's form must either
// commit to that same tab's state or fail with HodlDerivationCancelledError;
// it must never write its result into a tab that became active mid-flight
// (which would corrupt that key's saved wallet and silently lose the wallet
// the user actually derived). Tab switches cancel; a refused archive and an
// undisturbed derivation still commit to their originating key.
//
// The real app.js functions run under a stub DOM through the shared slice
// harness; only the derivation boundary (the slow wallet build) is stubbed,
// with a gate the test holds open while it switches tabs. The rejection
// condition is the app's own generation-counter machinery
// (hodlDerivationGeneration / hodlAssertDerivationActive), and the state
// invariant is asserted on the real hodlCaptureKey write path.
// Run with: npm test
import { test } from "node:test";
import assert from "node:assert/strict";
import { loadAppFunctions } from "./app-slice-harness.mjs";

// The sliced functions close over `document`; every touch is stubbed neutral.
const inert = new Proxy(function () {}, { get: (target, key) => key === Symbol.toPrimitive ? () => "" : key === "then" ? undefined : inert, apply: () => inert, construct: () => inert });

class HodlDerivationCancelledError extends Error {
  constructor() {
    super("Wallet derivation stopped.");
    this.name = "HodlDerivationCancelledError";
  }
}

// The derivation boundary, replaced per test: the seed wallet build is the
// slow step a user can interrupt by switching tabs.
let deriveImpl = null;
let msigInputsImpl = null;
const journal = [];
const keyCommits = [];
const msigCommits = [];

const unused = (name) => () => { throw new Error(`test stub: ${name} must not be called on this path`); };

const app = await (async () => {
  Object.assign(globalThis, { __ENTROPYLAB_TEST_HOOKS__: false, document: inert });
  try {
    return await loadAppFunctions(
      ["hodlCalculateKey", "hodlSelectKey", "hodlCaptureKey", "hodlInvalidateDerivation", "hodlStopDerivation", "hodlAssertDerivationActive", "hodlBuildMsig", "hodlSelectMsig", "hodlCaptureMsig", "hodlKeyManagerIgnore"],
      {
        stubs: {
          HodlDerivationCancelledError,
          hodlJournalKeyDerivation: null,
          // Load-time DOM touches (the shared var statement builds elements).
          hodlElement: () => inert,
          // Workspace plumbing.
          hodlSetWorkspaceError: () => {},
          hodlJournalLog: (...args) => journal.push(args),
          hodlErrorSpecFrom: (error) => ({ raw: String(error?.message || error) }),
          hodlFormatErrorSpec: () => "",
          hodlError: (message) => new Error(message),
          // Form readers the derive path consults.
          hodlBrainHdActive: () => false,
          hodlReadDerivationPlan: () => undefined,
          hodlReadCoinType: () => 0,
          hodlNetworkFromCoinType: () => "mainnet",
          hodlNetworkFamily: (network) => network,
          hodlReadAddressWindow: () => ({ start: 0, range: 1 }),
          hodlReadBranchWindow: () => ({ start: 0, range: 2 }),
          hodlPassphraseFieldBytes: () => "",
          hodlSelectedScriptType: () => "bip84",
          hodlDefaultHardening: () => ({}),
          hodlPassphraseBip39Enabled: () => false,
          hodlAnalyzeBip39Passphrase: () => ({ invalidRanges: [], incomplete: false, trailingSeparator: false }),
          // The seed path actually taken, gated so the test can switch tabs
          // while the wallet build is in flight.
          hodlSelectedSeedInput: () => ({ value: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", extended: false }),
          hodlValidateTargetMnemonic: (value) => ({ words: value.split(" ") }),
          hodlThrowIfFailed: () => {},
          hodlMnemonicWalletWithProgress: (...args) => deriveImpl(...args),
          // The commit path under test: fingerprint confirm passes, the commit
          // itself is recorded rather than re-run (its own tests cover it).
          hodlConfirmKeyFingerprint: async () => true,
          hodlSetSelectedScriptType: () => {},
          hodlSnapshotKeySummary: () => {},
          hodlCommitDerivedKey: () => keyCommits.push("key"),
          hodlDisposeDroppedWallets: () => {},
          hodlFocusWalletResult: () => {},
          // hodlCaptureKey's remaining helpers.
          hodlStorePassphrase: () => {},
          hodlReadHardening: () => ({}),
          hodlSelectedNetwork: () => "mainnet",
          hodlDiceFieldName: () => "dice",
          hodlPrivateKeyValues: () => ({}),
          hodlNormalizePrivateKeyKind: () => "hex-key",
          hodlBrainWalletOutput: () => "scalar",
          // Tab rendering around the switch.
          hodlRenderKeyTabs: () => {},
          hodlRestoreKey: () => {},
          hodlRenderMsigTabs: () => {},
          hodlRestoreMsig: () => {},
          // Key-manager bookkeeping around the ignore.
          hodlKeyManagerEntry: (state) => ({ name: state.name }),
          hodlKeyManagerRender: () => {},
          hodlKeyManagerStatus: () => {},
          // The cancellation wipe is not exercised here (no active derivation
          // control object in the direct-drive harness): row keys are a
          // hodlDeriveWithProgress concern, covered by the browser suite.
          hodlSettleDerivationKeys: () => {},
          // The multisig twin's inputs and commit.
          hodlValidatedMsigInputs: () => msigInputsImpl(),
          hodlMsigKeysSorted: () => true,
          hodlMsigBranchDescriptor: () => "wsh(sortedmulti(2,...))",
          hodlMsigAddressRow: () => ({ address: "bc1q…", index: 0 }),
          hodlAddressBranchRole: () => "receive",
          hodlAddressBranchLabel: () => "Receive",
          hodlDescriptorWithChecksum: (descriptor) => descriptor,
          hodlMsigPolicyOp: () => "sortedmulti",
          hodlMsigScriptOrder: () => "sorted",
          hodlWatchOnlyMultipathDescriptor: () => "wdesc",
          hodlSnapshotMsigSummary: () => {},
          hodlCommitDerivedMsig: () => msigCommits.push("msig"),
          hodlClearMsigOut: () => {},
          hodlScriptKind: () => "p2wsh",
          hodlSelectedLegacyMultisigStandard: () => "bip87",
          hodlMsigRowSpec: () => ({}),
          hodlMergeMsigXpubs: () => {},
          // Entropy-mode branches the seed path never reaches.
          hodlDPlusRolls: unused("hodlDPlusRolls"),
          hodlDPlusFinalSteps: unused("hodlDPlusFinalSteps"),
          hodlDPlusStepChecksumLabel: unused("hodlDPlusStepChecksumLabel"),
          hodlSeedConfig: unused("hodlSeedConfig"),
          hodlBitBoxRolls: unused("hodlBitBoxRolls"),
          hodlTargetLastWords: unused("hodlTargetLastWords"),
          hodlAnalyzeDiceInput: unused("hodlAnalyzeDiceInput"),
          hodlDiceEntropy: unused("hodlDiceEntropy"),
          hodlEntropyWalletWithProgress: unused("hodlEntropyWalletWithProgress"),
          hodlSelectedCardsEntropy: unused("hodlSelectedCardsEntropy"),
          hodlSelectedEntropy: unused("hodlSelectedEntropy"),
          hodlImportedWalletWithProgress: unused("hodlImportedWalletWithProgress"),
          hodlBrainAcked: unused("hodlBrainAcked"),
          hodlBrainLabEntropy: unused("hodlBrainLabEntropy"),
          hodlBrainWalletPassphrase: unused("hodlBrainWalletPassphrase"),
          hodlBrainWalletTrimEnabled: unused("hodlBrainWalletTrimEnabled"),
          hodlAssertPrivateKeyKind: unused("hodlAssertPrivateKeyKind"),
          hodlSingleKeyWallet: unused("hodlSingleKeyWallet"),
        },
        settable: ["hodlKeys", "hodlActiveKey", "hodlMsigs", "hodlActiveMsig", "hodlKeyMode", "hodlWorkspace", "hodlActiveDerivation"],
      },
    );
  } finally {
    delete globalThis.__ENTROPYLAB_TEST_HOOKS__;
    delete globalThis.document;
  }
})();
globalThis.document = inert;

const keyState = (id, number) => ({ id, number, name: `Key ${number}`, isLab: false, color: "", createdAt: "", fields: { keyKind: "wif", privateKeys: {} }, result: null, reveal: false });
const msigState = (id, number) => ({ id, number, name: `Multisig ${number}`, isLab: false, color: "", createdAt: "", fields: {}, result: null, reveal: false });

// A deferred wallet build: resolves once the test releases the gate.
const gatedDerivation = (wallet) => {
  let entered, release;
  const enteredPromise = new Promise((resolve) => (entered = resolve));
  const gate = new Promise((resolve) => (release = resolve));
  deriveImpl = async () => {
    entered();
    await gate;
    return wallet;
  };
  return { enteredPromise, release };
};

const keyStation = (count) => {
  const keys = Array.from({ length: count }, (_, index) => keyState(index + 1, index + 1));
  app.__set.hodlKeys(keys);
  app.__set.hodlActiveKey(0);
  app.__set.hodlKeyMode("seed");
  return keys;
};

const msigStation = (count) => {
  const msigs = Array.from({ length: count }, (_, index) => msigState(index + 1, index + 1));
  app.__set.hodlMsigs(msigs);
  app.__set.hodlActiveMsig(0);
  return msigs;
};

// The commit must not happen for the interrupted derivation: it either lands
// on the tab that started it or is cancelled. Anything else corrupts the tab
// the user switched to.
const outcome = (pending) => pending.then(() => "committed", (error) => error);

test("switching key tabs mid-derivation cancels the commit instead of corrupting the switched-to key", async () => {
  const keys = keyStation(2);
  keyCommits.length = 0;
  const wallet = { kind: "wallet", network: "mainnet", masterFingerprint: "aaaa0001" };
  const { enteredPromise, release } = gatedDerivation(wallet);
  const pending = app.hodlCalculateKey({ setTotal() {}, step() {} });
  await enteredPromise;
  app.hodlSelectKey(1); // the user clicks key 2's tab while key 1's wallet is deriving
  release();
  const result = await outcome(pending);
  assert.ok(result instanceof HodlDerivationCancelledError, "the in-flight derivation must be cancelled once the active key changes; instead it committed");
  assert.equal(keys[1].result, null, "the switched-to key kept its own state");
  assert.equal(keys[0].result, null, "the interrupted key never received the result either");
  assert.equal(keyCommits.length, 0, "no key commit ran for the cancelled derivation");
});

test("an undisturbed derivation still commits to its own key", async () => {
  const keys = keyStation(2);
  keyCommits.length = 0;
  const wallet = { kind: "wallet", network: "mainnet", masterFingerprint: "aaaa0002" };
  const { enteredPromise, release } = gatedDerivation(wallet);
  const pending = app.hodlCalculateKey({ setTotal() {}, step() {} });
  await enteredPromise;
  release();
  assert.equal(await pending, true, "the uninterrupted derivation completes");
  assert.equal(keys[0].result, wallet, "the result committed to the key it started from");
  assert.equal(keys[1].result, null, "the other key was never touched");
  assert.deepEqual(keyCommits, ["key"], "the commit ran once, on the originating key");
});

test("key completion Debug events keep their owner when another workspace is selected", async () => {
  for (const tool of ["calc", "journal"]) {
    keyStation(1); journal.length = 0;
    app.__set.hodlWorkspace(tool);
    const wallet = { kind: "wallet", network: "mainnet", masterFingerprint: "aaaa0002" };
    const { enteredPromise, release } = gatedDerivation(wallet);
    const pending = app.hodlCalculateKey({ setTotal() {}, step() {} }, "derive", { logTool: tool });
    await enteredPromise;
    app.__set.hodlWorkspace("psbt");
    release(); assert.equal(await pending, true);
    assert.deepEqual(journal.filter(([action]) => action === "derive"), [["derive", "aaaa0002", tool]]);
  }
});

test("switching multisig tabs mid-build cancels the commit instead of corrupting the switched-to wallet", async () => {
  const msigs = msigStation(2);
  msigCommits.length = 0;
  msigInputsImpl = () => ({
    network: "mainnet", coinType: 0, count: 1, addressStart: 0, branchStart: 0, branchRange: 1,
    n: 2, m: 2, kind: "p2wsh", purpose: 48, hardening: {}, legacyStandard: null,
    nodes: [], xpubs: [], keyTokens: [], accountSummary: { account: 0, mixed: false },
    accountWarning: null, customWarning: null, specCustom: false,
  });
  let entered, release;
  const enteredPromise = new Promise((resolve) => (entered = resolve));
  const gate = new Promise((resolve) => (release = resolve));
  const tracker = { setTotal() {}, step() { entered(); return gate; } };
  const pending = app.hodlBuildMsig(tracker);
  await enteredPromise;
  app.hodlSelectMsig(1); // the user clicks the second multisig tab mid-build
  release();
  const result = await outcome(pending);
  assert.ok(result instanceof HodlDerivationCancelledError, "the in-flight multisig build must be cancelled once the active tab changes; instead it committed");
  assert.equal(msigs[1].result, null, "the switched-to multisig kept its own state");
  assert.equal(msigs[0].result, null, "the interrupted multisig never received the result either");
  assert.equal(msigCommits.length, 0, "no multisig commit ran for the cancelled build");
});

test("archiving the active station key mid-derivation is refused and the result commits only to its originating key", async () => {
  const keys = keyStation(2);
  const origin = keys[0], adjacent = keys[1];
  adjacent.result = { kind: "wallet", network: "mainnet", masterFingerprint: "bbbb0004" };
  const adjacentBefore = structuredClone(adjacent);
  keyCommits.length = 0;
  const wallet = { kind: "wallet", network: "mainnet", masterFingerprint: "aaaa0003" };
  const { enteredPromise, release } = gatedDerivation(wallet);
  const pending = app.hodlCalculateKey({ setTotal() {}, step() {} });
  await enteredPromise;
  const eventsBefore = journal.length;
  app.hodlKeyManagerIgnore(origin);
  assert.equal(keys.length, 2, "the refused archive removed a station key");
  assert.equal(keys[0], origin, "the originating key lost its station slot");
  assert.equal(keys[1], adjacent, "the adjacent key moved into the active slot");
  assert.deepEqual(adjacent, adjacentBefore, "the archive attempt changed the adjacent key");
  assert.equal(journal.length, eventsBefore, "the refused archive recorded a mutation");
  release();
  assert.equal(await pending, true, "the refused archive cancelled the active derivation");
  assert.equal(origin.result, wallet, "the result did not commit to its originating key");
  assert.deepEqual(adjacent, adjacentBefore, "the derivation overwrote the adjacent key");
  assert.deepEqual(keyCommits, ["key"], "the derivation must commit exactly once");
});

// --- edits that change the key's inputs while its derivation runs ----------
//
// Red team 2026-11-09. A derivation reads its inputs once, then yields while
// it works; its commit captures the form as it stands. Typing in a field
// already stops it. Four actions changed the inputs without stopping it: the
// Method dropdown and the seed-length dropdown (both stop their own click,
// so the form's click handler never sees them), a word replaced in the
// Secure entry picker, and "Import into Key Station" from the Core Wallet
// tab. Each could leave a key whose stored inputs are not the ones its
// wallet was derived from, so a key file or backup of it restores another
// wallet. They now call hodlStopDerivation("key") first.

const appSource = (await import("node:fs")).readFileSync(new URL("../src/js/app.js", import.meta.url), "utf8");
const sourceOf = (start, end) => {
  const from = appSource.indexOf(start);
  assert.ok(from >= 0, `app.js has ${start}`);
  return appSource.slice(from, appSource.indexOf(end, from + start.length));
};

test("stopping the key derivation mid-flight cancels the commit", async () => {
  const keys = keyStation(1);
  keyCommits.length = 0;
  const control = { kind: "key", buttonId: null, cancelled: false, rowKeys: [], nodes: [] };
  app.__set.hodlActiveDerivation(control);
  try {
    const wallet = { kind: "wallet", network: "mainnet", masterFingerprint: "aaaa0040" };
    const { enteredPromise, release } = gatedDerivation(wallet);
    const pending = app.hodlCalculateKey({ setTotal() {}, step() {} });
    await enteredPromise;
    app.hodlStopDerivation("key"); // what each of the four edits now does first
    assert.equal(control.cancelled, true);
    release();
    const result = await outcome(pending);
    assert.ok(result instanceof HodlDerivationCancelledError, "the derivation must not commit once an edit stopped it; instead it committed");
    assert.equal(keys[0].result, null, "the key keeps no result from the inputs that were replaced");
    assert.equal(keyCommits.length, 0, "no key commit ran for the stopped derivation");
  } finally {
    app.__set.hodlActiveDerivation(null);
  }
});

test("stopping the key derivation leaves a multisig build alone", () => {
  const control = { kind: "msig", buttonId: null, cancelled: false, rowKeys: [], nodes: [] };
  app.__set.hodlActiveDerivation(control);
  try {
    app.hodlStopDerivation("key");
    assert.equal(control.cancelled, false, "a key edit does not cancel the multisig workspace's build");
  } finally {
    app.__set.hodlActiveDerivation(null);
  }
});

test("each edit that replaces the key's inputs stops the running derivation first", () => {
  const stop = 'hodlStopDerivation("key")';
  // The Method dropdown: only on a real change, and before the form is redrawn.
  const method = sourceOf("hodlKeyModeSelectEl.onchange = () => {", "\n};");
  assert.ok(method.indexOf("=== hodlKeyMode) return;") >= 0 && method.indexOf("=== hodlKeyMode) return;") < method.indexOf(stop), "an unchanged Method stops nothing");
  assert.ok(method.indexOf(stop) >= 0 && method.indexOf(stop) < method.indexOf("hodlSetMode("), "the Method dropdown stops the derivation before it switches");
  // The seed length: after the two early returns (locked, unchanged), before the capture.
  const length = sourceOf("function hodlSetSeedLength(words) {", "\n}\n");
  assert.equal(length.split(stop).length, 2, "one stop in hodlSetSeedLength");
  assert.ok(length.lastIndexOf("return;", length.indexOf(stop)) >= 0, "the early returns come first: a refused or unchanged length stops nothing");
  assert.ok(length.indexOf(stop) < length.indexOf("hodlCaptureKey();"), "the seed-length change stops the derivation before it captures the form");
  // A word picked, replaced or removed in the Secure entry picker.
  const picker = sourceOf("function hodlSecureSeedChanged() {", "\n}\n");
  assert.ok(picker.indexOf(stop) >= 0 && picker.indexOf(stop) < picker.indexOf("hodlInvalidateActiveKeyOutput();"), "the seed picker stops the derivation first");
  // The Core Wallet import: after its argument check, before it touches the Key Station.
  const core = sourceOf("function hodlCoreImportIntoStation(item) {", "\n}\n");
  assert.ok(core.indexOf(stop) >= 0 && core.indexOf(stop) < core.indexOf("hodlFillLabFromKey("), "the Core import stops the derivation before it fills the Key Station");
});
