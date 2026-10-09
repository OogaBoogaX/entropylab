// Key-switch / derivation race: selecting, deleting or replacing the active
// key (or multisig) while a derivation is in flight must cancel that
// derivation — never let its commit land on the tab the user switched to.
//
// Security contract: a derivation started from one tab's form must either
// commit to that same tab's state or fail with HodlDerivationCancelledError;
// it must never write its result into a tab that became active mid-flight
// (which would corrupt that key's saved wallet and silently lose the wallet
// the user actually derived).
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
      ["hodlCalculateKey", "hodlSelectKey", "hodlCaptureKey", "hodlInvalidateDerivation", "hodlAssertDerivationActive", "hodlBuildMsig", "hodlSelectMsig", "hodlCaptureMsig"],
      {
        stubs: {
          HodlDerivationCancelledError,
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
          hodlJournalCaptureDerivedKey: () => {},
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
        settable: ["hodlKeys", "hodlActiveKey", "hodlMsigs", "hodlActiveMsig", "hodlKeyMode"],
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
