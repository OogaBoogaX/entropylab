// The multisig descriptor import panel decomposes a full multisig descriptor:
// the wrapper picks the script type, multi/sortedmulti picks the key order,
// and the threshold plus one key expression per co-signer fill the quorum and
// the fields. The #checksum is verified, private keys are refused, and shapes
// the form cannot reproduce (a fixed derivation path, a trailing path deeper
// than the receive/change branch step, a non-NUMS Taproot internal key) fail
// with directions.
// Run with: npm test
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { HDKey } from "@scure/bip32";
import { mnemonicToSeedSync } from "@scure/bip39";
import { createBase58check } from "@scure/base";
import { sha256 } from "@noble/hashes/sha2.js";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const app = readFileSync(join(root, "src/js/app.js"), "utf8");
const page = readFileSync(join(root, "src/index.html"), "utf8");
const shell = readFileSync(join(root, "src/shell.html"), "utf8");

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

const source = [
  loadSlice("hodlDescriptorSymbolValues"),
  loadSlice("hodlDescriptorPolymod"),
  loadSlice("hodlDescriptorChecksum"),
  loadSlice("hodlDescriptorWithChecksum"),
  loadSlice("hodlStripDescriptorChecksum"),
  loadSlice("hodlNormalizeOriginPath"),
  loadSlice("hodlParseKeyOrigin"),
  loadSlice("hodlDescriptorKeyExpressions"),
  loadSlice("hodlParseMultisigCosigner"),
  loadSlice("hodlSplitDescriptorArgs"),
  loadSlice("hodlUnwrapDescriptor"),
  loadSlice("hodlMsigDescriptorKeyText"),
  loadSlice("hodlParseMsigDescriptor"),
].join("\n");
// Stub the extended-key decoder: these tests assert which key text the parser
// hands to it and how keys are counted and refused, not base58check itself.
// The checksum charset constants are pulled from their var declaration in
// app.js so the test tracks the real values.
const hodlParseExtendedKey = (key) => ({ receivedKey: key, isPrivate: key.slice(0, 4).toLowerCase().endsWith("prv") });
const charsets = app.match(/var hodlDescriptorInputCharset = "([^"]+)", hodlBech32Charset = "([^"]+)";/);
assert.ok(charsets, "descriptor checksum charsets");
const load = (name) => new Function("hodlParseExtendedKey", "hodlDescriptorInputCharset", "hodlBech32Charset", "hodlMsigSliderLimit", `${source}; return ${name};`)(hodlParseExtendedKey, charsets[1], charsets[2], 15);
const hodlParseMsigDescriptor = load("hodlParseMsigDescriptor");
const hodlDescriptorWithChecksum = load("hodlDescriptorWithChecksum");

const base58check = createBase58check(sha256);
const seed = mnemonicToSeedSync(
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
);
const master = HDKey.fromMasterSeed(seed);
const fingerprint = master.fingerprint.toString(16).padStart(8, "0");

// Re-encode an extended key with different version bytes (xpub -> Zpub etc.).
const reversion = (xkey, version) => {
  const payload = base58check.decode(xkey);
  payload.set([(version >>> 24) & 0xff, (version >>> 16) & 0xff, (version >>> 8) & 0xff, version & 0xff], 0);
  return base58check.encode(payload);
};
const ZPUB = 0x02aa7ed3;
const ZPRV = 0x02aa7a99;

const nodeA = master.derive("m/48'/0'/0'/2'");
const nodeB = master.derive("m/48'/0'/1'/2'");
const nodeC = master.derive("m/48'/0'/2'/2'");
const zpubA = reversion(nodeA.publicExtendedKey, ZPUB);
const zpubB = reversion(nodeB.publicExtendedKey, ZPUB);
const zpubC = reversion(nodeC.publicExtendedKey, ZPUB);
const zprvA = reversion(nodeA.privateExtendedKey, ZPRV);
const keyA = `[${fingerprint}/48h/0h/0h/2h]${zpubA}`;
const keyB = `[${fingerprint}/48h/0h/1h/2h]${zpubB}`;
const keyC = `[${fingerprint}/48h/0h/2h/2h]${zpubC}`;
const NUMS = "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0";

test("a wsh sortedmulti descriptor decomposes into quorum, kind, order, and keys", () => {
  const descriptor = hodlDescriptorWithChecksum(`wsh(sortedmulti(2,${keyA}/0/*,${keyB}/0/*,${keyC}/0/*))`);
  const parsed = hodlParseMsigDescriptor(descriptor);
  assert.equal(parsed.m, 2);
  assert.equal(parsed.n, 3);
  assert.equal(parsed.sorted, true);
  assert.equal(parsed.kind, "p2wsh");
  assert.deepEqual(parsed.keys, [keyA, keyB, keyC], "the branch wildcard is stripped, origin and key stay intact");
});

test("sh, sh(wsh), and bare multi wrappers map to script kinds", () => {
  const nested = hodlParseMsigDescriptor(hodlDescriptorWithChecksum(`sh(wsh(multi(2,${keyA}/0/*,${keyB}/0/*)))`));
  assert.equal(nested.kind, "p2sh-p2wsh");
  assert.equal(nested.sorted, false);
  const legacy = hodlParseMsigDescriptor(hodlDescriptorWithChecksum(`sh(multi(1,${keyA}/0/*))`));
  assert.equal(legacy.kind, "p2sh");
  assert.equal(legacy.m, 1);
  assert.equal(legacy.n, 1);
  const bare = hodlParseMsigDescriptor(`sortedmulti(2,${keyA}/0/*,${keyB}/0/*)`);
  assert.equal(bare.kind, null, "no wrapper keeps the selected script type");
});

test("a present checksum is verified, not just stripped", () => {
  const descriptor = hodlDescriptorWithChecksum(`wsh(sortedmulti(2,${keyA}/0/*,${keyB}/0/*))`);
  const corrupted = descriptor.slice(0, -1) + (descriptor.endsWith("0") ? "1" : "0");
  assert.throws(() => hodlParseMsigDescriptor(corrupted), /checksum does not match/);
  assert.doesNotThrow(() => hodlParseMsigDescriptor(descriptor));
  assert.doesNotThrow(() => hodlParseMsigDescriptor(descriptor.slice(0, descriptor.lastIndexOf("#"))), "no checksum is accepted too");
});

test("multipath suffixes strip like plain branch wildcards", () => {
  const parsed = hodlParseMsigDescriptor(`wsh(sortedmulti(2,${keyA}/<0;1>/*,${keyB}/<0;1>/*))`);
  assert.deepEqual(parsed.keys, [keyA, keyB]);
});

// Issue #389: the import used to drop every trailing step, so a descriptor
// whose keys ended in /0/20/* imported as …/0/* — the displayed and exported
// wallet silently differed from the imported one. Every shape is now either
// reproduced exactly — public steps before the branch step stay on the key,
// and the branch step sets the form's branch window — or refused.
test("public steps before the branch step stay on the key, and the branch sets the window (issue #389)", () => {
  // /0/20/* is the public step /0 on each key, then branch 20.
  const deeper = hodlParseMsigDescriptor(`wsh(sortedmulti(2,${keyA}/0/20/*,${keyB}/0/20/*))`);
  assert.deepEqual(deeper.keys, [`${keyA}/0`, `${keyB}/0`]);
  assert.deepEqual([deeper.branchStart, deeper.branchRange], [20, 1]);
  // Each key keeps its own public steps; the branch is shared.
  const mixed = hodlParseMsigDescriptor(`wsh(sortedmulti(2,${keyA}/7/<0;1>/*,${keyB}/<0;1>/*))`);
  assert.deepEqual(mixed.keys, [`${keyA}/7`, keyB]);
  assert.deepEqual([mixed.branchStart, mixed.branchRange], [0, 2]);
  // A branch outside receive/change is a one-branch window there.
  const five = hodlParseMsigDescriptor(`wsh(sortedmulti(2,${keyA}/5/*,${keyB}/5/*))`);
  assert.deepEqual(five.keys, [keyA, keyB]);
  assert.deepEqual([five.branchStart, five.branchRange], [5, 1]);
  const pair = hodlParseMsigDescriptor(`wsh(sortedmulti(2,${keyA}/<2;3>/*,${keyB}/<2;3>/*))`);
  assert.deepEqual([pair.branchStart, pair.branchRange], [2, 2]);
});

test("shapes the form still cannot reproduce are refused, not rewritten (issue #389)", () => {
  // A multipath with a gap, or wider than the form's two-branch window.
  assert.throws(
    () => hodlParseMsigDescriptor(`wsh(sortedmulti(2,${keyA}/<0;2>/*,${keyB}/<0;2>/*))`),
    /would change the wallet/,
  );
  assert.throws(
    () => hodlParseMsigDescriptor(`wsh(sortedmulti(2,${keyA}/<0;1;2>/*,${keyB}/<0;1;2>/*))`),
    /would change the wallet/,
  );
  // A hardened step below an extended public key cannot be derived at all.
  assert.throws(() => hodlParseMsigDescriptor(`wsh(sortedmulti(2,${keyA}/1h/0/*,${keyB}/1h/0/*))`));
  assert.throws(() => hodlParseMsigDescriptor(`wsh(sortedmulti(2,${keyA}/5h/*,${keyB}/5h/*))`));
  // A multipath anywhere but the branch step.
  assert.throws(
    () => hodlParseMsigDescriptor(`wsh(sortedmulti(2,${keyA}/<0;1>/0/*,${keyB}/<0;1>/0/*))`),
    /would change the wallet/,
  );
  // No branch step at all: the tool always derives one below the key.
  assert.throws(
    () => hodlParseMsigDescriptor(`wsh(sortedmulti(2,${keyA}/*,${keyB}/*))`),
    /would change the wallet/,
  );
  // A fixed key with no wildcard names one address the form never derives.
  assert.throws(
    () => hodlParseMsigDescriptor(`sh(multi(1,${keyA}))`),
    /no derivation|cannot reproduce/,
  );
});

test("reproducible tails still import: receive, change, and the receive/change multipath", () => {
  for (const [tail, window] of [["/0/*", [0, 1]], ["/1/*", [1, 1]], ["/<0;1>/*", [0, 2]], ["/<1;0>/*", [0, 2]]]) {
    const parsed = hodlParseMsigDescriptor(`wsh(sortedmulti(2,${keyA}${tail},${keyB}${tail}))`);
    assert.deepEqual(parsed.keys, [keyA, keyB], `tail ${tail}`);
    assert.deepEqual([parsed.branchStart, parsed.branchRange], window, `tail ${tail}: branch window`);
  }
});

const bip45A = `[${fingerprint}/45h]${nodeA.publicExtendedKey}`;
const bip45B = `[${fingerprint}/45h]${nodeB.publicExtendedKey}`;
// Plain-xpub twins of keyA/keyB for the rust-miniscript round-trip (the crate
// does not read SLIP-132 versions).
const xkeyA = `[${fingerprint}/48h/0h/0h/2h]${nodeA.publicExtendedKey}`;
const xkeyB = `[${fingerprint}/48h/0h/1h/2h]${nodeB.publicExtendedKey}`;

// Issue #389 follow-up: the per-key tail check alone accepted
// wsh(sortedmulti(2,A/0/*,B/1/*)) — the form derives ONE shared branch window
// below every key, so both reconstructions (all keys on /0/*, or all on /1/*)
// derive different addresses than the imported descriptor.
test("co-signer keys that name different branches are refused (issue #389)", () => {
  assert.throws(
    () => hodlParseMsigDescriptor(`wsh(sortedmulti(2,${keyA}/0/*,${keyB}/1/*))`),
    /different branches.*would change the wallet/,
  );
  // A sole branch step beside a receive/change multipath disagrees the same way.
  assert.throws(
    () => hodlParseMsigDescriptor(`wsh(sortedmulti(2,${keyA}/0/*,${keyB}/<0;1>/*))`),
    /different branches/,
  );
  // The BIP45 cosigner step does not hide a branch disagreement.
  assert.throws(
    () => hodlParseMsigDescriptor(`sh(sortedmulti(1,${bip45A}/0/0/*,${bip45B}/0/1/*))`),
    /different branches/,
  );
});

test("the one-element multipath folds, but multipath element order IS a branch disagreement (issue #389)", () => {
  // <0> and /0 expand identically, so those spellings agree.
  const spelledOut = hodlParseMsigDescriptor(`wsh(sortedmulti(2,${keyA}/<0>/*,${keyB}/0/*))`);
  assert.deepEqual(spelledOut.keys, [keyA, keyB]);
  // BIP-389 expands multipath wildcards positionally: <0;1> beside <1;0>
  // pairs A/0 with B/1 and A/1 with B/0 — no shared branch reproduces it.
  assert.throws(
    () => hodlParseMsigDescriptor(`wsh(sortedmulti(2,${keyA}/<0;1>/*,${keyB}/<1;0>/*))`),
    /different branches/,
  );
});

test("an accepted import reconstructs the descriptor's own addresses (rust-miniscript)", async () => {
  const { descriptorDerive } = await import("../src/js/addresses.js");
  // The tool derives imported keys through its own /branch/* suffix; both
  // branches of a <0;1> import must land on the descriptor's expansions.
  const parsed = hodlParseMsigDescriptor(`wsh(sortedmulti(2,${xkeyA}/<0;1>/*,${xkeyB}/<0;1>/*))`);
  for (const branch of [0, 1]) {
    const reconstructed = `wsh(sortedmulti(2,${parsed.keys.map((key) => `${key}/${branch}/*`).join(",")}))`;
    const expansion = `wsh(sortedmulti(2,${xkeyA}/${branch}/*,${xkeyB}/${branch}/*))`;
    assert.equal(descriptorDerive(reconstructed, 3, "mainnet").address, descriptorDerive(expansion, 3, "mainnet").address, `branch ${branch}`);
  }
  // …and the mixed-branch shape guarded against really was a different
  // wallet under either shared-branch reconstruction.
  const original = descriptorDerive(`wsh(sortedmulti(2,${xkeyA}/0/*,${xkeyB}/1/*))`, 0, "mainnet").address;
  assert.notEqual(descriptorDerive(`wsh(sortedmulti(2,${xkeyA}/0/*,${xkeyB}/0/*))`, 0, "mainnet").address, original, "all-receive reconstruction");
  assert.notEqual(descriptorDerive(`wsh(sortedmulti(2,${xkeyA}/1/*,${xkeyB}/1/*))`, 0, "mainnet").address, original, "all-change reconstruction");
  // The reversed-multipath bypass too: <0;1> beside <1;0> expands in lockstep
  // to (A/0,B/1) and (A/1,B/0) — neither shared-branch reconstruction reaches
  // either original expansion.
  const reversedPairs = [
    descriptorDerive(`wsh(sortedmulti(2,${xkeyA}/0/*,${xkeyB}/1/*))`, 0, "mainnet").address,
    descriptorDerive(`wsh(sortedmulti(2,${xkeyA}/1/*,${xkeyB}/0/*))`, 0, "mainnet").address,
  ];
  const shared = [
    descriptorDerive(`wsh(sortedmulti(2,${xkeyA}/0/*,${xkeyB}/0/*))`, 0, "mainnet").address,
    descriptorDerive(`wsh(sortedmulti(2,${xkeyA}/1/*,${xkeyB}/1/*))`, 0, "mainnet").address,
  ];
  for (const reconstructed of shared) for (const expansion of reversedPairs) assert.notEqual(reconstructed, expansion);
});

test("a BIP45 cosigner step ahead of the branch wildcard still imports", () => {
  // sh(multi) over 45-purpose origins: /0/0/* is cosigner 0, receive branch —
  // exactly what the BIP45 compose re-derives.
  const parsed = hodlParseMsigDescriptor(`sh(sortedmulti(1,${bip45A}/0/0/*,${bip45B}/0/0/*))`);
  assert.deepEqual(parsed.keys, [bip45A, bip45B]);
  const bothBranches = hodlParseMsigDescriptor(`sh(sortedmulti(1,${bip45A}/0/<0;1>/*,${bip45B}/0/<0;1>/*))`);
  assert.deepEqual(bothBranches.keys, [bip45A, bip45B]);
  // A cosigner index other than 0 is not what the tool derives.
  assert.throws(() => hodlParseMsigDescriptor(`sh(sortedmulti(1,${bip45A}/1/0/*,${bip45B}/0/0/*))`), /would change the wallet/);
  // And the cosigner step does not excuse a deeper path.
  assert.throws(() => hodlParseMsigDescriptor(`sh(sortedmulti(1,${bip45A}/0/0/20/*,${bip45B}/0/0/*))`), /would change the wallet/);
});

// Issue #389 follow-up: the cosigner step used to be optional — a bare /0/*
// on a 45-purpose key read as "branch 0", so sh(sortedmulti(2,A/0/*,B/0/0/*))
// passed the per-key and cross-key checks, yet the BIP45 compose rebuilt BOTH
// keys as /0/0/*: A derived a different wallet than the descriptor named.
test("a BIP45 key without its cosigner step is refused, not rewritten (issue #389)", () => {
  assert.throws(
    () => hodlParseMsigDescriptor(`sh(sortedmulti(2,${bip45A}/0/*,${bip45B}/0/0/*))`),
    /Co-signer 1: .*BIP45.*\/0\/\*.*would change the wallet/,
  );
  // Both keys bare is the same rewrite twice over, not an agreement.
  assert.throws(
    () => hodlParseMsigDescriptor(`sh(sortedmulti(2,${bip45A}/0/*,${bip45B}/0/*))`),
    /BIP45.*would change the wallet/,
  );
  assert.throws(
    () => hodlParseMsigDescriptor(`sh(sortedmulti(2,${bip45A}/<0;1>/*,${bip45B}/<0;1>/*))`),
    /BIP45.*would change the wallet/,
  );
});

test("an accepted BIP45 import reconstructs the descriptor's own addresses (rust-miniscript)", async () => {
  const { descriptorDerive } = await import("../src/js/addresses.js");
  // The BIP45 compose derives imported keys through its /0/<branch>/* suffix;
  // both branches of a /0/<0;1>/* import must land on the descriptor's expansions.
  const parsed = hodlParseMsigDescriptor(`sh(sortedmulti(2,${bip45A}/0/<0;1>/*,${bip45B}/0/<0;1>/*))`);
  assert.deepEqual(parsed.keys, [bip45A, bip45B]);
  for (const branch of [0, 1]) {
    const reconstructed = `sh(sortedmulti(2,${parsed.keys.map((key) => `${key}/0/${branch}/*`).join(",")}))`;
    const expansion = `sh(sortedmulti(2,${bip45A}/0/${branch}/*,${bip45B}/0/${branch}/*))`;
    assert.equal(descriptorDerive(reconstructed, 3, "mainnet").address, descriptorDerive(expansion, 3, "mainnet").address, `branch ${branch}`);
  }
  // …and the bare-tail shape guarded against really was a different wallet:
  // the compose would have rebuilt A/0/* as A/0/0/*.
  const original = descriptorDerive(`sh(sortedmulti(2,${bip45A}/0/*,${bip45B}/0/0/*))`, 0, "mainnet").address;
  const rebuilt = descriptorDerive(`sh(sortedmulti(2,${bip45A}/0/0/*,${bip45B}/0/0/*))`, 0, "mainnet").address;
  assert.notEqual(rebuilt, original, "cosigner-step reconstruction");
});

test("an extended private key in the descriptor is refused", () => {
  assert.throws(
    () => hodlParseMsigDescriptor(`wsh(sortedmulti(1,[${fingerprint}/48h/0h/0h/2h]${zprvA}/0/*,${keyB}/0/*))`),
    /extended private key/,
  );
});

test("a fixed derivation path after a key is refused with directions", () => {
  assert.throws(
    () => hodlParseMsigDescriptor(`wsh(sortedmulti(2,${keyA}/1,${keyB}/0/*))`),
    /fixed path/,
  );
});

test("a Taproot descriptor imports only over the NUMS internal key", () => {
  const parsed = hodlParseMsigDescriptor(`tr(${NUMS},multi_a(2,${keyA}/<0;1>/*,${keyB}/<0;1>/*))`);
  assert.equal(parsed.kind, "p2tr");
  assert.equal(parsed.m, 2);
  assert.equal(parsed.sorted, false);
  assert.throws(
    () => hodlParseMsigDescriptor(`tr(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,sortedmulti_a(2,${keyA}/<0;1>/*,${keyB}/<0;1>/*))`),
    /NUMS/,
  );
});

test("single-sig wrappers and broken thresholds are refused", () => {
  assert.throws(() => hodlParseMsigDescriptor(`wpkh(${keyA}/0/*)`), /not a multisig descriptor/);
  assert.throws(() => hodlParseMsigDescriptor(`wsh(sortedmulti(4,${keyA}/0/*,${keyB}/0/*))`), /exceeds/);
  assert.throws(() => hodlParseMsigDescriptor(""), /Paste a multisig output descriptor first/);
});

test("more keys than the quorum supports are refused", () => {
  const many = Array.from({ length: 16 }, () => `${keyA}/0/*`).join(",");
  assert.throws(() => hodlParseMsigDescriptor(`wsh(sortedmulti(2,${many}))`), /at most 15/);
});

test("both markups ship the multisig wallet descriptor import panel and the app wires it", () => {
  for (const markup of [shell]) {
    assert.ok(markup.includes('id="msig-descriptor"'), "descriptor textarea");
    assert.ok(markup.includes('id="msig-descriptor-import"'), "import button");
    assert.ok(markup.includes('id="msig-descriptor-status"'), "status line");
    assert.ok(markup.includes('id="msig-descriptor-import" type="button" disabled'), "the import button ships disabled — the descriptor field starts empty");
    assert.ok(markup.indexOf('id="msig-import"') < markup.indexOf('class="msig-threshold-labels"'), "descriptor import comes before manual quorum selection");
  }
  assert.ok(app.includes('addEventListener("click", hodlImportMsigDescriptor)'), "the import button is wired");
});

test("a successful descriptor import locks its m-of-n policy until the multisig is cleared", () => {
  const importer = loadSlice("hodlImportMsigDescriptor");
  const lock = loadSlice("hodlSetMsigThresholdLock");
  const reset = loadSlice("hodlResetMsigForm");
  const capture = loadSlice("hodlCaptureMsig");
  const restore = loadSlice("hodlRestoreMsig");
  assert.ok(importer.includes("hodlSetMsigThresholdLock(true)"), "import locks the populated quorum");
  assert.ok(lock.includes("fieldset.disabled = locked"), "the range controls are disabled while locked");
  assert.ok(lock.includes("mNumber.disabled = locked") && lock.includes("nNumber.disabled = locked"), "the numeric quorum controls are disabled while locked");
  assert.ok(reset.includes("hodlSetMsigThresholdLock(false)"), "clearing the multisig restores manual quorum selection");
  assert.ok(capture.includes("state.fields.thresholdLocked"), "the imported lock is captured with its multisig tab");
  assert.ok(restore.includes("Boolean(state.fields.thresholdLocked)"), "the imported lock returns when its multisig tab is restored");
  assert.ok(restore.includes("Imported descriptor locks this multisig quorum."), "the restored status describes the quorum lock without implying every policy control is locked");
});

test("the import button disables while any co-signer field holds text", () => {
  const sync = loadSlice("hodlSyncMsigDescriptorImport");
  assert.ok(sync.includes("button.disabled = occupied || empty"), "occupied fields or an empty descriptor disable the button");
  assert.ok(sync.includes('aria-disabled'), "the disabled state is announced");
  assert.ok(sync.includes("Clear the co-signer fields to import a descriptor."), "the hint explains the disabled state");
  // The sync follows every path that changes what the co-signer fields hold:
  // a fill rebuild, typing or a session-key pick (the textarea oninput), and
  // the reset. The import itself still guards against occupied fields.
  const fill = loadSlice("hodlFillKeys");
  assert.ok(fill.includes("hodlSyncMsigDescriptorImport(true)"), "typing in a co-signer field re-syncs and drops any import result");
  assert.ok(fill.includes("hodlSyncMsigDescriptorImport();"), "rebuilding the fields re-syncs");
  const importer = loadSlice("hodlImportMsigDescriptor");
  assert.ok(importer.includes("already hold keys"), "the import refuses occupied fields even if the button state is bypassed");
  const fillAt = importer.indexOf("hodlFillKeys(imported.keys)"), pickersAt = importer.indexOf("hodlRefreshMsigSessionPickers()");
  assert.ok(fillAt >= 0 && pickersAt > fillAt, "after the fields fill, the session pickers refresh so a co-signer that matches a Key Lab key shows its lifehash and pressed chip, as if picked by hand");
});
