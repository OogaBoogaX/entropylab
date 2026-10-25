// Tests for src/js/core-importdescriptors.js — watch-only Bitcoin Core
// importdescriptors JSON. Calculator export, not a generator.
// Run with: node --test test/core-importdescriptors.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import vm from "node:vm";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "url";
import { HDKey } from "@scure/bip32";
import { mnemonicToSeedSync } from "@scure/bip39";
import { NETWORK, TEST_NETWORK, p2pkh, p2sh, p2tr, p2wpkh } from "@scure/btc-signer";
import { BITCOIND, CHAIN_FIXTURES, withChainNode } from "./bitcoind-harness.mjs";
import {
  CORE_IMPORT_RANGE_END,
  assertMatchingWatchDescriptors,
  buildDeriveAddressesCommands,
  buildImportDescriptorsJson,
  canonicalizeWatchDescriptor,
  coreDeriveAddressesHelp,
  coreImportDescriptorsFilename,
  descriptorChecksum,
  stripDescriptorChecksum,
} from "../src/js/core-importdescriptors.js";
import { b58checkDecode, b58checkEncode, descriptorChecksum as harnessChecksum, loadModule } from "./wallet-export-harness.mjs";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const read = (path) => readFileSync(join(root, path), "utf8");
const codec = { decode: b58checkDecode, encode: b58checkEncode };

const seed = mnemonicToSeedSync(
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
);
const master = HDKey.fromMasterSeed(seed);
const fingerprint = master.fingerprint.toString(16).padStart(8, "0");
const nodeA = master.derive("m/48'/0'/0'/2'");
const nodeB = master.derive("m/48'/0'/1'/2'");
const nodeC = master.derive("m/48'/0'/2'/2'");
const keyA = `[${fingerprint}/48h/0h/0h/2h]${nodeA.publicExtendedKey}`;
const keyB = `[${fingerprint}/48h/0h/1h/2h]${nodeB.publicExtendedKey}`;
const keyC = `[${fingerprint}/48h/0h/2h/2h]${nodeC.publicExtendedKey}`;
const receiveBody = `wsh(sortedmulti(2,${keyA}/0/*,${keyB}/0/*,${keyC}/0/*))`;
const changeBody = `wsh(sortedmulti(2,${keyA}/1/*,${keyB}/1/*,${keyC}/1/*))`;
const receive = `${receiveBody}#${descriptorChecksum(receiveBody)}`;
const change = `${changeBody}#${descriptorChecksum(changeBody)}`;

const bip84 = master.derive("m/84'/0'/0'");
const bip84ReceiveBody = `wpkh([${fingerprint}/84h/0h/0h]${bip84.publicExtendedKey}/0/*)`;
const bip84ChangeBody = `wpkh([${fingerprint}/84h/0h/0h]${bip84.publicExtendedKey}/1/*)`;
const bip84Receive = `${bip84ReceiveBody}#${harnessChecksum(bip84ReceiveBody)}`;
const bip84Change = `${bip84ChangeBody}#${harnessChecksum(bip84ChangeBody)}`;

const parse = (json) => JSON.parse(json);

// Exercise the application adapter with independently derived public fixtures.
function keyExportHarness() {
  const source = read("src/js/app.js");
  const context = vm.createContext({ buildImportDescriptorsJson, buildDeriveAddressesCommands, hodlBase58Check: codec,
    hodlWalletExport: loadModule(), hodlDescriptorChecksum: descriptorChecksum, hodlT: text => text, hodlTText: text => text,
    hodlWalletDatBirthday: "genesis", hodlAccountId: "bip84", hodlWalletResult: null });
  for (const name of ["hodlError", "hodlFormatErrorSpec", "hodlMsigCoreImportCodec", "hodlCoreImportDescriptorsWallet", "hodlCoreDescriptorUnits", "hodlCoreImportDescriptorsJson", "hodlCoreDeriveAddressesText", "hodlCoreImportDescriptorsPublicWallet", "hodlCoreImportDescriptorsError", "hodlCopyCoreImportDescriptors", "hodlCopyCoreDeriveAddresses", "hodlCopyCoreText", "hodlDownloadCoreImportDescriptors", "hodlKeyCoreImportDescriptorsMarkup", "hodlMsigCoreImportDescriptorsMarkup", "hodlCoreImportDescriptorsNote", "hodlCoreImportDescriptorsButtons", "hodlCoreDeriveAddressesNote"]) {
    const match = source.match(new RegExp(`^function ${name}\\([^]*?^}`, "m"));
    assert.ok(match, `application export adapter ${name} exists`);
    vm.runInContext(match[0], context);
  }
  return context;
}

test("Key Station exports only the selected public account with the existing birthday and range rules", () => {
  const ui = keyExportHarness();
  const accounts = [44, 49, 84, 86].map((purpose) => {
    const node = master.derive(`m/${purpose}'/0'/0'`);
    const wrap = body => purpose === 49 ? `sh(wpkh(${body}))` : `${purpose === 44 ? "pkh" : purpose === 86 ? "tr" : "wpkh"}(${body})`;
    const descriptor = branch => {
      const body = wrap(`[${fingerprint}/${purpose}h/0h/0h]${node.publicExtendedKey}/${branch}/*`);
      return `${body}#${harnessChecksum(body)}`;
    };
    return { def: { id: `bip${purpose}` }, receiveDescriptor: descriptor(0), changeDescriptor: descriptor(1),
      addressBranches: [{ branch: 0, rows: [{ index: 5000 }] }, { branch: 1, rows: [{ index: 5002 }] }],
      get privateNode() { throw new Error("private material read"); },
      get receiveDescriptorPriv() { throw new Error("private descriptor read"); },
      get changeDescriptorPriv() { throw new Error("private descriptor read"); } };
  });
  ui.hodlWalletResult = { kind: "hd", accounts, get seed() { throw new Error("seed read"); } };
  for (const account of accounts) for (const birthday of ["genesis", "now"]) {
    ui.hodlAccountId = account.def.id;
    ui.hodlWalletDatBirthday = birthday;
    ui.hodlRevealPrivate = true;
    assert.deepEqual(parse(ui.hodlCoreImportDescriptorsJson("calc")), [false, true].map(internal => ({
      desc: internal ? account.changeDescriptor : account.receiveDescriptor,
      active: true, internal, timestamp: birthday === "now" ? "now" : 0, range: [0, internal ? 6002 : 6000],
    })));
  }
  ui.hodlAccountId = "stale-account";
  assert.throws(() => ui.hodlCoreImportDescriptorsJson("calc"), /account/i, "a stale selection must not export a fallback account");
  ui.hodlAccountId = "bip84";
  accounts[2].receiveDescriptor = `wpkh(${master.privateExtendedKey}/0/*)`;
  assert.throws(() => ui.hodlCoreImportDescriptorsJson("calc"), /private key/);
  ui.hodlWalletResult = null;
  assert.equal(ui.hodlCoreImportDescriptorsJson("calc"), "");
  ui.hodlWalletResult = { kind: "single" };
  assert.equal(ui.hodlCoreImportDescriptorsJson("calc"), "");
});

test("Key Station refuses missing selected accounts without copying or downloading", () => {
  const ui = keyExportHarness();
  const error = { textContent: "" };
  let copies = 0, downloads = 0;
  ui.document = { getElementById: id => id === "key-core-importdescriptors-error" ? error : null };
  ui.hodlErrorSpecFrom = error => ({ raw: error.message });
  ui.copyText = () => { copies++; return Promise.resolve(false); };
  ui.Blob = class { constructor() { downloads++; } };
  const accounts = [84, 86].map(purpose => customAccount(purpose, "mainnet", 0, 2).account);
  ui.hodlAccountId = "stale-account";
  for (const available of [accounts, [accounts[1]], []]) {
    ui.hodlWalletResult = { kind: "hd", accounts: available };
    assert.throws(() => ui.hodlCoreImportDescriptorsJson("calc"), /account/i);
    for (const handler of [ui.hodlCopyCoreImportDescriptors, ui.hodlDownloadCoreImportDescriptors]) {
      error.textContent = "";
      handler("calc");
      assert.ok(error.textContent, "missing account must produce a visible refusal");
      assert.equal(copies, 0);
      assert.equal(downloads, 0);
    }
  }
});

// The expected branch mapping is stated independently of the adapter: only
// branch 1 in a window starting at 0 is internal; the first external branch
// is active, and additional external branches stay watched but inactive.
const CUSTOM_WINDOWS = [[0, 1], [1, 1], [2, 1], [0, 4], [1, 3], [3, 2]];
function customAccount(purpose, network, start, count, hardened = false) {
  const mainnet = network === "mainnet";
  const node = HDKey.fromMasterSeed(seed, mainnet ? undefined : { public: 0x043587cf, private: 0x04358394 })
    .derive(`m/${purpose}'/${mainnet ? 0 : 1}'/0'`);
  const wrap = key => purpose === 49 ? `sh(wpkh(${key}))` : `${purpose === 44 ? "pkh" : purpose === 86 ? "tr" : "wpkh"}(${key})`;
  const addressBranches = Array.from({ length: count }, (_, offset) => {
    const branch = start + offset;
    const key = hardened ? `${node.deriveChild(branch + 0x80000000).publicExtendedKey}/*` : `${node.publicExtendedKey}/${branch}/*`;
    const body = wrap(key);
    return { branch, publicDescriptor: `${body}#${harnessChecksum(body)}`, rows: [{ index: branch + 2,
      get privateKey() { throw new Error("row private key read"); } }],
      get privateDescriptor() { throw new Error("branch private descriptor read"); } };
  });
  const account = { def: { id: `bip${purpose}` }, branchStart: start, branchHardened: hardened, addressBranches,
    receiveDescriptor: addressBranches.find(entry => entry.branch === 0)?.publicDescriptor ?? null,
    changeDescriptor: addressBranches.find(entry => entry.branch === 1)?.publicDescriptor ?? null,
    get privateNode() { throw new Error("private node read"); },
    get receiveDescriptorPriv() { throw new Error("private descriptor read"); },
    get changeDescriptorPriv() { throw new Error("private descriptor read"); } };
  const net = mainnet ? NETWORK : { ...TEST_NETWORK, bech32: network === "regtest" ? "bcrt" : "tb" };
  const expectedAddress = (branch, index) => {
    const key = node.deriveChild(branch + (hardened ? 0x80000000 : 0)).deriveChild(index).publicKey;
    return (purpose === 44 ? p2pkh(key, net) : purpose === 49 ? p2sh(p2wpkh(key, net), net) : purpose === 86 ? p2tr(key.slice(1), undefined, net) : p2wpkh(key, net)).address;
  };
  return { account, expectedAddress };
}
for (const [start, count] of CUSTOM_WINDOWS) {
  test(`Key Station preserves branch window ${start}+${count} without reading private getters`, () => {
    const ui = keyExportHarness();
    const { account } = customAccount(84, "mainnet", start, count);
    ui.hodlWalletResult = { kind: "hd", accounts: [account] };
    const entries = parse(ui.hodlCoreImportDescriptorsJson("calc"));
    assert.deepEqual(entries, account.addressBranches.map((entry, offset) => ({
      desc: entry.publicDescriptor, internal: start === 0 && entry.branch === 1,
      active: offset === 0 || (start === 0 && entry.branch === 1), timestamp: 0, range: [0, 1002 + entry.branch],
    })));
    assert.ok(ui.hodlKeyCoreImportDescriptorsMarkup(account), "custom-only windows must offer an export control");
  });
}
test("branch-aware exports retain the refusal of unrelated unhardened branch keys", () => {
  const ui = keyExportHarness();
  const { account } = customAccount(84, "mainnet", 0, 2);
  const body = `wpkh(${master.derive("m/84'/0'/1'").publicExtendedKey}/1/*)`;
  account.addressBranches[1].publicDescriptor = `${body}#${harnessChecksum(body)}`;
  account.changeDescriptor = account.addressBranches[1].publicDescriptor;
  ui.hodlWalletResult = { kind: "hd", accounts: [account] };
  assert.throws(() => ui.hodlCoreImportDescriptorsJson("calc"), /different keys/);
});

test("export refuses an unrepresentable custom branch instead of silently omitting it", () => {
  const ui = keyExportHarness();
  const { account } = customAccount(84, "mainnet", 0, 3);
  account.addressBranches[2].publicDescriptor = null;
  ui.hodlWalletResult = { kind: "hd", accounts: [account] };
  assert.throws(() => ui.hodlCoreImportDescriptorsJson("calc"), /public descriptor/);
});
test("Key Station export failures reach the result's error slot without copying or downloading", () => {
  const ui = keyExportHarness();
  const elements = { error: { textContent: "", hidden: true }, "key-core-importdescriptors-error": { textContent: "" } };
  ui.document = { getElementById: id => elements[id] };
  ui.hodlErrorSpecFrom = error => ({ raw: error.message });
  ui.hodlSetWorkspaceError = (_, spec) => { elements.error.textContent = spec?.raw ?? ""; };
  let copies = 0, downloads = 0;
  ui.copyText = () => { copies++; return Promise.resolve(false); };
  ui.Blob = class { constructor() { downloads++; } };
  const { account } = customAccount(84, "mainnet", 0, 2);
  account.receiveDescriptor = "invalid";
  account.addressBranches[0].publicDescriptor = "invalid";
  ui.hodlWalletResult = { kind: "hd", accounts: [account] };
  for (const handler of [ui.hodlCopyCoreImportDescriptors, ui.hodlDownloadCoreImportDescriptors]) {
    elements["key-core-importdescriptors-error"].textContent = "";
    handler("calc");
    assert.ok(elements["key-core-importdescriptors-error"].textContent, "failure was sent to a hidden input panel");
    assert.equal(copies, 0);
    assert.equal(downloads, 0);
  }
  ui.hodlCoreImportDescriptorsError("calc", null);
  assert.equal(elements["key-core-importdescriptors-error"].textContent, "", "the real formatter must clear a prior error");
  assert.equal(ui.hodlFormatErrorSpec(null), "");
});

// BIP32 CKDpub cannot derive a hardened child. Hardened key origins are
// metadata; a branch xpub derived privately before export can still use /*.
test("watch-only JSON refuses hardened steps after every public key", () => {
  for (const version of [0x0488b21e, 0x043587cf, 0x04b24746, 0x02aa7ed3]) {
    const raw = b58checkDecode(nodeB.publicExtendedKey);
    new DataView(raw.buffer, raw.byteOffset, raw.byteLength).setUint32(0, version);
    const key = b58checkEncode(raw);
    for (const tail of ["0h/*", "0H/*", "0'/*", "0/1h/*", "*h", "*H", "*'"]) {
      for (const body of [`wpkh(${key}/${tail})`, `wsh(sortedmulti(2,${keyA}/0/*,${key}/${tail}))`]) {
        const descriptor = `${body}#${harnessChecksum(body)}`;
        const unit = { descriptor, internal: false, active: true, rangeEnd: 1000 };
        const reason = /hardened.*public key/i;
        assert.throws(() => canonicalizeWatchDescriptor(descriptor, codec), reason);
        assert.throws(() => buildImportDescriptorsJson({ receiveDescriptor: descriptor, ...codec }), reason);
        assert.throws(() => buildImportDescriptorsJson({ descriptorUnits: [unit], branchHardened: true, ...codec }), reason);
      }
    }
  }
});

test("Key Station refuses hardened public paths but keeps prederived hardened branches", () => {
  const ui = keyExportHarness();
  const { account } = customAccount(84, "mainnet", 2, 2, true);
  ui.hodlWalletResult = { kind: "hd", accounts: [account] };
  assert.deepEqual(parse(ui.hodlCoreImportDescriptorsJson("calc")).map(entry => entry.desc), account.addressBranches.map(entry => entry.publicDescriptor));
  const body = `wpkh([${fingerprint}/84h/0h/0h]${nodeA.publicExtendedKey}/0h/*)`;
  account.addressBranches[1].publicDescriptor = `${body}#${harnessChecksum(body)}`;
  assert.throws(() => ui.hodlCoreImportDescriptorsJson("calc"), /hardened.*public key/i);
});

test("watch-only JSON preserves hardened origins and unhardened multi-step public paths", () => {
  const branch = master.derive("m/84'/0'/0'/2'");
  for (const body of [
    `wpkh([${fingerprint}/84h/0h/0h/2h]${branch.publicExtendedKey}/*)`,
    `sh(sortedmulti(1,${keyA}/0/0/*))`,
  ]) {
    const descriptor = `${body}#${harnessChecksum(body)}`;
    assert.equal(parse(buildImportDescriptorsJson({ receiveDescriptor: descriptor }))[0].desc, descriptor);
  }
});

// Contract: export public descriptors for the selected script and wallet kind;
// refuse malformed keys, unsupported shapes, and a different spending policy.
// Rejection conditions follow the wallet.dat guard added in #1039.
test("Key Station refuses descriptors that disagree with its account or Core's supported shapes", () => {
  const ui = keyExportHarness();
  const xpub = master.derive("m/84'/0'/0'").publicExtendedKey;
  const withChecksum = body => `${body}#${harnessChecksum(body)}`;
  for (const [body, reason] of [
    [`pkh(${xpub}/0/*)`, /script type/],
    [`wsh(sortedmulti(1,${xpub}/0/*))`, /wallet kind|descriptor family/],
    [`wpkh(tr(${xpub}/0/*))`, /descriptor shape/],
    [`${xpub}/0/*`, /descriptor shape/],
    [`wpkh(${xpub}/2147483648/*)`, /2\^31/],
    [`wpkh([00000000/084h]${xpub}/0/*)`, /leading zeros/],
    [`wpkh(${xpub.slice(0, -1)}${xpub.endsWith("1") ? "2" : "1"}/0/*)`, /valid extended key/],
  ]) {
    ui.hodlWalletResult = { kind: "hd", accounts: [{ def: { id: "bip84" }, receiveDescriptor: withChecksum(body) }] };
    assert.throws(() => ui.hodlCoreImportDescriptorsJson("calc"), error => {
      assert.match(error.message, reason);
      assert.ok(!error.message.includes(xpub), "refusal must not disclose key material");
      return true;
    }, body.split("(")[0]);
  }
  ui.hodlWalletResult = { kind: "msig", script: "p2wsh", receiveDescriptor: withChecksum(`wpkh(${xpub}/0/*)`) };
  assert.throws(() => ui.hodlCoreImportDescriptorsJson("msig"), /wallet kind|descriptor family/);
});

test("checksum matches the independent Core reference", () => {
  assert.equal(descriptorChecksum(receiveBody), harnessChecksum(receiveBody));
});

test("Key Station handles imported watch-only keys and never reuses a previous wallet's export", () => {
  const ui = keyExportHarness();
  const makeAccount = (node) => {
    const descriptor = branch => {
      const body = `wpkh(${node.publicExtendedKey}/${branch}/*)`;
      return `${body}#${harnessChecksum(body)}`;
    };
    return { def: { id: "bip84" }, receiveDescriptor: descriptor(0), changeDescriptor: descriptor(1), receive: [{ index: 0 }] };
  };
  const first = makeAccount(master.derive("m/84'/0'/0'"));
  const second = makeAccount(master.derive("m/84'/0'/1'"));
  // An imported zpub carries the same public payload as its Core xpub.
  const xpub = master.derive("m/84'/0'/0'").publicExtendedKey;
  const raw = b58checkDecode(xpub);
  raw.set([0x04, 0xb2, 0x47, 0x46]);
  const zpub = b58checkEncode(raw);
  const imported = { ...first };
  for (const name of ["receiveDescriptor", "changeDescriptor"]) {
    const body = stripDescriptorChecksum(first[name]).replace(xpub, zpub);
    imported[name] = `${body}#${harnessChecksum(body)}`;
  }
  ui.hodlWalletResult = { kind: "hd", accounts: [imported] };
  const beforeSwitch = parse(ui.hodlCoreImportDescriptorsJson("calc"));
  assert.deepEqual(beforeSwitch.map(entry => entry.desc), [first.receiveDescriptor, first.changeDescriptor]);
  ui.hodlWalletResult = { kind: "hd", accounts: [second] };
  assert.equal(parse(ui.hodlCoreImportDescriptorsJson("calc"))[0].desc, second.receiveDescriptor);
  assert.equal(ui.hodlCoreImportDescriptorsJson("msig"), "", "a stale multisig control cannot export the active key");
  second.receive[0].index = 998999;
  assert.deepEqual(parse(ui.hodlCoreImportDescriptorsJson("calc"))[0].range, [0, 999999]);
  second.receive[0].index = 999000;
  assert.throws(() => ui.hodlCoreImportDescriptorsJson("calc"), /importdescriptors refuses a range span/);
  ui.hodlWalletResult = { kind: "msig", script: "p2wsh", receiveDescriptor: receive, changeDescriptor: change };
  assert.equal(ui.hodlCoreImportDescriptorsJson("calc"), "", "a stale key control cannot export the active multisig");
  assert.equal(parse(ui.hodlCoreImportDescriptorsJson("msig"))[0].desc, receive);
});

test("JSON.parse of the export is an array of length 2", () => {
  const entries = parse(buildImportDescriptorsJson({ receiveDescriptor: receive, changeDescriptor: change }));
  assert.equal(entries.length, 2);
});

test("receive is external, change is internal, both active, default range matches wallet.dat", () => {
  const walletSrc = read("src/js/wallet-export.js");
  const range = walletSrc.match(/const RANGE_END = (\d+)/);
  assert.equal(CORE_IMPORT_RANGE_END, Number(range[1]));
  const [external, internal] = parse(buildImportDescriptorsJson({ receiveDescriptor: receive, changeDescriptor: change }));
  assert.equal(external.internal, false);
  assert.equal(internal.internal, true);
  assert.equal(external.active, true);
  assert.equal(internal.active, true);
  // No displayed-window number handed over: the range keeps Core's default
  // lookahead, ending at 0 + RANGE_END, exactly as wallet-export.js's
  // branchRangeFromRows reports a wallet it was given no rows for.
  assert.deepEqual(external.range, [0, CORE_IMPORT_RANGE_END]);
  assert.deepEqual(internal.range, [0, CORE_IMPORT_RANGE_END]);
});

test("the import range runs past the displayed address window like the wallet.dat export (audit B7b)", () => {
  // The wallet.dat side pins this arithmetic outright (wallet-export.test.mjs
  // "descriptor ranges cover displayed addresses plus a recovery gap"): rows
  // indexed 5000..5002 are watched through 5002 + 1000 = 6002, start pinned
  // to 0 so a fresh Core wallet's first getnewaddress is receive index 0.
  // The msig screen can display address windows up to 2^31-1; an export that
  // still said [0, 1000] would leave every shown address above 1000 unwatched.
  const [external, internal] = parse(buildImportDescriptorsJson({ receiveDescriptor: receive, changeDescriptor: change, rangeEnd: 5002 }));
  assert.deepEqual(external.range, [0, 6002]);
  assert.deepEqual(internal.range, [0, 6002]);
  // A window ending at 0 is exactly Core's default range.
  const [zero] = parse(buildImportDescriptorsJson({ receiveDescriptor: receive, rangeEnd: 0 }));
  assert.deepEqual(zero.range, [0, CORE_IMPORT_RANGE_END]);
  // The deepest windows (up to the last unhardened BIP32 child index) are
  // refused outright: Core's own import bound — a range span under
  // 1,000,000 — is tighter than the index bound, so [0, 2^31-1] would be
  // JSON the online node rejects. The Core-bound test below pins the exact
  // refusal boundary (999,000) against a port of ParseDescriptorRange.
});

test("a displayed window the export cannot cover is refused (audit B7b)", () => {
  // Core can watch at most 0..2^31-1; deeper or malformed window ends must
  // fail loudly instead of shipping an import that misses displayed rows.
  for (const rangeEnd of [-1, 0.5, Number.NaN, "5002", 2147483648, Number.POSITIVE_INFINITY, Number.MAX_SAFE_INTEGER]) {
    assert.throws(
      () => buildImportDescriptorsJson({ receiveDescriptor: receive, changeDescriptor: change, rangeEnd }),
      /a whole number from 0 to 2,147,483,647/,
    );
  }
});

// Bitcoin Core's own import bound (ParseDescriptorRange, src/rpc/util.cpp,
// applied by importdescriptors): a range whose span reaches 1,000,000 is
// refused at import with "Range is too large". The range start is pinned at
// 0, so a displayed end of 999,000 would export [0, 1000000] — JSON Core
// rejects on the online node. Refuse those ends at build time (#861 review).
// coreRangeError is a port of Core's check, the independent oracle.
const coreRangeError = ([low, high]) =>
  low < 0 ? "Range should be greater or equal than 0"
  : Math.floor(high / 2 ** 31) !== 0 ? "End of range is too high"
  : low > high ? "Range specified as [begin,end] must not have begin after end"
  : high - low >= 1000000 ? "Range is too large"
  : null;
test("a window Core's importdescriptors would refuse at import is refused at export (audit B7b)", () => {
  for (const rangeEnd of [5002, 998998, 998999]) {
    const [entry] = parse(buildImportDescriptorsJson({ receiveDescriptor: receive, rangeEnd }));
    assert.equal(coreRangeError(entry.range), null, `shown end ${rangeEnd} produces a range Core accepts`);
  }
  for (const rangeEnd of [999000, 5000000, 2147482647, 2147483647]) {
    assert.throws(
      () => buildImportDescriptorsJson({ receiveDescriptor: receive, changeDescriptor: change, rangeEnd }),
      /importdescriptors refuses a range span/,
      `shown end ${rangeEnd} must be refused, not exported as JSON Core rejects`,
    );
  }
});

test("default timestamp is number 0; now mode is the string now", () => {
  const genesis = parse(buildImportDescriptorsJson({ receiveDescriptor: receive, changeDescriptor: change }));
  assert.equal(genesis[0].timestamp, 0);
  assert.equal(typeof genesis[0].timestamp, "number");
  const created = parse(buildImportDescriptorsJson({ receiveDescriptor: receive, changeDescriptor: change, timestamp: "now" }));
  assert.equal(created[0].timestamp, "now");
  assert.equal(created[1].timestamp, "now");
  assert.throws(
    () => buildImportDescriptorsJson({ receiveDescriptor: receive, changeDescriptor: change, timestamp: 1710000000 }),
    /timestamp must be 0 or "now"/,
  );
});

test("desc strings include a matching BIP-380 checksum", () => {
  const [external, internal] = parse(buildImportDescriptorsJson({ receiveDescriptor: receive, changeDescriptor: change }));
  for (const entry of [external, internal]) {
    const hash = entry.desc.lastIndexOf("#");
    assert.ok(hash > 0);
    assert.equal(entry.desc.slice(hash + 1), descriptorChecksum(entry.desc.slice(0, hash)));
  }
});

test("bodies are the msig receive and change descriptors with origins kept", () => {
  const [external, internal] = parse(buildImportDescriptorsJson({ receiveDescriptor: receive, changeDescriptor: change }));
  assert.equal(stripDescriptorChecksum(external.desc), receiveBody);
  assert.equal(stripDescriptorChecksum(internal.desc), changeBody);
  assert.match(external.desc, new RegExp(`\\[${fingerprint}/48h/0h/0h/2h\\]`));
  assert.match(external.desc, /sortedmulti\(2,/);
});

test("the JSON never contains xprv-family keys, a mnemonic, or a seed", () => {
  const json = buildImportDescriptorsJson({ receiveDescriptor: receive, changeDescriptor: change });
  assert.doesNotMatch(json, /[xyztuvYZUV]prv/);
  assert.doesNotMatch(json, /abandon/);
  assert.doesNotMatch(json, /mnemonic|passphrase|seed phrase/i);
});

test("receive and change only differ by /0/* vs /1/*", () => {
  const [external, internal] = parse(buildImportDescriptorsJson({ receiveDescriptor: receive, changeDescriptor: change }));
  assert.equal(
    stripDescriptorChecksum(external.desc).replaceAll("/0/*", "/1/*"),
    stripDescriptorChecksum(internal.desc),
  );
  assertMatchingWatchDescriptors(external.desc, internal.desc);
});

test("a receive-only wallet still exports one external descriptor", () => {
  const entries = parse(buildImportDescriptorsJson({ receiveDescriptor: receive }));
  assert.equal(entries.length, 1);
  assert.equal(entries[0].internal, false);
  assert.equal(entries[0].desc, receive);
});

test("deriveaddresses commands cover receive and change with the displayed window", () => {
  const commands = buildDeriveAddressesCommands({ receiveDescriptor: bip84Receive, changeDescriptor: bip84Change, displayedEnd: 19 });
  assert.equal(commands, `deriveaddresses "${bip84Receive}" "[0,19]"\nderiveaddresses "${bip84Change}" "[0,19]"\n`);
  const [jsonReceive, jsonChange] = parse(buildImportDescriptorsJson({ receiveDescriptor: bip84Receive, changeDescriptor: bip84Change }));
  assert.equal(commands.split("\n")[0], `deriveaddresses "${jsonReceive.desc}" "[0,19]"`);
  assert.equal(commands.split("\n")[1], `deriveaddresses "${jsonChange.desc}" "[0,19]"`);
});

test("deriveaddresses commands keep descriptor-unit order and per-unit windows", () => {
  const units = [
    { descriptor: bip84Receive, internal: false, active: true, displayedEnd: 5 },
    { descriptor: bip84Change, internal: true, active: true, displayedEnd: 7 },
  ];
  const commands = buildDeriveAddressesCommands({ descriptorUnits: units });
  assert.equal(commands, `deriveaddresses "${bip84Receive}" "[0,5]"\nderiveaddresses "${bip84Change}" "[0,7]"\n`);
  const [jsonReceive, jsonChange] = parse(buildImportDescriptorsJson({ descriptorUnits: units }));
  assert.equal(commands.split("\n")[0], `deriveaddresses "${jsonReceive.desc}" "[0,5]"`);
  assert.equal(commands.split("\n")[1], `deriveaddresses "${jsonChange.desc}" "[0,7]"`);
});

test("branch-aware deriveaddresses needs an explicit displayed window and ignores the lookahead rangeEnd", () => {
  // The projection's units carry rangeEnd (displayed end plus Core's
  // importdescriptors lookahead); deriveaddresses must check the displayed
  // window only, and never fall back to [0,19] for a unit without one.
  const units = [
    { descriptor: bip84Receive, internal: false, active: true, rangeEnd: 5002 },
    { descriptor: bip84Change, internal: true, active: true, rangeEnd: 5003 },
  ];
  assert.throws(() => buildDeriveAddressesCommands({ descriptorUnits: units }), /displayedEnd/);
  // A top-level displayedEnd does not stand in for a branch's own window.
  assert.throws(() => buildDeriveAddressesCommands({ descriptorUnits: units, displayedEnd: 5000 }), /displayedEnd/);
  const withOne = [{ ...units[0], displayedEnd: 5000 }, units[1]];
  assert.throws(() => buildDeriveAddressesCommands({ descriptorUnits: withOne, displayedEnd: 5000 }), /displayedEnd/);
  assert.equal(
    buildDeriveAddressesCommands({ descriptorUnits: [{ ...units[0], displayedEnd: 5000 }, { ...units[1], displayedEnd: 5002 }] }),
    `deriveaddresses "${bip84Receive}" "[0,5000]"\nderiveaddresses "${bip84Change}" "[0,5002]"\n`,
  );
});

test("deriveaddresses rewrites SLIP-132 zpub to xpub", () => {
  const raw = b58checkDecode(bip84.publicExtendedKey);
  raw.set([0x04, 0xb2, 0x47, 0x46]);
  const zpub = b58checkEncode(raw);
  const body = `wpkh([${fingerprint}/84h/0h/0h]${zpub}/0/*)`;
  const descriptor = `${body}#${harnessChecksum(body)}`;
  const commands = buildDeriveAddressesCommands({ receiveDescriptor: descriptor, displayedEnd: 19, decode: codec.decode, encode: codec.encode });
  assert.equal(commands, `deriveaddresses "${bip84Receive}" "[0,19]"\n`);
  assert.doesNotMatch(commands, /zpub/);
});

test("deriveaddresses refuses an extended private key without echoing it", () => {
  const xprv = bip84.privateExtendedKey;
  const body = `wpkh(${xprv}/0/*)`;
  const descriptor = `${body}#${harnessChecksum(body)}`;
  assert.throws(() => buildDeriveAddressesCommands({ receiveDescriptor: descriptor }), error => {
    assert.match(error.message, /extended private key/);
    assert.ok(!error.message.includes(xprv));
    return true;
  });
});

test("deriveaddresses refuses mismatched receive/change keys unless branchHardened", () => {
  const other = master.derive("m/84'/0'/1'");
  const otherBody = `wpkh([${fingerprint}/84h/0h/1h]${other.publicExtendedKey}/1/*)`;
  const otherChange = `${otherBody}#${harnessChecksum(otherBody)}`;
  assert.throws(() => buildDeriveAddressesCommands({ receiveDescriptor: bip84Receive, changeDescriptor: otherChange }), /different keys/);
  const commands = buildDeriveAddressesCommands({ receiveDescriptor: bip84Receive, changeDescriptor: otherChange, branchHardened: true, displayedEnd: 19 });
  assert.equal(commands, `deriveaddresses "${bip84Receive}" "[0,19]"\nderiveaddresses "${otherChange}" "[0,19]"\n`);
});

test("deriveaddresses range defaults, overrides and refuses unsafe windows", () => {
  // No implied window: the check must cover exactly what the page shows.
  assert.throws(() => buildDeriveAddressesCommands({ receiveDescriptor: bip84Receive }), /displayedEnd/);
  assert.throws(() => buildDeriveAddressesCommands({ receiveDescriptor: bip84Receive, rangeEnd: 1019 }), /displayedEnd/);
  assert.match(buildDeriveAddressesCommands({ receiveDescriptor: bip84Receive, displayedEnd: 42 }), /"\[0,42\]"/);
  const units = [
    { descriptor: bip84Receive, internal: false, active: true, displayedEnd: 3 },
    { descriptor: bip84Change, internal: true, active: true, displayedEnd: 8 },
  ];
  const lines = buildDeriveAddressesCommands({ descriptorUnits: units }).trimEnd().split("\n");
  assert.match(lines[0], /"\[0,3\]"/);
  assert.match(lines[1], /"\[0,8\]"/);
  assert.throws(() => buildDeriveAddressesCommands({ receiveDescriptor: bip84Receive, displayedEnd: 999999 }), /deriveaddresses refuses a range span/);
  for (const displayedEnd of [-1, 1.5, "19", Number.NaN, Number.POSITIVE_INFINITY, null, 2147483648]) {
    assert.throws(() => buildDeriveAddressesCommands({ receiveDescriptor: bip84Receive, displayedEnd }), /a whole number from 0 to 2,147,483,647/);
  }
});

test("deriveaddresses output is one paste-safe line per descriptor with a trailing newline", () => {
  const commands = buildDeriveAddressesCommands({ receiveDescriptor: bip84Receive, changeDescriptor: bip84Change, displayedEnd: 4 });
  assert.ok(commands.endsWith("\n"));
  assert.ok(!commands.endsWith("\n\n"));
  const lines = commands.trimEnd().split("\n");
  assert.equal(lines.length, 2);
  for (const line of lines) assert.match(line, /^deriveaddresses "[^"\n]+" "\[0,\d+\]"$/);
});

test("deriveaddresses refuses descriptors that would break the command line", () => {
  for (const bad of [
    `wpkh(${bip84.publicExtendedKey}/0/*)"`,
    `wpkh(${bip84.publicExtendedKey}/0/*)\n`,
    `wpkh(${bip84.publicExtendedKey}/0/*)\``,
    `wpkh(${bip84.publicExtendedKey}/0/*)$`,
    `wpkh(${bip84.publicExtendedKey}/0/*)\\`,
    `wpkh(${bip84.publicExtendedKey}/0/*)!`,
  ]) {
    assert.throws(() => buildDeriveAddressesCommands({ receiveDescriptor: bad }), /double quote or newline|shell metacharacter/);
  }
});

// The app's copy reads the same public units as the Core JSON, each branch
// over exactly its displayed window (the deepest row shown), never the
// importdescriptors range with its lookahead.
for (const [start, count] of CUSTOM_WINDOWS) {
  test(`Key Station deriveaddresses covers branch window ${start}+${count} exactly as displayed`, () => {
    const ui = keyExportHarness();
    const { account } = customAccount(84, "mainnet", start, count);
    ui.hodlWalletResult = { kind: "hd", accounts: [account] };
    assert.equal(ui.hodlCoreDeriveAddressesText("calc"),
      account.addressBranches.map(entry => `deriveaddresses "${entry.publicDescriptor}" "[0,${entry.branch + 2}]"\n`).join(""));
  });
}

test("deriveaddresses follows each branch's deepest displayed row, for Key Station and multisig", () => {
  const ui = keyExportHarness();
  const account = { def: { id: "bip84" }, receiveDescriptor: bip84Receive, changeDescriptor: bip84Change,
    addressBranches: [{ branch: 0, rows: [{ index: 5000 }, { index: 5019 }, { index: 5007 }] }, { branch: 1, rows: [{ index: 3 }] }],
    get receiveDescriptorPriv() { throw new Error("private descriptor read"); },
    get changeDescriptorPriv() { throw new Error("private descriptor read"); } };
  ui.hodlWalletResult = { kind: "hd", accounts: [account] };
  assert.equal(ui.hodlCoreDeriveAddressesText("calc"), `deriveaddresses "${bip84Receive}" "[0,5019]"\nderiveaddresses "${bip84Change}" "[0,3]"\n`);
  assert.equal(ui.hodlCoreDeriveAddressesText("msig"), "", "a stale multisig control cannot copy the active key");
  ui.hodlWalletResult = { kind: "msig", script: "p2wsh", receiveDescriptor: receive, changeDescriptor: change,
    receive: [{ index: 0 }, { index: 1 }, { index: 2 }], change: [{ index: 0 }] };
  assert.equal(ui.hodlCoreDeriveAddressesText("msig"), `deriveaddresses "${receive}" "[0,2]"\nderiveaddresses "${change}" "[0,0]"\n`);
  assert.equal(ui.hodlCoreDeriveAddressesText("calc"), "", "a stale key control cannot copy the active multisig");
  // A branch that shows no rows has no window to check: refuse, never [0,0].
  ui.hodlWalletResult = { kind: "msig", script: "p2wsh", receiveDescriptor: receive, changeDescriptor: change,
    receive: [{ index: 0 }], change: [] };
  assert.throws(() => ui.hodlCoreDeriveAddressesText("msig"), /displayedEnd/);
});

test("Copy Core deriveaddresses copies the lines and flashes Copied; a refusal copies nothing", async () => {
  const ui = keyExportHarness();
  const button = { textContent: "Copy Core deriveaddresses", isConnected: true, classList: { add() {}, remove() {} } };
  const elements = { "key-core-importdescriptors-error": { textContent: "" }, "key-copy-deriveaddresses": button };
  ui.document = { getElementById: id => elements[id] ?? null };
  ui.hodlErrorSpecFrom = error => ({ raw: error.message });
  ui.setTimeout = () => 0;
  ui.clearTimeout = () => {};
  const copied = [];
  ui.copyText = text => { copied.push(text); return Promise.resolve(true); };
  const { account } = customAccount(84, "mainnet", 0, 2);
  ui.hodlWalletResult = { kind: "hd", accounts: [account] };
  ui.hodlCopyCoreDeriveAddresses("calc");
  await Promise.resolve();
  // Expected text from the fixture, not from the code under test.
  assert.deepEqual(copied, [account.addressBranches.map(entry => `deriveaddresses "${entry.publicDescriptor}" "[0,${entry.branch + 2}]"\n`).join("")]);
  assert.equal(button.textContent, "Copied");
  account.addressBranches[0].publicDescriptor = "invalid";
  account.receiveDescriptor = "invalid";
  ui.hodlCopyCoreDeriveAddresses("calc");
  assert.ok(elements["key-core-importdescriptors-error"].textContent, "the refusal reaches the result's error slot");
  assert.equal(copied.length, 1, "a refused export copies nothing");
});

test("the deriveaddresses copy and its note show only in a preview build", () => {
  const ui = keyExportHarness();
  const { account } = customAccount(84, "mainnet", 0, 2);
  const msig = { kind: "msig", script: "p2wsh", receiveDescriptor: receive, changeDescriptor: change, receive: [{ index: 0 }], change: [{ index: 0 }] };
  // A test-hook build without the preview flag: the Key Station export, no copy.
  ui.__ENTROPYLAB_TEST_HOOKS__ = true;
  ui.__ENTROPYLAB_PREVIEW__ = false;
  assert.match(ui.hodlKeyCoreImportDescriptorsMarkup(account), /id="key-copy-importdescriptors"/);
  assert.doesNotMatch(ui.hodlKeyCoreImportDescriptorsMarkup(account), /deriveaddresses/);
  ui.hodlWalletResult = msig;
  assert.doesNotMatch(ui.hodlMsigCoreImportDescriptorsMarkup(), /deriveaddresses/);
  // A release build: the Key Station export stays hidden, as before.
  ui.__ENTROPYLAB_TEST_HOOKS__ = false;
  assert.equal(ui.hodlKeyCoreImportDescriptorsMarkup(account), "");
  // A preview build shows both blocks with the button beside the
  // importdescriptors copy and the agreed note.
  ui.__ENTROPYLAB_PREVIEW__ = true;
  for (const [prefix, markup] of [["key", ui.hodlKeyCoreImportDescriptorsMarkup(account)], ["msig", ui.hodlMsigCoreImportDescriptorsMarkup()]]) {
    assert.match(markup, new RegExp(`id="${prefix}-copy-importdescriptors"[^]*?</button>\\s*<button class="btn secondary" id="${prefix}-copy-deriveaddresses" type="button" aria-describedby="${prefix}-core-deriveaddresses-help">Copy Core deriveaddresses</button>`));
    assert.ok(markup.includes(`<p class="edge-note is-public" id="${prefix}-core-deriveaddresses-help">${coreDeriveAddressesHelp()}</p>`), `${prefix}: the agreed note`);
  }
  const app = read("src/js/app.js");
  assert.match(app, /\["copy-deriveaddresses", hodlCopyCoreDeriveAddresses\]/, "the button is bound with the other Core exports");
});

test("deriveaddresses help points at the Core console and the same network", () => {
  const help = coreDeriveAddressesHelp();
  assert.equal(typeof help, "string");
  assert.match(help, /Window → Console/);
  assert.match(help, /same network/);
});

test("SLIP-132 Zpub is rewritten to xpub when the codec is supplied", () => {
  const zpub = (() => {
    const raw = b58checkDecode(nodeA.publicExtendedKey);
    raw[0] = 0x02; raw[1] = 0xaa; raw[2] = 0x7e; raw[3] = 0xd3;
    return b58checkEncode(raw);
  })();
  assert.match(zpub, /^Zpub/);
  const slipBody = `wsh(sortedmulti(2,[${fingerprint}/48h/0h/0h/2h]${zpub}/0/*,${keyB}/0/*))`;
  const slip = `${slipBody}#${descriptorChecksum(slipBody)}`;
  assert.throws(() => canonicalizeWatchDescriptor(slip), /SLIP-132|Base58Check codec/);
  const canonical = canonicalizeWatchDescriptor(slip, codec);
  assert.match(canonical, /xpub/);
  assert.doesNotMatch(canonical, /Zpub/);
  const json = buildImportDescriptorsJson({ receiveDescriptor: slip, decode: codec.decode, encode: codec.encode });
  assert.match(json, /xpub/);
  assert.doesNotMatch(json, /Zpub/);
});

test("an extended private key is refused", () => {
  const xprv = nodeA.privateExtendedKey;
  const body = `wsh(sortedmulti(1,[${fingerprint}/48h/0h/0h/2h]${xprv}/0/*))`;
  const descriptor = `${body}#${descriptorChecksum(body)}`;
  assert.throws(
    () => buildImportDescriptorsJson({ receiveDescriptor: descriptor, changeDescriptor: change }),
    /extended private key/,
  );
});

test("capital SLIP-132 multisig private keys are refused", () => {
  // Yprv, Zprv (mainnet), Uprv, Vprv (testnet) — the private counterparts of
  // the capital public prefixes this module rewrites.
  for (const version of [0x0295b005, 0x02aa7a99, 0x024285b5, 0x02575048]) {
    const raw = b58checkDecode(nodeA.privateExtendedKey);
    raw[0] = version >>> 24 & 255; raw[1] = version >>> 16 & 255; raw[2] = version >>> 8 & 255; raw[3] = version & 255;
    const key = b58checkEncode(raw);
    assert.match(key, /^[YZUV]prv/);
    const body = `wsh(sortedmulti(1,${key}/0/*))`;
    const descriptor = `${body}#${descriptorChecksum(body)}`;
    assert.throws(() => buildImportDescriptorsJson({ receiveDescriptor: descriptor }), /extended private key/);
  }
});

test("mismatched receive/change keys are refused", () => {
  const other = `wsh(sortedmulti(2,${keyA}/1/*,${keyB}/1/*))`;
  const otherDesc = `${other}#${descriptorChecksum(other)}`;
  assert.throws(
    () => buildImportDescriptorsJson({ receiveDescriptor: receive, changeDescriptor: otherDesc }),
    /different keys/,
  );
});

test("missing descriptors and a bad checksum are refused", () => {
  assert.throws(() => buildImportDescriptorsJson({}), /No watch-only descriptors/);
  const corrupted = receive.slice(0, -1) + (receive.endsWith("0") ? "1" : "0");
  assert.throws(() => buildImportDescriptorsJson({ receiveDescriptor: corrupted }), /checksum does not match/);
});

test("branch-unit serialization preserves explicit flags and rejects private or invalid exports", () => {
  const unit = { descriptor: receive, internal: false, active: false, rangeEnd: 999999 };
  assert.deepEqual(parse(buildImportDescriptorsJson({ descriptorUnits: [unit] })), [{
    desc: receive, internal: false, active: false, timestamp: 0, range: [0, 999999],
  }]);
  assert.throws(() => buildImportDescriptorsJson({ descriptorUnits: [] }), /No watch-only descriptors/);
  assert.throws(() => buildImportDescriptorsJson({ descriptorUnits: [{ ...unit, active: "false" }] }), /explicit internal and active/);
  assert.throws(() => buildImportDescriptorsJson({ descriptorUnits: [{ ...unit, rangeEnd: 1000000 }] }), /range span/);
  assert.throws(() => buildImportDescriptorsJson({ descriptorUnits: [{ ...unit, descriptor: `wpkh(${master.privateExtendedKey}/0/*)` }] }), /private key/);
  const corrupted = receive.slice(0, -1) + (receive.endsWith("0") ? "1" : "0");
  assert.throws(() => buildImportDescriptorsJson({ descriptorUnits: [{ ...unit, descriptor: corrupted }] }), /checksum/);
});

test("filename includes the m-of-n policy when present", () => {
  assert.equal(coreImportDescriptorsFilename({ m: 3, n: 7 }), "entropylab-msig-3of7-importdescriptors.json");
  assert.equal(coreImportDescriptorsFilename({}), "entropylab-importdescriptors.json");
});

test("the builder never talks to the network", () => {
  const source = read("src/js/core-importdescriptors.js");
  assert.doesNotMatch(source, /\bfetch\b|XMLHttpRequest|WebSocket|RTCPeerConnection|sendBeacon|WebTransport/);
});

test("MS Station result markup renders every documented export; no new workspace tab", () => {
  const app = read("src/js/app.js");
  const shell = read("src/shell.html");
  // Audit B7a: README.md/llms.txt promise the msig wallet.dat, the watch-only
  // policy sheet (print + save) and the BIP 388 policy (copy + save); every
  // one of those controls must appear in the markup hodlShowMsig renders, and
  // hodlShowMsig must interpolate each builder, not a copy of it.
  assert.match(app, /id="\$\{prefix\}-copy-importdescriptors"/);
  assert.match(app, /id="\$\{prefix\}-save-importdescriptors"/);
  assert.match(app, /id="msig-download-wallet-dat"/);
  assert.match(app, /id="msig-print-policy-sheet"/);
  assert.match(app, /id="msig-save-policy-sheet"/);
  assert.match(app, /id="msig-copy-bip388"/);
  assert.match(app, /id="msig-save-bip388"/);
  assert.match(app, /hodlT\("Copy Core importdescriptors"\)/);
  assert.match(app, /hodlT\("Save Core Watch-only JSON"\)/);
  assert.match(app, /buildImportDescriptorsJson/);
  assert.match(app, /hodlCoreImportDescriptorsButtons\("msig"\)/);
  const showStart = app.indexOf("function hodlShowMsig(");
  const show = app.slice(showStart, app.indexOf("\nvar ", showStart));
  assert.match(show, /\$\{hodlMsigCoreImportDescriptorsMarkup\(\)\}/);
  assert.match(show, /\$\{hodlMsigPolicySheetMarkup\(\)\}/);
  assert.match(show, /\$\{hodlMsigBip388Markup\(\)\}/);
  assert.doesNotMatch(shell, /msig-copy-importdescriptors|msig-save-importdescriptors/);
  assert.doesNotMatch(shell, /id="workspace-tabs"[\s\S]{0,2000}importdescriptors/);
  assert.match(shell, /id="workspace-tabs"/);
});

test("wallet.dat export accepts watch-only msig and still ignores private material", () => {
  const source = read("src/js/wallet-export.js");
  assert.match(source, /kind === "msig"/);
  assert.match(source, /multiKey: true/);
  assert.match(source, /privateDescriptor: null/);
});

// Core is the consumer of this JSON. Independently derived scure addresses
// check both branches, including index 0 when the displayed window starts at 2.
test("Bitcoin Core and JSON export refuse hardened derivation from xpub", { skip: !BITCOIND, timeout: 120000 }, async () => {
  await withChainNode("regtest", cli => {
    const rpc = (...args) => JSON.parse(cli(args).stdout);
    rpc("-named", "createwallet", "wallet_name=refusals", "disable_private_keys=true", "blank=true");
    const node = HDKey.fromMasterSeed(seed, { public: 0x043587cf, private: 0x04358394 }).derive("m/84'/1'/0'");
    for (const tail of ["0h/*", "0'/*", "*h"]) {
      const body = `wpkh([${fingerprint}/84h/1h/0h]${node.publicExtendedKey}/${tail})`;
      const descriptor = `${body}#${harnessChecksum(body)}`;
      const [result] = rpc("-rpcwallet=refusals", "importdescriptors", JSON.stringify([
        { desc: descriptor, active: true, internal: false, timestamp: 0, range: [0, 1] },
      ]));
      assert.equal(result.success, false, "Core cannot derive hardened children from a public key");
      assert.match(result.error.message, /hardened/i);
      assert.throws(() => buildImportDescriptorsJson({ receiveDescriptor: descriptor }), /hardened.*public key/i);
    }
  });
});

for (const network of Object.keys(CHAIN_FIXTURES)) {
  test(`Bitcoin Core imports Key Station JSON on ${network}`, { skip: !BITCOIND, timeout: 120000 }, async () => {
    const ui = keyExportHarness(), mainnet = network === "mainnet";
    const net = mainnet ? NETWORK : { ...TEST_NETWORK, bech32: network === "regtest" ? "bcrt" : "tb" };
    const versions = mainnet ? undefined : { public: 0x043587cf, private: 0x04358394 };
    await withChainNode(network, (cli) => {
      const rpc = (...args) => JSON.parse(cli(args).stdout);
      for (const purpose of [44, 49, 84, 86]) {
        const node = HDKey.fromMasterSeed(seed, versions).derive(`m/${purpose}'/${mainnet ? 0 : 1}'/0'`);
        const descriptor = branch => {
          const key = `${node.publicExtendedKey}/${branch}/*`;
          const body = purpose === 49 ? `sh(wpkh(${key}))` : `${purpose === 44 ? "pkh" : purpose === 86 ? "tr" : "wpkh"}(${key})`;
          return `${body}#${harnessChecksum(body)}`;
        };
        const expected = (branch, index) => {
          const key = node.deriveChild(branch).deriveChild(index).publicKey;
          return (purpose === 44 ? p2pkh(key, net) : purpose === 49 ? p2sh(p2wpkh(key, net), net) : purpose === 86 ? p2tr(key.slice(1), undefined, net) : p2wpkh(key, net)).address;
        };
        ui.hodlAccountId = `bip${purpose}`;
        ui.hodlRevealPrivate = true;
        ui.hodlWalletResult = { kind: "hd", accounts: [{ def: { id: ui.hodlAccountId },
          receiveDescriptor: descriptor(0), changeDescriptor: descriptor(1), receive: [{ index: 2 }], change: [{ index: 2 }],
          get privateNode() { throw new Error("private material read"); },
          get receiveDescriptorPriv() { throw new Error("private descriptor read"); },
          get changeDescriptorPriv() { throw new Error("private descriptor read"); } }] };
        for (const birthday of ["genesis", "now"]) {
          ui.hodlWalletDatBirthday = birthday;
          const name = `key-${purpose}-${birthday}`, wallet = `-rpcwallet=${name}`;
          rpc("-named", "createwallet", `wallet_name=${name}`, "disable_private_keys=true", "blank=true");
          assert.ok(rpc(wallet, "importdescriptors", ui.hodlCoreImportDescriptorsJson("calc")).every(entry => entry.success));
          const stored = rpc(wallet, "listdescriptors").descriptors;
          assert.equal(stored.length, 2);
          assert.equal(rpc(wallet, "getwalletinfo").private_keys_enabled, false);
          for (const entry of stored) {
            assert.deepEqual(entry.range, [0, 1002]);
            // Core v31.1 rpc/backup.cpp clamps 0 to 1 and resolves "now"
            // to the current chain tip's median time, not the wall clock.
            assert.equal(entry.timestamp, birthday === "genesis" ? 1 : rpc("getblockchaininfo").mediantime);
            assert.equal(rpc("getdescriptorinfo", entry.desc).hasprivatekeys, false);
            assert.deepEqual(rpc("deriveaddresses", entry.desc, "[2,2]"), [expected(entry.internal ? 1 : 0, 2)]);
          }
          const type = { 44: "legacy", 49: "p2sh-segwit", 84: "bech32", 86: "bech32m" }[purpose];
          assert.equal(cli([wallet, "getnewaddress", "", type]).stdout.trim(), expected(0, 0));
          assert.equal(cli([wallet, "getrawchangeaddress", type]).stdout.trim(), expected(1, 0));
        }
      }
    });
  });
}

for (const network of Object.keys(CHAIN_FIXTURES)) {
  test(`Bitcoin Core preserves Key Station custom branches on ${network}`, { skip: !BITCOIND, timeout: 120000 }, async () => {
    const ui = keyExportHarness();
    await withChainNode(network, cli => {
      const rpc = (...args) => JSON.parse(cli(args).stdout);
      for (const purpose of [44, 49, 84, 86]) for (const [start, count, hardened] of [...CUSTOM_WINDOWS, [2, 2, true]]) {
        const { account, expectedAddress } = customAccount(purpose, network, start, count, hardened);
        ui.hodlAccountId = account.def.id;
        ui.hodlWalletResult = { kind: "hd", accounts: [account] };
        const entries = parse(ui.hodlCoreImportDescriptorsJson("calc"));
        assert.equal(entries.length, count, "no selected branch may be omitted");
        assert.deepEqual(entries.map(entry => entry.internal), Array.from({ length: count }, (_, offset) => start === 0 && start + offset === 1));
        assert.deepEqual(entries.map(entry => entry.active), Array.from({ length: count }, (_, offset) => offset === 0 || (start === 0 && start + offset === 1)));
        const wallet = `-rpcwallet=custom-${purpose}-${start}-${count}-${Boolean(hardened)}`;
        rpc("-named", "createwallet", `wallet_name=${wallet.slice(11)}`, "disable_private_keys=true", "blank=true");
        assert.ok(rpc(wallet, "importdescriptors", JSON.stringify(entries)).every(entry => entry.success));
        const stored = rpc(wallet, "listdescriptors").descriptors;
        assert.equal(stored.length, count);
        for (let offset = 0; offset < count; offset++) {
          const branch = start + offset;
          const entry = stored.find(entry => entry.desc === account.addressBranches[offset].publicDescriptor);
          assert.ok(entry, "Core must retain every displayed descriptor");
          // Core's help documents internal only for active descriptors. Actual
          // external/change issuance is independently checked below; ischange
          // in getaddressinfo is an address-book heuristic, not this flag.
          if (entry.active) assert.equal(entry.internal, start === 0 && branch === 1);
          assert.equal(entry.active, offset === 0 || (start === 0 && branch === 1));
          assert.deepEqual(entry.range, [0, 1002 + branch]);
          assert.deepEqual(rpc("deriveaddresses", entry.desc, `[${branch + 2},${branch + 2}]`), [expectedAddress(branch, branch + 2)]);
          const info = rpc(wallet, "getaddressinfo", expectedAddress(branch, branch + 2));
          assert.equal(info.ismine, true, "Core must actually watch the branch");
        }
        const type = { 44: "legacy", 49: "p2sh-segwit", 84: "bech32", 86: "bech32m" }[purpose];
        assert.equal(cli([wallet, "getnewaddress", "", type]).stdout.trim(), expectedAddress(start, 0));
        if (start === 0 && count > 1) assert.equal(cli([wallet, "getrawchangeaddress", type]).stdout.trim(), expectedAddress(1, 0));
        else assert.notEqual(cli([wallet, "getrawchangeaddress", type], { check: false }).status, 0, "no change branch may be invented");
      }
    });
  });
}

// Core runs the copied lines: each prints the branch's addresses from index 0
// through the deepest displayed row, matching independently derived ones.
for (const network of Object.keys(CHAIN_FIXTURES)) {
  test(`Bitcoin Core runs the Key Station deriveaddresses copy on ${network}`, { skip: !BITCOIND, timeout: 120000 }, async () => {
    const ui = keyExportHarness();
    await withChainNode(network, cli => {
      const rpc = (...args) => JSON.parse(cli(args).stdout);
      for (const purpose of [44, 49, 84, 86]) for (const [start, count, hardened] of [...CUSTOM_WINDOWS, [2, 2, true]]) {
        const { account, expectedAddress } = customAccount(purpose, network, start, count, hardened);
        ui.hodlAccountId = account.def.id;
        ui.hodlWalletResult = { kind: "hd", accounts: [account] };
        const lines = ui.hodlCoreDeriveAddressesText("calc").trimEnd().split("\n");
        assert.equal(lines.length, count, "one line per displayed branch");
        lines.forEach((line, offset) => {
          const [, descriptor, range] = line.match(/^deriveaddresses "([^"]+)" "(\[0,\d+\])"$/);
          const branch = start + offset;
          assert.deepEqual(rpc("deriveaddresses", descriptor, range), Array.from({ length: branch + 3 }, (_, index) => expectedAddress(branch, index)));
        });
      }
    });
  });
}
