// Tests for src/js/wallet-export.js (Bitcoin Core wallet.dat export) using
// Node's built-in test runner.
//
// The gold standard: REF_WATCH_ONLY_RECORDS / REF_PRIVATE_RECORDS in
// wallet-export-reference.mjs are the exact rows of wallet.dat `main` tables
// produced by Bitcoin Core v28.3.0 (regtest) via createwallet +
// importdescriptors of the reference descriptors. The tests rebuild those
// rows with the module and an independent, dependency-free reference
// implementation of the crypto (secp256k1/BIP32/checksums over BigInt and
// node:crypto — the vendor bundle is not used), then verify the generated
// database files with Python's sqlite3 (the real SQLite C library).
//
// The same generated file shapes were also validated by loading them with
// bitcoind (loadwallet) and spending from the private variant on regtest.
// The final section automates that: where bitcoind is installed, every chain
// the network picker advertises loads its generated file (issue #329).
//
// Run with `npm run test:wallet-export` or `npm test`.
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { createServer } from "node:net";
import {
  REF_ACCOUNT_TPUB,
  REF_CREATION_TIME,
  REF_PRIVATE_DESCRIPTORS,
  REF_PRIVATE_RECORDS,
  REF_PUBLIC_DESCRIPTORS,
  REF_WATCH_ONLY_RECORDS,
} from "./wallet-export-reference.mjs";
import {
  B58,
  BASE_G,
  CHECKSUM_CHARSET,
  FIELD_P,
  INPUT_CHARSET,
  ORDER_N,
  PYTHON_SQLITE,
  asMap,
  b58checkDecode,
  b58checkEncode,
  b58encode,
  bigintBytes,
  bytesToHex,
  deps,
  deriveBranchBody,
  descriptorChecksum,
  hdDeriveHardened,
  hdMasterFromSeed,
  hdNodeFrom,
  hexToBytes,
  loadModule,
  modPow,
  moduleRecords,
  pointAdd,
  pointMul,
  publicKeyForPrivate,
  read,
  ripemd160,
  serPub,
  serializeExtendedKey,
  sha256,
  sqliteReadBack,
  unserPub,
} from "./wallet-export-harness.mjs";

const sqliteSrc = read("src/js/sqlite-writer.js");
const walletSrc = read("src/js/wallet-export.js");
const app = read("src/js/app.js");


// --- reference wallets ------------------------------------------------------

// refD descriptors all share one account key (m/44'/1'/0'); its public form:
const publicFormOf = (privateDescriptor) => {
  const body = privateDescriptor
    .slice(0, privateDescriptor.lastIndexOf("#"))
    .replace(/tprv[1-9A-HJ-NP-Za-km-z]{90,}/, REF_ACCOUNT_TPUB);
  return `${body}#${descriptorChecksum(body)}`;
};
const REF_PRIVATE_PUBLIC_FORMS = REF_PRIVATE_DESCRIPTORS.map(publicFormOf);

const SCRIPT_DEFS = [
  { id: "bip44", bip: "BIP44", label: "Legacy", script: "p2pkh" },
  { id: "bip49", bip: "BIP49", label: "Nested SegWit", script: "p2sh-p2wpkh" },
  { id: "bip86", bip: "BIP86", label: "Taproot", script: "p2tr" },
  { id: "bip84", bip: "BIP84", label: "Native SegWit", script: "p2wpkh" },
];
const makeAccounts = (publics, privates) =>
  SCRIPT_DEFS.map((def, i) => ({
    def,
    accountPath: `m/${def.id.slice(3)}'/1'/0'`,
    receiveDescriptor: publics[i * 2],
    changeDescriptor: publics[i * 2 + 1],
    receiveDescriptorPriv: privates[i * 2],
    changeDescriptorPriv: privates[i * 2 + 1],
  }));

const WATCH_ONLY_WALLET = {
  kind: "hd",
  network: "regtest",
  accounts: makeAccounts(REF_PUBLIC_DESCRIPTORS, new Array(8).fill(null)),
};
const PRIVATE_WALLET = {
  kind: "hd",
  network: "regtest",
  accounts: makeAccounts(REF_PRIVATE_PUBLIC_FORMS, REF_PRIVATE_DESCRIPTORS),
};


// --- tests ------------------------------------------------------------------

test("never generates network traffic", () => {
  for (const source of [sqliteSrc, walletSrc]) {
    assert.doesNotMatch(source, /\bfetch\b|XMLHttpRequest|WebSocket|RTCPeerConnection|sendBeacon|WebTransport/);
  }
});

test("reference implementations agree with the fixture", () => {
  // every fixture descriptor carries the checksum its body must produce
  for (const descriptor of [...REF_PUBLIC_DESCRIPTORS, ...REF_PRIVATE_DESCRIPTORS]) {
    const [body, checksum] = descriptor.split("#");
    assert.equal(descriptorChecksum(body), checksum, `checksum mismatch: ${descriptor.slice(0, 40)}`);
  }
  // account branch-0 cache body as Core wrote it in refB2/refD
  const cache = REF_WATCH_ONLY_RECORDS.find(([key]) => key.startsWith("15" + "77616c6c657464657363726970746f726361636865"));
  const body = deriveBranchBody(REF_ACCOUNT_TPUB, 0);
  assert.equal("4a" + bytesToHex(body), cache[1]);
  // secp256k1 generator sanity
  assert.equal(
    bytesToHex(publicKeyForPrivate(Uint8Array.from([...new Array(31).fill(0), 1]))),
    "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
  );
});

test("watch-only records are byte-identical to a Bitcoin Core wallet", () => {
  const mine = moduleRecords(WATCH_ONLY_WALLET, false, REF_CREATION_TIME);
  const reference = asMap(REF_WATCH_ONLY_RECORDS);
  assert.equal(mine.size, reference.size);
  for (const [key, value] of reference) {
    assert.ok(mine.has(key), `missing record ${key.slice(0, 60)}`);
    assert.equal(mine.get(key), value, `record value mismatch at ${key.slice(0, 60)}`);
  }
  // no private-key records in a watch-only export
  assert.ok(![...mine.keys()].some((key) => key.includes("77616c6c657464657363726970746f726b6579")));
  // flags = DESCRIPTORS | BLANK | DISABLE_PRIVATE_KEYS
  assert.equal(mine.get("05666c616773"), "0000000007000000");
});

test("private records are byte-identical to a Bitcoin Core wallet", () => {
  const mine = moduleRecords(PRIVATE_WALLET, true, REF_CREATION_TIME);
  const reference = asMap(REF_PRIVATE_RECORDS);
  assert.equal(mine.size, reference.size);
  for (const [key, value] of reference) {
    assert.ok(mine.has(key), `missing record ${key.slice(0, 60)}`);
    assert.equal(mine.get(key), value, `record value mismatch at ${key.slice(0, 60)}`);
  }
  // 8 descriptorkey records, one per descriptor; flags = DESCRIPTORS | BLANK
  const keyRecords = [...mine.keys()].filter((key) => key.includes("77616c6c657464657363726970746f726b6579"));
  assert.equal(keyRecords.length, 8);
  assert.equal(mine.get("05666c616773"), "0000000006000000");
});

test("accounts without private material stay watch-only in a private export", () => {
  const watchOnly = moduleRecords(WATCH_ONLY_WALLET, false, REF_CREATION_TIME);
  const fallback = moduleRecords(WATCH_ONLY_WALLET, true, REF_CREATION_TIME);
  assert.deepEqual([...fallback.keys()].sort(), [...watchOnly.keys()].sort());
  for (const key of watchOnly.keys()) assert.equal(fallback.get(key), watchOnly.get(key));
});

// Regression: the h->' compat rewrite must stay inside the [origin] segment.
// About 1 in 375 account xpubs end in a digit followed by the base58 letter
// "h"; a body-wide rewrite corrupted that xpub, and Bitcoin Core refused to
// load the wallet ("descriptor ID calculated by the wallet differs from the
// one in DB"). Both xpubs below are real m/84'/0'/0' account keys with that
// ending, so the old code path is exercised exactly.
const XPUB_TAIL_4H = "xpub6DGDSTSv42ve3BBRALC4UVi3LdaoQjA9R2yV9RSDojTRKQTK5Jk73WKqm6v392eeF3Lxawf8gHiBpD5xBDx7HYvbkLoZ6e1Emu9fvW2M24h";
const XPUB_TAIL_2H = "xpub6ChZ8GTJVLpepi3oLPQUHRx6H7RkwQ6bsoqvSfwTw5jZuRithtrc75Tfq7H3sa8bXkA9d35K3CdJDY5B2aTFmdFEp19AGWT7XTXDVFvCn2h";

const DESCRIPTOR_PREFIX = "10" + "77616c6c657464657363726970746f72"; // length-prefixed "walletdescriptor"
const descriptorIds = (records) =>
  [...records.keys()].filter((key) => key.startsWith(DESCRIPTOR_PREFIX)).map((key) => key.slice(DESCRIPTOR_PREFIX.length));
const digitHWallet = (descriptorFor) => ({
  kind: "hd",
  network: "mainnet",
  accounts: [{
    def: { id: "bip84" },
    receiveDescriptor: descriptorFor(XPUB_TAIL_4H),
    changeDescriptor: descriptorFor(XPUB_TAIL_2H),
  }],
});

test("descriptor ids keep account xpubs ending in <digit>h byte-identical", () => {
  const descriptorFor = (xpub) => {
    const body = `wpkh([00000000/84h/0h/0h]${xpub}/0/*)`;
    return `${body}#${descriptorChecksum(body)}`;
  };
  const records = moduleRecords(digitHWallet(descriptorFor), false, REF_CREATION_TIME);
  const ids = descriptorIds(records);
  assert.equal(ids.length, 2);
  for (const xpub of [XPUB_TAIL_4H, XPUB_TAIL_2H]) {
    // What Core computes at load: origin steps rendered with ', key material
    // (including its trailing "h") re-encoded untouched.
    const compat = `wpkh([00000000/84'/0'/0']${xpub}/0/*)`;
    const expectedId = bytesToHex(sha256(new TextEncoder().encode(`${compat}#${descriptorChecksum(compat)}`)));
    assert.ok(ids.includes(expectedId), `record id for ...${xpub.slice(-12)} must match Core's DescriptorID`);
  }
  // The stored descriptor string keeps the original xpub text as well.
  const storedValues = ids.map((id) => Buffer.from(records.get(DESCRIPTOR_PREFIX + id), "hex").toString());
  for (const xpub of [XPUB_TAIL_4H, XPUB_TAIL_2H]) {
    assert.ok(storedValues.some((value) => value.includes(xpub)), `stored descriptor keeps ...${xpub.slice(-12)} verbatim`);
  }
});

test("origin-less descriptors keep a <digit>h xpub byte-identical", () => {
  // Imported account keys export without a key origin (the app does not
  // fabricate one). With nothing to rewrite, the compat form is the body
  // itself — the body-wide rewrite corrupted these xpubs just the same.
  const descriptorFor = (xpub) => {
    const body = `wpkh(${xpub}/0/*)`;
    return `${body}#${descriptorChecksum(body)}`;
  };
  const records = moduleRecords(digitHWallet(descriptorFor), false, REF_CREATION_TIME);
  const ids = descriptorIds(records);
  assert.equal(ids.length, 2);
  for (const xpub of [XPUB_TAIL_4H, XPUB_TAIL_2H]) {
    const body = `wpkh(${xpub}/0/*)`;
    const expectedId = bytesToHex(sha256(new TextEncoder().encode(`${body}#${descriptorChecksum(body)}`)));
    assert.ok(ids.includes(expectedId), `record id for origin-less ...${xpub.slice(-12)} must hash the unchanged body`);
  }
});

// Regression for the Harden branch option: the watch-only descriptor is
// "wpkh([fp/84h/0h/0h/0h]xpubBranch/*)" — the branch xpub IS the descriptor
// root key. Core caches the root key itself when the path after it is empty
// (BIP32PubkeyProvider) and looks the root pubkey up in walletdescriptorkey.
// Deriving branch 0/1 of that key for the cache made Core watch a different
// subtree, and recording the account key left the spending variant unable to
// sign (root pubkey lookup misses in m_map_keys).
test("hardened-branch descriptors cache and sign with the descriptor root key", () => {
  const seed = new Uint8Array(32);
  seed[31] = 1;
  const master = hdMasterFromSeed(seed);
  const fp = bytesToHex(ripemd160(sha256(publicKeyForPrivate(master.secret))).subarray(0, 4));
  let account = master;
  for (const step of [84, 0, 0]) account = hdDeriveHardened(account, step);
  const accountXprv = serializeExtendedKey(account, 0x0488ade4, true);
  const branch = (b) => hdDeriveHardened(account, b);
  const branchXpub = (b) => serializeExtendedKey(branch(b), 0x0488b21e, false);
  const descriptorFor = (b) => {
    const body = `wpkh([${fp}/84h/0h/0h/${b}h]${branchXpub(b)}/*)`;
    return `${body}#${descriptorChecksum(body)}`;
  };
  const privateDescriptorFor = (b) => {
    const body = `wpkh([${fp}/84h/0h/0h]${accountXprv}/${b}'/*)`;
    return `${body}#${descriptorChecksum(body)}`;
  };
  const wallet = {
    kind: "hd",
    network: "mainnet",
    accounts: [{
      def: { id: "bip84" },
      receiveDescriptor: descriptorFor(0),
      changeDescriptor: descriptorFor(1),
      receiveDescriptorPriv: privateDescriptorFor(0),
      changeDescriptorPriv: privateDescriptorFor(1),
    }],
  };

  // Watch-only: the cache parent is the branch xpub itself (raw 74-byte body).
  const watch = moduleRecords(wallet, false, REF_CREATION_TIME);
  const cachePrefix = "15" + "77616c6c657464657363726970746f726361636865"; // \x15walletdescriptorcache
  const caches = [...watch.entries()].filter(([key]) => key.startsWith(cachePrefix)).map(([, value]) => value);
  assert.equal(caches.length, 2);
  for (const b of [0, 1]) {
    const expected = "4a" + bytesToHex(b58checkDecode(branchXpub(b)).slice(4));
    assert.ok(caches.includes(expected), `cache parent for branch ${b} is the descriptor root key itself`);
  }

  // Spending: each key record maps the branch pubkey to the branch secret.
  const spending = moduleRecords(wallet, true, REF_CREATION_TIME);
  const keyRecords = [...spending.entries()].filter(([key]) => key.includes("77616c6c657464657363726970746f726b6579"));
  assert.equal(keyRecords.length, 2);
  for (const b of [0, 1]) {
    const pubkey = bytesToHex(publicKeyForPrivate(branch(b).secret));
    const record = keyRecords.find(([key]) => key.endsWith("21" + pubkey));
    assert.ok(record, `key record for branch ${b} names the branch pubkey`);
    const secret = bytesToHex(branch(b).secret);
    assert.ok(record[1].startsWith("d6") && record[1].includes(secret), `key record for branch ${b} carries the branch secret`);
  }
});

test("generated watch-only wallet.dat verifies with real SQLite", { skip: !PYTHON_SQLITE }, () => {
  const { buildWalletDat } = loadModule();
  const bytes = buildWalletDat(WATCH_ONLY_WALLET, false, deps, REF_CREATION_TIME);
  assert.equal(new TextDecoder().decode(bytes.subarray(0, 15)), "SQLite format 3");
  const report = sqliteReadBack(bytes);
  assert.equal(report.integrity, "ok");
  assert.equal(report.app_id, 0xfabfb5da); // regtest magic
  assert.equal(report.user_version, 0);
  assert.deepEqual(asMap(report.rows), asMap(REF_WATCH_ONLY_RECORDS));
});

test("generated private wallet.dat verifies with real SQLite", { skip: !PYTHON_SQLITE }, () => {
  const { buildWalletDat } = loadModule();
  const bytes = buildWalletDat(PRIVATE_WALLET, true, deps, REF_CREATION_TIME);
  const report = sqliteReadBack(bytes);
  assert.equal(report.integrity, "ok");
  assert.deepEqual(asMap(report.rows), asMap(REF_PRIVATE_RECORDS));
});

test("network selects the application id and best-block locator", () => {
  const { buildWalletRecords, buildWalletDat } = loadModule();
  const bestblockKey = "12" + "62657374626c6f636b5f6e6f6d65726b6c65"; // "bestblock_nomerkle"
  // Every picker network writes its own network magic and genesis locator:
  // signet and regtest share testnet's key/address family but are NOT aliases
  // for it in the wallet metadata (issue #329). The signet row is the default
  // signet; custom-challenge signets get a different magic in Core and are
  // out of scope.
  const chains = {
    mainnet: { magic: "f9beb4d9", genesis: "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f" },
    testnet: { magic: "0b110907", genesis: "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943" },
    signet: { magic: "0a03cf40", genesis: "00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6" },
    regtest: { magic: "fabfb5da", genesis: "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206" },
  };
  for (const [network, { magic, genesis }] of Object.entries(chains)) {
    const wallet = { ...WATCH_ONLY_WALLET, network };
    const bytes = buildWalletDat(wallet, false, deps, REF_CREATION_TIME);
    assert.equal(bytesToHex(bytes.subarray(68, 72)), magic, `${network} application id`);
    const locator = moduleRecords(wallet, false, REF_CREATION_TIME).get(bestblockKey);
    assert.ok(locator.endsWith(bytesToHex(hexToBytes(genesis).reverse())), `${network} bestblock locator should name its genesis block`);
  }
  assert.throws(() => buildWalletRecords({ ...WATCH_ONLY_WALLET, network: "mutinynet" }, false, deps, REF_CREATION_TIME), /unknown network/);
});

test("descriptor ranges cover displayed addresses plus a recovery gap", () => {
  const { buildWalletRecords, walletDescriptorUnits } = loadModule();
  const wallet = structuredClone(WATCH_ONLY_WALLET);
  wallet.accounts[0].addressBranches = [
    { branch: 0, rows: [{ index: 5000 }, { index: 5001 }, { index: 5002 }] },
    { branch: 1, rows: [{ index: 7000 }] },
  ];

  const units = walletDescriptorUnits(wallet, false);
  assert.deepEqual(
    units.slice(0, 2).map(({ nextIndex, rangeStart, rangeEnd }) => ({ nextIndex, rangeStart, rangeEnd })),
    [
      { nextIndex: 5003, rangeStart: 5000, rangeEnd: 6002 },
      { nextIndex: 7001, rangeStart: 7000, rangeEnd: 8000 },
    ],
  );

  const records = buildWalletRecords(wallet, false, deps, REF_CREATION_TIME);
  const descriptorValues = records
    .filter(([key]) => key[0] === 16 && new TextDecoder().decode(key.slice(1, 17)) === "walletdescriptor")
    .map(([, value]) => Buffer.from(value));
  const readRange = (value) => {
    const first = value[0];
    const lengthBytes = first < 253 ? 1 : first === 253 ? 3 : first === 254 ? 5 : 9;
    const descriptorLength = first < 253 ? first : first === 253 ? value.readUInt16LE(1) : first === 254 ? value.readUInt32LE(1) : Number(value.readBigUInt64LE(1));
    const offset = lengthBytes + descriptorLength + 8;
    return {
      nextIndex: value.readUInt32LE(offset),
      rangeStart: value.readUInt32LE(offset + 4),
      rangeEnd: value.readUInt32LE(offset + 8),
    };
  };
  assert.deepEqual(readRange(descriptorValues[0]), { nextIndex: 5003, rangeStart: 5000, rangeEnd: 6002 });
  assert.deepEqual(readRange(descriptorValues[1]), { nextIndex: 7001, rangeStart: 7000, rangeEnd: 8000 });
});

test("button gating: only HD wallets with descriptors", () => {
  const { hasDescriptors } = loadModule();
  assert.equal(hasDescriptors(null), false);
  assert.equal(hasDescriptors({}), false);
  assert.equal(hasDescriptors({ kind: "single", wifCompressed: "L..." }), false);
  assert.equal(hasDescriptors({ kind: "msig", receiveDescriptor: "wsh(...)#x", changeDescriptor: "wsh(...)#y" }), false);
  assert.equal(hasDescriptors({ kind: "hd", accounts: [] }), false);
  assert.equal(hasDescriptors(WATCH_ONLY_WALLET), true);
});

test("a receive-only wallet still exports: units cover whichever branches exist (issue #366)", () => {
  const { hasDescriptors, hasPrivateDescriptors, walletDescriptorUnits, buildWalletRecords } = loadModule();
  const wallet = structuredClone(WATCH_ONLY_WALLET);
  for (const account of wallet.accounts) {
    account.changeDescriptor = null;
    account.changeDescriptorPriv = null;
  }
  assert.equal(hasDescriptors(wallet), true, "receive-only wallets must have an export");
  const units = walletDescriptorUnits(wallet, false);
  assert.equal(units.length, 4);
  assert.ok(units.every((unit) => !unit.internal), "no internal-branch units");
  const records = buildWalletRecords(wallet, false, deps, REF_CREATION_TIME);
  const names = records.map(([key]) => new TextDecoder().decode(key.slice(1, 1 + key[0])));
  assert.equal(names.filter((name) => name === "activeexternalspk").length, 4);
  assert.ok(!names.includes("activeinternalspk"), "a branch that was never derived must not produce an active record");
  assert.equal(names.filter((name) => name === "walletdescriptor").length, 4);
  // The secrets-variant label/filename honesty helpers track real material.
  assert.equal(hasPrivateDescriptors(wallet), false);
  assert.equal(hasPrivateDescriptors(PRIVATE_WALLET), true);
  // Symmetric case: a change-only wallet (custom branch start) exports too.
  const changeOnly = structuredClone(WATCH_ONLY_WALLET);
  for (const account of changeOnly.accounts) {
    account.receiveDescriptor = null;
    account.receiveDescriptorPriv = null;
  }
  const changeUnits = walletDescriptorUnits(changeOnly, false);
  assert.equal(changeUnits.length, 4);
  assert.ok(changeUnits.every((unit) => unit.internal), "no external-branch units");
});

test("the app keys the secrets label and filename to actual material (issue #366)", () => {
  const app = read("src/js/app.js");
  assert.match(app, /withSecrets = includePrivate && hodlWalletExport\.hasPrivateDescriptors\(hodlWalletResult\)/);
  assert.match(app, /walletDatButtonLabel\(withSecrets\)/);
  assert.match(app, /withSecrets = hodlRevealPrivate && hodlWalletExport\.hasPrivateDescriptors\(hodlWalletResult\)/);
  assert.match(app, /walletDatFilename\(hodlWalletResult, withSecrets\)/);
});

test("filename announces the wallet fingerprint and watch-only vs secrets", () => {
  const { walletDatFilename } = loadModule();
  const wallet = { masterFingerprint: "73C5DA0A" };
  // Unique, identifiable files: the master XFP names the wallet (issue #77).
  assert.equal(walletDatFilename(wallet, false), "entropylab-73c5da0a-watch-only-wallet.dat");
  assert.equal(walletDatFilename(wallet, true), "entropylab-73c5da0a-private-wallet-secrets.dat");
  assert.equal(walletDatFilename(wallet), "entropylab-73c5da0a-watch-only-wallet.dat");
  // Without a usable fingerprint the names fall back to the plain forms.
  assert.equal(walletDatFilename(null, false), "watch-only-wallet.dat");
  assert.equal(walletDatFilename({ masterFingerprint: "not-an-xfp" }, true), "private-wallet-secrets.dat");
  assert.equal(walletDatFilename(), "watch-only-wallet.dat");
});

test("button label follows the reveal state", () => {
  const { walletDatButtonLabel } = loadModule();
  assert.equal(walletDatButtonLabel(false), "Download watch-only wallet.dat");
  const shown = walletDatButtonLabel(true);
  assert.match(shown, /secrets/i);
  assert.match(shown, /xprv/i);
  assert.match(shown, /\.dat/);
});

test("template, build script, and app wiring ship the export", () => {
  const template = read("src/index.html");
  const build = read("scripts/build.mjs");
  const css = read("src/css/styles.css");
  assert.match(template, /\/\*@@JS_WALLET_EXPORT@@\*\//);
  assert.match(build, /wallet-export\.js/);
  assert.match(build, /JS_WALLET_EXPORT/);
  // The button renders next to #save in the wallet-data-actions row, and its
  // label follows the material that exists, not the reveal flag alone (#366).
  assert.match(app, /id="save"[^>]*>\$\{downloadLabel\}<\/button>\s*\$\{hodlWalletDatControl\(privateSheet\)\}/);
  assert.match(app, /hodlSaveRecoveryControl\s*\(\s*\)\s*\{\s*return\s*`<div class="wallet-data-actions no-print">[^`]*\$\{hodlWalletDatControl\(\s*(?:false|!1)\s*\)\}/);
  assert.match(app, /id="download-wallet-dat"[^>]*>\$\{hodlWalletExport\.walletDatButtonLabel\(withSecrets\)\}/);
  assert.match(app, /hodlWalletExport\.hasDescriptors\(hodlWalletResult\)/);
  assert.match(app, /hodlWalletExport\.buildWalletDat\(\s*hodlWalletResult\s*,\s*withSecrets\s*,\s*hodlWalletDatDeps\(\s*\)\s*,\s*creationTime\s*\)/);
  assert.match(app, /hodlWalletExport\.walletDatFilename\(hodlWalletResult, withSecrets\)/);
  assert.match(app, /document\.getElementById\("download-wallet-dat"\)/);
  assert.match(css, /\.save-wallet-dat/);
});

// --- UI wiring: the real app.js controls rendered against stubbed globals ---

const extract = (startNeedle, endNeedle) => {
  const start = app.indexOf(startNeedle);
  const end = app.indexOf(endNeedle, start);
  if (start < 0 || end < 0) throw new Error(`extract failed: ${startNeedle}`);
  return app.slice(start, end);
};

// The UI harness executes the real app.js controls and download handler in a
// module scope where the vendor globals they read (tr, Cs, sr, le, Gt, xe,
// cr) are backed by the reference implementations above.
const harnessSource = `
import { createHash, createHmac } from "node:crypto";
const FIELD_P = ${FIELD_P.toString()}n;
const ORDER_N = ${ORDER_N.toString()}n;
const BASE_G = [${BASE_G[0].toString()}n, ${BASE_G[1].toString()}n];
const B58 = ${JSON.stringify(B58)};
const INPUT_CHARSET = ${JSON.stringify(INPUT_CHARSET)};
const CHECKSUM_CHARSET = ${JSON.stringify(CHECKSUM_CHARSET)};
${[modPow, pointAdd, pointMul, serPub, unserPub, bigintBytes, b58encode, b58checkDecode, b58checkEncode, sha256, ripemd160, bytesToHex, descriptorChecksum, deriveBranchBody, publicKeyForPrivate, hdNodeFrom].map((fn) => `const ${fn.name} = ${fn.toString()};`).join("\n")}
const captured = { blob: null, name: "" };
const elements = new Map();
const URL = {
  createObjectURL: (blob) => { captured.blob = blob; return "blob:mock"; },
  revokeObjectURL: () => {},
};
class Blob {
  constructor(parts, options) { this.parts = parts; this.type = options?.type ?? ""; }
}
const document = {
  createElement: () => ({ click() { captured.name = this.download; } }),
  getElementById: (id) => elements.get(id) ?? null,
  querySelectorAll: (selector) => [...elements.values()].filter((element) => element.matches?.(selector)),
};
let hodlWalletResult = null, hodlRevealPrivate = false, hodlWalletDatBirthday = "genesis";
const hodlSha256 = (bytes) => sha256(bytes);
const hodlDescriptorChecksum = descriptorChecksum;
const hodlBase58Check = { decode: b58checkDecode };
const hodlReversionExtendedKey = (text, version) => {
  const raw = b58checkDecode(text).slice();
  raw[0] = (version >>> 24) & 255; raw[1] = (version >>> 16) & 255; raw[2] = (version >>> 8) & 255; raw[3] = version & 255;
  return b58checkEncode(raw);
};
const hodlExtendedKeyVersions = { mainnet: { x: { pub: 0x0488b21e } } };
const hodlHDKey = { fromExtendedKey: (text) => hdNodeFrom(b58checkDecode(text)) };
const hodlSecp256k1 = { getPublicKey: (secret) => publicKeyForPrivate(secret) };
function hodlBindAddressMatch(){}
// app.js calls the i18n t() directly now; the harness runs it in English.
const hodlT = (source, vars) => !vars ? source : source.replace(/\{(\w+)\}/g, (_, name) => (vars[name] == null ? "{" + name + "}" : String(vars[name])));
${extract("function hodlPrivateDataControls", "function hodlWalletMessages")}
${extract("function hodlWalletDatDeps", "function hodlFocusWalletResult")}
${sqliteSrc}
${walletSrc}
const setResult = (value, flag) => { hodlWalletResult = value; hodlRevealPrivate = flag; };
const setWalletDatBirthday = (value) => { hodlWalletDatBirthday = value; };
export { captured, elements, hodlPrivateDataControls, hodlSaveRecoveryControl, hodlDownloadWalletDat, hodlBindWalletResultActions, setResult, setWalletDatBirthday };
`;

// Keep the transient harness out of test/ so parallel suites that list the
// directory (e.g. the parse check) never see it.
const harnessDir = mkdtempSync(join(tmpdir(), "entropylab-harness-"));
const harnessPath = join(harnessDir, "wallet-export-harness.mjs");
writeFileSync(harnessPath, harnessSource);
const ui = await import(pathToFileURL(harnessPath).href);
rmSync(harnessDir, { recursive: true });

test("controls render the wallet.dat button next to #save only when descriptors exist", () => {
  ui.setResult(WATCH_ONLY_WALLET, false);
  const watchHtml = ui.hodlPrivateDataControls("wallet-private-description");
  assert.match(watchHtml, /id="save"/);
  assert.match(watchHtml, /id="download-wallet-dat"[^>]*>Download watch-only wallet\.dat<\/button>/);

  // The reveal flag alone must not produce a secrets label on a wallet that
  // has no private descriptors (issue #366): watch-only stays watch-only.
  ui.setResult(WATCH_ONLY_WALLET, true);
  const noSecretsHtml = ui.hodlPrivateDataControls("wallet-private-description");
  assert.match(noSecretsHtml, /id="download-wallet-dat"[^>]*>Download watch-only wallet\.dat<\/button>/);

  // With private descriptors present, the reveal flag yields the secrets label.
  ui.setResult(PRIVATE_WALLET, true);
  const privateHtml = ui.hodlPrivateDataControls("wallet-private-description");
  assert.match(privateHtml, /id="download-wallet-dat"[^>]*>Download wallet\.dat with secrets \(xprvs\)<\/button>/);

  ui.setResult({ kind: "single", wifCompressed: "L..." }, false);
  assert.doesNotMatch(ui.hodlPrivateDataControls("single-private-description", "single"), /download-wallet-dat/);

  ui.setResult(WATCH_ONLY_WALLET, false);
  assert.match(ui.hodlSaveRecoveryControl(), /id="download-wallet-dat"[^>]*>Download watch-only wallet\.dat<\/button>/);
});

test("download handler emits a real wallet.dat through the app code path", { skip: !PYTHON_SQLITE }, () => {
  ui.setResult(PRIVATE_WALLET, true);
  ui.hodlDownloadWalletDat();
  assert.equal(ui.captured.name, "private-wallet-secrets.dat");
  assert.equal(ui.captured.blob.type, "application/octet-stream");
  const bytes = new Uint8Array(ui.captured.blob.parts[0]);
  assert.equal(new TextDecoder().decode(bytes.subarray(0, 15)), "SQLite format 3");
  const report = sqliteReadBack(bytes);
  assert.equal(report.integrity, "ok");
  // the only nondeterminism is creation_time; read it back and rebuild
  const descriptorRow = report.rows.find(([key]) => key.startsWith("10" + "77616c6c657464657363726970746f72"));
  const value = Buffer.from(descriptorRow[1], "hex");
  const creationTime = Number(value.readBigUInt64LE(1 + value[0]));
  const expected = asMap(
    loadModule()
      .buildWalletRecords(PRIVATE_WALLET, true, deps, creationTime)
      .map(([key, val]) => [bytesToHex(key), bytesToHex(val)]),
  );
  assert.deepEqual(asMap(report.rows), expected);
});

// Issue #95: a recovered wallet exported with the export time as its
// descriptor birthday is not rescanned back to its real history by Bitcoin
// Core. The download defaults to a genesis birthday (creation time 0) so
// recovery discovers older transactions; "now" is written only on request.
const readBackCreationTime = (bytes) => {
  const report = sqliteReadBack(bytes);
  const descriptorRow = report.rows.find(([key]) => key.startsWith("10" + "77616c6c657464657363726970746f72"));
  const value = Buffer.from(descriptorRow[1], "hex");
  return Number(value.readBigUInt64LE(1 + value[0]));
};

test("wallet.dat download defaults to a genesis birthday for recovery", { skip: !PYTHON_SQLITE }, () => {
  ui.setResult(WATCH_ONLY_WALLET, false);
  ui.setWalletDatBirthday("genesis");
  ui.hodlDownloadWalletDat();
  assert.equal(readBackCreationTime(new Uint8Array(ui.captured.blob.parts[0])), 0);
});

test("wallet.dat download writes the current time only for keys confirmed new", { skip: !PYTHON_SQLITE }, () => {
  ui.setResult(PRIVATE_WALLET, true);
  ui.setWalletDatBirthday("now");
  const before = Math.floor(Date.now() / 1000) - 1;
  ui.hodlDownloadWalletDat();
  const after = Math.floor(Date.now() / 1000) + 1;
  const creationTime = readBackCreationTime(new Uint8Array(ui.captured.blob.parts[0]));
  assert.ok(creationTime >= before && creationTime <= after, `creation time ${creationTime} is not the export time`);
  ui.setWalletDatBirthday("genesis");
});

test("the wallet.dat control offers the birthday choice with genesis as the safe default", () => {
  ui.setResult(WATCH_ONLY_WALLET, false);
  const html = ui.hodlSaveRecoveryControl();
  assert.match(html, /data-wallet-dat-birthday/);
  assert.match(html, /<option value="genesis" selected>Recovering keys/);
  assert.match(html, /<option value="now">New keys/);
  // The tradeoff and the manual repair path are explained next to the button.
  assert.match(html, /wallet-dat-birthday-help/);
  assert.match(html, /rescanblockchain 0/);
  // The app reset keeps a stale "new keys" choice out of later derivations.
  assert.match(app, /function hodlCalculateKey\(progress\) \{\s*hodlSetWorkspaceError\("key", null\);\s*\n?[^}]*hodlWalletDatBirthday = "genesis";/);
  assert.match(app, /hodlWalletDatBirthday === "now" \? Math\.floor\(Date\.now\(\) \/ 1000\) : 0/);
});

test("binding attaches the download to #download-wallet-dat and tolerates missing elements", () => {
  ui.setResult(WATCH_ONLY_WALLET, false);
  assert.doesNotThrow(() => ui.hodlBindWalletResultActions());

  const button = {
    id: "download-wallet-dat",
    listeners: {},
    cloneNode() { return { ...this, id: this.id, listeners: {} }; },
    replaceWith(node) { ui.elements.set(node.id, node); },
    addEventListener(type, fn) { this.listeners[type] = fn; },
    click() { this.listeners.click?.(); },
  };
  ui.elements.set("download-wallet-dat", button);
  ui.hodlBindWalletResultActions();
  ui.captured.name = "";
  ui.elements.get("download-wallet-dat").click();
  assert.equal(ui.captured.name, "watch-only-wallet.dat");
  ui.elements.clear();
});

// --- Bitcoin Core integration (skipped where bitcoind is not installed) ----
//
// For every chain the header picker advertises, a fresh bitcoind on that
// chain must load the generated wallet.dat, and the signing variant must
// hand out the chain's own address form — including regtest's bcrt1… —
// because the SQLite application id and the bestblock locator are
// chain-specific (issue #329). A file carrying another chain's metadata must
// be refused. CI runners and the dev image skip this; run it where Bitcoin
// Core is installed (verified with v31.1.0).
const BITCOIND = (() => {
  const daemon = spawnSync("bitcoind", ["--version"], { stdio: "pipe" });
  const cli = spawnSync("bitcoin-cli", ["--version"], { stdio: "pipe" });
  return daemon.status === 0 && cli.status === 0;
})();

// Re-version every extended key in a descriptor (tpub<->xpub and tprv<->xprv
// payloads have the same layout) and re-checksum it — what the app does when
// the mainnet family re-labels the same key material.
const reversionDescriptor = (descriptor, publicVersion, privateVersion) => {
  const body = descriptor
    .slice(0, descriptor.lastIndexOf("#"))
    .replace(/[txyzuv](?:prv|pub)[1-9A-HJ-NP-Za-km-z]{90,}/g, (key) => {
      const raw = b58checkDecode(key).slice();
      const version = key.slice(1, 4) === "prv" ? privateVersion : publicVersion;
      raw[0] = (version >>> 24) & 255;
      raw[1] = (version >>> 16) & 255;
      raw[2] = (version >>> 8) & 255;
      raw[3] = version & 255;
      return b58checkEncode(raw);
    });
  return `${body}#${descriptorChecksum(body)}`;
};

const CHAIN_FIXTURES = {
  mainnet: { flag: "", subdir: ".", bech32Prefix: "bc1q" },
  testnet: { flag: "-testnet", subdir: "testnet3", bech32Prefix: "tb1q" },
  signet: { flag: "-signet", subdir: "signet", bech32Prefix: "tb1q" },
  regtest: { flag: "-regtest", subdir: "regtest", bech32Prefix: "bcrt1q" },
};

// The wallet the app exports for each chain: the reference key material,
// versioned the way that chain's encoding family versions it.
const chainWallets = (network) => {
  const toMainnet = (descriptor) => reversionDescriptor(descriptor, 0x0488b21e, 0x0488ade4);
  const asChain = (descriptors) => descriptors.map((d) => (network === "mainnet" ? toMainnet(d) : d));
  return {
    watch: { kind: "hd", network, accounts: makeAccounts(asChain(REF_PUBLIC_DESCRIPTORS), new Array(8).fill(null)) },
    priv: { kind: "hd", network, accounts: makeAccounts(asChain(REF_PRIVATE_PUBLIC_FORMS), asChain(REF_PRIVATE_DESCRIPTORS)) },
  };
};

// An OS-assigned localhost port keeps parallel or repeated runs from
// colliding with a real node.
const freePort = () =>
  new Promise((resolve, reject) => {
    const server = createServer();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address();
      server.close(() => resolve(port));
    });
  });

const sleepSync = (ms) => Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);

// Boots a fresh node for the chain, runs `body(cli)` where
// cli(...rpcArgs) returns the parsed JSON result (asserting success), and
// always shuts the node down again.
const withChainNode = async (network, body) => {
  const fixture = CHAIN_FIXTURES[network];
  const port = await freePort();
  const datadir = mkdtempSync(join(tmpdir(), `entropylab-bitcoind-${network}-`));
  const flagArgs = fixture.flag ? [fixture.flag] : [];
  const cliArgs = [...flagArgs, `-datadir=${datadir}`, "-rpcuser=el", "-rpcpassword=el", `-rpcport=${port}`];
  const cli = (args, { check = true } = {}) => {
    const run = spawnSync("bitcoin-cli", [...cliArgs, ...args], { encoding: "utf8", maxBuffer: 1 << 22 });
    if (check && run.status !== 0) throw new Error(`bitcoin-cli ${args[0]} failed on ${network}: ${run.stderr.trim()}`);
    return run;
  };
  try {
    execFileSync("bitcoind", [...flagArgs, `-datadir=${datadir}`, "-listen=0", "-connect=0", "-server", "-rpcuser=el", "-rpcpassword=el", `-rpcport=${port}`, "-daemon"], { stdio: "pipe" });
    cli(["-rpcwait", "getblockchaininfo"]);
    await body((args, options) => cli(args, options), join(datadir, fixture.subdir, "wallets"));
  } finally {
    spawnSync("bitcoin-cli", [...cliArgs, "stop"], { stdio: "pipe" });
    // stop returns before the process exits; wait for the RPC to go quiet so
    // the datadir removal cannot race a late flush.
    for (let waited = 0; waited < 300; waited++) {
      if (cli(["getblockchaininfo"], { check: false }).status !== 0) break;
      sleepSync(100);
    }
    rmSync(datadir, { recursive: true, force: true });
  }
};

for (const network of Object.keys(CHAIN_FIXTURES)) {
  test(`bitcoind on ${network} loads the generated wallet.dat`, { skip: !BITCOIND, timeout: 120000 }, async () => {
    const { buildWalletDat } = loadModule();
    const wallets = chainWallets(network);
    const watchBytes = buildWalletDat(wallets.watch, false, deps, 0);
    const privBytes = buildWalletDat(wallets.priv, true, deps, 0);
    await withChainNode(network, (cli, walletsDir) => {
      for (const [name, bytes] of [["elwatch", watchBytes], ["elpriv", privBytes]]) {
        mkdirSync(join(walletsDir, name), { recursive: true });
        writeFileSync(join(walletsDir, name, "wallet.dat"), bytes);
        assert.equal(JSON.parse(cli(["loadwallet", name]).stdout).name, name, `${network} refused its ${name} wallet`);
      }
      const watchInfo = JSON.parse(cli(["-rpcwallet=elwatch", "getwalletinfo"]).stdout);
      assert.equal(watchInfo.format, "sqlite");
      assert.equal(watchInfo.descriptors, true);
      assert.equal(watchInfo.private_keys_enabled, false);
      const privInfo = JSON.parse(cli(["-rpcwallet=elpriv", "getwalletinfo"]).stdout);
      assert.equal(privInfo.private_keys_enabled, true);
      // The signing wallet hands out the chain's own SegWit address: bc1q… on
      // mainnet, tb1q… on testnet AND signet, bcrt1q… on regtest.
      const address = cli(["-rpcwallet=elpriv", "getnewaddress", "", "bech32"]).stdout.trim();
      assert.ok(address.startsWith(CHAIN_FIXTURES[network].bech32Prefix), `${network} address ${address} has the wrong HRP`);
      if (network === "regtest") {
        // The regression from issue #329: a file built with testnet metadata
        // is not a regtest wallet and must be refused.
        mkdirSync(join(walletsDir, "elwrong"), { recursive: true });
        writeFileSync(join(walletsDir, "elwrong", "wallet.dat"), buildWalletDat(chainWallets("testnet").watch, false, deps, 0));
        assert.notEqual(cli(["loadwallet", "elwrong"], { check: false }).status, 0, "a testnet-magic wallet loaded on regtest");
      }
    });
  });
}
