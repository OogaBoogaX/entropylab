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
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { HDKey } from "@scure/bip32";
import { mnemonicToSeedSync } from "@scure/bip39";
import { canonicalizeWatchDescriptor } from "../src/js/core-importdescriptors.js";
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
import { BITCOIND, CHAIN_FIXTURES, waitForChainNodeExit, withChainNode } from "./bitcoind-harness.mjs";

const sqliteSrc = read("src/js/sqlite-writer.js");
const walletSrc = read("src/js/wallet-export.js");
const app = read("src/js/app.js");
// Absolute file URL into src/js/, for the real export modules the app's msig
// handlers call (the harness writes its module outside the source tree).
const srcUrl = (name) => pathToFileURL(join(dirname(fileURLToPath(import.meta.url)), "..", "src/js", name)).href;


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

// AR-03: a window starting at 1 or 2 exports branches beyond 0/1. Each of
// them needs its own private descriptor, or the wallet.dat has a public
// descriptor with no walletdescriptorkey record and Core cannot sign for it
// (or, with no private material at all, is filed as watch-only).
test("a private export carries a key record for every branch of a non-default window (AR-03)", () => {
  const withBranch = (descriptor, branch) => {
    const body = descriptor.slice(0, descriptor.lastIndexOf("#")).replace(/\/\d+\/\*/, `/${branch}/*`);
    return `${body}#${descriptorChecksum(body)}`;
  };
  const base = REF_PRIVATE_DESCRIPTORS[6]; // wpkh account tprv, /0/*
  const accountSecret = bytesToHex(b58checkDecode(base.match(/tprv[1-9A-HJ-NP-Za-km-z]+/)[0]).slice(46, 78));
  const accountPubkey = bytesToHex(publicKeyForPrivate(hexToBytes(accountSecret)));
  for (const start of [1, 2]) {
    const addressBranches = [start, start + 1].map((branch) => {
      const privateDescriptor = withBranch(base, branch);
      return { branch, publicDescriptor: publicFormOf(privateDescriptor), privateDescriptor };
    });
    const wallet = { kind: "hd", network: "regtest", accounts: [{ def: { id: "bip84" }, branchStart: start, addressBranches }] };
    const records = moduleRecords(wallet, true, REF_CREATION_TIME), state = `window ${start}/${start + 1}`;
    assert.equal(descriptorIds(records).length, 2, `${state}: both branches need a descriptor record`);
    const keyRecords = [...records.entries()].filter(([key]) => key.includes("77616c6c657464657363726970746f726b6579"));
    assert.equal(keyRecords.length, 2, `${state}: one key record per exported branch`);
    for (const [key, value] of keyRecords) {
      assert.ok(key.endsWith("21" + accountPubkey), `${state}: the key record names the account key`);
      assert.ok(value.includes(accountSecret), `${state}: the key record carries the account secret`);
    }
    // DESCRIPTORS | BLANK, not DESCRIPTORS | BLANK | DISABLE_PRIVATE_KEYS.
    assert.equal(records.get("05666c616773"), "0000000006000000", `${state}: the file advertises private keys`);
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

test("a branch window starting above 0 exports every derived branch as external", () => {
  // The picker can derive branches {1, 2}; the old [0, 1] loop exported only
  // branch 1 and filed it as change, so Core watched no receive chain.
  const { walletDescriptorUnits } = loadModule();
  const wallet = structuredClone(WATCH_ONLY_WALLET);
  wallet.accounts = [wallet.accounts[0]];
  wallet.accounts[0].branchStart = 1;
  wallet.accounts[0].addressBranches = [
    { branch: 1, publicDescriptor: REF_PUBLIC_DESCRIPTORS[0], rows: [{ index: 0 }] },
    { branch: 2, publicDescriptor: REF_PUBLIC_DESCRIPTORS[1], rows: [{ index: 0 }] },
  ];
  const units = walletDescriptorUnits(wallet, false);
  assert.equal(units.length, 2, "both derived branches must be exported");
  assert.deepEqual(units.map((unit) => unit.descriptor), REF_PUBLIC_DESCRIPTORS.slice(0, 2));
  assert.deepEqual(units.map((unit) => unit.internal), [false, false], "branches 1 and 2 are not Core's change chain");
});

test("button gating: HD wallets with descriptors, and msig watch-only", () => {
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
  // The wallet keeps its spending descriptors as key material (#546 B2); the
  // export view carries them as text for the check and the file.
  assert.match(app, /withSecrets = includePrivate && hodlWalletExport\.hasPrivateDescriptors\(hodlWalletExportView\(hodlWalletResult\)\)/);
  assert.match(app, /walletDatButtonLabel\(withSecrets\)/);
  assert.match(app, /exported = hodlWalletResult\.kind !== "msig" && hodlRevealPrivate \? hodlWalletExportView\(hodlWalletResult\) : hodlWalletResult/);
  assert.match(app, /withSecrets = hodlWalletResult\.kind !== "msig" && hodlRevealPrivate && hodlWalletExport\.hasPrivateDescriptors\(exported\)/);
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

// --- watch-only multisig ----------------------------------------------------

const msigSeed = mnemonicToSeedSync(
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
);
const msigMaster = HDKey.fromMasterSeed(msigSeed);
const msigFingerprint = msigMaster.fingerprint.toString(16).padStart(8, "0");
const msigNode = (account) => msigMaster.derive(`m/48'/0'/${account}'/2'`);
const msigKey = (account) => {
  const node = msigNode(account);
  return `[${msigFingerprint}/48h/0h/${account}h/2h]${node.publicExtendedKey}`;
};
const msigBody = (branch) => `wsh(sortedmulti(2,${msigKey(0)}/${branch}/*,${msigKey(1)}/${branch}/*,${msigKey(2)}/${branch}/*))`;
const msigDesc = (branch) => `${msigBody(branch)}#${descriptorChecksum(msigBody(branch))}`;
const MSIG_WALLET = {
  kind: "msig",
  network: "mainnet",
  script: "p2wsh",
  m: 2,
  n: 3,
  receiveDescriptor: msigDesc(0),
  changeDescriptor: msigDesc(1),
  receive: [{ index: 0 }, { index: 1 }],
  change: [{ index: 0 }, { index: 1 }],
};

// BIP 45 puts two steps between the key and the wildcard ("…/0/0/*"). The
// wallet.dat exporter reads one branch step above the wildcard and the BIP 388
// builder only rewrites "/0/*" and "/1/*", so both refuse that shape while the
// Core importdescriptors JSON still handles it. The controls must follow suit
// instead of only failing on click.
const bip45Body = `wsh(sortedmulti(1,${msigKey(0)}/0/0/*))`;
const BIP45_WALLET = {
  ...MSIG_WALLET,
  receiveDescriptor: `${bip45Body}#${descriptorChecksum(bip45Body)}`,
  changeDescriptor: `${bip45Body}#${descriptorChecksum(bip45Body)}`,
};

test("an unsupported descriptor tail is reported, not left to throw on click", () => {
  const { walletDatSupported, bip388Supported } = loadModule();
  assert.equal(walletDatSupported(MSIG_WALLET), true, "a /0/* /1/* multisig is still exportable");
  assert.equal(walletDatSupported(WATCH_ONLY_WALLET), true);
  assert.equal(walletDatSupported(BIP45_WALLET), false, "wallet.dat cannot place a two-step tail");
  assert.equal(walletDatSupported({ kind: "hd", network: "mainnet", accounts: [] }), false, "nothing to export");
  assert.equal(bip388Supported(MSIG_WALLET), true);
  assert.equal(bip388Supported(BIP45_WALLET), false, "BIP 388 only rewrites /0/* and /1/*");
});

test("a kept 'now' birthday becomes 0 for a BIP 45 Core JSON export", () => {
  ui.setResult(MSIG_WALLET, false);
  ui.setWalletDatBirthday("now");
  ui.setResult(BIP45_WALLET, false);
  const imported = JSON.parse(ui.hodlMsigCoreImportDescriptorsJson());
  assert.equal(imported.length, 2);
  for (const record of imported) assert.equal(record.timestamp, 0, "recovery of an old BIP 45 wallet must scan from genesis");
  ui.setResult(MSIG_WALLET, false);
  for (const record of JSON.parse(ui.hodlMsigCoreImportDescriptorsJson())) assert.equal(record.timestamp, "now", "a supported wallet keeps the choice");
  ui.setWalletDatBirthday("genesis");
});

test("a BIP 45 result hides the wallet.dat and BIP 388 controls but keeps Core JSON", () => {
  ui.setResult(BIP45_WALLET, false);
  const json = ui.hodlMsigCoreImportDescriptorsMarkup();
  assert.match(json, /id="msig-save-importdescriptors"/);
  assert.match(json, /id="msig-copy-importdescriptors"/);
  assert.doesNotMatch(json, /id="msig-download-wallet-dat"/);
  assert.match(json, /data-wallet-dat-birthday/, "the Core JSON timestamp uses the birthday, so its picker stays");
  assert.match(json, /id="msig-birthday-help"/, "and so does the recovery warning");
  assert.equal(ui.msigBip388Markup(), "");

  ui.setResult(MSIG_WALLET, false);
  assert.match(ui.hodlMsigCoreImportDescriptorsMarkup(), /id="msig-download-wallet-dat"/);
  assert.match(ui.msigBip388Markup(), /id="msig-save-bip388"/);
});

// The writer reads every co-signer's tail, not only the first: the Multisig
// station honours a co-signer's trailing path ("…xpub/5" composes as
// "…xpub/5/0/*"), so one deep key after the first must hide the controls too.
const mixedTailBody = (branch) => `wsh(sortedmulti(2,${msigKey(0)}/${branch}/*,${msigKey(1)}/5/${branch}/*,${msigKey(2)}/${branch}/*))`;
const MIXED_TAIL_WALLET = {
  ...MSIG_WALLET,
  receiveDescriptor: `${mixedTailBody(0)}#${descriptorChecksum(mixedTailBody(0))}`,
  changeDescriptor: `${mixedTailBody(1)}#${descriptorChecksum(mixedTailBody(1))}`,
};

test("a deep tail on a later co-signer is unsupported too (R1003-2)", () => {
  const { walletDatSupported, bip388Supported, buildWalletRecords } = loadModule();
  assert.throws(() => buildWalletRecords(MIXED_TAIL_WALLET, false, msigDeps, 0), /unsupported descriptor path shape/, "the writer refuses the second co-signer's tail");
  assert.equal(walletDatSupported(MIXED_TAIL_WALLET), false);
  assert.equal(bip388Supported(MIXED_TAIL_WALLET), false);

  ui.setResult(MIXED_TAIL_WALLET, false);
  const json = ui.hodlMsigCoreImportDescriptorsMarkup();
  assert.match(json, /id="msig-save-importdescriptors"/, "Core JSON still exports the shape");
  assert.doesNotMatch(json, /id="msig-download-wallet-dat"/);
  assert.equal(ui.msigBip388Markup(), "");
  ui.setResult(MSIG_WALLET, false);
});

const msigDeps = {
  ...deps,
  canonicalizeDescriptor: (descriptor) => canonicalizeWatchDescriptor(descriptor, { decode: b58checkDecode, encode: b58checkEncode }),
};

test("msig watch-only export has descriptors, never private keys, names the policy", () => {
  const { hasDescriptors, hasPrivateDescriptors, walletDatFilename, walletDescriptorUnits, buildWalletRecords } = loadModule();
  assert.equal(hasDescriptors(MSIG_WALLET), true);
  assert.equal(hasPrivateDescriptors(MSIG_WALLET), false);
  assert.equal(walletDatFilename(MSIG_WALLET, true), "entropylab-msig-2of3-watch-only-wallet.dat");
  assert.equal(walletDatFilename(MSIG_WALLET, false), "entropylab-msig-2of3-watch-only-wallet.dat");
  const units = walletDescriptorUnits(MSIG_WALLET, true);
  assert.equal(units.length, 2);
  assert.ok(units.every((unit) => unit.privateDescriptor == null && unit.multiKey && unit.type === 2));
  const records = buildWalletRecords(MSIG_WALLET, true, msigDeps, 0);
  const names = records.map(([key]) => new TextDecoder().decode(key.slice(1, 1 + key[0])));
  assert.equal(names.filter((name) => name === "walletdescriptor").length, 2);
  assert.equal(names.filter((name) => name === "walletdescriptorcache").length, 6);
  assert.equal(names.filter((name) => name === "walletdescriptorkey").length, 0);
  assert.equal(names.filter((name) => name === "activeexternalspk").length, 1);
  assert.equal(names.filter((name) => name === "activeinternalspk").length, 1);
  const blob = records.map(([, value]) => Buffer.from(value).toString("latin1")).join("");
  assert.doesNotMatch(blob, /[xyztuvYZUV]prv/);
  assert.doesNotMatch(blob, /abandon/);
});

test("msig cache parents match independent CKD of each co-signer", () => {
  const { buildWalletRecords } = loadModule();
  const records = buildWalletRecords(MSIG_WALLET, false, msigDeps, 0);
  const cachePrefix = "15" + "77616c6c657464657363726970746f726361636865";
  const caches = records
    .map(([key, value]) => [bytesToHex(key), bytesToHex(value)])
    .filter(([key]) => key.startsWith(cachePrefix));
  assert.equal(caches.length, 6);
  const expected = [];
  for (const branch of [0, 1]) {
    for (const account of [0, 1, 2]) {
      expected.push("4a" + bytesToHex(deriveBranchBody(msigNode(account).publicExtendedKey, branch)));
    }
  }
  const got = caches.map(([, value]) => value).sort();
  assert.deepEqual(got, [...expected].sort());
});

const cacheKeyIndex = (keyHex) => {
  const bytes = hexToBytes(keyHex);
  const offset = bytes.length - 4;
  return bytes[offset] | (bytes[offset + 1] << 8) | (bytes[offset + 2] << 16) | (bytes[offset + 3] << 24);
};

const readDescriptorRange = (value) => {
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

test("msig watch-only nextIndex is 0 so first getnewaddress is receive 0", () => {
  const { walletDescriptorUnits, buildWalletRecords } = loadModule();
  const units = walletDescriptorUnits(MSIG_WALLET, false);
  assert.ok(units.every((unit) => unit.nextIndex === 0 && unit.rangeStart === 0));
  const records = buildWalletRecords(MSIG_WALLET, false, msigDeps, 0);
  const descriptorValues = records
    .filter(([key]) => key[0] === 16 && new TextDecoder().decode(key.slice(1, 17)) === "walletdescriptor")
    .map(([, value]) => Buffer.from(value));
  assert.equal(descriptorValues.length, 2);
  for (const value of descriptorValues) {
    const range = readDescriptorRange(value);
    assert.equal(range.nextIndex, 0);
    assert.equal(range.rangeStart, 0);
  }
});

const NUMS = "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0";
const msigTrNode = (account) => msigMaster.derive(`m/86'/0'/${account}'`);
const msigTrKey = (account) => {
  const node = msigTrNode(account);
  return `[${msigFingerprint}/86h/0h/${account}h]${node.publicExtendedKey}`;
};
const msigTrBody = (branch) => `tr(${NUMS},sortedmulti_a(2,${msigTrKey(0)}/${branch}/*,${msigTrKey(1)}/${branch}/*,${msigTrKey(2)}/${branch}/*))`;
const msigTrDesc = (branch) => `${msigTrBody(branch)}#${descriptorChecksum(msigTrBody(branch))}`;
const MSIG_TR_WALLET = {
  kind: "msig",
  network: "mainnet",
  script: "p2tr",
  m: 2,
  n: 3,
  receiveDescriptor: msigTrDesc(0),
  changeDescriptor: msigTrDesc(1),
  receive: [{ index: 0 }, { index: 1 }],
  change: [{ index: 0 }, { index: 1 }],
};

test("msig Taproot cache indexes skip the NUMS internal key", () => {
  const { buildWalletRecords } = loadModule();
  const cachePrefix = "15" + "77616c6c657464657363726970746f726361636865";
  const nativeIndexes = buildWalletRecords(MSIG_WALLET, false, msigDeps, 0)
    .map(([key]) => bytesToHex(key))
    .filter((key) => key.startsWith(cachePrefix))
    .map(cacheKeyIndex);
  assert.deepEqual([...new Set(nativeIndexes)].sort((a, b) => a - b), [0, 1, 2]);

  const tap = buildWalletRecords(MSIG_TR_WALLET, false, msigDeps, 0);
  const tapCaches = tap
    .map(([key, value]) => [bytesToHex(key), bytesToHex(value)])
    .filter(([key]) => key.startsWith(cachePrefix));
  assert.equal(tapCaches.length, 6);
  const tapIndexes = tapCaches.map(([key]) => cacheKeyIndex(key));
  assert.deepEqual([...new Set(tapIndexes)].sort((a, b) => a - b), [1, 2, 3]);
  assert.equal(tapIndexes.includes(0), false);

  const expected = [];
  for (const branch of [0, 1]) {
    for (const account of [0, 1, 2]) {
      expected.push("4a" + bytesToHex(deriveBranchBody(msigTrNode(account).publicExtendedKey, branch)));
    }
  }
  assert.deepEqual(tapCaches.map(([, value]) => value).sort(), [...expected].sort());
});

test("msig Zpub is rewritten to xpub before it is stored", () => {
  const { buildWalletRecords } = loadModule();
  const raw = b58checkDecode(msigNode(0).publicExtendedKey);
  raw[0] = 0x02; raw[1] = 0xaa; raw[2] = 0x7e; raw[3] = 0xd3;
  const zpub = b58checkEncode(raw);
  assert.match(zpub, /^Zpub/);
  const slipBody = `wsh(sortedmulti(1,[${msigFingerprint}/48h/0h/0h/2h]${zpub}/0/*))`;
  const wallet = {
    kind: "msig",
    network: "mainnet",
    script: "p2wsh",
    receiveDescriptor: `${slipBody}#${descriptorChecksum(slipBody)}`,
  };
  assert.throws(() => loadModule().buildWalletRecords(wallet, false, deps, 0), /xpub\/tpub|Base58Check codec/);
  const records = buildWalletRecords(wallet, false, msigDeps, 0);
  const stored = records
    .filter(([key]) => new TextDecoder().decode(key.slice(1, 1 + key[0])) === "walletdescriptor")
    .map(([, value]) => new TextDecoder().decode(value));
  assert.equal(stored.length, 1);
  assert.match(stored[0], /xpub/);
  assert.doesNotMatch(stored[0], /Zpub/);
});

test("msig refuses an extended private key", () => {
  const { buildWalletRecords } = loadModule();
  const body = `wsh(sortedmulti(1,${msigNode(0).privateExtendedKey}/0/*))`;
  const wallet = {
    kind: "msig",
    network: "mainnet",
    script: "p2wsh",
    receiveDescriptor: `${body}#${descriptorChecksum(body)}`,
  };
  assert.throws(() => buildWalletRecords(wallet, false, msigDeps, 0), /private key/);
});

test("generated msig watch-only wallet.dat verifies with real SQLite", { skip: !PYTHON_SQLITE }, () => {
  const { buildWalletDat } = loadModule();
  const bytes = buildWalletDat(MSIG_WALLET, false, msigDeps, 0);
  const back = sqliteReadBack(bytes);
  assert.equal(back.integrity, "ok");
  const joined = back.rows.map(([, value]) => Buffer.from(value, "hex").toString("latin1")).join("");
  assert.doesNotMatch(joined, /[xyztuvYZUV]prv/);
  assert.match(joined, /wsh\(sortedmulti\(2,/);
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
  assert.match(app, /hodlWalletExport\.buildWalletDat\(\s*exported\s*,\s*withSecrets\s*,\s*hodlWalletDatDeps\(\s*\)\s*,\s*creationTime\s*\)/);
  assert.match(app, /hodlWalletExport\.walletDatFilename\(hodlWalletResult, withSecrets\)/);
  assert.match(app, /document\.getElementById\("download-wallet-dat"\)/);
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
// The UI harness executes the real app.js controls and download handler in a
// module scope where the vendor globals they read (tr, Cs, sr, le, Gt, xe,
// cr) are backed by the reference implementations above. The export modules
// the msig handlers reach (policy sheet, BIP 388 policy, Core JSON) are the
// app's own, imported from src/ — only the browser edges (clipboard, print,
// QR, workspace error line) are stubbed and recorded.
const harnessSource = `
import { createHash, createHmac } from "node:crypto";
import { canPrintPolicySheet, policySheetFilename, policySheetHtml, policySheetText } from ${JSON.stringify(srcUrl("msig-policy-sheet.js"))};
import { buildBip388PolicyText, bip388PolicyFilename } from ${JSON.stringify(srcUrl("bip388-policy.js"))};
import { buildImportDescriptorsJson, canonicalizeWatchDescriptor, coreImportDescriptorsFilename } from ${JSON.stringify(srcUrl("core-importdescriptors.js"))};
const FIELD_P = ${FIELD_P.toString()}n;
const ORDER_N = ${ORDER_N.toString()}n;
const BASE_G = [${BASE_G[0].toString()}n, ${BASE_G[1].toString()}n];
const B58 = ${JSON.stringify(B58)};
const INPUT_CHARSET = ${JSON.stringify(INPUT_CHARSET)};
const CHECKSUM_CHARSET = ${JSON.stringify(CHECKSUM_CHARSET)};
${[modPow, pointAdd, pointMul, serPub, unserPub, bigintBytes, b58encode, b58checkDecode, b58checkEncode, sha256, ripemd160, bytesToHex, descriptorChecksum, deriveBranchBody, publicKeyForPrivate, hdNodeFrom].map((fn) => `const ${fn.name} = ${fn.toString()};`).join("\n")}
const captured = { blob: null, name: "" };
const elements = new Map();
const copies = [], calls = [];
const copyText = (text) => { copies.push(String(text)); return Promise.resolve(false); };
const hodlTText = (source) => source;
const hodlQrSvg = () => "";
const hodlSetWorkspaceError = (scope, spec) => { calls.push(["workspace-error", scope, spec]); };
const hodlErrorSpecFrom = (error) => ({ raw: String(error?.message ?? error) });
const window = { print: () => { calls.push(["print"]); }, addEventListener() {}, removeEventListener() {} };
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
  body: { appendChild() {}, classList: { add() {}, remove() {} } },
};
let hodlWalletResult = null, hodlRevealPrivate = false, hodlWalletDatBirthday = "genesis";
const hodlSha256 = (bytes) => sha256(bytes);
const hodlDescriptorChecksum = descriptorChecksum;
const hodlBase58Check = { decode: b58checkDecode, encode: b58checkEncode };
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
// Tolerates an app.js without this markup function so the pre-fix tree fails
// on the render assertions, not on the harness import.
const msigBip388Markup = typeof hodlMsigBip388Markup === "function" ? hodlMsigBip388Markup : () => "";
const setResult = (value, flag) => { hodlWalletResult = value; hodlRevealPrivate = flag; };
const setWalletDatBirthday = (value) => { hodlWalletDatBirthday = value; };
export { captured, elements, copies, calls, hodlMsigCoreImportDescriptorsJson, hodlPrivateDataControls, hodlSaveRecoveryControl, hodlDownloadWalletDat, hodlBindWalletResultActions, hodlMsigCoreImportDescriptorsMarkup, hodlMsigPolicySheetMarkup, msigBip388Markup, hodlBindMsigCoreImportDescriptors, setResult, setWalletDatBirthday };
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
  assert.match(app, /function hodlCalculateKey\(progress, action = "derive"\) \{\s*hodlSetWorkspaceError\("key", null\);\s*\n?[^}]*hodlWalletDatBirthday = "genesis";/);
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

// --- Audit B7: the msig result renders and wires every documented export ----
//
// README.md/llms.txt promise the watch-only wallet.dat, the importdescriptors
// JSON, the one-page policy sheet and the BIP 388 policy for a derived
// multisig; B7a found the wallet.dat/policy-sheet/BIP-388 controls bound but
// never rendered, and B7b found the JSON range unable to cover a displayed
// address window above index 1000.

// A displayable 2-of-3 result, shaped the way MS Station's hodlWalletResult
// carries one: the same keys as MSIG_WALLET, with a first receive row the
// policy sheet can print. BIP173's published example address stands in for
// the derived row (the sheet's content layout is pinned in
// msig-policy-sheet.test.mjs; here only the wiring matters).
const MSIG_VIEW_WALLET = {
  ...MSIG_WALLET,
  addressStart: 0,
  receive: [
    { index: 0, address: "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq", path: "m/48'/0'/0'/2'/0/0" },
    { index: 1 },
  ],
};

const MSIG_EXPORT_CONTROLS = [
  "msig-save-importdescriptors",
  "msig-copy-importdescriptors",
  "msig-download-wallet-dat",
  "msig-print-policy-sheet",
  "msig-save-policy-sheet",
  "msig-copy-bip388",
  "msig-save-bip388",
];

// An element double for the msig export controls: the binder hardens each
// button through cloneNode/replaceWith before addEventListener, so the double
// replays both steps and keeps the attached listener for a click.
const stubControl = (id) => ({
  id,
  listeners: {},
  classList: { add() {}, remove() {} },
  isConnected: false,
  textContent: "",
  cloneNode() { return { ...this, listeners: {} }; },
  replaceWith(node) { ui.elements.set(node.id, node); },
  addEventListener(type, fn) { this.listeners[type] = fn; },
  click() { this.listeners.click?.(); },
});

test("a derived msig renders every documented export control (audit B7a)", () => {
  ui.setResult(MSIG_VIEW_WALLET, false);
  const html = `${ui.hodlMsigCoreImportDescriptorsMarkup()}\n${ui.hodlMsigPolicySheetMarkup()}\n${ui.msigBip388Markup()}`;
  for (const id of MSIG_EXPORT_CONTROLS) assert.ok(html.includes(`id="${id}"`), `the rendered msig output is missing #${id}`);
});

test("the msig export binder tolerates elements that were never rendered", () => {
  ui.setResult(MSIG_VIEW_WALLET, false);
  assert.doesNotThrow(() => ui.hodlBindMsigCoreImportDescriptors());
});

test("every rendered msig export control fires its handler through the real binder (audit B7a)", () => {
  ui.setResult(MSIG_VIEW_WALLET, false);
  for (const id of MSIG_EXPORT_CONTROLS) ui.elements.set(id, stubControl(id));
  ui.hodlBindMsigCoreImportDescriptors();

  // The Core JSON download carries the importdescriptors array...
  ui.captured.name = "";
  ui.elements.get("msig-save-importdescriptors").click();
  assert.equal(ui.captured.name, "entropylab-msig-2of3-importdescriptors.json");
  const saved = JSON.parse(ui.captured.blob.parts[0]);
  assert.equal(saved.length, 2);
  assert.equal(saved[0].internal, false);
  assert.equal(saved[1].internal, true);
  // ...and the copy variant hands the same entries to the clipboard.
  ui.elements.get("msig-copy-importdescriptors").click();
  assert.deepEqual(JSON.parse(ui.copies.at(-1)), saved);

  // The watch-only wallet.dat downloads through the app's own build path.
  ui.captured.name = "";
  ui.captured.blob = null;
  ui.elements.get("msig-download-wallet-dat").click();
  assert.equal(ui.captured.name, "entropylab-msig-2of3-watch-only-wallet.dat");
  assert.equal(ui.captured.blob.type, "application/octet-stream");
  assert.ok(ui.captured.blob.parts[0].length > 1000, "wallet.dat bytes were built");

  // The policy sheet prints and saves.
  ui.calls.length = 0;
  ui.elements.get("msig-print-policy-sheet").click();
  assert.deepEqual(ui.calls, [["print"]], "the print control must reach window.print");
  ui.captured.name = "";
  ui.elements.get("msig-save-policy-sheet").click();
  assert.equal(ui.captured.name, "entropylab-msig-2of3-watch-only-policy.txt");
  assert.match(ui.captured.blob.parts[0], /WATCH-ONLY MULTISIG POLICY SHEET/);

  // The BIP 388 policy copies and saves (semantics checked in
  // bip388-policy.test.mjs; here the template proves the wiring).
  ui.elements.get("msig-copy-bip388").click();
  assert.match(ui.copies.at(-1), /descriptor_template: wsh\(sortedmulti\(2,@0\/\*\*,@1\/\*\*,@2\/\*\*\)\)/);
  ui.captured.name = "";
  ui.elements.get("msig-save-bip388").click();
  assert.equal(ui.captured.name, "entropylab-msig-2of3-bip388.txt");

  assert.deepEqual(ui.calls.filter(([name]) => name === "workspace-error"), []);
  ui.elements.clear();
});

test("the Core JSON download covers the displayed address window plus Core's lookahead (audit B7b)", () => {
  // The same arithmetic the wallet.dat records pin above: displayed receive
  // rows 5000..5002 are watched through 6002, start pinned to 0.
  ui.setResult({
    kind: "msig",
    network: "mainnet",
    script: "p2wsh",
    m: 2,
    n: 3,
    sorted: true,
    receiveDescriptor: MSIG_WALLET.receiveDescriptor,
    changeDescriptor: MSIG_WALLET.changeDescriptor,
    receive: [{ index: 5000 }, { index: 5001 }, { index: 5002 }],
    change: [{ index: 5000 }],
  }, false);
  for (const id of ["msig-save-importdescriptors", "msig-copy-importdescriptors"]) ui.elements.set(id, stubControl(id));
  ui.hodlBindMsigCoreImportDescriptors();
  ui.captured.blob = null;
  ui.elements.get("msig-save-importdescriptors").click();
  const entries = JSON.parse(ui.captured.blob.parts[0]);
  for (const entry of entries) assert.deepEqual(entry.range, [0, 6002], "saved JSON range");
  ui.elements.get("msig-copy-importdescriptors").click();
  for (const entry of JSON.parse(ui.copies.at(-1))) assert.deepEqual(entry.range, [0, 6002], "copied JSON range");
  ui.elements.clear();
});

test("the Core note qualifies its index-0 claim once the window starts deeper (audit B7b copy)", () => {
  ui.setResult(MSIG_VIEW_WALLET, false);
  assert.match(ui.hodlMsigCoreImportDescriptorsMarkup(), /index 0 here/);
  ui.setResult({
    ...MSIG_VIEW_WALLET,
    receive: [{ index: 5000, address: MSIG_VIEW_WALLET.receive[0].address, path: "m/48'/0'/0'/2'/0/5000" }],
    change: [{ index: 5000 }],
  }, false);
  const html = ui.hodlMsigCoreImportDescriptorsMarkup();
  assert.doesNotMatch(html, /index 0 here/);
  assert.match(html, /index 0/);
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



test("Core fixture cleanup stops at the PID-file boundary", () => {
  let checks = 0, sleeps = 0;
  assert.equal(waitForChainNodeExit("fixture.pid", () => ++checks < 3, () => sleeps++, 5), true);
  assert.equal(sleeps, 2);
  assert.equal(waitForChainNodeExit("fixture.pid", () => true, () => {}, 2), false);
});


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

test("bitcoind loads a generated msig watch-only wallet.dat", { skip: !BITCOIND, timeout: 120000 }, async () => {
  const { buildWalletDat } = loadModule();
  const wallet = {
    ...MSIG_WALLET,
    network: "regtest",
    receiveDescriptor: reversionDescriptor(MSIG_WALLET.receiveDescriptor, 0x043587cf, 0x04358394),
    changeDescriptor: reversionDescriptor(MSIG_WALLET.changeDescriptor, 0x043587cf, 0x04358394),
  };
  const bytes = buildWalletDat(wallet, true, msigDeps, 0);
  await withChainNode("regtest", (cli, walletsDir) => {
    mkdirSync(join(walletsDir, "elmsig"), { recursive: true });
    writeFileSync(join(walletsDir, "elmsig", "wallet.dat"), bytes);
    assert.equal(JSON.parse(cli(["loadwallet", "elmsig"]).stdout).name, "elmsig");
    const info = JSON.parse(cli(["-rpcwallet=elmsig", "getwalletinfo"]).stdout);
    assert.equal(info.format, "sqlite");
    assert.equal(info.descriptors, true);
    assert.equal(info.private_keys_enabled, false);
    const address = cli(["-rpcwallet=elmsig", "getnewaddress"]).stdout.trim();
    const expectedReceive = JSON.parse(cli(["deriveaddresses", wallet.receiveDescriptor, "[0,0]"]).stdout)[0];
    assert.equal(address, expectedReceive);
    const change = cli(["-rpcwallet=elmsig", "getrawchangeaddress"]).stdout.trim();
    const expectedChange = JSON.parse(cli(["deriveaddresses", wallet.changeDescriptor, "[0,0]"]).stdout)[0];
    assert.equal(change, expectedChange);
  });
});

test("bitcoind loads a generated msig Taproot watch-only wallet.dat", { skip: !BITCOIND, timeout: 120000 }, async () => {
  const { buildWalletDat } = loadModule();
  const wallet = {
    ...MSIG_TR_WALLET,
    network: "regtest",
    receiveDescriptor: reversionDescriptor(MSIG_TR_WALLET.receiveDescriptor, 0x043587cf, 0x04358394),
    changeDescriptor: reversionDescriptor(MSIG_TR_WALLET.changeDescriptor, 0x043587cf, 0x04358394),
  };
  const bytes = buildWalletDat(wallet, true, msigDeps, 0);
  await withChainNode("regtest", (cli, walletsDir) => {
    mkdirSync(join(walletsDir, "elmsigtr"), { recursive: true });
    writeFileSync(join(walletsDir, "elmsigtr", "wallet.dat"), bytes);
    assert.equal(JSON.parse(cli(["loadwallet", "elmsigtr"]).stdout).name, "elmsigtr");
    const info = JSON.parse(cli(["-rpcwallet=elmsigtr", "getwalletinfo"]).stdout);
    assert.equal(info.format, "sqlite");
    assert.equal(info.descriptors, true);
    assert.equal(info.private_keys_enabled, false);
    const address = cli(["-rpcwallet=elmsigtr", "getnewaddress", "", "bech32m"]).stdout.trim();
    const expectedReceive = JSON.parse(cli(["deriveaddresses", wallet.receiveDescriptor, "[0,0]"]).stdout)[0];
    assert.equal(address, expectedReceive);
    const change = cli(["-rpcwallet=elmsigtr", "getrawchangeaddress", "bech32m"]).stdout.trim();
    const expectedChange = JSON.parse(cli(["deriveaddresses", wallet.changeDescriptor, "[0,0]"]).stdout)[0];
    assert.equal(change, expectedChange);
  });
});
