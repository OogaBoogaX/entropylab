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
  const imported = JSON.parse(ui.hodlCoreImportDescriptorsJson());
  assert.equal(imported.length, 2);
  for (const record of imported) assert.equal(record.timestamp, 0, "recovery of an old BIP 45 wallet must scan from genesis");
  ui.setResult(MSIG_WALLET, false);
  for (const record of JSON.parse(ui.hodlCoreImportDescriptorsJson())) assert.equal(record.timestamp, "now", "a supported wallet keeps the choice");
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

test("a repeated co-signer key reads its own tail in each slot", () => {
  // Deep sweep of cb18b09 (GLM 5.3, Kimi K3, Muse Spark, Nemotron 3 Ultra,
  // DeepSeek V4.1): the tail of a repeated key was read from its first copy,
  // so "xpubA/0/*,xpubA/5/0/*" passed as two "/0/*" slots and the second
  // slot cached xpubA/0 as its parent instead of xpubA/5/0.
  const { walletDatSupported, buildWalletRecords } = loadModule();
  const body = (slots) => `wsh(sortedmulti(2,${slots.map(([account, tail]) => msigKey(account) + tail).join(",")}))`;
  const desc = (slots) => `${body(slots)}#${descriptorChecksum(body(slots))}`;
  const wallet = (receive, change) => ({ ...MSIG_WALLET, receiveDescriptor: desc(receive), changeDescriptor: desc(change) });
  // The two-step copy is refused in either order, as it is on its own.
  assert.equal(walletDatSupported(wallet([[0, "/0/*"], [0, "/5/0/*"], [2, "/0/*"]], [[0, "/1/*"], [0, "/5/1/*"], [2, "/1/*"]])), false);
  assert.equal(walletDatSupported(wallet([[0, "/5/0/*"], [0, "/0/*"], [2, "/0/*"]], [[0, "/5/1/*"], [0, "/1/*"], [2, "/1/*"]])), false);
  // Two one-step copies on different branches: each slot caches its own parent.
  const repeated = wallet([[0, "/0/*"], [0, "/2/*"], [2, "/0/*"]], [[0, "/1/*"], [0, "/3/*"], [2, "/1/*"]]);
  assert.equal(walletDatSupported(repeated), true);
  const cachePrefix = "15" + "77616c6c657464657363726970746f726361636865";
  const got = buildWalletRecords(repeated, false, msigDeps, 0)
    .map(([key, value]) => [bytesToHex(key), bytesToHex(value)])
    .filter(([key]) => key.startsWith(cachePrefix))
    .map(([key, value]) => `${cacheKeyIndex(key)}:${value}`);
  const parent = (account, branch) => "4a" + bytesToHex(deriveBranchBody(msigNode(account).publicExtendedKey, branch));
  const expected = [[0, 0, 0], [1, 0, 2], [2, 2, 0], [0, 0, 1], [1, 0, 3], [2, 2, 1]].map(([slot, account, branch]) => `${slot}:${parent(account, branch)}`);
  assert.deepEqual(got.sort(), expected.sort());
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
export { captured, elements, copies, calls, hodlCoreImportDescriptorsJson, hodlPrivateDataControls, hodlSaveRecoveryControl, hodlDownloadWalletDat, hodlBindWalletResultActions, hodlMsigCoreImportDescriptorsMarkup, hodlMsigPolicySheetMarkup, msigBip388Markup, hodlBindMsigCoreImportDescriptors, setResult, setWalletDatBirthday };
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
  assert.match(app, /function hodlCalculateKey\([^\n]*\) \{\s*hodlSetWorkspaceError\("key", null\);\s*\n?[^}]*hodlWalletDatBirthday = "genesis";/);
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
  for (const entry of entries) assert.deepEqual(entry.range, [0, entry.internal ? 6000 : 6002], "saved per-branch JSON range");
  ui.elements.get("msig-copy-importdescriptors").click();
  for (const entry of JSON.parse(ui.copies.at(-1))) assert.deepEqual(entry.range, [0, entry.internal ? 6000 : 6002], "copied per-branch JSON range");
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

// --- REQUIRE_BITCOIND: the interop CI job must fail, not skip --------------

// The "Bitcoin Core interop" CI job sets REQUIRE_BITCOIND=1 so a runner that
// lost its bitcoind fails instead of skipping every interop test. The gate
// lives at the harness's import, so these tests exercise it in child
// processes whose PATH decides what the probe finds. (Dynamic imports: this
// child-process plumbing is used nowhere else in this file.)
const importHarness = async (pathEnv, requireBitcoind) => {
  const { spawnSync } = await import("node:child_process");
  const { dirname, join } = await import("node:path");
  const { fileURLToPath, pathToFileURL } = await import("node:url");
  const harnessUrl = pathToFileURL(join(dirname(fileURLToPath(import.meta.url)), "bitcoind-harness.mjs")).href;
  const env = { ...process.env };
  for (const key of Object.keys(env)) if (key.toUpperCase() === "PATH" || key === "REQUIRE_BITCOIND") delete env[key];
  env.PATH = pathEnv;
  if (requireBitcoind) env.REQUIRE_BITCOIND = "1";
  return spawnSync(process.execPath, ["--input-type=module", "-e", `import ${JSON.stringify(harnessUrl)};`], { env, encoding: "utf8" });
};

const tempBinDir = async (label) => {
  const { mkdtempSync } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const { join } = await import("node:path");
  return mkdtempSync(join(tmpdir(), label));
};

const removeDir = async (dir) => {
  const { rmSync } = await import("node:fs");
  rmSync(dir, { recursive: true, force: true });
};

test("REQUIRE_BITCOIND=1 throws at import when bitcoind and bitcoin-cli are missing", async (t) => {
  const dir = await tempBinDir("entropylab-no-bitcoind-");
  t.after(() => removeDir(dir));
  const run = await importHarness(dir, true);
  assert.ifError(run.error);
  assert.notEqual(run.status, 0, "a runner without the binaries must fail, not skip");
  assert.match(run.stderr, /REQUIRE_BITCOIND=1/);
  assert.match(run.stderr, /bitcoind/);
});

test("without REQUIRE_BITCOIND a missing bitcoind still means skip, not failure", async (t) => {
  const dir = await tempBinDir("entropylab-no-bitcoind-");
  t.after(() => removeDir(dir));
  const run = await importHarness(dir, false);
  assert.ifError(run.error);
  assert.equal(run.status, 0, run.stderr);
});

// The positive case (both binaries on PATH) is the CI interop job itself.


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

// --- Stryker survivor coverage for src/js/wallet-export.js -----------------
//
// Equivalent mutants with no observable effect:
// - hex() validation/loop mutants at src/js/wallet-export.js:94/96: hex() is
//   only called with the valid constant DER templates at module load and is
//   not exported.
// - compactSize negative-length mutants at :125: compactSize is only called
//   with non-negative lengths from streamString and fixed record fields.
// - compactSize :128 `true` and `length < 0xffffffff`: they differ only for
//   lengths at or above 0xffffffff, which cannot be produced by a JS string.
// - tailsSupported :333 label string: the label only appears in an error that
//   tailsSupported catches and turns into false.
// - buildWalletRecords :437 DER length: the DER length is fixed by the
//   constants and the 33-byte pubkey check, so no input can make it differ
//   from 214.
// - buildWalletRecords :446 der.fill(0): der is a local buffer that is never
//   exposed after the record is built; removing the wipe has no observable
//   effect.
// Survivors left alive (need a valid fixture):
// - descriptorKeyTail `at < 0` -> `at <= 0`: a leading '#' makes
//   stripChecksum return an empty body, so `at` is -1 under both the check
//   and the mutant; `at === 0` needs the extended key to open the descriptor
//   body, which no valid BIP380 descriptor does (they open with a script
//   expression). The old checksum-marker test could not tell the two apart,
//   so it was deleted instead of kept as false coverage.
// - stripChecksum `hash >= 0` -> `hash > 0`: distinguished only by a
//   checksum marker at index 0, whose refusal is the same empty-body
//   accident.
// - descriptorKeyTail branch-level wildcard `$` alternative: needs a valid
//   fixture ending at the wildcard; valid descriptors close with `)`.
// - cacheKeyExpIndex `startsWith` -> `includes`: needs a valid fixture; the
//   only distinguishing input is an invalid nested wpkh(tr(...)).
// - PRIVATE_KEY `{90,}` quantifier and the prefix letters no fixture uses
//   (tprv/yprv/uprv/vprv/Yprv/Uprv): the only distinguishing inputs are
//   invalid short or misspelled keys. Removing the regex outright, or
//   breaking the xprv/Zprv prefixes it must catch, is pinned by the
//   multisig refusal tests below.
// - addBranch's duplicate/null/invalid-entry guards and the
//   `windowStart <= 0`/`windowStart <= 1` boundaries: the app never produces
//   duplicate branch entries, null or non-integer branch numbers, or a
//   window starting above the default without addressBranches. The old
//   tests pinned that such state is silently ignored (first-wins, a lone
//   change branch, zero units) — fail-open behaviour that must not be
//   enshrined — so they were deleted and these mutants stay alive until
//   the source fails closed.
// - buildWalletRecords HD xprv routing: needs a valid fixture or a fail-closed
//   HD-specific error; a watch-only export now refuses an HD xprv outright
//   (the private-key guard pinned above), so only a spending fixture can
//   kill the routing mutant. Left alive.
// - extendedKeyBody's 78-byte payload check: the shape guard decodes and
//   length-checks every descriptor key before any record is written, so a
//   base58Decode returning the wrong length is refused earlier with the
//   guard's own error and the check can no longer be reached.
// - buildWalletRecords' empty multisig pubs check ("no extended key found in
//   watch-only descriptor"): the shape guard requires every co-signer to be
//   an extended key and the private-key guard refuses an all-xprv key list,
//   so extractExtendedPubs can no longer come back empty for a descriptor
//   that reached the record builder.
// - branchRangeFromRows' row filter (null rows, indexes at or above
//   0x80000000): the old test pinned that malformed rows are silently
//   ignored and the range falls back to 0..1000 — fail-open — so it was
//   deleted rather than kept as false coverage; those boundaries stay alive
//   until the source fails closed. (Index 0 is still covered.)
// - walletDescriptorUnits' unknown-script account skip (the
//   `type === undefined` continue): the old assertion pinned that a
//   malformed account is silently omitted; left alive until the source
//   fails closed.

const validDescriptorWithLength = (target) => {
  const base = `wpkh([00000000]${XPUB_TAIL_4H}/0/*)`;
  const baseLength = base.length + 9; // # + 8-char checksum
  let needed = target - baseLength;
  assert.ok(needed >= 0, `target ${target} is shorter than the base descriptor`);
  let path = "";
  if (needed % 2 === 1) {
    path += "/0h";
    needed -= 3;
  }
  path += "/0".repeat(needed / 2);
  const body = `wpkh([00000000${path}]${XPUB_TAIL_4H}/0/*)`;
  assert.equal(body.length + 9, target, `descriptor length ${target}`);
  return `${body}#${descriptorChecksum(body)}`;
};

const mutantHdWallet = (descriptor, extra = {}) => ({
  kind: "hd",
  network: "mainnet",
  accounts: [{ def: { id: "bip84" }, receiveDescriptor: descriptor, ...extra }],
});

test("compactSize boundaries match Bitcoin CompactSize", () => {
  const { buildWalletRecords } = loadModule();
  const cases = [
    [252, "fc"],
    [253, "fdfd00"],
    [65535, "fdffff"],
    [65536, "fe00000100"],
  ];
  for (const [length, prefix] of cases) {
    const wallet = mutantHdWallet(validDescriptorWithLength(length));
    const records = buildWalletRecords(wallet, false, deps, 0);
    const record = records.find(([key]) => bytesToHex(key).startsWith(DESCRIPTOR_PREFIX));
    assert.ok(record, `descriptor record for length ${length}`);
    assert.ok(bytesToHex(record[1]).startsWith(prefix), `CompactSize prefix for length ${length}`);
  }
});

test("multi-digit branch steps are parsed to the end of the descriptor", () => {
  const { buildWalletRecords } = loadModule();
  const body = `wpkh(${XPUB_TAIL_4H}/10/*)`;
  const wallet = mutantHdWallet(`${body}#${descriptorChecksum(body)}`);
  const records = buildWalletRecords(wallet, false, deps, 0);
  const cache = records.find(([key]) => bytesToHex(key).startsWith("15" + "77616c6c657464657363726970746f726361636865"));
  assert.ok(cache, "cache record");
  assert.equal(bytesToHex(cache[1]), "4a" + bytesToHex(deriveBranchBody(XPUB_TAIL_4H, 10)));
});

test("unsupported descriptor path shapes are refused", () => {
  const { buildWalletRecords } = loadModule();
  const twoStep = `wpkh(${XPUB_TAIL_4H}/0/0/*)`;
  assert.throws(() => buildWalletRecords(mutantHdWallet(`${twoStep}#${descriptorChecksum(twoStep)}`), false, deps, 0), /unsupported descriptor path shape/);
  const hardenedIndex = `wpkh(${XPUB_TAIL_4H}/2147483648/*)`;
  assert.throws(() => buildWalletRecords(mutantHdWallet(`${hardenedIndex}#${descriptorChecksum(hardenedIndex)}`), false, deps, 0), /unsupported descriptor path shape/);
});

test("a branch row at index 0 counts toward the next index", () => {
  const { walletDescriptorUnits } = loadModule();
  const zero = structuredClone(WATCH_ONLY_WALLET);
  zero.accounts = [zero.accounts[0]];
  zero.accounts[0].addressBranches = [{ branch: 0, rows: [{ index: 0 }] }];
  assert.equal(walletDescriptorUnits(zero, false)[0].nextIndex, 1);
});

test("msig addressBranches add branches beyond the default window", () => {
  const { walletDescriptorUnits } = loadModule();
  const wallet = structuredClone(MSIG_WALLET);
  // A different branch step on the same key set, with its own checksum: as a
  // copy of the receive descriptor, the assertion below could not tell the
  // branch's own descriptor from the wallet's fallback.
  const desc2 = msigDesc(2);
  wallet.addressBranches = [{ branch: 2, publicDescriptor: desc2 }];
  const units = walletDescriptorUnits(wallet, false);
  assert.equal(units.length, 3);
  assert.equal(units[2].descriptor, desc2);
});

test("msig branches are exported in ascending branch order", () => {
  const { walletDescriptorUnits } = loadModule();
  const wallet = structuredClone(MSIG_WALLET);
  const desc0 = MSIG_WALLET.receiveDescriptor;
  const desc1 = MSIG_WALLET.changeDescriptor;
  // Distinct from desc0: with branch 2 reusing the receive descriptor, a
  // descending sort produced the same expected array.
  const desc2 = msigDesc(2);
  wallet.addressBranches = [
    { branch: 2, publicDescriptor: desc2 },
    { branch: 0, publicDescriptor: desc0 },
    { branch: 1, publicDescriptor: desc1 },
  ];
  const units = walletDescriptorUnits(wallet, false);
  assert.deepEqual(units.map((unit) => unit.descriptor), [desc0, desc1, desc2]);
});

test("msig branch descriptors fall back to the wallet receive/change descriptors", () => {
  const { walletDescriptorUnits } = loadModule();
  const wallet = structuredClone(MSIG_WALLET);
  wallet.addressBranches = [
    { branch: 0, rows: [{ index: 0 }] },
    { branch: 1, rows: [{ index: 0 }] },
  ];
  const units = walletDescriptorUnits(wallet, false);
  assert.equal(units.length, 2);
  assert.equal(units[0].descriptor, MSIG_WALLET.receiveDescriptor);
  assert.equal(units[1].descriptor, MSIG_WALLET.changeDescriptor);
});

test("msig branch rows fall back to the wallet receive/change rows", () => {
  const { walletDescriptorUnits } = loadModule();
  const wallet = structuredClone(MSIG_WALLET);
  wallet.receive = [{ index: 5 }];
  wallet.change = [{ index: 7 }];
  wallet.addressBranches = [
    { branch: 0, publicDescriptor: MSIG_WALLET.receiveDescriptor },
    { branch: 1, publicDescriptor: MSIG_WALLET.changeDescriptor },
  ];
  const units = walletDescriptorUnits(wallet, false);
  assert.equal(units[0].rangeEnd, 1005);
  assert.equal(units[1].rangeEnd, 1007);
});

test("msig branch rows use entry.rows when present", () => {
  const { walletDescriptorUnits } = loadModule();
  const wallet = structuredClone(MSIG_WALLET);
  wallet.receive = [{ index: 5 }];
  wallet.change = [{ index: 7 }];
  wallet.addressBranches = [
    { branch: 0, publicDescriptor: MSIG_WALLET.receiveDescriptor, rows: [{ index: 10 }] },
    { branch: 1, publicDescriptor: MSIG_WALLET.changeDescriptor, rows: [{ index: 20 }] },
  ];
  const units = walletDescriptorUnits(wallet, false);
  assert.equal(units[0].rangeEnd, 1010);
  assert.equal(units[1].rangeEnd, 1020);
});

test("msig internal flags mark only branch 1 of a 0/1 window", () => {
  const { walletDescriptorUnits } = loadModule();
  const units = walletDescriptorUnits(MSIG_WALLET, false);
  assert.equal(units[0].internal, false);
  assert.equal(units[1].internal, true);
});

test("walletDescriptorUnits refuses non-HD wallets without throwing", () => {
  const { walletDescriptorUnits } = loadModule();
  assert.deepEqual(walletDescriptorUnits(null, false), []);
  assert.deepEqual(walletDescriptorUnits({ kind: "hd" }, false), []);
});

test("HD branches are exported in ascending branch order", () => {
  const { walletDescriptorUnits } = loadModule();
  const wallet = structuredClone(WATCH_ONLY_WALLET);
  wallet.accounts = [wallet.accounts[0]];
  const desc0 = REF_PUBLIC_DESCRIPTORS[0];
  const desc1 = REF_PUBLIC_DESCRIPTORS[1];
  const desc2 = REF_PUBLIC_DESCRIPTORS[2];
  wallet.accounts[0].addressBranches = [
    { branch: 2, publicDescriptor: desc2 },
    { branch: 0, publicDescriptor: desc0 },
    { branch: 1, publicDescriptor: desc1 },
  ];
  const units = walletDescriptorUnits(wallet, false);
  assert.deepEqual(units.map((unit) => unit.descriptor), [desc0, desc1, desc2]);
});

test("HD branch descriptors are strings, not booleans", () => {
  const { walletDescriptorUnits } = loadModule();
  const wallet = structuredClone(WATCH_ONLY_WALLET);
  wallet.accounts = [wallet.accounts[0]];
  const units = walletDescriptorUnits(wallet, false);
  assert.equal(units.length, 2);
  assert.equal(units[0].descriptor, REF_PUBLIC_DESCRIPTORS[0]);
  assert.equal(units[1].descriptor, REF_PUBLIC_DESCRIPTORS[1]);
});

test("HD private descriptors fall back to the account private descriptors", () => {
  const { walletDescriptorUnits } = loadModule();
  const wallet = structuredClone(PRIVATE_WALLET);
  wallet.accounts = [wallet.accounts[0]];
  const units = walletDescriptorUnits(wallet, true);
  assert.equal(units[0].privateDescriptor, REF_PRIVATE_DESCRIPTORS[0]);
});

test("HD branch rows fall back to the account receive/change rows", () => {
  const { walletDescriptorUnits } = loadModule();
  const wallet = structuredClone(WATCH_ONLY_WALLET);
  wallet.accounts = [wallet.accounts[0]];
  wallet.accounts[0].receive = [{ index: 5 }];
  wallet.accounts[0].change = [{ index: 7 }];
  wallet.accounts[0].addressBranches = [
    { branch: 0, publicDescriptor: REF_PUBLIC_DESCRIPTORS[0] },
    { branch: 1, publicDescriptor: REF_PUBLIC_DESCRIPTORS[1] },
    { branch: 2, publicDescriptor: REF_PUBLIC_DESCRIPTORS[2] },
  ];
  const units = walletDescriptorUnits(wallet, false);
  assert.equal(units[0].nextIndex, 6);
  assert.equal(units[1].nextIndex, 8);
  assert.equal(units[2].nextIndex, 0);
});

test("hasDescriptors is false for wallets with no exportable descriptors", () => {
  const { hasDescriptors } = loadModule();
  assert.equal(hasDescriptors(null), false);
  assert.equal(hasDescriptors({ kind: "hd", accounts: [] }), false);
});

test("hasPrivateDescriptors is true when any unit has private material", () => {
  const { hasPrivateDescriptors } = loadModule();
  const wallet = structuredClone(PRIVATE_WALLET);
  for (const account of wallet.accounts.slice(0, -1)) {
    account.receiveDescriptorPriv = null;
    account.changeDescriptorPriv = null;
  }
  assert.equal(hasPrivateDescriptors(wallet), true);
});

test("walletDatSupported accepts a supported multisig wallet", () => {
  const { walletDatSupported } = loadModule();
  assert.equal(walletDatSupported(MSIG_WALLET), true);
});

test("walletDatSupported refuses a descriptor with no extended public keys", () => {
  const { walletDatSupported } = loadModule();
  const body = "wsh(sortedmulti(1,notakey/0/*))";
  const wallet = {
    kind: "msig",
    network: "mainnet",
    script: "p2wsh",
    receiveDescriptor: `${body}#${descriptorChecksum(body)}`,
  };
  assert.equal(walletDatSupported(wallet), false);
});

test("walletDatSupported refuses a hardened branch step", () => {
  const { walletDatSupported } = loadModule();
  const body = `wpkh(${XPUB_TAIL_4H}/0h/*)`;
  const wallet = mutantHdWallet(`${body}#${descriptorChecksum(body)}`);
  assert.equal(walletDatSupported(wallet), false);
});

test("bip388Supported refuses branches outside 0 and 1", () => {
  const { bip388Supported } = loadModule();
  const body = `wpkh(${XPUB_TAIL_4H}/2/*)`;
  const wallet = mutantHdWallet(`${body}#${descriptorChecksum(body)}`);
  assert.equal(bip388Supported(wallet), false);
});

test("buildWalletRecords refuses a null wallet", () => {
  const { buildWalletRecords } = loadModule();
  assert.throws(() => buildWalletRecords(null, false, deps, 0), /unknown network/);
});

// The co-signer xpub passes every public-key check, so the PRIVATE_KEY
// detection is the only thing refusing these exports: with that regex
// removed, the records are built and the private key is embedded in a
// "watch-only" wallet.dat.
test("multisig refuses an extended private key", () => {
  const { buildWalletRecords } = loadModule();
  const body = `wsh(sortedmulti(2,${msigKey(0)}/0/*,${msigNode(0).privateExtendedKey}/0/*))`;
  const wallet = {
    kind: "msig",
    network: "mainnet",
    script: "p2wsh",
    receiveDescriptor: `${body}#${descriptorChecksum(body)}`,
  };
  assert.throws(() => buildWalletRecords(wallet, false, deps, 0), /refused an extended private key/);
});

test("multisig refuses SLIP-132 uppercase private keys", () => {
  const { buildWalletRecords } = loadModule();
  const raw = b58checkDecode(msigNode(0).privateExtendedKey).slice();
  raw[0] = 0x02; raw[1] = 0xaa; raw[2] = 0x7a; raw[3] = 0x99;
  const zprv = b58checkEncode(raw);
  assert.match(zprv, /^Zprv/);
  const body = `wsh(sortedmulti(2,${msigKey(0)}/0/*,${zprv}/0/*))`;
  const wallet = {
    kind: "msig",
    network: "mainnet",
    script: "p2wsh",
    receiveDescriptor: `${body}#${descriptorChecksum(body)}`,
  };
  assert.throws(() => buildWalletRecords(wallet, false, deps, 0), /refused an extended private key/);
});


test("multisig refuses a non-xpub/tpub extended public key", () => {
  const { buildWalletRecords } = loadModule();
  const raw = b58checkDecode(msigNode(0).publicExtendedKey).slice();
  raw[0] = 0x04; raw[1] = 0x9d; raw[2] = 0x7c; raw[3] = 0xb2;
  const ypub = b58checkEncode(raw);
  assert.match(ypub, /^ypub/);
  const body = `wsh(sortedmulti(2,${msigKey(0)}/0/*,${ypub}/0/*))`;
  const wallet = {
    kind: "msig",
    network: "mainnet",
    script: "p2wsh",
    receiveDescriptor: `${body}#${descriptorChecksum(body)}`,
  };
  assert.throws(() => buildWalletRecords(wallet, false, deps, 0), /Base58Check codec/);
});

test("buildWalletRecords refuses a hardened step after a public key", () => {
  const { buildWalletRecords } = loadModule();
  const body = `wpkh(${XPUB_TAIL_4H}/0h/*)`;
  const wallet = mutantHdWallet(`${body}#${descriptorChecksum(body)}`);
  assert.throws(() => buildWalletRecords(wallet, false, deps, 0), /hardened step after a public key/);
});

// Checks only the buffers passed to the injected dependencies: they must be
// zeroed before buildWalletRecords returns. Copies taken inside the module
// are not observable through this seam, so this is not a proof that every
// secret copy is wiped.
test("private export zeroes the key buffers passed to injected dependencies", () => {
  const { buildWalletRecords } = loadModule();
  const capturedRaw = [], capturedSecret = [], capturedKeyHash = [];
  const wipeDeps = {
    ...deps,
    base58Decode: (text) => {
      const raw = deps.base58Decode(text);
      if (text.startsWith("xprv") || text.startsWith("tprv")) capturedRaw.push(raw);
      return raw;
    },
    publicKeyForPrivate: (secret) => {
      capturedSecret.push(secret);
      return deps.publicKeyForPrivate(secret);
    },
    sha256: (bytes) => {
      const hash = deps.sha256(bytes);
      if (bytes.length === 32) capturedKeyHash.push(hash);
      return hash;
    },
  };
  const wallet = structuredClone(PRIVATE_WALLET);
  wallet.accounts = [wallet.accounts[0]];
  buildWalletRecords(wallet, true, wipeDeps, 0);
  assert.ok(capturedRaw.length > 0, "captured raw xprv payloads");
  assert.ok(capturedSecret.length > 0, "captured secrets");
  assert.ok(capturedKeyHash.length > 0, "captured key hashes");
  for (const raw of capturedRaw) assert.ok(raw.every((byte) => byte === 0), "raw xprv payload is wiped");
  for (const secret of capturedSecret) assert.ok(secret.every((byte) => byte === 0), "secret is wiped");
  for (const hash of capturedKeyHash) assert.ok(hash.every((byte) => byte === 0), "key hash is wiped");
});

test("private export wipes key buffers when the key record build throws", () => {
  const { buildWalletRecords } = loadModule();
  const capturedRaw = [], capturedSecret = [], capturedHashInput = [], capturedInnerHash = [];
  let sawSecret = false;
  const throwingDeps = {
    ...deps,
    base58Decode: (text) => {
      const raw = deps.base58Decode(text);
      if (text.startsWith("xprv") || text.startsWith("tprv")) capturedRaw.push(raw);
      return raw;
    },
    publicKeyForPrivate: (secret) => {
      sawSecret = true;
      capturedSecret.push(secret);
      return deps.publicKeyForPrivate(secret);
    },
    sha256: (bytes) => {
      if (sawSecret && bytes.length === 247) {
        capturedHashInput.push(bytes);
        return deps.sha256(bytes);
      }
      if (sawSecret && bytes.length === 32) {
        capturedInnerHash.push(bytes);
        throw new Error("forced sha256 failure");
      }
      return deps.sha256(bytes);
    },
  };
  const wallet = structuredClone(PRIVATE_WALLET);
  wallet.accounts = [wallet.accounts[0]];
  assert.throws(() => buildWalletRecords(wallet, true, throwingDeps, 0), /forced sha256 failure/);
  assert.ok(capturedRaw.length > 0, "captured raw xprv payloads");
  assert.ok(capturedSecret.length > 0, "captured secrets");
  assert.ok(capturedHashInput.length > 0, "captured key-hash input");
  assert.ok(capturedInnerHash.length > 0, "captured inner key hash");
  for (const raw of capturedRaw) assert.ok(raw.every((byte) => byte === 0), "raw xprv payload is wiped");
  for (const secret of capturedSecret) assert.ok(secret.every((byte) => byte === 0), "secret is wiped");
  for (const input of capturedHashInput) assert.ok(input.every((byte) => byte === 0), "key-hash input is wiped");
  for (const hash of capturedInnerHash) assert.ok(hash.every((byte) => byte === 0), "inner key hash is wiped");
});

test("msig filename falls back when m or n is not a safe integer", () => {
  const { walletDatFilename } = loadModule();
  assert.equal(walletDatFilename({ kind: "msig", m: 2, n: undefined }, false), "entropylab-msig-watch-only-wallet.dat");
  assert.equal(walletDatFilename({ kind: "msig", m: undefined, n: 3 }, false), "entropylab-msig-watch-only-wallet.dat");
});

test("filename rejects fingerprints with extra characters", () => {
  const { walletDatFilename } = loadModule();
  assert.equal(walletDatFilename({ masterFingerprint: "xx73C5DA0A" }, false), "watch-only-wallet.dat");
  assert.equal(walletDatFilename({ masterFingerprint: "73C5DA0Axx" }, false), "watch-only-wallet.dat");
});

// --- Defense-in-depth: descriptor shapes the writer cannot place ----------
//
// The exporter only receives wallets the app derived itself, but it must not
// trust that: a bare extended key, a nested script wrapper, or a multisig
// co-signer that does not parse used to become a wallet.dat Bitcoin Core
// refuses to load — or watches a different policy than the one shown. The
// writer refuses every such shape before any record is written, and the
// error names wrappers only, never key material.
test("unplaceable descriptor shapes fail closed before any record is written", () => {
  const { buildWalletRecords } = loadModule();
  const xpub = msigNode(0).publicExtendedKey;
  const xprv = msigNode(0).privateExtendedKey;
  const withChecksum = (body) => `${body}#${descriptorChecksum(body)}`;
  const hdWallet = (receiveDescriptor, receiveDescriptorPriv = null) => ({
    kind: "hd",
    network: "mainnet",
    accounts: [{
      def: { id: "bip84" },
      receiveDescriptor,
      changeDescriptor: null,
      receiveDescriptorPriv,
      changeDescriptorPriv: null,
    }],
  });
  const msigWallet = (receiveDescriptor) => ({
    kind: "msig",
    network: "mainnet",
    script: "p2wsh",
    m: 1,
    n: 2,
    receiveDescriptor,
  });
  const cases = [
    ["bare extended key with no script wrapper", hdWallet(withChecksum(`${xpub}/0/*`)), false],
    ["nested script wrapper", hdWallet(withChecksum(`wpkh(tr(${xpub}/0/*))`)), false],
    ["multisig co-signer that does not parse", msigWallet(withChecksum(`wsh(sortedmulti(1,xprv1,${xpub}/0/*))`)), false],
    ["invalid descriptor checksum", hdWallet(`wpkh(${xpub}/0/*)#deadbeef`), false],
    ["nested script wrapper on the private descriptor", hdWallet(withChecksum(`wpkh(${xpub}/0/*)`), withChecksum(`wpkh(tr(${xprv}/0/*))`)), true],
  ];
  for (const [shape, wallet, includePrivate] of cases) {
    let error = null;
    try {
      buildWalletRecords(wallet, includePrivate, deps, 0);
    } catch (caught) {
      error = caught;
    }
    assert.ok(error instanceof Error, `${shape}: must throw instead of building a wallet.dat`);
    assert.match(error.message, /unsupported descriptor shape|invalid descriptor checksum|not a valid extended key/, `${shape}: the error names the refused shape`);
    assert.ok(!error.message.includes(xpub) && !error.message.includes(xprv), `${shape}: the error must not contain key material`);
    assert.doesNotMatch(error.message, /[1-9A-HJ-NP-Za-km-z]{50,}/, `${shape}: the error must not carry base58 key text`);
  }
});

test("the shape guard leaves valid single-sig and multisig exports byte-identical", () => {
  const { buildWalletRecords } = loadModule();
  // Single-sig: still exactly the rows Bitcoin Core v28.3.0 wrote for the
  // same descriptors — watch-only and private variants alike.
  for (const [wallet, includePrivate, expected] of [
    [WATCH_ONLY_WALLET, false, REF_WATCH_ONLY_RECORDS],
    [PRIVATE_WALLET, true, REF_PRIVATE_RECORDS],
  ]) {
    const mine = moduleRecords(wallet, includePrivate, REF_CREATION_TIME);
    const reference = asMap(expected);
    assert.equal(mine.size, reference.size);
    for (const [key, value] of reference) {
      assert.ok(mine.has(key), `missing record ${key.slice(0, 60)}`);
      assert.equal(mine.get(key), value, `record value mismatch at ${key.slice(0, 60)}`);
    }
  }
  // Multisig: the pinned expectations are unchanged — two stored descriptors
  // that keep every co-signer key, six cache parents matching the independent
  // CKD of each co-signer's branch key, and no private-key records.
  const records = buildWalletRecords(MSIG_WALLET, false, msigDeps, 0);
  const names = records.map(([key]) => new TextDecoder().decode(key.slice(1, 1 + key[0])));
  assert.equal(names.filter((name) => name === "walletdescriptor").length, 2);
  assert.equal(names.filter((name) => name === "walletdescriptorcache").length, 6);
  assert.equal(names.filter((name) => name === "walletdescriptorkey").length, 0);
  const storedValues = records
    .filter(([key]) => key[0] === 16 && new TextDecoder().decode(key.slice(1, 17)) === "walletdescriptor")
    .map(([, value]) => Buffer.from(value).toString("latin1"));
  assert.equal(storedValues.length, 2);
  for (const value of storedValues) {
    for (const account of [0, 1, 2]) {
      assert.ok(value.includes(msigNode(account).publicExtendedKey), "the stored descriptor keeps every co-signer key");
    }
  }
  const cachePrefix = "15" + "77616c6c657464657363726970746f726361636865";
  const caches = records.map(([key, value]) => [bytesToHex(key), bytesToHex(value)]).filter(([key]) => key.startsWith(cachePrefix));
  const expectedCaches = [];
  for (const branch of [0, 1]) {
    for (const account of [0, 1, 2]) {
      expectedCaches.push("4a" + bytesToHex(deriveBranchBody(msigNode(account).publicExtendedKey, branch)));
    }
  }
  assert.deepEqual(caches.map(([, value]) => value).sort(), [...expectedCaches].sort());
});

// PR1034-1: a watch-only export must never carry private key material. The
// shape guard's key pattern accepted prv keys, and the only PRIVATE_KEY
// refusal sat inside the multisig branch, so a single-sig watch-only
// walletdescriptor record stored an xprv verbatim — and its cache record the
// xprv's raw body, secret included — in a file flagged disable-private-keys.
test("a watch-only export refuses extended private keys, single-sig or multisig", () => {
  const { buildWalletRecords } = loadModule();
  const xprv = msigNode(0).privateExtendedKey;
  const xpub = msigNode(0).publicExtendedKey;
  const withChecksum = (body) => `${body}#${descriptorChecksum(body)}`;
  const hdWallet = (receiveDescriptor) => ({
    kind: "hd",
    network: "mainnet",
    accounts: [{ def: { id: "bip84" }, receiveDescriptor, changeDescriptor: null }],
  });
  const msigWallet = (receiveDescriptor) => ({
    kind: "msig",
    network: "mainnet",
    script: "p2wsh",
    m: 1,
    n: 1,
    receiveDescriptor,
  });
  assert.throws(() => buildWalletRecords(hdWallet(withChecksum(`wpkh(${xprv}/*)`)), false, deps, 0), /private key/);
  assert.throws(() => buildWalletRecords(msigWallet(withChecksum(`wsh(sortedmulti(1,${xprv}/*))`)), false, msigDeps, 0), /private key/);
  // No record of any watch-only export carries private key bytes or a
  // private extended key string: every record key and value is scanned.
  const records = buildWalletRecords(hdWallet(withChecksum(`wpkh(${xpub}/0/*)`)), false, deps, 0);
  const blob = records.map(([key, value]) => Buffer.from(key).toString("latin1") + Buffer.from(value).toString("latin1")).join("");
  assert.ok(!blob.includes(xprv), "no record may carry the extended private key string");
  assert.ok(!blob.includes(Buffer.from(b58checkDecode(xprv).slice(46, 78)).toString("latin1")), "no record may carry private key bytes");
  assert.doesNotMatch(blob, /[xyztuvYZUV]prv/);
});

// PR1034-2: the guard accepts h, H and ' hardened markers, but toCompatForm
// only rewrote origins whose steps were all digits-or-h — any ' or H step
// left the whole origin untouched, so h steps kept their spelling and the
// stored DescriptorID disagreed with the one Core recomputes at load
// (DBErrors::CORRUPT). Core's compat form renders every hardened step with ',
// whichever marker the input used.
test("descriptor ids equal Core's compat-form hash for h, H and ' origins", () => {
  const xpub = msigNode(0).publicExtendedKey;
  const walletFor = (origin) => {
    const body = `wpkh(${origin}${xpub}/0/*)`;
    return {
      kind: "hd",
      network: "mainnet",
      accounts: [{ def: { id: "bip84" }, receiveDescriptor: `${body}#${descriptorChecksum(body)}`, changeDescriptor: null }],
    };
  };
  for (const [origin, compatOrigin] of [
    ["[00000000/84h/0h/0h]", "[00000000/84'/0'/0']"],
    ["[00000000/84H/0H/0H]", "[00000000/84'/0'/0']"],
    ["[00000000/84'/0'/0']", "[00000000/84'/0'/0']"],
    ["[00000000/84h/0'/0H]", "[00000000/84'/0'/0']"],
  ]) {
    const records = moduleRecords(walletFor(origin), false, REF_CREATION_TIME);
    const ids = descriptorIds(records);
    assert.equal(ids.length, 1, `one descriptor record for origin ${origin}`);
    // Core's normalisation rule, applied independently of the module: every
    // hardened step renders as ', key material untouched.
    const compat = `wpkh(${compatOrigin}${xpub}/0/*)`;
    const expectedId = bytesToHex(sha256(new TextEncoder().encode(`${compat}#${descriptorChecksum(compat)}`)));
    assert.equal(ids[0], expectedId, `DescriptorID for origin ${origin} must be Core's compat-form hash`);
  }
});

// PR1034-3: the multisig shapes matched \d+ for the threshold and never
// counted the key list, so 0-of-N or k>N descriptors — and key counts beyond
// the script type's limit — became a wallet.dat Bitcoin Core's ParseMulti
// refuses to load.
test("multisig thresholds and key counts outside Core's limits fail closed", () => {
  const { buildWalletRecords } = loadModule();
  const key = (account) => `${msigNode(account).publicExtendedKey}/0/*`;
  const withChecksum = (body) => `${body}#${descriptorChecksum(body)}`;
  const msigWallet = (script, body) => ({ kind: "msig", network: "mainnet", script, m: 1, n: 1, receiveDescriptor: withChecksum(body) });
  // Bitcoin Core refuses k < 1 and k > n.
  assert.throws(() => buildWalletRecords(msigWallet("p2wsh", `wsh(multi(0,${key(0)}))`), false, deps, 0), /threshold/);
  assert.throws(() => buildWalletRecords(msigWallet("p2wsh", `wsh(multi(2,${key(0)}))`), false, deps, 0), /threshold/);
  assert.throws(() => buildWalletRecords(msigWallet("p2wsh", `wsh(multi(3,${key(0)},${key(1)}))`), false, deps, 0), /threshold/);
  // A leading zero would be stored verbatim and hashed into a DescriptorID
  // Core recomputes from its own spelling (Kimi K3 on #1034).
  assert.throws(() => buildWalletRecords(msigWallet("p2wsh", `wsh(multi(01,${key(0)},${key(1)}))`), false, deps, 0), /threshold/);
  // Key counts beyond the script type's limit: at most 20 for wsh, 15 for sh.
  const wshBody = (count) => `wsh(multi(1,${Array.from({ length: count }, (_, i) => key(i)).join(",")}))`;
  const shBody = (count) => `sh(multi(1,${Array.from({ length: count }, (_, i) => key(i)).join(",")}))`;
  assert.throws(() => buildWalletRecords(msigWallet("p2wsh", wshBody(21)), false, deps, 0), /threshold/);
  assert.throws(() => buildWalletRecords(msigWallet("p2sh", shBody(16)), false, deps, 0), /threshold/);
  // The limits themselves are inclusive: 20 keys in wsh, 15 in sh still export.
  assert.ok(buildWalletRecords(msigWallet("p2wsh", wshBody(20)), false, deps, 0).length > 0);
  assert.ok(buildWalletRecords(msigWallet("p2sh", shBody(15)), false, deps, 0).length > 0);
});

// PR1034-4: Core's compat form re-renders the key origin from parsed bytes,
// so the fingerprint prints with HexStr — lowercase — exactly as the h/H/'
// markers re-render as '. toCompatForm rewrote only the markers, so an
// uppercase-hex fingerprint hashed a DescriptorID Core recomputes from the
// lowercase spelling, and loadwallet failed with "descriptor ID calculated
// by the wallet differs from the one in DB" (DBErrors::CORRUPT).
test("descriptor ids equal Core's compat-form hash for uppercase-hex fingerprints", () => {
  const xpub = msigNode(0).publicExtendedKey;
  const walletFor = (origin) => {
    const body = `wpkh(${origin}${xpub}/0/*)`;
    return {
      kind: "hd",
      network: "mainnet",
      accounts: [{ def: { id: "bip84" }, receiveDescriptor: `${body}#${descriptorChecksum(body)}`, changeDescriptor: null }],
    };
  };
  for (const [origin, compatOrigin] of [
    ["[ABCDEF01/84h/0h/0h]", "[abcdef01/84'/0'/0']"],
    ["[AbCdEf01/84h/0h/0h]", "[abcdef01/84'/0'/0']"],
    ["[abcdef01/84h/0h/0h]", "[abcdef01/84'/0'/0']"],
  ]) {
    const records = moduleRecords(walletFor(origin), false, REF_CREATION_TIME);
    const ids = descriptorIds(records);
    assert.equal(ids.length, 1, `one descriptor record for origin ${origin}`);
    // Core's normalisation rule, applied independently of the module: the
    // fingerprint re-renders lowercase, every hardened step as ', key
    // material untouched — so every spelling of the fingerprint hashes the
    // same DescriptorID.
    const compat = `wpkh(${compatOrigin}${xpub}/0/*)`;
    const expectedId = bytesToHex(sha256(new TextEncoder().encode(`${compat}#${descriptorChecksum(compat)}`)));
    assert.equal(ids[0], expectedId, `DescriptorID for origin ${origin} must be Core's compat-form hash`);
  }
});

// PR1034-4: the same HexStr re-rendering lowercases a hex Taproot internal
// key: tr(<64 hex>,sortedmulti_a(...)) written with uppercase hex hashed a
// DescriptorID Core recomputes from the lowercase spelling.
test("descriptor ids equal Core's compat-form hash for an uppercase-hex Taproot internal key", () => {
  const { buildWalletRecords } = loadModule();
  const withChecksum = (body) => `${body}#${descriptorChecksum(body)}`;
  const bodyFor = (nums) => `tr(${nums},sortedmulti_a(2,${msigTrKey(0)}/0/*,${msigTrKey(1)}/0/*,${msigTrKey(2)}/0/*))`;
  const walletFor = (nums) => ({
    kind: "msig",
    network: "mainnet",
    script: "p2tr",
    m: 2,
    n: 3,
    receiveDescriptor: withChecksum(bodyFor(nums)),
  });
  const idOf = (nums) => {
    const records = buildWalletRecords(walletFor(nums), false, deps, 0);
    const ids = records
      .filter(([key]) => key[0] === 16 && new TextDecoder().decode(key.slice(1, 17)) === "walletdescriptor")
      .map(([key]) => bytesToHex(key.slice(17)));
    assert.equal(ids.length, 1, "one descriptor record");
    return ids[0];
  };
  // Core's normalisation rule, applied independently of the module: the
  // x-only internal key re-renders lowercase, every hardened step as '.
  const compatKey = (account) => `[${msigFingerprint}/86'/0'/${account}']${msigTrNode(account).publicExtendedKey}`;
  const compat = `tr(${NUMS},sortedmulti_a(2,${compatKey(0)}/0/*,${compatKey(1)}/0/*,${compatKey(2)}/0/*))`;
  const expectedId = bytesToHex(sha256(new TextEncoder().encode(`${compat}#${descriptorChecksum(compat)}`)));
  assert.equal(idOf(NUMS.toUpperCase()), expectedId, "an uppercase-hex internal key must hash Core's compat form");
  assert.equal(idOf(NUMS), expectedId, "the lowercase spelling hashes the same DescriptorID");
});

// PR1034-4: Core's parser accepts a path step with leading zeros
// (ParseUInt32("084") = 84) but its compat form prints the parsed uint32
// without them, so the stored DescriptorID would disagree with the one Core
// recomputes at load. The app never writes such a step; the guard refuses it
// — a step is 0 or [1-9][0-9]* — naming no key material.
test("path steps with leading zeros fail closed", () => {
  const { buildWalletRecords } = loadModule();
  const xpub = msigNode(0).publicExtendedKey;
  const withChecksum = (body) => `${body}#${descriptorChecksum(body)}`;
  const hdWallet = (receiveDescriptor) => ({
    kind: "hd",
    network: "mainnet",
    accounts: [{ def: { id: "bip84" }, receiveDescriptor, changeDescriptor: null }],
  });
  const msigWallet = (receiveDescriptor) => ({
    kind: "msig",
    network: "mainnet",
    script: "p2wsh",
    m: 1,
    n: 1,
    receiveDescriptor,
  });
  for (const [shape, wallet] of [
    ["origin step", hdWallet(withChecksum(`wpkh([00000000/084h/0h/0h]${xpub}/0/*)`))],
    ["key path step", hdWallet(withChecksum(`wpkh([00000000/84h/0h/0h]${xpub}/00/*)`))],
    ["multisig co-signer path step", msigWallet(withChecksum(`wsh(sortedmulti(1,${msigKey(0)}/00/*))`))],
  ]) {
    let error = null;
    try {
      buildWalletRecords(wallet, false, deps, 0);
    } catch (caught) {
      error = caught;
    }
    assert.ok(error instanceof Error, `${shape}: must throw instead of building a wallet.dat`);
    assert.match(error.message, /leading zero/, `${shape}: the error names the refused step shape`);
    assert.ok(!error.message.includes(xpub), `${shape}: the error must not contain key material`);
  }
  // Canonical steps — including a bare 0 — still export.
  assert.ok(buildWalletRecords(hdWallet(withChecksum(`wpkh([00000000/84h/0h/0h]${xpub}/0/*)`)), false, deps, 0).length > 0);
});

// Round 4, item 1 (wrapper/type mismatch): walletDescriptorUnits and
// msigDescriptorUnits set unit.type — the activeexternalspk/activeinternalspk
// output type — from the account def or wallet.script. The guard must refuse
// a descriptor whose wrapper produces a different script type: a p2wsh
// multisig exporting sh(multi(...)) would be filed under type 2 for a P2SH
// script, a wallet.dat that watches a different policy than the app showed.
test("a descriptor whose wrapper disagrees with the wallet's declared output type fails closed", () => {
  const { buildWalletRecords } = loadModule();
  const xpub = msigNode(0).publicExtendedKey;
  const withChecksum = (body) => `${body}#${descriptorChecksum(body)}`;
  const hdWallet = (id, receiveDescriptor) => ({
    kind: "hd",
    network: "mainnet",
    accounts: [{ def: { id }, receiveDescriptor, changeDescriptor: null }],
  });
  const msigWallet = (script, receiveDescriptor) => ({ kind: "msig", network: "mainnet", script, m: 1, n: 1, receiveDescriptor });
  for (const [shape, wallet] of [
    ["p2wsh multisig exporting sh(multi(...))", msigWallet("p2wsh", withChecksum(`sh(multi(1,${xpub}/0/*))`))],
    ["p2sh multisig exporting wsh(...)", msigWallet("p2sh", withChecksum(`wsh(sortedmulti(1,${xpub}/0/*))`))],
    ["p2sh-p2wsh multisig exporting sh(multi(...))", msigWallet("p2sh-p2wsh", withChecksum(`sh(multi(1,${xpub}/0/*))`))],
    ["p2tr multisig exporting wsh(...)", msigWallet("p2tr", withChecksum(`wsh(sortedmulti(1,${xpub}/0/*))`))],
    ["bip84 account exporting pkh(...)", hdWallet("bip84", withChecksum(`pkh(${xpub}/0/*)`))],
    ["bip44 account exporting wpkh(...)", hdWallet("bip44", withChecksum(`wpkh(${xpub}/0/*)`))],
    ["bip49 account exporting wpkh(...)", hdWallet("bip49", withChecksum(`wpkh(${xpub}/0/*)`))],
    ["bip86 account exporting sh(wpkh(...))", hdWallet("bip86", withChecksum(`sh(wpkh(${xpub}/0/*))`))],
  ]) {
    let error = null;
    try {
      buildWalletRecords(wallet, false, deps, 0);
    } catch (caught) {
      error = caught;
    }
    assert.ok(error instanceof Error, `${shape}: must throw instead of building a wallet.dat`);
    assert.match(error.message, /script type/, `${shape}: the error names the mismatch`);
    assert.ok(!error.message.includes(xpub), `${shape}: the error must not contain key material`);
  }
  // The mapping is inclusive on the accepted side: every wrapper the app
  // pairs with a script type still exports.
  for (const [script, body] of [
    ["p2sh", `sh(multi(1,${xpub}/0/*))`],
    ["p2sh-p2wsh", `sh(wsh(sortedmulti(1,${xpub}/0/*)))`],
    ["p2wsh", `wsh(sortedmulti(1,${xpub}/0/*))`],
    ["p2tr", `tr(${NUMS},sortedmulti_a(1,${xpub}/0/*))`],
  ]) {
    assert.ok(
      buildWalletRecords(msigWallet(script, withChecksum(body)), false, deps, 0).length > 0,
      `${script}: the matching wrapper still exports`,
    );
  }
});

// Round 4, item 2 (checksum): Core's LoadDescriptorWalletRecords parses every
// stored descriptor with require_checksum = true, so a descriptor handed over
// without one must be stored WITH the module's checksum appended — not
// refused, and not stored verbatim (loadwallet would fail with "Missing
// checksum"). The stored string and the DescriptorID must both be exactly
// what Core computes.
test("a checksum-less descriptor is stored with the checksum Core requires", () => {
  const xpub = msigNode(0).publicExtendedKey;
  const body = `wpkh(${xpub}/0/*)`; // no origin: the compat form is the body itself
  const wallet = {
    kind: "hd",
    network: "mainnet",
    accounts: [{ def: { id: "bip84" }, receiveDescriptor: body, changeDescriptor: null }],
  };
  const records = moduleRecords(wallet, false, 0);
  const ids = descriptorIds(records);
  assert.equal(ids.length, 1, "one descriptor record");
  // Core's DescriptorID, computed independently of the module: SHA-256 over
  // the compat form plus its checksum.
  const expectedId = bytesToHex(sha256(new TextEncoder().encode(`${body}#${descriptorChecksum(body)}`)));
  assert.equal(ids[0], expectedId, "the record key is Core's DescriptorID");
  // The record value is streamString(stored) followed by the creation time
  // and range fields; the descriptor is the CompactSize-length-prefixed
  // string at the front (short enough here for a one-byte length).
  const value = Buffer.from(records.get(DESCRIPTOR_PREFIX + ids[0]), "hex");
  assert.ok(value[0] < 253, "the descriptor takes a one-byte CompactSize length");
  const stored = new TextDecoder().decode(value.subarray(1, 1 + value[0]));
  assert.equal(stored, `${body}#${descriptorChecksum(body)}`, "the stored descriptor carries the checksum Core requires");
});

// Round 4, item 3 (Taproot internal key): the supported shape is
// tr(NUMS,(sorted)multi_a(...)) with BIP 341's NUMS point H — the only
// internal key the app writes. The module cannot check the curve validity of
// an arbitrary x-only key, so anything but H must fail closed: Core's
// ParsePubkey calls XOnlyPubKey::IsFullyValid and refuses the wallet.
test("a Taproot multisig internal key that is not the BIP 341 NUMS point fails closed", () => {
  const { buildWalletRecords } = loadModule();
  const withChecksum = (body) => `${body}#${descriptorChecksum(body)}`;
  const bodyFor = (nums) => `tr(${nums},sortedmulti_a(2,${msigTrKey(0)}/0/*,${msigTrKey(1)}/0/*,${msigTrKey(2)}/0/*))`;
  const walletFor = (nums) => ({
    kind: "msig",
    network: "mainnet",
    script: "p2tr",
    m: 2,
    n: 3,
    receiveDescriptor: withChecksum(bodyFor(nums)),
  });
  for (const [shape, nums] of [
    ["thirty-two zero bytes", "0".repeat(64)],
    ["a different x-only key", "0101010101010101010101010101010101010101010101010101010101010101"],
    ["NUMS with the first byte changed", `51${NUMS.slice(2)}`],
  ]) {
    let error = null;
    try {
      buildWalletRecords(walletFor(nums), false, deps, 0);
    } catch (caught) {
      error = caught;
    }
    assert.ok(error instanceof Error, `${shape}: must throw instead of building a wallet.dat`);
    assert.match(error.message, /NUMS/, `${shape}: the error names the refused internal key`);
    assert.ok(!error.message.includes(nums), `${shape}: the error must not contain the refused key`);
  }
  // H itself — either hex case — still exports (the uppercase spelling's
  // DescriptorID is pinned by the compat-form test above).
  assert.ok(buildWalletRecords(walletFor(NUMS), false, deps, 0).length > 0);
  assert.ok(buildWalletRecords(walletFor(NUMS.toUpperCase()), false, deps, 0).length > 0);
});

// Round 4, item 4 (path step magnitude): Core's ParseKeyPath refuses a key
// path element whose number is 2^31 or more, hardened or not ("Path value
// too large"), in a key origin or a key path alike. The guard's step
// patterns accepted any \d+ with no upper bound, so such a descriptor still
// became a wallet.dat Core refuses to load.
test("path steps of 2^31 or more fail closed", () => {
  const { buildWalletRecords } = loadModule();
  const xpub = msigNode(0).publicExtendedKey;
  const withChecksum = (body) => `${body}#${descriptorChecksum(body)}`;
  const hdWallet = (receiveDescriptor) => ({
    kind: "hd",
    network: "mainnet",
    accounts: [{ def: { id: "bip84" }, receiveDescriptor, changeDescriptor: null }],
  });
  const msigWallet = (receiveDescriptor) => ({
    kind: "msig",
    network: "mainnet",
    script: "p2wsh",
    m: 1,
    n: 1,
    receiveDescriptor,
  });
  for (const [shape, wallet] of [
    ["origin step, hardened", hdWallet(withChecksum(`wpkh([00000000/4294967296h]${xpub}/0/*)`))],
    ["origin step, unhardened", hdWallet(withChecksum(`wpkh([00000000/2147483648]${xpub}/0/*)`))],
    ["key path step", hdWallet(withChecksum(`wpkh([00000000/84h/0h/0h]${xpub}/2147483648/*)`))],
    ["multisig co-signer origin step", msigWallet(withChecksum(`wsh(sortedmulti(1,[00000000/4294967296h]${xpub}/0/*))`))],
  ]) {
    let error = null;
    try {
      buildWalletRecords(wallet, false, deps, 0);
    } catch (caught) {
      error = caught;
    }
    assert.ok(error instanceof Error, `${shape}: must throw instead of building a wallet.dat`);
    assert.match(error.message, /2\^31/, `${shape}: the error names the refused step magnitude`);
    assert.ok(!error.message.includes(xpub), `${shape}: the error must not contain key material`);
  }
  // The boundary is Core's own: a step just below 2^31 still exports.
  assert.ok(buildWalletRecords(hdWallet(withChecksum(`wpkh([00000000/2147483647h]${xpub}/0/*)`)), false, deps, 0).length > 0);
});

// Round 5, item 1 (single-sig SLIP-132): the shape guard's key pattern
// accepts ypub/zpub/upub/vpub, but only multisig units were canonicalized
// (`if (unit.multiKey && ...)`), so a single-sig descriptor carrying a zpub
// was stored verbatim — Bitcoin Core's descriptor parser accepts only
// xpub/tpub, and loadwallet refused the file. Every unit's watch-only
// descriptor is now stored in canonical form, and the DescriptorID is
// computed from that stored form.
test("a single-sig zpub is rewritten to xpub before it is stored", () => {
  const { buildWalletRecords } = loadModule();
  const raw = b58checkDecode(msigNode(0).publicExtendedKey).slice();
  raw[0] = 0x04; raw[1] = 0xb2; raw[2] = 0x47; raw[3] = 0x46;
  const zpub = b58checkEncode(raw);
  assert.match(zpub, /^zpub/);
  const xpub = msigNode(0).publicExtendedKey;
  const slipBody = `wpkh([${msigFingerprint}/84h/0h/0h]${zpub}/0/*)`;
  const wallet = {
    kind: "hd",
    network: "mainnet",
    accounts: [{ def: { id: "bip84" }, receiveDescriptor: `${slipBody}#${descriptorChecksum(slipBody)}`, changeDescriptor: null }],
  };
  // Without the Base58Check codec in deps the SLIP-132 key cannot be
  // rewritten, so the export is refused instead of storing a zpub verbatim.
  assert.throws(() => buildWalletRecords(wallet, false, deps, 0), /Base58Check codec/);
  const records = buildWalletRecords(wallet, false, msigDeps, 0);
  const descriptorRecord = records.find(([key]) => key[0] === 16 && new TextDecoder().decode(key.slice(1, 17)) === "walletdescriptor");
  assert.ok(descriptorRecord, "one descriptor record");
  // Core's DescriptorID, computed independently of the module from the
  // canonical xpub form: SHA-256 over the compat form plus its checksum.
  const canonicalBody = `wpkh([${msigFingerprint}/84h/0h/0h]${xpub}/0/*)`;
  const compat = `wpkh([${msigFingerprint}/84'/0'/0']${xpub}/0/*)`;
  const expectedId = bytesToHex(sha256(new TextEncoder().encode(`${compat}#${descriptorChecksum(compat)}`)));
  assert.equal(bytesToHex(descriptorRecord[0].slice(17)), expectedId, "the record key is Core's DescriptorID of the canonical form");
  const value = Buffer.from(descriptorRecord[1]);
  assert.ok(value[0] < 253, "the descriptor takes a one-byte CompactSize length");
  assert.equal(
    new TextDecoder().decode(value.subarray(1, 1 + value[0])),
    `${canonicalBody}#${descriptorChecksum(canonicalBody)}`,
    "the stored descriptor is the canonical xpub form",
  );
  // An xpub descriptor is untouched by the canonicalizer: with or without
  // it in deps, the records are byte-identical.
  const xpubWallet = {
    kind: "hd",
    network: "mainnet",
    accounts: [{ def: { id: "bip84" }, receiveDescriptor: `${canonicalBody}#${descriptorChecksum(canonicalBody)}`, changeDescriptor: null }],
  };
  assert.deepEqual(
    buildWalletRecords(xpubWallet, false, deps, 0).map(([key, row]) => [bytesToHex(key), bytesToHex(row)]),
    buildWalletRecords(xpubWallet, false, msigDeps, 0).map(([key, row]) => [bytesToHex(key), bytesToHex(row)]),
    "an xpub descriptor exports byte-identically without the canonicalizer",
  );
});

// Round 5, item 2 (wallet kind vs descriptor family): the guard tied the
// wrapper to the output type but not to the wallet kind, so an HD account
// carrying wsh(sortedmulti(...)) of the same output type (wsh is bech32,
// like wpkh) passed — and the writer cached only the first co-signer's key —
// while a multisig wallet carrying wpkh(...) passed in reverse, exporting a
// single-signature wallet.dat under an "msig-MofN" filename.
test("the descriptor family must match the wallet kind", () => {
  const { buildWalletRecords } = loadModule();
  const xpubA = msigNode(0).publicExtendedKey;
  const xpubB = msigNode(1).publicExtendedKey;
  const withChecksum = (body) => `${body}#${descriptorChecksum(body)}`;
  const hdWithMultisig = {
    kind: "hd",
    network: "mainnet",
    accounts: [{
      def: { id: "bip84" },
      receiveDescriptor: withChecksum(`wsh(sortedmulti(2,${xpubA}/0/*,${xpubB}/0/*))`),
      changeDescriptor: null,
    }],
  };
  assert.throws(() => buildWalletRecords(hdWithMultisig, false, deps, 0), /wallet kind|descriptor family/);
  const msigWithSingleSig = {
    kind: "msig",
    network: "mainnet",
    script: "p2wsh",
    m: 2,
    n: 3,
    receiveDescriptor: withChecksum(`wpkh(${xpubA}/0/*)`),
  };
  assert.throws(() => buildWalletRecords(msigWithSingleSig, false, deps, 0), /wallet kind|descriptor family/);
});

// Round 5, item 3 (support checks): walletDatSupported only ran
// tailsSupported, so the app offered the wallet.dat control for wallets the
// shape guard refuses — the control failed only on click. The gating path
// injects no crypto, so the guard runs on the descriptor text alone there.
test("walletDatSupported returns false for a wallet the shape guard refuses", () => {
  const { walletDatSupported, buildWalletRecords } = loadModule();
  const xpub = msigNode(0).publicExtendedKey;
  const withChecksum = (body) => `${body}#${descriptorChecksum(body)}`;
  // Round 4's script-type mismatch: the tail parses, so tailsSupported alone
  // says yes, but the guard refuses the export.
  const scriptTypeMismatch = {
    kind: "msig",
    network: "mainnet",
    script: "p2wsh",
    m: 1,
    n: 1,
    receiveDescriptor: withChecksum(`sh(multi(1,${xpub}/0/*))`),
  };
  assert.throws(() => buildWalletRecords(scriptTypeMismatch, false, deps, 0), /script type/);
  assert.equal(walletDatSupported(scriptTypeMismatch), false, "the control must not render for a guard-refused wallet");
  // The wallet-kind mismatch (round 5, item 2) is gated the same way.
  const kindMismatch = {
    kind: "msig",
    network: "mainnet",
    script: "p2wsh",
    m: 2,
    n: 3,
    receiveDescriptor: withChecksum(`wpkh(${xpub}/0/*)`),
  };
  assert.equal(walletDatSupported(kindMismatch), false);
  // Wallets the guard accepts still render the control.
  assert.equal(walletDatSupported(MSIG_WALLET), true);
  assert.equal(walletDatSupported(WATCH_ONLY_WALLET), true);
});
