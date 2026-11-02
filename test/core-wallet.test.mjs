// Tests for src/js/core-wallet.js (Bitcoin Core wallet.dat inspection,
// verification, and extension) using Node's built-in test runner.
//
// The ground truth is the same Bitcoin Core v28.3.0 fixture set the export
// suite uses (test/wallet-export-reference.mjs): the exact `main` table rows
// of real Core wallets. The reader side (src/js/sqlite-reader.js) and the
// rebuild path are additionally cross-checked against Python's sqlite3.
// Run with `npm test`.
import { test } from "node:test";
import assert from "node:assert/strict";
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
  GENERATED_MASTER_FINGERPRINT,
  GENERATED_ROOT_TPRV,
  GENERATED_ROWS,
  GENERATED_SEED,
  buildGeneratedUnitRecords,
} from "./core-generated-fixture.mjs";
import {
  PYTHON_SQLITE,
  b58checkDecode,
  b58checkEncode,
  bytesToHex,
  deps,
  descriptorChecksum,
  hdDeriveHardened,
  hdMasterFromSeed,
  hexToBytes,
  publicKeyForPrivate,
  read,
  ripemd160,
  serializeExtendedKey,
  sha256,
  sqliteReadBack,
} from "./wallet-export-harness.mjs";

const loadModule = () =>
  new Function(
    `${read("src/js/sqlite-writer.js")}\n${read("src/js/sqlite-reader.js")}\n${read("src/js/wallet-export.js")}\n${read("src/js/core-wallet.js")}\nreturn { writer: hodlSqliteWriter, reader: hodlSqliteReader, export: hodlWalletExport, core: hodlCoreWallet };`,
  )();

// The full dep set the app injects: the export's record deps plus descriptor
// canonicalization and extended-key neutering, all from the harness's
// independent reference crypto.
const neuterExtendedKey = (text) => {
  const raw = b58checkDecode(text.trim());
  if (raw.length !== 78 || raw[45] !== 0) throw new Error("not a private extended key");
  const version = /^(?:tprv|uprv|vprv)/.test(text.trim()) ? 0x043587cf : 0x0488b21e;
  const body = Uint8Array.from([
    (version >>> 24) & 255, (version >>> 16) & 255, (version >>> 8) & 255, version & 255,
    raw[4], ...raw.slice(5, 45), ...publicKeyForPrivate(raw.slice(46, 78)),
  ]);
  return b58checkEncode(body);
};
const coreDeps = {
  ...deps,
  canonicalizeDescriptor: (descriptor) =>
    canonicalizeWatchDescriptor(descriptor, { decode: b58checkDecode, encode: b58checkEncode }),
  neuterExtendedKey,
};

const MAIN_SQL = "CREATE TABLE main(key BLOB PRIMARY KEY NOT NULL, value BLOB NOT NULL)";
const REGTEST_APP_ID = 0xfabfb5da;

// A wallet.dat file from ground-truth Core rows.
const dbFromRecords = (records, applicationId = REGTEST_APP_ID) =>
  loadModule().writer.createDatabase({
    applicationId,
    tables: [{ name: "main", sql: MAIN_SQL, primaryKey: 0, rows: records.map(([key, value]) => [hexToBytes(key), hexToBytes(value)]) }],
  });

const parseRecords = (records, applicationId) => loadModule().core.parseWalletDat(dbFromRecords(records, applicationId));

// A fresh account descriptor (m/84'/1'/9') that is not in the reference
// wallets, in public and private form.
const EXTRA_ACCOUNT = (() => {
  const master = hdMasterFromSeed(new Uint8Array(32).fill(9));
  let node = master;
  for (const index of [84, 1, 9]) node = hdDeriveHardened(node, index);
  const tpub = serializeExtendedKey(node, 0x043587cf, false);
  const tprv = serializeExtendedKey(node, 0x04358394, true); // tprv version bytes
  const publicBody = `wpkh([aaaa0009/84h/1h/9h]${tpub}/0/*)`;
  const privateBody = `wpkh([aaaa0009/84h/1h/9h]${tprv}/0/*)`;
  return {
    public: `${publicBody}#${descriptorChecksum(publicBody)}`,
    private: `${privateBody}#${descriptorChecksum(privateBody)}`,
  };
})();

const tones = (checks) => checks.map((check) => check.tone);
const badChecks = (checks) => checks.filter((check) => check.tone === "bad");

test("never generates network traffic", () => {
  for (const src of [read("src/js/core-wallet.js"), read("src/js/sqlite-reader.js"), read("src/js/core-wallet-ui.js")]) {
    assert.doesNotMatch(src, /\bfetch\b|XMLHttpRequest|WebSocket|RTCPeerConnection|sendBeacon|WebTransport/);
  }
});

test("the build and the shell register the module and the tab", () => {
  const build = read("scripts/build.mjs");
  const template = read("src/index.html");
  assert.match(build, /core-wallet\.js/);
  assert.match(build, /JS_CORE_WALLET/);
  assert.match(template, /\/\*@@JS_CORE_WALLET@@\*\//);
  const app = read("src/js/app.js");
  assert.match(app, /import \{ (?:\w+, )*initCoreWallet(?:, \w+)* \} from "\.\/core-wallet-ui\.js"/);
  assert.match(app, /initCoreWallet\(\{ deps: hodlWalletDatDeps\(\), onImportIntoStation: hodlCoreImportIntoStation, copiedIcon: hodlCopiedIconMarkup, copyIcon: hodlClipboardIconMarkup \}\)/);
});

test("parses a real Core watch-only wallet and verifies clean", () => {
  const { core } = loadModule();
  const doc = parseRecords(REF_WATCH_ONLY_RECORDS);
  assert.equal(doc.network, "regtest");
  assert.equal(doc.meta.version, 280300);
  assert.equal(doc.meta.minversion, 169900);
  assert.deepEqual(core.flagNames(doc.meta.flags), ["disable private keys", "blank", "descriptors"]);
  assert.equal(doc.descriptors.length, 8);
  assert.equal(doc.meta.actives.length, 8);
  assert.equal(doc.others.length, 0);
  // Every descriptor grouped its cache and active records.
  for (const entry of doc.descriptors) {
    assert.equal(entry.caches.length, 1);
    assert.equal(entry.keys.length, 0);
    assert.ok(entry.active, "descriptor must be the active spk for its type");
    assert.ok(REF_PUBLIC_DESCRIPTORS.includes(entry.descriptor));
  }
  const checks = core.verifyWalletDoc(doc, coreDeps);
  assert.deepEqual(badChecks(checks), [], JSON.stringify(badChecks(checks), null, 2));
  assert.deepEqual([...new Set(tones(checks))], ["ok"]);
});

test("parses a real Core private wallet: key records verify and stay grouped", () => {
  const { core } = loadModule();
  const doc = parseRecords(REF_PRIVATE_RECORDS);
  assert.deepEqual(core.flagNames(doc.meta.flags), ["blank", "descriptors"]);
  assert.equal(doc.descriptors.length, 8);
  for (const entry of doc.descriptors) assert.equal(entry.keys.length, 1, "each descriptor carries one key record");
  const checks = core.verifyWalletDoc(doc, coreDeps);
  assert.deepEqual(badChecks(checks), [], JSON.stringify(badChecks(checks), null, 2));
  assert.ok(checks.some((check) => check.label === "Private key record" && check.tone === "ok"));
});

test("round-trips: parse → rebuild re-reads to the same records", () => {
  const { core } = loadModule();
  const doc = parseRecords(REF_WATCH_ONLY_RECORDS);
  const rebuilt = core.buildWalletDat(doc);
  const reparsed = core.parseWalletDat(rebuilt);
  assert.deepEqual(
    reparsed.rows.map(([key, value]) => [bytesToHex(key), bytesToHex(value)]),
    doc.rows.map(([key, value]) => [bytesToHex(key), bytesToHex(value)]),
  );
  assert.deepEqual(badChecks(core.verifyWalletDoc(reparsed, coreDeps)), []);
});

test("rebuilt files pass the real SQLite library", { skip: !PYTHON_SQLITE }, () => {
  const { core } = loadModule();
  const doc = parseRecords(REF_PRIVATE_RECORDS);
  const report = sqliteReadBack(core.buildWalletDat(doc));
  assert.equal(report.integrity, "ok");
  assert.equal(report.app_id, REGTEST_APP_ID);
  assert.deepEqual(
    [...report.rows].sort(),
    REF_PRIVATE_RECORDS.map(([key, value]) => [key, value]).sort(),
  );
});

test("rejects non-SQLite and non-wallet files with clear errors", () => {
  const { core } = loadModule();
  assert.throws(() => core.parseWalletDat(new Uint8Array(8192)), /bad magic/);
  // A SQLite database without the wallet's main table is not a wallet.
  const empty = loadModule().writer.createDatabase({
    applicationId: 0,
    tables: [{ name: "other", sql: "CREATE TABLE other(x)", rows: [[1]] }],
  });
  assert.throws(() => core.parseWalletDat(empty), /no `main` table/);
});

test("detects a tampered descriptor (checksum and id both trip)", () => {
  const { core } = loadModule();
  // Flip one character inside the first descriptor string of the
  // ground-truth rows; the container stays valid, the claims do not.
  const records = REF_WATCH_ONLY_RECORDS.map(([key, value]) => [key, value]);
  const row = records.find(([key]) => key.startsWith("1077616c6c657464657363726970746f72")); // "walletdescriptor"
  const value = hexToBytes(row[1]);
  const at = value.indexOf(0x2f); // a '/' inside the descriptor text
  value[at] = 0x2f === value[at] ? 0x3a : 0x2f;
  row[1] = bytesToHex(value);
  const doc = parseRecords(records);
  const checks = core.verifyWalletDoc(doc, coreDeps);
  const bad = badChecks(checks);
  assert.ok(bad.length >= 2, `expected checksum and id failures, got ${JSON.stringify(bad)}`);
  assert.ok(bad.some((check) => check.label === "Descriptor checksum"));
  assert.ok(bad.some((check) => check.label === "Descriptor id"));
});

test("detects a wrong cache parent (Core would watch the wrong subtree)", () => {
  const { core } = loadModule();
  const records = REF_WATCH_ONLY_RECORDS.map(([key, value]) => [key, value]);
  const cache = records.find(([key]) => key.startsWith("1577616c6c657464657363726970746f726361636865")); // "walletdescriptorcache"
  const value = hexToBytes(cache[1]);
  value[value.length - 1] ^= 0x01; // corrupt the cached pubkey
  cache[1] = bytesToHex(value);
  const doc = parseRecords(records);
  const bad = badChecks(core.verifyWalletDoc(doc, coreDeps));
  assert.ok(bad.some((check) => check.label === "Descriptor cache"), JSON.stringify(bad));
});

test("detects an active record whose type does not match the descriptor wrapper", () => {
  const { core } = loadModule();
  const doc = parseRecords(REF_WATCH_ONLY_RECORDS);
  const entry = doc.descriptors.find((item) => item.active && item.functions.join(":") === "wpkh" && !item.active.internal);
  assert.ok(entry, "fixture has an active native-SegWit receive descriptor");
  entry.active.type = 3; // filed as Taproot
  assert.ok(badChecks(core.verifyWalletDoc(doc, coreDeps)).some((check) => /marked type 3 but its wrapper is type 2/.test(check.detail)));
});

test("detects an active record filed on the wrong chain", () => {
  const { core } = loadModule();
  const doc = parseRecords(REF_WATCH_ONLY_RECORDS);
  const entry = doc.descriptors.find((item) => item.active && !item.active.internal && /\/0\/\*\)/.test(item.descriptor));
  assert.ok(entry, "fixture has an active receive branch");
  entry.active.internal = true;
  assert.ok(badChecks(core.verifyWalletDoc(doc, coreDeps)).some((check) => /filed as internal but its branch is receive/.test(check.detail)));
});

test("checks every active record that names one descriptor, not only the last", () => {
  const { core } = loadModule();
  const records = REF_WATCH_ONLY_RECORDS.map(([key, value]) => [key, value]);
  const change = parseRecords(records).descriptors.find((item) => item.functions.join(":") === "wpkh" && /\/1\/\*\)/.test(item.descriptor));
  assert.ok(change, "fixture has a native-SegWit change descriptor");
  // Receive pointer for type 2 now names the change descriptor, which its
  // own internal pointer also names: one record is wrong whichever is read.
  const external = records.find(([key]) => key === "1161637469766565787465726e616c73706b02"); // activeexternalspk type 2
  external[1] = change.id;
  const bad = badChecks(core.verifyWalletDoc(parseRecords(records), coreDeps)).map((check) => check.detail);
  assert.ok(bad.some((line) => /filed as external but its branch is change/.test(line)), JSON.stringify(bad));
  assert.ok(bad.some((line) => /named by 2 active records/.test(line)), JSON.stringify(bad));
});

test("descriptor key versions must belong to the wallet's network", () => {
  const { core } = loadModule();
  // Core decodes an extended key against the chain's own base58 prefixes:
  // tpub on every test chain, xpub on mainnet; anything else fails to load.
  const regtest = core.verifyWalletDoc(parseRecords(REF_WATCH_ONLY_RECORDS), coreDeps);
  assert.ok(regtest.some((check) => check.tone === "ok" && check.label === "Descriptor network"));
  assert.ok(!regtest.some((check) => check.tone === "bad" && check.label === "Descriptor network"));
  const signet = core.verifyWalletDoc(parseRecords(REF_WATCH_ONLY_RECORDS, 0x0a03cf40), coreDeps);
  assert.ok(!signet.some((check) => check.tone === "bad" && check.label === "Descriptor network"), "tpub is right on signet too");
  const mainnet = core.verifyWalletDoc(parseRecords(REF_WATCH_ONLY_RECORDS, 0xf9beb4d9), coreDeps);
  assert.equal(mainnet.filter((check) => check.tone === "bad" && check.label === "Descriptor network").length, 8, "every tpub descriptor in a mainnet file");
});

test("a descriptor with a character outside Core's charset yields checks, not a throw", () => {
  const { core } = loadModule();
  const doc = parseRecords(REF_WATCH_ONLY_RECORDS);
  doc.descriptors[0].descriptor = doc.descriptors[0].descriptor.replace("#", "!#");
  // The app's checksum implementation throws on a character outside Core's
  // charset; model that instead of the harness's permissive reference.
  const strict = { ...coreDeps, checksum: (body) => { if (body.includes("!")) throw new Error("bad character");
    return coreDeps.checksum(body); } };
  const bad = badChecks(core.verifyWalletDoc(doc, strict)).map((check) => check.detail);
  assert.ok(bad.some((line) => /checksum mismatch/.test(line)));
  assert.ok(bad.some((line) => /cannot be recomputed/.test(line)));
});

test("detects duplicate descriptor ids and duplicate active slots", () => {
  const { core } = loadModule();
  const doc = parseRecords(REF_WATCH_ONLY_RECORDS);
  doc.descriptors.push({ ...doc.descriptors[0] });
  doc.meta.actives.push({ ...doc.meta.actives[0] });
  const bad = badChecks(core.verifyWalletDoc(doc, coreDeps)).map((check) => check.detail);
  assert.ok(bad.some((line) => /duplicate walletdescriptor id/.test(line)));
  assert.ok(bad.some((line) => /more than one /.test(line)));
});

test("detects an active record pointing at a missing descriptor", () => {
  const { core } = loadModule();
  const records = REF_WATCH_ONLY_RECORDS.map(([key, value]) => [key, value]);
  const active = records.find(([key]) => key === "1161637469766565787465726e616c73706b00"); // activeexternalspk type 0
  active[1] = "00".repeat(32);
  const doc = parseRecords(records);
  const bad = badChecks(core.verifyWalletDoc(doc, coreDeps));
  assert.ok(bad.some((check) => check.label === "Active scriptPubKey"), JSON.stringify(bad));
});

test("flags record corruption as undecodable instead of losing the record", () => {
  const { core } = loadModule();
  const records = REF_WATCH_ONLY_RECORDS.map(([key, value]) => [key, value]);
  const version = records.find(([key]) => key === "0776657273696f6e");
  version[1] = "ff"; // u32le truncated to one byte
  const doc = parseRecords(records);
  assert.equal(doc.meta.version, undefined);
  assert.equal(doc.others.length, 1);
  assert.equal(doc.others[0].name, "version");
  assert.ok(doc.others[0].error);
  const bad = badChecks(core.verifyWalletDoc(doc, coreDeps));
  assert.ok(bad.some((check) => check.label === "Undecodable record"));
  // The raw row survives for the rebuild, untouched.
  assert.ok(doc.rows.some(([key]) => bytesToHex(key) === "0776657273696f6e"));
});

test("unitFromDescriptor shapes a watch-only unit like the export does", () => {
  const { core } = loadModule();
  const unit = core.unitFromDescriptor(EXTRA_ACCOUNT.public, { internal: false, active: true }, coreDeps);
  assert.equal(unit.type, 2); // wpkh
  assert.equal(unit.internal, false);
  assert.equal(unit.multiKey, false);
  assert.equal(unit.privateDescriptor, null);
  assert.equal(unit.descriptor, EXTRA_ACCOUNT.public);
  assert.deepEqual([unit.nextIndex, unit.rangeStart, unit.rangeEnd], [0, 0, 1000]);
});

test("unitFromDescriptor neuters a private descriptor and keeps the secret", () => {
  const { core } = loadModule();
  const unit = core.unitFromDescriptor(EXTRA_ACCOUNT.private, { internal: true, active: false }, coreDeps);
  assert.equal(unit.privateDescriptor, EXTRA_ACCOUNT.private);
  assert.equal(unit.descriptor, EXTRA_ACCOUNT.public, "the stored form is the neutered public descriptor");
  assert.ok(!unit.descriptor.includes("tprv"));
  assert.equal(unit.internal, true);
});

test("unitFromDescriptor rewrites SLIP-132 keys and rejects bad input", () => {
  const { core } = loadModule();
  // Re-version the account key bytes as SLIP-132 vpub (0x045f1cf6) instead of
  // tpub — a prefix swap alone would break the Base58Check checksum.
  const raw = b58checkDecode(REF_ACCOUNT_TPUB);
  const vpubKey = b58checkEncode(Uint8Array.from([0x04, 0x5f, 0x1c, 0xf6, ...raw.slice(4)]));
  const vpubBody = `pkh([420c9ea3/44h/1h/0h]${vpubKey}/0/*)`;
  const unit = core.unitFromDescriptor(vpubBody, { internal: false }, coreDeps);
  assert.ok(unit.descriptor.includes("tpub"), "vpub must be re-versioned to tpub");
  assert.ok(unit.descriptor.includes("#"), "checksum must be appended");
  assert.throws(() => core.unitFromDescriptor("wpkh(xpub123/0)", {}, coreDeps), /wildcard/);
  assert.throws(() => core.unitFromDescriptor("   ", {}, coreDeps), /Paste a descriptor/);
  // combo() has no OutputType; Core would not activate it either.
  const combo = `combo(${REF_ACCOUNT_TPUB}/0/*)`;
  assert.throws(() => core.unitFromDescriptor(combo, {}, coreDeps), /Unsupported descriptor function/);
  // More than one extended private key is the multisig private case.
  assert.throws(
    () => core.unitFromDescriptor(`wsh(sortedmulti(${EXTRA_ACCOUNT.private.slice(0, -9)},${EXTRA_ACCOUNT.private.slice(0, -9)}/0/*)`, {}, coreDeps),
    /Multisig/,
  );
});

test("unitFromDescriptor refuses a path step Core would normalize out of the stored text", () => {
  const { core } = loadModule();
  // "/00/*" parses in Core but its DescriptorID is recomputed from the
  // normalized "/0/*", so a file storing the raw text fails load.
  const zero = `wpkh([420c9ea3/84h/1h/0h]${REF_ACCOUNT_TPUB}/00/*)`;
  assert.throws(() => core.unitFromDescriptor(zero, {}, coreDeps), /leading zero|path step/);
  // A step at 2^31 is beyond Core's parser.
  const huge = `wpkh([420c9ea3/84h/1h/0h]${REF_ACCOUNT_TPUB}/2147483648/*)`;
  assert.throws(() => core.unitFromDescriptor(huge, {}, coreDeps), /path shape/);
});

test("an encrypted wallet refuses a private descriptor that would land in plaintext", () => {
  const { core } = loadModule();
  const crypted = ["1a77616c6c657464657363726970746f72637279707465646b6579" + "00".repeat(32) + "21" + "02".repeat(33), "f0" + "01".repeat(48)];
  const doc = parseRecords([...REF_PRIVATE_RECORDS, crypted]);
  const unit = core.unitFromDescriptor(EXTRA_ACCOUNT.private, { internal: false }, coreDeps);
  assert.throws(() => core.appendDescriptorRows(doc, unit, coreDeps, REF_CREATION_TIME), /encrypted/);
});

test("an out-of-range key secret reports a check instead of aborting verification", () => {
  const { core } = loadModule();
  const rows = REF_PRIVATE_RECORDS.map(([key, value]) => [key, value]);
  const keyPrefix = "1377616c6c657464657363726970746f726b6579";
  const record = rows.find(([key]) => key.startsWith(keyPrefix));
  const value = hexToBytes(record[1]);
  value.fill(0, 1 + 8, 1 + 40); // zero the 32-byte secret, keep the DER shape
  record[1] = bytesToHex(value);
  const doc = parseRecords(rows);
  const checks = core.verifyWalletDoc(doc, coreDeps);
  assert.ok(checks.some((item) => item.tone === "bad" && /not a valid secp256k1 private key/.test(item.detail)));
});

test("a malformed key record reports a check instead of aborting the whole verification", () => {
  const { core } = loadModule();
  const rows = REF_PRIVATE_RECORDS.map(([key, value]) => [key, value]);
  const keyPrefix = "1377616c6c657464657363726970746f726b6579";
  const record = rows.find(([key]) => key.startsWith(keyPrefix));
  // compactSize(3) + three bytes + the 32-byte record hash: too short to
  // carry the 32-byte secret the verifier reads.
  record[1] = "03abcdef" + "00".repeat(32);
  const doc = parseRecords(rows);
  const checks = core.verifyWalletDoc(doc, coreDeps);
  assert.ok(checks.some((item) => item.tone === "bad" && /expected DER/.test(item.detail)), "the short key record must be a bad check");
});

test("adding a descriptor appends records, rebuilds, and re-verifies clean", () => {
  const { core } = loadModule();
  const doc = parseRecords(REF_WATCH_ONLY_RECORDS);
  const unit = core.unitFromDescriptor(EXTRA_ACCOUNT.public, { internal: false, active: false }, coreDeps);
  const rows = core.appendDescriptorRows(doc, unit, coreDeps, REF_CREATION_TIME);
  const reparsed = core.parseWalletDat(core.buildWalletDat(doc, rows));
  assert.equal(reparsed.descriptors.length, 9);
  const added = reparsed.descriptors.find((entry) => entry.descriptor === unit.descriptor);
  assert.ok(added, "the new descriptor must be in the rebuilt wallet");
  assert.equal(added.active, null, "inactive descriptors get no active record");
  assert.equal(reparsed.meta.actives.length, 8, "existing active records are untouched");
  assert.deepEqual(badChecks(core.verifyWalletDoc(reparsed, coreDeps)), []);
});

test("an active addition replaces the previous active record for its type", () => {
  const { core } = loadModule();
  const doc = parseRecords(REF_WATCH_ONLY_RECORDS);
  const before = doc.meta.actives.find((active) => !active.internal && active.type === 2);
  const unit = core.unitFromDescriptor(EXTRA_ACCOUNT.public, { internal: false, active: true }, coreDeps);
  const rows = core.appendDescriptorRows(doc, unit, coreDeps, REF_CREATION_TIME);
  const reparsed = core.parseWalletDat(core.buildWalletDat(doc, rows));
  assert.equal(reparsed.meta.actives.length, 8, "replacement, not duplication");
  const after = reparsed.meta.actives.find((active) => !active.internal && active.type === 2);
  assert.notEqual(after.id, before.id);
  const added = reparsed.descriptors.find((entry) => entry.descriptor === unit.descriptor);
  assert.deepEqual(after.id, added.id);
  assert.deepEqual(badChecks(core.verifyWalletDoc(reparsed, coreDeps)), []);
});

test("adding the same descriptor twice is refused, as Core refuses it", () => {
  const { core } = loadModule();
  const doc = parseRecords(REF_WATCH_ONLY_RECORDS);
  const unit = core.unitFromDescriptor(REF_PUBLIC_DESCRIPTORS[0], { internal: false }, coreDeps);
  assert.throws(() => core.appendDescriptorRows(doc, unit, coreDeps, REF_CREATION_TIME), /already in this wallet/);
});

test("an added descriptor's keys must belong to the wallet's chain", () => {
  const { core } = loadModule();
  // BIP32 test vector 1 master keys (mainnet xpub/xprv versions).
  const xpub = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";
  const xprv = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";
  assert.equal(neuterExtendedKey(xprv), xpub, "the vector pair");
  const mainnetUnit = core.unitFromDescriptor(`wpkh(${xpub}/0/*)`, {}, coreDeps);
  const testUnit = core.unitFromDescriptor(EXTRA_ACCOUNT.public, {}, coreDeps);
  // Core decodes keys with the chain's own prefixes, so a foreign one would
  // make the rebuilt file fail to load: refused on every test chain…
  for (const applicationId of [REGTEST_APP_ID, 0x0a03cf40]) {
    const doc = parseRecords(REF_WATCH_ONLY_RECORDS, applicationId);
    assert.throws(() => core.appendDescriptorRows(doc, mainnetUnit, coreDeps, REF_CREATION_TIME), /network/);
    assert.ok(core.appendDescriptorRows(doc, testUnit, coreDeps, REF_CREATION_TIME).length > doc.rows.length);
  }
  // …and the other way round on mainnet.
  const mainnet = parseRecords(REF_WATCH_ONLY_RECORDS, 0xf9beb4d9);
  assert.throws(() => core.appendDescriptorRows(mainnet, testUnit, coreDeps, REF_CREATION_TIME), /network/);
  assert.ok(core.appendDescriptorRows(mainnet, mainnetUnit, coreDeps, REF_CREATION_TIME).length > mainnet.rows.length);
  // A private descriptor is checked too (its stored form is the neutered xpub).
  const signing = parseRecords(REF_PRIVATE_RECORDS);
  const privateUnit = core.unitFromDescriptor(`wpkh(${xprv}/0/*)`, {}, coreDeps);
  assert.throws(() => core.appendDescriptorRows(signing, privateUnit, coreDeps, REF_CREATION_TIME), /network/);
  // A file whose chain is unknown has no prefix a key could match.
  const unknown = parseRecords(REF_WATCH_ONLY_RECORDS, 0x12345678);
  assert.equal(unknown.network, null);
  assert.throws(() => core.appendDescriptorRows(unknown, testUnit, coreDeps, REF_CREATION_TIME), /network/);
});

test("a private descriptor joins a signing wallet and verifies", () => {
  const { core } = loadModule();
  const doc = parseRecords(REF_PRIVATE_RECORDS);
  const unit = core.unitFromDescriptor(EXTRA_ACCOUNT.private, { internal: false, active: false }, coreDeps);
  const rows = core.appendDescriptorRows(doc, unit, coreDeps, REF_CREATION_TIME);
  const reparsed = core.parseWalletDat(core.buildWalletDat(doc, rows));
  const added = reparsed.descriptors.find((entry) => entry.descriptor === unit.descriptor);
  assert.ok(added);
  assert.equal(added.keys.length, 1, "the neutered descriptor gets its key record");
  assert.deepEqual(badChecks(core.verifyWalletDoc(reparsed, coreDeps)), []);
});

test("a one-key multisig wrapper is still treated as a multisig shape", () => {
  const { core } = loadModule();
  const doc = parseRecords(REF_PRIVATE_RECORDS);
  const descriptor = `wsh(multi(1,${REF_ACCOUNT_TPUB}/0/*))`;
  const unit = core.unitFromDescriptor(descriptor, { internal: false }, coreDeps);
  assert.equal(unit.multiKey, true, "one key, still the multi shape");
  assert.equal(unit.type, 2);
  const rows = core.appendDescriptorRows(doc, unit, coreDeps, REF_CREATION_TIME);
  const reparsed = core.parseWalletDat(core.buildWalletDat(doc, rows));
  assert.deepEqual(badChecks(core.verifyWalletDoc(reparsed, coreDeps)), []);
});

test("a multisig active record's output type is checked against its wrapper", () => {
  const { core } = loadModule();
  // Core's OutputType for each multisig wrapper: sh = LEGACY (0),
  // sh(wsh) = P2SH_SEGWIT (1), wsh = BECH32 (2).
  for (const [descriptor, type] of [
    [`sh(multi(1,${REF_ACCOUNT_TPUB}/0/*))`, 0],
    [`sh(wsh(sortedmulti(1,${REF_ACCOUNT_TPUB}/0/*)))`, 1],
    [`wsh(multi(1,${REF_ACCOUNT_TPUB}/0/*))`, 2],
  ]) {
    const doc = parseRecords(REF_WATCH_ONLY_RECORDS);
    const unit = core.unitFromDescriptor(descriptor, { internal: false, active: true }, coreDeps);
    assert.equal(unit.type, type);
    const reparsed = core.parseWalletDat(core.buildWalletDat(doc, core.appendDescriptorRows(doc, unit, coreDeps, REF_CREATION_TIME)));
    assert.deepEqual(badChecks(core.verifyWalletDoc(reparsed, coreDeps)), [], descriptor);
    const added = reparsed.descriptors.find((entry) => entry.descriptor === unit.descriptor);
    added.active.type = 3; // filed as Taproot
    assert.ok(badChecks(core.verifyWalletDoc(reparsed, coreDeps)).some((check) => new RegExp(`marked type 3 but its wrapper is type ${type}`).test(check.detail)), descriptor);
  }
});

test("a multisig descriptor's single xprv is found in a later slot, not the first xpub", () => {
  const { core } = loadModule();
  const doc = parseRecords(REF_PRIVATE_RECORDS);
  const privKey = EXTRA_ACCOUNT.private.match(/tprv[1-9A-HJ-NP-Za-km-z]{90,}/)[0];
  const descriptor = `wsh(sortedmulti(1,${REF_ACCOUNT_TPUB}/0/*,${privKey}/0/*))`;
  const unit = core.unitFromDescriptor(descriptor, { internal: false }, coreDeps);
  assert.ok(!unit.descriptor.includes("tprv"), "the stored form is neutered");
  const rows = core.appendDescriptorRows(doc, unit, coreDeps, REF_CREATION_TIME);
  const reparsed = core.parseWalletDat(core.buildWalletDat(doc, rows));
  const added = reparsed.descriptors.find((entry) => entry.descriptor === unit.descriptor);
  assert.ok(added);
  assert.equal(added.keys.length, 1, "one key record for the one xprv");
  const expectedPubkey = publicKeyForPrivate(b58checkDecode(privKey).slice(46, 78));
  assert.deepEqual(added.keys[0].pubkey, expectedPubkey, "the record belongs to the xprv, not the first xpub");
  assert.deepEqual(badChecks(core.verifyWalletDoc(reparsed, coreDeps)), []);
});

test("a watch-only wallet refuses a private descriptor, like Core", () => {
  const { core } = loadModule();
  const doc = parseRecords(REF_WATCH_ONLY_RECORDS);
  const unit = core.unitFromDescriptor(EXTRA_ACCOUNT.private, { internal: false }, coreDeps);
  assert.throws(() => core.appendDescriptorRows(doc, unit, coreDeps, REF_CREATION_TIME), /disable-private-keys/);
});

test("unknown record types survive a rebuild byte-for-byte", () => {
  const { core } = loadModule();
  const extra = ["07707572706f7365", "0102"]; // a made-up "purpose"-shaped record
  const doc = parseRecords([...REF_WATCH_ONLY_RECORDS, extra]);
  assert.equal(doc.others.length, 1);
  const reparsed = core.parseWalletDat(core.buildWalletDat(doc));
  assert.ok(reparsed.rows.some(([key, value]) => bytesToHex(key) === extra[0] && bytesToHex(value) === extra[1]));
});

// --- Key Station import (stationImports) -------------------------------------
// Contract: import is offered only for secrets that provably ARE the node the
// descriptor's embedded extended key names (its pubkey field matches the key
// record's pubkey both ways), reassembled into a depth-0 root or depth-3
// account xprv in the wallet's own network family. Watch-only wallets,
// encrypted wallets (walletdescriptorcryptedkey), and secrets whose records
// cannot be tied to that node must be refused, never guessed.

// stationImports needs base58 encode and hash160 on top of the core deps;
// both come from the harness's independent reference crypto here.
const importDeps = {
  ...coreDeps,
  base58Encode: b58checkEncode,
  // Full HASH160, exactly as the app's has160 dep returns; the module takes
  // the BIP32 fingerprint head itself.
  hash160: (bytes) => ripemd160(sha256(bytes)),
};
const parseHex = (records) => loadModule().core.parseWalletDat(
  dbFromRecords(records.map(([key, value]) => [bytesToHex(hexToBytes(key)), bytesToHex(hexToBytes(value))])),
);

test("a Core-generated wallet imports as exactly one root key", () => {
  const { core } = loadModule();
  const doc = parseHex(GENERATED_ROWS);
  const result = core.stationImports(doc, importDeps);
  assert.equal(result.reason, null);
  assert.equal(result.skipped, 0);
  assert.equal(result.imports.length, 1, "six descriptors share one master key");
  const [item] = result.imports;
  assert.equal(item.kind, "root");
  assert.equal(item.script, null, "a root import covers every script type");
  assert.equal(item.internal, true);
  assert.equal(item.external, true);
  // Ground truth: GENERATED_ROOT_TPRV is the harness-serialized BIP32 root of
  // the fixed fixture seed — assembly must reproduce it byte for byte.
  assert.equal(item.xprv, GENERATED_ROOT_TPRV);
  assert.equal(item.fingerprint, GENERATED_MASTER_FINGERPRINT);
  assert.equal(item.fingerprint.length, 8, "the displayed fingerprint is the BIP32 4-byte head");
});

test("import and verification zero their secret temporaries", () => {
  const { core } = loadModule();
  const doc = parseHex(GENERATED_ROWS);
  const seen = [];
  const spy = (fn) => (bytes) => { seen.push(bytes); return fn(bytes); };
  const spied = { ...importDeps, publicKeyForPrivate: spy(importDeps.publicKeyForPrivate), base58Encode: spy(importDeps.base58Encode) };
  const result = core.stationImports(doc, spied);
  assert.equal(result.imports[0].xprv, GENERATED_ROOT_TPRV, "the key is assembled before its buffers are wiped");
  core.verifyWalletDoc(doc, spied);
  assert.ok(seen.length > 0);
  for (const bytes of seen) assert.ok(bytes.every((byte) => byte === 0), "a secret or xprv buffer was left populated");
  // The parsed records themselves stay intact: they are the wallet's data.
  assert.ok(doc.descriptors.some((entry) => entry.keys.some((key) => key.der.some((byte) => byte !== 0))));
});

test("an imported account-key wallet imports as one account xprv per script type", () => {
  const { core } = loadModule();
  const doc = parseRecords(REF_PRIVATE_RECORDS);
  const result = core.stationImports(doc, importDeps);
  assert.equal(result.reason, null);
  assert.equal(result.skipped, 0);
  assert.equal(result.imports.length, 4, "one import per (account key, script type)");
  // Ground truth: the reference wallet's descriptors publish the account tprv
  // itself; the assembled key must equal it exactly, script-mapped.
  const refTprv = REF_PRIVATE_DESCRIPTORS[0].match(/(tprv[1-9A-HJ-NP-Za-km-z]{90,})/)[1];
  const scripts = ["bip44", "bip49", "bip84", "bip86"];
  for (const item of result.imports) {
    assert.equal(item.kind, "account");
    assert.equal(item.xprv, refTprv);
    assert.ok(scripts.includes(item.script));
    assert.equal(item.internal, true);
    assert.equal(item.external, true);
    // node fingerprint = the account key's HASH160 — independently computed
    // from the reference account xpub's pubkey.
    assert.equal(item.fingerprint, bytesToHex(ripemd160(sha256(b58checkDecode(REF_ACCOUNT_TPUB).slice(45, 78))).subarray(0, 4)));
    assert.equal(item.fingerprint.length, 8);
  }
  assert.deepEqual(result.imports.map((item) => item.script).sort(), scripts);
});

test("an import carries the wallet's chain and the origin's account and fingerprint", () => {
  const { core } = loadModule();
  // A root import from a regtest wallet: the chain is regtest (bcrt1…), not
  // just the tprv family; no origin, account 0' is the path Key Station uses.
  const [root] = core.stationImports(parseHex(GENERATED_ROWS), importDeps).imports;
  assert.equal(root.network, "regtest");
  assert.equal(root.account, 0);
  assert.equal(root.originFingerprint, null);
  // An account import: the origin [420c9ea3/<purpose>h/1h/0h] claims a master
  // fingerprint the account key cannot prove, and names the account.
  const signet = core.stationImports(parseRecords(REF_PRIVATE_RECORDS, 0x0a03cf40), importDeps).imports;
  assert.equal(signet.length, 4);
  for (const item of signet) {
    assert.equal(item.network, "signet");
    assert.equal(item.account, 0);
    assert.equal(item.originFingerprint, "420c9ea3");
  }
  // Account 5' in the origin still imports (the key is the account node),
  // and the item names account 5, not the 0' default.
  const doc = parseRecords(REF_PRIVATE_RECORDS);
  for (const entry of doc.descriptors) entry.descriptor = entry.descriptor.replace(/\/1h\/0h\]/, "/1h/5h]");
  const fifth = core.stationImports(doc, importDeps).imports;
  assert.equal(fifth.length, 4);
  for (const item of fifth) assert.equal(item.account, 5);
});

test("a tr(NUMS, multi_a) script-path key is not imported as BIP86 key-path", () => {
  const { core } = loadModule();
  const nums = "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0";
  const privKey = EXTRA_ACCOUNT.private.match(/tprv[1-9A-HJ-NP-Za-km-z]{90,}/)[0];
  const unit = core.unitFromDescriptor(`tr(${nums},multi_a(1,${privKey}/0/*))`, {}, coreDeps);
  const doc = parseRecords(REF_PRIVATE_RECORDS);
  const rows = core.appendDescriptorRows(doc, unit, coreDeps, REF_CREATION_TIME);
  const reparsed = core.parseWalletDat(core.buildWalletDat(doc, rows));
  const result = core.stationImports(reparsed, importDeps);
  assert.equal(result.imports.length, 4, "only the four account key-path imports remain");
  assert.ok(result.skipped >= 1, "the script-path key is counted as skipped");
});

test("a watch-only wallet has nothing to import", () => {
  const { core } = loadModule();
  const doc = parseRecords(REF_WATCH_ONLY_RECORDS);
  const result = core.stationImports(doc, importDeps);
  assert.equal(result.reason, "no-private-keys");
  assert.deepEqual(result.imports, []);
});

test("an encrypted Core wallet is refused, not guessed at", () => {
  const { core } = loadModule();
  // Any walletdescriptorcryptedkey record marks an encrypted wallet: its
  // secrets are not in the file in usable form. The name is 26 characters
  // (0x1a); the payload shape is irrelevant to the refusal.
  const crypted = ["1a77616c6c657464657363726970746f72637279707465646b6579" + "00".repeat(32) + "21" + "02".repeat(33), "f0" + "01".repeat(48)];
  const doc = parseHex([...GENERATED_ROWS, crypted]);
  const result = core.stationImports(doc, importDeps);
  assert.equal(result.reason, "encrypted");
  assert.deepEqual(result.imports, []);
});

test("a master key with a short path (not the standard account path) is refused", () => {
  const { core } = loadModule();
  const doc = parseHex(GENERATED_ROWS);
  // Core would watch m/0/i; Key Station derives m/84'/1'/0'/0/i.
  for (const entry of doc.descriptors) entry.descriptor = entry.descriptor.replace(/\/(?:44|84|86)h\/1h\/0h\/([01])\/\*\)/, "/$1/*)");
  const result = core.stationImports(doc, importDeps);
  assert.equal(result.reason, "unsupported-key-records");
  assert.deepEqual(result.imports, []);
  assert.equal(result.skipped, 6);
});

test("a master key on a non-zero account is refused", () => {
  const { core } = loadModule();
  const doc = parseHex(GENERATED_ROWS);
  // Key Station always derives account 0'; this watches m/…/5h/….
  for (const entry of doc.descriptors) entry.descriptor = entry.descriptor.replace("/1h/0h/", "/1h/5h/");
  const result = core.stationImports(doc, importDeps);
  assert.equal(result.imports.length, 0);
  assert.equal(result.skipped, 6);
});

test("an account key with an extra path step is refused", () => {
  const { core } = loadModule();
  const doc = parseRecords(REF_PRIVATE_RECORDS);
  // account/7/0/i; Key Station would derive account/0/i.
  for (const entry of doc.descriptors) entry.descriptor = entry.descriptor.replace(/\/([01])\/\*\)/, "/7/$1/*)");
  const result = core.stationImports(doc, importDeps);
  assert.equal(result.imports.length, 0);
  assert.equal(result.skipped, 8);
});

test("an account key origin whose purpose disagrees with the script is refused", () => {
  const { core } = loadModule();
  const doc = parseRecords(REF_PRIVATE_RECORDS);
  for (const entry of doc.descriptors) entry.descriptor = entry.descriptor.replace("/44h/1h/0h", "/84h/1h/0h");
  const result = core.stationImports(doc, importDeps);
  // The two bip44 descriptors are refused; the other three scripts still import.
  assert.equal(result.imports.length, 3);
  assert.equal(result.skipped, 2);
});

test("key records whose secrets do not match their own pubkeys are refused", () => {
  const { core } = loadModule();
  const rows = GENERATED_ROWS.map(([key, value]) => [key, value]);
  const keyPrefix = "1377616c6c657464657363726970746f726b6579"; // streamString("walletdescriptorkey")
  const records = rows.filter(([key]) => key.startsWith(keyPrefix));
  assert.ok(records.length > 1, "fixture wallet has key records to tamper");
  // value = compactSize(214) || der(214) || hash; flip one secret byte in
  // every record (the sole shared secret no longer proves itself anywhere).
  for (const record of records) {
    const value = hexToBytes(record[1]);
    value[1 + 8] ^= 0x01;
    record[1] = bytesToHex(value);
  }
  const doc = parseHex(rows);
  const result = core.stationImports(doc, importDeps);
  assert.equal(result.reason, "unsupported-key-records");
  assert.deepEqual(result.imports, []);
});

test("a tampered secret record is skipped, while the proven copies still import", () => {
  const { core } = loadModule();
  const rows = GENERATED_ROWS.map(([key, value]) => [key, value]);
  const keyPrefix = "1377616c6c657464657363726970746f726b6579"; // streamString("walletdescriptorkey")
  const record = rows.find(([key]) => key.startsWith(keyPrefix));
  const value = hexToBytes(record[1]);
  value[1 + 8] ^= 0x01;
  record[1] = bytesToHex(value);
  const doc = parseHex(rows);
  const result = core.stationImports(doc, importDeps);
  // The other key records still prove the same master key; the corrupt one
  // drops out and is counted.
  assert.equal(result.reason, null);
  assert.equal(result.skipped, 1);
  assert.equal(result.imports.length, 1);
  assert.equal(result.imports[0].xprv, GENERATED_ROOT_TPRV);
});

test("a record naming a node the descriptor's embedded key is not is refused", () => {
  const { core } = loadModule();
  // A copy of the generated wallet whose descriptors embed a DIFFERENT
  // wallet's root tpub: the key records still carry the fixture's secret, so
  // the assembled node would be someone else's account — refuse.
  const other = sha256(new TextEncoder().encode("entropylab core-wallet import fixture other"));
  const otherTpub = serializeExtendedKey(hdMasterFromSeed(other), 0x043587cf, false);
  const records = [
    ...GENERATED_ROWS.slice(0, 5),
    ...buildGeneratedUnitRecords(GENERATED_SEED, { embeddedTpub: otherTpub }).map(([key, value]) => [bytesToHex(key), bytesToHex(value)]),
  ];
  const doc = parseHex(records);
  const result = core.stationImports(doc, importDeps);
  assert.equal(result.reason, "unsupported-key-records");
  assert.deepEqual(result.imports, []);
});

// --- Core Wallet UI (src/js/core-wallet-ui.js) ------------------------------
// The UI module is an ES module; strip its imports and provide the app's
// helpers so the handlers can be exercised against a minimal fake DOM.

const loadCoreWalletUi = () => {
  const source = read("src/js/core-wallet-ui.js")
    .replace(/^import .*$/gm, "")
    .replace(/^export /gm, "");
  const t = (text, params) => text.replace(/\{(\w+)\}/g, (_, key) => params?.[key] ?? `{${key}}`);
  const tAttr = t;
  const tHtml = t;
  // A private cell is marked, so a test can tell where its copy would go.
  const expandableHtml = (text, options = {}) => (options.privateValue ? `[private]${text}[/private]` : text);
  const initExpandable = () => {};
  const hodlCoreWallet = loadModule().core;
  const factory = new Function(
    "t", "tAttr", "tHtml", "expandableHtml", "initExpandable", "hodlCoreWallet", "base58checkDecode",
    `${source}\nreturn { initCoreWallet, descriptorHoldsSecret };`,
  );
  return factory(t, tAttr, tHtml, expandableHtml, initExpandable, hodlCoreWallet, b58checkDecode);
};

const makeFakeElement = (id) => ({
  id,
  value: "",
  checked: false,
  hidden: false,
  disabled: false,
  textContent: "",
  innerHTML: "",
  dataset: {},
  files: [],
  listeners: {},
  addEventListener(type, handler) { this.listeners[type] = handler; },
  setAttribute(name, value) { this[name] = value; },
  querySelectorAll() { return this.buttons ?? []; },
});

const setupCoreWalletUi = () => {
  const originalDocument = globalThis.document;
  const originalAddEventListener = globalThis.addEventListener;
  const ids = [
    "core-upload", "core-file", "core-download", "core-wipe", "core-error",
    "core-out", "core-reveal", "core-add", "core-add-text", "core-add-internal",
    "core-add-active", "core-add-go",
  ];
  const elements = Object.fromEntries(ids.map((id) => [id, makeFakeElement(id)]));
  const documentListeners = {};
  globalThis.document = {
    getElementById: (id) => elements[id] ?? null,
    addEventListener: (type, handler) => { documentListeners[type] = handler; },
  };
  globalThis.addEventListener = () => {};
  const { initCoreWallet } = loadCoreWalletUi();
  const imported = [];
  initCoreWallet({
    deps: importDeps,
    onImportIntoStation: (item) => imported.push(item),
    copyIcon: "",
    copiedIcon: "",
  });
  const cleanup = () => {
    globalThis.document = originalDocument;
    globalThis.addEventListener = originalAddEventListener;
  };
  return { elements, documentListeners, imported, cleanup };
};

test("hodl:conceal clears a pasted private descriptor but leaves a watch-only one", (t) => {
  const { elements, documentListeners, cleanup } = setupCoreWalletUi();
  t.after(cleanup);
  const addText = elements["core-add-text"];
  const xprv = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";
  const yprv = "Yprv" + xprv.slice(4);
  const xpub = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";
  addText.value = xprv;
  documentListeners["hodl:conceal"]();
  assert.equal(addText.value, "", "a pasted xprv must be cleared on conceal");
  addText.value = yprv;
  documentListeners["hodl:conceal"]();
  assert.equal(addText.value, "", "a pasted Yprv must be cleared on conceal");
  addText.value = xpub;
  documentListeners["hodl:conceal"]();
  assert.equal(addText.value, xpub, "a watch-only xpub is harmless and stays");
  // A checksum must match, as in the report (MiniMax, round 14).
  const body = `wpkh(${xpub}/0/*)`;
  const sum = coreDeps.checksum(body);
  addText.value = `${body}#${sum}`;
  documentListeners["hodl:conceal"]();
  assert.equal(addText.value, `${body}#${sum}`, "a watch-only descriptor under its checksum stays");
  addText.value = `${body}#${sum[0] === "q" ? "p" : "q"}${sum.slice(1)}`;
  documentListeners["hodl:conceal"]();
  assert.equal(addText.value, "", "a descriptor under a checksum that does not match must be cleared on conceal");
});

test("a failed verification refuses the import handler even if the button is clicked", async (t) => {
  const { elements, imported, cleanup } = setupCoreWalletUi();
  t.after(cleanup);
  const out = elements["core-out"];
  out.buttons = [0, 1, 2, 3].map((index) => {
    const button = makeFakeElement(`import-${index}`);
    button.dataset.coreImportGo = String(index);
    return button;
  });
  const records = REF_PRIVATE_RECORDS.map(([key, value]) => [key, value]);
  const version = records.find(([key]) => key === "0776657273696f6e");
  version[1] = "ff"; // u32le truncated to one byte
  const bytes = dbFromRecords(records);
  const file = elements["core-file"];
  file.files = [{ size: bytes.length, arrayBuffer: async () => bytes.slice().buffer }];
  file.listeners.change();
  await new Promise((resolve) => setTimeout(resolve, 0));
  out.buttons[0].listeners.click();
  assert.equal(imported.length, 0, "a failed document must not import");
  // Copy is asserted for presence only (AGENTS.md): the refusal shows a message.
  assert.ok(elements["core-error"].textContent.trim(), "a refused import shows a message");
});

// A descriptor record Core wrote is public (its keys sit in walletdescriptorkey
// records), but the file can come from anywhere: a descriptor is public only
// when the reader can read it with Core's grammar and finds only public keys
// in it; anything else is private (#1347: K3.1 rounds 8 and 12, Astra rounds
// 9, 13 and 14, GLM round 13). Fail closed.
test("a descriptor is public only in a public form; anything else is private", () => {
  const { descriptorHoldsSecret } = loadCoreWalletUi();
  const xpub = "xpub6CUGRUonZSQ4TWtTMmzXdrXDtypWKiKrhko4egpiMZbpiaQL2jkwSB1icqYh2cfDfVxdx4df189oLKnC5fSwqPfgyP3hooxujYzAu3fDVmz";
  const xprv = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";
  const wif = "L1aW4aubDFB7yfras2S1mN3bqg9nwySY8nkoLmJebSLD5BWv3ENZ";
  assert.equal(wif.length, 52);
  assert.equal(descriptorHoldsSecret(`wpkh([d34db33f/84h/0h/0h]${xpub}/0/*)#abcdefgh`), false);
  assert.equal(descriptorHoldsSecret(`pkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)`), false);
  assert.equal(descriptorHoldsSecret(`wpkh(${xprv}/84h/0h/0h/0/*)`), true);
  assert.equal(descriptorHoldsSecret(`sh(wpkh(${wif}))`), true);
  assert.equal(descriptorHoldsSecret(`pk(5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ)`), true, "an uncompressed-key WIF (51 characters)");
  // Public forms Core writes or imports.
  // A valid tpub (the old fixture failed its own Base58Check checksum, which
  // the reader now requires; K3.1, round 15).
  const tpub = "tpubD6NzVbkrYhZ4XgiXtGrdW5XDAPFCL9h7we1vwNCpn8tGbBcgfVYjXyhWo4E1xkh56hjod1RhGjxbaTLV3X4FyWuejifB9jusQ46QzG87VKp";
  assert.equal(descriptorHoldsSecret(`tr([d34db33f/86h/1h/0h]${tpub}/<0;1>/*)#abcdefgh`), false, "a multipath tpub descriptor");
  assert.equal(descriptorHoldsSecret(`wsh(sortedmulti(2,[d34db33f/48h/0h/0h/2h]${xpub}/0/*,02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5))`), false, "a multisig");
  assert.equal(descriptorHoldsSecret("wsh(and_v(v:pk(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5),older(144)))"), false, "a miniscript policy");
  assert.equal(descriptorHoldsSecret(`pkh(04${"ab".repeat(64)})`), false, "an uncompressed hex pubkey");
  // Everything else fails closed.
  assert.equal(descriptorHoldsSecret(`wpkh(${"11".repeat(32)})`), true, "a raw 32-byte hex key (K3.1, round 12)");
  assert.equal(descriptorHoldsSecret(`tr(${"11".repeat(32)})`), true, "an x-only key cannot be told from a raw secret");
  assert.equal(descriptorHoldsSecret("wpkh(abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about)"), true, "words");
  assert.equal(descriptorHoldsSecret(`raw(${"11".repeat(32)})`), true, "raw() can hold anything");
  assert.equal(descriptorHoldsSecret("addr(bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq)"), true, "addr() is not a key form");
  assert.equal(descriptorHoldsSecret(`wsh(sha256(${"11".repeat(32)}))`), true, "a hash body is 32 raw bytes");
  assert.equal(descriptorHoldsSecret(`pkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)#${wif}`), true, "a checksum suffix is 8 characters");
  assert.equal(descriptorHoldsSecret(""), false, "an empty field holds nothing");
  // Each token must sit where the grammar puts it (GLM, round 13).
  const pubkey = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
  assert.equal(descriptorHoldsSecret("deadbeef/".repeat(7) + "deadbeef"), true, "8-hex chunks are not fingerprints (GLM's repro)");
  assert.equal(descriptorHoldsSecret(`wpkh(${"deadbeef/".repeat(7)}deadbeef)`), true, "a fingerprint sits right after [");
  assert.equal(descriptorHoldsSecret(`wpkh([d34db33f/deadbeef/cafebabe]${xpub}/0/*)`), true, "a second fingerprint in a key origin");
  assert.equal(descriptorHoldsSecret(`wsh(and_v(v,pk(${pubkey})))`), true, "a wrapper sits before :");
  assert.equal(descriptorHoldsSecret(`wpkh(pk,${pubkey})`), true, "a function sits before (");
  assert.equal(descriptorHoldsSecret(`wpkh(${pubkey}/${pubkey})`), true, "a key sits after (, ',', { or ]");
  assert.equal(descriptorHoldsSecret("144"), true, "a number sits inside a function");
  assert.equal(descriptorHoldsSecret("wpkh(00010203/04050607/08090a0b/0c0d0e0f)"), true, "Astra's segmented entropy (round 13)");
  assert.equal(descriptorHoldsSecret("wpkh(00010203/04050607/08090801/02030405)"), true, "digit-only chunks are not a number argument");
  assert.equal(descriptorHoldsSecret(`wpkh([d34db33f/2147483648]${xpub}/0/*)`), true, "a path step Core refuses (2^31)");
  assert.equal(descriptorHoldsSecret(`wpkh([d34db33f/2147483647h]${xpub}/0/*)`), false, "the largest path step");
  assert.equal(descriptorHoldsSecret(`wsh(or_i(0,and_v(v:pk(${pubkey}),after(1234567))))`), false, "number arguments");
  assert.equal(descriptorHoldsSecret(xpub), false, "a bare xpub");
  assert.equal(descriptorHoldsSecret(`${xpub}/0/*`), false, "a bare xpub with a path");
  assert.equal(descriptorHoldsSecret(`wpkh([12345678/84h/0h/0h]${xpub}/0/*)`), false, "an all-digit fingerprint");
  assert.equal(descriptorHoldsSecret(`tr(${xpub}/0/*,{pk(${pubkey}),pk([d34db33f/1]${xpub}/1/*)})`), false, "a script tree");
  assert.equal(descriptorHoldsSecret(`tr(${xpub}/0/*,{pk(${"11".repeat(32)}),pk(${pubkey})})`), true, "an x-only leaf key stays private");
  // Each argument must be the kind Core's function takes (Astra, round 14).
  assert.equal(descriptorHoldsSecret("wpkh(00010203,04050607,08090801,02030405,06070809,01020304,05060708,09010203)"), true, "numbers where wpkh() takes a key (Astra's repro)");
  assert.equal(descriptorHoldsSecret(`multi(1,${pubkey},1234567890)`), true, "a number where multi() takes a key");
  assert.equal(descriptorHoldsSecret(`multi(3,${pubkey},${pubkey})`), true, "a threshold above its count");
  assert.equal(descriptorHoldsSecret(`multi(0,${pubkey})`), true, "a threshold of 0");
  assert.equal(descriptorHoldsSecret(`wsh(and_v(v:pk(${pubkey}),older(2147483648)))`), true, "a lock time Core refuses (2^31)");
  assert.equal(descriptorHoldsSecret(`wsh(and_v(v:pk(${pubkey}),older(0144)))`), true, "a number with a leading zero");
  assert.equal(descriptorHoldsSecret("older(144)"), true, "a miniscript fragment outside wsh() or tr()");
  assert.equal(descriptorHoldsSecret(`wpkh(${pubkey}/0)`), true, "a path after a hex key");
  assert.equal(descriptorHoldsSecret("wpkh(/1/2/3)"), true, "path steps without a key");
  assert.equal(descriptorHoldsSecret(`pkh(${xpub}/<0;1>/<2;3>)`), true, "two multipath steps");
  assert.equal(descriptorHoldsSecret(`wpkh([d34db33f/84H]${xpub}/0/*)`), true, "a step marked H, which Core does not read");
  assert.equal(descriptorHoldsSecret(`wsh(and_v(v:sortedmulti(1,${pubkey}),older(1)))`), true, "sortedmulti() inside a fragment");
  assert.equal(descriptorHoldsSecret(`wpkh(04${"ab".repeat(64)})`), true, "an uncompressed key in segwit");
  assert.equal(descriptorHoldsSecret(`tr(${xpub}/0/*,multi(1,${pubkey}))`), true, "multi() in a tr() leaf");
  assert.equal(descriptorHoldsSecret(`wsh(${`and_v(v:pk(${pubkey}),`.repeat(50)}1${")".repeat(50)})`), false, "nested fragments");
  assert.equal(descriptorHoldsSecret(`wsh(${"and_v(1,".repeat(100000)}1${")".repeat(100000)})`), true, "nesting too deep to read fails closed");
  assert.equal(descriptorHoldsSecret(`pkh(${pubkey})${"00".repeat(32)}`), true, "bytes after the descriptor");
  const ui = read("src/js/core-wallet-ui.js");
  assert.match(ui, /export const descriptorHoldsSecret = \(text\) => !hodlCoreWallet\.descriptorIsPublic\(text, base58checkDecode\);/, "the report uses the reader's rule");
  assert.match(ui, /push\(tHtml\("Descriptor"\), fileValueHtml\(entry\.descriptor, \{[^\n]*isPublic: entry\.shownPublic === true \}\)\);/, "the Descriptor cell is public only when the verification vouched for it");
  assert.match(ui, /const privateHex = \(bytes, label\) => fileValueHtml\(bytesToHex\(bytes\), \{ label, bytes: bytes\.length \}\);/, "an undecoded record's bytes are never public");
  assert.match(ui, /privateHex\(record\.value, tHtml\("Record value \(hex\)"\)\)/);
  assert.match(ui, /privateHex\(record\.key, tHtml\("Record key \(hex\)"\)\)/);
  assert.match(ui, /const fileValueHtml = \(text, \{ label, isPublic = false, bytes \} = \{\}\) => \(isPublic\n\s*\? expandableHtml\(text, \{ label \}\)\n\s*: reveal\.checked\n\s*\? expandableHtml\(text, \{ label, privateValue: true \}\)/, "a value not vouched for is redacted until revealed and a private value when shown");
});

// An outside reference for the rule above: descriptors from Bitcoin Core's
// own tests (src/test/descriptor_tests.cpp, read 2026-11-01). Its public forms
// read as public, its forms with private keys as private, and the forms it
// refuses to parse as private (DeepSeek red team, round 14: the rule's tests
// should not only restate the rule).
test("Bitcoin Core's descriptor test vectors read as Core reads them", () => {
  const { descriptorHoldsSecret } = loadCoreWalletUi();
  const publicForms = [
    "combo([01234567]xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL)",
    "multi(1,03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd,04a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd5b8dec5235a0fa8722476c7709c02559e3aa73aa03918ba2d492eea75abea235)",
    "pkh([deadbeef/1/2'/3/4']03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd)",
    "rawtr([5a61ff8e/86h/1h/0h]xpub6DtZpc9PRL2B6pwoNGysmHAaBofDmWv5S6KQEKKGPKhf5fV62ywDtSziSApYVK3JnYY5KUSgiCwiXW5wtd8z7LNBxT9Mu5sEro8itdGfTeA/1/*)#vwgx7hj9",
    "sh(wpkh(xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8/10/20/30/40/*'))",
    "sh(wsh(thresh(2,ndv:after(1000),a:and_n(multi(1,xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL,xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y/0),n:older(2)))))",
    "tr(xpub6CY33ZvKuS63kwDnpNCCo5YrrgkUXgdUKdCVhd4Dru5gCB3z8wGnqFiUP98Za5pYSYF5KmvBHTY3Ra8FAJGggzBjuHS69WzN8gscPupuZwK/<2;3>,l:pk(xpub6E9a95u27Qqa13XEz62FUgaFMWzHnHrb54dWfMHU7K9A33eDccvUkbu1sHYoByHAgJdR326rWqn9pGZgZHz1afDprW5gGwS4gUX8Ri6aGPZ))",
    "wsh(or_d(pk([2557c640/48h/1h/0h/2h]xpub6ArU6mnJDxmynaVKLV8FiFDaA9bVUw6efLEqt99qGK6B4QVWiNjc21JNFKkXNjgT8NCUmpFpSSBrYFtWEAqGirbqT4J1bRFpWyAnYdzmZUm/<0;1>/*),and_v(v:pkh([00aabb22/48h/1h/0h/2h]xpub6ArU6mnJDxmyogzqia2fdnD3gWHvfDtZAHdmKx4ccJwUBZd3rpgQM9qgmPAn1mqT2yh81uvGGohMkg3fNLoXZzn7sRo4a1X3KnCAVot2yuS/<0;1>/*),older(2))))",
    "wsh(thresh(1,pk(xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL),a:pkh(xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y/0)))",
  ];
  const privateForms = [
    "pkh([deadbeef/1/2'/3/4']L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1)",
    "sh(wpkh(xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi/10/20/30/40/*'))",
    "combo(5KYZdUEo39z3FPrtuX2QbbwGnNP5zTd7yyr2SC1j299sBCnWjss)",
  ];
  const unparsable = [
    "pkh([deadbeef]/1/2'/3/4']03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd)",
    "pkh(deadbeef/1/2h/3/4h]03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd)",
    "pkh(xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB/2147483648)",
    "pkh(xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB/<0;1>/<2;3>)",
    "multi(0,03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd,04a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd5b8dec5235a0fa8722476c7709c02559e3aa73aa03918ba2d492eea75abea235)",
    "multi(3,03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd,04a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd5b8dec5235a0fa8722476c7709c02559e3aa73aa03918ba2d492eea75abea235)",
    "multi(a,03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd,04a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd5b8dec5235a0fa8722476c7709c02559e3aa73aa03918ba2d492eea75abea235)",
    "sh(sh(pk(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd)))",
    "sh(combo(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd))",
    "sh(tr(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd))",
    "sh(wpkh(04a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd5b8dec5235a0fa8722476c7709c02559e3aa73aa03918ba2d492eea75abea235))",
    "tr(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd,multi(1,032707170c71d8f75e4ca4e3fce870b9409dcaf12b051d3bcadff74747fa7619c0))",
    "multi_a(1,03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd)",
    "combo([012345678]xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL)",
  ];
  for (const descriptor of publicForms) assert.equal(descriptorHoldsSecret(descriptor), false, descriptor);
  for (const descriptor of privateForms) assert.equal(descriptorHoldsSecret(descriptor), true, descriptor);
  for (const descriptor of unparsable) assert.equal(descriptorHoldsSecret(descriptor), true, descriptor);
});

// A descriptor that carries a key is private DOM like the key records
// (Astra, round 9): redacted until revealed, hidden again on hodl:conceal,
// and private in the expand window while shown.
test("a key-bearing descriptor is redacted until revealed and concealed again on hodl:conceal", async (t) => {
  const { elements, documentListeners, cleanup } = setupCoreWalletUi();
  t.after(cleanup);
  const xprv = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";
  const records = REF_WATCH_ONLY_RECORDS.map(([key, value]) => [key, value]);
  const row = records.find(([key]) => key.startsWith("1077616c6c657464657363726970746f72")); // "walletdescriptor"
  const text = Buffer.from(row[1], "hex").toString("latin1");
  assert.match(text, /tpub[1-9A-HJ-NP-Za-km-z]{107}/);
  const secret = text.replace(/tpub[1-9A-HJ-NP-Za-km-z]{107}/, xprv); // same length: the record's size prefix holds
  row[1] = Buffer.from(secret, "latin1").toString("hex");
  const bytes = dbFromRecords(records);
  const file = elements["core-file"], out = elements["core-out"], reveal = elements["core-reveal"];
  file.files = [{ size: bytes.length, arrayBuffer: async () => bytes.slice().buffer }];
  file.listeners.change();
  await new Promise((resolve) => setTimeout(resolve, 0));
  assert.equal(elements["core-error"].textContent, "", "the crafted file must still load");
  assert.ok(out.innerHTML.includes("[420c9ea3/44h/1h/0h]"), "the report did not render the watch-only descriptors");
  assert.ok(!out.innerHTML.includes(xprv), "a key-bearing descriptor is shown while nothing is revealed");
  reveal.checked = true;
  reveal.listeners.change();
  assert.ok(out.innerHTML.includes(`[private]pkh([420c9ea3/44h/1h/0h]${xprv}`), "a revealed key-bearing descriptor must be a private value");
  documentListeners["hodl:conceal"]();
  assert.equal(reveal.checked, false, "conceal must turn reveal off");
  assert.ok(!out.innerHTML.includes(xprv), "a key-bearing descriptor is shown after conceal");
});

// An undecoded record can hold anything (K3.1, round 9): its value is private
// DOM like the key records, redacted until revealed and hidden again on
// hodl:conceal (Astra, round 10), and a private value in the expand window;
// so are its key bytes (round 11). A type name Bitcoin Core writes is public.
test("an undecoded record's key bytes and value are private DOM; a type name Core writes is public", async (t) => {
  const { elements, documentListeners, cleanup } = setupCoreWalletUi();
  t.after(cleanup);
  const wifHex = Buffer.from("L1aW4aubDFB7yfras2S1mN3bqg9nwySY8nkoLmJebSLD5BWv3ENZ").toString("hex");
  const entropyHex = "000102030405060708090a0b0c0d0e0f"; // short enough to be shown inline, were it shown
  const bytes = dbFromRecords([...REF_WATCH_ONLY_RECORDS, ["027478", wifHex], ["046e616d65", entropyHex]]); // "tx" and "name" records, which the reader does not decode
  const file = elements["core-file"], out = elements["core-out"], reveal = elements["core-reveal"];
  file.files = [{ size: bytes.length, arrayBuffer: async () => bytes.slice().buffer }];
  file.listeners.change();
  await new Promise((resolve) => setTimeout(resolve, 0));
  assert.equal(elements["core-error"].textContent, "", "the file must load");
  assert.ok(!out.innerHTML.includes(wifHex) && !out.innerHTML.includes(entropyHex), "an undecoded value is shown while nothing is revealed");
  // The key bytes can carry anything too (K3.1, round 11): only the decoded
  // type name is public.
  assert.ok(!out.innerHTML.includes("027478") && !out.innerHTML.includes("046e616d65"), "an undecoded record's key bytes are shown while nothing is revealed");
  assert.ok(out.innerHTML.includes(">tx<") && out.innerHTML.includes(">name<"), "a type name Bitcoin Core writes must be shown");
  reveal.checked = true;
  reveal.listeners.change();
  assert.ok(out.innerHTML.includes(`[private]${wifHex}[/private]`), "a revealed record value must be a private value");
  assert.ok(out.innerHTML.includes(`[private]${entropyHex}[/private]`), "a short revealed record value must be a private value too");
  assert.ok(out.innerHTML.includes("[private]027478[/private]"), "a revealed record key must be a private value");
  documentListeners["hodl:conceal"]();
  assert.equal(reveal.checked, false, "conceal must turn reveal off");
  assert.ok(!out.innerHTML.includes(wifHex) && !out.innerHTML.includes(entropyHex) && !out.innerHTML.includes("027478"), "an undecoded value or key is shown after conceal");
});

// A record key can carry key material as well as a value (K3.1, round 11):
// a key that embeds a WIF appears nowhere while nothing is revealed.
test("an undecoded record's key bytes never show while nothing is revealed", async (t) => {
  const { elements, cleanup } = setupCoreWalletUi();
  t.after(cleanup);
  const wif = "L1aW4aubDFB7yfras2S1mN3bqg9nwySY8nkoLmJebSLD5BWv3ENZ";
  const keyHex = "046e6f7465" + Buffer.from(wif).toString("hex");
  const bytes = dbFromRecords([...REF_WATCH_ONLY_RECORDS, [keyHex, "00"]]);
  const file = elements["core-file"], out = elements["core-out"];
  file.files = [{ size: bytes.length, arrayBuffer: async () => bytes.slice().buffer }];
  file.listeners.change();
  await new Promise((resolve) => setTimeout(resolve, 0));
  assert.equal(elements["core-error"].textContent, "", "the file must load");
  assert.equal(elements["core-reveal"].checked, false);
  assert.ok(!out.innerHTML.includes(keyHex) && !out.innerHTML.includes(Buffer.from(wif).toString("hex").slice(0, 32)), "a record key's bytes are shown while nothing is revealed");
});

// A cache parent is public only when the verification recomputed it from the
// descriptor's own public key (GLM, round 11): any other body is unknown
// bytes, private DOM until revealed.
test("a cache parent is public when verified and private DOM otherwise", async (t) => {
  const load = async (records) => {
    const { elements, documentListeners, cleanup } = setupCoreWalletUi();
    t.after(cleanup);
    const bytes = dbFromRecords(records);
    const file = elements["core-file"];
    file.files = [{ size: bytes.length, arrayBuffer: async () => bytes.slice().buffer }];
    file.listeners.change();
    await new Promise((resolve) => setTimeout(resolve, 0));
    assert.equal(elements["core-error"].textContent, "", "the file must load");
    return { elements, documentListeners };
  };
  const cacheRow = (records) => records.find(([key]) => key.startsWith("1577616c6c657464657363726970746f726361636865")); // "walletdescriptorcache"
  const genuine = REF_WATCH_ONLY_RECORDS.map(([key, value]) => [key, value]);
  const genuineBody = bytesToHex(hexToBytes(cacheRow(genuine)[1]).subarray(-74)); // the serialized node is the value's tail
  const shown = await load(genuine);
  assert.ok(shown.elements["core-out"].innerHTML.includes(genuineBody) && !shown.elements["core-out"].innerHTML.includes(`[private]${genuineBody}`), "a verified cache parent is public while nothing is revealed");
  const crafted = REF_WATCH_ONLY_RECORDS.map(([key, value]) => [key, value]);
  const value = hexToBytes(cacheRow(crafted)[1]);
  value[value.length - 1] ^= 0x01; // not the descriptor's parent any more
  cacheRow(crafted)[1] = bytesToHex(value);
  const craftedBody = bytesToHex(value.subarray(-74));
  const hidden = await load(crafted);
  const out = hidden.elements["core-out"], reveal = hidden.elements["core-reveal"];
  assert.ok(!out.innerHTML.includes(craftedBody), "an unverified cache parent is shown while nothing is revealed");
  reveal.checked = true;
  reveal.listeners.change();
  assert.ok(out.innerHTML.includes(`[private]${craftedBody}[/private]`), "a revealed unverified cache parent must be a private value");
  hidden.documentListeners["hodl:conceal"]();
  assert.ok(!out.innerHTML.includes(craftedBody), "an unverified cache parent is shown after conceal");
});

// Shared by the round 13 tests: load a record list into a fresh report.
const loadReport = async (t, records) => {
  const { elements, documentListeners, cleanup } = setupCoreWalletUi();
  t.after(cleanup);
  const bytes = dbFromRecords(records);
  const file = elements["core-file"];
  file.files = [{ size: bytes.length, arrayBuffer: async () => bytes.slice().buffer }];
  file.listeners.change();
  await new Promise((resolve) => setTimeout(resolve, 0));
  assert.equal(elements["core-error"].textContent, "", "the file must load");
  return { out: elements["core-out"], reveal: elements["core-reveal"], conceal: documentListeners["hodl:conceal"] };
};

// A record's type name is whatever the file put in its key: a name Bitcoin
// Core does not write is private, in the table and in the verification lines
// (Kimi and K3.1, round 12).
test("a record type name Core does not write is private, also in the verification lines", async (t) => {
  const wif = "L1aW4aubDFB7yfras2S1mN3bqg9nwySY8nkoLmJebSLD5BWv3ENZ";
  const keyHex = "34" + Buffer.from(wif).toString("hex"); // CompactSize 52: the name is the WIF
  const { out, reveal, conceal } = await loadReport(t, [...REF_WATCH_ONLY_RECORDS, [keyHex, "00"]]);
  assert.ok(!out.innerHTML.includes(wif), "a made-up type name is shown while nothing is revealed");
  reveal.checked = true;
  reveal.listeners.change();
  assert.ok(out.innerHTML.includes(`[private]${wif}[/private]`), "a revealed made-up type name must be a private value");
  conceal();
  assert.ok(!out.innerHTML.includes(wif), "a made-up type name is shown after conceal");
  // An orphaned key record whose name is made up is reported without it.
  const { core } = loadModule();
  const doc = parseRecords([...REF_WATCH_ONLY_RECORDS, [keyHex, "00"]]);
  const record = doc.records.find((candidate) => candidate.name === wif);
  const badCount = (checks) => checks.filter((check) => check.tone === "bad").length;
  const before = badCount(core.verifyWalletDoc(doc, coreDeps));
  record.orphan = true;
  record.error = "unexpected key tail";
  const checks = core.verifyWalletDoc(doc, coreDeps);
  // Copy is not pinned (AGENTS.md; GLM, round 14): the record gets its two
  // lines, and neither names it.
  assert.equal(badCount(checks), before + 2, "the orphaned, undecodable record is reported");
  const lines = checks.map((check) => `${check.label} ${check.detail}`).join("\n");
  assert.ok(!lines.includes(wif), "a verification line names a record by a made-up name");
});

// The pubkey beside a private key record is public once the verification
// derived it from that record's own private key; any other bytes are private
// (Astra, round 12).
test("a key record's pubkey is public only when it matches its private key", async (t) => {
  const genuine = REF_PRIVATE_RECORDS.map(([key, value]) => [key, value]);
  const keyRow = genuine.find(([key]) => key.startsWith("1377616c6c657464657363726970746f726b6579")); // "walletdescriptorkey"
  const genuinePubkey = Buffer.from(keyRow[0], "hex").subarray(-33).toString("hex");
  const shown = await loadReport(t, genuine);
  assert.ok(shown.out.innerHTML.includes(genuinePubkey) && !shown.out.innerHTML.includes(`[private]${genuinePubkey}`), "a verified pubkey is public while nothing is revealed");
  const wif = "Kzyv4uF39d4Jrw2W7UryTHwZr1zQVNk4dAFyqE6BuMrMh1Za7uhp";
  const crafted = REF_PRIVATE_RECORDS.map(([key, value]) => [key, value]);
  const row = crafted.find(([key]) => key.startsWith("1377616c6c657464657363726970746f726b6579"));
  const key = Buffer.from(row[0], "hex");
  row[0] = Buffer.concat([key.subarray(0, 52), Buffer.from([52]), Buffer.from(wif)]).toString("hex"); // Astra's repro
  const { out } = await loadReport(t, crafted);
  assert.ok(!out.innerHTML.includes(Buffer.from(wif).toString("hex")), "unverified pubkey bytes are shown while nothing is revealed");
});

// A descriptor id is 32 bytes from the record key: public once recomputed
// from the descriptor's text, private otherwise.
test("a descriptor id is public only when it is the recomputed DescriptorID", async (t) => {
  const genuine = REF_WATCH_ONLY_RECORDS.map(([key, value]) => [key, value]);
  const row = genuine.find(([key]) => key.startsWith("1077616c6c657464657363726970746f72")); // length 16, "walletdescriptor", then the id
  const genuineId = Buffer.from(row[0], "hex").subarray(-32).toString("hex");
  const shown = await loadReport(t, genuine);
  assert.ok(shown.out.innerHTML.includes(genuineId), "a verified descriptor id is public");
  const secret = "11".repeat(32);
  const crafted = REF_WATCH_ONLY_RECORDS.map(([key, value]) => [key, value]);
  const craftedRow = crafted.find(([key]) => key === row[0]);
  craftedRow[0] = row[0].slice(0, -64) + secret;
  const { out, reveal } = await loadReport(t, crafted);
  assert.ok(!out.innerHTML.includes(secret), "an id that is not the recomputed DescriptorID is shown while nothing is revealed");
  reveal.checked = true;
  reveal.listeners.change();
  assert.ok(out.innerHTML.includes(`[private]${secret}[/private]`), "a revealed unverified id must be a private value");
});

// A descriptor's checksum suffix is eight free characters unless it matches:
// the report shows a descriptor with reveal off only when it does (DeepSeek
// red team, round 13), and the verification lines then name it by place.
test("a descriptor is public only under a checksum that matches", async (t) => {
  const genuine = REF_WATCH_ONLY_RECORDS.map(([key, value]) => [key, value]);
  const row = genuine.find(([key]) => key.startsWith("1077616c6c657464657363726970746f72")); // "walletdescriptor"
  const descriptor = Buffer.from(row[1], "hex").toString("latin1").match(/[a-z]+\([\x21-\x7e]*#[0-9a-z]{8}/)[0];
  const shown = await loadReport(t, genuine);
  assert.ok(shown.out.innerHTML.includes(descriptor) && !shown.out.innerHTML.includes(`[private]${descriptor}`), "a genuine descriptor is public while nothing is revealed");
  const sum = descriptor.slice(-8);
  const craftedDescriptor = descriptor.slice(0, -8) + (sum[0] === "q" ? "p" : "q") + sum.slice(1);
  const crafted = REF_WATCH_ONLY_RECORDS.map(([key, value]) => [key, key === row[0] ? value.replace(Buffer.from(descriptor).toString("hex"), Buffer.from(craftedDescriptor).toString("hex")) : value]);
  assert.notEqual(crafted.find(([key]) => key === row[0])[1], row[1]);
  const { out, reveal, conceal } = await loadReport(t, crafted);
  assert.ok(!out.innerHTML.includes(craftedDescriptor), "a descriptor whose checksum does not match is shown while nothing is revealed");
  reveal.checked = true;
  reveal.listeners.change();
  assert.ok(out.innerHTML.includes(`[private]${craftedDescriptor}[/private]`), "a revealed unverified descriptor must be a private value");
  conceal();
  assert.ok(!out.innerHTML.includes(craftedDescriptor), "an unverified descriptor is shown after conceal");
  const { core } = loadModule();
  const failed = core.verifyWalletDoc(parseRecords(crafted), coreDeps).filter((check) => check.tone === "bad");
  // Copy is not pinned (AGENTS.md; GLM, round 14): one line fails, and it
  // names the descriptor by its place.
  assert.equal(failed.length, 1, "the checksum mismatch is reported");
  const line = `${failed[0].label} ${failed[0].detail}`;
  assert.match(line, /#\d+/, "the failed line names the descriptor by its place");
  assert.ok(!line.includes(craftedDescriptor.slice(0, 21)), "a verification line names an unverified descriptor by its text");
});

// A descriptor Core's grammar does not read is private even under a checksum
// that matches: Astra's round-14 repro, numbers where wpkh() takes a key.
test("a descriptor Core does not read is private under a matching checksum", async (t) => {
  const body = "wpkh(00010203,04050607,08090801,02030405,06070809,01020304,05060708,09010203)";
  const descriptor = Buffer.from(`${body}#${coreDeps.checksum(body)}`);
  const records = REF_WATCH_ONLY_RECORDS.map(([key, value]) => [key, value]);
  const row = records.find(([key]) => key.startsWith("1077616c6c657464657363726970746f72")); // "walletdescriptor"
  const old = Buffer.from(row[1], "hex");
  assert.ok(old[0] < 253 && descriptor.length < 253, "one-byte CompactSize length prefixes");
  row[1] = Buffer.concat([Buffer.from([descriptor.length]), descriptor, old.subarray(1 + old[0])]).toString("hex");
  const { out, reveal, conceal } = await loadReport(t, records);
  assert.equal(reveal.checked, false);
  assert.ok(!out.innerHTML.includes(body), "a descriptor Core does not read is shown while nothing is revealed");
  reveal.checked = true;
  reveal.listeners.change();
  assert.ok(out.innerHTML.includes(`[private]${body}#`), "a revealed unread descriptor must be a private value");
  conceal();
  assert.ok(!out.innerHTML.includes(body), "a descriptor Core does not read is shown after conceal");
});

// A block-locator hash is public when it is a block hash on its face: the
// genesis block, or proof-of-work zeros off regtest.
test("block-locator hashes are public only when they are block hashes on their face", async (t) => {
  const { core } = loadModule();
  const regtestGenesis = "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206";
  assert.equal(core.locatorHashPublic("regtest", regtestGenesis), true);
  assert.equal(core.locatorHashPublic("regtest", "11".repeat(32)), false, "regtest has no proof of work to read");
  assert.equal(core.locatorHashPublic("mainnet", "00000000000000000002a7c4c1e48d76c5a37902165a270156b7a8d72728a054"), true, "a mainnet block");
  assert.equal(core.locatorHashPublic("mainnet", "11".repeat(32)), false, "32 bytes without proof of work");
  assert.equal(core.locatorHashPublic("mainnet", "00000001" + "ff".repeat(28)), false, "above mainnet's proof-of-work limit (Astra, round 13: 20 zero bits passed)");
  assert.equal(core.locatorHashPublic("testnet", "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943"), true, "testnet's genesis");
  assert.equal(core.locatorHashPublic("signet", "00000377ae" + "00".repeat(27)), true, "signet's limit itself");
  assert.equal(core.locatorHashPublic("signet", "00000377af" + "00".repeat(27)), false, "above signet's limit");
  assert.equal(core.locatorHashPublic("mainnet", "00000000000000000002A7C4C1E48D76C5A37902165A270156B7A8D72728A054"), false, "only lowercase hex, as the reader writes it");
  assert.equal(core.locatorHashPublic(null, regtestGenesis), false, "an unknown network vouches for nothing");
  const secret = "11".repeat(32);
  const locator = (hash) => `00000000${"01"}${Buffer.from(hash, "hex").reverse().toString("hex")}`; // version 0, one hash
  const bestblockKey = "12" + Buffer.from("bestblock_nomerkle").toString("hex");
  assert.ok(REF_WATCH_ONLY_RECORDS.some(([key]) => key === bestblockKey), "the reference wallet has a bestblock_nomerkle record");
  const crafted = REF_WATCH_ONLY_RECORDS.filter(([key]) => key !== bestblockKey).concat([[bestblockKey, locator(secret)]]);
  const { out, reveal } = await loadReport(t, crafted);
  assert.ok(!out.innerHTML.includes(secret), "a locator hash without proof of work is shown while nothing is revealed");
  reveal.checked = true;
  reveal.listeners.change();
  assert.ok(out.innerHTML.includes(`[private]${secret}[/private]`), "a revealed unproven locator must be a private value");
});

// The redacted row counts a descriptor's bytes through a UTF-8 copy; that
// copy is zeroed once counted (K3.1, round 10).
test("counting a redacted descriptor's bytes leaves no unzeroed copy of it", async (t) => {
  const { elements, cleanup } = setupCoreWalletUi();
  t.after(cleanup);
  const xprv = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";
  const records = REF_WATCH_ONLY_RECORDS.map(([key, value]) => [key, value]);
  const row = records.find(([key]) => key.startsWith("1077616c6c657464657363726970746f72")); // "walletdescriptor"
  const text = Buffer.from(row[1], "hex").toString("latin1");
  row[1] = Buffer.from(text.replace(/tpub[1-9A-HJ-NP-Za-km-z]{107}/, xprv), "latin1").toString("hex");
  const bytes = dbFromRecords(records);
  // Every UTF-8 encoding made from here on is kept, to check it was zeroed.
  const OriginalTextEncoder = globalThis.TextEncoder;
  const encoded = [];
  globalThis.TextEncoder = class extends OriginalTextEncoder {
    encode(text) { const bytes = super.encode(text); encoded.push(bytes); return bytes; }
  };
  t.after(() => { globalThis.TextEncoder = OriginalTextEncoder; });
  const file = elements["core-file"], out = elements["core-out"];
  file.files = [{ size: bytes.length, arrayBuffer: async () => bytes.slice().buffer }];
  file.listeners.change();
  await new Promise((resolve) => setTimeout(resolve, 0));
  assert.equal(elements["core-error"].textContent, "", "the crafted file must load");
  assert.ok(!out.innerHTML.includes(xprv), "the key-bearing descriptor must be redacted");
  const copies = encoded.filter((array) => array.length >= xprv.length);
  assert.ok(copies.length > 0, "the redacted row counts the descriptor's bytes through a UTF-8 copy");
  for (const copy of copies) assert.ok(copy.every((byte) => byte === 0), "a copy made to count the descriptor's bytes was not zeroed");
});

// The verification lines name each descriptor by its first characters; for
// a key-bearing one (a crafted file) those characters are the key's, and the
// lines show while the descriptor is redacted (Astra, round 11). Such a
// descriptor is named by its place instead; a public one keeps its text.
test("the verification lines never show a key-bearing descriptor's text", async (t) => {
  const { elements, documentListeners, cleanup } = setupCoreWalletUi();
  t.after(cleanup);
  const wif = "L1aW4aubDFB7yfras2S1mN3bqg9nwySY8nkoLmJebSLD5BWv3ENZ";
  const body = `wpkh(${wif})`;
  const descriptor = Buffer.from(`${body}#${coreDeps.checksum(body)}`);
  const records = REF_WATCH_ONLY_RECORDS.map(([key, value]) => [key, value]);
  const row = records.find(([key]) => key.startsWith("1077616c6c657464657363726970746f72")); // "walletdescriptor"
  const old = Buffer.from(row[1], "hex");
  assert.ok(old[0] < 253 && descriptor.length < 253, "one-byte CompactSize length prefixes");
  row[1] = Buffer.concat([Buffer.from([descriptor.length]), descriptor, old.subarray(1 + old[0])]).toString("hex");
  const bytes = dbFromRecords(records);
  const file = elements["core-file"], out = elements["core-out"], reveal = elements["core-reveal"];
  file.files = [{ size: bytes.length, arrayBuffer: async () => bytes.slice().buffer }];
  file.listeners.change();
  await new Promise((resolve) => setTimeout(resolve, 0));
  assert.equal(elements["core-error"].textContent, "", "the crafted file must load");
  assert.equal(reveal.checked, false);
  assert.ok(!out.innerHTML.includes(wif.slice(0, 16)), "a key-bearing descriptor's first characters are shown while nothing is revealed");
  // Copy is not pinned (AGENTS.md; GLM, round 14): every check is listed.
  const listed = out.innerHTML.match(/<li data-tone="/g) ?? [];
  assert.equal(listed.length, loadModule().core.verifyWalletDoc(parseRecords(records), coreDeps).length, "the descriptor's checks are still listed");
  assert.ok(out.innerHTML.includes("pkh([420c9ea3/44h/1h/0h"), "a public descriptor is still named by its text");
  reveal.checked = true;
  reveal.listeners.change();
  assert.ok(out.innerHTML.includes(`[private]${body}#`), "the revealed descriptor is a private value");
  documentListeners["hodl:conceal"]();
  assert.ok(!out.innerHTML.includes(wif.slice(0, 16)), "a key-bearing descriptor's first characters are shown after conceal");
});

// K3.1 (round 15): an "xpub" followed by the right number of Base58
// characters had the shape of an extended public key without being one; two
// WIFs after "xpub" read as public and showed unredacted. An extended key now
// counts as public only when it decodes as one.
test("an xpub-shaped token that does not decode as an extended public key is private", () => {
  const { descriptorHoldsSecret } = loadCoreWalletUi();
  const a = "L1aW4aubDFB7yfras2S1mN3bqg9nwySY8nkoLmJebSLD5BWv3ENZ";
  const b = "Kzyv4uF39d4Jrw2W7UryTHwZr1zQVNk4dAFyqE6BuMrMh1Za7uhp";
  assert.equal(descriptorHoldsSecret(`wpkh(xpub${a}${b})`), true, "K3.1's repro: two WIFs after xpub");
  assert.equal(descriptorHoldsSecret(`xpub${a}${b}`), true, "the bare value too (the Core add field)");
  const xpub = "xpub6CUGRUonZSQ4TWtTMmzXdrXDtypWKiKrhko4egpiMZbpiaQL2jkwSB1icqYh2cfDfVxdx4df189oLKnC5fSwqPfgyP3hooxujYzAu3fDVmz";
  assert.equal(descriptorHoldsSecret(`wpkh(${xpub}/0/*)`), false, "a real xpub stays public");
  const flipped = xpub.slice(0, 60) + (xpub[60] === "a" ? "b" : "a") + xpub.slice(61);
  assert.equal(descriptorHoldsSecret(`wpkh(${flipped}/0/*)`), true, "one changed character fails the checksum");
  const { core } = loadModule();
  assert.equal(core.descriptorIsPublic(`wpkh(${xpub}/0/*)`), false, "without a decoder no extended key is vouched for");
  assert.equal(core.descriptorIsPublic(`wpkh(${xpub}/0/*)`, b58checkDecode), true);
});

// K3.1 (round 15): the DescriptorID input (the whole descriptor, which a
// crafted file can make key-bearing) was zeroed only when hashing succeeded.
test("the descriptor id's UTF-8 copy is zeroed even when hashing throws", (t) => {
  const wif = "L1aW4aubDFB7yfras2S1mN3bqg9nwySY8nkoLmJebSLD5BWv3ENZ";
  const body = `wpkh(${wif})`;
  const idText = `${body}#${coreDeps.checksum(body)}`;
  const descriptor = Buffer.from(idText);
  const records = REF_WATCH_ONLY_RECORDS.map(([key, value]) => [key, value]);
  const row = records.find(([key]) => key.startsWith("1077616c6c657464657363726970746f72")); // "walletdescriptor"
  const old = Buffer.from(row[1], "hex");
  assert.ok(old[0] < 253 && descriptor.length < 253, "one-byte CompactSize length prefixes");
  row[1] = Buffer.concat([Buffer.from([descriptor.length]), descriptor, old.subarray(1 + old[0])]).toString("hex");
  const doc = parseHex(records);
  const OriginalTextEncoder = globalThis.TextEncoder;
  const encoded = [];
  globalThis.TextEncoder = class extends OriginalTextEncoder {
    encode(text) { const bytes = super.encode(text); encoded.push({ text, bytes }); return bytes; }
  };
  t.after(() => { globalThis.TextEncoder = OriginalTextEncoder; });
  const failing = { ...coreDeps, sha256: (input) => {
    if (Buffer.from(input).toString("latin1").includes(wif)) throw new Error("hash failure");
    return coreDeps.sha256(input);
  } };
  const { core } = loadModule();
  core.verifyWalletDoc(doc, failing);
  globalThis.TextEncoder = OriginalTextEncoder;
  const copies = encoded.filter((entry) => entry.text === idText);
  assert.ok(copies.length > 0, "the descriptor id is hashed from a UTF-8 copy");
  for (const { bytes } of copies) assert.ok(bytes.every((byte) => byte === 0), "the copy was not zeroed after the hash threw");
});
