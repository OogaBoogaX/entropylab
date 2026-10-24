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
  assert.match(app, /import \{ initCoreWallet \} from "\.\/core-wallet-ui\.js"/);
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
  const expandableHtml = (text) => text;
  const initExpandable = () => {};
  const hodlCoreWallet = loadModule().core;
  const factory = new Function(
    "t", "tAttr", "tHtml", "expandableHtml", "initExpandable", "hodlCoreWallet",
    `${source}\nreturn { initCoreWallet };`,
  );
  return factory(t, tAttr, tHtml, expandableHtml, initExpandable, hodlCoreWallet);
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
