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
  serializeExtendedKey,
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
  assert.match(app, /initCoreWallet\(\{ deps: hodlWalletDatDeps\(\) \}\)/);
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
