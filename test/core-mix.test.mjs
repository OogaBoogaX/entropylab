// Tests for src/js/core-mix.js (issue #552): mixing a Bitcoin Core
// wallet.dat's spend secrets with a dice/card transcript into new seed
// entropy. Run with `npm test`.
//
// The wallet fixtures are the same Bitcoin Core v28.3.0 ground truth the
// core-wallet suite uses; every expected hash is computed here with
// node:crypto, never with the module under test.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { coreMixEntropy, coreMixSecrets, wipeCoreMixSecrets } from "../src/js/core-mix.js";
import { REF_PRIVATE_RECORDS, REF_WATCH_ONLY_RECORDS } from "./wallet-export-reference.mjs";
import { GENERATED_ROWS, GENERATED_SEED, buildGeneratedUnitRecords } from "./core-generated-fixture.mjs";
import { bytesToHex, hdMasterFromSeed, hexToBytes, publicKeyForPrivate, read, sha256 } from "./wallet-export-harness.mjs";

const MAIN_SQL = "CREATE TABLE main(key BLOB PRIMARY KEY NOT NULL, value BLOB NOT NULL)";
const REGTEST_APP_ID = 0xfabfb5da;

const loadModule = () =>
  new Function(
    `${read("src/js/sqlite-writer.js")}\n${read("src/js/sqlite-reader.js")}\n${read("src/js/wallet-export.js")}\n${read("src/js/core-wallet.js")}\nreturn { writer: hodlSqliteWriter, core: hodlCoreWallet };`,
  )();

const dbFromRecords = (records, applicationId = REGTEST_APP_ID) =>
  loadModule().writer.createDatabase({
    applicationId,
    tables: [{ name: "main", sql: MAIN_SQL, primaryKey: 0, rows: records.map(([key, value]) => [hexToBytes(key), hexToBytes(value)]) }],
  });

const parseRecords = (records, applicationId) => loadModule().core.parseWalletDat(dbFromRecords(records, applicationId));

// The app injects src/js/hashes.js sha256 and the curve helper; the harness
// provides the same two functions from independent reference crypto.
const mixDeps = { publicKeyForPrivate, sha256 };

const TRANSCRIPT = "dice: 4 2 6 1 5 3 3 6 1 4 2 5";

const utf8 = (text) => new TextEncoder().encode(text);
const sha256Of = (...parts) =>
  createHash("sha256").update(Buffer.concat(parts.map((part) => Buffer.from(part)))).digest();

const compareBytes = (a, b) => {
  for (let index = 0; index < Math.min(a.length, b.length); index++) if (a[index] !== b[index]) return a[index] - b[index];
  return a.length - b.length;
};

// A second, independent Core-generated wallet: two distinct master secrets in
// one file, so sorting and de-duplication are actually exercised. Its active
// scriptPubKey records are dropped — they would collide with the first
// wallet's (the key is the same for both).
const OTHER_SEED = sha256(utf8("entropylab core-mix second wallet"));
const ACTIVE_KEY_PREFIXES = ["1161637469766565787465726e616c73706b", "11616374697665696e7465726e616c73706b"];
const TWO_WALLET_ROWS = [
  ...GENERATED_ROWS,
  ...buildGeneratedUnitRecords(OTHER_SEED)
    .map(([key, value]) => [bytesToHex(key), bytesToHex(value)])
    .filter(([key]) => !ACTIVE_KEY_PREFIXES.some((prefix) => key.startsWith(prefix))),
];
const TWO_WALLET_SECRETS = [hdMasterFromSeed(GENERATED_SEED).secret, hdMasterFromSeed(OTHER_SEED).secret].sort(compareBytes);

test("the same wallet and transcript always give the same entropy", () => {
  const first = coreMixSecrets(parseRecords(GENERATED_ROWS), mixDeps);
  const second = coreMixSecrets(parseRecords(GENERATED_ROWS), mixDeps);
  assert.equal(first.count, 1, "a Core-generated wallet carries one master secret");
  assert.equal(first.secrets.length, 1);
  assert.equal(first.secrets[0].length, 32);
  assert.match(first.fingerprint, /^[0-9a-f]{8}$/);
  assert.deepEqual(second.secrets, first.secrets);
  assert.equal(second.fingerprint, first.fingerprint);
  const a = coreMixEntropy(first.secrets, TRANSCRIPT, 32, mixDeps);
  const b = coreMixEntropy(second.secrets, TRANSCRIPT, 32, mixDeps);
  assert.equal(a.length, 32);
  assert.deepEqual(a, b);
  wipeCoreMixSecrets(first.secrets);
  wipeCoreMixSecrets(second.secrets);
});

test("descriptor and key order do not change the secrets, the fingerprint or the entropy", () => {
  const forward = coreMixSecrets(parseRecords(TWO_WALLET_ROWS), mixDeps);
  assert.equal(forward.count, 2, "two wallets, two distinct master secrets");
  assert.deepEqual(forward.secrets, TWO_WALLET_SECRETS, "sorted ascending, bytewise");
  const reversed = parseRecords(TWO_WALLET_ROWS);
  reversed.descriptors.reverse();
  for (const entry of reversed.descriptors) entry.keys.reverse();
  const backward = coreMixSecrets(reversed, mixDeps);
  assert.deepEqual(backward.secrets, forward.secrets);
  assert.equal(backward.count, forward.count);
  assert.equal(backward.fingerprint, forward.fingerprint);
  assert.deepEqual(
    coreMixEntropy(backward.secrets, TRANSCRIPT, 32, mixDeps),
    coreMixEntropy(forward.secrets, TRANSCRIPT, 32, mixDeps),
  );
  wipeCoreMixSecrets(forward.secrets);
  wipeCoreMixSecrets(backward.secrets);
});

test("the entropy and fingerprint match an independent SHA-256 of the specified preimages", () => {
  const { secrets, count, fingerprint } = coreMixSecrets(parseRecords(TWO_WALLET_ROWS), mixDeps);
  assert.equal(count, 2);
  const expectedFingerprint = sha256Of(
    utf8("entropylab-core-mix-fp-v1"), Uint8Array.of(0), ...TWO_WALLET_SECRETS,
  ).toString("hex").slice(0, 8);
  assert.equal(fingerprint, expectedFingerprint);
  const digest = sha256Of(
    utf8("entropylab-core-mix-v1"), Uint8Array.of(0), ...TWO_WALLET_SECRETS, Uint8Array.of(0), utf8(TRANSCRIPT),
  );
  for (const size of [16, 20, 24, 28, 32]) {
    assert.deepEqual(coreMixEntropy(secrets, TRANSCRIPT, size, mixDeps), new Uint8Array(digest.subarray(0, size)), `${size} bytes`);
  }
  wipeCoreMixSecrets(secrets);
});

test("a different transcript or a different wallet changes the entropy", () => {
  const { secrets } = coreMixSecrets(parseRecords(GENERATED_ROWS), mixDeps);
  const base = coreMixEntropy(secrets, TRANSCRIPT, 32, mixDeps);
  assert.notDeepEqual(coreMixEntropy(secrets, `${TRANSCRIPT} `, 32, mixDeps), base, "the transcript is hashed exactly, not trimmed");
  assert.notDeepEqual(coreMixEntropy(secrets, "cards: AS 2H 3D", 32, mixDeps), base);
  const other = coreMixSecrets(parseRecords(REF_PRIVATE_RECORDS), mixDeps);
  assert.notDeepEqual(other.secrets, secrets, "a different wallet has a different secret");
  assert.notDeepEqual(coreMixEntropy(other.secrets, TRANSCRIPT, 32, mixDeps), base);
  wipeCoreMixSecrets(secrets);
  wipeCoreMixSecrets(other.secrets);
});

test("an empty or whitespace-only transcript is refused", () => {
  const { secrets } = coreMixSecrets(parseRecords(GENERATED_ROWS), mixDeps);
  for (const transcript of ["", " ", "   \n\t "]) {
    assert.throws(() => coreMixEntropy(secrets, transcript, 32, mixDeps), { message: /^empty-transcript:/ }, JSON.stringify(transcript));
  }
  wipeCoreMixSecrets(secrets);
});

test("a watch-only wallet has no secret to mix", () => {
  assert.throws(() => coreMixSecrets(parseRecords(REF_WATCH_ONLY_RECORDS), mixDeps), { message: /^watch-only:/ });
});

test("an encrypted wallet is refused before any secret is read", () => {
  // Any walletdescriptorcryptedkey record marks an encrypted wallet: its
  // secrets are not in the file in usable form. The name is 26 characters
  // (0x1a); the payload shape is irrelevant to the refusal.
  const crypted = ["1a77616c6c657464657363726970746f72637279707465646b6579" + "00".repeat(32) + "21" + "02".repeat(33), "f0" + "01".repeat(48)];
  assert.throws(() => coreMixSecrets(parseRecords([...GENERATED_ROWS, crypted]), mixDeps), { message: /^encrypted:/ });
});

test("a secret that does not match its record pubkey is refused without leaking it", () => {
  const rows = GENERATED_ROWS.map(([key, value]) => [key, value]);
  const record = rows.find(([key]) => key.startsWith("1377616c6c657464657363726970746f726b6579")); // "walletdescriptorkey"
  const value = hexToBytes(record[1]);
  value[1 + 8] ^= 0x01; // one byte of the 32-byte secret, DER shape intact
  record[1] = bytesToHex(value);
  const secretHex = bytesToHex(value.slice(1 + 8, 1 + 40));
  let message = "";
  try {
    coreMixSecrets(parseRecords(rows), mixDeps);
  } catch (error) {
    message = error.message;
  }
  assert.match(message, /^key-mismatch:/);
  assert.ok(!message.includes(secretHex), "the refusal must not carry key material");
});

test("a key record that is not the expected DER shape is refused", () => {
  const rows = GENERATED_ROWS.map(([key, value]) => [key, value]);
  const record = rows.find(([key]) => key.startsWith("1377616c6c657464657363726970746f726b6579"));
  // compactSize(3) + three bytes + the 32-byte record hash: too short to be
  // the 214-byte CPrivKey Core writes.
  record[1] = "03abcdef" + "00".repeat(32);
  assert.throws(() => coreMixSecrets(parseRecords(rows), mixDeps), { message: /^malformed-key:/ });
});

test("the entropy is not the wallet's own seed, a secret, or a dice-only hash", () => {
  const { secrets } = coreMixSecrets(parseRecords(GENERATED_ROWS), mixDeps);
  const entropy = coreMixEntropy(secrets, TRANSCRIPT, 32, mixDeps);
  assert.notDeepEqual(entropy, secrets[0], "not the wallet's own secret");
  assert.notDeepEqual(entropy, hdMasterFromSeed(GENERATED_SEED).secret);
  assert.notDeepEqual(entropy, GENERATED_SEED, "not the seed the fixture wallet was made from");
  assert.notDeepEqual(entropy, new Uint8Array(sha256Of(utf8(TRANSCRIPT))), "not sha256(transcript) — the domains differ");
  wipeCoreMixSecrets(secrets);
});

test("only the five seed lengths are accepted, and an empty secret list is refused", () => {
  const { secrets } = coreMixSecrets(parseRecords(GENERATED_ROWS), mixDeps);
  for (const size of [0, 1, 15, 17, 18, 31, 33, 64]) {
    assert.throws(() => coreMixEntropy(secrets, TRANSCRIPT, size, mixDeps), Error, `${size} bytes`);
  }
  assert.throws(() => coreMixEntropy([], TRANSCRIPT, 32, mixDeps), Error);
  wipeCoreMixSecrets(secrets);
});

test("wipeCoreMixSecrets zeroes every secret", () => {
  const { secrets } = coreMixSecrets(parseRecords(TWO_WALLET_ROWS), mixDeps);
  assert.equal(secrets.length, 2);
  assert.ok(secrets.every((secret) => secret.some((byte) => byte !== 0)), "the secrets start populated");
  wipeCoreMixSecrets(secrets);
  for (const secret of secrets) assert.ok(secret.every((byte) => byte === 0), "every byte is zeroed");
});

// MiniMax's review of f3ed754: a hash that returns a Node Buffer (whose slice
// is a view) must not let the finally-block wipe zero the returned entropy.
test("a Buffer-returning sha256 still yields the same, non-zero entropy", async () => {
  const { createHash } = await import("node:crypto");
  const bufferSha256 = (bytes) => createHash("sha256").update(bytes).digest();
  const secrets = [new Uint8Array(32).fill(7), new Uint8Array(32).fill(9)];
  const viaBuffer = coreMixEntropy(secrets, "1 2 3 4 5 6", 32, { sha256: bufferSha256 });
  const viaArray = coreMixEntropy(secrets, "1 2 3 4 5 6", 32, { sha256: (bytes) => new Uint8Array(bufferSha256(bytes)) });
  assert.ok(viaBuffer.some((byte) => byte !== 0), "not wiped to zeros");
  assert.deepEqual([...viaBuffer], [...viaArray]);
});
