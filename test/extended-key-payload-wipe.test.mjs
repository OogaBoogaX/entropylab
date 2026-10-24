// Secret byte buffers are overwritten after use (SECURITY.md). The helpers
// that swap an extended key's version bytes (xprv -> zprv, the SLIP-132
// export every BIP84 account shows), read its version, parse a pasted key,
// and encode or decode a WIF each decoded or built the payload that holds the
// private key (78 bytes for an extended key, 33 or 34 for a WIF) and dropped
// it unzeroed. The residue audit found the result in Chrome's renderer after
// Wipe: 24 copies of a BIP84 account key and 2 of the master key, two per
// version swap, in freed 80-byte heap slots.
//
// Contract: every payload buffer these helpers decode or build is all zero
// once they return, on success and on refusal, and what they return is
// unchanged; a key the caller passes in is left intact.
//
// Expected values: BIP32 test vector 1's master xprv, reversioned to zprv
// with @scure/base, and the compressed WIF of private key 1 encoded with
// @scure/base. Run with `npm test`.
import { beforeEach, test } from "node:test";
import assert from "node:assert/strict";
import { createBase58check } from "@scure/base";
import { sha256 } from "@noble/hashes/sha2.js";
import { base58checkDecode, base58checkEncode } from "../src/js/base58.js";
import { loadAppFunctions } from "./app-slice-harness.mjs";

const scure = createBase58check(sha256);
const reversion = (text, version) => {
  const raw = Uint8Array.from(scure.decode(text));
  new DataView(raw.buffer).setUint32(0, version);
  return scure.encode(raw);
};
// BIP32 test vector 1, chain m.
const XPRV = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";
const ZPRV_VERSION = 0x04b2430c, XPRV_VERSION = 0x0488ade4;
const ZPRV = reversion(XPRV, ZPRV_VERSION);
const KEY_ONE = Uint8Array.from({ length: 32 }, (_, i) => (i === 31 ? 1 : 0));
const WIF_ONE = scure.encode(Uint8Array.from([0x80, ...KEY_ONE, 0x01]));

// Every buffer handed to or returned by Base58Check, so the test can look at
// it after the helper returns. The app's hodlBase58Check wraps these two.
const seen = [];
const recordingEncode = (payload) => { seen.push(payload); return base58checkEncode(payload); };
const recordingDecode = (text) => { const out = base58checkDecode(text); seen.push(out); return out; };
// The prefix table is filled by page-boot statements the harness does not
// run; the two mainnet rows these keys need stand in for it.
const hodlExtendedKeyPrefixTable = [
  { network: "mainnet", family: "x", scope: "singlesig", private: true, ver: XPRV_VERSION, name: "xprv" },
  { network: "mainnet", family: "z", scope: "singlesig", private: true, ver: ZPRV_VERSION, name: "zprv" },
];
const app = await loadAppFunctions(
  ["hodlReversionExtendedKey", "hodlReadExtendedKeyVersion", "hodlEncodeWif", "hodlDecodeWif", "hodlParseExtendedKey"],
  { stubs: { base58checkEncode: recordingEncode, base58checkDecode: recordingDecode, hodlExtendedKeyPrefixTable } },
);
beforeEach(() => { seen.length = 0; });
const allZero = (label) => {
  assert.ok(seen.length > 0, `${label}: nothing went through Base58Check, so this proves nothing`);
  for (const [i, bytes] of seen.entries()) assert.ok(bytes.every((b) => b === 0), `${label}: payload buffer ${i + 1} of ${seen.length} still holds key material`);
  seen.length = 0;
};

test("swapping an extended private key's version wipes both payload copies", () => {
  assert.equal(app.hodlReversionExtendedKey(XPRV, ZPRV_VERSION), ZPRV);
  allZero("xprv -> zprv");
  assert.equal(app.hodlReversionExtendedKey(ZPRV, XPRV_VERSION), XPRV);
  allZero("zprv -> xprv");
});

test("reading an extended private key's version wipes its payload", () => {
  assert.equal(app.hodlReadExtendedKeyVersion(ZPRV), ZPRV_VERSION);
  allZero("version read");
});

test("encoding a WIF wipes the payload it built and leaves the caller's key intact", () => {
  const key = Uint8Array.from(KEY_ONE);
  assert.equal(app.hodlEncodeWif(key, true, "mainnet"), WIF_ONE);
  allZero("WIF encode");
  assert.deepEqual(key, KEY_ONE, "the caller's key must not be zeroed");
});

test("decoding a WIF wipes the decoded payload, and returns the key, on success and refusal", () => {
  const decoded = app.hodlDecodeWif(WIF_ONE);
  assert.deepEqual(decoded.priv, KEY_ONE);
  assert.equal(decoded.compressed, true);
  assert.equal(decoded.network, "mainnet");
  allZero("WIF decode");
  // A compressed payload without the 0x01 suffix is refused after decoding.
  const badSuffix = scure.encode(Uint8Array.from([0x80, ...KEY_ONE, 0x02]));
  assert.throws(() => app.hodlDecodeWif(badSuffix), /0x01 suffix/);
  allZero("refused WIF decode");
});

test("parsing a pasted extended private key wipes every payload it decodes, accepted or refused", () => {
  const parsed = app.hodlParseExtendedKey(ZPRV);
  assert.equal(parsed.isPrivate, true);
  assert.equal(parsed.family, "z");
  assert.equal(parsed.xkey, XPRV);
  assert.equal(parsed.node.privateExtendedKey, XPRV);
  allZero("zprv parse");
  // A version no table row knows is refused after the payload is decoded.
  assert.throws(() => app.hodlParseExtendedKey(reversion(XPRV, 0x12345678)), /Not a recognized extended key/);
  allZero("refused parse");
});
