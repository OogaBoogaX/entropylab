import test from "node:test";
import assert from "node:assert/strict";

import {
  HSM_SECRET_ENCRYPTED,
  HSM_SECRET_INVALID,
  HSM_SECRET_MNEMONIC_NO_PASS,
  HSM_SECRET_MNEMONIC_WITH_PASS,
  HSM_SECRET_PLAIN,
  deriveClnNode,
  detectHsmSecretType,
  hkdfSha256,
  hmacSha256,
  readClnMnemonic,
} from "../src/js/hsm-secret.js";
import { secp256k1Ready } from "../src/js/secp256k1.js";
import { hashesReady } from "../src/js/hashes.js";

await Promise.all([secp256k1Ready, hashesReady]);

// CLN v26.06.9, tests/test_wallet.py: the mnemonic hsm_secret that
// `lightning-hsmtool generatehsm` writes with no passphrase.
const ABANDON = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const RITUAL = "ritual idle hat sunny universe pluck key alpha wing cake have wedding";

const utf8 = (text) => new TextEncoder().encode(text);
const toHex = (bytes) => Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
const fromHex = (text) => Uint8Array.from(text.match(/../g), (byte) => parseInt(byte, 16));

// A type-2 hsm_secret: 32 zero bytes (the "no passphrase" marker) followed by
// the mnemonic text, exactly as `lightning-hsmtool generatehsm` writes it.
const type2File = (mnemonic) => {
  const words = utf8(mnemonic);
  const file = new Uint8Array(32 + words.length);
  file.set(words, 32);
  return file;
};

// Every refusal must be a keyed error: `code` is the stable machine
// identifier and `key` is a non-empty translatable string. Tests never pin
// the English sentence itself (AGENTS.md).
const refusal = (input) => {
  try {
    readClnMnemonic(input);
  } catch (error) {
    assert.equal(typeof error.key, "string", "refusals must carry a translatable key");
    assert.ok(error.key.length > 0, "the refusal key must not be empty");
    return error;
  }
  assert.fail("readClnMnemonic accepted input it must refuse");
};

test("detectHsmSecretType mirrors CLN's length and prefix rules", () => {
  assert.equal(detectHsmSecretType(new Uint8Array(31)), HSM_SECRET_INVALID);
  assert.equal(detectHsmSecretType(new Uint8Array(32)), HSM_SECRET_PLAIN);
  assert.equal(detectHsmSecretType(new Uint8Array(73)), HSM_SECRET_ENCRYPTED);
  assert.equal(detectHsmSecretType(type2File(ABANDON)), HSM_SECRET_MNEMONIC_NO_PASS);
  const withPassphrase = type2File(RITUAL);
  withPassphrase[0] = 0x42;
  assert.equal(detectHsmSecretType(withPassphrase), HSM_SECRET_MNEMONIC_WITH_PASS);
});

test("hmacSha256 matches RFC 4231 test case 1", () => {
  const key = new Uint8Array(20).fill(0x0b);
  const mac = hmacSha256(key, utf8("Hi There"));
  assert.equal(toHex(mac), "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
});

test("hkdfSha256 matches RFC 5869 test case 1", () => {
  const ikm = new Uint8Array(22).fill(0x0b);
  const salt = fromHex("000102030405060708090a0b0c");
  const info = fromHex("f0f1f2f3f4f5f6f7f8f9");
  const okm = hkdfSha256(ikm, salt, info, 42);
  assert.equal(
    toHex(okm),
    "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
  );
});

test("hkdfSha256 refuses an output longer than 255 * 32 bytes (RFC 5869)", () => {
  const ikm = new Uint8Array(22).fill(0x0b);
  const salt = fromHex("000102030405060708090a0b0c");
  const info = fromHex("f0f1f2f3f4f5f6f7f8f9");
  // RFC 5869 §2.3: L <= 255 * HashLen, so 255 * 32 is the largest legal output.
  assert.equal(hkdfSha256(ikm, salt, info, 255 * 32).length, 255 * 32);
  assert.throws(() => hkdfSha256(ikm, salt, info, 255 * 32 + 1), RangeError);
});

test("deriveClnNode reproduces CLN's node id for a type-2 mnemonic", () => {
  const { nodeId } = deriveClnNode(ABANDON, "bitcoin");
  assert.equal(nodeId, "03653e90c1ce4660fd8505dd6d643356e93cfe202af109d382787639dd5890e87d");
});

test("deriveClnNode reproduces CLN's dumponchaindescriptors output", () => {
  const { descriptors } = deriveClnNode(ABANDON, "bitcoin");
  assert.deepEqual(descriptors, [
    "wpkh(xpub6BgBgsespWvERF3LHQu6CnqdvfEvtMcQjYrcRzx53QJjSxarj2afYWcLteoGVky7D3UKDP9QyrLprQ3VCECoY49yfdDEHGCtMMj92pReUsQ/0/*)#hjszq0wk",
    "sh(wpkh(xpub6BgBgsespWvERF3LHQu6CnqdvfEvtMcQjYrcRzx53QJjSxarj2afYWcLteoGVky7D3UKDP9QyrLprQ3VCECoY49yfdDEHGCtMMj92pReUsQ/0/*))#u0t3u3xz",
    "tr(xpub6BgBgsespWvERF3LHQu6CnqdvfEvtMcQjYrcRzx53QJjSxarj2afYWcLteoGVky7D3UKDP9QyrLprQ3VCECoY49yfdDEHGCtMMj92pReUsQ/0/*)#8e7pq23w",
  ]);
});

test("deriveClnNode uses the test-network key version without changing the node id", () => {
  const main = deriveClnNode(ABANDON, "bitcoin");
  const testnet = deriveClnNode(ABANDON, "testnet");
  assert.equal(testnet.nodeId, main.nodeId);
  assert.match(testnet.xpub, /^tpub/);
  assert.ok(testnet.descriptors.every((descriptor) => descriptor.includes(testnet.xpub)));
});

test("deriveClnNode refuses inherited object properties as network names", () => {
  for (const network of ["constructor", "__proto__", "toString", "hasOwnProperty"]) {
    assert.throws(
      () => deriveClnNode(ABANDON, network),
      (error) => error.code === "hsm-secret-network" && typeof error.key === "string",
    );
  }
});

test("a type-2 hsm_secret file derives the same node as its words", () => {
  const fromFile = readClnMnemonic(type2File(ABANDON));
  assert.equal(fromFile, ABANDON);
  assert.deepEqual(deriveClnNode(fromFile, "bitcoin"), deriveClnNode(ABANDON, "bitcoin"));
});

test("readClnMnemonic normalizes the words lightning-hsmtool getsecret prints", () => {
  assert.equal(readClnMnemonic(`  ${ABANDON.toUpperCase()}\n`), ABANDON);
});

test("readClnMnemonic refuses every non-type-2 shape with its own code", () => {
  const withPassphrase = type2File(RITUAL);
  withPassphrase[0] = 0x42;
  const cases = [
    ["hsm-secret-plain", new Uint8Array(32).fill(7)],
    ["hsm-secret-encrypted", new Uint8Array(73).fill(7)],
    ["hsm-secret-passphrase", withPassphrase],
    ["hsm-secret-invalid-mnemonic", "abandon ".repeat(12).trim()],
    ["hsm-secret-truncated", type2File("abandon ".repeat(11).trim())],
    ["hsm-secret-trailing", type2File(`${ABANDON} extra`)],
  ];
  for (const [code, input] of cases) {
    const error = refusal(input);
    assert.equal(error.code, code);
  }
});

test("a short hsm_secret file is refused as truncated", () => {
  assert.equal(refusal(new Uint8Array(16)).code, "hsm-secret-truncated");
});
