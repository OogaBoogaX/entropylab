// BIP-47 reusable payment codes, against the test vectors linked from the BIP
// (gist SamouraiDev/6aad669604c5930864bd). @scure/bip39 and @scure/bip32 are
// dev-only oracles: the seeds and the BIP32 walk come from them, everything
// BIP-47 comes from src/js/bip47.js.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { mnemonicToSeedSync } from "@scure/bip39";
import { HDKey } from "../src/js/hdkey.js";
import { secp256k1 } from "../src/js/secp256k1.js";
import { base58checkDecode } from "../src/js/base58.js";
import {
  BIP47_BASE58_VERSION,
  BIP47_INDEX_MAX,
  BIP47_PAYLOAD_BYTES,
  BIP47_PURPOSE,
  BIP47_VERSION_V1,
  blindPaymentCode,
  blindingFactor,
  bytesToHex,
  coinTypeForNetwork,
  decodePaymentCode,
  derivePaymentCodeFromExtendedKey,
  derivePaymentCodeKeys,
  deriveReceiveAddresses,
  deriveSendAddresses,
  encodePaymentCode,
  findDerivedAddress,
  hexToBytes,
  maskPaymentCodePayload,
  notificationAddress,
  notificationPublicKey,
  paymentCodeFromNode,
  paymentCodeNode,
  paymentCodePath,
  paymentCodePayloadFromScript,
  parseIndex,
  serializeOutpoint,
  serializePaymentCode,
  sharedSecretScalar,
  unblindPaymentCode,
} from "../src/js/bip47.js";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const vectors = JSON.parse(readFileSync(join(root, "test/fixtures/bip47-vectors.json"), "utf8"));
const { alice, bob, secretPoints, aliceToBobAddresses, notification } = vectors;

const aliceSeed = mnemonicToSeedSync(alice.mnemonic);
const bobSeed = mnemonicToSeedSync(bob.mnemonic);
const aliceRoot = () => HDKey.fromMasterSeed(aliceSeed);
const bobRoot = () => HDKey.fromMasterSeed(bobSeed);
const designatedPrivateKey = () => base58checkDecode(notification.designatedInputWif).slice(1, 33);

test("the fixture seeds match the published BIP32 seeds", () => {
  assert.equal(bytesToHex(aliceSeed), alice.seed);
  assert.equal(bytesToHex(bobSeed), bob.seed);
});

test("the payment code path is m/47'/coin_type'/identity'", () => {
  assert.equal(BIP47_PURPOSE, 47);
  assert.equal(paymentCodePath(0, 0), "m/47'/0'/0'");
  assert.equal(paymentCodePath(1, 3), "m/47'/1'/3'");
  assert.equal(coinTypeForNetwork("mainnet"), 0);
  assert.equal(coinTypeForNetwork("testnet"), 1);
});

test("the binary payment code is the published 80-byte layout", () => {
  assert.equal(BIP47_PAYLOAD_BYTES, 80);
  assert.equal(BIP47_BASE58_VERSION, 0x47);
  const keys = derivePaymentCodeKeys(aliceRoot(), { coinType: 0, identity: 0 });
  const payload = keys.payload;
  assert.equal(payload.length, 80);
  assert.equal(payload[0], BIP47_VERSION_V1, "byte 0 is the version");
  assert.equal(payload[1], 0, "byte 1 is the features bit field, all zero without Bitmessage");
  assert.ok(payload[2] === 0x02 || payload[2] === 0x03, "byte 2 is the sign byte");
  assert.deepEqual([...payload.slice(67)], new Array(13).fill(0), "bytes 67-79 are reserved and zero-filled");
  assert.equal(bytesToHex(payload), alice.payload);
});

test("official payment codes derive from the published seeds", () => {
  assert.equal(derivePaymentCodeKeys(aliceRoot(), { coinType: 0, identity: 0 }).paymentCode, alice.paymentCode);
  assert.equal(derivePaymentCodeKeys(bobRoot(), { coinType: 0, identity: 0 }).paymentCode, bob.paymentCode);
});

test("payment codes round-trip through Base58Check", () => {
  for (const code of [alice.paymentCode, bob.paymentCode]) {
    const decoded = decodePaymentCode(code);
    assert.equal(decoded.version, BIP47_VERSION_V1);
    assert.equal(decoded.features, 0);
    assert.equal(decoded.bitmessage, false);
    assert.equal(decoded.publicKey.length, 33);
    assert.equal(decoded.chainCode.length, 32);
    assert.equal(encodePaymentCode(decoded.payload), code);
  }
});

test("serializePaymentCode rebuilds the published payload from its parts", () => {
  const decoded = decodePaymentCode(alice.paymentCode);
  const rebuilt = serializePaymentCode({ publicKey: decoded.publicKey, chainCode: decoded.chainCode });
  assert.equal(bytesToHex(rebuilt), alice.payload);
  assert.equal(bytesToHex(paymentCodeFromNode(paymentCodeNode(alice.paymentCode))), alice.payload);
});

test("official notification addresses and the 0th ECDH key pair match", () => {
  const aliceKeys = derivePaymentCodeKeys(aliceRoot(), { coinType: 0, identity: 0 });
  const bobKeys = derivePaymentCodeKeys(bobRoot(), { coinType: 0, identity: 0 });
  assert.equal(aliceKeys.notificationAddress, alice.notificationAddress);
  assert.equal(bobKeys.notificationAddress, bob.notificationAddress);
  assert.equal(bytesToHex(aliceKeys.notificationPrivateKey), alice.a0);
  assert.equal(bytesToHex(aliceKeys.notificationPublicKey), alice.A0);
  assert.equal(bytesToHex(bobKeys.notificationPublicKey), bob.notificationPublicKey);
  // The notification address is public: it comes out of the payment code alone.
  assert.equal(notificationAddress(bob.paymentCode, "mainnet"), bob.notificationAddress);
  assert.equal(bytesToHex(notificationPublicKey(bob.paymentCode)), bob.notificationPublicKey);
});

test("a payment code's unhardened children reproduce b0..b9 and B0..B9", () => {
  const node = bobRoot().derive("m/47'/0'/0'");
  for (let i = 0; i < bob.privateKeys.length; i++) {
    const child = node.deriveChild(i);
    assert.equal(bytesToHex(child.privateKey), bob.privateKeys[i], `b${i}`);
    assert.equal(bytesToHex(child.publicKey), bob.publicKeys[i], `B${i}`);
  }
  // The same public children come out of the payment code with no secrets.
  const watchOnly = paymentCodeNode(bob.paymentCode);
  for (let i = 0; i < bob.publicKeys.length; i++) {
    assert.equal(bytesToHex(watchOnly.deriveChild(i).publicKey), bob.publicKeys[i], `B${i} watch-only`);
  }
});

test("sending derives the ten published Alice-to-Bob addresses", () => {
  const aliceKeys = derivePaymentCodeKeys(aliceRoot(), { coinType: 0, identity: 0 });
  const sent = deriveSendAddresses({
    senderPrivateKey: aliceKeys.notificationPrivateKey,
    recipientPaymentCode: bob.paymentCode,
    start: 0,
    count: 10,
  });
  assert.equal(sent.length, 10);
  for (let i = 0; i < 10; i++) {
    assert.equal(sent[i].index, i);
    assert.equal(sent[i].secretPointX, secretPoints[i], `S${i}`);
    assert.equal(sent[i].address, aliceToBobAddresses[i], `address ${i}`);
  }
});

test("receiving derives the same ten addresses and their spending keys", () => {
  const node = bobRoot().derive("m/47'/0'/0'");
  const received = deriveReceiveAddresses({
    recipientNode: node,
    senderPaymentCode: alice.paymentCode,
    start: 0,
    count: 10,
    includePrivate: true,
  });
  assert.equal(received.length, 10);
  for (let i = 0; i < 10; i++) {
    assert.equal(received[i].secretPointX, secretPoints[i], `S${i}`);
    assert.equal(received[i].address, aliceToBobAddresses[i], `address ${i}`);
    // b' = b + s must be the key behind the address the sender computed.
    const derivedPublic = bytesToHex(secp256k1.getPublicKey(hexToBytes(received[i].privateKey), true));
    assert.equal(derivedPublic, received[i].publicKey, `b'${i} rebuilds B'${i}`);
  }
});

test("receive keys stay hidden unless the caller asks for them", () => {
  const node = bobRoot().derive("m/47'/0'/0'");
  const received = deriveReceiveAddresses({ recipientNode: node, senderPaymentCode: alice.paymentCode, count: 3 });
  for (const entry of received) assert.equal(entry.privateKey, "");
});

test("watch-only material is refused for anything that needs a private key", () => {
  const watchOnly = paymentCodeNode(bob.paymentCode);
  assert.throws(
    () => deriveReceiveAddresses({ recipientNode: watchOnly, senderPaymentCode: alice.paymentCode, count: 1 }),
    /private/i,
  );
  assert.throws(
    () => deriveReceiveAddresses({ recipientNode: watchOnly, senderPaymentCode: alice.paymentCode, count: 1, includePrivate: true }),
    /private/i,
  );
  // A neutered root still produces the public half: payment code + address.
  const neutered = bobRoot().derive("m/47'/0'/0'").neutered();
  const keys = derivePaymentCodeFromExtendedKey(neutered.publicExtendedKey, { coinType: 0, identity: 0 });
  assert.equal(keys.watchOnly, true);
  assert.equal(keys.paymentCode, bob.paymentCode);
  assert.equal(keys.notificationAddress, bob.notificationAddress);
  assert.equal(keys.notificationPrivateKey, null);
});

test("an account xprv at depth 3 produces the same payment code as the root", () => {
  const account = bobRoot().derive("m/47'/0'/0'");
  const keys = derivePaymentCodeFromExtendedKey(account.privateExtendedKey, { coinType: 0, identity: 0 });
  assert.equal(keys.paymentCode, bob.paymentCode);
  assert.equal(keys.watchOnly, false);
  assert.equal(bytesToHex(keys.notificationPrivateKey), bob.privateKeys[0]);
});

test("an extended key at the wrong depth is refused rather than guessed at", () => {
  const wrong = bobRoot().derive("m/47'/0'");
  assert.throws(() => derivePaymentCodeFromExtendedKey(wrong.privateExtendedKey), /depth 3/);
});

test("the notification outpoint serializes txid-reversed with a little-endian vout", () => {
  assert.equal(bytesToHex(serializeOutpoint(notification.txid, notification.vout)), notification.outpoint);
  assert.throws(() => serializeOutpoint(notification.txid, -1), /vout/);
  assert.throws(() => serializeOutpoint("00", 0), /32 bytes/);
});

test("blinding a payment code reproduces the published mask and payload", () => {
  const aliceKeys = derivePaymentCodeKeys(aliceRoot(), { coinType: 0, identity: 0 });
  const bobKeys = derivePaymentCodeKeys(bobRoot(), { coinType: 0, identity: 0 });
  const blinded = blindPaymentCode({
    payload: aliceKeys.payload,
    senderPrivateKey: designatedPrivateKey(),
    recipientNotificationPublicKey: bobKeys.notificationPublicKey,
    txid: notification.txid,
    vout: notification.vout,
  });
  assert.equal(bytesToHex(blinded.secretPointX), notification.secretPointX);
  assert.equal(bytesToHex(blinded.mask), notification.blindingMask);
  assert.equal(bytesToHex(blinded.blinded), notification.blindedPayload);
  assert.equal(bytesToHex(blinded.outpoint), notification.outpoint);
});

test("the blinding factor is HMAC-SHA512 keyed by the outpoint over the secret point x", () => {
  // The BIP prose writes the two arguments in one order for the sender and the
  // other for the recipient; the published mask settles which one is real.
  const mask = blindingFactor(hexToBytes(notification.outpoint), hexToBytes(notification.secretPointX));
  assert.equal(bytesToHex(mask), notification.blindingMask);
  assert.throws(() => blindingFactor(hexToBytes(notification.outpoint).slice(0, 32), hexToBytes(notification.secretPointX)), /36-byte/);
});

test("unblinding a pasted notification payload recovers the sender's payment code", () => {
  const bobKeys = derivePaymentCodeKeys(bobRoot(), { coinType: 0, identity: 0 });
  const designatedPublicKey = secp256k1.getPublicKey(designatedPrivateKey(), true);
  const recovered = unblindPaymentCode({
    blinded: hexToBytes(notification.blindedPayload),
    notificationPrivateKey: bobKeys.notificationPrivateKey,
    designatedPublicKey,
    txid: notification.txid,
    vout: notification.vout,
  });
  assert.equal(recovered.paymentCode, alice.paymentCode);
  assert.equal(bytesToHex(recovered.payload), alice.payload);
  assert.equal(recovered.decoded.version, BIP47_VERSION_V1);
});

test("an unblinded payload whose x value is off the curve is reported, not thrown", () => {
  const bobKeys = derivePaymentCodeKeys(bobRoot(), { coinType: 0, identity: 0 });
  const designatedPublicKey = secp256k1.getPublicKey(designatedPrivateKey(), true);
  // A payload that is not this sender's unblinds to garbage. BIP-47 says ignore
  // it rather than fail. Masking is its own inverse, so blinding a payload with
  // an x value above the field order gives an input that unblinds to exactly
  // that — no search, no luck.
  const offCurve = hexToBytes(alice.payload);
  offCurve.fill(0xff, 3, 35);
  const blinded = maskPaymentCodePayload(offCurve, hexToBytes(notification.blindingMask));
  const recovered = unblindPaymentCode({
    blinded,
    notificationPrivateKey: bobKeys.notificationPrivateKey,
    designatedPublicKey,
    outpoint: hexToBytes(notification.outpoint),
  });
  assert.equal(bytesToHex(recovered.payload), bytesToHex(offCurve));
  assert.equal(recovered.decoded, null);
  assert.equal(recovered.paymentCode, "");
  // The same rejection guards a directly pasted payment code.
  assert.throws(() => decodePaymentCode(encodePaymentCode(offCurve)), /not a secp256k1 point|Invalid public key/);
});

test("masking is its own inverse", () => {
  const mask = hexToBytes(notification.blindingMask);
  const once = maskPaymentCodePayload(hexToBytes(alice.payload), mask);
  assert.equal(bytesToHex(once), notification.blindedPayload);
  assert.equal(bytesToHex(maskPaymentCodePayload(once, mask)), alice.payload);
  // Version, features, sign and the reserved tail are outside the mask.
  assert.equal(once[0], 0x01);
  assert.equal(once[1], 0x00);
  assert.deepEqual([...once.slice(67)], new Array(13).fill(0));
});

test("the notification payload reads out of the published OP_RETURN script", () => {
  assert.equal(bytesToHex(paymentCodePayloadFromScript(notification.opReturnScript)), notification.blindedPayload);
  assert.equal(bytesToHex(paymentCodePayloadFromScript(notification.blindedPayload)), notification.blindedPayload);
  assert.throws(() => paymentCodePayloadFromScript("6a0100"), /80-byte OP_RETURN/);
});

test("verifying a pasted address checks it against a derived window, not the chain", () => {
  const aliceKeys = derivePaymentCodeKeys(aliceRoot(), { coinType: 0, identity: 0 });
  const sent = deriveSendAddresses({
    senderPrivateKey: aliceKeys.notificationPrivateKey,
    recipientPaymentCode: bob.paymentCode,
    start: 0,
    count: 10,
  });
  const hit = findDerivedAddress(aliceToBobAddresses[4], sent);
  assert.equal(hit.found, true);
  assert.equal(hit.index, 4);
  const miss = findDerivedAddress(bob.notificationAddress, sent);
  assert.equal(miss.found, false);
  assert.equal(miss.index, null);
  assert.throws(() => findDerivedAddress("  ", sent), /Paste an address/);
});

test("testnet addresses follow the network without changing the payment code", () => {
  const keys = derivePaymentCodeKeys(bobRoot(), { coinType: 1, identity: 0, network: "testnet" });
  assert.ok(keys.notificationAddress.startsWith("m") || keys.notificationAddress.startsWith("n"));
  // BIP-47 defines one Base58 version byte, so a payment code stays P-prefixed.
  assert.ok(keys.paymentCode.startsWith("PM8T"));
});

test("indexes, counts, and malformed payment codes are rejected", () => {
  assert.equal(parseIndex("7"), 7);
  assert.equal(BIP47_INDEX_MAX, 2147483647);
  assert.throws(() => parseIndex(-1), /integer from 0/);
  assert.throws(() => parseIndex(BIP47_INDEX_MAX + 1), /integer from 0/);
  assert.throws(() => decodePaymentCode(""), /empty/);
  assert.throws(() => decodePaymentCode(bob.notificationAddress), /80 bytes|version byte/);
  assert.throws(() => encodePaymentCode(new Uint8Array(79)), /80 bytes/);
  const aliceKeys = derivePaymentCodeKeys(aliceRoot(), { coinType: 0, identity: 0 });
  assert.throws(
    () => deriveSendAddresses({ senderPrivateKey: aliceKeys.notificationPrivateKey, recipientPaymentCode: bob.paymentCode, count: 0 }),
    /1 and 1000/,
  );
});

test("an out-of-group shared secret is reported rather than reduced", () => {
  const point = secp256k1.Point.fromBytes(hexToBytes(bob.notificationPublicKey));
  const shared = sharedSecretScalar(hexToBytes(alice.a0), point);
  assert.equal(bytesToHex(shared.pointX), secretPoints[0]);
  assert.equal(shared.bytes.length, 32);
  assert.throws(() => sharedSecretScalar(new Uint8Array(32), point), /out of the secp256k1 range/);
});

test("derivation nodes do not leak the root's private key back to the caller", () => {
  const keys = derivePaymentCodeKeys(aliceRoot(), { coinType: 0, identity: 0 });
  // The notification private key is the one secret the caller asked for; the
  // account node and every intermediate must already be wiped.
  assert.equal(keys.notificationPrivateKey.length, 32);
  assert.equal(keys.publicKey.length, 33);
  assert.equal(keys.chainCode.length, 32);
  assert.equal(Object.prototype.hasOwnProperty.call(keys, "privateKey"), false);
});
