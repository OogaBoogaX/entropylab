import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { HDKey } from "@scure/bip32";
import { secp256k1 } from "../src/js/secp256k1.js";
import { hash160 } from "../src/js/hashes.js";
import {
  BIP352_K_MAX,
  createLabeledSilentPaymentAddress,
  createSilentPaymentOutputs,
  decodeSilentPaymentAddress,
  deriveSilentPaymentKeys,
  eligibleInputKeys,
  encodeSilentPaymentAddress,
  encodeSpscan,
  encodeSpspend,
  extractInputPubKey,
  formatSpDescriptor,
  generateLabel,
  hrpForNetwork,
  p2trAddressFromXonly,
  scanSilentPaymentOutputs,
  spendPrivForOutput,
  taprootOutputPrivateKey,
  taggedHash,
  inputHash,
  parseWitnessHex,
  serUint32,
  scalarFromBytes,
  Point,
  hexToBytes,
  bytesToHex,
  vinHasSpendData,
} from "../src/js/bip352.js";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const vectors = JSON.parse(readFileSync(join(root, "test/fixtures/bip352-send-and-receive.json"), "utf8"));

test("K_max matches the published reference (2323)", () => {
  assert.equal(BIP352_K_MAX, 2323);
});

test("a witness stack with trailing bytes is refused, not truncated", () => {
  assert.deepEqual(parseWitnessHex("0100"), [new Uint8Array()]);
  assert.throws(() => parseWitnessHex("010000"), /trailing bytes/);
  // A 0xfe count is read unsigned: 0x80000000 was a negative number before.
  assert.throws(() => parseWitnessHex("fe00000080"), /Witness ended early/);
});

test("tagged hash is BIP-340 style with the BIP-352 tags", () => {
  const digest = taggedHash("BIP0352/Label", new Uint8Array(32), new Uint8Array(4));
  assert.equal(digest.length, 32);
});

test("official receiving addresses encode from the given scan/spend keys", () => {
  const given = vectors[0].receiving[0].given.key_material;
  const expected = vectors[0].receiving[0].expected.addresses[0];
  const scan = hexToBytes(given.scan_priv_key);
  const spend = hexToBytes(given.spend_priv_key);
  const scanPoint = secp256k1.Point.fromBytes(secp256k1.getPublicKey(scan, true));
  const spendPoint = secp256k1.Point.fromBytes(secp256k1.getPublicKey(spend, true));
  const address = encodeSilentPaymentAddress(scanPoint, spendPoint, "sp");
  assert.equal(address, expected);
  const decoded = decodeSilentPaymentAddress(address, "sp");
  assert.equal(bytesToHex(decoded.scan.toBytes(true)), bytesToHex(secp256k1.getPublicKey(scan, true)));
  assert.equal(bytesToHex(decoded.spend.toBytes(true)), bytesToHex(secp256k1.getPublicKey(spend, true)));
});

test("labeled addresses from the even-parity vector match the published set", () => {
  const row = vectors.find((item) => item.comment.startsWith("Receiving with labels: label with even parity"));
  const given = row.receiving[0].given;
  const scan = hexToBytes(given.key_material.scan_priv_key);
  const spend = hexToBytes(given.key_material.spend_priv_key);
  const spendPoint = secp256k1.Point.fromBytes(secp256k1.getPublicKey(spend, true));
  const scanPoint = secp256k1.Point.fromBytes(secp256k1.getPublicKey(scan, true));
  const addresses = [encodeSilentPaymentAddress(scanPoint, spendPoint, "sp")];
  for (const label of given.labels) addresses.push(createLabeledSilentPaymentAddress(scan, spendPoint, label, "sp"));
  assert.deepEqual(addresses, row.receiving[0].expected.addresses);
});

for (const [index, vector] of vectors.entries()) {
  test(`BIP-352 vector ${index}: ${vector.comment} (send)`, () => {
    for (const sending of vector.sending) {
      const vins = sending.given.vin;
      const { pubkeys } = eligibleInputKeys(vins);
      const expectedPubs = sending.expected.input_pub_keys || [];
      assert.deepEqual(pubkeys.map((entry) => bytesToHex(entry.point.toBytes(true))), expectedPubs);
      if (!pubkeys.length) {
        assert.deepEqual(sending.expected.outputs[0], []);
        continue;
      }
      const result = createSilentPaymentOutputs(vins, sending.given.recipients, { hrp: "sp" });
      if (sending.expected.input_private_key_sum && result.inputPrivateKeySum && result.inputPrivateKeySum !== "0".repeat(64)) {
        assert.equal(result.inputPrivateKeySum, sending.expected.input_private_key_sum);
      }
      // Exact counts first, then an order-insensitive multiset match (vectors
      // permit alternative orderings) — never a Set, which would hide a lost
      // duplicate (issue #332).
      const actual = result.outputs;
      const matched = sending.expected.outputs.some((candidate) => {
        return actual.length === candidate.length && [...actual].sort().join(",") === [...candidate].sort().join(",");
      });
      assert.equal(matched, true, `send outputs ${actual.join(",")} did not match any expected set`);
    }
  });

  test(`BIP-352 vector ${index}: ${vector.comment} (receive)`, () => {
    for (const receiving of vector.receiving) {
      const given = receiving.given;
      const expected = receiving.expected;
      const scan = hexToBytes(given.key_material.scan_priv_key);
      const spend = hexToBytes(given.key_material.spend_priv_key);
      const spendPub = secp256k1.getPublicKey(spend, true);
      const scanPoint = secp256k1.Point.fromBytes(secp256k1.getPublicKey(scan, true));
      const spendPoint = secp256k1.Point.fromBytes(spendPub);
      const addresses = [encodeSilentPaymentAddress(scanPoint, spendPoint, "sp")];
      for (const label of given.labels || []) addresses.push(createLabeledSilentPaymentAddress(scan, spendPoint, label, "sp"));
      assert.deepEqual(addresses, expected.addresses);
      const result = scanSilentPaymentOutputs({
        scanPriv: scan,
        spendPub,
        vins: given.vin,
        outputs: given.outputs,
        labels: given.labels || [],
      });
      if (expected.input_pub_key_sum) assert.equal(result.inputPubKeySum, expected.input_pub_key_sum);
      if (expected.tweak) assert.equal(result.tweak, expected.tweak);
      if (expected.shared_secret) assert.equal(result.sharedSecret, expected.shared_secret);
      if (Array.isArray(expected.outputs)) {
        const actual = new Set(result.outputs.map((row) => `${row.pub_key}:${row.priv_key_tweak}`));
        const expect = new Set(expected.outputs.map((row) => `${row.pub_key}:${row.priv_key_tweak}`));
        assert.deepEqual(actual, expect);
        for (const row of result.outputs) {
          const full = spendPrivForOutput(spend, row.priv_key_tweak);
          const pub = secp256k1.getPublicKey(full, true);
          assert.equal(bytesToHex(pub.slice(1)), row.pub_key);
          if (row.label !== null) assert.ok((given.labels || []).includes(row.label), `label ${row.label} must come from the scanned label set`);
        }
      } else if ("n_outputs" in expected) {
        assert.equal(result.outputs.length, expected.n_outputs);
      } else {
        assert.fail("vector is missing outputs / n_outputs");
      }
    }
  });
}

test("hardened BIP-352 paths refuse watch-only seeds", () => {
  const seed = hexToBytes("00".repeat(64));
  const keys = deriveSilentPaymentKeys(seed, { coinType: 0, account: 0 });
  assert.equal(keys.scanPath, "m/352'/0'/0'/1'/0");
  assert.equal(keys.spendPath, "m/352'/0'/0'/0'/0");
  assert.equal(keys.scanPriv.length, 32);
  assert.equal(keys.spendPriv.length, 32);
  const address = encodeSilentPaymentAddress(keys.scanPoint, keys.spendPoint, "sp");
  assert.match(address, /^sp1q/);
  const roundTrip = decodeSilentPaymentAddress(address, "sp");
  assert.equal(bytesToHex(roundTrip.scan.toBytes(true)), bytesToHex(keys.scanPub));
  const xpub = HDKey.fromMasterSeed(seed).derive("m/84'/0'/0'").publicExtendedKey;
  const watch = HDKey.fromExtendedKey(xpub);
  assert.equal(watch.privateKey, null);
  assert.throws(() => watch.derive("m/352'/0'/0'/1'/0"));
  // Bech32m case rules: all-uppercase is a valid encoding, mixed case is not
  // (issue #335) — reject before any lowercasing launders it.
  assert.deepEqual(decodeSilentPaymentAddress(address.toUpperCase(), "sp").hrp, "sp");
  const mixed = address.slice(0, 6) + address[6].toUpperCase() + address.slice(7);
  assert.ok(mixed !== mixed.toLowerCase() && mixed !== mixed.toUpperCase());
  assert.throws(() => decodeSilentPaymentAddress(mixed, "sp"), /mixed case/);
});

test("BIP-392 spscan / spspend encode and wrap in sp()", () => {
  const scan = hexToBytes("0f694e068028a717f8af6b9411f9a133dd3565258714cc226594b34db90c1f2c");
  const spend = hexToBytes("9d6ad855ce3417ef84e836892e5a56392bfba05fa5d97ccea30e266f540e08b3");
  const spendPub = secp256k1.getPublicKey(spend, true);
  const spscan = encodeSpscan(scan, spendPub, "mainnet");
  const spspend = encodeSpspend(scan, spend, "mainnet");
  assert.match(spscan, /^spscan1q/);
  assert.match(spspend, /^spspend1q/);
  assert.equal(formatSpDescriptor(spscan), `sp(${spscan})`);
  const tsp = encodeSpscan(scan, spendPub, "testnet");
  assert.match(tsp, /^tspscan1q/);
});

test("computed silent-payment outputs encode as mainnet P2TR", () => {
  const address = p2trAddressFromXonly("3e9fce73d4e77a4809908e3c3a2e54ee147b9312dc5044a193d1fc85de46e3c1", "mainnet");
  assert.match(address, /^bc1p/);
});

test("NUMS internal-key taproot inputs are skipped by extractInputPubKey", () => {
  const vector = vectors.find((item) => item.comment.includes("NUMS point"));
  const vins = vector.sending[0].given.vin;
  const extracted = vins.map((vin) => extractInputPubKey(vin));
  const present = extracted.filter(Boolean);
  assert.equal(present.length, vector.sending[0].expected.input_pub_keys.length);
});

test("a P2SH-P2WPKH input whose redeem script does not hash to its prevout is refused", () => {
  // BIP143's P2SH-P2WPKH worked example: the redeem script
  // 001479091972186c449eb1ded22b78e40d009bdf0089 hashes (hash160) to
  // 4733f37cf4db86fbc2efed2500b4f4e49f312023.
  const pub = "03ad1d8e89212f0b92c74d23bb710c00662ad1470198ac48c43f7d6f93a2a26873";
  const base = {
    txid: "11".repeat(32),
    vout: 0,
    scriptSig: "16001479091972186c449eb1ded22b78e40d009bdf0089",
    // Only the last witness item is read; the signature placeholder is never parsed.
    txinwitness: "02" + "47" + "00".repeat(71) + "21" + pub,
    prevout: "a9144733f37cf4db86fbc2efed2500b4f4e49f31202387",
  };
  const extracted = extractInputPubKey(base);
  assert.equal(bytesToHex(extracted.point.toBytes(true)), pub);
  // The same unlocking data under a prevout whose hash it does not commit
  // to (a mistyped prevout, say) must be refused: skipping it would leave a
  // key the chain counts out of the sender's sum.
  const mismatchedPrevout = { ...base, prevout: "a914" + "00".repeat(20) + "87" };
  assert.throws(() => extractInputPubKey(mismatchedPrevout), /redeem script its prevout commits to/);
  assert.throws(() => eligibleInputKeys([mismatchedPrevout]), /redeem script its prevout commits to/);
  // Likewise a redeem script the prevout does not commit to, and a push
  // that is not the single 22-byte redeem push.
  assert.throws(() => extractInputPubKey({ ...base, scriptSig: "160014" + "00".repeat(20) }), /redeem script its prevout commits to/);
  // A non-minimal OP_PUSHDATA1 push of the right redeem script.
  assert.throws(() => extractInputPubKey({ ...base, scriptSig: "4c16" + base.scriptSig.slice(2) }), /redeem script its prevout commits to/);
  // The witness key must hash to the redeem script's key hash: another
  // input's key (here the generator point) or a missing witness is refused.
  const otherKey = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
  assert.throws(() => extractInputPubKey({ ...base, txinwitness: "02" + "47" + "00".repeat(71) + "21" + otherKey }), /witness key does not hash/);
  assert.throws(() => extractInputPubKey({ ...base, txinwitness: "" }), /witness key does not hash/);
  // Native P2WPKH under the same key hash: the matching key counts, and a
  // mismatched or missing witness key is refused the same way.
  const native = { ...base, scriptSig: "", prevout: "001479091972186c449eb1ded22b78e40d009bdf0089" };
  assert.equal(bytesToHex(extractInputPubKey(native).point.toBytes(true)), pub);
  assert.throws(() => extractInputPubKey({ ...native, txinwitness: "02" + "47" + "00".repeat(71) + "21" + otherKey }), /witness key does not hash/);
  assert.throws(() => extractInputPubKey({ ...native, txinwitness: "" }), /witness key does not hash/);
  // The redeem script pasted as the scriptSig (missing its push byte) and an
  // empty scriptSig are refused too, not dropped from the key sum.
  assert.throws(() => extractInputPubKey({ ...base, scriptSig: base.scriptSig.slice(2) }), /redeem script its prevout commits to/);
  assert.throws(() => extractInputPubKey({ ...base, scriptSig: "" }), /redeem script its prevout commits to/);
  // A consistent P2SH-P2WSH spend (BIP143's worked example: redeem
  // 0020a16b…cb54 under P2SH a9149993…a587) is ineligible and still skipped.
  const p2shP2wsh = {
    ...base,
    scriptSig: "220020a16b5755f7f6f96dbd65f5f0d6ab9418b89af4b1f14a1bb8a09062c35f0dcb54",
    prevout: "a9149993a429037b5d912407a71c252019287b8d27a587",
  };
  assert.equal(extractInputPubKey(p2shP2wsh), null);
});

test("hrp follows the wallet network", () => {
  assert.equal(hrpForNetwork("mainnet"), "sp");
  assert.equal(hrpForNetwork("testnet"), "tsp");
  assert.equal(hrpForNetwork("signet"), "tsp");
});

test("group sizes beyond K_max fail before any expansion", () => {
  const address = vectors[0].receiving[0].expected.addresses[0];
  const vin = vectors[0].sending[0].given.vin;
  // A pasted count this large would exhaust memory if recipients were
  // expanded before the per-group K_max check; it must fail silently instead.
  const result = createSilentPaymentOutputs(vin, [{ address, count: 1e10 }], { hrp: "sp" });
  assert.deepEqual(result.outputs, []);
  assert.equal(result.sharedSecrets, null);
  assert.throws(() => createSilentPaymentOutputs(vin, [{ address, count: 0 }], { hrp: "sp" }), /positive integer/);
});

test("future SegWit inputs fail sending and make v0 receivers skip the transaction", () => {
  const sending = structuredClone(vectors[0].sending[0].given);
  const futureWitnessInput = {
    txid: "22".repeat(32),
    vout: 1,
    scriptSig: "",
    txinwitness: "",
    prevout: { scriptPubKey: { hex: "5220" + "33".repeat(32) } },
  };
  sending.vin.push(futureWitnessInput);
  assert.throws(
    () => createSilentPaymentOutputs(sending.vin, sending.recipients, { hrp: "sp" }),
    /future SegWit version/i,
  );

  const receiving = vectors[0].receiving[0].given;
  const scan = hexToBytes(receiving.key_material.scan_priv_key);
  const spend = hexToBytes(receiving.key_material.spend_priv_key);
  const result = scanSilentPaymentOutputs({
    scanPriv: scan,
    spendPub: secp256k1.getPublicKey(spend, true),
    vins: [...receiving.vin, futureWitnessInput],
    outputs: vectors[0].sending[0].expected.outputs[0],
    labels: receiving.labels || [],
  });
  assert.deepEqual(result, { outputs: [], inputPubKeySum: null, tweak: null, sharedSecret: null });
});

test("sender rejects a private key that does not match its eligible input", () => {
  const given = structuredClone(vectors[0].sending[0].given);
  given.vin[0].private_key = "00".repeat(31) + "01";
  assert.throws(
    () => createSilentPaymentOutputs(given.vin, given.recipients, { hrp: "sp" }),
    /input 0 private key does not match/i,
  );
});

test("generateLabel is deterministic", () => {
  const scan = hexToBytes("0f694e068028a717f8af6b9411f9a133dd3565258714cc226594b34db90c1f2c");
  const a = generateLabel(scan, 0);
  const b = generateLabel(scan, 0);
  const c = generateLabel(scan, 1);
  assert.equal(a, b);
  assert.notEqual(a, c);
});

test("deliberately coincident generated outputs are both kept (issue #332)", () => {
  // A spend point crafted relative to another spend point and the known
  // per-index tweaks makes two requested outputs coincide: with recipient
  // spend P at k=0, Q = P + (t0 - t1)·G makes Q + t1·G === P + t0·G.
  // Deduplication would silently drop one payment.
  const sending = vectors[0].sending.find((s) => s.given.vin.length && s.expected.outputs[0].length);
  const vins = sending.given.vin;
  const recipient = sending.given.recipients[0];
  const { scan, spend } = decodeSilentPaymentAddress(recipient.address, "sp");
  const base = createSilentPaymentOutputs(vins, [recipient], { hrp: "sp" });
  assert.equal(base.outputs.length, 1);
  const secret = hexToBytes(base.sharedSecrets[0]);
  const t0 = scalarFromBytes(taggedHash("BIP0352/SharedSecret", secret, serUint32(0)));
  const t1 = scalarFromBytes(taggedHash("BIP0352/SharedSecret", secret, serUint32(1)));
  const n = BigInt("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"); // secp256k1 group order
  const delta = (((t0 - t1) % n) + n) % n;
  const crafted = spend.add(Point.BASE.multiply(delta));
  const second = { address: encodeSilentPaymentAddress(scan, crafted, "sp"), count: 1 };
  const result = createSilentPaymentOutputs(vins, [recipient, second], { hrp: "sp" });
  assert.equal(result.outputs.length, 2, "both requested outputs must be returned");
  assert.equal(result.outputs[1], result.outputs[0], "the crafted outputs coincide");
  assert.equal(result.outputs[0], base.outputs[0], "the first output is untouched");
});

test("P2SH commitment is checked with or without a witness; legacy P2SH stays ineligible", () => {
  const hash160Hex = (bytes) => bytesToHex(hash160(bytes));
  const key = hexToBytes("03ad1d8e89212f0b92c74d23bb710c00662ad1470198ac48c43f7d6f93a2a26873");
  // BIP143's P2SH-P2WPKH worked example redeem script.
  const redeem = hexToBytes("001479091972186c449eb1ded22b78e40d009bdf0089");
  const base = {
    txid: "11".repeat(32),
    vout: 0,
    scriptSig: "16" + bytesToHex(redeem),
    txinwitness: "02" + "47" + "00".repeat(71) + "21" + bytesToHex(key),
    prevout: "a914" + hash160Hex(redeem) + "87",
  };
  // The BIP143 vector still returns the key, and a consistent P2SH-P2WSH
  // spend (BIP143's redeem 0020a16b…cb54) is still ineligible.
  assert.equal(bytesToHex(extractInputPubKey(base).point.toBytes(true)), bytesToHex(key));
  const p2wshRedeem = hexToBytes("0020a16b5755f7f6f96dbd65f5f0d6ab9418b89af4b1f14a1bb8a09062c35f0dcb54");
  assert.equal(extractInputPubKey({ ...base, scriptSig: "22" + bytesToHex(p2wshRedeem), prevout: "a914" + hash160Hex(p2wshRedeem) + "87" }), null);
  // A pasted vin with no witness and one mangled field must be refused, not
  // silently dropped from the sender's key sum while the chain counts it.
  const noWitness = { ...base, txinwitness: "" };
  assert.throws(() => extractInputPubKey({ ...noWitness, prevout: "a914" + "00".repeat(20) + "87" }), /redeem script its prevout commits to/);
  assert.throws(() => extractInputPubKey({ ...noWitness, scriptSig: bytesToHex(redeem) }), /redeem script its prevout commits to/);
  assert.throws(() => eligibleInputKeys([{ ...noWitness, prevout: "a914" + "00".repeat(20) + "87" }]), /redeem script its prevout commits to/);
  // A legacy P2SH 1-of-1 multisig spend: consistent, ineligible, no witness.
  const multisigKey = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
  const multisigRedeem = hexToBytes("5121" + multisigKey + "51ae");
  const multisig = {
    txid: "33".repeat(32),
    vout: 0,
    scriptSig: "00" + "47" + "30" + "44" + "00".repeat(69) + "25" + bytesToHex(multisigRedeem),
    txinwitness: "",
    prevout: "a914" + hash160Hex(multisigRedeem) + "87",
  };
  assert.equal(extractInputPubKey(multisig), null);
  // The same spend carrying a witness is consensus-invalid (WITNESS_UNEXPECTED).
  assert.throws(() => extractInputPubKey({ ...multisig, txinwitness: "0140" + "5a".repeat(64) }), /redeem script its prevout commits to/);
  // A mistyped prevout, and a non-push opcode in front of the redeem push.
  assert.throws(() => extractInputPubKey({ ...multisig, prevout: "a914" + "00".repeat(20) + "87" }), /redeem script its prevout commits to/);
  assert.throws(() => extractInputPubKey({ ...multisig, scriptSig: "76" + multisig.scriptSig }), /redeem script its prevout commits to/);
});

test("a P2PKH input reveals its key or is refused", () => {
  const hash160Hex = (bytes) => bytesToHex(hash160(bytes));
  const compressed = hexToBytes("03ad1d8e89212f0b92c74d23bb710c00662ad1470198ac48c43f7d6f93a2a26873");
  // The secp256k1 generator point in uncompressed form (published constant).
  const uncompressed = hexToBytes("0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8");
  const scriptSigFor = (keyBytes) => "47" + "30" + "44" + "00".repeat(69) + bytesToHex(Uint8Array.of(keyBytes.length)) + bytesToHex(keyBytes);
  const vinFor = (keyBytes) => ({
    txid: "44".repeat(32),
    vout: 0,
    scriptSig: scriptSigFor(keyBytes),
    txinwitness: "",
    prevout: "76a914" + hash160Hex(keyBytes) + "88ac",
  });
  // A compressed key hashing to the key hash is eligible, as before.
  assert.equal(bytesToHex(extractInputPubKey(vinFor(compressed)).point.toBytes(true)), bytesToHex(compressed));
  // An uncompressed key is consistent but ineligible under BIP-352.
  assert.equal(extractInputPubKey(vinFor(uncompressed)), null);
  // A scriptSig holding a key that does not hash to the prevout's key hash
  // is mangled paste: skipping the input would silently drop it from the
  // key sum while the chain counts it.
  assert.throws(() => extractInputPubKey({ ...vinFor(uncompressed), scriptSig: scriptSigFor(compressed) }), /does not contain the key/);
});

test("a P2TR input with no witness is refused, not skipped", () => {
  const vin = { txid: "55".repeat(32), vout: 0, scriptSig: "", txinwitness: "", prevout: "5120" + "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798" };
  assert.throws(() => extractInputPubKey(vin), /P2TR input has no witness/);
  assert.throws(() => eligibleInputKeys([vin]), /P2TR input has no witness/);
  // With a key-path signature the same input is eligible.
  assert.equal(extractInputPubKey({ ...vin, txinwitness: "0140" + "5a".repeat(64) }).isTaproot, true);
});

test("a large legacy P2SH redeem pushed with OP_PUSHDATA1/2/4 is read little-endian and stays ineligible", () => {
  const key = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
  // 1-of-8 multisig: OP_1 <8 x 33-byte key> OP_8 OP_CHECKMULTISIG, 275 bytes.
  const redeem = hexToBytes("51" + ("21" + key).repeat(8) + "58ae");
  assert.equal(redeem.length, 275);
  const prevout = "a914" + bytesToHex(hash160(redeem)) + "87";
  const sig = "47" + "30" + "44" + "00".repeat(69);
  const vin = (push) => ({ txid: "66".repeat(32), vout: 0, scriptSig: "00" + sig + push + bytesToHex(redeem), txinwitness: "", prevout });
  // 275 = 0x0113: OP_PUSHDATA2 13 01, OP_PUSHDATA4 13 01 00 00.
  assert.equal(extractInputPubKey(vin("4d1301")), null);
  assert.equal(extractInputPubKey(vin("4e13010000")), null);
  // The big-endian reading (0x1301 = 4865) would overrun; so does a length one too long.
  assert.throws(() => extractInputPubKey(vin("4d1401")), /redeem script its prevout commits to/);
  // A 37-byte redeem pushed with OP_PUSHDATA1 is read the same way.
  const small = hexToBytes("5121" + key + "51ae");
  assert.equal(extractInputPubKey({ txid: "66".repeat(32), vout: 1, scriptSig: "00" + sig + "4c25" + bytesToHex(small), txinwitness: "", prevout: "a914" + bytesToHex(hash160(small)) + "87" }), null);
});

test("an unsigned input carrying its private key sends exactly like its signed form", () => {
  // A sender builds the outputs before signing, so its inputs have no
  // scriptSig or witness: eligibility and the key come from the prevout
  // script type and the scalar, and must agree with the later signed spend.
  const scalar = hexToBytes("11".repeat(32));
  const pub = secp256k1.getPublicKey(scalar, true);
  const keyHash = bytesToHex(hash160(pub));
  const tweaked = taprootOutputPrivateKey(scalar);
  const recipient = vectors[0].receiving[0].expected.addresses[0];
  const sigPush = "47" + "30" + "44" + "00".repeat(69);
  const keyPush = "21" + bytesToHex(pub);
  const sigWitness = "02" + "47" + "00".repeat(71) + keyPush;
  const cases = [
    ["P2PKH", "76a914" + keyHash + "88ac", sigPush + keyPush, "", scalar],
    ["P2WPKH", "0014" + keyHash, "", sigWitness, scalar],
    ["P2SH-P2WPKH", "a914" + bytesToHex(hash160(hexToBytes("0014" + keyHash))) + "87", "16" + "0014" + keyHash, sigWitness, scalar],
    ["P2TR", "5120" + bytesToHex(secp256k1.getPublicKey(tweaked, true).slice(1)), "", "01" + "40" + "5a".repeat(64), tweaked],
  ];
  for (const [name, prevout, scriptSig, txinwitness, key] of cases) {
    const base = { txid: "66".repeat(32), vout: 0, prevout };
    const recipients = [{ address: recipient, count: 1 }];
    const unsigned = createSilentPaymentOutputs([{ ...base, scriptSig: "", txinwitness: "", private_key: key }], recipients, { hrp: "sp" });
    const signed = createSilentPaymentOutputs([{ ...base, scriptSig, txinwitness, private_key: key }], recipients, { hrp: "sp" });
    assert.equal(unsigned.outputs.length, 1, name);
    assert.deepEqual(unsigned, signed, name);
  }
});

test("an unsigned input whose private key does not produce its prevout is refused", () => {
  const scalar = hexToBytes("11".repeat(32));
  const wrong = hexToBytes("22".repeat(32));
  const pub = secp256k1.getPublicKey(scalar, true);
  const keyHash = bytesToHex(hash160(pub));
  const tweaked = taprootOutputPrivateKey(scalar);
  const recipient = vectors[0].receiving[0].expected.addresses[0];
  const prevouts = [
    "76a914" + keyHash + "88ac",
    "0014" + keyHash,
    "a914" + bytesToHex(hash160(hexToBytes("0014" + keyHash))) + "87",
    "5120" + bytesToHex(secp256k1.getPublicKey(tweaked, true).slice(1)),
  ];
  for (const prevout of prevouts) {
    const vin = { txid: "77".repeat(32), vout: 0, scriptSig: "", txinwitness: "", prevout, private_key: wrong };
    assert.throws(() => createSilentPaymentOutputs([vin], [{ address: recipient, count: 1 }], { hrp: "sp" }), /does not match its eligible input public key/);
  }
});

test("an unsigned P2WSH input is skipped, and an unsigned input without its key is still refused", () => {
  const scalar = hexToBytes("11".repeat(32));
  const pub = secp256k1.getPublicKey(scalar, true);
  const recipient = vectors[0].receiving[0].expected.addresses[0];
  // P2WSH is not an eligible type: even carrying a key, the input is skipped.
  const p2wsh = { txid: "88".repeat(32), vout: 0, scriptSig: "", txinwitness: "", prevout: "0020" + "ab".repeat(32), private_key: scalar };
  const skipped = createSilentPaymentOutputs([p2wsh], [{ address: recipient, count: 1 }], { hrp: "sp" });
  assert.deepEqual(skipped.outputs, []);
  assert.deepEqual(skipped.inputPubKeys, []);
  // Without a private key an unsigned P2WPKH input keeps the #1018 refusal:
  // there is no witness key to check against the prevout's key hash.
  const p2wpkh = { txid: "99".repeat(32), vout: 0, scriptSig: "", txinwitness: "", prevout: "0014" + bytesToHex(hash160(pub)) };
  assert.throws(() => eligibleInputKeys([p2wpkh]), /witness key does not hash/);
  assert.throws(() => createSilentPaymentOutputs([p2wpkh], [{ address: recipient, count: 1 }], { hrp: "sp" }), /witness key does not hash/);
});

test("unsigned uncompressed-key inputs stay ineligible, and a witness array counts as spend data", () => {
  const scalar = hexToBytes("0000000000000000000000000000000000000000000000000000000000000001");
  const uncompressed = hexToBytes("0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8");
  const compressed = hexToBytes("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
  const unsigned = (prevout) => ({ txid: "77".repeat(32), vout: 0, scriptSig: "", txinwitness: "", prevout, private_key: bytesToHex(scalar) });
  // Paying the uncompressed key: consistent, ineligible (skipped), like the signed form.
  assert.deepEqual(eligibleInputKeys([unsigned("76a914" + bytesToHex(hash160(uncompressed)) + "88ac")]).pubkeys, []);
  assert.deepEqual(eligibleInputKeys([unsigned("0014" + bytesToHex(hash160(uncompressed)))]).pubkeys, []);
  // A key hash of neither form is still refused.
  assert.throws(() => eligibleInputKeys([unsigned("76a914" + "00".repeat(20) + "88ac")]), /does not match its eligible input public key/);
  // A vin given in the witness-array form is spend data: a mismatched
  // witness key is refused rather than replaced by the private key's.
  const p2wpkh = { ...unsigned("0014" + bytesToHex(hash160(compressed))), witness: [hexToBytes("47" + "00".repeat(71)), hexToBytes("03ad1d8e89212f0b92c74d23bb710c00662ad1470198ac48c43f7d6f93a2a26873")] };
  assert.throws(() => eligibleInputKeys([p2wpkh]), /witness key does not hash/);
  assert.equal(eligibleInputKeys([{ ...p2wpkh, witness: [hexToBytes("47" + "00".repeat(71)), compressed] }]).pubkeys.length, 1);
});

test("unsigned P2SH: an uncompressed-key P2SH-P2WPKH match is skipped, other P2SH is refused until its scriptSig is pasted", () => {
  const scalar = "0000000000000000000000000000000000000000000000000000000000000001";
  const uncompressed = hexToBytes("0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8");
  const wrapped = (key) => { const redeem = hexToBytes("0014" + bytesToHex(hash160(key))); return "a914" + bytesToHex(hash160(redeem)) + "87"; };
  const unsigned = (prevout, extra = {}) => ({ txid: "88".repeat(32), vout: 0, scriptSig: "", txinwitness: "", prevout, private_key: scalar, ...extra });
  assert.deepEqual(eligibleInputKeys([unsigned(wrapped(uncompressed))]).pubkeys, []);
  // P2SH-P2WSH: refused while unsigned; with its redeem push pasted it is skipped.
  const p2wshRedeem = hexToBytes("0020a16b5755f7f6f96dbd65f5f0d6ab9418b89af4b1f14a1bb8a09062c35f0dcb54");
  const p2wshPrevout = "a914" + bytesToHex(hash160(p2wshRedeem)) + "87";
  assert.throws(() => eligibleInputKeys([unsigned(p2wshPrevout)]), /does not match its eligible input public key/);
  assert.deepEqual(eligibleInputKeys([unsigned(p2wshPrevout, { scriptSig: "22" + bytesToHex(p2wshRedeem) })]).pubkeys, []);
  // An empty witness array next to hex witness data is spend data, not unsigned.
  const keyhashVin = { txid: "88".repeat(32), vout: 1, scriptSig: "", witness: [], txinwitness: "02" + "47" + "00".repeat(71) + "21" + "03ad1d8e89212f0b92c74d23bb710c00662ad1470198ac48c43f7d6f93a2a26873", prevout: "001479091972186c449eb1ded22b78e40d009bdf0089" };
  assert.equal(vinHasSpendData(keyhashVin), true);
});

test("a witness array of hex strings is read, and an empty array does not hide txinwitness", () => {
  const key = "03ad1d8e89212f0b92c74d23bb710c00662ad1470198ac48c43f7d6f93a2a26873";
  const prevout = "001479091972186c449eb1ded22b78e40d009bdf0089";
  const sig = "00".repeat(71);
  // Hex-string items are spend data and are checked, not dropped.
  assert.equal(eligibleInputKeys([{ txid: "99".repeat(32), vout: 0, scriptSig: "", witness: [sig, key], prevout }]).pubkeys.length, 1);
  assert.throws(() => eligibleInputKeys([{ txid: "99".repeat(32), vout: 0, scriptSig: "", witness: [sig, "02" + key.slice(2)], prevout, private_key: "00".repeat(31) + "01" }]), /witness key does not hash/);
  // An empty witness array next to hex witness data uses the hex data.
  const vin = { txid: "99".repeat(32), vout: 1, scriptSig: "", witness: [], txinwitness: "02" + "47" + sig + "21" + key, prevout };
  assert.equal(bytesToHex(extractInputPubKey(vin).point.toBytes(true)), key);
  assert.equal(eligibleInputKeys([vin]).pubkeys.length, 1);
});

test("unsigned hybrid-key inputs are skipped like their uncompressed form", () => {
  // SEC1 hybrid encoding: the uncompressed body under 0x06 (even y) or 0x07
  // (odd y). G is a published constant with even y; -G (scalar n-1, n
  // published) shares its x with the odd-y prefix.
  const scalar = "0000000000000000000000000000000000000000000000000000000000000001";
  const negScalar = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140";
  const g = secp256k1.getPublicKey(hexToBytes(scalar), true);
  const negG = secp256k1.getPublicKey(hexToBytes(negScalar), true);
  assert.equal(bytesToHex(g), "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
  assert.equal(bytesToHex(negG), "0379be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
  const hybrid = hexToBytes("06" + "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8");
  const negHybrid = Uint8Array.from(secp256k1.Point.fromBytes(negG).toBytes(false));
  negHybrid[0] = 0x07;
  const wrapped = (key) => { const redeem = hexToBytes("0014" + bytesToHex(hash160(key))); return "a914" + bytesToHex(hash160(redeem)) + "87"; };
  const unsigned = (prevout, key = scalar) => ({ txid: "77".repeat(32), vout: 0, scriptSig: "", txinwitness: "", prevout, private_key: key });
  // The signed form (scriptSig pushing the hybrid key) is skipped, so the
  // unsigned form must be too: consistent but ineligible under BIP-352.
  assert.equal(extractInputPubKey({ txid: "77".repeat(32), vout: 0, scriptSig: "47" + "30" + "44" + "00".repeat(69) + "41" + bytesToHex(hybrid), txinwitness: "", prevout: "76a914" + bytesToHex(hash160(hybrid)) + "88ac" }), null);
  assert.deepEqual(eligibleInputKeys([unsigned("76a914" + bytesToHex(hash160(hybrid)) + "88ac")]).pubkeys, []);
  assert.deepEqual(eligibleInputKeys([unsigned("0014" + bytesToHex(hash160(hybrid)))]).pubkeys, []);
  assert.deepEqual(eligibleInputKeys([unsigned(wrapped(hybrid))]).pubkeys, []);
  assert.deepEqual(eligibleInputKeys([unsigned("76a914" + bytesToHex(hash160(negHybrid)) + "88ac", negScalar)]).pubkeys, []);
  // A key hash matching no encoding of the scalar's key is still refused.
  assert.throws(() => eligibleInputKeys([unsigned("76a914" + "00".repeat(20) + "88ac")]), /does not match its eligible input public key/);
  assert.throws(() => eligibleInputKeys([unsigned("0014" + "00".repeat(20))]), /does not match its eligible input public key/);
  assert.throws(() => eligibleInputKeys([unsigned(wrapped(hexToBytes("02" + "00".repeat(32))))]), /does not match its eligible input public key/);
});
