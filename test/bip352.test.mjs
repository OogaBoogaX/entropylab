import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { HDKey } from "@scure/bip32";
import { secp256k1 } from "../src/js/secp256k1.js";
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
  taggedHash,
  inputHash,
  serUint32,
  scalarFromBytes,
  Point,
  hexToBytes,
  bytesToHex,
} from "../src/js/bip352.js";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const vectors = JSON.parse(readFileSync(join(root, "test/fixtures/bip352-send-and-receive.json"), "utf8"));

test("K_max matches the published reference (2323)", () => {
  assert.equal(BIP352_K_MAX, 2323);
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
