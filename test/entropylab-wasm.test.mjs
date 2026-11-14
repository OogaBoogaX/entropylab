// Tests for the libsecp256k1 WASM facade (src/js/secp256k1.js, loaded by
// src/js/entropylab-wasm.js).
// Run with `npm test` (part of the default and CI suites).
//
// Two layers of assurance:
//  1. Fixed, independently published constants (generator point, 2G).
//  2. Differential checks against @noble/curves (pinned, previously the
//     implementation): the migration must be byte-for-byte behavior
//     preserving, including RFC 6979 extra-entropy semantics used for
//     Bitcoin Core-style low-r grinding.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { secp256k1 as noble } from "@noble/curves/secp256k1.js";
import { secp256k1, secp256k1Ready } from "../src/js/secp256k1.js";

const root = dirname(dirname(fileURLToPath(import.meta.url)));

const hexToBytes = (hex) => new Uint8Array(hex.match(/.{2}/g).map((b) => parseInt(b, 16)));
const bytesToHex = (bytes) => [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");

// Fixed inputs; nothing here is secret.
const KEY1 = new Uint8Array(32).fill(0).map((_, i) => (i === 31 ? 1 : 0)); // 0x01
const MSG = new Uint8Array(32).map((_, i) => (i * 7 + 3) & 0xff);
const KEY = new Uint8Array(32).map((_, i) => (i * 13 + 5) & 0xff);
const G_COMPRESSED = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const TWO_G_COMPRESSED = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";

test("secp256k1Ready resolves (WASM initialized synchronously under Node)", async () => {
  await secp256k1Ready;
});

test("committed WASM artifact is intact (sha256 in module header matches payload)", () => {
  const source = readFileSync(join(root, "src/js/entropylab-wasm-b64.js"), "utf8");
  const declared = source.match(/wasm sha256: ([0-9a-f]{64})/);
  assert.ok(declared, "module header carries the wasm sha256");
  const b64 = source.match(/export const ENTROPYLAB_WASM_B64 =\s*"([A-Za-z0-9+/=]+)";/);
  assert.ok(b64, "module exports the base64 payload");
  const actual = createHash("sha256").update(Buffer.from(b64[1], "base64")).digest("hex");
  assert.equal(actual, declared[1]);
});

test("committed WASM carries no build-host paths (remapped at build time)", () => {
  const source = readFileSync(join(root, "src/js/entropylab-wasm-b64.js"), "utf8");
  const payload = Buffer.from(source.match(/"([A-Za-z0-9+/=]+)"/)[1], "base64").toString("latin1");
  for (const banned of ["/home/", "/Users/", ".cargo/", ".rustup/"]) {
    assert.equal(payload.includes(banned), false, `build fingerprints the build host: ${banned}`);
  }
});

test("getPublicKey(1) is the generator point, compressed and uncompressed", () => {
  assert.equal(bytesToHex(secp256k1.getPublicKey(KEY1, true)), G_COMPRESSED);
  const uncompressed = secp256k1.getPublicKey(KEY1, false);
  assert.equal(uncompressed.length, 65);
  assert.equal(uncompressed[0], 4);
  assert.equal(bytesToHex(uncompressed.slice(1, 33)), G_COMPRESSED.slice(2));
});

test("getPublicKey rejects invalid private keys", () => {
  assert.throws(() => secp256k1.getPublicKey(new Uint8Array(32), true)); // zero
  assert.throws(() => secp256k1.getPublicKey(new Uint8Array(31), true)); // wrong length
});

test("sign is byte-identical to noble for plain RFC 6979 and extra entropy", () => {
  const cases = [
    { extraEntropy: false },
    { extraEntropy: new Uint8Array(32) }, // 32 zero bytes are mixed in
    { extraEntropy: (() => { const b = new Uint8Array(32); b[0] = 7; return b; })() }, // Core grind counter
  ];
  for (const options of cases) {
    const got = secp256k1.sign(MSG, KEY, { prehash: false, ...options });
    const want = noble.sign(MSG, KEY, { prehash: false, ...options });
    assert.equal(bytesToHex(got), bytesToHex(want));
    assert.equal(got.length, 64); // compact r || s, low-S
  }
});

test("sign refuses random extra entropy and unhashed messages", () => {
  assert.throws(() => secp256k1.sign(MSG, KEY, { prehash: false, extraEntropy: true }), /extraEntropy/);
  assert.throws(() => secp256k1.sign(new Uint8Array(5), KEY, {}), /prehash/);
  assert.throws(() => secp256k1.sign(MSG, new Uint8Array(32), { prehash: false }));
});

test("verify round-trips and rejects tampering", () => {
  const sig = secp256k1.sign(MSG, KEY, { prehash: false });
  const pubkey = secp256k1.getPublicKey(KEY, true);
  assert.equal(secp256k1.verify(sig, MSG, pubkey, { prehash: false }), true);
  const wrong = MSG.slice();
  wrong[0] ^= 1;
  assert.equal(secp256k1.verify(sig, wrong, pubkey, { prehash: false }), false);
});

test("verify high-S policy matches noble (lowS: false accepts via normalization)", () => {
  const sig = secp256k1.sign(MSG, KEY, { prehash: false });
  const pubkey = secp256k1.getPublicKey(KEY, true);
  const n = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
  const s = BigInt("0x" + bytesToHex(sig.slice(32)));
  const highS = n - s;
  const malleated = new Uint8Array([...sig.slice(0, 32), ...hexToBytes(highS.toString(16).padStart(64, "0"))]);
  const der = secp256k1.Signature.fromBytes(malleated).toBytes("der");
  assert.equal(secp256k1.verify(der, MSG, pubkey, { prehash: false, format: "der", lowS: false }), true);
  assert.equal(secp256k1.verify(der, MSG, pubkey, { prehash: false, format: "der", lowS: true }), false);
  // noble agrees on both policy settings.
  assert.equal(noble.verify(der, MSG, pubkey, { prehash: false, format: "der", lowS: false }), true);
  assert.equal(noble.verify(der, MSG, pubkey, { prehash: false, format: "der", lowS: true }), false);
});

test("verify never throws on malformed input", () => {
  const pubkey = secp256k1.getPublicKey(KEY, true);
  assert.equal(secp256k1.verify(new Uint8Array(3), MSG, pubkey, { prehash: false }), false);
  assert.equal(secp256k1.verify(new Uint8Array(64), MSG, pubkey, { prehash: false }), false);
  assert.equal(secp256k1.verify(secp256k1.sign(MSG, KEY, { prehash: false }), MSG, new Uint8Array(33), { prehash: false }), false);
});

test("Signature strict DER <-> compact round-trip, lax encodings rejected", () => {
  const sig = secp256k1.sign(MSG, KEY, { prehash: false });
  const der = secp256k1.Signature.fromBytes(sig).toBytes("der");
  const back = secp256k1.Signature.fromBytes(der, "der").toBytes("compact");
  assert.equal(bytesToHex(back), bytesToHex(sig));
  // agrees with noble's strict DER parser
  assert.equal(bytesToHex(noble.Signature.fromBytes(der, "der").toBytes("compact")), bytesToHex(sig));
  assert.throws(() => secp256k1.Signature.fromBytes(new Uint8Array([0x30, 0]), "der"));
  assert.throws(() => secp256k1.Signature.fromBytes(sig.slice(0, 63)));
});

test("Point: add and multiply match published constants and noble", () => {
  const G = secp256k1.Point.fromBytes(hexToBytes(G_COMPRESSED));
  const twoG = G.add(G);
  assert.equal(bytesToHex(twoG.toBytes(true)), TWO_G_COMPRESSED);
  assert.equal(bytesToHex(secp256k1.Point.BASE.multiply(2n).toBytes(true)), TWO_G_COMPRESSED);
  const fiveG = secp256k1.Point.BASE.multiply(2n).add(secp256k1.Point.BASE.multiply(3n));
  assert.equal(bytesToHex(fiveG.toBytes(true)), bytesToHex(noble.Point.BASE.multiply(5n).toBytes(true)));
  // uncompressed round-trip
  assert.equal(fiveG.toBytes(false).length, 65);
  assert.equal(bytesToHex(secp256k1.Point.fromBytes(fiveG.toBytes(false)).toBytes(true)), bytesToHex(fiveG.toBytes(true)));
});

test("Point rejects non-curve encodings", () => {
  const junk = new Uint8Array(33); // 0x00 prefix and zero x is not a point
  assert.throws(() => secp256k1.Point.fromBytes(junk));
  const badPrefix = hexToBytes(G_COMPRESSED);
  badPrefix[0] = 0x07;
  assert.throws(() => secp256k1.Point.fromBytes(badPrefix));
});

// ── Round 1 (kept): ECDSA public-key recovery ──────────────────────────────
// recover() backs the BOLT11 invoice decoder. The expected public key comes
// from noble, and the recovery id is derived from noble's own point math
// (R = (z/s)G + (r/s)P), never from the facade under test.
const RECOVER_PRIV = hexToBytes("e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35");
const RECOVER_MSG = hexToBytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
const CURVE_N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;

const modPow = (base, exp, mod) => {
  let result = 1n;
  let b = base % mod;
  for (let e = exp; e > 0n; e >>= 1n) {
    if (e & 1n) result = (result * b) % mod;
    b = (b * b) % mod;
  }
  return result;
};

const signWithRecovery = (msg = RECOVER_MSG) => {
  const compact = noble.sign(msg, RECOVER_PRIV, { prehash: false });
  const z = BigInt("0x" + bytesToHex(msg));
  const r = BigInt("0x" + bytesToHex(compact.slice(0, 32)));
  const s = BigInt("0x" + bytesToHex(compact.slice(32)));
  const sInv = modPow(s, CURVE_N - 2n, CURVE_N);
  const P = noble.Point.BASE.multiply(BigInt("0x" + bytesToHex(RECOVER_PRIV)));
  const R = noble.Point.BASE.multiply((z * sInv) % CURVE_N).add(P.multiply((r * sInv) % CURVE_N));
  const raw = R.toBytes(false);
  const x = BigInt("0x" + bytesToHex(raw.slice(1, 33)));
  const recid = (raw[64] & 1) | (x >= CURVE_N ? 2 : 0);
  return { msg, compact, recid, expected: bytesToHex(noble.getPublicKey(RECOVER_PRIV, true)) };
};

// Fixed, deterministic candidate messages (SHA-256 of a constant label; no
// randomness). The fixtures are the first candidate of each recovery-id
// parity, so both recid 0 and recid 1 are always exercised.
const recoverCandidate = (i) =>
  new Uint8Array(createHash("sha256").update(`entropylab recover fixture ${i}`).digest());

const recoverFixtures = () => {
  const fixtures = [];
  const seen = new Set();
  for (let i = 0; seen.size < 2 && i < 64; i++) {
    const fixture = signWithRecovery(recoverCandidate(i));
    if ((fixture.recid === 0 || fixture.recid === 1) && !seen.has(fixture.recid)) {
      seen.add(fixture.recid);
      fixtures.push(fixture);
    }
  }
  return fixtures;
};

test("recover returns the compressed key noble recovers for each parity", () => {
  const fixtures = recoverFixtures();
  const recids = new Set(fixtures.map((f) => f.recid));
  assert.ok(recids.has(0), "fixtures include recid 0");
  assert.ok(recids.has(1), "fixtures include recid 1");
  for (const { msg, compact, recid, expected } of fixtures) {
    const actual = secp256k1.recover(msg, compact, recid);
    assert.ok(actual instanceof Uint8Array);
    assert.equal(actual.length, 33);
    assert.equal(bytesToHex(actual), expected);
    // Flipping the parity bit must never recover the expected key.
    const flipped = secp256k1.recover(msg, compact, recid ^ 1);
    assert.ok(flipped === null || bytesToHex(flipped) !== expected, "flipped parity must not recover the expected key");
  }
});

test("recover refuses malformed input", () => {
  const { msg, compact, recid } = signWithRecovery();
  assert.equal(secp256k1.recover(msg, compact, 4), null);
  assert.equal(secp256k1.recover(msg, compact.slice(0, 63), recid), null);
  assert.equal(secp256k1.recover(msg.slice(0, 31), compact, recid), null);
  const zeroR = new Uint8Array(64);
  zeroR.set(compact.slice(32), 32);
  assert.equal(secp256k1.recover(msg, zeroR, recid), null);
});

// ── Round 2: BIP-340 Schnorr verification ──────────────────────────────────
// Official verification vectors from bip-0340/test-vectors.csv, indices 0-14,
// including every FALSE case: r = p (12), public key not on the curve (5) or
// x >= p (14), negated message (7), negated s (8), s = n (13), sG - eP at
// infinity (9, 10), and r not an X coordinate (11).
import { schnorr as nobleSchnorr } from "@noble/curves/secp256k1.js";

const BIP340_VECTORS = [
  {
    index: 0,
    pubkey: "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
    message: "0000000000000000000000000000000000000000000000000000000000000000",
    signature:
      "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0",
    valid: true,
  },
  {
    index: 1,
    pubkey: "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
    message: "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
    signature:
      "6896BD60EEAE296DB48A229FF71DFE071BDE413E6D43F917DC8DCF8C78DE33418906D11AC976ABCCB20B091292BFF4EA897EFCB639EA871CFA95F6DE339E4B0A",
    valid: true,
  },
  {
    index: 2,
    pubkey: "DD308AFEC5777E13121FA72B9CC1B7CC0139715309B086C960E18FD969774EB8",
    message: "7E2D58D8B3BCDF1ABADEC7829054F90DDA9805AAB56C77333024B9D0A508B75C",
    signature:
      "5831AAEED7B44BB74E5EAB94BA9D4294C49BCF2A60728D8B4C200F50DD313C1BAB745879A5AD954A72C45A91C3A51D3C7ADEA98D82F8481E0E1E03674A6F3FB7",
    valid: true,
  },
  {
    index: 3,
    pubkey: "25D1DFF95105F5253C4022F628A996AD3A0D95FBF21D468A1B33F8C160D8F517",
    message: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
    signature:
      "7EB0509757E246F19449885651611CB965ECC1A187DD51B64FDA1EDC9637D5EC97582B9CB13DB3933705B32BA982AF5AF25FD78881EBB32771FC5922EFC66EA3",
    valid: true,
  },
  {
    index: 4,
    pubkey: "D69C3509BB99E412E68B0FE8544E72837DFA30746D8BE2AA65975F29D22DC7B9",
    message: "4DF3C3F68FCC83B27E9D42C90431A72499F17875C81A599B566C9889B9696703",
    signature:
      "00000000000000000000003B78CE563F89A0ED9414F5AA28AD0D96D6795F9C6376AFB1548AF603B3EB45C9F8207DEE1060CB71C04E80F593060B07D28308D7F4",
    valid: true,
  },
  {
    index: 5,
    pubkey: "EEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34",
    message: "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
    signature:
      "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E17776969E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B",
    valid: false,
  },
  {
    index: 6,
    pubkey: "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
    message: "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
    signature:
      "FFF97BD5755EEEA420453A14355235D382F6472F8568A18B2F057A14602975563CC27944640AC607CD107AE10923D9EF7A73C643E166BE5EBEAFA34B1AC553E2",
    valid: false,
  },
  {
    index: 7,
    pubkey: "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
    message: "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
    signature:
      "1FA62E331EDBC21C394792D2AB1100A7B432B013DF3F6FF4F99FCB33E0E1515F28890B3EDB6E7189B630448B515CE4F8622A954CFE545735AAEA5134FCCDB2BD",
    valid: false,
  },
  {
    index: 8,
    pubkey: "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
    message: "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
    signature:
      "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E177769961764B3AA9B2FFCB6EF947B6887A226E8D7C93E00C5ED0C1834FF0D0C2E6DA6",
    valid: false,
  },
  {
    index: 9,
    pubkey: "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
    message: "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
    signature:
      "0000000000000000000000000000000000000000000000000000000000000000123DDA8328AF9C23A94C1FEECFD123BA4FB73476F0D594DCB65C6425BD186051",
    valid: false,
  },
  {
    index: 10,
    pubkey: "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
    message: "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
    signature:
      "00000000000000000000000000000000000000000000000000000000000000017615FBAF5AE28864013C099742DEADB4DBA87F11AC6754F93780D5A1837CF197",
    valid: false,
  },
  {
    index: 11,
    pubkey: "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
    message: "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
    signature:
      "4A298DACAE57395A15D0795DDBFD1DCB564DA82B0F269BC70A74F8220429BA1D69E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B",
    valid: false,
  },
  {
    index: 12,
    pubkey: "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
    message: "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
    signature:
      "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F69E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B",
    valid: false,
  },
  {
    index: 13,
    pubkey: "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
    message: "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
    signature:
      "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E177769FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
    valid: false,
  },
  {
    index: 14,
    pubkey: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC30",
    message: "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
    signature:
      "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E17776969E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B",
    valid: false,
  },
];

test("schnorr.verify matches the official BIP-340 vectors 0-14", () => {
  for (const vector of BIP340_VECTORS) {
    assert.equal(
      secp256k1.schnorr.verify(hexToBytes(vector.signature), hexToBytes(vector.message), hexToBytes(vector.pubkey)),
      vector.valid,
      `BIP-340 vector ${vector.index}`
    );
  }
});

test("schnorr.verify never throws on malformed input", () => {
  const { signature, message, pubkey } = BIP340_VECTORS[0];
  const sig = hexToBytes(signature);
  const msg = hexToBytes(message);
  const pub = hexToBytes(pubkey);
  assert.equal(secp256k1.schnorr.verify(sig.slice(0, 63), msg, pub), false);
  assert.equal(secp256k1.schnorr.verify(sig, msg.slice(0, 31), pub), false);
  assert.equal(secp256k1.schnorr.verify(sig, msg, pub.slice(0, 31)), false);
  assert.equal(secp256k1.schnorr.verify(new Uint8Array(64), msg, pub), false);
  assert.equal(secp256k1.schnorr.verify(sig, msg, new Uint8Array(32).fill(0xff)), false); // x >= p
  assert.equal(secp256k1.schnorr.verify("not bytes", msg, pub), false);
});

test("schnorr.verify agrees with noble on noble-produced signatures", () => {
  const priv = hexToBytes("e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35");
  const pub = nobleSchnorr.getPublicKey(priv);
  assert.equal(pub.length, 32);
  // The facade's compressed key carries the same x coordinate.
  assert.equal(bytesToHex(secp256k1.getPublicKey(priv, true).slice(1)), bytesToHex(pub));
  for (const message of [MSG, new Uint8Array(32), new Uint8Array(32).fill(0xff)]) {
    const sig = nobleSchnorr.sign(message, priv, new Uint8Array(32));
    assert.equal(nobleSchnorr.verify(sig, message, pub), true);
    assert.equal(secp256k1.schnorr.verify(sig, message, pub), true);
    const tampered = message.slice();
    tampered[0] ^= 1;
    assert.equal(secp256k1.schnorr.verify(sig, tampered, pub), false);
  }
});
