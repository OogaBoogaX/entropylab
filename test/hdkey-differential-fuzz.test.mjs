// Differential fuzz of BIP32 derivation: src/js/hdkey.js (the app's HDKey,
// rust-bitcoin's bip32 compiled to WASM) against @scure/bip32 (pinned, an
// independent implementation). Same seed, same path, same version bytes —
// every node must be byte-identical on both sides, and any disagreement fails
// the run. Published BIP32 vectors stay in hdkey-bip39-wasm.test.mjs; this
// suite sweeps seeds and paths those vectors never reach.
//
// Offline and deterministic: the PRNG below exists only in this file, the
// seed is fixed, and it is never reseeded from the clock, so a red run
// reproduces byte-for-byte. The iteration number, seed, and path are in every
// failure message.
//
// Run with `node --test test/hdkey-differential-fuzz.test.mjs` or `npm test`.
// HDKEY_FUZZ_ITERATIONS=5000 and HDKEY_PUB_FUZZ_ITERATIONS=5000 widen a local
// run; CI runs the defaults.
import { test } from "node:test";
import assert from "node:assert/strict";
import { HDKey as ScureHDKey } from "@scure/bip32";
import { HDKey, HARDENED_OFFSET } from "../src/js/hdkey.js";
import { fuzzEnv, mulberry32, replayLine, withReplay } from "./fuzz-kit.mjs";

// --- deterministic randomness ------------------------------------------------

const FUZZ_SEED = 0x5eed0032;
const DEFAULT_ITERATIONS = 200;
const HDKEY_ENV = fuzzEnv("HDKEY_FUZZ", { defaultSeed: FUZZ_SEED, defaultIterations: DEFAULT_ITERATIONS });
const ITERATIONS = HDKEY_ENV.iterations;
const MASTER_TEST_NAME = "src/js/hdkey.js and @scure/bip32 derive identical nodes";

// Mainnet BIP32 version bytes, passed explicitly to both implementations.
const VERSIONS = { private: 0x0488ade4, public: 0x0488b21e };

const hex = (bytes) => Buffer.from(bytes).toString("hex");
const view = (node) => ({
  publicKey: hex(node.publicKey),
  chainCode: hex(node.chainCode),
  depth: node.depth,
  index: node.index,
  parentFingerprint: node.parentFingerprint,
  xpub: node.publicExtendedKey,
  xprv: node.privateExtendedKey,
});

// Field by field, so a failure names the field, the case, and both values.
const assertSameNode = (left, right, where) => {
  const a = view(left), b = view(right);
  for (const field of Object.keys(a)) {
    assert.equal(a[field], b[field], `${where}: ${field} differs\n  src/js/hdkey.js: ${a[field]}\n  @scure/bip32:    ${b[field]}`);
  }
};

// Runs the same operation on both sides. Every input here is valid, so a
// throw on either side is a disagreement too, reported with the other
// side's result.
const both = (where, leftFn, rightFn) => {
  const run = (fn) => {
    try {
      return { node: fn() };
    } catch (error) {
      return { error };
    }
  };
  const l = run(leftFn), r = run(rightFn);
  if (l.error || r.error) {
    const show = (side) => (side.error ? `threw ${side.error.message}` : JSON.stringify(view(side.node)));
    assert.fail(`${where}: only ${l.error && r.error ? "neither" : l.error ? "@scure/bip32" : "src/js/hdkey.js"} succeeded\n  src/js/hdkey.js: ${show(l)}\n  @scure/bip32:    ${show(r)}`);
  }
  assertSameNode(l.node, r.node, where);
  return [l.node, r.node];
};

test(MASTER_TEST_NAME, () => {
  assert.ok(Number.isSafeInteger(ITERATIONS) && ITERATIONS > 0, `HDKEY_FUZZ_ITERATIONS must be a positive integer, got ${process.env.HDKEY_FUZZ_ITERATIONS}`);
  try {
    const rand = mulberry32(HDKEY_ENV.seed);
    const rint = (n) => Math.floor(rand() * n);
    const pick = (items) => items[rint(items.length)];
    const randomBytes = (n) => Uint8Array.from({ length: n }, () => rint(256));
    const randomIndex = () => (rint(8) === 0 ? pick([0, 1, HARDENED_OFFSET - 1]) : rint(HARDENED_OFFSET));
    for (let i = 0; i < ITERATIONS; i++) {
      const seed = randomBytes(pick([16, 32, 64]));
      const steps = Array.from({ length: 1 + rint(8) }, () => ({ index: randomIndex(), hardened: rint(2) === 1 }));
      const path = "m/" + steps.map(({ index, hardened }) => `${index}${hardened ? "'" : ""}`).join("/");
      const where = `iteration ${i}, seed ${hex(seed)}, path ${path}`;

      const [left, right] = both(`${where}, master`, () => HDKey.fromMasterSeed(seed, VERSIONS), () => ScureHDKey.fromMasterSeed(seed, VERSIONS));

      // Step by step, so a disagreement names the first node where it appears.
      let l = left, r = right;
      steps.forEach(({ index, hardened }, depth) => {
        const child = index + (hardened ? HARDENED_OFFSET : 0);
        [l, r] = both(`${where}, step ${depth + 1} (child ${child})`, () => l.deriveChild(child), () => r.deriveChild(child));
      });

      // The whole path through each side's own path parser lands on the same node.
      const [leftChild, rightChild] = both(`${where}, derive(path)`, () => left.derive(path), () => right.derive(path));
      assertSameNode(leftChild, r, `${where}, derive(path) against the stepwise walk`);

      // The xprv round-trips through fromExtendedKey to the same child.
      const [leftRestored] = both(`${where}, fromExtendedKey(xprv)`,
        () => HDKey.fromExtendedKey(leftChild.privateExtendedKey, VERSIONS),
        () => ScureHDKey.fromExtendedKey(rightChild.privateExtendedKey, VERSIONS));
      assertSameNode(leftRestored, rightChild, `${where}, fromExtendedKey(xprv) against the derived child`);
    }
  } catch (error) {
    throw withReplay(error, replayLine("HDKEY_FUZZ", HDKEY_ENV.seed, ITERATIONS, MASTER_TEST_NAME, "test/hdkey-differential-fuzz.test.mjs"));
  }
});

// BIP32's two derivation functions, fuzzed against each other. CKDpriv takes
// any mix of hardened and unhardened steps: holding the private key, a path
// may move between them freely. CKDpub takes unhardened steps only, and must
// land on the same key the private walk reaches; a hardened step from a
// public-only node must be refused by both implementations, never computed.
// A second fixed seed keeps the corpus above unchanged.
const PUBLIC_FUZZ_SEED = 0x5eed0033;
const PUBLIC_ENV = fuzzEnv("HDKEY_PUB_FUZZ", { defaultSeed: PUBLIC_FUZZ_SEED, defaultIterations: DEFAULT_ITERATIONS });
const PUBLIC_ITERATIONS = PUBLIC_ENV.iterations;
const PUBLIC_TEST_NAME = "public derivation matches private derivation and refuses hardened steps";
test(PUBLIC_TEST_NAME, () => {
  const refused = (fn) => {
    try {
      fn();
    } catch {
      return true;
    }
    return false;
  };
  let hardenedRefusals = 0, publicSteps = 0;
  try {
    const prng = mulberry32(PUBLIC_ENV.seed), n = (limit) => Math.floor(prng() * limit);
    const index = () => (n(8) === 0 ? [0, 1, HARDENED_OFFSET - 1][n(3)] : n(HARDENED_OFFSET));
    for (let i = 0; i < PUBLIC_ITERATIONS; i++) {
      const seed = Uint8Array.from({ length: 32 }, () => n(256));
      const steps = Array.from({ length: 1 + n(10) }, () => index() + (n(2) ? HARDENED_OFFSET : 0));
      const where = `iteration ${i}, seed ${hex(seed)}, children ${steps.join("/")}`;
      let privateNode = HDKey.fromMasterSeed(seed, VERSIONS), scurePrivate = ScureHDKey.fromMasterSeed(seed, VERSIONS);
      steps.forEach((child, depth) => {
        // Public-only views of the current node, rebuilt from its xpub.
        const publicNode = HDKey.fromExtendedKey(privateNode.publicExtendedKey, VERSIONS), scurePublic = ScureHDKey.fromExtendedKey(scurePrivate.publicExtendedKey, VERSIONS);
        assert.equal(publicNode.privateKey, null, `${where}: an xpub produced a private key`);
        const nextPrivate = privateNode.deriveChild(child), nextScure = scurePrivate.deriveChild(child);
        assertSameNode(nextPrivate, nextScure, `${where}, private step ${depth + 1}`);
        if (child >= HARDENED_OFFSET) {
          assert.ok(refused(() => publicNode.deriveChild(child)), `${where}, step ${depth + 1}: src/js/hdkey.js derived a hardened child from an xpub`);
          assert.ok(refused(() => scurePublic.deriveChild(child)), `${where}, step ${depth + 1}: @scure/bip32 derived a hardened child from an xpub`);
          hardenedRefusals++;
        } else {
          const publicChild = publicNode.deriveChild(child), scurePublicChild = scurePublic.deriveChild(child);
          for (const [label, node] of [["src/js/hdkey.js", publicChild], ["@scure/bip32", scurePublicChild]]) {
            assert.equal(node.privateKey, null, `${where}, step ${depth + 1}: ${label} public derivation produced a private key`);
            assert.equal(node.publicExtendedKey, nextScure.publicExtendedKey, `${where}, step ${depth + 1}: ${label} CKDpub differs from CKDpriv`);
          }
          publicSteps++;
        }
        privateNode = nextPrivate;
        scurePrivate = nextScure;
      });
    }
    // Both branches must actually have been exercised.
    assert.ok(hardenedRefusals > PUBLIC_ITERATIONS && publicSteps > PUBLIC_ITERATIONS, `corpus too narrow: ${hardenedRefusals} hardened, ${publicSteps} unhardened steps`);
  } catch (error) {
    throw withReplay(error, replayLine("HDKEY_PUB_FUZZ", PUBLIC_ENV.seed, PUBLIC_ITERATIONS, PUBLIC_TEST_NAME, "test/hdkey-differential-fuzz.test.mjs"));
  }
});
