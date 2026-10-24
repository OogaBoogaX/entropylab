// MS Station co-signer path edits.
//
// Contract: a co-signer's extended public key is replaced on a path edit only
// when a loaded session root reproduces that exact key (public key and chain
// code) at the row's previous origin; the replacement is the root's key at the
// new origin, hardened steps included. A key no session root reproduces is
// never replaced. Re-derivation itself follows any path, hardened or not and
// at any depth; whether the result is accepted is the card's spec's call.
//
// A spec card holds its co-signer to that spec exactly: the spec's depth and
// the policy's hardening (every published spec hardens each of its steps).
// A co-signer that departs from it — m/0h, an unhardened account, a key
// deeper than the spec's path such as an exported receive-branch xpub — is
// refused unless the user chooses the Custom spec, which accepts it with the
// restore-needs-the-descriptor warning (browser suite).
// hodlMsigCustomPathReason names the departure as display text (never a note
// object, which rendered as "[object Object]") and is empty for a standard
// path; which paths depart is pinned by the tests above.
//
// The reference for every derived key is @scure/bip32 (BIP32), independent of
// the app's own derivation.
// Run with: npm test
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { HDKey } from "@scure/bip32";
import { HDKey as AppHDKey } from "../src/js/hdkey.js";
import { mnemonicToSeedSync } from "@scure/bip39";
import { createBase58check } from "@scure/base";
import { sha256 } from "@noble/hashes/sha2.js";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const app = readFileSync(join(root, "src/js/app.js"), "utf8");

function loadFunction(name) {
  const start = app.indexOf(`function ${name}(`);
  assert.ok(start >= 0, `missing ${name}`);
  let depth = 0;
  // The body opens at ") {": a default parameter may itself hold braces.
  for (let i = app.indexOf(") {", start) + 2; i < app.length; i++) {
    if (app[i] === "{") depth++;
    else if (app[i] === "}" && --depth === 0) return app.slice(start, i + 1);
  }
  throw new Error(`unterminated ${name}`);
}
const load = (name, deps = {}) => new Function(...Object.keys(deps), `${loadFunction(name)}; return ${name};`)(...Object.values(deps));

const codec = createBase58check(sha256);
const hodlBase58Check = { decode: codec.decode, encode: codec.encode };
const hodlExtendedKeyVersions = {
  mainnet: { x: { pub: 0x0488b21e, prv: 0x0488ade4 } },
  testnet: { x: { pub: 0x043587cf, prv: 0x04358394 } },
};
const hodlNote = (key, vars) => (vars == null ? { key } : { key, vars });
const hodlError = (key) => new Error(key);
const hodlEq = load("hodlEq");
const hodlNetworkFamily = load("hodlNetworkFamily");
const hodlReversionExtendedKey = load("hodlReversionExtendedKey", { hodlBase58Check });
const hodlSerializeExtendedKey = load("hodlSerializeExtendedKey", { hodlReversionExtendedKey, hodlExtendedKeyVersions, hodlNetworkFamily });
const hodlNormalizeOriginPath = load("hodlNormalizeOriginPath");
const hodlMultisigScriptLabel = load("hodlMultisigScriptLabel", { hodlT: (key) => key });
const hodlOriginScriptError = load("hodlOriginScriptError", { hodlNormalizeOriginPath, hodlNote, hodlMultisigScriptLabel });
const hodlPathComponent = load("hodlPathComponent");
const hodlMultisigAccountKeyError = load("hodlMultisigAccountKeyError", { hodlNote, hodlPathComponent });
const hodlMultisigAccountNumber = load("hodlMultisigAccountNumber", { hodlNormalizeOriginPath, hodlError });
const hodlMsigOriginHardening = load("hodlMsigOriginHardening", { hodlNormalizeOriginPath });
const hodlTText = (key, vars) => key.replace(/\{(\w+)\}/g, (_, name) => String(vars?.[name]));
const hodlFormatNote = load("hodlFormatNote", { hodlTText });
const hodlMsigCustomPathReason = load("hodlMsigCustomPathReason", { hodlFormatNote, hodlMsigOriginHardening, hodlMultisigAccountKeyError, hodlOriginScriptError });
const hodlMsigRederivedKey = load("hodlMsigRederivedKey", { hodlEq, hodlSerializeExtendedKey });

// BIP39 "abandon" x11 + "about"; master fingerprint 73c5da0a.
const seed = mnemonicToSeedSync("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about");
const otherSeed = mnemonicToSeedSync("zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong");
const reference = (path, s = seed) => HDKey.fromMasterSeed(s).derive(path);
const STANDARD = { purpose: true, coinType: true, account: true, script: true, branch: false, address: false };

test("a session root re-derives the co-signer key at an edited origin, hardened or not", () => {
  const current = reference("m/48'/0'/0'/2'");
  for (const next of ["m/48'/0'/1'/2'", "m/48'/0'/0/2'", "m/48/0/7/2'", "m/48'/0'/0'/2'/1", "m/48'/0'/0'/2'/1'/9"]) {
    assert.equal(hodlMsigRederivedKey(HDKey.fromMasterSeed(seed), current, "m/48'/0'/0'/2'", next, "mainnet"), reference(next).publicExtendedKey, next);
  }
  const testnetCurrent = reference("m/87'/1'/0'");
  const tpub = hodlMsigRederivedKey(HDKey.fromMasterSeed(seed), testnetCurrent, "m/87'/1'/0'", "m/87'/1'/3", "testnet");
  assert.match(tpub, /^tpub/);
  assert.equal(HDKey.fromExtendedKey(tpub, { private: 0x04358394, public: 0x043587cf }).publicKey.toString(), reference("m/87'/1'/3").publicKey.toString());
});

test("a key the session root does not reproduce at the previous origin is never replaced", () => {
  const sessionRoot = () => HDKey.fromMasterSeed(seed);
  // A key from another seed.
  assert.equal(hodlMsigRederivedKey(sessionRoot(), reference("m/48'/0'/0'/2'", otherSeed), "m/48'/0'/0'/2'", "m/48'/0'/1'/2'", "mainnet"), "");
  // This seed's key, but claimed at a different origin than the one that made it.
  assert.equal(hodlMsigRederivedKey(sessionRoot(), reference("m/48'/0'/0'/2'"), "m/48'/0'/0'/1'", "m/48'/0'/1'/2'", "mainnet"), "");
  // The right public key with a foreign chain code.
  const real = reference("m/48'/0'/0'/2'"), forged = new HDKey({ publicKey: real.publicKey, chainCode: reference("m/48'/0'/1'/2'").chainCode });
  assert.equal(hodlMsigRederivedKey(sessionRoot(), forged, "m/48'/0'/0'/2'", "m/48'/0'/1'/2'", "mainnet"), "");
});

test("a spec card holds each step to the policy hardening, not the key's own", () => {
  const reason = (path, kind, purpose) => {
    const key = HDKey.fromMasterSeed(seed).derive("m/" + path.replace(/h/g, "'"));
    return hodlMsigCustomPathReason({ depth: key.depth, childNumber: key.index, origin: { fingerprint: "73c5da0a", path } }, kind, "mainnet", purpose, 0, STANDARD);
  };
  // Unhardened purpose, coin type or account steps are not BIP48/87/45.
  for (const [path, kind, purpose] of [["48/0h/0h/2h", "p2wsh", 48], ["48h/0/0h/1h", "p2sh-p2wsh", 48], ["48h/0h/5/2h", "p2wsh", 48], ["87h/0h/3", "p2tr", 87], ["45", "p2sh", 45]]) {
    const text = reason(path, kind, purpose);
    assert.ok(text && !text.includes("[object"), `${path} was accepted on its spec card: ${text}`);
  }
  // The account number still reads each origin's own hardening (Custom cards).
  assert.equal(hodlMultisigAccountNumber({ path: "48h/0h/5/2h" }, "p2wsh", 48, hodlMsigOriginHardening({ path: "48h/0h/5/2h" }, STANDARD).account), 5);
});

test("per-row hardening still refuses wrong indexes and a non-standard script step", () => {
  const refuse = (path, kind, purpose, coinType = 0) => {
    const origin = { fingerprint: "73c5da0a", path };
    assert.notEqual(hodlOriginScriptError(origin, kind, "mainnet", purpose, coinType, hodlMsigOriginHardening(origin, STANDARD)), "", path);
  };
  refuse("48h/0h/0h/2", "p2wsh", 48); // BIP48 script type is always hardened
  refuse("48h/0h/0h/1h", "p2wsh", 48); // wrong script type
  refuse("49h/0h/0h/2h", "p2wsh", 48); // wrong purpose
  refuse("48/1h/0h/2h", "p2wsh", 48); // wrong coin type
  refuse("46", "p2sh", 45);
  // The BIP48 script-account key must still end at the hardened script child.
  const unhardenedScript = HDKey.fromMasterSeed(seed).derive("m/48'/0'/0'/2");
  const origin = { path: "48h/0h/0h/2" };
  assert.notEqual(hodlMultisigAccountKeyError({ depth: unhardenedScript.depth, childNumber: unhardenedScript.index }, "p2wsh", 48, hodlMsigOriginHardening(origin, STANDARD)), "");
});

test("a spec card holds the spec's key itself, never one above or below it", () => {
  const check = (path, kind, purpose) => {
    const origin = { fingerprint: "73c5da0a", path }, hardening = hodlMsigOriginHardening(origin, STANDARD);
    const key = HDKey.fromMasterSeed(seed).derive("m/" + path.replace(/h/g, "'"));
    return [hodlMultisigAccountKeyError({ depth: key.depth, childNumber: key.index }, kind, purpose, hardening), hodlOriginScriptError(origin, kind, "mainnet", purpose, 0, hardening)];
  };
  for (const [path, kind, purpose] of [
    ["48h/0h/0h/2h", "p2wsh", 48],
    ["48h/0h/0h/1h", "p2sh-p2wsh", 48],
    ["87h/0h/0h", "p2tr", 87],
    ["45h", "p2sh", 45],
    // The singlesig BIPs double as co-signer specs at their account key.
    ["44h/0h/0h", "p2sh", 44],
    ["49h/0h/0h", "p2sh-p2wsh", 49],
    ["84h/0h/0h", "p2wsh", 84],
  ]) assert.deepEqual(check(path, kind, purpose), ["", ""], path);
  for (const [path, kind, purpose] of [
    // Below the spec's key: an exported receive-branch xpub, or any extra step.
    ["48h/0h/0h/2h/0", "p2wsh", 48],
    ["48h/0h/0h/2h/1h/7", "p2wsh", 48],
    ["48h/0h/0h/1h/3h", "p2sh-p2wsh", 48],
    ["87h/0h/0h/0", "p2tr", 87],
    ["87h/0h/0h/2", "p2sh", 87],
    ["45h/0", "p2sh", 45],
    ["48h/0h/0h", "p2wsh", 48], // no script step
    ["48h/0h/0h/1h/1", "p2wsh", 48], // wrong script step under the extra one
    ["48h/0h/0h/2/1", "p2wsh", 48], // unhardened script step under the extra one
    ["48h/1h/0h/2h/1", "p2wsh", 48], // wrong coin type under the extra one
    ["87h/0h", "p2tr", 87], // no account
    ["46h/0", "p2sh", 45], // wrong purpose under the extra one
    // A BIP44/49/84 card holds the depth-3 account key only: the depth-4
    // BIP48-shaped key at the card's own purpose is not that spec's key.
    ["44h/0h/0h/2h", "p2sh", 44],
    ["49h/0h/0h/1h", "p2sh-p2wsh", 49],
    ["84h/0h/0h/2h", "p2wsh", 84],
  ]) assert.notDeepEqual(check(path, kind, purpose), ["", ""], path);
});

test("a non-standard co-signer path is named as custom in display text, a standard one is not", () => {
  const reason = (path, kind, purpose, coinType = 0) => {
    const key = HDKey.fromMasterSeed(seed).derive("m/" + path.replace(/h/g, "'"));
    return hodlMsigCustomPathReason({ depth: key.depth, childNumber: key.index, origin: { fingerprint: "73c5da0a", path } }, kind, "mainnet", purpose, coinType, STANDARD);
  };
  for (const [path, kind, purpose] of [
    ["48h/0h/0h/2h", "p2wsh", 48],
    ["48h/0h/1h/1h", "p2sh-p2wsh", 48],
    ["87h/0h/0h", "p2tr", 87],
    ["45h", "p2sh", 45],
  ]) assert.equal(reason(path, kind, purpose), "", path);
  for (const [path, kind, purpose] of [
    ["0h", "p2wsh", 0], // a single custom step, as in m/0'
    ["48h/0h/1", "p2wsh", 48], // the account edited without its script step
    ["48h/0h/0h/1h", "p2wsh", 48], // another script type's step
    ["48h/0h/0h/2", "p2wsh", 48], // unhardened script step
    ["48h/0h/0h/2h/1", "p2wsh", 48], // below the script-account key
    ["87h/0h", "p2tr", 87], // stops short of the account
    ["46h", "p2sh", 46],
  ]) {
    const text = reason(path, kind, purpose);
    assert.equal(typeof text, "string", path);
    assert.ok(text && !text.includes("[object"), `${path}: ${text}`);
  }
});

// --- seeded fuzzing ----------------------------------------------------------
//
// Random origins mixing hardened and unhardened steps in any order, e.g.
// m/48'/0/0'/0'. Holding the seed, BIP32 derives any such path, so the
// re-derived key must equal @scure/bip32's key at the new origin, with the
// app's own HDKey (src/js/hdkey.js) as the session root. It must equal
// nothing at all when the row's key is not the root's key at the claimed
// previous origin: another seed, one step's hardening flipped, one index
// moved, or the right public key under a foreign chain code. The validators
// meanwhile answer every origin with display text, never a note object or a
// throw. Fixed seed, never reseeded; MSIG_FUZZ_ITERATIONS widens a local run.
const FUZZ_SEED = 0x5eed0048;
const FUZZ_ITERATIONS = process.env.MSIG_FUZZ_ITERATIONS === undefined ? 200 : Number(process.env.MSIG_FUZZ_ITERATIONS);
const fuzzRandom = (() => {
  let a = FUZZ_SEED >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
})();
const fuzzInt = (limit) => Math.floor(fuzzRandom() * limit);
const fuzzSteps = (max) => Array.from({ length: 1 + fuzzInt(max) }, () => ({ index: fuzzInt(8) === 0 ? [0, 1, 2147483647][fuzzInt(3)] : fuzzInt(100), hardened: fuzzInt(2) === 1 }));
const pathOf = (steps) => "m/" + steps.map(({ index, hardened }) => `${index}${hardened ? "'" : ""}`).join("/");

test(`fuzz: re-derivation follows any hardened/unhardened mix and never replaces a key the root did not make (seed 0x${FUZZ_SEED.toString(16)}, ${FUZZ_ITERATIONS} iterations)`, () => {
  assert.ok(Number.isSafeInteger(FUZZ_ITERATIONS) && FUZZ_ITERATIONS > 0, `MSIG_FUZZ_ITERATIONS must be a positive integer, got ${process.env.MSIG_FUZZ_ITERATIONS}`);
  let mixed = 0;
  for (let i = 0; i < FUZZ_ITERATIONS; i++) {
    const fuzzSeed = Uint8Array.from({ length: 32 }, () => fuzzInt(256));
    const previous = fuzzSteps(6), next = fuzzSteps(6), previousPath = pathOf(previous), nextPath = pathOf(next);
    const where = `iteration ${i}, seed ${Buffer.from(fuzzSeed).toString("hex")}, ${previousPath} -> ${nextPath}`;
    const sessionRoot = () => AppHDKey.fromMasterSeed(fuzzSeed);
    const key = reference(previousPath, fuzzSeed);
    if (next.some((step, index) => step.hardened && next.slice(0, index).some((earlier) => !earlier.hardened))) mixed++;

    // Holding the seed, any mix of hardened and unhardened steps derives.
    assert.equal(hodlMsigRederivedKey(sessionRoot(), key, previousPath, nextPath, "mainnet"), reference(nextPath, fuzzSeed).publicExtendedKey, where);

    // A key the root does not reproduce at the claimed origin stays put.
    const flip = fuzzInt(previous.length), shift = fuzzInt(previous.length);
    const flipped = pathOf(previous.map((step, index) => (index === flip ? { ...step, hardened: !step.hardened } : step)));
    const shifted = pathOf(previous.map((step, index) => (index === shift ? { ...step, index: step.index === 2147483647 ? step.index - 1 : step.index + 1 } : step)));
    const foreignChain = new HDKey({ publicKey: key.publicKey, chainCode: reference(nextPath, fuzzSeed).chainCode });
    for (const [label, candidate, claimed] of [
      ["another seed's key", reference(previousPath, otherSeed), previousPath],
      [`claimed at ${flipped} (hardening flipped)`, key, flipped],
      [`claimed at ${shifted} (index moved)`, key, shifted],
      ["a foreign chain code", foreignChain, previousPath],
    ]) {
      if (claimed === previousPath && label === "a foreign chain code" && Buffer.compare(Buffer.from(key.chainCode), Buffer.from(foreignChain.chainCode)) === 0) continue;
      assert.equal(hodlMsigRederivedKey(sessionRoot(), candidate, claimed, nextPath, "mainnet"), "", `${where}: replaced ${label}`);
    }

    // Every origin gets display text from the validators, whatever its shape.
    const origin = { fingerprint: "73c5da0a", path: nextPath.slice(2).replace(/'/g, "h") }, derived = reference(nextPath, fuzzSeed);
    for (const kind of ["p2sh", "p2sh-p2wsh", "p2wsh", "p2tr"]) {
      for (const purpose of [next[0].index, 45, 48, 87]) {
        const text = hodlMsigCustomPathReason({ depth: derived.depth, childNumber: derived.index, origin }, kind, "mainnet", purpose, 0, STANDARD);
        assert.equal(typeof text, "string", `${where}: ${kind}/${purpose} returned ${typeof text}`);
        assert.ok(!text.includes("[object"), `${where}: ${kind}/${purpose} rendered ${text}`);
      }
    }
  }
  // The corpus must reach the case in question: a hardened step after an unhardened one.
  assert.ok(mixed > FUZZ_ITERATIONS / 10, `corpus too narrow: ${mixed} unhardened-then-hardened paths`);
});
