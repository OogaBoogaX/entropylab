import test from "node:test";
import assert from "node:assert/strict";
import { mnemonicToSeedSync } from "../src/js/bip39.js";
import { HDKey } from "../src/js/hdkey.js";
import { base58checkDecode, base58checkEncode } from "../src/js/base58.js";
import { descriptorChecksum } from "../src/js/core-importdescriptors.js";
import { checkDescriptorKeyReuse } from "../src/js/descriptor-reuse.js";

// BIP-39 test vector: the "abandon … about" mnemonic.
const MNEMONIC = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const master = HDKey.fromMasterSeed(mnemonicToSeedSync(MNEMONIC));
const X = master.derive("m/84'/0'/0'").publicExtendedKey;
const Y = master.derive("m/84'/0'/1'").publicExtendedKey;

const NUMS = "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0";

const hex = (bytes) => Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");

function withVersion(key, version) {
  const raw = base58checkDecode(key);
  const next = new Uint8Array(raw);
  next[0] = version >>> 24 & 255;
  next[1] = version >>> 16 & 255;
  next[2] = version >>> 8 & 255;
  next[3] = version & 255;
  return base58checkEncode(next);
}

function assertCode(fn, code) {
  let message = null;
  try {
    fn();
  } catch (error) {
    message = error.message;
  }
  assert.ok(message !== null, `expected a refusal with ${code}:`);
  assert.ok(message.startsWith(`${code}:`), `expected ${code}:, got ${message}`);
}

test("wpkh(X/<0;1>/*) expands to two branches with no reuse", () => {
  const result = checkDescriptorKeyReuse(`wpkh(${X}/<0;1>/*)`);
  assert.equal(result.branches, 2);
  assert.equal(result.indexes, 20);
  assert.equal(result.keys, 1);
  assert.equal(result.collisionCount, 0);
  assert.deepEqual(result.collisions, []);
});

test("wpkh(X/<0;0>/*) reports the same key in both branches", () => {
  const result = checkDescriptorKeyReuse(`wpkh(${X}/<0;0>/*)`);
  assert.equal(result.branches, 2);
  assert.equal(result.keys, 1);
  assert.equal(result.collisionCount, 20);
  assert.equal(result.collisions.length, 20);
  for (const collision of result.collisions) {
    assert.equal(collision.first.branch, 0);
    assert.equal(collision.second.branch, 1);
    assert.equal(collision.first.slot, 0);
    assert.equal(collision.second.slot, 0);
    assert.equal(collision.first.index, collision.second.index);
  }
});

test("wsh(multi(2,X/<0;1>/*,X/<1;2>/*)) reports cross-branch reuse a branch-0-only check misses", () => {
  const result = checkDescriptorKeyReuse(`wsh(multi(2,${X}/<0;1>/*,${X}/<1;2>/*))`);
  assert.equal(result.branches, 2);
  assert.equal(result.keys, 2);
  assert.equal(result.collisionCount, 20);
  // Branch 0 alone derives X/0/i (slot 0) and X/1/i (slot 1): all distinct,
  // so a Core check that only looks at branch 0 sees nothing wrong.
  const account = HDKey.fromExtendedKey(X);
  const branch0 = new Set();
  for (let i = 0; i < 20; i += 1) {
    branch0.add(hex(account.derive(`m/0/${i}`).publicKey));
    branch0.add(hex(account.derive(`m/1/${i}`).publicKey));
  }
  assert.equal(branch0.size, 40);
  // The reuse is X/1/i: branch 1 slot 0 against branch 0 slot 1.
  for (const collision of result.collisions) {
    assert.equal(collision.first.branch, 0);
    assert.equal(collision.first.slot, 1);
    assert.equal(collision.second.branch, 1);
    assert.equal(collision.second.slot, 0);
  }
});

test("wsh(sortedmulti(2,X/<0;1>/*,Y/<0;1>/*)) has no reuse", () => {
  const result = checkDescriptorKeyReuse(`wsh(sortedmulti(2,${X}/<0;1>/*,${Y}/<0;1>/*))`);
  assert.equal(result.branches, 2);
  assert.equal(result.keys, 2);
  assert.equal(result.collisionCount, 0);
});

test("wsh(multi(2,X/0/*,X/0/*)) reports the same key twice at every index", () => {
  const result = checkDescriptorKeyReuse(`wsh(multi(2,${X}/0/*,${X}/0/*))`);
  assert.equal(result.branches, 1);
  assert.equal(result.keys, 2);
  assert.equal(result.collisionCount, 20);
  for (const collision of result.collisions) {
    assert.equal(collision.first.slot, 0);
    assert.equal(collision.second.slot, 1);
    assert.equal(collision.first.index, collision.second.index);
  }
});

test("tr(NUMS,sortedmulti_a(2,X/<0;1>/*,Y/<0;1>/*)) has no reuse", () => {
  const result = checkDescriptorKeyReuse(`tr(${NUMS},sortedmulti_a(2,${X}/<0;1>/*,${Y}/<0;1>/*))`);
  assert.equal(result.branches, 2);
  assert.equal(result.keys, 2);
  assert.equal(result.collisionCount, 0);
});

test("SLIP-132 spellings behave exactly like the xpub", () => {
  const ypub = withVersion(X, 0x049d7cb2);
  const zpub = withVersion(X, 0x04b24746);
  const expected = checkDescriptorKeyReuse(`wpkh(${X}/<0;1>/*)`);
  assert.deepEqual(checkDescriptorKeyReuse(`wpkh(${ypub}/<0;1>/*)`), expected);
  assert.deepEqual(checkDescriptorKeyReuse(`wpkh(${zpub}/<0;1>/*)`), expected);
});

test("a valid checksum is accepted and a wrong one refused", () => {
  const body = `wpkh(${X}/<0;1>/*)`;
  const checksum = descriptorChecksum(body);
  assert.equal(checkDescriptorKeyReuse(`${body}#${checksum}`).branches, 2);
  const wrong = checksum.slice(0, 7) + (checksum[7] === "q" ? "p" : "q");
  assertCode(() => checkDescriptorKeyReuse(`${body}#${wrong}`), "checksum");
});

test("private key material is refused without echoing the key", () => {
  const xprv = master.derive("m/84'/0'/0'").privateExtendedKey;
  const zprv = withVersion(xprv, 0x04b2430c);
  const wif = base58checkEncode(Uint8Array.from([0x80, ...new Uint8Array(32).fill(1), 0x01]));
  assert.match(wif, /^[5KL9c][1-9A-HJ-NP-Za-km-z]{50,51}$/);
  for (const secret of [xprv, zprv, wif]) {
    let message = null;
    try {
      checkDescriptorKeyReuse(`wpkh(${secret}/0/*)`);
    } catch (error) {
      message = error.message;
    }
    assert.ok(message !== null, "expected a refusal");
    assert.ok(message.startsWith("private:"), message);
    assert.ok(!message.includes(secret), "the message must not echo the key");
  }
});

test("multipath length mismatch is refused", () => {
  assertCode(() => checkDescriptorKeyReuse(`wsh(multi(2,${X}/<0;1>/*,${Y}/<0;1;2>/*))`), "multipath-length");
});

test("hardened derivation after the extended key is refused", () => {
  assertCode(() => checkDescriptorKeyReuse(`wpkh(${X}/0h/*)`), "hardened");
  assertCode(() => checkDescriptorKeyReuse(`wpkh(${X}/0'/*)`), "hardened");
});

test("a non-ranged key is refused", () => {
  assertCode(() => checkDescriptorKeyReuse(`wpkh(${X}/0)`), "unranged");
  assertCode(() => checkDescriptorKeyReuse(`wpkh(${X})`), "unranged");
});

test("limits are refused", () => {
  const descriptor = `wpkh(${X}/<0;1>/*)`;
  assertCode(() => checkDescriptorKeyReuse(descriptor, { indexes: 0 }), "limit");
  assertCode(() => checkDescriptorKeyReuse(descriptor, { indexes: 1001 }), "limit");
  assertCode(() => checkDescriptorKeyReuse(descriptor, { indexes: 1.5 }), "limit");
  const manyKeys = Array.from({ length: 21 }, () => `${X}/0/*`).join(",");
  assertCode(() => checkDescriptorKeyReuse(`wsh(multi(2,${manyKeys}))`), "limit");
  const manyValues = Array.from({ length: 9 }, (_, i) => i).join(";");
  assertCode(() => checkDescriptorKeyReuse(`wpkh(${X}/<${manyValues}>/*)`), "limit");
  const twentyKeys = Array.from({ length: 20 }, () => `${X}/<0;1>/*`).join(",");
  assertCode(() => checkDescriptorKeyReuse(`wsh(multi(2,${twentyKeys}))`, { indexes: 1000 }), "limit");
});

test("the collision list is capped at 20 while the count is complete", () => {
  const result = checkDescriptorKeyReuse(`wsh(multi(2,${X}/0/*,${X}/0/*))`, { indexes: 30 });
  assert.equal(result.collisionCount, 30);
  assert.equal(result.collisions.length, 20);
});

test("reported pubkeys match HDKey derivation", () => {
  const result = checkDescriptorKeyReuse(`wpkh(${X}/<0;0>/*)`, { indexes: 3 });
  assert.equal(result.collisionCount, 3);
  const account = HDKey.fromExtendedKey(X);
  for (const collision of result.collisions) {
    assert.equal(collision.pubkey, hex(account.derive(`m/0/${collision.first.index}`).publicKey));
    // No fixed steps, one multipath value (0), then the index: xpub…/0/i.
    assert.equal(collision.first.path, `xpub…/0/${collision.first.index}`);
    assert.equal(collision.second.path, `xpub…/0/${collision.second.index}`);
  }
});

// Red-team on 94a96ec (DR-3): the budget counts the fixed steps walked to
// each branch node, not only the indexes below it.
test("the derivation budget includes fixed path steps", () => {
  const steps = Array.from({ length: 40 }, (_, i) => String(i)).join("/");
  const keys = Array.from({ length: 20 }, () => `${X}/${steps}/*`).join(",");
  // 20 keys x (40 steps + 990 indexes) = 20,600 > 20,000, though 20 x 990 = 19,800 alone would pass.
  assert.throws(() => checkDescriptorKeyReuse(`wsh(multi(1,${keys}))`, { indexes: 990 }), /^Error: limit:/);
});
