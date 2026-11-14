// Tests for src/js/bip388-policy.js — BIP 388 wallet policy from a derived
// watch-only multisig. Calculator export, not a generator.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "url";
import { HDKey } from "@scure/bip32";
import { mnemonicToSeedSync } from "@scure/bip39";
import {
  bip388PolicyFilename,
  buildBip388Policy,
  buildBip388PolicyText,
} from "../src/js/bip388-policy.js";
import { descriptorChecksum } from "../src/js/core-importdescriptors.js";
import { b58checkDecode, b58checkEncode } from "./wallet-export-harness.mjs";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const read = (path) => readFileSync(join(root, path), "utf8");
const codec = { decode: b58checkDecode, encode: b58checkEncode };

const seed = mnemonicToSeedSync(
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
);
const master = HDKey.fromMasterSeed(seed);
const fingerprint = master.fingerprint.toString(16).padStart(8, "0");
const nodeA = master.derive("m/48'/0'/0'/2'");
const nodeB = master.derive("m/48'/0'/1'/2'");
const nodeC = master.derive("m/48'/0'/2'/2'");
const keyA = `[${fingerprint}/48h/0h/0h/2h]${nodeA.publicExtendedKey}`;
const keyB = `[${fingerprint}/48h/0h/1h/2h]${nodeB.publicExtendedKey}`;
const keyC = `[${fingerprint}/48h/0h/2h/2h]${nodeC.publicExtendedKey}`;
const receiveBody = `wsh(sortedmulti(2,${keyA}/0/*,${keyB}/0/*,${keyC}/0/*))`;
const changeBody = `wsh(sortedmulti(2,${keyA}/1/*,${keyB}/1/*,${keyC}/1/*))`;
const receive = `${receiveBody}#${descriptorChecksum(receiveBody)}`;
const change = `${changeBody}#${descriptorChecksum(changeBody)}`;

test("2-of-3 native sortedmulti becomes @0/** @1/** @2/**", () => {
  const policy = buildBip388Policy({ receiveDescriptor: receive, changeDescriptor: change });
  assert.equal(policy.descriptorTemplate, "wsh(sortedmulti(2,@0/**,@1/**,@2/**))");
  assert.equal(policy.keys.length, 3);
  assert.equal(policy.keys[0], `[${fingerprint}/48'/0'/0'/2']${nodeA.publicExtendedKey}`);
  assert.equal(policy.keys[1], `[${fingerprint}/48'/0'/1'/2']${nodeB.publicExtendedKey}`);
  assert.equal(policy.keys[2], `[${fingerprint}/48'/0'/2'/2']${nodeC.publicExtendedKey}`);
});

test("a valid 2-of-3 with distinct keys keeps the exact template and keys", () => {
  const policy = buildBip388Policy({ receiveDescriptor: receive, changeDescriptor: change });
  assert.equal(policy.descriptorTemplate, "wsh(sortedmulti(2,@0/**,@1/**,@2/**))");
  assert.deepEqual(policy.keys, [
    `[${fingerprint}/48'/0'/0'/2']${nodeA.publicExtendedKey}`,
    `[${fingerprint}/48'/0'/1'/2']${nodeB.publicExtendedKey}`,
    `[${fingerprint}/48'/0'/2'/2']${nodeC.publicExtendedKey}`,
  ]);
});

test("text export is watch-only and names the template", () => {
  const text = buildBip388PolicyText({ receiveDescriptor: receive, changeDescriptor: change });
  assert.match(text, /descriptor_template: wsh\(sortedmulti\(2,@0\/\*\*,@1\/\*\*,@2\/\*\*\)\)/);
  assert.match(text, /@0 \[/);
  assert.match(text, /Cannot spend/);
  assert.doesNotMatch(text, /abandon/);
  assert.doesNotMatch(text, /[xyztuvYZUV]prv/);
  assert.doesNotMatch(text, /\/0\/\*/);
});

test("Zpub is rewritten to xpub in the key vector", () => {
  const raw = b58checkDecode(nodeA.publicExtendedKey);
  raw[0] = 0x02; raw[1] = 0xaa; raw[2] = 0x7e; raw[3] = 0xd3;
  const zpub = b58checkEncode(raw);
  const slipBody = `wsh(sortedmulti(1,[${fingerprint}/48h/0h/0h/2h]${zpub}/0/*))`;
  const slip = `${slipBody}#${descriptorChecksum(slipBody)}`;
  const policy = buildBip388Policy({ receiveDescriptor: slip, decode: codec.decode, encode: codec.encode });
  assert.equal(policy.descriptorTemplate, "wsh(sortedmulti(1,@0/**))");
  assert.match(policy.keys[0], /xpub/);
  assert.doesNotMatch(policy.keys[0], /Zpub/);
});

test("an extended private key is refused", () => {
  const body = `wsh(sortedmulti(1,${nodeA.privateExtendedKey}/0/*))`;
  const descriptor = `${body}#${descriptorChecksum(body)}`;
  assert.throws(() => buildBip388Policy({ receiveDescriptor: descriptor }), /private key/);
});

test("taproot NUMS is refused", () => {
  const inner = `tr(50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0,sortedmulti_a(2,${keyA}/0/*,${keyB}/0/*))`;
  const descriptor = `${inner}#${descriptorChecksum(inner)}`;
  assert.throws(() => buildBip388Policy({ receiveDescriptor: descriptor }), /NUMS/);
});

test("BIP45 two-step tails are refused", () => {
  const inner = `sh(sortedmulti(2,${keyA}/0/0/*,${keyB}/0/0/*))`;
  const descriptor = `${inner}#${descriptorChecksum(inner)}`;
  assert.throws(() => buildBip388Policy({ receiveDescriptor: descriptor }), /no \/0\/\* or \/1\/\*|BIP45/);
});

test("a key repeated in more than one slot is refused", () => {
  const body = `wsh(sortedmulti(2,${keyA}/0/*,${keyA}/1/*,${keyC}/0/*))`;
  const descriptor = `${body}#${descriptorChecksum(body)}`;
  assert.throws(() => buildBip388Policy({ receiveDescriptor: descriptor }), /more than one slot/);
});

test("a receive key on the change branch is refused", () => {
  const body = `wsh(sortedmulti(2,${keyA}/0/*,${keyB}/1/*))`;
  const descriptor = `${body}#${descriptorChecksum(body)}`;
  assert.throws(() => buildBip388Policy({ receiveDescriptor: descriptor }), /every receive key must end in \/0\/\*/);
});

test("receive and change with swapped branches are refused", () => {
  assert.throws(() => buildBip388Policy({ receiveDescriptor: change, changeDescriptor: receive }), /every receive key must end in \/0\/\*/);
});

test("a change key on the receive branch is refused", () => {
  assert.throws(() => buildBip388Policy({ receiveDescriptor: receive, changeDescriptor: receive }), /every receive key must end in \/0\/\*/);
});

test("the same xpub with a different origin in two slots is refused", () => {
  const body = `wsh(sortedmulti(2,${keyA}/0/*,[01234567/48h/0h/0h/2h]${nodeA.publicExtendedKey}/1/*,${keyC}/0/*))`;
  const descriptor = `${body}#${descriptorChecksum(body)}`;
  assert.throws(() => buildBip388Policy({ receiveDescriptor: descriptor }), /more than one slot/);
});

test("the same xpub with a missing origin in two slots is refused", () => {
  const body = `wsh(sortedmulti(2,${nodeA.publicExtendedKey}/0/*,${keyA}/1/*,${keyC}/0/*))`;
  const descriptor = `${body}#${descriptorChecksum(body)}`;
  assert.throws(() => buildBip388Policy({ receiveDescriptor: descriptor }), /more than one slot/);
});

test("the same key twice in one branch is refused", () => {
  const body = `wsh(sortedmulti(2,${keyA}/0/*,${keyA}/0/*,${keyC}/0/*))`;
  const descriptor = `${body}#${descriptorChecksum(body)}`;
  assert.throws(() => buildBip388Policy({ receiveDescriptor: descriptor }), /more than one slot/);
});

test("filename names the policy", () => {
  assert.equal(bip388PolicyFilename({ m: 2, n: 3 }), "entropylab-msig-2of3-bip388.txt");
  assert.equal(bip388PolicyFilename({}), "entropylab-bip388.txt");
});
