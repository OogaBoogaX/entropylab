// Animated UR for a watch-only descriptor or BIP-388 policy that does not
// fit one QR. Same sequential UR family as crypto-psbt (bytewords, 1-N
// parts, not a fountain code). A short descriptor stays the text QR it
// has today. An extended private key is refused. Issue #632.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { HDKey } from "@scure/bip32";
import { mnemonicToSeedSync } from "@scure/bip39";
import { buildBip388PolicyText } from "../src/js/bip388-policy.js";
import { descriptorChecksum } from "../src/js/core-importdescriptors.js";
import { base58check } from "@scure/base";
import { sha256 } from "@noble/hashes/sha2.js";
import { WATCH_ONLY_QR_STATIC_MAX_CHARS, hodlUrDecodeWatchOnly, watchOnlyQrPlan, watchOnlyQrButtonOptions, hodlCborBstr, hodlUrEncodeMessage } from "../src/js/psbt-ur.js";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const app = readFileSync(join(root, "src/js/app.js"), "utf8");

const seed = mnemonicToSeedSync(
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
);
const master = HDKey.fromMasterSeed(seed);

function rangedKey(account) {
  const node = master.derive(`m/48'/0'/${account}'/2'`);
  const fingerprint = master.fingerprint.toString(16).padStart(8, "0");
  return `[${fingerprint}/48h/0h/${account}h/2h]${node.publicExtendedKey}`;
}

function policyText(count) {
  const keys = Array.from({ length: count }, (_, index) => rangedKey(index));
  const body = `wsh(sortedmulti(${count},${keys.map((key) => `${key}/0/*`).join(",")}))`;
  return buildBip388PolicyText({ receiveDescriptor: `${body}#${descriptorChecksum(body)}` });
}

test("a short descriptor stays one static QR of the descriptor text", () => {
  const descriptor = "wpkh([73c5da0a/84h/0h/0h]xpub6CUGRUonZSQ4TWtTMmzXdrXDtypWKiKrhko4egpiMZbpiaQL2jkwSB1icqYh2cfDfVxdx4df189oLKnC8fRrjw7A9f/0/*)";
  assert.ok(descriptor.length <= WATCH_ONLY_QR_STATIC_MAX_CHARS);
  const plan = watchOnlyQrPlan(descriptor);
  assert.equal(plan.mode, "static");
  assert.equal(plan.text, descriptor);
  assert.equal(plan.parts, undefined);
  assert.doesNotMatch(descriptor, /[xyztuvYZUV]prv/);
});

test("a BIP-388 policy that overflows one QR splits, round-trips, and has no private key", () => {
  const text = policyText(10);
  assert.ok(text.length > WATCH_ONLY_QR_STATIC_MAX_CHARS, "fixture must overflow one QR");
  assert.doesNotMatch(text, /[xyztuvYZUV]prv/);
  assert.doesNotMatch(text, /abandon/);
  const plan = watchOnlyQrPlan(text);
  assert.equal(plan.mode, "ur");
  assert.ok(plan.parts.length > 1);
  for (const part of plan.parts) {
    assert.match(part, /^UR:BYTES\/\d+-\d+\/[A-Z]+$/);
    assert.doesNotMatch(part, /PRV/);
  }
  assert.equal(hodlUrDecodeWatchOnly(plan.parts.join("\n")), text);
});

test("an extended private key is refused and not encoded", () => {
  const secret = master.derive("m/48'/0'/0'/2'").privateExtendedKey;
  assert.match(secret, /xprv/);
  assert.throws(() => watchOnlyQrPlan(`wsh(${secret}/0/*)`), /private key/);
  assert.throws(() => watchOnlyQrPlan(secret + "x".repeat(WATCH_ONLY_QR_STATIC_MAX_CHARS)), /private key/);
});

test("the watch-only QR button uses the shared animated overlay, not a new tab", () => {
  assert.match(app, /kind === "watch"/);
  assert.match(app, /watchOnly:\s*true/);
  // The BIP-388 policy field is built as a watch-only field (wiring, not copy).
  const policyField = app.slice(app.indexOf("function hodlMsigBip388Field("), app.indexOf("function hodlMsigBip388PolicyText("));
  assert.match(policyField, /hodlCopyFieldHtml\([^;]*\{ watchOnly: true \}\)/);
  assert.doesNotMatch(app, /workspace.*watch-only-ur|data-tab="ur"/);
});

// SLIP-132 private version bytes (mainnet/testnet, single/multisig).
// Fixed BIP39 fixture above; no funding material is generated.
const privateVersions = [
  ["xprv", 0x0488ade4], ["yprv", 0x049d7878], ["zprv", 0x04b2430c],
  ["Yprv", 0x0295b005], ["Zprv", 0x02aa7a99], ["tprv", 0x04358394],
  ["uprv", 0x044a4e28], ["vprv", 0x045f18bc], ["Uprv", 0x024285b5],
  ["Vprv", 0x02575048],
];
for (const [prefix, privateVersion] of privateVersions) {
  test(`${prefix} private material is refused on encode and decode`, () => {
    const key = HDKey.fromMasterSeed(seed, { private: privateVersion, public: 0x0488b21e }).privateExtendedKey;
    assert.ok(key.startsWith(prefix));
    for (const text of [key, `wpkh(${key}/0/*)`, `Name: wallet\nPolicy: wpkh(@0/**)\nKey: ${key}`]) {
      assert.throws(() => watchOnlyQrPlan(text), /private key/);
      // Use the generic transport to bypass the watch-only encoder guard;
      // decode must independently reject both single and multipart payloads.
      for (const maxBytes of [2000, 40]) {
        const parts = hodlUrEncodeMessage("bytes", hodlCborBstr(new TextEncoder().encode(text)), { maxBytes });
        assert.throws(() => hodlUrDecodeWatchOnly(parts.join("\n")), /private key/);
      }
    }
  });
}

for (const [length, mode] of [[1000, "static"], [1001, "ur"]]) {
  test(`exactly ${length} characters selects ${mode}`, () => {
    // The planner transports opaque public text; descriptor validity is
    // checked elsewhere. These fixed ASCII fixtures pin the QR boundary.
    const text = "a".repeat(length);
    const plan = watchOnlyQrPlan(text);
    assert.equal(plan.mode, mode);
    if (mode === "static") assert.equal(plan.text, text);
    else {
      assert.ok(plan.parts.length > 1);
      assert.equal(hodlUrDecodeWatchOnly(plan.parts.join("\n")), text);
    }
  });
}

// Private material other than extended keys (review 5643207552): WIF keys and
// raw 32-byte hex keys in key positions. Expected outcome: refused on encode
// and decode, and no QR button. Published WIFs for private key 1 (Bitcoin
// wiki, "Wallet import format"); testnet WIFs are encoded here with
// @scure/base, independently of psbt-ur.js.
const one = new Uint8Array(32); one[31] = 1;
const wif = (version, compressed) => base58check(sha256).encode(Uint8Array.from([version, ...one, ...(compressed ? [1] : [])]));
const privateForms = [
  ["mainnet uncompressed WIF", "5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAnchuDf"],
  ["mainnet compressed WIF", "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn"],
  ["review's compressed WIF", "L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1"],
  ["testnet uncompressed WIF", wif(0xef, false)],
  ["testnet compressed WIF", wif(0xef, true)],
  ["raw 64-hex key", "0000000000000000000000000000000000000000000000000000000000000001"],
];
test("the testnet WIF fixtures have the published shapes", () => {
  assert.match(wif(0xef, false), /^9[1-9A-HJ-NP-Za-km-z]{50}$/);
  assert.match(wif(0xef, true), /^c[1-9A-HJ-NP-Za-km-z]{51}$/);
});
for (const [name, key] of privateForms) {
  test(`a ${name} is refused on encode and decode and gets no QR button`, () => {
    const texts = [`wpkh(${key})`, `combo(${key})`, `tr(${key})`, `Name: wallet\nPolicy: wpkh(@0/**)\nKey: ${key}`];
    texts.push(texts[0] + " ".repeat(WATCH_ONLY_QR_STATIC_MAX_CHARS));
    for (const text of texts) {
      assert.throws(() => watchOnlyQrPlan(text), (error) => /private key/.test(error.message) && !error.message.includes(key));
      assert.equal(watchOnlyQrButtonOptions(text), null, `${name} offered a QR button`);
      for (const maxBytes of [2000, 40]) {
        const parts = hodlUrEncodeMessage("bytes", hodlCborBstr(new TextEncoder().encode(text)), { maxBytes });
        assert.throws(() => hodlUrDecodeWatchOnly(parts.join("\n")), /private key/);
      }
    }
  });
}
test("an extended private key gets no QR button", () => {
  const secret = master.derive("m/48'/0'/0'/2'").privateExtendedKey;
  assert.equal(watchOnlyQrButtonOptions(`wsh(${secret}/0/*)`), null);
});

// Public forms keep their QR: an xpub (111 base58 characters, which contain
// WIF-length windows by chance), a compressed public key (66 hex) and BIP-341's
// NUMS internal key, which Taproot multisig descriptors carry.
test("public keys, the NUMS internal key and long policies keep their QR", () => {
  const nums = "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0";
  const xpubKey = rangedKey(0);
  const publics = [
    `wpkh(${xpubKey}/0/*)`,
    "wpkh(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)",
    `tr(${nums},sortedmulti_a(2,${rangedKey(0)}/0/*,${rangedKey(1)}/0/*))`,
  ];
  for (const text of publics) {
    assert.equal(watchOnlyQrPlan(text).mode, "static");
    assert.deepEqual(watchOnlyQrButtonOptions(text), {});
  }
  const policy = policyText(10);
  assert.deepEqual(watchOnlyQrButtonOptions(policy), { animate: "watch" });
});

// One guard: the field builder asks psbt-ur.js whether to offer a QR, and keeps
// no private-key pattern of its own that could drift from it.
test("the watch-only QR button and frames come from the shared modules", () => {
  const field = app.slice(app.indexOf("function hodlCopyFieldHtml("), app.indexOf("function hodlWatchOnlyDescriptorExport("));
  const frames = app.slice(app.indexOf("function hodlPsbtQrFrames("), app.indexOf("function hodlCopyFieldHtml("));
  assert.match(app, /watchOnlyQrButtonHtml as hodlWatchOnlyQrButton\b[^;]*from "\.\/address-qr\.js"/);
  assert.match(app, /watchOnlyQrFrames as hodlWatchOnlyQrFrames\b[^;]*from "\.\/psbt-ur\.js"/);
  assert.match(field, /hodlWatchOnlyQrButton\(value, labelText\)/);
  assert.match(frames, /kind === "watch"\) return hodlWatchOnlyQrFrames\(value\)/);
  assert.doesNotMatch(field, /prv/);
});
