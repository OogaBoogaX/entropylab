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
import { WATCH_ONLY_QR_STATIC_MAX_CHARS, hodlUrDecodeWatchOnly, watchOnlyQrPlan, hodlCborBstr, hodlUrEncodeMessage } from "../src/js/psbt-ur.js";

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
  // The label must reach the field through the translation call site; the
  // copy itself is content, not contract (AGENTS.md).
  assert.match(app, /hodlCopyFieldHtml\(hodlTText\("BIP 388 wallet policy"\)/);
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
