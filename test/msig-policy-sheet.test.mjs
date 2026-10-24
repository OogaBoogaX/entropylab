// Tests for src/js/msig-policy-sheet.js — watch-only one-page policy sheet.
// Calculator export, not a generator.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "url";
import { HDKey } from "@scure/bip32";
import { mnemonicToSeedSync } from "@scure/bip39";
import {
  buildPolicySheet,
  canPrintPolicySheet,
  policySheetFilename,
  policySheetHtml,
  policySheetText,
} from "../src/js/msig-policy-sheet.js";
import { descriptorChecksum } from "../src/js/core-importdescriptors.js";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const read = (path) => readFileSync(join(root, path), "utf8");

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
const receive = `${receiveBody}#${descriptorChecksum(receiveBody)}`;
const ADDRESS = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq";

const wallet = {
  kind: "msig",
  network: "mainnet",
  script: "p2wsh",
  sorted: true,
  m: 2,
  n: 3,
  receiveDescriptor: receive,
  scriptOrder: [
    { position: 1, fingerprint, path: "48h/0h/0h/2h" },
    { position: 2, fingerprint, path: "48h/0h/1h/2h" },
    { position: 3, fingerprint, path: "48h/0h/2h/2h" },
  ],
  receive: [{ index: 0, address: ADDRESS, path: "m/48'/0'/0'/2'/0/0" }],
};

test("gating: needs a derived msig with address 0 and a checksum", () => {
  assert.equal(canPrintPolicySheet(null), false);
  assert.equal(canPrintPolicySheet({ kind: "hd" }), false);
  assert.equal(canPrintPolicySheet({ kind: "msig", receiveDescriptor: receive }), false);
  assert.equal(canPrintPolicySheet(wallet), true);
});

test("filename names the policy", () => {
  assert.equal(policySheetFilename(wallet), "entropylab-msig-2of3-watch-only-policy.txt");
  assert.equal(policySheetFilename({}), "entropylab-msig-watch-only-policy.txt");
});

test("text sheet carries address, checksum, fingerprints; never a mnemonic or xprv", () => {
  const text = policySheetText(wallet);
  assert.match(text, /WATCH-ONLY MULTISIG POLICY SHEET/);
  assert.match(text, new RegExp(ADDRESS));
  assert.match(text, /Descriptor checksum: #/);
  assert.match(text, new RegExp(fingerprint));
  assert.match(text, /2-of-3 sortedmulti/);
  assert.match(text, /Native SegWit/);
  assert.match(text, /Cannot spend/);
  assert.match(text, new RegExp(receive.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
  assert.doesNotMatch(text, /abandon/);
  assert.doesNotMatch(text, /[xyztuvYZUV]prv/);
  assert.doesNotMatch(text, /mnemonic|passphrase|seed phrase/i);
});

test("html sheet is print-safe, includes a QR slot, and is loud on testnet", () => {
  const qr = "<svg data-qr=\"1\"></svg>";
  const html = policySheetHtml(wallet, { qrSvg: () => qr });
  assert.match(html, /EntropyLab/);
  assert.match(html, new RegExp(ADDRESS));
  assert.match(html, /data-qr/);
  assert.match(html, /msig-policy-checksum/);
  assert.doesNotMatch(html, /msig-policy-network-loud/);
  assert.doesNotMatch(html, /abandon|[xyztuvYZUV]prv/);
  const testnet = policySheetHtml({ ...wallet, network: "testnet" }, { qrSvg: () => qr });
  assert.match(testnet, /msig-policy-network-loud/);
  assert.match(testnet, /testnet/);
});

test("a private descriptor is refused", () => {
  const xprv = nodeA.privateExtendedKey;
  const body = `wsh(sortedmulti(1,${xprv}/0/*))`;
  const bad = {
    kind: "msig",
    script: "p2wsh",
    m: 1,
    n: 1,
    receiveDescriptor: `${body}#${descriptorChecksum(body)}`,
    receive: [{ index: 0, address: ADDRESS }],
  };
  assert.equal(canPrintPolicySheet(bad), false);
  assert.throws(() => buildPolicySheet(bad), /private key|receive address 0/);
});
