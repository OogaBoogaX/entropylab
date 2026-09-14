// Tests for src/js/core-importdescriptors.js — watch-only Bitcoin Core
// importdescriptors JSON. Calculator export, not a generator.
// Run with: node --test test/core-importdescriptors.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "url";
import { HDKey } from "@scure/bip32";
import { mnemonicToSeedSync } from "@scure/bip39";
import {
  CORE_IMPORT_RANGE_END,
  assertMatchingWatchDescriptors,
  buildImportDescriptorsJson,
  canonicalizeWatchDescriptor,
  coreImportDescriptorsFilename,
  descriptorChecksum,
  stripDescriptorChecksum,
} from "../src/js/core-importdescriptors.js";
import { b58checkDecode, b58checkEncode, descriptorChecksum as harnessChecksum } from "./wallet-export-harness.mjs";

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

const parse = (json) => JSON.parse(json);

test("checksum matches the independent Core reference", () => {
  assert.equal(descriptorChecksum(receiveBody), harnessChecksum(receiveBody));
});

test("JSON.parse of the export is an array of length 2", () => {
  const entries = parse(buildImportDescriptorsJson({ receiveDescriptor: receive, changeDescriptor: change }));
  assert.equal(entries.length, 2);
});

test("receive is external, change is internal, both active, range matches wallet.dat", () => {
  const walletSrc = read("src/js/wallet-export.js");
  const range = walletSrc.match(/const RANGE_END = (\d+)/);
  assert.equal(CORE_IMPORT_RANGE_END, Number(range[1]));
  const [external, internal] = parse(buildImportDescriptorsJson({ receiveDescriptor: receive, changeDescriptor: change }));
  assert.equal(external.internal, false);
  assert.equal(internal.internal, true);
  assert.equal(external.active, true);
  assert.equal(internal.active, true);
  assert.deepEqual(external.range, [0, 1000]);
  assert.deepEqual(internal.range, [0, 1000]);
});

test("default timestamp is number 0; now mode is the string now", () => {
  const genesis = parse(buildImportDescriptorsJson({ receiveDescriptor: receive, changeDescriptor: change }));
  assert.equal(genesis[0].timestamp, 0);
  assert.equal(typeof genesis[0].timestamp, "number");
  const created = parse(buildImportDescriptorsJson({ receiveDescriptor: receive, changeDescriptor: change, timestamp: "now" }));
  assert.equal(created[0].timestamp, "now");
  assert.equal(created[1].timestamp, "now");
  assert.throws(
    () => buildImportDescriptorsJson({ receiveDescriptor: receive, changeDescriptor: change, timestamp: 1710000000 }),
    /timestamp must be 0 or "now"/,
  );
});

test("desc strings include a matching BIP-380 checksum", () => {
  const [external, internal] = parse(buildImportDescriptorsJson({ receiveDescriptor: receive, changeDescriptor: change }));
  for (const entry of [external, internal]) {
    const hash = entry.desc.lastIndexOf("#");
    assert.ok(hash > 0);
    assert.equal(entry.desc.slice(hash + 1), descriptorChecksum(entry.desc.slice(0, hash)));
  }
});

test("bodies are the msig receive and change descriptors with origins kept", () => {
  const [external, internal] = parse(buildImportDescriptorsJson({ receiveDescriptor: receive, changeDescriptor: change }));
  assert.equal(stripDescriptorChecksum(external.desc), receiveBody);
  assert.equal(stripDescriptorChecksum(internal.desc), changeBody);
  assert.match(external.desc, new RegExp(`\\[${fingerprint}/48h/0h/0h/2h\\]`));
  assert.match(external.desc, /sortedmulti\(2,/);
});

test("the JSON never contains xprv-family keys, a mnemonic, or a seed", () => {
  const json = buildImportDescriptorsJson({ receiveDescriptor: receive, changeDescriptor: change });
  assert.doesNotMatch(json, /[xyztuvYZUV]prv/);
  assert.doesNotMatch(json, /abandon/);
  assert.doesNotMatch(json, /mnemonic|passphrase|seed phrase/i);
});

test("receive and change only differ by /0/* vs /1/*", () => {
  const [external, internal] = parse(buildImportDescriptorsJson({ receiveDescriptor: receive, changeDescriptor: change }));
  assert.equal(
    stripDescriptorChecksum(external.desc).replaceAll("/0/*", "/1/*"),
    stripDescriptorChecksum(internal.desc),
  );
  assertMatchingWatchDescriptors(external.desc, internal.desc);
});

test("a receive-only wallet still exports one external descriptor", () => {
  const entries = parse(buildImportDescriptorsJson({ receiveDescriptor: receive }));
  assert.equal(entries.length, 1);
  assert.equal(entries[0].internal, false);
  assert.equal(entries[0].desc, receive);
});

test("SLIP-132 Zpub is rewritten to xpub when the codec is supplied", () => {
  const zpub = (() => {
    const raw = b58checkDecode(nodeA.publicExtendedKey);
    raw[0] = 0x02; raw[1] = 0xaa; raw[2] = 0x7e; raw[3] = 0xd3;
    return b58checkEncode(raw);
  })();
  assert.match(zpub, /^Zpub/);
  const slipBody = `wsh(sortedmulti(2,[${fingerprint}/48h/0h/0h/2h]${zpub}/0/*,${keyB}/0/*))`;
  const slip = `${slipBody}#${descriptorChecksum(slipBody)}`;
  assert.throws(() => canonicalizeWatchDescriptor(slip), /SLIP-132|Base58Check codec/);
  const canonical = canonicalizeWatchDescriptor(slip, codec);
  assert.match(canonical, /xpub/);
  assert.doesNotMatch(canonical, /Zpub/);
  const json = buildImportDescriptorsJson({ receiveDescriptor: slip, decode: codec.decode, encode: codec.encode });
  assert.match(json, /xpub/);
  assert.doesNotMatch(json, /Zpub/);
});

test("an extended private key is refused", () => {
  const xprv = nodeA.privateExtendedKey;
  const body = `wsh(sortedmulti(1,[${fingerprint}/48h/0h/0h/2h]${xprv}/0/*))`;
  const descriptor = `${body}#${descriptorChecksum(body)}`;
  assert.throws(
    () => buildImportDescriptorsJson({ receiveDescriptor: descriptor, changeDescriptor: change }),
    /extended private key/,
  );
});

test("capital SLIP-132 multisig private keys are refused", () => {
  // Yprv, Zprv (mainnet), Uprv, Vprv (testnet) — the private counterparts of
  // the capital public prefixes this module rewrites.
  for (const version of [0x0295b005, 0x02aa7a99, 0x024285b5, 0x02575048]) {
    const raw = b58checkDecode(nodeA.privateExtendedKey);
    raw[0] = version >>> 24 & 255; raw[1] = version >>> 16 & 255; raw[2] = version >>> 8 & 255; raw[3] = version & 255;
    const key = b58checkEncode(raw);
    assert.match(key, /^[YZUV]prv/);
    const body = `wsh(sortedmulti(1,${key}/0/*))`;
    const descriptor = `${body}#${descriptorChecksum(body)}`;
    assert.throws(() => buildImportDescriptorsJson({ receiveDescriptor: descriptor }), /extended private key/);
  }
});

test("mismatched receive/change keys are refused", () => {
  const other = `wsh(sortedmulti(2,${keyA}/1/*,${keyB}/1/*))`;
  const otherDesc = `${other}#${descriptorChecksum(other)}`;
  assert.throws(
    () => buildImportDescriptorsJson({ receiveDescriptor: receive, changeDescriptor: otherDesc }),
    /different keys/,
  );
});

test("missing descriptors and a bad checksum are refused", () => {
  assert.throws(() => buildImportDescriptorsJson({}), /No watch-only descriptors/);
  const corrupted = receive.slice(0, -1) + (receive.endsWith("0") ? "1" : "0");
  assert.throws(() => buildImportDescriptorsJson({ receiveDescriptor: corrupted }), /checksum does not match/);
});

test("filename includes the m-of-n policy when present", () => {
  assert.equal(coreImportDescriptorsFilename({ m: 3, n: 7 }), "entropylab-msig-3of7-importdescriptors.json");
  assert.equal(coreImportDescriptorsFilename({}), "entropylab-importdescriptors.json");
});

test("the builder never talks to the network", () => {
  const source = read("src/js/core-importdescriptors.js");
  assert.doesNotMatch(source, /\bfetch\b|XMLHttpRequest|WebSocket|RTCPeerConnection|sendBeacon|WebTransport/);
});

test("MS Station result markup wires copy/save and wallet.dat; no new workspace tab", () => {
  const app = read("src/js/app.js");
  const shell = read("src/shell.html");
  assert.match(app, /id="msig-copy-importdescriptors"/);
  assert.match(app, /id="msig-save-importdescriptors"/);
  assert.match(app, /id="msig-download-wallet-dat"/);
  assert.match(app, /hodlT\("Copy Core importdescriptors"\)/);
  assert.match(app, /hodlT\("Save Core watch-only JSON"\)/);
  assert.match(app, /hodlT\("Download watch-only wallet.dat"\)/);
  assert.match(app, /buildImportDescriptorsJson/);
  assert.match(app, /function hodlShowMsig\(/);
  assert.doesNotMatch(shell, /msig-copy-importdescriptors|msig-save-importdescriptors|msig-download-wallet-dat/);
  assert.doesNotMatch(shell, /id="workspace-tabs"[\s\S]{0,2000}importdescriptors/);
  assert.match(shell, /id="workspace-tabs"/);
});

test("wallet.dat export accepts watch-only msig and still ignores private material", () => {
  const source = read("src/js/wallet-export.js");
  assert.match(source, /kind === "msig"/);
  assert.match(source, /multiKey: true/);
  assert.match(source, /privateDescriptor: null/);
});
