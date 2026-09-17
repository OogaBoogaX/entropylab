// Tests for the Lightning node identity tool (src/js/lightning.js): the LND
// and LDK (ldk-node) derivations, their differential checks against
// @scure/bip32 + @scure/bip39 (pinned dev dependencies, previously the
// app's implementation), and the tool's wiring into the shell and app.
// Run with `npm test`.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { HDKey as ScureHDKey } from "@scure/bip32";
import { mnemonicToSeedSync as scureMnemonicToSeed } from "@scure/bip39";
import { deriveLndNode, deriveLdkNode, isKnownInternalVersion } from "../src/js/lightning.js";
import { aezeedDecode } from "../src/js/aezeed.js";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const read = (path) => readFileSync(join(root, path), "utf8");
const hexToBytes = (hex) => new Uint8Array(hex.match(/.{2}/g).map((b) => parseInt(b, 16)));
const bytesToHex = (bytes) => [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");

// ── LND: entropy16 is the BIP32 seed; node key at m/1017'/coin'/6'/0/0 ─────

test("LND node key differential vs @scure/bip32, both coin types", () => {
  for (const entropyHex of ["81b637d86359e6960de795e41e0b4cfd", "000102030405060708090a0b0c0d0e0f"]) {
    for (const coinType of [0, 1]) {
      const master = ScureHDKey.fromMasterSeed(hexToBytes(entropyHex));
      const path = `m/1017'/${coinType}'/6'/0/0`;
      const expected = bytesToHex(master.derive(path).publicKey);
      const derived = deriveLndNode(hexToBytes(entropyHex), coinType);
      assert.equal(derived.nodePubKey, expected, `${entropyHex} at ${path}`);
      assert.equal(derived.path, path);
      assert.equal(derived.rootXprv, master.privateExtendedKey, "root xprv matches");
    }
  }
});

test("aezeed to LND node key, end to end from the published vector", () => {
  // The toolkit characterization mnemonic (test/aezeed-wasm.test.mjs)
  // deciphers to entropy 000102030405060708090a0b0c0d0e0f; its mainnet node
  // key must equal the one @scure/bip32 derives from that entropy.
  const words = (
    "ability result leisure oven shiver wedding toe broccoli exclude " +
    "mosquito kind van action waste merit bundle robust source able " +
    "advice core humor kitchen siren"
  ).split(" ");
  const decoded = aezeedDecode(words, "");
  const derived = deriveLndNode(decoded.entropy, 0);
  const expected = ScureHDKey.fromMasterSeed(hexToBytes("000102030405060708090a0b0c0d0e0f")).derive("m/1017'/0'/6'/0/0");
  assert.equal(derived.nodePubKey, bytesToHex(expected.publicKey));
});

test("LND derivation validates its inputs", () => {
  assert.throws(() => deriveLndNode(new Uint8Array(15), 0), /16 bytes/);
  assert.throws(() => deriveLndNode(hexToBytes("000102030405060708090a0b0c0d0e0f"), 2), /Coin type/);
});

test("only known aezeed internal versions derive a node key", () => {
  // LND writes internal version 0 and rejects anything else; guggero's
  // toolkit also emits 1. Deriving from an unknown version would print a
  // node key no implementation would ever use.
  assert.ok(isKnownInternalVersion(0), "LND's version");
  assert.ok(isKnownInternalVersion(1), "the toolkit's version");
  for (const unknown of [2, 3, 255]) assert.ok(!isKnownInternalVersion(unknown), `version ${unknown} is refused`);
  const lnSource = read("src/js/lightning.js");
  assert.match(lnSource, /if \(!isKnownInternalVersion\(decoded\.internalVersion\)\)/, "the tool gates on it before deriving");
  assert.match(lnSource, /code: "internal-version"/, "the refusal is a named error");
});

// ── LDK (ldk-node): seed64 -> master -> its key re-seeds -> m/0' ───────────

const ldkExpected = (mnemonic, passphrase) => {
  const seed = scureMnemonicToSeed(mnemonic, passphrase);
  const master1 = ScureHDKey.fromMasterSeed(seed);
  const master2 = ScureHDKey.fromMasterSeed(master1.privateKey);
  const node = master2.deriveChild(0x80000000);
  return { nodePubKey: bytesToHex(node.publicKey), rootXprv: master1.privateExtendedKey };
};

test("LDK node key differential vs @scure (trezor mnemonics, with and without passphrase)", () => {
  const mnemonics = [
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
    "legal winner thank year wave sausage worth useful legal winner thank yellow",
    "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote",
  ];
  for (const mnemonic of mnemonics) {
    for (const passphrase of ["", "TREZOR"]) {
      const expected = ldkExpected(mnemonic, passphrase);
      const derived = deriveLdkNode(mnemonic, passphrase);
      assert.equal(derived.nodePubKey, expected.nodePubKey, `${mnemonic.slice(0, 20)}… pass="${passphrase}"`);
      assert.equal(derived.rootXprv, expected.rootXprv, "stage-1 root xprv matches");
      assert.equal(derived.path, "m/0'");
    }
  }
});

test("the two-stage LDK derivation is not the plain m/0' of the seed", () => {
  // Guards the subtle part: KeysManager re-seeds from the master's private
  // key. Deriving m/0' directly from the 64-byte seed must NOT match.
  const mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
  const seed = scureMnemonicToSeed(mnemonic, "");
  const plain = bytesToHex(ScureHDKey.fromMasterSeed(seed).deriveChild(0x80000000).publicKey);
  assert.notEqual(deriveLdkNode(mnemonic, "").nodePubKey, plain);
});

// ── Wiring: shell markup, tab registry, show/hide, lifecycle ────────────────

const shell = read("src/shell.html");
const appSource = read("src/js/app.js");

test("the Lightning card ships in the shell with its controls", () => {
  assert.match(shell, /<section class="card no-print tool-card" id="ln-card" role="tabpanel" hidden>/);
  for (const id of ["ln-format", "ln-network", "ln-seed", "ln-pass", "ln-go", "ln-wipe", "ln-session", "ln-error", "ln-out"]) {
    assert.ok(shell.includes(`id="${id}"`), `${id} is missing from the shell`);
  }
  assert.match(shell, /id="ln-tool-intro"/);
});

test("the tab registry and workspace switcher carry the Lightning tool", () => {
  for (const entry of [/\["psbt", "PSBT", "PSBT"\]/, /\["ln", "Lightning", "LN"\]/, /\["journal", "Journal", "Journal"\]/]) {
    assert.match(appSource, entry);
  }
  assert.match(appSource, /getElementById\("ln-card"\)\.hidden = id !== "ln"/);
  assert.match(appSource, /\["bip85", "sp", "msig", "calc", "vanity", "ln"\]\.forEach/);
  assert.match(appSource, /import \{ hodlInitLn, hodlLnInvWipeMem, hodlLnWipeMem \} from "\.\/lightning\.js"/);
  assert.match(appSource, /hodlInitLn\(\{ journalLog: hodlJournalLog, qrSvg: hodlQrSvg, networkChoice: \(\) => hodlNetworkChoice \}\)/);
});

test("a format or network change wipes the derived result", () => {
  // A stale mainnet pubkey next to a flipped "Testnet" select is how a
  // correct seed looks wrong: the change handler wipes and re-renders.
  const lnSource = read("src/js/lightning.js");
  const listener = lnSource.match(/for \(const id of \["ln-format", "ln-network"\]\) \{\s*document\.getElementById\(id\)\?\.addEventListener\("change", \(\) => \{([\s\S]*?)\}\);\s*\}/);
  assert.ok(listener, "the change listener exists");
  assert.match(listener[1], /hodlLnWipeMem\(\)/, "the change wipes the derived result");
  assert.match(listener[1], /hodlLnRender\(\)/, "the change re-renders the empty state");
  assert.match(listener[1], /hodlLnSyncFormat\(\)/, "the change still syncs the network field");
});
