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
import { deriveLndNode, deriveLdkNode, isKnownInternalVersion, hodlInitLn } from "../src/js/lightning.js";
import { aezeedDecode } from "../src/js/aezeed.js";
import { MiniDocument } from "./mini-dom.mjs";

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
  assert.match(shell, /<div class="card no-print tool-card" id="ln-card" role="tabpanel" hidden>/);
  for (const id of ["ln-format", "ln-network", "ln-seed", "ln-pass", "ln-go", "ln-wipe", "ln-session", "ln-error", "ln-out"]) {
    assert.ok(shell.includes(`id="${id}"`), `${id} is missing from the shell`);
  }
  assert.match(shell, /id="ln-tool-intro"/);
});

test("the workspace switcher retains the held-back Lightning implementation", () => {
  for (const entry of [/\["psbt", "Transactions", "Txns"\]/, /\["journal", "Journal", "Journal"\]/]) {
    assert.match(appSource, entry);
  }
  assert.match(appSource, /getElementById\("ln-card"\)\.hidden = id !== "ln"/);
  assert.match(appSource, /\["bip85", "sp", "msig", "calc", "vanity", "ln", "core"\]\.forEach/);
  assert.match(appSource, /import \{ hodlInitLn, hodlLnWipeMem \} from "\.\/lightning\.js"/);
  assert.match(appSource, /hodlInitLn\(\{ journalLog: hodlJournalLog, copyIcon: hodlClipboardIconMarkup \}\)/);
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

// ── Tool behaviour through the real wiring (mini DOM) ───────────────────────

// The published aezeed characterization mnemonic (see the end-to-end test
// above): it deciphers to entropy 000102030405060708090a0b0c0d0e0f.
const AEZEED_VECTOR_WORDS =
  "ability result leisure oven shiver wedding toe broccoli exclude " +
  "mosquito kind van action waste merit bundle robust source able " +
  "advice core humor kitchen siren";
const BIP39_VECTOR_WORDS = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

// The tool wired over a mini DOM: the fixture carries the ids hodlInitLn
// touches, and the derive runs through the real Derive button handler.
function lnPage() {
  const page = new MiniDocument();
  globalThis.document = page;
  // The selects carry the shell's options (shell.html #ln-card): a <select>
  // only holds a set value that matches one of its options, so without them
  // the fixture cannot switch the tool off aezeed and the BIP-39/LDK path
  // never runs.
  page.body.innerHTML = '<select id="ln-format"><option value="aezeed" selected>aezeed · LND cipher seed</option><option value="bip39">BIP-39 · LDK (ldk-node)</option></select>'
    + '<div id="ln-network-field"><select id="ln-network"><option value="mainnet" selected>Mainnet</option><option value="testnet">Testnet</option></select></div>'
    + '<textarea id="ln-seed"></textarea><input id="ln-pass" type="password">'
    + '<button id="ln-go" type="button"></button><button id="ln-wipe" type="button"></button>'
    + '<p id="ln-session"></p><p id="ln-error"></p><div id="ln-out"></div>'
    + '<span id="ln-seed-help"></span>';
  hodlInitLn({ journalLog() {}, copyIcon: () => "" });
  return page;
}

// hodlInitLn assigns the Derive button's onclick; call it (the mini DOM
// keeps it as a property), falling back to a dispatched click event.
const lnDerive = (page) => {
  const go = page.getElementById("ln-go");
  if (typeof go.onclick === "function") go.onclick();
  else go.dispatchEvent(new Event("click", { bubbles: true }));
};

test("the tool derives the published aezeed vector through its real wiring", () => {
  const page = lnPage();
  try {
    page.getElementById("ln-seed").value = AEZEED_VECTOR_WORDS;
    lnDerive(page);
    assert.equal(page.getElementById("ln-error").textContent, "", "the derive reported an error");
    const expected = ScureHDKey.fromMasterSeed(hexToBytes("000102030405060708090a0b0c0d0e0f")).derive("m/1017'/0'/6'/0/0");
    assert.ok(page.getElementById("ln-out").innerHTML.includes(bytesToHex(expected.publicKey)), "the derived node pubkey is not on screen");
  } finally {
    delete globalThis.document;
  }
});

test("the tool derives the LDK node key through its real wiring", () => {
  const page = lnPage();
  try {
    page.getElementById("ln-format").value = "bip39";
    page.getElementById("ln-seed").value = BIP39_VECTOR_WORDS;
    lnDerive(page);
    assert.equal(page.getElementById("ln-error").textContent, "", "the derive reported an error");
    assert.ok(page.getElementById("ln-out").innerHTML.includes(ldkExpected(BIP39_VECTOR_WORDS, "").nodePubKey), "the derived node pubkey is not on screen");
  } finally {
    delete globalThis.document;
  }
});

test("an oversized seed paste is refused before any normalizing or deriving", () => {
  // The 24-word vector plus 6 kB of punctuation noise: the normalizer would
  // strip the noise and derive, so the length refusal must come first.
  const page = lnPage();
  try {
    page.getElementById("ln-seed").value = `${AEZEED_VECTOR_WORDS} ${"1!".repeat(3000)}`;
    lnDerive(page);
    // The refusal is the keyed "seed-too-long" error; its wording is
    // translatable copy, so assert the outcome, not the text: an error is
    // shown and nothing was derived (the normalizer would have stripped the
    // noise and derived had the length check come after it).
    assert.ok(page.getElementById("ln-error").textContent.length > 0, "the oversized paste was not refused");
    assert.equal(page.getElementById("ln-out").innerHTML, "", "an oversized paste derived a node key");
  } finally {
    delete globalThis.document;
  }
});

test("the LDK tool path refuses a lone-surrogate passphrase and derives nothing", () => {
  const page = lnPage();
  try {
    page.getElementById("ln-format").value = "bip39";
    page.getElementById("ln-seed").value = BIP39_VECTOR_WORDS;
    page.getElementById("ln-pass").value = "word\uD800";
    lnDerive(page);
    // The refusal is the keyed "passphrase-utf8" error; assert the outcome,
    // not the translatable wording.
    assert.ok(page.getElementById("ln-error").textContent.length > 0, "the passphrase was not refused");
    assert.equal(page.getElementById("ln-out").innerHTML, "", "a refused passphrase derived a node key");
  } finally {
    delete globalThis.document;
  }
});

test("deriveLdkNode refuses a passphrase that is not well-formed Unicode", () => {
  // A BIP39 passphrase is UTF-8 text; a lone surrogate would silently encode
  // as U+FFFD and derive a wallet the user never typed (the station's BIP39
  // path refuses the same, #1015). Both halves of the rule: a high surrogate
  // not followed by a low one, and a low surrogate without a high one.
  for (const bad of ["\uD800", "\uDC00", "word\uD800", "word\uDC00word", "\uD800\uD800", "word\uD800A"]) {
    // The wrong side here was the test, not the derivation: the guard throws
    // the keyed refusal, but assert.throws does not hand the caught error
    // back, so the .code/.key assertions read undefined. Capture it
    // explicitly and assert on the error object itself.
    let error = null;
    try {
      deriveLdkNode(BIP39_VECTOR_WORDS, bad);
    } catch (thrown) {
      error = thrown;
    }
    assert.ok(error, `passphrase ${JSON.stringify(bad)} derived`);
    // The error's code is the stable marker; the key is translatable copy,
    // asserted only for presence (AGENTS.md).
    assert.equal(error.code, "passphrase-utf8");
    assert.ok(typeof error.key === "string" && error.key.length > 0, "the refusal carries a translation key");
  }
  // Control: a real astral character (a high+low pair) is honest UTF-8 and
  // derives exactly what the independent @scure implementation derives.
  const paired = "pass\uD83D\uDE00";
  assert.equal(deriveLdkNode(BIP39_VECTOR_WORDS, paired).nodePubKey, ldkExpected(BIP39_VECTOR_WORDS, paired).nodePubKey);
});
