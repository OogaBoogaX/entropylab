// The passphrase vault (src/js/passphrase-vault.js): the BIP39 passphrase
// field never holds the passphrase. The residue audit counted up to 14 copies
// of a typed passphrase in Chrome's page process; a field's value is text the
// page cannot erase, and the browser's editor, undo history, session restore
// and extensions all keep or read it.
//
// Contract: while the vault is active the field holds only bullets, one per
// character, whatever the edit (typed keys, deletions, a paste, an IME
// composition, an edit the browser will not let a page cancel, a value set
// by script, the on-screen keyboard); the vault holds exactly the
// passphrase, its UTF-8 bytes are the standard encoding, and the caret
// lands where the edit ends. Inactive (BIP39-word mode) the field is
// ordinary. The seed from the passphrase's bytes equals the seed from its
// text.
//
// Expected values: Node's TextEncoder (UTF-8), the BIP39 test vector with
// passphrase TREZOR (trezor/python-mnemonic vectors.json), and @scure/bip39
// as the reference for a non-ASCII passphrase.
// Run with `npm test`.
import { test } from "node:test";
import assert from "node:assert/strict";
import { runInNewContext } from "node:vm";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { mnemonicToSeedSync as scureSeed } from "@scure/bip39";
import { PassphraseVault, VAULT_MASK, bindVaultField } from "../src/js/passphrase-vault.js";
import { mnemonicToSeedSync } from "../src/js/bip39.js";

const utf8 = (text) => new TextEncoder().encode(text);
const hex = (bytes) => Buffer.from(bytes).toString("hex");
const PASSPHRASES = ["", "TREZOR", "correct horse battery staple", "Grüße, 東京! cafe\u0301 🔑🌕 naïve"];

test("the vault's UTF-8 is the standard encoding, both ways, astral characters included", () => {
  for (const text of PASSPHRASES) {
    const vault = new PassphraseVault();
    vault.setText(text);
    assert.equal(hex(vault.bytes()), hex(utf8(text)), JSON.stringify(text));
    assert.equal(vault.length, [...text].length);
    assert.equal(vault.text(), text);
    const back = new PassphraseVault();
    back.setBytes(utf8(text));
    assert.equal(back.text(), text);
    assert.equal(back.isAscii, /^[\x00-\x7f]*$/.test(text));
  }
});

test("edits land where they are made, and a long passphrase grows the store", () => {
  const vault = new PassphraseVault();
  vault.setText("ace");
  vault.replace(1, 1, "b");
  assert.equal(vault.text(), "abce");
  vault.replace(2, 3, "");
  assert.equal(vault.text(), "abe");
  vault.replace(0, 3, "🔑x");
  assert.equal(vault.text(), "🔑x");
  const long = "p".repeat(40) + "🌕".repeat(40);
  vault.replace(1, 1, long);
  assert.equal(vault.text(), "🔑" + long + "x");
  assert.equal(hex(vault.bytes()), hex(utf8("🔑" + long + "x")));
  vault.replace(1, 1 + [...long].length, "");
  assert.equal(vault.text(), "🔑x");
  vault.clear();
  assert.equal(vault.length, 0);
  assert.equal(vault.bytes().length, 0);
});

// A field that behaves as a browser's: listeners run in order, a cancelable
// beforeinput that nobody cancels is applied, and composition and
// uncancelable edits change the value before `input`.
class FakeField {
  constructor() { this.value = ""; this.selectionStart = 0; this.selectionEnd = 0; this.listeners = []; this.events = []; }
  addEventListener(type, listener) { this.listeners.push([type, listener]); }
  setSelectionRange(start, end) { this.selectionStart = start; this.selectionEnd = end; }
  dispatchEvent(event) {
    // The vault's own announcements are real Events; the edits this fake
    // makes are plain objects it can mark as cancelled.
    if (!(event instanceof Event)) {
      event.defaultPrevented = false;
      event.preventDefault = () => { event.defaultPrevented = true; };
    }
    this.events.push(event.type);
    for (const [type, listener] of this.listeners) if (type === event.type) listener(event);
    return !event.defaultPrevented;
  }
  // What the browser does with a keystroke, a paste or a deletion.
  edit(inputType, { data = null, paste = null, cancelable = true } = {}) {
    const event = { type: "beforeinput", inputType, data, cancelable, isComposing: false, dataTransfer: paste === null ? null : { getData: () => paste } };
    if (!this.dispatchEvent(event)) return false;
    const text = data ?? paste ?? "";
    let { selectionStart: start, selectionEnd: end } = this;
    if (inputType === "deleteContentBackward" && start === end) start = Math.max(0, start - 1);
    this.value = this.value.slice(0, start) + text + this.value.slice(end);
    this.setSelectionRange(start + text.length, start + text.length);
    this.dispatchEvent({ type: "input", inputType });
    return true;
  }
  type(text) { for (const char of text) this.edit("insertText", { data: char }); }
  select(start, end = start) { this.setSelectionRange(start, end); }
}
const bound = (active = () => true) => {
  const field = new FakeField(), vault = new PassphraseVault(), api = bindVaultField(field, vault, { active });
  return { field, vault, api };
};
const masked = (field, vault) => assert.equal(field.value, VAULT_MASK.repeat(vault.length), `the field holds ${JSON.stringify(field.value)}`);

test("typed keys never reach the field, and each still announces an input event", () => {
  const { field, vault } = bound();
  const typed = "Tr€zor 🔑!";
  field.type(typed);
  assert.equal(vault.text(), typed);
  masked(field, vault);
  assert.equal(field.selectionStart, [...typed].length);
  assert.equal(field.events.filter((type) => type === "input").length, [...typed].length, "the page's listeners must still hear every edit");
});

test("deletions and caret edits act on the passphrase, not on the bullets", () => {
  const { field, vault } = bound();
  field.type("passphrase");
  field.select(4);
  field.type("-");
  assert.equal(vault.text(), "pass-phrase");
  field.edit("deleteContentBackward");
  assert.equal(vault.text(), "passphrase");
  field.select(0, 4);
  field.edit("deleteContentBackward");
  assert.equal(vault.text(), "phrase");
  field.select(0);
  field.edit("deleteContentForward");
  assert.equal(vault.text(), "hrase");
  field.select(3);
  field.edit("deleteWordBackward");
  assert.equal(vault.text(), "se", "a word back, in a field of bullets, deletes to the start");
  masked(field, vault);
});

test("a paste replaces the selection, and undo has nothing to undo", () => {
  const { field, vault } = bound();
  field.type("abcdef");
  field.select(1, 5);
  field.edit("insertFromPaste", { paste: "XY" });
  assert.equal(vault.text(), "aXYf");
  assert.equal(field.selectionStart, 3);
  assert.equal(field.edit("historyUndo"), false, "undo must be cancelled: the browser's history holds nothing worth restoring");
  assert.equal(vault.text(), "aXYf");
  masked(field, vault);
});

test("an IME composition is taken into the vault when it ends", () => {
  const { field, vault } = bound();
  field.type("ab");
  field.select(1);
  field.dispatchEvent({ type: "compositionstart" });
  // The browser shows the composition in the field while it runs.
  for (const step of ["と", "とう", "東"]) {
    field.dispatchEvent({ type: "beforeinput", inputType: "insertCompositionText", data: step, cancelable: false, isComposing: true });
    field.value = "•" + step + "•";
    field.dispatchEvent({ type: "input", inputType: "insertCompositionText", isComposing: true });
  }
  field.dispatchEvent({ type: "compositionend" });
  assert.equal(vault.text(), "a東b");
  masked(field, vault);
  assert.equal(field.selectionStart, 2);
});

test("an edit the browser will not let a page cancel is moved into the vault", () => {
  const { field, vault } = bound();
  field.type("ab");
  field.select(1);
  field.edit("insertText", { data: "🔑", cancelable: false });
  assert.equal(vault.text(), "a🔑b");
  masked(field, vault);
  field.select(2);
  field.edit("deleteContentBackward", { cancelable: false });
  assert.equal(vault.text(), "ab");
  masked(field, vault);
});

test("a value set by script becomes the passphrase", () => {
  const { field, vault } = bound();
  field.value = "TREZOR";
  field.dispatchEvent({ type: "input", inputType: "insertText" });
  assert.equal(vault.text(), "TREZOR");
  masked(field, vault);
  field.value = "";
  field.dispatchEvent({ type: "input" });
  assert.equal(vault.length, 0);
});

test("the on-screen keyboard types through the vault", () => {
  const { field, vault, api } = bound();
  for (const key of "aA1! ") api.insert(key);
  api.deleteBackward();
  assert.equal(vault.text(), "aA1!");
  masked(field, vault);
  assert.equal(field.selectionStart, 4);
});

test("inactive, the field is ordinary; switching over moves the text, and back", () => {
  let active = true;
  const { field, vault, api } = bound(() => active);
  field.type("words");
  active = false;
  api.unmask();
  assert.equal(field.value, "words");
  assert.equal(vault.length, 0);
  field.type(" more");
  assert.equal(field.value, "words more", "inactive, typing must reach the field");
  api.setBytes(utf8("stored words"));
  assert.equal(field.value, "stored words");
  assert.equal(vault.length, 0, "a stored passphrase shown while inactive stayed in the vault");
  field.value = "words more";
  active = true;
  api.mask();
  assert.equal(vault.text(), "words more");
  masked(field, vault);
});

test("a stored passphrase is shown as bullets, and clearing empties both", () => {
  const { field, vault, api } = bound();
  api.setBytes(utf8("stored 🔑"));
  assert.equal(vault.text(), "stored 🔑");
  masked(field, vault);
  api.clear();
  assert.equal(vault.length, 0);
  assert.equal(field.value, "");
});

// BIP39: PBKDF2-HMAC-SHA512(NFKD(mnemonic), NFKD("mnemonic" + passphrase)).
const MNEMONIC = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const TREZOR_SEED = "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04";

test("the seed from passphrase bytes equals the seed from its text", () => {
  assert.equal(hex(mnemonicToSeedSync(MNEMONIC, utf8("TREZOR"))), TREZOR_SEED);
  assert.equal(hex(mnemonicToSeedSync(MNEMONIC, "TREZOR")), TREZOR_SEED);
  assert.equal(hex(mnemonicToSeedSync(MNEMONIC, new Uint8Array(0))), hex(scureSeed(MNEMONIC, "")));
  // Non-ASCII: composed and decomposed forms are one passphrase after NFKD.
  const composed = "café Grüße 東京", decomposed = composed.normalize("NFD");
  const expected = hex(scureSeed(MNEMONIC, composed));
  assert.equal(hex(mnemonicToSeedSync(MNEMONIC, utf8(composed))), expected);
  assert.equal(hex(mnemonicToSeedSync(MNEMONIC, utf8(decomposed))), expected);
});

// A leading U+FEFF is passphrase content, not a byte-order mark: NFKD keeps
// it, so the salt built from the passphrase's UTF-8 bytes must be the salt
// built from its text, and both must match the reference implementation,
// which hashes the BOM (audit C2-E). The byte path decodes the stored bytes
// once to normalize them; a default TextDecoder would strip the leading
// EF BB BF and derive a different wallet than the text path (and than
// Electrum and other NFKD keepers) for the same typed passphrase.
test("a leading U+FEFF in a passphrase is hashed, by bytes and by text alike", () => {
  const passphrase = "\uFEFFcorrect horse battery staple";
  const expected = hex(scureSeed(MNEMONIC, passphrase));
  assert.equal(hex(mnemonicToSeedSync(MNEMONIC, passphrase)), expected, "the text path keeps U+FEFF");
  assert.equal(hex(mnemonicToSeedSync(MNEMONIC, utf8(passphrase))), expected, "the byte path keeps U+FEFF");
  assert.notEqual(expected, hex(scureSeed(MNEMONIC, passphrase.slice(1))), "U+FEFF is hashed, not silently dropped");
});

// The key-file export writes the passphrase as text through
// hodlPassphraseText (app.js), and an imported key re-derives from that
// text. If the text loses a leading U+FEFF the export → import round trip
// opens a different wallet than the one on screen (#856 review): the slice
// below runs the shipping helpers from app.js, not a copy.
test("a U+FEFF-leading passphrase survives the key-file text seam", () => {
  const root = dirname(dirname(fileURLToPath(import.meta.url)));
  const app = readFileSync(join(root, "src/js/app.js"), "utf8");
  const slice = (name, next) => app.slice(app.indexOf(`function ${name}(`), app.indexOf(`function ${next}(`));
  const context = { TextDecoder };
  runInNewContext(slice("hodlTypedText", "hodlResultPassphrase") + slice("hodlPassphraseText", "hodlStorePassphrase"), context);
  const passphrase = "\uFEFFcorrect horse battery staple";
  const bytes = utf8(passphrase);
  const exportedText = context.hodlPassphraseText(bytes); // export: bytes → text
  assert.equal(exportedText, passphrase, "the exported text keeps the leading U+FEFF");
  const expected = hex(scureSeed(MNEMONIC, passphrase));
  assert.equal(hex(mnemonicToSeedSync(MNEMONIC, bytes)), expected, "the wallet the Key tab derives");
  assert.equal(hex(mnemonicToSeedSync(MNEMONIC, utf8(exportedText))), expected, "the wallet after export → import");
});

// Audit L9 ledger (input-parsing pass): setBytes decoded UTF-8 leniently —
// overlong forms, surrogates, code points past U+10FFFF, truncated sequences
// and stray continuation bytes were all silently accepted, and the poisoned
// store later made text() throw a RangeError. No live path feeds malformed
// bytes today; the hardening makes setBytes refuse them, so the vault's
// invariant (bytes() is the standard encoding of what text() returns) holds
// by validation, not by luck. Expected values are the WHATWG encoding rules:
// overlong forms, surrogates D800-DFFF and code points above U+10FFFF are
// not valid UTF-8.
test("setBytes refuses malformed UTF-8 instead of poisoning the store (audit L9)", () => {
  const rejects = (hexBytes, why) => {
    const vault = new PassphraseVault();
    vault.setText("keep");
    assert.throws(() => vault.setBytes(hexBytes()), why);
    assert.equal(vault.length, 0, `${why}: a refusal leaves the vault empty, not stale`);
  };
  // Overlong 2/3/4-byte encodings of '/'.
  rejects(() => Uint8Array.of(0xc0, 0xaf), "overlong 2-byte form");
  rejects(() => Uint8Array.of(0xe0, 0x80, 0xaf), "overlong 3-byte form");
  rejects(() => Uint8Array.of(0xf0, 0x80, 0x80, 0xaf), "overlong 4-byte form");
  // Surrogate range D800-DFFF and past U+10FFFF.
  rejects(() => Uint8Array.of(0xed, 0xa0, 0x80), "a UTF-8-encoded surrogate is not a code point");
  rejects(() => Uint8Array.of(0xf4, 0x90, 0x80, 0x80), "above U+10FFFF");
  // Structure errors.
  rejects(() => Uint8Array.of(0xc3), "a truncated sequence");
  rejects(() => Uint8Array.of(0xc3, 0x28), "a broken continuation byte");
  rejects(() => Uint8Array.of(0xf5, 0x80, 0x80, 0x80), "a lead byte beyond 0xf4");
  rejects(() => Uint8Array.of(0x80), "a stray continuation byte");
  // Canonical multi-byte input still round-trips through bytes() and text().
  const vault = new PassphraseVault();
  vault.setBytes(utf8("Grüße 🔑"));
  assert.equal(vault.text(), "Grüße 🔑");
  assert.equal(hex(vault.bytes()), hex(utf8("Grüße 🔑")));
});

// The vault's ENTRY paths take DOM strings, and a Windows WTF-16 clipboard
// can deliver a lone surrogate. The intake used to store it as a code point,
// bytes() then emitted the WTF-8 form (ED A0 80), and the strict setBytes
// refused the vault's own bytes — uncaught, out of hodlShowStoredPassphrase
// during a tab restore (app.js). TextEncoder's contract is the authority the
// rest of the app already runs on: a lone surrogate encodes as U+FFFD
// (EF BF BD), so the intake substitutes it and bytes() only ever produces
// what setBytes accepts (Kimi K3's follow-up review on audit L9).
test("lone surrogates never enter the vault: the intake matches TextEncoder's contract", () => {
  // Array.from splits an unpaired surrogate into its own point and joins a
  // pair into one, so anything surrogate-shaped at intake is unpaired.
  const vault = new PassphraseVault();
  vault.setText("a\uD800b");
  assert.equal(vault.length, 3, "the lone surrogate is one stored point");
  assert.equal(hex(vault.bytes()), hex(utf8("a\uFFFDb")), "bytes() encodes U+FFFD, never the WTF-8 form");
  assert.equal(vault.text(), "a\uFFFDb");
  assert.doesNotThrow(() => vault.setBytes(vault.bytes()), "the vault must consume its own bytes()");
  assert.equal(vault.text(), "a\uFFFDb", "the round trip through bytes() preserves the store");
  // The same contract on replace(), the typing / paste / composition path.
  const pasted = new PassphraseVault();
  pasted.setText("keep");
  pasted.replace(4, 4, "\uDEAD");
  assert.equal(hex(pasted.bytes()), hex(utf8("keep\uFFFD")), "a surrogate pasted mid-text");
  assert.doesNotThrow(() => pasted.setBytes(pasted.bytes()));
  assert.equal(pasted.text(), "keep\uFFFD");
});

// The decode accumulates the passphrase as code points before the store is
// touched; the success path zeroes that array, so a refusal must not abandon
// the decoded-so-far bytes un-wiped. Wipe discipline here is checked at the
// source, as the residue guards do (the array is a local — its state is not
// observable from outside).
test("every setBytes refusal wipes the code points decoded so far (source guard)", () => {
  const source = readFileSync(join(dirname(fileURLToPath(import.meta.url)), "..", "src/js/passphrase-vault.js"), "utf8");
  const setBytes = source.slice(source.indexOf("setBytes(bytes)"), source.indexOf("get isAscii"));
  assert.ok(setBytes.includes("setBytes(bytes)"), "the setBytes source was found");
  assert.match(setBytes, /catch/, "the decode loop has no refusal path that wipes points");
  assert.equal((setBytes.match(/points\.fill\(0\)/g) || []).length, 2, "exactly the success path and the refusal path zero points");
});
