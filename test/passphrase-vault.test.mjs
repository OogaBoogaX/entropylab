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

// Red-team F2: compositionend cannot tell a committed composition from a
// cancelled one. Esc (or a blur) makes the browser restore what the field
// held at compositionstart — the mask — and the handler used to read that
// back as the committed text: over a selection the "inserted" text is the
// mask's own bullets, and they went into the vault. The mask is one bullet
// per character either way, so the passphrase silently gained U+2022.
test("a cancelled composition over a selection leaves the vault unchanged", () => {
  const { field, vault } = bound();
  field.type("ab");
  field.select(0, 1);
  field.dispatchEvent({ type: "compositionstart" });
  // The browser shows the composition over the selection while it runs.
  field.dispatchEvent({ type: "beforeinput", inputType: "insertCompositionText", data: "と", cancelable: false, isComposing: true });
  field.value = "と•";
  field.dispatchEvent({ type: "input", inputType: "insertCompositionText", isComposing: true });
  // Esc: the browser restores what the field held at compositionstart.
  field.value = VAULT_MASK.repeat(2);
  field.dispatchEvent({ type: "compositionend" });
  assert.equal(vault.text(), "ab", "a cancelled composition commits nothing");
  assert.ok(!vault.text().includes(VAULT_MASK), "a mask bullet must never enter the vault");
  masked(field, vault);
});

test("a composition committed over a selection still inserts its text", () => {
  const { field, vault } = bound();
  field.type("ab");
  field.select(0, 1);
  field.dispatchEvent({ type: "compositionstart" });
  field.dispatchEvent({ type: "beforeinput", inputType: "insertCompositionText", data: "東", cancelable: false, isComposing: true });
  field.value = "東•";
  field.dispatchEvent({ type: "input", inputType: "insertCompositionText", isComposing: true });
  field.dispatchEvent({ type: "compositionend" });
  assert.equal(vault.text(), "東b");
  masked(field, vault);
  assert.equal(field.selectionStart, 1);
});

test("a bullet committed at a collapsed caret is the user's own character and is kept", () => {
  const { field, vault } = bound();
  field.type("ab");
  field.select(1, 1);
  field.dispatchEvent({ type: "compositionstart" });
  field.dispatchEvent({ type: "beforeinput", inputType: "insertCompositionText", data: "•", cancelable: false, isComposing: true });
  field.value = "•••";
  field.dispatchEvent({ type: "input", inputType: "insertCompositionText", isComposing: true });
  field.dispatchEvent({ type: "compositionend" });
  assert.equal(vault.text(), "a•b");
  masked(field, vault);
});

// PR #1027 review (all five reviewers): compositionend could not tell a
// committed composition of bullets from a cancelled one — over a selection
// both leave the field showing the mask — so a deliberate bullet committed
// over a selection was discarded and the vault silently kept the old
// passphrase. The CompositionEvent's data settles it: on a cancel the
// browser restores the masked field and the data is empty or the IME's own
// composing text, never the restored bullets, so data === text (non-empty)
// proves a commit.
test("bullets committed over a selection are the user's own text", () => {
  const { field, vault } = bound();
  field.type("ab");
  field.select(0, 1);
  field.dispatchEvent({ type: "compositionstart" });
  field.dispatchEvent({ type: "beforeinput", inputType: "insertCompositionText", data: "••", cancelable: false, isComposing: true });
  field.value = "•••"; // two committed bullets replaced the selected one
  field.dispatchEvent({ type: "input", inputType: "insertCompositionText", isComposing: true });
  field.dispatchEvent({ type: "compositionend", data: "••" });
  assert.equal(vault.text(), "••b");
  masked(field, vault);
});

test("a bullet replacing a selected character one for one cannot be told from a cancel and is not taken", () => {
  const { field, vault } = bound();
  field.type("ab");
  field.select(0, 1);
  field.dispatchEvent({ type: "compositionstart" });
  field.dispatchEvent({ type: "beforeinput", inputType: "insertCompositionText", data: "•", cancelable: false, isComposing: true });
  field.value = "••"; // identical to the field at compositionstart
  field.dispatchEvent({ type: "input", inputType: "insertCompositionText", isComposing: true });
  // A cancel of a composing "•" ends the same way, so nothing is guessed in.
  field.dispatchEvent({ type: "compositionend", data: "•" });
  assert.equal(vault.text(), "ab");
  masked(field, vault);
});

test("a composition cancelled with empty data commits nothing", () => {
  const { field, vault } = bound();
  field.type("ab");
  field.select(0, 1);
  field.dispatchEvent({ type: "compositionstart" });
  field.dispatchEvent({ type: "beforeinput", inputType: "insertCompositionText", data: "と", cancelable: false, isComposing: true });
  field.value = "と•";
  field.dispatchEvent({ type: "input", inputType: "insertCompositionText", isComposing: true });
  // Esc: the browser restores the mask and reports empty data.
  field.value = VAULT_MASK.repeat(2);
  field.dispatchEvent({ type: "compositionend", data: "" });
  assert.equal(vault.text(), "ab");
  assert.ok(!vault.text().includes(VAULT_MASK), "a mask bullet must never enter the vault");
  masked(field, vault);
});

test("a cancel whose data is the IME's own text still commits nothing", () => {
  const { field, vault } = bound();
  field.type("ab");
  field.select(0, 1);
  field.dispatchEvent({ type: "compositionstart" });
  field.dispatchEvent({ type: "beforeinput", inputType: "insertCompositionText", data: "と", cancelable: false, isComposing: true });
  field.value = "と•";
  field.dispatchEvent({ type: "input", inputType: "insertCompositionText", isComposing: true });
  // Esc: the field shows the restored mask; the event still carries the
  // IME's composing text, which is not what the field holds.
  field.value = VAULT_MASK.repeat(2);
  field.dispatchEvent({ type: "compositionend", data: "と" });
  assert.equal(vault.text(), "ab");
  masked(field, vault);
});

test("an Android-style commit applies the field's text when the event's data differs", () => {
  const { field, vault } = bound();
  field.type("ab");
  field.select(1);
  field.dispatchEvent({ type: "compositionstart" });
  field.dispatchEvent({ type: "beforeinput", inputType: "insertCompositionText", data: "one", cancelable: false, isComposing: true });
  field.value = "•one•";
  field.dispatchEvent({ type: "input", inputType: "insertCompositionText", isComposing: true });
  // Autocorrect rewrote the word: the event's data is not what the field holds.
  field.dispatchEvent({ type: "compositionend", data: "on" });
  assert.equal(vault.text(), "aoneb");
  masked(field, vault);
});

// Nemotron 3 Ultra on PR #1027: a composition started in vault mode survived
// a switch to word mode and back, and its late compositionend was applied to
// the re-masked field — mask bullets went into the vault. The switch ends
// any composition.
test("a compositionend from before a mode switch is ignored", () => {
  let active = true;
  const { field, vault, api } = bound(() => active);
  field.type("words");
  field.select(2);
  field.dispatchEvent({ type: "compositionstart" });
  field.dispatchEvent({ type: "beforeinput", inputType: "insertCompositionText", data: "と", cancelable: false, isComposing: true });
  field.value = "••と•••";
  field.dispatchEvent({ type: "input", inputType: "insertCompositionText", isComposing: true });
  active = false;
  api.unmask();
  assert.equal(field.value, "words");
  // Setting .value moved the caret to the end of the field.
  field.select(field.value.length);
  field.type(" more");
  active = true;
  api.mask();
  assert.equal(vault.text(), "words more");
  // The browser fires the compositionend the switch interrupted.
  field.dispatchEvent({ type: "compositionend", data: "と" });
  assert.equal(vault.text(), "words more");
  masked(field, vault);
});

test("a compositionend that arrives after a blur still commits, and the field is masked again", () => {
  const { field, vault } = bound();
  field.type("ab");
  field.select(1);
  field.dispatchEvent({ type: "compositionstart" });
  field.dispatchEvent({ type: "beforeinput", inputType: "insertCompositionText", data: "と", cancelable: false, isComposing: true });
  field.value = "•と•";
  field.dispatchEvent({ type: "input", inputType: "insertCompositionText", isComposing: true });
  field.dispatchEvent({ type: "blur" });
  // Some browsers fire the compositionend only after the blur. Ignoring it
  // would leave "と" showing unmasked in the field and missing from the vault.
  field.dispatchEvent({ type: "compositionend", data: "と" });
  assert.equal(vault.text(), "aとb");
  masked(field, vault);
});

// Reviews of #1027 (GLM 5.3, Kimi K3, DeepSeek V4.1): a change made to the
// vault from outside the field during an open composition must end it, or
// the late compositionend applies stale indices to the new contents.
test("a stored passphrase loaded during a composition ends it: the late compositionend is ignored", () => {
  const { field, vault, api } = bound();
  field.type("ab");
  field.select(1);
  field.dispatchEvent({ type: "compositionstart" });
  api.setBytes(new TextEncoder().encode("new"));
  field.dispatchEvent({ type: "compositionend", data: "と" });
  assert.equal(vault.text(), "new");
  masked(field, vault);
});

test("an on-screen keyboard edit during a composition ends it", () => {
  const { field, vault, api } = bound();
  field.type("ab");
  field.select(2);
  field.dispatchEvent({ type: "compositionstart" });
  api.insert("c");
  field.dispatchEvent({ type: "compositionend", data: "と" });
  assert.equal(vault.text(), "abc");
  masked(field, vault);
});

test("an empty composition committed over a selection deletes the selection", () => {
  const { field, vault } = bound();
  field.type("ab");
  field.select(0, 1);
  field.dispatchEvent({ type: "compositionstart" });
  // The composing text was deleted and the empty composition committed: the
  // field lost the selected character.
  field.value = VAULT_MASK;
  field.dispatchEvent({ type: "compositionend", data: "" });
  assert.equal(vault.text(), "b");
  masked(field, vault);
});

test("without event data, mask bullets read back over a selection are never taken", () => {
  const { field, vault } = bound();
  field.type("abc");
  field.select(0, 2);
  field.dispatchEvent({ type: "compositionstart" });
  // A browser without CompositionEvent.data, whose field shows one bullet
  // where two characters were selected.
  field.value = VAULT_MASK.repeat(2);
  field.dispatchEvent({ type: "compositionend" });
  assert.equal(vault.text(), "abc");
  masked(field, vault);
});

test("an on-screen key during a composition lands where the composition began, not at the composing caret", () => {
  const { field, vault, api } = bound();
  field.type("ab");
  field.select(1);
  field.dispatchEvent({ type: "compositionstart" });
  field.dispatchEvent({ type: "beforeinput", inputType: "insertCompositionText", data: "とう", cancelable: false, isComposing: true });
  field.value = "•とう•";
  field.setSelectionRange(3, 3);
  field.dispatchEvent({ type: "input", inputType: "insertCompositionText", isComposing: true });
  api.insert("c");
  assert.equal(vault.text(), "acb");
  masked(field, vault);
  field.dispatchEvent({ type: "compositionend", data: "とう" });
  assert.equal(vault.text(), "acb", "the abandoned composition is not applied later");
});

test("a browser edit in the middle of a composition resets the field to the vault instead of splicing", () => {
  const { field, vault } = bound();
  field.type("ab");
  field.select(1);
  field.dispatchEvent({ type: "compositionstart" });
  field.value = "•と•";
  field.dispatchEvent({ type: "input", inputType: "insertCompositionText", isComposing: true });
  // An autofill lands mid-composition.
  field.value = "secret";
  field.dispatchEvent({ type: "input", inputType: "insertReplacementText" });
  assert.equal(vault.text(), "ab");
  masked(field, vault);
  field.dispatchEvent({ type: "compositionend", data: "と" });
  assert.equal(vault.text(), "ab");
  masked(field, vault);
});

// Reviews of #1027 at f9480446 (GLM 5.3, Kimi K3, Muse Spark, DeepSeek V4.1).
test("switching back to the vault never overwrites the plain text it is about to store", () => {
  let vaultMode = true;
  const { field, vault, api } = bound(() => vaultMode);
  field.type("ab");
  field.select(1);
  field.dispatchEvent({ type: "compositionstart" });
  // The page sets the field's text and re-masks while that composition is
  // still open: mask() must store the text it was given, not a re-rendered mask.
  field.value = "plain passphrase";
  api.mask();
  assert.equal(vault.text(), "plain passphrase");
  masked(field, vault);
});

test("a cancelable edit in the middle of a composition applies to the restored selection, once", () => {
  const { field, vault } = bound();
  field.type("ab");
  field.select(1);
  field.dispatchEvent({ type: "compositionstart" });
  field.value = "•と•";
  field.setSelectionRange(2, 2);
  field.dispatchEvent({ type: "input", inputType: "insertCompositionText", isComposing: true });
  field.dispatchEvent({ type: "beforeinput", inputType: "insertText", data: "x", cancelable: true, isComposing: false });
  assert.equal(vault.text(), "axb");
  masked(field, vault);
  field.dispatchEvent({ type: "compositionend", data: "と" });
  assert.equal(vault.text(), "axb", "the abandoned composition is not applied later");
});

test("an on-screen key during a composition over a selection replaces that selection", () => {
  const { field, vault, api } = bound();
  field.type("abc");
  field.select(0, 2);
  field.dispatchEvent({ type: "compositionstart" });
  field.value = "と•";
  field.setSelectionRange(1, 1);
  field.dispatchEvent({ type: "input", inputType: "insertCompositionText", isComposing: true });
  api.insert("x");
  assert.equal(vault.text(), "xc");
  masked(field, vault);
});

test("an IME that keeps composing after an outside edit abandoned its composition never reaches the vault", () => {
  const { field, vault, api } = bound();
  field.type("ab");
  field.select(1);
  field.dispatchEvent({ type: "compositionstart" });
  field.value = "•と•";
  field.dispatchEvent({ type: "input", inputType: "insertCompositionText", isComposing: true });
  api.insert("c");
  assert.equal(vault.text(), "acb");
  // The IME goes on composing in the now-masked field, then ends.
  field.value = "•とう••";
  field.dispatchEvent({ type: "input", inputType: "insertCompositionText", isComposing: true });
  assert.equal(vault.text(), "acb", "composing text after the abandonment is never stored");
  masked(field, vault);
  field.value = "•とう••";
  field.dispatchEvent({ type: "compositionend", data: "とう" });
  assert.equal(vault.text(), "acb");
  masked(field, vault);
});

// Reviews of this fix (GLM 5.3, Kimi K3): composition text arriving after an
// abandonment went through beforeinput, which set `pending`, and then the
// input handler re-masked the field and returned with `pending` still set,
// so the next autofill was spliced at that stale caret ("abcret").
test("composing text after an abandonment leaves no stale caret for the next browser edit", () => {
  const { field, vault } = bound();
  field.type("ab");
  field.dispatchEvent({ type: "beforeinput", inputType: "insertCompositionText", data: "x", cancelable: false, isComposing: true });
  field.value = "••x";
  field.dispatchEvent({ type: "input", inputType: "insertCompositionText", isComposing: true });
  assert.equal(vault.text(), "ab", "composing text with no open composition is never stored");
  masked(field, vault);
  // A password manager fills the field: an input event with no beforeinput.
  field.value = "secret";
  field.dispatchEvent({ type: "input", inputType: "insertText" });
  assert.equal(vault.text(), "secret");
  masked(field, vault);
  // The same after a compositionend that arrives with no open composition.
  field.dispatchEvent({ type: "beforeinput", inputType: "insertCompositionText", data: "y", cancelable: false, isComposing: true });
  field.dispatchEvent({ type: "compositionend", data: "y" });
  field.value = "hunter2";
  field.dispatchEvent({ type: "input", inputType: "insertText" });
  assert.equal(vault.text(), "hunter2");
  masked(field, vault);
});

// DeepSeek V4.1 red-team of this fix: the same stale caret, reached by a
// composition that began while the field was inactive (word mode), so
// compositionstart was ignored and no composition is open once it is masked.
test("a composition begun while inactive leaves no stale caret once the field is masked", () => {
  let active = false;
  const { field, vault, api } = bound(() => active);
  field.value = "ab";
  field.dispatchEvent({ type: "compositionstart" });
  active = true;
  api.mask();
  field.value = "••と";
  field.setSelectionRange(3, 3);
  field.dispatchEvent({ type: "beforeinput", inputType: "insertCompositionText", data: "と", cancelable: false, isComposing: true });
  field.dispatchEvent({ type: "input", inputType: "insertCompositionText", isComposing: true });
  field.dispatchEvent({ type: "compositionend", data: "と" });
  assert.equal(vault.text(), "ab");
  field.value = "secret";
  field.dispatchEvent({ type: "input", inputType: "insertText" });
  assert.equal(vault.text(), "secret");
  masked(field, vault);
});

// DeepSeek V4.1 red-team of 34fa546: Input Events Level 2 has four
// composition input types; Safari fires deleteByComposition and
// insertFromComposition with isComposing false. Only two were recognised, so
// after an abandonment such an input fell through to the "set by script"
// path and stored the field's mask bullets as the passphrase.
for (const inputType of ["deleteByComposition", "insertFromComposition", "deleteCompositionText"]) {
  test(`${inputType} after an abandonment never reaches the vault`, () => {
    const { field, vault, api } = bound();
    field.type("ab");
    field.select(1);
    field.dispatchEvent({ type: "compositionstart" });
    field.value = "•と•";
    field.dispatchEvent({ type: "input", inputType: "insertCompositionText", isComposing: true });
    api.insert("c");
    assert.equal(vault.text(), "acb");
    field.dispatchEvent({ type: "beforeinput", inputType, data: null, cancelable: true, isComposing: false });
    assert.equal(vault.text(), "acb", "a composition-type beforeinput is not applied as an edit");
    field.value = "•とう••";
    field.dispatchEvent({ type: "input", inputType, isComposing: false });
    assert.equal(vault.text(), "acb", "composition input is never stored");
    assert.ok(!vault.text().includes(VAULT_MASK), "a mask bullet must never enter the vault");
    masked(field, vault);
  });
}

// DeepSeek V4.1 red-team of 947698a: a composition-type beforeinput saved the
// caret and returned. When no input event followed (another listener
// prevented it, or the browser made no change), that caret stayed, and the
// next autofill was spliced at it: "ab" with the caret at 1 became "aecreb".
for (const inputType of ["insertCompositionText", "deleteCompositionText", "insertFromComposition", "deleteByComposition"]) {
  for (const isComposing of [false, true]) {
    for (const prevented of [true, false]) {
      test(`a ${prevented ? "prevented" : "no-op"} ${inputType} (isComposing ${isComposing}) with no input leaves no stale caret`, () => {
        const { field, vault } = bound();
        field.type("ab");
        field.select(1);
        if (prevented) field.addEventListener("beforeinput", (event) => { if (event.inputType === inputType) event.preventDefault(); });
        field.dispatchEvent({ type: "beforeinput", inputType, data: "x", cancelable: true, isComposing });
        assert.equal(vault.text(), "ab", "a composition-type beforeinput is not applied as an edit");
        // A password manager fills the field: an input event with no beforeinput.
        field.value = "secret";
        field.dispatchEvent({ type: "input", inputType: "insertText" });
        assert.equal(vault.text(), "secret");
        masked(field, vault);
      });
    }
  }
}

// GLM 5.3 review of 0f3a854: WebKit dictation and autocorrect can send a
// composition-type edit with no composition session at all. The head dropped
// it (rock spliced it); with a non-composition inputType on its input event,
// the "set by script" path stored the edited mask, bullets included.
for (const inputType of ["insertCompositionText", "insertFromComposition"]) {
  test(`an ${inputType} edit outside any composition is spliced into the vault`, () => {
    const { field, vault } = bound();
    field.type("ab");
    field.select(1);
    field.dispatchEvent({ type: "beforeinput", inputType, data: "x", cancelable: false, isComposing: false });
    field.value = "•x•"; // the browser inserted into the masked field
    field.setSelectionRange(2, 2);
    field.dispatchEvent({ type: "input", inputType, isComposing: false });
    assert.equal(vault.text(), "axb");
    masked(field, vault);
  });
}

test("a composition-type edit reported by a plain input event never stores the mask", () => {
  const { field, vault } = bound();
  field.type("ab");
  field.select(1);
  field.dispatchEvent({ type: "beforeinput", inputType: "insertCompositionText", data: "x", cancelable: false, isComposing: false });
  field.value = "•x•";
  field.dispatchEvent({ type: "input", inputType: "insertText" });
  assert.ok(!vault.text().includes(VAULT_MASK), "a mask bullet must never enter the vault");
  assert.equal(vault.text(), "ab", "an edit that cannot be placed leaves the vault as it was");
  masked(field, vault);
});

test("a composition-type edit while the browser's composition is still open is not spliced", () => {
  // An outside edit abandoned the vault's composition, but the browser's own
  // session runs until compositionend: its edits stay out of the vault.
  const { field, vault, api } = bound();
  field.type("ab");
  field.select(1);
  field.dispatchEvent({ type: "compositionstart" });
  api.insert("c");
  field.dispatchEvent({ type: "beforeinput", inputType: "insertCompositionText", data: "x", cancelable: false, isComposing: false });
  field.value = "••x•";
  field.dispatchEvent({ type: "input", inputType: "insertCompositionText", isComposing: false });
  assert.equal(vault.text(), "acb");
  masked(field, vault);
});

// GLM 5.3 review of 901a522: the composition caret slot outlived a no-op
// composition beforeinput (and api vault changes), so a later input-only
// edit reported with a composition inputType was spliced at it.
for (const inputType of ["insertCompositionText", "insertFromComposition"]) {
  test(`a composition-typed ${inputType} fill after a no-op composition beforeinput replaces the vault`, () => {
    const { field, vault } = bound();
    field.type("ab");
    field.select(1);
    field.dispatchEvent({ type: "beforeinput", inputType, data: "x", cancelable: true, isComposing: false });
    field.value = "secret";
    field.dispatchEvent({ type: "input", inputType, isComposing: false });
    assert.equal(vault.text(), "secret");
    masked(field, vault);
  });
}

test("a stored passphrase loaded after a composition beforeinput leaves no caret for the next fill", () => {
  const { field, vault, api } = bound();
  field.type("ab");
  field.select(1);
  field.dispatchEvent({ type: "beforeinput", inputType: "insertFromComposition", data: "x", cancelable: true, isComposing: false });
  api.setBytes(new TextEncoder().encode("newpass"));
  field.value = "secret";
  field.dispatchEvent({ type: "input", inputType: "insertFromComposition", isComposing: false });
  assert.equal(vault.text(), "secret");
  masked(field, vault);
});

test("with no caret saved, a value holding the mask over a non-empty vault is not taken as the passphrase", () => {
  const { field, vault } = bound();
  field.type("ab");
  field.value = "•z•";
  field.dispatchEvent({ type: "input", inputType: "insertReplacementText" });
  assert.equal(vault.text(), "ab");
  masked(field, vault);
  // Into an empty field nothing was masked, so a bullet is the source's own.
  const empty = bound();
  empty.field.value = "a•b";
  empty.field.dispatchEvent({ type: "input", inputType: "insertText" });
  assert.equal(empty.vault.text(), "a•b");
});

// Red-team F5: a prevented beforeinput (Enter, Ctrl+Z) used to return with
// `pending` still holding the caret. The next edit the browser makes by
// itself — an autofill, a password manager, an Android-IME commit — arrives
// as `input` with no beforeinput and was spliced into the vault at those
// stale indices instead of replacing it: an autofilled "secret" became
// "aecreb" while the mask showed the expected six bullets.
test("a prevented Enter or undo leaves no stale caret for the next browser edit", () => {
  const { field, vault } = bound();
  field.type("ab");
  field.select(1);
  assert.equal(field.edit("insertParagraph"), false, "Enter is prevented: a single-line field");
  assert.equal(vault.text(), "ab");
  // A password manager fills the field: an input event with no beforeinput.
  field.value = "secret";
  field.dispatchEvent({ type: "input", inputType: "insertText" });
  assert.equal(vault.text(), "secret");
  masked(field, vault);
  field.select(2);
  assert.equal(field.edit("historyUndo"), false, "undo is prevented: the browser's history holds nothing");
  assert.equal(vault.text(), "secret");
  field.value = "hunter2";
  field.dispatchEvent({ type: "input", inputType: "insertText" });
  assert.equal(vault.text(), "hunter2");
  masked(field, vault);
  assert.ok(!vault.text().includes(VAULT_MASK), "a mask bullet must never enter the vault");
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
  // A lead byte that is not a legal start: 0x80-0xBF is a continuation,
  // 0xC0/0xC1 is always overlong, and 0xF5-0xFF starts past U+10FFFF (or a
  // 5/6-byte form). `9f bf` used to decode as U+07FF.
  rejects(() => Uint8Array.of(0x9f, 0xbf), "a continuation byte in the lead position");
  rejects(() => Uint8Array.of(0xbf, 0xbf), "a downward-range lead byte");
  rejects(() => Uint8Array.of(0xc1, 0xbf), "0xC1 can only spell an overlong form");
  rejects(() => Uint8Array.of(0xf9, 0xbf, 0xbf, 0xbf), "a lead byte beyond 0xf4");
  rejects(() => Uint8Array.of(0xfc, 0x80, 0x80, 0x80), "a 6-byte-form lead byte");
  // Canonical multi-byte input still round-trips through bytes() and text().
  const vault = new PassphraseVault();
  vault.setBytes(Uint8Array.of(0xc3, 0xa9));
  assert.equal(vault.text(), "\u00e9", "a canonical 2-byte form must still be accepted");
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
