// Passphrase vault: the BIP39 passphrase field keeps the passphrase out of
// its value. This reduces copies; it does not remove them.
//
// A field's value is text the page cannot erase, and the browser copies it
// on every keystroke: its editor, undo history and session restore, the
// accessibility tree, extensions that read .value, and every handler that
// reads it again. The residue audit (2026-10-03) counted up to 14 copies of
// a typed passphrase in Chrome's page process, and 2 more in its browser
// process.
//
// Here the field shows one bullet per character and nothing else. Each edit
// is caught as `beforeinput` and applied to the vault, which keeps the
// passphrase as Unicode code points in a typed array: it can be wiped, and it
// gives UTF-8 bytes without ever building a string (the encoder below is
// hand-written for that reason). An edit the browser does not let a page
// cancel (an IME composition, an Android keyboard's word) lands in the field,
// is read back once, moved into the vault, and masked again.
//
// What still reaches text: each typed key arrives as a one-character string
// (`event.data`), a paste or composition arrives as its text once, and
// showing the passphrase (`text()`) builds it. Deriving does not: an ASCII
// passphrase goes to PBKDF2 as bytes, and only a non-ASCII one is decoded,
// once, for its NFKD normalization.

export const VAULT_MASK = "•";

const codePoints = (text) => Array.from(String(text ?? ""), (char) => {
  const point = char.codePointAt(0);
  // Array.from already joins a surrogate pair into one point, so anything
  // surrogate-shaped here is unpaired — a lone surrogate from a WTF-16
  // clipboard or composition. It has no UTF-8 encoding: bytes() would emit
  // the WTF-8 form (ED A0 80), which setBytes refuses, and a tab restore
  // would then throw on the vault's own bytes. TextEncoder's contract is the
  // one the rest of the app runs on: substitute U+FFFD, so bytes() only ever
  // produces what setBytes accepts (follow-up review on audit L9).
  return point >= 0xd800 && point <= 0xdfff ? 0xfffd : point;
});

export class PassphraseVault {
  #points = new Uint32Array(32);
  #length = 0;

  get length() { return this.#length; }

  // Replaces the characters [start, end) with `text`, clamped to the vault.
  replace(start, end, text = "") {
    start = Math.max(0, Math.min(start, this.#length));
    end = Math.max(start, Math.min(end, this.#length));
    const insert = codePoints(text), old = this.#points, length = this.#length - (end - start) + insert.length;
    if (length > old.length) {
      // Grow into a new store and wipe the old one.
      const points = new Uint32Array(Math.max(length, old.length * 2));
      points.set(old.subarray(0, start));
      points.set(old.subarray(end, this.#length), start + insert.length);
      points.set(insert, start);
      old.fill(0);
      this.#points = points;
    } else {
      old.copyWithin(start + insert.length, end, this.#length); // handles the overlap
      old.set(insert, start);
      if (length < this.#length) old.fill(0, length, this.#length);
    }
    this.#length = length;
  }

  clear() {
    this.#points.fill(0);
    this.#length = 0;
  }

  setText(text) {
    this.clear();
    this.replace(0, 0, text);
  }

  // From UTF-8 bytes (a key tab's stored passphrase), without a string.
  // Strictly: overlong forms, surrogates, code points above U+10FFFF,
  // truncated sequences and stray continuation bytes are refused before the
  // store is touched — a poisoned store would only surface later as a
  // text() RangeError (audit L9). The refusal leaves the vault empty.
  setBytes(bytes) {
    this.clear();
    const points = [];
    try {
      const data = bytes ?? new Uint8Array();
      for (let i = 0; i < data.length;) {
        const b = data[i];
        // The lead byte itself must be a legal start: C0/C1 would spell an
        // overlong two-byte form, 80-BF is a stray continuation, and F5-FF
        // starts a code point above U+10FFFF (or a 5/6-byte form). Checking
        // only the payload and range let `9f bf` decode as U+07FF.
        const size = b < 0x80 ? 1 : b >= 0xc2 && b <= 0xdf ? 2 : b >= 0xe0 && b <= 0xef ? 3 : b >= 0xf0 && b <= 0xf4 ? 4 : 0;
        if (!size) throw new Error("The stored passphrase is not valid UTF-8.");
        if (i + size > data.length) throw new Error("The stored passphrase is not valid UTF-8 (truncated sequence).");
        let point, min;
        if (size === 1) {
          point = b;
        } else {
          point = b & (0xff >> (size + 1));
          // Continuation range, narrowed by the lead on the FIRST byte only:
          // E0/F0 and F4 forbid the overlong and beyond-U+10FFFF forms their
          // ranges would otherwise spell; later continuations are plain.
          const low = b === 0xe0 ? 0xa0 : b === 0xf0 ? 0x90 : 0x80;
          const high = b === 0xed ? 0x9f : b === 0xf4 ? 0x8f : 0xbf;
          for (let k = 1; k < size; k++) {
            const c = data[i + k];
            const cLow = k === 1 ? low : 0x80, cHigh = k === 1 ? high : 0xbf;
            if (c < cLow || c > cHigh) throw new Error("The stored passphrase is not valid UTF-8.");
            point = (point << 6) | (c & 0x3f);
          }
          min = size === 2 ? 0x80 : size === 3 ? 0x800 : 0x10000;
          if (point < min || point > 0x10ffff) throw new Error("The stored passphrase is not valid UTF-8.");
        }
        points.push(point);
        i += size;
      }
    } catch (error) {
      points.fill(0); // the code points decoded so far are passphrase material
      throw error;
    }
    if (points.length > this.#points.length) this.#points = new Uint32Array(points.length);
    this.#points.set(points);
    this.#length = points.length;
    points.fill(0);
  }

  get isAscii() {
    for (let i = 0; i < this.#length; i++) if (this.#points[i] >= 0x80) return false;
    return true;
  }

  // The passphrase as UTF-8 bytes: a fresh array the caller owns and wipes.
  bytes() {
    let size = 0;
    for (let i = 0; i < this.#length; i++) {
      const p = this.#points[i];
      size += p < 0x80 ? 1 : p < 0x800 ? 2 : p < 0x10000 ? 3 : 4;
    }
    const out = new Uint8Array(size);
    let o = 0;
    for (let i = 0; i < this.#length; i++) {
      const p = this.#points[i];
      if (p < 0x80) out[o++] = p;
      else if (p < 0x800) { out[o++] = 0xc0 | (p >> 6); out[o++] = 0x80 | (p & 0x3f); }
      else if (p < 0x10000) { out[o++] = 0xe0 | (p >> 12); out[o++] = 0x80 | ((p >> 6) & 0x3f); out[o++] = 0x80 | (p & 0x3f); }
      else { out[o++] = 0xf0 | (p >> 18); out[o++] = 0x80 | ((p >> 12) & 0x3f); out[o++] = 0x80 | ((p >> 6) & 0x3f); out[o++] = 0x80 | (p & 0x3f); }
    }
    return out;
  }

  // The passphrase as text: only to show it, or for a tool that takes text.
  // Built in chunks: spreading the whole store as call arguments throws a
  // RangeError past the engine's argument limit (a large paste, 100k+ code
  // points), which left unmask() and plain-mode setBytes failing before
  // vault.clear() ran.
  text() {
    let out = "";
    for (let i = 0; i < this.#length; i += 4096) {
      out += String.fromCodePoint(...this.#points.subarray(i, Math.min(i + 4096, this.#length)));
    }
    return out;
  }

  mask() {
    return VAULT_MASK.repeat(this.#length);
  }
}

// Binds `field` to `vault`. While `active()` says so, the field holds only
// the mask; otherwise the handlers stand aside and the field is ordinary.
// Every change to the vault is announced as an `input` event on the field,
// so the page's own listeners run as they did for typing.
// The four composition input types of Input Events Level 2. Safari fires
// deleteByComposition and insertFromComposition with isComposing false, so a
// check on isComposing or on "insertCompositionText" alone misses them.
const COMPOSITION_INPUT_TYPES = new Set(["insertCompositionText", "deleteCompositionText", "insertFromComposition", "deleteByComposition"]);
const isCompositionInputType = (type) => COMPOSITION_INPUT_TYPES.has(type ?? "");
// What a single-line field makes of inserted text (Chromium's and WebKit's
// TextFieldInputType, Firefox's default editor.singleLine.pasteNewlines):
// line breaks at the end are dropped, and every other one, CRLF counted as
// one, becomes a space. The vault holds what a native password field would,
// so a passphrase pasted with its trailing newline derives the seed other
// tools derive from it, and unmask() (whose value setter strips line breaks)
// shows exactly what the vault holds.
const singleLineText = (text) => text.replace(/[\r\n]+$/, "").replace(/\r\n|[\r\n]/g, " ");

export const bindVaultField = (field, vault, { active = () => true } = {}) => {
  let pending = null, composing = null, echoing = false;
  // Whether the browser has a composition open (compositionstart to
  // compositionend), which an abandonment does not end. A composition-type
  // edit outside any browser composition (WebKit dictation and autocorrect
  // send these) is an ordinary edit: its caret goes in its own slot, which
  // only a composition-type input reads, and only while the field confirms
  // it. Every path that drops `pending` drops this slot too.
  let browserComposing = false, compositionPending = null;
  const caret = () => [field.selectionStart ?? field.value.length, field.selectionEnd ?? field.value.length];
  const render = (at, end = at) => {
    field.value = vault.mask();
    field.setSelectionRange?.(at, end);
  };
  // While a composition is open the field holds raw composing text, so its
  // caret is not a vault index: drop the composition and put the mask back
  // with the selection the composition began on.
  const abandonComposition = () => {
    const open = composing;
    composing = null;
    pending = null;
    compositionPending = null;
    if (open && active()) render(open.start, open.end);
  };
  // A change made to the vault from outside the field ends any open
  // composition without touching the field: mask() and unmask() read or set
  // field.value themselves, so a render here would overwrite the text they
  // move (it turned a plain-mode passphrase into bullets).
  const endComposition = () => {
    composing = null;
    pending = null;
    compositionPending = null;
  };
  // A saved caret still describes the field only while everything outside
  // the edited span is the mask the field held before the edit.
  const confirmsCaret = (saved, value) => {
    if (!saved) return false;
    const { start, end } = saved, mask = vault.mask(), added = value.length - (vault.length - (end - start));
    if (added < 0) return value === VAULT_MASK.repeat(value.length);
    return value.slice(0, start) === mask.slice(0, start) && value.slice(start + added) === mask.slice(end);
  };
  const echo = (inputType) => {
    echoing = true;
    try {
      field.dispatchEvent(typeof InputEvent === "function" ? new InputEvent("input", { bubbles: true, inputType, data: null }) : new Event("input", { bubbles: true }));
    } finally {
      echoing = false;
    }
  };
  const apply = (from, to, text, inputType) => {
    vault.replace(from, to, text);
    render(from + codePoints(text).length);
    echo(inputType);
  };

  field.addEventListener("beforeinput", (event) => {
    if (!active()) return;
    // A cancelable edit in the middle of a composition (the field holds raw
    // composing text, so its caret is not a vault index): drop the
    // composition first, then apply the edit to the restored selection.
    if (composing && !event.isComposing && !isCompositionInputType(event.inputType) && event.cancelable) abandonComposition();
    const type = event.inputType || "";
    // Composition text is only taken at compositionend, so no input event
    // reads a caret saved here. Saving one anyway left it stale whenever no
    // input followed (a composition input another listener prevented, or a
    // no-op one), and the next beforeinput-less edit (an autofill) was spliced
    // at it.
    compositionPending = null;
    if (event.isComposing || isCompositionInputType(type)) {
      pending = null;
      if (!event.isComposing && !browserComposing && !composing) {
        const [start, end] = caret();
        compositionPending = { start, end };
      }
      return;
    }
    const [start, end] = caret();
    pending = { start, end };
    if (!event.cancelable) return;
    event.preventDefault();
    let from = start, to = end, text = "";
    if (type.startsWith("insert")) {
      if (type === "insertLineBreak" || type === "insertParagraph") {
        pending = null; // prevented, so no input event will consume it
        return;
      }
      text = singleLineText(event.data ?? event.dataTransfer?.getData("text/plain") ?? "");
    } else if (type === "deleteContentBackward") {
      if (start === end) from = Math.max(0, start - 1);
    } else if (type === "deleteContentForward") {
      if (start === end) to = Math.min(vault.length, end + 1);
    } else if (type.startsWith("delete") && type.endsWith("Backward")) {
      // A word or line back, in a field of bullets: to the start, as a
      // password field does.
      if (start === end) from = 0;
    } else if (type.startsWith("delete") && type.endsWith("Forward")) {
      if (start === end) to = vault.length;
    } else if (!type.startsWith("delete")) {
      pending = null; // prevented, so no input event will consume it
      return; // undo, redo, formatting: nothing in a field of bullets to do
    }
    pending = null;
    apply(from, to, text, type);
  });

  field.addEventListener("compositionstart", () => {
    browserComposing = true;
    compositionPending = null;
    if (!active()) return;
    const [start, end] = caret();
    composing = { start, end, before: vault.length, value: field.value };
  });
  field.addEventListener("compositionend", (event) => {
    browserComposing = false;
    compositionPending = null;
    if (!active()) return;
    // A composition already abandoned (an outside edit ended it) commits
    // nothing; the field only has to show the mask again.
    if (!composing) {
      pending = null;
      if (field.value !== vault.mask()) render(Math.min(field.selectionStart ?? vault.length, vault.length));
      return;
    }
    const { start, end, before, value: prior } = composing;
    composing = null;
    pending = null;
    const value = field.value, added = value.length - (before - (end - start));
    const text = value.slice(start, start + Math.max(0, added));
    // A field unchanged since compositionstart committed nothing. (A bullet
    // that replaces a selected character one for one leaves the field
    // identical too; that cannot be told from a cancel, so it is not taken:
    // a mask character never enters the vault on a guess.)
    if (value === prior) {
      render(start);
      return;
    }
    // On a cancel the event's data is empty or the IME's own composing text,
    // never the restored bullets, so a changed field whose text equals the
    // data is a commit, even a commit of bullets over a selection.
    if (typeof event.data === "string" && event.data.length > 0 && event.data === text) {
      apply(start, end, text, "insertCompositionText");
      return;
    }
    // A cancelled composition (Esc, a blur) restores what the field held at
    // compositionstart — the mask — so the text read back is the mask's own
    // bullets where the vault holds the passphrase. Nothing was committed:
    // take nothing, and never copy masked characters into the vault. A bullet
    // committed at a collapsed caret covers no vault text, so it is the
    // user's own character and is kept.
    const maskOverSelection = end > start && text.length > 0 && text === VAULT_MASK.repeat(text.length);
    if (maskOverSelection) {
      render(start);
      return;
    }
    // Android and other IMEs whose event.data differs from the field's text
    // (e.g. after autocorrect): what the field holds is the commit.
    apply(start, end, text, "insertCompositionText");
  });

  // An edit the browser made itself, or a value set by script. Runs on the
  // field before the page's listeners on its ancestors, so they see the mask.
  field.addEventListener("input", (event) => {
    if (!active() || echoing) {
      compositionPending = null;
      return;
    }
    const compositionInput = Boolean(event?.isComposing) || isCompositionInputType(event?.inputType);
    if (compositionInput && !composing) {
      // Composition text is only ever taken at compositionend. After an
      // outside edit abandoned a composition the browser's own session runs
      // on, and what the IME composes in it is never stored; the field is
      // kept masked instead.
      if (event?.isComposing || browserComposing) {
        pending = null;
        compositionPending = null;
        render(Math.min(field.selectionStart ?? vault.length, vault.length));
        return;
      }
      // Outside any composition it is an ordinary browser edit (WebKit
      // dictation, autocorrect). Its caret is the one its own beforeinput
      // saved, and only if the field confirms it; otherwise no caret is used,
      // and the guarded paths below decide.
      pending = confirmsCaret(compositionPending, field.value) ? compositionPending : null;
      compositionPending = null;
    } else {
      compositionPending = null;
    }
    if (composing) {
      if (compositionInput) return;
      // Any other edit in the middle of a composition (an autofill, a
      // password manager) cannot be placed: the field mixes mask bullets and
      // raw composing text. Abandon both and show the vault as it is, a
      // visible reset rather than a silent splice at stale indices.
      abandonComposition();
      return;
    }
    const value = field.value;
    if (value === vault.mask()) {
      pending = null;
      return;
    }
    if (pending) {
      const { start, end } = pending, added = value.length - (vault.length - (end - start));
      if (added >= 0) {
        const text = value.slice(start, start + added);
        vault.replace(start, end, text);
        render(start + codePoints(text).length);
      } else {
        // Deleted further than the selection: the caret marks where.
        const at = Math.min(field.selectionStart ?? 0, start), lost = vault.length - value.length;
        vault.replace(at, at + lost, "");
        render(at);
      }
    } else if (vault.length && value.includes(VAULT_MASK)) {
      // No caret was saved, and the field held the mask: a bullet in it now
      // may be the mask's own, edited in a way no event described. A mask
      // character never enters the vault on a guess, so show the vault as it
      // is instead.
      render(Math.min(field.selectionStart ?? vault.length, vault.length));
    } else {
      // Set by script: the whole value is the passphrase.
      vault.setText(value);
      render(vault.length);
    }
    pending = null;
  });

  // Any change to the vault made from outside the field ends an open
  // composition: a compositionend that arrives later would apply its stale
  // indices to the new contents (mask bullets into the vault).


  return {
    // The on-screen keyboard: insert at the caret, or delete before it.
    insert: (text) => {
      abandonComposition();
      const [start, end] = caret();
      apply(start, end, text, "insertText");
    },
    deleteBackward: () => {
      abandonComposition();
      const [start, end] = caret();
      apply(start === end ? Math.max(0, start - 1) : start, end, "", "deleteContentBackward");
    },
    // Script-side: the field shows `bytes` (a stored passphrase), or nothing.
    setBytes: (bytes) => {
      endComposition();
      try {
        vault.setBytes(bytes);
      } catch (error) {
        // The refusal left the vault empty: the field must not keep showing
        // the previous passphrase's mask (or text) over it.
        if (active()) render(0);
        else field.value = "";
        throw error;
      }
      if (active()) render(vault.length);
      else {
        field.value = vault.text();
        vault.clear();
      }
    },
    clear: () => {
      endComposition();
      vault.clear();
      field.value = "";
    },
    // Leaving the vault (a mode that edits the field's text itself) and
    // coming back to it. Either switch ends any composition: a late
    // compositionend from before it must be ignored.
    unmask: () => {
      endComposition();
      field.value = vault.text();
      vault.clear();
    },
    mask: () => {
      endComposition();
      vault.setText(field.value);
      render(vault.length);
    },
  };
};
