// Passphrase vault: the BIP39 passphrase field never holds the passphrase.
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
        const size = b < 0x80 ? 1 : b >= 0xf0 ? 4 : b >= 0xe0 ? 3 : 2;
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
  text() {
    return String.fromCodePoint(...this.#points.subarray(0, this.#length));
  }

  mask() {
    return VAULT_MASK.repeat(this.#length);
  }
}

// Binds `field` to `vault`. While `active()` says so, the field holds only
// the mask; otherwise the handlers stand aside and the field is ordinary.
// Every change to the vault is announced as an `input` event on the field,
// so the page's own listeners run as they did for typing.
export const bindVaultField = (field, vault, { active = () => true } = {}) => {
  let pending = null, composing = null, echoing = false;
  const caret = () => [field.selectionStart ?? field.value.length, field.selectionEnd ?? field.value.length];
  const render = (at) => {
    field.value = vault.mask();
    field.setSelectionRange?.(at, at);
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
    const [start, end] = caret();
    pending = { start, end };
    const type = event.inputType || "";
    if (event.isComposing || type === "insertCompositionText" || !event.cancelable) return;
    event.preventDefault();
    let from = start, to = end, text = "";
    if (type.startsWith("insert")) {
      if (type === "insertLineBreak" || type === "insertParagraph") return;
      text = event.data ?? event.dataTransfer?.getData("text/plain") ?? "";
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
      return; // undo, redo, formatting: nothing in a field of bullets to do
    }
    pending = null;
    apply(from, to, text, type);
  });

  field.addEventListener("compositionstart", () => {
    if (!active()) return;
    const [start, end] = caret();
    composing = { start, end, before: vault.length };
  });
  field.addEventListener("compositionend", () => {
    if (!active() || !composing) return;
    const { start, end, before } = composing;
    composing = null;
    pending = null;
    const value = field.value, added = value.length - (before - (end - start));
    apply(start, end, value.slice(start, start + Math.max(0, added)), "insertCompositionText");
  });

  // An edit the browser made itself, or a value set by script. Runs on the
  // field before the page's listeners on its ancestors, so they see the mask.
  field.addEventListener("input", () => {
    if (!active() || echoing || composing) return;
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
    } else {
      // Set by script: the whole value is the passphrase.
      vault.setText(value);
      render(vault.length);
    }
    pending = null;
  });

  return {
    // The on-screen keyboard: insert at the caret, or delete before it.
    insert: (text) => {
      const [start, end] = caret();
      apply(start, end, text, "insertText");
    },
    deleteBackward: () => {
      const [start, end] = caret();
      apply(start === end ? Math.max(0, start - 1) : start, end, "", "deleteContentBackward");
    },
    // Script-side: the field shows `bytes` (a stored passphrase), or nothing.
    setBytes: (bytes) => {
      vault.setBytes(bytes);
      if (active()) render(vault.length);
      else {
        field.value = vault.text();
        vault.clear();
      }
    },
    clear: () => {
      vault.clear();
      field.value = "";
    },
    // Leaving the vault (a mode that edits the field's text itself) and
    // coming back to it.
    unmask: () => {
      field.value = vault.text();
      vault.clear();
    },
    mask: () => {
      vault.setText(field.value);
      render(vault.length);
    },
  };
};
