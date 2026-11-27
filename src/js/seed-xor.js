// Coldcard Seed XOR: validate two or more same-length 12/18/24-word English
// BIP39 parts, XOR their entropy (not their checksum bits), and recompute the
// result's checksum; refuse every other phrase. An all-zero result is valid,
// matching Coldcard, but the UI warns about it.
//
// References: Coldcard firmware docs/seed-xor.md and testing/test_seed_xor.py
// at fab5f64a. The fixed published vectors for both operations are in
// test/seed-xor.test.mjs. Splitting is deterministic only: EntropyLab never
// supplies the entropy or randomness for a split.
import { entropyToMnemonic, mnemonicToEntropy, validateMnemonic } from "./bip39.js";
import { sha256 } from "./hashes.js";
import { t, tAttr } from "./i18n.js";
import { privateCopyButtonHtml } from "./private-data.js";

const encoder = new TextEncoder();
const BYTES_FOR_WORDS = new Map([[12, 16], [18, 24], [24, 32]]);
const ZERO_WORDS = new Map([
  [12, `${"abandon ".repeat(11)}about`],
  [18, `${"abandon ".repeat(17)}agent`],
  [24, `${"abandon ".repeat(23)}art`],
]);

const canonical = (part, index, name = `Seed XOR part ${index + 1}`) => {
  if (typeof part !== "string") throw new Error(`${name} must be a seed phrase.`);
  const phrase = part.trim().toLowerCase().split(/\s+/).join(" ");
  const count = phrase ? phrase.split(" ").length : 0;
  if (!BYTES_FOR_WORDS.has(count)) throw new Error(`${name} must contain 12, 18, or 24 words.`);
  if (!validateMnemonic(phrase)) throw new Error(`${name} has an unknown word or invalid BIP39 checksum.`);
  return phrase;
};

const entropyParts = (parts) => {
  if (!Array.isArray(parts) || parts.length < 2) throw new Error("Seed XOR needs at least two parts.");
  const decoded = [];
  try {
    let wordCount = 0;
    for (const [index, part] of parts.entries()) {
      const phrase = canonical(part, index);
      const count = phrase.split(" ").length;
      if (wordCount && count !== wordCount) throw new Error("Every Seed XOR part must have the same length.");
      wordCount = count;
      decoded.push(mnemonicToEntropy(phrase));
    }
    return decoded;
  } catch (error) {
    for (const entropy of decoded) entropy.fill(0);
    throw error;
  }
};

export function seedXorMnemonic(parts) {
  const decoded = entropyParts(parts);
  let result = new Uint8Array(0);
  try {
    result = new Uint8Array(decoded[0]);
    for (const entropy of decoded.slice(1)) for (let index = 0; index < result.length; index++) result[index] ^= entropy[index];
    return entropyToMnemonic(result);
  } finally {
    result.fill(0);
    for (const entropy of decoded) entropy.fill(0);
  }
}

const doubleSha256 = (bytes) => {
  const first = sha256(bytes);
  try {
    return sha256(first);
  } finally {
    first.fill(0);
  }
};

export function splitSeedXorMnemonics(mnemonic, count) {
  if (!Number.isInteger(count) || count < 2 || count > 4) throw new Error("Coldcard's deterministic Seed XOR split offers 2, 3, or 4 parts.");
  const phrase = canonical(mnemonic, 0, "Original seed phrase");
  let original = new Uint8Array(0), input = new Uint8Array(0);
  const generated = [];
  try {
    original = mnemonicToEntropy(phrase);
    const prefix = encoder.encode("Batshitoshi ");
    for (let index = 0; index < count - 1; index++) {
      const suffix = encoder.encode(`${index} of ${count} parts`);
      input = new Uint8Array(prefix.length + original.length + suffix.length);
      input.set(prefix);
      input.set(original, prefix.length);
      input.set(suffix, prefix.length + original.length);
      const hash = doubleSha256(input);
      generated.push(hash.slice(0, original.length));
      hash.fill(0);
      input.fill(0);
    }
    const last = new Uint8Array(original);
    generated.push(last);
    for (const entropy of generated.slice(0, -1)) for (let index = 0; index < last.length; index++) last[index] ^= entropy[index];
    const phrases = generated.map((entropy) => entropyToMnemonic(entropy));
    return phrases;
  } catch (error) {
    // Keep the public validation error specific without reflecting any phrase.
    if (/checksum/.test(error.message)) throw new Error("Original seed phrase has an unknown word or invalid BIP39 checksum.");
    throw error;
  } finally {
    original.fill(0);
    input.fill(0);
    for (const entropy of generated) entropy.fill(0);
  }
}

let currentDocument = null;
let copyIcon = () => "";
let lastParts = [];

const element = (id) => (currentDocument || document).getElementById(id);

function clearResult() {
  lastParts = [];
  const result = element("seedxor-result");
  if (result) {
    result.replaceChildren();
    result.hidden = true;
  }
  const warning = element("seedxor-warning");
  if (warning) {
    warning.hidden = true;
    warning.textContent = "";
  }
  const error = element("seedxor-error");
  if (error) error.textContent = "";
  const revealField = element("seedxor-reveal-field");
  if (revealField) revealField.hidden = true;
}

function renderResult() {
  const result = element("seedxor-result");
  if (!result) return;
  result.replaceChildren();
  const reveal = element("seedxor-reveal");
  if (!lastParts.length || !reveal?.checked) {
    result.hidden = !lastParts.length;
    if (lastParts.length) {
      const note = currentDocument.createElement("p");
      note.className = "muted";
      note.textContent = t("The private seed words stay hidden until you reveal them.");
      result.append(note);
    }
    return;
  }
  result.hidden = false;
  const labels = lastParts.length === 1 ? [t("Restored seed phrase")] : lastParts.map((_, index) => t("Part {letter}", { letter: String.fromCharCode(65 + index) }));
  for (const [index, phrase] of lastParts.entries()) {
    const field = currentDocument.createElement("div");
    field.className = "field private-field is-revealed";
    field.setAttribute("data-private-field", "");
    const label = currentDocument.createElement("p");
    label.className = "label copy-field-label";
    label.textContent = labels[index];
    label.insertAdjacentHTML("beforeend", privateCopyButtonHtml(copyIcon, { label: t("Copy seed phrase to EntropyLab's clipboard") }));
    const value = currentDocument.createElement("p");
    value.className = "psbt-kv";
    value.setAttribute("data-private-value", "");
    value.setAttribute("data-i18n-skip", "");
    value.setAttribute("translate", "no");
    value.setAttribute("aria-label", tAttr(labels[index]));
    value.textContent = phrase;
    field.append(label, value);
    result.append(field);
  }
}

function showResult(parts) {
  lastParts = parts;
  const revealField = element("seedxor-reveal-field");
  if (revealField) revealField.hidden = false;
  const reveal = element("seedxor-reveal");
  if (reveal) reveal.checked = false;
  renderResult();
  const warning = element("seedxor-warning");
  if (warning && parts.length === 1 && [...ZERO_WORDS.values()].includes(parts[0])) {
    warning.textContent = t("WARNING: the restored seed has all-zero entropy. Check that you entered the intended parts; Coldcard permits this result, but it is not a safe wallet seed.");
    warning.hidden = false;
  }
}

function activeParts() {
  const count = Number(element("seedxor-parts")?.value || 2);
  return ["a", "b", "c", "d"].slice(0, count).map((letter) => element(`seedxor-part-${letter}`)?.value || "");
}

function syncPartCount() {
  const count = Number(element("seedxor-parts")?.value || 2);
  for (const [index, letter] of ["a", "b", "c", "d"].entries()) {
    const wrapper = element(`seedxor-part-${letter}-field`);
    if (wrapper) wrapper.hidden = index >= count;
    if (index >= count) {
      const field = element(`seedxor-part-${letter}`);
      if (field) field.value = "";
    }
  }
  clearResult();
}

function selectMode(mode) {
  const restore = mode !== "split";
  const restorePanel = element("seedxor-restore-panel");
  const splitPanel = element("seedxor-split-panel");
  if (restorePanel) restorePanel.hidden = !restore;
  if (splitPanel) splitPanel.hidden = restore;
  for (const name of ["restore", "split"]) {
    const button = element(`seedxor-mode-${name}`);
    if (button) {
      button.classList.toggle("active", (name === "restore") === restore);
      button.setAttribute("aria-pressed", String((name === "restore") === restore));
    }
  }
  clearResult();
}

export function seedXorWipeMem() {
  lastParts = [];
  const doc = currentDocument || (typeof document !== "undefined" ? document : null);
  if (!doc) return;
  for (const field of doc.querySelectorAll("#seedxor-card textarea")) field.value = "";
  clearResult();
  const reveal = element("seedxor-reveal");
  if (reveal) reveal.checked = false;
  const parts = element("seedxor-parts");
  if (parts) parts.value = "2";
  const count = element("seedxor-split-count");
  if (count) count.value = "2";
  selectMode("restore");
  syncPartCount();
}

export function initSeedXor({ doc = document, copyIcon: icon = () => "" } = {}) {
  currentDocument = doc;
  copyIcon = icon;
  if (!element("seedxor-card")) return;
  clearResult();
  syncPartCount();
  selectMode("restore");
  for (const mode of ["restore", "split"]) {
    const button = element(`seedxor-mode-${mode}`);
    if (button) button.onclick = () => selectMode(mode);
  }
  const count = element("seedxor-parts");
  if (count) count.addEventListener("change", syncPartCount);
  const restore = element("seedxor-restore");
  if (restore) restore.onclick = () => {
    clearResult();
    try {
      showResult([seedXorMnemonic(activeParts())]);
    } catch (error) {
      const status = element("seedxor-error");
      if (status) status.textContent = error.message || t("The Seed XOR parts could not be restored.");
    }
  };
  const split = element("seedxor-split");
  if (split) split.onclick = () => {
    clearResult();
    try {
      showResult(splitSeedXorMnemonics(element("seedxor-original")?.value || "", Number(element("seedxor-split-count")?.value || 2)));
    } catch (error) {
      const status = element("seedxor-error");
      if (status) status.textContent = error.message || t("The seed phrase could not be split.");
    }
  };
  const reveal = element("seedxor-reveal");
  if (reveal) reveal.addEventListener("change", renderResult);
  const wipe = element("seedxor-wipe");
  if (wipe) wipe.onclick = seedXorWipeMem;
  cardListeners(doc);
}

function cardListeners(doc) {
  const card = element("seedxor-card");
  if (!card) return;
  card.addEventListener("input", (event) => {
    if (event.target?.id !== "seedxor-reveal") clearResult();
  });
}
