// The Verify tab's "Check a SeedQR copy" panel (preview builds only). The
// user taps the squares of a SeedQR they copied by hand, or pastes its
// digits; seedqr-grid.js reads the copy square by square and this panel
// shows what it decodes to, which squares are wrong, and the seed's master
// fingerprint and first receive addresses to compare with the wallet.
//
// Security contract: the entered squares, the pasted text, the passphrase
// and everything decoded from them live only in this closure and the
// panel's own DOM: nothing goes to storage, the clipboard, the console or
// the network. Words appear only after Show words, and conceal() hides them
// again. clear() (the panel's Clear, Clear Fields, End Session and pagehide)
// empties every field and the result and zeroes every buffer the panel
// owns; a copy past the correction limit never shows a seed.

import { SEEDQR_GRID_SIZES, checkSeedQrGrid, parseSeedQrText, seedQrLayout, seedQrReferenceGrid } from "./seedqr-grid.js";
import { bip39English, seedFromIndices } from "./bip39.js";
import { HDKey } from "./hdkey.js";
import { addressFor } from "./addresses.js";

const ADDRESS_COUNT = 3;
const ACCOUNT_PATH = "m/84'/0'/0'/0";

const escapeHtml = (text) => String(text).replace(/[&<>"']/g, (character) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[character]);

// A SeedQR drawn as a copy grid: rows and columns numbered from 1 at the top
// left, a heavier line after every 5th square like the SeedSigner templates,
// and `wrong` (a Set of row*size+col) outlined. It is a picture to copy from
// or to compare with, not a code to scan.
export function seedQrCopyGridSvg(grid, size, { wrong = null, label = "" } = {}) {
  const margin = 2, side = margin + size + 0.5;
  let dark = "", thin = "", heavy = "", labels = "", marks = "";
  for (let row = 0; row < size; row++) for (let col = 0; col < size; col++) {
    if (grid[row * size + col]) dark += `M${margin + col} ${margin + row}h1v1h-1z`;
    if (wrong?.has(row * size + col)) marks += `<rect x="${margin + col + 0.1}" y="${margin + row + 0.1}" width="0.8" height="0.8"/>`;
  }
  for (let i = 0; i <= size; i++) {
    const line = `M${margin + i} ${margin}v${size}M${margin} ${margin + i}h${size}`;
    if (i % 5 === 0 || i === size) heavy += line;
    else thin += line;
    if (i < size) labels += `<text x="${margin - 0.35}" y="${margin + i + 0.5}" text-anchor="end">${i + 1}</text><text x="${margin + i + 0.5}" y="${margin - 0.45}" text-anchor="middle">${i + 1}</text>`;
  }
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${side} ${side}" role="img" aria-label="${escapeHtml(label)}"><rect width="${side}" height="${side}" fill="#ffffff"/><path d="${dark}" fill="#111111"/><path d="${thin}" fill="none" stroke="#9a9a9a" stroke-width="0.04"/><path d="${heavy}" fill="none" stroke="#111111" stroke-width="0.1"/><g fill="#d40000" fill-opacity="0.45" stroke="#d40000" stroke-width="0.16">${marks}</g><g font-family="monospace" font-size="0.55" fill="#111111" dominant-baseline="central">${labels}</g></svg>`;
}

// The copy grid for a SeedQR the app displays, with the mask it uses, for
// the SeedQR export: the same uqr encoding (level L, uqr's mask choice) as
// the code shown beside it. The caller owns `indices`.
export function seedQrCopyGridMarkup(format, indices, translate = (text) => text) {
  const say = sayWith(translate);
  const reference = seedQrReferenceGrid(format, indices);
  try {
    return `<details class="wallet-advanced seedqr-copy-grid" data-seedqr-copy-grid data-seedqr-mask="${reference.mask}"><summary>${escapeHtml(say("Copy grid"))}</summary><div class="qr qr-seed seedqr-copy-grid-image">${seedQrCopyGridSvg(reference.grid, reference.size, { label: say("SeedQR copy grid, {size} by {size} squares", { size: reference.size }) })}</div><p class="muted">${escapeHtml(say("Mask pattern {mask}. Rows and columns are numbered from 1 at the top left.", { mask: reference.mask }))}</p><p class="muted">${escapeHtml(say(MASK_NOTE))}</p></details>`;
  } finally {
    reference.grid.fill(0);
  }
}

const MASK_NOTE = "Two correct encoders can choose different mask patterns for the same seed, so their grids differ square by square. Compare grids square by square only when the masks match. Check a SeedQR copy (Verify tab) decodes the copy instead, so any mask works.";
const FINAL_CHECK = "Compare the master fingerprint and the first address with your wallet. That is the final check: a 12-word seed's checksum is only 4 bits, so a wrong copy can still decode to a valid seed.";
const REGION_TEXT = {
  data: "",
  finder: " (finder pattern)",
  timing: " (timing pattern)",
  alignment: " (alignment pattern)",
  dark: " (dark square)",
  format: " (format squares)",
  remainder: " (unused square)",
};
const FAILURE_TEXT = {
  size: "This grid is not a SeedQR size. Nothing was decoded.",
  format: "The format squares beside the finder patterns cannot be read, so the mask is unknown. Nothing was decoded. Check those squares first.",
  "ecc-level": "This QR uses error correction level {ecc}. SeedQR uses level L. Nothing was decoded.",
  "too-many-errors": "This copy has too many wrong squares to decode. No seed is shown. A scanner would refuse it too.",
  "not-seedqr": "This QR decodes, but not to a SeedQR. No seed is shown.",
};
const MAX_LISTED = 40;

function sayWith(translate) {
  // A translation may or may not fill {placeholders}; fill any it leaves.
  return (text, vars) => {
    const translated = String(translate(text, vars) ?? "");
    if (!vars) return translated;
    return translated.replace(/\{(\w+)\}/g, (match, name) => (Object.prototype.hasOwnProperty.call(vars, name) ? String(vars[name]) : match));
  };
}

// Master fingerprint and the first m/84'/0'/0'/0/i addresses, from the
// indices alone; every seed and private key buffer is wiped before return.
function defaultDerive(indices, passphrase) {
  const seed = seedFromIndices(indices, passphrase);
  let master = null, branch = null;
  try {
    master = HDKey.fromMasterSeed(seed);
    const fingerprint = (master.fingerprint >>> 0).toString(16).padStart(8, "0");
    branch = master.derive(ACCOUNT_PATH);
    const addresses = [];
    for (let i = 0; i < ADDRESS_COUNT; i++) {
      const child = branch.deriveChild(i);
      try {
        addresses.push(addressFor("p2wpkh", child.publicKey, "mainnet"));
      } finally {
        child.wipePrivateData();
      }
    }
    return { fingerprint, addresses };
  } finally {
    seed.fill(0);
    branch?.wipePrivateData();
    master?.wipePrivateData();
  }
}

export function mountSeedQrCheck(host, {
  translate = (text) => text,
  privateValue = (value) => escapeHtml(value),
  derive = defaultDerive,
  doc = document,
  win = window,
} = {}) {
  const say = sayWith(translate);
  const make = (tag, props) => {
    const node = doc.createElement(tag);
    if (props) for (const name of Object.keys(props)) {
      const value = props[name];
      if (name === "text") node.textContent = value;
      else if (name === "class") node.className = value;
      else if (name === "hidden") node.hidden = !!value;
      else node.setAttribute(name, value);
    }
    return node;
  };
  const segmented = (id, label, options) => {
    const group = make("div", { class: "segmented-control", id, role: "group", "aria-label": say(label) });
    const buttons = options.map(([value, text]) => {
      const button = make("button", { type: "button", class: "tab", "data-value": value, "aria-pressed": "false", text: say(text) });
      group.appendChild(button);
      return button;
    });
    return { group, buttons };
  };

  // Layout follows docs/UI_Patterns.md: labels, field notes, edge notes,
  // `.row.tool-actions` action rows and `.btn` buttons. Styles: #seedqr-check-*.
  const mode = segmented("seedqr-check-mode", "How to enter the copy", [["grid", "Tap the squares"], ["text", "Paste digits"]]);
  const kind = segmented("seedqr-check-kind", "SeedQR type", [["standard", "SeedQR"], ["compact", "CompactSeedQR"]]);
  const words = segmented("seedqr-check-words", "Seed length", [["12", "12 words"], ["24", "24 words"]]);
  const view = segmented("seedqr-check-view", "Part of the grid to show", [["all", "Whole grid"], ["0", "Top left"], ["1", "Top right"], ["2", "Bottom left"], ["3", "Bottom right"]]);
  const gridPanel = make("div", { id: "seedqr-check-grid-panel" });
  const sizeNote = make("p", { class: "field-note", id: "seedqr-check-size", "aria-live": "polite" });
  const gridNode = make("div", { class: "seedqr-entry-grid", id: "seedqr-check-grid", role: "group" });
  const fixedNote = make("p", { class: "field-note", text: say("The finder, timing and alignment squares and the dark square are the same in every SeedQR of this size, so they can be filled in for you. Check them on your copy anyway: a scanner needs them. The format squares beside the finders depend on the mask, so enter those from your copy.") });
  const gridActions = make("div", { class: "row tool-actions" });
  const fixedButton = make("button", { type: "button", class: "btn secondary", id: "seedqr-check-fixed", text: say("Fill in the fixed patterns") });
  const checkButton = make("button", { type: "button", class: "btn primary", id: "seedqr-check-run", text: say("Check copy") });
  const textPanel = make("div", { id: "seedqr-check-text-panel", hidden: true });
  const textLabel = make("label", { class: "label", for: "seedqr-check-text", text: say("SeedQR digits (48 or 96) or CompactSeedQR hex") });
  const textInput = make("textarea", { id: "seedqr-check-text", class: "field", rows: "3", spellcheck: "false", autocomplete: "off", autocapitalize: "off", inputmode: "numeric" });
  const textActions = make("div", { class: "row tool-actions" });
  const textButton = make("button", { type: "button", class: "btn primary", id: "seedqr-check-text-run", text: say("Check digits") });
  const clearButton = make("button", { type: "button", class: "btn secondary", id: "seedqr-check-clear", text: say("Clear") });
  const result = make("div", { id: "seedqr-check-result", "data-state": "empty" });
  const status = make("p", { class: "edge-note", id: "seedqr-check-status", role: "status", "aria-live": "polite" });
  const list = make("ol", { class: "seedqr-check-list", id: "seedqr-check-differences", hidden: true });
  const picture = make("div", { class: "qr qr-seed seedqr-check-picture", id: "seedqr-check-picture", hidden: true });
  const pictureNote = make("p", { class: "field-note", id: "seedqr-check-picture-note", hidden: true });
  const seedBlock = make("div", { id: "seedqr-check-seed", hidden: true });
  const seedSummary = make("p", { class: "label", id: "seedqr-check-summary" });
  const wordsRow = make("div", { class: "row" });
  const wordsValue = make("div", { id: "seedqr-check-words-value", translate: "no" });
  const revealButton = make("button", { type: "button", class: "btn secondary", id: "seedqr-check-reveal", "aria-pressed": "false", text: say("Show words") });
  const passLabel = make("label", { class: "label", for: "seedqr-check-pass", text: say("Passphrase (optional)") });
  const passInput = make("input", { id: "seedqr-check-pass", class: "field", autocomplete: "off", spellcheck: "false", autocapitalize: "off" });
  const fingerprintLabel = make("p", { class: "label", text: say("Master fingerprint") });
  const fingerprintValue = make("p", { class: "addr-text", id: "seedqr-check-fingerprint", "data-public-value": "", "data-i18n-skip": "", translate: "no" });
  const addressLabel = make("p", { class: "label", text: say("First receive addresses (Native SegWit, m/84'/0'/0'/0/0 to /2)") });
  const addressList = make("ol", { class: "seedqr-check-addresses", id: "seedqr-check-addresses", start: "0", "data-i18n-skip": "", translate: "no" });
  const finalNote = make("p", { class: "edge-note is-info", id: "seedqr-check-final", text: say(FINAL_CHECK) });

  gridActions.append(fixedButton, checkButton);
  gridPanel.append(kind.group, words.group, sizeNote, view.group, gridNode, fixedNote, gridActions);
  textActions.append(textButton);
  textPanel.append(textLabel, textInput, textActions);
  wordsRow.append(wordsValue, revealButton);
  seedBlock.append(seedSummary, wordsRow, passLabel, passInput, fingerprintLabel, fingerprintValue, addressLabel, addressList, finalNote);
  result.append(status, list, picture, pictureNote, seedBlock);
  const clearRow = make("div", { class: "row tool-actions" });
  clearRow.append(clearButton);
  host.replaceChildren(mode.group, gridPanel, textPanel, clearRow, result);

  // ── State ────────────────────────────────────────────────────────────────
  let entry = "grid", format = "standard", wordCount = 12, part = "all";
  let size = SEEDQR_GRID_SIZES[format][wordCount];
  let grid = new Uint8Array(size * size);
  let wrong = new Set();
  let seed = null; // { format, words, indices } once a copy or pasted text decodes
  let revealed = false;
  let destroyed = false;

  const press = (group, value) => {
    for (const button of group.buttons) button.setAttribute("aria-pressed", String(button.getAttribute("data-value") === value));
  };

  const dropSeed = () => {
    if (seed?.indices) seed.indices.fill(0);
    seed = null;
    revealed = false;
    passInput.value = "";
    wordsValue.innerHTML = "";
    fingerprintValue.textContent = "";
    addressList.replaceChildren();
    seedBlock.hidden = true;
  };

  const resetResult = () => {
    dropSeed();
    wrong = new Set();
    status.textContent = "";
    status.className = "edge-note";
    list.replaceChildren();
    list.hidden = true;
    picture.innerHTML = "";
    picture.hidden = true;
    pictureNote.textContent = "";
    pictureNote.hidden = true;
    result.setAttribute("data-state", "empty");
  };

  const half = () => Math.ceil(size / 2);
  const visible = () => {
    if (part === "all") return { rows: [0, size], cols: [0, size] };
    const quarter = Number(part), cut = half();
    return { rows: quarter < 2 ? [0, cut] : [cut, size], cols: quarter % 2 === 0 ? [0, cut] : [cut, size] };
  };

  const cellLabel = (row, col) => say("Row {row}, column {col}", { row: row + 1, col: col + 1 });
  const paintCell = (button, cell) => {
    button.setAttribute("aria-pressed", String(grid[cell] === 1));
    button.classList.toggle("is-wrong", wrong.has(cell));
  };

  const renderGrid = () => {
    const { rows, cols } = visible();
    const columns = cols[1] - cols[0];
    gridNode.setAttribute("aria-label", say("SeedQR copy, {size} by {size} squares", { size }));
    gridNode.setAttribute("data-size", String(size));
    gridNode.style.setProperty("--seedqr-columns", String(columns));
    const nodes = [make("span", { class: "seedqr-entry-corner", "aria-hidden": "true" })];
    for (let col = cols[0]; col < cols[1]; col++) nodes.push(make("span", { class: `seedqr-entry-heading${(col + 1) % 5 === 0 ? " is-group-end" : ""}`, "aria-hidden": "true", text: String(col + 1) }));
    for (let row = rows[0]; row < rows[1]; row++) {
      nodes.push(make("span", { class: `seedqr-entry-heading${(row + 1) % 5 === 0 ? " is-group-end" : ""}`, "aria-hidden": "true", text: String(row + 1) }));
      for (let col = cols[0]; col < cols[1]; col++) {
        const cell = row * size + col;
        const button = make("button", {
          type: "button",
          class: `seedqr-entry-cell${(col + 1) % 5 === 0 ? " is-group-end-col" : ""}${(row + 1) % 5 === 0 ? " is-group-end-row" : ""}`,
          "data-seedqr-cell": String(cell),
          "aria-label": cellLabel(row, col),
        });
        paintCell(button, cell);
        button.onclick = () => {
          if (destroyed) return;
          grid[cell] ^= 1;
          wrong.delete(cell);
          paintCell(button, cell);
          if (result.getAttribute("data-state") !== "empty") markStale();
        };
        nodes.push(button);
      }
    }
    gridNode.replaceChildren(...nodes);
    sizeNote.textContent = say("{size} by {size} squares. Rows and columns are numbered from 1 at the top left, with a heavier line after every 5th square.", { size });
  };

  const markStale = () => {
    dropSeed();
    result.setAttribute("data-state", "stale");
    status.className = "edge-note is-muted";
    status.textContent = say("The copy changed. Check it again.");
  };

  const setSize = () => {
    const next = SEEDQR_GRID_SIZES[format][wordCount];
    press(kind, format);
    press(words, String(wordCount));
    if (next !== size) {
      grid.fill(0);
      size = next;
      grid = new Uint8Array(size * size);
      resetResult();
    }
    renderGrid();
  };

  const renderSeed = () => {
    if (!seed) return;
    const name = seed.format === "compact-seedqr" ? "CompactSeedQR" : "SeedQR";
    seedSummary.textContent = say("{format} · {words} words", { format: name, words: seed.words });
    wordsValue.innerHTML = privateValue(revealed ? Array.from(seed.indices, (index) => bip39English[index]).join(" ") : "•".repeat(seed.words * 4), revealed);
    revealButton.textContent = say(revealed ? "Hide words" : "Show words");
    revealButton.setAttribute("aria-pressed", String(revealed));
    renderDerived();
    seedBlock.hidden = false;
  };

  const renderDerived = () => {
    if (!seed) return;
    let derived;
    try {
      derived = derive(seed.indices, passInput.value);
    } catch {
      fingerprintValue.textContent = say("Unavailable");
      addressList.replaceChildren();
      return;
    }
    fingerprintValue.textContent = derived.fingerprint;
    addressList.replaceChildren(...derived.addresses.map((address) => make("li", { class: "addr-text", "data-public-value": "", text: address })));
  };

  const showDifferences = (differences) => {
    const items = differences.slice(0, MAX_LISTED).map(({ row, col, dark, region }) => make("li", {
      "data-seedqr-row": String(row + 1),
      "data-seedqr-col": String(col + 1),
      text: say(dark ? "Row {row}, column {col} should be filled{area}" : "Row {row}, column {col} should be empty{area}", { row: row + 1, col: col + 1, area: say(REGION_TEXT[region] ?? "") }),
    }));
    if (differences.length > MAX_LISTED) items.push(make("li", { text: say("…and {count} more", { count: differences.length - MAX_LISTED }) }));
    list.replaceChildren(...items);
    list.hidden = items.length === 0;
  };

  const runGrid = () => {
    resetResult();
    const outcome = checkSeedQrGrid(grid, size);
    wrong = new Set(outcome.differences.map(({ row, col }) => row * size + col));
    for (const button of gridNode.querySelectorAll("[data-seedqr-cell]")) paintCell(button, Number(button.getAttribute("data-seedqr-cell")));
    showDifferences(outcome.differences);
    picture.innerHTML = seedQrCopyGridSvg(grid, size, { wrong, label: say("Your copy, wrong squares marked") });
    picture.hidden = false;
    if (!outcome.ok) {
      result.setAttribute("data-state", "failed");
      status.className = "edge-note is-private";
      status.textContent = say(FAILURE_TEXT[outcome.reason] ?? FAILURE_TEXT["not-seedqr"], { ecc: outcome.ecc ?? "" });
      if (outcome.differences.length) {
        pictureNote.textContent = say("The squares listed can be checked without decoding: they are the same in every SeedQR of this size.");
        pictureNote.hidden = false;
      }
      return;
    }
    seed = { format: outcome.format, words: outcome.words, indices: outcome.indices };
    const count = outcome.differences.length;
    pictureNote.textContent = say("Mask pattern {mask}, read from the copy's format squares.", { mask: outcome.mask });
    pictureNote.hidden = false;
    if (count === 0) {
      result.setAttribute("data-state", "exact");
      status.className = "edge-note is-public";
      status.textContent = say("Exact match. Every square matches a fresh encoding of what this copy decodes to.");
    } else {
      result.setAttribute("data-state", "wrong-squares");
      status.className = "edge-note is-private";
      status.textContent = outcome.correctedCodewords
        ? say("This copy decodes, but {count} squares are wrong. A scanner would hide this: error correction fixed {fixed} of {total} codewords, and at most {max} can be fixed. Correct the squares listed.", { count, fixed: outcome.correctedCodewords, total: outcome.totalCodewords, max: outcome.maxCorrectable })
        : say("This copy decodes, but {count} squares are wrong. Correct the squares listed.", { count });
    }
    renderSeed();
  };

  const runText = () => {
    resetResult();
    const parsed = parseSeedQrText(textInput.value);
    if (!parsed) {
      result.setAttribute("data-state", "failed");
      status.className = "edge-note is-private";
      status.textContent = say("These are not SeedQR digits (48 or 96 digits) or CompactSeedQR hex (32 or 64 characters) with a valid checksum. No seed is shown.");
      return;
    }
    seed = { format: parsed.format, words: parsed.words, indices: parsed.indices };
    result.setAttribute("data-state", "parsed");
    status.className = "edge-note is-public";
    status.textContent = say("These digits are a valid SeedQR.");
    const reference = seedQrReferenceGrid(seed.format, seed.indices);
    picture.innerHTML = seedQrCopyGridSvg(reference.grid, reference.size, { label: say("SeedQR copy grid, {size} by {size} squares", { size: reference.size }) });
    reference.grid.fill(0);
    picture.hidden = false;
    pictureNote.textContent = `${say("This is how EntropyLab draws this SeedQR: mask pattern {mask}.", { mask: reference.mask })} ${say(MASK_NOTE)}`;
    pictureNote.hidden = false;
    renderSeed();
  };

  const setEntry = (next) => {
    entry = next;
    press(mode, entry);
    gridPanel.hidden = entry !== "grid";
    textPanel.hidden = entry !== "text";
    resetResult();
    renderGrid();
  };

  for (const button of mode.buttons) button.onclick = () => setEntry(button.getAttribute("data-value"));
  for (const button of kind.buttons) button.onclick = () => {
    format = button.getAttribute("data-value");
    setSize();
  };
  for (const button of words.buttons) button.onclick = () => {
    wordCount = Number(button.getAttribute("data-value"));
    setSize();
  };
  for (const button of view.buttons) button.onclick = () => {
    part = button.getAttribute("data-value");
    press(view, part);
    renderGrid();
  };
  fixedButton.onclick = () => {
    const { regions, fixed } = seedQrLayout(size);
    for (let cell = 0; cell < grid.length; cell++) if (regions[cell] >= 1 && regions[cell] <= 4) {
      grid[cell] = fixed[cell];
      wrong.delete(cell);
    }
    if (result.getAttribute("data-state") !== "empty") markStale();
    renderGrid();
  };
  checkButton.onclick = runGrid;
  textButton.onclick = runText;
  textInput.oninput = () => {
    if (result.getAttribute("data-state") !== "empty") resetResult();
  };
  revealButton.onclick = () => {
    revealed = !revealed;
    renderSeed();
  };
  passInput.oninput = renderDerived;

  const clear = () => {
    grid.fill(0);
    textInput.value = "";
    resetResult();
    renderGrid();
  };
  clearButton.onclick = clear;

  // Phones get a quarter at a time, so the squares are big enough to tap.
  let narrow = false;
  try {
    narrow = Boolean(win.matchMedia?.("(max-width: 600px)").matches);
  } catch {
    narrow = false;
  }
  part = narrow ? "0" : "all";
  press(view, part);
  setEntry("grid");
  setSize();

  return {
    clear,
    conceal() {
      if (!revealed) return;
      revealed = false;
      renderSeed();
    },
    destroy() {
      clear();
      destroyed = true;
      host.replaceChildren();
    },
  };
}
