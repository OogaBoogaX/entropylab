// Secure entry: the seed word picker (P2a). It owns the picker's DOM and
// writes the caller's seed entry only through seedSet and seedUndo. P2b wires
// it into the Key Station behind the preview flag and the Secure entry switch;
// app.js does not import it yet.
//
// Security contract: the picker never keeps a word string beyond the moment it
// is shown, never speaks a word, zeroes every temporary index and entropy
// buffer, and clears every field on conceal and destroy without ever wiping
// the caller's entry. The one exception is an explicit paste: the pasted text
// is a string, which the page cannot erase, and the note under the picker says
// so. The caller destroys a picker before mounting another on the same entry.

const CHIP_DOTS = "••••";
const WORD_DOTS = "••••••";
const MAX_MATCHES = 24;
const WORD_COUNT = 2048;

const TEXT = {
  position: "Word {n} of {total}",
  help: "Type the beginning of the word, then choose a match.",
  chip: "Word {n}, entered. Review or replace.",
  prefixLabel: "Beginning of word {n}",
  oneMatch: "1 matching word",
  manyMatches: "{count} matching words",
  noMatch: "No matching word. Check the spelling or remove a letter.",
  narrow: "Type more letters to narrow the list.",
  undo: "Undo last word",
  pasteOpen: "Paste a whole phrase…",
  reviewAll: "Review words one by one",
  note: "Select a word number above to review or replace that word. Pasting creates a text copy in browser memory, and clearing this field does not clear your system clipboard.",
  progress: "{count} of {total} words entered.",
  checksumOk: "Seed checksum passed. Review the word order before continuing.",
  checksumBad: "Seed checksum does not match. Check the words and their order.",
  caveat: "A passing checksum does not confirm this is the seed you intended.",
  entered: "Word {n} entered. Word {next} of {total}",
  reviewHeading: "Editing word {n} of {total}",
  showWord: "Show this word",
  reviewNote: "Only this word is shown, and only while \"Show this word\" is on. Replacing it keeps every other word in its place.",
  replaceLabel: "Beginning of the replacement word",
  replace: "Replace word",
  cancel: "Cancel",
  replaced: "Word {n} replaced. Continue with word {next}.",
  prev: "Previous word",
  next: "Next word",
  pasteLabel: "Paste the phrase",
  pasteUse: "Use this phrase",
  pasteFail: "This phrase does not have {total} words from the BIP39 English list. Nothing was changed.",
};

export function mountSeedPicker(host, {
  entry,
  wordlist,
  seedSet,
  seedUndo,
  seedIndices,
  entropyFromWordIndices,
  translate = (text) => text,
  onChange = () => {},
  doc = document,
  win = window,
} = {}) {
  if (!entry || typeof entry !== "object" || entry.kind !== "seed") throw new Error("A seed picker needs a seed entry.");
  if (!Array.isArray(wordlist) || wordlist.length !== WORD_COUNT) throw new Error("A seed picker needs the 2048-word BIP39 list.");
  if (typeof seedSet !== "function" || typeof seedUndo !== "function" || typeof seedIndices !== "function" || typeof entropyFromWordIndices !== "function") throw new Error("A seed picker needs the seed entry helpers.");

  // A translation may or may not fill {placeholders}; fill any it leaves.
  const say = (text, vars) => {
    const translated = String(translate(text, vars) ?? "");
    if (!vars) return translated;
    return translated.replace(/\{(\w+)\}/g, (match, name) => (Object.prototype.hasOwnProperty.call(vars, name) ? String(vars[name]) : match));
  };

  const make = (tag, props) => {
    const node = doc.createElement(tag);
    if (props) for (const name of Object.keys(props)) {
      const value = props[name];
      if (name === "text") node.textContent = value;
      else if (name === "class") node.className = value;
      else if (name === "hidden") node.hidden = !!value;
      else if (name === "checked") node.checked = !!value;
      else node.setAttribute(name, value);
    }
    return node;
  };

  const textAttributes = (describedBy) => ({
    autocomplete: "off",
    autocapitalize: "off",
    autocorrect: "off",
    spellcheck: "false",
    translate: "no",
    inputmode: "text",
    "aria-describedby": describedBy,
  });
  const fieldAttributes = (describedBy) => ({ type: "text", ...textAttributes(describedBy) });

  // Layout follows docs/UI_Patterns.md: action rows are `.row.tool-actions`,
  // buttons are `.btn` variants, and the secret warnings are red edge notes.
  // Styles live in styles.css (#seed-picker-*), including `[hidden]` for `.btn`.
  const positionLine = make("p", { class: "label", id: "seed-picker-position" });
  const helpLine = make("p", { class: "field-note", id: "seed-picker-help", text: say(TEXT.help) });
  const chips = make("div", { class: "row", id: "seed-picker-chips" });

  const entryArea = make("div", { id: "seed-picker-entry" });
  const prefixLabel = make("label", { class: "field", id: "seed-picker-prefix-label" });
  const prefixText = make("span", { id: "seed-picker-prefix-text" });
  const prefixField = make("input", { id: "seed-picker-prefix", ...fieldAttributes("seed-picker-count") });
  prefixLabel.appendChild(prefixText);
  prefixLabel.appendChild(prefixField);
  const countLine = make("p", { class: "field-note", id: "seed-picker-count", role: "status", "aria-live": "polite" });
  const narrowLine = make("p", { class: "field-note", id: "seed-picker-narrow", hidden: true, text: say(TEXT.narrow) });
  const matches = make("div", { class: "row", id: "seed-picker-matches" });
  entryArea.appendChild(prefixLabel);
  entryArea.appendChild(countLine);
  entryArea.appendChild(narrowLine);
  entryArea.appendChild(matches);

  const review = make("div", { id: "seed-picker-review", hidden: true });
  const reviewHeading = make("p", { class: "label", id: "seed-picker-review-heading", tabindex: "-1" });
  const reviewWord = make("div", { id: "seed-picker-review-word" });
  const showLabel = make("label", { class: "field", id: "seed-picker-review-show-label" });
  const showBox = make("input", { type: "checkbox", id: "seed-picker-review-show" });
  const showText = make("span", { id: "seed-picker-review-show-text", text: say(TEXT.showWord) });
  showLabel.appendChild(showBox);
  showLabel.appendChild(showText);
  const reviewNote = make("p", { class: "field-note", id: "seed-picker-review-note", text: say(TEXT.reviewNote) });
  const replaceLabel = make("label", { class: "field", id: "seed-picker-replace-label" });
  const replaceText = make("span", { id: "seed-picker-replace-text", text: say(TEXT.replaceLabel) });
  const replaceField = make("input", { id: "seed-picker-replace-prefix", ...fieldAttributes("seed-picker-replace-count") });
  replaceLabel.appendChild(replaceText);
  replaceLabel.appendChild(replaceField);
  const replaceCount = make("p", { class: "field-note", id: "seed-picker-replace-count", role: "status", "aria-live": "polite" });
  const replaceNarrow = make("p", { class: "field-note", id: "seed-picker-replace-narrow", hidden: true, text: say(TEXT.narrow) });
  const replaceMatches = make("div", { class: "row", id: "seed-picker-replace-matches" });
  const replaceButton = make("button", { type: "button", class: "btn primary", id: "seed-picker-replace", disabled: "", text: say(TEXT.replace) });
  const reviewCancel = make("button", { type: "button", class: "btn secondary", id: "seed-picker-review-cancel", text: say(TEXT.cancel) });
  const reviewPrev = make("button", { type: "button", class: "btn secondary", id: "seed-picker-review-prev", text: say(TEXT.prev) });
  const reviewNext = make("button", { type: "button", class: "btn secondary", id: "seed-picker-review-next", text: say(TEXT.next) });
  const reviewActions = make("div", { class: "row tool-actions" });
  reviewActions.appendChild(replaceButton);
  reviewActions.appendChild(reviewCancel);
  reviewActions.appendChild(reviewPrev);
  reviewActions.appendChild(reviewNext);
  review.appendChild(reviewHeading);
  review.appendChild(reviewWord);
  review.appendChild(showLabel);
  review.appendChild(reviewNote);
  review.appendChild(replaceLabel);
  review.appendChild(replaceCount);
  review.appendChild(replaceNarrow);
  review.appendChild(replaceMatches);
  review.appendChild(reviewActions);

  const actions = make("div", { class: "row tool-actions" });
  const undoButton = make("button", { type: "button", class: "btn secondary", id: "seed-picker-undo", text: say(TEXT.undo) });
  const pasteOpen = make("button", { type: "button", class: "btn secondary", id: "seed-picker-paste-open", text: say(TEXT.pasteOpen) });
  const reviewAll = make("button", { type: "button", class: "btn secondary", id: "seed-picker-review-all", hidden: true, text: say(TEXT.reviewAll) });
  actions.appendChild(undoButton);
  actions.appendChild(pasteOpen);
  actions.appendChild(reviewAll);

  const paste = make("div", { id: "seed-picker-paste", hidden: true });
  const pasteLabel = make("label", { class: "field", id: "seed-picker-paste-label" });
  const pasteText = make("span", { id: "seed-picker-paste-text-label", text: say(TEXT.pasteLabel) });
  const pasteField = make("textarea", { id: "seed-picker-paste-text", ...textAttributes("seed-picker-paste-error") });
  pasteLabel.appendChild(pasteText);
  pasteLabel.appendChild(pasteField);
  const pasteError = make("p", { class: "field-note", id: "seed-picker-paste-error", hidden: true });
  const pasteActions = make("div", { class: "row tool-actions" });
  const pasteUse = make("button", { type: "button", class: "btn primary", id: "seed-picker-paste-use", text: say(TEXT.pasteUse) });
  const pasteCancel = make("button", { type: "button", class: "btn secondary", id: "seed-picker-paste-cancel", text: say(TEXT.cancel) });
  pasteActions.appendChild(pasteUse);
  pasteActions.appendChild(pasteCancel);
  paste.appendChild(pasteLabel);
  paste.appendChild(pasteError);
  paste.appendChild(pasteActions);

  const note = make("p", { class: "field-note edge-note is-private", id: "seed-picker-note", text: say(TEXT.note) });
  const progress = make("p", { class: "field-note", id: "seed-picker-progress", role: "status", "aria-live": "polite" });
  const caveat = make("p", { class: "field-note edge-note", id: "seed-picker-caveat", hidden: true, text: say(TEXT.caveat) });

  host.replaceChildren(positionLine, helpLine, chips, entryArea, review, actions, paste, note, progress, caveat);

  let checksum = "none";
  let reviewing = false;
  let reviewPosition = 0;
  let stagedIndex = null;
  let destroyed = false;

  const notify = () => {
    try {
      onChange({ count: entry.count, length: entry.length, complete: entry.count === entry.length, checksum });
    } catch {}
  };

  const checkChecksum = () => {
    if (entry.count !== entry.length) {
      checksum = "none";
      return;
    }
    let indices = null;
    let entropy = null;
    try {
      indices = seedIndices(entry);
      entropy = entropyFromWordIndices(indices);
      checksum = "ok";
    } catch {
      checksum = "bad";
    } finally {
      try { indices?.fill(0); } catch {}
      try { entropy?.fill(0); } catch {}
    }
  };

  const renderChips = () => {
    chips.replaceChildren();
    for (let position = 0; position < entry.count; position += 1) {
      const chip = make("button", {
        type: "button",
        class: "btn secondary",
        "data-word-position": String(position + 1),
        "aria-label": say(TEXT.chip, { n: position + 1 }),
      });
      chip.appendChild(make("span", { "aria-hidden": "true", text: String(position + 1) }));
      chip.appendChild(make("span", { "aria-hidden": "true", text: CHIP_DOTS }));
      chip.addEventListener("click", () => openReview(position));
      chips.appendChild(chip);
    }
  };

  const renderPosition = () => {
    if (entry.count === entry.length) positionLine.textContent = say(TEXT.progress, { count: entry.length, total: entry.length });
    else positionLine.textContent = say(TEXT.position, { n: entry.count + 1, total: entry.length });
  };

  const renderProgress = () => {
    if (entry.count !== entry.length) {
      progress.setAttribute("data-picker-state", "incomplete");
      progress.textContent = say(TEXT.progress, { count: entry.count, total: entry.length });
      caveat.hidden = true;
      return;
    }
    if (checksum === "ok") {
      progress.setAttribute("data-picker-state", "checksum-ok");
      progress.textContent = say(TEXT.checksumOk);
      caveat.hidden = false;
    } else {
      progress.setAttribute("data-picker-state", "checksum-bad");
      progress.textContent = say(TEXT.checksumBad);
      caveat.hidden = true;
    }
  };

  const renderVisibility = () => {
    const done = entry.count === entry.length;
    entryArea.hidden = done || reviewing;
    prefixField.hidden = done || reviewing;
    matches.hidden = done || reviewing;
    review.hidden = !reviewing;
    // Review, Undo and Paste are exclusive: an edit under an open review
    // would leave it showing a word that is no longer stored.
    undoButton.hidden = entry.count === 0 || reviewing;
    pasteOpen.hidden = reviewing;
    reviewAll.hidden = !done || reviewing;
    prefixText.textContent = say(TEXT.prefixLabel, { n: entry.count + 1 });
  };

  const render = () => {
    checkChecksum();
    renderChips();
    renderPosition();
    renderProgress();
    renderVisibility();
  };

  const renderMatches = (prefix, container, countNode, narrowNode, onPick) => {
    const query = String(prefix ?? "").trim().toLowerCase();
    container.replaceChildren();
    if (!query) {
      countNode.textContent = "";
      if (narrowNode) narrowNode.hidden = true;
      return;
    }
    const found = [];
    for (let index = 0; index < wordlist.length; index += 1) {
      if (wordlist[index].startsWith(query)) found.push(index);
    }
    if (found.length === 0) {
      countNode.textContent = say(TEXT.noMatch);
      if (narrowNode) narrowNode.hidden = true;
      return;
    }
    countNode.textContent = found.length === 1 ? say(TEXT.oneMatch) : say(TEXT.manyMatches, { count: found.length });
    if (found.length > MAX_MATCHES) {
      if (narrowNode) narrowNode.hidden = false;
      return;
    }
    if (narrowNode) narrowNode.hidden = true;
    for (const index of found) {
      // Candidate words are seed material: never translated or rewritten.
      const button = make("button", { type: "button", class: "btn secondary", "data-word-index": String(index), translate: "no", "data-i18n-skip": "", text: wordlist[index] });
      button.addEventListener("click", () => onPick(index));
      container.appendChild(button);
    }
  };

  const focusPrefix = () => {
    try { prefixField.focus(); } catch {}
  };

  const pickWord = (index) => {
    if (destroyed || entry.count >= entry.length) return;
    const position = entry.count;
    try {
      seedSet(entry, position, index);
    } catch {
      return;
    }
    prefixField.value = "";
    matches.replaceChildren();
    countLine.textContent = "";
    narrowLine.hidden = true;
    render();
    if (entry.count === entry.length) {
      renderProgress();
    } else {
      progress.setAttribute("data-picker-state", "incomplete");
      progress.textContent = say(TEXT.entered, { n: position + 1, next: entry.count + 1, total: entry.length });
    }
    notify();
    focusPrefix();
  };

  const onPrefixInput = () => {
    renderMatches(prefixField.value, matches, countLine, narrowLine, pickWord);
  };

  const onPrefixKeydown = (event) => {
    if (event.key !== "Enter") return;
    // An Enter that confirms an IME composition belongs to the IME.
    if (event.isComposing) return;
    event.preventDefault();
    const query = String(prefixField.value ?? "").trim().toLowerCase();
    if (!query) return;
    const found = [];
    for (let index = 0; index < wordlist.length; index += 1) {
      if (wordlist[index].startsWith(query)) found.push(index);
    }
    if (found.length === 1) pickWord(found[0]);
  };

  const onUndo = () => {
    if (destroyed || entry.count === 0) return;
    closeReview();
    try {
      seedUndo(entry);
    } catch {
      return;
    }
    render();
    notify();
    focusPrefix();
  };

  const resetReviewStaging = () => {
    stagedIndex = null;
    replaceField.value = "";
    replaceCount.textContent = "";
    replaceNarrow.hidden = true;
    replaceMatches.replaceChildren();
    replaceButton.setAttribute("disabled", "");
  };

  const renderReviewWord = () => {
    reviewWord.replaceChildren();
    if (!showBox.checked || entry.wiped || reviewPosition >= entry.count) {
      reviewWord.textContent = WORD_DOTS;
      return;
    }
    const indices = seedIndices(entry);
    let word;
    try {
      word = wordlist[indices[reviewPosition]];
    } finally {
      indices.fill(0);
    }
    if (typeof word !== "string") {
      reviewWord.textContent = WORD_DOTS;
      return;
    }
    reviewWord.appendChild(make("span", { translate: "no", "data-i18n-skip": "", "data-private-value": "", text: word }));
  };

  const renderReview = () => {
    reviewHeading.textContent = say(TEXT.reviewHeading, { n: reviewPosition + 1, total: entry.length });
    renderReviewWord();
    reviewPrev.disabled = reviewPosition <= 0;
    reviewNext.disabled = reviewPosition >= entry.count - 1;
  };

  const openReview = (position) => {
    if (destroyed || entry.wiped || entry.count === 0) return;
    closePaste();
    reviewing = true;
    reviewPosition = Math.max(0, Math.min(entry.count - 1, position));
    showBox.checked = false;
    resetReviewStaging();
    renderReview();
    renderVisibility();
    try { reviewHeading.focus(); } catch {}
  };

  const closeReview = () => {
    if (!reviewing) return;
    reviewing = false;
    showBox.checked = false;
    // A shown word leaves the DOM with the review, not just the screen.
    renderReviewWord();
    resetReviewStaging();
    renderVisibility();
    focusPrefix();
  };

  const moveReview = (delta) => {
    if (!reviewing) return;
    const next = reviewPosition + delta;
    if (next < 0 || next >= entry.count) return;
    reviewPosition = next;
    showBox.checked = false;
    resetReviewStaging();
    renderReview();
    try { reviewHeading.focus(); } catch {}
  };

  const stageWord = (index) => {
    stagedIndex = index;
    replaceButton.removeAttribute("disabled");
  };

  const onReplace = () => {
    if (destroyed || stagedIndex == null) return;
    const position = reviewPosition;
    try {
      seedSet(entry, position, stagedIndex);
    } catch {
      return;
    }
    resetReviewStaging();
    render();
    renderReview();
    if (entry.count === entry.length) {
      renderProgress();
    } else {
      progress.setAttribute("data-picker-state", "incomplete");
      progress.textContent = say(TEXT.replaced, { n: position + 1, next: entry.count + 1, total: entry.length });
    }
    notify();
  };

  const onShowToggle = () => {
    renderReviewWord();
  };

  const onReplaceInput = () => {
    // A word staged from the previous text is not what the field shows now.
    stagedIndex = null;
    replaceButton.setAttribute("disabled", "");
    renderMatches(replaceField.value, replaceMatches, replaceCount, replaceNarrow, stageWord);
  };

  const onReplaceKeydown = (event) => {
    if (event.key !== "Enter") return;
    // An Enter that confirms an IME composition belongs to the IME.
    if (event.isComposing) return;
    event.preventDefault();
    const query = String(replaceField.value ?? "").trim().toLowerCase();
    if (!query) return;
    const found = [];
    for (let index = 0; index < wordlist.length; index += 1) {
      if (wordlist[index].startsWith(query)) found.push(index);
    }
    if (found.length === 1) stageWord(found[0]);
  };

  const openPaste = () => {
    if (destroyed) return;
    closeReview();
    paste.hidden = false;
    pasteError.hidden = true;
    pasteError.textContent = "";
    try { pasteField.focus(); } catch {}
  };

  const closePaste = () => {
    pasteField.value = "";
    pasteError.hidden = true;
    pasteError.textContent = "";
    paste.hidden = true;
  };

  const onPasteUse = () => {
    if (destroyed) return;
    const words = String(pasteField.value ?? "").trim().toLowerCase().split(/\s+/).filter((word) => word.length > 0);
    let indices = null;
    let ok = false;
    try {
      if (words.length === entry.length) {
        indices = new Uint16Array(entry.length);
        let valid = true;
        for (let i = 0; i < words.length; i += 1) {
          const index = wordlist.indexOf(words[i]);
          if (index < 0) { valid = false; break; }
          indices[i] = index;
        }
        if (valid) {
          const before = seedIndices(entry);
          try {
            while (entry.count > 0) seedUndo(entry);
            for (let i = 0; i < indices.length; i += 1) seedSet(entry, i, indices[i]);
            ok = true;
          } catch {
            // Put the previous words back, so "Nothing was changed" holds.
            try {
              while (entry.count > 0) seedUndo(entry);
              for (let i = 0; i < before.length; i += 1) seedSet(entry, i, before[i]);
            } catch {}
          } finally {
            before.fill(0);
          }
        }
      }
    } catch {
      ok = false;
    } finally {
      try { indices?.fill(0); } catch {}
      pasteField.value = "";
    }
    if (!ok) {
      pasteError.textContent = say(TEXT.pasteFail, { total: entry.length });
      pasteError.hidden = false;
      return;
    }
    pasteError.hidden = true;
    pasteError.textContent = "";
    paste.hidden = true;
    render();
    if (entry.count === entry.length) {
      renderProgress();
    } else {
      progress.setAttribute("data-picker-state", "incomplete");
      progress.textContent = say(TEXT.progress, { count: entry.count, total: entry.length });
    }
    notify();
    focusPrefix();
  };

  const onConceal = () => {
    showBox.checked = false;
    renderReviewWord();
    prefixField.value = "";
    pasteField.value = "";
    matches.replaceChildren();
    countLine.textContent = "";
    narrowLine.hidden = true;
    // Clears the replacement field and disarms a staged word with it.
    resetReviewStaging();
  };

  const onVisibility = () => {
    if (doc.visibilityState === "hidden") onConceal();
  };

  prefixField.addEventListener("input", onPrefixInput);
  prefixField.addEventListener("keydown", onPrefixKeydown);
  replaceField.addEventListener("input", onReplaceInput);
  replaceField.addEventListener("keydown", onReplaceKeydown);
  showBox.addEventListener("change", onShowToggle);
  undoButton.addEventListener("click", onUndo);
  pasteOpen.addEventListener("click", openPaste);
  pasteUse.addEventListener("click", onPasteUse);
  pasteCancel.addEventListener("click", closePaste);
  reviewAll.addEventListener("click", () => openReview(0));
  reviewCancel.addEventListener("click", closeReview);
  reviewPrev.addEventListener("click", () => moveReview(-1));
  reviewNext.addEventListener("click", () => moveReview(1));
  replaceButton.addEventListener("click", onReplace);
  doc.addEventListener("hodl:conceal", onConceal);
  doc.addEventListener("visibilitychange", onVisibility);

  render();

  const destroy = () => {
    if (destroyed) return;
    destroyed = true;
    try { doc.removeEventListener("hodl:conceal", onConceal); } catch {}
    try { doc.removeEventListener("visibilitychange", onVisibility); } catch {}
    showBox.checked = false;
    try { renderReviewWord(); } catch {}
    // A unique match button's text is the word itself.
    try { matches.replaceChildren(); } catch {}
    try { resetReviewStaging(); } catch {}
    stagedIndex = null;
    prefixField.value = "";
    replaceField.value = "";
    pasteField.value = "";
    try { host.replaceChildren(); } catch {}
  };

  const focus = () => {
    if (reviewing) {
      try { reviewHeading.focus(); } catch {}
      return;
    }
    focusPrefix();
  };

  return { destroy, focus };
}
