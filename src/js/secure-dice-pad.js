// Secure entry: the strict dice pad (P4a). It owns the pad's DOM and writes
// the caller's rolls entry only through rollsPush and rollsUndo. Part B wires
// it into the Key Station behind the preview flag and the Secure entry switch;
// app.js does not import it yet.
//
// Security contract: the pad never keeps a roll beyond the one the user asks
// to see, never reads the whole sequence, never puts more than one face in the
// DOM or announces one, and clears the shown face on conceal and destroy
// without ever wiping the caller's entry. It takes no paste and lets nothing
// be copied, cut or dragged out of it. The caller destroys a pad before
// mounting another on the same entry.

const DOTS = "•";

const TEXT = {
  // APPROVED
  record: "Record roll: {n}",
  // APPROVED
  recorded: "{count} rolls recorded · Next: roll {next}",
  // DRAFT (owner OK pending)
  recordedOne: "{count} roll recorded · Next: roll {next}",
  // DRAFT (owner OK pending)
  full: "{count} rolls recorded. Secure entry holds up to {max} rolls.",
  // APPROVED
  undo: "Undo last roll",
  // APPROVED
  undone: "Last roll removed. {count} rolls recorded.",
  // DRAFT (owner OK pending)
  undoneOne: "Last roll removed. {count} roll recorded.",
  // APPROVED
  review: "Review one roll…",
  // DRAFT (owner OK pending)
  reviewHeading: "Roll {n} of {total}",
  // DRAFT (owner OK pending)
  positionLabel: "Roll number",
  // DRAFT (owner OK pending)
  showRoll: "Show this roll",
  // DRAFT (owner OK pending)
  reviewNote: "Only this roll is shown, and only while “Show this roll” is on.",
  // DRAFT (owner OK pending)
  prev: "Previous roll",
  // DRAFT (owner OK pending)
  next: "Next roll",
  // DRAFT (owner OK pending)
  close: "Close review",
};

export function mountSecureDicePad(host, {
  entry,
  rollsPush,
  rollsUndo,
  rollAt,
  labelledBy = "",
  translate = (text) => text,
  onChange = () => {},
  doc = document,
} = {}) {
  if (!entry || typeof entry !== "object" || entry.kind !== "rolls" || !(entry.rolls instanceof Uint8Array) || !Number.isInteger(entry.count)) throw new Error("A dice pad needs a rolls entry.");
  if (typeof rollsPush !== "function" || typeof rollsUndo !== "function" || typeof rollAt !== "function") throw new Error("A dice pad needs the rolls entry helpers.");

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

  const pad = make("div", { id: "secure-dice-pad", class: "dice-input-pad faces-1-6", role: "group" });
  if (labelledBy) pad.setAttribute("aria-labelledby", labelledBy);
  const faceButtons = [];
  for (let face = 1; face <= 6; face += 1) {
    const button = make("button", {
      type: "button",
      "data-secure-roll": String(face),
      "aria-label": say(TEXT.record, { n: face }),
      text: String(face),
    });
    button.addEventListener("click", () => record(face));
    faceButtons.push(button);
    pad.appendChild(button);
  }

  const status = make("p", { class: "field-note", id: "secure-dice-status", role: "status", "aria-live": "polite" });

  const actions = make("div", { class: "row tool-actions" });
  const undoButton = make("button", { type: "button", class: "btn secondary", id: "secure-dice-undo", hidden: true, text: say(TEXT.undo) });
  const reviewOpen = make("button", { type: "button", class: "btn secondary", id: "secure-dice-review-open", hidden: true, text: say(TEXT.review) });
  actions.appendChild(undoButton);
  actions.appendChild(reviewOpen);

  const review = make("div", { id: "secure-dice-review", hidden: true });
  const reviewHeading = make("p", { class: "label", id: "secure-dice-review-heading", tabindex: "-1" });
  const positionLabel = make("label", { class: "field" });
  const positionText = make("span", { text: say(TEXT.positionLabel) });
  const positionInput = make("input", {
    type: "number",
    id: "secure-dice-review-position",
    min: "1",
    max: String(entry.count),
    step: "1",
    inputmode: "numeric",
    autocomplete: "off",
  });
  positionLabel.appendChild(positionText);
  positionLabel.appendChild(positionInput);
  const faceContainer = make("div", { id: "secure-dice-review-face", text: DOTS });
  const showLabel = make("label", { class: "field" });
  const showBox = make("input", { type: "checkbox", id: "secure-dice-review-show" });
  const showText = make("span", { text: say(TEXT.showRoll) });
  showLabel.appendChild(showBox);
  showLabel.appendChild(showText);
  const reviewNote = make("p", { class: "field-note", text: say(TEXT.reviewNote) });
  const reviewActions = make("div", { class: "row tool-actions" });
  const reviewPrev = make("button", { type: "button", class: "btn secondary", id: "secure-dice-review-prev", text: say(TEXT.prev) });
  const reviewNext = make("button", { type: "button", class: "btn secondary", id: "secure-dice-review-next", text: say(TEXT.next) });
  const reviewClose = make("button", { type: "button", class: "btn secondary", id: "secure-dice-review-close", text: say(TEXT.close) });
  reviewActions.appendChild(reviewPrev);
  reviewActions.appendChild(reviewNext);
  reviewActions.appendChild(reviewClose);
  review.appendChild(reviewHeading);
  review.appendChild(positionLabel);
  review.appendChild(faceContainer);
  review.appendChild(showLabel);
  review.appendChild(reviewNote);
  review.appendChild(reviewActions);

  host.replaceChildren(pad, status, actions, review);

  let reviewing = false;
  let reviewPosition = 0;
  let lastAction = "recorded";
  let destroyed = false;

  const notify = () => {
    try {
      onChange({ count: entry.count, capacity: entry.rolls.length, full: entry.count === entry.rolls.length });
    } catch {}
  };

  const renderStatus = () => {
    const full = entry.count === entry.rolls.length;
    status.setAttribute("data-roll-count", String(entry.count));
    status.setAttribute("data-roll-state", full ? "full" : "open");
    if (full) {
      status.textContent = say(TEXT.full, { count: entry.count, max: entry.rolls.length });
    } else if (lastAction === "undone") {
      status.textContent = say(entry.count === 1 ? TEXT.undoneOne : TEXT.undone, { count: entry.count });
    } else {
      status.textContent = say(entry.count === 1 ? TEXT.recordedOne : TEXT.recorded, { count: entry.count, next: entry.count + 1 });
    }
  };

  const renderFace = () => {
    faceContainer.replaceChildren();
    // A face is shown only for the roll the field names: a number still being
    // typed, out of range or in another notation shows none (Grok, Kimi,
    // MiniMax, Astra).
    const named = String(positionInput.value ?? "").trim() === String(reviewPosition + 1);
    if (!showBox.checked || !named || entry.wiped || reviewPosition < 0 || reviewPosition >= entry.count) {
      if (showBox.checked && !named) showBox.checked = false;
      faceContainer.textContent = DOTS;
      return;
    }
    let face;
    try {
      face = rollAt(entry, reviewPosition);
    } catch {
      showBox.checked = false;
      faceContainer.textContent = DOTS;
      return;
    }
    if (!Number.isInteger(face) || face < 1 || face > 6) {
      showBox.checked = false;
      faceContainer.textContent = DOTS;
      return;
    }
    faceContainer.appendChild(make("span", {
      "data-secure-dice-face": "",
      "data-private-value": "",
      translate: "no",
      "data-i18n-skip": "",
      text: String(face),
    }));
  };

  const renderReview = () => {
    if (!reviewing) return;
    reviewHeading.textContent = say(TEXT.reviewHeading, { n: reviewPosition + 1, total: entry.count });
    positionInput.setAttribute("max", String(entry.count));
    positionInput.value = String(reviewPosition + 1);
    reviewPrev.disabled = reviewPosition <= 0;
    reviewNext.disabled = reviewPosition >= entry.count - 1;
    renderFace();
  };

  const renderVisibility = () => {
    const full = entry.count === entry.rolls.length;
    for (const button of faceButtons) button.disabled = full;
    pad.hidden = reviewing;
    undoButton.hidden = entry.count === 0 || reviewing;
    reviewOpen.hidden = entry.count === 0 || reviewing;
    review.hidden = !reviewing;
  };

  const render = () => {
    renderStatus();
    renderVisibility();
    if (reviewing) renderReview();
  };

  const record = (face) => {
    if (destroyed || reviewing) return;
    // The pad already knows a full entry cannot take another roll; do not
    // call into the entry layer for a roll it would refuse.
    if (entry.count >= entry.rolls.length) {
      render();
      return;
    }
    try {
      rollsPush(entry, face);
    } catch {
      render();
      return;
    }
    lastAction = "recorded";
    render();
    notify();
  };

  const onUndo = () => {
    if (destroyed || reviewing) return;
    try {
      rollsUndo(entry);
    } catch {
      render();
      return;
    }
    lastAction = "undone";
    render();
    notify();
    if (entry.count === 0) {
      try { faceButtons[0].focus(); } catch {}
    }
  };

  const openReview = () => {
    if (destroyed || entry.wiped || entry.count === 0) return;
    reviewing = true;
    reviewPosition = entry.count - 1;
    showBox.checked = false;
    renderReview();
    renderVisibility();
    try { reviewHeading.focus(); } catch {}
  };

  const closeReview = () => {
    if (!reviewing) return;
    reviewing = false;
    showBox.checked = false;
    renderFace();
    renderVisibility();
    try { reviewOpen.focus(); } catch {}
  };

  const moveReview = (delta) => {
    if (!reviewing) return;
    const next = reviewPosition + delta;
    if (next < 0 || next >= entry.count) return;
    reviewPosition = next;
    showBox.checked = false;
    renderReview();
    try { reviewHeading.focus(); } catch {}
  };

  const onPositionInput = () => {
    if (!reviewing) return;
    // Any edit hides the face first, so it never sits beside another number.
    showBox.checked = false;
    renderFace();
    const raw = String(positionInput.value ?? "").trim();
    if (!/^\d+$/.test(raw)) return;
    const n = Number(raw);
    if (!Number.isInteger(n) || n < 1 || n > entry.count) return;
    reviewPosition = n - 1;
    renderReview();
  };

  // Leaving the field with a number it cannot use puts the current one back.
  const onPositionChange = () => {
    if (reviewing) renderReview();
  };

  const onShowToggle = () => {
    if (!reviewing) {
      showBox.checked = false;
      return;
    }
    renderFace();
  };

  const onPadKeydown = (event) => {
    if (event.repeat) {
      event.preventDefault();
      return;
    }
    if (event.isComposing || event.ctrlKey || event.altKey || event.metaKey) return;
    const key = String(event.key ?? "");
    if (!/^[1-6]$/.test(key)) return;
    event.preventDefault();
    record(Number(key));
  };

  const onConceal = () => {
    showBox.checked = false;
    renderFace();
  };

  const onVisibility = () => {
    if (doc.visibilityState === "hidden") onConceal();
  };

  const blockClipboard = (event) => {
    event.preventDefault();
  };
  const HOST_BLOCKED = ["copy", "cut", "dragstart"];
  // A copy or a drag goes to where it started, which may be outside the pad
  // while the selection covers a shown face: refuse a selection that touches
  // the face. Only a shown face is secret, so a page-wide copy (Ctrl+A) still
  // works while none is shown (GLM, Grok, Kimi, MiniMax, round 2).
  const blockSelection = (event) => {
    try {
      const face = faceContainer.querySelector?.("[data-secure-dice-face]");
      if (!face) return;
      const selection = doc.getSelection?.();
      if (selection && !selection.isCollapsed && selection.containsNode?.(face, true)) event.preventDefault();
    } catch {}
  };
  const DOC_BLOCKED = ["copy", "cut", "dragstart"];
  // The roll number takes no paste or drop either (Kimi, round 2).
  const blockInput = (event) => event.preventDefault();

  pad.addEventListener("keydown", onPadKeydown);
  undoButton.addEventListener("click", onUndo);
  reviewOpen.addEventListener("click", openReview);
  showBox.addEventListener("change", onShowToggle);
  positionInput.addEventListener("input", onPositionInput);
  positionInput.addEventListener("change", onPositionChange);
  positionInput.addEventListener("paste", blockInput);
  positionInput.addEventListener("drop", blockInput);
  reviewPrev.addEventListener("click", () => moveReview(-1));
  reviewNext.addEventListener("click", () => moveReview(1));
  reviewClose.addEventListener("click", closeReview);
  for (const type of HOST_BLOCKED) host.addEventListener(type, blockClipboard);
  for (const type of DOC_BLOCKED) doc.addEventListener(type, blockSelection);
  doc.addEventListener("hodl:conceal", onConceal);
  doc.addEventListener("visibilitychange", onVisibility);

  render();

  const destroy = () => {
    if (destroyed) return;
    destroyed = true;
    try { doc.removeEventListener("hodl:conceal", onConceal); } catch {}
    try { doc.removeEventListener("visibilitychange", onVisibility); } catch {}
    for (const type of HOST_BLOCKED) {
      try { host.removeEventListener(type, blockClipboard); } catch {}
    }
    for (const type of DOC_BLOCKED) {
      try { doc.removeEventListener(type, blockSelection); } catch {}
    }
    showBox.checked = false;
    try { faceContainer.replaceChildren(); } catch {}
    try { host.replaceChildren(); } catch {}
  };

  const focus = () => {
    if (reviewing) {
      try { reviewHeading.focus(); } catch {}
      return;
    }
    const first = faceButtons.find((button) => !button.disabled)
      ?? [undoButton, reviewOpen].find((button) => !button.hidden)
      ?? faceButtons[0];
    try { first.focus(); } catch {}
  };

  return { destroy, focus };
}
