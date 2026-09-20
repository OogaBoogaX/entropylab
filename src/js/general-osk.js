// ==== EntropyLab general on-screen keyboard ====
// For non-sensitive text/number inputs on touch devices.
// Shows only when (pointer: coarse) is detected.
// Follows the existing hodlKeyboardToggleMarkup / hodlKeyboardMarkup patterns.
(function () {
  "use strict";

  // !!! DEBUG-ONLY OVERRIDE — REMOVE BEFORE SUBMITTING THE PR !!!
  // Forces the OSK on for desktop development (pikvm/laptop iteration).
  // When done iterating, delete this const to restore touch-only gating.
  const GENERAL_OSK_FORCE_ON = true;

  // Only on touch devices (unless the debug override above is set)
  if (!GENERAL_OSK_FORCE_ON && !window.matchMedia("(pointer: coarse)").matches) return;

  const KEYBOARD_ID = "general-osk";
  const TOGGLE_CLASS = "general-keyboard-toggle";

  // Keyboard SVG icon (same visual language as existing seed-keyboard-toggle)
  const toggleSVG = `<svg viewBox="0 0 64 44" aria-hidden="true" focusable="false"><rect class="seed-keyboard-icon-case" x="3" y="6" width="58" height="32" rx="4"/><g class="seed-keyboard-icon-keys"><rect x="9" y="10" width="4" height="5" rx=".5"/><rect x="15" y="10" width="4" height="5" rx=".5"/><rect x="21" y="10" width="4" height="5" rx=".5"/><rect x="27" y="10" width="4" height="5" rx=".5"/><rect x="33" y="10" width="4" height="5" rx=".5"/><rect x="39" y="10" width="4" height="5" rx=".5"/><rect x="45" y="10" width="4" height="5" rx=".5"/><rect x="51" y="10" width="4" height="5" rx=".5"/><rect x="12" y="18" width="4" height="5" rx=".5"/><rect x="18" y="18" width="4" height="5" rx=".5"/><rect x="24" y="18" width="4" height="5" rx=".5"/><rect x="30" y="18" width="4" height="5" rx=".5"/><rect x="36" y="18" width="4" height="5" rx=".5"/><rect x="42" y="18" width="4" height="5" rx=".5"/><rect x="48" y="18" width="4" height="5" rx=".5"/><rect x="17" y="28" width="30" height="5" rx=".75"/></g></svg>`;

  let activeInput = null;
  let keyboardVisible = false;

  // Fields already covered by existing on-screen keyboards
  const EXISTING_KEYBOARD_FIELDS = new Set([
    "entropy-input", "pass", "private-key-input", "base64-input", "bech32-input",
  ]);

  // Per-field keyboard layouts. A field listed here gets a purpose-built
  // multi-row keyboard; everything else falls back to the full layout.
  // Rows render as flex rows that fill the panel width; keeping each row's
  // key count equal makes all keys approximately the same size.
  const FIELD_CHARSETS = {
    // Derivation path: digits on row 1; m / ' + backspace on row 2
    "derivation-path": [
      ["1", "2", "3", "4", "5", "6", "7", "8", "9", "0"],
      ["m", "/", "'", "backspace"],
    ],
  };

  function charsetFor(input) {
    if (FIELD_CHARSETS[input.id]) return FIELD_CHARSETS[input.id];
    if (input.inputMode === "numeric" || input.type === "number") {
      return [["1", "2", "3", "4", "5", "6", "7", "8", "9", "0"]];
    }
    return null; // full layout
  }

  function isEligibleInput(input) {
    if (!input || !input.id) return false;
    if (EXISTING_KEYBOARD_FIELDS.has(input.id)) return false;
    const type = (input.type || "text").toLowerCase();
    if (!["text", "number"].includes(type)) return false;
    if (input.disabled || input.readOnly) return false;
    return true;
  }

  function buildToggle(input) {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = TOGGLE_CLASS + " seed-keyboard-toggle";
    btn.dataset.generalOskToggle = input.id;
    btn.setAttribute("aria-label", "Show on-screen keyboard");
    btn.setAttribute("aria-expanded", "false");
    btn.innerHTML = toggleSVG;
    btn.addEventListener("click", function (e) {
      e.preventDefault();
      toggleKeyboard(input);
    });
    return btn;
  }

  function buildKeyboardPanel(charset) {
      const panel = document.createElement("div");
      panel.className = "seed-keyboard general-osk-panel";
      panel.id = KEYBOARD_ID;
      panel.setAttribute("data-on-screen-keyboard", "");
      panel.setAttribute("role", "group");
      panel.setAttribute("aria-label", "On-screen keyboard");
      panel.hidden = true;

      if (charset) {
        // Purpose-built multi-row keyboard for this field's layout.
        // Every row is a general-osk-key-row (flex, fills panel width);
        // equal key counts per row = uniform key sizes.
        let html = "";
        for (const row of charset) {
          html += '<div class="seed-keyboard-row general-osk-key-row">';
          for (const k of row) {
            if (k === "backspace") {
              html += `<button type="button" class="seed-keyboard-key seed-keyboard-delete" data-general-key="backspace" aria-label="Backspace"><svg viewBox="0 0 24 18" aria-hidden="true" focusable="false"><path d="M9 2h11a2 2 0 0 1 2 2v10a2 2 0 0 1-2 2H9L2 9l7-7Z"/><path d="m12 6 6 6m0-6-6 6"/></svg></button>`;
            } else {
              html += `<button type="button" class="seed-keyboard-key" data-general-key="${k}" aria-label="Enter ${k}">${k}</button>`;
            }
          }
          html += '</div>';
        }
        panel.innerHTML = html;
      } else {
      // Full layout: matches existing seed-keyboard structure
      // Row 1: numbers + symbols, Row 2: qwerty, Row 3: asdf, Row 4: zxcv + mode + space
      const numbers = "1 2 3 4 5 6 7 8 9 0 / ' \u232b".split(" ");
      const row1 = "q w e r t y u i o p".split(" ");
      const row2 = "a s d f g h j k l".split(" ");
      const row3 = "z x c v b n m".split(" ");

      let html = '<div class="seed-keyboard-row">';
      for (const k of numbers) {
        if (k === "\u232b") {
          html += `<button type="button" class="seed-keyboard-key seed-keyboard-delete" data-general-key="backspace" aria-label="Backspace"><svg viewBox="0 0 24 18" aria-hidden="true" focusable="false"><path d="M9 2h11a2 2 0 0 1 2 2v10a2 2 0 0 1-2 2H9L2 9l7-7Z"/><path d="m12 6 6 6m0-6-6 6"/></svg></button>`;
        } else {
          html += `<button type="button" class="seed-keyboard-key" data-general-key="${k}">${k}</button>`;
        }
      }
      html += '</div><div class="seed-keyboard-row">';
      for (const k of row1) {
        html += `<button type="button" class="seed-keyboard-key" data-general-key="${k}">${k}</button>`;
      }
      html += '</div><div class="seed-keyboard-row">';
      for (const k of row2) {
        html += `<button type="button" class="seed-keyboard-key" data-general-key="${k}">${k}</button>`;
      }
      html += '</div><div class="seed-keyboard-row">';
      for (const k of row3) {
        html += `<button type="button" class="seed-keyboard-key" data-general-key="${k}">${k}</button>`;
      }
      html += `<button type="button" class="seed-keyboard-mode" data-general-key="mode" aria-label="Change keyboard mode">aA1</button>`;
      html += `<button type="button" class="seed-keyboard-space" data-general-key=" " aria-label="Enter space">space</button>`;
      html += '</div>';
      panel.innerHTML = html;
    }
    return panel;
  }

  function toggleKeyboard(input) {
    activeInput = input;
    let panel = document.getElementById(KEYBOARD_ID);

    // Determine this field's character set (null = full layout)
    const charset = charsetFor(input);

    // Rebuild panel if mode changed or doesn't exist
    // Serialize the (possibly nested) layout for change detection
    const charsetId = charset ? charset.map((r) => r.join("")).join("|") : "full";
    if (!panel || panel.dataset.charset !== charsetId) {
      if (panel) panel.remove();
      panel = buildKeyboardPanel(charset);
      panel.dataset.charset = charsetId;
      document.body.append(panel);
      // Wire key clicks
      panel.addEventListener("click", function (e) {
        const key = e.target.closest("[data-general-key]");
        if (!key) return;
        e.preventDefault();
        applyKey(key.dataset.generalKey);
      });
    }

    if (keyboardVisible && panel.dataset.activeFor === input.id) {
      // Hide
      panel.hidden = true;
      keyboardVisible = false;
      panel.dataset.activeFor = "";
      document.querySelectorAll(`[data-general-osk-toggle]`).forEach((b) => {
        b.setAttribute("aria-expanded", "false");
        b.setAttribute("aria-label", "Show on-screen keyboard");
      });
    } else {
      // Show
      panel.hidden = false;
      keyboardVisible = true;
      panel.dataset.activeFor = input.id;
      document.querySelectorAll(`[data-general-osk-toggle="${input.id}"]`).forEach((b) => {
        b.setAttribute("aria-expanded", "true");
        b.setAttribute("aria-label", "Hide on-screen keyboard");
      });
      // Position the panel below the field's ROW (not inside the grid cell,
      // which would squash it to half width or drop it into the wrong column).
      // Justification follows the field's column: a field in the row's LEFT
      // grid column gets a left-justified keyboard, a field in the RIGHT
      // column gets a right-justified one, so the keyboard sits under the
      // field that opened it.
      const field = input.closest("label.field, .field") || input.parentElement;
      const row = field && field.closest(".key-settings-row");
      if (row && row.parentNode) {
        row.parentNode.insertBefore(panel, row.nextSibling);
        // Column detection: compare the field against the row's first grid child
        const firstCell = row.firstElementChild;
        const inLeftColumn = !firstCell || field === firstCell || firstCell.contains(field);
        panel.classList.toggle("general-osk-left", inLeftColumn);
      } else if (field && field.parentNode) {
        field.parentNode.insertBefore(panel, field.nextSibling);
        panel.classList.remove("general-osk-left");
      }
      input.focus();
    }
  }

  function applyKey(key) {
    if (!activeInput) return;
    const input = activeInput;
    const start = input.selectionStart || 0;
    const end = input.selectionEnd || 0;
    const value = input.value || "";

    if (key === "backspace") {
      if (start === end && start > 0) {
        input.value = value.slice(0, start - 1) + value.slice(end);
        input.selectionStart = input.selectionEnd = start - 1;
      } else {
        input.value = value.slice(0, start) + value.slice(end);
        input.selectionStart = input.selectionEnd = start;
      }
    } else if (key === "mode") {
      // TODO: cycle between lower/upper/numeric (future enhancement)
      return;
    } else {
      input.value = value.slice(0, start) + key + value.slice(end);
      input.selectionStart = input.selectionEnd = start + key.length;
    }

    input.dispatchEvent(new Event("input", { bubbles: true }));
    input.dispatchEvent(new Event("change", { bubbles: true }));
    input.focus();
  }

  function initGeneralOSK() {
    if (document.getElementById(KEYBOARD_ID)) return; // already init'd

    // Find all eligible inputs and add toggle buttons
    document.querySelectorAll("input").forEach(function (input) {
      if (!isEligibleInput(input)) return;
      if (input.dataset.generalOskAttached) return;
      input.dataset.generalOskAttached = "1";

      // Toggle sits directly beneath the input (inside the field container,
      // before any help note) so it visually belongs to the field it opens
      const wrapper = input.parentElement;
      if (wrapper) {
        const toggle = buildToggle(input);
        input.insertAdjacentElement("afterend", toggle);
      }
    });

    // Hide keyboard when clicking outside an input
    document.addEventListener("click", function (e) {
      if (!keyboardVisible) return;
      if (e.target.closest("[data-general-osk-toggle]")) return;
      if (e.target.closest("#" + KEYBOARD_ID)) return;
      if (e.target.tagName === "INPUT") return;
      // Click elsewhere — hide
      const panel = document.getElementById(KEYBOARD_ID);
      if (panel) panel.hidden = true;
      keyboardVisible = false;
      document.querySelectorAll("[data-general-osk-toggle]").forEach((b) => {
        b.setAttribute("aria-expanded", "false");
      });
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", initGeneralOSK);
  } else {
    initGeneralOSK();
  }
})();
// ==== end general on-screen keyboard ====
