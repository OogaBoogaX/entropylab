
// Optional on-screen virtual keyboards for the entropy input fields.
// Any field marked with data-vk="<layout>" gets a small keyboard glyph that
// toggles an on-screen keyboard for pointer-based entry. A Shuffle control
// reorders the character keys on every press so key positions do not stay
// predictable across entries.
(() => {
  const layouts = {
    dice: { label: "dice rolls", keys: "123456", columns: 2 },
    dplus: { label: "D++ rolls", keys: "1234567890ABCDEF", columns: 4, dplus: true },
    "dplus-numbered": { label: "D++ rolls", keys: "123456789ABCDEFG", columns: 4, dplus: true },
    hex: { label: "hexadecimal entropy", keys: "0123456789ABCDEF", columns: 4 },
    bin: {
      label: "binary entropy",
      keys: [
        { character: "0", text: "Heads (0)", aria: "Enter Heads as binary 0", className: "coin-button" },
        { character: "1", text: "Tails (1)", aria: "Enter Tails as binary 1", className: "coin-button" }
      ]
    },
    seed: { label: "seed phrase", keys: "abcdefghijklmnopqrstuvwxyz", columns: 6, space: true },
    key: { label: "private key", keys: "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz", columns: 4, space: true }
  };

  const entry = (definition, index) => {
    const detail = typeof definition === "string"
      ? { character: definition, text: definition, aria: `Insert ${definition}` }
      : definition;
    return { className: "", ...detail, index };
  };

  const enhanced = new WeakSet();

  const randomBelow = (max) => {
    const buffer = new Uint32Array(1);
    const limit = Math.floor(0x100000000 / max) * max;
    do {
      crypto.getRandomValues(buffer);
    } while (buffer[0] >= limit);
    return buffer[0] % max;
  };

  const shuffled = (values) => {
    const result = [...values];
    for (let index = result.length - 1; index > 0; index--) {
      const swap = randomBelow(index + 1);
      [result[index], result[swap]] = [result[swap], result[index]];
    }
    return result;
  };

  const insertText = (target, text) => {
    const start = target.selectionStart ?? target.value.length;
    const end = target.selectionEnd ?? start;
    target.setRangeText(text, start, end, "end");
    target.dispatchEvent(new InputEvent("input", {
      bubbles: true,
      composed: true,
      inputType: "insertText",
      data: text
    }));
  };

  const deleteBackward = (target) => {
    let start = target.selectionStart ?? target.value.length;
    const end = target.selectionEnd ?? start;
    if (start === end) {
      if (start === 0) return;
      start -= 1;
    }
    target.setRangeText("", start, end, "start");
    target.dispatchEvent(new InputEvent("input", {
      bubbles: true,
      composed: true,
      inputType: "deleteContentBackward",
      data: null
    }));
  };

  const holdFocus = (button) => {
    button.addEventListener("pointerdown", (event) => event.preventDefault());
  };

  const makeKey = (className, text, ariaLabel, onPress) => {
    const button = document.createElement("button");
    button.type = "button";
    button.className = `vk-key ${className}`.trim();
    button.textContent = text;
    button.setAttribute("aria-label", ariaLabel);
    holdFocus(button);
    button.onclick = onPress;
    return button;
  };

  const dplusLabel = (character) => {
    if (character === "G") return { text: "16 (G)", aria: "Numbered D16 face 16, entered as G" };
    const decimal = Number.parseInt(character, 16);
    return { text: decimal >= 10 ? `${decimal} (${character})` : character, aria: `D16 face ${character}` };
  };

  const enhance = (field) => {
    if (enhanced.has(field)) return;
    const layout = layouts[field.dataset.vk];
    if (!layout || !field.parentNode) return;
    enhanced.add(field);

    const host = field.closest(".dice-input-shell") || field;
    const wrap = document.createElement("div");
    wrap.className = "vk-wrap";
    host.before(wrap);
    wrap.appendChild(host);

    const toggle = document.createElement("button");
    toggle.type = "button";
    toggle.className = "vk-toggle";
    toggle.textContent = "⌨︎";
    toggle.title = "Toggle the on-screen keyboard";
    toggle.setAttribute("aria-label", `Toggle the on-screen keyboard for the ${layout.label} field`);
    toggle.setAttribute("aria-expanded", "false");
    holdFocus(toggle);

    const panel = document.createElement("div");
    panel.className = "vk-panel";
    panel.hidden = true;
    panel.setAttribute("role", "group");
    panel.setAttribute("aria-label", `On-screen keyboard for the ${layout.label} field`);

    const grid = document.createElement("div");
    grid.className = "vk-grid dice-input-pad";
    if (layout.columns) grid.style.setProperty("--vk-columns", String(layout.columns));
    const renderKeys = (order) => {
      grid.replaceChildren(...order.map((definition, index) => {
        const key = layout.dplus && typeof definition === "string"
          ? { character: definition, ...dplusLabel(definition), className: "dplus" }
          : entry(definition, index);
        return makeKey(key.className, key.text, key.aria, () => insertText(field, key.character));
      }));
    };
    let order = [...layout.keys];
    renderKeys(order);

    const setOpen = (open) => {
      panel.hidden = !open;
      toggle.setAttribute("aria-expanded", String(open));
      wrap.classList.toggle("vk-open", open);
    };
    toggle.onclick = () => setOpen(panel.hidden);

    const controls = document.createElement("div");
    controls.className = "vk-controls";
    if (layout.space) {
      controls.appendChild(makeKey("vk-space", "Space", "Insert a space", () => insertText(field, " ")));
    }
    controls.append(
      makeKey("vk-backspace", "⌫", "Delete the previous character", () => deleteBackward(field)),
      makeKey("vk-shuffle", "Shuffle", "Shuffle the key order", () => {
        order = shuffled(order);
        renderKeys(order);
      }),
      makeKey("vk-done", "Done", "Hide the on-screen keyboard", () => setOpen(false))
    );

    panel.append(grid, controls);
    wrap.append(toggle, panel);
  };

  const enhanceWithin = (node) => {
    if (!(node instanceof Element)) return;
    if (node.matches("[data-vk]")) enhance(node);
    node.querySelectorAll("[data-vk]").forEach(enhance);
  };

  document.querySelectorAll("[data-vk]").forEach(enhance);
  new MutationObserver((records) => {
    records.forEach((record) => record.addedNodes.forEach(enhanceWithin));
  }).observe(document.body, { childList: true, subtree: true });
})();
