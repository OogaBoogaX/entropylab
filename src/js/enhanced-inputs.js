// Replaces <select> elements with custom dropdown listboxes (the only form
// controls this file touches — text/number inputs are handled elsewhere).
(() => {
  const enhanced = new WeakSet();
  const roots = new Set();

  const close = (root) => {
    root.classList.remove("open");
    root.querySelector(".custom-select-button")?.setAttribute("aria-expanded", "false");
    root.querySelector(".custom-select-list")?.setAttribute("hidden", "");
  };

  const closeAll = (except) => {
    roots.forEach((root) => {
      if (root !== except) close(root);
    });
  };

  const enhance = (select) => {
    if (enhanced.has(select)) return;
    enhanced.add(select);
    select.classList.add("custom-select-native");

    const root = document.createElement("div");
    root.className = "custom-select";
    const button = document.createElement("button");
    button.type = "button";
    button.className = "custom-select-button";
    button.setAttribute("aria-haspopup", "listbox");
    button.setAttribute("aria-expanded", "false");
    const label = document.createElement("span");
    label.className = "custom-select-value";
    const chevron = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    chevron.setAttribute("class", "custom-select-chevron");
    chevron.setAttribute("viewBox", "0 0 24 24");
    chevron.setAttribute("aria-hidden", "true");
    chevron.setAttribute("focusable", "false");
    const chevronPath = document.createElementNS("http://www.w3.org/2000/svg", "path");
    chevronPath.setAttribute("d", "m6 9 6 6 6-6");
    chevron.append(chevronPath);
    button.append(label, chevron);
    const list = document.createElement("div");
    list.className = "custom-select-list";
    list.setAttribute("role", "listbox");
    list.hidden = true;
    root.append(button, list);
    select.after(root);
    roots.add(root);

    // A select may hand the list an icon for each value: the option keeps its
    // plain text for the native control and assistive tech, and the custom
    // rendering puts the mark in front of it.
    const iconFor = (option) =>
      (typeof select.entropylabOptionIcon === "function" && option ? select.entropylabOptionIcon(option.value) : null);
    // Only the icon path wraps the text, so a plain select keeps the bare
    // textContent it has always carried.
    const textSpan = (text) => {
      const span = document.createElement("span");
      span.textContent = text;
      return span;
    };

    const sync = () => {
      const selected = select.options[select.selectedIndex] || select.options[0];
      const selectedIcon = iconFor(selected);
      if (selectedIcon) label.replaceChildren(selectedIcon, textSpan(selected?.textContent || "Select"));
      else label.textContent = selected?.textContent || "Select";
      const visibleOptions = [...select.options].filter((option) => option.dataset.customSelectPlaceholder !== "true");
      list.replaceChildren(...visibleOptions.map((option) => {
        const item = document.createElement("button");
        item.type = "button";
        item.className = "custom-select-option";
        item.setAttribute("role", "option");
        item.setAttribute("aria-selected", String(option.value === select.value));
        item.disabled = option.disabled;
        const optionIcon = iconFor(option);
        if (optionIcon) item.replaceChildren(optionIcon, textSpan(option.textContent));
        else item.textContent = option.textContent;
        item.onclick = (event) => {
          event.preventDefault();
          event.stopPropagation();
          select.value = option.value;
          sync();
          close(root);
          button.focus({ preventScroll: true });
          setTimeout(() => {
            if (select.isConnected) select.dispatchEvent(new Event("change", { bubbles: true }));
          }, 0);
        };
        return item;
      }));
    };

    const open = () => {
      closeAll(root);
      root.classList.add("open");
      button.setAttribute("aria-expanded", "true");
      list.hidden = false;
    };

    button.onclick = () => root.classList.contains("open") ? close(root) : open();
    button.onkeydown = (event) => {
      if (["ArrowDown", "Enter", " "].includes(event.key)) {
        event.preventDefault();
        open();
        (list.querySelector('[aria-selected="true"]:not(:disabled)') || list.querySelector(".custom-select-option:not(:disabled)"))?.focus();
      }
    };
    list.onkeydown = (event) => {
      const items = [...list.querySelectorAll(".custom-select-option:not(:disabled)")];
      const index = items.indexOf(document.activeElement);
      if (event.key === "ArrowDown") {
        event.preventDefault();
        items[Math.min(index + 1, items.length - 1)]?.focus();
      } else if (event.key === "ArrowUp") {
        event.preventDefault();
        items[Math.max(index - 1, 0)]?.focus();
      } else if (event.key === "Escape") {
        close(root);
        button.focus();
      }
    };

    select.addEventListener("change", sync);
    select.addEventListener("entropylab:sync-select", sync);
    new MutationObserver(sync).observe(select, { childList: true, subtree: true });
    sync();
  };

  const enhanceWithin = (node) => {
    if (!(node instanceof Element)) return;
    if (node.matches("select")) enhance(node);
    node.querySelectorAll("select").forEach(enhance);
  };

  document.querySelectorAll("select").forEach(enhance);
  new MutationObserver((records) => {
    records.forEach((record) => record.addedNodes.forEach(enhanceWithin));
  }).observe(document.body, { childList: true, subtree: true });

  document.addEventListener("click", (event) => {
    roots.forEach((root) => {
      if (!root.contains(event.target)) close(root);
    });
  });
})();
