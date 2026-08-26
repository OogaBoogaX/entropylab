(() => {
  const wrap = document.querySelector("#btc-calc > .wrap");
  if (!wrap) return;

  const control = document.createElement("label");
  control.className = "bryan-mode-control no-print";
  const checkbox = document.createElement("input");
  checkbox.type = "checkbox";
  checkbox.id = "bryan-mode";
  checkbox.setAttribute("aria-label", "Bryan mode: use bare HTML");
  control.append(checkbox, document.createTextNode(" Bryan mode (bare HTML)"));
  wrap.prepend(control);

  const stylesheetStates = new Map();
  const inlineStyleStates = new Map();
  let inlineStyleObserver = null;

  const removeInlineStyles = (root) => {
    const elements = [];
    if (root instanceof Element && root.hasAttribute("style")) elements.push(root);
    root.querySelectorAll?.("[style]").forEach(element => elements.push(element));
    elements.forEach(element => {
      inlineStyleStates.set(element, element.getAttribute("style"));
      element.removeAttribute("style");
    });
  };

  const enableBryanMode = () => {
    [...document.styleSheets].forEach(stylesheet => {
      stylesheetStates.set(stylesheet, stylesheet.disabled);
      stylesheet.disabled = true;
    });
    removeInlineStyles(document);
    inlineStyleObserver = new MutationObserver(mutations => {
      mutations.forEach(mutation => {
        if (mutation.type === "attributes") removeInlineStyles(mutation.target);
        mutation.addedNodes.forEach(node => removeInlineStyles(node));
      });
    });
    inlineStyleObserver.observe(document.documentElement, {
      attributes: true,
      attributeFilter: ["style"],
      childList: true,
      subtree: true
    });
  };

  const disableBryanMode = () => {
    inlineStyleObserver?.disconnect();
    inlineStyleObserver = null;
    stylesheetStates.forEach((disabled, stylesheet) => {
      stylesheet.disabled = disabled;
    });
    stylesheetStates.clear();
    inlineStyleStates.forEach((style, element) => {
      if (element.isConnected && style !== null) element.setAttribute("style", style);
    });
    inlineStyleStates.clear();
  };

  checkbox.addEventListener("change", () => {
    if (checkbox.checked) enableBryanMode();
    else disableBryanMode();
  });
})();
