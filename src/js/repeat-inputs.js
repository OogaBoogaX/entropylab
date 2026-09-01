// Hold-to-repeat key auto-repeat for the on-screen keypads: holding a keypad
// button repeats its character insertion (after a delay, then an interval)
// through the beforeinput/input pipeline of the focused text control.
(() => {
  const repeatableInputTypes = new Set(["text", "search", "tel", "url", "password"]);
  const repeatDelay = 350;
  const repeatInterval = 45;
  let heldKey = null;

  const isRepeatableTextControl = (target) => {
    if (target instanceof HTMLTextAreaElement) return true;
    return target instanceof HTMLInputElement && repeatableInputTypes.has(target.type);
  };

  const stopRepeating = (expectedState) => {
    if (expectedState && heldKey !== expectedState) return;
    const state = heldKey;
    heldKey = null;
    if (!state) return;
    clearTimeout(state.delayTimer);
    clearInterval(state.intervalTimer);
  };

  const insertText = (target, text) => {
    const beforeInput = new InputEvent("beforeinput", {
      bubbles: true,
      cancelable: true,
      composed: true,
      inputType: "insertText",
      data: text
    });
    if (!target.dispatchEvent(beforeInput) || !target.isConnected) return false;

    const start = target.selectionStart ?? target.value.length;
    const end = target.selectionEnd ?? start;
    let insertion = text;
    if (target.maxLength >= 0) {
      const remaining = target.maxLength - (target.value.length - (end - start));
      insertion = insertion.slice(0, Math.max(0, remaining));
    }
    if (!insertion) return false;

    target.setRangeText(insertion, start, end, "end");
    target.dispatchEvent(new InputEvent("input", {
      bubbles: true,
      composed: true,
      inputType: "insertText",
      data: insertion
    }));
    return true;
  };

  const repeatHeldKey = (state) => {
    if (
      heldKey !== state ||
      !state.target.isConnected ||
      document.activeElement !== state.target ||
      state.target.disabled ||
      state.target.readOnly
    ) {
      stopRepeating(state);
      return;
    }
    insertText(state.target, state.text);
  };

  const beginRepeating = (state) => {
    if (heldKey !== state || state.intervalTimer) return;
    clearTimeout(state.delayTimer);
    repeatHeldKey(state);
    if (heldKey !== state) return;
    state.intervalTimer = setInterval(() => repeatHeldKey(state), repeatInterval);
  };

  document.addEventListener("keydown", (event) => {
    const target = event.target;
    if (
      event.isComposing ||
      event.defaultPrevented ||
      event.metaKey ||
      event.ctrlKey ||
      event.altKey ||
      event.key.length !== 1 ||
      !isRepeatableTextControl(target) ||
      target.disabled ||
      target.readOnly
    ) return;

    const identity = event.code || event.key;
    if (event.repeat) {
      if (heldKey && heldKey.target === target && heldKey.identity === identity) {
        event.preventDefault();
        heldKey.text = event.key;
        beginRepeating(heldKey);
      }
      return;
    }

    stopRepeating();
    const state = {
      target,
      identity,
      text: event.key,
      delayTimer: 0,
      intervalTimer: 0
    };
    heldKey = state;
    state.delayTimer = setTimeout(() => beginRepeating(state), repeatDelay);
  });

  document.addEventListener("keyup", (event) => {
    if (!heldKey) return;
    const identity = event.code || event.key;
    if (identity === heldKey.identity) stopRepeating();
  });
  document.addEventListener("focusout", (event) => {
    if (heldKey?.target === event.target) stopRepeating();
  });
  window.addEventListener("blur", () => stopRepeating());
  document.addEventListener("visibilitychange", () => {
    if (document.hidden) stopRepeating();
  });
})();
