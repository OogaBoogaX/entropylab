import { test } from "node:test";
import assert from "node:assert/strict";
import { MiniDocument } from "./mini-dom.mjs";
import { initNonceHistoryConfirm } from "../src/js/nonce-history-confirm.js";

async function withDialog(run) {
  const previous = globalThis.document;
  const document = new MiniDocument();
  globalThis.document = document;
  const opener = document.createElement("button");
  document.body.append(opener);
  const dialog = initNonceHistoryConfirm();
  for (const button of document.querySelectorAll("button")) {
    button.focus = () => { document.activeElement = button; };
    button.click = () => {
      if (!button.disabled) button.dispatchEvent({ type: "click", target: button });
    };
  }
  const el = (name) => document.getElementById(name === "modal" ? "nonce-history-confirm-modal" : `nonce-history-confirm-${name}`);
  try {
    await run({ dialog, document, opener, el });
  } finally {
    globalThis.document = previous;
  }
}

test("download mode keeps the primary disabled until both fields match, then resolves the passphrase", async () => {
  await withDialog(async ({ dialog, document, opener, el }) => {
    const decision = dialog.open({ mode: "download", opener });
    assert.equal(document.activeElement, el("cancel"));
    assert.equal(el("dialog").getAttribute("role"), "dialog");
    assert.equal(el("dialog").getAttribute("aria-modal"), "true");
    for (const name of ["labelledby", "describedby"]) {
      assert.ok(document.getElementById(el("dialog").getAttribute(`aria-${name}`)));
    }
    assert.equal(el("primary").disabled, true);
    el("passphrase").value = "long unique passphrase";
    el("passphrase").dispatchEvent({ type: "input", target: el("passphrase") });
    assert.equal(el("primary").disabled, true);
    el("repeat").value = "different";
    el("repeat").dispatchEvent({ type: "input", target: el("repeat") });
    assert.equal(el("primary").disabled, true);
    el("repeat").value = "long unique passphrase";
    el("repeat").dispatchEvent({ type: "input", target: el("repeat") });
    assert.equal(el("primary").disabled, false);
    el("primary").click();
    assert.equal(await decision, "long unique passphrase");
    assert.equal(el("passphrase").value, "");
    assert.equal(el("repeat").value, "");
    assert.ok(el("modal").hidden);
    assert.equal(document.activeElement, opener);
  });
});

test("Cancel and Escape resolve null and empty the fields", async () => {
  await withDialog(async ({ dialog, document, opener, el }) => {
    let decision = dialog.open({ mode: "download", opener });
    el("passphrase").value = "secret";
    el("repeat").value = "secret";
    el("cancel").click();
    assert.equal(await decision, null);
    assert.equal(el("passphrase").value, "");
    assert.equal(el("repeat").value, "");
    decision = dialog.open({ mode: "download", opener });
    el("modal").dispatchEvent({ type: "keydown", key: "Escape" });
    assert.equal(await decision, null);
    assert.equal(el("passphrase").value, "");
    assert.equal(el("repeat").value, "");
  });
});

test("import mode hides the repeat field and resolves the passphrase", async () => {
  await withDialog(async ({ dialog, document, opener, el }) => {
    const decision = dialog.open({ mode: "import", opener });
    assert.equal(el("repeat").hidden, true);
    assert.equal(el("primary").disabled, true);
    el("passphrase").value = "pass";
    el("passphrase").dispatchEvent({ type: "input", target: el("passphrase") });
    assert.equal(el("primary").disabled, false);
    el("primary").click();
    assert.equal(await decision, "pass");
    assert.equal(el("passphrase").value, "");
  });
});

test("settling empties every text node", async () => {
  await withDialog(async ({ dialog, document, opener, el }) => {
    const decision = dialog.open({ mode: "download", opener });
    el("cancel").click();
    await decision;
    for (const name of ["title", "message", "passphrase-label", "repeat-label", "primary", "cancel"]) {
      assert.equal(el(name).textContent, "");
    }
  });
});
