import { test } from "node:test";
import assert from "node:assert/strict";
import { MiniDocument } from "./mini-dom.mjs";
import { initSecureEntryConfirm } from "../src/js/secure-entry-confirm.js";

async function withDialog(run) {
  const previous = globalThis.document;
  const document = new MiniDocument();
  globalThis.document = document;
  const opener = document.createElement("button");
  document.body.append(opener);
  const dialog = initSecureEntryConfirm();
  for (const button of document.querySelectorAll("button")) {
    button.focus = () => { document.activeElement = button; };
    button.click = () => {
      if (!button.disabled) button.dispatchEvent({ type: "click", target: button });
    };
  }
  const el = (name) => document.getElementById(name === "modal" ? "secure-entry-modal" : `secure-entry-confirm-${name}`);
  try {
    await run({ dialog, document, opener, el });
  } finally {
    globalThis.document = previous;
  }
}

test("mode on with one name defaults to Cancel and Keep resolves keep", async () => {
  await withDialog(async ({ dialog, document, opener, el }) => {
    const decision = dialog.open({ mode: "on", names: ["Key 1"], canKeep: true, opener });
    assert.equal(document.activeElement, el("cancel"));
    assert.equal(el("dialog").getAttribute("role"), "dialog");
    assert.equal(el("dialog").getAttribute("aria-modal"), "true");
    for (const name of ["labelledby", "describedby"]) {
      assert.ok(document.getElementById(el("dialog").getAttribute(`aria-${name}`)));
    }
    assert.equal(el("names").hidden, true);
    for (const name of ["title", "message", "primary", "secondary", "cancel"]) {
      assert.ok(el(name).textContent.trim());
    }
    el("primary").click();
    assert.equal(await decision, "keep");
    assert.ok(el("modal").hidden);
    assert.equal(document.activeElement, opener);
  });
});

test("mode on with two names lists them as text and Clear resolves clear", async () => {
  await withDialog(async ({ dialog, document, opener, el }) => {
    const hostile = `<img src=x onerror=alert(1)>`;
    const decision = dialog.open({ mode: "on", names: ["Key 1", hostile], canKeep: true, opener });
    const items = el("names").querySelectorAll("li");
    assert.equal(items.length, 2);
    assert.equal(items[0].textContent, "Key 1");
    assert.equal(items[1].textContent, hostile);
    assert.equal(items[1].children.length, 0);
    assert.equal(el("names").hidden, false);
    el("secondary").click();
    assert.equal(await decision, "clear");
  });
});

test("canKeep false hides primary and shows the cannot-keep note", async () => {
  await withDialog(async ({ dialog, document, opener, el }) => {
    const decision = dialog.open({ mode: "on", names: ["Key 1"], canKeep: false, opener });
    assert.equal(el("primary").hidden, true);
    assert.equal(el("cannot-keep").hidden, false);
    el("primary").click();
    assert.equal(el("modal").hidden, false);
    el("cancel").click();
    assert.equal(await decision, null);
  });
});

test("mode off resolves convert, then clear, then Escape null", async () => {
  await withDialog(async ({ dialog, document, opener, el }) => {
    let decision = dialog.open({ mode: "off", opener });
    el("primary").click();
    assert.equal(await decision, "convert");
    decision = dialog.open({ mode: "off", opener });
    el("secondary").click();
    assert.equal(await decision, "clear");
    decision = dialog.open({ mode: "off", opener });
    el("modal").dispatchEvent({ type: "keydown", key: "Escape" });
    assert.equal(await decision, null);
  });
});

test("opening while open settles the first request with null", async () => {
  await withDialog(async ({ dialog, document, opener, el }) => {
    const first = dialog.open({ mode: "on", names: ["Key 1"], canKeep: true, opener });
    const second = dialog.open({ mode: "off", opener });
    assert.equal(await first, null);
    el("primary").click();
    assert.equal(await second, "convert");
  });
});

test("unknown mode resolves null and shows nothing", async () => {
  await withDialog(async ({ dialog, document, opener, el }) => {
    const decision = dialog.open({ mode: "bogus", opener });
    assert.equal(await decision, null);
    assert.ok(el("modal").hidden);
    // Turning on with no key names has nothing to ask about.
    for (const names of [[], undefined, "Key 1"]) {
      assert.equal(await dialog.open({ mode: "on", names, canKeep: true, opener }), null);
      assert.ok(el("modal").hidden);
      assert.equal(el("message").textContent, "");
    }
  });
});

test("settling empties every text node and the names list", async () => {
  await withDialog(async ({ dialog, document, opener, el }) => {
    const decision = dialog.open({ mode: "on", names: ["Key 1", "Key 2"], canKeep: true, opener });
    el("cancel").click();
    await decision;
    for (const name of ["title", "message", "cannot-keep", "primary", "secondary", "cancel"]) {
      assert.equal(el(name).textContent, "");
    }
    assert.equal(el("names").children.length, 0);
  });
});
