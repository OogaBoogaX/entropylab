import { test } from "node:test";
import assert from "node:assert/strict";
import { MiniDocument } from "./mini-dom.mjs";
import { initJournalClearConfirm } from "../src/js/journal-clear-confirm.js";

async function withDialog(run, download = async () => true) {
  const previous = globalThis.document;
  const document = new MiniDocument();
  globalThis.document = document;
  const opener = document.createElement("button");
  document.body.append(opener);
  let discarded = 0, downloads = 0;
  const dialog = initJournalClearConfirm({
    onDownload: (isCurrent) => { downloads++; return download(isCurrent); },
    onDiscard: () => discarded++,
  });
  // MiniDOM's click only runs onclick and its focus is intentionally inert.
  // Model those browser operations locally for this event-listener dialog.
  for (const button of document.querySelectorAll("button")) {
    button.focus = () => { document.activeElement = button; };
    button.click = () => {
      if (!button.disabled) button.dispatchEvent({ type: "click", target: button });
    };
  }
  const el = (name) => document.getElementById(`journal-clear-${name}`);
  try {
    dialog.show(opener);
    await run({ dialog, document, opener, el, counts: () => ({ discarded, downloads }) });
  } finally {
    globalThis.document = previous;
  }
}

const settle = () => new Promise((resolve) => setImmediate(resolve));
function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}

test("clear confirmation defaults to Cancel and only explicit Discard clears", async () => {
  await withDialog(async ({ dialog, document, opener, el, counts }) => {
    assert.equal(document.activeElement, el("cancel"));
    assert.equal(el("dialog").getAttribute("role"), "dialog");
    assert.equal(el("dialog").getAttribute("aria-modal"), "true");
    for (const name of ["labelledby", "describedby"]) {
      assert.ok(document.getElementById(el("dialog").getAttribute(`aria-${name}`)));
    }
    el("cancel").click();
    assert.ok(el("modal").hidden);
    assert.equal(document.activeElement, opener);
    assert.deepEqual(counts(), { discarded: 0, downloads: 0 });
    // Hidden controls cannot authorize a later clear.
    el("discard").click();
    assert.equal(counts().discarded, 0);
    dialog.show(opener);
    el("discard").click();
    assert.equal(counts().discarded, 1);
    assert.ok(el("modal").hidden);
  });
});

test("Escape and backdrop dismiss without clearing or downloading", async () => {
  await withDialog(async ({ dialog, opener, el, counts }) => {
    el("modal").dispatchEvent({ type: "keydown", key: "Escape" });
    assert.ok(el("modal").hidden);
    dialog.show(opener);
    el("modal").dispatchEvent({ type: "click", target: el("modal") });
    assert.ok(el("modal").hidden);
    assert.deepEqual(counts(), { discarded: 0, downloads: 0 });
  });
});

test("download first keeps the Journal until Discard, even after success", async () => {
  const gate = deferred();
  await withDialog(async ({ el, document, counts }) => {
    el("download").click();
    el("download").click();
    el("discard").click();
    assert.deepEqual(counts(), { discarded: 0, downloads: 1 });
    assert.ok(el("download").disabled && el("discard").disabled);
    assert.equal(document.activeElement, el("cancel"));
    gate.resolve(true);
    await settle();
    assert.equal(el("modal").hidden, false);
    assert.equal(counts().discarded, 0);
    assert.ok(el("status").textContent.trim());
    assert.equal(el("download").disabled, false);
    el("discard").click();
    assert.equal(counts().discarded, 1);
  }, () => gate.promise);
});

test("failed backup keeps the Journal and reports a text-only status", async () => {
  for (const fail of [async () => false, async () => { throw new Error("<img src=x>"); }]) {
    await withDialog(async ({ el, counts }) => {
      el("download").click();
      await settle();
      assert.equal(el("modal").hidden, false);
      assert.equal(counts().discarded, 0);
      assert.ok(el("status").textContent.trim());
      assert.equal(el("status").children.length, 0);
      assert.equal(el("discard").disabled, false);
      el("cancel").click();
      assert.equal(counts().discarded, 0);
    }, fail);
  }
});

test("cancel or teardown invalidates an in-flight backup and its late status", async () => {
  for (const teardown of [false, true]) {
    const gate = deferred();
    let isCurrent;
    await withDialog(async ({ dialog, opener, el, counts }) => {
      el("download").click();
      assert.equal(isCurrent(), true);
      if (teardown) dialog.hide({ restoreFocus: false });
      else el("cancel").click();
      assert.equal(isCurrent(), false);
      dialog.show(opener);
      assert.equal(isCurrent(), false, "reopening must not revive the old download");
      gate.resolve(true);
      await settle();
      assert.equal(el("status").textContent, "");
      assert.equal(el("download").disabled, false);
      assert.equal(counts().discarded, 0);
    }, (current) => { isCurrent = current; return gate.promise; });
  }
});

test("the same clear dialog exports a captured scope without clearing it, then resets its defaults", async () => {
  const gate = deferred();
  await withDialog(async ({ dialog, opener, el, counts }) => {
    const defaults = ["title", "message", "download", "discard"].map((name) => el(name).textContent);
    dialog.hide();
    let exported = 0, cleared = 0;
    const content = { title: "<report> title", message: "<report> explanation", downloadLabel: "<report> export", discardLabel: "<report> clear", preparingMessage: "<report> pending", successMessage: "<report> handed off", errorMessage: "<report> retained" };
    dialog.show(opener, { ...content, onDownload: () => { exported++; return gate.promise; }, onDiscard: () => cleared++ });
    for (const [name, key] of [["title", "title"], ["message", "message"], ["download", "downloadLabel"], ["discard", "discardLabel"]]) {
      assert.equal(el(name).textContent, content[key]);
      assert.equal(el(name).children.length, 0);
    }
    el("download").click();
    el("download").click();
    el("discard").click();
    assert.equal(exported, 1);
    assert.equal(cleared, 0);
    assert.deepEqual(counts(), { downloads: 0, discarded: 0 });
    assert.equal(el("status").textContent, content.preparingMessage);
    gate.resolve(true);
    await settle();
    assert.equal(el("modal").hidden, false);
    assert.equal(cleared, 0);
    assert.equal(el("status").textContent, content.successMessage);
    assert.equal(el("status").children.length, 0);
    el("discard").click();
    assert.equal(cleared, 1);
    dialog.show(opener);
    assert.deepEqual(["title", "message", "download", "discard"].map((name) => el(name).textContent), defaults);
    el("discard").click();
    assert.equal(cleared, 1);
    assert.deepEqual(counts(), { downloads: 0, discarded: 1 });
  });
});

test("a failed scope export keeps its dialog and permits retry or explicit clear", async () => {
  await withDialog(async ({ dialog, opener, el, counts }) => {
    dialog.hide();
    let exported = 0, cleared = 0;
    dialog.show(opener, {
      errorMessage: "<report> error",
      onDownload: async () => { exported++; if (exported === 1) throw new Error("private failure"); return false; },
      onDiscard: () => cleared++,
    });
    for (let attempt = 0; attempt < 2; attempt++) {
      el("download").click();
      await settle();
      assert.equal(el("modal").hidden, false);
      assert.equal(el("status").textContent, "<report> error");
      assert.equal(el("status").children.length, 0);
      assert.equal(el("download").disabled, false);
      assert.equal(el("discard").disabled, false);
      assert.equal(cleared, 0);
    }
    assert.equal(exported, 2);
    assert.deepEqual(counts(), { downloads: 0, discarded: 0 });
    el("discard").click();
    assert.equal(cleared, 1);
  });
});

test("scope replacement and dismissal invalidate export and cannot replay clear", async () => {
  for (const dismiss of ["scope", "cancel", "escape", "backdrop", "teardown"]) {
    const gate = deferred();
    await withDialog(async ({ dialog, opener, el, counts }) => {
      dialog.hide();
      let valid = true, current, cleared = 0;
      dialog.show(opener, {
        isCurrent: () => valid,
        onDownload: (isCurrent) => { current = isCurrent; return gate.promise; },
        onDiscard: () => cleared++,
      });
      el("download").click();
      assert.equal(current(), true);
      if (dismiss === "scope") valid = false;
      else if (dismiss === "cancel") el("cancel").click();
      else if (dismiss === "escape") el("modal").dispatchEvent({ type: "keydown", key: "Escape" });
      else if (dismiss === "backdrop") el("modal").dispatchEvent({ type: "click", target: el("modal") });
      else dialog.hide({ restoreFocus: false });
      assert.equal(current(), false);
      gate.resolve(true);
      await settle();
      el("discard").click();
      assert.equal(cleared, 0);
      assert.deepEqual(counts(), { downloads: 0, discarded: 0 });
      dialog.hide();
      dialog.show(opener);
      assert.equal(el("status").textContent, "");
      assert.equal(current(), false);
    });
  }
});
