import { test } from "node:test";
import assert from "node:assert/strict";
import { MiniDocument } from "./mini-dom.mjs";
import { initJournalKeyImportConfirm } from "../src/js/journal-key-import-confirm.js";

async function withDialog(run) {
  const previous = globalThis.document, document = new MiniDocument();
  globalThis.document = document;
  const opener = document.createElement("button");
  document.body.append(opener);
  let dialog;
  try {
    dialog = initJournalKeyImportConfirm();
    for (const button of document.querySelectorAll("button")) {
      button.focus = () => { document.activeElement = button; };
      button.click = () => { if (!button.disabled) button.dispatchEvent({ type: "click", target: button }); };
    }
    opener.focus();
    const el = (name) => document.getElementById(`journal-key-import-${name}`);
    await run({ dialog, document, opener, el });
  } finally {
    dialog?.close({ restoreFocus: false });
    globalThis.document = previous;
  }
}

const preview = { mode: "preview", names: ["Wallet label <img src=x onerror=alert(1)>"], archivedCount: 2 };
const conflict = { mode: "conflict", name: "Imported <script>name</script>", existingName: "Existing <b>wallet</b>",
  importedNetwork: "testnet", existingNetwork: "mainnet", importedPath: "m/84'/1'/1'/0/0", existingPath: "m/84'/0'/0'/0/0",
  importedScript: "Taproot <script>type</script>", existingScript: "SegWit <b>type</b>",
  importedRecovery: "Seed <img src=x>", existingRecovery: "Watch-only <svg>" };
const draft = { mode: "draft", name: "Draft <svg onload=alert(1)>" };

test("preview shows literal input names and archive count; only the explicit primary choice authorizes derivation", async () => {
  await withDialog(async ({ dialog, document, el }) => {
    const pending = dialog.open(preview);
    assert.equal(document.activeElement, el("cancel"));
    assert.equal(el("dialog").getAttribute("role"), "dialog");
    assert.equal(el("dialog").getAttribute("aria-modal"), "true");
    for (const name of ["labelledby", "describedby"]) assert.ok(document.getElementById(el("dialog").getAttribute(`aria-${name}`)));
    assert.equal(el("names").children.length, 1);
    assert.equal(el("names").children[0].textContent, preview.names[0]);
    assert.equal(el("names").children[0].children.length, 0);
    assert.ok(el("names").hasAttribute("data-i18n-skip"));
    assert.ok(el("summary").textContent.includes("1"));
    assert.ok(el("summary").textContent.includes("2"));
    assert.equal(el("secondary").hidden, true);
    el("primary").click();
    assert.equal(await pending, "derive");
    assert.equal(el("modal").hidden, true);
    assert.equal(el("names").children.length, 0);
  });
});

test("archive-only preview authorizes import without authorizing derivation", async () => {
  await withDialog(async ({ dialog, document, el }) => {
    const pending = dialog.open({ mode: "preview", names: [], archivedCount: 2 });
    assert.equal(document.activeElement, el("cancel"));
    assert.equal(el("names").hidden, true);
    assert.ok(el("summary").textContent.includes("2"));
    assert.ok(el("primary").textContent);
    el("primary").click();
    assert.equal(await pending, "import");
  });
});

for (const [button, decision] of [["primary", "keep"], ["secondary", "append"]]) test(`wallet setup conflict returns ${decision} only from its corresponding choice`, async () => {
  await withDialog(async ({ dialog, document, el }) => {
    const pending = dialog.open(conflict);
    assert.equal(document.activeElement, el("cancel"));
    for (const [id, value] of [["imported-name", conflict.name], ["existing-name", conflict.existingName], ["imported-network", conflict.importedNetwork], ["existing-network", conflict.existingNetwork], ["imported-path", conflict.importedPath], ["existing-path", conflict.existingPath], ["imported-script", conflict.importedScript], ["existing-script", conflict.existingScript], ["imported-recovery", conflict.importedRecovery], ["existing-recovery", conflict.existingRecovery]]) {
      assert.ok(el(id), `${id} must be available for comparing setups`);
      assert.equal(el(id).textContent, value);
      assert.equal(el(id).children.length, 0);
      assert.ok(el(id).hasAttribute("data-i18n-skip"));
    }
    assert.equal(el("details").hidden, false);
    assert.equal(el("secondary").hidden, false);
    el(button).click();
    assert.equal(await pending, decision);
    assert.ok(!el("modal").textContent.includes(conflict.name));
    assert.ok(!el("modal").textContent.includes(conflict.existingPath));
  });
});

test("single-key conflict displays literal encoding metadata and HD conflicts hide that row", async () => {
  await withDialog(async ({ dialog, el }) => {
    const values = { existingEncoding: "Encoding A <img src=x>", importedEncoding: "Encoding B <svg>" };
    let pending = dialog.open({ ...conflict, ...values });
    assert.equal(el("encoding-row").hidden, false);
    for (const [id, value] of [["existing-encoding", values.existingEncoding], ["imported-encoding", values.importedEncoding]]) {
      assert.equal(el(id).textContent, value);
      assert.equal(el(id).children.length, 0);
    }
    dialog.close();
    assert.equal(await pending, null);
    pending = dialog.open(conflict);
    assert.equal(el("encoding-row").hidden, true);
    assert.equal(el("existing-encoding").textContent, "");
    assert.equal(el("imported-encoding").textContent, "");
    dialog.close();
    assert.equal(await pending, null);
  });
});

test("unfinished input replacement requires explicit Load and defaults to cancellation", async () => {
  await withDialog(async ({ dialog, document, el }) => {
    const pending = dialog.open(draft);
    assert.equal(document.activeElement, el("cancel"));
    assert.equal(el("name").textContent, draft.name);
    assert.equal(el("name").children.length, 0);
    assert.equal(el("secondary").hidden, true);
    el("secondary").click();
    assert.equal(el("modal").hidden, false, "a hidden choice accepted the draft");
    el("primary").click();
    assert.equal(await pending, "load");
    assert.equal(el("name").textContent, "");
  });
});

for (const mode of [preview, conflict, draft]) test(`${mode.mode} Cancel, Escape, backdrop, and teardown resolve null and scrub labels`, async () => {
  await withDialog(async ({ dialog, document, opener, el }) => {
    for (const dismiss of [
      () => el("cancel").click(),
      () => el("modal").dispatchEvent({ type: "keydown", key: "Escape" }),
      () => el("modal").dispatchEvent({ type: "click", target: el("modal") }),
      () => dialog.close(),
    ]) {
      const pending = dialog.open(mode);
      dismiss();
      assert.equal(await pending, null);
      assert.equal(el("modal").hidden, true);
      assert.equal(document.activeElement, opener);
      for (const value of [...(mode.names || []), mode.name, mode.existingName, mode.importedPath, mode.existingPath, mode.importedScript, mode.existingScript, mode.importedRecovery, mode.existingRecovery].filter(Boolean)) assert.ok(!el("modal").textContent.includes(value));
      el("primary").click();
      el("secondary").click();
      assert.equal(el("modal").hidden, true);
    }
  });
});

test("replacement cancels the previous request once and preserves its external focus destination", async () => {
  await withDialog(async ({ dialog, document, opener, el }) => {
    let settled = 0;
    const first = dialog.open(preview).then((value) => { settled++; return value; });
    const second = dialog.open(conflict);
    assert.equal(await first, null);
    assert.equal(settled, 1);
    assert.ok(!el("modal").textContent.includes(preview.names[0]));
    el("secondary").click();
    el("primary").click();
    dialog.close();
    assert.equal(await second, "append");
    assert.equal(settled, 1);
    assert.equal(document.activeElement, opener);
  });
});

test("teardown does not restore focus and unknown modes never expose authorization choices", async () => {
  await withDialog(async ({ dialog, document, el }) => {
    const pending = dialog.open(preview), focused = document.activeElement;
    dialog.close({ restoreFocus: false });
    assert.equal(await pending, null);
    assert.equal(document.activeElement, focused);
    assert.equal(await dialog.open({ mode: "unexpected", name: "must not retain" }), null);
    assert.equal(el("modal").hidden, true);
    assert.ok(!el("modal").textContent.includes("must not retain"));
  });
});

test("focus cycling includes only the choices available to the current mode", async () => {
  await withDialog(async ({ dialog, document, el }) => {
    for (const options of [preview, conflict, draft]) {
      const pending = dialog.open(options);
      const tab = () => el("modal").dispatchEvent({ type: "keydown", key: "Tab", preventDefault() {} });
      tab();
      assert.equal(document.activeElement, el("primary"));
      tab();
      assert.equal(document.activeElement, options.mode === "conflict" ? el("secondary") : el("cancel"));
      dialog.close();
      assert.equal(await pending, null);
    }
  });
});
