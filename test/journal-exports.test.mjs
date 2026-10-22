// Section exports use the open Journal's protection and cannot finish after
// its generation ends. Key exports contain every active and archived input
// set; old UI selections must neither filter exports nor mutate on download.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import vm from "node:vm";
import { keyVaultIdentity, serializeKeyVault } from "../src/js/keymanager.js";

const source = readFileSync(new URL("../src/js/app.js", import.meta.url), "utf8");
const extract = (name) => {
  const match = source.match(new RegExp(`^async function ${name}\\([^]*?^}`, "m"));
  assert.ok(match, name);
  return match[0];
};
const input = (id, name) => ({ id, name, fields: { seed: `${name} secret inputs` } });
function harness({ unlocked = true, encrypted = true, selected = ["1"], states = [input(1, "First"), input(2, "Second")] } = {}) {
  let resolve, reject;
  const pending = new Promise((yes, no) => { resolve = yes; reject = no; });
  const seals = [], downloads = [], effects = [];
  const keys = { passwordProtected: true };
  const context = vm.createContext({
    hodlJournalKeys: keys, hodlJournalGeneration: 0, hodlJournalEncryptDownloads: encrypted,
    hodlJournalUnlocked: () => unlocked,
    hodlKeyManagerIds: new Set(selected), hodlKeyManagerIgnored: [input(3, "Archived")],
    hodlKeyManagerStates: () => states, hodlKeyManagerEntry: (state) => structuredClone(state),
    keyVaultIdentity, serializeKeyVault,
    hodlJournalSealExport: (...args) => { seals.push(args); return pending; },
    hodlJournalDownload: (...args) => downloads.push(args),
    hodlJournalError: (...args) => effects.push(["error", ...args]),
    hodlJournalSetStatus: (...args) => effects.push(["notes-status", ...args]),
    hodlKeyManagerStatus: (...args) => effects.push(["key-status", ...args]),
    hodlKeyManagerRender: () => effects.push(["render"]),
    hodlJournalLog: (...args) => effects.push(["log", ...args]),
    hodlTText: (text) => text,
  });
  vm.runInContext(["hodlJournalDownloadContent", "hodlKeyManagerDownload"].map(extract).join("\n"), context);
  return { context, keys, seals, downloads, effects, resolve, reject };
}

for (const encrypted of [true, false]) test(`section export uses Journal protection with old encryption flag ${encrypted}`, async () => {
  const ui = harness({ encrypted });
  const run = ui.context.hodlJournalDownloadContent("notebook", "notes.json", "private notes");
  assert.equal(ui.seals.length, 1, "section content bypassed Journal protection");
  assert.deepEqual(ui.seals[0], ["notebook", "private notes", ui.keys]);
  assert.equal(ui.downloads.length, 0, "download happened before encryption completed");
  ui.resolve({ sealed: "opaque ciphertext" });
  await run;
  assert.equal(ui.downloads.length, 1);
  assert.ok(!ui.downloads[0][1].includes("private notes"), "section export contains plaintext");
});

for (const action of ["section", "keys"]) test(`${action} export refuses a closed Journal before encryption`, async () => {
  const ui = harness({ unlocked: false });
  const run = action === "section" ? ui.context.hodlJournalDownloadContent("notebook", "notes.json", "private notes") : ui.context.hodlKeyManagerDownload();
  // Let even the old implementation settle so a missing guard is measured
  // by encryption/download calls rather than an unresolved fixture promise.
  ui.resolve({ sealed: "opaque ciphertext" });
  await Promise.resolve(run).catch(() => {});
  assert.equal(ui.seals.length, 0, "a closed Journal started encryption");
  assert.equal(ui.downloads.length, 0, "a closed Journal exported content");
});

for (const action of ["section", "keys"]) for (const result of ["success", "failure"]) {
  test(`${action} export drops a stale encryption ${result} without download or UI effects`, async () => {
    const ui = harness();
    const run = action === "section" ? ui.context.hodlJournalDownloadContent("notebook", "notes.json", "private notes") : ui.context.hodlKeyManagerDownload();
    assert.equal(ui.seals.length, 1);
    ui.context.hodlJournalGeneration++;
    ui.effects.length = 0;
    if (result === "success") ui.resolve({ sealed: "opaque ciphertext" });
    else ui.reject(new Error("stale encryption failure"));
    await assert.doesNotReject(run, "a stale export leaked its failure after teardown");
    assert.deepEqual(ui.downloads, [], "a stale export still downloaded");
    assert.deepEqual(ui.effects, [], "a stale export changed the new session's UI");
  });
}

for (const selected of [["1"], []]) test(`key export includes all inputs with ${selected.length} old selections`, async () => {
  const ui = harness({ selected });
  const run = ui.context.hodlKeyManagerDownload();
  assert.equal(ui.seals.length, 1);
  assert.equal(ui.seals[0][0], "key-manager");
  assert.equal(ui.seals[0][2], ui.keys);
  const vault = JSON.parse(ui.seals[0][1]);
  assert.deepEqual(vault.keys.map((entry) => entry.name), ["First", "Second"]);
  assert.deepEqual(vault.ignoredKeys.map((entry) => entry.name), ["Archived"]);
  assert.deepEqual([...ui.context.hodlKeyManagerIds], selected, "export changed old selection state");
  ui.resolve({ sealed: "opaque ciphertext" });
  await run;
  assert.equal(ui.downloads.length, 1);
});

test("an archived-only key collection remains exportable", async () => {
  const ui = harness({ states: [], selected: [] });
  const run = ui.context.hodlKeyManagerDownload();
  assert.equal(ui.seals.length, 1, "archived inputs were omitted from export");
  const vault = JSON.parse(ui.seals[0][1]);
  assert.deepEqual(vault.keys, []);
  assert.deepEqual(vault.ignoredKeys.map((entry) => entry.name), ["Archived"]);
  ui.resolve({ sealed: "opaque ciphertext" });
  await run;
  assert.equal(ui.downloads.length, 1);
});
