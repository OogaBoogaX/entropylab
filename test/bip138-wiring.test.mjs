// The BIP-138 backup is a preview-only extra: the shell block is stripped from
// release builds, the module is imported lazily, and the export refuses to
// offer a file it could not open again with every recipient key.
// Run with: npm test
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { applyPreviewBlocks } from "../scripts/preview-blocks.mjs";
import { MiniDocument } from "./mini-dom.mjs";
import { loadAppFunctions } from "./app-slice-harness.mjs";
import * as bip138 from "../src/js/bip138.js";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const app = readFileSync(join(root, "src/js/app.js"), "utf8");
const shell = readFileSync(join(root, "src/shell.html"), "utf8");
const hex = (bytes) => Buffer.from(bytes).toString("hex");
const utf8 = (text) => new TextEncoder().encode(text);
const tick = async () => { for (let i = 0; i < 4; i++) await new Promise((resolve) => setImmediate(resolve)); };

const XPUB_A = "xpub6FC1fXFP1GXLX5TKtcjHGT4q89SDRehkQLtbKJ2PzWcvbBHtyDsJPLtpLtkGqYNYZdVVAjRQ5kug9CsapegmmeRutpP7PW4u4wVF9JfkDhw";
const XPUB_B = "xpub6EWhjpPa6FqrcaPBuGBZRJVjzGJ1ZsMygRF26RwN932Vfkn1gyCiTbECVitBjRCkexEvetLdiqzTcYimmzYxyR1BZ79KNevgt61PDcukmC7";
const XPUB_C = "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL";
const XPRV = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";
const DESC = "wsh(sortedmulti(2,[6738736c/48'/0'/0'/2']" + XPUB_A + "/<0;1>/*,[b2b1f0cf/48'/0'/0'/2']" + XPUB_B + "/<0;1>/*))";

const OPEN_IDS = ["msig-backup-open", "msig-backup-file", "msig-backup-xpub-row", "msig-backup-xpub", "msig-backup-status"];

test("the open controls are a preview block", () => {
  const preview = applyPreviewBlocks(shell, true);
  const release = applyPreviewBlocks(shell, false);
  for (const id of OPEN_IDS) {
    assert.ok(preview.includes(`id="${id}"`), id);
    assert.ok(!release.includes(`id="${id}"`), id);
  }
  assert.ok(release.includes('id="msig-descriptor"'));
  assert.ok(release.includes('id="msig-descriptor-import"'));
});

test("the open controls sit inside the import panel", () => {
  const document = new MiniDocument();
  document.body.innerHTML = applyPreviewBlocks(shell, true);
  const panel = document.getElementById("msig-import");
  assert.ok(panel);
  for (const id of OPEN_IDS) assert.ok(panel.querySelector(`#${id}`), id);
  const file = document.getElementById("msig-backup-file");
  assert.equal(file.getAttribute("type"), "file");
  assert.equal(file.hidden, true);
  assert.equal(document.getElementById("msig-backup-xpub-row").hidden, true);
  assert.equal(document.getElementById("msig-backup-status").hidden, true);
  assert.ok(document.getElementById("msig-backup-xpub-row").querySelector("#msig-backup-xpub"));
  assert.equal(document.getElementById("msig-backup-status").getAttribute("role"), "status");
  const text = applyPreviewBlocks(shell, true);
  assert.ok(text.indexOf('id="msig-descriptor"') < text.indexOf('id="msig-backup-open"'));
  assert.ok(text.indexOf('id="msig-backup-open"') < text.indexOf('id="msig-descriptor-import"'));
});

test("app.js loads the module lazily, only in preview builds", () => {
  assert.equal(app.split('import("./bip138.js")').length - 1, 1);
  assert.ok(!app.includes('from "./bip138.js"'));
  const loader = app.slice(app.indexOf("function hodlLoadBip138("));
  const body = loader.slice(0, loader.indexOf("\n}"));
  assert.ok(body.includes('import("./bip138.js")'));
  assert.ok(body.indexOf('typeof __ENTROPYLAB_PREVIEW__ !== "undefined" && __ENTROPYLAB_PREVIEW__') < body.indexOf('import("./bip138.js")'));
});

test("the reset and init hooks sit where the wiring expects", () => {
  const restore = app.slice(app.indexOf("function hodlRestoreMsig("), app.indexOf("function hodlWipeActiveMsig("));
  const valueAt = restore.indexOf("descriptor.value = state.fields.descriptor");
  const resetAt = restore.indexOf('if (typeof hodlMsigBip138Reset === "function") hodlMsigBip138Reset();');
  const fillAt = restore.indexOf("hodlFillKeys(");
  assert.ok(valueAt >= 0 && resetAt > valueAt && fillAt > resetAt);
  const resetForm = app.slice(app.indexOf("function hodlResetMsigForm("), app.indexOf("function hodlInitMsig("));
  assert.ok(resetForm.indexOf("descriptorPanel.open = true") < resetForm.indexOf('if (typeof hodlMsigBip138Reset === "function") hodlMsigBip138Reset();'));
  const init = app.slice(app.indexOf("function hodlInitMsig("), app.indexOf("// The multisig script type is a button group"));
  assert.ok(init.indexOf('document.getElementById("msig-descriptor")?.addEventListener("input"') < init.indexOf('if (typeof hodlInitMsigBip138Open === "function") hodlInitMsigBip138Open();'));
  assert.ok(app.slice(app.indexOf("function hodlSyncMsigDescriptorImport(")).includes("hodlMsigBip138Pending()"));
  const show = app.slice(app.indexOf("function hodlShowMsig("), app.indexOf("// BIP-138 encrypted backups"));
  assert.ok(show.indexOf("hodlMsigBip388Markup()") < show.indexOf("hodlMsigBip138HostMarkup()"));
  assert.ok(show.indexOf("hodlBindMsigCoreImportDescriptors()") < show.indexOf("hodlMountMsigBip138Backup()"));
});

test("the backup host renders only for a preview multisig result", async () => {
  const saved = { document: globalThis.document, preview: globalThis.__ENTROPYLAB_PREVIEW__ };
  try {
    globalThis.document = new MiniDocument();
    const slice = await loadAppFunctions(["hodlMsigBip138HostMarkup"], { settable: ["hodlWalletResult"] });
    assert.equal(slice.hodlMsigBip138HostMarkup(), "");
    globalThis.__ENTROPYLAB_PREVIEW__ = true;
    slice.__set.hodlWalletResult({ kind: "msig", walletDescriptor: DESC });
    assert.ok(slice.hodlMsigBip138HostMarkup().includes('id="msig-bip138-host"'));
    slice.__set.hodlWalletResult({ kind: "key" });
    assert.equal(slice.hodlMsigBip138HostMarkup(), "");
  } finally {
    globalThis.document = saved.document;
    if (saved.preview === undefined) delete globalThis.__ENTROPYLAB_PREVIEW__;
    else globalThis.__ENTROPYLAB_PREVIEW__ = saved.preview;
  }
});

test("the backup markup lists excluded keys and the downloads", async () => {
  const saved = { document: globalThis.document };
  try {
    globalThis.document = new MiniDocument();
    const slice = await loadAppFunctions(["hodlMsigBip138Markup"]);
    const host = globalThis.document.createElement("div");
    host.innerHTML = slice.hodlMsigBip138Markup({ exclusions: [{ index: 1, reason: "literal", internal: false }, { index: null, reason: "nums", internal: true }], ready: true });
    const excluded = host.querySelectorAll("[data-bip138-excluded]");
    assert.equal(excluded.length, 1);
    assert.equal(excluded[0].getAttribute("data-bip138-excluded"), "2");
    assert.ok(host.querySelector("#msig-bip138-download"));
    assert.ok(host.querySelector("#msig-bip138-download-text"));
    assert.equal(host.querySelectorAll("[data-bip138-none]").length, 0);
    assert.equal(host.querySelector("#msig-bip138").firstElementChild.tagName, "SUMMARY");
    const notReady = globalThis.document.createElement("div");
    notReady.innerHTML = slice.hodlMsigBip138Markup({ exclusions: [], ready: false });
    assert.ok(notReady.querySelector("[data-bip138-none]"));
    assert.equal(notReady.querySelectorAll("button").length, 0);
    const reasons = ["literal", "nums", "exposed"].map((reason) => slice.hodlMsigBip138Markup({ exclusions: [{ index: 0, reason, internal: false }], ready: true }));
    assert.equal(new Set(reasons).size, 3);
  } finally {
    globalThis.document = saved.document;
  }
});

test("the export downloads a backup that opens with a recipient key", async () => {
  const saved = { document: globalThis.document, createObjectURL: URL.createObjectURL, revokeObjectURL: URL.revokeObjectURL, preview: globalThis.__ENTROPYLAB_PREVIEW__ };
  const blobs = [], links = [];
  try {
    globalThis.__ENTROPYLAB_PREVIEW__ = true;
    globalThis.document = new MiniDocument();
    globalThis.document.body.innerHTML = '<div id="msig-bip138-host"></div>';
    URL.createObjectURL = (blob) => { blobs.push(blob); return "blob:test"; };
    URL.revokeObjectURL = () => {};
    const createElement = globalThis.document.createElement.bind(globalThis.document);
    globalThis.document.createElement = (tag) => { const element = createElement(tag); if (tag === "a") links.push(element); return element; };
    const slice = await loadAppFunctions(["hodlMountMsigBip138Backup", "hodlDownloadMsigBip138"], { stubs: { hodlLoadBip138: () => Promise.resolve(bip138) }, settable: ["hodlWalletResult"] });
    const result = { kind: "msig", walletDescriptor: DESC };
    slice.__set.hodlWalletResult(result);
    slice.hodlMountMsigBip138Backup();
    await tick();
    assert.ok(globalThis.document.getElementById("msig-bip138"));
    globalThis.document.getElementById("msig-bip138-download").dispatchEvent(new Event("click"));
    assert.equal(links[0].download, "wallet-backup.bip138");
    const bytes = new Uint8Array(await blobs[0].arrayBuffer());
    const keyA = bip138.bip138KeyFromXpubText(XPUB_A).key;
    assert.equal(bip138.bip138OpenDescriptorBackup(bytes, keyA).descriptor, DESC);
    globalThis.document.getElementById("msig-bip138-download-text").dispatchEvent(new Event("click"));
    assert.equal(links[1].download, "wallet-backup.txt");
    const text = await blobs[1].text();
    assert.equal(hex(bip138.bip138BytesFromText(text)), hex(bytes));
    slice.__set.hodlWalletResult({ kind: "msig", walletDescriptor: DESC });
    const before = blobs.length;
    globalThis.document.getElementById("msig-bip138-download").dispatchEvent(new Event("click"));
    assert.equal(blobs.length, before);
  } finally {
    globalThis.document = saved.document;
    if (saved.createObjectURL === undefined) delete URL.createObjectURL; else URL.createObjectURL = saved.createObjectURL;
    if (saved.revokeObjectURL === undefined) delete URL.revokeObjectURL; else URL.revokeObjectURL = saved.revokeObjectURL;
    if (saved.preview === undefined) delete globalThis.__ENTROPYLAB_PREVIEW__;
    else globalThis.__ENTROPYLAB_PREVIEW__ = saved.preview;
  }
});

test("a descriptor with private keys shows nothing", async () => {
  const saved = { document: globalThis.document, preview: globalThis.__ENTROPYLAB_PREVIEW__ };
  try {
    globalThis.__ENTROPYLAB_PREVIEW__ = true;
    globalThis.document = new MiniDocument();
    globalThis.document.body.innerHTML = '<div id="msig-bip138-host"></div>';
    const slice = await loadAppFunctions(["hodlMountMsigBip138Backup"], { stubs: { hodlLoadBip138: () => Promise.resolve(bip138) }, settable: ["hodlWalletResult"] });
    slice.__set.hodlWalletResult({ kind: "msig", walletDescriptor: `wsh(multi(1,${XPRV}/0/*))` });
    slice.hodlMountMsigBip138Backup();
    await tick();
    assert.equal(globalThis.document.getElementById("msig-bip138-host").innerHTML, "");
    slice.__set.hodlWalletResult({ kind: "msig", walletDescriptor: `wsh(multi(1,${XPUB_A},${XPUB_B}))` });
    slice.hodlMountMsigBip138Backup();
    await tick();
    const host = globalThis.document.getElementById("msig-bip138-host");
    assert.ok(host.querySelector("[data-bip138-none]"));
    assert.equal(host.querySelectorAll("[data-bip138-excluded]").length, 2);
    assert.equal(host.querySelectorAll("button").length, 0);
  } finally {
    globalThis.document = saved.document;
    if (saved.preview === undefined) delete globalThis.__ENTROPYLAB_PREVIEW__;
    else globalThis.__ENTROPYLAB_PREVIEW__ = saved.preview;
  }
});

test("a pasted backup opens into the descriptor field", async () => {
  const saved = { document: globalThis.document, preview: globalThis.__ENTROPYLAB_PREVIEW__ };
  try {
    globalThis.__ENTROPYLAB_PREVIEW__ = true;
    globalThis.document = new MiniDocument();
    globalThis.document.body.innerHTML = applyPreviewBlocks(shell, true);
    const slice = await loadAppFunctions(["hodlInitMsigBip138Open", "hodlMsigBip138Pending", "hodlMsigBip138Reset"], { stubs: { hodlLoadBip138: () => Promise.resolve(bip138) } });
    slice.hodlInitMsigBip138Open();
    const built = bip138.bip138CreateDescriptorBackup(DESC);
    const base64 = bip138.bip138ToBase64(built.bytes);
    const field = globalThis.document.getElementById("msig-descriptor");
    const row = globalThis.document.getElementById("msig-backup-xpub-row");
    const status = globalThis.document.getElementById("msig-backup-status");
    const xpub = globalThis.document.getElementById("msig-backup-xpub");
    field.value = base64;
    field.dispatchEvent(new Event("input"));
    await tick();
    assert.equal(row.hidden, false);
    assert.equal(status.getAttribute("data-bip138-status"), "prompt");
    assert.equal(slice.hodlMsigBip138Pending(), true);
    xpub.value = XPUB_C;
    xpub.dispatchEvent(new Event("input"));
    assert.equal(status.getAttribute("data-bip138-status"), "wrong-key");
    assert.equal(field.value, base64);
    assert.equal(row.hidden, false);
    xpub.value = XPRV;
    xpub.dispatchEvent(new Event("input"));
    assert.equal(xpub.value, "");
    assert.equal(status.getAttribute("data-bip138-status"), "prompt");
    assert.ok(!status.textContent.includes("xprv"));
    assert.equal(field.value, base64);
    let inputs = 0;
    field.addEventListener("input", () => { inputs++; });
    xpub.value = `[6738736c/48'/0'/0'/2']${XPUB_A}/<0;1>/*`;
    xpub.dispatchEvent(new Event("input"));
    assert.equal(field.value, DESC);
    assert.equal(inputs, 1);
    assert.equal(row.hidden, true);
    assert.equal(xpub.value, "");
    assert.equal(status.hidden, true);
    assert.equal(slice.hodlMsigBip138Pending(), false);
  } finally {
    globalThis.document = saved.document;
    if (saved.preview === undefined) delete globalThis.__ENTROPYLAB_PREVIEW__;
    else globalThis.__ENTROPYLAB_PREVIEW__ = saved.preview;
  }
});

test("a chosen file is read, validated and the picker reset", async () => {
  const saved = { document: globalThis.document, preview: globalThis.__ENTROPYLAB_PREVIEW__ };
  try {
    globalThis.__ENTROPYLAB_PREVIEW__ = true;
    globalThis.document = new MiniDocument();
    globalThis.document.body.innerHTML = applyPreviewBlocks(shell, true);
    const slice = await loadAppFunctions(["hodlInitMsigBip138Open"], { stubs: { hodlLoadBip138: () => Promise.resolve(bip138) } });
    slice.hodlInitMsigBip138Open();
    const built = bip138.bip138CreateDescriptorBackup(DESC);
    const file = globalThis.document.getElementById("msig-backup-file");
    const row = globalThis.document.getElementById("msig-backup-xpub-row");
    const status = globalThis.document.getElementById("msig-backup-status");
    const field = globalThis.document.getElementById("msig-descriptor");
    const choose = (data) => {
      file.value = "C:\\fakepath\\x";
      Object.defineProperty(file, "files", { value: [{ size: data.length, arrayBuffer: async () => data.buffer.slice(0) }], configurable: true });
      file.dispatchEvent(new Event("change"));
    };
    choose(built.bytes);
    await tick();
    assert.equal(file.value, "");
    assert.equal(row.hidden, false);
    assert.equal(field.value, "");
    choose(utf8(bip138.bip138ToBase64(built.bytes)));
    await tick();
    assert.equal(row.hidden, false);
    choose(utf8("hello"));
    await tick();
    assert.equal(status.getAttribute("data-bip138-status"), "not-backup");
    assert.equal(row.hidden, true);
    choose(built.bytes.slice(0, 40));
    await tick();
    assert.equal(status.getAttribute("data-bip138-status"), "damaged");
    const version2 = built.bytes.slice();
    version2[6] = 2;
    choose(version2);
    await tick();
    assert.equal(status.getAttribute("data-bip138-status"), "unsupported");
    file.value = "C:\\fakepath\\x";
    Object.defineProperty(file, "files", { value: [{ size: 1048577, arrayBuffer: async () => { throw new Error("must not read"); } }], configurable: true });
    file.dispatchEvent(new Event("change"));
    await tick();
    assert.equal(status.getAttribute("data-bip138-status"), "not-backup");
  } finally {
    globalThis.document = saved.document;
    if (saved.preview === undefined) delete globalThis.__ENTROPYLAB_PREVIEW__;
    else globalThis.__ENTROPYLAB_PREVIEW__ = saved.preview;
  }
});

test("reset drops a held backup", async () => {
  const saved = { document: globalThis.document, preview: globalThis.__ENTROPYLAB_PREVIEW__ };
  try {
    globalThis.__ENTROPYLAB_PREVIEW__ = true;
    globalThis.document = new MiniDocument();
    globalThis.document.body.innerHTML = applyPreviewBlocks(shell, true);
    const slice = await loadAppFunctions(["hodlInitMsigBip138Open", "hodlMsigBip138Reset"], { stubs: { hodlLoadBip138: () => Promise.resolve(bip138) } });
    slice.hodlInitMsigBip138Open();
    const built = bip138.bip138CreateDescriptorBackup(DESC);
    const field = globalThis.document.getElementById("msig-descriptor");
    const row = globalThis.document.getElementById("msig-backup-xpub-row");
    const status = globalThis.document.getElementById("msig-backup-status");
    const xpub = globalThis.document.getElementById("msig-backup-xpub");
    field.value = bip138.bip138ToBase64(built.bytes);
    field.dispatchEvent(new Event("input"));
    await tick();
    assert.equal(row.hidden, false);
    field.value = "";
    slice.hodlMsigBip138Reset();
    assert.equal(row.hidden, true);
    assert.equal(status.getAttribute("data-bip138-status"), "");
    xpub.value = XPUB_A;
    xpub.dispatchEvent(new Event("input"));
    assert.equal(field.value, "");
  } finally {
    globalThis.document = saved.document;
    if (saved.preview === undefined) delete globalThis.__ENTROPYLAB_PREVIEW__;
    else globalThis.__ENTROPYLAB_PREVIEW__ = saved.preview;
  }
});
