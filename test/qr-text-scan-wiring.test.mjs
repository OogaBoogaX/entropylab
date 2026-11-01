import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import vm from "node:vm";
import { applyPreviewBlocks } from "../scripts/preview-blocks.mjs";
import * as panelModule from "../src/js/qr-text-scan.js";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const app = readFileSync(join(root, "src/js/app.js"), "utf8");
const shell = readFileSync(join(root, "src/shell.html"), "utf8");
const lightning = readFileSync(join(root, "src/js/lightning.js"), "utf8");

function sliceFunction(source, name) {
  const start = source.indexOf(`function ${name}(`);
  if (start < 0) return "";
  // Skip the parameter list first: it can hold destructuring braces
  // (hodlInitLn's options), which are not the body.
  let index = start + `function ${name}`.length, parens = 0;
  for (; index < source.length; index++) {
    if (source[index] === "(") parens++;
    else if (source[index] === ")" && --parens === 0) break;
  }
  let depth = 0;
  for (index = source.indexOf("{", index); index < source.length; index++) {
    if (source[index] === "{") depth++;
    else if (source[index] === "}" && --depth === 0) return source.slice(start, index + 1);
  }
  throw new Error(`Could not extract ${name}`);
}

const appSlice = (name) => sliceFunction(app, name);
const HOSTS = [
  ["ln-inv-scan-host", "ln-inv-input", "lightning", ""],
  ["sp-recipients-scan-host", "sp-recipients", "sp", "append"],
  ["bip47-contact-scan-host", "bip47-contact", "payment-code", ""],
  ["msig-descriptor-scan-host", "msig-descriptor", "descriptor", ""],
  ["descriptor-reuse-scan-host", "descriptor-reuse-text", "descriptor", ""],
  ["core-add-scan-host", "core-add-text", "descriptor", ""],
];

test("the shell hosts are empty public-text divs in every build", () => {
  const lines = shell.split("\n");
  const fields = new Set();
  for (const [hostId, fieldId, accept, mode] of HOSTS) {
    const index = lines.findIndex((line) => line.includes(`id="${hostId}"`));
    assert.ok(index > 0, `#${hostId} is missing`);
    assert.match(lines[index].trim(), new RegExp(`^<div\\b[^>]*\\bid="${hostId}"[^>]*></div>$`));
    assert.match(lines[index], new RegExp(`data-scan-field="${fieldId}"`));
    assert.match(lines[index], new RegExp(`data-scan-accept="${accept}"`));
    if (mode) assert.match(lines[index], new RegExp(`data-scan-mode="${mode}"`));
    else assert.doesNotMatch(lines[index], /data-scan-mode=/);
    const previous = lines[index - 1].trim();
    assert.ok(previous.includes(`id="${fieldId}"`) || previous === "</label>");
    const fieldIndex = lines.findIndex((line) => line.includes(`id="${fieldId}"`));
    assert.ok(fieldIndex >= 0 && fieldIndex < index);
    fields.add(fieldId);
  }
  const used = [...shell.matchAll(/data-scan-field="([^"]+)"/g)].map((match) => match[1]);
  // Each field has exactly one host; the shell's order is its own.
  assert.deepEqual([...used].sort(), [...fields].sort());
  assert.equal((shell.match(/data-scan-mode="append"/g) || []).length, 1);
  const release = applyPreviewBlocks(shell, false);
  const preview = applyPreviewBlocks(shell, true);
  for (const [hostId] of HOSTS) {
    assert.ok(release.includes(`id="${hostId}"`));
    assert.ok(preview.includes(`id="${hostId}"`));
  }
});

test("bind reads no preview flag and mounts through the real export", () => {
  const bind = appSlice("hodlBindTextScans");
  assert.ok(bind);
  assert.equal((bind.match(/import\(/g) || []).length, 1);
  assert.match(bind, /import\("\.\/qr-text-scan\.js"\)/);
  assert.doesNotMatch(bind, /__ENTROPYLAB_PREVIEW__/);
  assert.match(bind, /module\.mountTextScan\(host, \{ field, accept: host\.dataset\.scanAccept, mode: host\.dataset\.scanMode \|\| "replace" \}\)/);
  assert.equal(typeof panelModule.mountTextScan, "function");
  assert.equal(typeof panelModule.retireQrDecoders, "function");
  assert.match(app, /const hodlTextScanClears = \[\["ln-inv-clear", "ln-inv-card"\], \["sp-wipe", "sp-card"\], \["psbt-wipe", "psbt-card"\], \["core-wipe", "core-card"\]\];/);
});

function bindContext(specs, { importPromise = null, containers = [] } = {}) {
  const elements = new Map();
  const hosts = specs.map((spec) => {
    const host = {
      id: spec.id,
      isConnected: spec.connected !== false,
      childNodes: [],
      dataset: { scanField: spec.fieldId, scanAccept: spec.accept, scanMode: spec.mode },
      replaceChildren() { this.childNodes = []; },
    };
    if (spec.id) elements.set(spec.id, host);
    if (spec.fieldId && spec.field !== false) elements.set(spec.fieldId, { id: spec.fieldId });
    return host;
  });
  for (const container of containers) elements.set(container.id, container);
  const sandbox = {
    document: {
      querySelectorAll: (selector) => selector === "[data-scan-field]" ? hosts : [],
      getElementById: (id) => elements.get(id) ?? null,
    },
    hodlTextScans: [],
    hodlTextScanModule: null,
    hodlTextScanImport: importPromise,
    hodlTextScanEpoch: 0,
  };
  const context = vm.createContext(sandbox);
  vm.runInContext(`${appSlice("hodlBindTextScans")}\n${appSlice("hodlDestroyTextScans")}\n${appSlice("hodlResetTextScans")}`, context);
  return { context, hosts, elements };
}

test("bind mounts each host once and skips a host with no id or no field", async () => {
  const none = bindContext([]);
  none.context.hodlBindTextScans();
  assert.equal(none.context.hodlTextScanImport, null);

  let resolveImport;
  const importPromise = new Promise((resolve) => { resolveImport = resolve; });
  const { context } = bindContext([
    { id: "h-ln", fieldId: "ln-inv-input", accept: "lightning" },
    { id: "h-sp", fieldId: "sp-recipients", accept: "sp", mode: "append" },
    { id: "", fieldId: "ln-inv-input", accept: "lightning" },
    { id: "h-missing", fieldId: "no-such-field", accept: "xpub", field: false },
  ], { importPromise });
  const mounted = [];
  resolveImport({
    mountTextScan: (host, options) => {
      mounted.push({ id: host.id, field: options.field.id, accept: options.accept, mode: options.mode });
      host.childNodes.push("panel");
      return { destroy() { host.childNodes = []; } };
    },
  });
  context.hodlBindTextScans();
  await new Promise((resolve) => setImmediate(resolve));
  assert.deepEqual(mounted, [
    { id: "h-ln", field: "ln-inv-input", accept: "lightning", mode: "replace" },
    { id: "h-sp", field: "sp-recipients", accept: "sp", mode: "append" },
  ]);
  context.hodlBindTextScans();
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(mounted.length, 2);
});

test("a mount pending at teardown is dropped and the next bind mounts", async () => {
  let resolveImport;
  const importPromise = new Promise((resolve) => { resolveImport = resolve; });
  const { context, hosts } = bindContext([{ id: "h-ln", fieldId: "ln-inv-input", accept: "lightning" }], { importPromise });
  let mounted = 0;
  const module = {
    mountTextScan: (host) => {
      mounted += 1;
      host.childNodes.push("panel");
      return { destroy() { host.childNodes = []; } };
    },
  };
  context.hodlBindTextScans();
  context.hodlDestroyTextScans();
  resolveImport(module);
  await importPromise;
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(mounted, 0);
  assert.equal(hosts[0].childNodes.length, 0);
  context.hodlBindTextScans();
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(mounted, 1);
  assert.equal(context.hodlTextScans.length, 1);
});

test("reset destroys and remounts only the named card and a disconnected host", async () => {
  let resolveImport;
  const importPromise = new Promise((resolve) => { resolveImport = resolve; });
  const specs = [
    { id: "h-in", fieldId: "ln-inv-input", accept: "lightning" },
    { id: "h-out", fieldId: "sp-recipients", accept: "sp", mode: "append" },
    { id: "h-gone", fieldId: "bip47-contact", accept: "payment-code" },
  ];
  const container = { id: "c1", contains: (node) => node.id === "h-in" };
  const { context, hosts } = bindContext(specs, { importPromise, containers: [container] });
  const destroyed = [];
  let mounted = 0;
  resolveImport({
    mountTextScan: (host) => {
      mounted += 1;
      const generation = mounted;
      host.childNodes.push(generation);
      return {
        destroy() {
          destroyed.push(host.id);
          if (host.id === "h-gone") throw new Error("the camera would not stop");
          host.childNodes = [];
        },
      };
    },
  });
  context.hodlBindTextScans();
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(mounted, 3);
  hosts[2].isConnected = false;
  context.hodlResetTextScans("c1");
  await new Promise((resolve) => setImmediate(resolve));
  assert.deepEqual(destroyed, ["h-in", "h-gone"]);
  assert.equal(mounted, 4);
  assert.equal(context.hodlTextScans.map((entry) => entry.host.id).sort().join(), "h-in,h-out");
  assert.equal(hosts[2].childNodes.length, 0);
  assert.doesNotThrow(() => context.hodlDestroyTextScans());
  assert.doesNotThrow(() => context.hodlDestroyTextScans());
});

test("End Session, locale, boot and workspace wire the text panels around the PSBT panels", () => {
  const wipe = appSlice("hodlInitSecretFieldAutoClear");
  const psbtDestroy = wipe.indexOf("hodlDestroyPsbtScans()");
  const textDestroy = wipe.indexOf("hodlDestroyTextScans()");
  const keyRetire = wipe.indexOf("hodlKeyScanModule?.retireQrDecoders()");
  const textRetire = wipe.indexOf("hodlTextScanModule?.retireQrDecoders()");
  const psbtBind = wipe.indexOf("hodlBindPsbtScans()");
  const textBind = wipe.indexOf("hodlBindTextScans()");
  assert.ok(textDestroy > psbtDestroy && textDestroy < keyRetire);
  assert.ok(textRetire > keyRetire);
  assert.ok(textBind > psbtBind);

  const apply = appSlice("hodlApplyLocale");
  const localeTextDestroy = apply.indexOf("hodlDestroyTextScans()");
  const localeTextBind = apply.indexOf("hodlBindTextScans()");
  const localePsbtDestroy = apply.indexOf("hodlDestroyPsbtScans()");
  assert.ok(localeTextDestroy >= 0 && localeTextBind > localeTextDestroy && localeTextBind < localePsbtDestroy);
  const psbtAt = apply.indexOf("hodlBindPsbtScans()");
  assert.match(apply.slice(psbtAt), /^hodlBindPsbtScans\(\);[^\n]*\n\}$/);

  const boot = appSlice("hodlBoot");
  const bootPsbt = boot.indexOf("hodlBindPsbtScans()");
  const bootText = boot.indexOf("hodlBindTextScans()");
  assert.ok(bootText > bootPsbt);
  assert.match(boot.slice(bootText), /hodlBindTextScans\(\);\n  for \(let \[button, card\] of hodlTextScanClears\)/);

  const show = appSlice("hodlShowWorkspace");
  const resetAt = show.indexOf('if (typeof hodlResetTextScans === "function") hodlResetTextScans();');
  assert.ok(resetAt >= 0 && resetAt < show.indexOf("hodlWorkspace = id;"));
});

test("co-signer rows, multisig restore, and the invoice field are wired", () => {
  const fill = appSlice("hodlFillKeys");
  const destroyAt = fill.indexOf('if (typeof hodlDestroyTextScans === "function") hodlDestroyTextScans("msig-keys");');
  const htmlAt = fill.indexOf('box.innerHTML = "";');
  assert.ok(destroyAt >= 0 && destroyAt < htmlAt);
  assert.ok(fill.includes('"msig-scan-x-" + i'));
  assert.ok(fill.includes("scanHost.dataset.scanField = ta.id"));
  assert.ok(fill.includes('scanHost.dataset.scanAccept = "xpub"'));
  assert.ok(fill.includes("content.append(chips, keyStatus, lab, scanHost, specLabel, originFields, advanced)"));
  assert.ok(fill.lastIndexOf('if (typeof hodlBindTextScans === "function") hodlBindTextScans();') > fill.lastIndexOf("hodlRefreshMsigSessionPickers();"));

  const restore = appSlice("hodlRestoreMsig");
  const restoreAt = restore.indexOf('if (typeof hodlResetTextScans === "function") hodlResetTextScans("msig-card");');
  assert.ok(restoreAt >= 0 && restoreAt < restore.indexOf("hodlFillKeys("));

  const init = sliceFunction(lightning, "hodlInitLn");
  assert.ok(init.indexOf('getElementById("ln-inv-input")') >= 0);
  assert.ok(init.includes('addEventListener("input", hodlLnInvReset)'));
});

test("switching PSBT tools resets the card only when the tool changes", () => {
  let resets = [];
  const context = vm.createContext({
    hodlPsbtTool: "inspector",
    hodlResetPsbtScans() {},
    hodlResetTextScans(root) { resets.push(root); },
    hodlSyncPsbtTool() {},
    hodlJournalLog() {},
    document: { querySelector: () => null },
  });
  vm.runInContext(appSlice("hodlShowPsbtTool"), context);
  context.hodlShowPsbtTool("inspector");
  assert.deepEqual(resets, []);
  context.hodlShowPsbtTool("editor");
  assert.deepEqual(resets, ["psbt-card"]);
});

test("switching privacy tools resets the text panels only when the tool changes", () => {
  let resets = 0;
  const context = vm.createContext({
    hodlPrivacyTool: "sp",
    hodlPrivacyTools: [["sp", "sp-card"], ["bip47", "bip47-card"]],
    hodlResetTextScans() { resets += 1; },
    hodlSyncPrivacyTool() {},
    hodlJournalLog() {},
    hodlBip47Conceal() {},
    document: { getElementById: () => ({}), querySelector: () => null },
  });
  vm.runInContext(appSlice("hodlShowPrivacyTool"), context);
  context.hodlShowPrivacyTool("sp");
  assert.equal(resets, 0);
  context.hodlShowPrivacyTool("bip47");
  assert.equal(resets, 1);
});

test("reindexing co-signers retargets each scan host", () => {
  const rows = [0, 1].map((n) => {
    const ta = { id: "old-" + n };
    const scanHost = { id: "old-scan-" + n, dataset: {} };
    return {
      ta,
      scanHost,
      row: {
        setAttribute() {},
        querySelector(selector) {
          if (selector === "textarea") return ta;
          if (selector === "[data-scan-field]") return scanHost;
          return null;
        },
      },
    };
  });
  let reset = null;
  const context = vm.createContext({
    document: { querySelectorAll: () => rows.map((item) => item.row) },
    hodlTText: () => "",
    hodlSyncMsigKeyMoveButtons() {},
    hodlUpdateMsigKeyPlaceholders() {},
    hodlResetTextScans(card) { reset = card; },
  });
  vm.runInContext(appSlice("hodlReindexMsigKeys"), context);
  context.hodlReindexMsigKeys();
  rows.forEach((item, index) => {
    assert.equal(item.scanHost.id, "msig-scan-x-" + index);
    assert.equal(item.scanHost.dataset.scanField, "msig-x-" + index);
    assert.equal(item.scanHost.dataset.scanField, item.ta.id);
  });
  assert.equal(reset, "msig-keys");
});
