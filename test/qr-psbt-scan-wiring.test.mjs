// The PSBT scan panels are wired like the Key Station's: preview-only hosts
// in the shell, a lazy import of the panel module, and a teardown wherever
// the Key Station's panel is torn down. These checks read the source and run
// the teardown, so removing any piece of the wiring fails here.
// Run with `npm test`.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import vm from "node:vm";
import { applyPreviewBlocks } from "../scripts/preview-blocks.mjs";
import * as panelModule from "../src/js/qr-psbt-scan.js";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const app = readFileSync(join(root, "src/js/app.js"), "utf8");
const shell = readFileSync(join(root, "src/shell.html"), "utf8");

// Slice one self-contained function out of app.js (the bundle cannot be
// evaluated wholesale in Node), as test/ui-behaviors.test.mjs does.
function appSlice(name) {
  const start = app.indexOf(`function ${name}(`);
  if (start < 0) return "";
  let depth = 0;
  for (let index = app.indexOf("{", start); index < app.length; index++) {
    if (app[index] === "{") depth++;
    else if (app[index] === "}" && --depth === 0) return app.slice(start, index + 1);
  }
  throw new Error(`Could not extract ${name}`);
}

// The three fields the owner asked for: PSBT Inspector, Nonce Inspector and
// PSBT Editor.
const HOSTS = [
  ["psbt-scan-host", "psbt-text"], ["nonce-scan-host", "nonce-text"], ["psbted-scan-host", "psbted-text"],
  ["rbf-scan-host", "psbt-rbf-original"], ["audit-scan-host", "psbt-audit-before"], ["psbted-compare-scan-host", "psbted-compare-text"],
];
const hostsDeclaration = app.match(/const hodlPsbtScanHosts = \[[\s\S]*?\];/)?.[0] ?? "";
const bindSource = appSlice("hodlBindPsbtScans");
const destroySource = appSlice("hodlDestroyPsbtScans");

const resetSource = appSlice("hodlResetPsbtScans");

// A context with the real host list and the real bind, destroy and reset
// functions, and a document that answers only for the ids given.
function bindContext(ids, { importPromise = null } = {}) {
  const elements = new Map(ids.map((id) => [id, { id, isConnected: true, childNodes: [], replaceChildren() { this.childNodes = []; } }]));
  const sandbox = {
    document: { getElementById: (id) => elements.get(id) ?? null },
    hodlPsbtScans: [],
    hodlPsbtScanModule: null,
    // A pending import stands in for the real one, so a test controls when
    // the module arrives.
    hodlPsbtScanImport: importPromise,
  };
  const context = vm.createContext(sandbox);
  vm.runInContext(`var hodlPsbtScanEpoch = 0;\n${hostsDeclaration}\n${bindSource}\n${destroySource}\n${resetSource}`, context);
  return { context, elements };
}

// The panels ship in every build: the wiring reads no preview flag, and
// without a host (the slice harness) it does nothing at all.
test("hodlBindPsbtScans reads no preview flag and imports nothing when no host exists", () => {
  assert.ok(bindSource, "hodlBindPsbtScans is missing from app.js");
  assert.ok(hostsDeclaration, "hodlPsbtScanHosts is missing from app.js");
  assert.doesNotMatch(bindSource, /__ENTROPYLAB_PREVIEW__/, "the PSBT scan panels are not preview-gated any more");
  const none = bindContext([]);
  none.context.hodlBindPsbtScans();
  assert.equal(none.context.hodlPsbtScanImport, null, "with no host nothing is imported");
  const some = bindContext(["psbt-scan-host", "psbt-text"]);
  assert.doesNotThrow(() => some.context.hodlBindPsbtScans());
  assert.notEqual(some.context.hodlPsbtScanImport, null, "with a host the module is imported");
});

// The export the wiring calls must exist on the real module: a renamed
// export would otherwise throw inside the mount's try and leave an empty host
// (MiniMax, #1357).
test("the wiring calls an export the panel module really has", () => {
  const name = bindSource.match(/module\.(\w+)\(host, \{ field \}\)/)?.[1];
  assert.ok(name, "the wiring must mount through module.<export>(host, { field })");
  assert.equal(typeof panelModule[name], "function", `qr-psbt-scan.js does not export ${name}`);
  assert.equal(typeof panelModule.retireQrDecoders, "function", "End Session retires the decoders through the module");
});

test("the wiring imports the panel module once and mounts the three host/field pairs", () => {
  assert.ok(bindSource, "hodlBindPsbtScans is missing from app.js");
  assert.ok(hostsDeclaration, "hodlPsbtScanHosts is missing from app.js");
  assert.equal((bindSource.match(/import\(/g) || []).length, 1, "the module is imported once, lazily");
  assert.match(bindSource, /import\("\.\/qr-psbt-scan\.js"\)/, "the panel module is ./qr-psbt-scan.js");
  assert.match(bindSource, /mountPsbtScan\(host, \{ field \}\)/, "the panel is mounted on the host with the field; it translates its own strings");
  assert.doesNotMatch(bindSource, /translate/, "no translator is passed: the module reads the page catalog itself");
  for (const [hostId, fieldId] of HOSTS) {
    assert.ok(hostsDeclaration.includes(`["${hostId}", "${fieldId}"]`), `${hostId} → ${fieldId} is not wired`);
  }
  assert.equal((hostsDeclaration.match(/\["/g) || []).length, HOSTS.length, "exactly the PSBT fields are wired");
});

// A mount still waiting on the import when the panels are torn down (End
// Session, a language switch) must mount nothing: the next bind mounts anew
// (DeepSeek red team, #1357).
test("a mount pending at teardown is dropped, and the next bind mounts anew", async () => {
  let resolveImport;
  const importPromise = new Promise((resolve) => { resolveImport = resolve; });
  const { context, elements } = bindContext(["psbt-scan-host", "psbt-text"], { importPromise });
  let mounted = 0;
  const module = { mountPsbtScan: (host) => { mounted += 1; host.childNodes.push("panel"); return { destroy() { host.childNodes = []; } }; } };
  context.hodlBindPsbtScans();
  context.hodlDestroyPsbtScans();
  resolveImport(module);
  await importPromise;
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(mounted, 0, "the mount that was pending at teardown must be dropped");
  assert.equal(elements.get("psbt-scan-host").childNodes.length, 0, "the host stays empty after the teardown");
  context.hodlBindPsbtScans();
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(mounted, 1, "a bind after the teardown mounts the panel");
  assert.equal(context.hodlPsbtScans.length, 1);
});

test("hodlDestroyPsbtScans destroys every panel, leaves the shared decoders alone and is idempotent", () => {
  assert.ok(destroySource, "hodlDestroyPsbtScans is missing from app.js");
  const destroyed = [];
  let retired = 0;
  const nonceHost = { id: "nonce-scan-host", childNodes: ["panel"], replaceChildren() { this.childNodes = []; } };
  const context = vm.createContext({
    document: { getElementById: (id) => (id === "nonce-scan-host" ? nonceHost : null) },
    hodlPsbtScans: [
      { hostId: "psbt-scan-host", panel: { destroy: () => destroyed.push("psbt") } },
      { hostId: "nonce-scan-host", panel: { destroy: () => { destroyed.push("nonce"); throw new Error("the camera would not stop"); } } },
    ],
    hodlPsbtScanModule: { retireQrDecoders: () => { retired += 1; } },
  });
  vm.runInContext(`var hodlPsbtScanEpoch = 0;\n${destroySource}`, context);
  assert.doesNotThrow(() => context.hodlDestroyPsbtScans(), "one panel's failure must not escape the teardown");
  assert.deepEqual(destroyed, ["psbt", "nonce"], "every panel is destroyed, even after one throws");
  assert.equal(nonceHost.childNodes.length, 0, "a panel that would not come down leaves no markup behind");
  assert.equal(context.hodlPsbtScanEpoch, 1, "a teardown bumps the epoch, so a pending mount is dropped");
  assert.equal(context.hodlPsbtScans.length, 0, "the mounted list is emptied");
  assert.equal(retired, 0, "the shared decoders are left alone: the nonce ceremony's frame decoder uses the same registry");
  assert.doesNotThrow(() => context.hodlDestroyPsbtScans(), "a second teardown must not throw");
  assert.deepEqual(destroyed, ["psbt", "nonce"], "a second teardown destroys nothing");
  assert.equal(context.hodlPsbtScans.length, 0, "the mounted list stays empty");
});

test("End Session and the language switch tear the panels down", () => {
  const wipe = appSlice("hodlInitSecretFieldAutoClear");
  assert.ok(wipe, "hodlInitSecretFieldAutoClear is missing from app.js");
  const keyDestroy = wipe.indexOf("hodlKeyScan?.destroy()");
  const psbtDestroy = wipe.indexOf("hodlDestroyPsbtScans()");
  assert.ok(keyDestroy >= 0, "End Session no longer destroys the Key Station panel");
  assert.ok(psbtDestroy > keyDestroy, "End Session must destroy the PSBT panels next to the Key Station's");
  assert.ok(psbtDestroy - keyDestroy < 400, "the PSBT teardown belongs with the Key Station's, before the wipe continues");
  const psbtRetire = wipe.indexOf("hodlPsbtScanModule?.retireQrDecoders()");
  assert.ok(psbtRetire > psbtDestroy, "End Session retires the decoders after the PSBT panels are destroyed");
  const keyBind = wipe.indexOf("hodlBindKeyScan()"), psbtBind = wipe.indexOf("hodlBindPsbtScans()");
  assert.ok(keyBind > psbtRetire && psbtBind > keyBind, "End Session re-mounts the PSBT panels after the Key Station's, so the Scan buttons come back");
  const apply = appSlice("hodlApplyLocale");
  assert.ok(apply, "hodlApplyLocale is missing from app.js");
  const destroyAt = apply.indexOf("hodlDestroyPsbtScans()");
  const bindAt = apply.indexOf("hodlBindPsbtScans()");
  assert.ok(destroyAt >= 0, "the language switch must tear the panels down");
  assert.ok(bindAt > destroyAt, "the language switch must re-mount the panels after tearing them down");
  assert.ok(apply.indexOf("hodlPaintKeySummary()") < destroyAt, "the panels re-mount after the rest of the page is repainted");
  assert.match(apply.slice(bindAt), /^hodlBindPsbtScans\(\);[^\n]*\n\}$/, "the re-mount is the last thing the language switch does");
});

test("the shell holds one host after each PSBT field, in every build", () => {
  const lines = shell.split("\n");
  for (const [hostId, fieldId] of HOSTS) {
    const index = lines.findIndex((line) => line.includes(`id="${hostId}"`));
    assert.ok(index > 0, `#${hostId} is missing from the shell`);
    // The host is one empty div alone on its line; its class is styling, not
    // a hook (AGENTS.md: tests hook on ids and data-*, never classes).
    assert.match(lines[index].trim(), new RegExp(`^<div [^>]*\\bid="${hostId}"[^>]*></div>$`), `#${hostId} must be one empty div, alone on its line`);
    const fieldIndex = lines.findIndex((line) => line.includes(`id="${fieldId}"`));
    assert.ok(fieldIndex >= 0 && fieldIndex < index, `#${hostId} must follow #${fieldId}`);
    // A one-line field label ends on the line before the host too.
    assert.ok(lines[index - 1].trim().endsWith("</label>"), `#${hostId} must follow the field's closing label directly`);
  }
  // The build's own transform: the release artifact ships the hosts, like
  // the preview build.
  const release = applyPreviewBlocks(shell, false);
  const preview = applyPreviewBlocks(shell, true);
  for (const [hostId] of HOSTS) {
    assert.ok(release.includes(`id="${hostId}"`), `the release build must ship #${hostId}`);
    assert.ok(preview.includes(`id="${hostId}"`), `the preview build must keep #${hostId}`);
  }
});

// A tool's own Clear and leaving the Transactions workspace close an open
// panel (its camera would otherwise keep streaming) and give the host a
// fresh, closed one (GLM and MiniMax, #1357).
test("Clear and leaving the Transactions workspace give every host a fresh, closed panel", async () => {
  assert.ok(resetSource, "hodlResetPsbtScans is missing from app.js");
  const destroyAt = resetSource.indexOf("hodlDestroyPsbtScans()"), bindAt = resetSource.indexOf("hodlBindPsbtScans()");
  assert.ok(destroyAt >= 0 && bindAt > destroyAt, "a reset tears the panels down, then mounts them anew");
  // Behaviour: a mounted panel is destroyed and a new one mounted.
  let resolveImport;
  const importPromise = new Promise((resolve) => { resolveImport = resolve; });
  const { context, elements } = bindContext(["psbt-scan-host", "psbt-text"], { importPromise });
  const destroyed = [];
  let mounted = 0;
  const module = { mountPsbtScan: (host) => { mounted += 1; const id = mounted; host.childNodes.push("panel"); return { destroy() { destroyed.push(id); host.childNodes = []; } }; } };
  resolveImport(module);
  context.hodlBindPsbtScans();
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(mounted, 1);
  context.hodlResetPsbtScans();
  await new Promise((resolve) => setImmediate(resolve));
  assert.deepEqual(destroyed, [1], "the open panel is destroyed");
  assert.equal(mounted, 2, "a fresh panel is mounted on the host");
  assert.equal(elements.get("psbt-scan-host").childNodes.length, 1, "the host holds the new panel only");
  assert.equal(context.hodlPsbtScans.length, 1);
  // Wiring: the three Clear buttons, at boot, after the first mount.
  const boot = appSlice("hodlBoot");
  assert.ok(boot, "hodlBoot is missing from app.js");
  const wiring = boot.match(/for \(let id of \[([^\]]*)\]\) document\.getElementById\(id\)\?\.addEventListener\("click", hodlResetPsbtScans\);/);
  assert.ok(wiring, "boot must give each PSBT tool's Clear a click listener that resets the panels");
  assert.deepEqual(wiring[1].split(",").map((id) => id.trim().replace(/"/g, "")).sort(), ["nonce-wipe", "psbt-wipe", "psbted-wipe"], "the Inspector, Nonce Inspector and Editor Clear buttons");
  assert.ok(boot.indexOf(wiring[0]) > boot.indexOf("hodlBindPsbtScans()"), "the listeners follow the first mount");
  // Wiring: switching between the Inspector, Nonce Inspector and Editor tabs
  // hides the card an open panel sits in, so it resets the panels first, and
  // only on a real change (Kimi, GLM, MiniMax, round 1).
  const tool = appSlice("hodlShowPsbtTool");
  assert.ok(tool, "hodlShowPsbtTool is missing from app.js");
  const toolReset = tool.indexOf('if (changed && typeof hodlResetPsbtScans === "function") hodlResetPsbtScans();');
  assert.ok(toolReset >= 0, "switching PSBT tools must reset the panels when the tool changes");
  assert.ok(toolReset < tool.indexOf("hodlSyncPsbtTool();"), "the reset runs before the cards are switched");
  // Behaviour: a real switch resets once; re-selecting the shown tool does not.
  let resets = 0;
  const toolContext = vm.createContext({
    hodlPsbtTool: "inspector",
    hodlResetPsbtScans: () => { resets += 1; },
    hodlSyncPsbtTool: () => {},
    hodlJournalLog: () => {},
    document: { querySelector: () => null },
  });
  vm.runInContext(tool, toolContext);
  toolContext.hodlShowPsbtTool("inspector");
  assert.equal(resets, 0, "re-selecting the shown tool keeps an open panel open");
  toolContext.hodlShowPsbtTool("editor");
  assert.equal(resets, 1, "switching to another tool closes the open panel");
  // Wiring: leaving the Transactions workspace, before the workspace changes.
  const show = appSlice("hodlShowWorkspace");
  assert.ok(show, "hodlShowWorkspace is missing from app.js");
  const leave = show.indexOf('if (hodlWorkspace === "psbt" && typeof hodlResetPsbtScans === "function") hodlResetPsbtScans();');
  assert.ok(leave >= 0, "leaving the Transactions workspace must reset the panels (guarded, like the Privacy conceal, for the slice harness)");
  assert.ok(leave < show.indexOf("hodlWorkspace = id;"), "the reset reads the workspace being left, so it runs before the switch");
});
