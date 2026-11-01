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
const HOSTS = [["psbt-scan-host", "psbt-text"], ["nonce-scan-host", "nonce-text"], ["psbted-scan-host", "psbted-text"]];
const hostsDeclaration = app.match(/const hodlPsbtScanHosts = \[[\s\S]*?\];/)?.[0] ?? "";
const bindSource = appSlice("hodlBindPsbtScans");
const destroySource = appSlice("hodlDestroyPsbtScans");

// A context with the real host list and the real bind function, and a
// document that answers only for the ids given. The flag is a getter, so a
// read is visible; a release build defines no flag at all.
function bindContext(ids, { defineFlag = true } = {}) {
  const reads = { count: 0 };
  const sandbox = {
    document: { getElementById: (id) => (ids.includes(id) ? { id, isConnected: true, childNodes: [] } : null) },
    hodlTText: (text) => text,
    hodlPsbtScans: [],
    hodlPsbtScanModule: null,
    hodlPsbtScanImport: null,
  };
  if (defineFlag) Object.defineProperty(sandbox, "__ENTROPYLAB_PREVIEW__", { get() { reads.count += 1; return false; }, configurable: true });
  const context = vm.createContext(sandbox);
  vm.runInContext(`${hostsDeclaration}\n${bindSource}`, context);
  return { context, reads };
}

test("hodlBindPsbtScans returns before reading the preview flag when no host exists", () => {
  assert.ok(bindSource, "hodlBindPsbtScans is missing from app.js");
  assert.ok(hostsDeclaration, "hodlPsbtScanHosts is missing from app.js");
  // The flag is read only through the typeof guard: a release build defines
  // no constant, so a bare read throws.
  assert.match(bindSource, /typeof __ENTROPYLAB_PREVIEW__ !== "undefined" && __ENTROPYLAB_PREVIEW__/);
  assert.doesNotMatch(bindSource.replace(/typeof __ENTROPYLAB_PREVIEW__ !== "undefined" && __ENTROPYLAB_PREVIEW__/g, ""), /__ENTROPYLAB_PREVIEW__/, "the preview flag is read bare somewhere in the function");
  const none = bindContext([]);
  none.context.hodlBindPsbtScans();
  assert.equal(none.reads.count, 0, "with no host the function must return before reading the flag");
  const some = bindContext(["psbt-scan-host", "psbt-text"]);
  some.context.hodlBindPsbtScans();
  assert.ok(some.reads.count > 0, "with a host the flag decides whether the module is imported");
  const release = bindContext(["psbt-scan-host", "psbt-text"], { defineFlag: false });
  assert.doesNotThrow(() => release.context.hodlBindPsbtScans(), "a bare read of the undefined flag would throw");
});

test("the wiring imports the panel module once and mounts the three host/field pairs", () => {
  assert.ok(bindSource, "hodlBindPsbtScans is missing from app.js");
  assert.ok(hostsDeclaration, "hodlPsbtScanHosts is missing from app.js");
  assert.equal((bindSource.match(/import\(/g) || []).length, 1, "the module is imported once, lazily");
  assert.match(bindSource, /import\("\.\/qr-psbt-scan\.js"\)/, "the panel module is ./qr-psbt-scan.js");
  assert.match(bindSource, /mountPsbtScan\(host, \{[^}]*\bfield\b[^}]*translate: hodlTText/, "the panel is mounted on the host with the field and the page translator");
  for (const [hostId, fieldId] of HOSTS) {
    assert.ok(hostsDeclaration.includes(`["${hostId}", "${fieldId}"]`), `${hostId} → ${fieldId} is not wired`);
  }
  assert.equal((hostsDeclaration.match(/\["/g) || []).length, HOSTS.length, "exactly the three PSBT fields are wired");
});

test("hodlDestroyPsbtScans destroys every panel, retires the decoders and is idempotent", () => {
  assert.ok(destroySource, "hodlDestroyPsbtScans is missing from app.js");
  const destroyed = [];
  let retired = 0;
  const context = vm.createContext({
    hodlPsbtScans: [
      { hostId: "psbt-scan-host", panel: { destroy: () => destroyed.push("psbt") } },
      { hostId: "nonce-scan-host", panel: { destroy: () => { destroyed.push("nonce"); throw new Error("the camera would not stop"); } } },
    ],
    hodlPsbtScanModule: { retireQrDecoders: () => { retired += 1; } },
  });
  vm.runInContext(destroySource, context);
  assert.doesNotThrow(() => context.hodlDestroyPsbtScans(), "one panel's failure must not escape the teardown");
  assert.deepEqual(destroyed, ["psbt", "nonce"], "every panel is destroyed, even after one throws");
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

test("the shell holds one preview-gated host after each PSBT field", () => {
  const lines = shell.split("\n");
  for (const [hostId, fieldId] of HOSTS) {
    const index = lines.findIndex((line) => line.includes(`id="${hostId}"`));
    assert.ok(index > 0, `#${hostId} is missing from the shell`);
    assert.equal(lines[index].trim(), `<div class="psbt-scan-host" id="${hostId}"></div>`, `#${hostId} must be the only markup on its line`);
    assert.equal(lines[index - 1].trim(), "<!-- preview -->", `#${hostId} must sit inside a preview block`);
    assert.equal(lines[index + 1].trim(), "<!-- /preview -->", `#${hostId} must close its preview block`);
    const fieldIndex = lines.findIndex((line) => line.includes(`id="${fieldId}"`));
    assert.ok(fieldIndex >= 0 && fieldIndex < index, `#${hostId} must follow #${fieldId}`);
    assert.equal(lines[index - 2].trim(), "</label>", `#${hostId} must follow the field's closing label`);
  }
  // The build's own transform: the release artifact drops the hosts, the
  // preview build keeps them.
  const release = applyPreviewBlocks(shell, false);
  const preview = applyPreviewBlocks(shell, true);
  for (const [hostId] of HOSTS) {
    assert.ok(!release.includes(hostId), `the release build must not ship #${hostId}`);
    assert.ok(preview.includes(hostId), `the preview build must keep #${hostId}`);
  }
});
