import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { loadAppFunctions } from "./app-slice-harness.mjs";

const app = readFileSync(new URL("../src/js/app.js", import.meta.url), "utf8");

const functionBody = (name) => {
  const start = app.indexOf(`function ${name}(`);
  assert.ok(start >= 0, `${name} is missing`);
  const open = app.indexOf("{", start);
  let depth = 0;
  for (let i = open; i < app.length; i += 1) {
    if (app[i] === "{") depth += 1;
    else if (app[i] === "}") {
      depth -= 1;
      if (depth === 0) return app.slice(start, i + 1);
    }
  }
  throw new Error(`${name} has no end`);
};

// The seed scan ships with Secure entry (owner 11-04): its host renders in
// every build and the bind reads no preview flag.
test("the seed scan host ships in every build", () => {
  assert.match(app, /function hodlSeedScanHostMarkup\(\) \{\s*return '<div id="seed-scan-host"><\/div>';\s*\}/);
  const start = app.indexOf("function hodlBindSeedScan()");
  assert.ok(start >= 0, "hodlBindSeedScan is missing");
  assert.doesNotMatch(app.slice(start, app.indexOf("\n}\n", start)), /__ENTROPYLAB_PREVIEW__/);
});

test("the words branch renders the seed scan host in both forms", () => {
  assert.ok(app.includes('<div id="seed-picker-host"></div>${hodlSeedScanHostMarkup()}'));
  // After the word suggestions, so the seed field, keyboard and suggestions
  // keep their pinned order (ui-defaults).
  assert.ok(app.includes('<div id="last-words" translate="no" class="row last-word-options"></div>${hodlSeedScanHostMarkup()}'));
});

test("the form and End Session destroy the seed scan panel", () => {
  const render = functionBody("hodlRenderKeyForm");
  assert.match(render, /hodlSeedScan\?\.destroy\(\)/);
  assert.match(render, /hodlSeedScan = null/);
  const wipeStart = app.indexOf("let clearSecretFields = () => {");
  assert.ok(wipeStart >= 0, "clearSecretFields is missing");
  const wipe = app.slice(wipeStart, app.indexOf("\n  };", wipeStart));
  assert.match(wipe, /hodlSeedScan\?\.destroy\(\)/);
  assert.match(wipe, /hodlSeedScan = null/);
  assert.match(wipe, /hodlSeedScanOpenAfterMount = false/);
  assert.match(wipe, /hodlBindSeedScan\(\)/);
});

test("hodlBindSeedScan mounts a seed panel with the shared import", () => {
  const body = functionBody("hodlBindSeedScan");
  assert.match(body, /accept: "seed"/);
  assert.match(body, /idPrefix: "seed-scan"/);
  // The open request is taken before any bail, so a mount that bails never
  // leaves it for a later one (Kimi, autofix review).
  const take = body.indexOf("let openNow = hodlSeedScanOpenAfterMount;");
  const clear = body.indexOf("hodlSeedScanOpenAfterMount = false;", take);
  assert.ok(take >= 0 && take < clear && clear < body.indexOf("if (!module || hodlSeedScan"), "the flag is cleared before the bail");
  assert.match(body, /wordlist: hodlBip39Wordlist/);
  assert.match(body, /beforeOpen: hodlSeedScanBeforeOpen/);
  assert.match(body, /onSeed: hodlSeedScanLoad/);
  assert.match(body, /afterLoad: hodlSeedScanAfterLoad,/);
  assert.match(body, /import\("\.\/qr-key-scan\.js"\)/);
});

test("hodlSeedScanBeforeOpen turns Secure entry on only when it is off", () => {
  const body = functionBody("hodlSeedScanBeforeOpen");
  assert.match(body, /!hodlSecureEntryOn/);
  assert.match(body, /await hodlSecureEntryToggle\(true\)/);
  assert.match(body, /hodlSeedScanOpenAfterMount = true/);
  assert.match(body, /hodlSeedScanOpenAfterMount = false/);
});

test("hodlSeedScanLoad zeroes the caller's indices in a finally", () => {
  const body = functionBody("hodlSeedScanLoad");
  assert.match(body, /finally \{\s*try \{ indices\.fill\(0\); \} catch \{\}\s*\}/);
});

test("hodlSeedScanLoad installs the scanned indices and empties the seed text", async () => {
  const state = { fields: { seed: "old words" }, lastWord: "old", targetWords: 24, result: { kind: "seed" }, reveal: true, error: "bad", errorSpec: {}, globalSync: true, globalSyncSource: "seed:words" };
  const entry = { kind: "seed", length: 12, indices: new Uint16Array(12), count: 0, wiped: false, rev: 0 };
  let installed = null;
  const order = [], wiped = [], cleared = [];
  const previous = state.result;
  const stubs = {
    hodlSecureSeedActive: () => true,
    hodlKeys: [state],
    hodlActiveKey: 0,
    hodlSecureKeyOf: () => "k1",
    hodlSecureSession: {},
    seedEntry: (length) => {
      entry.length = length;
      return entry;
    },
    seedSet: (target, position, index) => {
      target.indices[position] = index;
      target.count = Math.max(target.count, position + 1);
    },
    sessionSet: (session, key, method, value) => {
      order.push("install");
      installed = { session, key, method, value };
    },
    hodlInvalidateLiveKeyResult: () => {
      order.push("invalidate");
      state.result = null;
      state.reveal = false;
    },
    hodlClearGlobalSyncCopies: (target) => cleared.push(target),
    hodlWipeUnsharedWalletRows: (result) => wiped.push(result),
    hodlRenderKeyForm: () => {},
    hodlRestoreFormFields: () => {},
    hodlUpdateSeedLengthControl: () => {},
    hodlSecureSeedChanged: () => {},
  };
  const { hodlSeedScanLoad } = await loadAppFunctions(["hodlSeedScanLoad"], { stubs });
  const indices = new Uint16Array([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3]);
  hodlSeedScanLoad(indices, 12);
  assert.ok(indices.every((index) => index === 0), "the caller's buffer was not zeroed");
  assert.equal(installed.key, "k1");
  assert.equal(installed.method, "seed");
  assert.equal(installed.value, entry);
  assert.deepEqual(Array.from(entry.indices), [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3]);
  assert.equal(entry.count, 12);
  assert.equal(state.fields.seed, "");
  assert.equal(state.lastWord, "");
  assert.equal(state.targetWords, 12);
  assert.equal(state.result, null);
  assert.equal(state.reveal, false);
  assert.equal(state.error, "");
  assert.equal(state.errorSpec, null);
  // GLM, MiniMax (round 4): a derivation on the old words stops before the
  // new words go in; Kimi, MiniMax: the old wallet is wiped.
  assert.deepEqual(order, ["invalidate", "install"]);
  assert.deepEqual(wiped, [previous]);
  assert.deepEqual(cleared, [state]);
});

test("hodlSeedScanLoad throws when it cannot load, so the panel says nothing was loaded", async () => {
  let installed = false;
  const stubs = {
    hodlSecureSeedActive: () => false,
    hodlKeys: [{ fields: { seed: "" } }],
    hodlActiveKey: 0,
    hodlSecureKeyOf: () => "k1",
    hodlSecureSession: {},
    seedEntry: () => { throw new Error("not reached"); },
    seedSet: () => {},
    sessionSet: () => { installed = true; },
    hodlInvalidateLiveKeyResult: () => {},
    hodlWipeUnsharedWalletRows: () => {},
    hodlRenderKeyForm: () => {},
    hodlRestoreFormFields: () => {},
    hodlUpdateSeedLengthControl: () => {},
    hodlSecureSeedChanged: () => {},
  };
  const { hodlSeedScanLoad } = await loadAppFunctions(["hodlSeedScanLoad"], { stubs });
  const indices = new Uint16Array(12).fill(5);
  assert.throws(() => hodlSeedScanLoad(indices, 12));
  assert.equal(installed, false);
  assert.ok(indices.every((index) => index === 0), "the caller's buffer is zeroed even then");
});

test("a scan replaces a seed typed as word numbers too, and a failed redraw does not undo a load", () => {
  // Kimi (round 5): the replace note and the load ignored the Numbers field.
  const replaces = functionBody("hodlSeedScanReplaces");
  assert.match(replaces, /state\.fields\?\.seedNumbers/);
  const load = functionBody("hodlSeedScanLoad");
  assert.match(load, /state\.fields\.seedNumbers = "";/);
  // GLM (round 5): after sessionSet the redraw is guarded, so a throw there
  // cannot reach the panel's "nothing was loaded".
  const installed = load.indexOf("sessionSet(hodlSecureSession, key, \"seed\", entry);");
  const guarded = load.indexOf("try {\n      hodlRenderKeyForm();");
  assert.ok(installed > 0 && guarded > installed, "the redraw after the install is inside a try");
});

test("an open request is dropped for a hidden page", () => {
  // K3.1 (#1364 round 6): the mount after Secure entry turns on must not
  // start the camera out of sight.
  const body = functionBody("hodlBindSeedScan");
  assert.match(body, /if \(openNow && document\.visibilityState !== "hidden"\) try \{ hodlSeedScan\.open\(\); \} catch \{\}/);
});

// Continue redraws the form, and the new picker mounts only once its import
// resolves, so a focus call made right after the load would find no picker and
// leave focus on the page body (Claude, checking the autofix round).
test("a scanned seed's focus goes to the picker, after its mount when needed", () => {
  const after = functionBody("hodlSeedScanAfterLoad");
  assert.match(after, /if \(hodlSeedPicker\) \{\s*try \{ hodlSeedPicker\.focus\(\); \} catch \{\}\s*return;\s*\}\s*hodlSeedPickerFocusOnMount = true;/);
  const mount = functionBody("hodlMountSeedPicker");
  assert.match(mount, /if \(hodlSeedPickerFocusOnMount\) \{\s*hodlSeedPickerFocusOnMount = false;\s*try \{ hodlSeedPicker\.focus\(\); \} catch \{\}\s*\}/);
  assert.ok(mount.indexOf("hodlSeedPickerFocusOnMount") > mount.indexOf("module.mountSeedPicker("), "the mount focuses only once the picker exists");
  // A redraw drops a request left from an earlier load.
  assert.match(functionBody("hodlRenderKeyForm"), /hodlSeedPicker = null;\s*hodlSeedPickerFocusOnMount = false;/);
});

// The words are installed before the copies are cleared, so a throw there must
// not reach the panel as "nothing was loaded" (Kimi, #1439 gate). A wallet made
// from a private key keeps its fields, as at turn-on Keep; the live result is
// invalidated first, so the check reads the result kept from before it
// (GLM, MiniMax, red team, #1439 gate r2).
test("the seed scan clears Global sync copies of the old words, guarded", () => {
  const body = functionBody("hodlSeedScanLoad");
  assert.match(body, /if \(state\.globalSync && \["seed:words", "seed:numbers"\]\.includes\(state\.globalSyncSource\) && previous\?\.kind !== "single"\) \{\s*try \{ hodlClearGlobalSyncCopies\(state\); \} catch \{\}\s*\}/);
  const kept = body.indexOf("let previous = state.result;");
  assert.ok(kept >= 0 && kept < body.indexOf("hodlInvalidateLiveKeyResult()"), "the result is read before it is invalidated");
  assert.ok(body.indexOf("hodlInvalidateLiveKeyResult()") < body.indexOf("previous?.kind"));
  assert.doesNotMatch(body, /globalSyncSource\)[^\n]*state\.result\?\.kind/);
});
