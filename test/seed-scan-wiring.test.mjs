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

test("the seed scan host is preview-gated", () => {
  assert.match(app, /function hodlSeedScanHostMarkup\(\) \{\s*return typeof __ENTROPYLAB_PREVIEW__ !== "undefined" && __ENTROPYLAB_PREVIEW__ \? '<div id="seed-scan-host"><\/div>' : "";\s*\}/);
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
  const clear = body.indexOf("hodlSeedScanOpenAfterMount = false;");
  assert.ok(take >= 0 && take < clear && clear < body.indexOf("if (!module || hodlSeedScan"), "the flag is cleared before the bail");
  assert.match(body, /wordlist: hodlBip39Wordlist/);
  assert.match(body, /beforeOpen: hodlSeedScanBeforeOpen/);
  assert.match(body, /onSeed: hodlSeedScanLoad/);
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
  const state = { fields: { seed: "old words" }, lastWord: "old", targetWords: 24, result: { kind: "seed" }, reveal: true, error: "bad", errorSpec: {} };
  const entry = { kind: "seed", length: 12, indices: new Uint16Array(12), count: 0, wiped: false, rev: 0 };
  let installed = null;
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
      installed = { session, key, method, value };
    },
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
});
