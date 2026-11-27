import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { applyPreviewBlocks } from "../scripts/preview-blocks.mjs";

const appSource = readFileSync(new URL("../src/js/app.js", import.meta.url), "utf8");
const shell = readFileSync(new URL("../src/shell.html", import.meta.url), "utf8");

function extractFunction(name) {
  const start = appSource.indexOf(`function ${name}(`);
  assert.ok(start >= 0, `${name} is missing from src/js/app.js`);
  let depth = 0;
  for (let i = appSource.indexOf("{", start); i < appSource.length; i++) {
    if (appSource[i] === "{") depth++;
    else if (appSource[i] === "}" && --depth === 0) return appSource.slice(start, i + 1);
  }
  throw new Error(`unbalanced braces in ${name}`);
}

function fakeButton(tool) {
  const button = {
    dataset: { seedtoolsTool: tool },
    attrs: {},
    classes: new Set(),
    tabIndex: -1,
    focused: false,
    setAttribute(name, value) { button.attrs[name] = value; },
    getAttribute(name) { return button.attrs[name]; },
    focus() { button.focused = true; },
  };
  button.classList = {
    toggle(name, on) { if (on) button.classes.add(name); else button.classes.delete(name); },
  };
  return button;
}

function fakeDocument(tools) {
  const buttons = tools.map(fakeButton);
  const cards = Object.fromEntries(tools.map((tool) => [`${tool}-card`, { hidden: true }]));
  const strip = { querySelectorAll: (selector) => (selector === "[data-seedtools-tool]" ? buttons : []) };
  const manager = { hidden: true };
  const intro = { hidden: true };
  return {
    buttons,
    cards,
    manager,
    intro,
    getElementById(id) {
      if (id === "seedtools-tool-tabs") return strip;
      if (id === "seedtools-manager") return manager;
      if (id === "seedtools-tool-intro") return intro;
      return cards[id] ?? null;
    },
    querySelector(selector) {
      const match = /^#seedtools-tool-tabs \[data-seedtools-tool="([^"]+)"\]$/.exec(selector);
      return match ? buttons.find((button) => button.dataset.seedtoolsTool === match[1]) ?? null : null;
    },
  };
}

function loadSeedTools(document, { tools = [["bip85", "bip85-card"]], workspace = "bip85" } = {}) {
  const journal = [];
  const source = [
    `"use strict";`,
    `var hodlSeedTool = "bip85";`,
    `var hodlSeedTools = ${JSON.stringify(tools)};`,
    extractFunction("hodlSyncSeedTool"),
    extractFunction("hodlShowSeedTool"),
    extractFunction("hodlInitSeedToolTabs"),
    `return { hodlSyncSeedTool, hodlShowSeedTool, hodlInitSeedToolTabs, get tool() { return hodlSeedTool; } };`,
  ].join("\n");
  const factory = new Function("document", "hodlJournalLog", "hodlInitTabDrag", "hodlWorkspace", source);
  const api = factory(document, (...args) => journal.push(args), () => {}, workspace);
  return {
    init: api.hodlInitSeedToolTabs,
    show: api.hodlShowSeedTool,
    sync: api.hodlSyncSeedTool,
    get tool() { return api.tool; },
    journal,
  };
}

test("the Seed tools workspace is preview-only", () => {
  const preview = applyPreviewBlocks(shell, true);
  const release = applyPreviewBlocks(shell, false);
  assert.match(preview, /id="seedtools-manager"/);
  assert.match(preview, /id="seedtools-tool-tabs"/);
  assert.match(preview, /id="seedtools-tool-intro"/);
  assert.match(preview, /Seed tools/);
  assert.doesNotMatch(release, /id="seedtools-manager"/);
  assert.doesNotMatch(release, /id="seedtools-tool-tabs"/);
  assert.doesNotMatch(release, /id="seedtools-tool-intro"/);
  assert.doesNotMatch(release, /Seed tools/);
  assert.match(release, /aria-label="BIP-85 Child"/);
  assert.match(release, /<span class="workspace-tab-full">BIP-85<\/span>/);
  assert.match(release, /<span class="workspace-tab-short">BIP-85<\/span>/);
});

test("the preview station strip has one BIP-85 child seeds station", () => {
  const preview = applyPreviewBlocks(shell, true);
  const strip = /<div class="key-tabs" id="seedtools-tool-tabs"[\s\S]*?<\/div>/.exec(preview);
  assert.ok(strip, "the preview build is missing the Seed tools station tab list");
  const buttons = [...strip[0].matchAll(/<button\b[^>]*>/g)].map((match) => match[0]);
  assert.equal(buttons.length, 1, "one station ships in preview");
  assert.match(buttons[0], /data-seedtools-tool="bip85"/);
  assert.match(buttons[0], /aria-controls="bip85-card"/);
  assert.match(buttons[0], /role="tab"/);
  assert.match(buttons[0], /aria-selected="true"/);
  assert.match(strip[0], /BIP-85 child seeds/);
});

test("the Seed tools manager, intro and card show only on the bip85 workspace", () => {
  const document = fakeDocument(["bip85"]);
  const api = loadSeedTools(document);
  api.init();
  assert.equal(document.manager.hidden, false);
  assert.equal(document.intro.hidden, false);
  assert.equal(document.cards["bip85-card"].hidden, false);
  const elsewhere = fakeDocument(["bip85"]);
  loadSeedTools(elsewhere, { workspace: "calc" }).init();
  assert.equal(elsewhere.manager.hidden, true);
  assert.equal(elsewhere.intro.hidden, true);
  assert.equal(elsewhere.cards["bip85-card"].hidden, true);
});

test("the station tabs answer the arrow keys and keep focus inside the strip", () => {
  const document = fakeDocument(["bip85"]);
  const api = loadSeedTools(document);
  api.init();
  const [bip85] = document.buttons;
  let prevented = false;
  bip85.onkeydown({ key: "ArrowRight", preventDefault() { prevented = true; } });
  assert.equal(prevented, true);
  assert.equal(api.tool, "bip85");
  assert.equal(bip85.focused, true);
  assert.equal(bip85.getAttribute("aria-selected"), "true");
  assert.equal(document.cards["bip85-card"].hidden, false);
});

test("the bip85 workspace tab is renamed in preview only", () => {
  const declaration = /var hodlWorkspaceTabs = (\[[\s\S]*?\]);/.exec(appSource);
  assert.ok(declaration, "the workspace tab list is missing");
  assert.match(declaration[1], /\["bip85", "BIP-85 Child", "BIP-85", "BIP-85"\]/, "the release tab entry is unchanged");
  assert.match(appSource, /if \(PREVIEW\) \{\s*let bip85Tab = hodlWorkspaceTabs\.find\(\(\[id\]\) => id === "bip85"\);\s*if \(bip85Tab\) \{\s*bip85Tab\[1\] = "Seed tools";\s*bip85Tab\[2\] = "Seeds";\s*bip85Tab\[3\] = "Seed tools";\s*\}\s*\}/);
});

// Round 2 (Claude's pre-merge read): app.js is an ES module, so it runs in
// strict mode. A function declared inside a block is scoped to that block,
// and the call sites outside it throw ReferenceError in a preview build.
test("the seed station functions are top-level declarations", () => {
  for (const name of ["hodlSyncSeedTool", "hodlShowSeedTool", "hodlInitSeedToolTabs"]) {
    assert.match(appSource, new RegExp(`^function ${name}\\(`, "m"), `${name} must be declared at column 0, outside any block`);
  }
});

test("no function declaration sits inside a top-level if (PREVIEW) block", () => {
  const lines = appSource.split("\n");
  for (let i = 0; i < lines.length; i++) {
    if (lines[i] !== "if (PREVIEW) {") continue;
    for (let j = i + 1; j < lines.length && lines[j] !== "}"; j++) {
      assert.doesNotMatch(lines[j], /^\s+function\s+\w+\s*\(/, `line ${j + 1} declares a function inside the if (PREVIEW) block at line ${i + 1}`);
    }
  }
});
