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

// Each station row is [tool, ...element ids]. The mock document answers for
// every element the rows name, and for the Seed XOR reveal switch.
const SEED_TOOLS = [["bip85", "bip85-card", "bip85-tool-intro", "bip85-manager"], ["seedxor", "seedxor-card", "seedxor-tool-intro"]];

function fakeDocument(rows) {
  const buttons = rows.map(([tool]) => fakeButton(tool));
  const cards = {};
  for (const [tool, ...ids] of rows) {
    if (!ids.length) ids.push(`${tool}-card`);
    for (const id of ids) cards[id] = { hidden: true };
  }
  const reveal = { checked: false, events: [], dispatchEvent(event) { reveal.events.push(event); return true; } };
  const strip = { querySelectorAll: (selector) => (selector === "[data-seedtools-tool]" ? buttons : []) };
  const manager = { hidden: true };
  const intro = { hidden: true };
  return {
    buttons,
    cards,
    reveal,
    manager,
    intro,
    getElementById(id) {
      if (id === "seedtools-tool-tabs") return strip;
      if (id === "seedtools-manager") return manager;
      if (id === "seedtools-tool-intro") return intro;
      if (id === "seedxor-reveal") return reveal;
      return cards[id] ?? null;
    },
    querySelector(selector) {
      const match = /^#seedtools-tool-tabs \[data-seedtools-tool="([^"]+)"\]$/.exec(selector);
      return match ? buttons.find((button) => button.dataset.seedtoolsTool === match[1]) ?? null : null;
    },
  };
}

function loadSeedTools(document, { tools = SEED_TOOLS, workspace = "bip85" } = {}) {
  const journal = [];
  // hodlSeedXorConceal is the fix under test: on the current source it is
  // absent, so the conceal assertions must fail on behaviour, not on a
  // missing harness piece.
  const conceal = appSource.includes("function hodlSeedXorConceal(") ? extractFunction("hodlSeedXorConceal") : "";
  const source = [
    `"use strict";`,
    `var hodlSeedTool = "bip85";`,
    `var hodlSeedTools = ${JSON.stringify(tools)};`,
    conceal,
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

test("the preview station strip has two stations: BIP-85 child seeds, then Seed XOR", () => {
  const preview = applyPreviewBlocks(shell, true);
  const strip = /<div class="key-tabs" id="seedtools-tool-tabs"[\s\S]*?<\/div>/.exec(preview);
  assert.ok(strip, "the preview build is missing the Seed tools station tab list");
  const buttons = [...strip[0].matchAll(/<button\b[\s\S]*?<\/button>/g)].map((match) => match[0]);
  assert.equal(buttons.length, 2, "two stations ship in preview");
  assert.match(buttons[0], /data-seedtools-tool="bip85"/);
  assert.match(buttons[0], /aria-controls="bip85-card"/);
  assert.match(buttons[0], /role="tab"/);
  assert.match(buttons[0], /aria-selected="true"/);
  assert.match(buttons[0], /BIP-85 child seeds/);
  assert.match(buttons[1], /data-seedtools-tool="seedxor"/);
  assert.match(buttons[1], /aria-controls="seedxor-card"/);
  assert.match(buttons[1], /role="tab"/);
  assert.match(buttons[1], /aria-selected="false"/);
});

test("the Seed tools manager and intro show only on the Seed tools workspace", () => {
  const document = fakeDocument(SEED_TOOLS);
  const api = loadSeedTools(document);
  api.init();
  assert.equal(document.manager.hidden, false);
  assert.equal(document.intro.hidden, false);
  const elsewhere = fakeDocument(SEED_TOOLS);
  loadSeedTools(elsewhere, { workspace: "calc" }).init();
  assert.equal(elsewhere.manager.hidden, true);
  assert.equal(elsewhere.intro.hidden, true);
  for (const id of ["bip85-card", "bip85-tool-intro", "bip85-manager", "seedxor-card", "seedxor-tool-intro"]) {
    assert.equal(elsewhere.cards[id].hidden, true, `${id} is hidden outside the Seed tools workspace`);
  }
});

test("the two stations swap their card and their intro together", () => {
  const document = fakeDocument(SEED_TOOLS);
  const api = loadSeedTools(document);
  api.init();
  assert.equal(document.cards["bip85-card"].hidden, false);
  assert.equal(document.cards["bip85-tool-intro"].hidden, false);
  assert.equal(document.cards["seedxor-card"].hidden, true);
  assert.equal(document.cards["seedxor-tool-intro"].hidden, true);
  api.show("seedxor");
  assert.equal(document.cards["bip85-card"].hidden, true);
  assert.equal(document.cards["bip85-tool-intro"].hidden, true, "the BIP-85 intro leaves with its card");
  assert.equal(document.cards["seedxor-card"].hidden, false);
  assert.equal(document.cards["seedxor-tool-intro"].hidden, false, "the Seed XOR intro arrives with its card");
  api.show("bip85");
  assert.equal(document.cards["bip85-card"].hidden, false);
  assert.equal(document.cards["bip85-tool-intro"].hidden, false);
  assert.equal(document.cards["seedxor-card"].hidden, true);
  assert.equal(document.cards["seedxor-tool-intro"].hidden, true);
});

test("the BIP-85 child strip belongs to the BIP-85 station", () => {
  const document = fakeDocument(SEED_TOOLS);
  const api = loadSeedTools(document);
  api.init();
  assert.equal(document.cards["bip85-manager"].hidden, false, "the BIP-85 child strip shows with its station");
  api.show("seedxor");
  assert.equal(document.cards["bip85-manager"].hidden, true, "the BIP-85 child strip leaves with its station");
  api.show("bip85");
  assert.equal(document.cards["bip85-manager"].hidden, false, "the BIP-85 child strip returns with its station");
  const elsewhere = fakeDocument(SEED_TOOLS);
  loadSeedTools(elsewhere, { workspace: "calc" }).init();
  assert.equal(elsewhere.cards["bip85-manager"].hidden, true, "outside the Seed tools workspace it is hidden");
});

test("a station row naming an element that is not in the document is skipped", () => {
  const document = fakeDocument(SEED_TOOLS);
  delete document.cards["bip85-manager"];
  const api = loadSeedTools(document);
  assert.doesNotThrow(() => api.init());
  assert.equal(document.cards["bip85-card"].hidden, false);
});

test("the station tabs answer the arrow keys and keep focus inside the strip", () => {
  const document = fakeDocument(SEED_TOOLS);
  const api = loadSeedTools(document);
  api.init();
  const [bip85, seedxor] = document.buttons;
  let prevented = false;
  bip85.onkeydown({ key: "ArrowRight", preventDefault() { prevented = true; } });
  assert.equal(prevented, true);
  assert.equal(api.tool, "seedxor");
  assert.equal(seedxor.focused, true);
  assert.equal(seedxor.getAttribute("aria-selected"), "true");
  assert.equal(bip85.getAttribute("aria-selected"), "false");
  assert.equal(document.cards["seedxor-card"].hidden, false);
  assert.equal(document.cards["bip85-card"].hidden, true);
  seedxor.onkeydown({ key: "Home", preventDefault() {} });
  assert.equal(api.tool, "bip85");
  assert.equal(document.cards["bip85-card"].hidden, false);
});

test("leaving the Seed XOR station conceals a revealed result; staying does not", () => {
  const document = fakeDocument(SEED_TOOLS);
  const api = loadSeedTools(document);
  api.init();
  api.show("seedxor");
  assert.equal(document.reveal.checked, false, "opening the station reveals nothing");
  assert.equal(document.reveal.events.length, 0);
  document.reveal.checked = true;
  api.show("seedxor");
  assert.equal(document.reveal.checked, true, "re-selecting the shown station leaves the reveal alone");
  assert.equal(document.reveal.events.length, 0);
  api.show("bip85");
  assert.equal(document.reveal.checked, false, "leaving the station unchecks the reveal");
  assert.equal(document.reveal.events.length, 1, "exactly one change event is dispatched");
  assert.equal(document.reveal.events[0].type, "change");
  assert.equal(document.reveal.events[0].bubbles, true, "seed-xor.js hears it bubbling through the card");
  api.show("seedxor");
  document.reveal.checked = true;
  api.show("nonsense");
  assert.equal(api.tool, "bip85", "an unknown id falls back to BIP-85");
  assert.equal(document.reveal.checked, false, "a fallback conceals too");
  assert.equal(document.reveal.events.length, 2);
});

test("leaving the Seed XOR station with nothing revealed dispatches nothing", () => {
  const document = fakeDocument(SEED_TOOLS);
  const api = loadSeedTools(document);
  api.init();
  api.show("seedxor");
  api.show("bip85");
  assert.equal(document.reveal.checked, false);
  assert.equal(document.reveal.events.length, 0, "an unchecked reveal dispatches no change event");
});

test("preview builds carry no Seed XOR workspace tab", () => {
  const preview = applyPreviewBlocks(shell, true);
  assert.equal((preview.match(/aria-controls="seedxor-card"/g) || []).length, 1, "only the Seed tools station controls the card");
});

test("release builds carry neither Seed tools nor a Seed XOR station", () => {
  const release = applyPreviewBlocks(shell, false);
  assert.doesNotMatch(release, /data-seedtools-tool="seedxor"/);
  assert.doesNotMatch(release, /id="seedtools-tool-tabs"/);
});

test("the Seed XOR intro and card stay where they are, right under the strip", () => {
  const preview = applyPreviewBlocks(shell, true);
  const strip = preview.indexOf('id="seedtools-tool-tabs"');
  const intro = preview.indexOf('id="seedxor-tool-intro"');
  assert.ok(strip > 0 && intro > strip, "the Seed XOR intro follows the Seed tools strip");
  assert.ok(preview.indexOf('id="seedxor-card"') > intro, "the Seed XOR card follows its intro");
});

test("hodlShowWorkspace conceals a revealed Seed XOR result when leaving Seed tools", () => {
  const show = extractFunction("hodlShowWorkspace");
  assert.match(show, /if \(hodlWorkspace === "bip85" && typeof hodlSeedXorConceal === "function"\) hodlSeedXorConceal\(\);/, "the conceal runs beside the BIP-47 one");
  assert.doesNotMatch(show, /\bhodlSeedTool\b/, "the slice harnesses run hodlShowWorkspace without the station state");
  assert.doesNotMatch(show, /seedxor-card|seedxor-tool-intro/, "the station sync owns the Seed XOR card and intro");
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
  for (const name of ["hodlSeedXorConceal", "hodlSyncSeedTool", "hodlShowSeedTool", "hodlInitSeedToolTabs"]) {
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
