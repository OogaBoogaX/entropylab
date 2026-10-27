import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { applyPreviewBlocks } from "../scripts/preview-blocks.mjs";

const appSource = readFileSync(new URL("../src/js/app.js", import.meta.url), "utf8");
const shell = readFileSync(new URL("../src/shell.html", import.meta.url), "utf8");

// Pull one function out of app.js by name. Braces inside the body balance
// (template literals included), so counting them finds the closing brace.
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
    dataset: { privacyTool: tool },
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
  const strip = { querySelectorAll: (selector) => (selector === "[data-privacy-tool]" ? buttons : []) };
  const manager = { hidden: true };
  return {
    buttons,
    cards,
    getElementById(id) {
      if (id === "privacy-tool-tabs") return strip;
      if (id === "privacy-manager") return manager;
      return cards[id] ?? null;
    },
    querySelector(selector) {
      const match = /^#privacy-tool-tabs \[data-privacy-tool="([^"]+)"\]$/.exec(selector);
      return match ? buttons.find((button) => button.dataset.privacyTool === match[1]) ?? null : null;
    },
  };
}

// Run the real station functions against a fake DOM. The station table is
// passed in so the keyboard test can stand in for the rows later PRs add.
function loadPrivacy(document, { tools = [["sp", "sp-card"]], workspace = "sp" } = {}) {
  const journal = [];
  const source = [
    `var hodlPrivacyTool = "sp";`,
    `var hodlPrivacyTools = ${JSON.stringify(tools)};`,
    extractFunction("hodlSyncPrivacyTool"),
    extractFunction("hodlShowPrivacyTool"),
    extractFunction("hodlInitPrivacyToolTabs"),
    `return { hodlSyncPrivacyTool, hodlShowPrivacyTool, hodlInitPrivacyToolTabs, get tool() { return hodlPrivacyTool; } };`,
  ].join("\n");
  const factory = new Function("document", "hodlJournalLog", "hodlInitTabDrag", "hodlWorkspace", source);
  const api = factory(document, (...args) => journal.push(args), () => {}, workspace);
  return {
    init: api.hodlInitPrivacyToolTabs,
    show: api.hodlShowPrivacyTool,
    sync: api.hodlSyncPrivacyTool,
    get tool() { return api.tool; },
    journal,
  };
}

test("the privacy station switcher ships only in preview builds", () => {
  const release = applyPreviewBlocks(shell, false);
  assert.doesNotMatch(release, /privacy-tool-tabs|data-privacy-tool/, "a release build must not carry the station switcher");
  const preview = applyPreviewBlocks(shell, true);
  assert.match(preview, /id="privacy-tool-tabs"/);
  assert.ok(preview.indexOf('id="privacy-tool-tabs"') < preview.indexOf('id="sp-tool-intro"'), "the station tabs sit above the Silent Payments intro");
  const strip = /<div class="key-tabs" id="privacy-tool-tabs"[\s\S]*?<\/div>/.exec(preview);
  assert.ok(strip, "the preview build is missing the privacy station tab list");
  const buttons = [...strip[0].matchAll(/<button\b[^>]*>/g)].map((match) => match[0]);
  assert.equal(buttons.length, 1, "one station ships today");
  assert.match(buttons[0], /data-privacy-tool="sp"/);
  assert.match(buttons[0], /aria-controls="sp-card"/);
  assert.match(buttons[0], /role="tab"/);
  assert.match(buttons[0], /aria-selected="true"/);
});

test("the station tabs are wired only behind the preview flag", () => {
  const callSites = appSource.split("\n").filter((line) => line.includes("hodlInitPrivacyToolTabs()") && !line.trimStart().startsWith("function "));
  assert.equal(callSites.length, 1, "hodlInitPrivacyToolTabs is called exactly once");
  assert.match(callSites[0], /^\s*if \(PREVIEW\) hodlInitPrivacyToolTabs\(\);\s*$/);
});

test("an unknown station id falls back to Silent Payments", () => {
  const document = fakeDocument(["sp"]);
  const api = loadPrivacy(document);
  api.init();
  api.show("nonsense");
  assert.equal(api.tool, "sp");
  assert.equal(document.buttons[0].getAttribute("aria-selected"), "true");
  assert.equal(document.buttons[0].tabIndex, 0);
  assert.equal(document.cards["sp-card"].hidden, false);
  assert.deepEqual(api.journal, [], "no station change is logged when the id falls back to the current one");
});

test("the station tabs answer the arrow, Home and End keys", () => {
  const document = fakeDocument(["sp", "bip47"]);
  const api = loadPrivacy(document, { tools: [["sp", "sp-card"], ["bip47", "bip47-card"]] });
  api.init();
  const [sp, bip47] = document.buttons;
  const press = (button, key) => {
    let prevented = false;
    button.onkeydown({ key, preventDefault() { prevented = true; } });
    return prevented;
  };
  assert.equal(press(sp, "ArrowRight"), true);
  assert.equal(api.tool, "bip47");
  assert.equal(bip47.getAttribute("aria-selected"), "true");
  assert.equal(sp.getAttribute("aria-selected"), "false");
  assert.equal(bip47.focused, true);
  assert.equal(document.cards["bip47-card"].hidden, false);
  assert.equal(document.cards["sp-card"].hidden, true);
  assert.deepEqual(api.journal, [["tool-tab", "bip47", "sp"]]);
  press(bip47, "ArrowLeft");
  assert.equal(api.tool, "sp");
  press(sp, "End");
  assert.equal(api.tool, "bip47");
  press(bip47, "Home");
  assert.equal(api.tool, "sp");
  assert.equal(press(sp, "Tab"), false, "other keys are left alone");
});

test("the station strip shows only on the Privacy workspace and follows workspace switches", () => {
  const onPrivacy = fakeDocument(["sp"]);
  loadPrivacy(onPrivacy).init();
  assert.equal(onPrivacy.getElementById("privacy-manager").hidden, false);
  const elsewhere = fakeDocument(["sp"]);
  loadPrivacy(elsewhere, { workspace: "calc" }).init();
  assert.equal(elsewhere.getElementById("privacy-manager").hidden, true, "the strip sits outside the cards, so its wrapper must hide on other workspaces");
  const preview = applyPreviewBlocks(shell, true);
  assert.match(preview, /<div class="key-manager no-print" id="privacy-manager" hidden>\s*<div class="key-tab-strip">\s*<div class="key-tabs" id="privacy-tool-tabs"/, "the strip sits in a wrapper that starts hidden, like #psbt-manager");
  assert.equal(elsewhere.cards["sp-card"].hidden, true);
  const switcher = extractFunction("hodlShowWorkspace");
  assert.match(switcher, /hodlSyncPsbtTool\(\);\s*hodlSyncJournalTool\(\);\s*hodlSyncPrivacyTool\(\);/, "a workspace switch re-syncs the strip");
});

test("the Silent Payments workspace tab is named Privacy", () => {
  const declaration = /var hodlWorkspaceTabs = (\[[\s\S]*?\]);/.exec(appSource);
  assert.ok(declaration, "the workspace tab list is missing");
  const entry = /\["sp", "([^"]*)", "([^"]*)"(?:, "([^"]*)")?\]/.exec(declaration[1]);
  assert.ok(entry, "the sp workspace tab entry is missing");
  assert.equal(entry[1], "Privacy");
  assert.equal(entry[2], "Privacy");
  const tab = /<button[^>]*class="workspace-tab"[^>]*aria-controls="sp-card"[^>]*>([\s\S]*?)<\/button>/.exec(shell);
  assert.ok(tab, "the sp workspace tab button is missing");
  assert.match(tab[0], /aria-label="Privacy"/);
  assert.match(tab[1], /<span class="workspace-tab-full">Privacy<\/span>/);
  assert.match(tab[1], /<span class="workspace-tab-short">Privacy<\/span>/);
});
