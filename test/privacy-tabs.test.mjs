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
  const conceals = [];
  const source = [
    `var hodlPrivacyTool = "sp";`,
    `var hodlPrivacyTools = ${JSON.stringify(tools)};`,
    extractFunction("hodlSyncPrivacyTool"),
    extractFunction("hodlShowPrivacyTool"),
    extractFunction("hodlInitPrivacyToolTabs"),
    `return { hodlSyncPrivacyTool, hodlShowPrivacyTool, hodlInitPrivacyToolTabs, get tool() { return hodlPrivacyTool; } };`,
  ].join("\n");
  const factory = new Function("document", "hodlJournalLog", "hodlInitTabDrag", "hodlWorkspace", "hodlBip47Conceal", source);
  const api = factory(document, (...args) => journal.push(args), () => {}, workspace, () => conceals.push(true));
  return {
    init: api.hodlInitPrivacyToolTabs,
    show: api.hodlShowPrivacyTool,
    sync: api.hodlSyncPrivacyTool,
    get tool() { return api.tool; },
    journal,
    conceals,
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
  assert.equal(buttons.length, 2, "two stations ship in preview");
  assert.match(buttons[0], /data-privacy-tool="sp"/);
  assert.match(buttons[0], /aria-controls="sp-card"/);
  assert.match(buttons[0], /role="tab"/);
  assert.match(buttons[0], /aria-selected="true"/);
  assert.match(buttons[1], /data-privacy-tool="bip47"/);
  assert.match(buttons[1], /aria-controls="bip47-card"/);
  assert.match(buttons[1], /role="tab"/);
  assert.match(buttons[1], /aria-selected="false"/);
});

test("the BIP-47 card ships only in preview builds and holds its sections in order", () => {
  const release = applyPreviewBlocks(shell, false);
  assert.doesNotMatch(release, /id="bip47-card"|data-bip47-section/, "a release build must not carry the BIP-47 card");
  const preview = applyPreviewBlocks(shell, true);
  assert.match(preview, /<div\b[^>]*\bid="bip47-card"[^>]*\brole="tabpanel"[^>]*\bhidden>/, "the card starts hidden, like every other station card");
  const sections = [...preview.matchAll(/data-bip47-section="([^"]+)"/g)].map((match) => match[1]);
  assert.deepEqual(sections, ["intro", "source", "own", "counterparty", "pairs", "notify"], "the sections run intro → source → your code → counterparty → payment addresses → notification check");
  for (const id of ["bip47-session-keys", "bip47-session-keys-note", "bip47-key", "bip47-pass", "bip47-network", "bip47-path", "bip47-go", "bip47-error", "bip47-own", "bip47-contact", "bip47-decode", "bip47-contact-out"]) {
    assert.match(preview, new RegExp(`id="${id}"`), `#${id} is missing from the preview build`);
  }
  assert.match(preview, /id="bip47-contact-out" aria-live="polite"/);
});

test("the BIP-47 station joins the privacy tool list only behind the preview flag", () => {
  const declaration = /var hodlPrivacyTools = (\[[\s\S]*?\]);/.exec(appSource);
  assert.ok(declaration, "the privacy tool list is missing");
  assert.doesNotMatch(declaration[1], /bip47/, "the BIP-47 station must not ship in release builds");
  const pushes = appSource.split("\n").filter((line) => line.includes("hodlPrivacyTools.push"));
  assert.equal(pushes.length, 1, "the BIP-47 station is added exactly once");
  // It joins from the station's own init, which returns before this unless
  // the preview-only card markup exists.
  const initStart = appSource.indexOf("function hodlInitBip47() {");
  const init = appSource.slice(initStart, appSource.indexOf("\nfunction ", initStart + 1));
  assert.ok(init.includes(pushes[0].trim()), "the station row is added inside hodlInitBip47");
  assert.ok(init.indexOf('if (!document.getElementById("bip47-card")) return;') < init.indexOf("hodlPrivacyTools.push"), "only after the preview card is found");
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

test("switching away from the BIP-47 station conceals a revealed key; switching to it does not", () => {
  const document = fakeDocument(["sp", "bip47"]);
  const api = loadPrivacy(document, { tools: [["sp", "sp-card"], ["bip47", "bip47-card"]] });
  api.init();
  api.show("bip47");
  assert.equal(api.conceals.length, 0, "opening the BIP-47 station has nothing to conceal");
  api.show("sp");
  assert.equal(api.conceals.length, 1, "leaving the BIP-47 station conceals it");
  api.show("nonsense");
  assert.equal(api.conceals.length, 2, "a fallback to Silent Payments conceals too");
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

// Review on round 1 (GLM 5.3): clearing or deleting a Key Station key must
// wipe a BIP-47 session that uses it, as both handlers already do for SP.
test("both Key Station clear/delete handlers also wipe a BIP-47 session using that key", () => {
  const spSites = appSource.split("if (hodlSpSource === source) {").length - 1;
  assert.ok(spSites >= 2, "the SP per-key wipe sites exist");
  const pattern = /if \(typeof hodlBip47ReleaseSource === "function"\) hodlBip47ReleaseSource\(source\);\n\s*if \(hodlSpSource === source\) \{/g;
  assert.equal((appSource.match(pattern) || []).length, spSites, "every SP per-key wipe site has the BIP-47 wipe beside it");
  assert.match(fnSource("hodlBip47ReleaseSource"), /if \(\(hodlBip47Source && hodlBip47Source === source\) \|\| \(hodlBip47Origin && hodlBip47Origin === source\)\) hodlBip47WipeSource\(\);/, "the hook wipes only the session that used, or copied text from, the dropped key");
  const wipeSource = appSource.slice(appSource.indexOf("function hodlBip47WipeSource()"), appSource.indexOf("function hodlBip47ClearContact()"));
  for (const needle of ["hodlBip47Invalidate()", "\"bip47-key\"", "\"bip47-pass\"", "hodlClearStationPassphrase(\"bip47-pass\")"]) {
    assert.ok(wipeSource.includes(needle), `hodlBip47WipeSource clears ${needle}`);
  }
});

test("a network change clears every result and the decoded contact, but keeps the key and its Key Station link", () => {
  assert.match(appSource, /network\.addEventListener\("change", \(\) => \{ hodlBip47ClearResults\(\); hodlBip47ClearContact\(\); hodlSyncBip47Path\(\); \}\);/);
  // Wiping the root here would also drop hodlBip47Source, so a Key Station
  // key deleted afterwards would no longer clear the seed left in the field.
  assert.doesNotMatch(fnSource("hodlBip47ClearResults"), /hodlBip47WipeKeys|hodlBip47Source/);
  assert.match(fnSource("hodlBip47Invalidate"), /hodlBip47WipeKeys\(\);\s*hodlBip47ClearResults\(\);/);
});

test("an invalid start index is refused, never rewritten to a valid one", () => {
  // Codex review (10-28): rewriting -1 to 0 could show an already used
  // address; validation fails closed instead.
  const rows = fnSource("hodlBip47RunRows");
  assert.match(rows, /if \(!Number\.isInteger\(start\) \|\| start < 0 \|\| start > 2147483647\) \{\s*throw new Error\(/);
  assert.doesNotMatch(rows, /Math\.trunc\(start\)|field\.value = String\(start\)/);
});

test("editing key text copied from a Key Station key also drops that key's passphrase", () => {
  // Gemini red team (10-28): kept, the copied passphrase would outlive the
  // Key Station key's wipe and apply silently to a newly pasted seed.
  assert.match(fnSource("hodlInitBip47"), /if \(hodlBip47Origin\) hodlClearStationPassphrase\("bip47-pass"\);\s*hodlBip47Origin = "";/);
});

// Review on round 2 (GLM 5.3): a revealed spending key is hidden by every
// conceal trigger and every way of leaving the station, and End Session's
// reset of the direction also resets its control.
const fnSource = (name) => {
  const start = appSource.indexOf(`function ${name}(`);
  assert.ok(start >= 0, `${name} exists`);
  const next = appSource.indexOf("\nfunction ", start + 1);
  return appSource.slice(start, next < 0 ? undefined : next);
};

test("every conceal trigger and station or workspace exit hides a revealed BIP-47 key", () => {
  assert.match(fnSource("hodlConcealPrivateValues"), /hodlBip47Conceal\(\)/, "blur, tab hide, idle and print conceal it");
  assert.match(fnSource("hodlShowPrivacyTool"), /if \(next !== "bip47" && typeof hodlBip47Conceal === "function"\) hodlBip47Conceal\(\);/, "switching to another station conceals it");
  assert.match(fnSource("hodlShowWorkspace"), /if \(hodlWorkspace === "sp" && typeof hodlBip47Conceal === "function"\) hodlBip47Conceal\(\);/, "leaving the Privacy workspace conceals it");
});

test("End Session clears the revealed key and resets the direction together with its control", () => {
  const wipe = fnSource("hodlBip47WipeMem");
  assert.match(wipe, /hodlBip47Revealed = null;/);
  assert.match(wipe, /hodlBip47SetDirection\("send"\);/);
  assert.doesNotMatch(wipe, /hodlBip47Direction = /, "the direction never changes without its control");
  const setDirection = fnSource("hodlBip47SetDirection");
  assert.match(setDirection, /aria-pressed/);
});

// Round 3: the notification check is a closed disclosure after the pairs
// disclosure, inside the preview block. Elements are extracted by counting
// nested tags, so a nested id never truncates the block it sits in.
function detailsBlock(html, id) {
  const at = html.indexOf(`id="${id}"`);
  assert.ok(at >= 0, `#${id} is missing`);
  const open = html.lastIndexOf("<details", at);
  assert.ok(open >= 0, `#${id} is not a details element`);
  let depth = 0;
  const tag = /<details\b|<\/details>/g;
  tag.lastIndex = open;
  let match;
  while ((match = tag.exec(html))) {
    if (match[0] === "</details>") {
      depth--;
      if (depth === 0) return html.slice(open, match.index + match[0].length);
    } else depth++;
  }
  throw new Error(`unclosed details for #${id}`);
}

function divBlock(html, id) {
  const at = html.indexOf(`id="${id}"`);
  assert.ok(at >= 0, `#${id} is missing`);
  const open = html.lastIndexOf("<div", at);
  assert.ok(open >= 0, `#${id} is not a div element`);
  let depth = 0;
  const tag = /<div\b|<\/div>/g;
  tag.lastIndex = open;
  let match;
  while ((match = tag.exec(html))) {
    if (match[0] === "</div>") {
      depth--;
      if (depth === 0) return html.slice(open, match.index + match[0].length);
    } else depth++;
  }
  throw new Error(`unclosed div for #${id}`);
}

test("the notification check ships only in preview, after the pairs disclosure", () => {
  const release = applyPreviewBlocks(shell, false);
  assert.doesNotMatch(release, /id="bip47-notify"|data-bip47-section="notify"/, "a release build must not carry the notification check");
  const preview = applyPreviewBlocks(shell, true);
  const sections = [...preview.matchAll(/data-bip47-section="([^"]+)"/g)].map((match) => match[1]);
  assert.deepEqual(sections, ["intro", "source", "own", "counterparty", "pairs", "notify"], "the notification check follows the payment addresses");
  const card = divBlock(preview, "bip47-card");
  assert.ok(card.includes('id="bip47-notify"'), "the notification check sits inside the BIP-47 card");
  assert.ok(card.includes('id="bip47-notify-manual"'), "the manual override sits inside the BIP-47 card");
  assert.ok(card.indexOf('id="bip47-pairs"') < card.indexOf('id="bip47-notify"'), "the notification check follows the pairs disclosure");
});

test("the notification check holds its prerequisite, transaction, manual override, action and results in order", () => {
  const preview = applyPreviewBlocks(shell, true);
  const block = detailsBlock(preview, "bip47-notify");
  assert.match(block, /^<details\b(?![^>]*\bopen\b)[^>]*\bid="bip47-notify"[^>]*\bdata-bip47-section="notify"[^>]*>/, "the check is a closed disclosure at rest");
  for (const id of ["bip47-notify-needs", "bip47-notify-tx", "bip47-notify-manual", "bip47-notify-input", "bip47-notify-pub", "bip47-notify-go", "bip47-notify-out"]) {
    assert.ok(block.includes(`id="${id}"`), `#${id} sits inside the notification check`);
  }
  const order = ["bip47-notify-needs", "bip47-notify-tx", "bip47-notify-manual", "bip47-notify-go", "bip47-notify-out"].map((id) => block.indexOf(`id="${id}"`));
  assert.deepEqual(order, [...order].sort((a, b) => a - b), "the parts run prerequisite → transaction → manual override → action → results");
  const manual = detailsBlock(preview, "bip47-notify-manual");
  assert.match(manual, /^<details\b(?![^>]*\bopen\b)[^>]*\bid="bip47-notify-manual"[^>]*>/, "the manual override is closed at rest");
  assert.ok(manual.includes('id="bip47-notify-input"'));
  assert.ok(manual.includes('id="bip47-notify-pub"'));
  assert.ok(!manual.includes('id="bip47-notify-go"'), "the action sits outside the manual override");
  assert.match(block, /<textarea id="bip47-notify-tx" rows="4" spellcheck="false" autocomplete="off" autocapitalize="off">/);
  assert.match(block, /<input id="bip47-notify-pub" spellcheck="false" autocomplete="off" autocapitalize="off">/);
  assert.match(block, /<select id="bip47-notify-input"><option value="" disabled selected><\/option><\/select>/, "the picker starts with one disabled, selected, empty option");
  assert.match(block, /<div id="bip47-notify-out" aria-live="polite"><\/div>/);
});

test("End Session clears the notification check's public inputs and closes the manual override", () => {
  const wipe = fnSource("hodlBip47WipeMem");
  assert.match(wipe, /hodlBip47ClearNotify\(\)/, "the report is cleared");
  assert.match(wipe, /"bip47-notify-tx"/, "the pasted transaction is cleared");
  assert.match(wipe, /"bip47-notify-pub"/, "the manual public key is cleared");
  assert.match(wipe, /bip47-notify-input/, "the input picker is reset");
  assert.match(wipe, /bip47-notify-manual/, "the manual override is closed");
  assert.match(wipe, /\.open = false/);
});
