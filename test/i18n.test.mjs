import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";
import { hodlLocaleCodes, hodlSelectableLocales, hodlNormalizeLocale, t, tHtml, hodlSetLocale, hodlGetLocale } from "../src/js/i18n.js";
import * as labelTables from "../src/js/i18n-labels.js";
import { collectSources } from "../scripts/i18n-sources.mjs";
import { MiniDocument, MiniNodeFilter } from "./mini-dom.mjs";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");

const readCatalog = (code) => JSON.parse(readFileSync(join(root, "src/locales", `${code}.json`), "utf8"));

test("the English source text is the key: no en.json catalog ships", () => {
  assert.deepEqual(
    readdirSync(join(root, "src/locales")).filter((name) => name === "en.json"),
    [],
    "src/locales/en.json must not exist — English lives at the call site",
  );
});

test("catalog content is valid and drift is report-only", () => {
  // Invalid catalog values and source markup outside the sanitizer table
  // fail CI. Missing and dead entries are reported but never fail: a feature
  // PR must be able to change English copy without touching every locale,
  // and the translation workflow fills and prunes afterwards.
  execFileSync(process.execPath, [join(root, "scripts/i18n-sync.mjs")], { stdio: "pipe" });
});

// The field helpers take the English label as their first argument and
// translate it inside, so a literal label at any of their call sites must be
// a translation source, or i18n:sync prunes its translations as dead.
test("labels passed to the field helpers are translation sources", async () => {
  const sources = await collectSources(root), known = new Set(sources instanceof Map ? sources.keys() : sources);
  const app = readFileSync(join(root, "src/js/app.js"), "utf8");
  const labels = [...app.matchAll(/\bhodl(?:Public|Private|PrivateKey)FieldHtml\("((?:[^"\\]|\\.)*)"/g)].map((match) => JSON.parse(`"${match[1]}"`));
  assert.ok(labels.length > 10, "fixture: the field helpers have literal labels");
  assert.deepEqual(labels.filter((label) => !known.has(label)), []);
});

test("module translator imports and aliases are translation sources", async (context) => {
  const fixture = mkdtempSync(join(tmpdir(), "entropylab-i18n-sources-"));
  context.after(() => rmSync(fixture, { recursive: true, force: true }));
  mkdirSync(join(fixture, "src/js"), { recursive: true });
  const files = {
    "package.json": '{"type":"module"}',
    "src/index.html": "",
    "src/shell.html": "",
    "src/js/i18n-labels.js": "export {};",
    "src/js/module.js": `
      import { t, tHtml, tAttr, hodlGetLocale } from "./i18n.js";
      t("Plain {n}", { n: "Not a source" });
      tHtml("<strong>Rich</strong>");
      tAttr("Attribute");
      hodlGetLocale("Not a translator");
      object.t("Not a direct call");
      not_t("Not a translator suffix");
    `,
    "src/js/aliases.js": `
      import {
        t as text, tHtml as html, tAttr as $attr,
      } from './i18n.js';
      text("Aliased text");
      html("Aliased HTML");
      $attr("Aliased attribute");
    `,
    "src/js/unrelated.js": `
      import { t, tHtml, tAttr } from "./other.js";
      t("Unrelated text");
      tHtml("Unrelated HTML");
      tAttr("Unrelated attribute");
    `,
    "src/js/local.js": 'const t = (value) => value; t("Local function");',
    "src/js/network-check.js": 't("Pre-boot network");',
    "src/js/wallet-export.js": 't("Pre-boot wallet");',
  };
  for (const [name, source] of Object.entries(files)) writeFileSync(join(fixture, name), source);
  assert.deepEqual([...await collectSources(fixture)].sort(), [
    "Plain {n}", "<strong>Rich</strong>", "Attribute",
    "Aliased text", "Aliased HTML", "Aliased attribute",
    "Pre-boot network", "Pre-boot wallet",
  ].sort());
});

test("warning and address QR translator literals are translation sources", async () => {
  const sources = await collectSources(root);
  for (const name of ["low-entropy-confirm.js", "fingerprint-collision-confirm.js", "address-qr.js"]) {
    const module = readFileSync(join(root, "src/js", name), "utf8");
    const labels = [...module.matchAll(/\bt(?:Html|Attr)?\("((?:[^"\\]|\\.)*)"/g)]
      .map((match) => JSON.parse(`"${match[1]}"`));
    assert.ok(labels.length > 0, `${name} must supply translator literals`);
    assert.deepEqual(labels.filter((label) => !sources.has(label)), [], `${name} has uncollected translation sources`);
  }
});

test("every locale stays selectable, translated or not", () => {
  assert.deepEqual(hodlSelectableLocales(), [...hodlLocaleCodes]);
});

test("t interpolates placeholders and falls back to the English source", () => {
  hodlSetLocale("en", false);
  assert.equal(t("{n} words", { n: 12 }), "12 words");
  assert.equal(t("This string was never catalogued"), "This string was never catalogued");
});

test("a partial locale falls back to English per missing string", () => {
  hodlSetLocale("es", false);
  assert.equal(t("This string was never catalogued"), "This string was never catalogued");
  assert.equal(t("{n} palabras", { n: 3 }), "3 palabras", "an uncatalogued source still interpolates");
  hodlSetLocale("en", false);
});

test("t drops markup (text view) while tHtml keeps the allowlisted form (HTML view)", () => {
  const key = Object.keys(readCatalog("es"))
    .find((source) => source.includes("<a ") && source.includes("<code>"));
  assert.ok(key, "fixture: a catalog key carrying an anchor and code");
  const linkText = /<a [^>]*>([^<]+)<\/a>/.exec(key)?.[1];
  const href = /<a href=\\?"([^"\\]+)/.exec(key)?.[1];
  assert.ok(linkText && href, "fixture: the key's anchor and target are readable");
  hodlSetLocale("es", false);
  const plain = t(key);
  assert.ok(!plain.includes("<"), "text view carries no markup into DOM text sinks");
  assert.ok(plain.includes(linkText), "text view keeps the link text");
  const rich = tHtml(key);
  assert.ok(rich.includes(`<a href=${href}`), "HTML view keeps the English source's pinned anchor target");
  assert.ok(rich.includes("<code>"), "HTML view keeps allowlisted formatting");
  hodlSetLocale("en", false);
});

test("t translates through the active locale catalog", () => {
  const es = readCatalog("es");
  const entry = Object.entries(es).find(([key, value]) => value && !key.includes("<") && !value.includes("<"));
  assert.ok(entry, "es catalog has no markup-free entry");
  hodlSetLocale("es", false);
  assert.equal(t(entry[0]), entry[1]);
  assert.equal(hodlGetLocale(), "es");
  hodlSetLocale("en", false);
  assert.equal(t(entry[0]), entry[0]);
});

test("locale allowlist rejects unknown codes", () => {
  assert.equal(hodlNormalizeLocale("pt-BR"), "en");
  assert.equal(hodlNormalizeLocale("pt"), "pt");
  assert.ok(hodlSelectableLocales().includes("en"));
});

test("the enum-family label tables are non-empty strings keyed by their enum values", () => {
  assert.equal(labelTables.hodlKeyModeLabels.dice, "Dice rolls");
  assert.equal(labelTables.hodlNetworkNames.regtest, "Regtest");
  assert.ok(Object.keys(labelTables.hodlHexFormatLabels).length >= 6);
  for (const table of Object.values(labelTables)) {
    const walk = (value) => {
      if (typeof value === "string") assert.ok(value.length > 0, "empty label");
      else if (Array.isArray(value)) value.forEach(walk);
      else if (value && typeof value === "object") Object.values(value).forEach(walk);
    };
    walk(table);
  }
});

// The content sweep (hodlApplyStaticI18n and its lookup helpers) is
// module-private, and i18n.js builds its sanitized catalogs from the
// committed JSON at import time, so the real module can never see a hostile
// value. To still run the app's own sweep against one, the test loads the
// sweep section of i18n.js verbatim — from the sweep comment block through
// hodlApplyStaticI18n — rebounding only the two catalog tables and the
// active locale (the same run-the-real-code approach as
// test/app-slice-harness.mjs; nothing is re-implemented).
async function loadSweep(catalogs) {
  const source = readFileSync(join(root, "src/js/i18n.js"), "utf8");
  const start = source.indexOf("// The content sweep translates the DOM in place");
  const end = source.indexOf("export function hodlReadStoredLocale");
  assert.ok(start >= 0 && end > start, "the i18n.js sweep section markers moved");
  const module = [
    'let hodlLocale = "zz";',
    `const hodlLocaleTextCatalogs = { zz: ${JSON.stringify(catalogs.text ?? {})} };`,
    `const hodlLocaleHtmlCatalogs = { zz: ${JSON.stringify(catalogs.html ?? {})} };`,
    source.slice(start, end),
  ].join("\n");
  const directory = mkdtempSync(join(tmpdir(), "entropylab-i18n-sweep-"));
  writeFileSync(join(directory, "sweep.mjs"), module);
  try {
    return await import(pathToFileURL(join(directory, "sweep.mjs")).href);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

// A page for the sweep: the mini-dom supplies the tree walk, get/setAttribute
// and innerHTML parsing the sweep drives.
function sweepPage(markup) {
  const document = new MiniDocument();
  globalThis.document = document;
  globalThis.NodeFilter = MiniNodeFilter;
  document.body.innerHTML = markup;
  return document;
}
function leavePage() {
  delete globalThis.document;
  delete globalThis.NodeFilter;
}

test("a non-string catalog value is not a translation: the sweep leaves the DOM untouched (audit B6)", async () => {
  const sweep = await loadSweep({
    text: {
      // The finding's payload shape: an array coerces to its markup at a sink.
      "Text key": ['<img src=x onerror="globalThis.__entropyLabPwned = true">'],
      "Attr key": { injected: "value" },
      // An empty string was never a translation: it falls back to the source.
      "Blank key": "",
      "Clean text": "Translated text",
      "Clean attr": "Translated attr",
    },
    html: {
      "Rich key": ['<img src=x onerror="globalThis.__entropyLabPwned = true">'],
      "<em>Clean rich</em>": "<strong>Translated rich</strong>",
    },
  });
  const document = sweepPage([
    "<p>Text key</p>",
    "<p>Blank key</p>",
    "<p>Clean text</p>",
    '<button aria-label="Attr key" title="Clean attr">Do</button>',
    "<div data-i18n-rich>Rich key</div>",
    "<div data-i18n-rich><em>Clean rich</em></div>",
  ].join(""));
  try {
    sweep.hodlApplyStaticI18n(document);
    const [textParagraph, blankParagraph, cleanParagraph] = document.querySelectorAll("p");
    const button = document.querySelector("button");
    const [rich, cleanRich] = document.querySelectorAll("[data-i18n-rich]");
    assert.equal(textParagraph.textContent, "Text key");
    assert.equal(blankParagraph.textContent, "Blank key");
    assert.equal(button.getAttribute("aria-label"), "Attr key");
    assert.equal(rich.innerHTML, "Rich key");
    assert.equal(document.querySelectorAll("img").length, 0, "no catalog markup reached the live DOM");
    // Clean string hits still translate, in place.
    assert.equal(cleanParagraph.textContent, "Translated text");
    assert.equal(button.getAttribute("title"), "Translated attr");
    assert.equal(cleanRich.innerHTML, "<strong>Translated rich</strong>");
  } finally {
    leavePage();
  }
});

test("the sweep never takes a translation from a catalog's prototype chain (audit B6)", async () => {
  const sweep = await loadSweep({ text: {}, html: {} });
  const document = sweepPage('<p title="Proto attr">Proto key</p>');
  Object.prototype["Proto key"] = "polluted text";
  Object.prototype["Proto attr"] = "polluted attr";
  try {
    sweep.hodlApplyStaticI18n(document);
    const paragraph = document.querySelector("p");
    assert.equal(paragraph.textContent, "Proto key");
    assert.equal(paragraph.getAttribute("title"), "Proto attr");
  } finally {
    leavePage();
    delete Object.prototype["Proto key"];
    delete Object.prototype["Proto attr"];
  }
});

test("t() and tHtml() never take a translation from a catalog's prototype chain (#867)", () => {
  // The page sweeps refuse inherited catalog hits (audit B6, above). The
  // lookups behind t() and tHtml() must refuse them too, or a polluted
  // Object.prototype supplies markup that tHtml() hands to an HTML sink.
  const source = "zz-source-not-in-any-catalog";
  const [ownSource, ownText] = Object.entries(readCatalog("de")).find(([key, value]) => typeof value === "string" && value && value !== key && !/[<>&{}]/.test(key + value));
  hodlSetLocale("de", false);
  Object.prototype[source] = "<img src=x onerror=alert(1)>polluted";
  try {
    assert.equal(t(source), source, "t() falls back to the English source");
    assert.equal(tHtml(source), source, "tHtml() falls back to the English source");
    assert.equal(t(ownSource), ownText, "an own catalog entry still translates in t()");
    assert.equal(tHtml(ownSource), ownText, "an own catalog entry still translates in tHtml()");
  } finally {
    delete Object.prototype[source];
    hodlSetLocale("en", false);
  }
});
