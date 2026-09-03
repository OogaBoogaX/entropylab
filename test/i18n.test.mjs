import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import en from "../src/locales/en.json" with { type: "json" };
import es from "../src/locales/es.json" with { type: "json" };
import { hodlApplyStaticI18n, hodlCompleteLocales, hodlGetLocale, hodlLocaleCodes, hodlLocaleIsComplete, hodlNormalizeLocale, t, tHtml, hodlSetLocale } from "../src/js/i18n.js";
import { hodlSanitizeCatalogHtml } from "../src/js/i18n-sanitize.js";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const readLocale = (code) => JSON.parse(readFileSync(join(root, "src/locales", `${code}.json`), "utf8"));

test("English catalog is the source of truth and has no empty strings", () => {
  const keys = Object.keys(en);
  assert.ok(keys.length > 40);
  for (const key of keys) {
    assert.equal(typeof en[key], "string");
    assert.ok(en[key].length > 0, key);
  }
});

test("non-English catalogs contain only non-empty strings", () => {
  for (const code of hodlLocaleCodes) {
    if (code === "en") continue;
    const catalog = readLocale(code);
    for (const key of Object.keys(catalog)) {
      assert.equal(typeof catalog[key], "string", `${code} ${key}`);
      assert.ok(catalog[key].length > 0, `${code} ${key}`);
    }
  }
});

test("t interpolates placeholders and falls back to English", () => {
  hodlSetLocale("en", false);
  assert.equal(t("seedLength.words", { n: 12 }), "12 words");
  assert.equal(tHtml("error.origin.multipathLast"), hodlSanitizeCatalogHtml(en["error.origin.multipathLast"]));
  const warnings = [];
  const originalWarn = console.warn;
  console.warn = (message) => warnings.push(message);
  try {
    assert.equal(t("missing.key"), "missing.key");
    assert.equal(tHtml("missing.key"), "missing.key");
  } finally {
    console.warn = originalWarn;
  }
  assert.deepEqual(warnings, ["Missing English translation key: missing.key"]);
});

test("locale allowlist rejects unknown codes", () => {
  assert.equal(hodlNormalizeLocale("pt-BR"), "en");
  assert.equal(hodlNormalizeLocale("pt"), "pt");
  assert.equal(hodlLocaleIsComplete("en"), true);
});

test("every known locale stays selectable while individual keys fall back", () => {
  assert.deepEqual(hodlCompleteLocales(), hodlLocaleCodes);
  hodlSetLocale("es", false);
  assert.equal(hodlGetLocale(), "es");
  hodlSetLocale("en", false);
});

test("a missing translation falls back through both sanitized catalog views", async () => {
  const key = "error.origin.multipathLast";
  const saved = es[key];
  delete es[key];
  try {
    const missingModule = await import(`../src/js/i18n.js?missing=${Date.now()}`);
    missingModule.hodlSetLocale("es", false);
    assert.equal(missingModule.t(key), en[key]);
    assert.equal(missingModule.tHtml(key), hodlSanitizeCatalogHtml(en[key]));
    assert.equal(missingModule.hodlLocaleIsComplete("es"), false);
  } finally {
    es[key] = saved;
  }
});

test("a source hash marked stale makes both catalog views fall back to English", async () => {
  globalThis.__entropyLabStaleTranslations = { es: ["seedLength.words", "error.origin.multipathLast"] };
  try {
    const staleModule = await import(`../src/js/i18n.js?stale=${Date.now()}`);
    staleModule.hodlSetLocale("es", false);
    assert.equal(staleModule.t("seedLength.words", { n: 12 }), "12 words");
    assert.equal(staleModule.tHtml("error.origin.multipathLast"), hodlSanitizeCatalogHtml(en["error.origin.multipathLast"]));
    assert.equal(staleModule.hodlLocaleIsComplete("es"), false);
  } finally {
    delete globalThis.__entropyLabStaleTranslations;
  }
});

test("the browser pseudo locale is not disabled by a real locale's stale keys", async () => {
  const key = "action.derive";
  globalThis.__ENTROPYLAB_TEST_HOOKS__ = true;
  globalThis.__entropyLabTest = { pseudoCatalog: { ...en, [key]: "⟦I18N⟧derive⟦/I18N⟧" } };
  globalThis.__entropyLabStaleTranslations = { de: [key] };
  try {
    const pseudoModule = await import(`../src/js/i18n.js?pseudo-stale=${Date.now()}`);
    pseudoModule.hodlSetLocale("de", false);
    assert.equal(pseudoModule.t(key), "⟦I18N⟧derive⟦/I18N⟧");
  } finally {
    delete globalThis.__ENTROPYLAB_TEST_HOOKS__;
    delete globalThis.__entropyLabTest;
    delete globalThis.__entropyLabStaleTranslations;
  }
});

test("the production document path cannot activate the browser pseudo catalog", async () => {
  const key = "action.derive";
  const savedDocument = globalThis.document;
  const savedLocation = globalThis.location;
  globalThis.__ENTROPYLAB_TEST_HOOKS__ = true;
  globalThis.__entropyLabTest = { pseudoCatalog: { ...en, [key]: "pseudo-production-bypass" } };
  globalThis.document = {
    documentElement: {},
    getElementById() { return null; },
    querySelectorAll() { return []; },
  };
  globalThis.location = { pathname: "/entropylab.html" };
  try {
    const productionModule = await import(`../src/js/i18n.js?production-hook=${Date.now()}`);
    productionModule.hodlSetLocale("de", false);
    assert.notEqual(productionModule.t(key), "pseudo-production-bypass");
  } finally {
    if (savedDocument === undefined) delete globalThis.document;
    else globalThis.document = savedDocument;
    if (savedLocation === undefined) delete globalThis.location;
    else globalThis.location = savedLocation;
    delete globalThis.__ENTROPYLAB_TEST_HOOKS__;
    delete globalThis.__entropyLabTest;
  }
});

test("a removed English key cannot reactivate an obsolete locale value", async () => {
  const key = "seedLength.words";
  const saved = en[key];
  const warnings = [];
  const originalWarn = console.warn;
  delete en[key];
  globalThis.__entropyLabStaleTranslations = { es: [key] };
  console.warn = (message) => warnings.push(message);
  try {
    const obsoleteModule = await import(`../src/js/i18n.js?obsolete=${Date.now()}`);
    obsoleteModule.hodlSetLocale("es", false);
    assert.equal(obsoleteModule.t(key, { n: 12 }), key);
    assert.equal(obsoleteModule.tHtml(key, { n: 12 }), key);
    assert.deepEqual(warnings, [`Missing English translation key: ${key}`]);
  } finally {
    console.warn = originalWarn;
    delete globalThis.__entropyLabStaleTranslations;
    en[key] = saved;
  }
});

test("static translations set accessibility and behavior labels through DOM attributes", () => {
  const values = new Map();
  const element = (keyAttribute, key) => ({
    getAttribute(name) { return name === keyAttribute ? key : null; },
    setAttribute(name, value) { values.set(name, value); },
  });
  const title = element("data-i18n-title", "header.downloadAria");
  const alt = element("data-i18n-alt", "locale.label");
  const ariaPlaceholder = element("data-i18n-aria-placeholder", "journal.notes.prompt");
  const copyLabel = element("data-i18n-copy-label", "journal.notes.copy");
  const copiedLabel = element("data-i18n-copied-label", "journal.notes.copied");
  const root = { querySelectorAll(selector) {
    if (selector === "[data-i18n-title]") return [title];
    if (selector === "[data-i18n-alt]") return [alt];
    if (selector === "[data-i18n-aria-placeholder]") return [ariaPlaceholder];
    if (selector === "[data-i18n-copy-label]") return [copyLabel];
    if (selector === "[data-i18n-copied-label]") return [copiedLabel];
    return [];
  } };
  hodlSetLocale("en", false);
  hodlApplyStaticI18n(root);
  assert.equal(values.get("title"), en["header.downloadAria"]);
  assert.equal(values.get("alt"), en["locale.label"]);
  assert.equal(values.get("aria-placeholder"), en["journal.notes.prompt"]);
  assert.equal(values.get("data-copy-label"), en["journal.notes.copy"]);
  assert.equal(values.get("data-copied-label"), en["journal.notes.copied"]);
});

test("static translations preserve build values passed through data variables", () => {
  const elements = [
    {
      textContent: "",
      getAttribute(name) {
        if (name === "data-i18n") return "shell.footerVersionCommit";
        if (name === "data-i18n-vars") return '{"version":"0.1.3"}';
        return null;
      },
    },
    {
      textContent: "",
      getAttribute(name) {
        if (name === "data-i18n") return "literal.footerCommitShort";
        if (name === "data-i18n-vars") return '{"commit":"0123abc"}';
        return null;
      },
    },
  ];
  const root = { querySelectorAll(selector) { return selector === "[data-i18n]" ? elements : []; } };
  hodlSetLocale("en", false);
  hodlApplyStaticI18n(root);
  assert.equal(elements[0].textContent, "v0.1.3 · commit");
  assert.equal(elements[1].textContent, "0123abc");
});

test("the static locale sweep cannot overwrite a runtime-owned subtree", () => {
  const runtime = {
    innerHTML: "<code>live-wallet-result</code>",
    getAttribute(name) { return name === "data-i18n-html" ? "msig.intro" : null; },
    closest(selector) { return selector === "[data-runtime-owned]" ? this : null; },
  };
  const runtimeAttribute = {
    getAttribute(name) { return name === "data-i18n-title" ? "header.downloadAria" : null; },
    closest(selector) { return selector === "[data-runtime-owned]" ? runtime : null; },
    setAttribute() { throw new Error("runtime-owned attribute was overwritten"); },
  };
  const root = { querySelectorAll(selector) {
    if (selector === "[data-i18n-html]") return [runtime];
    if (selector === "[data-i18n-title]") return [runtimeAttribute];
    return [];
  } };
  hodlSetLocale("es", false);
  hodlApplyStaticI18n(root);
  assert.equal(runtime.innerHTML, "<code>live-wallet-result</code>");
});
