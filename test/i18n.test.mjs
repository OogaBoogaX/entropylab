import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import en from "../src/locales/en.json" with { type: "json" };
import { hodlApplyStaticI18n, hodlCompleteLocales, hodlGetLocale, hodlLocaleCodes, hodlLocaleIsComplete, hodlNormalizeLocale, t, hodlSetLocale } from "../src/js/i18n.js";

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

test("non-English catalogs contain only non-empty English keys", () => {
  for (const code of hodlLocaleCodes) {
    if (code === "en") continue;
    const catalog = readLocale(code);
    for (const key of Object.keys(catalog)) {
      assert.ok(Object.hasOwn(en, key), `${code} unknown key ${key}`);
      assert.equal(typeof catalog[key], "string", `${code} ${key}`);
      assert.ok(catalog[key].length > 0, `${code} ${key}`);
    }
  }
});

test("t interpolates placeholders and falls back to English", () => {
  hodlSetLocale("en", false);
  assert.equal(t("seedLength.words", { n: 12 }), "12 words");
  assert.equal(t("missing.key"), "missing.key");
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

test("a source hash marked stale makes the shipped catalog fall back to English", async () => {
  globalThis.__entropyLabStaleTranslations = { es: ["seedLength.words"] };
  try {
    const staleModule = await import(`../src/js/i18n.js?stale=${Date.now()}`);
    staleModule.hodlSetLocale("es", false);
    assert.equal(staleModule.t("seedLength.words", { n: 12 }), "12 words");
    assert.equal(staleModule.hodlLocaleIsComplete("es"), false);
  } finally {
    delete globalThis.__entropyLabStaleTranslations;
  }
});

test("static translations set title and alt through DOM attributes", () => {
  const values = new Map();
  const element = (keyAttribute, key) => ({
    getAttribute(name) { return name === keyAttribute ? key : null; },
    setAttribute(name, value) { values.set(name, value); },
  });
  const title = element("data-i18n-title", "header.downloadAria");
  const alt = element("data-i18n-alt", "locale.label");
  const root = { querySelectorAll(selector) {
    if (selector === "[data-i18n-title]") return [title];
    if (selector === "[data-i18n-alt]") return [alt];
    return [];
  } };
  hodlSetLocale("en", false);
  hodlApplyStaticI18n(root);
  assert.equal(values.get("title"), en["header.downloadAria"]);
  assert.equal(values.get("alt"), en["locale.label"]);
});
