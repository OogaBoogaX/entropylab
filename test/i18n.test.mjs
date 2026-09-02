import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import en from "../src/locales/en.json" with { type: "json" };
import { hodlLocaleCodes, hodlLocaleIsComplete, hodlNormalizeLocale, t, hodlSetLocale } from "../src/js/i18n.js";

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

test("complete locales match English keys exactly", () => {
  for (const code of hodlLocaleCodes) {
    if (code === "en") continue;
    const catalog = readLocale(code);
    if (!Object.keys(catalog).length) continue;
    assert.deepEqual(Object.keys(catalog).sort(), Object.keys(en).sort(), code);
    for (const key of Object.keys(en)) {
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
