import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { hodlLocaleCodes, hodlSelectableLocales, hodlNormalizeLocale, t, tHtml, hodlSetLocale, hodlGetLocale } from "../src/js/i18n.js";
import * as labelTables from "../src/js/i18n-labels.js";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");

const readCatalog = (code) => JSON.parse(execFileSync("cat", [join(root, "src/locales", `${code}.json`)], { encoding: "utf8" }));

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
