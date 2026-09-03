// Catalog validation: a lint over every translated value, whoever wrote it.
// The sanitizer (i18n-sanitize.js) is what keeps the app safe; this test keeps
// mistakes from reaching review in the first place. Non-English catalogs may
// omit English keys — missing and stale keys fall back to English at runtime
// and are reported here, not failed.
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { hodlCatalogAllowedTags, hodlCatalogTagAllowed, hodlCatalogTokens } from "../src/js/i18n-sanitize.js";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const locales = ["es", "pt", "fr", "de"];
const readJson = (path) => JSON.parse(readFileSync(path, "utf8"));
const en = readJson(join(root, "src/locales/en.json"));

const tagsOf = (value) => hodlCatalogTokens(value).filter((token) => token.text === undefined).map((token) => `${token.closing ? "/" : ""}${token.name}${Object.entries(token.attrs ?? {}).map(([name, attr]) => ` ${name}="${attr}"`).join("")}`).sort();
const placeholdersOf = (value) => [...value.matchAll(/\{(\w+)\}/g)].map((match) => match[1]).sort();
// Bidirectional overrides, zero-width characters and other controls pass a tag
// check but can make a string render differently from how it reads in review.
// C0 controls except tab/newline, DEL, zero-width and directional formatting
// characters, the invisible operators, the isolates, and the byte order mark.
const controlCharacters = new RegExp("[" + [[0, 8], [11, 12], [14, 31], [127, 127], [0x200b, 0x200f], [0x202a, 0x202e], [0x2060, 0x2064], [0x2066, 0x2069], [0xfeff, 0xfeff]].map(([from, to]) => String.fromCodePoint(from) + "-" + String.fromCodePoint(to)).join("") + "]");
const forbidden = [/<script/i, /\bon[a-z]+\s*=/i, /javascript:/i, /\bdata:/i];

function problemsWith(code, key, value, source) {
  const problems = [];
  if (typeof value !== "string" || !value.length) return [`${code} ${key}: empty`];
  if (controlCharacters.test(value)) problems.push(`${code} ${key}: control or bidirectional character`);
  for (const pattern of forbidden) if (pattern.test(value)) problems.push(`${code} ${key}: matches ${pattern}`);
  for (const token of hodlCatalogTokens(value)) {
    if (token.text !== undefined) continue;
    if (!hodlCatalogTagAllowed(token)) problems.push(`${code} ${key}: tag not allowed: ${token.raw}`);
  }
  if (source !== undefined) {
    assert.ok(typeof source === "string");
    if (tagsOf(value).join("|") !== tagsOf(source).join("|")) problems.push(`${code} ${key}: tags differ from English (${tagsOf(source).join(" ") || "none"})`);
    if (placeholdersOf(value).join("|") !== placeholdersOf(source).join("|")) problems.push(`${code} ${key}: placeholders differ from English (${placeholdersOf(source).join(" ") || "none"})`);
  }
  return problems;
}

test("the English catalog uses only allowlisted markup and no control characters", () => {
  const problems = [];
  for (const [key, value] of Object.entries(en)) problems.push(...problemsWith("en", key, value));
  assert.deepEqual(problems, []);
  assert.ok(Object.keys(hodlCatalogAllowedTags).length >= 4);
});

for (const code of locales) {
  test(`${code}: every translated value is a valid rendering of its English source`, () => {
    const catalog = readJson(join(root, "src/locales", `${code}.json`));
    const problems = [];
    const missing = [];
    for (const key of Object.keys(catalog)) {
      if (!(key in en)) { problems.push(`${code} ${key}: not an English key`); continue; }
      problems.push(...problemsWith(code, key, catalog[key], en[key]));
      const ratio = catalog[key].length / Math.max(en[key].length, 1);
      if (en[key].length >= 20 && (ratio < 0.3 || ratio > 3)) console.warn(`i18n length warning: ${code} ${key} is ${ratio.toFixed(1)}x the English`);
    }
    for (const key of Object.keys(en)) if (!(key in catalog)) missing.push(key);
    if (missing.length) console.warn(`i18n: ${code} is missing ${missing.length} key(s); they fall back to English`);
    assert.deepEqual(problems, []);
  });

  test(`${code}: the source-hash sidecar, when present, matches the catalog`, () => {
    const path = join(root, "src/locales/.sources", `${code}.json`);
    if (!existsSync(path)) return;
    const sidecar = readJson(path);
    const catalog = readJson(join(root, "src/locales", `${code}.json`));
    const problems = [];
    for (const [key, hash] of Object.entries(sidecar)) {
      if (!(key in en)) problems.push(`${code} sidecar ${key}: not an English key`);
      if (!/^[0-9a-f]{64}$/.test(String(hash))) problems.push(`${code} sidecar ${key}: malformed hash`);
    }
    for (const key of Object.keys(catalog)) if (!(key in sidecar)) problems.push(`${code} sidecar: no hash for translated key ${key}`);
    assert.deepEqual(problems, []);
  });
}
