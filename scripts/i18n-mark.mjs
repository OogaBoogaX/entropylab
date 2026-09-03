import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { i18nLocaleCodes, i18nLocaleStatus, i18nSourceHash } from "./i18n-common.mjs";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const readJson = (path) => JSON.parse(readFileSync(path, "utf8"));

export function markTranslationSources(english, catalog, sidecar, keys) {
  if (!Array.isArray(keys) || !keys.length) throw new Error("At least one --key is required.");
  const next = { ...sidecar };
  for (const key of keys) {
    if (!Object.hasOwn(english, key)) throw new Error(`Unknown English key: ${key}`);
    if (typeof catalog[key] !== "string" || !catalog[key]) throw new Error(`The translated catalog has no value for: ${key}`);
    next[key] = i18nSourceHash(english[key]);
  }
  const status = i18nLocaleStatus(english, catalog, next);
  if (status.problems.length) throw new Error(status.problems.join("\n"));
  return Object.fromEntries(Object.keys(catalog).map((key) => [key, next[key]]));
}

function optionValues(argv, option) {
  const values = [];
  for (let index = 0; index < argv.length; index += 1) {
    if (argv[index] === option) values.push(argv[index + 1]);
  }
  return values;
}

export function runI18nMark(argv = process.argv.slice(2)) {
  const locales = optionValues(argv, "--locale");
  const keys = optionValues(argv, "--key");
  if (locales.length !== 1 || !i18nLocaleCodes.includes(locales[0])) throw new Error("Use exactly one supported --locale (es, pt, fr, or de).");
  if (keys.some((key) => !key)) throw new Error("Every --key needs a value.");
  const code = locales[0];
  const english = readJson(join(root, "src/locales/en.json"));
  const catalog = readJson(join(root, `src/locales/${code}.json`));
  const path = join(root, `src/locales/.sources/${code}.json`);
  const sidecar = readJson(path);
  const next = markTranslationSources(english, catalog, sidecar, keys);
  writeFileSync(path, `${JSON.stringify(next, null, 2)}\n`);
  console.log(`Marked ${keys.length} ${code} translation source(s) current.`);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  try { runI18nMark(); }
  catch (error) { console.error(error.message); process.exitCode = 1; }
}
