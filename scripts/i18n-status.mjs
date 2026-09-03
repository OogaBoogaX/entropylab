import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { i18nLocaleCodes, i18nLocaleStatus } from "./i18n-common.mjs";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const readJson = (path) => JSON.parse(readFileSync(path, "utf8"));

export function readI18nStatus(code) {
  const english = readJson(join(root, "src/locales/en.json"));
  const catalog = readJson(join(root, `src/locales/${code}.json`));
  const sidecar = readJson(join(root, `src/locales/.sources/${code}.json`));
  return i18nLocaleStatus(english, catalog, sidecar);
}

function requestedLocales(argv) {
  const index = argv.indexOf("--locale");
  if (index === -1) return i18nLocaleCodes;
  const code = argv[index + 1];
  if (!i18nLocaleCodes.includes(code)) throw new Error(`Unknown locale: ${code ?? "(missing)"}`);
  return [code];
}

export function printI18nStatus(argv = process.argv.slice(2)) {
  let invalid = false;
  for (const code of requestedLocales(argv)) {
    const status = readI18nStatus(code);
    console.log(`${code}: ${status.missing.length} missing, ${status.stale.length} stale, ${status.obsolete.length} obsolete`);
    if (status.missing.length) console.log(`  missing: ${status.missing.join(", ")}`);
    if (status.stale.length) console.log(`  stale: ${status.stale.join(", ")}`);
    if (status.obsolete.length) console.log(`  obsolete: ${status.obsolete.join(", ")}`);
    for (const problem of status.problems) console.error(`  invalid: ${problem}`);
    invalid ||= status.problems.length > 0;
  }
  if (invalid) process.exitCode = 1;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) printI18nStatus();
