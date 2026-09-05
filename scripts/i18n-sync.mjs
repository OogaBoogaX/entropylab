// EntropyLab i18n sync: checks the locale catalogs (and their translation-
// provenance sidecars) against every user-facing English source string.
//
//   node scripts/i18n-sync.mjs           check (CI): invalid catalog content
//                                        (see scripts/i18n-validate.mjs),
//                                        sidecar source-hash corruption, or
//                                        source markup outside the sanitizer
//                                        table fails the build; missing
//                                        translations, dead entries, and
//                                        sidecar drift are reported, never
//                                        failed — they are normal between a
//                                        UI change and the next automated
//                                        translation run
//   node scripts/i18n-sync.mjs --write   prune dead entries from catalogs and
//                                        sidecars (new sources are left
//                                        missing on purpose: the translation
//                                        workflow fills them)
//
// Source extraction lives in scripts/i18n-sources.mjs and is shared with the
// translation workflow, so the drift reported here is exactly the workload
// the workflow picks up.
import { existsSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { collectSources } from "./i18n-sources.mjs";
import { catalogProblems, sidecarProblems, sourceMarkupProblems } from "./i18n-validate.mjs";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const write = process.argv.includes("--write");

const sources = await collectSources(root);

const locales = {};
for (const name of readdirSync(join(root, "src/locales"))) {
  if (name === "en.json") continue; // retired: the source text is the key
  if (name.endsWith(".json")) locales[name] = JSON.parse(readFileSync(join(root, "src/locales", name), "utf8"));
}
const sidecars = {};
const sidecarDir = join(root, "src/locales/.sources");
if (existsSync(sidecarDir)) {
  for (const name of readdirSync(sidecarDir)) {
    if (name.endsWith(".json")) sidecars[name] = JSON.parse(readFileSync(join(sidecarDir, name), "utf8"));
  }
}

// The markup tripwire: extracted sources are trusted code, but every markup
// form they carry must exist in the sanitizer table, or translations of the
// string would render as escaped text. A feature PR that adds a link or a new
// formatting form fails here until hodlCatalogAllowedTags grows.
const sourceProblems = [...sources].flatMap((source) => sourceMarkupProblems(source));
for (const problem of sourceProblems.slice(0, 20)) console.log(`INVALID source: ${problem}`);
if (sourceProblems.length > 20) console.log(`…and ${sourceProblems.length - 20} more invalid sources`);

let invalid = 0;
for (const [name, catalog] of Object.entries(locales)) {
  const problems = catalogProblems(catalog);
  invalid += problems.length;
  for (const problem of problems.slice(0, 20)) console.log(`${name}: INVALID ${problem}`);
  if (problems.length > 20) console.log(`${name}: …and ${problems.length - 20} more invalid entries`);

  // The sidecar records sha256(English source) for every translated key. A
  // mismatched or malformed hash is corruption — the hash is deterministic —
  // so it fails the build like invalid catalog content. Missing/extra hashes
  // are drift: the translation workflow (or --write) repairs them.
  const sidecar = sidecars[name] ?? {};
  const side = sidecarProblems(catalog, sidecar);
  invalid += side.invalid.length;
  for (const problem of side.invalid.slice(0, 20)) console.log(`${name}: INVALID sidecar ${problem}`);
  if (side.invalid.length > 20) console.log(`${name}: …and ${side.invalid.length - 20} more invalid sidecar entries`);
  if (side.drift.length) console.log(`${name}: sidecar drift: ${side.drift.length} entries (report only — the translation workflow repairs)`);

  const missing = [...sources].filter((source) => typeof catalog[source] !== "string" || !catalog[source]);
  const dead = Object.keys(catalog).filter((key) => !sources.has(key));
  if (missing.length || dead.length) {
    console.log(`${name}: ${missing.length} missing, ${dead.length} dead (report only — English fallback until the translation workflow runs)`);
    for (const source of missing.slice(0, 20)) console.log(`  missing: ${JSON.stringify(source.slice(0, 90))}`);
    for (const key of dead.slice(0, 20)) console.log(`  dead:    ${JSON.stringify(key.slice(0, 90))}`);
    if (missing.length > 20 || dead.length > 20) console.log("  …");
  } else {
    console.log(`${name}: in sync (${sources.size} sources)`);
  }
  if (write) {
    const next = {};
    for (const [key, value] of Object.entries(catalog)) if (sources.has(key)) next[key] = value;
    writeFileSync(join(root, "src/locales", name), JSON.stringify(next, null, 2) + "\n");
    if (name in sidecars) {
      // Prune sidecar hashes alongside their dead catalog entries. Missing
      // hashes are NOT written here: recording provenance is the translation
      // workflow's job (it knows the translation was actually made from the
      // current English text).
      const nextSidecar = {};
      for (const [key, hash] of Object.entries(sidecar)) if (key in next) nextSidecar[key] = hash;
      writeFileSync(join(sidecarDir, name), JSON.stringify(nextSidecar, null, 2) + "\n");
    }
  }
}
console.log(`extracted ${sources.size} source strings`);
if (write) console.log("catalogs rewritten: dead entries pruned");
process.exit(invalid + sourceProblems.length ? 1 : 0);

