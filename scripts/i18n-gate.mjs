// Translation-only PR gate (issue #286): locale files may only change through
// the post-merge translation automation. Any pull request whose diff touches
// src/locales/ must prove all of:
//   - the author is the configured GitHub App's bot identity;
//   - the base is rock and the head branch is in the automation namespace
//     (i18n/translate-<lang>);
//   - exactly one locale catalog and its matching provenance sidecar changed
//     — no JavaScript, HTML, workflow, dependency, build, or config file;
//   - the changed catalog and sidecar pass validation (content + source
//     hashes, exactly consistent with each other).
// The label is never trusted by itself. Auto-merge's expected-head-SHA check
// (set by the publish job) completes the binding: the merged commit is the
// exact commit this gate validated.
//
//   node scripts/i18n-gate.mjs --author <login> --app-slug <slug> \
//     --base rock --head i18n/translate-es --files <changed file> [...]
//
// Exit 0 when the PR touches no locale files (nothing to gate) or every check
// passes; exit 1 with all reasons otherwise.
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { catalogProblems, sidecarProblems } from "./i18n-validate.mjs";
import { BRANCH_PATTERN } from "./i18n-publish.mjs";

const root = dirname(dirname(fileURLToPath(import.meta.url)));

// Pure scope check, exported for tests. Returns every violation; an empty
// array means the PR is outside the gate's scope (no locale files changed).
// Until TRANSLATION_APP_SLUG is configured the gate is inert on purpose:
// there is no bot identity to check against, so locale PRs are ordinary
// human-reviewed PRs exactly as they were before the gate existed. Failing
// closed would block every human locale fix — including the very PR that
// bootstraps the sidecars — while guarding nothing. Once the slug is set the
// gate fails closed as designed: only the App's bot may touch locale files.
export function gateProblems({ author, appSlug, baseRef, headRef, changedFiles }) {
  if (!changedFiles.some((file) => file.startsWith("src/locales/"))) return [];
  if (!appSlug) return [];
  const problems = [];
  if (author !== `${appSlug}[bot]`) {
    problems.push(`locale files changed but the PR author is "${author}" — locale files may only change via the translation automation (${appSlug}[bot])`);
  }
  if (baseRef !== "rock") problems.push(`translation PRs must target rock, not "${baseRef}"`);
  const branchMatch = BRANCH_PATTERN.exec(headRef ?? "");
  if (!branchMatch) {
    problems.push(`head branch "${headRef}" is outside the automation namespace i18n/translate-<lang>`);
    return problems; // without a language the file scope cannot be checked
  }
  const lang = branchMatch[1];
  const allowed = new Set([`src/locales/${lang}.json`, `src/locales/.sources/${lang}.json`]);
  for (const file of changedFiles) {
    if (!allowed.has(file)) problems.push(`file outside the translation-only scope: ${file} (a translation PR touches exactly ${[...allowed].join(" and ")})`);
  }
  if (!changedFiles.includes(`src/locales/${lang}.json`)) {
    problems.push(`the catalog src/locales/${lang}.json did not change`);
  }
  if (!changedFiles.includes(`src/locales/.sources/${lang}.json`)) {
    problems.push(`the provenance sidecar src/locales/.sources/${lang}.json did not change — catalog and sidecar always move together`);
  }
  return problems;
}

// Content check: the changed catalog and sidecar on disk (the PR head
// checkout) must validate — and must be exactly consistent with each other.
export function contentProblems(repoRoot, lang) {
  const catalogPath = join(repoRoot, "src/locales", `${lang}.json`);
  const sidecarPath = join(repoRoot, "src/locales/.sources", `${lang}.json`);
  const problems = [];
  if (!existsSync(catalogPath)) return [`${catalogPath} does not exist`];
  const catalog = JSON.parse(readFileSync(catalogPath, "utf8"));
  for (const problem of catalogProblems(catalog)) problems.push(`catalog: ${problem}`);
  if (!existsSync(sidecarPath)) {
    problems.push(`provenance sidecar ${sidecarPath} does not exist`);
    return problems;
  }
  const side = sidecarProblems(catalog, JSON.parse(readFileSync(sidecarPath, "utf8")));
  for (const problem of [...side.invalid, ...side.drift]) problems.push(`sidecar: ${problem}`);
  return problems;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const args = process.argv.slice(2);
  const value = (flag) => {
    const at = args.indexOf(flag);
    return at === -1 ? undefined : args[at + 1];
  };
  const author = value("--author");
  const appSlug = value("--app-slug") || process.env.TRANSLATION_APP_SLUG || "";
  const baseRef = value("--base");
  const headRef = value("--head");
  const filesAt = args.indexOf("--files");
  const changedFiles = filesAt === -1 ? [] : args.slice(filesAt + 1).filter((arg) => !arg.startsWith("--"));

  const problems = gateProblems({ author, appSlug, baseRef, headRef, changedFiles });
  if (!changedFiles.some((file) => file.startsWith("src/locales/"))) {
    console.log("no locale files changed — translation gate not in scope");
    process.exit(0);
  }
  if (!appSlug) {
    // Inert, but never silently: an Actions annotation on every locale-touching
    // PR makes a missing (or accidentally removed) slug visible in the checks UI
    // instead of passing without a trace.
    console.log("::warning::TRANSLATION_APP_SLUG is not configured — locale files changed with the translation gate inert (ordinary human review applies)");
    console.log("TRANSLATION_APP_SLUG is not configured — translation automation not set up, gate not in scope");
    process.exit(0);
  }
  const lang = BRANCH_PATTERN.exec(headRef ?? "")?.[1];
  if (lang && !problems.length) {
    for (const problem of contentProblems(root, lang)) problems.push(problem);
  }
  if (problems.length) {
    for (const problem of problems) console.error(`GATE: ${problem}`);
    process.exit(1);
  }
  console.log(`translation gate passed: ${headRef} → ${baseRef}, ${changedFiles.length} files, catalog + sidecar valid`);
}

