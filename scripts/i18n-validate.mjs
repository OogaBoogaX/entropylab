// Catalog validator: the gate every locale change must pass before it can
// reach rock. The runtime sanitizer (src/js/i18n-sanitize.js) is the last
// boundary — it renders a hostile catalog value safely no matter what — but
// its fallbacks (escaping rejected markup, dropping tags, auto-closing
// nesting) would silently mangle honest translations too. This validator is
// the early boundary: anything the sanitizer could not render byte-faithfully
// is rejected here, loudly, before merge.
//
//   node scripts/i18n-validate.mjs src/locales/es.json [...]
//
// Rules for every key → value pair (the key is the English source text):
//   - the value is a non-empty, non-blank string — an untranslated string is
//     a missing key, never an empty value;
//   - no bidirectional overrides, zero-width characters, or other unexpected
//     controls (the exact set the sanitizer neutralizes);
//   - the {placeholder} set is identical to the English source's — a changed,
//     dropped, or invented placeholder would corrupt interpolated output;
//   - every tag matches a fixed allowlist form exactly and nesting is
//     balanced — the sanitizer must not have to escape, drop, or auto-close
//     anything;
//   - anchors carry only the fixed forms the English source itself carries:
//     a translation may drop a link but can never retarget or invent one;
//   - no entity or character references beyond the five the sanitizer emits
//     (amp, lt, gt, quot, #39) — a browser could decode the others into bidi
//     or invisible text;
//   - no javascript:/vbscript:/data: scheme text anywhere.
//
// Missing and dead keys are NOT problems here: partial locales are normal by
// design (per-string English fallback), and dead keys are inert data the
// translation workflow prunes. scripts/i18n-sync.mjs reports both.
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";
import {
  hodlCatalogHasControlCharacters,
  hodlCatalogTagForm,
  hodlCatalogTokens,
} from "../src/js/i18n-sanitize.js";

const hodlPlaceholderPattern = /\{(\w+)\}/g;

export const placeholdersOf = (text) =>
  [...String(text ?? "").matchAll(hodlPlaceholderPattern)].map((match) => match[1]).sort();

// The only character references the sanitizer will ever emit or preserve;
// every other reference is escaped at render time, so a catalog carrying one
// would display it literally — fail it here instead.
const canonicalEntities = new Set(["amp", "lt", "gt", "quot", "#39"]);

// Fixed attribute forms are compared by identity: hodlCatalogTagForm returns
// the allowlist table's own frozen objects, so two tokens matching the same
// form hold the same reference.
const anchorFormsOf = (text) => {
  const forms = new Set();
  for (const token of hodlCatalogTokens(text)) {
    if (token.text !== undefined || token.name !== "a") continue;
    const form = hodlCatalogTagForm(token);
    if (form) forms.add(form);
  }
  return forms;
};

export function valueProblems(key, value) {
  const problems = [];
  if (typeof value !== "string") return [`value is ${value === null ? "null" : typeof value}, not a string`];
  if (!value.trim()) problems.push("empty translation — omit the key instead of committing an empty value");
  if (hodlCatalogHasControlCharacters(value))
    problems.push("contains bidirectional overrides, zero-width characters, or unexpected control characters");

  const expected = placeholdersOf(key);
  const actual = placeholdersOf(value);
  if (expected.join(" ") !== actual.join(" "))
    problems.push(`placeholders {${actual.join("},{")}} do not match the English source {${expected.join("},{")}}`);

  for (const match of value.matchAll(/&(?:#x[0-9a-fA-F]+|#\d+|[a-zA-Z]+);/g)) {
    const entity = match[0].slice(1, -1);
    if (!canonicalEntities.has(entity)) problems.push(`non-canonical character reference &${entity};`);
  }

  const scheme = /(javascript|vbscript|data)\s*:/i.exec(value);
  if (scheme) problems.push(`contains a ${scheme[1].toLowerCase()}: scheme`);

  const keyAnchorForms = anchorFormsOf(key);
  const stack = [];
  for (const token of hodlCatalogTokens(value)) {
    if (token.text !== undefined) continue;
    const form = hodlCatalogTagForm(token);
    if (!form) {
      problems.push(`markup outside the allowlist: ${JSON.stringify(token.raw.slice(0, 60))}`);
      continue;
    }
    if (token.closing) {
      if (stack.pop() !== token.name) problems.push(`unbalanced nesting at </${token.name}>`);
      continue;
    }
    if (token.name === "a" && !keyAnchorForms.has(form))
      problems.push("anchor does not match a link carried by the English source");
    stack.push(token.name);
  }
  for (const name of stack) problems.push(`unclosed <${name}>`);
  return problems;
}

export function catalogProblems(catalog) {
  const problems = [];
  for (const [key, value] of Object.entries(catalog ?? {})) {
    for (const problem of valueProblems(key, value)) {
      problems.push(`${JSON.stringify(key.length > 70 ? key.slice(0, 70) + "…" : key)}: ${problem}`);
    }
  }
  return problems;
}

// Extracted English sources are reviewed code and render raw, so they need no
// value validation — but every markup form they carry must exist in the
// sanitizer table, or translations of the string would render as escaped
// text. This is the tripwire that keeps the table complete: a feature PR that
// adds a new link or formatting form fails here until the table grows.
export function sourceMarkupProblems(source) {
  const problems = [];
  for (const token of hodlCatalogTokens(source)) {
    if (token.text !== undefined) continue;
    if (!hodlCatalogTagForm(token)) {
      problems.push(`source markup outside the sanitizer allowlist: ${JSON.stringify(token.raw.slice(0, 60))} — extend hodlCatalogAllowedTags in src/js/i18n-sanitize.js`);
    }
  }
  return problems;
}

// sha256 of the English source text a translation was made from — the value
// recorded in the translation-provenance sidecar (src/locales/.sources/). The
// English text is the catalog key, so the hash is deterministic: any mismatch
// between sidecar and key is corruption or a stale provenance claim, never a
// legitimate state.
export const hashSource = (source) => createHash("sha256").update(String(source), "utf8").digest("hex");

// Sidecar validation, split by severity:
//   invalid — malformed hashes and hashes that do not match the English key;
//     deterministic corruption, fails CI like invalid catalog content;
//   drift   — catalog keys with no recorded hash and hashes with no catalog
//     entry; normal between runs, repaired by the translation workflow.
// The translation-only PR gate and the publish job treat both as failures
// (a translation PR must leave catalog and sidecar exactly consistent); the
// sync check fails on `invalid` and only reports `drift`.
export function sidecarProblems(catalog, sidecar) {
  const invalid = [];
  const drift = [];
  const entries = sidecar && typeof sidecar === "object" ? Object.entries(sidecar) : [];
  const keys = catalog && typeof catalog === "object" ? Object.keys(catalog) : [];
  for (const [key, hash] of entries) {
    if (!keys.includes(key)) {
      drift.push(`source hash with no catalog entry: ${JSON.stringify(key.slice(0, 70))}`);
      continue;
    }
    if (typeof hash !== "string" || !/^[0-9a-f]{64}$/.test(hash)) {
      invalid.push(`malformed source hash for ${JSON.stringify(key.slice(0, 70))}`);
      continue;
    }
    if (hash !== hashSource(key)) {
      invalid.push(`source hash does not match the English key for ${JSON.stringify(key.slice(0, 70))}`);
    }
  }
  for (const key of keys) {
    if (!entries.some(([sidecarKey]) => sidecarKey === key)) {
      drift.push(`no source hash for translated key ${JSON.stringify(key.slice(0, 70))}`);
    }
  }
  return { invalid, drift };
}

// CLI: validate catalog files (used by the translation-only PR gate and by
// the publish job of the translation workflow).
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const files = process.argv.slice(2);
  if (!files.length) {
    console.error("usage: node scripts/i18n-validate.mjs <catalog.json> [...]");
    process.exit(2);
  }
  let failures = 0;
  for (const file of files) {
    let catalog;
    try {
      catalog = JSON.parse(readFileSync(file, "utf8"));
    } catch (error) {
      console.log(`${file}: unreadable catalog (${error.message})`);
      failures++;
      continue;
    }
    const problems = catalogProblems(catalog);
    failures += problems.length;
    for (const problem of problems.slice(0, 20)) console.log(`${file}: ${problem}`);
    if (problems.length > 20) console.log(`${file}: …and ${problems.length - 20} more`);
    if (!problems.length) console.log(`${file}: valid (${Object.keys(catalog).length} entries)`);
  }
  process.exit(failures ? 1 : 0);
}
