// Translation generation — job A of the post-merge translation workflow:
// generate and validate, with no repository write access.
//
//   node scripts/i18n-translate.mjs --out <dir> [--lang es] [--limit N]
//
// Environment:
//   TRANSLATE_API_KEY   bearer token for the chat-completions endpoint (secret)
//   TRANSLATE_API_URL   chat-completions endpoint (default: OpenRouter)
//   TRANSLATE_MODEL     model id (required)
//
// Safety properties (issue #286):
//   - reads only committed English sources, committed catalogs (the
//     glossary examples) and the committed context file
//     (scripts/i18n-context.json) — never issue text, PR text, web content,
//     or any other arbitrary input;
//   - the model is given no tools, and every request is schema-constrained to
//     exactly the requested keys with additionalProperties: false;
//   - a separate audit call reviews each translation for meaning changes
//     (dropped negations, receive/change swaps, missing clauses); flagged
//     keys fall back to "missing" — the safe English path — and are never
//     written. The one exception is a value equal to its `exact` correction:
//     that text was reviewed in the context file, so it skips the audit;
//   - every translated value passes the catalog validator the moment it
//     arrives, and the final catalog + sidecar must validate or the run fails
//     and writes nothing for that language;
//   - this script never writes outside --out; the publish job
//     (scripts/i18n-publish.mjs) is the only writer to GitHub.
import { existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { collectSources } from "./i18n-sources.mjs";
import { catalogProblems, hashSource, sidecarProblems, valueProblems } from "./i18n-validate.mjs";

const root = dirname(dirname(fileURLToPath(import.meta.url)));

export const LANGUAGE_NAMES = { es: "Spanish", fr: "French", pt: "Portuguese", de: "German" };

// Committed per-string context (issue #862). A translation is generated once
// and never revisited, and the model sees each string bare, so a wrong one
// ("Output public key" read as a verb) had no way back. Each entry is keyed
// by the English source string:
//   note            context for every language, shown to the translate and
//                   audit calls;
//   noteByLanguage  { lang: context for that language only };
//   retranslate     { lang: the committed value to replace }: while the
//                   catalog still holds exactly that value it is translated
//                   again, in place. Once replaced, the pin no longer matches
//                   and the entry goes quiet, so a run never churns it. A
//                   retranslation that fails any check below leaves the
//                   committed value as it is, and the next run tries again;
//   mustContain     { lang: [substrings] } every translation of the key must
//                   carry, such as a browser's own name for a setting;
//   exact           { lang: value } the translation must be exactly this
//                   string, for a reviewed correction whose wording is
//                   settled (a one-word fix that keeps the rest of the
//                   committed sentence as it is).
// A translation that fails mustContain or exact is dropped on arrival: a
// missing string stays English, and a pinned one keeps its committed value.
// The file is committed repo content, reviewed like code: it is not a way
// for anything outside the tree to reach the model.
export const CONTEXT_PATH = "scripts/i18n-context.json";
const CONTEXT_FIELDS = new Set(["note", "noteByLanguage", "retranslate", "mustContain", "exact"]);

export function contextProblems(context, sources) {
  const problems = [];
  if (!context || typeof context !== "object" || Array.isArray(context)) return ["the context file must be a JSON object"];
  const isText = (value) => typeof value === "string" && value.trim() !== "";
  const byLanguage = (key, field, value, check) => {
    if (!value || typeof value !== "object" || Array.isArray(value)) return problems.push(`${JSON.stringify(key)}: ${field} must map languages to values`);
    for (const [lang, item] of Object.entries(value)) {
      if (!(lang in LANGUAGE_NAMES)) problems.push(`${JSON.stringify(key)}: ${field} names unknown language ${JSON.stringify(lang)}`);
      else if (!check(item)) problems.push(`${JSON.stringify(key)}: ${field}.${lang} has the wrong shape`);
    }
  };
  for (const [key, entry] of Object.entries(context)) {
    if (sources && !sources.has(key)) problems.push(`${JSON.stringify(key)} is not a current English source string`);
    if (!entry || typeof entry !== "object" || Array.isArray(entry)) {
      problems.push(`${JSON.stringify(key)}: the entry must be an object`);
      continue;
    }
    for (const field of Object.keys(entry)) if (!CONTEXT_FIELDS.has(field)) problems.push(`${JSON.stringify(key)}: unknown field ${JSON.stringify(field)}`);
    if ("note" in entry && !isText(entry.note)) problems.push(`${JSON.stringify(key)}: note must be non-empty text`);
    if ("noteByLanguage" in entry) byLanguage(key, "noteByLanguage", entry.noteByLanguage, isText);
    if ("retranslate" in entry) byLanguage(key, "retranslate", entry.retranslate, isText);
    if ("mustContain" in entry) byLanguage(key, "mustContain", entry.mustContain, (list) => Array.isArray(list) && list.length > 0 && list.every(isText));
    if ("exact" in entry) byLanguage(key, "exact", entry.exact, isText);
  }
  return problems;
}

// The committed context, or {} when the file does not exist. A malformed
// file fails the run (nothing is written); an entry whose English string is
// gone is ignored here, and the test suite fails on it before merge.
export function loadContext(root) {
  const path = join(root, CONTEXT_PATH);
  if (!existsSync(path)) return {};
  const context = JSON.parse(readFileSync(path, "utf8"));
  const problems = contextProblems(context);
  if (problems.length) throw new Error(`${CONTEXT_PATH} is malformed:\n${problems.join("\n")}`);
  return context;
}

// Own entries only: an English string such as "constructor" must not find an
// inherited property.
const contextEntry = (context, key) => (Object.hasOwn(context, key) ? context[key] : undefined);
const forLanguage = (map, lang) => (map && Object.hasOwn(map, lang) ? map[lang] : undefined);

const contextNote = (context, key, lang) => {
  const entry = contextEntry(context, key);
  return [entry?.note, forLanguage(entry?.noteByLanguage, lang)].filter(Boolean).join(" ");
};

const contextValueProblems = (context, key, lang, value) => {
  const entry = contextEntry(context, key);
  const problems = (forLanguage(entry?.mustContain, lang) ?? [])
    .filter((term) => !value.includes(term))
    .map((term) => `context: must contain ${JSON.stringify(term)}`);
  const exact = forLanguage(entry?.exact, lang);
  if (exact !== undefined && value !== exact) problems.push("context: must be exactly the committed correction");
  return problems;
};

const DEFAULT_API_URL = "https://openrouter.ai/api/v1/chat/completions";

// Batches stay small: schema-constrained responses are most reliable with a
// compact key set, and a failed call wastes less work.
const BATCH_SIZE = 20;

// An array of {key, translation} pairs, not an object keyed by the English
// strings: providers escape string FIELDS correctly, but gemini's
// json_schema mode emits property NAMES containing quotes unescaped, which
// produced invalid JSON whenever a UI string carried a quote. Key coverage
// is enforced below, on arrival.
export const translationSchema = (keys) => ({
  type: "object",
  properties: {
    translations: {
      type: "array",
      items: {
        type: "object",
        properties: { key: { type: "string" }, translation: { type: "string" } },
        required: ["key", "translation"],
        additionalProperties: false,
      },
    },
  },
  required: ["translations"],
  additionalProperties: false,
});

export const auditSchema = {
  type: "object",
  properties: {
    verdicts: {
      type: "array",
      items: {
        type: "object",
        properties: {
          key: { type: "string" },
          ok: { type: "boolean" },
          problem: { type: "string" },
        },
        required: ["key", "ok", "problem"],
        additionalProperties: false,
      },
    },
  },
  required: ["verdicts"],
  additionalProperties: false,
};

// One chat-completions call. Retries once on network errors and 429/5xx.
export async function chat({ url, key, model, name, schema, messages }) {
  const body = JSON.stringify({
    model,
    messages,
    temperature: 0,
    response_format: { type: "json_schema", json_schema: { name, schema, strict: true } },
  });
  let lastError;
  for (let attempt = 0; attempt < 2; attempt++) {
    let response;
    try {
      response = await fetch(url, {
        method: "POST",
        headers: { "content-type": "application/json", authorization: `Bearer ${key}` },
        body,
      });
    } catch (error) {
      lastError = error;
      continue;
    }
    if (response.ok) {
      const data = await response.json();
      let content = data?.choices?.[0]?.message?.content;
      if (typeof content !== "string") {
        // An empty choice (provider cut the stream to nothing) is the same
        // transient class as a truncated one — retry it, don't fail the run.
        lastError = new Error("LLM response carried no message content");
        continue;
      }
      // Providers sometimes wrap the JSON in markdown fences, and a slow or
      // rate-limited stream can truncate it mid-response: strip fences, and
      // retry a parse failure rather than failing the whole language on a
      // transient.
      content = content.trim().replace(/^```(?:json)?\s*\n?/, "").replace(/\n?```\s*$/, "");
      try {
        return JSON.parse(content);
      } catch (error) {
        lastError = error;
        continue;
      }
    }
    lastError = new Error(`LLM request failed: HTTP ${response.status} ${(await response.text()).slice(0, 200)}`);
    if (response.status !== 429 && response.status < 500) break;
  }
  throw lastError;
}

// `notes` maps some of the requested strings to their committed context
// (scripts/i18n-context.json). A batch without notes sends exactly what it
// always did.
const translateMessages = (languageName, glossary, keys, notes = {}) => {
  const noted = Object.keys(notes).length > 0;
  return [
    {
      role: "system",
      content: [
        `You translate Bitcoin wallet user-interface strings from English to ${languageName}.`,
        "- Preserve every {placeholder} byte-for-byte; never translate placeholder names.",
        "- Preserve every HTML tag and attribute byte-for-byte; translate only the text between tags.",
        "- Never translate URLs, or Bitcoin terms of art such as PSBT, BIP39, xpub, seed phrase, or the word EntropyLab.",
        "- Match the terminology of the supplied existing translations.",
        ...(noted ? ["- Some strings have a note in \"notes\", keyed by the string: it explains the string's context or gives the exact localized names to use. Follow it; never translate the note itself or copy it into a translation."] : []),
        "- Return JSON only: an object with a \"translations\" array of {\"key\", \"translation\"} pairs, one per requested string.",
      ].join(" "),
    },
    {
      role: "user",
      content: JSON.stringify(noted ? { glossary, strings: keys, notes } : { glossary, strings: keys }),
    },
  ];
};

// A pair may carry its committed note, so a translation that follows it (a
// browser's own localized name for a setting, say) is not failed as a
// meaning change.
const auditMessages = (languageName, pairs) => [
  {
    role: "system",
    content: [
      `You audit Bitcoin wallet user-interface translations from English to ${languageName}.`,
      "For each pair, decide whether the translation preserves the meaning exactly.",
      "Fail a pair for: a dropped or added negation; swapped receive/change, send/receive, or similar antonyms;",
      "a missing or added clause; changed numbers, units, placeholders, or URLs; markup that changes the meaning.",
      "Do not fail a pair for style, register, or word-order preferences — only meaning errors fail.",
      ...(pairs.some((pair) => pair.note) ? ["A pair with a \"note\" carries the string's committed context: judge the translation against the English as that note explains it, and fail a pair that ignores the note."] : []),
    ].join(" "),
  },
  {
    role: "user",
    content: JSON.stringify({ pairs }),
  },
];

const chunks = (items, size) => {
  const out = [];
  for (let i = 0; i < items.length; i += size) out.push(items.slice(i, i + size));
  return out;
};

// The workload for one language: which committed entries survive, which are
// dead, which a context pin sends back for translation (stale), and which
// sources still need a translation. A stale entry is not kept, so it is
// missing again and stays out of the glossary.
export async function languageWorkload(root, lang, limit) {
  const sources = await collectSources(root);
  const context = loadContext(root);
  const catalogPath = join(root, "src/locales", `${lang}.json`);
  const catalog = existsSync(catalogPath) ? JSON.parse(readFileSync(catalogPath, "utf8")) : {};
  const keep = {};
  const stale = [];
  let dead = 0;
  for (const [key, value] of Object.entries(catalog)) {
    if (!sources.has(key)) dead++;
    else if (forLanguage(contextEntry(context, key)?.retranslate, lang) === value) stale.push(key);
    else keep[key] = value;
  }
  let missing = [...sources].filter((source) => !keep[source]);
  if (limit) missing = missing.slice(0, limit);
  return { sources, context, catalog, keep, stale, dead, missing };
}

// Translate one language into outDir. Returns a per-language report; throws
// (writing nothing) if the final catalog or sidecar fails validation.
export async function translateLanguage({ root, lang, outDir, client, limit, log = console.log }) {
  const languageName = LANGUAGE_NAMES[lang] ?? lang;
  const { context, catalog, keep, stale, dead, missing } = await languageWorkload(root, lang, limit);

  const translated = {};
  const dropped = [];
  if (missing.length) {
    // Glossary: short committed pairs anchor the model's terminology. Only
    // committed catalog content is ever shown to the model.
    const glossary = Object.fromEntries(
      Object.entries(keep)
        .filter(([key, value]) => key.length <= 80 && value.length <= 80)
        .slice(0, 40),
    );
    for (const batch of chunks(missing, BATCH_SIZE)) {
      const notes = Object.fromEntries(batch.map((key) => [key, contextNote(context, key, lang)]).filter(([, note]) => note));
      const result = await client.chat({
        name: "translate",
        schema: translationSchema(batch),
        messages: translateMessages(languageName, glossary, batch, notes),
      });
      const proposals = new Map((result?.translations ?? []).map((pair) => [pair.key, pair.translation]));
      const accepted = {};
      for (const key of batch) {
        const value = proposals.get(key);
        if (typeof value !== "string" || !value.trim()) {
          dropped.push({ key, problem: "the model returned no translation" });
          continue;
        }
        // Validate on arrival: a single bad placeholder or disallowed tag
        // must not poison the batch — the key just stays missing.
        const problems = [...valueProblems(key, value), ...contextValueProblems(context, key, lang, value)];
        if (problems.length) {
          dropped.push({ key, problem: problems.join("; ") });
          continue;
        }
        accepted[key] = value;
      }
      // A value with an `exact` correction has already been required to equal
      // it, so it is the committed text a pull request reviewed. The audit has
      // nothing to add, and it has rejected such values as different from the
      // identical required text, so a reviewed correction never landed.
      const reviewed = Object.keys(accepted).filter((key) => forLanguage(contextEntry(context, key)?.exact, lang) !== undefined);
      for (const key of reviewed) translated[key] = accepted[key];
      const acceptedKeys = Object.keys(accepted).filter((key) => !reviewed.includes(key));
      if (acceptedKeys.length) {
        const audit = await client.chat({
          name: "audit",
          schema: auditSchema,
          messages: auditMessages(languageName, acceptedKeys.map((key) => (notes[key] ? { key, translation: accepted[key], note: notes[key] } : { key, translation: accepted[key] }))),
        });
        const verdicts = new Map((audit?.verdicts ?? []).map((verdict) => [verdict.key, verdict]));
        for (const key of acceptedKeys) {
          const verdict = verdicts.get(key);
          if (verdict && verdict.ok === false) {
            dropped.push({ key, problem: `semantic audit: ${verdict.problem}` });
          } else {
            translated[key] = accepted[key];
          }
        }
      }
      log(`${lang}: batch of ${batch.length} → ${Object.keys(translated).length} translated, ${dropped.length} dropped so far`);
    }
  }

  // Preserve the committed key order and append new translations in source
  // order, so the first automated PR is a minimal diff and later ones stay
  // stable. A stale entry's replacement takes its old place; one whose
  // retranslation was dropped keeps its committed value, so a failed
  // correction changes nothing a reader sees and the next run tries again.
  const catalogNext = {};
  for (const key of Object.keys(catalog)) {
    if (Object.hasOwn(keep, key)) catalogNext[key] = keep[key];
    else if (stale.includes(key)) catalogNext[key] = translated[key] ?? catalog[key];
  }
  for (const key of missing) if (translated[key] && !Object.hasOwn(catalogNext, key)) catalogNext[key] = translated[key];
  const sidecarNext = Object.fromEntries(Object.keys(catalogNext).map((key) => [key, hashSource(key)]));

  // Final gate: the same validator CI runs. Any failure stops the batch —
  // nothing is written, the workflow fails, and the publish job never runs.
  const problems = catalogProblems(catalogNext);
  const side = sidecarProblems(catalogNext, sidecarNext);
  const failures = [...problems, ...side.invalid, ...side.drift];
  if (failures.length) {
    throw new Error(`${lang}: generated catalog failed validation:\n${failures.slice(0, 10).join("\n")}`);
  }

  const sidecarPath = join(root, "src/locales/.sources", `${lang}.json`);
  const sidecarPrev = existsSync(sidecarPath) ? JSON.parse(readFileSync(sidecarPath, "utf8")) : {};
  const changed =
    JSON.stringify(catalogNext) !== JSON.stringify(catalog) ||
    JSON.stringify(sidecarNext) !== JSON.stringify(sidecarPrev);

  const report = {
    lang,
    kept: Object.keys(keep).length,
    dead,
    stale: stale.length,
    requested: missing.length,
    translated: Object.keys(translated).length,
    dropped,
    stillMissing: missing.length - Object.keys(translated).length,
    changed,
  };
  if (changed) {
    mkdirSync(join(outDir, ".sources"), { recursive: true });
    writeFileSync(join(outDir, `${lang}.json`), JSON.stringify(catalogNext, null, 2) + "\n");
    writeFileSync(join(outDir, ".sources", `${lang}.json`), JSON.stringify(sidecarNext, null, 2) + "\n");
  }
  return report;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const args = process.argv.slice(2);
  const value = (flag) => {
    const at = args.indexOf(flag);
    return at === -1 ? undefined : args[at + 1];
  };
  const outDir = value("--out");
  const key = process.env.TRANSLATE_API_KEY;
  const url = process.env.TRANSLATE_API_URL || DEFAULT_API_URL;
  const model = process.env.TRANSLATE_MODEL;
  if (!outDir || !key || !model) {
    console.error("usage: TRANSLATE_API_KEY=… TRANSLATE_MODEL=… node scripts/i18n-translate.mjs --out <dir> [--lang es] [--limit N]");
    process.exit(2);
  }
  const onlyLang = value("--lang");
  const limit = value("--limit") ? Number(value("--limit")) : undefined;
  const langs = onlyLang
    ? [onlyLang]
    : readdirSync(join(root, "src/locales"))
        .filter((name) => name.endsWith(".json") && name !== "en.json")
        .map((name) => name.replace(/\.json$/, ""));
  const client = { chat: (request) => chat({ url, key, model, ...request }) };
  const reports = [];
  let failed = 0;
  for (const lang of langs) {
    try {
      const report = await translateLanguage({ root, lang, outDir, client, limit });
      reports.push(report);
      console.log(
        `${lang}: kept ${report.kept}, pruned ${report.dead} dead` +
          (report.stale ? `, ${report.stale} pinned for retranslation` : "") +
          `, translated ${report.translated}/${report.requested} missing` +
          (report.dropped.length ? `, dropped ${report.dropped.length} (left as English fallback)` : "") +
          (report.changed ? "" : " — no changes"),
      );
    } catch (error) {
      failed++;
      console.error(`${lang}: FAILED — ${error.message}`);
    }
  }
  mkdirSync(outDir, { recursive: true });
  writeFileSync(join(outDir, "report.json"), JSON.stringify({ model, reports }, null, 2) + "\n");
  process.exit(failed ? 1 : 0);
}

