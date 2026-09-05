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
//   - reads only committed English sources and committed catalogs (the
//     glossary examples) — never issue text, PR text, web content, or any
//     other arbitrary input;
//   - the model is given no tools, and every request is schema-constrained to
//     exactly the requested keys with additionalProperties: false;
//   - a separate audit call reviews each translation for meaning changes
//     (dropped negations, receive/change swaps, missing clauses); flagged
//     keys fall back to "missing" — the safe English path — and are never
//     written;
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

const DEFAULT_API_URL = "https://openrouter.ai/api/v1/chat/completions";

// Batches stay small: schema-constrained responses are most reliable with a
// compact key set, and a failed call wastes less work.
const BATCH_SIZE = 20;

// Exactly the requested keys, nothing else — a model that invents or drops
// keys fails the provider's own schema check.
export const translationSchema = (keys) => ({
  type: "object",
  properties: Object.fromEntries(keys.map((key) => [key, { type: "string" }])),
  required: [...keys],
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
      const content = data?.choices?.[0]?.message?.content;
      if (typeof content !== "string") throw new Error("LLM response carried no message content");
      return JSON.parse(content);
    }
    lastError = new Error(`LLM request failed: HTTP ${response.status} ${(await response.text()).slice(0, 200)}`);
    if (response.status !== 429 && response.status < 500) break;
  }
  throw lastError;
}

const translateMessages = (languageName, glossary, keys) => [
  {
    role: "system",
    content: [
      `You translate Bitcoin wallet user-interface strings from English to ${languageName}.`,
      "- Preserve every {placeholder} byte-for-byte; never translate placeholder names.",
      "- Preserve every HTML tag and attribute byte-for-byte; translate only the text between tags.",
      "- Never translate URLs, or Bitcoin terms of art such as PSBT, BIP39, xpub, seed phrase, or the word EntropyLab.",
      "- Match the terminology of the supplied existing translations.",
      "- Return JSON only: an object mapping each English string to its translation.",
    ].join(" "),
  },
  {
    role: "user",
    content: JSON.stringify({ glossary, strings: keys }),
  },
];

const auditMessages = (languageName, pairs) => [
  {
    role: "system",
    content: [
      `You audit Bitcoin wallet user-interface translations from English to ${languageName}.`,
      "For each pair, decide whether the translation preserves the meaning exactly.",
      "Fail a pair for: a dropped or added negation; swapped receive/change, send/receive, or similar antonyms;",
      "a missing or added clause; changed numbers, units, placeholders, or URLs; markup that changes the meaning.",
      "Do not fail a pair for style, register, or word-order preferences — only meaning errors fail.",
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
// dead, and which sources still need a translation.
export async function languageWorkload(root, lang, limit) {
  const sources = await collectSources(root);
  const catalogPath = join(root, "src/locales", `${lang}.json`);
  const catalog = existsSync(catalogPath) ? JSON.parse(readFileSync(catalogPath, "utf8")) : {};
  const keep = {};
  let dead = 0;
  for (const [key, value] of Object.entries(catalog)) {
    if (sources.has(key)) keep[key] = value;
    else dead++;
  }
  let missing = [...sources].filter((source) => !keep[source]);
  if (limit) missing = missing.slice(0, limit);
  return { sources, catalog, keep, dead, missing };
}

// Translate one language into outDir. Returns a per-language report; throws
// (writing nothing) if the final catalog or sidecar fails validation.
export async function translateLanguage({ root, lang, outDir, client, limit, log = console.log }) {
  const languageName = LANGUAGE_NAMES[lang] ?? lang;
  const { catalog, keep, dead, missing } = await languageWorkload(root, lang, limit);

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
      const proposals = await client.chat({
        name: "translate",
        schema: translationSchema(batch),
        messages: translateMessages(languageName, glossary, batch),
      });
      const accepted = {};
      for (const key of batch) {
        const value = proposals?.[key];
        if (typeof value !== "string" || !value.trim()) {
          dropped.push({ key, problem: "the model returned no translation" });
          continue;
        }
        // Validate on arrival: a single bad placeholder or disallowed tag
        // must not poison the batch — the key just stays missing.
        const problems = valueProblems(key, value);
        if (problems.length) {
          dropped.push({ key, problem: problems.join("; ") });
          continue;
        }
        accepted[key] = value;
      }
      const acceptedKeys = Object.keys(accepted);
      if (acceptedKeys.length) {
        const audit = await client.chat({
          name: "audit",
          schema: auditSchema,
          messages: auditMessages(languageName, acceptedKeys.map((key) => ({ key, translation: accepted[key] }))),
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
  // stable.
  const catalogNext = { ...keep };
  for (const key of missing) if (translated[key]) catalogNext[key] = translated[key];
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
        `${lang}: kept ${report.kept}, pruned ${report.dead} dead, translated ${report.translated}/${report.requested} missing` +
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

