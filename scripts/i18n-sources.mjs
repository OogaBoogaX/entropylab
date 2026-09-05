// Shared English-source extraction for the i18n tooling. This is the single
// definition of "every user-facing English string": scripts/i18n-sync.mjs
// checks catalog drift against it, and scripts/i18n-translate.mjs derives the
// translation workload from it. Extracting twice would let the two disagree.
//
// Source strings come from exactly three places:
//   1. t("…") / hodlT(…) / hodlTText(…) / hodlTAttr(…) / hodlError(…) /
//      hodlNote(…) literals in src/js — the English text is the catalog key
//      (bare t( only in the standalone pre-boot scripts, where it aliases
//      globalThis.hodlT/hodlTText);
//   2. every string exported from src/js/i18n-labels.js (the enum-indexed
//      label families);
//   3. text nodes, aria-label/placeholder/title attributes, and
//      [data-i18n-rich] blocks in src/shell.html and src/index.html.
// <noscript> content cannot be translated (no JavaScript, no sweep) and build
// tokens ({{VERSION}}…) never match at runtime; both are excluded.
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

export const normalize = (text) => String(text ?? "").replace(/\s+/g, " ").trim();

// --- 1. JavaScript call-site literals ---------------------------------------
// Every string literal inside the first argument of a translating call,
// including ternary branches: hodlT(cond ? "Enter one" : "Enter many").
const firstArgLiterals = (src, start) => {
  const found = [];
  let i = start, depth = 1;
  while (i < src.length && depth > 0) {
    const ch = src[i];
    if (ch === '"') {
      let j = i + 1;
      while (j < src.length && src[j] !== '"') j += src[j] === "\\" ? 2 : 1;
      found.push(JSON.parse(src.slice(i, j + 1)));
      i = j + 1;
      continue;
    }
    if (ch === "(" || ch === "[" || ch === "{") depth++;
    else if (ch === ")" || ch === "]" || ch === "}") depth--;
    else if (ch === "," && depth === 1) break; // second argument: never a source
    i++;
  }
  return found;
};

const callSites = (root) => {
  const found = new Set();
  const files = readdirSync(join(root, "src/js")).filter((name) => name.endsWith(".js"));
  for (const name of files) {
    const src = readFileSync(join(root, "src/js", name), "utf8");
    // Bare t() is an i18n alias only in the two standalone pre-boot scripts;
    // everywhere else it is an ordinary local variable. app.js imports the
    // three sink-specific translators under the hodlT/hodlTText/hodlTAttr
    // names; the longest names come first so the alternation cannot match a
    // prefix. The field helpers take the English label as their first
    // argument and translate it internally, so their literals are sources too.
    const translating = ["hodlPublicFieldHtml", "hodlPrivateFieldHtml", "hodlTText", "hodlTAttr", "hodlT", "hodlError", "hodlNote"];
    const fns = name === "wallet-export.js" || name === "network-check.js" ? [...translating, "t"] : translating;
    const pattern = new RegExp(`(?:^|[^\\w$.])(?:${fns.join("|")})\\(`, "gm");
    for (const match of src.matchAll(pattern)) {
      for (const text of firstArgLiterals(src, match.index + match[0].length)) {
        if (normalize(text)) found.add(text);
      }
    }
  }
  return found;
};

// --- 2. Enum-family label tables --------------------------------------------
const labelTables = async (root) => {
  const labels = await import(pathToFileURL(join(root, "src/js/i18n-labels.js")).href);
  const found = new Set();
  const walk = (value) => {
    if (typeof value === "string") {
      if (normalize(value)) found.add(value);
    } else if (Array.isArray(value)) value.forEach(walk);
    else if (value && typeof value === "object") Object.values(value).forEach(walk);
  };
  Object.values(labels).forEach(walk);
  return found;
};

// --- 3. Markup ---------------------------------------------------------------
// <noscript> content can never be translated (no JavaScript, no sweep); the
// <title> is the browser-tab brand line. Neither is a source.
const SKIP_CONTENT = new Set(["script", "style", "noscript", "pre", "textarea", "template", "code", "title"]);
const SWEPT_ATTRS = ["aria-label", "placeholder", "title"];

const markupSources = (root, file) => {
  const html = readFileSync(join(root, file), "utf8");
  const found = new Set();
  let i = 0;
  const stack = [];
  const skipDepth = () => stack.filter((tag) => SKIP_CONTENT.has(tag)).length;
  const decodeEntities = (raw) =>
    raw
      .replace(/&#x([0-9a-fA-F]+);/g, (_, hex) => String.fromCodePoint(parseInt(hex, 16)))
      .replace(/&#(\d+);/g, (_, dec) => String.fromCodePoint(Number(dec)))
      .replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"').replace(/&apos;/g, "'");
  const addText = (raw) => {
    const text = normalize(decodeEntities(raw));
    if (!text || !/\p{L}/u.test(text)) return; // punctuation/digits only: nothing to translate
    if (text.includes("{{") || text.includes("/*@@")) return; // build tokens never match at runtime
    if (!skipDepth()) found.add(text);
  };
  while (i < html.length) {
    if (html.startsWith("<!--", i)) {
      i = html.indexOf("-->", i);
      if (i === -1) break;
      i += 3;
      continue;
    }
    if (html.startsWith("<!", i) || html.startsWith("<?", i)) {
      const end = html.indexOf(">", i);
      if (end === -1) break;
      i = end + 1;
      continue;
    }
    if (html[i] === "<") {
      const close = html[i + 1] === "/";
      const tagMatch = html.slice(i).match(/^<\/?([a-zA-Z][\w-]*)/);
      if (!tagMatch) { i++; continue; }
      const tag = tagMatch[1].toLowerCase();
      const end = html.indexOf(">", i);
      if (end === -1) break;
      const rawTag = html.slice(i, end + 1);
      if (!close) {
        if (/ data-i18n-skip[\s>]/.test(rawTag + ">")) {
          // Explicitly untranslatable subtree (brand names, the build stamp).
          const rich = captureRich(html, end + 1, tag);
          if (rich) {
            i = rich.end;
            continue;
          }
        }
        if (skipDepth()) {
          // inside a skipped subtree: only track nesting of the same tag
        } else {
          for (const attr of SWEPT_ATTRS) {
            const attrMatch = rawTag.match(new RegExp(` ${attr}="([^"]*)"`));
            if (attrMatch) addText(attrMatch[1]);
          }
          if (/ data-i18n-rich[\s>]/.test(rawTag + ">")) {
            // The catalog source for a rich block is its inner HTML, matched
            // against the serialized DOM at runtime with whitespace collapsed.
            // The capture covers the whole subtree, so the text walk skips it.
            const rich = captureRich(html, end + 1, tag);
            if (rich != null) {
              const text = normalize(rich.inner);
              if (text && !text.includes("{{")) found.add(text);
              i = rich.end;
              continue;
            }
          }
        }
        if (!/^(area|base|br|col|embed|hr|img|input|link|meta|source|track|wbr)$/.test(tag) && !/\/>$/.test(rawTag)) {
          stack.push(tag);
        }
      } else {
        const at = stack.lastIndexOf(tag);
        if (at !== -1) stack.length = at;
      }
      i = end + 1;
      continue;
    }
    const next = html.indexOf("<", i);
    addText(html.slice(i, next === -1 ? html.length : next));
    i = next === -1 ? html.length : next;
  }
  return found;
};

// Inner HTML of a rich element starting just after its open tag, plus the
// index just past its closing tag (so the caller can skip the subtree).
const captureRich = (html, from, tag) => {
  let depth = 1;
  const openOrClose = new RegExp(`<\\/?${tag}(?:\\s[^>]*)?>`, "g");
  openOrClose.lastIndex = from;
  let m;
  while ((m = openOrClose.exec(html))) {
    if (m[0].startsWith("</")) depth--;
    else if (!m[0].endsWith("/>")) depth++;
    if (depth === 0) return { inner: html.slice(from, m.index), end: m.index + m[0].length };
  }
  return null;
};

// Never translated: the locale picker's own option labels, the brand mark, and
// the format examples that must be typed or pasted byte-for-byte (placeholders
// and samples). Editing one in the shell revives it as a missing translation,
// so this list cannot quietly go stale.
const NON_SOURCES = [
  "EN", "ES", "PT", "FR", "DE",
  "EntropyLab",
  "Team Ooga Booga",
  "3e9fce73d4e77a4809908e3c3a2e54ee147b9312dc5044a193d1fc85de46e3c1", // sample SP scan fingerprint
  "[fingerprint/48h/0h/0h/2h]xpub…",
  "wsh(sortedmulti(2,[fingerprint/48h/0h/0h/2h]Zpub…/0/*, …))",
  "bc1q…",
  "cHNidP8B...",
  "cHNidP8B… or 020000000001…",
  "sp1qqgste7k9hx0q… sp1qqgste7k9hx0q… 2",
  '[{"txid":"…","vout":0,"scriptSig":"…","txinwitness":"","prevout":{"scriptPubKey":{"hex":"…"}},"private_key":"…"}]',
];

// Every user-facing English source string in the tree rooted at `root`
// (the repository root — the directory containing src/).
export const collectSources = async (root) => {
  const sources = new Set([...callSites(root), ...(await labelTables(root))]);
  for (const file of ["src/shell.html", "src/index.html"]) {
    for (const source of markupSources(root, file)) sources.add(source);
  }
  for (const nonSource of NON_SOURCES) sources.delete(nonSource);
  return sources;
};
