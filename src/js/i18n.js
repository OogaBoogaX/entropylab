// EntropyLab i18n. The English source text is the translation key: call sites
// read `t("Save watch-only sheet")`, and each locale catalog maps that English
// sentence to its translation. A lookup miss returns the source itself, so an
// untranslated string always renders correct English, never a raw key name.
// Enum-indexed label families (network names, input formats, …) cannot be
// literals at the call site; their English lives in i18n-labels.js and flows
// through the same content-keyed t(). scripts/i18n-sync.mjs extracts every
// source string and reports catalog drift; missing or dead entries are normal
// between a UI change and the next automated translation run.
//
// Catalogs are data written outside the reviewed-code path (today by hand,
// soon by the translation automation), so no catalog value is trusted: every
// catalog is rebuilt from the markup allowlist in i18n-sanitize.js once, here,
// in two views. t()/tAttr() read the plain-text view (markup dropped, safe
// for textContent/setAttribute); tHtml() reads the HTML view (allowlisted
// formatting only, entity-escaped text, safe to interpolate into an HTML
// template). A value the sanitizer cannot keep is never rendered as markup.
import es from "../locales/es.json" with { type: "json" };
import pt from "../locales/pt.json" with { type: "json" };
import fr from "../locales/fr.json" with { type: "json" };
import de from "../locales/de.json" with { type: "json" };
import { hodlEscapeAttribute, hodlEscapeHtmlText, hodlSanitizeCatalog, hodlSanitizeCatalogHtml, hodlSanitizeTextCatalog } from "./i18n-sanitize.js";

export const hodlLocaleCodes = Object.freeze(["en", "es", "pt", "fr", "de"]);
export const hodlLocaleStorageKey = "entropylab-locale";
export const hodlLocaleMeta = Object.freeze({
  en: { htmlLang: "en", label: "English", short: "EN" },
  es: { htmlLang: "es", label: "Español", short: "ES" },
  pt: { htmlLang: "pt-BR", label: "Português", short: "PT" },
  fr: { htmlLang: "fr", label: "Français", short: "FR" },
  de: { htmlLang: "de", label: "Deutsch", short: "DE" },
});

// Every catalog is rebuilt from the markup allowlist once, here. Plain DOM
// sinks and HTML sinks use separate sanitized views so neither has to guess
// its output context or re-sanitize after placeholder substitution.
const hodlLocaleHtmlCatalogs = { es: hodlSanitizeCatalog(es), pt: hodlSanitizeCatalog(pt), fr: hodlSanitizeCatalog(fr), de: hodlSanitizeCatalog(de) };
const hodlLocaleTextCatalogs = { es: hodlSanitizeTextCatalog(es), pt: hodlSanitizeTextCatalog(pt), fr: hodlSanitizeTextCatalog(fr), de: hodlSanitizeTextCatalog(de) };
let hodlLocale = "en";
let hodlLocaleListener = null;

export function hodlNormalizeLocale(code) {
  return hodlLocaleCodes.includes(code) ? code : "en";
}

// Every locale is always selectable. Missing or stale entries fall back to
// the English source per string, so a partially translated language is useful
// immediately; the post-merge translation workflow fills the gaps.
export function hodlSelectableLocales() {
  return [...hodlLocaleCodes];
}

export function hodlGetLocale() {
  return hodlLocale;
}

function hodlCatalogValue(catalogs, source) {
  let catalog = catalogs[hodlLocale];
  let text = catalog ? catalog[source] : undefined;
  return typeof text === "string" && text ? text : source;
}

function hodlInterpolate(text, vars, render) {
  if (!vars) return text;
  return text.replace(/\{(\w+)\}/g, (_, name) => (vars[name] == null ? `{${name}}` : render(vars[name])));
}

// Plain strings are only for DOM textContent/setAttribute and other non-HTML
// consumers. Placeholder values stay byte-faithful because the sink does not
// parse them.
export function t(source, vars) {
  return hodlInterpolate(hodlCatalogValue(hodlLocaleTextCatalogs, source), vars, String);
}

// HTML strings retain catalog-authored allowlisted markup. Placeholder values
// are encoded as text before insertion and are never passed back through the
// allowlist, so they cannot introduce even an otherwise allowed element. A
// lookup miss returns the committed English source, markup included — the
// source is reviewed code, trusted at the same level as the templates.
export function tHtml(source, vars) {
  let catalog = hodlLocaleHtmlCatalogs[hodlLocale];
  let text = catalog && typeof catalog[source] === "string" && catalog[source] ? catalog[source] : source;
  return hodlInterpolate(text, vars, hodlEscapeHtmlText);
}

export function tAttr(source, vars) {
  return hodlEscapeAttribute(t(source, vars));
}
// The standalone pre-boot scripts (network-check.js, wallet-export.js) reach
// the translators through the globals; they run before the module graph boots
// and fall back to their inline English until it does.
if (typeof globalThis !== "undefined") {
  globalThis.hodlT = tHtml;
  globalThis.hodlTText = t;
  globalThis.hodlTAttr = tAttr;
  globalThis.hodlSanitizeCatalogHtml = hodlSanitizeCatalogHtml;
}

// The content sweep translates the DOM in place by matching normalized text
// against the catalog. The English original of every touched node is cached on
// first sight, so switching between non-English locales never tries to match
// an already-translated string; nodes first rendered in a non-English locale
// (dynamic templates call t() directly) are mapped back through the reverse
// index of every catalog. Skipped subtrees: raw-text and non-rendering
// elements, and anything marked data-i18n-skip.
const hodlI18nOriginals = new WeakMap();
const hodlI18nAttrOriginals = new WeakMap();
let hodlI18nReverse = null;

export function hodlI18nNormalize(text) {
  return String(text ?? "").replace(/\s+/g, " ").trim();
}

// The reverse index maps rendered (sanitized) translations back to their
// English source, so nodes first rendered under a non-English locale can be
// retranslated on the next switch. Text-view entries win; HTML-view entries
// cover the rich blocks.
function hodlI18nReverseIndex() {
  if (!hodlI18nReverse) {
    hodlI18nReverse = new Map();
    for (let catalogs of [hodlLocaleTextCatalogs, hodlLocaleHtmlCatalogs]) {
      for (let catalog of Object.values(catalogs)) {
        for (let [source, translated] of Object.entries(catalog)) {
          if (translated && !hodlI18nReverse.has(translated)) hodlI18nReverse.set(translated, source);
        }
      }
    }
  }
  return hodlI18nReverse;
}

function hodlI18nSourceFor(cache, node, current) {
  let source = cache.get(node);
  if (source === undefined) {
    source = hodlI18nReverseIndex().get(current) ?? current;
    cache.set(node, source);
  }
  return source;
}

function hodlI18nSweepTextNode(node, catalog) {
  let raw = node.nodeValue, current = hodlI18nNormalize(raw);
  if (!current) return;
  let source = hodlI18nSourceFor(hodlI18nOriginals, node, current);
  let next = catalog && catalog[source] ? catalog[source] : source;
  if (current === next) return;
  node.nodeValue = raw.match(/^\s*/)[0] + next + raw.match(/\s*$/)[0];
}

function hodlI18nSweepAttribute(el, attr, catalog) {
  let raw = el.getAttribute(attr);
  if (raw == null) return;
  let current = hodlI18nNormalize(raw);
  if (!current) return;
  let perElement = hodlI18nAttrOriginals.get(el);
  if (!perElement) {
    perElement = {};
    hodlI18nAttrOriginals.set(el, perElement);
  }
  let source = perElement[attr];
  if (source === undefined) {
    source = hodlI18nReverseIndex().get(current) ?? current;
    perElement[attr] = source;
  }
  let next = catalog && catalog[source] ? catalog[source] : source;
  if (current !== next) el.setAttribute(attr, next);
}

// Rich blocks carry inline markup, so the catalog source is the block's HTML
// and the translation replaces innerHTML. The value comes from the sanitized
// HTML view: whatever the committed catalog says, only allowlisted formatting
// reaches the page.
function hodlI18nSweepRich(el, catalog) {
  let source = hodlI18nSourceFor(hodlI18nOriginals, el, hodlI18nNormalize(el.innerHTML));
  let next = catalog && catalog[source] ? catalog[source] : source;
  // Round-trip the candidate through the parser so the comparison matches the
  // browser's own serialization (the sanitizer emits attributes unquoted).
  // The candidate is already sanitized allowlist output, so parsing is safe.
  let probe = el.ownerDocument.createElement("template");
  probe.innerHTML = next;
  if (hodlI18nNormalize(el.innerHTML) !== hodlI18nNormalize(probe.innerHTML)) el.innerHTML = next;
}

export function hodlApplyStaticI18n(root = document) {
  if (typeof document === "undefined" || !document.body) return;
  let textCatalog = hodlLocaleTextCatalogs[hodlLocale] || null;
  let htmlCatalog = hodlLocaleHtmlCatalogs[hodlLocale] || null;
  let walker = document.createTreeWalker(root === document ? document.body : root, NodeFilter.SHOW_TEXT, {
    acceptNode(node) {
      let parent = node.parentElement;
      if (!parent) return NodeFilter.FILTER_REJECT;
      if (/^(SCRIPT|STYLE|NOSCRIPT|PRE|TEXTAREA|TEMPLATE)$/.test(parent.tagName)) return NodeFilter.FILTER_REJECT;
      if (parent.closest("[data-i18n-skip]")) return NodeFilter.FILTER_REJECT;
      return NodeFilter.FILTER_ACCEPT;
    },
  });
  let nodes = [];
  while (walker.nextNode()) nodes.push(walker.currentNode);
  for (let node of nodes) hodlI18nSweepTextNode(node, textCatalog);
  let scope = root === document ? document : root;
  scope.querySelectorAll("[data-i18n-rich]").forEach((el) => hodlI18nSweepRich(el, htmlCatalog));
  scope.querySelectorAll("[aria-label], [placeholder], [title]").forEach((el) => {
    if (el.closest("[data-i18n-skip]")) return;
    for (let attr of ["aria-label", "placeholder", "title"]) hodlI18nSweepAttribute(el, attr, textCatalog);
  });
}

export function hodlReadStoredLocale() {
  try {
    return hodlNormalizeLocale(localStorage.getItem(hodlLocaleStorageKey));
  } catch {
    return "en";
  }
}

function hodlWriteStoredLocale(code) {
  try {
    localStorage.setItem(hodlLocaleStorageKey, code);
  } catch {
  }
}

export function hodlSetLocale(code, persist = true) {
  let next = hodlNormalizeLocale(code);
  hodlLocale = next;
  if (typeof document !== "undefined") {
    document.documentElement.lang = hodlLocaleMeta[next].htmlLang;
    let select = document.getElementById("locale-select");
    if (select && select.value !== next) select.value = next;
  }
  // The listener re-renders the dynamic regions first — their t() calls now
  // produce the new locale — and the sweep then settles everything static
  // without mistaking freshly translated content for English originals.
  if (hodlLocaleListener) hodlLocaleListener(next);
  if (typeof document !== "undefined") hodlApplyStaticI18n();
  if (persist) hodlWriteStoredLocale(next);
}

export function hodlFillLocaleSelect(select) {
  if (!select) return;
  let current = hodlGetLocale();
  select.innerHTML = "";
  for (let code of hodlSelectableLocales()) {
    let option = document.createElement("option");
    option.value = code;
    option.textContent = hodlLocaleMeta[code].short;
    select.appendChild(option);
  }
  select.value = current;
  select.setAttribute("aria-label", t("Language"));
  select.onchange = () => hodlSetLocale(select.value);
}

export function hodlInitLocale(onChange) {
  hodlLocaleListener = typeof onChange === "function" ? onChange : null;
  let stored = hodlReadStoredLocale();
  if (typeof document !== "undefined") hodlFillLocaleSelect(document.getElementById("locale-select"));
  hodlSetLocale(stored, false);
}
