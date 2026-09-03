import en from "../locales/en.json" with { type: "json" };
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
// sinks and HTML sinks use separate sanitized views so neither has to guess its
// output context or re-sanitize after placeholder substitution.
const hodlLocaleHtmlCatalogs = { en: hodlSanitizeCatalog(en), es: hodlSanitizeCatalog(es), pt: hodlSanitizeCatalog(pt), fr: hodlSanitizeCatalog(fr), de: hodlSanitizeCatalog(de) };
const hodlLocaleTextCatalogs = { en: hodlSanitizeTextCatalog(en), es: hodlSanitizeTextCatalog(es), pt: hodlSanitizeTextCatalog(pt), fr: hodlSanitizeTextCatalog(fr), de: hodlSanitizeTextCatalog(de) };
const hodlStaleLocaleKeys = globalThis.__entropyLabStaleTranslations || {};
let hodlLocale = "en";
let hodlLocaleListener = null;

function hodlTranslationIsStale(code, key) {
  return Array.isArray(hodlStaleLocaleKeys[code]) && hodlStaleLocaleKeys[code].includes(key);
}

export function hodlNormalizeLocale(code) {
  return hodlLocaleCodes.includes(code) ? code : "en";
}

export function hodlLocaleIsComplete(code) {
  code = hodlNormalizeLocale(code);
  let catalog = hodlLocaleTextCatalogs[hodlNormalizeLocale(code)];
  if (!catalog) return false;
  return Object.keys(en).every((key) => typeof catalog[key] === "string" && catalog[key].length > 0 && !hodlTranslationIsStale(code, key));
}

export function hodlCompleteLocales() {
  // Kept under its original name for callers from the first i18n release.
  // A partial catalog remains selectable because t() falls back per key.
  return hodlLocaleCodes;
}

export function hodlGetLocale() {
  return hodlLocale;
}

function hodlCatalogValue(catalogs, key) {
  let catalog = catalogs[hodlLocale] || catalogs.en;
  let text = catalog[key];
  if (typeof text !== "string" || !text || hodlTranslationIsStale(hodlLocale, key)) text = catalogs.en[key];
  return typeof text === "string" ? text : key;
}

function hodlInterpolate(text, vars, render) {
  if (!vars) return text;
  return text.replace(/\{(\w+)\}/g, (_, name) => (vars[name] == null ? `{${name}}` : render(vars[name])));
}

// Plain strings are only for DOM textContent/setAttribute and other non-HTML
// consumers. Placeholder values stay byte-faithful because the sink does not
// parse them.
export function t(key, vars) {
  return hodlInterpolate(hodlCatalogValue(hodlLocaleTextCatalogs, key), vars, String);
}

// HTML strings retain catalog-authored allowlisted markup. Placeholder values
// are encoded as text before insertion and are never passed back through the
// allowlist, so they cannot introduce even an otherwise allowed element.
export function tHtml(key, vars) {
  return hodlInterpolate(hodlCatalogValue(hodlLocaleHtmlCatalogs, key), vars, hodlEscapeHtmlText);
}

export function tAttr(key, vars) {
  return hodlEscapeAttribute(t(key, vars));
}
if (typeof globalThis !== "undefined") {
  globalThis.hodlT = tHtml;
  globalThis.hodlTText = t;
  globalThis.hodlTAttr = tAttr;
  globalThis.hodlSanitizeCatalogHtml = hodlSanitizeCatalogHtml;
}

export function hodlApplyStaticI18n(root = document) {
  root.querySelectorAll("[data-i18n]").forEach((el) => {
    el.textContent = t(el.getAttribute("data-i18n"), hodlI18nVars(el));
  });
  root.querySelectorAll("[data-i18n-html]").forEach((el) => {
    el.innerHTML = tHtml(el.getAttribute("data-i18n-html"), hodlI18nVars(el));
  });
  root.querySelectorAll("[data-i18n-aria]").forEach((el) => {
    el.setAttribute("aria-label", t(el.getAttribute("data-i18n-aria"), hodlI18nVars(el)));
  });
  root.querySelectorAll("[data-i18n-placeholder]").forEach((el) => {
    el.setAttribute("placeholder", t(el.getAttribute("data-i18n-placeholder"), hodlI18nVars(el)));
  });
  root.querySelectorAll("[data-i18n-title]").forEach((el) => {
    el.setAttribute("title", t(el.getAttribute("data-i18n-title"), hodlI18nVars(el)));
  });
  root.querySelectorAll("[data-i18n-alt]").forEach((el) => {
    el.setAttribute("alt", t(el.getAttribute("data-i18n-alt"), hodlI18nVars(el)));
  });
}

function hodlI18nVars(el) {
  let raw = el.getAttribute("data-i18n-vars");
  if (!raw) return undefined;
  try {
    return JSON.parse(raw);
  } catch {
    return undefined;
  }
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
    hodlApplyStaticI18n();
  }
  if (persist) hodlWriteStoredLocale(next);
  if (hodlLocaleListener) hodlLocaleListener(next);
}

export function hodlFillLocaleSelect(select) {
  if (!select) return;
  let current = hodlGetLocale();
  select.innerHTML = "";
  for (let code of hodlCompleteLocales()) {
    let option = document.createElement("option");
    option.value = code;
    option.textContent = hodlLocaleMeta[code].short;
    select.appendChild(option);
  }
  select.value = current;
  select.setAttribute("aria-label", t("locale.label"));
  select.onchange = () => hodlSetLocale(select.value);
}

export function hodlInitLocale(onChange) {
  hodlLocaleListener = typeof onChange === "function" ? onChange : null;
  let stored = hodlReadStoredLocale();
  if (typeof document !== "undefined") hodlFillLocaleSelect(document.getElementById("locale-select"));
  hodlSetLocale(stored, false);
}
