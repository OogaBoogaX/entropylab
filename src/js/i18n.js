import en from "../locales/en.json" with { type: "json" };
import es from "../locales/es.json" with { type: "json" };
import pt from "../locales/pt.json" with { type: "json" };
import fr from "../locales/fr.json" with { type: "json" };
import de from "../locales/de.json" with { type: "json" };
import { hodlSanitizeCatalog, hodlSanitizeCatalogHtml } from "./i18n-sanitize.js";

export const hodlLocaleCodes = Object.freeze(["en", "es", "pt", "fr", "de"]);
export const hodlLocaleStorageKey = "entropylab-locale";
export const hodlLocaleMeta = Object.freeze({
  en: { htmlLang: "en", label: "English", short: "EN" },
  es: { htmlLang: "es", label: "Español", short: "ES" },
  pt: { htmlLang: "pt-BR", label: "Português", short: "PT" },
  fr: { htmlLang: "fr", label: "Français", short: "FR" },
  de: { htmlLang: "de", label: "Deutsch", short: "DE" },
});

// Every catalog is rebuilt from the markup allowlist once, here, so nothing
// downstream — t(), the data-i18n-html branch, or a template that interpolates
// hodlT() into innerHTML — can ever see a raw catalog value.
const hodlLocaleCatalogs = { en: hodlSanitizeCatalog(en), es: hodlSanitizeCatalog(es), pt: hodlSanitizeCatalog(pt), fr: hodlSanitizeCatalog(fr), de: hodlSanitizeCatalog(de) };
let hodlLocale = "en";
let hodlLocaleListener = null;

export function hodlNormalizeLocale(code) {
  return hodlLocaleCodes.includes(code) ? code : "en";
}

export function hodlLocaleIsComplete(code) {
  let catalog = hodlLocaleCatalogs[hodlNormalizeLocale(code)];
  if (!catalog) return false;
  return Object.keys(en).every((key) => typeof catalog[key] === "string" && catalog[key].length > 0);
}

export function hodlCompleteLocales() {
  return hodlLocaleCodes.filter((code) => code === "en" || hodlLocaleIsComplete(code));
}

export function hodlGetLocale() {
  return hodlLocale;
}

export function t(key, vars) {
  let catalog = hodlLocaleCatalogs[hodlLocale] || hodlLocaleCatalogs.en;
  let text = catalog[key];
  if (typeof text !== "string" || !text) text = hodlLocaleCatalogs.en[key];
  if (typeof text !== "string") return key;
  if (!vars) return text;
  return text.replace(/\{(\w+)\}/g, (_, name) => (vars[name] == null ? `{${name}}` : String(vars[name])));
}
if (typeof globalThis !== "undefined") {
  globalThis.hodlT = t;
  globalThis.hodlSanitizeCatalogHtml = hodlSanitizeCatalogHtml;
}

export function hodlApplyStaticI18n(root = document) {
  root.querySelectorAll("[data-i18n]").forEach((el) => {
    el.textContent = t(el.getAttribute("data-i18n"), hodlI18nVars(el));
  });
  root.querySelectorAll("[data-i18n-html]").forEach((el) => {
    el.innerHTML = t(el.getAttribute("data-i18n-html"), hodlI18nVars(el));
  });
  root.querySelectorAll("[data-i18n-aria]").forEach((el) => {
    el.setAttribute("aria-label", t(el.getAttribute("data-i18n-aria"), hodlI18nVars(el)));
  });
  root.querySelectorAll("[data-i18n-placeholder]").forEach((el) => {
    el.setAttribute("placeholder", t(el.getAttribute("data-i18n-placeholder"), hodlI18nVars(el)));
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
  if (!hodlLocaleIsComplete(next)) next = "en";
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
