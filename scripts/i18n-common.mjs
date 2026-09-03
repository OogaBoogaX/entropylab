import { createHash } from "node:crypto";

export const i18nLocaleCodes = Object.freeze(["es", "pt", "fr", "de"]);

export function i18nSourceHash(value) {
  if (typeof value !== "string") throw new TypeError("An English catalog value must be a string.");
  return createHash("sha256").update(value, "utf8").digest("hex");
}

export function i18nLocaleStatus(english, catalog, sidecar) {
  const missing = [];
  const stale = [];
  const obsolete = [];
  const problems = [];

  for (const key of Object.keys(english)) {
    if (!Object.hasOwn(catalog, key)) missing.push(key);
  }

  for (const key of Object.keys(catalog)) {
    const current = Object.hasOwn(english, key);
    if (!current) obsolete.push(key);
    if (!Object.hasOwn(sidecar, key)) {
      problems.push(`no source hash for translated key ${key}`);
      continue;
    }
    const hash = sidecar[key];
    if (typeof hash !== "string" || !/^[0-9a-f]{64}$/.test(hash)) {
      problems.push(`malformed source hash for ${key}`);
      continue;
    }
    if (current && hash !== i18nSourceHash(english[key])) stale.push(key);
  }

  for (const key of Object.keys(sidecar)) {
    if (!Object.hasOwn(catalog, key)) problems.push(`source hash ${key} has no translated catalog value`);
  }

  return { missing, stale, obsolete, problems };
}
