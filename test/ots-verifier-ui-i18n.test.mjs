// Verify card i18n wiring — the Verify workspace ships in every build, so its
// visible text must go through t() like every other module's. These tests hook
// on source structure and English behaviour, never on translated copy.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import { formatResult, formatError } from "../src/js/ots-verifier-ui.js";
import { OtsBudgetError } from "../src/js/ots-parser.js";

const SOURCE = readFileSync(new URL("../src/js/ots-verifier-ui.js", import.meta.url), "utf8");

// Result and status codes are values, not copy: they stay untranslated.
const CODES = new Set([
  "MATCHES_SUPPLIED_HEADER",
  "INVALID",
  "HEADER_REQUIRED",
  "PENDING",
  "INCOMPLETE",
  "UNSUPPORTED",
  "ERROR",
  "CANCELLED",
]);

test("ots-verifier-ui imports t from ./i18n.js", () => {
  assert.match(SOURCE, /import\s*\{\s*t\s*\}\s*from\s*"\.\/i18n\.js";/);
});

test("every headline/body/text property is a t() call, a join, a variable, \"\" or a code", () => {
  const bad = [];
  for (const match of SOURCE.matchAll(/\b(headline|body|text):[ \t]*"([^"\\]*)"/g)) {
    const [, prop, value] = match;
    if (value === "" || CODES.has(value)) continue;
    bad.push(`${prop}: "${value}"`);
  }
  assert.deepEqual(bad, [], `untranslated property values: ${bad.join(", ")}`);
});

test("no headline/body/text property is a template literal", () => {
  assert.doesNotMatch(SOURCE, /\b(headline|body|text):[ \t]*`/);
});

test("no textContent assignment is a bare string or a template literal", () => {
  const bad = [];
  for (const match of SOURCE.matchAll(/textContent[ \t]*=[ \t]*([^;\n]*)/g)) {
    const value = match[1].trim();
    if (value.startsWith('"') && value !== '""') bad.push(value);
    if (value.startsWith("`")) bad.push(value);
  }
  assert.deepEqual(bad, [], `untranslated textContent: ${bad.join(", ")}`);
});

test("formatResult renders the English PENDING headline through t()", () => {
  assert.equal(
    formatResult({ result: "PENDING", paths: [], summary: {} }).headline,
    "PENDING — NO COMPLETED BITCOIN ATTESTATION",
  );
});

test("formatError renders the English resource-limit headline with the code", () => {
  const err = new OtsBudgetError("too-many-ops", "more than 1024 op nodes");
  assert.equal(formatError(err).headline, "Resource limit: too-many-ops");
});
