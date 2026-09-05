// The catalog validator is the merge gate for locale changes: anything the
// runtime sanitizer could not render byte-faithfully must fail here first.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { catalogProblems, hashSource, sidecarProblems, sourceMarkupProblems, valueProblems } from "../scripts/i18n-validate.mjs";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");

const valid = (key, value) => assert.deepEqual(valueProblems(key, value), []);
const invalid = (key, value, fragment) => {
  const problems = valueProblems(key, value);
  assert.ok(problems.length > 0, `expected a problem for ${JSON.stringify(value)}`);
  if (fragment) assert.ok(problems.some((problem) => problem.includes(fragment)), `expected "${fragment}" in ${JSON.stringify(problems)}`);
};

test("honest translations pass", () => {
  valid("Save watch-only sheet", "Guardar hoja de solo lectura");
  valid("{n} words", "{n} palabras");
  valid("Fair dice: <strong>{n}</strong> sides", "Dados justos: <strong>{n}</strong> caras");
  valid(
    "Ian Coleman BIP39: <a href=\"https://github.com/iancoleman/bip39\" target=\"_blank\" rel=\"noopener noreferrer\">github.com/iancoleman/bip39</a>",
    "BIP39 de Ian Coleman: <a href=\"https://github.com/iancoleman/bip39\" target=\"_blank\" rel=\"noopener noreferrer\">github.com/iancoleman/bip39</a>",
  );
  valid("D++ D8 &amp; D16 method", "Método D++ D8 &amp; D16");
  valid("Raw & unparsed ampersand", "Y sin codificar & así");
  // A translation may drop the source's link; it just cannot retarget one.
  valid("See <a href=\"https://github.com/iancoleman/bip39\" target=\"_blank\" rel=\"noopener noreferrer\">BIP39</a> docs", "Ver la documentación de BIP39");
});

test("rejects empty and non-string values", () => {
  invalid("k", "", "empty translation");
  invalid("k", "   ", "empty translation");
  invalid("k", null, "not a string");
  invalid("k", 42, "not a string");
});

test("rejects bidi overrides, zero-width, and control characters", () => {
  invalid("k", "tran\u202Eslated", "zero-width");
  invalid("k", "tran​slated", "zero-width");
  invalid("k", "translated", "control");
});

test("rejects placeholder drift", () => {
  invalid("{n} words", "palabras", "placeholders");
  invalid("{n} words", "{count} palabras", "placeholders");
  invalid("{n} words", "{n} {extra} palabras", "placeholders");
});

test("rejects markup outside the allowlist and unbalanced nesting", () => {
  invalid("k", "<script>alert(1)</script>", "outside the allowlist");
  invalid("k", "<strong onclick=x>bold</strong>", "outside the allowlist");
  invalid("k", "<em>unclosed", "unclosed");
  invalid("k", "stray</em>", "unbalanced");
  invalid("k", "<strong><em>crossed</strong></em>", "unbalanced");
  invalid("k", "<span class=\"other\">x</span>", "outside the allowlist");
});

test("anchors can never be invented or retargeted", () => {
  const key = "See <a href=\"https://github.com/iancoleman/bip39\" target=\"_blank\" rel=\"noopener noreferrer\">BIP39</a>";
  invalid(key, "Ver <a href=\"https://evil.example/bip39\" target=\"_blank\" rel=\"noopener noreferrer\">BIP39</a>", "outside the allowlist");
  invalid(key, "Ver <a href=\"https://github.com/pointbiz/bitaddress.org\" target=\"_blank\" rel=\"noopener noreferrer\">BIP39</a>", "does not match a link");
  invalid("no link here", "Ver <a href=\"https://github.com/iancoleman/bip39\" target=\"_blank\" rel=\"noopener noreferrer\">BIP39</a>", "does not match a link");
});

test("rejects non-canonical character references and executable schemes", () => {
  invalid("k", "one&nbsp;two", "non-canonical");
  invalid("k", "one&#8203;two", "non-canonical");
  invalid("k", "one&#x202E;two", "non-canonical");
  invalid("k", "run javascript:alert(1)", "scheme");
  invalid("k", "run data:text/html,x", "scheme");
});

test("catalogProblems prefixes the offending key", () => {
  const problems = catalogProblems({ "{n} words": "palabras" });
  assert.equal(problems.length, 1);
  assert.match(problems[0], /\{n\} words.*placeholders/);
});

test("source markup tripwire: sources may only carry sanitizer-table forms", () => {
  assert.deepEqual(sourceMarkupProblems("Plain <code>x</code> and <strong>y</strong>"), []);
  const problems = sourceMarkupProblems("New <a href=\"https://unlisted.example/\" target=\"_blank\" rel=\"noopener noreferrer\">link</a>");
  assert.equal(problems.length, 1);
  assert.match(problems[0], /extend hodlCatalogAllowedTags/);
});

test("hashSource is the provenance hash the sidecar records", () => {
  // The well-known sha256 test vector pins the encoding (utf8, hex).
  assert.equal(hashSource("abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  assert.match(hashSource("Save"), /^[0-9a-f]{64}$/);
});

test("sidecarProblems: consistent catalog and sidecar are clean", () => {
  const catalog = { Save: "Guardar", "{n} words": "{n} palabras" };
  const sidecar = Object.fromEntries(Object.keys(catalog).map((k) => [k, hashSource(k)]));
  assert.deepEqual(sidecarProblems(catalog, sidecar), { invalid: [], drift: [] });
});

test("sidecarProblems: malformed and mismatched hashes are invalid", () => {
  const catalog = { Save: "Guardar" };
  assert.deepEqual(sidecarProblems(catalog, { Save: "not-a-hash" }).invalid.length, 1);
  assert.match(sidecarProblems(catalog, { Save: "0".repeat(64) }).invalid[0], /does not match the English key/);
});

test("sidecarProblems: missing and extra hashes are drift, not invalid", () => {
  const catalog = { Save: "Guardar", Cancel: "Cancelar" };
  const onlySave = { Save: hashSource("Save") };
  const plusExtra = { ...onlySave, Cancel: hashSource("Cancel"), Ghost: hashSource("Ghost") };
  const missing = sidecarProblems(catalog, onlySave);
  assert.equal(missing.invalid.length, 0);
  assert.equal(missing.drift.length, 1);
  assert.match(missing.drift[0], /Cancel/);
  const extra = sidecarProblems(catalog, plusExtra);
  assert.equal(extra.invalid.length, 0);
  assert.equal(extra.drift.length, 1);
  assert.match(extra.drift[0], /Ghost/);
});

test("the CLI gates catalog files", () => {
  const dir = mkdtempSync(join(tmpdir(), "entropylab-i18n-validate-"));
  try {
    const good = join(dir, "good.json");
    const bad = join(dir, "bad.json");
    writeFileSync(good, JSON.stringify({ "Save": "Guardar" }));
    writeFileSync(bad, JSON.stringify({ "Save": "<img src=x onerror=alert(1)>" }));
    execFileSync(process.execPath, [join(root, "scripts/i18n-validate.mjs"), good], { stdio: "pipe" });
    assert.throws(
      () => execFileSync(process.execPath, [join(root, "scripts/i18n-validate.mjs"), bad], { stdio: "pipe" }),
      /Command failed/,
      "an invalid catalog must exit non-zero",
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
