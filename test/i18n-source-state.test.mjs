import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { i18nLocaleStatus, i18nSourceHash } from "../scripts/i18n-common.mjs";
import { markTranslationSources } from "../scripts/i18n-mark.mjs";
import { syncI18nSource } from "../scripts/i18n-sync.mjs";
import { collectRepositoryUnwired, collectUnwiredMarkup } from "../scripts/i18n-wiring.mjs";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const en = JSON.parse(readFileSync(join(root, "src/locales/en.json"), "utf8"));

test("source hashes are SHA-256 of the exact UTF-8 English value", () => {
  assert.equal(i18nSourceHash("hello"), "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
  assert.notEqual(i18nSourceHash("Hello"), i18nSourceHash("hello"));
});

test("locale status separates missing and stale work from invalid sidecars", () => {
  const english = { current: "Current", changed: "New", missing: "Missing" };
  const catalog = { current: "Actual", changed: "Anterior" };
  const sidecar = { current: i18nSourceHash("Current"), changed: i18nSourceHash("Old") };
  assert.deepEqual(i18nLocaleStatus(english, catalog, sidecar), {
    missing: ["missing"],
    stale: ["changed"],
    obsolete: [],
    problems: [],
  });
});

test("one changed English value becomes stale independently in each language", () => {
  const english = { changed: "New", unchanged: "Same" };
  const catalog = { changed: "Traduit", unchanged: "Même" };
  const oldSources = { changed: i18nSourceHash("Old"), unchanged: i18nSourceHash("Same") };
  const currentSources = { changed: i18nSourceHash("New"), unchanged: i18nSourceHash("Same") };

  assert.deepEqual(i18nLocaleStatus(english, catalog, oldSources), {
    missing: [], stale: ["changed"], obsolete: [], problems: [],
  });
  assert.deepEqual(i18nLocaleStatus(english, catalog, currentSources), {
    missing: [], stale: [], obsolete: [], problems: [],
  });
});

test("locale status rejects missing, malformed, and orphaned source records", () => {
  const status = i18nLocaleStatus(
    { good: "Good", noHash: "No hash" },
    { good: "Bien", noHash: "Sin hash", unknown: "Unknown" },
    { good: "bad", orphan: i18nSourceHash("Orphan") },
  );
  assert.deepEqual(status.stale, []);
  assert.deepEqual(status.obsolete, ["unknown"]);
  assert.deepEqual(status.problems, [
    "malformed source hash for good",
    "no source hash for translated key noHash",
    "no source hash for translated key unknown",
    "source hash orphan has no translated catalog value",
  ]);
});

test("removed English keys become valid obsolete work for later cleanup", () => {
  const status = i18nLocaleStatus(
    { current: "Current" },
    { current: "Actual", removed: "Anterior" },
    { current: i18nSourceHash("Current"), removed: i18nSourceHash("Removed") },
  );
  assert.deepEqual(status, { missing: [], stale: [], obsolete: ["removed"], problems: [] });
});

test("marking a translation updates only the named source hashes in catalog order", () => {
  const english = { one: "One", two: "Two" };
  const catalog = { one: "Uno", two: "Dos" };
  const oldOne = i18nSourceHash("Old one");
  const marked = markTranslationSources(english, catalog, { one: oldOne }, ["two"]);
  assert.deepEqual(marked, { one: oldOne, two: i18nSourceHash("Two") });
  assert.deepEqual(i18nLocaleStatus(english, catalog, marked), { missing: [], stale: ["one"], obsolete: [], problems: [] });
});

test("marking refuses unknown or untranslated keys", () => {
  assert.throws(() => markTranslationSources({ one: "One" }, {}, {}, ["one"]), /no value/);
  assert.throws(() => markTranslationSources({ one: "One" }, { one: "Uno" }, {}, ["two"]), /Unknown English key/);
});

test("sync rewrites text, rich HTML, variables, and translated attributes", () => {
  const catalog = {
    plain: "Fish & <chips>",
    rich: "Use <strong>{thing}</strong>",
    aria: "Say \"{thing}\"",
  };
  const source = `<p data-i18n="plain">old</p><p data-i18n-html="rich" data-i18n-vars='{"thing":"now"}'>old</p><input aria-label="old" data-i18n-aria="aria" data-i18n-vars='{"thing":"hello"}'>`;
  const result = syncI18nSource(source, catalog);
  assert.deepEqual(result.problems, []);
  assert.equal(result.output, `<p data-i18n="plain">Fish &amp; &lt;chips&gt;</p><p data-i18n-html="rich" data-i18n-vars='{"thing":"now"}'>Use <strong>now</strong></p><input aria-label="Say &quot;hello&quot;" data-i18n-aria="aria" data-i18n-vars='{"thing":"hello"}'>`);
  assert.deepEqual(syncI18nSource(result.output, catalog).output, result.output);
});

test("sync escapes catalog text before writing a JavaScript template literal", () => {
  const source = "const html = `<p data-i18n=\"key\">old</p>`;";
  const result = syncI18nSource(source, { key: "`${value}` \\ path" }, { javascriptTemplate: true });
  assert.deepEqual(result.problems, []);
  assert.equal(result.output, "const html = `<p data-i18n=\"key\">\\`\\${value}\\` \\\\ path</p>`;");
  assert.doesNotThrow(() => new Function(result.output));
});

test("sync rejects unknown keys and missing attribute fallbacks without modifying input", () => {
  const source = `<p data-i18n="unknown">old</p><input data-i18n-placeholder="known">`;
  const result = syncI18nSource(source, { known: "Known" });
  assert.equal(result.output, source);
  assert.equal(result.problems.length, 2);
  assert.match(result.problems[0], /unknown English key unknown/);
  assert.match(result.problems[1], /needs an existing placeholder fallback/);
});

test("sync validates immediate and deferred translation helpers", () => {
  const source = `hodlT("rich"); hodlTText("plain"); hodlTAttr("attribute"); hodlNote("note"); hodlError("error"); hodlTText("unknown")`;
  const result = syncI18nSource(source, { rich: "Rich", plain: "Plain", attribute: "Attribute", note: "Note", error: "Error" });
  assert.deepEqual(result.references, ["attribute", "error", "note", "plain", "rich", "unknown"]);
  assert.deepEqual(result.problems, ["source: hodlT references unknown English key unknown"]);
});

test("sync validates every statically visible ternary branch", () => {
  const source = [
    `hodlTText(flag ? "known.one" : nested ? "known.two" : "typo.branch")`,
    `hodlTText(runtimeKey)`,
    `hodlTText(kind === "condition.with.dots" ? "known.one" : "known.two")`,
  ].join("; ");
  const catalog = { "known.one": "One", "known.two": "Two" };
  const result = syncI18nSource(source, catalog);
  assert.deepEqual(result.references, ["known.one", "known.two", "typo.branch"]);
  assert.equal(result.unvalidatedCalls.length, 1);
  assert.match(result.unvalidatedCalls[0], /runtimeKey/);
  assert.deepEqual(result.problems, ["source: hodlT references unknown English key typo.branch"]);

});

test("sync rejects dynamic prefixes that cannot prove every complete key", () => {
  const catalog = { "known.one": "One", "known.two": "Two" };
  for (const source of [`hodlT("known." + id)`, "hodlTAttr(`known.${id}`)"]) {
    const result = syncI18nSource(source, catalog);
    assert.deepEqual(result.problems, ["source: hodlT dynamic key prefix must enumerate complete English keys: known."]);
  }
});

test("the committed sources contain only known literal references and generated fallbacks", () => {
  for (const [file, javascriptTemplate] of [["src/index.html", false], ["src/js/app.js", true]]) {
    const source = readFileSync(join(root, file), "utf8");
    const result = syncI18nSource(source, en, { fileName: file, javascriptTemplate });
    assert.deepEqual(result.problems, []);
    assert.equal(result.output, source, `${file}: run npm run i18n:sync`);
    assert.ok(result.references.length > 0, file);
  }
});

test("computed-key call sites enumerate every current English alternative", () => {
  const source = readFileSync(join(root, "src/js/app.js"), "utf8");
  for (const key of ["dice.fairness.verdict.fair", "note.importedDetectedPrivate", "cards.meta.hashedReadyOne", "note.numberBaseEntropy"]) {
    const withoutKey = { ...en };
    delete withoutKey[key];
    const result = syncI18nSource(source, withoutKey, { fileName: "src/js/app.js", javascriptTemplate: true });
    assert.ok(result.problems.some((problem) => problem.includes(key)), `${key} was not statically validated`);
  }
});

test("the wiring inventory notices new hardcoded text and attributes", () => {
  assert.deepEqual(collectUnwiredMarkup(`<p>New words</p><input placeholder="Type here"><p data-i18n="known">Known</p>`, "fixture"), [
    "fixture:input:@placeholder:Type here",
    "fixture:p:text:New words",
  ]);
});

test("the committed legacy wiring inventory is exact", () => {
  const baseline = JSON.parse(readFileSync(join(root, "scripts/i18n-unwired.json"), "utf8"));
  assert.deepEqual(collectRepositoryUnwired(), baseline);
});
