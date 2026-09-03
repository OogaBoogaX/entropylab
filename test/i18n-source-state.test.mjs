import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { i18nLocaleStatus, i18nSourceHash } from "../scripts/i18n-common.mjs";
import { markTranslationSources } from "../scripts/i18n-mark.mjs";
import { i18nMarkupTokens, i18nSourceFiles, repositoryUiSourceFiles, syncI18nSource } from "../scripts/i18n-sync.mjs";
import { collectAnnotatedShellFragments, collectRepositoryUnwired, collectUnannotatedStaticShells, collectUnwiredMarkup, i18nRuntimeAttribute } from "../scripts/i18n-wiring.mjs";

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

test("sync requires static variable bindings to match catalog placeholders exactly", () => {
  const catalog = { greeting: "Hello {name}" };
  const missing = `<p data-i18n="greeting">Hello name</p>`;
  const extra = `<p data-i18n="greeting" data-i18n-vars='{"name":"Ada","unused":"x"}'>Hello Ada</p>`;
  assert.match(syncI18nSource(missing, catalog).problems[0], /expects variables \[name\] but received \[\]/);
  assert.match(syncI18nSource(extra, catalog).problems[0], /expects variables \[name\] but received \[name, unused\]/);
});

test("the committed sources contain only known literal references and generated fallbacks", () => {
  const files = i18nSourceFiles();
  assert.ok(files.includes("src/index.html"));
  assert.ok(files.includes("src/js/app.js"));
  for (const file of files) {
    const source = readFileSync(join(root, file), "utf8");
    const result = syncI18nSource(source, en, { fileName: file, javascriptTemplate: file.endsWith(".js") });
    assert.deepEqual(result.problems, []);
    assert.equal(result.output, source, `${file}: run npm run i18n:sync`);
    assert.ok(result.references.length > 0, file);
  }
});

test("source discovery follows new and removed nested UI files without an inventory", () => {
  const directory = mkdtempSync(join(tmpdir(), "entropylab-i18n-sources-"));
  try {
    mkdirSync(join(directory, "src", "feature"), { recursive: true });
    writeFileSync(join(directory, "src", "index.html"), "<main data-i18n=\"heading\">Heading</main>");
    writeFileSync(join(directory, "src", "feature", "panel.js"), "root.innerHTML = `<p data-i18n=\"body\">Body</p>`;");
    writeFileSync(join(directory, "src", "feature", "plain.js"), "export const value = 1;");
    writeFileSync(join(directory, "src", "feature", "payload-wasm-b64.js"), "hodlT(\"must.not.scan.generated.payload\")");
    assert.deepEqual(repositoryUiSourceFiles(directory), ["src/feature/panel.js", "src/feature/plain.js", "src/index.html"]);
    assert.deepEqual(i18nSourceFiles(directory), ["src/feature/panel.js", "src/index.html"]);
  } finally {
    rmSync(directory, { recursive: true, force: true });
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

test("the wiring scan notices new hardcoded text and attributes", () => {
  assert.deepEqual(collectUnwiredMarkup(`<p>New words</p><input placeholder="Type here"><p data-i18n="known">Known</p>`, "fixture"), [
    "fixture:input:@placeholder:Type here",
    "fixture:p:text:New words",
  ]);
});

test("runtime ownership is source-local and cannot hide source content", () => {
  assert.deepEqual(collectUnwiredMarkup(`<p id="live" ${i18nRuntimeAttribute}></p>`, "fixture"), []);
  assert.ok(collectUnwiredMarkup(`<p id="live" ${i18nRuntimeAttribute}>Hidden copy</p>`, "fixture").some((entry) => entry.includes("contains source text")));
  const hidden = collectUnwiredMarkup(`<section id="too-wide" ${i18nRuntimeAttribute}><button>Hidden static action</button></section>`, "fixture");
  assert.ok(hidden.some((entry) => entry.includes("contains static markup")));
  const conflicting = collectUnwiredMarkup(`<p id="live" ${i18nRuntimeAttribute} data-i18n="key">Fallback</p>`, "fixture");
  assert.ok(conflicting.some((entry) => entry.includes("cannot also carry a translation marker")));
  assert.ok(collectUnwiredMarkup(`<p ${i18nRuntimeAttribute}>Fallback</p>`, "fixture").some((entry) => entry.includes("needs an id")));
  assert.ok(collectUnwiredMarkup(`<input id="live" ${i18nRuntimeAttribute}>`, "fixture").some((entry) => entry.includes("cannot be self-closing")));
});

test("static-shell regions are discovered by annotation rather than filename", () => {
  const source = `const root = document.querySelector("main"); /* i18n-static-shell */ root.innerHTML = \`<p>New words</p>\`;`;
  const fragments = collectAnnotatedShellFragments(source, "src/js/new-feature.js");
  assert.equal(fragments.length, 1);
  assert.deepEqual(collectUnwiredMarkup(fragments[0].markup, fragments[0].label), ["src/js/new-feature.js#static-shell-1:p:text:New words"]);
  assert.throws(() => collectAnnotatedShellFragments(`/* i18n-static-shell */ const copy = \`<p>Bypass</p>\`;`, "bad.js"), /must immediately annotate/);
  assert.throws(() => collectAnnotatedShellFragments(`/* i18n-static-shell */ root.innerHTML = \`<p>${"${copy}"}</p>\`;`, "bad.js"), /cannot contain interpolation/);
  assert.throws(() => collectAnnotatedShellFragments("/* i18n-static-shell */ root.innerHTML = `<p>Never closed", "bad.js"), /unterminated/);
});

test("new static innerHTML assignments cannot opt out of shell wiring", () => {
  assert.deepEqual(collectUnannotatedStaticShells("root.innerHTML = `<p>Bypass</p>`;", "new.js"), [
    "new.js:1: static innerHTML literal needs an immediate /* i18n-static-shell */ annotation",
  ]);
  assert.deepEqual(collectUnannotatedStaticShells("/* i18n-static-shell */ root.innerHTML = `<p>Checked</p>`;", "new.js"), []);
  assert.deepEqual(collectUnannotatedStaticShells("root.innerHTML = `<p>${runtime}</p>`;", "runtime.js"), []);
  assert.deepEqual(collectUnannotatedStaticShells("root.innerHTML = '';", "clear.js"), []);
  assert.ok(collectUnannotatedStaticShells("root.innerHTML = '<p>Bypass</p>';", "quoted.js").length);
  assert.ok(collectUnannotatedStaticShells('root.innerHTML = ("<p>Parenthesized bypass</p>");', "parenthesized.js").length);
  assert.ok(collectUnannotatedStaticShells('root.innerHTML = "<p>Leading literal</p>" + runtime;', "concatenated.js").length);
  assert.ok(collectUnannotatedStaticShells('root.innerHTML = runtime + "<p>Trailing literal bypass</p>";', "trailing-concatenated.js").length);
  assert.ok(collectUnannotatedStaticShells('root.outerHTML = "<p>Outer bypass</p>";', "outer.js").length);
  assert.ok(collectUnannotatedStaticShells('root.insertAdjacentHTML("beforeend", "<p>Adjacent bypass</p>");', "adjacent.js").length);
  assert.deepEqual(collectUnannotatedStaticShells('root.insertAdjacentHTML("beforeend", `<p>${runtime}</p>`);', "adjacent-runtime.js"), []);
});

test("wired elements can be added and removed without updating an element inventory", () => {
  const catalog = { existing: "Existing", added: "Added" };
  for (const source of [
    `<section><p data-i18n="existing">Existing</p></section>`,
    `<section><p data-i18n="existing">Existing</p><button data-i18n="added">Added</button></section>`,
    `<section></section>`,
  ]) {
    assert.deepEqual(collectUnwiredMarkup(source, "fixture"), []);
    assert.deepEqual(syncI18nSource(source, catalog).problems, []);
  }
});

test("the committed sources have no unwired static-shell text", () => {
  assert.deepEqual(collectRepositoryUnwired(), []);
});

test("plain-text i18n markers never own child elements", () => {
  for (const file of i18nSourceFiles()) {
    const stack = [];
    const problems = [];
    for (const token of i18nMarkupTokens(readFileSync(join(root, file), "utf8"))) {
      if (token.closing) {
        for (let index = stack.length - 1; index >= 0; index -= 1) {
          const frame = stack.pop();
          if (frame.name === token.name) break;
        }
        continue;
      }
      const owner = stack.findLast((frame) => frame.key);
      if (owner) problems.push(`${owner.key} contains <${token.name}>`);
      if (!token.selfClosing) stack.push({ name: token.name, key: token.attributes.get("data-i18n")?.value ?? "" });
    }
    assert.deepEqual(problems, [], file);
  }
});

test("runtime-owned outputs are discovered from source instead of a permanent id list", () => {
  const tokens = i18nMarkupTokens(readFileSync(join(root, "src/js/app.js"), "utf8"));
  const runtime = tokens.filter((token) => token.attributes.has(i18nRuntimeAttribute));
  assert.ok(runtime.length > 0);
  for (const token of runtime) {
    const id = token.attributes.get("id")?.value;
    assert.ok(id, `${token.name} runtime boundary has no id`);
    assert.equal([...token.attributes.keys()].some((name) => name === "data-i18n" || name.startsWith("data-i18n-")), false, id);
  }
});
