// The catalog sanitizer is the boundary between translated text and the DOM:
// whatever a catalog says, only allowlisted markup can reach innerHTML.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import {
  hodlCatalogAllowedTags,
  hodlCatalogHasMarkup,
  hodlCatalogTokens,
  hodlSanitizeCatalog,
  hodlSanitizeCatalogHtml,
} from "../src/js/i18n-sanitize.js";
import { t, tAttr } from "../src/js/i18n.js";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const locales = ["en", "es", "pt", "fr", "de"];
const readLocale = (code) => JSON.parse(readFileSync(join(root, "src/locales", `${code}.json`), "utf8"));

test("plain text passes through byte for byte, including a bare angle bracket", () => {
  for (const value of ["Save entry", "A multipath step like <0;1> must be the last trailing path step.", "5 > 3 and 3 < 5", "Fish & chips", ""]) {
    assert.equal(hodlCatalogHasMarkup(value), false);
    assert.equal(hodlSanitizeCatalogHtml(value), value);
  }
});

test("allowlisted markup survives exactly", () => {
  const value = 'Paste <span class="mono">[fingerprint/48h/0h/0h/2h]xpub…</span> and <strong>Derive</strong> or <em>wait</em>, see <code>m = 0</code>. <a href="entropylab.html" download="entropylab.html">Download EntropyLab</a>';
  assert.equal(hodlSanitizeCatalogHtml(value), value);
});

test("every shape of executable or foreign markup is emitted as visible text", () => {
  const cases = {
    '<img src=x onerror="alert(1)">hi': "&lt;img src=x onerror=\"alert(1)\"&gt;hi",
    "<script>alert(1)</script>": "&lt;script&gt;alert(1)&lt;/script&gt;",
    // A rejected open tag leaves its close tag with nothing to close; like an
    // HTML parser, the stray close is dropped rather than rendered.
    '<span class="mono" onclick="alert(1)">x</span>': "&lt;span class=\"mono\" onclick=\"alert(1)\"&gt;x",
    '<span class="other">x</span>': "&lt;span class=\"other\"&gt;x",
    '<a href="javascript:alert(1)">x</a>': "&lt;a href=\"javascript:alert(1)\"&gt;x",
    '<a href="entropylab.html" download="evil.html">x</a>': "&lt;a href=\"entropylab.html\" download=\"evil.html\"&gt;x",
    "<b>bold</b>": "&lt;b&gt;bold&lt;/b&gt;",
    "<!-- comment --><strong>x</strong>": "&lt;!-- comment --&gt;<strong>x</strong>",
    "<?xml ?><em>x</em>": "&lt;?xml ?&gt;<em>x</em>",
    "<strong>unterminated": "<strong>unterminated</strong>",
    "<strong>text <span class=\"mono\">y</strong> z</span>": '<strong>text <span class="mono">y</span></strong> z',
    "</strong>stray close": "stray close",
    "<STRONG>upper</STRONG>": "<strong>upper</strong>",
    '<span class="mono" class="mono">dup</span>': '<span class="mono">dup</span>',
    "<strong": "&lt;strong",
    "a < b <strong>c</strong>": "a &lt; b <strong>c</strong>",
  };
  for (const [input, expected] of Object.entries(cases)) assert.equal(hodlSanitizeCatalogHtml(input), expected, input);
});

test("the output alphabet is closed: only allowlisted tags and their fixed attributes can appear", () => {
  const hostile = [
    "<svg><script>alert(1)</script></svg>",
    '<span class="mono"><img src=x onerror=alert(1)></span>',
    "<a href=\"entropylab.html\" download=\"entropylab.html\" onmouseover=\"alert(1)\">x</a>",
    "<span class=mono>unquoted</span>",
    "<strong/>self",
    "<strong >spaced</strong >",
    "<strong\nnewline>x</strong>",
  ];
  const tagPattern = /<(\/?)([a-z]+)((?:\s[a-z]+="[^"]*")*)>/g;
  for (const input of hostile) {
    const output = hodlSanitizeCatalogHtml(input);
    let stripped = output.replace(tagPattern, (match, closing, name, attrs) => {
      assert.ok(name in hodlCatalogAllowedTags, `${input} -> unexpected tag ${match}`);
      for (const [, attribute, value] of attrs.matchAll(/\s([a-z]+)="([^"]*)"/g)) {
        assert.equal(hodlCatalogAllowedTags[name][attribute], value, `${input} -> unexpected attribute ${attribute}`);
      }
      return "";
    });
    assert.doesNotMatch(stripped, /[<>]/, `${input} -> raw angle bracket survived: ${output}`);
  }
});

test("sanitizing is idempotent and leaves every current catalog value unchanged", () => {
  for (const code of locales) {
    const catalog = readLocale(code);
    const clean = hodlSanitizeCatalog(catalog);
    assert.deepEqual(Object.keys(clean), Object.keys(catalog), code);
    for (const key of Object.keys(catalog)) {
      assert.equal(clean[key], catalog[key], `${code} ${key} would be altered by the sanitizer`);
      assert.equal(hodlSanitizeCatalogHtml(clean[key]), clean[key], `${code} ${key} is not a fixed point`);
    }
  }
});

test("the tokenizer sees tags the way the sanitizer does", () => {
  const tokens = hodlCatalogTokens('a <span class="mono">b</span> <0;1> <x-y data-z=1>');
  // A '<' that does not start a tag stays inside the text run.
  assert.deepEqual(tokens.map((token) => token.text ?? `${token.closing ? "/" : ""}${token.name}`), ["a ", "span", "b", "/span", " <", "0;1> ", "x-y"]);
  assert.deepEqual(tokens[1].attrs, { class: "mono" });
  assert.deepEqual(tokens[6].attrs, { "data-z": "1" });
});

test("placeholder values are sanitized after interpolation", () => {
  const hostile = '<img src=x onerror="globalThis.__entropyLabPwned = true">';
  const translated = t("seedLength.words", { n: hostile });
  assert.equal(translated, '&lt;img src=x onerror="globalThis.__entropyLabPwned = true"&gt; words');
  assert.doesNotMatch(translated, /<img\b/i);
});

test("translated template attributes escape every HTML quote and delimiter", () => {
  const hostile = '" hidden style="display:none" onfocus="globalThis.__entropyLabPwned = true\' data-x=\'x';
  const translated = tAttr("seedLength.words", { n: hostile });
  assert.equal(translated, "&quot; hidden style=&quot;display:none&quot; onfocus=&quot;globalThis.__entropyLabPwned = true&#39; data-x=&#39;x words");
  assert.doesNotMatch(translated, /[<>"']/);
});

test("quoted template attributes use the attribute-safe translation helper", () => {
  const source = readFileSync(join(root, "src/js/app.js"), "utf8");
  const rawTranslationInAttribute = /\b(?:aria-label|title|placeholder)="\$\{(?:[^{}]|\{[^{}]*\})*?\bhodlT\(/g;
  assert.deepEqual([...source.matchAll(rawTranslationInAttribute)].map((match) => match[0]), []);
});

test("i18n.js routes every catalog through the sanitizer before t() can read it", () => {
  const source = readFileSync(join(root, "src/js/i18n.js"), "utf8");
  assert.match(source, /import \{[^}]*hodlSanitizeCatalog[^}]*\} from "\.\/i18n-sanitize\.js"/);
  assert.match(source, /const hodlLocaleCatalogs = \{ en: hodlSanitizeCatalog\(en\), es: hodlSanitizeCatalog\(es\), pt: hodlSanitizeCatalog\(pt\), fr: hodlSanitizeCatalog\(fr\), de: hodlSanitizeCatalog\(de\) \}/);
  // The English fallback inside t() must read the sanitized copy, not the raw import.
  assert.match(source, /let catalog = hodlLocaleCatalogs\[hodlLocale\] \|\| hodlLocaleCatalogs\.en;[\s\S]*?text = hodlLocaleCatalogs\.en\[key\]/);
  assert.match(source, /let interpolated = text\.replace[\s\S]*?return hodlSanitizeCatalogHtml\(interpolated\)/);
  assert.match(source, /globalThis\.hodlTAttr = tAttr/);
  assert.match(source, /globalThis\.hodlSanitizeCatalogHtml = hodlSanitizeCatalogHtml/);
});
