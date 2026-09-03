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
  hodlEscapeAttribute,
  hodlSanitizeCatalog,
  hodlSanitizeCatalogHtml,
  hodlSanitizeCatalogText,
  hodlSanitizeTextCatalog,
} from "../src/js/i18n-sanitize.js";
import { t, tAttr, tHtml } from "../src/js/i18n.js";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const locales = ["en", "es", "pt", "fr", "de"];
const readLocale = (code) => JSON.parse(readFileSync(join(root, "src/locales", `${code}.json`), "utf8"));

test("plain text is encoded for an HTML sink, including entities and bare angle brackets", () => {
  const cases = new Map([
    ["Save entry", "Save entry"],
    ["A multipath step like <0;1> must be last.", "A multipath step like &lt;0;1&gt; must be last."],
    ["5 > 3 and 3 < 5", "5 &gt; 3 and 3 &lt; 5"],
    ["Fish & chips", "Fish &amp; chips"],
    ['Say "yes" and don\'t blink', "Say &quot;yes&quot; and don&#39;t blink"],
    ["balance&#8238;", "balance&amp;#8238;"],
    ["", ""],
  ]);
  for (const [value, expected] of cases) {
    assert.equal(hodlCatalogHasMarkup(value), false);
    assert.equal(hodlSanitizeCatalogHtml(value), expected);
  }
});

test("allowlisted markup survives exactly", () => {
  const value = 'Paste <span class="mono">[fingerprint/48h/0h/0h/2h]xpub…</span> and <strong>Derive</strong> or <em>wait</em>, see <code>m = 0</code>. <a href="entropylab.html" download="entropylab.html">Download EntropyLab</a>';
  assert.equal(hodlSanitizeCatalogHtml(value), "Paste <span class=mono>[fingerprint/48h/0h/0h/2h]xpub…</span> and <strong>Derive</strong> or <em>wait</em>, see <code>m = 0</code>. <a href=entropylab.html download=entropylab.html>Download EntropyLab</a>");
});

test("every shape of executable or foreign markup is emitted as visible text", () => {
  const cases = {
    '<img src=x onerror="alert(1)">hi': "&lt;img src=x onerror=&quot;alert(1)&quot;&gt;hi",
    "<script>alert(1)</script>": "&lt;script&gt;alert(1)&lt;/script&gt;",
    // A rejected open tag leaves its close tag with nothing to close; like an
    // HTML parser, the stray close is dropped rather than rendered.
    '<span class="mono" onclick="alert(1)">x</span>': "&lt;span class=&quot;mono&quot; onclick=&quot;alert(1)&quot;&gt;x",
    '<span class="other">x</span>': "&lt;span class=&quot;other&quot;&gt;x",
    '<a href="javascript:alert(1)">x</a>': "&lt;a href=&quot;javascript:alert(1)&quot;&gt;x",
    '<a href="entropylab.html" download="evil.html">x</a>': "&lt;a href=&quot;entropylab.html&quot; download=&quot;evil.html&quot;&gt;x",
    "<b>bold</b>": "&lt;b&gt;bold&lt;/b&gt;",
    "<!-- comment --><strong>x</strong>": "&lt;!-- comment --&gt;<strong>x</strong>",
    "<?xml ?><em>x</em>": "&lt;?xml ?&gt;<em>x</em>",
    "<strong>unterminated": "<strong>unterminated</strong>",
    "<strong>text <span class=\"mono\">y</strong> z</span>": "<strong>text <span class=mono>y</span></strong> z",
    "</strong>stray close": "stray close",
    "<STRONG>upper</STRONG>": "<strong>upper</strong>",
    '<span class="mono" class="mono">dup</span>': "<span class=mono>dup</span>",
    "<strong": "&lt;strong",
    "a < b <strong>c</strong>": "a &lt; b <strong>c</strong>",
  };
  for (const [input, expected] of Object.entries(cases)) assert.equal(hodlSanitizeCatalogHtml(input), expected, input);
});

test("the output alphabet is closed: only allowlisted tags and their fixed attributes can appear", () => {
  for (const [tag, attributes] of Object.entries(hodlCatalogAllowedTags)) {
    for (const [attribute, value] of Object.entries(attributes)) {
      assert.match(value, /^[A-Za-z0-9._-]+$/, `${tag}.${attribute} must remain safe for unquoted canonical output`);
    }
  }
  const hostile = [
    "<svg><script>alert(1)</script></svg>",
    '<span class="mono"><img src=x onerror=alert(1)></span>',
    "<a href=\"entropylab.html\" download=\"entropylab.html\" onmouseover=\"alert(1)\">x</a>",
    "<span class=mono>unquoted</span>",
    "<strong/>self",
    "<strong >spaced</strong >",
    "<strong\nnewline>x</strong>",
  ];
  const tagPattern = /<(\/?)([a-z]+)((?:\s[a-z]+=[A-Za-z0-9._-]+)*)>/g;
  for (const input of hostile) {
    const output = hodlSanitizeCatalogHtml(input);
    let stripped = output.replace(tagPattern, (match, closing, name, attrs) => {
      assert.ok(name in hodlCatalogAllowedTags, `${input} -> unexpected tag ${match}`);
      for (const [, attribute, value] of attrs.matchAll(/\s([a-z]+)=([A-Za-z0-9._-]+)/g)) {
        assert.equal(hodlCatalogAllowedTags[name][attribute], value, `${input} -> unexpected attribute ${attribute}`);
      }
      return "";
    });
    assert.doesNotMatch(stripped, /[<>]/, `${input} -> raw angle bracket survived: ${output}`);
  }
});

test("HTML and text catalog views are idempotent and cover every current value", () => {
  for (const code of locales) {
    const catalog = readLocale(code);
    const clean = hodlSanitizeCatalog(catalog);
    const text = hodlSanitizeTextCatalog(catalog);
    assert.deepEqual(Object.keys(clean), Object.keys(catalog), code);
    assert.deepEqual(Object.keys(text), Object.keys(catalog), code);
    for (const key of Object.keys(catalog)) {
      assert.equal(hodlSanitizeCatalogHtml(clean[key]), clean[key], `${code} ${key} is not a fixed point`);
      assert.equal(hodlSanitizeCatalogText(text[key]), text[key], `${code} ${key} text is not a fixed point`);
      assert.doesNotMatch(clean[key], /["']/, `${code} ${key} HTML output must not contain attribute delimiters`);
    }
  }
});

test("the text view removes allowed formatting and leaves rejected markup inert for DOM text sinks", () => {
  assert.equal(hodlSanitizeCatalogText("Use <strong>care</strong> & verify"), "Use care & verify");
  assert.equal(hodlSanitizeCatalogText('<img src=x onerror="x">visible'), '<img src=x onerror="x">visible');
});

test("the tokenizer sees tags the way the sanitizer does", () => {
  const tokens = hodlCatalogTokens('a <span class="mono">b</span> <0;1> <x-y data-z=1>');
  // A '<' that does not start a tag stays inside the text run.
  assert.deepEqual(tokens.map((token) => token.text ?? `${token.closing ? "/" : ""}${token.name}`), ["a ", "span", "b", "/span", " <", "0;1> ", "x-y"]);
  assert.deepEqual(tokens[1].attrs, { class: "mono" });
  assert.deepEqual(tokens[6].attrs, { "data-z": "1" });
});

test("HTML placeholders are escaped before insertion and never re-enter the allowlist", () => {
  const hostile = '<img src=x onerror="globalThis.__entropyLabPwned = true">';
  const translated = tHtml("seedLength.words", { n: hostile });
  assert.equal(translated, "&lt;img src=x onerror=&quot;globalThis.__entropyLabPwned = true&quot;&gt; words");
  assert.doesNotMatch(translated, /<img\b/i);
  assert.doesNotMatch(translated, /["']/);
  assert.equal(tHtml("seedLength.words", { n: "<strong>attacker</strong>" }), "&lt;strong&gt;attacker&lt;/strong&gt; words");
  assert.equal(tHtml("seedLength.words", { n: "</strong><script>x</script>" }), "&lt;/strong&gt;&lt;script&gt;x&lt;/script&gt; words");
  assert.equal(tHtml("seedLength.words", { n: "&#x202E;" }), "&amp;#x202E; words");
  assert.equal(tHtml("seedLength.words", { n: 12 }), "12 words");
  assert.equal(tHtml("seedLength.words"), "{n} words");
  assert.equal(t("seedLength.words", { n: hostile }), `${hostile} words`);
});

test("translated template attributes escape every HTML quote and delimiter", () => {
  const hostile = '" hidden style="display:none" onfocus="globalThis.__entropyLabPwned = true\' data-x=\'x';
  const translated = tAttr("seedLength.words", { n: hostile });
  assert.equal(translated, "&quot; hidden style=&quot;display:none&quot; onfocus=&quot;globalThis.__entropyLabPwned = true&#39; data-x=&#39;x words");
  assert.doesNotMatch(translated, /[<>"']/);
  assert.equal(hodlEscapeAttribute("it's <b> & more"), "it&#39;s &lt;b&gt; &amp; more");
});

test("i18n.js routes every catalog through the sanitizer before t() can read it", () => {
  const source = readFileSync(join(root, "src/js/i18n.js"), "utf8");
  assert.match(source, /const hodlLocaleHtmlCatalogs = \{ en: hodlSanitizeCatalog\(en\), es: hodlSanitizeCatalog\(es\), pt: hodlSanitizeCatalog\(pt\), fr: hodlSanitizeCatalog\(fr\), de: hodlSanitizeCatalog\(de\) \}/);
  assert.match(source, /const hodlLocaleTextCatalogs = \{ en: hodlSanitizeTextCatalog\(en\), es: hodlSanitizeTextCatalog\(es\), pt: hodlSanitizeTextCatalog\(pt\), fr: hodlSanitizeTextCatalog\(fr\), de: hodlSanitizeTextCatalog\(de\) \}/);
  assert.match(source, /export function tHtml[\s\S]*?hodlEscapeHtmlText/);
  assert.doesNotMatch(source, /hodlSanitizeCatalogHtml\(interpolated\)/);
  assert.match(source, /return hodlEscapeAttribute\(t\(key, vars\)\)/);
  assert.match(source, /globalThis\.hodlT = tHtml/);
  assert.match(source, /globalThis\.hodlTAttr = tAttr/);
  assert.match(source, /globalThis\.hodlSanitizeCatalogHtml = hodlSanitizeCatalogHtml/);
});
