// The catalog sanitizer is the boundary between translated text and the DOM:
// whatever a catalog says, only allowlisted markup can reach innerHTML.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import {
  hodlCatalogAllowedTags,
  hodlCatalogHasControlCharacters,
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
const locales = ["es", "pt", "fr", "de"];
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

test("the fixed attribution anchor survives only in its complete, exact form", () => {
  const exact = '<a href="https://github.com/iancoleman/bip39" target="_blank" rel="noopener noreferrer">github.com/iancoleman/bip39</a>';
  assert.equal(hodlSanitizeCatalogHtml(exact), '<a href=https://github.com/iancoleman/bip39 target=_blank rel="noopener noreferrer">github.com/iancoleman/bip39</a>');
  // Any deviation — a missing attribute, an extra one, a different URL — and
  // the whole tag is emitted as visible text.
  const cases = [
    '<a href="https://github.com/iancoleman/bip39">github.com/iancoleman/bip39</a>',
    '<a href="https://github.com/iancoleman/bip39" target="_blank">github.com/iancoleman/bip39</a>',
    '<a href="https://github.com/iancoleman/bip39" target="_blank" rel="noopener noreferrer" data-x="1">github.com/iancoleman/bip39</a>',
    '<a href="https://github.com/iancoleman/bip39.evil.example" target="_blank" rel="noopener noreferrer">github.com/iancoleman/bip39</a>',
    '<a target="_blank" rel="noopener noreferrer" href="https://github.com/iancoleman/bip39">reordered is fine semantically but still exact-matched</a>',
  ];
  assert.equal(hodlSanitizeCatalogHtml(cases[0]), "&lt;a href=&quot;https://github.com/iancoleman/bip39&quot;&gt;github.com/iancoleman/bip39");
  assert.equal(hodlSanitizeCatalogHtml(cases[1]), "&lt;a href=&quot;https://github.com/iancoleman/bip39&quot; target=&quot;_blank&quot;&gt;github.com/iancoleman/bip39");
  assert.equal(hodlSanitizeCatalogHtml(cases[2]), "&lt;a href=&quot;https://github.com/iancoleman/bip39&quot; target=&quot;_blank&quot; rel=&quot;noopener noreferrer&quot; data-x=&quot;1&quot;&gt;github.com/iancoleman/bip39");
  assert.equal(hodlSanitizeCatalogHtml(cases[3]), "&lt;a href=&quot;https://github.com/iancoleman/bip39.evil.example&quot; target=&quot;_blank&quot; rel=&quot;noopener noreferrer&quot;&gt;github.com/iancoleman/bip39");
  assert.equal(hodlSanitizeCatalogHtml(cases[4]), '<a href=https://github.com/iancoleman/bip39 target=_blank rel="noopener noreferrer">reordered is fine semantically but still exact-matched</a>');
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

test("the output alphabet is closed: only allowlisted tags and their fixed attribute forms can appear", () => {
  // The renderer must never have to quote a table value with a quote of its
  // own: fixed values are either token-safe (emitted unquoted) or contain no
  // quote/angle characters at all (emitted wrapped in plain double quotes).
  for (const [tag, forms] of Object.entries(hodlCatalogAllowedTags)) {
    for (const form of forms) {
      for (const [attribute, value] of Object.entries(form)) {
        assert.doesNotMatch(value, /["'`<>]/, `${tag}.${attribute} must never contain a quote or angle bracket`);
      }
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
  const tagPattern = /<(\/?)([a-z]+)((?:\s[a-z]+=(?:"[^"]*"|[A-Za-z0-9._:/-]+))*)>/g;
  const allowedForms = Object.fromEntries(Object.entries(hodlCatalogAllowedTags).map(([tag, forms]) => [tag, forms]));
  for (const input of hostile) {
    const output = hodlSanitizeCatalogHtml(input);
    let stripped = output.replace(tagPattern, (match, closing, name, attrs) => {
      assert.ok(name in allowedForms, `${input} -> unexpected tag ${match}`);
      if (closing) return "";
      const seen = {};
      for (const [, attribute, value] of attrs.matchAll(/\s([a-z]+)=("([^"]*)"|[A-Za-z0-9._:/-]+)/g)) {
        seen[attribute] = attribute === "rel" && value.startsWith('"') ? value.slice(1, -1) : value;
      }
      const forms = allowedForms[name];
      assert.ok(forms.some((form) => {
        const fixed = Object.keys(form), names = Object.keys(seen);
        return fixed.length === names.length && names.every((n) => form[n] === seen[n]);
      }), `${input} -> attribute set not a fixed form: ${JSON.stringify(seen)}`);
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
      // The only quotes the HTML view may ever contain belong to the fixed
      // attribution link's rel rendering — never to catalog text.
      assert.doesNotMatch(clean[key].replaceAll('rel="noopener noreferrer"', "rel=fixed-attribution"), /["']/, `${code} ${key} HTML output must not contain attribute delimiters`);
    }
  }
});

test("the text view removes allowed formatting and leaves rejected markup inert for DOM text sinks", () => {
  assert.equal(hodlSanitizeCatalogText("Use <strong>care</strong> & verify"), "Use care & verify");
  assert.equal(hodlSanitizeCatalogText('<img src=x onerror="x">visible'), '<img src=x onerror="x">visible');
});

test("the neutralizer covers the invisible Unicode ranges (audit S36-1)", () => {
  // Invisible or reformatting codepoints a catalog string must never carry to
  // the page: soft hyphen, Hangul fillers and Jungseong filler, Mongolian
  // vowel separator, Braille pattern blank, halfwidth Hangul filler, line and
  // paragraph separators, the deprecated interlinear anchors, language tags,
  // and the variation selectors. Both endpoints of every added range.
  const added = [0x00ad, 0x115f, 0x1160, 0x180e, 0x2800, 0x3164, 0xffa0, 0x2028, 0x2029, 0x2065, 0x206a, 0x206f, 0xfe00, 0xfe0f, 0xe0001, 0xe0020, 0xe007f];
  // The ranges the table already had must behave identically under the u flag:
  // the endpoints of each, including the already-passing bidi/zero-width ones.
  const existing = [0x00, 0x08, 0x0b, 0x0c, 0x0e, 0x1f, 0x7f, 0x9f, 0x061c, 0x200b, 0x200f, 0x202a, 0x202e, 0x2060, 0x2064, 0x2066, 0x2069, 0xfeff];
  for (const cp of [...added, ...existing]) {
    const char = String.fromCodePoint(cp), where = `U+${cp.toString(16).toUpperCase()}`;
    assert.equal(hodlSanitizeCatalogText(`a${char}b`), "a\uFFFDb", `${where} in the text view`);
    assert.equal(hodlSanitizeCatalogHtml(`a${char}b`), "a\uFFFDb", `${where} in the HTML view`);
    assert.equal(hodlCatalogHasControlCharacters(`a${char}b`), true, `${where} is detected`);
  }
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
  const translated = tHtml("{n} words", { n: hostile });
  assert.equal(translated, "&lt;img src=x onerror=&quot;globalThis.__entropyLabPwned = true&quot;&gt; words");
  assert.doesNotMatch(translated, /<img\b/i);
  assert.doesNotMatch(translated, /["']/);
  assert.equal(tHtml("{n} words", { n: "<strong>attacker</strong>" }), "&lt;strong&gt;attacker&lt;/strong&gt; words");
  assert.equal(tHtml("{n} words", { n: "</strong><script>x</script>" }), "&lt;/strong&gt;&lt;script&gt;x&lt;/script&gt; words");
  assert.equal(tHtml("{n} words", { n: "&#x202E;" }), "&amp;#x202E; words");
  assert.equal(tHtml("{n} words", { n: 12 }), "12 words");
  assert.equal(tHtml("{n} words"), "{n} words");
  assert.equal(t("{n} words", { n: hostile }), `${hostile} words`);
});

test("translated template attributes escape every HTML quote and delimiter", () => {
  const hostile = '" hidden style="display:none" onfocus="globalThis.__entropyLabPwned = true\' data-x=\'x';
  const translated = tAttr("{n} words", { n: hostile });
  assert.equal(translated, "&quot; hidden style=&quot;display:none&quot; onfocus=&quot;globalThis.__entropyLabPwned = true&#39; data-x=&#39;x words");
  assert.doesNotMatch(translated, /[<>"']/);
  assert.equal(hodlEscapeAttribute("it's <b> & more"), "it&#39;s &lt;b&gt; &amp; more");
});

test("a hostile catalog value can only reach t() and tHtml() sanitized", () => {
  // Simulate a committed catalog gone bad: every read path must return the
  // sanitized rendering, so nothing a catalog says can execute.
  const dirty = { "Greeting": 'Hello <img src=x onerror="alert(1)">' };
  assert.equal(hodlSanitizeCatalog(dirty)["Greeting"], "Hello &lt;img src=x onerror=&quot;alert(1)&quot;&gt;");
  assert.equal(hodlSanitizeTextCatalog(dirty)["Greeting"], 'Hello <img src=x onerror="alert(1)">');
});

test("non-string catalog values are dropped by both catalog views, never passed through (audit B6)", () => {
  // JSON catalogs can carry arrays, objects, numbers — a value the sweep
  // assigns to innerHTML coerces to its string payload. The sanitizer is the
  // trust boundary, so it must refuse the entry, not pass it through.
  const dirty = {
    "Array value": ['<img src=x onerror="alert(1)">'],
    "Object value": { injected: "<img src=x onerror=alert(1)>" },
    "Number value": 7,
    "Boolean value": true,
    "Null value": null,
    "Clean value": "Use <strong>care</strong>",
  };
  const html = hodlSanitizeCatalog(dirty), text = hodlSanitizeTextCatalog(dirty);
  assert.deepEqual(Object.keys(html), ["Clean value"]);
  assert.deepEqual(Object.keys(text), ["Clean value"]);
  assert.equal(html["Clean value"], "Use <strong>care</strong>");
  assert.equal(text["Clean value"], "Use care");
});

test("a __proto__ key in a JSON-parsed catalog cannot mutate the sanitized catalog's prototype", () => {
  // JSON.parse creates an own "__proto__" property; assigning it onto a plain
  // object would hit the Object.prototype setter instead of adding an entry.
  const dirty = JSON.parse('{"__proto__": {"polluted": "yes"}, "Greeting": "Hello"}');
  assert.equal(Object.hasOwn(dirty, "__proto__"), true);
  for (const clean of [hodlSanitizeCatalog(dirty), hodlSanitizeTextCatalog(dirty)]) {
    assert.equal(Object.getPrototypeOf(clean), Object.prototype);
    assert.equal(Object.hasOwn(clean, "__proto__"), false);
    assert.equal(clean.polluted, undefined);
    assert.equal(clean.Greeting, "Hello");
  }
});

test("i18n.js routes every catalog through the sanitizer before t() can read it", () => {
  const source = readFileSync(join(root, "src/js/i18n.js"), "utf8");
  assert.match(source, /const hodlLocaleHtmlCatalogs = \{ es: hodlSanitizeCatalog\(es\), pt: hodlSanitizeCatalog\(pt\), fr: hodlSanitizeCatalog\(fr\), de: hodlSanitizeCatalog\(de\) \}/);
  assert.match(source, /const hodlLocaleTextCatalogs = \{ es: hodlSanitizeTextCatalog\(es\), pt: hodlSanitizeTextCatalog\(pt\), fr: hodlSanitizeTextCatalog\(fr\), de: hodlSanitizeTextCatalog\(de\) \}/);
  assert.match(source, /export function tHtml[\s\S]*?hodlEscapeHtmlText/);
  assert.doesNotMatch(source, /hodlSanitizeCatalogHtml\(interpolated\)/);
  assert.match(source, /return hodlEscapeAttribute\(t\(source, vars\)\)/);
  assert.match(source, /globalThis\.hodlT = tHtml/);
  assert.match(source, /globalThis\.hodlTAttr = tAttr/);
  assert.match(source, /globalThis\.hodlSanitizeCatalogHtml = hodlSanitizeCatalogHtml/);
});
