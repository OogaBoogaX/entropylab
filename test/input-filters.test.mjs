// The character filters behind the entropy, seed, and key fields. They are
// the first thing standing between a paste and a derivation: over-filtering
// silently changes the input (a different wallet), under-filtering lets
// misleading characters through to the analyzers.
// Run with `npm test`.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = dirname(fileURLToPath(import.meta.url));
const app = readFileSync(join(root, "..", "src/js/app.js"), "utf8");

function loadSlice(name) {
  const start = app.indexOf(`function ${name}(`);
  assert.ok(start >= 0, name);
  let depth = 0;
  for (let index = app.indexOf("{", start); index < app.length; index++) {
    if (app[index] === "{") depth++;
    else if (app[index] === "}" && --depth === 0) return app.slice(start, index + 1);
  }
  throw new Error(`Could not extract ${name}`);
}

const api = new Function(
  `
  ${["hodlLooksExtendedKey", "hodlFilterHex", "hodlFilterBin", "hodlFilterSeed", "hodlFilterKey"].map(loadSlice).join("\n")}
  return { hodlLooksExtendedKey, hodlFilterHex, hodlFilterBin, hodlFilterSeed, hodlFilterKey };
  `,
)();

const { hodlLooksExtendedKey, hodlFilterHex, hodlFilterBin, hodlFilterSeed, hodlFilterKey } = api;

test("the hex filter keeps hexadecimal characters and whitespace only", () => {
  assert.equal(hodlFilterHex("0x AbCdEf 019\t"), "0 AbCdEf 019\t", "the x of a 0x prefix is filtered out");
  assert.equal(hodlFilterHex("gh!@#$%^&*()z"), "");
  assert.equal(hodlFilterHex(""), "");
});

test("the binary filter keeps 0, 1, and whitespace only", () => {
  assert.equal(hodlFilterBin("0101 1100"), "0101 1100");
  assert.equal(hodlFilterBin("01201a3"), "0101", "digits past 1 and letters drop out");
});

test("the seed filter lowercases words, keeps punctuation, and never mangles an extended key", () => {
  assert.equal(hodlFilterSeed("Abandon ABILITY"), "abandon ability");
  assert.equal(hodlFilterSeed("word-one_two!"), "word-one_two!", "punctuation reaches the validator");
  assert.equal(hodlFilterSeed('["Abandon","Ability"]'), '["abandon","ability"]', "a JSON list keeps every character and is lowercased");
  const xpub = `xpub6BosfCnifzxcFwrSzQiqu2DBVTshkCXacvNsWGYJVVhhawA7d4R5WSWGFNbi8Aw6ZRc1brxMyWMzG3DSSSSoekkudhUd9yLb6qx39T9nMdj`;
  assert.equal(hodlFilterSeed(xpub), xpub, "extended keys are case-sensitive and must survive verbatim");
  const xprvLike = `xprv${"A".repeat(107)}`;
  assert.equal(hodlFilterSeed(xprvLike), xprvLike);
  // Wrapping punctuation is not part of the key: the bare key comes back so
  // the seed analysis still sees an extended key and imports it.
  for (const wrapped of [`[${xpub}]`, `"${xpub}",`, `  ["${xpub}"]  `, `${xpub}\n`]) {
    assert.equal(hodlFilterSeed(wrapped), xpub, JSON.stringify(wrapped));
  }
  // A mark inside the key is never deleted: the text is not returned as a key,
  // and the key's own validation refuses it later.
  const marked = `${xpub.slice(0, 40)}-${xpub.slice(40)}`;
  const markedResult = hodlFilterSeed(marked);
  assert.equal(hodlLooksExtendedKey(markedResult), false, "a key with a mark in the middle is not a key");
  assert.ok(markedResult.includes("-"), "the mark is kept for the validator to refuse");
  // Hyphen-joined recovery words are never glued into a fake key, wrapped or not.
  for (const first of ["track", "umbrella", "vacant", "yard", "zoo"]) {
    const phrase = [first, ...Array(23).fill("abandon")].join("-");
    assert.equal(hodlLooksExtendedKey(phrase), false, `${first}: not an extended key`);
    assert.equal(hodlFilterSeed(phrase), phrase, `${first}: every hyphen kept`);
    assert.equal(hodlFilterSeed(`[${phrase}]`), `[${phrase}]`, `${first}: wrapped, still not a key`);
  }
  const twelve = ["zoo", ...Array(11).fill("abandon")].join("-");
  assert.equal(hodlFilterSeed(twelve), twelve, "12 hyphen-joined words are not glued into one");
  assert.equal(hodlFilterSeed("XpubShortMixedCase"), "xpubshortmixedcase", "short mixed-case text is not an extended key");
  assert.equal(hodlFilterSeed(null), "");
});

test("the extended-key shape test is the gate the seed filter relies on", () => {
  assert.equal(hodlLooksExtendedKey("xpub6BosfCnifzxcFwrSzQiqu2DBVTshkCXacvNsWGYJVVhhawA7d4R5WSWGFNbi8Aw6ZRc1brxMyWMzG3DSSSSoekkudhUd9yLb6qx39T9nMdj"), true);
  assert.equal(hodlLooksExtendedKey(`  xpub${"1".repeat(107)}  `), true, "surrounding whitespace is tolerated");
  assert.equal(hodlLooksExtendedKey("xpubShort"), false);
  assert.equal(hodlLooksExtendedKey(`qpub${"1".repeat(107)}`), false, "q is not an extended-key prefix");
  assert.equal(hodlLooksExtendedKey(`xpub${"1".repeat(107)}!`), false, "punctuation breaks the shape");
});

test("the key filter passes brain-wallet text through untouched", () => {
  assert.equal(hodlFilterKey("any $ymbols! are—allowed éè", "brain"), "any $ymbols! are—allowed éè");
  assert.equal(hodlFilterKey("KxFC1jmwwCoACiCAWZ3eXa96mBM6tb3TYzGmf6YwgdGWZgawvrtJ", "wif"), "KxFC1jmwwCoACiCAWZ3eXa96mBM6tb3TYzGmf6YwgdGWZgawvrtJ");
  assert.equal(hodlFilterKey("KxFC!@#$%^&*()", "wif"), "KxFC", "non-brain kinds strip everything but alphanumerics and whitespace");
  assert.equal(hodlFilterKey("0x1234 abcd", "hex-key"), "0x1234 abcd", "the hex analyzer owns the 0x handling");
});
