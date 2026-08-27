import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const read = (path) => readFileSync(new URL(`../${path}`, import.meta.url), "utf8");
const template = read("src/index.html");
const app = read("src/js/app.js");
const vendor = read("src/js/vendor.js");
const css = read("src/css/styles.css");
const built = read("index.html");

test("the shuffle helper is defined once with unbiased cryptographic randomness", () => {
  assert.match(vendor, /function hodlShuffle\(values\)/);
  assert.match(vendor, /crypto\.getRandomValues\(buffer\)/);
  assert.match(vendor, /while \(buffer\[0\] >= limit\)/);
  assert.match(vendor, /\[result\[index\], result\[swap\]\] = \[result\[swap\], result\[index\]\]/);
  const occurrences = `${app}\n${vendor}`.match(/hodlShuffle/g) ?? [];
  assert.ok(occurrences.length >= 6, "hodlShuffle should shuffle every pad layout");
});

test("every entropy input pad offers a Shuffle control", () => {
  assert.equal(app.match(/data-pad-shuffle/g)?.length, 8, "expected four Shuffle templates plus four bindings");
  assert.match(app, /<div class="pad-toolbar"><button type="button" data-pad-shuffle>Shuffle<\/button><\/div>/);
  assert.match(app, /shuffleButton\.onclick=\(\)=>\{hodlCaptureKey\(\);hodlRenderKeyForm\(\);hodlRestoreFormFields\(hodlKeys\[hodlActiveKey\]\)/);
});

test("the existing dice, D++, and entropy pads shuffle their keys", () => {
  assert.match(app, /dplusPad=hodlShuffle\(dplusFaces\)\.map/);
  assert.match(app, /\$\{hodlShuffle\(\[1,3,5,2,4,6\]\)\.map/);
  assert.match(app, /\$\{hodlShuffle\(entropyCharacters\)\.map/);
});

test("seed phrase and private key modes get fixed on-screen pads", () => {
  assert.match(app, /<div class="dice-input-pad seed-pad" role="group" aria-label="Seed phrase keyboard">\$\{hodlShuffle\(\[\.\.\."abcdefghijklmnopqrstuvwxyz"\]\)\.map/);
  assert.match(app, /<div class="dice-input-pad key-pad" role="group" aria-label="Private key keyboard">\$\{hodlShuffle\(\[\.\.\."123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"\]\)\.map/);
  assert.match(app, /class="pad-wide" data-vk-character="0" aria-label="Insert 0">0 \(hex only\)/);
  assert.match(app, /button\.dataset\.entropyDigit\|\|button\.dataset\.vkCharacter/);
});

test("pad styles cover the toolbar and per-layout grids", () => {
  for (const selector of [".pad-toolbar", ".seed-pad", ".key-pad", ".dplus-pad", ".hex-keypad"]) {
    assert.ok(css.includes(selector), `missing ${selector} styles`);
  }
  assert.match(css, /\.dice-input-pad\.seed-pad \{ grid-template-columns: repeat\(6, minmax\(0, 1fr\)\); \}/);
  assert.match(css, /\.dice-input-pad\.key-pad \{ grid-template-columns: repeat\(4, minmax\(0, 1fr\)\); \}/);
  assert.match(css, /\.pad-toolbar button:hover \{ color: var\(--accent\); \}/);
});

test("the shuffle helper is present in the compiled application", () => {
  assert.ok(!template.includes("@@JS_KEYBOARD@@"), "template must not reference the removed keyboard module");
  assert.ok(built.includes("function hodlShuffle(values)"), "compiled index.html is missing the shuffle helper");
  assert.ok(built.includes("data-pad-shuffle"), "compiled index.html is missing the shuffle control");
  assert.ok(built.includes('class="dice-input-pad seed-pad"'), "compiled index.html is missing the seed pad");
  assert.ok(built.includes('class="dice-input-pad key-pad"'), "compiled index.html is missing the private-key pad");
});
