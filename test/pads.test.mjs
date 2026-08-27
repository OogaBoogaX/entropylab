import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const read = (path) => readFileSync(new URL(`../${path}`, import.meta.url), "utf8");
const app = read("src/js/app.js");
const vendor = read("src/js/vendor.js");
const css = read("src/css/styles.css");
const built = read("index.html");

test("the shuffle helper is defined once with unbiased cryptographic randomness", () => {
  assert.match(vendor, /function hodlShuffle\(values\)/);
  assert.match(vendor, /crypto\.getRandomValues\(buffer\)/);
  assert.match(vendor, /while \(buffer\[0\] >= limit\)/);
  assert.match(vendor, /\[result\[index\], result\[swap\]\] = \[result\[swap\], result\[index\]\]/);
});

test("pads render in logical order by default and shuffle only when opted in", () => {
  // Every pad guards shuffling behind the hodlPadShuffle flag.
  assert.match(app, /dplusPad=\(hodlPadShuffle\?hodlShuffle\(dplusFaces\):dplusFaces\)/);
  assert.match(app, /\$\{\(hodlPadShuffle\?hodlShuffle\(\[1,2,3,4,5,6\]\):\[1,2,3,4,5,6\]\)\.map/);
  assert.match(app, /entropyCharacters=binary\?\["0","1"\]:\(hodlPadShuffle\?hodlShuffle\(\[\.\.\."0123456789ABCDEF"\]\):\[\.\.\."0123456789ABCDEF"\]\)/);
  assert.match(app, /\$\{\(hodlPadShuffle\?hodlShuffle\(\[\.\.\."abcdefghijklmnopqrstuvwxyz"\]\):\[\.\.\."abcdefghijklmnopqrstuvwxyz"\]\)\.map/);
  assert.match(app, /\$\{\(hodlPadShuffle\?hodlShuffle\(\[\.\.\."123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"\]\):\[\.\.\."123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"\]\)\.map/);
});

test("shuffle is opt-in via a checkbox on every entropy pad", () => {
  assert.match(vendor, /function hodlShuffle/);
  const toggles = app.match(/id="pad-shuffle-toggle"/g) ?? [];
  assert.equal(toggles.length, 4, "expected one Shuffle checkbox per entropy input mode");
  assert.match(app, /<label class="pad-shuffle-toggle"><input type="checkbox" id="pad-shuffle-toggle"/);
  assert.match(app, /shuffleToggle\.onchange=\(\)=>\{hodlCaptureKey\(\)/);
  assert.match(app, /state\.padShuffle=hodlPadShuffle/);
  assert.match(app, /hodlPadShuffle=Boolean\(state\.padShuffle\)/);
  assert.doesNotMatch(app, /data-pad-shuffle/);
});

test("dice pad shuffles only digits 1-6 while Heads/Tails stay fixed and separate", () => {
  assert.match(app, /dice-digits">\$\{\(hodlPadShuffle\?hodlShuffle\(\[1,2,3,4,5,6\]\):\[1,2,3,4,5,6\]\)\.map/);
  // Coin buttons are appended after the digits, never part of the shuffle.
  const dicePad = app.match(/let dicePad=ge==="dplus"[\s\S]*?<\/div>`;/)[0];
  const shuffleEnd = dicePad.indexOf("}).join()");
  assert.ok(shuffleEnd < dicePad.indexOf('data-d="H"'), "Heads button must follow the shuffled digits");
  assert.ok(shuffleEnd < dicePad.indexOf('data-d="T"'), "Tails button must follow the shuffled digits");
  assert.match(css, /\.dice-input-pad\.dice-digits \.coin-button \{ grid-column: 1 \/ -1; \}/);
});

test("hex pad groups rows 0-7 then 8-F and reuses the existing keypad styles", () => {
  assert.match(app, /entropyCharacters=binary\?\["0","1"\]:\(hodlPadShuffle\?hodlShuffle\(\[\.\.\."0123456789ABCDEF"\]\):\[\.\.\."0123456789ABCDEF"\]\)/);
  assert.match(app, /dice-input-pad dplus entropy-keypad\$\{binary\?" binary-keypad":""\}/);
});

test("seed phrase and private key modes keep fixed on-screen pads", () => {
  assert.match(app, /<div class="dice-input-pad seed-pad" role="group" aria-label="Seed phrase keyboard">/);
  assert.match(app, /<div class="dice-input-pad key-pad" role="group" aria-label="Private key keyboard">/);
  assert.match(app, /class="pad-wide" data-vk-character="0" aria-label="Insert 0">0 \(hex only\)/);
  assert.match(app, /button\.dataset\.entropyDigit\|\|button\.dataset\.vkCharacter/);
});

test("pad styles cover the toggle and per-layout grids", () => {
  for (const selector of [".pad-shuffle-toggle", ".seed-pad", ".key-pad", ".dplus-pad", ".hex-keypad", ".dice-digits"]) {
    assert.ok(css.includes(selector), `missing ${selector} styles`);
  }
  assert.match(css, /\.dice-input-pad\.seed-pad \{ grid-template-columns: repeat\(6, minmax\(0, 1fr\)\); \}/);
  assert.match(css, /\.dice-input-pad\.key-pad \{ grid-template-columns: repeat\(4, minmax\(0, 1fr\)\); \}/);
  assert.doesNotMatch(css, /\.pad-toolbar/);
});

test("the shuffle helper is present in the compiled application", () => {
  assert.ok(built.includes("function hodlShuffle(values)"), "compiled index.html is missing the shuffle helper");
  assert.ok(built.includes('id="pad-shuffle-toggle"'), "compiled index.html is missing the shuffle checkbox");
  assert.ok(built.includes('class="dice-input-pad seed-pad"'), "compiled index.html is missing the seed pad");
  assert.ok(built.includes('class="dice-input-pad key-pad"'), "compiled index.html is missing the private-key pad");
});
