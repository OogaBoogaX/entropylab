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
  assert.match(app, /let diceFaces=hodlPadShuffle\?hodlShuffle\(\[1,3,5,2,4,6\]\):\[1,3,5,2,4,6\]/);
  assert.match(app, /entropyCharacters=binary\?\["0","1"\]:\(hodlPadShuffle\?hodlShuffle\(\[\.\.\."0123456789ABCDEF"\]\):\[\.\.\."0123456789ABCDEF"\]\)/);
  assert.match(app, /\$\{\(hodlPadShuffle\?hodlShuffle\(\[\.\.\."abcdefghijklmnopqrstuvwxyz"\]\):\[\.\.\."abcdefghijklmnopqrstuvwxyz"\]\)\.map/);
  assert.match(app, /\$\{\(hodlPadShuffle\?hodlShuffle\(keyCharacters\):keyCharacters\)\.map/);
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

test("dice pad keeps the original with-coin layout and shuffles only digits 1-6", () => {
  // Same layout as the static template: digit slots 1,3,5 / 2,4,6 with
  // Heads/Tails fixed in the wide right-hand column.
  assert.match(app, /let diceFaces=hodlPadShuffle\?hodlShuffle\(\[1,3,5,2,4,6\]\):\[1,3,5,2,4,6\]/);
  const dicePad = app.match(/let dicePad=ge==="dplus"[\s\S]*?<\/div>`;/)[0];
  assert.match(dicePad, /dice-input-pad with-coin/);
  assert.ok(dicePad.indexOf("slice(0,3)") < dicePad.indexOf('data-d="H"'), "Heads button must follow the first digit row");
  assert.ok(dicePad.indexOf('data-d="H"') < dicePad.indexOf("slice(3)"), "second digit row must follow Heads");
  assert.ok(dicePad.indexOf("slice(3)") < dicePad.indexOf('data-d="T"'), "Tails button must follow the second digit row");
  assert.doesNotMatch(app, /dice-digits/);
  assert.doesNotMatch(css, /dice-digits/);
  assert.match(css, /\.dice-input-pad\.with-coin \{ grid-template-columns: repeat\(3, minmax\(0, 1fr\)\) minmax\(0, 3fr\); \}/);
});

test("pads reshuffle in place after each keypress when shuffle is enabled", () => {
  assert.match(app, /function hodlShufflePadButtons\(container,selector\)/);
  assert.match(app, /if\(!hodlPadShuffle\|\|!container\)return/);
  // Dice digits shuffle after a digit press; coin presses do not trigger it.
  assert.match(app, /hodlInsertDiceControl\(input,button\);if\(!button\.dataset\.coin\)hodlShufflePadButtons\(button\.parentElement,"\[data-d\]:not\(\[data-coin\]\)"\)/);
  assert.match(app, /hodlInsertEntropyControl\(entropyInput,button\);hodlShufflePadButtons\(button\.parentElement,"\[data-entropy-digit\]"\)/);
  assert.match(app, /hodlInsertEntropyControl\(seedInput,button\);hodlShufflePadButtons\(button\.parentElement,"\[data-vk-character\]"\)/);
  assert.match(app, /hodlInsertEntropyControl\(keyInput,button\);hodlShufflePadButtons\(button\.parentElement,"\[data-vk-character\]"\)/);
  // The in-place shuffle preserves non-matching siblings (coins, wide keys).
  assert.match(app, /let positions=buttons\.map\(button=>\[\.\.\.container\.children\]\.indexOf\(button\)\),order=hodlShuffle\(\[\.\.\.buttons\.keys\(\)\]\)/);
  assert.match(app, /buttons\.forEach\(button=>button\.remove\(\)\)/);
  assert.match(app, /positions\.forEach\(\(position,slotIndex\)=>container\.insertBefore\(buttons\[order\[slotIndex\]\],container\.children\[position\]\?\?null\)\)/);
});

test("hex pad groups rows 0-7 then 8-F and reuses the existing keypad styles", () => {
  assert.match(app, /entropyCharacters=binary\?\["0","1"\]:\(hodlPadShuffle\?hodlShuffle\(\[\.\.\."0123456789ABCDEF"\]\):\[\.\.\."0123456789ABCDEF"\]\)/);
  assert.match(app, /dice-input-pad dplus entropy-keypad\$\{binary\?" binary-keypad":""\}/);
});

test("seed phrase and private key modes keep fixed on-screen pads", () => {
  assert.match(app, /<div class="dice-input-pad seed-pad" role="group" aria-label="Seed phrase keyboard">/);
  assert.match(app, /<div class="dice-input-pad key-pad" role="group" aria-label="Private key keyboard">/);
  assert.doesNotMatch(app, /pad-wide/);
  assert.match(app, /button\.dataset\.entropyDigit\|\|button\.dataset\.vkCharacter/);
});

test("private key pad cycles numbers, lowercase, and uppercase next to the shuffle toggle", () => {
  assert.match(app, /hodlKeyCharset==="upper"\?\[\.\.\."ABCDEFGHJKLMNPQRSTUVWXYZ"\]:hodlKeyCharset==="lower"\?\[\.\.\."abcdefghijkmnopqrstuvwxyz"\]/);
  assert.match(app, /hodlKeyCharset=hodlKeyCharset==="number"\?"lower":hodlKeyCharset==="lower"\?"upper":"number"/);
  assert.match(app, /<button type="button" class="pad-shuffle-toggle" id="key-charset-cycle"/);
  // The cycle button sits right after the Shuffle pad keys toggle.
  const keyForm = app.match(/Private key format[\s\S]*?hodlBindKeyFields\(\)/)[0];
  assert.ok(keyForm.indexOf('id="pad-shuffle-toggle"') < keyForm.indexOf('id="key-charset-cycle"'), "cycle button must follow the shuffle toggle");
});

test("private key pad offers the 0 key only for the WIF/hex format", () => {
  // 0 is not a base58 digit, so minikey and brain wallet pads omit it.
  assert.match(app, /keyKind==="wif-or-hex"\?\[\.\.\."0123456789"\]:\[\.\.\."123456789"\]/);
  // Switching the private key format re-renders the pad so the 0 key follows the format.
  assert.match(app, /input\[name="kk"\]'\)\.forEach\(radio=>radio\.addEventListener\("change",\(\)=>\{hodlCaptureKey\(\);hodlRenderKeyForm\(\)/);
});

test("pad styles cover the toggle and per-layout grids", () => {
  for (const selector of [".pad-shuffle-toggle", ".seed-pad", ".key-pad", ".dplus-pad", ".hex-keypad", ".with-coin"]) {
    assert.ok(css.includes(selector), `missing ${selector} styles`);
  }
  assert.match(css, /\.dice-input-pad\.seed-pad \{ grid-template-columns: repeat\(6, minmax\(0, 1fr\)\); \}/);
  assert.match(css, /\.dice-input-pad\.key-pad \{ grid-template-columns: repeat\(8, minmax\(0, 1fr\)\); \}/);
  assert.doesNotMatch(css, /\.pad-toolbar/);
  assert.doesNotMatch(css, /pad-wide/);
});

test("the shuffle helper is present in the compiled application", () => {
  assert.ok(built.includes("function hodlShuffle(values)"), "compiled index.html is missing the shuffle helper");
  assert.ok(built.includes('id="pad-shuffle-toggle"'), "compiled index.html is missing the shuffle checkbox");
  assert.ok(built.includes('class="dice-input-pad seed-pad"'), "compiled index.html is missing the seed pad");
  assert.ok(built.includes('class="dice-input-pad key-pad"'), "compiled index.html is missing the private-key pad");
});
