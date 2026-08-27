import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const read = (path) => readFileSync(new URL(`../${path}`, import.meta.url), "utf8");
const template = read("src/index.html");
const app = read("src/js/app.js");
const css = read("src/css/styles.css");
const keyboard = read("src/js/virtual-keyboard.js");
const build = read("scripts/build.mjs");
const built = read("index.html");

test("every entropy input mode offers a virtual keyboard layout", () => {
  assert.match(app, /<textarea id="dice" data-vk="\$\{[^}]*\}"[^>]*aria-describedby="dice-help dice-meta"/);
  assert.match(app, /<textarea id="\$\{inputId\}" data-vk="\$\{inputId\}"/);
  assert.match(app, /<textarea id="seed" data-vk="seed"/);
  assert.match(app, /<textarea id="key" data-vk="key"/);
  for (const layout of ["dice", "dplus", "dplus-numbered", "hex", "bin", "seed", "key"]) {
    assert.match(keyboard, new RegExp(`"${layout}"|${layout}: \\{`), `missing ${layout} layout`);
  }
});

test("the dice keyboard layout follows the active dice method", () => {
  assert.match(app, /data-vk="\$\{ge==="dplus"\?\(hodlDPlusNumberedD16\?"dplus-numbered":"dplus"\):"dice"\}"/);
  assert.match(keyboard, /dice: \{ label: "dice rolls", keys: "123456"/);
  assert.match(keyboard, /dplus: \{ label: "D\+\+ rolls", keys: "1234567890ABCDEF"/);
  assert.match(keyboard, /"dplus-numbered": \{ label: "D\+\+ rolls", keys: "123456789ABCDEFG"/);
});

test("keyboard shuffles character keys with unbiased cryptographic randomness", () => {
  assert.match(keyboard, /crypto\.getRandomValues\(buffer\)/);
  assert.match(keyboard, /while \(buffer\[0\] >= limit\)/);
  assert.match(keyboard, /\[result\[index\], result\[swap\]\] = \[result\[swap\], result\[index\]\]/);
  assert.match(keyboard, /order = shuffled\(order\)/);
  assert.match(keyboard, /"Shuffle the key order"/);
});

test("keyboard entry dispatches real input events so field sanitizers run", () => {
  assert.match(keyboard, /inputType: "insertText"/);
  assert.match(keyboard, /inputType: "deleteContentBackward"/);
  assert.match(keyboard, /target\.setRangeText\(text, start, end, "end"\)/);
  assert.match(keyboard, /target\.setRangeText\("", start, end, "start"\)/);
  assert.match(keyboard, /target\.dispatchEvent\(new InputEvent\("input"/);
});

test("keyboard toggle is an accessible glyph that keeps focus in the field", () => {
  assert.match(keyboard, /className = "vk-toggle"/);
  assert.match(keyboard, /aria-expanded/);
  assert.match(keyboard, /pointerdown", \(event\) => event\.preventDefault\(\)/);
  assert.match(keyboard, /field\.closest\("\.dice-input-shell"\)/);
});

test("keyboard styles cover the toggle, panel, grid, and controls", () => {
  for (const selector of [".vk-wrap", ".vk-toggle", ".vk-panel", ".vk-grid", ".vk-key", ".vk-controls"]) {
    assert.ok(css.includes(selector), `missing ${selector} styles`);
  }
  assert.match(css, /\.vk-toggle\[aria-expanded="true"\]/);
  assert.match(css, /\.vk-panel\[hidden\] \{ display: none; \}/);
});

test("the keyboard module is inlined by the build", () => {
  assert.ok(template.includes("/*@@JS_KEYBOARD@@*/"), "template is missing the keyboard placeholder");
  assert.ok(build.includes('read("js/virtual-keyboard.js")'), "build is missing the keyboard source");
  assert.ok(build.includes("/*@@JS_KEYBOARD@@*/"), "build is missing the keyboard replacement");
  assert.ok(built.includes("vk-toggle"), "compiled index.html is missing the keyboard module");
  assert.ok(built.includes('data-vk="${ge==='), "compiled index.html is missing the dice keyboard hook");
  assert.ok(built.includes('data-vk="seed"'), "compiled index.html is missing the seed keyboard hook");
});
