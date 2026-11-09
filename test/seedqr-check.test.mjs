// The Verify tab's "Check a SeedQR copy" panel (src/js/seedqr-check.js).
//
// Security contract: a seed (words, fingerprint, addresses) is shown only
// for a copy that decodes, words only after Show words and never after
// conceal(), conceal() also takes the entered squares, the pasted digits and
// the picture off the page, and clear() leaves no entered square, pasted
// text, passphrase, word or derived value behind. The panel writes no
// storage, console or network. Exact, wrong-squares and failed results are
// distinct states. Addresses follow the page's network.
//
// Expected fingerprints and addresses come from @scure/bip39, @scure/bip32
// and @scure/btc-signer (the repo's pinned reference libraries), not from
// the panel's own derivation path.
// Run with: npm test
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { mnemonicToSeedSync } from "@scure/bip39";
import { HDKey as ScureHDKey } from "@scure/bip32";
import { TEST_NETWORK, p2wpkh } from "@scure/btc-signer";
import { MiniDocument } from "./mini-dom.mjs";
import { mountSeedQrCheck, seedQrCopyGridMarkup, seedQrCopyGridSvg } from "../src/js/seedqr-check.js";
import { seedQrLayout } from "../src/js/seedqr-grid.js";
import { bip39English } from "../src/js/bip39.js";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const spec = JSON.parse(readFileSync(join(root, "test/fixtures/seedqr/spec-vectors.json"), "utf8"));
const vector = (name) => spec.vectors.find((entry) => entry.name === name);

// Signet shares testnet's encodings; regtest differs only in its bech32 HRP.
const REGTEST = { ...TEST_NETWORK, bech32: "bcrt" };
const reference = (mnemonic, passphrase = "", network = "mainnet") => {
  const master = ScureHDKey.fromMasterSeed(mnemonicToSeedSync(mnemonic, passphrase));
  const branch = master.derive(network === "mainnet" ? "m/84'/0'/0'/0" : "m/84'/1'/0'/0");
  const encoding = network === "mainnet" ? undefined : network === "regtest" ? REGTEST : TEST_NETWORK;
  return {
    fingerprint: master.fingerprint.toString(16).padStart(8, "0"),
    addresses: [0, 1, 2].map((i) => p2wpkh(branch.deriveChild(i).publicKey, encoding).address),
  };
};

function mount(options = {}) {
  const doc = new MiniDocument();
  const host = doc.createElement("div");
  doc.body.appendChild(host);
  const panel = mountSeedQrCheck(host, { doc, win: {}, ...options });
  const $ = (id) => doc.getElementById(id);
  const cells = () => doc.querySelectorAll("[data-seedqr-cell]");
  const choose = (groupId, value) => $(groupId).querySelector(`[data-value="${value}"]`).click();
  // Taps every square whose wanted state differs from what is shown.
  const enter = (rows) => {
    for (const cell of cells()) {
      const index = Number(cell.getAttribute("data-seedqr-cell"));
      const size = rows.length, want = rows[Math.floor(index / size)][index % size] === "1";
      if ((cell.getAttribute("aria-pressed") === "true") !== want) cell.click();
    }
  };
  const tap = (row, col) => doc.querySelector(`[data-seedqr-cell="${row * Number($("seedqr-check-grid").getAttribute("data-size")) + col}"]`).click();
  const pressed = () => cells().filter((cell) => cell.getAttribute("aria-pressed") === "true").map((cell) => cell.getAttribute("data-seedqr-cell"));
  const addresses = () => $("seedqr-check-addresses").querySelectorAll("li").map((item) => item.textContent);
  return { doc, host, panel, $, cells, choose, enter, tap, pressed, addresses, state: () => $("seedqr-check-result").getAttribute("data-state") };
}

const flipRows = (rows, cells) => {
  const grid = rows.map((row) => row.split(""));
  for (const [row, col] of cells) grid[row][col] = grid[row][col] === "1" ? "0" : "1";
  return grid.map((row) => row.join(""));
};

test("the grid starts as an empty 25 by 25 SeedQR and follows the chosen type and length", () => {
  const ui = mount();
  assert.equal(ui.cells().length, 625);
  assert.ok(ui.cells().every((cell) => cell.getAttribute("aria-pressed") === "false"));
  ui.choose("seedqr-check-words", "24");
  assert.equal(ui.cells().length, 841);
  ui.choose("seedqr-check-kind", "compact");
  assert.equal(ui.cells().length, 625);
  ui.choose("seedqr-check-words", "12");
  assert.equal(ui.cells().length, 441);
  // A quarter at a time: the top-left quarter of 21 is 11 by 11.
  ui.choose("seedqr-check-view", "0");
  assert.equal(ui.cells().length, 121);
  ui.choose("seedqr-check-view", "3");
  assert.equal(ui.cells().length, 100);
  assert.equal(ui.cells()[0].getAttribute("data-seedqr-cell"), String(11 * 21 + 11));
});

test("phones start on a quarter of the grid", () => {
  const ui = mount({ win: { matchMedia: () => ({ matches: true }) } });
  assert.equal(ui.cells().length, 13 * 13);
});

test("an exact copy: exact state, the spec words behind Show words, fingerprint and addresses match the reference", () => {
  const v = vector("vector 4 standard");
  const ui = mount();
  ui.enter(v.rows);
  ui.$("seedqr-check-run").click();
  assert.equal(ui.state(), "exact");
  assert.equal(ui.$("seedqr-check-seed").hidden, false);
  assert.equal(ui.$("seedqr-check-differences").hidden, true);
  const expected = reference(v.words);
  assert.equal(ui.$("seedqr-check-fingerprint").textContent, expected.fingerprint);
  assert.deepEqual(ui.$("seedqr-check-addresses").querySelectorAll("li").map((item) => item.textContent), expected.addresses);
  // Hidden until revealed; hidden again by conceal().
  const words = v.words.split(" ");
  assert.ok(!words.some((word) => ui.host.textContent.includes(` ${word} `)));
  assert.ok(!ui.host.innerHTML.includes(v.words));
  ui.$("seedqr-check-reveal").click();
  assert.ok(ui.$("seedqr-check-words-value").textContent.includes(v.words));
  ui.panel.conceal();
  assert.ok(!ui.host.innerHTML.includes(v.words));
  assert.equal(ui.$("seedqr-check-reveal").getAttribute("aria-pressed"), "false");
});

test("the passphrase changes the fingerprint and addresses, as the reference does", () => {
  const v = vector("vector 1 standard");
  const ui = mount();
  ui.choose("seedqr-check-words", "24");
  ui.enter(v.rows);
  ui.$("seedqr-check-run").click();
  const pass = ui.$("seedqr-check-pass");
  pass.value = "TREZOR";
  pass.oninput();
  const expected = reference(v.words, "TREZOR");
  assert.equal(ui.$("seedqr-check-fingerprint").textContent, expected.fingerprint);
  assert.deepEqual(ui.$("seedqr-check-addresses").querySelectorAll("li").map((item) => item.textContent), expected.addresses);
});

test("wrong squares: a distinct state, and every wrong square listed by row and column from 1", () => {
  const v = vector("vector 5 standard");
  const { order } = seedQrLayout(25);
  // Two data squares in different codewords, and one timing square.
  const picks = [order[3], order[8 * 20 + 1], 6 * 25 + 11].map((cell) => [Math.floor(cell / 25), cell % 25]);
  const ui = mount();
  ui.enter(flipRows(v.rows, picks));
  ui.$("seedqr-check-run").click();
  assert.equal(ui.state(), "wrong-squares");
  assert.notEqual(ui.state(), "exact");
  const listed = ui.$("seedqr-check-differences").querySelectorAll("li").map((item) => `${item.getAttribute("data-seedqr-row")},${item.getAttribute("data-seedqr-col")}`).sort();
  assert.deepEqual(listed, picks.map(([row, col]) => `${row + 1},${col + 1}`).sort());
  // It still decodes, so the seed is shown for the final comparison.
  assert.equal(ui.$("seedqr-check-fingerprint").textContent, reference(v.words).fingerprint);
  // The wrong squares are marked on the entry grid; fixing them all and
  // checking again gives an exact match.
  assert.deepEqual(ui.doc.querySelectorAll("[data-seedqr-wrong]").map((cell) => Number(cell.getAttribute("data-seedqr-cell"))).sort((a, b) => a - b), picks.map(([row, col]) => row * 25 + col).sort((a, b) => a - b));
  for (const [row, col] of picks) ui.tap(row, col);
  assert.equal(ui.doc.querySelectorAll("[data-seedqr-wrong]").length, 0);
  assert.equal(ui.state(), "stale");
  assert.equal(ui.$("seedqr-check-seed").hidden, true);
  ui.$("seedqr-check-run").click();
  assert.equal(ui.state(), "exact");
});

test("past the correction limit: failed, and no seed, word or fingerprint anywhere", () => {
  const v = vector("vector 6 standard");
  const { order } = seedQrLayout(25);
  const picks = [0, 3, 7, 12, 20].map((codeword) => order[codeword * 8 + 2]).map((cell) => [Math.floor(cell / 25), cell % 25]);
  const ui = mount();
  ui.enter(flipRows(v.rows, picks));
  ui.$("seedqr-check-run").click();
  assert.equal(ui.state(), "failed");
  assert.equal(ui.$("seedqr-check-seed").hidden, true);
  assert.equal(ui.$("seedqr-check-fingerprint").textContent, "");
  assert.equal(ui.$("seedqr-check-addresses").querySelectorAll("li").length, 0);
  ui.$("seedqr-check-reveal").click();
  assert.ok(!v.words.split(" ").slice(0, 3).some((word) => ui.host.innerHTML.includes(word)));
});

test("conceal() takes the entered squares and the picture off the page until Show my copy", () => {
  const v = vector("vector 4 standard");
  const ui = mount();
  // Nothing entered: nothing to hide, and the grid stays.
  ui.panel.conceal();
  assert.equal(ui.cells().length, 625);
  assert.equal(ui.$("seedqr-check-concealed").hidden, true);
  ui.enter(v.rows);
  ui.$("seedqr-check-run").click();
  const before = ui.pressed(), picture = ui.$("seedqr-check-picture").innerHTML;
  assert.ok(before.length > 0 && picture.length > 0);
  ui.panel.conceal();
  assert.equal(ui.cells().length, 0);
  assert.equal(ui.$("seedqr-check-picture").innerHTML, "");
  assert.equal(ui.$("seedqr-check-picture").hidden, true);
  assert.equal(ui.$("seedqr-check-concealed").hidden, false);
  assert.ok(!ui.host.innerHTML.includes(v.words));
  // The result and the public values stay; the copy comes back unchanged.
  assert.equal(ui.state(), "exact");
  assert.equal(ui.$("seedqr-check-fingerprint").textContent, reference(v.words).fingerprint);
  ui.$("seedqr-check-unconceal").click();
  assert.deepEqual(ui.pressed(), before);
  assert.equal(ui.$("seedqr-check-picture").innerHTML, picture);
  assert.equal(ui.$("seedqr-check-concealed").hidden, true);
  // Hidden while unchecked too: a copy half entered is the seed in part.
  ui.panel.clear();
  ui.tap(0, 0);
  ui.panel.conceal();
  assert.equal(ui.cells().length, 0);
  ui.$("seedqr-check-unconceal").click();
  assert.deepEqual(ui.pressed(), ["0"]);
});

test("conceal() blanks pasted digits, checked or not, and Clear drops what it held", () => {
  const v = vector("vector 2 standard");
  const ui = mount();
  ui.choose("seedqr-check-mode", "text");
  ui.$("seedqr-check-text").value = v.digits;
  ui.panel.conceal();
  assert.equal(ui.$("seedqr-check-text").value, "");
  assert.equal(ui.$("seedqr-check-concealed").hidden, false);
  ui.$("seedqr-check-unconceal").click();
  assert.equal(ui.$("seedqr-check-text").value, v.digits);
  ui.$("seedqr-check-text-run").click();
  assert.equal(ui.state(), "parsed");
  ui.panel.conceal();
  assert.equal(ui.$("seedqr-check-text").value, "");
  assert.equal(ui.$("seedqr-check-picture").innerHTML, "");
  assert.ok(!ui.host.innerHTML.includes(v.digits));
  ui.$("seedqr-check-unconceal").click();
  assert.equal(ui.$("seedqr-check-text").value, v.digits);
  assert.notEqual(ui.$("seedqr-check-picture").innerHTML, "");
  // Clear while hidden forgets the held copy as well.
  ui.panel.conceal();
  ui.$("seedqr-check-clear").click();
  assert.equal(ui.$("seedqr-check-concealed").hidden, true);
  assert.equal(ui.$("seedqr-check-text").value, "");
  assert.equal(ui.state(), "empty");
});

test("the addresses follow the page's network and change with it", () => {
  const v = vector("vector 4 standard");
  let network = "testnet";
  const ui = mount({ network: () => network });
  ui.enter(v.rows);
  ui.$("seedqr-check-run").click();
  assert.deepEqual(ui.addresses(), reference(v.words, "", "testnet").addresses);
  for (network of ["regtest", "signet", "mainnet"]) {
    ui.doc.dispatchEvent({ type: "hodl:network-default" });
    assert.deepEqual(ui.addresses(), reference(v.words, "", network).addresses, network);
  }
  // The fingerprint is the seed's, on every network.
  assert.equal(ui.$("seedqr-check-fingerprint").textContent, reference(v.words).fingerprint);
  ui.panel.destroy();
  assert.equal(ui.doc.listenerCount("hodl:network-default"), 0);
});

test("a language switch relabels the panel and keeps the copy and its result", () => {
  const v = vector("vector 5 standard");
  const { order } = seedQrLayout(25);
  const picks = [order[3], order[8 * 20 + 1]].map((cell) => [Math.floor(cell / 25), cell % 25]);
  let language = "en";
  const ui = mount({ translate: (text) => (language === "en" ? text : `[${language}] ${text}`) });
  ui.enter(flipRows(v.rows, picks));
  ui.$("seedqr-check-run").click();
  const before = ui.pressed(), fingerprint = ui.$("seedqr-check-fingerprint").textContent;
  language = "xx";
  ui.panel.retranslate();
  const translated = (text) => text.startsWith("[xx] ");
  for (const id of ["seedqr-check-run", "seedqr-check-fixed", "seedqr-check-clear", "seedqr-check-reveal", "seedqr-check-status", "seedqr-check-size"]) {
    assert.ok(translated(ui.$(id).textContent), id);
  }
  assert.ok(translated(ui.$("seedqr-check-mode").getAttribute("aria-label")));
  assert.ok(translated(ui.cells()[0].getAttribute("aria-label")));
  assert.ok(ui.$("seedqr-check-differences").querySelectorAll("li").every((item) => translated(item.textContent)));
  assert.equal(ui.state(), "wrong-squares");
  assert.deepEqual(ui.pressed(), before);
  assert.equal(ui.$("seedqr-check-fingerprint").textContent, fingerprint);
  // A hidden copy stays hidden.
  ui.panel.conceal();
  ui.panel.retranslate();
  assert.equal(ui.cells().length, 0);
  assert.ok(translated(ui.$("seedqr-check-unconceal").textContent));
});

test("Fill in the fixed patterns sets exactly the finder, timing, alignment and dark squares", () => {
  const ui = mount();
  ui.$("seedqr-check-fixed").click();
  const { regions, fixed } = seedQrLayout(25);
  for (const cell of ui.cells()) {
    const index = Number(cell.getAttribute("data-seedqr-cell"));
    const want = regions[index] >= 1 && regions[index] <= 4 && fixed[index] === 1;
    assert.equal(cell.getAttribute("aria-pressed") === "true", want, `square ${index}`);
  }
});

test("pasted digits: valid digits show the seed and a reference grid; others fail with no seed", () => {
  const v = vector("vector 2 standard");
  const ui = mount();
  ui.choose("seedqr-check-mode", "text");
  assert.equal(ui.$("seedqr-check-grid-panel").hidden, true);
  ui.$("seedqr-check-text").value = v.digits;
  ui.$("seedqr-check-text-run").click();
  assert.equal(ui.state(), "parsed");
  assert.equal(ui.$("seedqr-check-fingerprint").textContent, reference(v.words).fingerprint);
  assert.equal(ui.$("seedqr-check-picture").hidden, false);
  ui.$("seedqr-check-text").value = v.digits.slice(0, 95);
  ui.$("seedqr-check-text").oninput();
  ui.$("seedqr-check-text-run").click();
  assert.equal(ui.state(), "failed");
  assert.equal(ui.$("seedqr-check-seed").hidden, true);
  assert.equal(ui.$("seedqr-check-fingerprint").textContent, "");
});

test("clear() leaves nothing entered, pasted, typed, decoded or derived", () => {
  const v = vector("vector 4 standard");
  const ui = mount();
  ui.enter(v.rows);
  ui.$("seedqr-check-run").click();
  ui.$("seedqr-check-reveal").click();
  ui.$("seedqr-check-pass").value = "secret";
  ui.$("seedqr-check-text").value = v.digits;
  ui.panel.clear();
  assert.equal(ui.state(), "empty");
  assert.ok(ui.cells().every((cell) => cell.getAttribute("aria-pressed") === "false"));
  assert.equal(ui.$("seedqr-check-text").value, "");
  assert.equal(ui.$("seedqr-check-pass").value, "");
  assert.equal(ui.$("seedqr-check-fingerprint").textContent, "");
  assert.equal(ui.$("seedqr-check-picture").innerHTML, "");
  assert.ok(!ui.host.innerHTML.includes(v.words.split(" ")[0]));
  // The panel's own Clear button runs the same clear.
  ui.enter(v.rows);
  ui.$("seedqr-check-clear").click();
  assert.ok(ui.cells().every((cell) => cell.getAttribute("aria-pressed") === "false"));
  ui.panel.destroy();
  assert.equal(ui.host.childNodes.length, 0);
});

test("the copy grid shows the mask its code uses and numbers every row and column", () => {
  const v = vector("vector 4 standard");
  const indices = Uint16Array.from(v.words.split(" "), (word) => bip39English.indexOf(word));
  const doc = new MiniDocument();
  const host = doc.createElement("div");
  host.innerHTML = seedQrCopyGridMarkup("standard-seedqr", indices);
  const details = host.querySelector("[data-seedqr-copy-grid]");
  assert.match(details.getAttribute("data-seedqr-mask"), /^[0-7]$/);
  const labels = host.querySelectorAll("text").map((node) => node.textContent);
  assert.equal(labels.length, 50);
  for (let i = 1; i <= 25; i++) assert.equal(labels.filter((label) => label === String(i)).length, 2);
  // Wrong squares are outlined; nothing else is.
  const svg = seedQrCopyGridSvg(new Uint8Array(625), 25, { wrong: new Set([0, 624]) });
  assert.equal((svg.match(/<rect x=/g) ?? []).length, 2);
});

test("the panel's modules use no storage, console, clipboard or network API", () => {
  for (const file of ["src/js/seedqr-check.js", "src/js/seedqr-grid.js"]) {
    const source = readFileSync(join(root, file), "utf8").replace(/^\s*\/\/.*$/gm, "");
    for (const api of ["localStorage", "sessionStorage", "indexedDB", "console.", "navigator.clipboard", "fetch(", "XMLHttpRequest", "WebSocket", "sendBeacon", "getUserMedia"]) {
      assert.ok(!source.includes(api), `${file} uses ${api}`);
    }
  }
});
