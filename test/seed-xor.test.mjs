// Coldcard-compatible Seed XOR. Fixed examples come from Coldcard's
// docs/seed-xor.md and testing/test_seed_xor.py; independent reference encoding
// for supplementary arithmetic comes from @scure/bip39 (already a dev dependency).
// Run with: node --test test/seed-xor.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { entropyToMnemonic } from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english.js";
import { applyPreviewBlocks } from "../scripts/preview-blocks.mjs";
import { seedXorMnemonic, splitSeedXorMnemonics, initSeedXor, seedXorWipeMem } from "../src/js/seed-xor.js";
import { MiniDocument } from "./mini-dom.mjs";
import { decorateAppPaste, initAppPaste } from "../src/js/app-paste.js";
import { initPrivateCopy } from "../src/js/private-data.js";
import { appClipboardClear, appClipboardText } from "../src/js/app-clipboard.js";
import { loadAppFunctions } from "./app-slice-harness.mjs";

const { hodlAppPasteInto } = await loadAppFunctions(["hodlAppPasteInto"]);

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const read = (path) => readFileSync(join(root, path), "utf8");
const words = (hex) => entropyToMnemonic(Buffer.from(hex, "hex"), wordlist);
const repeated = (byte, length) => byte.repeat(length);

// Coldcard docs/seed-xor.md, lines 170–219 (firmware fab5f64a).
const COLDCARD_24 = [
  "romance wink lottery autumn shop bring dawn tongue range crater truth ability miss spice fitness easy legal release recall obey exchange recycle dragon room",
  "lion misery divide hurry latin fluid camp advance illegal lab pyramid unaware eager fringe sick camera series noodle toy crowd jeans select depth lounge",
  "vault nominee cradle silk own frown throw leg cactus recall talent worry gadget surface shy planet purpose coffee drip few seven term squeeze educate",
];
const COLDCARD_24_RESULT = "silent toe meat possible chair blossom wait occur this worth option bag nurse find fish scene bench asthma bike wage world quit primary indoor";

// Coldcard testing/test_seed_xor.py, lines 183–187 (firmware fab5f64a).
const COLDCARD_18 = [
  "example twelve meadow embrace neither sign ribbon equal inspire guess episode piece fatal unlock prefer unhappy vanish curtain",
  "ostrich present hold dwarf area say act carpet eight jeans student warfare access cause offer suit dawn height",
  "sure lawsuit half gym fatal column remain dash cage orchard frame reform robust social inspire online evolve lobster",
];
const COLDCARD_18_RESULT = "ancient dish minute goddess smooth foil auction floor bean mimic scale transfer trumpet alter echo push mass task";

// Coldcard docs/seed-xor.md, lines 223–264 (firmware fab5f64a).
const COLDCARD_12 = [
  "romance wink lottery autumn shop bring dawn tongue range crater truth ability",
  "boat unfair shell violin tree robust open ride visual forest vintage approve",
  "lion misery divide hurry latin fluid camp advance illegal lab pyramid unhappy",
];
const COLDCARD_12_RESULT = "cannon opinion leader nephew found yard metal galaxy crouch between real trade";

for (const [length, parts, expected] of [[24, COLDCARD_24, COLDCARD_24_RESULT], [18, COLDCARD_18, COLDCARD_18_RESULT], [12, COLDCARD_12, COLDCARD_12_RESULT]]) {
  test(`Coldcard's published ${length}-word parts restore exactly`, () => {
    assert.equal(seedXorMnemonic(parts), expected);
    assert.equal(seedXorMnemonic([...parts].reverse()), expected, "part order does not matter");
  });
}

test("Coldcard's device-confirmed deterministic 12-word split is reproduced and restores", () => {
  // http://github.com/AndreasGassmann/seed-xor/issues/1: actual Coldcard output,
  // confirmed against its deterministic double-SHA256 construction.
  const original = "leisure twenty acoustic better student orient deer negative uniform enforce payment hill";
  const expected = [
    "happy lucky goddess element beach rare tackle island sniff melt blame gauge",
    "blanket hurdle great fall series company tone tortoise cactus scene repair arctic",
  ];
  assert.deepEqual(splitSeedXorMnemonics(original, 2), expected);
  assert.equal(seedXorMnemonic(expected), original);
});

test("Coldcard's published deterministic 24-word split is reproduced and restores", () => {
  // Coldcard tutorial vector retained by AndreasGassmann/seed-xor's tests.
  const original = "gain series drill glad laugh online that witness daring enough arm anger benefit honey convince cool fortune pigeon leg shallow evoke room hat knock";
  const expected = [
    "famous taste quality canvas enable sword kit frequent urge solid attract subject danger robot add slight barrel planet hurt pyramid warrior wild drive myth",
    "arrest boss universe drip crumble effort pink parade suggest lounge air tent car stock coach tongue enable access awesome head rich domain client verb",
  ];
  assert.deepEqual(splitSeedXorMnemonics(original, 2), expected);
  assert.equal(seedXorMnemonic(expected), original);
});

const ZERO_24 = words(repeated("00", 32));
const FF_24 = words(repeated("ff", 32));
const F0_24 = words(repeated("f0", 32));
const OF_24 = words(repeated("0f", 32));

test("restore accepts more than four parts, as Coldcard does; zero output stays valid", () => {
  assert.equal(seedXorMnemonic([ZERO_24, FF_24, ZERO_24, ZERO_24, ZERO_24]), FF_24);
  assert.equal(seedXorMnemonic([ZERO_24, ZERO_24]), ZERO_24, "Coldcard warns about zero output but permits it");
});

test("restore refuses missing, malformed, checksummed-wrong, mixed-length and unsupported-length phrases", () => {
  assert.throws(() => seedXorMnemonic([]), /at least two/i);
  assert.throws(() => seedXorMnemonic([ZERO_24]), /at least two/i);
  assert.throws(() => seedXorMnemonic([ZERO_24, "not a seed phrase"]), /part 2/i);
  assert.throws(() => seedXorMnemonic([ZERO_24, "abandon ".repeat(12).trim()]), /part 2.*checksum|checksum.*part 2/i);
  assert.throws(() => seedXorMnemonic([ZERO_24, words(repeated("00", 16))]), /same length/i);
  assert.throws(() => seedXorMnemonic([words(repeated("00", 20)), words(repeated("ff", 20))]), /12, 18, or 24/);
  assert.throws(() => seedXorMnemonic([ZERO_24, null]), /part 2/i);
});

test("restore canonicalizes harmless case and whitespace without changing the words", () => {
  const parts = COLDCARD_12.map((part) => `  ${part.toUpperCase().replaceAll(" ", "\n")}  `);
  assert.equal(seedXorMnemonic(parts), COLDCARD_12_RESULT);
});

test("the 12-word example from Coldcard's device tests also restores exactly", () => {
  const parts = [
    "become wool crumble brand camera cement gloom sell stand once connect stage",
    "save saddle indicate embrace detail weasel spread life staff mushroom bicycle light",
    "unlock damp injury tape enhance pause sheriff onion valley panic finger moon",
  ];
  assert.equal(seedXorMnemonic(parts), "drama jeans craft mixture filter lamp invest suggest vacant neutral history swim");
});

test("Coldcard's all-ones cancellations reproduce the published zero and one results", () => {
  const lengths = [[12, "wrong"], [18, "when"], [24, "vote"]];
  for (const [length, finalWord] of lengths) {
    const zero = `${"abandon ".repeat(length - 1)}${length === 12 ? "about" : length === 18 ? "agent" : "art"}`;
    const ones = `${"zoo ".repeat(length - 1)}${finalWord}`;
    assert.equal(seedXorMnemonic(Array(7).fill(ones)), ones);
    assert.equal(seedXorMnemonic(Array(4).fill(ones)), zero);
  }
});

test("deterministic split refuses an invalid phrase or a part count Coldcard does not offer", () => {
  assert.throws(() => splitSeedXorMnemonics("abandon ".repeat(12).trim(), 2), /checksum/i);
  for (const count of [0, 1, 2.5, 5, "3"]) assert.throws(() => splitSeedXorMnemonics(COLDCARD_12_RESULT, count), /2, 3, or 4/);
});

test("preview blocks hide every Seed XOR control from release markup", () => {
  const shell = read("src/shell.html");
  const release = applyPreviewBlocks(shell, false);
  const preview = applyPreviewBlocks(shell, true);
  assert.equal(release.includes('id="seedxor-card"'), false);
  assert.equal(release.includes('aria-controls="seedxor-card"'), false);
  assert.equal(preview.includes('id="seedxor-card"'), true);
  assert.equal(preview.includes('aria-controls="seedxor-card"'), true);
  const app = read("src/js/app.js");
  assert.match(app, /if \(__ENTROPYLAB_PREVIEW__\) hodlWorkspaceTabs\.splice\(hodlWorkspaceTabs\.findIndex\(\(\[id\]\) => id === "journal"\), 0, \["seedxor"/, "the preview-only tab is inserted immediately before Journal");
});

const withSeedXorDocument = (body) => {
  const previous = Object.getOwnPropertyDescriptor(globalThis, "document");
  const doc = new MiniDocument();
  doc.body.innerHTML = `
    <section id="seedxor-card">
      <button id="seedxor-mode-restore" data-seedxor-mode="restore"></button>
      <button id="seedxor-mode-split" data-seedxor-mode="split"></button>
      <div id="seedxor-restore-panel">
        <select id="seedxor-parts"><option value="2">2</option><option value="3">3</option><option value="4">4</option></select>
        <div id="seedxor-part-a-field"><label><textarea id="seedxor-part-a" data-seedxor-part></textarea></label></div>
        <div id="seedxor-part-b-field"><label><textarea id="seedxor-part-b" data-seedxor-part></textarea></label></div>
        <div id="seedxor-part-c-field"><label><textarea id="seedxor-part-c" data-seedxor-part></textarea></label></div>
        <div id="seedxor-part-d-field"><label><textarea id="seedxor-part-d" data-seedxor-part></textarea></label></div>
        <button id="seedxor-restore"></button>
      </div>
      <div id="seedxor-split-panel" hidden>
        <textarea id="seedxor-original"></textarea>
        <select id="seedxor-split-count"><option value="2">2</option><option value="3">3</option><option value="4">4</option></select>
        <button id="seedxor-split"></button>
      </div>
      <button id="seedxor-wipe"></button>
      <label id="seedxor-reveal-field" hidden><input id="seedxor-reveal" type="checkbox" data-private-reveal></label>
      <p id="seedxor-error"></p>
      <p id="seedxor-warning" hidden></p>
      <div id="seedxor-result" hidden></div>
    </section>`;
  Object.defineProperty(globalThis, "document", { configurable: true, value: doc });
  try {
    initSeedXor();
    decorateAppPaste(doc, { labelFor: (id) => id });
    return body(doc);
  } finally {
    seedXorWipeMem();
    if (previous) Object.defineProperty(globalThis, "document", previous);
    else delete globalThis.document;
  }
};

const revealSeedXor = (doc) => {
  const reveal = doc.getElementById("seedxor-reveal");
  reveal.checked = true;
  reveal.dispatchEvent({ type: "change", target: reveal });
  return [...doc.querySelectorAll("[data-private-value]")].map((node) => node.textContent);
};

test("part-count visibility includes each field's app-clipboard paste control", () => withSeedXorDocument((doc) => {
  assert.equal(doc.getElementById("seedxor-part-c-field").hidden, true);
  assert.ok(doc.getElementById("seedxor-part-c-field").querySelector('[data-app-paste="seedxor-part-c"]'));
  assert.equal(doc.getElementById("seedxor-part-c-field").querySelector("[data-app-paste-row]").hidden, false, "the wrapper, not an independent control, owns visibility");
  doc.getElementById("seedxor-parts").value = "3";
  doc.getElementById("seedxor-parts").dispatchEvent({ type: "change" });
  assert.equal(doc.getElementById("seedxor-part-c-field").hidden, false);
  assert.equal(doc.getElementById("seedxor-part-d-field").hidden, true);
}));

test("the website restores Coldcard parts only after all required inputs validate", () => withSeedXorDocument((doc) => {
  doc.getElementById("seedxor-parts").value = "3";
  doc.getElementById("seedxor-parts").dispatchEvent({ type: "change", target: doc.getElementById("seedxor-parts") });
  for (const [index, id] of ["a", "b", "c"].entries()) doc.getElementById(`seedxor-part-${id}`).value = COLDCARD_12[index];
  doc.getElementById("seedxor-restore").click();
  assert.deepEqual(revealSeedXor(doc), [COLDCARD_12_RESULT]);
  assert.equal(doc.getElementById("seedxor-error").textContent, "");

  doc.getElementById("seedxor-part-c-field").querySelector("textarea").value = "abandon ".repeat(12).trim();
  doc.getElementById("seedxor-restore").click();
  assert.equal(doc.getElementById("seedxor-result").hidden, true);
  assert.ok(doc.getElementById("seedxor-error").textContent.length > 0);
  assert.equal(doc.getElementById("seedxor-error").textContent.includes("abandon"), false, "errors never echo secret input");
}));

test("the website's deterministic split reproduces a Coldcard device result", () => withSeedXorDocument((doc) => {
  const original = "leisure twenty acoustic better student orient deer negative uniform enforce payment hill";
  doc.getElementById("seedxor-original").value = original;
  doc.getElementById("seedxor-split").click();
  assert.deepEqual(revealSeedXor(doc), [
    "happy lucky goddess element beach rare tackle island sniff melt blame gauge",
    "blanket hurdle great fall series company tone tortoise cactus scene repair arctic",
  ]);
}));

test("a copied split part pastes into the original and restore fields through the shared controls", () => withSeedXorDocument((doc) => {
  const original = "leisure twenty acoustic better student orient deer negative uniform enforce payment hill";
  const expectedA = "happy lucky goddess element beach rare tackle island sniff melt blame gauge";
  const expectedB = "blanket hurdle great fall series company tone tortoise cactus scene repair arctic";
  const savedInputEvent = Object.getOwnPropertyDescriptor(globalThis, "InputEvent");
  globalThis.InputEvent = class extends Event { constructor(type, init = {}) { super(type); this.inputType = init.inputType; } };
  Object.defineProperty(MiniDocument.prototype, "defaultView", { configurable: true, get() { return { getComputedStyle: () => ({ visibility: "visible" }) }; } });
  const rect = Object.getOwnPropertyDescriptor(Object.getPrototypeOf(doc.body), "getClientRects");
  Object.getPrototypeOf(doc.body).getClientRects = () => [{}];
  const stopPaste = initAppPaste({ doc, fill: hodlAppPasteInto });
  const stopCopy = initPrivateCopy({ copyIcon: () => "copy", copiedIcon: () => "copied" });
  appClipboardClear();
  try {
    doc.getElementById("seedxor-original").value = original;
    doc.getElementById("seedxor-split").click();
    revealSeedXor(doc);
    const click = (target) => doc.dispatchEvent({ type: "click", target });
    click(doc.querySelectorAll("[data-private-copy]")[0]);
    assert.equal(appClipboardText(), expectedA, "copy holds the exact displayed part");
    const originalPaste = doc.querySelector('[data-app-paste="seedxor-original"]');
    assert.equal(originalPaste.disabled, false);
    click(originalPaste);
    assert.equal(doc.getElementById("seedxor-original").value, expectedA);

    doc.getElementById("seedxor-original").value = original;
    doc.getElementById("seedxor-split").click();
    revealSeedXor(doc);
    click(doc.querySelectorAll("[data-private-copy]")[1]);
    assert.equal(appClipboardText(), expectedB);
    const restorePaste = doc.querySelector('[data-app-paste="seedxor-part-a"]');
    assert.equal(restorePaste.disabled, false);
    click(restorePaste);
    assert.equal(doc.getElementById("seedxor-part-a").value, expectedB);
  } finally {
    stopCopy();
    stopPaste();
    appClipboardClear();
    if (rect) Object.defineProperty(Object.getPrototypeOf(doc.body), "getClientRects", rect);
    else delete Object.getPrototypeOf(doc.body).getClientRects;
    delete MiniDocument.prototype.defaultView;
    if (savedInputEvent) Object.defineProperty(globalThis, "InputEvent", savedInputEvent);
    else delete globalThis.InputEvent;
  }
}));

test("a duplicate-part zero restore warns but still produces Coldcard's valid result", () => withSeedXorDocument((doc) => {
  doc.getElementById("seedxor-part-a").value = ZERO_24;
  doc.getElementById("seedxor-part-b").value = ZERO_24;
  doc.getElementById("seedxor-restore").click();
  assert.equal(doc.getElementById("seedxor-warning").hidden, false);
  assert.deepEqual(revealSeedXor(doc), [ZERO_24]);
}));

test("concealment removes private text and session wipe clears every input", () => withSeedXorDocument((doc) => {
  doc.getElementById("seedxor-part-a").value = COLDCARD_12[0];
  doc.getElementById("seedxor-part-b").value = COLDCARD_12[1];
  // Part C is the XOR complement of A and B in the published three-part set.
  doc.getElementById("seedxor-parts").value = "3";
  doc.getElementById("seedxor-parts").dispatchEvent({ type: "change" });
  doc.getElementById("seedxor-part-c").value = COLDCARD_12[2];
  doc.getElementById("seedxor-restore").click();
  assert.deepEqual(revealSeedXor(doc), [COLDCARD_12_RESULT]);
  const reveal = doc.getElementById("seedxor-reveal");
  reveal.checked = false;
  reveal.dispatchEvent({ type: "change", target: reveal });
  assert.equal(doc.querySelectorAll("[data-private-value]").length, 0);
  seedXorWipeMem();
  for (const field of doc.querySelectorAll("textarea")) assert.equal(field.value, "");
  assert.equal(doc.getElementById("seedxor-result").hidden, true);
  assert.equal(doc.querySelectorAll("[data-private-value]").length, 0);
}));
