import { test } from "node:test";
import { readFileSync } from "node:fs";
import assert from "node:assert/strict";
import { loadAppFunctions } from "./app-slice-harness.mjs";
import { MiniDocument } from "./mini-dom.mjs";
import {
  createSecureSession, sessionWipe, sessionDeleteKey, sessionGet, sessionSet,
  seedEntry, seedSet, seedIndices, seedUndo, planTurnOn, commitTurnOn,
  planTurnOff, commitTurnOff, discardPlan, SUPPORTED_METHODS,
} from "../src/js/secure-entry.js";
import { wordlist } from "../src/js/bip39-english.js";

const wordIndex = new Map(wordlist.map((word, index) => [word, index]));
const realSecureEntryStubs = {
  createSecureSession,
  sessionWipe,
  sessionDeleteKey,
  sessionGet,
  sessionSet,
  seedEntry,
  seedSet,
  seedIndices,
  seedUndo,
  planTurnOn,
  commitTurnOn,
  planTurnOff,
  commitTurnOff,
  discardPlan,
  hodlSecureSupported: SUPPORTED_METHODS,
};

test("hodlSwitchBarMarkup keeps the privacy bar byte for byte", async () => {
  const t = (text) => text;
  const oracle = ({ id = "reveal", revealed = false, describedBy = "recovery-sheet-disclosure" } = {}) => `<label class="privacy-bar${revealed ? " is-revealed" : ""}">
    <input type="checkbox" role="switch" id="${id}" data-private-reveal ${revealed ? "checked" : ""}${describedBy ? ` aria-describedby="${describedBy}"` : ""} />
    <span class="privacy-bar-state">${revealed ? t("Private data visible") : t("Private data hidden")}</span>
    <span class="privacy-bar-hint">${revealed ? t("Hide it before sharing your screen or stepping away") : t("Reveal only offline, on an air-gapped computer")}</span>
  </label>`;
  const mod = await loadAppFunctions(["hodlSwitchBarMarkup", "hodlPrivacyBarMarkup"], {
    stubs: { hodlT: t, hodlRevealPrivate: false },
  });
  for (const revealed of [false, true]) {
    assert.equal(mod.hodlPrivacyBarMarkup({ revealed }), oracle({ revealed }));
  }
  assert.equal(mod.hodlPrivacyBarMarkup({ id: "sp-reveal", revealed: true, describedBy: "" }), oracle({ id: "sp-reveal", revealed: true, describedBy: "" }));
  assert.equal(mod.hodlSwitchBarMarkup({ id: "x", checked: true, describedBy: "", state: "S", hint: "H", className: "secure-entry-bar" }), `<label class="privacy-bar secure-entry-bar">
    <input type="checkbox" role="switch" id="x" checked />
    <span class="privacy-bar-state">S</span>
    <span class="privacy-bar-hint">H</span>
  </label>`);
});

test("hodlRenderSecureEntryControl shows the switch only when available", async () => {
  const previous = globalThis.document;
  const doc = new MiniDocument();
  globalThis.document = doc;
  try {
    const host = doc.createElement("div");
    host.id = "secure-entry-host";
    doc.body.append(host);
    let available = false, seedActive = false;
    const mod = await loadAppFunctions(["hodlRenderSecureEntryControl"], {
      stubs: {
        ...realSecureEntryStubs,
        hodlSecureEntryAvailable: () => available,
        hodlSecureSeedActive: () => seedActive,
        hodlSecureEntryToggle: () => {},
        hodlT: (text) => text,
      },
      settable: ["hodlSecureEntryOn"],
    });
    mod.__set.hodlSecureEntryOn(false);
    mod.hodlRenderSecureEntryControl();
    assert.equal(host.hidden, true);
    assert.equal(host.innerHTML, "");

    available = true;
    mod.hodlRenderSecureEntryControl();
    assert.equal(host.hidden, false);
    const input = doc.getElementById("secure-entry-switch");
    assert.ok(input);
    assert.equal(input.hasAttribute("data-private-reveal"), false);
    assert.equal(doc.getElementById("secure-entry-unsupported"), null);

    mod.__set.hodlSecureEntryOn(true);
    seedActive = false;
    mod.hodlRenderSecureEntryControl();
    assert.ok(doc.getElementById("secure-entry-unsupported"));

    seedActive = true;
    mod.hodlRenderSecureEntryControl();
    assert.equal(doc.getElementById("secure-entry-unsupported"), null);
  } finally {
    globalThis.document = previous;
  }
});

test("turning on with no seed text commits without a dialog", async () => {
  const previous = globalThis.document;
  globalThis.document = { getElementById: () => null };
  try {
    let dialogCalls = 0;
    const session = createSecureSession();
    const keys = [{ id: 1, seedMethod: "words", fields: { seed: "" }, globalSync: true, globalSyncBitCount: 5, globalSyncSource: "x" }];
    const mod = await loadAppFunctions(["hodlSecureEntryToggle", "hodlSecureEntryOn"], {
      stubs: {
        ...realSecureEntryStubs,
        hodlSecureEntryDialog: async () => { dialogCalls++; return { open: async () => null }; },
        hodlCaptureKey: () => {},
        hodlRenderSecureEntryControl: () => {},
        hodlSetMode: () => {},
        hodlSyncKeyClearButton: () => {},
        hodlSyncDeriveButton: () => {},
        hodlQueueMasterFingerprintPreview: () => {},
        hodlNormalizeSeedMethod: (value) => value === "numbers" ? "numbers" : "words",
        hodlBip39WordIndex: wordIndex,
        hodlBip39Wordlist: wordlist,
        hodlKeyMode: "seed",
      },
      settable: ["hodlSecureEntryOn", "hodlSecureSession", "hodlKeys"],
    });
    mod.__set.hodlSecureSession(session);
    mod.__set.hodlKeys(keys);
    mod.__set.hodlSecureEntryOn(false);
    await mod.hodlSecureEntryToggle(true);
    assert.equal(dialogCalls, 0);
    assert.equal(mod.hodlSecureEntryOn, true);
    assert.equal(session.on, true);
    for (const key of keys) {
      assert.equal(key.globalSync, false);
      assert.equal(key.globalSyncBitCount, 0);
      assert.equal(key.globalSyncSource, "");
    }
  } finally {
    globalThis.document = previous;
  }
});

test("turning on with seed text keeps or clears the words", async () => {
  const previous = globalThis.document;
  globalThis.document = { getElementById: () => null };
  try {
    const session = createSecureSession();
    const phrase1 = "abandon ability able about above absent absorb abstract absurd abuse access accident";
    const phrase2 = "legal winner thank year wave sausage worth useful legal winner thank yellow";
    const keys = [
      { id: 1, name: "Key 1", seedMethod: "words", targetWords: 12, fields: { seed: phrase1 } },
      { id: 2, name: "Key 2", seedMethod: "words", targetWords: 12, fields: { seed: phrase2 } },
    ];
    let choice = "keep", lastOptions = null;
    const mod = await loadAppFunctions(["hodlSecureEntryToggle", "hodlSecureKeyOf", "hodlSecureEntryOn"], {
      stubs: {
        ...realSecureEntryStubs,
        hodlSecureEntryDialog: async () => ({ open: async (options) => { lastOptions = options; return choice; } }),
        hodlCaptureKey: () => {},
        hodlRenderSecureEntryControl: () => {},
        hodlSetMode: () => {},
        hodlSyncKeyClearButton: () => {},
        hodlSyncDeriveButton: () => {},
        hodlQueueMasterFingerprintPreview: () => {},
        hodlNormalizeSeedMethod: (value) => value === "numbers" ? "numbers" : "words",
        hodlBip39WordIndex: wordIndex,
        hodlBip39Wordlist: wordlist,
        hodlKeyMode: "seed",
      },
      settable: ["hodlSecureEntryOn", "hodlSecureSession", "hodlKeys"],
    });
    mod.__set.hodlSecureSession(session);
    mod.__set.hodlKeys(keys);
    mod.__set.hodlSecureEntryOn(false);
    await mod.hodlSecureEntryToggle(true);
    assert.equal(lastOptions.mode, "on");
    assert.equal(lastOptions.canKeep, true);
    assert.deepEqual(lastOptions.names, ["Key 1", "Key 2"]);
    assert.equal(mod.hodlSecureEntryOn, true);
    assert.equal(session.on, true);
    for (const key of keys) {
      assert.equal(key.fields.seed, "");
      const entry = sessionGet(session, mod.hodlSecureKeyOf(key), "seed");
      assert.ok(entry);
      assert.equal(entry.length, 12);
      const expected = key === keys[0] ? phrase1.split(" ") : phrase2.split(" ");
      assert.deepEqual([...entry.indices], expected.map((word) => wordIndex.get(word)));
    }

    const bad = [{ id: 3, name: "Bad", seedMethod: "words", targetWords: 12, fields: { seed: "abandon zzzz" } }];
    const badSession = createSecureSession();
    choice = null;
    mod.__set.hodlSecureSession(badSession);
    mod.__set.hodlKeys(bad);
    mod.__set.hodlSecureEntryOn(false);
    await mod.hodlSecureEntryToggle(true);
    assert.equal(lastOptions.canKeep, false);
    assert.equal(mod.hodlSecureEntryOn, false);
    assert.equal(bad[0].fields.seed, "abandon zzzz");
    assert.equal(sessionGet(badSession, mod.hodlSecureKeyOf(bad[0]), "seed"), null);
  } finally {
    globalThis.document = previous;
  }
});

test("turning on can clear or cancel without leaving a plan", async () => {
  const previous = globalThis.document;
  globalThis.document = { getElementById: () => null };
  try {
    const phrase = "abandon ability able about above absent absorb abstract absurd abuse access accident";
    let choice = "clear";
    const session = createSecureSession();
    const keys = [{ id: 1, name: "Key 1", seedMethod: "words", targetWords: 12, fields: { seed: phrase } }];
    const mod = await loadAppFunctions(["hodlSecureEntryToggle", "hodlSecureKeyOf", "hodlSecureEntryOn"], {
      stubs: {
        ...realSecureEntryStubs,
        hodlSecureEntryDialog: async () => ({ open: async () => choice }),
        hodlCaptureKey: () => {},
        hodlRenderSecureEntryControl: () => {},
        hodlSetMode: () => {},
        hodlSyncKeyClearButton: () => {},
        hodlSyncDeriveButton: () => {},
        hodlQueueMasterFingerprintPreview: () => {},
        hodlNormalizeSeedMethod: (value) => value === "numbers" ? "numbers" : "words",
        hodlBip39WordIndex: wordIndex,
        hodlBip39Wordlist: wordlist,
        hodlKeyMode: "seed",
      },
      settable: ["hodlSecureEntryOn", "hodlSecureSession", "hodlKeys"],
    });
    mod.__set.hodlSecureSession(session);
    mod.__set.hodlKeys(keys);
    mod.__set.hodlSecureEntryOn(false);
    await mod.hodlSecureEntryToggle(true);
    assert.equal(keys[0].fields.seed, "");
    assert.equal(session.entries.size, 0);
    assert.equal(session.on, true);
    assert.equal(mod.hodlSecureEntryOn, true);

    const cancelSession = createSecureSession();
    const cancelKeys = [{ id: 2, name: "Key 2", seedMethod: "words", targetWords: 12, fields: { seed: phrase } }];
    choice = null;
    mod.__set.hodlSecureSession(cancelSession);
    mod.__set.hodlKeys(cancelKeys);
    mod.__set.hodlSecureEntryOn(false);
    await mod.hodlSecureEntryToggle(true);
    assert.equal(cancelKeys[0].fields.seed, phrase);
    assert.equal(cancelSession.entries.size, 0);
    assert.equal(cancelSession.pending.size, 0);
    assert.equal(mod.hodlSecureEntryOn, false);
    assert.doesNotThrow(() => sessionWipe(cancelSession));
  } finally {
    globalThis.document = previous;
  }
});

test("turning off converts, clears or cancels", async () => {
  const previous = globalThis.document;
  globalThis.document = { getElementById: () => null };
  try {
    const words = "abandon ability able about above absent absorb abstract absurd abuse access accident".split(" ");
    const make = () => {
      const session = createSecureSession();
      const key = { id: 1, name: "Key 1", seedMethod: "words", targetWords: 12, fields: { seed: "" } };
      const entry = seedEntry(12);
      for (let i = 0; i < words.length; i += 1) seedSet(entry, i, wordIndex.get(words[i]));
      return { session, key, entry };
    };
    let choice = "convert";
    const mod = await loadAppFunctions(["hodlSecureEntryToggle", "hodlSecureKeyOf", "hodlSecureEntryOn", "hodlSecureEntryHasData"], {
      stubs: {
        ...realSecureEntryStubs,
        hodlSecureEntryDialog: async () => ({ open: async () => choice }),
        hodlCaptureKey: () => {},
        hodlRenderSecureEntryControl: () => {},
        hodlSetMode: () => {},
        hodlSyncKeyClearButton: () => {},
        hodlSyncDeriveButton: () => {},
        hodlQueueMasterFingerprintPreview: () => {},
        hodlNormalizeSeedMethod: (value) => value === "numbers" ? "numbers" : "words",
        hodlBip39WordIndex: wordIndex,
        hodlBip39Wordlist: wordlist,
        hodlKeyMode: "seed",
      },
      settable: ["hodlSecureEntryOn", "hodlSecureSession", "hodlKeys"],
    });

    const convert = make();
    mod.__set.hodlSecureSession(convert.session);
    mod.__set.hodlKeys([convert.key]);
    mod.__set.hodlSecureEntryOn(true);
    sessionSet(convert.session, mod.hodlSecureKeyOf(convert.key, true), "seed", convert.entry);
    await mod.hodlSecureEntryToggle(false);
    assert.equal(convert.key.fields.seed, words.join(" "));
    assert.equal(convert.session.entries.size, 0);
    assert.equal(mod.hodlSecureEntryOn, false);

    const clear = make();
    choice = "clear";
    mod.__set.hodlSecureSession(clear.session);
    mod.__set.hodlKeys([clear.key]);
    mod.__set.hodlSecureEntryOn(true);
    sessionSet(clear.session, mod.hodlSecureKeyOf(clear.key, true), "seed", clear.entry);
    await mod.hodlSecureEntryToggle(false);
    assert.equal(clear.key.fields.seed, "");
    assert.equal(clear.session.entries.size, 0);
    assert.equal(mod.hodlSecureEntryOn, false);

    const cancel = make();
    choice = null;
    mod.__set.hodlSecureSession(cancel.session);
    mod.__set.hodlKeys([cancel.key]);
    mod.__set.hodlSecureEntryOn(true);
    const owner = mod.hodlSecureKeyOf(cancel.key, true);
    sessionSet(cancel.session, owner, "seed", cancel.entry);
    await mod.hodlSecureEntryToggle(false);
    assert.equal(mod.hodlSecureEntryOn, true);
    assert.equal(sessionGet(cancel.session, owner, "seed"), cancel.entry);
    assert.equal(cancel.entry.count, 12);
  } finally {
    globalThis.document = previous;
  }
});

test("the seed form mounts the picker instead of a text field, and each render destroys the last one", () => {
  // hodlRenderKeyForm's closure is most of app.js (every method's branch), so
  // the slice harness cannot load it; this checks the seed branch's shape.
  const app = readFileSync(new URL("../src/js/app.js", import.meta.url), "utf8");
  const start = app.indexOf("function hodlRenderKeyForm() {");
  const body = app.slice(start, app.indexOf("\nfunction ", start + 1));
  const top = body.slice(0, body.indexOf('if (hodlKeyMode === "dice")'));
  assert.match(top, /try \{ hodlSeedPicker\?\.destroy\(\); \} catch \{\}\s*hodlSeedPicker = null;/);
  const seed = body.slice(body.indexOf('if (hodlKeyMode === "seed")'));
  const secure = seed.indexOf("if (hodlSecureSeedActive()) {"), textarea = seed.indexOf('id="seed"');
  assert.ok(secure > 0 && textarea > secure, "the secure branch comes before the words textarea");
  const branch = seed.slice(secure, seed.indexOf("return;", secure));
  assert.match(branch, /id="seed-picker-host"/);
  assert.match(branch, /hodlMountSeedPicker\(\)/);
  assert.doesNotMatch(branch, /id="seed"/);
});

test("global sync is disabled while secure entry is on", async () => {
  const doc = new MiniDocument();
  const mod = await loadAppFunctions(["hodlGlobalSyncControlMarkup"], {
    stubs: {
      hodlSecureEntryOn: true,
      hodlGlobalSyncUnknownBits: -1,
      hodlGlobalSyncMinimumBits: () => 128,
      hodlCopiedIconMarkup: () => "",
      hodlSyncWarningIconMarkup: () => "",
      hodlT: (text) => text,
    },
  });
  const host = doc.createElement("div");
  host.innerHTML = mod.hodlGlobalSyncControlMarkup({ globalSync: true, globalSyncBitCount: 128 });
  const input = host.querySelector("#global-entropy-sync");
  const status = host.querySelector("#global-sync-status");
  assert.ok(input);
  assert.equal(input.disabled, true);
  assert.equal(input.hasAttribute("checked"), false);
  assert.ok(status);
  assert.equal(status.hidden, true);
});

test("the seed length locks while secure words are entered", async () => {
  const previous = globalThis.document;
  const doc = new MiniDocument();
  globalThis.document = doc;
  try {
    const section = doc.createElement("section");
    section.id = "seed-length";
    doc.body.append(section);
    const help = doc.createElement("p");
    help.id = "seed-length-help";
    doc.body.append(help);
    const select = doc.createElement("select");
    select.id = "seed-length-select";
    for (const value of ["12", "15", "18", "21", "24"]) {
      const option = doc.createElement("option");
      option.setAttribute("value", value);
      option.textContent = `${value} words`;
      select.append(option);
    }
    select.value = "24";
    let count = 0;
    const mod = await loadAppFunctions(["hodlUpdateSeedLengthControl"], {
      stubs: {
        hodlSeedConfig: () => ({ words: 24 }),
        hodlSeedLengthSelectEl: select,
        hodlSecureSeedActive: () => true,
        hodlSecureSeedEntry: () => ({ count }),
        hodlKeyMode: "seed",
        hodlSeedMethod: "words",
        hodlSeedZeroIndexed: false,
        hodlCardMethod: "direct",
        hodlEntropyFormat: "hex",
        hodlEntropyFormatConfig: () => ({ remainderBits: 0 }),
        hodlDirectCardFinalRadices: () => [],
        hodlCardNeeded: () => ({ first: 0 }),
        hodlTText: (text) => text,
        hodlT: (text) => text,
      },
    });
    count = 1;
    mod.hodlUpdateSeedLengthControl();
    for (const option of select.options) {
      assert.equal(option.disabled, option.value !== "24");
    }
    assert.match(help.textContent, /undo or clear/);
    count = 0;
    mod.hodlUpdateSeedLengthControl();
    for (const option of select.options) assert.equal(option.disabled, false);
  } finally {
    globalThis.document = previous;
  }
});
