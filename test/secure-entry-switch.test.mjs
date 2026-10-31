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
    // mode: "seed" puts this key in the turn-on loop. Without the loop's
    // empty-text guard the key would be staged, the dialog would open and
    // dialogCalls would be 1.
    const keys = [{ id: 1, mode: "seed", seedMethod: "words", fields: { seed: "" }, globalSync: true, globalSyncBitCount: 5, globalSyncSource: "x" }];
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

test("an extended key in the seed field stays text and opens no dialog (MiniMax)", async () => {
  const previous = globalThis.document;
  const xprv = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";
  // The field on screen keeps the text too: the redraw saves it back into the
  // key, so emptying it here would silently drop the extended key.
  const field = { value: xprv, dataset: { previousValue: xprv } };
  globalThis.document = { getElementById: (id) => id === "seed" ? field : null };
  try {
    let dialogCalls = 0;
    const session = createSecureSession();
    // mode: "seed" puts this key in the turn-on loop. Without the
    // extended-key guard the xprv would be staged as seed text: the dialog
    // would open and the field would be cleared.
    const keys = [{ id: 1, mode: "seed", seedMethod: "words", fields: { seed: xprv }, globalSync: false }];
    const mod = await loadAppFunctions(["hodlSecureEntryToggle", "hodlSecureEntryOn"], {
      stubs: {
        ...realSecureEntryStubs,
        hodlSecureEntryDialog: async () => { dialogCalls++; return { open: async () => "clear" }; },
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
      settable: ["hodlSecureEntryOn", "hodlSecureSession", "hodlKeys", "hodlActiveKey"],
    });
    mod.__set.hodlSecureSession(session);
    mod.__set.hodlKeys(keys);
    mod.__set.hodlActiveKey(0);
    mod.__set.hodlSecureEntryOn(false);
    await mod.hodlSecureEntryToggle(true);
    assert.equal(dialogCalls, 0);
    assert.equal(keys[0].fields.seed, xprv);
    assert.equal(field.value, xprv, "the field on screen keeps the extended key");
    assert.equal(mod.hodlSecureEntryOn, true);
  } finally {
    globalThis.document = previous;
  }
});

test("Keep empties the field on screen when the active key's words moved", async () => {
  const previous = globalThis.document;
  const words = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
  const field = { value: words, dataset: { previousValue: words } };
  globalThis.document = { getElementById: (id) => id === "seed" ? field : null };
  try {
    const session = createSecureSession();
    const keys = [{ id: 1, name: "Key Station", mode: "seed", seedMethod: "words", targetWords: 12, fields: { seed: words }, globalSync: false }];
    const mod = await loadAppFunctions(["hodlSecureEntryToggle", "hodlSecureEntryOn"], {
      stubs: {
        ...realSecureEntryStubs,
        hodlSecureEntryDialog: async () => ({ open: async () => "keep" }),
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
      settable: ["hodlSecureEntryOn", "hodlSecureSession", "hodlKeys", "hodlActiveKey"],
    });
    mod.__set.hodlSecureSession(session);
    mod.__set.hodlKeys(keys);
    mod.__set.hodlActiveKey(0);
    mod.__set.hodlSecureEntryOn(false);
    await mod.hodlSecureEntryToggle(true);
    assert.equal(mod.hodlSecureEntryOn, true);
    assert.equal(keys[0].fields.seed, "");
    assert.equal(field.value, "");
    assert.equal(field.dataset.previousValue, undefined);
  } finally {
    globalThis.document = previous;
  }
});

test("a phrase longer than the key's length stays text and opens no dialog (MiniMax)", async () => {
  const previous = globalThis.document;
  globalThis.document = { getElementById: () => null };
  try {
    let dialogCalls = 0;
    const session = createSecureSession();
    // 24 valid words, but this key's length is 12.
    const phrase = Array(23).fill("abandon").concat("art").join(" ");
    // mode: "seed" puts this key in the turn-on loop. Without the word-count
    // guard the 24-word phrase would be staged for a 12-word key: the dialog
    // would open and the phrase would be cleared.
    const keys = [{ id: 1, mode: "seed", seedMethod: "words", targetWords: 12, fields: { seed: phrase }, globalSync: false }];
    const mod = await loadAppFunctions(["hodlSecureEntryToggle", "hodlSecureEntryOn"], {
      stubs: {
        ...realSecureEntryStubs,
        hodlSecureEntryDialog: async () => { dialogCalls++; return { open: async () => "clear" }; },
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
    assert.equal(keys[0].fields.seed, phrase);
    assert.equal(mod.hodlSecureEntryOn, true);
  } finally {
    globalThis.document = previous;
  }
});

test("turning on drops the last-word cache, and the length lock holds in hodlSetSeedLength (GLM, Kimi, MiniMax)", () => {
  const app = readFileSync(new URL("../src/js/app.js", import.meta.url), "utf8");
  const toggle = app.slice(app.indexOf("async function hodlSecureEntryToggle("), app.indexOf("\nfunction ", app.indexOf("async function hodlSecureEntryToggle(")));
  const committed = toggle.indexOf("hodlSecureEntryOn = true;");
  assert.ok(committed > 0 && toggle.indexOf("hodlLastWordCache.clear();", committed) > committed, "turning on clears the last-word cache");
  const setter = app.slice(app.indexOf("function hodlSetSeedLength("), app.indexOf("\nfunction ", app.indexOf("function hodlSetSeedLength(")));
  const guard = setter.indexOf("hodlSecureSeedHasWords(hodlSecureKeyOf(hodlKeys[hodlActiveKey]))");
  assert.ok(guard > 0 && guard < setter.indexOf("hodlCaptureKey();"), "the setter refuses a new length before changing anything");
});

test("End Session redraws a seed form that showed the picker (GLM)", () => {
  const app = readFileSync(new URL("../src/js/app.js", import.meta.url), "utf8");
  const end = app.indexOf("try { hodlSecureEntryEnd(); } catch {}");
  assert.ok(end > 0);
  assert.match(app.slice(end, end + 300), /try \{ if \(document\.getElementById\("seed-picker-host"\)\) hodlSetMode\(hodlKeyMode\); \} catch \{\}/);
});

test("the seed-length dropdown is told to resync only when something changed (MiniMax)", () => {
  const app = readFileSync(new URL("../src/js/app.js", import.meta.url), "utf8");
  const start = app.indexOf("function hodlUpdateSeedLengthControl(");
  const body = app.slice(start, app.indexOf("\nfunction ", start + 1));
  assert.equal(body.match(/dispatchEvent\(new Event\("entropylab:sync-select"\)\)/g)?.length, 1);
  assert.match(body, /if \(changed\) hodlSeedLengthSelectEl\.dispatchEvent/);
});

test("a redraw that throws after the commit leaves the switch on with the session (red team)", async () => {
  const previous = globalThis.document;
  globalThis.document = { getElementById: () => null };
  try {
    const session = createSecureSession();
    const keys = [{ id: 1, seedMethod: "words", fields: { seed: "" }, globalSync: false }];
    const mod = await loadAppFunctions(["hodlSecureEntryToggle", "hodlSecureEntryOn"], {
      stubs: {
        ...realSecureEntryStubs,
        hodlSecureEntryDialog: async () => ({ open: async () => null }),
        hodlCaptureKey: () => {},
        hodlRenderSecureEntryControl: () => {},
        hodlSetMode: () => { throw new Error("redraw failed"); },
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
    assert.equal(session.on, true);
    assert.equal(mod.hodlSecureEntryOn, true);
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
      { id: 1, name: "Key 1", mode: "seed", seedMethod: "words", targetWords: 12, fields: { seed: phrase1 } },
      { id: 2, name: "Key 2", mode: "seed", seedMethod: "words", targetWords: 12, fields: { seed: phrase2 } },
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

    const bad = [{ id: 3, name: "Bad", mode: "seed", seedMethod: "words", targetWords: 12, fields: { seed: "abandon zzzz" } }];
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

test("Clear marks a committed key and refuses Journal backup", async () => {
  const previous = globalThis.document;
  globalThis.document = { getElementById: () => null };
  try {
    const session = createSecureSession();
    const phrase = "abandon ability able about above absent absorb abstract absurd abuse access accident";
    const committed = { id: 1, name: "Committed", isLab: false, mode: "seed", seedMethod: "words", targetWords: 12, fields: { seed: phrase }, result: { masterFingerprint: "73c5da0a" } };
    const editor = { id: 2, name: "Editor", isLab: true, mode: "seed", seedMethod: "words", targetWords: 12, fields: { seed: phrase }, result: null };
    const keys = [committed, editor];
    const tTextCalls = [];
    const mod = await loadAppFunctions(["hodlSecureEntryToggle", "hodlSecureKeyOf", "hodlSecureEntryOn", "hodlSecureEntryBackupRefusal"], {
      stubs: {
        ...realSecureEntryStubs,
        hodlSecureEntryDialog: async () => ({ open: async () => "clear" }),
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
        hodlTText: (text) => { tTextCalls.push(text); return text; },
        hodlPrivateKeyValues: (fields) => fields.privateKeys,
        hodlEntropyFormats: { hex: {}, bin: {} },
      },
      settable: ["hodlSecureEntryOn", "hodlSecureSession", "hodlKeys"],
    });
    mod.__set.hodlSecureSession(session);
    mod.__set.hodlKeys(keys);
    mod.__set.hodlSecureEntryOn(false);
    await mod.hodlSecureEntryToggle(true);
    assert.equal(committed.secureCleared, true);
    assert.equal(committed.fields.seed, "");
    assert.equal("secureCleared" in editor, false);
    assert.equal(editor.fields.seed, "");
    const refusal = mod.hodlSecureEntryBackupRefusal();
    assert.ok(refusal instanceof Error);
    assert.ok(tTextCalls.some((text) => text.includes("cleared")));
  } finally {
    globalThis.document = previous;
  }
});

test("Keep leaves no secureCleared mark", async () => {
  const previous = globalThis.document;
  globalThis.document = { getElementById: () => null };
  try {
    const session = createSecureSession();
    const phrase = "abandon ability able about above absent absorb abstract absurd abuse access accident";
    const committed = { id: 1, name: "Committed", isLab: false, mode: "seed", seedMethod: "words", targetWords: 12, fields: { seed: phrase }, result: { masterFingerprint: "73c5da0a" } };
    const editor = { id: 2, name: "Editor", isLab: true, mode: "seed", seedMethod: "words", targetWords: 12, fields: { seed: phrase }, result: null };
    const keys = [committed, editor];
    const mod = await loadAppFunctions(["hodlSecureEntryToggle", "hodlSecureKeyOf", "hodlSecureEntryOn"], {
      stubs: {
        ...realSecureEntryStubs,
        hodlSecureEntryDialog: async () => ({ open: async () => "keep" }),
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
        hodlPrivateKeyValues: (fields) => fields.privateKeys,
        hodlEntropyFormats: { hex: {}, bin: {} },
      },
      settable: ["hodlSecureEntryOn", "hodlSecureSession", "hodlKeys"],
    });
    mod.__set.hodlSecureSession(session);
    mod.__set.hodlKeys(keys);
    mod.__set.hodlSecureEntryOn(false);
    await mod.hodlSecureEntryToggle(true);
    for (const key of keys) {
      assert.equal("secureCleared" in key, false);
      assert.equal(key.fields.seed, "");
    }
  } finally {
    globalThis.document = previous;
  }
});

test("Clear empties the fields Global sync filled", async () => {
  const previous = globalThis.document;
  globalThis.document = { getElementById: () => null };
  try {
    const session = createSecureSession();
    const phrase = "abandon ability able about above absent absorb abstract absurd abuse access accident";
    const synced = {
      id: 1, name: "Synced", mode: "seed", seedMethod: "words", targetWords: 12, globalSync: true, lastWord: "accident",
      fields: {
        seed: phrase, seedNumbers: "1 2 3", hex: "abcd", bin: "1010",
        dplusDice: "dplus", directCards: "cards", bitboxDice: "bitbox",
        name: "Synced", privateKeys: { wif: "wifvalue", "hex-key": "hexkeyvalue" },
      },
    };
    const unsynced = { id: 2, name: "Unsynced", mode: "seed", seedMethod: "words", targetWords: 12, globalSync: false, fields: { seed: phrase, hex: "beef" } };
    const keys = [synced, unsynced];
    const mod = await loadAppFunctions(["hodlSecureEntryToggle", "hodlSecureKeyOf", "hodlSecureEntryOn", "hodlClearGlobalSyncCopies"], {
      stubs: {
        ...realSecureEntryStubs,
        hodlSecureEntryDialog: async () => ({ open: async () => "clear" }),
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
        hodlPrivateKeyValues: (fields) => fields.privateKeys,
        hodlEntropyFormats: { hex: {}, bin: {} },
      },
      settable: ["hodlSecureEntryOn", "hodlSecureSession", "hodlKeys"],
    });
    mod.__set.hodlSecureSession(session);
    mod.__set.hodlKeys(keys);
    mod.__set.hodlSecureEntryOn(false);
    await mod.hodlSecureEntryToggle(true);
    for (const field of ["hex", "bin", "seed", "seedNumbers", "dplusDice", "directCards", "bitboxDice"]) {
      assert.equal(synced.fields[field], "", field);
    }
    assert.equal(synced.fields.privateKeys.wif, "");
    assert.equal(synced.fields.privateKeys["hex-key"], "");
    assert.equal(synced.fields.name, "Synced");
    assert.equal(synced.lastWord, "");
    assert.equal(unsynced.fields.hex, "beef");
    assert.equal(unsynced.fields.seed, "");
  } finally {
    globalThis.document = previous;
  }
});

test("Keep empties the fields Global sync filled from the words, so they stay only in Secure entry (owner 10-31)", async () => {
  const previous = globalThis.document;
  globalThis.document = { getElementById: () => null };
  try {
    const session = createSecureSession();
    const phrase = "abandon ability able about above absent absorb abstract absurd abuse access accident";
    const synced = {
      id: 1, name: "Synced", mode: "seed", seedMethod: "words", targetWords: 12, globalSync: true, globalSyncSource: "seed:words", lastWord: "accident",
      fields: {
        seed: phrase, seedNumbers: "1 2 3", hex: "abcd", bin: "1010",
        dplusDice: "dplus", directCards: "cards", bitboxDice: "bitbox",
        name: "Synced", privateKeys: { wif: "wifvalue", "hex-key": "hexkeyvalue" },
      },
    };
    const unsynced = { id: 2, name: "Unsynced", mode: "seed", seedMethod: "words", targetWords: 12, globalSync: false, lastWord: "kept", fields: { seed: phrase, hex: "beef" } };
    const keys = [synced, unsynced];
    const mod = await loadAppFunctions(["hodlSecureEntryToggle", "hodlSecureKeyOf", "hodlSecureEntryOn", "hodlClearGlobalSyncCopies"], {
      stubs: {
        ...realSecureEntryStubs,
        hodlSecureEntryDialog: async () => ({ open: async () => "keep" }),
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
        hodlPrivateKeyValues: (fields) => fields.privateKeys,
        hodlEntropyFormats: { hex: {}, bin: {} },
      },
      settable: ["hodlSecureEntryOn", "hodlSecureSession", "hodlKeys"],
    });
    mod.__set.hodlSecureSession(session);
    mod.__set.hodlKeys(keys);
    mod.__set.hodlSecureEntryOn(false);
    await mod.hodlSecureEntryToggle(true);
    assert.equal(mod.hodlSecureEntryOn, true);
    // Both keys' words moved into the session.
    for (const key of keys) {
      assert.ok(sessionGet(session, mod.hodlSecureKeyOf(key), "seed"), key.name);
      assert.equal(key.fields.seed, "");
      assert.equal("secureCleared" in key, false);
    }
    for (const field of ["hex", "bin", "seedNumbers", "dplusDice", "directCards", "bitboxDice"]) {
      assert.equal(synced.fields[field], "", field);
    }
    assert.equal(synced.fields.privateKeys.wif, "");
    assert.equal(synced.fields.privateKeys["hex-key"], "");
    assert.equal(synced.fields.name, "Synced");
    assert.equal(synced.lastWord, "");
    // A key without Global sync keeps its other fields: they are its own input.
    assert.equal(unsynced.fields.hex, "beef");
    assert.equal(unsynced.lastWord, "kept");
  } finally {
    globalThis.document = previous;
  }
});

test("Keep leaves a key's other fields unless the words were their source and its wallet can come from them (K3.1, Kimi, Astra)", async () => {
  const previous = globalThis.document;
  globalThis.document = { getElementById: () => null };
  try {
    const session = createSecureSession();
    const phrase = "abandon ability able about above absent absorb abstract absurd abuse access accident";
    const synced = (extra) => ({
      mode: "seed", seedMethod: "words", targetWords: 12, globalSync: true, lastWord: "accident",
      fields: { seed: phrase, hex: "abcd", bin: "1010", privateKeys: { wif: "wifvalue", "hex-key": "hexkeyvalue" } },
      ...extra,
    });
    // Derived from its private key, then switched to Seed mode.
    const single = synced({ id: 1, name: "Single", globalSyncSource: "seed:words", result: { kind: "single" } });
    // No wallet yet: a 256-bit hex key was the source, and 12 words hold only
    // its first 128 bits, so emptying it would lose the rest (K3.1).
    const hexKeySource = synced({ id: 4, name: "Hex key source", globalSyncSource: "key:hex-key", result: null });
    // Other modes keep their seed text as text (they are not listed at all).
    const keyMode = synced({ id: 2, name: "Key mode", mode: "key", result: { kind: "single" } });
    const hexMode = synced({ id: 3, name: "Hex mode", mode: "hex", result: { kind: "hd" } });
    const keys = [single, keyMode, hexMode, hexKeySource];
    const mod = await loadAppFunctions(["hodlSecureEntryToggle", "hodlSecureKeyOf", "hodlSecureEntryOn", "hodlClearGlobalSyncCopies"], {
      stubs: {
        ...realSecureEntryStubs,
        hodlSecureEntryDialog: async () => ({ open: async () => "keep" }),
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
        hodlPrivateKeyValues: (fields) => fields.privateKeys,
        hodlEntropyFormats: { hex: {}, bin: {} },
      },
      settable: ["hodlSecureEntryOn", "hodlSecureSession", "hodlKeys"],
    });
    mod.__set.hodlSecureSession(session);
    mod.__set.hodlKeys(keys);
    mod.__set.hodlSecureEntryOn(false);
    await mod.hodlSecureEntryToggle(true);
    assert.equal(mod.hodlSecureEntryOn, true);
    // The Seed-mode keys' words move; their private keys and entropy stay.
    for (const key of [single, hexKeySource]) {
      assert.ok(sessionGet(session, mod.hodlSecureKeyOf(key), "seed"), key.name);
      assert.equal(key.fields.seed, "", key.name);
      assert.equal(key.fields.hex, "abcd", key.name);
      assert.equal(key.fields.bin, "1010", key.name);
      assert.equal(key.fields.privateKeys.wif, "wifvalue", key.name);
      assert.equal(key.fields.privateKeys["hex-key"], "hexkeyvalue", key.name);
      assert.equal(key.lastWord, "accident", key.name);
    }
    for (const key of [keyMode, hexMode]) {
      assert.equal(mod.hodlSecureKeyOf(key), null, key.name);
      assert.equal(key.fields.seed, phrase, key.name);
      assert.equal(key.fields.hex, "abcd", key.name);
      assert.equal(key.fields.privateKeys.wif, "wifvalue", key.name);
    }
    for (const key of keys) assert.equal("secureCleared" in key, false, key.name);
  } finally {
    globalThis.document = previous;
  }
});

test("a successful derive removes the active key's secureCleared mark, after the result is in", () => {
  // The only way a marked key becomes backup-ready again is deriving it from
  // its words; hodlCalculateKey drops the mark once the derivation succeeded.
  const app = readFileSync(new URL("../src/js/app.js", import.meta.url), "utf8");
  const start = app.indexOf("async function hodlCalculateKey(");
  assert.ok(start >= 0);
  const fn = app.slice(start, app.indexOf("\n}\n", start));
  const drop = fn.indexOf("delete hodlKeys[hodlActiveKey].secureCleared");
  assert.ok(drop > 0, "hodlCalculateKey drops the mark");
  assert.equal(fn.indexOf("delete hodlKeys[hodlActiveKey].secureCleared", drop + 1), -1, "once");
  // Only after a skip decision has returned and the result is the wallet.
  const committed = fn.indexOf("hodlWalletResult = result;");
  assert.ok(committed > 0 && committed < drop);
  assert.ok(fn.indexOf('if (decision?.kind === "skip") return false;') < drop);
});

test("hodlKeyManagerEntry drops the secureCleared mark", async () => {
  const mod = await loadAppFunctions(["hodlKeyManagerEntry"], {
    stubs: { hodlPassphraseText: (value) => value },
  });
  const state = { id: 1, isLab: false, secureCleared: true, fields: { seed: "" } };
  const copy = mod.hodlKeyManagerEntry(state);
  assert.equal("secureCleared" in copy, false);
  assert.equal("isLab" in copy, false);
});

test("hodlCloneDerivedKey takes the mark from the source, not the existing key", async () => {
  const session = createSecureSession();
  const mod = await loadAppFunctions(["hodlCloneDerivedKey", "hodlSecureKeyOf"], {
    stubs: {
      ...realSecureEntryStubs,
      hodlStoredPassphraseBytes: (value) => value,
      hodlNewKeyState: () => ({ id: 9, fields: {} }),
    },
    settable: ["hodlSecureSession"],
  });
  mod.__set.hodlSecureSession(session);
  const lab = { id: 0, isLab: true, mode: "seed", seedMethod: "words", fields: { seed: "" }, result: { masterFingerprint: "abcd1234" } };
  const existing = { id: 2, fields: {}, secureCleared: true };
  const clone1 = mod.hodlCloneDerivedKey(lab, existing);
  assert.equal("secureCleared" in clone1, false);
  const markedLab = { ...lab, secureCleared: true };
  const clone2 = mod.hodlCloneDerivedKey(markedLab, existing);
  assert.equal(clone2.secureCleared, true);
});

test("turning on can clear or cancel without leaving a plan", async () => {
  const previous = globalThis.document;
  globalThis.document = { getElementById: () => null };
  try {
    const phrase = "abandon ability able about above absent absorb abstract absurd abuse access accident";
    let choice = "clear";
    const session = createSecureSession();
    const keys = [{ id: 1, name: "Key 1", mode: "seed", seedMethod: "words", targetWords: 12, fields: { seed: phrase } }];
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
    const cancelKeys = [{ id: 2, name: "Key 2", mode: "seed", seedMethod: "words", targetWords: 12, fields: { seed: phrase } }];
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

test("turning off converts, clears or cancels, and makes texts only for Convert", async () => {
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
    // planTurnOff joins the words into text, so it must run only after the
    // user chooses Convert: Clear and Cancel make no text copy (Kimi K3).
    const calls = [];
    const mod = await loadAppFunctions(["hodlSecureEntryToggle", "hodlSecureKeyOf", "hodlSecureEntryOn", "hodlSecureEntryHasData"], {
      stubs: {
        ...realSecureEntryStubs,
        planTurnOff: (session, serializers) => {
          calls.push("plan");
          return planTurnOff(session, serializers);
        },
        hodlSecureEntryDialog: async () => ({
          open: async () => {
            calls.push("dialog");
            return choice;
          },
        }),
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
    assert.deepEqual(calls, ["dialog", "plan"]);
    calls.length = 0;

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
    assert.deepEqual(calls, ["dialog"]);
    assert.equal(clear.entry.count, 0, "Clear wipes the entry");
    calls.length = 0;

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
    assert.deepEqual(calls, ["dialog"]);
  } finally {
    globalThis.document = previous;
  }
});

test("ending secure entry (pagehide, back/forward restore) marks a committed key whose words were only secure (GLM)", async () => {
  const words = "abandon ability able about above absent absorb abstract absurd abuse access accident".split(" ");
  const session = createSecureSession();
  const committed = { id: 1, name: "Committed", seedMethod: "words", targetWords: 12, fields: { seed: "" }, result: { masterFingerprint: "73c5da0a" } };
  const editor = { id: 2, name: "Editor", seedMethod: "words", targetWords: 12, fields: { seed: "" }, result: null };
  const plain = { id: 3, name: "Plain", seedMethod: "words", targetWords: 12, fields: { seed: words.join(" ") }, result: { masterFingerprint: "aaaaaaaa" } };
  const mod = await loadAppFunctions(["hodlSecureEntryEnd", "hodlSecureKeyOf", "hodlSecureEntryOn"], {
    stubs: { ...realSecureEntryStubs, hodlRenderSecureEntryControl: () => {} },
    settable: ["hodlSecureEntryOn", "hodlSecureSession", "hodlKeys"],
  });
  mod.__set.hodlSecureSession(session);
  mod.__set.hodlKeys([committed, editor, plain]);
  mod.__set.hodlSecureEntryOn(true);
  for (const state of [committed, editor]) {
    const entry = seedEntry(12);
    for (let i = 0; i < words.length; i += 1) seedSet(entry, i, wordIndex.get(words[i]));
    sessionSet(session, mod.hodlSecureKeyOf(state, true), "seed", entry);
  }
  mod.hodlSecureEntryEnd();
  assert.equal(committed.secureCleared, true);
  assert.equal("secureCleared" in editor, false);
  assert.equal("secureCleared" in plain, false);
  assert.equal(session.entries.size, 0);
  assert.equal(mod.hodlSecureEntryOn, false);
});

test("turning off with Clear marks a committed key whose words were only secure", async () => {
  const previous = globalThis.document;
  globalThis.document = { getElementById: () => null };
  try {
    const words = "abandon ability able about above absent absorb abstract absurd abuse access accident".split(" ");
    const make = () => {
      const session = createSecureSession();
      const committed = { id: 1, name: "Committed", seedMethod: "words", targetWords: 12, fields: { seed: "" }, result: { masterFingerprint: "73c5da0a" } };
      const editor = { id: 2, name: "Editor", seedMethod: "words", targetWords: 12, fields: { seed: "" }, result: null };
      const entry = seedEntry(12), editorEntry = seedEntry(12);
      for (let i = 0; i < words.length; i += 1) {
        seedSet(entry, i, wordIndex.get(words[i]));
        seedSet(editorEntry, i, wordIndex.get(words[i]));
      }
      return { session, keys: [committed, editor], committed, editor, entry, editorEntry };
    };
    let choice = "clear";
    const tTextCalls = [];
    const mod = await loadAppFunctions(["hodlSecureEntryToggle", "hodlSecureKeyOf", "hodlSecureEntryOn", "hodlSecureEntryBackupRefusal"], {
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
        hodlTText: (text) => { tTextCalls.push(text); return text; },
        hodlPrivateKeyValues: (fields) => fields.privateKeys,
        hodlEntropyFormats: { hex: {}, bin: {} },
      },
      settable: ["hodlSecureEntryOn", "hodlSecureSession", "hodlKeys"],
    });
    const arm = (fixture) => {
      mod.__set.hodlSecureSession(fixture.session);
      mod.__set.hodlKeys(fixture.keys);
      mod.__set.hodlSecureEntryOn(true);
      sessionSet(fixture.session, mod.hodlSecureKeyOf(fixture.committed, true), "seed", fixture.entry);
      sessionSet(fixture.session, mod.hodlSecureKeyOf(fixture.editor, true), "seed", fixture.editorEntry);
    };

    // Clear: the committed key keeps its wallet on screen but loses the only
    // copy of its words, so it is marked and Journal refuses it.
    const clear = make();
    arm(clear);
    await mod.hodlSecureEntryToggle(false);
    assert.equal(clear.committed.secureCleared, true);
    assert.equal("secureCleared" in clear.editor, false);
    assert.equal(clear.session.entries.size, 0);
    assert.equal(mod.hodlSecureEntryOn, false);
    const refusal = mod.hodlSecureEntryBackupRefusal();
    assert.ok(refusal instanceof Error);
    assert.ok(tTextCalls.some((text) => text.includes("cleared")));

    // Convert writes the words back as text, so nothing is marked.
    choice = "convert";
    const convert = make();
    arm(convert);
    await mod.hodlSecureEntryToggle(false);
    assert.equal("secureCleared" in convert.committed, false);
    assert.equal("secureCleared" in convert.editor, false);
    assert.equal(convert.committed.fields.seed, words.join(" "));
    assert.equal(convert.session.entries.size, 0);

    // Cancel leaves the session and the keys as they were.
    choice = null;
    const cancel = make();
    arm(cancel);
    await mod.hodlSecureEntryToggle(false);
    assert.equal("secureCleared" in cancel.committed, false);
    assert.equal("secureCleared" in cancel.editor, false);
    assert.equal(mod.hodlSecureEntryOn, true);
    assert.equal(cancel.session.entries.size, 2);
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
  const secure = seed.indexOf("if (hodlSecureSeedActive() && hodlSecureSeedPickerShown(state))"), textarea = seed.indexOf('id="seed"');
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
        hodlSecureEntryOn: true,
        hodlSecureSeedHasWords: () => count > 0,
        hodlSecureKeyOf: () => "k1",
        hodlKeys: [{}],
        hodlActiveKey: 0,
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
    const lockedHelp = help.textContent;
    count = 0;
    mod.hodlUpdateSeedLengthControl();
    for (const option of select.options) assert.equal(option.disabled, false);
    // The lock adds a note to the help line (checked by the change, not its words).
    assert.ok(lockedHelp.startsWith(help.textContent) && lockedHelp.length > help.textContent.length);
  } finally {
    globalThis.document = previous;
  }
});

test("deriving a new key drops the editor's secure words", async () => {
  const session = createSecureSession();
  const entry = seedEntry(12);
  for (let i = 0; i < 12; i += 1) seedSet(entry, i, i);
  const lab = { isLab: true, id: 1, result: { network: "mainnet" }, fields: { seed: "" } };
  const keys = [lab];
  let token = null;
  const mod = await loadAppFunctions(["hodlCommitDerivedKey", "hodlSecureKeyOf"], {
    stubs: {
      ...realSecureEntryStubs,
      hodlKeyManagerPending: [],
      hodlKeyManagerIgnored: [],
      hodlKeyManagerStates: () => [],
      hodlJournalUnlocked: () => false,
      hodlKeyWalletIdentity: () => null,
      hodlKeyManagerEntry: () => ({}),
      hodlNormalizePrivateKeyKind: (kind) => kind,
      hodlPrivateKeyValues: () => [],
      hodlKeyManagerCapacityError: () => "",
      hodlKeyManagerArchiveEntry: (entry) => entry,
      hodlNextKeyId: 1,
      hodlNextKeyNumber: 1,
      hodlReleaseKeyConsumers: () => {},
      hodlVanityApplying: false,
      hodlKeyNameTaken: () => false,
      hodlKeyManagerIds: new Set(),
      hodlKeyManagerActiveId: null,
      hodlKeyManagerDiscardInputs: () => {},
      // The real clone reads the editor's entry to set secureSource; this
      // stand-in does the same, so the last assertion pins the ordering.
      hodlCloneDerivedKey: (source) => ({ ...source, isLab: false, secureSource: sessionGet(session, token, "seed") != null, result: source.result }),
      hodlNewLabState: () => ({ isLab: true, fields: { seed: "" } }),
      hodlZeroKeyPassphrase: () => {},
      hodlRenderKeyTabs: () => {},
      hodlRestoreKey: () => {},
      hodlTText: (text) => text,
    },
    settable: ["hodlKeys", "hodlActiveKey", "hodlSecureSession", "hodlSecureKeys"],
  });
  mod.__set.hodlSecureKeys(new WeakMap());
  mod.__set.hodlSecureSession(session);
  mod.__set.hodlKeys(keys);
  mod.__set.hodlActiveKey(0);
  token = mod.hodlSecureKeyOf(lab, true);
  sessionSet(session, token, "seed", entry);
  mod.hodlCommitDerivedKey();
  assert.equal(entry.wiped, true);
  assert.equal(session.entries.size, 0);
  assert.equal(keys.at(-1).secureSource, true);
});

test("replacing an existing key drops its kept words and the editor's (GLM)", async () => {
  const session = createSecureSession();
  const kept = seedEntry(12), typed = seedEntry(12);
  for (let i = 0; i < 12; i += 1) {
    seedSet(kept, i, i);
    seedSet(typed, i, i + 1);
  }
  const lab = { isLab: true, id: 1, editSourceId: 2, result: { network: "mainnet" }, fields: { seed: "" } };
  const previous = { id: 2, result: { network: "mainnet" }, fields: { seed: "" } };
  const keys = [lab, previous];
  const mod = await loadAppFunctions(["hodlCommitDerivedKey", "hodlSecureKeyOf"], {
    stubs: {
      ...realSecureEntryStubs,
      hodlKeyManagerPending: [],
      hodlKeyManagerIgnored: [],
      hodlKeyManagerStates: () => [],
      hodlJournalUnlocked: () => false,
      hodlKeyWalletIdentity: () => "same-wallet",
      hodlKeyManagerCapacityError: () => "",
      hodlReleaseKeyConsumers: () => {},
      hodlVanityApplying: false,
      hodlKeyManagerIds: new Set(),
      hodlKeyManagerActiveId: null,
      hodlCloneDerivedKey: (source, existing) => ({ ...existing, isLab: false, result: source.result }),
      hodlNewLabState: () => ({ isLab: true, fields: { seed: "" } }),
      hodlZeroKeyPassphrase: () => {},
      hodlRenderKeyTabs: () => {},
      hodlRestoreKey: () => {},
      hodlTText: (text) => text,
    },
    settable: ["hodlKeys", "hodlActiveKey", "hodlSecureSession", "hodlSecureKeys"],
  });
  mod.__set.hodlSecureKeys(new WeakMap());
  mod.__set.hodlSecureSession(session);
  mod.__set.hodlKeys(keys);
  mod.__set.hodlActiveKey(0);
  sessionSet(session, mod.hodlSecureKeyOf(previous, true), "seed", kept);
  sessionSet(session, mod.hodlSecureKeyOf(lab, true), "seed", typed);
  mod.hodlCommitDerivedKey("update");
  assert.notEqual(keys[1], previous, "the existing key was replaced");
  assert.equal(kept.wiped, true);
  assert.equal(typed.wiped, true);
  assert.equal(session.entries.size, 0);
});

test("Edit Input moves a key's secure words into the editor", async () => {
  const session = createSecureSession();
  const entryA = seedEntry(12);
  const entryB = seedEntry(12);
  for (let i = 0; i < 12; i += 1) {
    seedSet(entryA, i, i);
    seedSet(entryB, i, i + 1);
  }
  const outgoing = { isLab: true, id: 1, fields: { seed: "" } };
  const source = { id: 2, fields: { seed: "" }, secureSource: false };
  const keys = [outgoing, source];
  const mod = await loadAppFunctions(["hodlEditKeyInputs", "hodlFillLabFromKey", "hodlSecureKeyOf"], {
    stubs: {
      ...realSecureEntryStubs,
      hodlCaptureKey: () => {},
      hodlSelectKey: () => {},
      hodlSelectLab: () => {},
      hodlCloneDerivedKey: (from, existing) => ({ ...existing, ...from }),
      hodlNewLabState: () => ({ isLab: true, fields: { seed: "" } }),
    },
    settable: ["hodlKeys", "hodlActiveKey", "hodlSecureSession", "hodlSecureKeys"],
  });
  mod.__set.hodlSecureKeys(new WeakMap());
  mod.__set.hodlSecureSession(session);
  mod.__set.hodlKeys(keys);
  mod.__set.hodlActiveKey(1);
  const outgoingToken = mod.hodlSecureKeyOf(outgoing, true);
  const sourceToken = mod.hodlSecureKeyOf(source, true);
  sessionSet(session, outgoingToken, "seed", entryB);
  sessionSet(session, sourceToken, "seed", entryA);
  mod.hodlEditKeyInputs();
  assert.equal(entryB.wiped, true);
  assert.equal(sessionGet(session, outgoingToken, "seed"), null);
  assert.equal(entryA.wiped, false);
  assert.equal(mod.hodlSecureKeyOf(source), null);
  assert.equal(source.secureSource, true);
  const lab = keys[0];
  assert.equal(lab.isLab, true);
  assert.equal(mod.hodlSecureKeyOf(lab), sourceToken);
  assert.equal(sessionGet(session, sourceToken, "seed"), entryA);
});

test("Edit Input leaves a cleared key's mark on the key, not the editor (MiniMax)", async () => {
  const session = createSecureSession();
  const outgoing = { isLab: true, id: 1, fields: { seed: "" } };
  const source = { id: 2, fields: { seed: "" }, secureSource: false, secureCleared: true, result: { kind: "hd" } };
  const keys = [outgoing, source];
  const mod = await loadAppFunctions(["hodlEditKeyInputs", "hodlFillLabFromKey", "hodlSecureKeyOf"], {
    stubs: {
      ...realSecureEntryStubs,
      hodlCaptureKey: () => {},
      hodlSelectKey: () => {},
      hodlSelectLab: () => {},
      hodlCloneDerivedKey: (from, existing) => ({ ...existing, ...from }),
      hodlNewLabState: () => ({ isLab: true, fields: { seed: "" } }),
    },
    settable: ["hodlKeys", "hodlActiveKey", "hodlSecureSession", "hodlSecureKeys"],
  });
  mod.__set.hodlSecureKeys(new WeakMap());
  mod.__set.hodlSecureSession(session);
  mod.__set.hodlKeys(keys);
  mod.__set.hodlActiveKey(1);
  mod.hodlEditKeyInputs();
  const lab = keys[0];
  assert.equal(lab.isLab, true);
  assert.equal(lab.result, null);
  assert.equal("secureCleared" in lab, false);
  assert.equal(source.secureCleared, true);
});

test("the switch is refused while a Journal batch runs", async () => {
  const previous = globalThis.document;
  globalThis.document = { getElementById: () => null };
  try {
    const session = createSecureSession();
    const entry = seedEntry(12);
    for (let i = 0; i < 12; i += 1) seedSet(entry, i, i);
    const key = { id: 1, seedMethod: "words", fields: { seed: "" } };
    let dialogCalls = 0, renderCalls = 0;
    const mod = await loadAppFunctions(["hodlSecureEntryToggle", "hodlSecureKeyOf", "hodlSecureEntryOn"], {
      stubs: {
        ...realSecureEntryStubs,
        hodlSecureEntryDialog: async () => { dialogCalls++; return { open: async () => "clear" }; },
        hodlCaptureKey: () => {},
        hodlRenderSecureEntryControl: () => { renderCalls++; },
        hodlSetMode: () => {},
        hodlSyncKeyClearButton: () => {},
        hodlSyncDeriveButton: () => {},
        hodlQueueMasterFingerprintPreview: () => {},
        hodlNormalizeSeedMethod: (value) => value === "numbers" ? "numbers" : "words",
        hodlBip39WordIndex: wordIndex,
        hodlBip39Wordlist: wordlist,
        hodlKeyMode: "seed",
      },
      settable: ["hodlSecureEntryOn", "hodlSecureSession", "hodlKeys", "hodlJournalKeyDerivation", "hodlSecureEntryBusy"],
    });
    mod.__set.hodlSecureSession(session);
    mod.__set.hodlKeys([key]);
    mod.__set.hodlSecureEntryOn(true);
    mod.__set.hodlSecureEntryBusy(false);
    mod.__set.hodlJournalKeyDerivation({});
    const token = mod.hodlSecureKeyOf(key, true);
    sessionSet(session, token, "seed", entry);
    await mod.hodlSecureEntryToggle(false);
    assert.equal(mod.hodlSecureEntryOn, true);
    assert.equal(dialogCalls, 0);
    assert.equal(entry.wiped, false);
    assert.equal(sessionGet(session, token, "seed"), entry);
    assert.ok(renderCalls > 0);
  } finally {
    globalThis.document = previous;
  }
});

test("the switch is disabled while a Journal batch runs", async () => {
  const previous = globalThis.document;
  const doc = new MiniDocument();
  globalThis.document = doc;
  try {
    const host = doc.createElement("div");
    host.id = "secure-entry-host";
    doc.body.append(host);
    const mod = await loadAppFunctions(["hodlRenderSecureEntryControl"], {
      stubs: {
        ...realSecureEntryStubs,
        hodlSecureEntryAvailable: () => true,
        hodlSecureSeedActive: () => false,
        hodlSecureEntryToggle: () => {},
        hodlSecureEntryHasData: () => false,
        hodlSecureKeyOf: () => null,
        hodlT: (text) => text,
      },
      settable: ["hodlSecureEntryOn", "hodlJournalKeyDerivation", "hodlKeys", "hodlActiveKey"],
    });
    mod.__set.hodlSecureEntryOn(true);
    mod.__set.hodlJournalKeyDerivation({});
    mod.__set.hodlKeys([{}]);
    mod.__set.hodlActiveKey(0);
    mod.hodlRenderSecureEntryControl();
    let checkbox = doc.getElementById("secure-entry-switch");
    assert.ok(checkbox);
    assert.equal(checkbox.disabled, true);
    mod.__set.hodlJournalKeyDerivation(null);
    mod.hodlRenderSecureEntryControl();
    checkbox = doc.getElementById("secure-entry-switch");
    assert.equal(checkbox.disabled, false);
  } finally {
    globalThis.document = previous;
  }
});

test("the switch notes a seed held as text and shows the picker once it is emptied", async () => {
  const previous = globalThis.document;
  const doc = new MiniDocument();
  globalThis.document = doc;
  try {
    const host = doc.createElement("div");
    host.id = "secure-entry-host";
    doc.body.append(host);
    let seedActive = true;
    const session = createSecureSession();
    const state = { fields: { seed: "abandon ability able about above absent absorb abstract absurd abuse access accident" } };
    const mod = await loadAppFunctions(["hodlRenderSecureEntryControl", "hodlSecureKeyOf"], {
      stubs: {
        ...realSecureEntryStubs,
        hodlSecureEntryAvailable: () => true,
        hodlSecureSeedActive: () => seedActive,
        hodlSecureEntryToggle: () => {},
        hodlT: (text) => text,
      },
      settable: ["hodlSecureEntryOn", "hodlJournalKeyDerivation", "hodlKeys", "hodlActiveKey", "hodlSecureSession", "hodlSecureKeys"],
    });
    mod.__set.hodlSecureKeys(new WeakMap());
    mod.__set.hodlSecureSession(session);
    mod.__set.hodlKeys([state]);
    mod.__set.hodlActiveKey(0);
    mod.__set.hodlSecureEntryOn(true);
    mod.__set.hodlJournalKeyDerivation(null);
    mod.hodlRenderSecureEntryControl();
    let note = doc.getElementById("secure-entry-text-backed");
    assert.ok(note);
    // Hooked on the note's id; its words are copy (AGENTS.md), so only check it says something.
    assert.ok(note.textContent.trim().length > 0);
    assert.equal(doc.getElementById("secure-entry-unsupported"), null);

    state.fields.seed = "";
    mod.hodlRenderSecureEntryControl();
    assert.equal(doc.getElementById("secure-entry-text-backed"), null);

    state.fields.seed = "abandon ability able about above absent absorb abstract absurd abuse access accident";
    const token = mod.hodlSecureKeyOf(state, true);
    const entry = seedEntry(12);
    for (let i = 0; i < 12; i += 1) seedSet(entry, i, i);
    sessionSet(session, token, "seed", entry);
    mod.hodlRenderSecureEntryControl();
    assert.equal(doc.getElementById("secure-entry-text-backed"), null);

    seedActive = false;
    mod.hodlRenderSecureEntryControl();
    assert.ok(doc.getElementById("secure-entry-unsupported"));
    assert.equal(doc.getElementById("secure-entry-text-backed"), null);
  } finally {
    globalThis.document = previous;
  }
});

test("emptying the seed text field while secure entry is on redraws into the picker", () => {
  const app = readFileSync(new URL("../src/js/app.js", import.meta.url), "utf8");
  const formStart = app.indexOf("function hodlRenderKeyForm() {");
  assert.ok(formStart > 0);
  const form = app.slice(formStart, app.indexOf("\nfunction ", formStart + 1));
  // The seed branch, not an earlier method's input handler.
  const seed = form.slice(form.indexOf('if (hodlKeyMode === "seed")'));
  // The words textarea's handler (the word-numbers one comes first).
  const start = seed.lastIndexOf("input.oninput = (event) => {", seed.indexOf("hodlApplyFilteredInput(input, hodlFilterSeed);"));
  assert.ok(start > 0);
  const body = seed.slice(start, seed.indexOf("};", start) + 2);
  assert.match(body, /if \(hodlSecureSeedActive\(\) && !input\.value\.trim\(\) && !hodlSecureSeedHasWords\(hodlSecureKeyOf\(state\)\)\) \{/);
  assert.match(body, /hodlSetMode\(hodlKeyMode\);/);
});

test("a blocked Convert shows the convert-failed note and keeps the switch on", async () => {
  const previous = globalThis.document;
  const doc = new MiniDocument();
  globalThis.document = doc;
  try {
    const host = doc.createElement("div");
    host.id = "secure-entry-host";
    doc.body.append(host);
    const session = createSecureSession();
    const key = { id: 1, name: "Key 1", mode: "seed", seedMethod: "words", targetWords: 12, fields: { seed: "" } };
    const entry = seedEntry(12);
    for (let i = 0; i < 12; i += 1) seedSet(entry, i, i);
    let choice = "convert";
    let dialogCalls = 0;
    const mod = await loadAppFunctions(["hodlSecureEntryToggle", "hodlRenderSecureEntryControl", "hodlSecureEntryOn"], {
      stubs: {
        ...realSecureEntryStubs,
        hodlSecureEntryAvailable: () => true,
        hodlSecureSeedActive: () => true,
        hodlSecureSeedPickerShown: () => true,
        hodlSwitchBarMarkup: () => "<switch>",
        hodlT: (text) => text,
        hodlSecureEntryDialog: async () => ({ open: async () => { dialogCalls += 1; return choice; } }),
        hodlCaptureKey: () => {},
        hodlSetMode: () => {},
        hodlSyncKeyClearButton: () => {},
        hodlSyncDeriveButton: () => {},
        hodlQueueMasterFingerprintPreview: () => {},
        hodlNormalizeSeedMethod: (value) => value === "numbers" ? "numbers" : "words",
        hodlBip39WordIndex: wordIndex,
        hodlBip39Wordlist: wordlist,
        hodlKeyMode: "seed",
        hodlSecureEntryHasData: () => true,
        hodlSecureKeyOf: (state) => String(state.id),
        hodlLooksExtendedKey: () => false,
        hodlLastWordCache: { clear: () => {} },
        planTurnOff: () => ({ ok: false, staged: [], blockers: [{ reason: "invalid" }], kind: "off", generation: 0 }),
        discardPlan: () => {},
      },
      settable: ["hodlSecureEntryOn", "hodlSecureSession", "hodlKeys", "hodlActiveKey", "hodlSecureEntryBusy", "hodlJournalKeyDerivation"],
    });
    mod.__set.hodlSecureSession(session);
    mod.__set.hodlKeys([key]);
    mod.__set.hodlActiveKey(0);
    mod.__set.hodlSecureEntryOn(true);
    mod.__set.hodlSecureEntryBusy(false);
    mod.__set.hodlJournalKeyDerivation(null);
    sessionSet(session, "1", "seed", entry);
    await mod.hodlSecureEntryToggle(false);
    assert.equal(mod.hodlSecureEntryOn, true);
    assert.ok(doc.getElementById("secure-entry-convert-failed"));
    assert.equal(dialogCalls, 1);

    choice = null;
    await mod.hodlSecureEntryToggle(false);
    assert.equal(mod.hodlSecureEntryOn, true);
    assert.equal(doc.getElementById("secure-entry-convert-failed"), null);
    assert.equal(dialogCalls, 2);

    const clearSession = createSecureSession();
    const clearKey = { id: 2, name: "Key 2", mode: "seed", seedMethod: "words", targetWords: 12, fields: { seed: "" } };
    const clearEntry = seedEntry(12);
    for (let i = 0; i < 12; i += 1) seedSet(clearEntry, i, i);
    sessionSet(clearSession, "2", "seed", clearEntry);
    choice = "clear";
    mod.__set.hodlSecureSession(clearSession);
    mod.__set.hodlKeys([clearKey]);
    mod.__set.hodlSecureEntryOn(true);
    await mod.hodlSecureEntryToggle(false);
    assert.equal(mod.hodlSecureEntryOn, false);
    assert.equal(doc.getElementById("secure-entry-convert-failed"), null);
  } finally {
    globalThis.document = previous;
  }
});

test("a Convert commit that throws without texts shows the convert-failed note", async () => {
  const previous = globalThis.document;
  const doc = new MiniDocument();
  globalThis.document = doc;
  try {
    const host = doc.createElement("div");
    host.id = "secure-entry-host";
    doc.body.append(host);
    const session = createSecureSession();
    const key = { id: 1, name: "Key 1", mode: "seed", seedMethod: "words", targetWords: 12, fields: { seed: "" } };
    const entry = seedEntry(12);
    for (let i = 0; i < 12; i += 1) seedSet(entry, i, i);
    const mod = await loadAppFunctions(["hodlSecureEntryToggle", "hodlRenderSecureEntryControl", "hodlSecureEntryOn"], {
      stubs: {
        ...realSecureEntryStubs,
        hodlSecureEntryAvailable: () => true,
        hodlSecureSeedActive: () => true,
        hodlSecureSeedPickerShown: () => true,
        hodlSwitchBarMarkup: () => "<switch>",
        hodlT: (text) => text,
        hodlSecureEntryDialog: async () => ({ open: async () => "convert" }),
        hodlCaptureKey: () => {},
        hodlSetMode: () => {},
        hodlSyncKeyClearButton: () => {},
        hodlSyncDeriveButton: () => {},
        hodlQueueMasterFingerprintPreview: () => {},
        hodlNormalizeSeedMethod: (value) => value === "numbers" ? "numbers" : "words",
        hodlBip39WordIndex: wordIndex,
        hodlBip39Wordlist: wordlist,
        hodlKeyMode: "seed",
        hodlSecureEntryHasData: () => true,
        hodlSecureKeyOf: (state) => String(state.id),
        hodlLooksExtendedKey: () => false,
        hodlLastWordCache: { clear: () => {} },
        planTurnOff: () => ({ ok: true, staged: [], blockers: [], kind: "off", generation: 0 }),
        discardPlan: () => {},
        commitTurnOff: () => { throw new Error("commit failed"); },
      },
      settable: ["hodlSecureEntryOn", "hodlSecureSession", "hodlKeys", "hodlActiveKey", "hodlSecureEntryBusy", "hodlJournalKeyDerivation"],
    });
    mod.__set.hodlSecureSession(session);
    mod.__set.hodlKeys([key]);
    mod.__set.hodlActiveKey(0);
    mod.__set.hodlSecureEntryOn(true);
    mod.__set.hodlSecureEntryBusy(false);
    mod.__set.hodlJournalKeyDerivation(null);
    sessionSet(session, "1", "seed", entry);
    await mod.hodlSecureEntryToggle(false);
    assert.equal(mod.hodlSecureEntryOn, true);
    assert.ok(doc.getElementById("secure-entry-convert-failed"));
  } finally {
    globalThis.document = previous;
  }
});

test("the seed picker load failure shows a note and retries on the next render", async () => {
  const previous = globalThis.document;
  const doc = new MiniDocument();
  globalThis.document = doc;
  try {
    const host = doc.createElement("div");
    host.id = "seed-picker-host";
    doc.body.append(host);
    const mod = await loadAppFunctions(["hodlMountSeedPicker", "hodlSeedPicker", "hodlSeedPickerImport"], {
      stubs: {
        hodlSecureSeedActive: () => true,
        hodlSecureSeedEntry: () => ({}),
        hodlBip39Wordlist: wordlist,
        seedSet: () => {},
        seedUndo: () => {},
        seedIndices: () => [],
        hodlEntropyFromWordIndices: () => [],
        hodlTText: (text) => text,
        hodlSecureSeedChanged: () => {},
        hodlT: (text) => text,
      },
      settable: ["hodlSeedPicker", "hodlSeedPickerImport"],
    });
    mod.__set.hodlSeedPicker(null);
    mod.__set.hodlSeedPickerImport(Promise.resolve(null));
    mod.hodlMountSeedPicker();
    await Promise.resolve();
    await Promise.resolve();
    assert.ok(doc.getElementById("seed-picker-load-error"));
    assert.equal(mod.hodlSeedPickerImport, null);

    host.innerHTML = "";
    mod.__set.hodlSeedPicker(null);
    mod.__set.hodlSeedPickerImport(Promise.resolve({ mountSeedPicker: () => { throw new Error("mount failed"); } }));
    mod.hodlMountSeedPicker();
    await Promise.resolve();
    await Promise.resolve();
    assert.ok(doc.getElementById("seed-picker-load-error"));
    assert.equal(mod.hodlSeedPicker, null);

    host.innerHTML = "";
    const mounted = { destroy: () => {} };
    mod.__set.hodlSeedPicker(null);
    mod.__set.hodlSeedPickerImport(Promise.resolve({ mountSeedPicker: () => mounted }));
    mod.hodlMountSeedPicker();
    await Promise.resolve();
    await Promise.resolve();
    assert.equal(doc.getElementById("seed-picker-load-error"), null);
    assert.equal(mod.hodlSeedPicker, mounted);
  } finally {
    globalThis.document = previous;
  }
});

test("a mount that throws after writing into the host leaves only the load-error note", async () => {
  const previous = globalThis.document;
  const doc = new MiniDocument();
  globalThis.document = doc;
  try {
    const host = doc.createElement("div");
    host.id = "seed-picker-host";
    doc.body.append(host);
    const mod = await loadAppFunctions(["hodlMountSeedPicker", "hodlSeedPicker", "hodlSeedPickerImport"], {
      stubs: {
        hodlSecureSeedActive: () => true,
        hodlSecureSeedEntry: () => ({}),
        hodlBip39Wordlist: wordlist,
        seedSet: () => {},
        seedUndo: () => {},
        seedIndices: () => [],
        hodlEntropyFromWordIndices: () => [],
        hodlTText: (text) => text,
        hodlSecureSeedChanged: () => {},
        hodlT: (text) => text,
      },
      settable: ["hodlSeedPicker", "hodlSeedPickerImport"],
    });
    mod.__set.hodlSeedPicker(null);
    mod.__set.hodlSeedPickerImport(Promise.resolve({
      mountSeedPicker: (target) => {
        const half = doc.createElement("div");
        half.id = "half-built-picker";
        target.append(half);
        throw new Error("mount failed after writing");
      },
    }));
    mod.hodlMountSeedPicker();
    await Promise.resolve();
    await Promise.resolve();
    assert.equal(host.childNodes.length, 1);
    assert.equal(host.childNodes[0].id, "seed-picker-load-error");
    assert.equal(doc.getElementById("seed-picker-load-error"), host.childNodes[0]);
    assert.equal(mod.hodlSeedPicker, null);
  } finally {
    globalThis.document = previous;
  }
});

test("turning on converts only Seed-mode keys, not old seed text in another mode", async () => {
  const previous = globalThis.document;
  globalThis.document = { getElementById: () => null };
  try {
    const phrase1 = "abandon ability able about above absent absorb abstract absurd abuse access accident";
    const phrase2 = "legal winner thank year wave sausage worth useful legal winner thank yellow";
    const makeKeys = () => [
      { id: 1, name: "Dice Key", mode: "dice", seedMethod: "words", targetWords: 12, fields: { seed: phrase1 } },
      { id: 2, name: "Seed Key", mode: "seed", seedMethod: "words", targetWords: 12, fields: { seed: phrase2 } },
    ];
    let choice = "keep";
    let lastOptions = null;
    let dialogCalls = 0;
    // The real hodlCaptureKey marks the active key with the editor's mode
    // (state.mode = hodlKeyMode); the last case relies on that, not on a
    // mode written into the fixture.
    let captureTarget = null;
    const mod = await loadAppFunctions(["hodlSecureEntryToggle", "hodlSecureEntryOn"], {
      stubs: {
        ...realSecureEntryStubs,
        hodlSecureEntryDialog: async () => ({ open: async (options) => { dialogCalls += 1; lastOptions = options; return choice; } }),
        hodlCaptureKey: () => { if (captureTarget) captureTarget.mode = "seed"; },
        hodlRenderSecureEntryControl: () => {},
        hodlSetMode: () => {},
        hodlSyncKeyClearButton: () => {},
        hodlSyncDeriveButton: () => {},
        hodlQueueMasterFingerprintPreview: () => {},
        hodlNormalizeSeedMethod: (value) => value === "numbers" ? "numbers" : "words",
        hodlBip39WordIndex: wordIndex,
        hodlBip39Wordlist: wordlist,
        hodlKeyMode: "seed",
        hodlSecureEntryHasData: () => false,
        hodlSecureKeyOf: (state) => String(state.id),
        hodlLooksExtendedKey: () => false,
        hodlLastWordCache: { clear: () => {} },
      },
      settable: ["hodlSecureEntryOn", "hodlSecureSession", "hodlKeys", "hodlActiveKey", "hodlSecureEntryBusy", "hodlJournalKeyDerivation"],
    });

    const keepSession = createSecureSession();
    const keepKeys = makeKeys();
    mod.__set.hodlSecureSession(keepSession);
    mod.__set.hodlKeys(keepKeys);
    mod.__set.hodlActiveKey(0);
    mod.__set.hodlSecureEntryOn(false);
    mod.__set.hodlSecureEntryBusy(false);
    mod.__set.hodlJournalKeyDerivation(null);
    await mod.hodlSecureEntryToggle(true);
    assert.equal(dialogCalls, 1);
    assert.deepEqual(lastOptions.names, ["Seed Key"]);
    assert.equal(mod.hodlSecureEntryOn, true);
    assert.equal(keepKeys[0].fields.seed, phrase1);
    assert.equal(sessionGet(keepSession, "1", "seed"), null);
    assert.equal(keepKeys[1].fields.seed, "");
    assert.ok(sessionGet(keepSession, "2", "seed"));

    const clearSession = createSecureSession();
    const clearKeys = makeKeys();
    choice = "clear";
    dialogCalls = 0;
    lastOptions = null;
    mod.__set.hodlSecureSession(clearSession);
    mod.__set.hodlKeys(clearKeys);
    mod.__set.hodlSecureEntryOn(false);
    await mod.hodlSecureEntryToggle(true);
    assert.equal(dialogCalls, 1);
    assert.deepEqual(lastOptions.names, ["Seed Key"]);
    assert.equal(mod.hodlSecureEntryOn, true);
    assert.equal(clearKeys[0].fields.seed, phrase1);
    assert.equal(sessionGet(clearSession, "1", "seed"), null);
    assert.equal(clearKeys[1].fields.seed, "");
    assert.equal(sessionGet(clearSession, "2", "seed"), null);

    const diceSession = createSecureSession();
    const diceKeys = [{ id: 3, name: "Dice Only", mode: "dice", seedMethod: "words", targetWords: 12, fields: { seed: phrase1 } }];
    choice = "keep";
    dialogCalls = 0;
    lastOptions = null;
    mod.__set.hodlSecureSession(diceSession);
    mod.__set.hodlKeys(diceKeys);
    mod.__set.hodlSecureEntryOn(false);
    await mod.hodlSecureEntryToggle(true);
    assert.equal(dialogCalls, 0);
    assert.equal(mod.hodlSecureEntryOn, true);
    assert.equal(diceKeys[0].fields.seed, phrase1);
    assert.equal(diceSession.entries.size, 0);

    // The Seed-mode key's mode comes from hodlCaptureKey (state.mode =
    // hodlKeyMode), not from the fixture: the real function marks the active
    // key before the turn-on loop reads it, so the key is still converted.
    const capturedSession = createSecureSession();
    const capturedKey = { id: 4, name: "Captured Seed", seedMethod: "words", targetWords: 12, fields: { seed: phrase2 } };
    captureTarget = capturedKey;
    choice = "keep";
    dialogCalls = 0;
    lastOptions = null;
    mod.__set.hodlSecureSession(capturedSession);
    mod.__set.hodlKeys([capturedKey]);
    mod.__set.hodlActiveKey(0);
    mod.__set.hodlSecureEntryOn(false);
    await mod.hodlSecureEntryToggle(true);
    assert.equal(capturedKey.mode, "seed");
    assert.equal(dialogCalls, 1);
    assert.deepEqual(lastOptions.names, ["Captured Seed"]);
    assert.equal(mod.hodlSecureEntryOn, true);
    assert.equal(capturedKey.fields.seed, "");
    assert.ok(sessionGet(capturedSession, "4", "seed"));
  } finally {
    globalThis.document = previous;
  }
});
