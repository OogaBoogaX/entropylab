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
    const keys = [{ id: 1, seedMethod: "words", fields: { seed: xprv }, globalSync: false }];
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
    const keys = [{ id: 1, name: "Key Station", seedMethod: "words", targetWords: 12, fields: { seed: words }, globalSync: false }];
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
    const keys = [{ id: 1, seedMethod: "words", targetWords: 12, fields: { seed: phrase }, globalSync: false }];
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
