// Secure entry P4b: the strict dice pad wired into the Key Station.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { loadAppFunctions } from "./app-slice-harness.mjs";
import { MiniDocument } from "./mini-dom.mjs";
import {
  createSecureSession, sessionWipe, sessionDeleteKey, sessionGet, sessionSet,
  seedEntry, seedSet, seedIndices, seedUndo, keyEntry, planTurnOn, commitTurnOn,
  planTurnOff, commitTurnOff, discardPlan, SUPPORTED_METHODS,
  rollsEntry, rollsPush, rollsUndo, rollAt, rollsCopy,
} from "../src/js/secure-entry.js";
import { seedFromIndices, indicesFromEntropy, entropyToMnemonic, mnemonicToSeedSync } from "../src/js/bip39.js";
import { wordlist } from "../src/js/bip39-english.js";
import { sha256 as wasmSha256 } from "../src/js/hashes.js";

const root = dirname(fileURLToPath(import.meta.url));
const app = readFileSync(join(root, "..", "src", "js", "app.js"), "utf8");
const wordIndex = new Map(wordlist.map((word, index) => [word, index]));

const secureEntryStubs = {
  createSecureSession, sessionWipe, sessionDeleteKey, sessionGet, sessionSet,
  seedEntry, seedSet, seedIndices, seedUndo, keyEntry,
  planTurnOn, commitTurnOn, planTurnOff, commitTurnOff, discardPlan,
  rollsEntry, rollsPush, rollsUndo, rollAt, rollsCopy,
  hodlSecureSupported: SUPPORTED_METHODS,
};

function fnSource(name) {
  const start = app.indexOf(`function ${name}(`);
  assert.ok(start >= 0, name);
  const end = app.indexOf("\nfunction ", start + 1);
  assert.ok(end > start, name);
  return app.slice(start, end);
}

function rollsText(count) {
  return "123456".repeat(Math.ceil(count / 6)).slice(0, count);
}

function entryFromDigits(digits, method) {
  const entry = rollsEntry(method, Math.max(400, digits.length));
  for (const face of digits) rollsPush(entry, Number(face));
  return entry;
}

const SIZES = [12, 15, 18, 21, 24];
const METHODS = ["coldcard", "coleman"];
const COUNTS = [1, 49, 50, 99, 100, 101, 400, 401, 1000];

test("hodlSecureDiceEntropyOf matches the text path and Node SHA-256", async () => {
  const mod = await loadAppFunctions(["hodlSecureDiceEntropyOf", "hodlDiceEntropy"], {
    stubs: secureEntryStubs,
  });
  for (const method of METHODS) {
    for (const words of SIZES) {
      for (const count of COUNTS) {
        const digits = rollsText(count);
        const entry = entryFromDigits(digits, method);
        const secure = mod.hodlSecureDiceEntropyOf(entry, words);
        const text = mod.hodlDiceEntropy(digits, method, words);
        const label = `${method} ${words} ${count}`;
        assert.equal(secure.ok, text.ok, label);
        assert.deepEqual(secure.bytes, text.bytes, label);
        assert.equal(secure.bits, text.bits, label);
        assert.equal(secure.sourceBits, text.sourceBits, label);
        assert.equal(secure.method, text.method, label);
        assert.deepEqual(secure.notes, text.notes, label);
        assert.deepEqual(secure.warnings, text.warnings, label);
        const transcript = method === "coleman" ? digits.replaceAll("6", "0") : digits;
        const digest = createHash("sha256").update(transcript).digest();
        assert.equal(Buffer.from(secure.bytes).toString("hex"), digest.subarray(0, secure.bytes.length).toString("hex"), label);
      }
    }
  }
});

test("hodlSecureDiceEntropyOf zeroes the hash input and the digest", async () => {
  let seenIn = null, seenOut = null;
  const mod = await loadAppFunctions(["hodlSecureDiceEntropyOf"], {
    stubs: {
      ...secureEntryStubs,
      hodlSha256: (input) => {
        seenIn = input;
        seenOut = wasmSha256(input);
        return seenOut;
      },
    },
  });
  const secure = mod.hodlSecureDiceEntropyOf(entryFromDigits("123456", "coldcard"), 24);
  assert.equal(secure.ok, true);
  assert.ok(secure.bytes.some((byte) => byte !== 0));
  assert.ok(seenIn.every((byte) => byte === 0));
  assert.ok(seenOut.every((byte) => byte === 0));
  assert.equal(fnSource("hodlSecureDiceEntropyOf").includes("`"), false);
  for (const token of ["join(", "TextEncoder", "fromCharCode"]) assert.equal(fnSource("hodlSecureDiceEntropyOf").includes(token), false, token);
});

test("the dice converter and serializer round-trip faces and zero their buffers", async () => {
  const made = [];
  const mod = await loadAppFunctions(["hodlSecureDiceEntryFromText", "hodlSecureDiceRollsText"], {
    stubs: {
      ...secureEntryStubs,
      rollsEntry: (method, capacity) => {
        const entry = rollsEntry(method, capacity);
        made.push(entry);
        return entry;
      },
    },
  });
  const entry = mod.hodlSecureDiceEntryFromText("1 2,3;4|5\n66", "coldcard");
  assert.deepEqual(Array.from({ length: entry.count }, (_, i) => rollAt(entry, i)), [1, 2, 3, 4, 5, 6, 6]);
  const originalFill = Uint8Array.prototype.fill;
  const fills = [];
  Uint8Array.prototype.fill = function (value) {
    if (this !== entry.rolls && this.length === entry.count) fills.push(this);
    return originalFill.call(this, value);
  };
  try {
    assert.equal(mod.hodlSecureDiceRollsText(entry), "1234566");
  } finally {
    Uint8Array.prototype.fill = originalFill;
  }
  assert.equal(fills.length, 1);
  assert.ok(fills[0].every((byte) => byte === 0));
  for (const bad of ["12a", "", ",", "1".repeat(4097)]) {
    made.length = 0;
    assert.throws(() => mod.hodlSecureDiceEntryFromText(bad, "coldcard"), bad);
    assert.equal(made.length, 0, bad);
  }
});

test("secure dice low-entropy warnings and fairness match the text path", async () => {
  const copies = [];
  const mod = await loadAppFunctions(["hodlSecureDiceLowEntropyWarning", "hodlLowEntropyWarningFor", "hodlSecureDiceFairnessReportsOf", "hodlDiceFairnessReports"], {
    stubs: {
      ...secureEntryStubs,
      rollsCopy: (entry) => {
        const copy = rollsCopy(entry);
        copies.push(copy);
        return copy;
      },
    },
  });
  for (const words of [12, 24]) {
    for (const count of [0, 1, 49, 50, 99, 100, 101]) {
      assert.deepEqual(mod.hodlSecureDiceLowEntropyWarning(count, words), mod.hodlLowEntropyWarningFor("dice", "coldcard", "1".repeat(count), words), `${words} ${count}`);
    }
  }
  assert.deepEqual(mod.hodlSecureDiceFairnessReportsOf(entryFromDigits(rollsText(29), "coldcard")), []);
  const enough = entryFromDigits(rollsText(30), "coldcard");
  assert.deepEqual(mod.hodlSecureDiceFairnessReportsOf(enough), mod.hodlDiceFairnessReports(rollsText(30), "coldcard", 24));
  assert.ok(copies.at(-1).every((byte) => byte === 0));
});

test("dice bytes derive the same seed through indices as through a mnemonic", async () => {
  const mod = await loadAppFunctions(["hodlSecureDiceEntropyOf"], { stubs: secureEntryStubs });
  const bytes = Uint8Array.from(mod.hodlSecureDiceEntropyOf(entryFromDigits("123456", "coldcard"), 24).bytes);
  const fromIndices = seedFromIndices(indicesFromEntropy(bytes));
  const fromPhrase = mnemonicToSeedSync(entropyToMnemonic(bytes, wordlist));
  assert.deepEqual(fromIndices, fromPhrase);
  const calc = app.slice(app.indexOf("async function hodlCalculateKey("), app.indexOf("\n}\n", app.indexOf("async function hodlCalculateKey(")));
  const secure = calc.slice(calc.indexOf("if (hodlSecureDiceApplies())"), calc.indexOf('} else if (hodlDiceMethod === "dplus")'));
  assert.match(secure, /hodlIndicesFromEntropy\(entropy\.bytes\)/);
  assert.match(secure, /hodlMnemonicWalletWithProgress\(\{ indices \}/);
  assert.doesNotMatch(secure, /hodlEntropyWalletWithProgress/);
});

test("secure dice routing follows the switch, the method and the pad on screen", async () => {
  const previous = globalThis.document;
  const doc = new MiniDocument();
  globalThis.document = doc;
  const supported = { seed: true, key: true, rolls: true, cards: false };
  try {
    // hodlKeyMode is a stub, one load per mode: as a settable name it would
    // pull in the page's mode select, which needs #modes.
    const load = (keyMode) => loadAppFunctions(["hodlSecureDiceActive", "hodlSecureDiceApplies", "hodlSecureEntryHasData", "hodlSecureKeyOf", "hodlSecureDiceEntry"], {
      stubs: { ...secureEntryStubs, hodlSecureSupported: supported, document: doc, hodlKeyMode: keyMode },
      settable: ["hodlSecureEntryOn", "hodlDiceMethod", "hodlKeys", "hodlActiveKey", "hodlSecureSession"],
    });
    const seedMode = await load("seed");
    seedMode.__set.hodlSecureEntryOn(true);
    assert.equal(seedMode.hodlSecureDiceActive(), false, "another method");
    const mod = await load("dice");
    const session = createSecureSession();
    const state = { id: 1, fields: { dice: "" } };
    mod.__set.hodlSecureSession(session);
    mod.__set.hodlKeys([state]);
    mod.__set.hodlActiveKey(0);
    mod.__set.hodlDiceMethod("coldcard");
    mod.__set.hodlSecureEntryOn(false);
    assert.equal(mod.hodlSecureDiceActive(), false);
    mod.__set.hodlSecureEntryOn(true);
    supported.rolls = false;
    assert.equal(mod.hodlSecureDiceActive(), false);
    supported.rolls = true;
    mod.__set.hodlDiceMethod("bitbox");
    assert.equal(mod.hodlSecureDiceActive(), false);
    mod.__set.hodlDiceMethod("dplus");
    assert.equal(mod.hodlSecureDiceActive(), false);
    mod.__set.hodlDiceMethod("coldcard");
    assert.equal(mod.hodlSecureDiceActive(), true);
    const owner = mod.hodlSecureKeyOf(state, true);
    const held = rollsEntry("coldcard", 400);
    rollsPush(held, 4);
    sessionSet(session, owner, "rolls", held);
    assert.equal(mod.hodlSecureEntryHasData(owner), true);
    const empty = rollsEntry("coldcard", 400);
    sessionSet(session, owner, "rolls", empty);
    state.fields.dice = "123456";
    assert.equal(mod.hodlSecureDiceApplies(), false);
    const host = doc.createElement("div");
    host.id = "secure-dice-host";
    doc.body.append(host);
    assert.equal(mod.hodlSecureDiceApplies(), true);
  } finally {
    globalThis.document = previous;
  }
});

test("turning Secure entry on and off keeps, clears and converts dice beside keys", async () => {
  const previous = globalThis.document;
  const diceField = { value: "1234 56", dataset: { previousValue: "1234 56" }, hodlDiceBeforeInput: "x" };
  const panels = Object.fromEntries(["dice-highlight", "dice-words", "last-words", "dice-fairness", "dice-meta"].map((id) => [id, { textContent: "x" }]));
  globalThis.document = { getElementById: (id) => id === "dice" ? diceField : panels[id] ?? null, querySelector: () => null };
  try {
    let choice = "keep", lastOptions = null;
    const wif = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ";
    const mod = await loadAppFunctions(["hodlSecureEntryToggle", "hodlSecureKeyOf", "hodlSecureEntryOn", "hodlSecureSession", "hodlClearGlobalSyncCopies", "hodlSecureDiceEntropyOf", "hodlDiceEntropy"], {
      stubs: {
        ...secureEntryStubs,
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
        hodlKeyMode: "dice",
        hodlPrivateKeyValues: (fields) => fields.privateKeys,
        hodlEntropyFormats: { hex: {}, bin: {} },
        hodlLastWordCache: { clear() {} },
        hodlLooksExtendedKey: () => false,
      },
      settable: ["hodlSecureEntryOn", "hodlSecureSession", "hodlKeys", "hodlActiveKey"],
    });
    const synced = {
      id: 1, name: "Dice", mode: "dice", diceMethod: "coldcard", globalSync: true, globalSyncSource: "dice:coldcard", lastWord: "kept",
      fields: { dice: "1234 56", hex: "abcd", bin: "1010", seed: "words", privateKeys: { wif: "wifvalue", "hex-key": "hexkey" } },
    };
    mod.__set.hodlSecureSession(createSecureSession());
    mod.__set.hodlKeys([synced]);
    mod.__set.hodlActiveKey(0);
    mod.__set.hodlSecureEntryOn(false);
    await mod.hodlSecureEntryToggle(true);
    assert.equal(lastOptions.canKeep, true);
    assert.deepEqual(lastOptions.names, ["Dice"]);
    const kept = sessionGet(mod.hodlSecureSession, mod.hodlSecureKeyOf(synced), "rolls");
    assert.deepEqual(Array.from({ length: kept.count }, (_, i) => rollAt(kept, i)), [1, 2, 3, 4, 5, 6]);
    assert.equal(synced.fields.dice, "");
    assert.equal(synced.fields.hex, "");
    assert.equal(synced.lastWord, "");
    assert.equal(diceField.value, "");
    assert.equal(diceField.dataset.previousValue, undefined);
    assert.equal(diceField.hodlDiceBeforeInput, undefined);
    for (const panel of Object.values(panels)) assert.equal(panel.textContent, "");

    const other = {
      id: 2, name: "Other", mode: "dice", diceMethod: "coldcard", globalSync: true, globalSyncSource: "number:hex", lastWord: "stay",
      fields: { dice: "11", hex: "beef", privateKeys: { wif: "", "hex-key": "" } },
    };
    mod.__set.hodlSecureSession(createSecureSession());
    mod.__set.hodlKeys([other]);
    mod.__set.hodlSecureEntryOn(false);
    await mod.hodlSecureEntryToggle(true);
    assert.equal(other.fields.hex, "beef");
    assert.equal(other.lastWord, "stay");
    assert.equal(other.fields.dice, "");

    const keyState = { id: 3, name: "Key", mode: "key", fields: { keyKind: "wif", privateKeys: { wif, "hex-key": "", minikey: "", brain: "" } } };
    const diceState = { id: 4, name: "Rolls", mode: "dice", diceMethod: "coldcard", fields: { dice: "123456" } };
    choice = "keep";
    lastOptions = null;
    mod.__set.hodlSecureSession(createSecureSession());
    mod.__set.hodlKeys([keyState, diceState]);
    mod.__set.hodlActiveKey(1);
    mod.__set.hodlSecureEntryOn(false);
    await mod.hodlSecureEntryToggle(true);
    assert.deepEqual(lastOptions.names, ["Key", "Rolls"]);
    assert.equal(sessionGet(mod.hodlSecureSession, mod.hodlSecureKeyOf(keyState), "key").vault.text(), wif);
    assert.equal(keyState.fields.privateKeys.wif, "");
    assert.equal(sessionGet(mod.hodlSecureSession, mod.hodlSecureKeyOf(diceState), "rolls").count, 6);
    assert.equal(diceState.fields.dice, "");

    const coleman = { id: 5, name: "Base 6", mode: "dice", diceMethod: "coleman", fields: { colemanDice: "65" } };
    mod.__set.hodlSecureSession(createSecureSession());
    mod.__set.hodlKeys([coleman]);
    mod.__set.hodlSecureEntryOn(false);
    await mod.hodlSecureEntryToggle(true);
    const colemanEntry = sessionGet(mod.hodlSecureSession, mod.hodlSecureKeyOf(coleman), "rolls");
    assert.equal(colemanEntry.method, "coleman");
    assert.deepEqual(Array.from({ length: 2 }, (_, i) => rollAt(colemanEntry, i)), [6, 5]);
    assert.equal(coleman.fields.colemanDice, "");

    const bad = { id: 6, name: "Bad", mode: "dice", diceMethod: "coldcard", fields: { dice: "12x" } };
    choice = null;
    lastOptions = null;
    mod.__set.hodlSecureSession(createSecureSession());
    mod.__set.hodlKeys([bad]);
    mod.__set.hodlSecureEntryOn(false);
    await mod.hodlSecureEntryToggle(true);
    assert.equal(lastOptions.canKeep, false);
    assert.equal(bad.fields.dice, "12x");
    assert.equal(mod.hodlSecureEntryOn, false);

    const bitbox = { id: 7, name: "BitBox", mode: "dice", diceMethod: "bitbox", fields: { bitboxDice: "111111" } };
    choice = "keep";
    lastOptions = null;
    mod.__set.hodlSecureSession(createSecureSession());
    mod.__set.hodlKeys([bitbox]);
    mod.__set.hodlSecureEntryOn(false);
    await mod.hodlSecureEntryToggle(true);
    assert.equal(lastOptions, null);
    assert.equal(bitbox.fields.bitboxDice, "111111");
    assert.equal(mod.hodlSecureSession.entries.size, 0);

    const marked = { id: 8, name: "Marked", mode: "dice", diceMethod: "coldcard", result: { kind: "hd" }, fields: { dice: "11" } };
    choice = "clear";
    mod.__set.hodlSecureSession(createSecureSession());
    mod.__set.hodlKeys([marked]);
    mod.__set.hodlSecureEntryOn(false);
    await mod.hodlSecureEntryToggle(true);
    assert.equal(marked.fields.dice, "");
    assert.equal(marked.secureCleared, true);
    assert.equal(mod.hodlSecureSession.entries.size, 0);

    for (const [method, field] of [["coldcard", "dice"], ["coleman", "colemanDice"]]) {
      const session = createSecureSession();
      const state = { id: 9, name: method, mode: "dice", diceMethod: method, fields: { dice: "", colemanDice: "" } };
      const entry = rollsEntry(method, 400);
      for (const face of [1, 2, 3, 4, 5, 6]) rollsPush(entry, face);
      mod.__set.hodlSecureSession(session);
      // A cards key that never had secure entry has no id: Convert still
      // runs (Claude, review).
      mod.__set.hodlKeys([state, { id: 10, name: "Cards", mode: "cards", fields: { cards: "" } }]);
      mod.__set.hodlSecureEntryOn(true);
      sessionSet(session, mod.hodlSecureKeyOf(state, true), "rolls", entry);
      choice = "convert";
      await mod.hodlSecureEntryToggle(false);
      assert.equal(state.fields[field], "123456", method);
      assert.equal(method === "coldcard" ? state.fields.colemanDice : state.fields.dice, "", method);
      assert.equal(mod.hodlSecureEntryOn, false, method);
    }

    // Gemini (#1395): an empty pad entry must not blank rolls kept as text.
    // A second key holds rolls, so turning off asks and Convert runs.
    const session = createSecureSession();
    const textBacked = { id: 11, name: "Typed", mode: "dice", diceMethod: "coldcard", fields: { dice: "6543", colemanDice: "" } };
    const held = { id: 12, name: "Held", mode: "dice", diceMethod: "coldcard", fields: { dice: "", colemanDice: "" } };
    mod.__set.hodlSecureSession(session);
    mod.__set.hodlKeys([textBacked, held]);
    mod.__set.hodlSecureEntryOn(true);
    sessionSet(session, mod.hodlSecureKeyOf(textBacked, true), "rolls", rollsEntry("coldcard", 400));
    const heldRolls = rollsEntry("coldcard", 400);
    for (const face of [1, 2]) rollsPush(heldRolls, face);
    sessionSet(session, mod.hodlSecureKeyOf(held, true), "rolls", heldRolls);
    choice = "convert";
    await mod.hodlSecureEntryToggle(false);
    assert.equal(held.fields.dice, "12");
    assert.equal(textBacked.fields.dice, "6543");
    assert.equal(mod.hodlSecureEntryOn, false);

    // Keep and Clear empty every dice field, not only the kept method's.
    for (const action of ["keep", "clear"]) {
      // privateKeys is there as hodlPrivateKeyValues makes it in the app; the
      // stub here only returns it.
      const fields = { dice: "123456", colemanDice: "654321", bitboxDice: "111111", dplusDice: "222222", seed: "copied words", hex: "abcd", privateKeys: { wif: "synced wif", "hex-key": "synced hex" } };
      // Global sync last ran from another dice method: its copies are made
      // from text this Keep empties, so they go too (#1439 red team).
      const state = { id: 20, name: action, mode: "dice", diceMethod: "coldcard", fields, globalSync: true, globalSyncSource: "dice:coleman", diceCoinPositions: [1, 0, 1], dplusLastWord: "abandon", lastWord: "zoo" };
      const session = createSecureSession();
      mod.__set.hodlSecureSession(session);
      mod.__set.hodlKeys([state]);
      mod.__set.hodlActiveKey(0);
      mod.__set.hodlSecureEntryOn(false);
      choice = action;
      lastOptions = null;
      await mod.hodlSecureEntryToggle(true);
      assert.equal(lastOptions.otherFormats, true, action);
      for (const name of ["dice", "colemanDice", "bitboxDice", "dplusDice"]) assert.equal(state.fields[name], "", `${action} ${name}`);
      assert.equal(state.fields.seed, "", `${action}: a Global sync copy from another dice method survived`);
      assert.equal(state.fields.hex, "", `${action} hex copy`);
      assert.deepEqual(state.fields.privateKeys, { wif: "", "hex-key": "" }, `${action} private-key copies`);
      assert.deepEqual(state.diceCoinPositions, [], `${action} coin positions`);
      assert.equal(state.dplusLastWord, "", `${action} D++ last word`);
      assert.equal(state.lastWord, "", `${action} last word`);
    }

    // lastWord is BitBox's pick only when BitBox rolls were there: Keep
    // without them leaves it, as it leaves the Global sync copies above.
    for (const [bitboxDice, expected] of [["", "seedword"], ["111111", ""]]) {
      const state = { id: 22, name: "Pick", mode: "dice", diceMethod: "coldcard", fields: { dice: "123456", bitboxDice }, lastWord: "seedword" };
      mod.__set.hodlSecureSession(createSecureSession());
      mod.__set.hodlKeys([state]);
      mod.__set.hodlActiveKey(0);
      mod.__set.hodlSecureEntryOn(false);
      choice = "keep";
      await mod.hodlSecureEntryToggle(true);
      assert.equal(state.fields.bitboxDice, "");
      assert.equal(state.lastWord, expected, `bitboxDice ${JSON.stringify(bitboxDice)}`);
    }

    // More than 400 typed rolls is keepable, and hashes like the text path.
    for (const count of [401, 1000]) {
      const text = rollsText(count);
      const state = { id: 21, name: "Many", mode: "dice", diceMethod: "coldcard", fields: { dice: text } };
      const session = createSecureSession();
      mod.__set.hodlSecureSession(session);
      mod.__set.hodlKeys([state]);
      mod.__set.hodlActiveKey(0);
      mod.__set.hodlSecureEntryOn(false);
      choice = "keep";
      lastOptions = null;
      await mod.hodlSecureEntryToggle(true);
      assert.equal(lastOptions.canKeep, true, `${count} rolls`);
      const entry = sessionGet(session, mod.hodlSecureKeyOf(state), "rolls");
      assert.equal(entry.count, count);
      const secure = mod.hodlSecureDiceEntropyOf(entry, 24);
      const textPath = mod.hodlDiceEntropy(text, "coldcard", 24);
      assert.deepEqual(secure.bytes, textPath.bytes, `${count} rolls hash`);
      assert.equal(state.fields.dice, "");
    }

    // More than 4096 typed rolls is not keepable.
    const tooMany = rollsText(4097);
    const tooManyState = { id: 22, name: "Too many", mode: "dice", diceMethod: "coldcard", fields: { dice: tooMany } };
    const tooManySession = createSecureSession();
    mod.__set.hodlSecureSession(tooManySession);
    mod.__set.hodlKeys([tooManyState]);
    mod.__set.hodlActiveKey(0);
    mod.__set.hodlSecureEntryOn(false);
    choice = "keep";
    lastOptions = null;
    await mod.hodlSecureEntryToggle(true);
    assert.equal(lastOptions.canKeep, false);
    assert.equal(tooManyState.fields.dice, tooMany);
    assert.equal(tooManySession.entries.size, 0);
  } finally {
    globalThis.document = previous;
  }
});

test("the secure dice form, mount and End Session name the pad", () => {
  const form = app.slice(app.indexOf("function hodlRenderKeyForm() {"), app.indexOf("\nfunction ", app.indexOf("function hodlRenderKeyForm() {") + 1));
  assert.match(form, /hodlSecureDicePad\?\.destroy\(\)/);
  const secure = fnSource("hodlRenderSecureDiceForm");
  assert.equal(secure.includes('id="dice"'), false);
  assert.match(secure, /id="secure-dice-host"/);
  assert.match(fnSource("hodlMountSecureDicePad"), /import\("\.\/secure-dice-pad\.js"\)/);
  const end = app.slice(app.indexOf("let clearSecretFields = () => {"), app.indexOf("hodlSyncWorkspaceCounts();", app.indexOf("let clearSecretFields = () => {")));
  assert.match(end, /hodlSecureDicePad\?\.destroy\(\)/);
  assert.match(end, /getElementById\("secure-dice-host"\)/);
});
