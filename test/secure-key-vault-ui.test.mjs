// Secure entry P3b-2: the masked private-key field.
//
// Contract: with Secure entry on, key mode and a non-brain kind, the private
// key is typed into a vault-bound masked field and parsed from bytes; every
// other case keeps today's textarea, and the reveal readout is removed on the
// next edit, on hodl:conceal and at End Session.
//
// These are source-level checks: the key form needs a DOM, and the app's
// existing secure-entry tests read the source the same way. They hook on ids,
// data-* attributes and function names, never on copy.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  SUPPORTED_METHODS, isSupported, createSecureSession, sessionWipe, sessionDeleteKey,
  sessionGet, sessionSet, seedEntry, seedSet, seedIndices, seedUndo, keyEntry,
  planTurnOn, commitTurnOn, planTurnOff, commitTurnOff, discardPlan,
  rollsEntry, rollsPush, rollsUndo, rollAt, rollsCopy,
} from "../src/js/secure-entry.js";
import { MiniDocument } from "./mini-dom.mjs";
import { loadAppFunctions } from "./app-slice-harness.mjs";

const source = readFileSync(new URL("../src/js/app.js", import.meta.url), "utf8");

// The body of a top-level function, from its declaration to the next one.
function block(name) {
  const start = source.indexOf(`function ${name}(`);
  assert.ok(start >= 0, `${name} is defined in app.js`);
  const next = source.indexOf("\nfunction ", start + 1);
  return source.slice(start, next < 0 ? source.length : next);
}

test("SUPPORTED_METHODS.key is true, so the key method is supported", () => {
  assert.equal(SUPPORTED_METHODS.key, true);
  assert.equal(isSupported("key"), true);
  assert.equal(SUPPORTED_METHODS.seed, true);
  // P4b: dice rolls are supported too.
  assert.equal(SUPPORTED_METHODS.rolls, true);
  assert.equal(SUPPORTED_METHODS.cards, false);
});

test("the key form renders the masked field only when Secure entry applies", () => {
  const form = block("hodlRenderKeyForm");
  assert.match(form, /hodlSecureKeyFormApplies\(/);
  assert.match(form, /<input id="secure-key"/);
  assert.match(form, /data-secure-key/);
  assert.doesNotMatch(form, /<input id="key"/);
  // The standard text field is still the fallback.
  assert.match(form, /<textarea id="key"/);
  assert.match(form, /hodlReleaseSecureKeyField\(\)/);
  assert.match(form, /hodlBindSecureKeyField\(\)/);
});

test("the masked field is bound to the key's vault, never to state.fields", () => {
  const bind = block("hodlBindSecureKeyField");
  assert.match(bind, /getElementById\("secure-key"\)/);
  assert.match(bind, /bindVaultField\(field, entry\.vault, \{ active: hodlSecureKeyActive \}\)/);
  assert.match(bind, /hodlSecureKeyEntry\(true\)/);
  assert.match(bind, /hodlSetMode\(hodlKeyMode\)/);
  assert.doesNotMatch(bind, /state\.fields/);
});

test("the reveal readout is removed on input, on hodl:conceal and at End Session", () => {
  const bind = block("hodlBindSecureKeyField");
  assert.match(bind, /addEventListener\("input"/);
  assert.match(bind, /hodlSecureKeyConceal\(\)/);
  assert.match(bind, /addEventListener\("hodl:conceal", hodlSecureKeyConceal\)/);
  const release = block("hodlReleaseSecureKeyField");
  assert.match(release, /removeEventListener\("hodl:conceal", hodlSecureKeyConceal\)/);
  assert.match(release, /data-secure-key-readout/);
});

test("the reveal never calls unmask, which would move the text into the DOM", () => {
  const reveal = block("hodlSecureKeyShowReadout") + block("hodlSecureKeyConceal") + block("hodlBindSecureKeyField") + block("hodlReleaseSecureKeyField");
  assert.doesNotMatch(reveal, /\.unmask\(/);
  assert.match(block("hodlSecureKeyShowReadout"), /entry\.vault\.text\(\)/);
});

test("the status line runs Derive's own checks and zeroes the parsed key in a finally", () => {
  // MiniMax, round 1: the line said "checksum passed" for a WIF of the other
  // network while Derive refused it. It now parses through the same function.
  const status = block("hodlSecureKeyStatus");
  assert.match(status, /hodlSecureKeyParsed\(network\)/);
  assert.doesNotMatch(status, /parsePrivateKeyBytes\(/);
  assert.match(status, /finally\s*\{[\s\S]*parsed\.priv\?\.fill\(0\)/);
  assert.match(status, /parsed\.minikey\?\.fill\(0\)/);
});

test("the status line shows only a count below a complete length", () => {
  const status = block("hodlSecureKeyStatus");
  assert.match(status, /hodlSecureKeyLengths\(kind\)/);
  assert.match(status, /count < Math\.max\(\.\.\.lengths\)/);
});

test("turning on plans the key method for a key with typed text", () => {
  const toggle = block("hodlSecureEntryToggle");
  assert.match(toggle, /methods: \{ key: \{ text:/);
  assert.match(toggle, /key: keyConverter/);
  assert.match(toggle, /entry\.vault\.setBytes\(bytes\)/);
  assert.match(toggle, /bytes\.fill\(0\)/);
});

test("turning off Convert writes the vault text back to the key's field", () => {
  const toggle = block("hodlSecureEntryToggle");
  assert.match(toggle, /key: keySerializer/);
  assert.match(toggle, /entry\.vault\.text\(\)/);
  assert.match(toggle, /hodlPrivateKeyValues\(state\.fields\)\[/);
});

test("a kind change on the standard form draws the masked field when Secure entry holds the key", () => {
  // Brain wallet uses the standard form. Choosing WIF again there must not
  // leave a text field on screen while derivation reads the vault.
  const at = source.indexOf("if (target.matches('input[name=\"kk\"]') && !document.getElementById(\"secure-key\") && hodlSecureKeyFormApplies(hodlKeys[hodlActiveKey])) hodlSetMode(hodlKeyMode);");
  assert.ok(at > 0, "the panel's kind-change listener redraws into the masked field");
  const listener = source.lastIndexOf('panel.addEventListener("change"', at);
  assert.ok(listener > 0 && source.indexOf("});", listener) > at, "inside the panel's change listener");
});


test("while the vault holds a key, only its own format can be chosen", async () => {
  // Astra, Grok, Kimi, GLM (round 1): a format change kept the vault's text,
  // read it as another format, and Convert filed it under the wrong one.
  const { loadAppFunctions } = await import("./app-slice-harness.mjs");
  const { hodlSecureKeyLockKinds } = await loadAppFunctions(["hodlSecureKeyLockKinds"]);
  const radios = ["wif", "hex-key", "minikey", "brain"].map((value) => ({ value, disabled: false }));
  hodlSecureKeyLockKinds(radios, "wif", true);
  assert.deepEqual(radios.map((radio) => radio.disabled), [false, true, true, true]);
  hodlSecureKeyLockKinds(radios, "wif", false);
  assert.deepEqual(radios.map((radio) => radio.disabled), [false, false, false, false], "an empty field frees every format");
  const bind = block("hodlBindSecureKeyField");
  assert.match(bind, /hodlSecureKeyLockKinds\(document\.querySelectorAll\('input\[name="kk"\]'\), hodlSecureKeyKind\(\), entry\.vault\.length > 0\)/);
  const input = bind.slice(bind.indexOf('field.addEventListener("input"'));
  assert.ok(input.indexOf("lockKinds()") > 0 && input.indexOf("lockKinds()") < input.indexOf("});"), "every edit re-checks the lock");
});

test("editing the masked field drops the shown wallet and refreshes the fingerprint", () => {
  const listener = source.slice(source.indexOf("function hodlInitMasterFingerprintPreview("));
  const branch = listener.slice(listener.indexOf('if (id === "secure-key") {'), listener.indexOf('if (!["pass", "dice", "hex",'));
  assert.ok(branch.length > 0, "the panel's input listener handles the masked field");
  assert.match(branch, /hodlInvalidateLiveKeyResult\(\);/);
  assert.match(branch, /hodlQueueMasterFingerprintPreview\(\);/);
  assert.match(branch, /return;/);
});

test("Show key reveals whatever the page-wide reveal setting is, and the button follows what is shown", () => {
  const readout = block("hodlSecureKeyShowReadout");
  assert.match(readout, /hodlPrivateValue\(entry\.vault\.text\(\), [^,()]+, true\)/);
  const bind = block("hodlBindSecureKeyField");
  assert.match(bind, /setAttribute\("aria-pressed", hodlSecureKeyRevealed \? "true" : "false"\)/);
});

test("turning Secure entry on clears Global sync copies made from a typed key", () => {
  const toggle = block("hodlSecureEntryToggle");
  assert.match(toggle, /if \(state\.globalSync && String\(state\.globalSyncSource \|\| ""\)\.startsWith\("key:"\)\) hodlClearGlobalSyncCopies\(state\);/, "Keep: copies computed from the key, whichever format was the source");
  const clear = toggle.slice(toggle.indexOf('} else if (choice === "clear") {'));
  const keyLoop = clear.slice(clear.indexOf("for (const { state } of keyStates)"));
  assert.ok(keyLoop.startsWith("for (const { state } of keyStates)"), "the Clear branch walks the key states");
  assert.match(keyLoop.slice(0, keyLoop.indexOf("hodlPrivateKeyValues")), /if \(state\.globalSync\) hodlClearGlobalSyncCopies\(state\);/, "Clear: every copy");
});

test("round 3: the status follows the network, an empty vault converts to nothing, the keyboard host is redrawn", () => {
  const bind = block("hodlBindSecureKeyField");
  assert.match(bind, /hodlSecureKeyNetworkWatch = hodlSecureKeyStatus;/);
  assert.match(bind, /network\?\.addEventListener\("change", hodlSecureKeyNetworkWatch\)/);
  assert.match(bind, /addEventListener\("hodl:network-default", hodlSecureKeyNetworkWatch\)/);
  const release = block("hodlReleaseSecureKeyField");
  assert.match(release, /removeEventListener\("hodl:network-default", hodlSecureKeyNetworkWatch\)/);
  assert.match(release, /removeEventListener\("change", hodlSecureKeyNetworkWatch\)/);
  assert.doesNotMatch(release, /hodlSecureKeyStatus/, "release names no status function (slice harness)");
  const toggle = block("hodlSecureEntryToggle");
  const keyBranch = toggle.slice(toggle.indexOf('else if (method === "key") {'));
  assert.ok(keyBranch.indexOf("if (!text) continue;") >= 0 && keyBranch.indexOf("if (!text) continue;") < keyBranch.indexOf("hodlPrivateKeyValues(state.fields)[kind] = text"), "an empty vault is skipped before anything is written");
  const form = block("hodlRenderKeyForm");
  const secure = form.slice(form.indexOf("hodlBindSecureKeyField();"));
  assert.ok(secure.indexOf("hodlRenderPassphraseKeyboard();") >= 0 && secure.indexOf("hodlRenderPassphraseKeyboard();") < secure.indexOf("return;"), "the masked branch redraws the keyboard host like every other branch");
});

test("round 4: an emptied private-key field goes back to the masked field", () => {
  const bind = block("hodlBindKeyFields");
  const apply = bind.slice(bind.indexOf("let apply = (event) => {"), bind.indexOf("let change = (event) => {"));
  // Grok (round 5): only the user's own input event redraws, never the
  // apply() at bind time.
  assert.match(apply, /if \(event\?\.type === "input" && !key\.value && state && hodlSecureKeyFormApplies\(state\)\) \{\s*hodlSetMode\(hodlKeyMode\);[\s\S]*?document\.getElementById\("secure-key"\)\?\.focus\(/);
});

test("round 5: Clear empties every private-key format of a key", () => {
  const toggle = block("hodlSecureEntryToggle");
  const clear = toggle.slice(toggle.indexOf('} else if (choice === "clear") {'));
  const keyLoop = clear.slice(clear.indexOf("for (const { state } of keyStates) {"), clear.indexOf("commitTurnOn("));
  assert.ok(keyLoop.length > 0, "the Clear branch walks the key states");
  // K3.1 (round 5): the brain-wallet text goes too.
  assert.match(keyLoop, /for \(const format of \["wif", "hex-key", "minikey", "brain"\]\) values\[format\] = "";/);
});

test("round 7: with the masked field on screen, Derive reads only its vault", () => {
  // K3.1 (round 6): an emptied masked field fell back to a text key stored
  // behind it.
  const applies = block("hodlSecureKeyApplies");
  const masked = applies.indexOf('if (document.getElementById("secure-key")) return true;');
  const text = applies.indexOf('document.getElementById("key")');
  assert.ok(masked >= 0 && masked < text, "the masked field is checked before any text key");
});

test("Keep empties every private-key format of a key", () => {
  const toggle = block("hodlSecureEntryToggle");
  const keep = toggle.slice(toggle.indexOf('if (choice === "keep" && plan.ok) {'), toggle.indexOf('} else if (choice === "clear") {'));
  const keyLoop = keep.slice(keep.indexOf("for (const { state } of keyStates) {"), keep.indexOf("for (const { state, method } of diceStates)"));
  assert.ok(keyLoop.length > 0, "the Keep branch walks the key states");
  assert.match(keyLoop, /let values = hodlPrivateKeyValues\(state\.fields\);/);
  assert.match(keyLoop, /for \(const format of \["wif", "hex-key", "minikey", "brain"\]\) values\[format\] = "";/);
});

test("the toggle passes otherFormats exactly when another slot holds text", async () => {
  const previous = globalThis.document;
  globalThis.document = { getElementById: () => null, querySelector: () => null };
  try {
    let lastOptions = null;
    const mod = await loadAppFunctions(["hodlSecureEntryToggle", "hodlSecureKeyOf", "hodlSecureEntryOn"], {
      stubs: {
        createSecureSession, sessionWipe, sessionDeleteKey, sessionGet, sessionSet,
        seedEntry, seedSet, seedIndices, seedUndo, keyEntry, planTurnOn, commitTurnOn,
        planTurnOff, commitTurnOff, discardPlan, rollsEntry, rollsPush, rollsUndo, rollAt, rollsCopy,
        hodlSecureSupported: SUPPORTED_METHODS,
        hodlSecureEntryDialog: async () => ({ open: async (options) => { lastOptions = options; return "keep"; } }),
        hodlCaptureKey: () => {},
        hodlRenderSecureEntryControl: () => {},
        hodlSetMode: () => {},
        hodlSyncKeyClearButton: () => {},
        hodlSyncDeriveButton: () => {},
        hodlQueueMasterFingerprintPreview: () => {},
        hodlNormalizeSeedMethod: (value) => value === "numbers" ? "numbers" : "words",
        hodlBip39WordIndex: new Map(),
        hodlBip39Wordlist: [],
        hodlKeyMode: "key",
        hodlPrivateKeyValues: (fields) => fields.privateKeys,
        hodlEntropyFormats: { hex: {}, bin: {} },
        hodlLastWordCache: { clear() {} },
        hodlLooksExtendedKey: () => false,
      },
      settable: ["hodlSecureEntryOn", "hodlSecureSession", "hodlKeys", "hodlActiveKey"],
    });
    const wif = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ";
    const hexKey = "0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d";
    const run = async (privateKeys) => {
      lastOptions = null;
      const state = { id: 1, name: "Key", mode: "key", fields: { keyKind: "wif", privateKeys } };
      mod.__set.hodlSecureSession(createSecureSession());
      mod.__set.hodlKeys([state]);
      mod.__set.hodlActiveKey(0);
      mod.__set.hodlSecureEntryOn(false);
      await mod.hodlSecureEntryToggle(true);
      return { state, options: lastOptions };
    };
    const only = await run({ wif, "hex-key": "", minikey: "", brain: "" });
    assert.equal(only.options.otherFormats, false, "only the format on screen holds text");
    assert.equal(only.state.fields.privateKeys.wif, "", "Keep empties the kept slot");
    const other = await run({ wif, "hex-key": hexKey, minikey: "", brain: "" });
    assert.equal(other.options.otherFormats, true, "another slot holds text");
    for (const format of ["wif", "hex-key", "minikey", "brain"]) assert.equal(other.state.fields.privateKeys[format], "", format);
  } finally {
    globalThis.document = previous;
  }
});

test("B2: a key held as text shows the text-backed note", () => {
  const control = block("hodlRenderSecureEntryControl");
  // Its words are copy (AGENTS.md): only check the note is a translated string.
  assert.match(control, /id="secure-entry-key-text-backed">\$\{hodlT\("/);
  const keyBranch = control.indexOf("hodlSecureKeyActive()");
  assert.ok(keyBranch >= 0 && control.indexOf("hodlSecureKeyFormApplies(hodlKeys[hodlActiveKey])") > keyBranch);
});

test("B3: the format hint names only the three key formats, never brain", () => {
  const hint = block("hodlSecureKeyFormatHint");
  // A hint and a button for each of WIF, hex and mini key, as literal
  // hodlTText calls: both are set as textContent, so hodlT's HTML-escaped
  // catalog would show an apostrophe as "&#39;" (AGENTS.md I6). The words
  // themselves are copy (AGENTS.md).
  assert.equal(hint.match(/hodlTText\("/g)?.length, 6);
  assert.doesNotMatch(hint, /hodlT\("/);
  for (const found of ['"wif"', '"hex-key"', '"minikey"']) assert.ok(hint.includes(`found === ${found} ?`), found);
  assert.doesNotMatch(hint, /hodlTText\([^)]*brain/i);
  assert.match(hint, /finally\s*\{\s*bytes\.fill\(0\);\s*\}/);
  for (const forbidden of ["String.fromCharCode", "TextDecoder", "`"]) assert.equal(hint.includes(forbidden), false, forbidden);
});

test("B3: a complete hex key in a WIF vault shows the hint and switches on click", async () => {
  const previous = globalThis.document;
  const doc = new MiniDocument();
  globalThis.document = doc;
  try {
    doc.body.innerHTML = '<input type="radio" name="kk" value="wif" checked /><p id="secure-key-status"></p>';
    const hexKey = "0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d";
    const wif = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ";
    const modeCalls = [];
    const mod = await loadAppFunctions(["hodlSecureKeyStatus", "hodlSecureKeyOf"], {
      stubs: {
        createSecureSession, sessionWipe, sessionDeleteKey, sessionGet, sessionSet,
        seedEntry, seedSet, seedIndices, seedUndo, keyEntry, planTurnOn, commitTurnOn,
        planTurnOff, commitTurnOff, discardPlan, rollsEntry, rollsPush, rollsUndo, rollAt, rollsCopy,
        hodlSecureSupported: SUPPORTED_METHODS,
        hodlKeyMode: "key",
        hodlSelectedNetwork: () => "mainnet",
        hodlT: (text) => text,
        hodlTText: (text) => text,
        hodlSetMode: (mode) => { modeCalls.push(mode); },
        hodlAssertPrivateKey: () => {},
        hodlSecureKeyRefusal: () => new Error("refused"),
        hodlError: (key, vars) => Object.assign(new Error(key), { spec: { key, vars } }),
        hodlNetworkFamily: (value) => value === "mainnet" ? "mainnet" : "testnet",
      },
      settable: ["hodlSecureEntryOn", "hodlKeys", "hodlActiveKey", "hodlSecureSession", "hodlSecureKeys"],
    });
    mod.__set.hodlSecureKeys(new WeakMap());
    const session = createSecureSession();
    mod.__set.hodlSecureSession(session);
    const state = { id: 1, fields: { keyKind: "wif", privateKeys: { wif: "", "hex-key": "", minikey: "", brain: "" } } };
    mod.__set.hodlKeys([state]);
    mod.__set.hodlActiveKey(0);
    mod.__set.hodlSecureEntryOn(true);
    const entry = keyEntry();
    entry.vault.setText(hexKey);
    sessionSet(session, mod.hodlSecureKeyOf(state, true), "key", entry);
    mod.hodlSecureKeyStatus();
    const hint = doc.getElementById("secure-key-format-hint");
    const button = doc.getElementById("secure-key-format-switch");
    assert.ok(hint?.textContent.trim(), "the hint is shown");
    assert.ok(button?.textContent.trim(), "the switch button is shown");
    button.click();
    assert.equal(state.fields.keyKind, "hex-key");
    assert.deepEqual(modeCalls, ["key"]);
    entry.vault.setText(wif);
    mod.hodlSecureKeyStatus();
    assert.equal(doc.getElementById("secure-key-format-hint"), null);
    assert.equal(doc.getElementById("secure-key-format-switch"), null);
  } finally {
    globalThis.document = previous;
  }
});

test("B3: a complete key shorter than the selected format shows the hint too", async () => {
  // Kimi K3, Grok, GLM and MiniMax (round 1): below the selected format's
  // complete length the status returned with the count before the hint ran.
  const previous = globalThis.document;
  const doc = new MiniDocument();
  globalThis.document = doc;
  try {
    const wif = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ";
    const miniKey = "S6c56bnXQiBjk9mqSYE7ykVQ7NzrRy";
    const hexKey = "0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d";
    const mod = await loadAppFunctions(["hodlSecureKeyStatus", "hodlSecureKeyOf"], {
      stubs: {
        createSecureSession, sessionWipe, sessionDeleteKey, sessionGet, sessionSet,
        seedEntry, seedSet, seedIndices, seedUndo, keyEntry, planTurnOn, commitTurnOn,
        planTurnOff, commitTurnOff, discardPlan, rollsEntry, rollsPush, rollsUndo, rollAt, rollsCopy,
        hodlSecureSupported: SUPPORTED_METHODS,
        hodlKeyMode: "key",
        hodlSelectedNetwork: () => "mainnet",
        hodlT: (text) => text,
        hodlTText: (text) => text,
        hodlSetMode: () => {},
        hodlAssertPrivateKey: () => {},
        hodlSecureKeyRefusal: () => new Error("refused"),
        hodlError: (key, vars) => Object.assign(new Error(key), { spec: { key, vars } }),
        hodlNetworkFamily: (value) => value === "mainnet" ? "mainnet" : "testnet",
      },
      settable: ["hodlSecureEntryOn", "hodlKeys", "hodlActiveKey", "hodlSecureSession", "hodlSecureKeys"],
    });
    mod.__set.hodlSecureKeys(new WeakMap());
    const session = createSecureSession();
    mod.__set.hodlSecureSession(session);
    const state = { id: 1, fields: { keyKind: "wif", privateKeys: { wif: "", "hex-key": "", minikey: "", brain: "" } } };
    mod.__set.hodlKeys([state]);
    mod.__set.hodlActiveKey(0);
    mod.__set.hodlSecureEntryOn(true);
    const entry = keyEntry();
    sessionSet(session, mod.hodlSecureKeyOf(state, true), "key", entry);
    const status = (selected, text) => {
      doc.body.innerHTML = `<input type="radio" name="kk" value="${selected}" checked /><p id="secure-key-status"></p>`;
      state.fields.keyKind = selected;
      entry.vault.setText(text);
      mod.hodlSecureKeyStatus();
      return doc.getElementById("secure-key-format-switch");
    };
    for (const [selected, text, found] of [["hex-key", wif, "wif"], ["hex-key", miniKey, "minikey"], ["wif", miniKey, "minikey"]]) {
      const button = status(selected, text);
      assert.ok(doc.getElementById("secure-key-format-hint"), `${found} under ${selected}: the hint`);
      assert.ok(button, `${found} under ${selected}: the switch`);
      button.click();
      assert.equal(state.fields.keyKind, found);
    }
    // A key of the selected format still being typed shows only the count.
    assert.equal(status("hex-key", hexKey.slice(0, 51)), null);
    assert.equal(doc.getElementById("secure-key-format-hint"), null);
    assert.equal(status("wif", wif.slice(0, 30)), null);
  } finally {
    globalThis.document = previous;
  }
});
