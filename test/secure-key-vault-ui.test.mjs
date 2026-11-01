// Secure entry P3b-2: the masked private-key field (preview builds only).
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
import { SUPPORTED_METHODS, isSupported } from "../src/js/secure-entry.js";

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
  assert.equal(SUPPORTED_METHODS.rolls, false);
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
  assert.match(toggle, /if \(state\.globalSync && state\.globalSyncSource === `key:\$\{kind\}`\) hodlClearGlobalSyncCopies\(state\);/, "Keep: copies computed from the key");
  const clear = toggle.slice(toggle.indexOf('} else if (choice === "clear") {'));
  const keyLoop = clear.slice(clear.indexOf("for (const { state, kind } of keyStates)"));
  assert.match(keyLoop.slice(0, keyLoop.indexOf("hodlPrivateKeyValues")), /if \(state\.globalSync\) hodlClearGlobalSyncCopies\(state\);/, "Clear: every copy");
});
