// The app's paste control: a button below each secret field that writes the
// value copied within EntropyLab back into the field. It never reads the
// system clipboard.
import { test } from "node:test";
import assert from "node:assert/strict";
import { MiniDocument } from "./mini-dom.mjs";
import { APP_PASTE_TARGETS, decorateAppPaste, syncAppPaste, initAppPaste } from "../src/js/app-paste.js";
import { appClipboardPut, appClipboardClear, appClipboardHas, appClipboardText } from "../src/js/app-clipboard.js";
import { loadAppFunctions } from "./app-slice-harness.mjs";

const withDocument = (body) => {
  const doc = new MiniDocument();
  const previous = Object.getOwnPropertyDescriptor(globalThis, "document");
  Object.defineProperty(globalThis, "document", { configurable: true, value: doc });
  appClipboardClear();
  try { return body(doc); }
  finally {
    appClipboardClear();
    if (previous) Object.defineProperty(globalThis, "document", previous);
    else delete globalThis.document;
  }
};

const click = (doc, target) => doc.dispatchEvent({ type: "click", target });

test("APP_PASTE_TARGETS lists the secret fields that get a control", () => {
  assert.deepEqual(APP_PASTE_TARGETS, [
    "seed", "key", "hex", "pass", "bip85-key", "bip47-key", "bip47-pass",
    "sp-key", "sp-pass", "psbt-key", "psbt-pass", "nonce-key", "nonce-pass",
    "ln-seed", "ln-pass", "core-add-text", "journal-input", "journal-phrase",
  ]);
});

test("decorateAppPaste adds one control per target field, right after its anchor", () => withDocument((doc) => {
  doc.body.innerHTML = `
    <label class="field">BIP85 <textarea id="bip85-key"></textarea></label>
    <div class="dice-input-shell"><textarea id="seed"></textarea></div>
    <input id="ln-pass">
    <input id="not-a-target">
  `;
  decorateAppPaste(doc, { pasteIcon: () => "<svg></svg>", labelFor: (id) => `Paste into ${id}` });
  const controls = doc.querySelectorAll("[data-app-paste]");
  assert.equal(controls.length, 3);
  const byId = Object.fromEntries(controls.map((button) => [button.dataset.appPaste, button]));
  assert.deepEqual(Object.keys(byId).sort(), ["bip85-key", "ln-pass", "seed"]);
  for (const id of ["bip85-key", "seed", "ln-pass"]) {
    assert.equal(byId[id].getAttribute("aria-controls"), id);
    // Each control is named for its own field.
    assert.equal(byId[id].getAttribute("aria-label"), `Paste into ${id}`);
    assert.equal(byId[id].getAttribute("title"), `Paste into ${id}`);
    assert.equal(byId[id].getAttribute("type"), "button");
  }
  const bip85Row = byId["bip85-key"].closest("[data-app-paste-row]");
  assert.equal(bip85Row.previousElementSibling, doc.getElementById("bip85-key").closest("label"));
  const seedRow = byId["seed"].closest("[data-app-paste-row]");
  assert.equal(seedRow.previousElementSibling, doc.getElementById("seed").closest(".dice-input-shell"));
  const lnPassRow = byId["ln-pass"].closest("[data-app-paste-row]");
  assert.equal(lnPassRow.previousElementSibling, doc.getElementById("ln-pass"));
  for (const row of doc.querySelectorAll("[data-app-paste-row]")) assert.equal(row.hidden, false, "the control stays in place");
  for (const button of controls) assert.equal(button.disabled, true, "disabled while nothing is copied");
  decorateAppPaste(doc, { pasteIcon: () => "<svg></svg>", labelFor: (id) => `Paste into ${id}` });
  assert.equal(doc.querySelectorAll("[data-app-paste]").length, 3);
  assert.equal(doc.querySelector('[data-app-paste="not-a-target"]'), null);
}));

// hodlApplyLocale decorates again: the names fill in the field's name, so no
// catalog sweep carries them across a language switch (GLM, #1347 r4).
test("decorating again names the existing controls anew, without adding any", () => withDocument((doc) => {
  doc.body.innerHTML = `<input id="ln-pass"><div class="dice-input-shell"><textarea id="seed"></textarea></div>`;
  decorateAppPaste(doc, { pasteIcon: () => "", labelFor: (id) => `Paste into ${id}` });
  const before = doc.querySelectorAll("[data-app-paste]");
  decorateAppPaste(doc, { pasteIcon: () => "", labelFor: (id) => `Pegar en ${id}` });
  const after = doc.querySelectorAll("[data-app-paste]");
  assert.equal(after.length, 2);
  for (const [index, button] of after.entries()) {
    assert.equal(button, before[index], "the same control stays in place");
    assert.equal(button.getAttribute("aria-label"), `Pegar en ${button.dataset.appPaste}`);
    assert.equal(button.getAttribute("title"), `Pegar en ${button.dataset.appPaste}`);
  }
}));

test("syncAppPaste enables or disables every control from the app clipboard", () => withDocument((doc) => {
  doc.body.innerHTML = `<input id="ln-pass"><input id="seed">`;
  decorateAppPaste(doc, { pasteIcon: () => "", labelFor: (id) => `Paste into ${id}` });
  appClipboardPut("secret");
  syncAppPaste(doc);
  for (const button of doc.querySelectorAll("[data-app-paste]")) assert.equal(button.disabled, false);
  appClipboardClear();
  syncAppPaste(doc);
  for (const button of doc.querySelectorAll("[data-app-paste]")) assert.equal(button.disabled, true);
}));

test("controls follow the app clipboard through hodl:app-clipboard once initAppPaste runs", () => withDocument((doc) => {
  doc.body.innerHTML = `<input id="ln-pass">`;
  decorateAppPaste(doc, { pasteIcon: () => "", labelFor: (id) => `Paste into ${id}` });
  const button = doc.querySelector("[data-app-paste]");
  assert.equal(button.disabled, true);
  const stop = initAppPaste({ fill: () => {}, doc });
  appClipboardPut("secret");
  assert.equal(button.disabled, false);
  appClipboardClear();
  assert.equal(button.disabled, true);
  stop();
}));

test("a click on the control fills the field with the held value", () => withDocument((doc) => {
  doc.body.innerHTML = `<input id="ln-pass">`;
  decorateAppPaste(doc, { pasteIcon: () => "", labelFor: (id) => `Paste into ${id}` });
  const calls = [];
  const stop = initAppPaste({ fill: (field) => calls.push(field.id), doc });
  const button = doc.querySelector('[data-app-paste="ln-pass"]');
  click(doc, button);
  assert.deepEqual(calls, []);
  appClipboardPut("secret");
  click(doc, button);
  assert.deepEqual(calls, ["ln-pass"]);
  assert.equal(appClipboardHas(), true, "the app clipboard keeps its value after a paste");
  stop();
}));

test("a click does nothing when the field is missing, disabled or read-only, or the button is disabled", () => withDocument((doc) => {
  doc.body.innerHTML = `<input id="ln-pass"><input id="seed" disabled><input id="key" readonly>`;
  decorateAppPaste(doc, { pasteIcon: () => "", labelFor: (id) => `Paste into ${id}` });
  const calls = [];
  const stop = initAppPaste({ fill: (field) => calls.push(field.id), doc });
  appClipboardPut("secret");
  const missing = doc.querySelector('[data-app-paste="ln-pass"]');
  doc.getElementById("ln-pass").remove();
  click(doc, missing);
  assert.deepEqual(calls, []);
  click(doc, doc.querySelector('[data-app-paste="seed"]'));
  assert.deepEqual(calls, []);
  click(doc, doc.querySelector('[data-app-paste="key"]'));
  assert.deepEqual(calls, []);
  const button = doc.querySelector('[data-app-paste="ln-pass"]');
  button.disabled = true;
  click(doc, button);
  assert.deepEqual(calls, []);
  stop();
}));

test("teardown removes both listeners", () => withDocument((doc) => {
  doc.body.innerHTML = `<input id="ln-pass">`;
  decorateAppPaste(doc, { pasteIcon: () => "", labelFor: (id) => `Paste into ${id}` });
  const stop = initAppPaste({ fill: () => {}, doc });
  assert.equal(doc.listenerCount("hodl:app-clipboard"), 1);
  assert.equal(doc.listenerCount("click"), 1);
  stop();
  assert.equal(doc.listenerCount("hodl:app-clipboard"), 0);
  assert.equal(doc.listenerCount("click"), 0);
}));

test("no code path reads the system clipboard", () => withDocument((doc) => {
  let read = 0;
  const previous = Object.getOwnPropertyDescriptor(globalThis, "navigator");
  Object.defineProperty(globalThis, "navigator", {
    configurable: true,
    value: { clipboard: { readText: () => { read += 1; throw new Error("readText must not be called"); } } },
  });
  try {
    doc.body.innerHTML = `<input id="ln-pass">`;
    decorateAppPaste(doc, { pasteIcon: () => "", labelFor: (id) => `Paste into ${id}` });
    const stop = initAppPaste({ fill: () => {}, doc });
    appClipboardPut("secret");
    click(doc, doc.querySelector('[data-app-paste="ln-pass"]'));
    assert.equal(read, 0);
    assert.equal(doc.listenerCount("paste"), 0);
    stop();
  } finally {
    if (previous) Object.defineProperty(globalThis, "navigator", previous);
    else delete globalThis.navigator;
  }
}));

// The app's own fill (hodlAppPasteInto): passphrase fields that keep their
// text in a vault get the bytes through the vault, never through .value; every
// other field gets the text and the same input event a paste would fire.
const passApi = { calls: [] }, stationFields = Object.create(null);
const recordingApi = (record, { refuse = false } = {}) => ({
  setBytes(bytes, options) {
    record.calls.push({ bytes, seen: Array.from(bytes), options });
    if (refuse) throw new Error("refused");
  },
});
Object.assign(passApi, recordingApi(passApi));
const fill = await loadAppFunctions(["hodlAppPasteInto"], { stubs: { hodlPassphraseVaultField: passApi, hodlStationPassphraseFields: stationFields } });
const fakeField = (id, tagName = "INPUT") => ({ id, tagName, value: "", events: [], focused: false, dispatchEvent(event) { this.events.push(event); return true; }, focus() { this.focused = true; } });
const withInputEvent = async (body) => {
  const saved = Object.getOwnPropertyDescriptor(globalThis, "InputEvent");
  globalThis.InputEvent = class extends Event { constructor(type, init = {}) { super(type, init); this.inputType = init.inputType; } };
  appClipboardClear();
  try { await body(); }
  finally {
    appClipboardClear();
    if (saved) Object.defineProperty(globalThis, "InputEvent", saved); else delete globalThis.InputEvent;
  }
};
const SECRET = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";
const encoded = (text) => Array.from(new TextEncoder().encode(text));

test("a text field gets the value and a paste's input event, and the app clipboard keeps it", () => withInputEvent(() => {
  appClipboardPut(SECRET);
  for (const id of ["bip85-key", "ln-pass"]) {
    const field = fakeField(id);
    fill.hodlAppPasteInto(field);
    assert.equal(field.value, SECRET, id);
    assert.equal(field.events.length, 1, id);
    assert.equal(field.events[0].type, "input");
    assert.equal(field.events[0].inputType, "insertFromPaste");
    assert.equal(field.focused, true);
  }
  assert.equal(appClipboardText(), SECRET);
}));

test("a vault passphrase field gets a copy of the bytes through its vault, with notify, and the copy is zeroed", () => withInputEvent(() => {
  appClipboardPut("correct horse battery staple");
  const station = { calls: [] };
  stationFields["psbt-pass"] = { api: recordingApi(station) };
  try {
    for (const [field, record] of [[fakeField("pass"), passApi], [fakeField("psbt-pass"), station]]) {
      record.calls.length = 0;
      fill.hodlAppPasteInto(field);
      assert.equal(record.calls.length, 1, field.id);
      assert.deepEqual(record.calls[0].seen, encoded("correct horse battery staple"));
      assert.deepEqual(record.calls[0].options, { notify: true });
      assert.ok(record.calls[0].bytes.every((byte) => byte === 0), "the copy handed to the vault is zeroed afterwards");
      assert.equal(field.value, "", "a vault field never gets the text through .value");
      assert.deepEqual(field.events, []);
    }
    assert.equal(appClipboardText(), "correct horse battery staple", "the held value is not the zeroed copy");
  } finally {
    delete stationFields["psbt-pass"];
  }
}));

test("a vault passphrase field without its vault, a refused vault, or an empty app clipboard changes nothing", () => withInputEvent(() => {
  const unbound = fakeField("sp-pass");
  appClipboardPut("passphrase");
  fill.hodlAppPasteInto(unbound);
  assert.equal(unbound.value, "");
  assert.deepEqual(unbound.events, []);
  const refused = { calls: [] };
  stationFields["nonce-pass"] = { api: recordingApi(refused, { refuse: true }) };
  try {
    assert.doesNotThrow(() => fill.hodlAppPasteInto(fakeField("nonce-pass")));
    assert.ok(refused.calls[0].bytes.every((byte) => byte === 0));
  } finally {
    delete stationFields["nonce-pass"];
  }
  appClipboardClear();
  const empty = fakeField("bip85-key");
  fill.hodlAppPasteInto(empty);
  assert.equal(empty.value, "");
  assert.deepEqual(empty.events, []);
}));

test("a single-line field takes line breaks as a typed paste would; a textarea keeps them", () => withInputEvent(() => {
  appClipboardPut("correct\nhorse\r\nbattery\n");
  const line = fakeField("ln-pass");
  fill.hodlAppPasteInto(line);
  assert.equal(line.value, "correct horse battery");
  const area = fakeField("journal-phrase", "TEXTAREA");
  fill.hodlAppPasteInto(area);
  assert.equal(area.value, "correct\nhorse\r\nbattery\n");
  passApi.calls.length = 0;
  fill.hodlAppPasteInto(fakeField("pass"));
  assert.deepEqual(passApi.calls[0].seen, encoded("correct horse battery"));
  assert.ok(passApi.calls[0].bytes.every((byte) => byte === 0));
  assert.equal(appClipboardText(), "correct\nhorse\r\nbattery\n", "the held value is unchanged");
}));
