// The two shipped UI IIFEs with no other Node-level coverage: online.js
// (hosted-preview warning banner — always on and never dismissible) and
// repeat-inputs.js (the hold-to-repeat state machine behind the on-screen
// keyboards). Also covers app.js's recovery-sheet version stamping.
// Run with `npm test`.
import { test, mock } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const rootDir = dirname(fileURLToPath(import.meta.url));
const onlineSource = readFileSync(join(rootDir, "..", "src/js/online.js"), "utf8");
const repeatSource = readFileSync(join(rootDir, "..", "src/js/repeat-inputs.js"), "utf8");
const appSource = readFileSync(join(rootDir, "..", "src/js/app.js"), "utf8");

// Slice one self-contained function out of app.js (the bundle cannot be
// evaluated wholesale in Node).
function appSlice(name) {
  const start = appSource.indexOf(`function ${name}(`);
  assert.ok(start >= 0, name);
  let depth = 0;
  for (let index = appSource.indexOf("{", start); index < appSource.length; index++) {
    if (appSource[index] === "{") depth++;
    else if (appSource[index] === "}" && --depth === 0) return appSource.slice(start, index + 1);
  }
  throw new Error(`Could not extract ${name}`);
}

// ── online.js ────────────────────────────────────────────────────────────────

const VERSION = "9.9.9-test";

function onlineHarness({ hostname, protocol = "https:", search = "", stored = null, storageThrows = false }) {
  const source = onlineSource.split("{{VERSION}}").join(VERSION);
  const calls = [];
  const banner = {
    hidden: true,
    removeAttribute: (name) => calls.push(["removeAttribute", name]),
    setAttribute: () => {},
  };
  const dismiss = {};
  const document = {
    getElementById: (id) => {
      calls.push(["getElementById", id]);
      return id === "online-warning" ? banner : id === "online-warning-dismiss" ? dismiss : null;
    },
  };
  const storage = {
    getItem: (key) => {
      calls.push(["getItem", key]);
      if (storageThrows) throw new Error("denied");
      return stored;
    },
    setItem: (key, value) => {
      calls.push(["setItem", key, value]);
      if (storageThrows) throw new Error("denied");
    },
  };
  const location = { hostname, protocol, search };
  new Function("location", "document", "localStorage", source)(location, document, storage);
  const formatRecoverySheet = new Function(`${appSlice("hodlFormatRecoverySheet").split("{{VERSION}}").join(VERSION)}; return hodlFormatRecoverySheet;`)();
  return { calls, banner, dismiss, formatRecoverySheet };
}

test("the online warning only appears on the hosted site (or an explicit local preview)", () => {
  for (const local of [
    { hostname: "", protocol: "file:", search: "" },
    { hostname: "localhost", protocol: "http:", search: "" },
    { hostname: "example.com", protocol: "https:", search: "" },
  ]) {
    const { calls } = onlineHarness(local);
    assert.equal(calls.length, 0, `no DOM access at all for ${JSON.stringify(local)}`);
  }
  const preview = onlineHarness({ hostname: "localhost", protocol: "http:", search: "?online-preview=1" });
  assert.ok(preview.calls.some(([name, id]) => name === "removeAttribute" && id === "hidden"), "explicit preview reveals the banner");
});

test("the hosted banner always reveals, is never dismissible, and never touches storage", () => {
  for (const hostname of ["entropylab.online", "www.entropylab.online", "ENTROPYLAB.ONLINE"]) {
    const { calls } = onlineHarness({ hostname });
    assert.ok(calls.some(([name, id]) => name === "removeAttribute" && id === "hidden"), hostname);
    assert.equal(calls.filter(([name]) => name === "getItem" || name === "setItem").length, 0, `${hostname}: storage is not consulted`);
    assert.equal(calls.some(([name, id]) => name === "getElementById" && id === "online-warning-dismiss"), false, `${hostname}: no dismiss control is wired`);
  }
  // Prior dismissal state and storage failures are both irrelevant now.
  for (const variant of [{ stored: VERSION }, { stored: "0.0.0" }, { storageThrows: true }]) {
    const { calls } = onlineHarness({ hostname: "entropylab.online", ...variant });
    assert.ok(calls.some(([name, id]) => name === "removeAttribute" && id === "hidden"), JSON.stringify(variant));
  }
});

test("the hosted banner step tolerates a missing banner element", () => {
  const source = onlineSource.split("{{VERSION}}").join(VERSION);
  const location = { hostname: "entropylab.online", protocol: "https:", search: "" };
  assert.doesNotThrow(() => new Function("location", "document", "localStorage", source)(location, { getElementById: () => null }, {}));
});

test("the recovery sheet is stamped with the build version exactly once", () => {
  const { formatRecoverySheet } = onlineHarness({ hostname: "example.com" });
  const sheet = formatRecoverySheet("ENTROPYLAB — RECOVERY SHEET\nComputed locally.");
  assert.equal(sheet, `ENTROPYLAB — RECOVERY SHEET\nENTROPYLAB V${VERSION}\nComputed locally.`);
  const already = `ENTROPYLAB — RECOVERY SHEET\nENTROPYLAB V${VERSION}\nComputed locally.`;
  assert.equal(formatRecoverySheet(already), already, "no double stamping");
});

// ── repeat-inputs.js ─────────────────────────────────────────────────────────

class FakeInputEvent {
  constructor(type, options = {}) {
    this.type = type;
    this.defaultPrevented = false;
    Object.assign(this, options);
  }
  preventDefault() {
    this.defaultPrevented = true;
  }
}

class FakeInput {
  constructor(type = "text") {
    this.type = type;
    this.value = "";
    this.selectionStart = 0;
    this.selectionEnd = 0;
    this.maxLength = -1;
    this.disabled = false;
    this.readOnly = false;
    this.isConnected = true;
    this.events = [];
    this.beforeinputListeners = [];
  }
  setRangeText(text, start, end, selectMode) {
    this.value = this.value.slice(0, start) + text + this.value.slice(end);
    if (selectMode === "end") this.selectionStart = this.selectionEnd = start + text.length;
  }
  dispatchEvent(event) {
    this.events.push(event);
    if (event.type === "beforeinput") for (const listener of this.beforeinputListeners) listener(event);
    return !event.defaultPrevented;
  }
}
class FakeTextArea extends FakeInput {}

function repeatHarness() {
  const listeners = new Map();
  const windowListeners = new Map();
  const document = {
    activeElement: null,
    hidden: false,
    addEventListener: (name, listener) => listeners.set(name, [...(listeners.get(name) || []), listener]),
  };
  const window = { addEventListener: (name, listener) => windowListeners.set(name, [...(windowListeners.get(name) || []), listener]) };
  new Function("document", "window", "HTMLInputElement", "HTMLTextAreaElement", "InputEvent", repeatSource)(
    document,
    window,
    FakeInput,
    FakeTextArea,
    FakeInputEvent,
  );
  const fire = (name, event) => {
    for (const listener of listeners.get(name) || []) listener(event);
  };
  return { document, fire, windowListeners };
}

const keydown = (target, key, extras = {}) => ({ target, key, code: `Key${key.toUpperCase()}`, repeat: false, isComposing: false, defaultPrevented: false, ...extras });

test("a held character key repeats after 350ms and then every 45ms", () => {
  mock.timers.enable({ apis: ["setTimeout", "setInterval"] });
  try {
    const { document, fire } = repeatHarness();
    const input = new FakeInput();
    document.activeElement = input;
    fire("keydown", keydown(input, "a"));
    mock.timers.tick(349);
    assert.equal(input.value, "", "no repeat before the delay elapses");
    mock.timers.tick(1);
    assert.equal(input.value, "a", "the first repeat fires at the delay");
    mock.timers.tick(45);
    assert.equal(input.value, "aa");
    mock.timers.tick(90);
    assert.equal(input.value, "aaaa");
    fire("keyup", { code: "KeyA", key: "a" });
    mock.timers.tick(500);
    assert.equal(input.value, "aaaa", "keyup stops the repeat");
  } finally {
    mock.timers.reset();
  }
});

test("native key repeats are suppressed and folded into the held state", () => {
  mock.timers.enable({ apis: ["setTimeout", "setInterval"] });
  try {
    const { document, fire } = repeatHarness();
    const input = new FakeInput();
    document.activeElement = input;
    fire("keydown", keydown(input, "a"));
    const repeated = keydown(input, "a", { repeat: true });
    repeated.preventDefault = () => (repeated.wasPrevented = true);
    fire("keydown", repeated);
    assert.equal(repeated.wasPrevented, true, "the native repeat is canceled in favor of ours");
    // The first native repeat hands the cadence over: the delay timer is
    // canceled, one repeat fires immediately, and the 45ms interval takes over.
    assert.equal(input.value, "a");
    mock.timers.tick(45);
    assert.equal(input.value, "aa");
    // A native repeat from a different key is ignored while ours is held.
    const other = keydown(input, "b", { repeat: true });
    other.preventDefault = () => (other.wasPrevented = true);
    fire("keydown", other);
    assert.equal(other.wasPrevented, undefined, "an unrelated repeat is left alone");
    mock.timers.tick(45);
    assert.equal(input.value, "aaa", "and never inserts its character");
    assert.ok(!input.value.includes("b"));
  } finally {
    mock.timers.reset();
  }
});

test("non-text controls, modifiers, and composition never arm the repeater", () => {
  mock.timers.enable({ apis: ["setTimeout", "setInterval"] });
  try {
    const { document, fire } = repeatHarness();
    const numberInput = new FakeInput("number");
    const textInput = new FakeInput();
    document.activeElement = textInput;
    fire("keydown", keydown(numberInput, "5"));
    fire("keydown", keydown(textInput, "a", { metaKey: true }));
    fire("keydown", keydown(textInput, "a", { ctrlKey: true }));
    fire("keydown", keydown(textInput, "a", { altKey: true }));
    fire("keydown", keydown(textInput, "a", { isComposing: true }));
    fire("keydown", keydown(textInput, "a", { defaultPrevented: true }));
    fire("keydown", keydown(textInput, "Enter"), "non-character keys are out of scope");
    mock.timers.tick(1000);
    assert.equal(numberInput.value, "");
    assert.equal(textInput.value, "");
    // A textarea is repeatable.
    const area = new FakeTextArea();
    document.activeElement = area;
    fire("keydown", keydown(area, "b"));
    mock.timers.tick(350);
    assert.equal(area.value, "b");
  } finally {
    mock.timers.reset();
  }
});

test("repeat insertion respects maxLength, selection replacement, and canceled beforeinput", () => {
  mock.timers.enable({ apis: ["setTimeout", "setInterval"] });
  try {
    const { document, fire } = repeatHarness();
    const input = new FakeInput();
    document.activeElement = input;
    input.maxLength = 3;
    input.value = "ab";
    input.selectionStart = input.selectionEnd = 2;
    fire("keydown", keydown(input, "c"));
    mock.timers.tick(350);
    assert.equal(input.value, "abc", "one character of headroom");
    mock.timers.tick(45);
    assert.equal(input.value, "abc", "at maxLength the insertion is empty and stops");
    // A selection is replaced, freeing headroom.
    input.selectionStart = 0;
    input.selectionEnd = 2;
    input.value = "ab";
    const selected = new FakeInput();
    document.activeElement = selected;
    selected.maxLength = 2;
    selected.value = "ab";
    selected.selectionStart = 0;
    selected.selectionEnd = 2;
    fire("keydown", keydown(selected, "c"));
    mock.timers.tick(350);
    assert.equal(selected.value, "c", "replacing a two-character selection with one character");
    // A canceled beforeinput blocks the insertion entirely.
    const guarded = new FakeInput();
    document.activeElement = guarded;
    guarded.beforeinputListeners.push((event) => event.preventDefault());
    fire("keydown", keydown(guarded, "x"));
    mock.timers.tick(400);
    assert.equal(guarded.value, "");
    assert.equal(guarded.events.filter((event) => event.type === "input").length, 0, "no input event without insertion");
  } finally {
    mock.timers.reset();
  }
});

test("focus loss, window blur, and tab hides all stop the repeat", () => {
  mock.timers.enable({ apis: ["setTimeout", "setInterval"] });
  try {
    for (const stop of ["focusout", "blur", "visibilitychange"]) {
      const { document, fire, windowListeners } = repeatHarness();
      const input = new FakeInput();
      document.activeElement = input;
      fire("keydown", keydown(input, "z"));
      mock.timers.tick(350);
      assert.equal(input.value, "z", `fixture: repeating began (${stop})`);
      if (stop === "focusout") fire("focusout", { target: input });
      else if (stop === "blur") for (const listener of windowListeners.get("blur") || []) listener();
      else {
        document.hidden = true;
        fire("visibilitychange", {});
      }
      mock.timers.tick(500);
      assert.equal(input.value, "z", `${stop} stopped the repeat`);
    }
  } finally {
    mock.timers.reset();
  }
});
