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

test("the online warning appears on any network-served origin, not just the canonical domain", () => {
  // Downloaded (file://) and loopback copies are local: no banner, no DOM access.
  for (const local of [
    { hostname: "", protocol: "file:", search: "" },
    { hostname: "localhost", protocol: "http:", search: "" },
    { hostname: "127.0.0.1", protocol: "http:", search: "" },
  ]) {
    const { calls } = onlineHarness(local);
    assert.equal(calls.length, 0, `no DOM access at all for ${JSON.stringify(local)}`);
  }
  // Any non-loopback http(s) origin is "online": the canonical domain, a
  // self-hosted mirror, and a LAN IP must all reveal the banner.
  for (const served of [
    { hostname: "example.com", protocol: "https:", search: "" },
    { hostname: "mirror.example.org", protocol: "http:", search: "" },
    { hostname: "192.168.1.50", protocol: "http:", search: "" },
  ]) {
    const { calls } = onlineHarness(served);
    assert.ok(
      calls.some(([name, id]) => name === "removeAttribute" && id === "hidden"),
      `network-served origin reveals the banner for ${JSON.stringify(served)}`,
    );
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

test("switching away from Vanity leaves an active grind running", () => {
  let cancelled = 0;
  const tabs = { querySelectorAll: () => [], children: [] };
  const element = () => ({ hidden: false });
  const makeWorkspace = new Function(
    "window", "document", "hodlElement", "hodlVanityCancel", "requestAnimationFrame", "cancelAnimationFrame",
    "hodlSyncPsbtTool", "hodlSyncJournalTool", "hodlJournalLog", "hodlOutEl", "hodlQueueSegmentedControlSync", "hodlSyncPrivacyTool",
    `let hodlWorkspace = "vanity";
     let hodlWorkspaceScrollFrame = 0;
     let hodlWalletResult = null;
     let hodlRevealPrivate = false;
     let hodlJournalKeyDerivation = null;
     ${appSlice("hodlShowWorkspace")}
     return (id) => hodlShowWorkspace(id);`,
  );
  const switchWorkspace = makeWorkspace(
    { scrollX: 0, scrollY: 0, scrollTo: () => {} },
    { getElementById: element },
    (selector) => selector === "#workspace-tabs" ? tabs : element(),
    () => cancelled++,
    (callback) => { callback(); return 1; },
    () => {},
    () => {},
    () => {},
    () => {},
    { innerHTML: "result" },
    () => {},
    () => {},
  );

  switchWorkspace("ln");
  assert.equal(cancelled, 0, "a workspace navigation must not cancel the active grinder");
});

test("changes that invalidate a vanity run still cancel it", () => {
  let cancelled = 0;
  const api = new Function(
    "hodlVanityCancel", "document", "hodlApplyFilteredInput", "hodlFilterVanityPrefix",
    "hodlVanityClearResults", "hodlVanitySyncScriptNote", "hodlVanityEstimate", "hodlVanitySyncMethod",
    `${appSlice("hodlVanityScriptChanged")}
     ${appSlice("hodlVanityMethodChanged")}
     return { hodlVanityScriptChanged, hodlVanityMethodChanged };`,
  )(
    () => cancelled++,
    { getElementById: () => null },
    () => {},
    (value) => value,
    () => {},
    () => {},
    () => {},
    () => {},
  );

  api.hodlVanityScriptChanged();
  api.hodlVanityMethodChanged();
  assert.equal(cancelled, 2, "script and method changes must each cancel the stale run");
});

test("a language switch says the Vanity status and error again in the new language", () => {
  // A filled-in string is not a catalog key, so the static sweep cannot carry
  // it across a switch: the station keeps its status and error lines as notes
  // and renders them, and the rest of its text, again.
  let locale = "en";
  const elements = { "vanity-status": { textContent: "" }, "vanity-error": { textContent: "" } }, rendered = [];
  const api = new Function(
    "document", "hodlTText", "hodlVanitySyncScriptNote", "hodlVanitySyncSource", "hodlRenderVanityOut",
    `let hodlVanityStatusNote = null, hodlVanityErrorNote = null;
     ${appSlice("hodlNote")}
     ${appSlice("hodlFormatNote")}
     ${appSlice("hodlVanitySetStatus")}
     ${appSlice("hodlSetVanityError")}
     ${appSlice("hodlRefreshVanityLocale")}
     return { hodlNote, hodlVanitySetStatus, hodlSetVanityError, hodlRefreshVanityLocale };`,
  )(
    { getElementById: (id) => elements[id] ?? null },
    (key, vars) => `<${locale}>` + key.replace(/\{(\w+)\}/g, (whole, name) => (vars?.[name] == null ? whole : String(vars[name]))),
    () => rendered.push("prefix help"),
    () => rendered.push("source panel"),
    () => rendered.push("matches"),
  );
  const note = api.hodlNote, status = () => elements["vanity-status"].textContent, error = () => elements["vanity-error"].textContent;

  api.hodlVanitySetStatus(note("{outcome}: {done} candidates, {found} matches. Next counter: {next}.", { outcome: note("Range complete"), done: "300", found: 8, next: "300" }));
  api.hodlSetVanityError(note("Key {key} is no longer in Key Station, so there is nothing to update.", { key: "5436d724" }));
  assert.equal(status(), "<en><en>Range complete: 300 candidates, 8 matches. Next counter: 300.");
  assert.equal(error(), "<en>Key 5436d724 is no longer in Key Station, so there is nothing to update.");

  locale = "de";
  api.hodlRefreshVanityLocale();
  assert.deepEqual(rendered, ["prefix help", "source panel", "matches"], "the station's other text renders again too");
  assert.equal(status(), "<de><de>Range complete: 300 candidates, 8 matches. Next counter: 300.", "the status, and the outcome inside it, follow the switch");
  assert.equal(error(), "<de>Key 5436d724 is no longer in Key Station, so there is nothing to update.", "the error follows the switch");

  // A worker's own message has no catalog key and stays as it was; a cleared
  // error stays cleared.
  api.hodlSetVanityError({ raw: "worker failed" });
  api.hodlRefreshVanityLocale();
  assert.equal(error(), "worker failed");
  api.hodlSetVanityError(null);
  api.hodlRefreshVanityLocale();
  assert.equal(error(), "", "a cleared error must not come back on a language switch");

  // hodlApplyLocale runs the refresh, and redraws the station key chips, whose
  // labels are filled in too.
  assert.match(appSlice("hodlApplyLocale"), /hodlRefreshPsbtLocale\(\);\s*hodlRefreshVanityLocale\(\);\s*hodlRefreshStationKeyPickers\(\);/);
  // The match table's hidden action header is escaped once, from the text
  // catalog: French "État de l'enfant" must not reach a screen reader as "&#39;".
  assert.match(appSlice("hodlRenderVanityOut"), /let actionHeader = run\.sourceKind === "bip85" \? hodlTText\("Child status"\) : hodlTText\("Update Key"\);/);
});

test("a language switch paints filled-in Key Station text again", () => {
  // "5436d724, selected. Activate or press F2 to rename.", "Seed phrase:
  // Direct word entry" and "Purpose index · Unhardened · …" are no catalog
  // keys, so the static sweep cannot carry them across a switch: the station
  // tabs, the key summary and the hardening notes render again. The notes go
  // before the estimate and the multisig account, which overwrite some of them.
  const apply = appSlice("hodlApplyLocale");
  assert.match(apply, /hodlRenderKeyTabs\(\);\s*hodlRenderMsigTabs\(\);\s*hodlRenderStationTabs\(hodlBip85Tabs\);\s*hodlRenderStationTabs\(hodlSpTabs\);\s*hodlPaintKeySummary\(\);/);
  assert.match(apply, /hodlUpdateHardeningHelp\(\);\s*hodlUpdateHardeningHelp\("msig-"\);\s*hodlUpdateAddressEstimate\(\);[\s\S]*hodlUpdateMsigAccount\(\);/);
});

test("the multisig account note, placeholder and warning follow the page language", () => {
  // hodlApplyLocale runs this after the hardening notes, so it has the last
  // word on #msig-account-help; whatever it writes must be translated, and
  // the mismatch warning is a note it formats (assigned as is, it read
  // "[object Object]").
  let locale = "en", summary, kind = "p2wsh", purpose = 48;
  const element = () => ({ value: "", placeholder: "", textContent: "", hidden: true, dataset: {} });
  const elements = { "msig-account": element(), "msig-account-help": element(), "msig-account-warning": element() };
  const update = new Function(
    "document", "hodlTText", "hodlScriptKind", "hodlReadHardening", "hodlReadMsigPurpose", "hodlStandardMsigPurpose", "hodlSyncDerivationPrime", "hodlReadMsigXpubs", "hodlSummarizeMultisigAccounts",
    `${appSlice("hodlNote")}
     ${appSlice("hodlFormatNote")}
     ${appSlice("hodlMultisigAccountWarning")}
     ${appSlice("hodlUpdateMsigAccount")}
     return hodlUpdateMsigAccount;`,
  )(
    { getElementById: (id) => elements[id] ?? null },
    (key, vars) => `<${locale}>` + key.replace(/\{(\w+)\}/g, (whole, name) => (vars?.[name] == null ? whole : String(vars[name]))),
    () => kind, () => ({ account: true }), () => purpose, () => purpose, () => {}, () => [], () => summary,
  );
  const help = () => elements["msig-account-help"].textContent, warning = elements["msig-account-warning"], field = elements["msig-account"];

  summary = { mixed: true, consistent: false, accounts: [0, 1], account: null };
  update();
  assert.equal(help(), "<en>Account index · <en>Hardened · Co-signer key origins use different account numbers.");
  assert.equal(field.placeholder, "<en>Derived from keys");
  assert.equal(warning.textContent, "<en>Co-signer account numbers do not match (0, 1). The Account field is shown as Mixed.");
  assert.equal(warning.hidden, false);
  locale = "de";
  update();
  assert.equal(help(), "<de>Account index · <de>Hardened · Co-signer key origins use different account numbers.", "the note follows a switch");
  assert.equal(warning.textContent, "<de>Co-signer account numbers do not match (0, 1). The Account field is shown as Mixed.", "the warning follows a switch");

  summary = { mixed: false, consistent: true, accounts: [3], account: 3 };
  update();
  assert.equal(help(), "<de>Account index · <de>Hardened · Derived from the co-signer account paths.");
  assert.equal(warning.textContent, "");
  assert.equal(warning.hidden, true);

  kind = "p2sh";
  purpose = 45;
  update();
  assert.equal(field.placeholder, "<de>Not applicable");
  assert.equal(help(), "<de>BIP45 purpose keys do not contain an account number.");
});

test("Silent Payment custom characters constrain only the first free character", () => {
  const filter = new Function(`${appSlice("hodlFilterVanityPrefix")}; return hodlFilterVanityPrefix;`)();
  const silentPayment = { prefix: "sp1qq", bech32: true, firstFree: "gf2tvdw0" };
  const otherBech32 = { prefix: "bc1q", bech32: true };
  const base58 = { prefix: "1", bech32: false };

  assert.equal(filter("SP1QQA GQ1Z", silentPayment), "gqz", "discard disallowed first characters and non-bech32 characters, then accept ordinary bech32 characters");
  assert.equal(filter("qaz", silentPayment), "", "a later character cannot become the first unless it is in the eight-character set");
  assert.equal(filter("tqz", silentPayment), "tqz", "the remaining characters use the full bech32 alphabet");
  assert.equal(filter("qaz", otherBech32), "qaz", "other bech32 address types still allow any bech32 character first");
  assert.equal(filter("1Love", base58), "Love", "base58 filtering keeps its existing rules");
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

// The on-screen delete button has its own pointer-driven hold state machine.
function keyboardDeleteHarness() {
  const input = { value: "abandon" };
  const listeners = new Map();
  const button = {
    disabled: false,
    addEventListener: (type, listener) => listeners.set(type, listener),
  };
  const bind = new Function(`${appSlice("hodlBindSeedKeyboardDelete")}; return hodlBindSeedKeyboardDelete;`)();
  bind(() => input, button, (field, text, deleting) => {
    assert.equal(deleting, true);
    field.value = field.value.slice(0, -1);
    button.disabled = !field.value;
  });
  const fire = (type) => {
    const event = { button: 0, pointerId: 17, defaultPrevented: false, preventDefault() { this.defaultPrevented = true; } };
    listeners.get(type)(event);
    return event;
  };
  return { input, fire };
}

test("holding keyboard delete removes once after the delay, then repeats until release", (t) => {
  t.mock.timers.enable({ apis: ["setTimeout", "setInterval"] });
  const { input, fire } = keyboardDeleteHarness();
  fire("pointerdown");
  t.mock.timers.tick(419);
  assert.equal(input.value, "abandon", "the hold delay has not elapsed");
  t.mock.timers.tick(1);
  assert.equal(input.value, "abando", "the initial delayed deletion is not a repeat");
  t.mock.timers.tick(69);
  assert.equal(input.value, "aband", "the interval deletes another character");
  fire("pointerup");
  assert.equal(fire("click").defaultPrevented, true, "the release click is suppressed");
  t.mock.timers.tick(1000);
  assert.equal(input.value, "aband", "release cancels the repeat timer");
  fire("click");
  assert.equal(input.value, "aban", "a subsequent ordinary click still deletes once");
});

test("releasing or cancelling keyboard delete before the delay prevents a late deletion", (t) => {
  t.mock.timers.enable({ apis: ["setTimeout", "setInterval"] });
  for (const stop of ["pointerup", "pointercancel", "pointerleave", "lostpointercapture"]) {
    const { input, fire } = keyboardDeleteHarness();
    fire("pointerdown");
    t.mock.timers.tick(100);
    fire(stop);
    t.mock.timers.tick(1000);
    assert.equal(input.value, "abandon", `${stop} cancels the pending hold timer`);
  }
});

test("a language switch paints the co-signer labels, the BIP-85 child and the Silent Payments results again", () => {
  // "Co-signer 2", "Move co-signer 2 up to position 1", the BIP-85 child's
  // labels and every Silent Payments line fill values into their text, so
  // the static sweep cannot carry them across a switch. A repaint redraws
  // what each one kept: it never derives a key or scans again.
  const apply = appSlice("hodlApplyLocale");
  assert.match(apply, /hodlReindexMsigKeys\(\);\s*hodlRenderBip85Out\(\);\s*hodlRefreshSpLocale\(\);/);
  const sp = appSlice("hodlRefreshSpLocale");
  assert.match(sp, /hodlPaintSpSession\(\)/);
  assert.match(sp, /if \(hodlSpSendLast\) hodlPaintSpSend\(\);\s*else if \(hodlSpVerifyMatches\) hodlPaintSpVerify\(\);/);
  assert.doesNotMatch(sp, /hodlRenderSpSend|hodlRenderSpVerify|hodlSpDeriveVinKeys|hodlSpDeriveSessionKeys/, "a switch repaints; it never derives or scans");
});
