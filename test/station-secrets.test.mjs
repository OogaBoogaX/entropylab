// #546 B3: each station drops every secret it holds, and never hands one on
// once it is gone.
//
// Security contract: a station never uses a key the Key Station has dropped
// (a wiped key's bytes are zeroed, so using it silently means the all-zero
// wallet, whose keys are public); re-rendering the Key Station form leaves no
// listener behind that keeps the old form and the key it showed; a BIP-85
// child holds its secret only as bytes, building the text only to show, copy
// or use it; and a finished vanity grind keeps no copy of the passphrase.
// What each station shows, copies and derives does not change, except that a
// hidden BIP-39 child shows its word count and no longer its length.
//
// Expected values: the published BIP39 vectors (trezor/python-mnemonic), the
// BIP-84 vector wallet (its words are the all-zero entropy's, the words a
// zeroed wallet reads back as), @scure/bip32 and @scure/bip39 as reference
// libraries, and the published BIP-85 children (bitcoin/bips bip-0085).
// Run with `npm test`.
import { test } from "node:test";
import assert from "node:assert/strict";
import { HDKey as ScureHDKey } from "@scure/bip32";
import { entropyToMnemonic, mnemonicToSeedSync } from "@scure/bip39";
import { wordlist as bip39English } from "@scure/bip39/wordlists/english.js";
import { hmac } from "@noble/hashes/hmac.js";
import { sha256, sha512 } from "@noble/hashes/sha2.js";
import { HDKey as AppHDKey } from "../src/js/hdkey.js";
import * as bip85 from "../src/js/bip85.js";
import { createHash, randomBytes } from "node:crypto";
import v8 from "node:v8";
import { readFileSync } from "node:fs";
import { VanityGrinder } from "../src/js/vanity.js";
import { loadAppFunctions } from "./app-slice-harness.mjs";
import { MiniDocument, MiniElement, MiniNodeFilter } from "./mini-dom.mjs";
const enhancedInputs = readFileSync(new URL("../src/js/enhanced-inputs.js", import.meta.url), "utf8");

const inert = new Proxy(function () {}, { get: (target, key) => key === Symbol.toPrimitive ? () => "" : key === "then" ? undefined : inert, apply: () => inert, construct: () => inert });
const load = async (names, options = {}) => {
  Object.assign(globalThis, { __ENTROPYLAB_TEST_HOOKS__: false, document: inert, window: inert });
  try {
    return await loadAppFunctions(names, options);
  } finally {
    delete globalThis.document;
    delete globalThis.window;
  }
};
const page = () => {
  globalThis.document = new MiniDocument();
  globalThis.NodeFilter = MiniNodeFilter;
  return globalThis.document;
};
const leave = () => {
  delete globalThis.NodeFilter;
  delete globalThis.document;
};
const fingerprintOf = (words, pass = "") => ScureHDKey.fromMasterSeed(mnemonicToSeedSync(words, pass)).fingerprint.toString(16).padStart(8, "0");

// ---- A dropped key is never handed to a station ----------------------------

// A published BIP39 vector (trezor/python-mnemonic) with its passphrase, and
// the words of the all-zero entropy: what a zeroed wallet reads back as.
const WORDS = "legal winner thank year wave sausage worth useful legal winner thank yellow";
const PASS = "TREZOR";
const ZEROED_WORDS = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const refreshed = [];
const pickers = await load(["hodlFillStationKeyPicker", "hodlSessionHdRootKeys", "hodlMnemonicWalletWithProgress", "hodlWipeWalletKeys", "hodlResultMnemonic", "hodlNewKeyState"], {
  stubs: {
    hodlSelectedScriptType: () => "bip84",
    hodlLiveWalletResults: () => new Set(),
    hodlKeyManagerPending: [],
    hodlAppendSessionKeyLifehashes: () => {},
    hodlRefreshStationKeyPickers: () => refreshed.push("stations"),
  },
  settable: ["hodlKeys", "hodlBip85Children"],
});
const keyboards = await load(["hodlBindSeedKeyboard", "hodlBindPassphraseKeyboard", "hodlSeedKeyboardMarkup", "hodlSeedKeyboardToggleMarkup", "hodlPrivateKeyKeyboardMarkup", "hodlPrivateKeyKeyboardToggleMarkup", "hodlPassphraseKeyboardMarkup", "hodlPassphraseKeyboardToggleMarkup"]);
// The release is new: loaded on its own, so its absence fails only its test.
const release = await load(["hodlReleaseFormListeners", "hodlBindSeedKeyboard", "hodlBindPassphraseKeyboard", "hodlSeedKeyboardMarkup", "hodlSeedKeyboardToggleMarkup", "hodlPrivateKeyKeyboardMarkup", "hodlPrivateKeyKeyboardToggleMarkup", "hodlPassphraseKeyboardMarkup", "hodlPassphraseKeyboardToggleMarkup"]).catch(() => null);
// The key fields, with what their handlers update stubbed; new like the release.
const keyFields = await load(["hodlBindKeyFields", "hodlReleaseFormListeners"], {
  stubs: Object.fromEntries(["hodlRenderPrivateKeyInputState","hodlUpdatePrivateKeyKeyboardKeys","hodlSyncBrainOutput","hodlUpdateKeyModeControls","hodlRenderPassphraseKeyboard","hodlUpdateDerivationPathPreview","hodlSyncKeyClearButton","hodlSyncDeriveButton","hodlInvalidateLiveKeyResult","hodlRetractBrainWalletResults","hodlSyncDiceHighlight"].map((name) => [name, () => {}])),
  settable: ["hodlKeys", "hodlActiveKey"],
}).catch(() => null);
const vanityStation = await load(["hodlVanityClearResults"], {
  stubs: { hodlRenderVanityOut: () => {}, hodlVanitySetStatus: () => {}, hodlVanitySyncControls: () => {} },
  settable: ["hodlVanityGrinder", "hodlVanityRunning"],
});
const vanityRender = await load(["hodlRenderVanityOut"], {
  stubs: { hodlFillKeyTabLifehash: () => {} },
  settable: ["hodlVanityMatches", "hodlVanityRun", "hodlVanityReveal", "hodlVanityFound"],
});
const station = await load(["hodlRenderLastWordPicker", "hodlBip85SessionKeyState", "hodlResultMnemonic", "hodlSeedSessionRoot", "hodlResultRootXprv", "hodlResultRootNode", "hodlSinglePrivateKey", "hodlBip85ChildFingerprint", "hodlRenderBip85Out", "hodlBip85WipeMem", "hodlSeedPhraseField"], {
  stubs: { hodlFillKeyTabLifehash: () => {} },
  settable: ["hodlBip85Children", "hodlActiveBip85", "hodlBip85Reveal"],
});
const tracker = { setTotal() {}, step() { return null; } };
const keyWallet = () => pickers.hodlMnemonicWalletWithProgress(WORDS, PASS, "mainnet", 2, undefined, 0, 0, tracker, 84, 0);
const keyState = (result) => ({ ...pickers.hodlNewKeyState("Key 1", 1, 1), result, fields: { seed: WORDS, pass: PASS } });
const labState = { isLab: true, id: 0, name: "Key Station", fields: {} };

test("the fixtures: a zeroed wallet reads back as the all-zero entropy's words", async () => {
  const result = await keyWallet();
  assert.equal(pickers.hodlResultMnemonic(result), WORDS);
  pickers.hodlWipeWalletKeys(result);
  assert.equal(pickers.hodlResultMnemonic(result), ZEROED_WORDS);
  assert.notEqual(fingerprintOf(ZEROED_WORDS), fingerprintOf(WORDS, PASS));
});

// [how the Key Station drops the key, the key state it leaves under the same id]
const DROPS = [
  ["Wipe, which leaves a blank key", () => pickers.hodlNewKeyState("Key 1", 1, 1)],
  ["deleting the key", null],
];
for (const [how, replacement] of DROPS) {
  test(`a chip drawn before ${how} hands no station the dropped key`, async () => {
    const document = page();
    try {
      document.body.innerHTML = '<div id="sp-session-keys"></div>';
      const result = await keyWallet(), picked = [];
      pickers.__set.hodlBip85Children([]);
      pickers.__set.hodlKeys([labState, keyState(result)]);
      pickers.hodlFillStationKeyPicker("sp-session-keys", "", (state) => picked.push(state));
      const chip = document.querySelector("#sp-session-keys [data-key-id]");
      assert.ok(chip, "the key is offered");
      // The Key Station drops the key: the state goes, and its bytes are zeroed.
      pickers.__set.hodlKeys(replacement ? [labState, replacement()] : [labState]);
      pickers.hodlWipeWalletKeys(result);
      chip.click();
      assert.deepEqual(picked.map((state) => pickers.hodlResultMnemonic(state.result)), [], "a station was handed the zeroed wallet");
    } finally {
      leave();
    }
  });
}

test("a chip hands a station the key as it is now", async () => {
  const document = page();
  try {
    document.body.innerHTML = '<div id="sp-session-keys"></div>';
    const first = await keyWallet(), picked = [];
    pickers.__set.hodlBip85Children([]);
    pickers.__set.hodlKeys([labState, keyState(first)]);
    pickers.hodlFillStationKeyPicker("sp-session-keys", "", (state) => picked.push(state));
    // Re-derived under the same id: the chip picks the new wallet.
    const second = await keyWallet(), current = keyState(second);
    pickers.__set.hodlKeys([labState, current]);
    document.querySelector("#sp-session-keys [data-key-id]").click();
    assert.equal(picked.length, 1);
    assert.equal(picked[0], current);
    assert.equal(pickers.hodlResultMnemonic(picked[0].result), WORDS);
  } finally {
    leave();
  }
});

// ---- Re-rendering the Key Station form leaves nothing behind ---------------

// The on-screen keyboards listen outside themselves: on the document, for focus
// moving between their fields, and on controls that outlive the form (the
// network select, the passphrase field). Every form render builds a new
// keyboard; a listener the next render cannot find stays for the rest of the
// session, and holds its form's fields (typed seed words or a private key) and
// the key state that form showed. As in the page, the controls outside the
// form stay while the form is replaced (#621 review).
const ACTIVITY = ["focusin", "input", "click", "keyup", "select"];
const PERSISTENT = [["network", ["change"]], ["pass", ["input", "focus", "blur", "click", "keyup", "select"]]];
const PAGE = '<div id="form"></div><input id="network" value="0"><input id="pass">';
const FORM_MARKUP = {
  seed: (api) => `${api.hodlSeedKeyboardToggleMarkup()}<textarea id="seed"></textarea>${api.hodlSeedKeyboardMarkup()}`,
  key: (api) => `${api.hodlPrivateKeyKeyboardToggleMarkup()}<textarea id="key"></textarea><div id="private-keyboard-host">${api.hodlPrivateKeyKeyboardMarkup()}</div>`,
  passphrase: (api) => `${api.hodlPassphraseKeyboardToggleMarkup()}<div id="passphrase-keyboard-host">${api.hodlPassphraseKeyboardMarkup()}</div>`,
};
const FORM_BIND = {
  seed: (api, document) => api.hodlBindSeedKeyboard(document.getElementById("seed"), 12),
  key: (api) => api.hodlBindPassphraseKeyboard("key", "private-keyboard-toggle", "private key", "private-keyboard"),
  passphrase: (api) => api.hodlBindPassphraseKeyboard("pass", "passphrase-keyboard-toggle", "passphrase", "passphrase-keyboard"),
};
const renderForm = (api, document, kind) => {
  document.getElementById("form").innerHTML = FORM_MARKUP[kind](api);
  FORM_BIND[kind](api, document);
};
// Every listener on the document and on the controls outside the form.
const outsideListeners = (document) => [
  ...ACTIVITY.map((type) => `document ${type}: ${document.listenerCount(type)}`),
  ...PERSISTENT.flatMap(([id, types]) => types.map((type) => `#${id} ${type}: ${document.getElementById(id).listenerCount(type)}`)),
];
const listening = (document) => outsideListeners(document).filter((line) => !line.endsWith(": 0"));

for (const [form, kind] of [["the seed phrase form", "seed"], ["the private key form", "key"], ["the passphrase keyboard", "passphrase"]]) {
  test(`rendering ${form} three times leaves the listeners of one render`, () => {
    const document = page();
    try {
      document.body.innerHTML = PAGE;
      renderForm(keyboards, document, kind);
      const once = outsideListeners(document);
      assert.ok(listening(document).length > 0, "the keyboard listens outside the form");
      renderForm(keyboards, document, kind);
      renderForm(keyboards, document, kind);
      assert.deepEqual(outsideListeners(document), once);
    } finally {
      leave();
    }
  });
}

// A new form lets go of the old form's keyboards: the Key Station form render
// releases them before it builds the next form, which may have no keyboard.
test("releasing the keyboards leaves nothing listening outside the form", () => {
  assert.equal(typeof release?.hodlReleaseFormListeners, "function", "the page has no way to release the keyboards");
  const document = page();
  try {
    document.body.innerHTML = PAGE;
    document.getElementById("form").innerHTML = FORM_MARKUP.seed(release) + FORM_MARKUP.key(release) + FORM_MARKUP.passphrase(release);
    for (const kind of ["seed", "key", "passphrase"]) FORM_BIND[kind](release, document);
    assert.ok(listening(document).length > 0, "the keyboards listen");
    release.hodlReleaseFormListeners();
    assert.deepEqual(listening(document), []);
  } finally {
    leave();
  }
});
test("the Key Station form render releases the keyboards before it builds the next form", () => {
  const source = readFileSync(new URL("../src/js/app.js", import.meta.url), "utf8");
  const render = source.slice(source.indexOf("function hodlRenderKeyForm() {"), source.indexOf("hodlFormEl.innerHTML", source.indexOf("function hodlRenderKeyForm() {")));
  assert.ok(render.includes("hodlReleaseFormListeners();"), "the form render does not release the old form's keyboards first");
});

// The review's case (#621): private key forms rendered, typed into and
// discarded, the network select kept. Only the digests of what was typed leave
// the frame that types it.
function typeAndDiscardPrivateKeys(document) {
  const typed = [];
  for (let render = 0; render < 3; render++) {
    renderForm(release, document, "key");
    const key = `L${randomBytes(24).toString("hex")}`;
    document.getElementById("key").value = key;
    typed.push({ digest: digestOf(key), length: key.length });
  }
  // The next form render: the old keyboards go, then the form.
  release.hodlReleaseFormListeners();
  document.getElementById("form").innerHTML = "";
  return typed;
}
test("a discarded private key form leaves no copy of the key typed into it", async () => {
  assert.equal(typeof release?.hodlReleaseFormListeners, "function", "the page has no way to release the keyboards");
  const document = page();
  try {
    document.body.innerHTML = PAGE;
    const typed = typeAndDiscardPrivateKeys(document);
    const held = [];
    for (const { digest, length } of typed) held.push(await heldCopies(digest, length));
    assert.deepEqual(held, [0, 0, 0], "a discarded private key is still held");
  } finally {
    leave();
  }
});

// The key fields listen on the network select as well, and hold the private
// keys typed into the form (#621 review): three Private key forms, each showing
// a key, then the key dropped (as a Wipe or a delete does) and the form
// replaced. Only the digests of the keys leave the frame that makes them.
function typeAndDiscardKeyFields(document) {
  const typed = [];
  for (let render = 0; render < 3; render++) {
    document.getElementById("form").innerHTML = '<input type="radio" name="kk" value="hex-key" checked><textarea id="key"></textarea>';
    const key = randomBytes(32).toString("hex");
    keyFields.__set.hodlKeys([{ isLab: true, id: 0, fields: { privateKeys: { "hex-key": key }, keyKind: "hex-key" } }]);
    keyFields.__set.hodlActiveKey(0);
    keyFields.hodlBindKeyFields();
    typed.push({ digest: digestOf(key), length: key.length });
  }
  // Each bind replaced the last: one listener on the network select.
  typed.networkListeners = document.getElementById("network").listenerCount("change");
  keyFields.__set.hodlKeys([]);
  keyFields.hodlReleaseFormListeners();
  document.getElementById("form").innerHTML = "";
  return typed;
}
test("a discarded private key form keeps no copy of the key its fields showed", async () => {
  assert.equal(typeof keyFields?.hodlReleaseFormListeners, "function", "the page has no way to release the form listeners");
  const document = page();
  try {
    document.body.innerHTML = PAGE;
    const typed = typeAndDiscardKeyFields(document);
    assert.equal(typed.networkListeners, 1, "each bind added a network listener");
    assert.equal(document.getElementById("network").listenerCount("change"), 0, "the release left a network listener");
    const held = [];
    for (const { digest, length } of typed) held.push(await heldCopies(digest, length));
    assert.deepEqual(held, [0, 0, 0], "a discarded private key is still held");
  } finally {
    leave();
  }
});

// ---- A BIP-85 child holds its secret only as bytes -------------------------

// The published test parent and its children (bitcoin/bips bip-0085, the
// values test/bip85.test.mjs pins): [name, spec, secret, entropy hex].
const BIP85_PARENT = "xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb";
const BIP85_CHILDREN = [
  ["BIP-39, 12 words", { app: "bip39", words: 12 }, "girl mad pet galaxy egg matter matrix prison refuse sense ordinary nose", "6250b68daf746d12a24d58b4787a714b"],
  ["BIP-39, 18 words", { app: "bip39", words: 18 }, "near account window bike charge season chef number sketch tomorrow excuse sniff circle vital hockey outdoor supply token", "938033ed8b12698449d4bbca3c853c66b293ea1b1ce9d9dc"],
  ["BIP-39, 24 words", { app: "bip39", words: 24 }, "puppy ocean match cereal symbol another shed magic wrap hammer bulb intact gadget divorce twin tonight reason outdoor destroy simple truth cigar social volcano", "ae131e2312cdc61331542efe0d1077bac5ea803adf24b313a4f0e48e9c51f37f"],
  ["WIF", { app: "wif" }, "Kzyv4uF39d4Jrw2W7UryTHwZr1zQVNk4dAFyqE6BuMrMh1Za7uhp", "7040bb53104f27367f317558e78a994ada7296c6fde36a364e5baf206e502bb1"],
  ["XPRV", { app: "xprv" }, "xprv9s21ZrQH143K2srSbCSg4m4kLvPMzcWydgmKEnMmoZUurYuBuYG46c6P71UGXMzmriLzCCBvKQWBUv3vPB3m1SATMhp3uEjXHJ42jFg7myX", "ead0b33988a616cf6a497f1c169d9e92562604e38305ccd3fc96f2252c177682"],
  ["HEX, 64 bytes", { app: "hex", numBytes: 64 }, "492db4698cf3b73a5a24998aa3e9d7fa96275d85724a91e71aa2d645442f878555d078fd1f1f67e368976f04137b1f7a0d19232136ca50c44614af72b5582a5c", "492db4698cf3b73a5a24998aa3e9d7fa96275d85724a91e71aa2d645442f878555d078fd1f1f67e368976f04137b1f7a0d19232136ca50c44614af72b5582a5c"],
  ["Base64 password", { app: "pwd-base64", length: 21 }, "dKLoepugzdVJvdL56ogNV", "74a2e87a9ba0cdd549bdd2f9ea880d554c6c355b08ed25088cfa88f3f1c4f74632b652fd4a8f5fda43074c6f6964a3753b08bb5210c8f5e75c07a4c2a20bf6e9"],
  ["Base85 password", { app: "pwd-base85", length: 12 }, "_s`{TW89)i4`", "f7cfe56f63dca2490f65fcbf9ee63dcd85d18f751b6b5e1c1b8733af6459c904a75e82b4a22efff9b9e69de2144b293aa8714319a054b6cb55826a8e51425209"],
];
const bip85Parent = AppHDKey.fromExtendedKey(BIP85_PARENT);
const deriveChild = (spec) => bip85.deriveApplication(bip85Parent, spec);
const hexOf = (bytes) => Buffer.from(bytes).toString("hex");
// Every string reachable from a value's own data properties (a getter is not
// run), never following a DOM node.
function stringsIn(value, seen = new Set(), out = []) {
  if (typeof value === "string") out.push(value);
  else if (value && typeof value === "object" && !ArrayBuffer.isView(value) && !value.nodeType && !seen.has(value)) {
    seen.add(value);
    for (const key of Reflect.ownKeys(value)) {
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (descriptor && "value" in descriptor) stringsIn(descriptor.value, seen, out);
    }
  }
  return out;
}
const holdsText = (value, ...secrets) => stringsIn(value).filter((text) => secrets.some((secret) => text.includes(secret)));

for (const [name, spec, secret, entropyHex] of BIP85_CHILDREN) {
  test(`BIP-85 ${name}: the child holds no text of its secret or entropy`, () => {
    assert.deepEqual(holdsText(deriveChild(spec), secret, entropyHex), []);
  });

  test(`BIP-85 ${name}: the child still reads as the published secret and entropy`, () => {
    const child = deriveChild(spec);
    assert.equal(child.secret, secret);
    assert.equal(child.entropyHex, entropyHex);
  });

  // A phrase has no length to mask at: its length would narrow its words, so
  // the view masks it word by word instead (below).
  test(`BIP-85 ${name}: the hidden mask length is the secret's fixed length, found without the text`, () => {
    assert.equal(bip85.bip85SecretLength?.(deriveChild(spec)), spec.app === "bip39" ? 0 : Array.from(secret).length);
  });

  test(`BIP-85 ${name}: wiping the child zeroes every byte it holds and empties its text`, () => {
    const child = deriveChild(spec), held = Reflect.ownKeys(child).map((key) => child[key]).filter((value) => ArrayBuffer.isView(value));
    assert.ok(held.length > 0);
    bip85.wipeBip85Result(child);
    assert.ok(held.every((bytes) => bytes.every((byte) => byte === 0)), "a byte array kept its secret");
    assert.equal(child.secret, "");
    assert.equal(child.entropyHex, "");
  });
}

const childState = (spec, id = 1) => ({ isLab: false, id, name: `child ${id}`, result: deriveChild(spec), reveal: false, fingerprint: "0badc0de", fingerprintKind: "master", network: "mainnet", parentFingerprint: "f00dcafe" });
const scureFingerprint = (node) => node.fingerprint.toString(16).padStart(8, "0");
const KEY_CHILDREN = BIP85_CHILDREN.filter(([, spec]) => ["bip39", "wif", "xprv"].includes(spec.app));

for (const [name, spec, secret, entropyHex] of KEY_CHILDREN) {
  test(`BIP-85 ${name}: the child's session key for other stations holds no text of it`, () => {
    assert.deepEqual(holdsText(station.hodlBip85SessionKeyState(childState(spec)), secret, entropyHex), []);
  });

  test(`BIP-85 ${name}: the session key gives the stations the child's own key`, () => {
    const result = station.hodlBip85SessionKeyState(childState(spec)).result;
    if (spec.app === "bip39") {
      assert.equal(station.hodlResultMnemonic(result), secret);
      for (const pass of ["", "TREZOR"]) {
        const root = station.hodlSeedSessionRoot(result, pass);
        assert.equal(root.privateExtendedKey, ScureHDKey.fromMasterSeed(mnemonicToSeedSync(secret, pass)).privateExtendedKey);
        root.wipePrivateData();
      }
    } else if (spec.app === "xprv") {
      assert.equal(station.hodlResultRootXprv(result), secret);
      const root = station.hodlResultRootNode(result);
      assert.equal(root.privateExtendedKey, secret);
      root.wipePrivateData();
    } else {
      assert.equal(hexOf(station.hodlSinglePrivateKey(result)), entropyHex);
    }
  });

  test(`BIP-85 ${name}: once the station drops the child, its session key gives nothing`, () => {
    const state = childState(spec), result = station.hodlBip85SessionKeyState(state).result;
    station.__set.hodlBip85Children([{ isLab: true, id: 0 }, state]);
    station.hodlBip85WipeMem();
    const given = [station.hodlResultMnemonic(result), station.hodlResultRootXprv(result), station.hodlSinglePrivateKey(result)];
    assert.deepEqual(given.filter(Boolean).map((value) => ArrayBuffer.isView(value) ? hexOf(value) : value), []);
  });
}

// Fingerprints, from the reference libraries: a BIP-39 child's master key, an
// XPRV child's own key, a WIF child's key, and SHA-256 of any other child.
for (const [name, spec, secret, entropyHex] of BIP85_CHILDREN) {
  test(`BIP-85 ${name}: the child's fingerprint`, () => {
    const expected = spec.app === "bip39" ? scureFingerprint(ScureHDKey.fromMasterSeed(mnemonicToSeedSync(secret)))
      : spec.app === "xprv" ? scureFingerprint(ScureHDKey.fromExtendedKey(secret))
        : spec.app === "wif" ? scureFingerprint(new ScureHDKey({ privateKey: Buffer.from(entropyHex, "hex") }))
          : hexOf(sha256(Buffer.from(entropyHex, "hex")).slice(0, 4));
    assert.equal(station.hodlBip85ChildFingerprint(deriveChild(spec)).value, expected);
  });
}

// The station view: hidden, it masks a secret at its fixed length (at least
// 12), a phrase word by word, and never builds the text; revealed, it shows
// exactly the child. Reads of the child's text are counted, wherever the
// child keeps it.
function renderChild(document, spec, reveal) {
  document.body.innerHTML = '<div id="bip85-out"></div>';
  const state = childState(spec), reads = { secret: 0, entropyHex: 0 };
  for (const key of Object.keys(reads)) {
    let owner = state.result;
    while (owner && !Object.getOwnPropertyDescriptor(owner, key)) owner = Object.getPrototypeOf(owner);
    const descriptor = Object.getOwnPropertyDescriptor(owner, key), result = state.result;
    Object.defineProperty(result, key, { configurable: true, get() { reads[key] += 1; return descriptor.get ? descriptor.get.call(result) : descriptor.value; } });
  }
  station.__set.hodlBip85Children([{ isLab: true, id: 0 }, state]);
  station.__set.hodlActiveBip85(1);
  station.__set.hodlBip85Reveal(reveal);
  station.hodlRenderBip85Out();
  return reads;
}
for (const [name, spec, secret, entropyHex] of BIP85_CHILDREN) {
  test(`BIP-85 ${name}: hidden, the view masks the child at its length and never builds its text`, () => {
    const document = page();
    try {
      const reads = renderChild(document, spec, false), out = document.getElementById("bip85-out");
      assert.deepEqual(reads, { secret: 0, entropyHex: 0 }, "the hidden view built the text");
      assert.equal(out.textContent.includes(secret) || out.textContent.includes(entropyHex), false);
      const masks = out.querySelectorAll("[aria-hidden=true]").map((node) => node.textContent).filter((text) => /^\u2022+$/.test(text)).map((text) => text.length);
      // A phrase mask has a space between words, so only the entropy is here.
      assert.deepEqual(masks, spec.app === "bip39" ? [Math.max(entropyHex.length, 12)] : [Math.max(Array.from(secret).length, 12), Math.max(entropyHex.length, 12)]);
    } finally {
      leave();
    }
  });

  test(`BIP-85 ${name}: revealed, the view shows exactly the child`, () => {
    const document = page();
    try {
      renderChild(document, spec, true);
      const text = document.getElementById("bip85-out").textContent;
      assert.ok(text.includes(secret), "the secret is shown");
      assert.ok(text.includes(entropyHex), "the entropy is shown");
    } finally {
      leave();
    }
  });
}

// A hidden BIP-39 child shows its word count, which the station form already
// shows, and nothing of its words: a mask as long as the phrase narrowed them.
// It masks exactly as the Key Station masks a hidden phrase. The children are
// computed with the reference libraries (the first is the published vector),
// and their lengths differ.
const referenceChild = (words, index) => {
  const node = ScureHDKey.fromExtendedKey(BIP85_PARENT).derive(`m/83696968'/39'/0'/${words}'/${index}'`);
  const entropy = hmac(sha512, new TextEncoder().encode("bip-entropy-from-k"), node.privateKey).slice(0, words * 4 / 3);
  return entropyToMnemonic(entropy, bip39English);
};
// The first mask in a view: bullets, and spaces between masked words.
const firstMask = (root) => root.querySelectorAll("[aria-hidden=true]").map((node) => node.textContent).find((text) => /^\u2022[\u2022 ]*$/.test(text));
test("BIP-85: a hidden BIP-39 child shows its word count and nothing of its words", () => {
  const document = page();
  try {
    for (const words of [12, 24]) {
      const phrases = [0, 1, 2, 3].map((index) => referenceChild(words, index));
      if (words === 12) assert.equal(phrases[0], BIP85_CHILDREN[0][2]);
      assert.ok(new Set(phrases.map((phrase) => phrase.length)).size > 1, "the children must differ in length");
      const masks = phrases.map((phrase, index) => {
        const reads = renderChild(document, { app: "bip39", words, index }, false), out = document.getElementById("bip85-out");
        assert.equal(reads.secret, 0, `${words} words, index ${index}: the hidden view built the phrase`);
        assert.ok(!out.textContent.includes(phrase), `${words} words, index ${index}: the view shows the phrase`);
        return firstMask(out);
      });
      assert.equal(new Set(masks).size, 1, `${words} words: the mask depends on the words (${masks.map((mask) => mask.length).join(", ")} characters)`);
      document.body.innerHTML = station.hodlSeedPhraseField("Your seed phrase", phrases[0]);
      const keyStation = firstMask(document.body);
      assert.equal(keyStation.split(" ").length, words);
      assert.equal(masks[0], keyStation, `${words} words: the child is not masked as the Key Station masks a phrase`);
    }
  } finally {
    leave();
  }
});

// ---- A finished vanity grind keeps no copy of the passphrase ---------------

// The grinder zeroes the run's key bytes when the run ends, but a run's
// closures share one scope, and one of them holds the passphrase as text: a
// closure kept past the run keeps the passphrase. Measured on this process's
// own heap: the passphrase is made here at random and only its SHA-256 kept,
// so any string in the heap that hashes to it is a copy the grinder holds.
const digestOf = (text) => createHash("sha256").update(text).digest("hex");
// Held means reachable from the heap's roots along strong edges. A string that
// only a weak edge still reaches (a WeakRef target the collector has not yet
// cleared) is not held: it once counted, and failed a CI run with a dropped
// picker no later run reproduced. Anything really held is held on every
// read, so a copy is read up to three times, a task apart, before it counts,
// and what holds it is printed.
async function heldCopies(digest, length) {
  let paths = [];
  for (let read = 0; read < 3; read++) {
    // A WeakRef keeps its target until the job that made it ends.
    await new Promise((resolve) => setImmediate(resolve));
    const chunks = [];
    for await (const chunk of v8.getHeapSnapshot()) chunks.push(chunk);
    paths = heldPaths(JSON.parse(Buffer.concat(chunks).toString("utf8")), (text) => text.length === length && digestOf(text) === digest);
    if (!paths.length) return 0;
  }
  console.error(`held (${paths.length}):\n${paths.join("\n\n")}`);
  return paths.length;
}
// The strong path from the root to each string node that matches, breadth
// first over every edge but the weak ones.
function heldPaths(snapshot, matches) {
  const { meta } = snapshot.snapshot, { nodes, edges, strings } = snapshot;
  const N = meta.node_fields.length, E = meta.edge_fields.length, nodeTypes = meta.node_types[0], edgeTypes = meta.edge_types[0];
  const typeAt = meta.node_fields.indexOf("type"), nameAt = meta.node_fields.indexOf("name"), edgeCountAt = meta.node_fields.indexOf("edge_count");
  const edgeTypeAt = meta.edge_fields.indexOf("type"), edgeNameAt = meta.edge_fields.indexOf("name_or_index"), edgeToAt = meta.edge_fields.indexOf("to_node");
  const count = nodes.length / N, firstEdge = new Uint32Array(count);
  for (let index = 0, total = 0; index < count; index++) {
    firstEdge[index] = total;
    total += nodes[index * N + edgeCountAt] * E;
  }
  const via = new Int32Array(count).fill(-1), viaEdge = new Int32Array(count).fill(-1), queue = [0], found = [];
  via[0] = 0;
  const label = (index) => `${nodeTypes[nodes[index * N + typeAt]]} ${strings[nodes[index * N + nameAt]].replace(/\s+/g, " ").slice(0, 60)}`;
  for (let head = 0; head < queue.length; head++) {
    const index = queue[head];
    if (/string/.test(nodeTypes[nodes[index * N + typeAt]]) && matches(strings[nodes[index * N + nameAt]])) {
      const path = [];
      for (let at = index; at !== 0; at = via[at]) {
        const edge = viaEdge[at], type = edgeTypes[edges[edge + edgeTypeAt]];
        path.unshift(`  --${type} ${["element", "hidden"].includes(type) ? edges[edge + edgeNameAt] : strings[edges[edge + edgeNameAt]]}--> ${label(at)}`);
      }
      found.push(path.join("\n"));
    }
    for (let edge = firstEdge[index], end = edge + nodes[index * N + edgeCountAt] * E; edge < end; edge += E) {
      const to = edges[edge + edgeToAt] / N;
      if (edgeTypes[edges[edge + edgeTypeAt]] === "weak" || via[to] !== -1) continue;
      via[to] = index;
      viaEdge[to] = edge;
      queue.push(to);
    }
  }
  return found;
}
// Workers that report ready, take the job, and report done, as the page's do.
function fakeWorkers() {
  const workers = [];
  const spawn = () => {
    const worker = { messages: [], terminated: false, onmessage: null, onerror: null, postMessage(message) { this.messages.push(message); }, terminate() { this.terminated = true; } };
    workers.push(worker);
    return { worker, url: null };
  };
  return { workers, spawn };
}
const RUN = { method: "passphrase", script: "p2wpkh", prefix: "q", start: 0n, count: 10n, workers: 1, passLen: 1, mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about" };
// Runs a grind to its end in a frame of its own, which is gone before the heap
// is read: only the grinder is kept, as the page keeps it. The passphrase is
// made here and only its digest and length leave.
function grindToEnd(ending) {
  const { workers, spawn } = fakeWorkers(), grinder = new VanityGrinder({}, spawn);
  const passphrase = `vanity-${randomBytes(12).toString("hex")}`, pass = { digest: digestOf(passphrase), length: passphrase.length };
  grinder.start({ ...RUN, passphrase });
  for (const worker of workers) worker.onmessage({ data: { type: "ready" } });
  if (ending === "completes") for (const worker of workers) worker.onmessage({ data: { type: "done", done: 10n, stopped: false } });
  else grinder.cancel();
  const ended = workers.length > 0 && workers.every((worker) => worker.terminated);
  workers.length = 0;
  return { grinder, ended, pass };
}
for (const ending of ["completes", "is cancelled"]) {
  test(`a vanity grind that ${ending} keeps no copy of the passphrase`, async () => {
    const { grinder, ended, pass } = grindToEnd(ending);
    assert.ok(ended, "the run ended");
    assert.equal(await heldCopies(pass.digest, pass.length), 0, "the grinder still holds the passphrase");
    assert.ok(grinder);
  });
}

// ---- What a station drops, it keeps nothing of -----------------------------

// The custom select (enhanced-inputs.js) builds a dropdown for each select and
// keeps a list of them to close one when another opens. A seed word picker is
// rebuilt on every render, and its select's handler holds the form's key state:
// a dropdown the page drops must not keep it. A marker made here stands for
// that state; only its digest leaves the frame that makes it.
const enhanceSelects = (document) => new Function("document", "Element", "MutationObserver", "Event", enhancedInputs)(document, MiniElement, class { observe() {} }, class {});
function dropPicker(document) {
  const marker = `picker-${randomBytes(12).toString("hex")}`, kept = { digest: digestOf(marker), length: marker.length };
  document.body.innerHTML = '<div id="last-words"></div>';
  station.hodlRenderLastWordPicker(document.getElementById("last-words"), ["account", "coin", "online"], "", () => marker, { forceSelect: true, targetWords: 12 });
  enhanceSelects(document);
  document.body.innerHTML = "";
  return kept;
}
test("a picker the page drops takes what its handlers held with it", async () => {
  const document = page();
  try {
    const kept = dropPicker(document);
    assert.ok(document.listenerCount("click") > 0, "the custom select listens on the page");
    assert.equal(await heldCopies(kept.digest, kept.length), 0, "the custom select still holds the dropped picker");
  } finally {
    leave();
  }
});

// The vanity station's own Wipe drops a finished grind: the grinder keeps its
// run, the words and passphrase with it, through its callbacks.
function finishedGrinder() {
  const marker = `grind-${randomBytes(12).toString("hex")}`, kept = { digest: digestOf(marker), length: marker.length };
  vanityStation.__set.hodlVanityRunning(false);
  vanityStation.__set.hodlVanityGrinder({ callbacks: { onDone: () => marker } });
  return kept;
}
test("the vanity station's Wipe keeps nothing of a finished grind", async () => {
  const kept = finishedGrinder();
  vanityStation.hodlVanityClearResults();
  assert.equal(await heldCopies(kept.digest, kept.length), 0, "the station still holds the finished grind");
});

// A masked matches table must not leak what it hides, not even the passphrase
// lengths through the column's width (audit A35-3): the mask is a fixed twelve
// bullets, so the masked width is fixed too. Revealed, the column still fits
// the longest passphrase shown.
test("a masked vanity table sizes its passphrase column by the mask, not the passphrases", () => {
  const widthWith = (passphrase, reveal) => {
    const calls = [];
    const out = { innerHTML: "", querySelectorAll: () => [], style: { setProperty: (name, value) => calls.push([name, value]), removeProperty() {} } };
    globalThis.document = { getElementById: (id) => (id === "vanity-out" ? out : id === "vanity-matches-heading" ? { textContent: "" } : null) };
    try {
      vanityRender.__set.hodlVanityMatches([{ passphrase, counter: 7n, address: "bc1qmatch", fingerprint: "73c5da0a", savedTo: "" }]);
      vanityRender.__set.hodlVanityRun({ method: "passphrase", script: "p2wpkh", sourceId: 1, sourceLabel: "Key 1", sourceKind: "key", passphrase: "", accountHardened: true, path: [], pathText: "m/84h/0h/0h" });
      vanityRender.__set.hodlVanityReveal(reveal);
      vanityRender.__set.hodlVanityFound(1);
      vanityRender.hodlRenderVanityOut();
    } finally {
      delete globalThis.document;
    }
    return calls.find(([name]) => name === "--vanity-pass-width")?.[1];
  };
  assert.deepEqual([widthWith("x".repeat(13), false), widthWith("y".repeat(30), false)], ["12ch", "12ch"], "a masked table sized its column by the hidden passphrases");
  assert.equal(widthWith("x".repeat(13), true), "13ch", "the revealed table no longer fits the shown passphrase");
});
