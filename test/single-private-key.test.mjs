// #546 B2 step 2c-1: a single-key result (a WIF, hex, Casascius mini key or
// brain-wallet key) holds its private key as bytes that can be zeroed, never
// as WIF or hex text. The WIFs and hex are encoded only where one is shown,
// copied or exported. Strings cannot be erased, so text held for the whole
// session defeats Wipe.
//
// Expected values: the published Bitcoin wiki WIF vector, the published
// Casascius mini key example, SHA-256 from @noble/hashes for mini and brain
// keys, and WIF encoding from @scure/base's Base58Check.
// Run with `npm test`.
import { test } from "node:test";
import assert from "node:assert/strict";
import { sha256 } from "@noble/hashes/sha2.js";
import { createBase58check, hex } from "@scure/base";
import { loadAppFunctions } from "./app-slice-harness.mjs";

const b58 = createBase58check(sha256);
const wifOf = (key, network, compressed) => b58.encode(Uint8Array.from([network === "mainnet" ? 0x80 : 0xef, ...key, ...(compressed ? [1] : [])]));
// Bitcoin wiki, "Wallet import format": this key's uncompressed mainnet WIF.
const WIKI_KEY = hex.decode("0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d");
const WIKI_WIF = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ";
// Bitcoin wiki, "Mini private key format": the Casascius example.
const MINI = "S6c56bnXQiBjk9mqSYE7ykVQ7NzrRy";
const MINI_KEY = hex.decode("4c7a9640c72dc2099f23715d0c8a0d8a35f8906e3cab61dd3f78b67bf887c9ab");
const BRAIN = "correct horse battery staple";
const utf8 = (text) => new TextEncoder().encode(text);

// The slices carry page-boot statements that run once at load; give them
// inert stand-ins there.
const inert = new Proxy(function () {}, { get: (target, key) => key === Symbol.toPrimitive ? () => "" : key === "then" ? undefined : inert, apply: () => inert, construct: () => inert });
const load = async (names, stubs = {}, settable = []) => {
  Object.assign(globalThis, { __ENTROPYLAB_TEST_HOOKS__: false, document: inert, window: inert });
  try {
    return await loadAppFunctions(names, { stubs, settable });
  } finally {
    delete globalThis.document;
    delete globalThis.window;
  }
};
const { hodlSingleKeyWallet } = await load(["hodlSingleKeyWallet"]);

// [label, input, kind, selected network, expected key, expected network]
const cases = [
  ["published WIF, uncompressed", WIKI_WIF, "wif", "mainnet", WIKI_KEY, "mainnet"],
  ["compressed WIF", wifOf(WIKI_KEY, "mainnet", true), "wif", "mainnet", WIKI_KEY, "mainnet"],
  ["testnet compressed WIF", wifOf(WIKI_KEY, "testnet", true), "wif", "testnet", WIKI_KEY, "testnet"],
  ["hex", hex.encode(WIKI_KEY).toUpperCase(), "hex-key", "mainnet", WIKI_KEY, "mainnet"],
  ["hex on testnet", hex.encode(WIKI_KEY), "hex-key", "testnet", WIKI_KEY, "testnet"],
  ["Casascius mini key", MINI, "minikey", "mainnet", MINI_KEY, "mainnet"],
  ["brain wallet", BRAIN, "brain", "mainnet", sha256(utf8(BRAIN)), "mainnet"],
];
const secretTexts = (key, network) => [wifOf(key, network, true), wifOf(key, network, false), hex.encode(key)];
const stringsIn = (value, seen = new Set(), out = []) => {
  if (typeof value === "string") out.push(value);
  else if (value && typeof value === "object" && !ArrayBuffer.isView(value) && !seen.has(value)) {
    seen.add(value);
    for (const key of Object.keys(value)) stringsIn(value[key], seen, out);
  }
  return out;
};

test("the oracles agree with the published vectors", () => {
  assert.equal(wifOf(WIKI_KEY, "mainnet", false), WIKI_WIF);
  assert.equal(hex.encode(sha256(utf8(MINI))), hex.encode(MINI_KEY));
  assert.equal(sha256(utf8(`${MINI}?`))[0], 0, "the mini key's check byte");
});

test("a single-key result holds its private key as bytes, never as WIF or hex text", () => {
  for (const [label, input, kind, network, key, expectedNetwork] of cases) {
    const result = hodlSingleKeyWallet(input, network, kind);
    const leaks = stringsIn(result).filter((text) => secretTexts(key, expectedNetwork).some((secret) => text.toLowerCase().includes(secret.toLowerCase())));
    assert.deepEqual(leaks.map((text) => text.slice(0, 8) + "…"), [], `${label}: the result holds the private key as text`);
    assert.deepEqual([...result.privateKey], [...key], `${label}: the result's key bytes`);
    assert.equal(result.network, expectedNetwork, label);
  }
});

test("each WIF and the hex are produced on request and match an independent encoder", async () => {
  const api = await load(["hodlSingleKeyWallet", "hodlSingleWif", "hodlSinglePrivateHex"]);
  for (const [label, input, kind, network, key, expectedNetwork] of cases) {
    const result = api.hodlSingleKeyWallet(input, network, kind);
    assert.equal(api.hodlSingleWif(result, true), wifOf(key, expectedNetwork, true), `${label}: compressed WIF`);
    assert.equal(api.hodlSingleWif(result, false), wifOf(key, expectedNetwork, false), `${label}: uncompressed WIF`);
    assert.equal(api.hodlSinglePrivateHex(result), hex.encode(key), `${label}: hex`);
  }
  assert.equal(api.hodlSingleWif(api.hodlSingleKeyWallet(WIKI_WIF, "mainnet", "wif"), false), WIKI_WIF);
  // Each encoding keeps one length for every key and network, so a hidden
  // field masks at that length without encoding the key.
  const lengths = new Set(), extremes = [new Uint8Array(32).fill(1), hex.decode("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140")];
  for (const extreme of extremes) for (const network of ["mainnet", "testnet"]) lengths.add([wifOf(extreme, network, true).length, wifOf(extreme, network, false).length, hex.encode(extreme).length].join("/"));
  assert.deepEqual([...lengths], ["52/51/64"]);
});

// The hidden view is a mask as long as the value and the revealed view is the
// value, both rendered with the unchanged private-field primitive around the
// independently encoded key. (The full single-key card is covered by the
// rendered page comparison against rock, which the PR records.)
test("the private key fields render the same, hidden and revealed", async () => {
  const view = await load(["hodlSingleKeyWallet", "hodlSinglePrivateFieldsHtml", "hodlPrivateFieldHtml"], {}, ["hodlRevealPrivate"]);
  for (const revealed of [false, true]) {
    view.__set.hodlRevealPrivate(revealed);
    for (const [label, input, kind, network, key, expectedNetwork] of cases) {
      const result = view.hodlSingleKeyWallet(input, network, kind), field = (name, value) => view.hodlPrivateFieldHtml(name, value, void 0, "muted");
      const expected = field("WIF compressed", wifOf(key, expectedNetwork, true)) + field("WIF uncompressed", wifOf(key, expectedNetwork, false)) + field("Hex private key", hex.encode(key)) + (kind === "minikey" ? field("Mini private key", MINI) : "");
      assert.equal(view.hodlSinglePrivateFieldsHtml(result), expected, `${revealed ? "revealed" : "hidden"}, ${label}`);
    }
  }
});

test("the recovery sheet carries the key only when private material is saved", async () => {
  const api = await load(["hodlSingleKeyWallet", "hodlRecoverySheetText"]);
  for (const [label, input, kind, network, key, expectedNetwork] of cases) {
    const result = api.hodlSingleKeyWallet(input, network, kind), secrets = secretTexts(key, expectedNetwork);
    const sheet = api.hodlRecoverySheetText(result, true), watch = api.hodlRecoverySheetText(result, false);
    for (const secret of secrets) assert.ok(sheet.includes(secret), `${label}: the private sheet lacks ${secret.slice(0, 6)}…`);
    assert.ok(!secrets.some((secret) => watch.toLowerCase().includes(secret.toLowerCase())), `${label}: the watch-only sheet carries the key`);
  }
});

// The derive path asserts the WIF's network family before calling
// (hodlAssertPrivateKeyKind), so hodlSingleKeyWallet never sees a mismatch
// today. If a future caller skips that check, the wallet must fail loudly
// rather than come back silently re-homed onto the WIF's network.
test("a WIF whose network family mismatches the selected chain is refused, not silently re-homed", () => {
  assert.throws(() => hodlSingleKeyWallet(wifOf(WIKI_KEY, "testnet", true), "mainnet", "wif"), /WIF is for/);
  assert.throws(() => hodlSingleKeyWallet(WIKI_WIF, "testnet", "wif"), /WIF is for/);
});

// A station session (the PSBT inspector) takes its own copy, which it zeroes
// when the session ends; zeroing it must leave the wallet's key intact.
test("a station session gets its own copy of the key, which it can zero alone", async () => {
  const api = await load(["hodlSingleKeyWallet", "hodlSinglePrivateKey", "hodlResultHasSingleKey"]);
  const result = api.hodlSingleKeyWallet(WIKI_WIF, "mainnet", "wif");
  const copy = api.hodlSinglePrivateKey(result);
  assert.deepEqual([...copy], [...WIKI_KEY]);
  copy.fill(0);
  assert.deepEqual([...result.privateKey], [...WIKI_KEY], "zeroing the session copy zeroed the wallet's key");
  assert.equal(api.hodlResultHasSingleKey(result), true);
  // A BIP-85 WIF child's session key carries its key as bytes (#546 B3).
  const child = { kind: "single", privateKey: Uint8Array.from(MINI_KEY) };
  assert.equal(api.hodlResultHasSingleKey(child), true);
  assert.deepEqual([...api.hodlSinglePrivateKey(child)], [...MINI_KEY]);
  assert.equal(api.hodlResultHasSingleKey({ kind: "single" }), false);
  assert.equal(api.hodlSinglePrivateKey({ kind: "single" }), null);
});

// The PSBT inspector offers a single key as a session chip and loads its own
// copy of the key from it.
test("the PSBT session offers a single key and loads its own copy of it", async () => {
  const result = hodlSingleKeyWallet(WIKI_WIF, "mainnet", "wif"), state = { id: 1, isLab: false, name: "Key 1", fields: {}, result };
  const api = await load(["hodlPsbtSourceKeys", "hodlUseActiveKeyForPsbt", "hodlPsbtPriv"], {
    hodlKeys: [{ id: 0, isLab: true, fields: {}, result: null }, state], hodlActiveKey: 1, hodlBip85Children: [], hodlBip85SessionKeyState: () => null, hodlPsbtWipeMem() {},
  });
  assert.deepEqual(api.hodlPsbtSourceKeys(), [state], "the single key is not offered as a session chip");
  api.hodlUseActiveKeyForPsbt(state);
  assert.deepEqual([...api.hodlPsbtPriv], [...WIKI_KEY], "the session key");
  assert.notEqual(api.hodlPsbtPriv, result.privateKey, "the session shares the wallet's key bytes");
});

// A single key's bytes are recorded by the derivation that made them, so one
// that never commits zeroes them with its row keys (hodlSettleDerivationKeys).
test("a single key is recorded by the derivation that decodes it", async () => {
  const api = await load(["hodlSingleKeyWallet", "hodlSettleDerivationKeys", "hodlActiveDerivation"], { hodlLiveWalletResults: () => new Set(), hodlKeyManagerPending: [] }, ["hodlActiveDerivation"]);
  const control = { kind: "key", cancelled: false, rowKeys: [], nodes: [] };
  api.__set.hodlActiveDerivation(control);
  const result = api.hodlSingleKeyWallet(WIKI_WIF, "mainnet", "wif");
  assert.ok(control.rowKeys.includes(result.privateKey), "the derivation did not record the key bytes");
  api.hodlSettleDerivationKeys(control);
  assert.ok(result.privateKey.every((byte) => byte === 0), "an uncommitted single key kept its bytes");
});
