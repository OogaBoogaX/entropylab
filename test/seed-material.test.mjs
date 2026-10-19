// #546 B2 step 2c-2: a seed wallet holds its BIP39 words, entropy and seed as
// bytes that can be zeroed, never as text. The words, entropy hex and seed
// hex are built only where they are shown, copied or exported, or handed to
// a station that takes the words as text. Strings cannot be erased, so text
// held for the whole session defeats Wipe.
//
// Expected values: the published BIP39 (Trezor) vectors, checked against
// @scure/bip39, and BIP32 roots from @scure/bip32.
// Run with `npm test`.
import { test } from "node:test";
import assert from "node:assert/strict";
import { HDKey as ScureHDKey } from "@scure/bip32";
import { mnemonicToSeedSync, entropyToMnemonic } from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english.js";
import { hex, createBase58check } from "@scure/base";
import { sha256 } from "@noble/hashes/sha2.js";
import { renderSVG } from "uqr";
import { VAULT_MASK } from "../src/js/passphrase-vault.js";
import { loadAppFunctions } from "./app-slice-harness.mjs";

// BIP39 test vectors (trezor/python-mnemonic vectors.json), passphrase "TREZOR".
const VECTORS = [
  { entropy: "00000000000000000000000000000000", last: "about", seed: "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04" },
  { entropy: "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f", last: "yellow", seed: "2e8905819b8723fe2c1d161860e5ee1830318dbf49a83bd451cfb8440c28bd6fa457fe1296106559a3c80937a1c1069be3a3a5bd381ee6260e8d9739fce1f607" },
  { entropy: "0000000000000000000000000000000000000000000000000000000000000000", last: "art", seed: "bda85446c68413707090a52022edd26a1c9462295029f2e60cd7c4f2bbd3097170af7a4d73245cafa9c3cca8d561a7c3de6f5d4a10be8ed2a5e608d68f92fcc8" },
].map((vector) => ({ ...vector, words: entropyToMnemonic(hex.decode(vector.entropy), wordlist), pass: "TREZOR" }));
const rootOf = (words, pass) => ScureHDKey.fromMasterSeed(mnemonicToSeedSync(words, pass));
const seedQrDigits = (words) => words.split(" ").map((word) => String(wordlist.indexOf(word)).padStart(4, "0")).join("");

const inert = new Proxy(function () {}, { get: (target, key) => key === Symbol.toPrimitive ? () => "" : key === "then" ? undefined : inert, apply: () => inert, construct: () => inert });
const b58 = createBase58check(sha256);
// Re-serialize an extended key with SLIP-132 version bytes: same payload, a
// different prefix (Yprv 0x0295b005, Zprv 0x02aa7a99 — both multisig scope).
const withVersion = (xkey, ver) => {
  const payload = b58.decode(xkey);
  new DataView(payload.buffer, payload.byteOffset).setUint32(0, ver);
  return b58.encode(payload);
};
const load = async (names, stubs = {}, settable = []) => {
  Object.assign(globalThis, { __ENTROPYLAB_TEST_HOOKS__: false, document: inert, window: inert });
  try {
    return await loadAppFunctions(names, { stubs: { hodlSelectedScriptType: () => "bip84", ...stubs }, settable });
  } finally {
    delete globalThis.document;
    delete globalThis.window;
  }
};
const tracker = { setTotal() {}, step() { return null; } };
const builders = await load(["hodlMnemonicWalletWithProgress", "hodlEntropyWalletWithProgress", "hodlImportedWalletWithProgress"]);
const fromWords = (vector) => builders.hodlMnemonicWalletWithProgress(vector.words, vector.pass, "mainnet", 2, undefined, 0, 0, tracker, 84, 0);
const fromEntropy = (vector) => builders.hodlEntropyWalletWithProgress({ bytes: hex.decode(vector.entropy), hex: vector.entropy, notes: [], warnings: [] }, vector.pass, "mainnet", 2, 0, 0, tracker, 84, 0);
const wallets = async () => {
  const out = [];
  for (const vector of VECTORS) out.push([`${vector.last}, typed words`, vector, await fromWords(vector)], [`${vector.last}, from entropy`, vector, await fromEntropy(vector)]);
  return out;
};
const stringsIn = (value, seen = new Set(), out = []) => {
  if (typeof value === "string") out.push(value);
  else if (value && typeof value === "object" && !ArrayBuffer.isView(value) && !seen.has(value)) {
    seen.add(value);
    for (const key of Object.keys(value)) stringsIn(value[key], seen, out);
  }
  return out;
};

test("the oracle agrees with the published BIP39 vectors", () => {
  for (const vector of VECTORS) {
    assert.equal(vector.words.split(" ").at(-1), vector.last);
    assert.equal(hex.encode(mnemonicToSeedSync(vector.words, vector.pass)), vector.seed);
  }
});

test("a seed wallet holds its words, entropy and seed as bytes, never as text", async () => {
  for (const [label, vector, wallet] of await wallets()) {
    const secrets = [vector.words, vector.entropy, vector.seed];
    const leaks = stringsIn(wallet).filter((text) => secrets.some((secret) => text.toLowerCase().includes(secret)));
    assert.deepEqual(leaks.map((text) => text.slice(0, 12) + "…"), [], `${label}: the wallet holds its seed material as text`);
    assert.equal(hex.encode(wallet.entropy), vector.entropy, `${label}: entropy bytes`);
    assert.equal(hex.encode(wallet.seed), vector.seed, `${label}: seed bytes`);
  }
});

test("the words, entropy hex and seed hex are produced on request and match BIP39", async () => {
  const api = await load(["hodlResultHasSeed", "hodlResultMnemonic", "hodlResultEntropyHex", "hodlResultSeedHex"]);
  for (const [label, vector, wallet] of await wallets()) {
    assert.equal(api.hodlResultHasSeed(wallet), true, label);
    assert.equal(api.hodlResultMnemonic(wallet), vector.words, `${label}: words`);
    assert.equal(api.hodlResultEntropyHex(wallet), vector.entropy, `${label}: entropy hex`);
    assert.equal(api.hodlResultSeedHex(wallet), vector.seed, `${label}: seed hex`);
  }
  // A BIP-85 child's session key carries the child's BIP39 entropy as bytes
  // (#546 B3); an imported root carries no seed material.
  const child = { kind: "hd", entropy: hex.decode(VECTORS[1].entropy) };
  assert.equal(api.hodlResultHasSeed(child), true);
  assert.equal(api.hodlResultMnemonic(child), VECTORS[1].words);
  const imported = await builders.hodlImportedWalletWithProgress(rootOf(VECTORS[0].words, "").privateExtendedKey, "mainnet", 2, 0, 0, tracker, 84, 0);
  assert.equal(api.hodlResultHasSeed(imported), false);
  assert.equal(api.hodlResultMnemonic(imported), null);
  assert.equal(api.hodlResultEntropyHex(imported), null);
  assert.equal(api.hodlResultSeedHex(imported), null);
});

// The hidden view masks each word at the same width, each hex value at its
// length and the passphrase at the fixed placeholder (its length would
// narrow a search for it); the revealed view is the value. Both are rendered
// with the unchanged primitives around the independently computed values, in
// the order the card has always used: words, SeedQR, passphrase, entropy, seed.
test("the recovery fields render the same, hidden and revealed", async () => {
  // The QR renderer is the uqr package, which the slice loader does not import.
  const view = await load(["hodlSeedRecoveryFields", "hodlSeedPhraseField", "hodlSeedQrExport", "hodlPrivateFieldHtml"], { hodlUqrRenderSvg: renderSVG }, ["hodlRevealPrivate"]);
  for (const revealed of [false, true]) {
    view.__set.hodlRevealPrivate(revealed);
    for (const [label, vector, wallet] of await wallets()) {
      const expected = [
        view.hodlSeedPhraseField(`Your seed phrase \xB7 ${vector.words.split(" ").length} words`, vector.words),
        view.hodlSeedQrExport(vector.words, { passphraseUsed: true, entropyHex: vector.entropy }),
        view.hodlPrivateFieldHtml("BIP39 passphrase", revealed ? vector.pass : ""),
        view.hodlPrivateFieldHtml("BIP39 entropy hex", vector.entropy),
        view.hodlPrivateFieldHtml("Master seed hex", vector.seed),
      ].join("");
      assert.equal(view.hodlSeedRecoveryFields(wallet).join(""), expected, `${revealed ? "revealed" : "hidden"}, ${label}`);
    }
    // Without a passphrase there is no passphrase field.
    const vector = { ...VECTORS[1], pass: "" }, wallet = await fromWords(vector), seed = hex.encode(mnemonicToSeedSync(vector.words, ""));
    const expected = view.hodlSeedPhraseField("Your seed phrase \xB7 12 words", vector.words) + view.hodlSeedQrExport(vector.words, { passphraseUsed: false, entropyHex: vector.entropy })
      + view.hodlPrivateFieldHtml("BIP39 entropy hex", vector.entropy) + view.hodlPrivateFieldHtml("Master seed hex", seed);
    assert.equal(view.hodlSeedRecoveryFields(wallet).join(""), expected, `${revealed ? "revealed" : "hidden"}, no passphrase`);
    // A BIP-85 child's session key carries the child's entropy as bytes (#546 B3).
    const words = VECTORS[2].words, child = { kind: "hd", entropy: hex.decode(VECTORS[2].entropy), passphraseUsed: false };
    assert.equal(view.hodlSeedRecoveryFields(child).join(""), view.hodlSeedPhraseField("Your seed phrase \xB7 24 words", words) + view.hodlSeedQrExport(words, { passphraseUsed: false, entropyHex: VECTORS[2].entropy })
      + view.hodlPrivateFieldHtml("BIP39 entropy hex", VECTORS[2].entropy), `${revealed ? "revealed" : "hidden"}, BIP-85 child words`);
  }
});

test("the recovery sheet carries the seed material only when private material is saved", async () => {
  const { hodlRecoverySheetText } = await load(["hodlRecoverySheetText"]);
  for (const [label, vector, wallet] of await wallets()) {
    const sheet = hodlRecoverySheetText(wallet, true), watch = hodlRecoverySheetText(wallet, false), words = vector.words.split(" ").length;
    const secrets = [vector.words, vector.entropy, vector.seed, ...(words === 12 || words === 24 ? [seedQrDigits(vector.words)] : [])];
    for (const secret of secrets) assert.ok(sheet.includes(secret), `${label}: the private sheet lacks ${secret.slice(0, 12)}…`);
    assert.ok(!secrets.some((secret) => watch.includes(secret)), `${label}: the watch-only sheet carries seed material`);
  }
});

// A station takes a key's root. A Key Station wallet hands over a copy of
// the root it was derived with; a BIP-85 child's session key derives one from
// the child's entropy, which it keeps as bytes (#546 B3).
test("a station session gets its own copy of the wallet's root", async () => {
  const { hodlSeedSessionRoot } = await load(["hodlSeedSessionRoot"]);
  const vector = VECTORS[1], wallet = await fromWords(vector), expected = rootOf(vector.words, vector.pass).privateExtendedKey;
  const root = hodlSeedSessionRoot(wallet, vector.pass);
  assert.equal(root.privateExtendedKey, expected);
  root.wipePrivateData();
  assert.equal(hodlSeedSessionRoot(wallet, vector.pass).privateExtendedKey, expected, "wiping the session copy wiped the wallet's root");
  const child = hodlSeedSessionRoot({ kind: "hd", entropy: hex.decode(vector.entropy) }, "");
  assert.equal(child.privateExtendedKey, rootOf(vector.words, "").privateExtendedKey, "a BIP-85 child's words");
});

// The stations that take a key with seed words load the same root as before,
// and SP Station still fills its key field with the words (a station input
// the user can see and edit).
test("PSBT, BIP-85, SP and Vanity load the wallet's own root and words", async () => {
  const vector = VECTORS[1], wallet = await fromWords(vector), state = { id: 7, name: "Key 7", fields: { pass: vector.pass, derivationAccountPath: "m/84'/0'/0'", branchStart: "0", addressStart: "0" }, result: wallet };
  const expected = rootOf(vector.words, vector.pass);
  const psbt = await load(["hodlUseActiveKeyForPsbt", "hodlPsbtHd"], { hodlKeys: [state], hodlActiveKey: 0, hodlPsbtWipeMem() {} });
  psbt.hodlUseActiveKeyForPsbt(state);
  assert.equal(psbt.hodlPsbtHd.privateExtendedKey, expected.privateExtendedKey, "PSBT session root");
  assert.notEqual(psbt.hodlPsbtHd, wallet.rootNode, "the PSBT session shares the wallet's root node");
  const bip85 = await load(["hodlUseKeyForBip85", "hodlBip85Root", "hodlBip85Note"], { hodlBip85WipeParent() {} });
  bip85.hodlUseKeyForBip85(state);
  assert.equal(bip85.hodlBip85Root.privateExtendedKey, expected.privateExtendedKey, "BIP-85 parent root");
  // The parent is still loaded as seed words, so the note warns that the
  // passphrase is part of it (children differ without it).
  assert.match(bip85.hodlBip85Note, /passphrase/i, "the BIP-85 parent lost its passphrase warning");
  const fields = new Map(["sp-error", "sp-key", "sp-pass", "sp-session"].map((id) => [id, { value: "", textContent: "" }]));
  const page = new Proxy(inert, { get: (target, key) => key === "getElementById" ? (id) => fields.get(id) ?? inert : inert[key] });
  const sp = await load(["hodlPickSpSessionKey", "hodlSpHd"], { document: page, hodlElement: () => inert, hodlSpWipeKeys() {}, hodlRefreshStationKeyPickers() {} });
  sp.hodlPickSpSessionKey(state);
  assert.equal(sp.hodlSpHd.privateExtendedKey, expected.privateExtendedKey, "SP session root");
  assert.equal(fields.get("sp-key").value, vector.words, "the SP key field");
  assert.equal(fields.get("sp-pass").value, vector.pass, "the SP passphrase field");
  assert.equal(fields.get("sp-error").textContent, "");
  const vanity = await load(["hodlVanityPlan"], { hodlVanityKeyLabel: () => "Key 7", hodlElement: () => inert });
  assert.equal(vanity.hodlVanityPlan(state, "passphrase", "p2wpkh").mnemonic, vector.words, "the passphrase grind's words");
  const parent = expected.derive("m/84'/0'"), plan = vanity.hodlVanityPlan(state, "derivation", "p2wpkh");
  assert.equal(hex.encode(plan.node), hex.encode(parent.privateKey) + hex.encode(parent.chainCode), "the derivation grind's node");
});

// Key Station refuses a multisig extended key outright ("…is a multisig
// extended key. Use it in Multi Signature…"). The BIP-85 root loader parsed
// the same keys with no scope check: a depth-0 Yprv/Zprv loaded silently and
// derived children as if it were an xprv root (audit L9).
test("the BIP-85 root loader refuses multisig extended keys, like Key Station", async () => {
  const bip85 = await load(["hodlBip85LoadXprv", "hodlBip85Root"], { hodlBip85WipeParent() {} });
  const rootXprv = rootOf(VECTORS[0].words, "").privateExtendedKey;
  assert.throws(() => bip85.hodlBip85LoadXprv(withVersion(rootXprv, 0x0295b005)), /multisig/i, "Yprv");
  assert.throws(() => bip85.hodlBip85LoadXprv(withVersion(rootXprv, 0x02aa7a99)), /multisig/i, "Zprv");
  assert.equal(bip85.hodlBip85Root, null, "a refused key must not become the parent");
  bip85.hodlBip85LoadXprv(rootXprv);
  assert.ok(bip85.hodlBip85Root.privateKey, "the singlesig root still loads");
});

// Station passphrase fields (SP, PSBT, Nonce) keep the passphrase in a vault.
// The field shows bullets. Readers take UTF-8 bytes. The root must be the
// published BIP39 vector (VECTORS[0], passphrase TREZOR) as @scure/bip32
// derives it from that seed; the field must not hold the passphrase text.
class StationPassField {
  constructor() {
    this.value = "";
    this.selectionStart = 0;
    this.selectionEnd = 0;
    this.listeners = new Map();
  }
  addEventListener(type, fn) {
    const list = this.listeners.get(type) || [];
    list.push(fn);
    this.listeners.set(type, list);
  }
  setSelectionRange(start, end) {
    this.selectionStart = start;
    this.selectionEnd = end;
  }
  dispatchEvent(event) {
    let prevented = false;
    if (typeof event.preventDefault !== "function") event.preventDefault = () => { prevented = true; };
    for (const fn of this.listeners.get(event.type) || []) fn(event);
    return !(prevented || event.defaultPrevented);
  }
  type(text) {
    for (const data of text) {
      this.dispatchEvent({ type: "beforeinput", inputType: "insertText", data, cancelable: true, isComposing: false, dataTransfer: null, bubbles: true });
    }
  }
}
test("station passphrase fields hold only bullets and still derive the published TREZOR seed", async () => {
  const vector = VECTORS[0], expected = rootOf(vector.words, vector.pass).privateExtendedKey;
  const fields = new Map(["sp-pass", "psbt-pass", "nonce-pass", "psbt-text", "psbt-key", "nonce-text", "nonce-key"].map((id) => [id, new StationPassField()]));
  const page = new Proxy(inert, { get: (target, key) => key === "getElementById" ? (id) => fields.get(id) || null : inert[key] });
  const api = await load([
    "hodlInitStationPassphraseVaults", "hodlStationPassphraseBytes", "hodlClearStationPassphrase", "hodlSetStationPassphrase",
    "hodlSpLoadKey", "hodlSpHd", "hodlLoadPsbtKey", "hodlPsbtHd", "hodlPsbtWipeMem", "hodlPsbtRunStamp",
  ], { document: page, hodlElement: () => inert });
  api.hodlInitStationPassphraseVaults();
  const bullets = VAULT_MASK.repeat(vector.pass.length);
  const loadRoot = (kind, id) => {
    const pass = api.hodlStationPassphraseBytes(id);
    try {
      if (kind === "sp") api.hodlSpLoadKey(vector.words, pass || "");
      else api.hodlLoadPsbtKey(vector.words, pass || "");
    } finally {
      if (pass) pass.fill(0);
    }
    const node = kind === "sp" ? api.hodlSpHd : api.hodlPsbtHd;
    assert.equal(node.privateExtendedKey, expected, `${id} derived a different root than the published TREZOR vector`);
    node.wipePrivateData();
  };
  for (const id of ["sp-pass", "psbt-pass", "nonce-pass"]) {
    const field = fields.get(id);
    field.type(vector.pass);
    assert.equal(field.value, bullets, `${id} showed the passphrase`);
    assert.equal(field.value.includes("T"), false, `${id} kept a letter of the passphrase`);
    loadRoot(id === "sp-pass" ? "sp" : "psbt", id);
    api.hodlClearStationPassphrase(id);
    assert.equal(field.value, "", `${id} stayed filled after clear`);
    assert.equal(api.hodlStationPassphraseBytes(id), "", `${id} vault survived clear`);
  }
  // A key tab's stored passphrase is bytes. The station field shows bullets,
  // and those bytes are the ones that derive.
  const stored = new TextEncoder().encode(vector.pass);
  api.hodlSetStationPassphrase("sp-pass", stored);
  assert.equal(new TextDecoder().decode(stored), vector.pass, "setting the station passphrase wiped the caller's bytes");
  assert.equal(fields.get("sp-pass").value, bullets, "setBytes wrote the passphrase into the field");
  loadRoot("sp", "sp-pass");
  // Same-length edits must change the PSBT run stamp. The field stays bullets
  // either way, so stamping its value would treat "ab" and "cd" as the same run.
  const pass = fields.get("psbt-pass");
  pass.type("ab");
  const first = api.hodlPsbtRunStamp({ text: "psbt-text", fields: ["psbt-key", "psbt-pass"] });
  pass.setSelectionRange(0, pass.value.length);
  pass.dispatchEvent({ type: "beforeinput", inputType: "insertText", data: "cd", cancelable: true, isComposing: false, dataTransfer: null, bubbles: true });
  const second = api.hodlPsbtRunStamp({ text: "psbt-text", fields: ["psbt-key", "psbt-pass"] });
  assert.equal(pass.value, VAULT_MASK.repeat(2), "a same-length edit put the passphrase in the field");
  assert.notEqual(first, second, "a same-length passphrase edit did not change the run stamp");
});

test("the journal still records a derived key's words", async () => {
  const vector = VECTORS[0], wallet = await fromWords(vector), doc = { entries: [] };
  const journal = await load(["hodlJournalSyncDerivedKeys"], { hodlJournalUnlocked: () => true, hodlJournalError() {} }, ["hodlJournalDoc"]);
  journal.__set.hodlJournalDoc(doc);
  const synced = journal.hodlJournalSyncDerivedKeys([{ id: 3, isLab: false, mode: "dice", diceMethod: "coldcard", name: "Key 3", fields: { dice: "1 2 3" }, result: wallet }]);
  assert.equal(synced.added, 1);
  assert.equal(doc.entries.length, 1);
  assert.equal(doc.entries[0].phrase, vector.words);
});

// Hidden, every word masks at the same width (#599), so nothing but the word
// count is needed to draw the hidden phrase, and BIP39 fixes the count by the
// entropy's length. A seed wallet keeps its entropy and seed, the two byte
// strings BIP39 defines, and the passphrase it was typed with (#546 B2 step
// 2c-3), and no other bytes about its words: their lengths would narrow each
// word to at most 555 of 2,048.
test("a seed wallet keeps its entropy, seed and passphrase and no other bytes", async () => {
  for (const [label, vector, wallet] of await wallets()) {
    const bytes = Object.keys(wallet).filter((key) => ArrayBuffer.isView(wallet[key])).sort();
    assert.deepEqual(bytes, ["entropy", "passphrase", "seed"], `${label}: the wallet keeps other bytes`);
    assert.equal(wallet.entropy.length * 3 / 4, vector.words.split(" ").length, `${label}: BIP39's word count from the entropy`);
  }
});

// The bytes are recorded by the derivation that made them, so one that never
// commits zeroes them with its row keys (hodlSettleDerivationKeys).
test("a seed wallet's bytes are recorded by the derivation that makes them", async () => {
  const api = await load(["hodlMnemonicWalletWithProgress", "hodlSettleDerivationKeys", "hodlActiveDerivation"], { hodlLiveWalletResults: () => new Set(), hodlKeyManagerPending: [] }, ["hodlActiveDerivation"]);
  const control = { kind: "key", cancelled: false, rowKeys: [], nodes: [] };
  api.__set.hodlActiveDerivation(control);
  const vector = VECTORS[0], wallet = await api.hodlMnemonicWalletWithProgress(vector.words, vector.pass, "mainnet", 2, undefined, 0, 0, tracker, 84, 0);
  for (const name of ["entropy", "seed"]) assert.ok(control.rowKeys.includes(wallet[name]), `the derivation did not record the ${name}`);
  api.hodlSettleDerivationKeys(control);
  for (const name of ["entropy", "seed"]) assert.ok(wallet[name].every((byte) => byte === 0), `an uncommitted wallet kept its ${name}`);
});
