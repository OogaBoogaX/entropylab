// #546 B2 step 2c-3: a wallet keeps no copy of a typed secret as text. What
// the user typed or pasted (the BIP39 passphrase, a Casascius mini key, an
// account-level extended private key) used to be copied into the wallet as
// strings for the whole session, and strings cannot be erased, so Wipe never
// reached them. The passphrase and the mini key are now kept as their UTF-8
// bytes and a pasted key only as the account's key node. Each is rebuilt as
// text only to show or export it. (The Key Station form's own copies of the
// input are B3.)
//
// Expected values: the typed inputs themselves; the published BIP39 (Trezor)
// and BIP84 vectors; the Bitcoin wiki's mini key; and the testnet account
// keys from @scure/bip32 with the SLIP-0132 versions.
// Run with `npm test`.
import { test } from "node:test";
import assert from "node:assert/strict";
import { HDKey as ScureHDKey } from "@scure/bip32";
import { mnemonicToSeedSync } from "@scure/bip39";
import { createBase58check } from "@scure/base";
import { sha256 } from "@noble/hashes/sha2.js";
import { renderSVG } from "uqr";
import { loadAppFunctions } from "./app-slice-harness.mjs";

const utf8 = (text) => new TextEncoder().encode(text);
// BIP39 vector (trezor/python-mnemonic vectors.json) with its passphrase, and
// two more passphrases: one longer than the 12-character mask floor, and one
// with accents, a combining mark, CJK and characters outside the BMP, kept
// exactly as typed (BIP39 normalizes only for the seed).
const WORDS = "legal winner thank year wave sausage worth useful legal winner thank yellow";
const PASSPHRASES = ["TREZOR", "correct horse battery staple", "Grüße, 東京! cafe\u0301 🔑🌕 naïve"];
// Bitcoin wiki, "Mini private key format": the Casascius example.
const MINI = "S6c56bnXQiBjk9mqSYE7ykVQ7NzrRy";
// BIP84's published account key for the "abandon … about" mnemonic, and the
// same account on testnet (m/84'/1'/0') under the SLIP-0132 versions.
const MNEMONIC = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const BIP84_ACCOUNT_ZPRV = "zprvAdG4iTXWBoARxkkzNpNh8r6Qag3irQB8PzEMkAFeTRXxHpbF9z4QgEvBRmfvqWvGp42t42nvgGpNgYSJA9iefm1yYNZKEm7z6qUWCroSQnE";
const b58 = createBase58check(sha256);
const reversion = (text, version) => {
  const raw = Uint8Array.from(b58.decode(text));
  new DataView(raw.buffer).setUint32(0, version);
  return b58.encode(raw);
};
const scureRoot = ScureHDKey.fromMasterSeed(mnemonicToSeedSync(MNEMONIC));
const mainAccount = scureRoot.derive("m/84'/0'/0'"), testAccount = scureRoot.derive("m/84'/1'/0'");
// [label, pasted text, network, coin type, prefix, Core export]
const PASTED = [
  ["mainnet zprv", BIP84_ACCOUNT_ZPRV, "mainnet", 0, "zprv", reversion(mainAccount.privateExtendedKey, 0x0488ade4)],
  ["mainnet xprv", reversion(mainAccount.privateExtendedKey, 0x0488ade4), "mainnet", 0, "xprv", null],
  ["testnet vprv", reversion(testAccount.privateExtendedKey, 0x045f18bc), "testnet", 1, "vprv", reversion(testAccount.privateExtendedKey, 0x04358394)],
  ["regtest vprv", reversion(testAccount.privateExtendedKey, 0x045f18bc), "regtest", 1, "vprv", reversion(testAccount.privateExtendedKey, 0x04358394)],
];

// The slices carry page-boot statements that run once at load; give them
// inert stand-ins there.
const inert = new Proxy(function () {}, { get: (target, key) => key === Symbol.toPrimitive ? () => "" : key === "then" ? undefined : inert, apply: () => inert, construct: () => inert });
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
const api = await load(["hodlMnemonicWalletWithProgress", "hodlImportedWalletWithProgress", "hodlSingleKeyWallet", "hodlSettleDerivationKeys", "hodlWipeWalletKeys", "hodlActiveDerivation"],
  { hodlLiveWalletResults: () => new Set(), hodlKeyManagerPending: [] }, ["hodlActiveDerivation"]);
const seedWallet = (pass) => api.hodlMnemonicWalletWithProgress(WORDS, pass, "mainnet", 2, undefined, 0, 0, tracker, 84, 0);
const miniWallet = () => api.hodlSingleKeyWallet(MINI, "mainnet", "minikey");
const pastedWallet = ([, text, network, coin]) => api.hodlImportedWalletWithProgress(text, network, 2, 0, 0, tracker, 84, coin);
const wallets = async () => [
  ...await Promise.all(PASSPHRASES.map(async (pass) => [`passphrase "${pass.slice(0, 8)}…"`, await seedWallet(pass), pass])),
  ["mini key", miniWallet(), MINI],
  ...await Promise.all(PASTED.map(async (entry) => [`pasted ${entry[0]}`, await pastedWallet(entry), entry[1]])),
];
const stringsIn = (value, seen = new Set(), out = []) => {
  if (typeof value === "string") out.push(value);
  else if (value && typeof value === "object" && !ArrayBuffer.isView(value) && !seen.has(value)) {
    seen.add(value);
    for (const key of Object.keys(value)) stringsIn(value[key], seen, out);
  }
  return out;
};
// Whether a result still yields the typed secret: as text anywhere in it, as
// bytes that still spell it, or (a pasted key) as a key node that still
// serializes to it.
const yields = (result, secret) => {
  let found = stringsIn(result).some((text) => text.includes(secret));
  const seen = new Set(), walk = (value) => {
    if (ArrayBuffer.isView(value)) found ||= new TextDecoder().decode(value) === secret;
    else if (value && typeof value === "object" && !seen.has(value)) {
      seen.add(value);
      if (value.privateNode?.privateKey) found ||= [0x0488ade4, 0x04b2430c, 0x04358394, 0x045f18bc].some((version) => reversion(value.privateNode.privateExtendedKey, version) === secret);
      for (const key of Object.keys(value)) walk(value[key]);
    }
  };
  walk(result);
  return found;
};

test("the oracles agree with the published vectors", () => {
  assert.equal(reversion(mainAccount.privateExtendedKey, 0x04b2430c), BIP84_ACCOUNT_ZPRV);
  assert.equal(sha256(utf8(`${MINI}?`))[0], 0, "the mini key's check byte");
  assert.deepEqual(PASSPHRASES.map((pass) => Array.from(pass).length), [6, 28, 25], "characters, as the hidden mask counts them");
});

test("a wallet keeps no copy of a typed secret as text", async () => {
  const leaking = (await wallets()).filter(([, result, secret]) => stringsIn(result).some((text) => text.includes(secret))).map(([label]) => label);
  assert.deepEqual(leaking, [], "these wallets keep the typed secret as text");
});

test("the passphrase and the mini key are kept as their UTF-8 bytes", async () => {
  for (const pass of PASSPHRASES) assert.deepEqual([...(await seedWallet(pass)).passphrase], [...utf8(pass)], `passphrase "${pass}"`);
  assert.deepEqual([...miniWallet().minikey], [...utf8(MINI)], "mini key");
  // Bitcoin wiki, "Wallet import format": a WIF has no mini key.
  for (const kept of [(await seedWallet("")).passphrase, (await pastedWallet(PASTED[0])).passphrase, api.hodlSingleKeyWallet("5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ", "mainnet", "wif").minikey])
    assert.ok(!kept?.length, "a wallet with nothing typed keeps nothing");
});

test("the typed secrets are rebuilt on request, as typed", async () => {
  const helpers = await load(["hodlResultPassphrase", "hodlResultMinikey", "hodlImportedPrivateKey", "hodlResultHasImportedPrivate"]);
  for (const pass of PASSPHRASES) assert.equal(helpers.hodlResultPassphrase(await seedWallet(pass)), pass);
  assert.equal(helpers.hodlResultPassphrase(await seedWallet("")), "");
  assert.equal(helpers.hodlResultMinikey(miniWallet()), MINI);
  for (const entry of PASTED) {
    const wallet = await pastedWallet(entry);
    assert.equal(helpers.hodlResultHasImportedPrivate(wallet), true, entry[0]);
    assert.equal(helpers.hodlImportedPrivateKey(wallet), entry[1], `${entry[0]}: as pasted`);
    assert.equal(wallet.importedPrivateLabel, entry[4], `${entry[0]}: prefix`);
  }
  const watchOnly = await api.hodlImportedWalletWithProgress(mainAccount.publicExtendedKey, "mainnet", 2, 0, 0, tracker, 84, 0);
  for (const wallet of [watchOnly, await seedWallet("TREZOR")]) {
    assert.equal(helpers.hodlResultHasImportedPrivate(wallet), false);
    assert.equal(helpers.hodlImportedPrivateKey(wallet), null);
  }
});

// The revealed passphrase is recovery material: typed into any BIP39 tool
// with the words, it must recover this wallet. A leading U+FEFF is part of
// the passphrase (BIP39 hashes it), so decoding its bytes must not drop it as
// a byte-order mark (Codex, #601). An unpaired surrogate is not a Unicode
// character, so it cannot be hashed as itself: the page's UTF-8 encoding
// derives the seed with U+FFFD in its place (@scure/bip39 refuses such a
// passphrase outright), and the revealed text shows that U+FFFD, which
// recovers the same wallet.
test("the revealed passphrase is exactly what the wallet was derived with", async () => {
  const helpers = await load(["hodlResultPassphrase"]);
  // [typed, the passphrase the seed hashes]
  const cases = [
    ["\uFEFFTREZOR", "\uFEFFTREZOR"], ["\uFEFF", "\uFEFF"], ["\uFEFF\uFEFFTREZOR", "\uFEFF\uFEFFTREZOR"], ["TREZOR\uFEFF", "TREZOR\uFEFF"],
    // A wallet once derived from a lone surrogate (hashed as U+FFFD) is
    // still recovered by typing the U+FFFD the page used to reveal.
    ["\uFFFDTREZOR", "\uFFFDTREZOR"],
  ];
  // The old page hashed the salt as TextEncoder bytes, which are identical for
  // "\uD800TREZOR" and "\uFFFDTREZOR", so the U+FFFD case above is that old wallet.
  assert.deepEqual(new TextEncoder().encode("mnemonic\uD800TREZOR"), new TextEncoder().encode("mnemonic\uFFFDTREZOR"));
  // A lone surrogate itself is refused: it has no UTF-8 encoding, and
  // substituting U+FFFD derived a wallet the user never typed.
  await assert.rejects(() => seedWallet("\uD800TREZOR"), /Invalid passphrase/);
  const rootOf = (pass) => ScureHDKey.fromMasterSeed(mnemonicToSeedSync(WORDS, pass)).privateExtendedKey;
  const wrong = [];
  for (const [typed, hashed] of cases) {
    const wallet = await seedWallet(typed), revealed = helpers.hodlResultPassphrase(wallet), name = JSON.stringify(typed);
    assert.equal(wallet.rootNode.privateExtendedKey, rootOf(hashed), `${name}: the wallet's root`);
    if (revealed !== hashed) wrong.push(`${name}: shows ${JSON.stringify(revealed)}`);
    else if (rootOf(revealed) !== wallet.rootNode.privateExtendedKey) wrong.push(`${name}: the shown passphrase recovers a different wallet`);
  }
  assert.deepEqual(wrong, []);
  // A leading U+FEFF changes the wallet, so dropping it is not cosmetic.
  assert.notEqual(rootOf("\uFEFFTREZOR"), rootOf("TREZOR"));
  assert.notEqual(rootOf("\uFEFF"), rootOf(""));
});

// Hidden, each field is a mask as long as the value (a passphrase shows the
// fixed placeholder, whatever its length) and revealed it is the value, both
// rendered with the unchanged private-field primitive around the independently
// known text. (The full card
// is covered by the rendered page comparison against rock, which the PR
// records.)
test("the passphrase, the pasted key and the card render the same, hidden and revealed", async () => {
  const view = await load(["hodlSeedRecoveryFields", "hodlSlip132Fields", "hodlHdWalletData", "hodlPrivateFieldHtml"],
    // The QR renderer is the uqr package, which the slice loader does not import;
    // the save controls are the card's own, not under test.
    { hodlUqrRenderSvg: renderSVG, hodlKeyGroupsOpen: () => new Set(), hodlPrivateDataControls: () => "", hodlSaveRecoveryControl: () => "" }, ["hodlRevealPrivate"]);
  for (const revealed of [false, true]) {
    view.__set.hodlRevealPrivate(revealed);
    const state = revealed ? "revealed" : "hidden", field = (label, value) => view.hodlPrivateFieldHtml(label, value, undefined, "label");
    // A leading U+FEFF is part of the passphrase and shows as typed.
    for (const pass of [...PASSPHRASES, "\uFEFFTREZOR", "\uFEFF"]) {
      const fields = view.hodlSeedRecoveryFields(await seedWallet(pass));
      assert.equal(fields[2], field("BIP39 passphrase", revealed ? pass : ""), `${state}: passphrase "${pass}"`);
    }
    for (const entry of PASTED) {
      const [label, text, , , prefix, core] = entry, wallet = await pastedWallet(entry);
      const accountFields = view.hodlSlip132Fields(wallet.accounts[0], wallet, true);
      assert.equal(accountFields.includes(text), revealed, `${state}: ${label} pasted key visibility`);
      if (core) assert.equal(accountFields.includes(core), revealed, `${state}: ${label} account key visibility`);
      const card = view.hodlHdWalletData(wallet), imported = field(`Imported ${prefix}`, text);
      assert.equal(card.split(imported).length, 2, `${state}: ${label} card shows the pasted key once`);
    }
  }
});

test("the recovery sheet carries the mini key and the pasted key only when private material is saved", async () => {
  const { hodlRecoverySheetText } = await load(["hodlRecoverySheetText"]);
  const mini = miniWallet();
  assert.ok(hodlRecoverySheetText(mini, true).includes(MINI), "private sheet: mini key");
  assert.ok(!hodlRecoverySheetText(mini, false).includes(MINI), "watch-only sheet: mini key");
  for (const entry of PASTED) {
    const wallet = await pastedWallet(entry);
    // The account's own lines carry its keys too; the pasted key is also the
    // imported key's own line.
    assert.ok(hodlRecoverySheetText(wallet, true).split("\n").includes(entry[1]), `private sheet: ${entry[0]}`);
    assert.ok(!hodlRecoverySheetText(wallet, false).includes(entry[1]), `watch-only sheet: ${entry[0]}`);
  }
  // The passphrase is never printed.
  const seed = await seedWallet("TREZOR");
  for (const reveal of [true, false]) assert.ok(!hodlRecoverySheetText(seed, reveal).includes("TREZOR"), `sheet (${reveal ? "private" : "watch-only"}): passphrase`);
});

// PSBT Station still refuses a pasted account key as its session key (it
// cannot infer the key's origin), and still takes a seed wallet's root.
test("PSBT Station still refuses a pasted account key", async () => {
  for (const entry of PASTED) {
    const psbt = await load(["hodlUseActiveKeyForPsbt", "hodlPsbtHd", "hodlPsbtPriv"], { hodlPsbtWipeMem() {} });
    const state = { id: 3, name: "Key 3", fields: {}, result: await pastedWallet(entry) };
    assert.throws(() => psbt.hodlUseActiveKeyForPsbt(state), undefined, `${entry[0]}: loaded as a session key`);
    assert.equal(psbt.hodlPsbtHd ?? psbt.hodlPsbtPriv ?? null, null, `${entry[0]}: left a session key`);
  }
  const psbt = await load(["hodlUseActiveKeyForPsbt", "hodlPsbtHd"], { hodlPsbtWipeMem() {} });
  psbt.hodlUseActiveKeyForPsbt({ id: 4, name: "Key 4", fields: { pass: "TREZOR" }, result: await seedWallet("TREZOR") });
  assert.equal(psbt.hodlPsbtHd.privateExtendedKey, ScureHDKey.fromMasterSeed(mnemonicToSeedSync(WORDS, "TREZOR")).privateExtendedKey, "a seed wallet's session root");
});

// The copies are recorded by the derivation that made them, so one that never
// commits drops them with its row keys (hodlSettleDerivationKeys), and a
// dropped wallet loses them with its keys (hodlWipeWalletKeys).
test("a wallet's typed copies go with its keys, committed or not", async () => {
  const builds = [
    ["passphrase", () => seedWallet("TREZOR"), "TREZOR"],
    ["mini key", async () => miniWallet(), MINI],
    ...PASTED.map((entry) => [`pasted ${entry[0]}`, () => pastedWallet(entry), entry[1]]),
  ];
  const kept = [];
  for (const [label, build, secret] of builds) {
    const control = { kind: "key", cancelled: false, rowKeys: [], nodes: [] };
    api.__set.hodlActiveDerivation(control);
    const uncommitted = await build();
    assert.ok(yields(uncommitted, secret), `${label}: the fresh wallet cannot rebuild its typed secret`);
    api.hodlSettleDerivationKeys(control);
    if (yields(uncommitted, secret)) kept.push(`${label}, uncommitted`);
    api.__set.hodlActiveDerivation(null);
    const dropped = await build();
    api.hodlWipeWalletKeys(dropped);
    if (yields(dropped, secret)) kept.push(`${label}, wiped`);
  }
  assert.deepEqual(kept, [], "these wallets still yield their typed secret");
});
