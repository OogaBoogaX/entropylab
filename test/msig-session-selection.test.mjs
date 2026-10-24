// Selection follows a proven session root across origin edits, never a
// fingerprint alone. Fixtures come from @scure/bip32 and the BIP39 vector.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import vm from "node:vm";
import { HDKey } from "@scure/bip32";
import { entropyToMnemonic, mnemonicToSeedSync } from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english.js";
import { hex } from "@scure/base";

const app = readFileSync(new URL("../src/js/app.js", import.meta.url), "utf8");
const mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const seed = mnemonicToSeedSync(mnemonic);
const origin = "m/48'/0'/0'/2'";
const reference = (path) => HDKey.fromMasterSeed(seed).derive(path);
const parsedAt = (path) => ({ node: reference(path), origin: { fingerprint: "73c5da0a", path: path.slice(2).replace(/'/g, "h") }, derivationPath: "" });
const state = { id: "fixture", result: { masterFingerprint: "73c5da0a", rootXprv: HDKey.fromMasterSeed(seed).privateExtendedKey } };
const option = { state, value: reference(origin).publicExtendedKey, baseId: hex.encode(reference(origin).publicKey) + ":" + hex.encode(reference(origin).chainCode) };

function harness(parsed, reuse = false, sessionState = state) {
  const sessionOption = { ...option, state: sessionState };
  const box = { buttons: [], replaceChildren() { this.buttons = []; }, appendChild(button) { this.buttons.push(button); } };
  const ta = { value: parsed ? parsed.node.publicExtendedKey : "", dispatchEvent() {} };
  const row = { parsed, querySelector(selector) { return selector === "textarea" ? ta : box; } };
  const emptyBox = { ...box, buttons: [] };
  const empty = { parsed: null, querySelector() { return emptyBox; } };
  let wipes = 0, seedBytes = null;
  const context = vm.createContext({
    document: { getElementById: () => ({ checked: reuse }), querySelectorAll: () => [row, empty] },
    Event: class {}, hodlHex: hex,
    hodlSessionMsigKeys: () => [sessionState], hodlMsigSessionKeyOption: () => sessionOption,
    hodlParseMsigRowKey: (item) => item.parsed,
    hodlMsigRowSpec: () => "bip48", hodlSyncMsigRowSpec() {}, hodlApplyMsigRowSpec() {},
    hodlCreateMsigSessionKeyButton: (entry, styling, active, unavailable, onSelect) => ({ keyId: entry.state.id, pressed: String(active), disabled: unavailable, click: onSelect }),
    hodlResultHasRoot: (result) => Boolean(result.rootXprv),
    hodlResultRootNode: (result) => {
      const root = HDKey.fromExtendedKey(result.rootXprv);
      const wipe = root.wipePrivateData.bind(root);
      root.wipePrivateData = () => { wipes++; wipe(); };
      return root;
    },
    hodlMnemonicToSeed: (words, pass) => (seedBytes = mnemonicToSeedSync(words, pass)), hodlHDKey: HDKey,
    hodlEntropyToMnemonic: entropyToMnemonic, hodlBip39Wordlist: wordlist,
    hodlWipeBytes: (bytes) => bytes?.fill(0),
    hodlEq: (a, b) => Buffer.from(a).equals(Buffer.from(b)),
  });
  for (const name of ["hodlResultHasSeed", "hodlResultMnemonic", "hodlSeedSessionRoot", "hodlMsigBaseKeyId", "hodlMsigSessionKeyMatches", "hodlMsigUsedBaseKeyIds", "hodlPickMsigSessionKey", "hodlRefreshMsigSessionPickers"]) {
    const source = app.match(new RegExp(`^function ${name}\\([^]*?^}`, "m"));
    if (source) vm.runInContext(source[0], context);
  }
  context.hodlRefreshMsigSessionPickers();
  return { box, emptyBox, ta, wipes: () => wipes, seedBytes: () => seedBytes };
}

test("session selection and click-to-remove survive account, hardening, spec and depth edits", () => {
  for (const path of [origin, "m/48'/0'/1'/2'", "m/48'/0'/1/2'", "m/87'/0'/1'", "m/0'", "m/48'/0'/1'/2'/3'"]) {
    const ui = harness(parsedAt(path));
    assert.equal(ui.box.buttons[0].pressed, "true", `selection lost at ${path}`);
    assert.equal(ui.emptyBox.buttons[0].disabled, true, `reuse enabled without opt-in at ${path}`);
    ui.box.buttons[0].click();
    assert.equal(ui.ta.value, "", `selected key was reloaded instead of removed at ${path}`);
    if (path !== origin) assert.ok(ui.wipes() > 0, "temporary root was not wiped");
    assert.equal(harness(parsedAt(path), true).emptyBox.buttons[0].disabled, false);
  }
});

test("selection refuses foreign keys, false origins and foreign chain codes under the session fingerprint", () => {
  const foreign = HDKey.fromMasterSeed(mnemonicToSeedSync("zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong")).derive("m/48'/0'/1'/2'");
  const real = parsedAt("m/48'/0'/1'/2'");
  for (const parsed of [
    { ...real, node: foreign },
    { ...real, origin: { ...real.origin, path: "48h/0h/2h/2h" } },
    { ...real, node: new HDKey({ publicKey: real.node.publicKey, chainCode: foreign.chainCode }) },
    { ...real, origin: null },
    { ...real, origin: { ...real.origin, fingerprint: "00000000" } },
    null,
  ]) {
    const ui = harness(parsed);
    assert.equal(ui.box.buttons[0].pressed, "false");
    assert.equal(ui.emptyBox.buttons[0].disabled, false);
  }
});

test("appended public paths keep the exported key selected", () => {
  assert.equal(harness({ ...parsedAt(origin), derivationPath: "1/2" }).box.buttons[0].pressed, "true");
});

test("a BIP85 mnemonic child keeps selection across path edits and wipes its temporary seed", () => {
  // A BIP-85 child's session key carries its BIP39 entropy as bytes (#546 B3):
  // the all-zero entropy, whose words are the vector above.
  const child = { id: "bip85:fixture", result: { masterFingerprint: "73c5da0a", entropy: new Uint8Array(16) } };
  assert.equal(entropyToMnemonic(child.result.entropy, wordlist), mnemonic);
  const ui = harness(parsedAt("m/87'/0'/1'"), false, child);
  assert.equal(ui.box.buttons[0].keyId, child.id);
  assert.equal(ui.box.buttons[0].pressed, "true");
  assert.equal(ui.emptyBox.buttons[0].disabled, true);
  ui.box.buttons[0].click();
  assert.equal(ui.ta.value, "");
  assert.ok(ui.seedBytes().every((byte) => byte === 0), "temporary mnemonic seed was not wiped");
});
