// Custom derivation path parsing and the numeric bounds check shared by the
// purpose/coin-type/account/branch/address fields. These guard every
// derivation the app runs: an index past 2^31-1 or a mis-parsed hardened
// marker would derive a different wallet than the user asked for.
// Run with `npm test`.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = dirname(fileURLToPath(import.meta.url));
const app = readFileSync(join(root, "..", "src/js/app.js"), "utf8");

function loadSlice(name) {
  const start = app.indexOf(`function ${name}(`);
  assert.ok(start >= 0, name);
  let depth = 0;
  for (let index = app.indexOf("{", start); index < app.length; index++) {
    if (app[index] === "{") depth++;
    else if (app[index] === "}" && --depth === 0) return app.slice(start, index + 1);
  }
  throw new Error(`Could not extract ${name}`);
}

const api = new Function(
  `
  ${["hodlPathComponent", "hodlOriginPathComponent", "hodlParseCustomDerivationPath", "hodlParseDerivationIndexText", "hodlSanitizeDerivationIndexDraft", "hodlReadDerivationIndex"].map(loadSlice).join("\n")}
  return { hodlPathComponent, hodlOriginPathComponent, hodlParseCustomDerivationPath, hodlSanitizeDerivationIndexDraft, hodlReadDerivationIndex };
  `,
)();

const { hodlParseCustomDerivationPath, hodlSanitizeDerivationIndexDraft, hodlReadDerivationIndex } = api;

test("custom paths parse into components, display path, and origin path", () => {
  assert.deepEqual(hodlParseCustomDerivationPath("m"), { components: [], path: "m", originPath: "", hasHardened: false });
  assert.deepEqual(hodlParseCustomDerivationPath("  m/0  "), {
    components: [{ index: 0, hardened: false }],
    path: "m/0",
    originPath: "0",
    hasHardened: false,
  });
  const parsed = hodlParseCustomDerivationPath("m/44'/0'/3'/1/5");
  assert.equal(parsed.path, "m/44'/0'/3'/1/5");
  assert.equal(parsed.originPath, "44h/0h/3h/1/5", "origin paths render h, never '");
  assert.equal(parsed.hasHardened, true);
  // h, H, and ' all mean hardened.
  for (const marker of ["h", "H", "'"]) {
    const [component] = hodlParseCustomDerivationPath(`m/7${marker}`).components;
    assert.equal(component.hardened, true, marker);
    assert.equal(component.index, 7, marker);
  }
  assert.equal(hodlParseCustomDerivationPath("m/1/2").hasHardened, false);
  // Leading zeros normalize away in the rendered path.
  assert.equal(hodlParseCustomDerivationPath("m/01/002").path, "m/1/2");
  assert.equal(hodlParseCustomDerivationPath("m/2147483647").components[0].index, 2147483647);
});

test("custom paths reject malformed shapes and out-of-range indexes", () => {
  for (const bad of ["", "M/0", "x/0", "m/", "m//1", "m/0/", "m/0''", "m/0hh", "m/-1", "m/1.5", "m/0x10", "m/abc", "m/0/ 1"]) {
    assert.throws(() => hodlParseCustomDerivationPath(bad), undefined, JSON.stringify(bad));
  }
  assert.throws(() => hodlParseCustomDerivationPath(""), /must start with m/);
  assert.throws(() => hodlParseCustomDerivationPath("m/2147483648"), /whole number from 0 to 2,147,483,647/);
  // A number beyond the safe-integer range passes the digit regex but must not parse.
  assert.throws(() => hodlParseCustomDerivationPath("m/99999999999999999999"), /whole number from 0 to 2,147,483,647/);
  assert.throws(() => hodlParseCustomDerivationPath("m/9007199254740991"), /whole number/);
});

test("derivation indexes accept whole numbers 0 to 2,147,483,647", () => {
  assert.equal(hodlReadDerivationIndex({ value: "0" }, "Index", false), 0);
  assert.equal(hodlReadDerivationIndex({ value: "2147483647" }, "Index", false), 2147483647);
  assert.equal(hodlReadDerivationIndex({ value: " 42 " }, "Index", false), 42, "surrounding whitespace is trimmed");
  for (const bad of ["", "1.5", "-1", "2147483648", "abc", "0x10", "1e3", "99999999999999999999", null, undefined]) {
    assert.throws(() => hodlReadDerivationIndex({ value: bad }, "Branch", false), /Branch must be a whole number from 0 to 2,147,483,647\./, String(bad));
  }
});

test("derivation index drafts allow digits followed by at most one hardening marker", () => {
  assert.equal(hodlSanitizeDerivationIndexDraft("84''12"), "84'");
  assert.equal(hodlSanitizeDerivationIndexDraft("8h4"), "8'");
  assert.equal(hodlSanitizeDerivationIndexDraft("H42"), "'");
  assert.equal(hodlSanitizeDerivationIndexDraft("12abc"), "12");
  assert.equal(hodlSanitizeDerivationIndexDraft(""), "");
});

test("the bounds check marks the offending field when asked", () => {
  const marks = [];
  const input = {
    value: "nope",
    classList: { toggle: (name, on) => marks.push(["toggle", name, on]) },
    setAttribute: (name, value) => marks.push(["attr", name, value]),
  };
  assert.throws(() => hodlReadDerivationIndex(input, "Account", true));
  assert.deepEqual(marks, [
    ["toggle", "bad", true],
    ["attr", "aria-invalid", "true"],
  ]);
  marks.length = 0;
  input.value = "12";
  assert.equal(hodlReadDerivationIndex(input, "Account", true), 12);
  assert.deepEqual(marks, [
    ["toggle", "bad", false],
    ["attr", "aria-invalid", "false"],
  ]);
});

test("a custom coin type warns that mainnet version bytes are used (issue #357)", () => {
  // hodlNetworkFromCoinType silently maps every non-1 coin type to mainnet
  // serialization; the derived wallet must carry a blocking warning so the
  // format is never mistaken for the intended coin's.
  const api2 = new Function(
    "hodlHDKey", "hodlBase58Check", "hodlExtendedKeyVersions", "hodlNote",
    `${["hodlNetworkFamily", "hodlCoinTypeFromNetwork", "hodlNetworkFromCoinType", "hodlReadExtendedKeyVersion", "hodlReversionExtendedKey", "hodlSerializeExtendedKey", "hodlRootWalletResult"].map(loadSlice).join("\n")}
     var hodlError = (k) => new Error(k);
     return { hodlRootWalletResult, hodlNetworkFromCoinType };`,
  )(
    null,
    { decode: () => new Uint8Array(78), encode: () => "xkey-stub" },
    { mainnet: { x: { prv: 0, pub: 0, prvName: "xprv", pubName: "xpub" } }, testnet: { x: { prv: 0, pub: 0, prvName: "tprv", pubName: "tpub" } } },
    (key, vars) => ({ key, vars }),
  );
  const rootStub = { privateKey: null, publicExtendedKey: "xpub-stub" };
  const source = { mnemonic: null, passphraseUsed: false, passphrase: "", entropyHex: null, seedHex: null, notes: [], warnings: [] };
  const custom = api2.hodlRootWalletResult(rootStub, "mainnet", source, 0, "00000000", [], 145);
  assert.ok(custom.warnings.some((note) => note.key.includes("not Bitcoin mainnet (0) or testnet (1)")), "custom coin type produced no mainnet-serialization warning");
  for (const coinType of [0, 1]) {
    const result = api2.hodlRootWalletResult(rootStub, coinType === 1 ? "testnet" : "mainnet", source, 0, "00000000", [], coinType);
    assert.ok(!result.warnings.length, `coin type ${coinType} must not warn`);
  }
  // The mapping itself is unchanged: 0 mainnet, 1 testnet, anything else
  // mainnet serialization — now loudly disclosed at the output.
  assert.equal(api2.hodlNetworkFromCoinType(145), "mainnet");
});
