// Private-key acceptance path: kind detection, incremental keyboard prefix
// predicates, Casascius minikeys, WIF/hex assertion, and the per-kind input
// analysis that drives the UI status line. Until now this logic was only
// source-matched; a regression in it either rejects valid recovery keys or —
// worse — accepts malformed input and derives the wrong wallet silently.
//
// The slice keeps app.js's own import statements (pointed at src/) so the
// tests run the app's real crypto facades, never stand-ins (see
// msig-address-kinds.test.mjs for why that matters).
// Run with `npm test`.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, unlinkSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const app = readFileSync(join(root, "src/js/app.js"), "utf8");

function slice(name) {
  const start = app.indexOf(`function ${name}(`);
  assert.ok(start >= 0, name);
  let depth = 0;
  for (let index = app.indexOf("{", start); index < app.length; index++) {
    if (app[index] === "{") depth++;
    else if (app[index] === "}" && --depth === 0) return app.slice(start, index + 1);
  }
  throw new Error(`Could not extract ${name}`);
}

// app.js's own import statements, with the module specifiers pointed at src/.
function importLine(module) {
  const match = app.match(new RegExp(`^import \\{[^}]*\\} from "\\./${module}\\.js";$`, "m"));
  assert.ok(match, `import from ./${module}.js`);
  return match[0].replace(`"./${module}.js"`, `"../src/js/${module}.js"`);
}

// The WIF codec (hodlBase58Check) and the secp256k1 group order (ff) live in one var
// statement; keep the app's own declarations rather than restating them.
const srStart = app.indexOf("var hodlBase58Check = ");
assert.ok(srStart >= 0, "var hodlBase58Check declaration");
const srEnd = app.indexOf(";\n", srStart);
assert.ok(srEnd > srStart, "var hodlBase58Check statement end");

const source = [
  importLine("hashes"),
  importLine("secp256k1"),
  importLine("coders"),
  importLine("base58"),
  app.slice(srStart, srEnd + 1),
  ...[
    "hodlDecodeWif",
    "hodlAssertPrivateKey",
    "hodlIsMiniKey",
    "hodlDecodeMiniKey",
    "hodlBrainWalletPassphrase",
    "hodlDecodeMiniPrivateKey",
    "hodlDetectPrivateKeyKind",
    "hodlNormalizePrivateKeyKind",
    "hodlHexPrivateKeyPrefix",
    "hodlWifPrivateKeyPrefix",
    "hodlMiniPrivateKeyPrefix",
    "hodlAssertPrivateKeyKind",
    "hodlPrivateKeyCharacterEntries",
    "hodlPrivateKeyInputAnalysis",
  ].map(slice),
  "export { hodlDetectPrivateKeyKind, hodlNormalizePrivateKeyKind, hodlHexPrivateKeyPrefix, hodlWifPrivateKeyPrefix, hodlMiniPrivateKeyPrefix, hodlDecodeMiniPrivateKey, hodlAssertPrivateKeyKind, hodlPrivateKeyCharacterEntries, hodlPrivateKeyInputAnalysis };",
].join("\n");

const modulePath = join(root, "test", `.private-key-inputs-${process.pid}.mjs`);
writeFileSync(modulePath, source);
let api;
try {
  api = await import(pathToFileURL(modulePath).href);
} finally {
  unlinkSync(modulePath);
}
const {
  hodlDetectPrivateKeyKind,
  hodlNormalizePrivateKeyKind,
  hodlHexPrivateKeyPrefix,
  hodlWifPrivateKeyPrefix,
  hodlMiniPrivateKeyPrefix,
  hodlDecodeMiniPrivateKey,
  hodlAssertPrivateKeyKind,
  hodlPrivateKeyCharacterEntries,
  hodlPrivateKeyInputAnalysis,
} = api;

// Fixed public vectors. The WIFs and minikeys all wrap the private key 1
// (except the wiki minikeys, whose digests are published); nothing is secret.
const KEY1_HEX = `${"0".repeat(63)}1`;
const WIF = {
  mainnetUncompressed: "5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAnchuDf",
  mainnetCompressed: "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn",
  testnetUncompressed: "91avARGdfge8E4tZfYLoxeJ5sGBdNJQH4kvjJoQFacbgwmaKkrx",
  testnetCompressed: "cMahea7zqjxrtgAbB7LSGbcQUr1uX1ojuat9jZodMN87JcbXMTcA",
};
// The two canonical examples from the Bitcoin wiki's "Mini private key format".
const MINIKEY_30 = "S6c56bnXQiBjk9mqSYE7ykVQ7NzrRy";
const MINIKEY_30_PRIV = "4c7a9640c72dc2099f23715d0c8a0d8a35f8906e3cab61dd3f78b67bf887c9ab";
const MINIKEY_22 = "SzavMBLoXU6kDrqtUVmffv";
const MINIKEY_22_PRIV = "e9873d79c6d87dc0fb6a5778633389f4453213303da61f20bd67fc233aa33262";
const MINIKEY_TAMPERED = "S6c56bnXQiBjk9mqSYE7ykVQ7NzrRz";

const hexOf = (bytes) => Buffer.from(bytes).toString("hex");

test("kind detection classifies minikey, WIF, and hex by shape only", () => {
  assert.equal(hodlDetectPrivateKeyKind(MINIKEY_22), "minikey");
  assert.equal(hodlDetectPrivateKeyKind(MINIKEY_30), "minikey");
  // Detection is deliberately shape-only; the checksum gate is downstream.
  assert.equal(hodlDetectPrivateKeyKind(MINIKEY_TAMPERED), "minikey");
  for (const wif of Object.values(WIF)) assert.equal(hodlDetectPrivateKeyKind(wif), "wif", wif);
  assert.equal(hodlDetectPrivateKeyKind(KEY1_HEX), "hex-key");
  assert.equal(hodlDetectPrivateKeyKind(`0x${KEY1_HEX}`), "hex-key");
  assert.equal(hodlDetectPrivateKeyKind(`0X${KEY1_HEX.toUpperCase()}`), "hex-key");
  // Whitespace inside a hex key is ignored for detection (it is stripped).
  assert.equal(hodlDetectPrivateKeyKind(`  ${KEY1_HEX.slice(0, 32)} ${KEY1_HEX.slice(32)}  `), "hex-key");
  // Whitespace inside a minikey or WIF is not.
  assert.equal(hodlDetectPrivateKeyKind(`${MINIKEY_30.slice(0, 15)} ${MINIKEY_30.slice(15)}`), null);
  assert.equal(hodlDetectPrivateKeyKind("0".repeat(63)), null);
  assert.equal(hodlDetectPrivateKeyKind("0".repeat(65)), null);
  assert.equal(hodlDetectPrivateKeyKind("5HpHag"), null);
  assert.equal(hodlDetectPrivateKeyKind(""), null);
  assert.equal(hodlDetectPrivateKeyKind("hello there"), null);
});

test("kind normalization resolves wif-or-hex from the value and defaults to wif", () => {
  assert.equal(hodlNormalizePrivateKeyKind("wif-or-hex", KEY1_HEX), "hex-key");
  assert.equal(hodlNormalizePrivateKeyKind("wif-or-hex", WIF.mainnetCompressed), "wif");
  assert.equal(hodlNormalizePrivateKeyKind("wif-or-hex", "garbage"), "wif");
  assert.equal(hodlNormalizePrivateKeyKind(undefined, ""), "wif");
  for (const kind of ["wif", "hex-key", "minikey", "brain"]) assert.equal(hodlNormalizePrivateKeyKind(kind), kind);
  assert.equal(hodlNormalizePrivateKeyKind("bogus"), "wif");
});

test("hex prefix predicate tracks viability and validates the completed key", () => {
  for (const prefix of ["", "0", "0x", "0X", "0x1aB", KEY1_HEX.slice(0, 63)]) {
    assert.equal(hodlHexPrivateKeyPrefix(prefix), true, JSON.stringify(prefix));
  }
  // A bare x, a doubled prefix, or a stray x in the body can never become hex.
  for (const bad of ["x1", "1x", "0xx1", "0x1x", "0xz1"]) {
    assert.equal(hodlHexPrivateKeyPrefix(bad), false, JSON.stringify(bad));
  }
  assert.equal(hodlHexPrivateKeyPrefix(KEY1_HEX), true);
  assert.equal(hodlHexPrivateKeyPrefix(`0x${KEY1_HEX}`), true);
  assert.equal(hodlHexPrivateKeyPrefix("a".repeat(64)), true, "0xAA…AA is inside the secp256k1 range");
  // The completed key is range-checked: zero and the group order are rejected.
  assert.equal(hodlHexPrivateKeyPrefix("0".repeat(64)), false);
  assert.equal(hodlHexPrivateKeyPrefix("f".repeat(64)), false);
  assert.equal(hodlHexPrivateKeyPrefix(`${KEY1_HEX}0`), false, "65 hex characters is too many");
});

test("WIF prefix predicate enforces network prefixes, length, and checksum", () => {
  assert.equal(hodlWifPrivateKeyPrefix("", "mainnet"), false);
  for (const first of ["5", "K", "L"]) assert.equal(hodlWifPrivateKeyPrefix(first, "mainnet"), true, first);
  for (const first of ["9", "c"]) assert.equal(hodlWifPrivateKeyPrefix(first, "testnet"), true, first);
  // Network crossover is rejected from the first character.
  for (const first of ["9", "c"]) assert.equal(hodlWifPrivateKeyPrefix(first, "mainnet"), false, first);
  for (const first of ["5", "K", "L"]) assert.equal(hodlWifPrivateKeyPrefix(first, "testnet"), false, first);
  assert.equal(hodlWifPrivateKeyPrefix("1", "mainnet"), false);
  assert.equal(hodlWifPrivateKeyPrefix("5Hp0", "mainnet"), false, "0 is not a Base58 character");
  // Uncompressed prefixes expect 51 characters, compressed expect 52.
  assert.equal(hodlWifPrivateKeyPrefix("5".repeat(52), "mainnet"), false, "a 5… WIF may not exceed 51");
  assert.equal(hodlWifPrivateKeyPrefix(`K${"H".repeat(51)}`, "mainnet"), false, "a K… WIF may not exceed 52");
  // Full-length candidates are checksum-verified.
  assert.equal(hodlWifPrivateKeyPrefix(WIF.mainnetUncompressed, "mainnet"), true);
  assert.equal(hodlWifPrivateKeyPrefix(WIF.mainnetCompressed, "mainnet"), true);
  assert.equal(hodlWifPrivateKeyPrefix(WIF.testnetUncompressed, "testnet"), true);
  assert.equal(hodlWifPrivateKeyPrefix(WIF.testnetCompressed, "testnet"), true);
  assert.equal(hodlWifPrivateKeyPrefix(WIF.mainnetCompressed, "testnet"), false, "mainnet WIF on the wrong network");
  assert.equal(hodlWifPrivateKeyPrefix(WIF.testnetCompressed, "mainnet"), false, "testnet WIF on the wrong network");
  assert.equal(hodlWifPrivateKeyPrefix(`${WIF.mainnetCompressed.slice(0, -1)}o`, "mainnet"), false, "tampered checksum");
});

test("minikey prefix predicate gates shape and checks the completed 30-char key", () => {
  assert.equal(hodlMiniPrivateKeyPrefix(""), false);
  assert.equal(hodlMiniPrivateKeyPrefix("S"), true);
  assert.equal(hodlMiniPrivateKeyPrefix("Szav"), true);
  // A complete 22-character minikey stays prefix-viable: 30 is also allowed.
  assert.equal(hodlMiniPrivateKeyPrefix(MINIKEY_22), true);
  assert.equal(hodlMiniPrivateKeyPrefix(MINIKEY_30), true);
  assert.equal(hodlMiniPrivateKeyPrefix(MINIKEY_TAMPERED), false, "checksum byte differs");
  assert.equal(hodlMiniPrivateKeyPrefix(`${MINIKEY_30}x`), false, "31 characters is too many");
  assert.equal(hodlMiniPrivateKeyPrefix("s6c56bnXQiBjk9mqSYE7ykVQ7NzrRy"), false, "lowercase s is not a minikey");
  assert.equal(hodlMiniPrivateKeyPrefix("S0"), false, "0 is not a Base58 character");
});

test("minikey decoding matches the published wiki vectors", () => {
  assert.equal(hexOf(hodlDecodeMiniPrivateKey(MINIKEY_30)), MINIKEY_30_PRIV);
  assert.equal(hexOf(hodlDecodeMiniPrivateKey(MINIKEY_22)), MINIKEY_22_PRIV);
  assert.equal(hexOf(hodlDecodeMiniPrivateKey(`  ${MINIKEY_30}  `)), MINIKEY_30_PRIV, "surrounding whitespace is trimmed");
  assert.throws(() => hodlDecodeMiniPrivateKey(MINIKEY_TAMPERED), /Not a valid Casascius mini private key\./);
  for (const bad of [`T${MINIKEY_30.slice(1)}`, "S0".padEnd(22, "1"), MINIKEY_30.slice(0, 21), MINIKEY_30.slice(0, 23)]) {
    assert.throws(() => hodlDecodeMiniPrivateKey(bad), /Mini keys must start with S and contain 22 or 30 Bitcoin Base58 characters\./, bad);
  }
});

test("assertPrivateKeyKind normalizes hex and rejects out-of-range keys", () => {
  assert.equal(hodlAssertPrivateKeyKind(KEY1_HEX, "mainnet", "hex-key"), KEY1_HEX);
  assert.equal(hodlAssertPrivateKeyKind(`0x${KEY1_HEX.toUpperCase()}`, "mainnet", "hex-key"), KEY1_HEX);
  assert.equal(hodlAssertPrivateKeyKind(`${KEY1_HEX.slice(0, 32)} ${KEY1_HEX.slice(32)}`, "mainnet", "hex-key"), KEY1_HEX);
  assert.throws(() => hodlAssertPrivateKeyKind("0".repeat(63), "mainnet", "hex-key"), /Enter exactly 64 hexadecimal characters/);
  assert.throws(() => hodlAssertPrivateKeyKind("0".repeat(64), "mainnet", "hex-key"), /out of the secp256k1 range/);
  assert.throws(() => hodlAssertPrivateKeyKind("f".repeat(64), "mainnet", "hex-key"), /out of the secp256k1 range/);
  assert.throws(() => hodlAssertPrivateKeyKind("   ", "mainnet", "hex-key"), /Enter a private key\./);
});

test("assertPrivateKeyKind validates WIF including the network", () => {
  for (const wif of [WIF.mainnetUncompressed, WIF.mainnetCompressed]) {
    assert.equal(hodlAssertPrivateKeyKind(wif, "mainnet", "wif"), wif);
  }
  assert.equal(hodlAssertPrivateKeyKind(WIF.testnetCompressed, "testnet", "wif"), WIF.testnetCompressed);
  assert.throws(
    () => hodlAssertPrivateKeyKind(WIF.testnetCompressed, "mainnet", "wif"),
    /This WIF is for testnet; Network is set to mainnet\./,
  );
  assert.throws(
    () => hodlAssertPrivateKeyKind(WIF.mainnetCompressed, "testnet", "wif"),
    /This WIF is for mainnet; Network is set to testnet\./,
  );
  assert.throws(() => hodlAssertPrivateKeyKind(`${WIF.mainnetCompressed.slice(0, -1)}o`, "mainnet", "wif"), /Enter a valid mainnet WIF/);
});

test("assertPrivateKeyKind decodes minikeys and passes brain phrases through", () => {
  assert.equal(hodlAssertPrivateKeyKind(MINIKEY_30, "mainnet", "minikey"), MINIKEY_30);
  assert.throws(() => hodlAssertPrivateKeyKind(MINIKEY_TAMPERED, "mainnet", "minikey"), /Not a valid Casascius mini private key\./);
  assert.equal(hodlAssertPrivateKeyKind("  padded phrase  ", "mainnet", "brain", false), "  padded phrase  ");
  assert.equal(hodlAssertPrivateKeyKind("  padded phrase  ", "mainnet", "brain", true), "padded phrase");
  assert.throws(() => hodlAssertPrivateKeyKind("   ", "mainnet", "brain", true), /Trimming boundary whitespace leaves an empty/);
  assert.throws(() => hodlAssertPrivateKeyKind("", "mainnet", "brain", false), /Enter the brain-wallet recovery passphrase\./);
});

test("character entries skip whitespace and keep astral characters whole", () => {
  assert.deepEqual(hodlPrivateKeyCharacterEntries("ab cd"), [
    { character: "a", start: 0, end: 1 },
    { character: "b", start: 1, end: 2 },
    { character: "c", start: 3, end: 4 },
    { character: "d", start: 4, end: 5 },
  ]);
  assert.deepEqual(hodlPrivateKeyCharacterEntries("\u{1F600}x"), [
    { character: "\u{1F600}", start: 0, end: 2 },
    { character: "x", start: 2, end: 3 },
  ]);
  assert.deepEqual(hodlPrivateKeyCharacterEntries(""), []);
  assert.deepEqual(hodlPrivateKeyCharacterEntries("  \t\n "), []);
});

test("brain analysis reports the exact-text and trim conventions", () => {
  let analysis = hodlPrivateKeyInputAnalysis("", "brain", "mainnet", false);
  assert.equal(analysis.ready, false);
  assert.match(analysis.status, /No text entered/);
  analysis = hodlPrivateKeyInputAnalysis("correct horse battery staple", "brain", "mainnet", false);
  assert.equal(analysis.ready, true);
  assert.match(analysis.status, /exact text will be used/);
  assert.doesNotMatch(analysis.status, /including boundary whitespace/);
  analysis = hodlPrivateKeyInputAnalysis("  padded  ", "brain", "mainnet", false);
  assert.equal(analysis.ready, true);
  assert.match(analysis.status, /exact text will be used, including boundary whitespace/);
  analysis = hodlPrivateKeyInputAnalysis("  padded  ", "brain", "mainnet", true);
  assert.equal(analysis.ready, true);
  assert.match(analysis.status, /boundary whitespace will be trimmed/);
  analysis = hodlPrivateKeyInputAnalysis("   ", "brain", "mainnet", true);
  assert.equal(analysis.ready, false);
  assert.match(analysis.status, /leaves an empty passphrase/);
  // Whitespace-only is still a usable exact-text passphrase when trim is off.
  analysis = hodlPrivateKeyInputAnalysis("   ", "brain", "mainnet", false);
  assert.equal(analysis.ready, true);
});

test("hex analysis counts, flags invalid and excess characters, and gates readiness", () => {
  let analysis = hodlPrivateKeyInputAnalysis("0".repeat(63), "hex-key", "mainnet", false);
  assert.equal(analysis.count, 63);
  assert.equal(analysis.remaining, 1);
  assert.equal(analysis.ready, false);
  assert.deepEqual(analysis.invalidRanges, []);
  analysis = hodlPrivateKeyInputAnalysis(KEY1_HEX, "hex-key", "mainnet", false);
  assert.equal(analysis.ready, true);
  assert.match(analysis.status, /64 of 64 hexadecimal characters entered/);
  assert.match(analysis.status, /valid secp256k1 private key/);
  analysis = hodlPrivateKeyInputAnalysis(`0x${KEY1_HEX}`, "hex-key", "mainnet", false);
  assert.equal(analysis.ready, true, "the 0x prefix is accepted");
  analysis = hodlPrivateKeyInputAnalysis(`${"0".repeat(63)}g`, "hex-key", "mainnet", false);
  assert.deepEqual(analysis.invalidRanges, [[63, 64]]);
  assert.match(analysis.status, /1 invalid character highlighted/);
  analysis = hodlPrivateKeyInputAnalysis("1".repeat(65), "hex-key", "mainnet", false);
  assert.deepEqual(analysis.invalidRanges, [[64, 65]]);
  assert.match(analysis.status, /65 hexadecimal characters entered · 64 required/);
  analysis = hodlPrivateKeyInputAnalysis("0".repeat(64), "hex-key", "mainnet", false);
  assert.equal(analysis.ready, false);
  assert.deepEqual(analysis.invalidRanges, [[0, 64]], "a complete but out-of-range key is highlighted whole");
  assert.match(analysis.status, /out of the secp256k1 range/);
});

test("WIF analysis derives the expected length from the prefix and checks the network", () => {
  let analysis = hodlPrivateKeyInputAnalysis(WIF.mainnetUncompressed, "wif", "mainnet", false);
  assert.equal(analysis.ready, true);
  assert.match(analysis.status, /51 of 51 WIF characters entered/);
  analysis = hodlPrivateKeyInputAnalysis(WIF.mainnetCompressed, "wif", "mainnet", false);
  assert.equal(analysis.ready, true);
  assert.match(analysis.status, /52 of 52 WIF characters entered/);
  analysis = hodlPrivateKeyInputAnalysis(WIF.testnetCompressed, "wif", "testnet", false);
  assert.equal(analysis.ready, true, "testnet WIF ready on testnet");
  // A wrong-network WIF is caught at the first character: the mainnet and
  // testnet prefix sets are disjoint, so the analyzer flags the prefix rather
  // than ever reaching the decode step. The "This WIF is for …" message comes
  // from hodlAssertPrivateKeyKind on the derive path (tested directly above).
  analysis = hodlPrivateKeyInputAnalysis(WIF.testnetCompressed, "wif", "mainnet", false);
  assert.equal(analysis.ready, false);
  assert.deepEqual(analysis.invalidRanges, [[0, 1]], "the testnet c… prefix is invalid on mainnet");
  assert.match(analysis.status, /1 invalid character highlighted · use mainnet Base58 WIF characters/);
  analysis = hodlPrivateKeyInputAnalysis(`1${"A".repeat(50)}`, "wif", "mainnet", false);
  assert.equal(analysis.required, null, "an unknown first character leaves the length undecided");
  assert.deepEqual(analysis.invalidRanges, [[0, 1]]);
  assert.match(analysis.status, /starts with 5, K, or L/);
  analysis = hodlPrivateKeyInputAnalysis(`5${"H".repeat(51)}`, "wif", "mainnet", false);
  assert.deepEqual(analysis.invalidRanges, [[51, 52]], "the 52nd character of a 5… WIF is excess");
  analysis = hodlPrivateKeyInputAnalysis("K".concat("H".repeat(50)), "wif", "mainnet", false);
  assert.equal(analysis.required, 52);
  assert.equal(analysis.remaining, 1);
  analysis = hodlPrivateKeyInputAnalysis(`K${"H".repeat(50)}0`, "wif", "mainnet", false);
  assert.deepEqual(analysis.invalidRanges, [[51, 52]], "a non-Base58 character is flagged");
});

test("minikey analysis tracks the 22-or-30 length rule and the checksum", () => {
  let analysis = hodlPrivateKeyInputAnalysis("", "minikey", "mainnet", false);
  assert.equal(analysis.ready, false);
  assert.match(analysis.status, /must start with S/);
  analysis = hodlPrivateKeyInputAnalysis(MINIKEY_22, "minikey", "mainnet", false);
  assert.equal(analysis.ready, true);
  assert.match(analysis.status, /22 of 22 Mini-key characters entered/);
  analysis = hodlPrivateKeyInputAnalysis(MINIKEY_30, "minikey", "mainnet", false);
  assert.equal(analysis.ready, true);
  assert.match(analysis.status, /30 of 30 Mini-key characters entered/);
  analysis = hodlPrivateKeyInputAnalysis(`S${"1".repeat(22)}`, "minikey", "mainnet", false);
  assert.equal(analysis.required, 30, "past 22 characters only the 30 form remains");
  assert.equal(analysis.remaining, 7);
  analysis = hodlPrivateKeyInputAnalysis(`${MINIKEY_30}x`, "minikey", "mainnet", false);
  assert.deepEqual(analysis.invalidRanges, [[30, 31]], "the 31st character is excess");
  analysis = hodlPrivateKeyInputAnalysis(`T${MINIKEY_30.slice(1)}`, "minikey", "mainnet", false);
  assert.deepEqual(analysis.invalidRanges[0], [0, 1], "a non-S first character is flagged");
  analysis = hodlPrivateKeyInputAnalysis(MINIKEY_TAMPERED, "minikey", "mainnet", false);
  assert.equal(analysis.ready, false);
  assert.deepEqual(analysis.invalidRanges, [[0, 30]], "a failed checksum is highlighted whole");
});
