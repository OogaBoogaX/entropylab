// Watch-only descriptor QR payload and multisig key-origin parsing.
// Run with `npm test`.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, unlinkSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const app = readFileSync(join(root, "src/js/app.js"), "utf8");

function extract(startNeedle, endNeedle) {
  const start = app.indexOf(startNeedle);
  const end = app.indexOf(endNeedle, start);
  if (start < 0 || end < 0) throw new Error(`extract failed: ${startNeedle}`);
  return app.slice(start, end);
}

const INPUT_CHARSET =
  "0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`JKLMNOPQRSTUVWXYZ";
const CHECKSUM_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

function descsumPolymod(symbols) {
  const GEN = [0xf5dee143af, 0x119f81b3da, 0x1010f5c26, 0x1d077e62e, 0x1077d1d3ea];
  let chk = 1n;
  for (const value of symbols) {
    const top = chk >> 35n;
    chk = ((chk & 0x7ffffffffn) << 5n) ^ BigInt(value);
    for (let i = 0; i < 5; i++) if ((top >> BigInt(i)) & 1n) chk ^= BigInt(GEN[i]);
  }
  return chk;
}

function descsumExpand(s) {
  const groups = [];
  const symbols = [];
  for (const character of s) {
    const index = INPUT_CHARSET.indexOf(character);
    if (index < 0) throw new Error(`Invalid descriptor character: ${character}`);
    symbols.push(index & 31);
    groups.push(index >> 5);
    if (groups.length === 3) {
      symbols.push(groups[0] * 9 + groups[1] * 3 + groups[2]);
      groups.length = 0;
    }
  }
  if (groups.length === 1) symbols.push(groups[0]);
  else if (groups.length === 2) symbols.push(groups[0] * 9 + groups[1] * 3);
  return symbols;
}

function independentChecksum(body) {
  const symbols = descsumExpand(body).concat([0, 0, 0, 0, 0, 0, 0, 0]);
  const polymod = descsumPolymod(symbols) ^ 1n;
  let checksum = "";
  for (let i = 0; i < 8; i++) checksum += CHECKSUM_CHARSET[Number((polymod >> BigInt(5 * (7 - i))) & 31n)];
  return checksum;
}

function loadSlice(startNeedle, endNeedle, extra) {
  const path = join(root, "test", `.descriptor-slice-${Math.random().toString(16).slice(2)}.mjs`);
  writeFileSync(path, `${extra ?? ""}\n${extract(startNeedle, endNeedle)}\n`);
  return path;
}

const originPath = loadSlice(
  "function hodlFilterXpub",
  "function hodlParseMultisigCosigner",
  "const hodlMaxPurpose = 2147483647;\nconst hodlCoinTypeFromNetwork = (network) => network === 'mainnet' ? 0 : 1;\nexport { hodlFilterXpub, hodlNormalizeOriginPath, hodlParseKeyOrigin, hodlOriginPathIndexes, hodlOriginMatchesParsedKey, hodlMultisigPurposeIndex, hodlOriginScriptError, hodlMultisigAccountNumber, hodlSummarizeMultisigAccounts, hodlMultisigAccountWarning, hodlMultisigOriginScriptKind, hodlMultisigScriptEvidence, hodlSummarizeMultisigScriptKinds };",
);
const {
  hodlFilterXpub,
  hodlNormalizeOriginPath,
  hodlParseKeyOrigin,
  hodlOriginPathIndexes,
  hodlOriginMatchesParsedKey,
  hodlMultisigPurposeIndex,
  hodlOriginScriptError,
  hodlMultisigAccountNumber,
  hodlSummarizeMultisigAccounts,
  hodlMultisigAccountWarning,
  hodlMultisigOriginScriptKind,
  hodlMultisigScriptEvidence,
  hodlSummarizeMultisigScriptKinds,
} = await import(pathToFileURL(originPath).href);
unlinkSync(originPath);


const checksumPrelude = `
const INPUT_CHARSET = ${JSON.stringify(INPUT_CHARSET)};
const CHECKSUM_CHARSET = ${JSON.stringify(CHECKSUM_CHARSET)};
${descsumPolymod.toString()}
${descsumExpand.toString()}
${independentChecksum.toString()}
function hodlDescriptorWithChecksum(body){return body+"#"+independentChecksum(body)}
export { hodlStripDescriptorChecksum, hodlWatchOnlyMultipathDescriptor, hodlDescriptorWithChecksum };
`;
const multipathPath = loadSlice(
  "function hodlStripDescriptorChecksum",
  "function hodlDescriptorQrSvg",
  checksumPrelude,
);
const { hodlWatchOnlyMultipathDescriptor, hodlDescriptorWithChecksum } = await import(pathToFileURL(multipathPath).href);
unlinkSync(multipathPath);
test("filter keeps descriptor origin punctuation", () => {
  const raw = "[73c5da0a/48h/1h/0h/2h]tpubABC";
  assert.equal(hodlFilterXpub(raw), raw);
  assert.equal(hodlFilterXpub("[73c5da0a/48'/1'/0'/2']tpubABC"), "[73c5da0a/48'/1'/0'/2']tpubABC");
});

test("origin parse normalizes apostrophes and strips /0/*", () => {
  assert.equal(hodlNormalizeOriginPath("m/48'/1'/0'/2'"), "48h/1h/0h/2h");
  const parsed = hodlParseKeyOrigin(
    "[73c5da0a/48h/1h/0h/2h]tpubDFH9dgzveyD8zTbPUFuLrGmCydNvxehyNdUXKJAQN8x4aZ4j6UZqGfnqFrD4NqyaTVGKbvEW54tsvPTK2UoSbCC1PJY8iCNiwTL3RWZEheQ/0/*",
  );
  assert.equal(parsed.origin.fingerprint, "73c5da0a");
  assert.equal(parsed.origin.path, "48h/1h/0h/2h");
  assert.match(parsed.key, /^tpubDFH9/);
  assert.equal(hodlParseKeyOrigin("tpubABC").origin, null);
});

test("placeholder fingerprint 00000000 is rejected", () => {
  assert.throws(
    () => hodlParseKeyOrigin("[00000000/48h/1h/0h/2h]tpubABC"),
    /00000000/,
  );
});

test("origin path must match key depth and script", () => {
  const origin = { fingerprint: "73c5da0a", path: "48h/1h/0h/2h" };
  const mock = { depth: 4, childNumber: 0x80000002 };
  assert.equal(hodlOriginMatchesParsedKey(origin, mock), "");
  assert.match(hodlOriginMatchesParsedKey({ fingerprint: "73c5da0a", path: "48h/1h/0h" }, mock), /steps/);
  assert.equal(hodlOriginScriptError(origin, "p2wsh", "testnet", 48), "");
  assert.equal(hodlOriginScriptError({ fingerprint: "73c5da0a", path: "48h/0h/0h/2h" }, "p2wsh", "mainnet", 48), "");
  assert.match(hodlOriginScriptError({ fingerprint: "73c5da0a", path: "48h/0h/0h/2h" }, "p2wsh", "testnet", 48), /1h/);
  assert.equal(hodlOriginMatchesParsedKey({ fingerprint: "73c5da0a", path: "45h" }, { depth: 1, childNumber: 0x8000002d }), "");
  assert.equal(hodlOriginScriptError({ fingerprint: "73c5da0a", path: "45h" }, "p2sh", "mainnet", 45), "");
  assert.match(hodlOriginScriptError({ fingerprint: "73c5da0a", path: "45h/0" }, "p2sh", "mainnet", 45), /without an account/);
  const bip87 = { fingerprint: "73c5da0a", path: "87h/0h/7h" };
  assert.equal(hodlOriginMatchesParsedKey(bip87, { depth: 3, childNumber: 0x80000007 }), "");
  assert.match(
    hodlOriginScriptError({ fingerprint: "73c5da0a", path: "45h" }, "p2sh", "mainnet", 87),
    /87h/,
  );
  assert.equal(hodlOriginScriptError({ fingerprint: "73c5da0a", path: "86h/0h/0h" }, "p2tr", "mainnet", 86), "");
  assert.equal(hodlOriginScriptError({ fingerprint: "73c5da0a", path: "69420h/0h/0h" }, "p2tr", "mainnet", 69420), "");
  assert.equal(hodlOriginScriptError({ fingerprint: "73c5da0a", path: "48h/69420h/0h/2h" }, "p2wsh", "mainnet", 48, 69420), "");
  assert.match(hodlOriginScriptError({ fingerprint: "73c5da0a", path: "48h/0h/0h/2h" }, "p2wsh", "mainnet", 48, 69420), /selected coin type/);
  assert.match(hodlOriginScriptError({ fingerprint: "73c5da0a", path: "84h/0h/0h" }, "p2tr", "mainnet", 86), /selected Purpose is 86h/);
  assert.match(hodlOriginScriptError({ fingerprint: "73c5da0a", path: "86h/0h/0h/0h" }, "p2tr", "mainnet", 86), /purpose, coin type, and account/);
  assert.match(hodlOriginScriptError({ fingerprint: "73c5da0a", path: "86h/1h/0h" }, "p2tr", "mainnet", 86), /0h/);
  assert.equal(hodlOriginPathIndexes("48h/1h/0h/2h").at(-1), 0x80000002);
});
test("multisig account is derived from BIP48 and BIP87 origins", () => {
  assert.equal(hodlMultisigAccountNumber({ path: "48h/0h/7h/2h" }, "p2wsh", 48), 7);
  assert.equal(hodlMultisigAccountNumber({ path: "48h/0h/3h/1h" }, "p2sh-p2wsh", 48), 3);
  assert.equal(hodlMultisigAccountNumber({ path: "87h/0h/9h" }, "p2sh", 87), 9);
  assert.equal(hodlMultisigAccountNumber({ path: "86h/0h/4h" }, "p2tr", 86), 4);
  assert.equal(hodlMultisigAccountNumber({ path: "45h" }, "p2sh", 45), null);
  assert.throws(
    () => hodlMultisigAccountNumber({ path: "48h/0h/7/2h" }, "p2wsh", 48),
    /must be hardened/,
  );
  assert.match(hodlOriginScriptError({ path: "48h/0h/7/2h" }, "p2wsh", "mainnet", 48), /must be hardened/);
});

test("multisig account summary reports mismatched accounts as mixed", () => {
  const matching = hodlSummarizeMultisigAccounts([4, 4, 4]);
  assert.deepEqual(matching, { account: 4, accounts: [4], consistent: true, mixed: false });
  assert.equal(hodlMultisigAccountWarning(matching), "");

  const mixed = hodlSummarizeMultisigAccounts([7, 2, 7, 4]);
  assert.deepEqual(mixed, { account: null, accounts: [2, 4, 7], consistent: false, mixed: true });
  assert.match(hodlMultisigAccountWarning(mixed), /do not match \(2, 4, 7\).*shown as Mixed/);
});

test("multisig script type is inferred from SLIP-132 prefixes and key origins", () => {
  assert.equal(hodlMultisigOriginScriptKind({ path: "45h" }), "p2sh");
  // Purpose 87 is the Taproot default as well, and BIP87 account keys are
  // script-agnostic, so a bare 87h origin must not select a script type.
  assert.equal(hodlMultisigOriginScriptKind({ path: "87h/0h/0h" }), null);
  assert.equal(hodlMultisigOriginScriptKind({ path: "48h/0h/0h/1h" }), "p2sh-p2wsh");
  assert.equal(hodlMultisigOriginScriptKind({ path: "48h/0h/0h/2h" }), "p2wsh");
  assert.equal(hodlMultisigOriginScriptKind({ path: "86h/0h/0h" }), "p2tr");
  assert.equal(hodlMultisigOriginScriptKind({ path: "48h/0h/0h/3h" }), null);
  assert.equal(hodlMultisigOriginScriptKind({ path: "84h/0h/0h" }), null);
  assert.equal(hodlMultisigPurposeIndex({ path: "45h" }), 45);
  assert.equal(hodlMultisigPurposeIndex({ path: "69420h/0h/0h/2h" }), 69420);
  assert.equal(hodlMultisigPurposeIndex({ path: "48/0h/0h/2h" }), 48);
  assert.equal(
    hodlOriginScriptError(
      { path: "48/0/0/2h" },
      "p2wsh",
      "mainnet",
      48,
      0,
      { purpose: false, coinType: false, account: false, address: false },
    ),
    "",
  );

  assert.deepEqual(
    hodlMultisigScriptEvidence({ scope: "multisig", family: "y", origin: { path: "48h/0h/0h/1h" } }),
    { prefixKind: "p2sh-p2wsh", originKind: "p2sh-p2wsh" },
  );
  assert.deepEqual(
    hodlMultisigScriptEvidence({ scope: "multisig", family: "z", origin: { path: "48h/0h/0h/1h" } }),
    { prefixKind: "p2wsh", originKind: "p2sh-p2wsh" },
  );
  assert.deepEqual(
    hodlMultisigScriptEvidence({ scope: "singlesig", family: "x", origin: { path: "87h/0h/0h" } }),
    { prefixKind: null, originKind: null },
  );

  assert.deepEqual(hodlSummarizeMultisigScriptKinds(["p2wsh", "p2wsh"]), {
    kind: "p2wsh",
    kinds: ["p2wsh"],
    mixed: false,
  });
  assert.deepEqual(hodlSummarizeMultisigScriptKinds(["p2wsh", "p2sh-p2wsh"]), {
    kind: "mixed",
    kinds: ["p2wsh", "p2sh-p2wsh"],
    mixed: true,
  });
});

test("BIP389 multipath recomputes the checksum", () => {
  const body =
    "wpkh([73c5da0a/84h/1h/0h]tpubDC5FSn4cz1dG9u1ytfDkCUmpJdbive4LmiYBiShpJcCshz45L7Ab3UyQwKDgEQb7b4yQ4Nv68wS4TibDkS1PYtzTszwrX2k4t5mGx8fS3x3/0/*)";
  const receive = hodlDescriptorWithChecksum(body);
  assert.equal(receive, `${body}#${independentChecksum(body)}`);
  const wallet = hodlWatchOnlyMultipathDescriptor(receive);
  assert.match(wallet, /\/<0;1>\/\*/);
  assert.equal(wallet.includes("/0/*"), false);
  assert.equal(wallet, `${wallet.slice(0, wallet.lastIndexOf("#"))}#${independentChecksum(wallet.slice(0, wallet.lastIndexOf("#")))}`);
});

test("BIP45 multipath keeps the co-signer branch before receive and change", () => {
  const body = "sh(sortedmulti(2,[73c5da0a/45h]xpubABC/0/0/*,[b8688df1/45h]xpubDEF/0/0/*))";
  const wallet = hodlWatchOnlyMultipathDescriptor(hodlDescriptorWithChecksum(body));
  assert.match(wallet, /\[73c5da0a\/45h\]xpubABC\/0\/<0;1>\/\*/);
  assert.match(wallet, /\[b8688df1\/45h\]xpubDEF\/0\/<0;1>\/\*/);
  assert.equal(wallet.includes("/0/0/*"), false);
});

test("BIP87 multipath uses its account key's receive and change branches", () => {
  const body = "sh(sortedmulti(1,[73c5da0a/87h/0h/4h]xpubABC/0/*))";
  const wallet = hodlWatchOnlyMultipathDescriptor(hodlDescriptorWithChecksum(body));
  assert.match(wallet, /\[73c5da0a\/87h\/0h\/4h\]xpubABC\/<0;1>\/\*/);
  assert.equal(wallet.includes("/0/0/*"), false);
});

test("originated 2-of-3 payload keeps fingerprints and fits a static QR", () => {
  const receive =
    "wsh(sortedmulti(2,[73c5da0a/48h/1h/0h/2h]tpubDFH9dgzveyD8zTbPUFuLrGmCydNvxehyNdUXKJAQN8x4aZ4j6UZqGfnqFrD4NqyaTVGKbvEW54tsvPTK2UoSbCC1PJY8iCNiwTL3RWZEheQ/0/*,[b8688df1/48h/1h/0h/2h]tpubDEfobrrtptRTbKf4gysDhoabneABDTAcdj3Vbn4XwPsLE2pmqpizSPRG6zHsbAMuiSgWmWPsYCLHTKTPpyrGJ5rAoTpKoQNZcxodiPf2tSJ/0/*,[3f635a63/48h/1h/0h/2h]tpubDFPtPArj4GzBEFHohegg1Xatrc1Fi9oSox5LzuSRX91miwQxuUrEpBxpvDRsmZYJKYFhgdK3UStsjC8JKXfUbMinjFqiEM4uNwzVaCaHpys/0/*))";
  const wallet = hodlWatchOnlyMultipathDescriptor(hodlDescriptorWithChecksum(receive));
  assert.match(wallet, /\[73c5da0a\/48h\/1h\/0h\/2h\]/);
  assert.match(wallet, /\[b8688df1\/48h\/1h\/0h\/2h\]/);
  assert.match(wallet, /\[3f635a63\/48h\/1h\/0h\/2h\]/);
  assert.equal((wallet.match(/\/<0;1>\/\*/g) || []).length, 3);
  assert.equal(wallet.includes("/0/*"), false);
  assert.ok(wallet.length < 1000);
  assert.equal(wallet.slice(-8), independentChecksum(wallet.slice(0, wallet.lastIndexOf("#"))));
});

test("taproot watch-only descriptor uses NUMS internal key and sortedmulti_a", () => {
  const body =
    "tr(50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0,sortedmulti_a(2,[73c5da0a/86h/0h/0h]xpubABC/0/*,[b8688df1/86h/0h/0h]xpubDEF/0/*))";
  const wallet = hodlWatchOnlyMultipathDescriptor(hodlDescriptorWithChecksum(body));
  assert.match(wallet, /^tr\(50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0,sortedmulti_a\(/);
  assert.match(wallet, /\[73c5da0a\/86h\/0h\/0h\]xpubABC\/<0;1>\/\*/);
  assert.match(wallet, /\[b8688df1\/86h\/0h\/0h\]xpubDEF\/<0;1>\/\*/);
  assert.equal(wallet.includes("/0/*"), false);
  assert.equal(wallet.slice(-8), independentChecksum(wallet.slice(0, wallet.lastIndexOf("#"))));
});

test("BIP48 script-path taproot origins keep the 3h leaf before receive and change", () => {
  const body =
    "tr(50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0,sortedmulti_a(1,[73c5da0a/48h/0h/0h/3h]xpubABC/0/*))";
  const wallet = hodlWatchOnlyMultipathDescriptor(hodlDescriptorWithChecksum(body));
  assert.match(wallet, /\[73c5da0a\/48h\/0h\/0h\/3h\]xpubABC\/<0;1>\/\*/);
});

test("listed-order watch-only descriptor keeps multi() key order", () => {
  const body =
    "wsh(multi(2,[73c5da0a/48h/1h/0h/2h]tpubABC/0/*,[b8688df1/48h/1h/0h/2h]tpubDEF/0/*))";
  const wallet = hodlWatchOnlyMultipathDescriptor(hodlDescriptorWithChecksum(body));
  assert.match(wallet, /wsh\(multi\(2,/);
  assert.match(wallet, /\[73c5da0a\/48h\/1h\/0h\/2h\]tpubABC\/<0;1>\/\*/);
  assert.match(wallet, /\[b8688df1\/48h\/1h\/0h\/2h\]tpubDEF\/<0;1>\/\*/);
  assert.equal(wallet.includes("sortedmulti"), false);
});

test("listed-order taproot descriptor keeps multi_a() key order", () => {
  const body =
    "tr(50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0,multi_a(2,[73c5da0a/86h/0h/0h]xpubABC/0/*,[b8688df1/86h/0h/0h]xpubDEF/0/*))";
  const wallet = hodlWatchOnlyMultipathDescriptor(hodlDescriptorWithChecksum(body));
  assert.match(wallet, /multi_a\(2,/);
  assert.equal(wallet.includes("sortedmulti_a"), false);
  assert.match(wallet, /\[73c5da0a\/86h\/0h\/0h\]xpubABC\/<0;1>\/\*/);
});
