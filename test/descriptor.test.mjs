// Watch-only descriptor QR payload and multisig key-origin parsing.
// Run with `npm test`.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, unlinkSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const app = readFileSync(join(root, "src/js/app.js"), "utf8");
function specText(value) {
  if (value == null || value === "") return "";
  if (typeof value === "string") return value;
  if (value && typeof value.key === "string") {
    // English-as-key: the spec key is already the English text.
    let text = value.key;
    if (value.vars) text = text.replace(/\{(\w+)\}/g, (_, n) => (value.vars[n] == null ? `{${n}}` : String(value.vars[n])));
    return text;
  }
  return String(value);
}

function extract(startNeedle, endNeedle) {
  const start = app.indexOf(startNeedle);
  const end = app.indexOf(endNeedle, start);
  if (start < 0 || end < 0) throw new Error(`extract failed: ${startNeedle}`);
  return app.slice(start, end);
}

function loadFunction(name) {
  const start = app.indexOf(`function ${name}(`);
  if (start < 0) throw new Error(`missing ${name}`);
  let depth = 0;
  for (let i = app.indexOf("{", start); i < app.length; i++) {
    if (app[i] === "{") depth++;
    else if (app[i] === "}" && --depth === 0) return app.slice(start, i + 1);
  }
  throw new Error(`unterminated ${name}`);
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
  `import { readFileSync } from "node:fs";
function hodlT(key, vars) {
  let text = key;
  if (vars) text = text.replace(/\\{(\\w+)\\}/g, (_, n) => (vars[n] == null ? "{" + n + "}" : String(vars[n])));
  return text;
}
function hodlNote(key, vars) { return vars == null ? { key } : { key, vars }; }
function hodlError(key, vars) {
  const err = new Error(hodlT(key, vars));
  err.hodlSpec = vars == null ? { key } : { key, vars };
  return err;
}
const hodlMaxPurpose = 2147483647;
const hodlCoinTypeFromNetwork = (network) => network === 'mainnet' ? 0 : 1;
export { hodlFilterXpub, hodlNormalizeOriginPath, hodlParseKeyOrigin, hodlOriginPathIndexes, hodlOriginMatchesParsedKey, hodlMultisigPurposeIndex, hodlOriginScriptError, hodlMultisigAccountNumber, hodlSummarizeMultisigAccounts, hodlMultisigAccountWarning, hodlMultisigOriginScriptKind, hodlMultisigScriptEvidence, hodlSummarizeMultisigScriptKinds };`,
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

const msigBranchPrelude = `
let hodlTestBranchWindow = { start: 0, range: 2 };
function hodlReadBranchWindow() { return hodlTestBranchWindow; }
function hodlTText(key, vars) {
  let text = key;
  if (vars) text = text.replace(/\\{(\\w+)\\}/g, (_, n) => (vars[n] == null ? "{" + n + "}" : String(vars[n])));
  return text;
}
function setHodlTestBranchWindow(start, range) { hodlTestBranchWindow = { start, range }; }
function hodlMsigKeyParts() { return {}; }
export { hodlMsigBranchWindowError, setHodlTestBranchWindow };
`;
const msigBranchPath = loadSlice(
  "function hodlMsigBranchWindowError",
  "function hodlMsigPathComponentLabel",
  msigBranchPrelude,
);
const { hodlMsigBranchWindowError, setHodlTestBranchWindow } = await import(pathToFileURL(msigBranchPath).href);
unlinkSync(msigBranchPath);


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
  // A trailing wildcard survives the field filter so the parser can see it.
  assert.equal(hodlFilterXpub(`${raw}/0/*`), `${raw}/0/*`);
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

test("origin parse tolerates branch wildcards and lone trailing slashes as decoration", () => {
  const body = "[73c5da0a/48h/1h/0h/2h]tpubDFH9dgzveyD8zTbPUFuLrGmCydNvxehyNdUXKJAQN8x4aZ4j6UZqGfnqFrD4NqyaTVGKbvEW54tsvPTK2UoSbCC1PJY8iCNiwTL3RWZEheQ";
  const bare = hodlParseKeyOrigin(body);
  for (const suffix of ["/0/*", "/<0;1>/*", "/", "/0/*/"]) {
    const parsed = hodlParseKeyOrigin(body + suffix);
    assert.equal(parsed.key, bare.key, `suffix ${suffix} was not fully stripped`);
    assert.deepEqual(parsed.origin, bare.origin, `suffix ${suffix} changed the origin`);
    assert.equal(parsed.derivationPath, "", `suffix ${suffix} must not become a derivation path`);
  }
});

test("origin parse honors a trailing numeric path, with or without decoration", () => {
  const body = "[73c5da0a/48h/1h/0h/2h]tpubDFH9dgzveyD8zTbPUFuLrGmCydNvxehyNdUXKJAQN8x4aZ4j6UZqGfnqFrD4NqyaTVGKbvEW54tsvPTK2UoSbCC1PJY8iCNiwTL3RWZEheQ";
  assert.equal(hodlParseKeyOrigin(body + "/0/1/0").derivationPath, "0/1/0");
  // A trailing slash alone is decoration; the path ahead of it still applies.
  assert.equal(hodlParseKeyOrigin(body + "/0/1/0/").derivationPath, "0/1/0");
  // A wildcard path is read the way the descriptor importer reads it: the
  // last plain step ahead of the wildcard is the branch and the steps before
  // it the signer's fixed path — xpub…/1/0/* is branch 0 below /1, not a
  // fixed /1/0 with the form's own branch added underneath.
  assert.equal(hodlParseKeyOrigin(body + "/1/0/*").derivationPath, "1");
  assert.equal(hodlParseKeyOrigin(body + "/1/0/*").branch, 0);
  assert.equal(hodlParseKeyOrigin(body + "/0/0/20/*").derivationPath, "0/0");
  assert.equal(hodlParseKeyOrigin(body + "/0/0/20/*").branch, 20);
  // A multipath step supplies the branches itself; the fixed path is what
  // precedes it.
  assert.equal(hodlParseKeyOrigin(body + "/0/0/20/<0;1>/*").derivationPath, "0/0/20");
  assert.equal(hodlParseKeyOrigin(body + "/0/0/20/<0;1>/*").branch, null);
  assert.deepEqual(hodlParseKeyOrigin(body + "/0/0/20/<0;1>/*").branches, [0, 1]);
  assert.deepEqual(hodlParseKeyOrigin(body + "/<2;3>/*").branches, [2, 3]);
  assert.deepEqual(hodlParseKeyOrigin(body + "/<0;1>/*").branches, [0, 1]);
  assert.equal(hodlParseKeyOrigin(body + "/5/*").branches, null);
  // A sole step ahead of the wildcard is that branch: /5/* is branch 5 with
  // no fixed path, /0/* and /1/* are the receive and change branches.
  assert.equal(hodlParseKeyOrigin(body + "/5/*").derivationPath, "");
  assert.equal(hodlParseKeyOrigin(body + "/5/*").branch, 5);
  assert.equal(hodlParseKeyOrigin(body + "/0/*").derivationPath, "");
  assert.equal(hodlParseKeyOrigin(body + "/0/*").branch, 0);
  assert.equal(hodlParseKeyOrigin(body + "/1/*").branch, 1);
  // Without a wildcard nothing is a branch: a manually appended child path
  // is honored in full, and a hardened last step stays in the path where
  // the unhardened-path check refuses it instead of being dropped.
  assert.equal(hodlParseKeyOrigin(body + "/0/1/0").branch, null);
  assert.equal(hodlParseKeyOrigin(body + "/0/1h/*").derivationPath, "0/1h");
  assert.equal(hodlParseKeyOrigin(body + "/0/1h/*").branch, null);
  // BIP45 keeps its cosigner step ahead of the branch: key/0/<branch>/*.
  const bip45 = "[73c5da0a/45h]tpubDFH9dgzveyD8zTbPUFuLrGmCydNvxehyNdUXKJAQN8x4aZ4j6UZqGfnqFrD4NqyaTVGKbvEW54tsvPTK2UoSbCC1PJY8iCNiwTL3RWZEheQ";
  assert.equal(hodlParseKeyOrigin(bip45 + "/0/0/*").derivationPath, "");
  assert.equal(hodlParseKeyOrigin(bip45 + "/0/0/*").branch, 0);
  assert.equal(hodlParseKeyOrigin(bip45 + "/0/1/*").branch, 1);
  assert.throws(() => hodlParseKeyOrigin(bip45 + "/3/0/*"), /BIP45/);
  // Malformed shapes fail loudly instead of being mangled.
  assert.throws(() => hodlParseKeyOrigin(body + "/0/*/1"), /wildcard/);
  assert.throws(() => hodlParseKeyOrigin(body + "/0/foo/1"), /Trailing path steps/);
  assert.throws(() => hodlParseKeyOrigin(body + "/0/1/<0;1>/<2;3>"), /Only one multipath/);
  assert.throws(() => hodlParseKeyOrigin(body + "/0/<0;1>/2"), /must be the last trailing path step/);
});

test("co-signer branch window refuses multipath branches outside it", () => {
  const body = "[73c5da0a/48h/1h/0h/2h]tpubDFH9dgzveyD8zTbPUFuLrGmCydNvxehyNdUXKJAQN8x4aZ4j6UZqGfnqFrD4NqyaTVGKbvEW54tsvPTK2UoSbCC1PJY8iCNiwTL3RWZEheQ";
  const outside = hodlParseKeyOrigin(body + "/<2;3>/*");
  assert.match(specText(hodlMsigBranchWindowError(null, outside)), /branches 2 and 3.*0-1/);
  assert.equal(hodlMsigBranchWindowError(null, hodlParseKeyOrigin(body + "/<0;1>/*")), "");
  setHodlTestBranchWindow(2, 2);
  assert.equal(hodlMsigBranchWindowError(null, outside), "");
  setHodlTestBranchWindow(0, 2);
  assert.match(specText(hodlMsigBranchWindowError(null, hodlParseKeyOrigin(body + "/5/*"))), /branch 5/);
});

test("co-signer branch window requires multipath branches in window order", () => {
  const parsed = (branches) => ({ branches });
  const single = (branch) => ({ branch });
  setHodlTestBranchWindow(0, 2);
  assert.equal(hodlMsigBranchWindowError(null, parsed([0, 1])), "");
  assert.match(specText(hodlMsigBranchWindowError(null, parsed([1, 0]))), /branches 1 and 0 in that order/);
  assert.match(specText(hodlMsigBranchWindowError(null, parsed([2, 3]))), /branches 2 and 3 in that order/);
  setHodlTestBranchWindow(2, 2);
  assert.equal(hodlMsigBranchWindowError(null, parsed([2, 3])), "");
  assert.match(specText(hodlMsigBranchWindowError(null, parsed([3, 2]))), /branches 3 and 2 in that order/);
  setHodlTestBranchWindow(0, 3);
  assert.match(specText(hodlMsigBranchWindowError(null, parsed([0, 1]))), /branches 0 and 1 in that order/);
  assert.equal(hodlMsigBranchWindowError(null, parsed([0, 1, 2])), "");
  setHodlTestBranchWindow(0, 2);
  assert.equal(
    specText(hodlMsigBranchWindowError(null, parsed([1, 0]))),
    "This key's descriptor uses branches 1 and 0 in that order; the form derives branches 0-1 in order. Change the branch window or import the full descriptor.",
  );
  // A malformed list the parser never produces is refused, not waved through.
  assert.match(specText(hodlMsigBranchWindowError(null, { branches: [] })), /in that order/);
  assert.match(specText(hodlMsigBranchWindowError(null, { branches: [0, NaN] })), /in that order/);
  // A plain single-branch key is unchanged: branch 1 is inside the window,
  // branch 5 is refused with the single-branch message.
  assert.equal(hodlMsigBranchWindowError(null, single(1)), "");
  assert.match(specText(hodlMsigBranchWindowError(null, single(5))), /branch 5, outside the form's branch window 0-1/);
});

// The wildcard tail a pasted key declares stays in the key field, so the
// declaration is read from the row's own parse on every sync, rebuild and
// restore; a key with no wildcard keeps its bare key.
const msigSyncPrelude = `
${loadFunction("hodlNormalizeOriginPath")}
${loadFunction("hodlParseKeyTail")}
${loadFunction("hodlParseKeyOrigin")}
${loadFunction("hodlMsigKeyParts")}
${loadFunction("hodlMsigWildcardTail")}
${loadFunction("hodlMsigBranchWindowError")}
${loadFunction("hodlMsigRowValue")}
function hodlError(key, vars) { return new Error(typeof key === "string" ? key : key.key); }
function hodlDescriptorKeyExpressions() { return null; }
let hodlTestBranchWindow = { start: 0, range: 2 };
function hodlReadBranchWindow() { return hodlTestBranchWindow; }
function setHodlTestBranchWindow(start, range) { hodlTestBranchWindow = { start, range }; }
function hodlTText(key, vars) {
  let text = key;
  if (vars) text = text.replace(/\\{(\\w+)\\}/g, (_, n) => (vars[n] == null ? "{" + n + "}" : String(vars[n])));
  return text;
}
function hodlDefaultMsigFullPath() { return "48h/0h/0h/2h"; }
function hodlParseCustomDerivationPath(value) {
  return { components: String(value ?? "").split("/").filter((step) => step !== "").map((step) => {
    let match = step.match(/^(\\d+)([hH']?)$/);
    return match ? { index: Number(match[1]), hardened: Boolean(match[2]) } : { index: step, hardened: false };
  }) };
}
function hodlOriginPathComponent(index, hardened) { return String(index) + (hardened ? "h" : ""); }
function hodlMsigFullPath(parsed) { return parsed.derivationPath ? parsed.origin.path + "/" + parsed.derivationPath : parsed.origin.path; }
function hodlRenderMsigPathComponents() {}
// The fixture tpub is a BIP48 account key at depth 4; the real parser reads
// that depth from the key itself, so a bare key's depth is set per test. A
// key with a tail fails exactly where the real decoder fails: base58check
// has no "/" or "*".
let hodlTestBareKeyDepth = 4;
function setHodlTestBareKeyDepth(depth) { hodlTestBareKeyDepth = depth; }
function hodlParseMultisigCosigner(raw) {
  let parts = hodlParseKeyOrigin(raw);
  if (parts.key.includes("/") || parts.key.includes("*")) throw new Error("Invalid extended key.");
  return { origin: parts.origin, key: parts.key, derivationPath: parts.derivationPath, branch: parts.branch, branches: parts.branches, bareWildcard: parts.bareWildcard, node: { depth: parts.origin ? parts.origin.path.split("/").length : hodlTestBareKeyDepth } };
}
export { hodlSyncMsigRowPathFromKey, hodlMsigRowValue, hodlMsigKeyParts, hodlMsigBranchWindowError, setHodlTestBranchWindow, setHodlTestBareKeyDepth };
`;
const msigSyncPath = loadSlice("function hodlSyncMsigRowPathFromKey", "function hodlApplyMsigRowPath", msigSyncPrelude);
const {
  hodlSyncMsigRowPathFromKey,
  hodlMsigRowValue,
  hodlMsigKeyParts,
  hodlMsigBranchWindowError: hodlMsigSyncBranchWindowError,
  setHodlTestBranchWindow: setHodlTestSyncBranchWindow,
  setHodlTestBareKeyDepth: setHodlTestSyncBareKeyDepth,
} = await import(pathToFileURL(msigSyncPath).href);
unlinkSync(msigSyncPath);

function msigSyncRow(value) {
  const field = (initial) => ({ value: initial ?? "", classList: { add() {}, remove() {}, toggle() {} }, setAttribute() {} });
  const row = {
    dataset: {},
    key: field(value),
    fingerprint: field(""),
    path: field(""),
    help: { textContent: "" },
    querySelector(selector) {
      if (selector === "textarea") return row.key;
      if (selector === ".msig-master-fingerprint") return row.fingerprint;
      if (selector === ".msig-full-path") return row.path;
      if (selector === ".msig-full-path-help") return row.help;
      return null;
    },
  };
  return row;
}
const MSIG_SYNC_ORIGIN = "[73c5da0a/48h/1h/0h/2h]";
const MSIG_SYNC_KEY = `${MSIG_SYNC_ORIGIN}tpubDFH9dgzveyD8zTbPUFuLrGmCydNvxehyNdUXKJAQN8x4aZ4j6UZqGfnqFrD4NqyaTVGKbvEW54tsvPTK2UoSbCC1PJY8iCNiwTL3RWZEheQ`;
const MSIG_SYNC_BARE = MSIG_SYNC_KEY.slice(MSIG_SYNC_ORIGIN.length);

test("a pasted branch stays in the key field and the row value through every sync", () => {
  setHodlTestSyncBranchWindow(0, 2);
  const row = msigSyncRow(`${MSIG_SYNC_KEY}/0/*`);
  hodlSyncMsigRowPathFromKey(row);
  assert.equal(row.key.value, `${MSIG_SYNC_BARE}/0/*`, "the key field keeps the declared branch");
  assert.equal(row.fingerprint.value, "73c5da0a", "the origin moved to the fingerprint field");
  assert.equal(row.path.value, "48h/1h/0h/2h", "the origin moved to the path field");
  assert.equal(hodlMsigSyncBranchWindowError(row, hodlMsigKeyParts(row.key.value)), "", "branch 0 is inside the window");
  assert.ok(hodlMsigRowValue(row).endsWith(`${MSIG_SYNC_BARE}/0/*`), "the row value carries the branch");
  // A no-op edit, a fingerprint edit or a rebuild runs the same sync again.
  hodlSyncMsigRowPathFromKey(row);
  assert.equal(row.key.value, `${MSIG_SYNC_BARE}/0/*`, "the second sync writes the same text back");
  assert.equal(row.fingerprint.value, "73c5da0a", "the second sync leaves the fingerprint alone");
  assert.equal(row.path.value, "48h/1h/0h/2h", "the second sync leaves the path alone");
  assert.equal(hodlMsigSyncBranchWindowError(row, hodlMsigKeyParts(row.key.value)), "");
});

test("a branch outside the window stays refused after the next sync", () => {
  setHodlTestSyncBranchWindow(0, 2);
  const row = msigSyncRow(`${MSIG_SYNC_KEY}/0/*`);
  hodlSyncMsigRowPathFromKey(row);
  assert.equal(hodlMsigSyncBranchWindowError(row, hodlMsigKeyParts(row.key.value)), "");
  setHodlTestSyncBranchWindow(5, 2);
  assert.match(specText(hodlMsigSyncBranchWindowError(row, hodlMsigKeyParts(row.key.value))), /branch 0, outside the form's branch window 5-6/);
  // The declaration lives in the key field, so the next sync cannot lose it.
  hodlSyncMsigRowPathFromKey(row);
  assert.equal(row.key.value, `${MSIG_SYNC_BARE}/0/*`);
  assert.match(specText(hodlMsigSyncBranchWindowError(row, hodlMsigKeyParts(row.key.value))), /branch 0, outside the form's branch window 5-6/);
  setHodlTestSyncBranchWindow(0, 2);
  assert.equal(hodlMsigSyncBranchWindowError(row, hodlMsigKeyParts(row.key.value)), "");
});

test("fixed child steps stay in the full-path field and the row value", () => {
  setHodlTestSyncBranchWindow(0, 2);
  const row = msigSyncRow(`${MSIG_SYNC_KEY}/1/0/*`);
  hodlSyncMsigRowPathFromKey(row);
  assert.equal(row.key.value, `${MSIG_SYNC_BARE}/0/*`, "the branch stays in the key field");
  assert.equal(row.path.value, "48h/1h/0h/2h/1", "the fixed step before the branch stays in the path field");
  assert.ok(hodlMsigRowValue(row).endsWith(`${MSIG_SYNC_BARE}/1/0/*`), "the row value carries the fixed step and the branch");
});

test("a multipath branch stays in the key field and is refused outside the window", () => {
  setHodlTestSyncBranchWindow(0, 2);
  const row = msigSyncRow(`${MSIG_SYNC_KEY}/<0;1>/*`);
  hodlSyncMsigRowPathFromKey(row);
  assert.equal(row.key.value, `${MSIG_SYNC_BARE}/<0;1>/*`);
  assert.equal(hodlMsigSyncBranchWindowError(row, hodlMsigKeyParts(row.key.value)), "");
  assert.ok(hodlMsigRowValue(row).endsWith(`${MSIG_SYNC_BARE}/<0;1>/*`));
  setHodlTestSyncBranchWindow(2, 2);
  assert.match(specText(hodlMsigSyncBranchWindowError(row, hodlMsigKeyParts(row.key.value))), /branches 0 and 1 in that order/);
});

test("a bare wildcard stays in the key field and is refused with directions", () => {
  assert.equal(hodlParseKeyOrigin(`${MSIG_SYNC_KEY}/*`).bareWildcard, true);
  assert.equal(hodlParseKeyOrigin(`${MSIG_SYNC_KEY}/0/*`).bareWildcard, false);
  assert.equal(hodlParseKeyOrigin(`${MSIG_SYNC_KEY}/<0;1>/*`).bareWildcard, false);
  assert.equal(hodlParseKeyOrigin(MSIG_SYNC_KEY).bareWildcard, false);
  setHodlTestSyncBranchWindow(0, 2);
  const row = msigSyncRow(`${MSIG_SYNC_KEY}/*`);
  hodlSyncMsigRowPathFromKey(row);
  assert.equal(row.key.value, `${MSIG_SYNC_BARE}/*`);
  const message = "This key's descriptor derives addresses directly below the key (/*), with no branch step; the form always adds a branch. Import the full descriptor instead.";
  assert.equal(specText(hodlMsigSyncBranchWindowError(row, hodlMsigKeyParts(row.key.value))), message);
  // A tolerated double slash reads as branch 0, exactly like the parser.
  const doubled = msigSyncRow(`${MSIG_SYNC_KEY}/0//*`);
  hodlSyncMsigRowPathFromKey(doubled);
  assert.equal(doubled.key.value, `${MSIG_SYNC_BARE}/0/*`);
  assert.equal(hodlMsigSyncBranchWindowError(doubled, hodlMsigKeyParts(doubled.key.value)), "");
});

test("a key with no wildcard keeps its bare key", () => {
  setHodlTestSyncBranchWindow(0, 2);
  for (const [pasted, path] of [[MSIG_SYNC_KEY, "48h/1h/0h/2h"], [`${MSIG_SYNC_KEY}/0/2`, "48h/1h/0h/2h/0/2"]]) {
    const row = msigSyncRow(pasted);
    hodlSyncMsigRowPathFromKey(row);
    assert.equal(row.key.value, MSIG_SYNC_BARE, pasted);
    assert.equal(row.path.value, path, pasted);
    assert.equal(hodlMsigSyncBranchWindowError(row, hodlMsigKeyParts(row.key.value)), "", pasted);
  }
});

test("a synced wildcard row round-trips through the co-signer parse on every sync", () => {
  setHodlTestSyncBranchWindow(0, 2);
  for (const tail of ["/0/*", "/<0;1>/*"]) {
    const row = msigSyncRow(`${MSIG_SYNC_KEY}${tail}`);
    hodlSyncMsigRowPathFromKey(row);
    assert.equal(row.key.value, `${MSIG_SYNC_BARE}${tail}`, "the first sync keeps the declared branch");
    const fingerprint = row.fingerprint.value, path = row.path.value;
    hodlSyncMsigRowPathFromKey(row);
    assert.equal(row.key.value, `${MSIG_SYNC_BARE}${tail}`, "the second sync writes the same text back");
    assert.equal(row.fingerprint.value, fingerprint, "the second sync leaves the fingerprint alone");
    assert.equal(row.path.value, path, "the second sync leaves the path alone");
    assert.equal(hodlMsigRowValue(row, true), `${MSIG_SYNC_KEY}${tail}`, "the row value rebuilds the origin-bearing key");
  }
});

test("a BIP45 row keeps its cosigner step through the sync and the rebuild", () => {
  setHodlTestSyncBranchWindow(0, 2);
  setHodlTestSyncBareKeyDepth(1);
  try {
    for (const [tail, stripped, rebuilt, declaration] of [
      ["/0/0/*", "/0/*", "/0/0/*", { branch: 0 }],
      ["/0/<0;1>/*", "/<0;1>/*", "/0/<0;1>/*", { branches: [0, 1] }],
    ]) {
      const row = msigSyncRow(`[73c5da0a/45h]${MSIG_SYNC_BARE}${tail}`);
      hodlSyncMsigRowPathFromKey(row);
      assert.equal(row.key.value, `${MSIG_SYNC_BARE}${tail}`, "the sync keeps the cosigner step in the key field");
      assert.equal(row.path.value, "45h", "the 45h origin moved to the path field");
      // The stripped text alone is not a BIP45 key the parser accepts.
      assert.throws(() => hodlParseKeyOrigin(`[73c5da0a/45h]${MSIG_SYNC_BARE}${stripped}`), /BIP45/, tail);
      const value = hodlMsigRowValue(row, true);
      assert.equal(value, `[73c5da0a/45h]${MSIG_SYNC_BARE}${rebuilt}`, "the rebuilt value re-adds cosigner step 0");
      // A second sync writes the same text back.
      hodlSyncMsigRowPathFromKey(row);
      assert.equal(row.key.value, `${MSIG_SYNC_BARE}${tail}`, "the second sync writes the same text back");
      assert.equal(row.path.value, "45h", "the second sync leaves the path alone");
      // The app's own parser reads the rebuilt value back to the same
      // declaration: cosigner 0, then the branch (or the branch multipath).
      const reparsed = hodlParseKeyOrigin(value);
      assert.equal(reparsed.origin.path, "45h", tail);
      assert.equal(reparsed.derivationPath, "", tail);
      if (declaration.branch != null) assert.equal(reparsed.branch, declaration.branch, tail);
      else assert.deepEqual(reparsed.branches, declaration.branches, tail);
    }
  } finally {
    setHodlTestSyncBareKeyDepth(4);
  }
});

test("an originless key with fixed steps is refused, not silently re-pathed", () => {
  setHodlTestSyncBranchWindow(0, 2);
  const row = msigSyncRow(`${MSIG_SYNC_BARE}/1/0/*`);
  row.fingerprint.value = "73c5da0a";
  row.path.value = "48h/1h/0h/2h";
  assert.throws(() => hodlMsigRowValue(row, true), /An extended key without an origin cannot include fixed steps/);
  hodlSyncMsigRowPathFromKey(row);
  assert.equal(row.key.value, `${MSIG_SYNC_BARE}/1/0/*`, "the sync leaves the key field untouched");
  assert.equal(row.path.value, "48h/1h/0h/2h", "the sync leaves the path field untouched");
});

test("a typed bare tail on a BIP45 row is refused, not promoted to cosigner 0", () => {
  setHodlTestSyncBranchWindow(0, 2);
  setHodlTestSyncBareKeyDepth(1);
  try {
    for (const tail of ["/0/*", "/<0;1>/*", "/2147483647/0/*"]) {
      const row = msigSyncRow(`${MSIG_SYNC_BARE}${tail}`);
      row.fingerprint.value = "73c5da0a";
      row.path.value = "45h";
      assert.throws(() => hodlMsigRowValue(row, true), /BIP45/, tail);
    }
  } finally {
    setHodlTestSyncBareKeyDepth(4);
  }
});

test("editing the path field after a paste cannot change which wallet the key text names", () => {
  setHodlTestSyncBranchWindow(0, 2);
  setHodlTestSyncBareKeyDepth(1);
  try {
    const toBip45 = msigSyncRow(`${MSIG_SYNC_KEY}/0/*`);
    hodlSyncMsigRowPathFromKey(toBip45);
    assert.equal(toBip45.key.value, `${MSIG_SYNC_BARE}/0/*`);
    toBip45.path.value = "45h";
    assert.throws(() => hodlMsigRowValue(toBip45, true), /BIP45/);
    const toFixed = msigSyncRow(`[73c5da0a/45h]${MSIG_SYNC_BARE}/0/0/*`);
    hodlSyncMsigRowPathFromKey(toFixed);
    assert.equal(toFixed.key.value, `${MSIG_SYNC_BARE}/0/0/*`);
    toFixed.path.value = "44h";
    assert.throws(() => hodlMsigRowValue(toFixed, true), /An extended key without an origin cannot include fixed steps/);
  } finally {
    setHodlTestSyncBareKeyDepth(4);
  }
});

test("hodlMsigKeyParts reads a BIP45 tail with the parser's own rule", () => {
  assert.equal(hodlMsigKeyParts("KEY/0/0/*", true).key, "KEY");
  assert.equal(hodlMsigKeyParts("KEY/0/0/*", true).derivationPath, "");
  assert.equal(hodlMsigKeyParts("KEY/0/0/*", true).branch, 0);
  assert.deepEqual(hodlMsigKeyParts("KEY/0/<0;1>/*", true).branches, [0, 1]);
  for (const tail of ["/0/*", "/<0;1>/*", "/3/0/*", "/2147483647/0/*"]) {
    assert.throws(() => hodlMsigKeyParts(`KEY${tail}`, true), /BIP45/, tail);
  }
  // Without the flag the tail is read as a plain branch, as before.
  assert.equal(hodlMsigKeyParts("KEY/0/*").branch, 0);
  assert.equal(hodlMsigKeyParts("KEY/1/0/*").derivationPath, "1");
});

test("hodlMsigKeyParts reads a wildcard tail from key text with no origin", () => {
  assert.equal(hodlMsigKeyParts("KEY").key, "KEY");
  assert.equal(hodlMsigKeyParts("KEY").branch, null);
  assert.equal(hodlMsigKeyParts("KEY/0/*").key, "KEY");
  assert.equal(hodlMsigKeyParts("KEY/0/*").branch, 0);
  assert.deepEqual(hodlMsigKeyParts("KEY/<0;1>/*").branches, [0, 1]);
  assert.equal(hodlMsigKeyParts("KEY/*").bareWildcard, true);
  assert.equal(hodlMsigKeyParts("KEY/1/0/*").derivationPath, "1");
  assert.equal(hodlMsigKeyParts("KEY/1/0/*").branch, 0);
});

test("hodlParseKeyOrigin still splits an origin and leaves an originless tail alone", () => {
  const origin = { fingerprint: "73c5da0a", path: "48h/1h/0h/2h" };
  const body = "[73c5da0a/48h/1h/0h/2h]KEY";
  assert.deepEqual(hodlParseKeyOrigin(body), { origin, key: "KEY", derivationPath: "", branch: null, branches: null, bareWildcard: false });
  assert.deepEqual(hodlParseKeyOrigin(`${body}/0/*`), { origin, key: "KEY", derivationPath: "", branch: 0, branches: null, bareWildcard: false });
  assert.deepEqual(hodlParseKeyOrigin(`${body}/<0;1>/*`), { origin, key: "KEY", derivationPath: "", branch: null, branches: [0, 1], bareWildcard: false });
  assert.deepEqual(hodlParseKeyOrigin(`${body}/*`), { origin, key: "KEY", derivationPath: "", branch: null, branches: null, bareWildcard: true });
  assert.deepEqual(hodlParseKeyOrigin(`${body}/1/0/*`), { origin, key: "KEY", derivationPath: "1", branch: 0, branches: null, bareWildcard: false });
  assert.deepEqual(hodlParseKeyOrigin("KEY/0/*"), { origin: null, key: "KEY/0/*" });
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
  assert.match(specText(hodlOriginMatchesParsedKey({ fingerprint: "73c5da0a", path: "48h/1h/0h" }, mock)), /steps/);
  assert.equal(hodlOriginScriptError(origin, "p2wsh", "testnet", 48), "");
  assert.equal(hodlOriginScriptError({ fingerprint: "73c5da0a", path: "48h/0h/0h/2h" }, "p2wsh", "mainnet", 48), "");
  assert.match(specText(hodlOriginScriptError({ fingerprint: "73c5da0a", path: "48h/0h/0h/2h" }, "p2wsh", "testnet", 48)), /1h/);
  assert.equal(hodlOriginMatchesParsedKey({ fingerprint: "73c5da0a", path: "45h" }, { depth: 1, childNumber: 0x8000002d }), "");
  assert.equal(hodlOriginScriptError({ fingerprint: "73c5da0a", path: "45h" }, "p2sh", "mainnet", 45), "");
  // A BIP45 card holds the depth-1 purpose key only; anything deeper is a
  // Custom path (which warns), and a wrong purpose is refused.
  assert.match(specText(hodlOriginScriptError({ fingerprint: "73c5da0a", path: "45h/0" }, "p2sh", "mainnet", 45)), /without an account/);
  assert.match(specText(hodlOriginScriptError({ fingerprint: "73c5da0a", path: "46h/0" }, "p2sh", "mainnet", 45)), /45h/);
  const bip87 = { fingerprint: "73c5da0a", path: "87h/0h/7h" };
  assert.equal(hodlOriginMatchesParsedKey(bip87, { depth: 3, childNumber: 0x80000007 }), "");
  assert.match(
    specText(hodlOriginScriptError({ fingerprint: "73c5da0a", path: "45h" }, "p2sh", "mainnet", 87)),
    /87h/,
  );
  assert.equal(hodlOriginScriptError({ fingerprint: "73c5da0a", path: "86h/0h/0h" }, "p2tr", "mainnet", 86), "");
  assert.equal(hodlOriginScriptError({ fingerprint: "73c5da0a", path: "69420h/0h/0h" }, "p2tr", "mainnet", 69420), "");
  assert.equal(hodlOriginScriptError({ fingerprint: "73c5da0a", path: "48h/69420h/0h/2h" }, "p2wsh", "mainnet", 48, 69420), "");
  assert.match(specText(hodlOriginScriptError({ fingerprint: "73c5da0a", path: "48h/0h/0h/2h" }, "p2wsh", "mainnet", 48, 69420)), /selected coin type/);
  assert.match(specText(hodlOriginScriptError({ fingerprint: "73c5da0a", path: "84h/0h/0h" }, "p2tr", "mainnet", 86)), /selected Purpose is 86h/);
  // A spec card holds the account key itself: neither above nor below it.
  assert.match(specText(hodlOriginScriptError({ fingerprint: "73c5da0a", path: "86h/0h/0h/0h" }, "p2tr", "mainnet", 86)), /purpose, coin type, and account/);
  assert.match(specText(hodlOriginScriptError({ fingerprint: "73c5da0a", path: "86h/0h" }, "p2tr", "mainnet", 86)), /purpose, coin type, and account/);
  assert.match(specText(hodlOriginScriptError({ fingerprint: "73c5da0a", path: "86h/1h/0h" }, "p2tr", "mainnet", 86)), /0h/);
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
  assert.match(specText(hodlOriginScriptError({ path: "48h/0h/7/2h" }, "p2wsh", "mainnet", 48)), /must be hardened/);
});

test("multisig account summary reports mismatched accounts as mixed", () => {
  const matching = hodlSummarizeMultisigAccounts([4, 4, 4]);
  assert.deepEqual(matching, { account: 4, accounts: [4], consistent: true, mixed: false });
  assert.equal(hodlMultisigAccountWarning(matching), "");

  const mixed = hodlSummarizeMultisigAccounts([7, 2, 7, 4]);
  assert.deepEqual(mixed, { account: null, accounts: [2, 4, 7], consistent: false, mixed: true });
  assert.match(specText(hodlMultisigAccountWarning(mixed)), /do not match \(2, 4, 7\).*shown as Mixed/);
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
  // The singlesig BIPs map to their multisig script type at account depth;
  // an unrecognized purpose selects nothing and stays custom.
  assert.equal(hodlMultisigOriginScriptKind({ path: "84h/0h/0h" }), "p2wsh");
  assert.equal(hodlMultisigOriginScriptKind({ path: "49h/0h/0h" }), "p2sh-p2wsh");
  assert.equal(hodlMultisigOriginScriptKind({ path: "44h/0h/0h" }), "p2sh");
  assert.equal(hodlMultisigOriginScriptKind({ path: "84h/0h/0h/2h" }), null);
  assert.equal(hodlMultisigOriginScriptKind({ path: "69420h/0h/0h" }), null);
  // A single step is BIP45's purpose key only at 45; any other single step,
  // such as a custom m/0h, selects no script type.
  assert.equal(hodlMultisigOriginScriptKind({ path: "45" }), "p2sh");
  assert.equal(hodlMultisigOriginScriptKind({ path: "0h" }), null);
  assert.equal(hodlMultisigOriginScriptKind({ path: "46h" }), null);
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
