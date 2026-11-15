// The signer availability report's wiring in app.js: preview only, read only,
// and placed just above the privacy signals.
// Run with `npm test`.
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { HDKey } from "../src/js/hdkey.js";
import { loadAppFunctions } from "./app-slice-harness.mjs";

const source = readFileSync(new URL("../src/js/app.js", import.meta.url), "utf8");
const bodyOf = (name) => {
  const start = source.indexOf("function " + name + "(");
  assert.ok(start >= 0, name + " is defined");
  const end = source.indexOf("\nfunction ", start + 1);
  return source.slice(start, end < 0 ? source.length : end);
};
const fixture = (name) => Uint8Array.from(Buffer.from(readFileSync(new URL(`./fixtures/psbt/${name}.b64`, import.meta.url), "utf8").trim(), "base64"));

test("app.js imports the pure report module exactly once", () => {
  const imports = source.match(/^import .* from "\.\/psbt-signer-report\.js";$/gm) ?? [];
  assert.equal(imports.length, 1);
  assert.match(imports[0], /psbtSignerReport/);
  assert.match(imports[0], /SIGNER_REPORT_ROW_LIMIT/);
});

test("the section returns before reading any key in a release build", () => {
  const body = bodyOf("hodlSignerReportSection");
  assert.match(body, /^function hodlSignerReportSection\(psbt, network\) \{\n  if \(!PREVIEW\) return "";/);
  assert.match(body, /finally \{[\s\S]*wipePrivateData\(\)/);
});

test("hodlRenderPsbt computes the report in its own try, after the nonce view returns, and places it above privacy", () => {
  const body = bodyOf("hodlRenderPsbt");
  const lines = body.split("\n");
  const calls = lines.filter((line) => line.includes("hodlSignerReportSection"));
  assert.equal(calls.length, 1);
  assert.match(calls[0], /^\s*try \{ signerReport = hodlSignerReportSection\(psbt, network\); \} catch \{\}$/);
  const nonce = body.indexOf('if (view === "nonce") return');
  assert.ok(nonce >= 0 && nonce < body.indexOf("hodlSignerReportSection"));
  assert.match(body, /return \(view === "inspect" \? html : html\.concat\(nonceHtml\)\)\.concat\(signerReport, privacy\)\.join\(""\);/);
});

test("hodlRenderRawTx does not mention the report", () => {
  assert.doesNotMatch(bodyOf("hodlRenderRawTx"), /hodlSignerReportSection|signerReport/);
});

test("a release build computes nothing", async () => {
  const app = await loadAppFunctions(["hodlSignerReportSection"], { stubs: { PREVIEW: false, hodlSignerReportSources: () => { throw new Error("must not run"); } } });
  assert.equal(app.hodlSignerReportSection({ inputs: [] }, "mainnet"), "");
});

test("a preview build with no sources renders nothing", async () => {
  const app = await loadAppFunctions(["hodlSignerReportSection"], { stubs: { PREVIEW: true, hodlSignerReportSources: () => [] } });
  assert.equal(app.hodlSignerReportSection({ inputs: [] }, "mainnet"), "");
});

test("a preview build renders one row per input and wipes the source node once", async () => {
  const root = HDKey.fromMasterSeed(new Uint8Array(32).fill(9));
  let wipes = 0;
  const node = {
    get depth() { return root.depth; },
    get fingerprint() { return root.fingerprint; },
    get publicKey() { return root.publicKey; },
    get chainCode() { return root.chainCode; },
    get hasPrivateKey() { return root.hasPrivateKey; },
    deriveChild: (index) => root.deriveChild(index),
    wipePrivateData() { wipes += 1; },
  };
  const app = await loadAppFunctions(["hodlSignerReportSection"], {
    stubs: {
      PREVIEW: true,
      hodlSignerReportSources: (sources) => { sources.push({ id: "1", label: "Key 1", private: true, node }); return sources; },
    },
  });
  const psbt = app.hodlSignerReportSection === undefined ? null : null;
  const parsed = await loadAppFunctions(["hodlParsePsbt"]);
  const html = app.hodlSignerReportSection(parsed.hodlParsePsbt(fixture("multisig-2of3-p2wsh")), "mainnet");
  assert.match(html, /data-signer-report/);
  assert.equal((html.match(/data-signer-report-input=/g) || []).length, 2);
  assert.equal(wipes, 1);
  root.wipePrivateData();
});

test("hodlSignerReportSources skips lab keys and never hands out private bytes", async () => {
  const root = HDKey.fromMasterSeed(new Uint8Array(32).fill(5));
  const account = root.derive("m/84'/0'/0'");
  const xpub = account.neutered().publicExtendedKey;
  account.wipePrivateData();
  const singleKey = new Uint8Array(32).fill(6);
  const app = await loadAppFunctions(["hodlSignerReportSources"], {
    stubs: {
      hodlKeys: [
        { id: 0, isLab: true, result: { kind: "hd", rootNode: root } },
        { id: 1, name: "Key 1", number: 1, isLab: false, fields: {}, result: { kind: "single", privateKey: singleKey } },
        { id: 2, name: "Key 2", number: 2, isLab: false, fields: {}, result: { kind: "hd", rootNode: root } },
        { id: 3, name: "Key 3", number: 3, isLab: false, fields: {}, result: { kind: "hd", importedPublicKey: true, accounts: [{ genericPublic: xpub }] } },
      ],
      hodlBip85Children: [],
    },
  });
  const sources = app.hodlSignerReportSources([]);
  assert.deepEqual(sources.map((entry) => entry.id), ["1", "2", "3"]);
  const single = sources[0];
  assert.equal(single.private, true);
  assert.equal(single.node, undefined);
  assert.equal(single.pubkeys.length, 2);
  assert.ok(singleKey.every((byte) => byte === 6), "the state's own private key bytes are unchanged");
  assert.notEqual(sources[1].node, root, "the report gets its own copy of the root");
  assert.equal(sources[2].private, false);
  assert.equal(sources[2].node.depth, 3);
  for (const entry of sources) try { entry.node?.wipePrivateData(); } catch {}
  root.wipePrivateData();
});

test("the signer report carries no DRAFT markers", () => {
  for (const name of ["hodlSignerReportReasonText", "hodlSignerReportHtml"]) {
    assert.doesNotMatch(bodyOf(name), /DRAFT \(owner OK pending\)/);
  }
});

test("the signer report uses the agreed strings verbatim", () => {
  const strings = [
    "Signer availability",
    "Read only. Nothing is signed. Loaded Key Station keys are matched to each input by public key. This does not check amounts, recipients or fees.",
    "Inputs: {total}. Loaded keys can sign: {ready}. Already signed or finalized: {done}. Not enough usable keys: {short}. Cannot determine: {unknown}.",
    "Can never be spent: {never}.",
    "Signer available: {keys}.",
    "{m} of {count} needed. All signers available: {keys}.",
    "{m} of {count} needed. Enough signers available: {keys}.",
    "Already has enough valid signatures.",
    "No loaded private key found within the searched paths.",
    "{m} of {count} needed. Only {have} covered by valid signatures or usable loaded keys within the searched paths.",
    "Cannot determine: {reason}.",
    "Not covered by this report yet.",
    "Usable loaded keys: {keys}.",
    "Watch-only match, no private key loaded: {keys}.",
    "Signatures in the file: {invalid} not valid, {unchecked} not checked, {valid} valid.",
    "{count} more inputs are counted above but not listed.",
    "When the file's key paths do not match, these were also searched: {paths}, receive and change addresses, indexes 0 to {last}.",
    "Finalized input data present",
    "Account-level key match. This version cannot sign with it: {keys}.",
    "Only an account-level key matched. This version cannot sign with it: {keys}.",
    "Can never be spent: its redeem script is larger than Bitcoin allows (520 bytes).",
  ];
  for (const text of strings) assert.ok(source.includes(text), text);
  const reasons = bodyOf("hodlSignerReportReasonText");
  for (const text of [
    "the details of the coin being spent are missing or do not match",
    "the redeem or witness script is missing or does not match",
    "signatures in the file could not be checked",
    "the path search reached its limit",
    "the redeem script is larger than Bitcoin allows (520 bytes)",
  ]) assert.ok(reasons.includes(text), text);
});

test("only the imported-private branch marks a source as account-level", () => {
  const body = bodyOf("hodlSignerReportSources");
  const branches = body.split("} else if (");
  const imported = branches.filter((part) => part.includes("hodlResultHasImportedPrivate"));
  assert.equal(imported.length, 1);
  assert.match(imported[0], /account: true/);
  for (const part of branches) if (!part.includes("hodlResultHasImportedPrivate")) assert.doesNotMatch(part, /account: true/);
});

test("prevoutVerified follows the non-witness UTXO", () => {
  const body = bodyOf("hodlSignerReportInputs");
  const trueLines = body.split("\n").filter((line) => line.includes("prevoutVerified: true"));
  assert.ok(trueLines.length > 0);
  for (const line of trueLines) assert.match(line, /nonWitnessUtxo/);
  assert.match(body, /prevoutVerified: false/);
});
