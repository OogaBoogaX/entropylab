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
