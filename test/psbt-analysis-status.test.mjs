import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const app = readFileSync(join(root, "src/js/app.js"), "utf8");

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

const escapeHtml = (value) => String(value).replace(/[&<>"']/g, (char) => ({
  "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
})[char]);
const hodlPsbtAnalysisSummary = new Function(
  "hodlEscapeHtml",
  `${loadSlice("hodlPsbtAnalysisSummary")}; return hodlPsbtAnalysisSummary;`,
)(escapeHtml);

const check = (state, label = "Nonce analysis") => ({ state, label, detail: `${state} detail` });

test("complete listed checks do not overstate a security conclusion", () => {
  const html = hodlPsbtAnalysisSummary([check("complete")]);
  assert.match(html, /LISTED CHECKS COMPLETE/);
  assert.match(html, /Completed/);
  assert.match(html, /does not prove that the PSBT claims are true or that the transaction is safe to sign/);
  assert.doesNotMatch(html, /ANALYSIS INCOMPLETE|ISSUES FOUND/);
});

test("a found problem preserves its blocking state", () => {
  const html = hodlPsbtAnalysisSummary([check("complete"), check("problem", "SIGHASH policy")]);
  assert.match(html, /ISSUES FOUND/);
  assert.match(html, /SIGHASH policy<\/strong> — <span class='psbt-bad'>Problem found/);
  assert.doesNotMatch(html, /ANALYSIS INCOMPLETE/);
});

test("a problem outranks incomplete coverage without hiding either state", () => {
  const html = hodlPsbtAnalysisSummary([
    check("problem", "SIGHASH policy"),
    check("incomplete", "Previous outputs & fee"),
  ]);
  assert.match(html, /<p class='psbt-bad'><strong>ISSUES FOUND — ANALYSIS ALSO INCOMPLETE<\/strong><\/p>/);
  assert.match(html, /Problem found/);
  assert.match(html, /Incomplete/);
  assert.match(html, /Previous outputs &amp; fee/);
  assert.doesNotMatch(html, /<p class='psbt-warn'><strong>|LISTED CHECKS COMPLETE/);
});

test("the report maps each implemented incomplete-analysis condition", () => {
  const render = loadSlice("hodlRenderPsbt") + loadSlice("hodlPsbtNonceCheck");
  for (const limitation of [
    "not checked against previous transactions or the blockchain",
    "No session key was loaded",
    "outputs outside that range remain unclassified",
    "finalized, Taproot, or undecodable signature data could not be evaluated",
    "unreadable signatures, fewer than two comparable ECDSA signatures, missing key/digest data, unsupported scripts, or Taproot/Schnorr signatures",
    "Tap-leaf or finalized-witness data could not be fully decoded",
  ]) assert.ok(render.includes(limitation), limitation);
});

const hodlPsbtNonceCheck = new Function(
  `${loadSlice("hodlPsbtNonceCheck")}; return hodlPsbtNonceCheck;`,
)();
const sig = { length: 1 };

test("nonce status never claims no repeated r while a repeat is suspected", () => {
  assert.equal(hodlPsbtNonceCheck([sig], [], false).state, "problem");
  const suspected = hodlPsbtNonceCheck([], [sig], false);
  assert.equal(suspected.state, "incomplete");
  assert.match(suspected.detail, /possible repeated ECDSA nonce/);
  assert.equal(hodlPsbtNonceCheck([], [], true).state, "incomplete");
  const clean = hodlPsbtNonceCheck([], [], false);
  assert.equal(clean.state, "complete");
  assert.match(clean.detail, /no repeated r was found/);
});
