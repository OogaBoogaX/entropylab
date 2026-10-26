import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { tHtml as hodlT, t as hodlTText, tAttr as hodlTAttr } from "../src/js/i18n.js";

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
  "hodlEscapeHtml", "hodlT", "hodlTAttr",
  `${loadSlice("hodlPsbtAnalysisSummary")}; return hodlPsbtAnalysisSummary;`,
)(escapeHtml, hodlT, hodlTAttr);
// The overall verdict line moved out of the summary into the answer block
// (TC's review, point 1); hodlPsbtOverallLine computes it and is extracted
// the same way.
const hodlPsbtOverallLine = new Function(
  "hodlT",
  `${loadSlice("hodlPsbtOverallLine")}; return hodlPsbtOverallLine;`,
)(hodlT);

const check = (state, label = "Nonce analysis") => ({ state, label, detail: `${state} detail` });

test("complete listed checks do not overstate a security conclusion", () => {
  // Re-pointed for TC's answer block: the overall line comes from
  // hodlPsbtOverallLine now, the rows and the closing note from the summary.
  const checks = [check("complete")];
  const html = hodlPsbtOverallLine(checks).html + hodlPsbtAnalysisSummary(checks);
  assert.match(html, /LISTED CHECKS COMPLETE/);
  assert.match(html, /Completed/);
  assert.match(html, /does not prove that the PSBT claims are true or that the transaction is safe to sign/);
  assert.doesNotMatch(html, /ANALYSIS INCOMPLETE|ISSUES FOUND/);
});

test("a found problem preserves its blocking state", () => {
  const checks = [check("complete"), check("problem", "SIGHASH policy")];
  const html = hodlPsbtOverallLine(checks).html + hodlPsbtAnalysisSummary(checks);
  assert.match(html, /ISSUES FOUND/);
  assert.match(html, /SIGHASH policy<\/span> — <span class='psbt-bad'>Problem found/);
  assert.doesNotMatch(html, /ANALYSIS INCOMPLETE/);
});

test("a problem outranks incomplete coverage without hiding either state", () => {
  const checks = [
    check("problem", "SIGHASH policy"),
    check("incomplete", "Previous outputs & fee"),
  ];
  const html = hodlPsbtOverallLine(checks).html + hodlPsbtAnalysisSummary(checks);
  assert.match(html, /<p class='psbt-bad'><strong>ISSUES FOUND — ANALYSIS ALSO INCOMPLETE<\/strong><\/p>/);
  assert.match(html, /Problem found/);
  assert.match(html, /Incomplete/);
  assert.match(html, /Previous outputs &amp; fee/);
  assert.doesNotMatch(html, /<p class='psbt-warn'><strong>|LISTED CHECKS COMPLETE/);
});

test("an impossible (negative) claimed fee escalates the fee check to a problem", () => {
  // Outputs exceeding claimed inputs is an inconsistency in the PSBT's own
  // data, not missing coverage: the banner must turn red, not stay yellow.
  const render = loadSlice("hodlRenderPsbt");
  assert.match(render, /feeInconsistent = 1/);
  // Re-pointed: the fee check has three states now (complete once every
  // input claims an amount); the pin is the escalation itself.
  assert.match(render, /state: feeInconsistent \? "problem" : knownInputs === tx\.inputs\.length \? "complete" : "incomplete"/);
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
  "hodlTText",
  `${loadSlice("hodlPsbtNonceCheck")}; return hodlPsbtNonceCheck;`,
)(hodlTText);
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

test("a nonce check incomplete only because there is nothing to compare carries the reason", () => {
  const row = hodlPsbtNonceCheck([], [], true, [], 1, 0, "", "nothing-to-compare");
  assert.equal(row.state, "incomplete", "the row still reads Incomplete");
  assert.equal(row.incompleteReason, "nothing-to-compare");
});

test("a nonce check incomplete for another cause carries no nothing-to-compare reason", () => {
  const row = hodlPsbtNonceCheck([], [], true, [], 1, 0, "", "");
  assert.equal(row.state, "incomplete");
  assert.equal(row.incompleteReason, undefined);
});

test("the overall line ignores a nothing-to-compare check", () => {
  const checks = [
    { state: "incomplete", label: "Nonce analysis", detail: "x", incompleteReason: "nothing-to-compare" },
    { state: "complete", label: "Other", detail: "y" },
  ];
  const line = hodlPsbtOverallLine(checks);
  assert.equal(line.state, "complete");
  assert.match(line.html, /LISTED CHECKS COMPLETE/);
});

test("the overall line still counts a nonce check incomplete for another cause", () => {
  const checks = [
    { state: "incomplete", label: "Nonce analysis", detail: "x" },
    { state: "complete", label: "Other", detail: "y" },
  ];
  const line = hodlPsbtOverallLine(checks);
  assert.equal(line.state, "incomplete");
  assert.match(line.html, /ANALYSIS INCOMPLETE/);
});
