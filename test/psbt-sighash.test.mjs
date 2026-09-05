// PSBT_IN_SIGHASH_TYPE and signature suffix policy must be decoded and be
// blocking without a session key. Regression coverage for each base type and
// ANYONECANPAY combination.
import { test } from "node:test";
import { t as hodlT } from "../src/js/i18n.js";
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

const hodlFind = (entries, type) => entries.filter((entry) => entry.type === type);
const { hodlSighashPolicy, hodlSighashLabel, hodlSighashProblems } = new Function(
  "hodlFind",
  "hodlT",
  `${["hodlSighashPolicy", "hodlSighashLabel", "hodlSighashProblems"].map(loadSlice).join("\n")}; return { hodlSighashPolicy, hodlSighashLabel, hodlSighashProblems };`,
)(hodlFind, hodlT);

const entry = (type, value, keydata = new Uint8Array(0)) => ({ type, keydata, val: value });
const u32 = (value) => Uint8Array.of(value & 255, (value >>> 8) & 255, (value >>> 16) & 255, (value >>> 24) & 255);

const BASES = [
  [1, "SIGHASH_ALL"],
  [2, "SIGHASH_NONE"],
  [3, "SIGHASH_SINGLE"],
];

test("the declared policy is parsed as an empty-keydata little-endian u32", () => {
  assert.equal(hodlSighashPolicy([entry(3, u32(1))]), 1);
  assert.equal(hodlSighashPolicy([entry(3, u32(0x82))]), 0x82);
  // a non-empty keydata declaration is not a policy
  assert.equal(hodlSighashPolicy([entry(3, u32(0x82), Uint8Array.of(1))]), null);
  // malformed length is rejected, not silently ignored
  assert.throws(() => hodlSighashPolicy([entry(3, Uint8Array.of(1))]), /malformed/);
});

test("every base type and its ANYONECANPAY form is labeled", () => {
  for (const [value, name] of BASES) {
    assert.ok(hodlSighashLabel(value).includes(name) && !hodlSighashLabel(value).includes("ANYONECANPAY"), name);
    assert.ok(hodlSighashLabel(value | 0x80).includes("ANYONECANPAY"), name);
  }
});

test("BIP341 SIGHASH_DEFAULT (0x00) is labeled, not reported as unknown", () => {
  assert.ok(hodlSighashLabel(0).includes("SIGHASH_DEFAULT"));
  assert.ok(hodlSighashLabel(0x80).includes("ANYONECANPAY"));
});

test("the inspector evaluates Taproot signature sighash bytes like ECDSA ones", () => {
  const render = loadSlice("hodlRenderPsbt");
  // Typed Taproot partial signatures (BIP371 key/script sig fields) are
  // parsed and run through the same blocking policy verdict as ECDSA
  // suffixes; anything but ALL/DEFAULT escalates to a psbt-bad row.
  assert.match(render, /hodlTapKeySigs\(entries, hodlFind\)\.concat\(hodlTapScriptSigs\(entries, hodlFind\)\)/);
  assert.match(render, /hodlTapSighashProblems\(declaredSighash, tapSignature\.sighash, hodlSighashLabel\)/);
  // A Taproot input declaring SIGHASH_DEFAULT (0x00) is not a policy
  // problem; a 0x00 declaration on any other input still is.
  assert.match(render, /declaredSighash === 0 && taprootInput/);
});

test("exact SIGHASH_ALL declared and signed produces no problem", () => {
  assert.deepEqual(hodlSighashProblems(1, 1), []);
  assert.deepEqual(hodlSighashProblems(null, 1), []);
});

test("non-ALL declarations are blocking even with an ALL suffix, in inspection mode", () => {
  for (const [value, name] of BASES.slice(1)) {
    for (const variant of [value, value | 0x80]) {
      const problems = hodlSighashProblems(variant, 1);
      assert.ok(problems.length >= 1 && problems[0].includes(name), `${name}: ${problems.join(" ")}`);
    }
  }
});

test("a non-ALL suffix is blocking even without a declared policy", () => {
  for (const [value, name] of BASES.slice(1)) {
    for (const variant of [value, value | 0x80]) {
      const problems = hodlSighashProblems(null, variant);
      assert.ok(problems.length === 1 && problems[0].includes(name), name);
    }
  }
});

test("a declared/signature mismatch is reported", () => {
  const problems = hodlSighashProblems(1, 0x82);
  assert.ok(problems.some((problem) => problem.includes("disagree")));
});

test("an agreed non-ALL policy still flags both sides of the request", () => {
  const problems = hodlSighashProblems(0x83, 0x83);
  assert.equal(problems.length, 2);
  assert.ok(problems.every((problem) => problem.includes("SIGHASH_SINGLE")), problems.join(" "));
});
