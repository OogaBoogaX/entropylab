// OpenTimestamps verifier UI tests — issue #315, phase 3.
//
// DOM-free tests for the pure helpers in src/js/ots-verifier-ui.js.
// The DOM-wiring `initOtsVerifier()` is exercised manually (browser) and
// isn't unit-tested here — the repo's test suite is Node-based without
// jsdom, so this matches the established convention (see other tool
// modules that similarly don't unit-test their DOM wiring).

import { test } from "node:test";
import assert from "node:assert/strict";

import { parseHexInput, formatResult, formatError } from "../src/js/ots-verifier-ui.js";
import { OtsParseError, OtsBudgetError } from "../src/js/ots-parser.js";

// ---- parseHexInput --------------------------------------------------------

test("parseHexInput: plain hex", () => {
  const u = parseHexInput("deadbeef");
  assert.equal(u.length, 4);
  assert.deepEqual(Array.from(u), [0xde, 0xad, 0xbe, 0xef]);
});

test("parseHexInput: leading 0x prefix is stripped", () => {
  const u = parseHexInput("0xdeadbeef");
  assert.equal(u.length, 4);
  assert.equal(u[0], 0xde);
});

test("parseHexInput: leading whitespace before a 0x prefix is accepted", () => {
  const u = parseHexInput(" 0xdeadbeef");
  assert.equal(u.length, 4);
  assert.equal(u[0], 0xde);
});

test("parseHexInput: uppercase is normalized", () => {
  const a = parseHexInput("DEADBEEF");
  const b = parseHexInput("deadbeef");
  assert.deepEqual(Array.from(a), Array.from(b));
});

test("parseHexInput: whitespace and commas stripped", () => {
  const u = parseHexInput("de ad  be\nef,12, 34");
  assert.deepEqual(Array.from(u), [0xde, 0xad, 0xbe, 0xef, 0x12, 0x34]);
});

test("parseHexInput: empty / whitespace-only input throws RangeError", () => {
  assert.throws(() => parseHexInput(""), RangeError);
  assert.throws(() => parseHexInput("   "), RangeError);
});

test("parseHexInput: odd length throws RangeError", () => {
  assert.throws(() => parseHexInput("abc"), RangeError);
});

test("parseHexInput: non-hex characters throw", () => {
  assert.throws(() => parseHexInput("nothex"), (e) => /non-hex/i.test(e.message));
});

test("parseHexInput: non-string input throws TypeError", () => {
  assert.throws(() => parseHexInput(123), TypeError);
  assert.throws(() => parseHexInput(undefined), TypeError);
  assert.throws(() => parseHexInput(null), TypeError);
});

// ---- formatResult ---------------------------------------------------------

const VERDICTS = [
  ["MATCHES_SUPPLIED_HEADER", "success"],
  ["INVALID", "danger"],
  ["HEADER_REQUIRED", "warning"],
  ["INCOMPLETE", "warning"],
  ["PENDING", "warning"],
  ["UNSUPPORTED", "neutral"],
];

test("formatResult: every verdict yields a non-empty headline and body with its tone", () => {
  for (const [result, tone] of VERDICTS) {
    const r = formatResult({ result, paths: [], summary: {} });
    assert.equal(r.tone, tone, result);
    assert.equal(typeof r.headline, "string", result);
    assert.ok(r.headline.length > 0, `${result} headline is non-empty`);
    assert.equal(typeof r.body, "string", result);
    assert.ok(r.body.length > 0, `${result} body is non-empty`);
  }
});

test("formatResult: every INVALID reason yields a non-empty headline and body", () => {
  const reasons = ["parse:BAD_MAGIC", "expected-digest", "original-file", "op-too-long", "header-mismatch"];
  for (const reason of reasons) {
    const r = formatResult({ result: "INVALID", reason, paths: [], summary: {} });
    assert.equal(r.tone, "danger", reason);
    assert.ok(r.headline.length > 0, `${reason} headline is non-empty`);
    assert.ok(r.body.length > 0, `${reason} body is non-empty`);
  }
});

test("formatResult: MATCHES warns the header is user-supplied and not verified", () => {
  const r = formatResult({ result: "MATCHES_SUPPLIED_HEADER", paths: [], summary: { matches: 1 } });
  assert.match(r.body, /Header supplied by user/);
  assert.match(r.body, /not verified/);
});

test("formatResult: PENDING does not establish Bitcoin anchoring", () => {
  const r = formatResult({ result: "PENDING", paths: [], summary: { pending: 1 } });
  assert.match(r.body, /does not establish Bitcoin anchoring/);
});

test("formatResult: INCOMPLETE is not a verdict about the proof", () => {
  const r = formatResult({ result: "INCOMPLETE", reason: "too-many-ops", paths: [], summary: {} });
  assert.match(r.body, /not a verdict about the proof/);
});

test("formatResult: unknown result returns neutral tone with the literal value", () => {
  const r = formatResult({ result: "WEIRD_NEW_STATE", paths: [], summary: {} });
  assert.equal(r.tone, "neutral");
  assert.equal(r.headline, "WEIRD_NEW_STATE");
});

// ---- formatError ----------------------------------------------------------

test("formatError: OtsParseError keeps the error code", () => {
  const err = new OtsParseError("BAD_MAGIC", "wrong magic");
  const r = formatError(err);
  assert.equal(r.tone, "danger");
  assert.ok(r.headline.includes("BAD_MAGIC"), "the code appears in the headline");
  assert.equal(r.body, err.message);
});

test("formatError: OtsBudgetError keeps the resource-limit code", () => {
  const err = new OtsBudgetError("too-many-ops", "more than 1024 op nodes");
  const r = formatError(err);
  assert.equal(r.tone, "danger");
  assert.ok(r.headline.includes("too-many-ops"), "the code appears in the headline");
  assert.equal(r.body, err.message);
});

test("formatError: RangeError surfaces the message", () => {
  const r = formatError(new RangeError("too short"));
  assert.equal(r.tone, "danger");
  assert.ok(r.headline.length > 0);
  assert.equal(r.body, "too short");
});

test("formatError: TypeError surfaces the message", () => {
  const r = formatError(new TypeError("expected a string"));
  assert.equal(r.tone, "danger");
  assert.ok(r.headline.length > 0);
  assert.equal(r.body, "expected a string");
});

test("formatError: unknown values fall back to String(err)", () => {
  const r = formatError("oops");
  assert.equal(r.tone, "danger");
  assert.match(r.body, /oops/);
});


