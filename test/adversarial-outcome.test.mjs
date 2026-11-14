// When the Jev adversarial run fails (test/adversarial/outcome.mjs). The
// nightly is green only if no scenario did something the app must never do.
//
// Contract: a scenario fails the run when the harness's own checks caught a
// network attempt, an uncaught exception or rejection, a failed invariant or
// a dead page, or when Jev's verdict is "broken". "ok", "suspect" and a
// missing verdict (no API key, the API down) never fails a scenario: a
// suspect is for a person to read, and an outage is not the app's fault.
//
// The run as a whole is another matter. With an API key configured, a run in
// which Jev judged no scenario at all is a judge outage or a refused key, and
// it fails: on 2026-10-09 a rejected key passed silently every night. A run
// with only some verdicts missing warns, naming them. With no key (local
// runs, forks) neither applies.
import { test } from "node:test";
import assert from "node:assert/strict";
import { judgeFailures, judgeWarnings, runFailures } from "./adversarial/outcome.mjs";

// One scenario's results, clean unless a test says otherwise.
const row = (overrides = {}) => ({ name: "scenario", choice: "ok", net: 0, exceptions: 0, rejections: 0, inv: 0, alive: true, failures: [], ...overrides });

test("a clean run, and verdicts that are for a person to read, do not fail", () => {
  assert.deepEqual(runFailures([row(), row({ name: "dice-oversized", choice: "suspect" })]), []);
  assert.deepEqual(runFailures([row({ choice: "(none)" })]), [], "a missing verdict failed the run");
  assert.deepEqual(runFailures([]), []);
});

test("each thing the app must never do fails the run, naming the scenario", () => {
  const cases = [
    [{ net: 2 }, /network/],
    [{ exceptions: 1 }, /exception/],
    [{ rejections: 3 }, /rejection/],
    [{ inv: 1, failures: ["120,000 identical rolls were reported as fair"] }, /120,000 identical rolls were reported as fair/],
    [{ alive: false }, /not alive/],
    [{ choice: "broken" }, /broken/],
  ];
  for (const [overrides, reason] of cases) {
    const failures = runFailures([row(), row({ name: "hostile", ...overrides })]);
    assert.equal(failures.length, 1, `${JSON.stringify(overrides)} did not fail exactly the one scenario`);
    assert.match(failures[0], /^hostile: /, "the failure does not name its scenario");
    assert.match(failures[0], reason);
  }
});

test("every reason a scenario fails is listed, and every failing scenario", () => {
  const failures = runFailures([row({ name: "a", net: 1, choice: "broken" }), row({ name: "b", exceptions: 1 })]);
  assert.equal(failures.length, 3);
  assert.deepEqual(failures.map((failure) => failure.split(":")[0]), ["a", "a", "b"]);
});

test("with a key configured, a run Jev judged no scenario in fails", () => {
  const unjudged = [row({ name: "a", choice: "(none)" }), row({ name: "b", choice: "(none)" })];
  assert.deepEqual(judgeFailures(unjudged, true), ["Jev judged none of the 2 scenario(s): the judge was unreachable or refused the API key"]);
  assert.deepEqual(judgeFailures(unjudged, false), [], "with no key configured there is nothing to judge with");
  assert.deepEqual(judgeFailures([], true), [], "no scenario ran");
  assert.deepEqual(judgeFailures([row({ name: "a", choice: "(none)" }), row({ name: "b", choice: "suspect" })], true), [], "one verdict is enough to show the judge answered");
});

test("with a key configured, a partly judged run warns about the gaps without failing", () => {
  const partial = [row({ name: "a" }), row({ name: "b", choice: "(none)" }), row({ name: "c", choice: "suspect" }), row({ name: "d", choice: "(none)" })];
  assert.deepEqual(judgeFailures(partial, true), []);
  assert.deepEqual(judgeWarnings(partial, true), ["Jev gave no verdict for 2 of 4 scenario(s): b, d"]);
  assert.deepEqual(judgeWarnings(partial, false), [], "no key configured: no warning");
  assert.deepEqual(judgeWarnings([row(), row({ name: "x", choice: "broken" })], true), [], "a fully judged run has no gap");
  // A run Jev judged nothing in is a failure, not also a warning.
  assert.deepEqual(judgeWarnings([row({ choice: "(none)" })], true), []);
});
