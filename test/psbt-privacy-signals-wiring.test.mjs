import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const source = readFileSync(new URL("../src/js/app.js", import.meta.url), "utf8");

const bodyOf = (name) => {
  const start = source.indexOf("function " + name + "(");
  assert.ok(start >= 0, name + " is defined");
  const end = source.indexOf("\nfunction ", start + 1);
  return source.slice(start, end < 0 ? source.length : end);
};

const APPROVED = [
  "Some inputs are finalized and others are not. This is the shape of a payjoin proposal, and also of a transaction still being signed by several people. Check every input amount and the fee before signing.",
  "Inputs carry key paths from {count} different master keys. These paths are claims written into the file, not proof of who owns the coins.",
  "{count} outputs pay exactly {amount}. Equal outputs are a coinjoin pattern; they also occur in batched payments.",
  "No payjoin or coinjoin pattern found in this transaction's structure; this does not rule either out.",
  "Some checks could not run: a raw transaction carries no key paths or signing state.",
];

test("app.js imports the pure signals module", () => {
  assert.match(source, /import\s*\{[^}]*psbtPrivacySignals[^}]*\}\s*from\s*["']\.\/psbt-privacy-signals\.js["']/);
});

test("the privacy section is hidden unless the preview flag is on, and absent without signals", () => {
  assert.match(bodyOf("hodlPrivacySignalsHtml"), /if \(!PREVIEW \|\| !signals\) return "";/);
});

test("the master-keys line counts master keys, not groups", () => {
  assert.match(bodyOf("hodlPrivacySignalsHtml"), /if \(signals\.originGroups >= 2\)/);
  assert.match(bodyOf("hodlPrivacySignalsHtml"), /\{ count: signals\.masterKeys \}/);
});

test("the section carries the approved data hooks", () => {
  const fn = bodyOf("hodlPrivacySignalsHtml");
  for (const hook of [
    "data-privacy-signals",
    "data-privacy-signal='proposal-shape'",
    "data-privacy-signal='origin-groups'",
    "data-privacy-signal='equal-outputs'",
    "data-privacy-signal='unavailable'",
    "data-privacy-signal='none'",
  ]) {
    assert.ok(fn.includes(hook), hook);
  }
});

// The call sits on one line inside its own try (GLM, round 1: an earlier try
// elsewhere in the function proved nothing), after the nonce view returns,
// and its result is only placed last in a return.
test("both render functions compute the section once, in its own try, and place it last", () => {
  for (const name of ["hodlRenderPsbt", "hodlRenderRawTx"]) {
    const fn = bodyOf(name);
    const lines = fn.split("\n");
    const calls = lines.filter((line) => line.includes("hodlPrivacySignalsHtml"));
    assert.equal(calls.length, 1, name + " computes it on one line");
    assert.match(calls[0], /^\s*try \{ privacy = hodlPrivacySignalsHtml\(psbtPrivacySignals\(\{ inputs: [^}]*\}\)\); \} catch \{\}$/, name + " computes it inside its own try");
    const nonce = fn.indexOf('if (view === "nonce") return');
    assert.ok(nonce >= 0 && nonce < fn.indexOf("hodlPrivacySignalsHtml"), name + " computes it after the nonce view returns");
    const uses = lines.filter((line) => /\bprivacy\b/.test(line) && !line.includes("hodlPrivacySignalsHtml") && !/let privacy = "";/.test(line));
    assert.ok(uses.length >= 1, name + " places it");
    for (const line of uses) assert.match(line, /^\s*(if \(view === "inspect"\) )?return .*privacy\)\.join\(""\);$/, name + " only places it last in a return");
  }
});

test("the five approved strings appear exactly once", () => {
  for (const text of APPROVED) {
    assert.equal(source.split(text).length - 1, 1, text.slice(0, 40));
  }
});

test("app.js does not import the payjoin checklist", () => {
  assert.ok(!/from\s+["'][^"']*payjoin-check\.js["']/.test(source));
});
