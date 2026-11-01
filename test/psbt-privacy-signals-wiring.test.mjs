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

test("the privacy section is hidden unless the preview flag is on", () => {
  assert.match(bodyOf("hodlPrivacySignalsHtml"), /if \(!PREVIEW\) return "";/);
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

test("both render functions push the section once, after the nonce view, inside a try", () => {
  for (const name of ["hodlRenderPsbt", "hodlRenderRawTx"]) {
    const fn = bodyOf(name);
    assert.equal(fn.split("hodlPrivacySignalsHtml").length - 1, 1, name + " calls it once");
    const call = fn.indexOf("hodlPrivacySignalsHtml");
    assert.ok(fn.includes("html.push(hodlPrivacySignalsHtml("), name + " pushes the result");
    const nonce = fn.indexOf('if (view === "nonce") return');
    assert.ok(nonce >= 0 && nonce < call, name + " calls it after the nonce view returns");
    assert.ok(fn.lastIndexOf("try {", call) >= 0, name + " wraps the call in try");
    assert.ok(fn.indexOf("catch", call) > call, name + " catches a throw");
  }
});

test("no other line reads the section result", () => {
  for (const name of ["hodlRenderPsbt", "hodlRenderRawTx"]) {
    const lines = bodyOf(name).split("\n").filter((line) => line.includes("hodlPrivacySignalsHtml"));
    assert.equal(lines.length, 1, name + " mentions it on one line");
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
