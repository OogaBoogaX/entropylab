// A BIP39 passphrase longer than 50 Unicode code points may not restore on
// some hardware wallets (Trezor raised its limit from 50 to 128 on
// 2026-11-01; older firmware and other devices keep their own limits).
// EntropyLab accepts any length, so it must warn exactly when the passphrase
// is that long: in the Key Station field and under a Vanity passphrase-grind
// result while passphrases show.
//
// Contract: a passphrase of more than 50 code points shows the note in the
// Key Station and under a revealed Vanity passphrase-grind result; an empty or
// shorter passphrase, a masked Vanity result and a derivation-grind result
// show nothing. The note's words are copy (AGENTS.md), so these tests hook on
// its id and the rule, never on its text or classes.
// Run with `npm test`.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const read = (path) => readFileSync(join(root, path), "utf8");

// The body of a top-level function, from its declaration to its closing brace
// at column 0 (the same slice the wiring tests use).
function functionSource(app, name) {
  const match = app.match(new RegExp(`^function ${name}\\([^]*?^}`, "m"));
  assert.ok(match, `app.js has no top-level ${name}`);
  return match[0];
}

test("the shell carries a hidden passphrase-length note after the passphrase field", () => {
  const shell = read("src/shell.html");
  const note = shell.match(/<p\b[^>]*\bid="passphrase-length-note"[^>]*>([^<]*)<\/p>/);
  assert.ok(note, "src/shell.html has no #passphrase-length-note paragraph");
  assert.match(note[0], /\bhidden\b/, "the note must start hidden");
  assert.ok(note[1].trim(), "the note says something");
  assert.ok(shell.indexOf('id="pass"') < shell.indexOf('id="passphrase-length-note"'), "the note sits after the passphrase field");
});

test("the Key Station passphrase state toggles the note by code-point length", () => {
  const source = functionSource(read("src/js/app.js"), "hodlRenderPassphraseInputState");
  assert.ok(source.includes('getElementById("passphrase-length-note")'), "the state renderer must reach the note");
  assert.match(source, /\.hidden\s*=/, "the renderer must set the note's hidden state");
  assert.match(source, />\s*50/, "the rule must be a > 50 comparison");
  assert.match(source, /\[\.\.\.input\.value\]\.length|Array\.from\(input\.value\)\.length/, "the field's length must be counted in code points");
  assert.match(source, /hodlPassphraseVault\.length/, "a vault-held passphrase must be measured by the vault's length");
});

test("the Vanity note shows only for a revealed passphrase-grind match over 50 code points", () => {
  const source = functionSource(read("src/js/app.js"), "hodlRenderVanityOut");
  const rule = source.match(/let lengthNote = ([\s\S]*?)\s+\?\s*`<p[^`]*\$\{hodlT\("[^"]+"\)\}<\/p>`\s*:\s*"";/);
  assert.ok(rule, "the note is one literal hodlT string chosen by a single rule");
  // Masked, the column is the mask's width so lengths do not leak (A35-3);
  // the note must not leak them either.
  assert.match(rule[1], /^hodlVanityReveal && /, "the note needs the passphrases revealed");
  assert.match(rule[1], /Array\.from\(match\.passphrase \?\? ""\)\.length > 50/, "the match's length is counted in code points");
  assert.ok(source.indexOf("let lengthNote") > source.indexOf("if (derivation)"), "the note sits in the passphrase branch, after the derivation branch returns");
});
