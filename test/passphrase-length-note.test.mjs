// A BIP39 passphrase longer than 50 Unicode code points may not restore on
// some hardware wallets (Trezor raised its limit from 50 to 128 on
// 2026-11-01; older firmware and other devices keep their own limits).
// EntropyLab accepts any length, so it must warn exactly when the passphrase
// is that long: in the Key Station field and under a Vanity passphrase-grind
// result. The approved string is pinned byte for byte.
//
// Contract: a passphrase of more than 50 code points shows the approved note
// in the Key Station and under a Vanity passphrase-grind result; an empty or
// shorter passphrase, and a derivation-grind result, show nothing.
// Run with `npm test`.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const read = (path) => readFileSync(join(root, path), "utf8");

const NOTE = "Some hardware wallets cannot restore a passphrase longer than 50 characters. Check yours before relying on it.";

// The body of a top-level function, from its declaration to its closing brace
// at column 0 (the same slice the wiring tests use).
function functionSource(app, name) {
  const match = app.match(new RegExp(`^function ${name}\\([^]*?^}`, "m"));
  assert.ok(match, `app.js has no top-level ${name}`);
  return match[0];
}

test("the shell carries the hidden passphrase-length note with the approved string", () => {
  const shell = read("src/shell.html");
  const note = shell.match(/<p\b[^>]*\bid="passphrase-length-note"[^>]*>([^<]*)<\/p>/);
  assert.ok(note, "src/shell.html has no #passphrase-length-note paragraph");
  assert.match(note[0], /\bhidden\b/, "the note must start hidden");
  assert.match(note[0], /class="field-note edge-note is-private"/, "the note must use the red edge-note style");
  assert.equal(note[1].trim(), NOTE, "the note must carry the approved string byte for byte");
});

test("the Key Station passphrase state toggles the note by code-point length", () => {
  const source = functionSource(read("src/js/app.js"), "hodlRenderPassphraseInputState");
  assert.ok(source.includes('getElementById("passphrase-length-note")'), "the state renderer must reach the note");
  assert.match(source, /\.hidden\s*=/, "the renderer must set the note's hidden state");
  assert.match(source, />\s*50/, "the rule must be a > 50 comparison");
  assert.match(source, /\[\.\.\.input\.value\]\.length|Array\.from\(input\.value\)\.length/, "the field's length must be counted in code points");
  assert.match(source, /hodlPassphraseVault\.length/, "a vault-held passphrase must be measured by the vault's length");
});

test("the Vanity passphrase-grind result carries the same note under a > 50 rule", () => {
  const source = functionSource(read("src/js/app.js"), "hodlRenderVanityOut");
  assert.ok(source.includes(NOTE), "the vanity result must render the approved string");
  assert.match(source, /hodlT\(\s*"Some hardware wallets cannot restore a passphrase longer than 50 characters\. Check yours before relying on it\."\s*\)/, "the note must go through hodlT");
  assert.match(source, />\s*50/, "the rule must be a > 50 comparison");
  assert.match(source, /Array\.from\(match\.passphrase|\[\.\.\.match\.passphrase/, "the match's length must be counted in code points");
  assert.ok(source.indexOf(NOTE) > source.indexOf("if (derivation)"), "the note must sit in the passphrase branch, after the derivation branch returns");
});
