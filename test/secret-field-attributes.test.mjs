// Text fields that take secrets must opt out of the browser's text services.
// Chrome spellchecks single-line text inputs, and with its Enhanced spell
// check setting on it sends the typed text to a Google service: for a seed,
// key, or BIP39 passphrase field that is network egress (CONTRIBUTING §3).
// Mobile keyboards may also auto-capitalize, which silently changes a
// passphrase. Password-type fields are exempt: browsers never spellcheck them.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const shell = readFileSync(join(root, "src/shell.html"), "utf8");

const fields = [...shell.matchAll(/<(input|textarea)\b[^>]*>/g)].map(([tag, kind]) => {
  const attr = (name) => tag.match(new RegExp(`\\s${name}="([^"]*)"`))?.[1];
  return { tag, kind, id: attr("id") ?? "", type: attr("type") ?? (kind === "textarea" ? "textarea" : "text"), attr };
});
// Every text-entry field whose id names a key, seed, or passphrase.
const secretFields = fields.filter((field) =>
  ["text", "textarea"].includes(field.type) && /(^|-)(key|seed|pass)$/.test(field.id));

test("the secret-field pattern finds the known seed, key, and passphrase fields", () => {
  const ids = secretFields.map((field) => field.id);
  for (const id of ["pass", "bip85-key", "sp-key", "sp-pass", "psbt-key", "psbt-pass", "nonce-key", "nonce-pass", "ln-seed"]) {
    assert.ok(ids.includes(id), `${id} is not matched; the guard below would skip it`);
  }
});

test("secret text fields disable spellcheck and autocomplete", () => {
  for (const field of secretFields) {
    assert.equal(field.attr("spellcheck"), "false", `#${field.id} must set spellcheck="false"`);
    assert.equal(field.attr("autocomplete"), "off", `#${field.id} must set autocomplete="off"`);
  }
});

test("secret text fields disable auto-capitalization, except the main passphrase which toggles it at runtime", () => {
  // #pass is excluded on purpose: hodlRenderPassphraseInputState sets its
  // autocapitalize from the BIP39-words switch; that behavior is a UI decision
  // outside this guard.
  for (const field of secretFields.filter((candidate) => candidate.id !== "pass")) {
    assert.equal(field.attr("autocapitalize"), "off", `#${field.id} must set autocapitalize="off"`);
  }
});
