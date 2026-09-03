// Upload support for the PSBT editor. Wallets (Sparrow, Coldcard, …) save a
// PSBT as a binary .psbt file that starts with the "psbt\xff" magic, while a
// "copy PSBT" export saved to disk is base64 (or hex) text.
// psbtBytesFromUpload accepts both: it sniffs the magic first, then falls
// back to the paste-box text rules, so a Sparrow binary loads as-is and a
// text export never needs re-encoding by hand. Run with `npm test`.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { psbtBytesFromText, psbtBytesFromUpload } from "../src/js/psbt-editor.js";
import { psbtInspectDoc } from "../src/js/psbt-wasm.js";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const read = (path) => readFileSync(join(root, path), "utf8");

// A real editor fixture doubles as the "Sparrow binary": the decoded bytes
// of the .b64 file are exactly what Sparrow writes into a .psbt file.
const fixtureB64 = read("test/fixtures/psbt/p2wpkh-1in-2out.b64").trim();
const fixtureBytes = Uint8Array.from(atob(fixtureB64), (char) => char.charCodeAt(0));
const fixtureHex = [...fixtureBytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");

test("a binary .psbt upload (Sparrow) passes through untouched and parses", () => {
  assert.deepEqual(psbtBytesFromUpload(fixtureBytes), fixtureBytes);
  const doc = psbtInspectDoc(psbtBytesFromUpload(fixtureBytes));
  assert.equal(doc.psbtVersion, 0);
  assert.ok(doc.tx.inputs.length >= 1, "fixture should carry inputs");
});

test("a base64 text export saved to disk decodes like the paste box", () => {
  assert.deepEqual(psbtBytesFromUpload(new TextEncoder().encode(fixtureB64)), fixtureBytes);
  assert.deepEqual(psbtBytesFromUpload(new TextEncoder().encode(`\n ${fixtureB64} \n`)), fixtureBytes);
});

test("a hex text file decodes like the paste box", () => {
  assert.deepEqual(psbtBytesFromUpload(new TextEncoder().encode(fixtureHex)), fixtureBytes);
  assert.deepEqual(psbtBytesFromUpload(new TextEncoder().encode(fixtureHex.toUpperCase())), fixtureBytes);
});

test("a UTF-8 BOM ahead of a text export is stripped by the text decode", () => {
  const bom = Uint8Array.of(0xef, 0xbb, 0xbf);
  const body = new TextEncoder().encode(fixtureB64);
  const bytes = new Uint8Array(bom.length + body.length);
  bytes.set(bom);
  bytes.set(body, bom.length);
  assert.deepEqual(psbtBytesFromUpload(bytes), fixtureBytes);
});

test("upload rejects what the paste box rejects, with its messages", () => {
  assert.throws(() => psbtBytesFromUpload(new Uint8Array()), /Choose a PSBT file/);
  assert.throws(() => psbtBytesFromUpload(new TextEncoder().encode("not a psbt at all")), /base64 or hex/);
  assert.throws(() => psbtBytesFromUpload(new Uint8Array(5e6 + 1)), /too large/);
  // A binary file without the magic is not assumed to be a PSBT.
  const corrupt = fixtureBytes.slice();
  corrupt[0] = 0x00;
  assert.throws(() => psbtBytesFromUpload(corrupt), /base64 or hex/);
});

test("upload and paste routes agree on the same PSBT", () => {
  assert.deepEqual(psbtBytesFromUpload(fixtureBytes), psbtBytesFromText(fixtureB64));
});

test("both markups carry the upload control, and the editor wires it", () => {
  const editor = read("src/js/psbt-editor.js");
  for (const markup of [read("src/index.html"), read("src/js/app.js")]) {
    assert.match(markup, /<button class="btn secondary" id="psbted-upload" type="button"[^>]*>/);
    assert.match(markup, /<input type="file" id="psbted-file" /);
    assert.match(markup, /binary \.psbt file as saved by Sparrow/);
  }
  assert.match(editor, /getElementById\("psbted-file"\)|\$\("psbted-file"\)/);
  assert.match(editor, /getElementById\("psbted-upload"\)|\$\("psbted-upload"\)/);
  assert.match(editor, /psbtBytesFromUpload\(new Uint8Array\(await chosen\.arrayBuffer\(\)\)\)/);
});

test("the result panel offers a binary .psbt download", () => {
  const editor = read("src/js/psbt-editor.js");
  assert.match(editor, /id="psbted-download"/);
  assert.match(editor, /new Blob\(\[resultBytes\]/);
  assert.match(editor, /link\.download = "edited\.psbt"/);
});
