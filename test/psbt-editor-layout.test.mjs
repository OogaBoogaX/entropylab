// The PSBT editor's unsigned-transaction tables are fixed-layout, so column
// widths come from the header row. These guards keep the utility columns
// (row index, delete) snug, the numeric columns sized near their real
// maxima, and the data columns (txid, scriptPubKey, key, value) wide — the
// regression this guards against is every column sharing the table equally,
// which squeezed the 64-character txid into the same width as a one-digit
// vout. Run with `npm test` (part of the default suite).
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const read = (path) => readFileSync(join(root, path), "utf8");

test("the transaction tables carry distinct classes with sized header columns", () => {
  const editor = read("src/js/psbt-editor.js");
  assert.match(editor, /<table class="psbted-pairs psbted-txins">/);
  assert.match(editor, /<table class="psbted-pairs psbted-txouts">/);
  // Utility columns: snug row index and delete cells.
  assert.match(editor, /<th class="psbted-idx">#<\/th>/);
  assert.match(editor, /<th class="psbted-col-del"><\/th>/);
  // Numeric columns sized by content class.
  assert.match(editor, /<th class="psbted-col-vout">vout<\/th>/);
  assert.match(editor, /<th class="psbted-col-seq">sequence<\/th>/);
  assert.match(editor, /<th class="psbted-col-val">Value \(sats\)<\/th>/);
  // The key-value tables size the field-name column and the delete column.
  assert.match(editor, /<table class="psbted-pairs psbted-kv">/);
  assert.match(editor, /<th class="psbted-col-field">Field<\/th>/);
});

test("the value cell holds just the input — the unit lives in the header", () => {
  const editor = read("src/js/psbt-editor.js");
  assert.match(editor, /Value \(sats\)/);
  assert.doesNotMatch(editor, /data-txout-val="\$\{index\}"[^>]*> sats<\/td>/);
});

test("the CSS gives the data columns the room and keeps fields compact", () => {
  const css = read("src/css/styles.css");
  assert.match(css, /\.psbted-pairs \.psbted-idx \{ width: 2\.5em; \}/);
  assert.match(css, /\.psbted-pairs \.psbted-col-del \{ width: 2\.4em; \}/);
  assert.match(css, /\.psbted-txins \.psbted-col-vout \{ width: 9ch; \}/);
  assert.match(css, /\.psbted-txins \.psbted-col-seq \{ width: 15ch; \}/);
  assert.match(css, /\.psbted-txouts \.psbted-col-val \{ width: 20ch; \}/);
  assert.match(css, /\.psbted-kv \.psbted-col-field \{ width: 15em; \}/);
  // Data-table density: no 44px control heights inside the tables.
  assert.match(css, /\.psbted-pairs input, \.psbted-add input, \.psbted-add select \{[^}]*min-height: 0;/);
  // Version/locktime are compact fields, not full-width rows.
  assert.match(css, /\.psbted-txhead input \{ width: 11em; \}/);
});

test("the script builder input gets the column's room and stays visible", () => {
  const css = read("src/css/styles.css");
  // The select must not claim a full-width field; the text input flexes.
  assert.match(css, /\.psbted-build select \{ width: auto; \}/);
  assert.match(css, /\.psbted-build input, \.psbted-build select \{[^}]*min-height: 0;/);
  // The placeholder announces all four input kinds in the wide cell.
  const editor = read("src/js/psbt-editor.js");
  assert.match(editor, /placeholder="address · OP_… ASM · 0x raw hex · text"/);
});

test("the Add input / Add output actions are not the pair-add grid", () => {
  const editor = read("src/js/psbt-editor.js");
  assert.match(editor, /<div class="psbted-add-el"><button type="button" class="btn secondary" data-tx-add="input">Add input<\/button><\/div>/);
  assert.match(editor, /<div class="psbted-add-el"><button type="button" class="btn secondary" data-tx-add="output">Add output<\/button><\/div>/);
  const css = read("src/css/styles.css");
  assert.match(css, /\.psbted-add-el \{ margin: 4px 0 14px; \}/);
  assert.match(css, /\.psbted-add-el \.btn \{ min-height: 0; padding: 6px 12px; \}/);
});
