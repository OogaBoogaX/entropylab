// OP_RETURN decode in the PSBT editor: an output row whose scriptPubKey is a
// data-carrier script shows the decoded payload (UTF-8 text when it decodes,
// hex otherwise) plus the protocol hint, instead of the bare asm fallback,
// and a non-zero value on such an output is flagged as burned. The decode
// reuses the inspector's parser (src/js/opreturn.js).
// Run with `npm test` (part of the default suite).
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { opReturnSummary } from "../src/js/psbt-editor.js";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const read = (path) => readFileSync(join(root, path), "utf8");

const OP_RETURN = "6a";
const push = (hex) => `${(hex.length / 2).toString(16).padStart(2, "0")}${hex}`;
const textHex = (text) => [...new TextEncoder().encode(text)].map((byte) => byte.toString(16).padStart(2, "0")).join("");

test("a text payload is quoted in the row's decode line", () => {
  const summary = opReturnSummary(OP_RETURN + push(textHex("Hello, Bitcoin")), 0);
  assert.equal(summary.burn, false);
  assert.match(summary.text, /^OP_RETURN · 14 bytes · “Hello, Bitcoin”$/);
});

test("a binary payload shows as hex", () => {
  const summary = opReturnSummary(OP_RETURN + push("deadbeefcafe"), 0);
  assert.match(summary.text, /6 bytes/);
  assert.match(summary.text, /hex deadbeefcafe/);
});

test("protocol hints ride along (ord / omni / runes-style)", () => {
  assert.match(opReturnSummary(OP_RETURN + push(textHex("ord")), 0).text, /ord-prefix/);
  assert.match(opReturnSummary(OP_RETURN + push(textHex("omni")), 0).text, /omni-prefix/);
  // OP_13 after OP_RETURN, the runes marker: 6a 5d
  assert.match(opReturnSummary(`${OP_RETURN}5d`, 0).text, /runes-style/);
});

test("a malformed data-carrier script says so instead of pretending", () => {
  const summary = opReturnSummary(`${OP_RETURN}4c`, 0); // PUSHDATA1 with no length byte
  assert.match(summary.text, /malformed: truncated PUSHDATA1/);
});

test("an empty OP_RETURN carries no payload preview", () => {
  assert.equal(opReturnSummary(OP_RETURN, 0).text, "OP_RETURN · 0 bytes");
});

test("a non-zero value on a data-carrier output is flagged as burned", () => {
  const summary = opReturnSummary(OP_RETURN + push(textHex("x")), 1000);
  assert.equal(summary.burn, true);
  assert.match(summary.text, /burns 1000 sats — unspendable/);
});

test("non-OP_RETURN scripts and half-typed hex leave the row untouched", () => {
  assert.equal(opReturnSummary("76a914" + "11".repeat(20) + "88ac", 0), null); // P2PKH
  assert.equal(opReturnSummary("6a0", 0), null); // odd-length hex mid-edit
  assert.equal(opReturnSummary("", 0), null);
});

test("the editor's output rows render the decode (and burn warning) from the parser", () => {
  const editor = read("src/js/psbt-editor.js");
  assert.match(editor, /import \{ parseOpReturn \} from "\.\/opreturn\.js"/);
  assert.match(editor, /opReturnSummary\(output\.scriptPubKey, output\.value\)/);
  assert.match(editor, /opret\?\.burn \? "psbted-note-warn" : "muted"/);
});
