import { test } from "node:test";
import assert from "node:assert/strict";
import { parseOpReturn, inspectPsbtOpReturns, describeOpReturn } from "../src/js/opreturn.js";

const hex = (s) => Uint8Array.from(s.match(/../g).map((b) => parseInt(b, 16)));

test("non-OP_RETURN scripts are ignored", () => {
  assert.equal(parseOpReturn(hex("0014ab".padEnd(44, "0"))), null);
  assert.equal(parseOpReturn(new Uint8Array()), null);
});

test("empty OP_RETURN is detected", () => {
  const parsed = parseOpReturn(hex("6a"));
  assert.equal(parsed.ok, true);
  assert.equal(parsed.payloadBytes, 0);
  assert.equal(parsed.pushes.length, 0);
});

test("single text push is previewed", () => {
  // OP_RETURN PUSH(11) "hello world"
  const parsed = parseOpReturn(hex("6a0b68656c6c6f20776f726c64"));
  assert.equal(parsed.ok, true);
  assert.equal(parsed.payloadBytes, 11);
  const lines = describeOpReturn({ ...parsed, amount: 0n, burned: false });
  assert.ok(lines[0].includes("11 bytes"));
  assert.ok(lines.some((line) => line.includes("hello world")));
});

test("the text preview neutralizes bidi and invisible characters, display only (audit S36-2)", () => {
  // 61 62 63 = "abc", e2 80 ae = U+202E (right-to-left override), 64 65 66 =
  // "def": rendered raw, the override reorders the surrounding report line.
  const parsed = parseOpReturn(hex("6a09616263e280ae646566"));
  assert.equal(parsed.ok, true);
  const lines = describeOpReturn({ ...parsed, amount: 0n, burned: false });
  const preview = lines.find((line) => line.startsWith("text: "));
  assert.ok(preview, "the payload decodes as UTF-8 text");
  assert.ok(!preview.includes("\u202E"), "the preview carries a live bidi override");
  assert.ok(preview.includes("abc\uFFFDdef"), "the override is named by the replacement character");
  // Display-only: the parsed payload keeps the raw bytes, so the transaction's
  // hex/base64 export reads exactly what the script pushes.
  assert.deepEqual([...parsed.payload], [0x61, 0x62, 0x63, 0xe2, 0x80, 0xae, 0x64, 0x65, 0x66]);
});

test("omni and runes-style hints", () => {
  assert.equal(parseOpReturn(hex("6a046f6d6e69")).hint, "omni-prefix");
  // OP_RETURN OP_13 PUSH(1) 00
  assert.equal(parseOpReturn(hex("6a5d0100")).hint, "runes-style (OP_13)");
});

test("non-push after OP_RETURN is malformed, not silent", () => {
  const parsed = parseOpReturn(hex("6aac"));
  assert.equal(parsed.ok, false);
  assert.match(parsed.error, /non-push/);
});

test("inspectPsbtOpReturns reports burns and skips pay-to-address outputs", () => {
  const report = inspectPsbtOpReturns({
    tx: {
      outputs: [
        { amount: 1000n, script: hex("0014" + "11".repeat(20)) },
        { amount: 546n, script: hex("6a046f6d6e69") },
        { amount: 0n, script: hex("6a0b68656c6c6f20776f726c64") },
      ],
    },
  });
  assert.equal(report.count, 2);
  assert.equal(report.burned, true);
  assert.equal(report.outputs[0].output, 1);
  assert.equal(report.outputs[0].burned, true);
  assert.equal(report.outputs[1].burned, false);
  assert.equal(report.payloadBytes, 4 + 11);
});

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

test("inspector source decodes OP_RETURN in the shared output renderer", () => {
  const app = readFileSync(join(dirname(fileURLToPath(import.meta.url)), "..", "src/js/app.js"), "utf8");
  assert.match(app, /from "\.\/opreturn\.js"/);
  assert.match(app, /parseOpReturn\(output\.script\)/);
  assert.match(app, /describeOpReturn/);
});
