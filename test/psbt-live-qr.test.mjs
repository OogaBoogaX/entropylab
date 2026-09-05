// Live editing + QR output in the PSBT editor. Every keystroke rebuilds
// through rust-bitcoin (the Re-serialize button is gone); the result panel
// always carries the current build as base64/hex and as a QR — one static
// code for small PSBTs, an animated ur:crypto-psbt sequence for larger ones.
// The plan logic (psbtQrPlan) is pure and tested here; the DOM wiring is
// asserted at source level and exercised end-to-end by the browser suite.
// Run with `npm test` (part of the default suite).
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { psbtQrPlan, PSBT_QR_STATIC_MAX_BYTES } from "../src/js/psbt-editor.js";
import { hodlUrDecodePsbt } from "../src/js/psbt-ur.js";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const read = (path) => readFileSync(join(root, path), "utf8");

const fixtureBytes = (name) => Uint8Array.from(atob(read(`test/fixtures/psbt/${name}`).trim()), (char) => char.charCodeAt(0));

test("a small PSBT plans a single static QR carrying its base64", () => {
  const bytes = fixtureBytes("p2wpkh-1in-2out.b64");
  assert.ok(bytes.length <= PSBT_QR_STATIC_MAX_BYTES, "fixture should fit the static path");
  const plan = psbtQrPlan(bytes);
  assert.equal(plan.mode, "static");
  assert.equal(plan.text, Buffer.from(bytes).toString("base64"));
});

test("a larger PSBT plans an animated UR crypto-psbt sequence", () => {
  const bytes = fixtureBytes("mixed-many-inputs.b64");
  assert.ok(bytes.length > PSBT_QR_STATIC_MAX_BYTES, "fixture should need fragments");
  const plan = psbtQrPlan(bytes);
  assert.equal(plan.mode, "ur");
  assert.ok(plan.parts.length > 1, "expected several fragments");
  for (const part of plan.parts) assert.match(part, /^UR:CRYPTO-PSBT\/\d+-\d+\/[A-Z2-9]+$/);
});

test("the uppercased UR fragments round-trip to the exact PSBT bytes", () => {
  const bytes = fixtureBytes("mixed-many-inputs.b64");
  const plan = psbtQrPlan(bytes);
  // Sparrow-style uppercase fragments: the decoder lowercases first, so the
  // denser alphanumeric QR encoding loses nothing.
  const decoded = hodlUrDecodePsbt(plan.parts.join("\n"));
  assert.deepEqual(decoded.psbt, bytes);
  assert.equal(decoded.parts, plan.parts.length);
});

test("the static/animated threshold is a hard byte count", () => {
  assert.equal(psbtQrPlan(new Uint8Array(PSBT_QR_STATIC_MAX_BYTES)).mode, "static");
  const over = psbtQrPlan(new Uint8Array(PSBT_QR_STATIC_MAX_BYTES + 1));
  assert.equal(over.mode, "ur");
  assert.ok(over.parts.length > 1);
});

test("the editor is live: no Re-serialize button, rebuild on every input event", () => {
  const editor = read("src/js/psbt-editor.js");
  assert.doesNotMatch(editor, /psbted-build" type="button"|id="psbted-build"/);
  assert.doesNotMatch(editor, /\$\("psbted-build"\)/);
  // Every field-edit handler runs the live rebuild.
  const handlers = editor.match(/addEventListener\("input"[\s\S]*?liveRebuild\(\);/g) || [];
  assert.ok(handlers.length >= 8, `expected live rebuild on every field handler, found ${handlers.length}`);
  assert.match(editor, /rebuild\(\{ restoreFocus: true \}\)/);
  // A failed keystroke keeps the fields and flags the last valid build.
  assert.match(editor, /stale = resultBytes !== null;/);
  assert.match(editor, /markResultStale\(\)/);
  // Loading builds immediately, so the result and QR appear without a click.
  assert.match(editor, /resultBytes = null;\s*\n\s*stale = false;\s*\n[\s\S]*?rebuild\(\);/);
});

test("the result panel renders the QR block and its animation plumbing", () => {
  const editor = read("src/js/psbt-editor.js");
  assert.match(editor, /import \{ renderSVG as renderQrSvg \} from "uqr"/);
  assert.match(editor, /import \{ hodlUrEncodePsbt \} from "\.\/psbt-ur\.js"/);
  assert.match(editor, /id="psbted-qr-code"/);
  assert.match(editor, /renderQrSvg\(plan\.text, QR_OPTIONS\)/);
  assert.match(editor, /renderQrSvg\(plan\.parts\[frame\], QR_OPTIONS\)/);
  assert.match(editor, /qrTimer = setInterval\(draw, 600\)/);
  // The animation timer dies with every re-render and with the wipe.
  const clears = editor.match(/clearInterval\(qrTimer\)/g) || [];
  assert.ok(clears.length >= 2, "render and renderResult both clear the QR timer");
  const css = read("src/css/styles.css");
  assert.match(css, /\.psbted-qr svg \{/);
  assert.match(css, /\.psbted-stale \{ opacity: /);
});

test("both intro texts describe the live rebuild and QR output", () => {
  for (const markup of [read("src/shell.html")]) {
    assert.match(markup, /Every edit rebuilds the file through rust-bitcoin as you type/);
    assert.match(markup, /animated ur:crypto-psbt sequence/);
  }
});
