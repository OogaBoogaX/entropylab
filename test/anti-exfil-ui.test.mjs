// Nonce Inspector transcript reader: release path vs preview path.
// Run with: npm run test:ci
import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import vm from "node:vm";

import { readAntiExfil } from "../src/js/anti-exfil.js";
import { aexbDecode, aexbVerify } from "../src/js/aexb.js";
import { secp256k1Ready } from "../src/js/secp256k1.js";
import { hashesReady } from "../src/js/hashes.js";

await secp256k1Ready;
await hashesReady;

const root = dirname(fileURLToPath(import.meta.url));
const app = readFileSync(join(root, "..", "src/js/app.js"), "utf8");

function loadSlice(name) {
  const start = app.indexOf(`function ${name}(`);
  assert.ok(start >= 0, name);
  let depth = 0;
  let end = -1;
  for (let i = app.indexOf("{", start); i < app.length; i++) {
    if (app[i] === "{") depth++;
    else if (app[i] === "}") {
      depth--;
      if (depth === 0) {
        end = i + 1;
        break;
      }
    }
  }
  assert.ok(end > start, name);
  return app.slice(start, end);
}

const hodlHex = {
  encode: (bytes) => Buffer.from(bytes).toString("hex"),
  decode: (hex) => Uint8Array.from(Buffer.from(hex, "hex")),
};
const hodlParseAntiExfil = new Function(
  "hodlHex",
  `${loadSlice("hodlParseAntiExfil")}; return hodlParseAntiExfil;`,
)(hodlHex);

// The helper runs in its own realm with the real modules, so a missing import
// or a stray global fails here rather than in the page.
const context = vm.createContext({ readAntiExfil, aexbVerify, hodlParseAntiExfil });
vm.runInContext(
  `${loadSlice("hodlVerifyAexbMessages")}; ${loadSlice("hodlReadNonceTranscript")}; globalThis.hodlReadNonceTranscript = hodlReadNonceTranscript;`,
  context,
);
const hodlReadNonceTranscript = context.hodlReadNonceTranscript;
const hodlAexbSlotVerdict = new Function(`${loadSlice("hodlAexbSlotVerdict")}; return hodlAexbSlotVerdict;`)();

// From test/psbt-anti-exfil.test.mjs, "parses host nonce and compressed opening as separate hex".
const jadeHost = "11".repeat(32);
const jadeOpening = "02466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f27";
// From test/psbt-bitbox-s2c.test.mjs, "one 32-byte field is the revealed host nonce, not the SHA256 commitment".
const bitboxHost = "11".repeat(32);
const bitboxOpening = "02466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f27";
const bitboxCommitment = hodlHex.encode(
  new Uint8Array(createHash("sha256").update(Buffer.from(bitboxHost, "hex")).digest()),
);

const positive = JSON.parse(
  readFileSync(join(root, "fixtures", "aexb", "protocol-v1-multislot-vectors.json"), "utf8"),
);
const negative = JSON.parse(
  readFileSync(join(root, "fixtures", "aexb", "protocol-v1-negative-vectors.json"), "utf8"),
);
const stage1 = positive.messages.find((vector) => vector.stage === 1);
const stage2 = positive.messages.find((vector) => vector.stage === 2);
const stage3 = positive.messages.find((vector) => vector.stage === 3);
const stage4 = positive.messages.find((vector) => vector.stage === 4);
const negativeStage4 = negative.cases.find((vector) => vector.stage === 4);

test("release path is exactly hodlParseAntiExfil", () => {
  const raw = `${jadeHost}\n${jadeOpening}`;
  const expected = hodlParseAntiExfil(raw);
  const release = hodlReadNonceTranscript(raw, false);
  assert.equal(release.kind, "jade");
  assert.equal(release.warningCode, null);
  assert.equal(release.aexb, null);
  assert.equal(hodlHex.encode(release.transcript.host), hodlHex.encode(expected.host));
  assert.equal(release.transcript.openings.length, expected.openings.length);
  assert.equal(hodlHex.encode(release.transcript.openings[0]), hodlHex.encode(expected.openings[0]));
});

test("release path reports a parse error instead of throwing", () => {
  const release = hodlReadNonceTranscript("aa".repeat(40), false);
  assert.ok(release.error);
  assert.equal(release.transcript, undefined);
});

test("preview path detects a two-value BitBox02 transcript", () => {
  const bitbox = hodlReadNonceTranscript(`${bitboxHost} ${bitboxCommitment} ${bitboxOpening}`, true);
  assert.equal(bitbox.kind, "bitbox02");
  assert.equal(bitbox.warningCode, null);
  assert.equal(hodlHex.encode(bitbox.transcript.host), bitboxHost);
  assert.equal(hodlHex.encode(bitbox.transcript.openings[0]), bitboxOpening);
});

test("preview path keeps the Jade/BitBox02 warning code for a single host nonce", () => {
  const jade = hodlReadNonceTranscript(`${jadeHost} ${jadeOpening}`, true);
  assert.equal(jade.kind, "jade");
  assert.equal(jade.warningCode, "jade-or-bitbox02");
  assert.equal(hodlHex.encode(jade.transcript.host), jadeHost);
});

test("preview path returns an AEXB verdict for an AEXB fixture", () => {
  // A single AEXB/AEXT message carries no earlier stage, so aexbVerify can
  // only refuse it: stage 4 has no reveal, stage 3 has no stage-2 commitment.
  const signatures = hodlReadNonceTranscript(stage4.message_hex, true);
  assert.equal(signatures.kind, "aexb");
  assert.equal(signatures.transcript, null);
  assert.equal(signatures.aexb.ok, false);
  assert.equal(signatures.aexb.reason, "MISSING_REVEAL");

  const reveal = hodlReadNonceTranscript(stage3.message_hex, true);
  assert.equal(reveal.kind, "aexb");
  assert.equal(reveal.aexb.ok, false);
  assert.equal(reveal.aexb.reason, "MISSING_COMMITMENT");
});

test("preview path verifies stages 2, 3 and 4 pasted one per line", () => {
  const result = hodlReadNonceTranscript([stage2.message_hex, stage3.message_hex, stage4.message_hex].join("\n"), true);
  assert.equal(result.kind, "aexb");
  assert.equal(result.aexb.ok, true);
  assert.equal(result.aexb.slots.length, positive.slot_count);
});

test("preview path verifies the same stages in reverse order", () => {
  const result = hodlReadNonceTranscript([stage4.message_hex, stage3.message_hex, stage2.message_hex].join("\n"), true);
  assert.equal(result.kind, "aexb");
  assert.equal(result.aexb.ok, true);
  assert.equal(result.aexb.slots.length, positive.slot_count);
});

test("preview path verifies stages 2, 3 and 4 when each message is line-wrapped", () => {
  const wrap = (hex) => hex.match(/.{1,64}/g).join("\n");
  const result = hodlReadNonceTranscript([stage2, stage3, stage4].map((vector) => wrap(vector.message_hex)).join("\n"), true);
  assert.equal(result.kind, "aexb");
  assert.equal(result.aexb.ok, true);
  assert.equal(result.aexb.slots.length, positive.slot_count);
});

test("preview path uses a stage-1 commitment when no stage-2 message is present", () => {
  const expected = aexbVerify(aexbDecode(stage4.message_hex), aexbDecode(stage3.message_hex), aexbDecode(stage1.message_hex));
  const result = hodlReadNonceTranscript([stage1.message_hex, stage3.message_hex, stage4.message_hex].join("\n"), true);
  assert.equal(result.kind, "aexb");
  assert.deepEqual(result.aexb, expected);
});

test("preview path refuses two messages with the same stage", () => {
  const result = hodlReadNonceTranscript([stage4.message_hex, stage4.message_hex].join("\n"), true);
  assert.equal(result.kind, "aexb");
  // The verdict is built inside the helper's realm, so compare its fields.
  assert.equal(result.aexb.ok, false);
  assert.equal(result.aexb.reason, "DUPLICATE_STAGE");
  assert.equal(result.aexb.slots.length, 0);
});

test("preview path verifies stage 4 and stage 3 without a commitment", () => {
  const expected = aexbVerify(aexbDecode(stage4.message_hex), aexbDecode(stage3.message_hex), null);
  const result = hodlReadNonceTranscript([stage4.message_hex, stage3.message_hex].join("\n"), true);
  assert.equal(result.kind, "aexb");
  assert.deepEqual(result.aexb, expected);
});

test("preview path refuses a negative stage-4 message with positive stages 2 and 3", () => {
  // The negative vector already fails while decoding (its expected_error), so
  // the reader names the third message and nothing is verified.
  const result = hodlReadNonceTranscript([stage2.message_hex, stage3.message_hex, negativeStage4.message_hex].join("\n"), true);
  assert.equal(result.kind, undefined);
  assert.equal(result.aexb, undefined);
  assert.match(result.error, /^Message 3: /);
});

test("preview path never reads a BitBox02 pair whose commitment does not match as BitBox02", () => {
  // hodlParseBitboxTranscript refuses two 32-byte fields that are not
  // SHA256(host nonce) and the host nonce, so such a pair is never a
  // BitBox02 transcript with a mismatched commitment.
  const wrongCommitment = "00".repeat(32);
  const result = hodlReadNonceTranscript(`${bitboxHost} ${wrongCommitment} ${bitboxOpening}`, true);
  assert.notEqual(result.kind, "bitbox02");
});

test("preview path returns an error for malformed input and nothing for empty input", () => {
  const bad = hodlReadNonceTranscript("not hex at all", true);
  assert.ok(bad.error);
  assert.deepEqual({ ...hodlReadNonceTranscript("", true) }, { transcript: null });
});

test("the render reads the transcript through the helper, behind the preview flag", () => {
  const render = loadSlice("hodlRenderPsbt");
  // The flag is read through a typeof guard, and a release build (or a slice
  // loaded alone) keeps the exact Jade-only call.
  assert.match(render, /let preview = typeof PREVIEW !== "undefined" && PREVIEW;/);
  assert.match(render, /let raw = \(options\?\.transcript \?\? document\.getElementById\("psbt-ax-transcript"\)\?\.value\) \|\| "";\s*if \(!preview\) transcript = hodlParseAntiExfil\(raw\);\s*else \{\s*const read = hodlReadNonceTranscript\(raw, true\);/);
  assert.match(app, /transcript: hodlParseAntiExfil\(raw\)/);
  // The preview labels are no longer an inline block: they are re-applied by
  // the locale listener, behind the same PREVIEW guard.
  assert.match(app, /if \(PREVIEW\) hodlApplyAexbPreviewLabels\(\);/);
  assert.match(app, /function hodlApplyAexbPreviewLabels\(\) \{[\s\S]*?Anti-exfil transcript \(Jade, BitBox02 or AEXB, optional\)/);
});

test("the preview flag is defined behind a typeof guard, so release builds still boot", () => {
  // Release builds leave __ENTROPYLAB_PREVIEW__ undeclared: a bare reference
  // would throw at boot in hodlInitPsbt and break the PSBT tools.
  assert.match(app, /^var PREVIEW = typeof __ENTROPYLAB_PREVIEW__ !== "undefined" && __ENTROPYLAB_PREVIEW__;$/m);
  assert.ok(app.indexOf("var PREVIEW =") < app.indexOf("function hodlInitPsbt()"), "PREVIEW is declared before hodlInitPsbt");
  // The imports sit with the module's others, not mid-file.
  assert.ok(app.indexOf('import { readAntiExfil } from "./anti-exfil.js";') < app.indexOf("function "), "anti-exfil import is at the top");
});

test("a failing AEXB verdict names the failing slot's reason, escaped outside hodlT", () => {
  const render = loadSlice("hodlRenderPsbt");
  assert.match(render, /hodlT\("AEXB transcript does not check out:"\) \+ " <code>" \+ hodlEscapeHtml\(aexbResult\.reason \|\| aexbResult\.slots\?\.find\(\(slot\) => !slot\.ok\)\?\.reason \|\| ""\) \+ "<\/code><\/p>"/);
});

test("the render passes the Jade/BitBox02 warning to hodlT as a literal", () => {
  const render = loadSlice("hodlRenderPsbt");
  // A literal, so the string catalog can find it; never a runtime string.
  assert.match(render, /transcriptWarningCode === "jade-or-bitbox02"\)[^\n]*hodlT\("/);
  assert.doesNotMatch(render, /hodlT\(transcriptWarning\b/);
});

test("preview path refuses a stage-3 reveal without a stage-4 signature message", () => {
  const result = hodlReadNonceTranscript([stage2.message_hex, stage3.message_hex].join("\n"), true);
  assert.equal(result.kind, "aexb");
  assert.equal(result.aexb.ok, false);
  assert.equal(result.aexb.reason, "MISSING_SIGNATURES");
  assert.equal(result.aexb.slots.length, 0);
  assert.equal(result.aexbSignatures, null);
});

test("preview path still reports a missing commitment for a lone stage-3 reveal", () => {
  const result = hodlReadNonceTranscript(stage3.message_hex, true);
  assert.equal(result.kind, "aexb");
  assert.equal(result.aexb.ok, false);
  assert.equal(result.aexb.reason, "MISSING_COMMITMENT");
  assert.equal(result.aexbSignatures, null);
});

test("preview path hands the stage-4 message to the render when the verdict passes", () => {
  const result = hodlReadNonceTranscript([stage2.message_hex, stage3.message_hex, stage4.message_hex].join("\n"), true);
  assert.equal(result.kind, "aexb");
  assert.equal(result.aexb.ok, true);
  assert.ok(result.aexbSignatures);
  assert.equal(result.aexbSignatures.stage, 4);
  assert.equal(hodlHex.encode(result.aexbSignatures.sessionId), hodlHex.encode(aexbDecode(stage4.message_hex).sessionId));
});

test("preview path withholds the stage-4 message when the verdict fails", () => {
  const result = hodlReadNonceTranscript(stage4.message_hex, true);
  assert.equal(result.kind, "aexb");
  assert.equal(result.aexb.ok, false);
  assert.equal(result.aexbSignatures, null);
});

test("the AEXB slot verdict matches a signature against its transcript slot", () => {
  const decoded = aexbDecode(stage4.message_hex);
  const slot = decoded.slots[0];
  const r = slot.signature.slice(0, 32);
  const s = slot.signature.slice(32);
  assert.equal(hodlAexbSlotVerdict([slot], slot.inputIndex, slot.signerPubkey, r, s, slot.messageHash), "match");
  // A low-s normalised copy of s names the same signature.
  const n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n;
  let value = 0n;
  for (const byte of s) value = (value << 8n) | BigInt(byte);
  let rest = n - value;
  const negated = new Uint8Array(32);
  for (let i = 31; i >= 0; i--) {
    negated[i] = Number(rest & 0xffn);
    rest >>= 8n;
  }
  assert.equal(hodlAexbSlotVerdict([slot], slot.inputIndex, slot.signerPubkey, r, negated, slot.messageHash), "match");
  // A changed r is a different signature.
  const changedR = r.slice();
  changedR[0] ^= 1;
  assert.equal(hodlAexbSlotVerdict([slot], slot.inputIndex, slot.signerPubkey, changedR, s, slot.messageHash), "mismatch");
  // A different message hash with a known sighash is a different message.
  const otherHash = new Uint8Array(32).fill(0x42);
  assert.equal(hodlAexbSlotVerdict([slot], slot.inputIndex, slot.signerPubkey, r, s, otherHash), "mismatch");
  // Without a known sighash the r and s still decide.
  assert.equal(hodlAexbSlotVerdict([slot], slot.inputIndex, slot.signerPubkey, r, s, null), "match");
  // Another input or another key has no slot.
  assert.equal(hodlAexbSlotVerdict([slot], slot.inputIndex + 1, slot.signerPubkey, r, s, slot.messageHash), "no-slot");
  const otherPubkey = slot.signerPubkey.slice();
  otherPubkey[0] = otherPubkey[0] === 2 ? 3 : 2;
  assert.equal(hodlAexbSlotVerdict([slot], slot.inputIndex, otherPubkey, r, s, slot.messageHash), "no-slot");
});

test("the render compares each signature with the AEXB transcript's slots", () => {
  const render = loadSlice("hodlRenderPsbt");
  assert.match(render, /else if \(aexbSignatures\) \{[\s\S]*?hodlAexbSlotVerdict\(aexbSignatures\.slots, index, hodlCompressedPubkey\(signature\.pubkey\), parts\.r, parts\.s, sighash\)/);
  assert.match(render, /aexbSignatures = read\.aexbSignatures \|\| null;/);
});

test("the AEXB summary line only turns green when every ECDSA signature in the PSBT matched", () => {
  const render = loadSlice("hodlRenderPsbt");
  // rfcTotal counts every ECDSA signature, including ones stopped before the
  // slot comparison, so any of those keeps the line from turning green.
  assert.match(render, /const aexbCovered = rfcTotal > 0 && aexbMatched === rfcTotal;/);
  assert.match(render, /aexbResult\.ok\s*\?\s*aexbCovered/);
  // Only the match branch counts, and the green line reports that count.
  assert.equal(render.match(/aexbMatched \+= 1;/g)?.length, 1);
  assert.match(render, /\{ n: aexbMatched \}/);
});
