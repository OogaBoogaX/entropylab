// Global entropy sync shares direct entropy bits across every input method. Hashed
// methods may publish their digest, but their original transcripts are never
// reverse-filled.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = dirname(fileURLToPath(import.meta.url));
const app = readFileSync(join(root, "..", "src/js/app.js"), "utf8");
const shell = readFileSync(join(root, "..", "src/shell.html"), "utf8");

function loadSlice(name) {
  const start = app.indexOf(`function ${name}(`);
  assert.ok(start >= 0, name);
  const body = app.indexOf("{", start);
  let depth = 0;
  for (let index = body; index < app.length; index++) {
    if (app[index] === "{") depth++;
    else if (app[index] === "}" && --depth === 0) return app.slice(start, index + 1);
  }
  throw new Error(`Could not extract ${name}`);
}

const formats = {
  bin: { id: "bin", bitsPerDigit: 1, alphabet: "01" },
  base4: { id: "base4", bitsPerDigit: 2, alphabet: "0123" },
  base8: { id: "base8", bitsPerDigit: 3, alphabet: "01234567" },
  hex: { id: "hex", bitsPerDigit: 4, alphabet: "0123456789ABCDEF" },
  base32: { id: "base32", bitsPerDigit: 5, alphabet: "0123456789ABCDEFGHJKMNPQRSTVWXYZ" },
  base64: { id: "base64", bitsPerDigit: 6, alphabet: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" },
};

const numberValue = new Function("formats", `
  function hodlEntropyFormatConfig(format) {
    return { ...formats[format], fullDigits: Math.floor(128 / formats[format].bitsPerDigit), remainderBits: 128 % formats[format].bitsPerDigit, binaryRemainder: format === "base32" || format === "base64", seed: { bits: 128 } };
  }
  function hodlGroupedBinary(value) { return value.match(/.{1,11}/g)?.join(" ") || ""; }
  ${loadSlice("hodlGlobalSyncNumberValue")}
  return hodlGlobalSyncNumberValue;
`)(formats);

test("global sync emits only complete destination symbols", () => {
  const bits = "10101";
  assert.equal(numberValue(bits, "bin", 12), "10101");
  assert.equal(numberValue(bits, "base4", 12), "22");
  assert.equal(numberValue(bits, "base8", 12), "5");
  assert.equal(numberValue(bits, "hex", 12), "A");
  assert.equal(numberValue(bits, "base32", 12), "N");
  assert.equal(numberValue(bits, "base64", 12), "");
});

test("global sync replaces the old workspace and number-base-only sync features", () => {
  assert.match(shell, /id="global-sync-host"/);
  assert.doesNotMatch(app, /global-sync-hash-host/);
  assert.match(app, /id="global-entropy-sync"/);
  assert.match(app, /globalSync: false/);
  assert.match(app, /Sync entropy across methods/);
  assert.match(app, /Hashed inputs update them one way and are never overwritten/);
  assert.doesNotMatch(app, /workspace-sync|WorkspaceSync|Sync this key to other workspaces/);
  assert.doesNotMatch(app, /sync-number-bases|syncNumberBases|numberBaseSync/);
});

test("hashed methods publish one way without being overwritten", () => {
  const classify = loadSlice("hodlGlobalSyncIsHashedMode");
  assert.match(classify, /hodlDiceMethod === "coldcard" \|\| hodlDiceMethod === "coleman"/);
  assert.match(classify, /hodlCardMethod === "hashed"/);
  assert.match(classify, /kind === "minikey" \|\| kind === "brain"/);
  const current = loadSlice("hodlGlobalSyncCurrentBits");
  assert.match(current, /hodlDiceEntropy\(value, hodlDiceMethod, config\.words\)/);
  assert.match(current, /hodlCardsEntropy\(value, config\.words, hodlCardColemanSymbols\)/);
  assert.match(current, /hodlBrainWalletPrivateKey\(value, hodlBrainWalletTrimEnabled\(\)\)/);
  const apply = loadSlice("hodlApplyGlobalSync");
  assert.doesNotMatch(apply, /fields\.dice\s*=/);
  assert.doesNotMatch(apply, /fields\.cards\s*=/);
  assert.doesNotMatch(apply, /privateKeys\.minikey\s*=/);
  assert.doesNotMatch(apply, /privateKeys\.brain\s*=/);
  const render = loadSlice("hodlRenderGlobalSyncControl");
  assert.match(render, /document\.getElementById\("global-sync-host"\)/);
  assert.doesNotMatch(render, /global-sync-hash-host/);
  assert.doesNotMatch(loadSlice("hodlGlobalSyncControlMarkup"), /disabled/);
});

test("BitBox direct input is isolated from hashed dice input", () => {
  assert.match(app, /bitboxDice: ""/);
  assert.match(app, /previousMethod === "bitbox" \? "bitboxDice" : "dice"/);
  assert.match(app, /hodlDiceMethod === "bitbox" \? state\.fields\.bitboxDice/);
});

test("pads and pickers that skip bubbling input events still trigger the sync", () => {
  // [data-d] writes the dice textarea without dispatching a bubbling "input"
  // event, #card-undo trims the card transcript the same way, and [data-lw]
  // only picks a word — the delegated click handler must re-run the sync for
  // all of them. Seed-length buttons stay excluded: they never edit input,
  // and re-syncing from an empty active method there would wipe destinations.
  assert.match(app, /target\.matches\("\[data-lw\], \[data-d\], #card-undo"\)\) hodlGlobalSyncFromCurrentInput\(\)/);
});

test("a brain wallet reports unknown strength instead of a green tick", () => {
  // A brain wallet publishes a 256-bit SHA-256 digest however guessable the
  // text behind it was, so the digest length must never be reported as if it
  // were counted entropy. Its own answer is required, and it has to stay
  // distinct from the null that means "this method's published count IS its
  // entropy" — number bases and typed seeds rely on that null to read healthy.
  const source = loadSlice("hodlGlobalSyncSourceBits");
  assert.match(source, /if \(kind === "brain"\) return hodlGlobalSyncUnknownBits;/);
  assert.doesNotMatch(source, /kind === "brain" \? null/);
  assert.match(app, /const hodlGlobalSyncUnknownBits = "unknown"/);

  const markup = loadSlice("hodlGlobalSyncControlMarkup");
  assert.match(markup, /syncUnknown = Boolean\(syncBits\) && reported === hodlGlobalSyncUnknownBits/);
  // The unknown case must not be folded into the numeric shortfall test, and
  // must not be able to satisfy the healthy branch.
  assert.match(markup, /syncShort = Boolean\(syncBits\) && !syncUnknown && effectiveBits < hodlGlobalSyncMinimumBits\(\)/);
  assert.match(markup, /syncShort \|\| syncUnknown \?/);
  assert.match(markup, /entropy unknown/);
});

test("a minikey reports its payload keyspace, not its 256-bit digest", () => {
  // A minikey is SHA-256(text) exactly like a brain wallet, format-constrained
  // to S plus 21 or 29 base58 characters, so the accepted 22-character form
  // tops out near 123 bits — under the feature's own 128-bit floor. Reporting
  // 256 for it would be the digest-length misreport the badge exists to catch.
  const source = loadSlice("hodlGlobalSyncSourceBits");
  assert.match(source, /if \(kind === "minikey"\) \{\s*let payload = String\(value\)\.trim\(\)\.length - 1;\s*return payload > 0 \? payload \* Math\.log2\(58\) : null;/);
  // The remaining private-key formats carry a full-length key.
  assert.match(source, /return 256;/);
  // 21 payload characters must land under the floor, 29 above it.
  assert.ok(Math.floor(21 * Math.log2(58)) < 128);
  assert.ok(Math.floor(29 * Math.log2(58)) >= 128);
});

test("cloning a derived key keeps the synced entropy verdict", () => {
  // The badge reads globalSyncSourceBits; a clone that drops it falls back to
  // reporting the published digest length as counted entropy, so the
  // shortfall and unknown cautions would vanish on every commit or edit.
  const clone = loadSlice("hodlCloneDerivedKey");
  assert.match(clone, /globalSyncBitCount: source\.globalSyncBitCount,/);
  assert.match(clone, /globalSyncSourceBits: source\.globalSyncSourceBits,/);
});
