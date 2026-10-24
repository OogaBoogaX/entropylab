// Seed-phrase copy text for the entropy word grid.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

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

const hodlSeedLengths = {
  12: { words: 12, bits: 128, bytes: 16 },
  18: { words: 18, bits: 192, bytes: 24 },
  24: { words: 24, bits: 256, bytes: 32 },
};
function hodlSeedConfig(words = 24) {
  return hodlSeedLengths[words] || hodlSeedLengths[24];
}
const hodlSeedPhraseCopyText = new Function("hodlSeedConfig", `${loadSlice("hodlSeedPhraseCopyText")}; return hodlSeedPhraseCopyText;`)(hodlSeedConfig);

const TWELVE = ["abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract", "absurd", "abuse", "access", "accident"];

test("copy text is space-separated BIP39 words when the grid is complete", () => {
  assert.equal(hodlSeedPhraseCopyText(TWELVE, 12), TWELVE.join(" "));
});

test("copy text includes a contiguous partial seed phrase", () => {
  assert.equal(hodlSeedPhraseCopyText(TWELVE.slice(0, 1), 12), TWELVE[0]);
  assert.equal(hodlSeedPhraseCopyText(TWELVE.slice(0, 5), 12), TWELVE.slice(0, 5).join(" "));
  assert.equal(hodlSeedPhraseCopyText([...TWELVE.slice(0, 11), ""], 12), TWELVE.slice(0, 11).join(" "));
});

test("copy text remains unavailable for an empty or discontinuous grid", () => {
  assert.equal(hodlSeedPhraseCopyText([], 24), "");
  assert.equal(hodlSeedPhraseCopyText(["abandon", "", "able"], 12), "");
});

test("copy control markup starts disabled", () => {
  assert.match(app, /data-copy-seed-phrase disabled/);
  assert.match(app, /function hodlSeedMetaRowMarkup/);
  assert.match(app, /function hodlSeedCopyRowMarkup/);
  assert.match(app, /container\.closest\("#form"\)\?\.querySelector\("\[data-copy-seed-phrase\]"\)/);
});
