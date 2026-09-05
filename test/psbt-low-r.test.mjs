// Bitcoin Core-style low-r grind helpers used by PSBT nonce checks.
// Run with: npm run test:lowr
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

const hodlLe32Counter = new Function(`${loadSlice("hodlLe32Counter")}; return hodlLe32Counter;`)();
const hodlIsLowR = new Function(`${loadSlice("hodlIsLowR")}; return hodlIsLowR;`)();

test("PSBT copy mentions Bitcoin Core-style low-r grinding", () => {
  assert.match(shell, /plain RFC 6979 or Bitcoin Core-style low-r grinding/);
  assert.match(app, /hodlRfc6979Compare\(\s*sighash\s*,\s*privateKey\s*,\s*parts\.r\s*\)/);
  assert.match(app, /extraEntropy\s*:\s*hodlLe32Counter\(\s*n\s*\)/);
  assert.match(app, /RFC 6979 comparison currently covers/);
});

test("little-endian 32-byte grind counter matches Bitcoin Core extra entropy", () => {
  const one = hodlLe32Counter(1);
  assert.equal(one.length, 32);
  assert.equal(one[0], 1);
  assert.equal(one[1], 0);
  assert.equal(one[2], 0);
  assert.equal(one[3], 0);
  assert.ok([...one.slice(4)].every((b) => b === 0));

  const n256 = hodlLe32Counter(256);
  assert.equal(n256[0], 0);
  assert.equal(n256[1], 1);
  assert.ok([...n256.slice(2)].every((b) => b === 0));
});

test("low-r is a 32-byte r whose first byte is below 0x80", () => {
  const low = new Uint8Array(32);
  low[0] = 0x7f;
  const high = new Uint8Array(32);
  high[0] = 0x80;
  assert.equal(hodlIsLowR(low), true);
  assert.equal(hodlIsLowR(high), false);
  assert.equal(hodlIsLowR(null), false);
  assert.equal(hodlIsLowR(new Uint8Array(0)), false);
});
