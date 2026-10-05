// BIP-93 Codex32 MS1 calculator. Vectors are the published BIP-93 strings.
// Checksum completion appends a checksum; it does not substitute characters
// to hunt for a transcription error. No fresh share set is generated.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  completeCodex32Checksum,
  deriveCodex32Share,
  parseCodex32,
  recoverCodex32Secret,
} from "../src/js/codex32.js";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const read = (path) => readFileSync(join(root, path), "utf8");

const v1 = "ms10testsxxxxxxxxxxxxxxxxxxxxxxxxxx4nzvca9cmczlw";
const shareA = "MS12NAMEA320ZYXWVUTSRQPNMLKJHGFEDCAXRPP870HKKQRM";
const shareC = "MS12NAMECACDEFGHJKLMNPQRSTUVWXYZ023FTR2GDZMPY6PN";
const shareD = "ms12namedll4f8jlh4e5vdvuldlfxu2jhdnlsm97xvenrxeg";
const secret2 = "ms12names6xqguzttxkeqnjsjzv4jv3nz5k3kwgsphuh6evw";
const secret3 = "ms13cashsllhdmn9m42vcsamx24zrxgs3qqjzqud4m0d6nln";
const cashA = "ms13casha320zyxwvutsrqpnmlkjhgfedca2a8d0zehn8a0t";
const cashC = "ms13cashcacdefghjklmnpqrstuvwxyz023949xq35my48dr";
const cashD = "ms13cashd0wsedstcdcts64cd7wvy4m90lm28w4ffupqs7rm";
const cashE = "ms13casheekgpemxzshcrmqhaydlp6yhms3ws7320xyxsar9";
const cashF = "ms13cashf8jh6sdrkpyrsp5ut94pj8ktehhw2hfvyrj48704";
const v4 = "ms10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyqqtum9pgv99ycma";
const v5 = "MS100C8VSM32ZXFGUHPCHTLUPZRY9X8GF2TVDW0S3JN54KHCE6MUA7LQPZYGSFJD6AN074RXVCEMLH8WU3TK925ACDEFGHJKLMNPQRSTUVWXY06FHPV80UNDVARHRAK";

test("BIP-93 unshared secrets decode to the published master seeds", () => {
  const cases = [
    [v1, "318c6318c6318c6318c6318c6318c631"],
    [secret3, "ffeeddccbbaa99887766554433221100"],
    [v4, "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100"],
    [v5, "dc5423251cb87175ff8110c8531d0952d8d73e1194e95b5f19d6f9df7c01111104c9baecdfea8cccc677fb9ddc8aec5553b86e528bcadfdcc201c17c638c47e9"],
    ["ms10seedsqqqsyqcyq5rqwzqfpg9scrgwpugpzysn9vaqzzvs20xnl", "000102030405060708090a0b0c0d0e0f10111213"],
    ["ms10seedsyqsjygeyy5nzw2pf9g4jctfw9ucrzv3nxs6nvdau84gz0632s0xs", "202122232425262728292a2b2c2d2e2f3031323334353637"],
    ["ms10seedsgpq5ys6yg4rywjzfff95cn2wfag9z5jn2324v46ct9d9hrcduqw8c3lccl", "404142434445464748494a4b4c4d4e4f505152535455565758595a5b"],
  ];
  for (const [codex, seed] of cases) {
    const parsed = parseCodex32(codex);
    assert.equal(parsed.index, "s");
    assert.equal(parsed.masterSeedHex, seed);
  }
});

test("Calculate Checksum appends the BIP-93 checksum and leaves a valid string unchanged", () => {
  assert.equal(completeCodex32Checksum(v1.slice(0, -13)), v1);
  assert.equal(completeCodex32Checksum(v4.slice(0, -13)), v4);
  assert.equal(completeCodex32Checksum(v5.slice(0, -15)).toLowerCase(), v5.toLowerCase());
  assert.equal(completeCodex32Checksum(v1.toUpperCase()), v1);
});

test("Calculate Checksum does not substitute a character to repair a bad payload", () => {
  const flipped = v4.slice(0, 12) + (v4[12] === "x" ? "q" : "x") + v4.slice(13);
  assert.equal(flipped.length, v4.length);
  assert.throws(() => completeCodex32Checksum(flipped), /does not search for a transcription error/);
  assert.throws(() => parseCodex32(flipped), /does not search for a transcription error/);
  const bad = "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxve740yyge2ghq";
  assert.throws(() => parseCodex32(bad), /checksum/i);
  const appended = completeCodex32Checksum(bad);
  assert.ok(appended.startsWith(bad), "completion must keep every typed character");
  assert.ok(appended.length > bad.length);
  assert.notEqual(appended.slice(0, bad.length), v1);
});

test("the same shares always recover the same secret and derive the same share", () => {
  assert.equal(recoverCodex32Secret([shareA, shareC]).codex32, secret2);
  assert.equal(recoverCodex32Secret([shareC, shareA]).codex32, secret2);
  assert.equal(recoverCodex32Secret([shareA, shareC]).masterSeedHex, "d1808e096b35b209ca12132b264662a5");
  assert.equal(deriveCodex32Share([shareA, shareC], "d").codex32, shareD);
  assert.equal(deriveCodex32Share([shareC, shareA], "D").codex32, shareD);
  assert.equal(deriveCodex32Share([secret3, cashA, cashC], "d").codex32, cashD);
  assert.equal(recoverCodex32Secret([cashA, cashC, cashD]).codex32, secret3);
  assert.equal(recoverCodex32Secret([cashA, cashE, cashF]).codex32, secret3);
  assert.equal(recoverCodex32Secret([cashF, cashE, cashC]).masterSeedHex, "ffeeddccbbaa99887766554433221100");
});

test("rejected MS1 inputs fail closed", () => {
  assert.throws(() => parseCodex32("Ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxuqxkk05lyf3x2"), /lowercase or all uppercase/);
  assert.throws(() => parseCodex32("cw1notaseed"), /Only MS1/);
  assert.throws(() => parseCodex32("cx1notakey"), /Only MS1/);
  assert.throws(() => completeCodex32Checksum("ms10testa" + "x".repeat(26)), /share index s/);
  assert.throws(() => parseCodex32("ms1fauxxxxxxxxxxxxxxxxxxxxxxxxxxxxxda3kr3s0s2swg"), /Threshold|length|bech32/);
  assert.throws(() => recoverCodex32Secret([cashA, cashC]), /exactly 3/);
  assert.throws(() => deriveCodex32Share([shareA, shareC], "a"), /already in the set/);
  assert.throws(() => deriveCodex32Share([shareA, shareC], "b"), /bech32/);
  const other = completeCodex32Checksum("ms12casha" + "x".repeat(26));
  assert.throws(() => recoverCodex32Secret([shareA, other]), /identifier/);
  assert.throws(() => parseCodex32(""), /Enter an MS1/);
});

test("the calculator does not generate entropy or accept other prefixes as tools", () => {
  const source = read("src/js/codex32.js");
  assert.doesNotMatch(source, /getRandomValues|Math\.random/);
  const shell = read("src/shell.html");
  assert.doesNotMatch(shell, /CW1|CX1/);
  assert.match(shell, /id="codex32-card"/);
  const app = read("src/js/app.js");
  assert.match(app, /hodlInitCodex32\(\)/);
  assert.match(app, /Codex32 are held back from release navigation/);
  assert.doesNotMatch(app, /\["codex32",/);
  assert.match(app, /getElementById\("codex32-shares"\)/);
});
