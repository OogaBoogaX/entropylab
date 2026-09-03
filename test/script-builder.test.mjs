// The PSBT editor's output-script builder: one input that auto-detects an
// address (encoded to its scriptPubKey), script ASM (assembled with minimal
// pushes), raw script hex (passed through), or OP_RETURN text (the fallback
// and the explicit modes). The ambiguous cases are the point: a mistyped
// address must error, never silently become an OP_RETURN, and digit-only
// hex counts as text unless 0x-prefixed. Run with `npm test`.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { assembleScriptAsm, buildOutputScript } from "../src/js/script-builder.js";
import { buildOpReturnScript, parseOpReturn } from "../src/js/opreturn.js";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const read = (path) => readFileSync(join(root, path), "utf8");

const textHex = (text) => [...new TextEncoder().encode(text)].map((byte) => byte.toString(16).padStart(2, "0")).join("");

test("addresses encode to their scriptPubKey, labelled by template", () => {
  assert.deepEqual(buildOutputScript("1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"), {
    scriptHex: "76a914751e76e8199196d454941c45d1b3a323f1433bd688ac",
    kind: "address",
    note: "P2PKH address",
  });
  assert.equal(buildOutputScript("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy").scriptHex, "a914b472a266d0bd89c13706a4132ccfb16f7c3b9fcb87");
  assert.equal(buildOutputScript("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4").scriptHex, "0014751e76e8199196d454941c45d1b3a323f1433bd6");
  // P2TR, the BIP-350 bech32m encoding of the same well-known program.
  assert.equal(buildOutputScript("bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr").scriptHex, "5120a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c");
});

test("the network selector rules which addresses decode", () => {
  assert.equal(buildOutputScript("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx", { network: "testnet" }).scriptHex, "0014751e76e8199196d454941c45d1b3a323f1433bd6");
  // A testnet address under mainnet (and vice versa) is an error — never a
  // silent OP_RETURN fallback.
  assert.throws(() => buildOutputScript("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx", { network: "mainnet" }), /does not decode on mainnet/);
  assert.throws(() => buildOutputScript("1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH", { network: "testnet" }), /does not decode on testnet/);
});

test("a mistyped address errors instead of becoming an OP_RETURN", () => {
  // Same shape as a valid bech32 address, corrupted checksum.
  assert.throws(() => buildOutputScript("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5"), /does not decode on mainnet/);
});

test("script ASM assembles with minimal push encoding", () => {
  assert.equal(
    assembleScriptAsm("OP_DUP OP_HASH160 0x00112233445566778899aabbccddeeff00112233 OP_EQUALVERIFY OP_CHECKSIG"),
    "76a91400112233445566778899aabbccddeeff0011223388ac"
  );
  // A 2-of-3 multisig, small integers included.
  const key = "02" + "aa".repeat(32);
  assert.equal(assembleScriptAsm(`2 0x${key} 0x${key} 0x${key} 3 OP_CHECKMULTISIG`), `5221${key}21${key}21${key}53ae`);
  // Small integers, with and without the OP_ prefix; -1 is 1NEGATE.
  assert.equal(assembleScriptAsm("OP_RETURN 0 -1 16"), "6a004f60");
  assert.equal(assembleScriptAsm("0"), "00");
  // Hex data pushes work bare when they cannot read as numbers.
  assert.equal(assembleScriptAsm("OP_RETURN deadbeef"), "6a04deadbeef");
});

test("ASM rejects unknown tokens, naming the offender", () => {
  assert.throws(() => assembleScriptAsm("OP_DUP OP_NOTAREALOP"), /Unknown script token "OP_NOTAREALOP"/);
  assert.throws(() => assembleScriptAsm("42"), /Unknown script token "42"/); // numbers above 16 are not pushes
  assert.throws(() => assembleScriptAsm(""), /Type the script as ASM/);
});

test("raw script hex passes through (0x-prefixed, or containing a-f)", () => {
  assert.equal(buildOutputScript("0x76a914" + "11".repeat(20) + "88ac").scriptHex, "76a914" + "11".repeat(20) + "88ac");
  assert.equal(buildOutputScript("76a914" + "11".repeat(20) + "88ac").kind, "raw");
  assert.equal(buildOutputScript("DEADBEEF").scriptHex, "deadbeef");
});

test("auto mode falls back to OP_RETURN text — including digit-only strings", () => {
  assert.equal(buildOutputScript("Hello, Bitcoin").scriptHex, "6a0e" + textHex("Hello, Bitcoin"));
  assert.equal(buildOutputScript("12345678").scriptHex, "6a08" + textHex("12345678"));
  assert.equal(buildOutputScript("12345678", { mode: "opreturn-hex" }).scriptHex, "6a0412345678");
});

test("explicit OP_RETURN modes override every other interpretation", () => {
  // Text mode treats even address-shaped and hex-shaped input as payload.
  assert.equal(buildOutputScript("deadbeef", { mode: "opreturn-text" }).scriptHex, "6a08" + textHex("deadbeef"));
  assert.equal(buildOutputScript("", { mode: "opreturn-text" }).scriptHex, "6a");
  assert.equal(buildOutputScript("", { mode: "opreturn-hex" }).scriptHex, "6a");
  assert.throws(() => buildOutputScript("xyz", { mode: "opreturn-hex" }), /even number of 0-9\/a-f digits/);
});

test("auto mode rejects the empty description", () => {
  assert.throws(() => buildOutputScript("   "), /Describe the script/);
  assert.throws(() => buildOutputScript("", { mode: "asm" }), /Type the script as ASM/);
});

test("builder output round-trips through the editor's OP_RETURN decoder", () => {
  const built = buildOutputScript("ord — here we go", { mode: "opreturn-text" });
  const parsed = parseOpReturn(Uint8Array.from(built.scriptHex.match(/../g), (hex) => parseInt(hex, 16)));
  assert.equal(parsed.ok, true);
  assert.equal(new TextDecoder().decode(parsed.payload), "ord — here we go");
  assert.equal(parsed.hint, "ord-prefix");
});

test("push encoding picks the smallest opcode at every boundary", () => {
  const scriptAt = (payloadBytes) => buildOpReturnScript([new Uint8Array(payloadBytes)]);
  assert.equal(scriptAt(75)[1], 75);
  assert.equal(scriptAt(76)[1], 0x4c); // PUSHDATA1
  assert.equal(scriptAt(255)[1], 0x4c);
  assert.equal(scriptAt(256)[1], 0x4d); // PUSHDATA2
  assert.throws(() => scriptAt(10000), /10,000-byte maximum/);
});

test("the editor renders the builder on every output row and wires it", () => {
  const editor = read("src/js/psbt-editor.js");
  assert.match(editor, /import \{ buildOutputScript \} from "\.\/script-builder\.js"/);
  assert.match(editor, /data-build-script="\$\{index\}"/);
  assert.match(editor, /data-build-mode="\$\{index\}"/);
  assert.match(editor, /data-build-apply="\$\{index\}"/);
  // The network comes from the header picker's getter, not a local select.
  assert.match(editor, /buildOutputScript\(text, \{ network: network\(\), mode \}\)/);
  const css = read("src/css/styles.css");
  assert.match(css, /\.psbted-build \{/);
});
