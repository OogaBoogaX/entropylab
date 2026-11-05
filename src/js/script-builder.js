// Output scriptPubKey builder for the PSBT editor. One input, four ways to
// describe a script:
//
//   - an address (P2PKH / P2SH / P2WPKH / P2WSH / P2TR, on the selected
//     network) — decoded and re-encoded as its scriptPubKey;
//   - script ASM ("OP_DUP OP_HASH160 0x0011… OP_EQUALVERIFY OP_CHECKSIG"),
//     assembled with minimal data-push encoding;
//   - raw script hex (0x-prefixed, or even-length with an a-f digit) —
//     passed through untouched;
//   - anything else in auto mode becomes the UTF-8 payload of an OP_RETURN
//     output; explicit modes force OP_RETURN text or hex regardless.
//
// The ambiguous cases are deliberate. In auto mode a token is read as an
// address when it starts with a bech32 HRP (bc1, tb1 or bcrt1), or starts
// with 1, 2, 3, m or n and is 21 to 61 whitespace-free characters, or is
// any whitespace-free token of 25 to 64 characters with at most two
// symbols; a /, : or @ keeps either shape arm as text. A token of that
// shape that does not decode is an error, never silently an OP_RETURN,
// while a mistyped address outside it (shorter, three or more symbols, an
// inserted space) still reads as text. Bare hex that reads as a Base58
// address is an address; other even-length hex with an a-f digit is raw
// script, and digit-only hex needs the 0x prefix — otherwise it is text. A
// bare number is text too, even -1..16: ASM starts with an OP_ name or comes
// from the explicit ASM mode. A silent payment address is refused: its output
// key depends on the transaction's inputs.
// The arms are spelled out above looksLikeAddress.
import { Address as BtcAddress, NETWORK as BTC_MAINNET, TEST_NETWORK as BTC_TESTNET, OutScript, OP } from "@scure/btc-signer";
import { hex as hexCoder } from "./coders.js";
import { buildOpReturnScript, encodeDataPush } from "./opreturn.js";

const bytesToHex = (bytes) => [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");

// Script templates, labelled like the flow diagram's tags.
const SCRIPT_KINDS = { pkh: "P2PKH", sh: "P2SH", wpkh: "P2WPKH", wsh: "P2WSH", tr: "P2TR" };
// Regtest shares testnet's Base58 prefixes and WIF byte; only the Bech32 HRP
// differs. scure ships no regtest parameters, so derive them.
const BTC_REGTEST = { ...BTC_TESTNET, bech32: "bcrt" };

// Opcode table over scure's OP enum, normalized to Bitcoin Core's asm
// spellings (with or without the OP_ prefix): OP enum mixes "OP_0",
// "PUSHDATA1" and "CHECKSIG" styles. PUSHDATA1/2/4 are left out — the
// assembler always picks the minimal push encoding for hex data itself.
const OPCODES = (() => {
  const table = new Map();
  for (const [name, code] of Object.entries(OP)) {
    const canonical = name.startsWith("OP_") ? name.slice(3) : name;
    if (/^PUSHDATA[124]$/.test(canonical)) continue;
    if (!table.has(canonical)) table.set(canonical, code);
  }
  table.set("FALSE", 0x00);
  table.set("TRUE", 0x51);
  table.set("NOP2", 0xb1); // OP_CHECKLOCKTIMEVERIFY's original name
  table.set("NOP3", 0xb2); // OP_CHECKSEQUENCEVERIFY's original name
  return table;
})();

const SMALL_INTEGERS = new Map([["-1", 0x4f], ["0", 0x00], ...Array.from({ length: 16 }, (_, n) => [String(n + 1), 0x50 + n + 1])]);

const isHex = (text) => /^(?:[0-9a-f]{2})*$/i.test(text);
// Decoding goes through coders' strict hex.decode (throws on odd length or
// non-hex digits) — isHex above already rejects those, this keeps the trap
// closed if a future caller forgets the guard.

// One ASM token: a small integer (-1..16), an opcode name, or hex data
// (0x-prefixed, or containing an a-f digit so it cannot read as a number).
// Returns the token's bytes and, for data, how many bytes it pushes.
const assembleToken = (token) => {
  if (SMALL_INTEGERS.has(token)) return { bytes: Uint8Array.of(SMALL_INTEGERS.get(token)), pushed: 0 };
  const name = token.toUpperCase().replace(/^OP_/, "");
  if (OPCODES.has(name)) return { bytes: Uint8Array.of(OPCODES.get(name)), pushed: 0 };
  const hex = token.replace(/^0x/i, "");
  if (isHex(hex) && (/^0x/i.test(token) || /[a-f]/i.test(hex))) {
    const data = hexCoder.decode(hex.toLowerCase());
    return { bytes: encodeDataPush(data), pushed: data.length };
  }
  throw new Error(`Unknown script token "${token}" — use an OP_ name, a small integer -1..16, or hex data (0x-prefixed).`);
};

export const assembleScriptAsm = (text) => {
  const tokens = String(text ?? "").trim().split(/\s+/).filter(Boolean);
  if (!tokens.length) throw new Error("Type the script as ASM: opcode names and hex data, space-separated.");
  const parts = tokens.map(assembleToken);
  // Consensus refuses to execute a push over 520 bytes, so a script holding
  // one can never be spent; only an OP_RETURN script, never spent anyway, may
  // carry one (red-team sweep 0eed735, script-builder #10).
  if (parts[0].bytes[0] !== OP.RETURN && parts.some((part) => part.pushed > 520)) {
    throw new Error("This data push exceeds 520 bytes, so the output cannot be spent. In this builder, only a script that starts with OP_RETURN may carry one, and that output cannot be spent either.");
  }
  const size = parts.reduce((sum, part) => sum + part.bytes.length, 0);
  if (size > 10000) throw new Error("The script would exceed the 10,000-byte maximum script size.");
  const script = new Uint8Array(size);
  let offset = 0;
  for (const { bytes } of parts) {
    script.set(bytes, offset);
    offset += bytes.length;
  }
  return bytesToHex(script);
};

// Address intent is decided by the shape of the token, not by a full regex
// that a mistyped character can fall out of. A string that starts like a
// bech32 or Base58 address but does not decode is an error; it must never
// become OP_RETURN text or a raw script (audit M7). The Base58 arms are
// capped at 60 body characters, just past the longest real Base58Check
// address, so long raw hex without a 0x prefix still falls through to the
// raw-script path. Two shape arms catch the typos the alphabet arms miss: a
// 1/2/3/m/n-prefixed token of address length with characters outside the
// alphabet — a confusable 0/O/I/l, a stray punctuation mark — and, because
// a typo in the first character leaves every prefix class, any
// whitespace-free token of 25 to 64 characters that is letters and digits
// apart from at most two symbols (a stray character in the first position,
// quotes or brackets left by a paste). A URL or e-mail separator (/, : or
// @) keeps either shape as text, as does a third symbol in the prefix-free
// one. The one exception throughout is raw-script hex — 0x-prefixed, or
// even-length with an a-f digit — which a mistyped address cannot be in
// practice, and which the raw-script path takes.
const symbolCount = (text) => (text.match(/[^0-9A-Za-z]/g) ?? []).length;
const addressShaped = (text) =>
  (/^[123mn]\S{20,60}$/.test(text) || (/^\S{25,64}$/.test(text) && symbolCount(text) <= 2)) && !/[/:@]/.test(text);
const looksLikeAddress = (text) =>
  /^(?:bc1|tb1|bcrt1)/i.test(text) || /^[123mn][1-9A-HJ-NP-Za-km-z]{20,60}$/.test(text) ||
  (addressShaped(text) && !/^0x/i.test(text) && !(isHex(text) && /[a-f]/i.test(text)));

const scriptFromAddress = (text, network) => {
  const params = network === "regtest" ? BTC_REGTEST : network === "testnet" ? BTC_TESTNET : BTC_MAINNET;
  const decoded = BtcAddress(params).decode(text);
  const script = OutScript.encode(decoded);
  return { scriptHex: bytesToHex(script), kind: "address", note: `${SCRIPT_KINDS[decoded.type] || decoded.type} address` };
};

// mode: "auto" | "asm" | "opreturn-text" | "opreturn-hex"
export const buildOutputScript = (input, { network = "mainnet", mode = "auto" } = {}) => {
  const text = String(input ?? "").trim();
  if (mode === "opreturn-text") {
    const payload = new TextEncoder().encode(text);
    return { scriptHex: bytesToHex(buildOpReturnScript(payload.length ? [payload] : [])), kind: "opreturn", note: `OP_RETURN text (${payload.length} bytes)` };
  }
  if (mode === "opreturn-hex") {
    const hex = text.replace(/^0x/i, "").replace(/\s/g, "");
    if (!isHex(hex)) throw new Error("OP_RETURN hex payload must be an even number of 0-9/a-f digits.");
    return { scriptHex: bytesToHex(buildOpReturnScript(hex ? [hexCoder.decode(hex.toLowerCase())] : [])), kind: "opreturn", note: `OP_RETURN hex (${hex.length / 2} bytes)` };
  }
  if (mode === "asm") return { scriptHex: assembleScriptAsm(text), kind: "asm", note: "assembled from ASM" };
  if (!text) throw new Error("Describe the script: paste an address, type ASM, or switch to an OP_RETURN mode.");

  // auto
  // A BIP-352 address fell through to OP_RETURN text, burning any value: an
  // address-like string must error (audit M7; red-team sweep 0eed735,
  // script-builder #13).
  if (/^(?:sp|tsp|sprt)1\S*$/i.test(text)) {
    throw new Error("Silent payment addresses (sp1… or tsp1…) can't be paid from this builder: the output key depends on the transaction's inputs. Use the Silent Payments tool on the Privacy tab.");
  }
  if (looksLikeAddress(text)) {
    try {
      return scriptFromAddress(text, network);
    } catch {
      throw new Error(`That looks like an address but does not decode on ${["testnet", "regtest"].includes(network) ? network : "mainnet"} — check the network selector and the spelling, or use the OP_RETURN-text mode if it is meant as text.`);
    }
  }
  const first = text.split(/\s+/, 1)[0];
  // ASM intent is explicit; an unknown token surfaces instead of falling
  // through to another interpretation. A bare small integer is not ASM
  // intent: "5" became OP_5, an anyone-can-spend output, where every other
  // number is text (red-team sweep 0eed735, script-builder #12).
  if (/^OP_/i.test(first)) return { scriptHex: assembleScriptAsm(text), kind: "asm", note: "assembled from ASM" };
  const hex = text.replace(/^0x/i, "").replace(/\s/g, "");
  if (isHex(hex) && (/^0x/i.test(text) || /[a-f]/i.test(hex))) {
    // A bare 0x was an empty, anyone-can-spend script, and raw hex had no
    // size cap where ASM and OP_RETURN have one (red-team sweep 0eed735,
    // script-builder #6 and #2).
    if (!hex) throw new Error("Type the script hex after 0x.");
    if (hex.length / 2 > 10000) throw new Error("The script would exceed the 10,000-byte maximum script size.");
    return { scriptHex: hex.toLowerCase(), kind: "raw", note: `raw script (${hex.length / 2} bytes)` };
  }
  // 0x marks raw script hex, so a malformed one (0x5, 0x51z) is an error, not
  // OP_RETURN text that burns the output's value (#1478 gate, Kimi). Text that
  // really starts with 0x goes in through the OP_RETURN-text mode.
  if (/^0x/i.test(text)) throw new Error("Script hex after 0x must be an even number of 0-9/a-f digits. To store this as text instead, use the OP_RETURN-text mode.");
  return { scriptHex: bytesToHex(buildOpReturnScript([new TextEncoder().encode(text)])), kind: "opreturn", note: `OP_RETURN text (${new TextEncoder().encode(text).length} bytes)` };
};
