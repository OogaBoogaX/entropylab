// Output scriptPubKey builder for the PSBT editor. One input, four ways to
// describe a script:
//
//   - an address (P2PKH / P2SH / P2WPKH / P2WSH / P2TR, on the selected
//     network) — decoded and re-encoded as its scriptPubKey;
//   - script ASM ("OP_DUP OP_HASH160 0x0011… OP_EQUALVERIFY OP_CHECKSIG"),
//     assembled with minimal data-push encoding;
//   - raw script hex (0x-prefixed, or containing an a-f digit) — passed
//     through untouched;
//   - anything else in auto mode becomes the UTF-8 payload of an OP_RETURN
//     output; explicit modes force OP_RETURN text or hex regardless.
//
// The ambiguous cases are deliberate: an address-shaped string that fails to
// decode is an error (never silently an OP_RETURN), and digit-only hex needs
// the 0x prefix to count as raw script — otherwise it is text.
import { Address as BtcAddress, NETWORK as BTC_MAINNET, TEST_NETWORK as BTC_TESTNET, OutScript, OP } from "@scure/btc-signer";
import { buildOpReturnScript, encodeDataPush } from "./opreturn.js";

const bytesToHex = (bytes) => [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");

// Script templates, labelled like the flow diagram's tags.
const SCRIPT_KINDS = { pkh: "P2PKH", sh: "P2SH", wpkh: "P2WPKH", wsh: "P2WSH", tr: "P2TR" };

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
const hexToBytes = (hex) => {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
};

// One ASM token: a small integer (-1..16), an opcode name, or hex data
// (0x-prefixed, or containing an a-f digit so it cannot read as a number).
const assembleToken = (token) => {
  if (SMALL_INTEGERS.has(token)) return Uint8Array.of(SMALL_INTEGERS.get(token));
  const name = token.toUpperCase().replace(/^OP_/, "");
  if (OPCODES.has(name)) return Uint8Array.of(OPCODES.get(name));
  const hex = token.replace(/^0x/i, "");
  if (isHex(hex) && (/^0x/i.test(token) || /[a-f]/i.test(hex))) return encodeDataPush(hexToBytes(hex.toLowerCase()));
  throw new Error(`Unknown script token "${token}" — use an OP_ name, a small integer -1..16, or hex data (0x-prefixed).`);
};

export const assembleScriptAsm = (text) => {
  const tokens = String(text ?? "").trim().split(/\s+/).filter(Boolean);
  if (!tokens.length) throw new Error("Type the script as ASM: opcode names and hex data, space-separated.");
  const parts = tokens.map(assembleToken);
  const size = parts.reduce((sum, part) => sum + part.length, 0);
  if (size > 10000) throw new Error("The script would exceed the 10,000-byte maximum script size.");
  const script = new Uint8Array(size);
  let offset = 0;
  for (const part of parts) {
    script.set(part, offset);
    offset += part.length;
  }
  return bytesToHex(script);
};

const looksLikeAddress = (text) =>
  /^(?:bc1|tb1|bcrt1)[02-9ac-hj-np-z]{6,}$/i.test(text) || /^[123mn][1-9A-HJ-NP-Za-km-z]{20,50}$/.test(text);

const scriptFromAddress = (text, network) => {
  const decoded = BtcAddress(network === "testnet" ? BTC_TESTNET : BTC_MAINNET).decode(text);
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
    return { scriptHex: bytesToHex(buildOpReturnScript(hex ? [hexToBytes(hex.toLowerCase())] : [])), kind: "opreturn", note: `OP_RETURN hex (${hex.length / 2} bytes)` };
  }
  if (mode === "asm") return { scriptHex: assembleScriptAsm(text), kind: "asm", note: "assembled from ASM" };
  if (!text) throw new Error("Describe the script: paste an address, type ASM, or switch to an OP_RETURN mode.");

  // auto
  if (looksLikeAddress(text)) {
    try {
      return scriptFromAddress(text, network);
    } catch {
      throw new Error(`That looks like an address but does not decode on ${network === "testnet" ? "testnet" : "mainnet"} — check the network selector and the spelling.`);
    }
  }
  const first = text.split(/\s+/, 1)[0];
  // ASM intent is explicit; an unknown token surfaces instead of falling
  // through to another interpretation.
  if (/^OP_/i.test(first) || SMALL_INTEGERS.has(text)) return { scriptHex: assembleScriptAsm(text), kind: "asm", note: "assembled from ASM" };
  const hex = text.replace(/^0x/i, "").replace(/\s/g, "");
  if (isHex(hex) && (/^0x/i.test(text) || /[a-f]/i.test(hex)))
    return { scriptHex: hex.toLowerCase(), kind: "raw", note: `raw script (${hex.length / 2} bytes)` };
  return { scriptHex: bytesToHex(buildOpReturnScript([new TextEncoder().encode(text)])), kind: "opreturn", note: `OP_RETURN text (${new TextEncoder().encode(text).length} bytes)` };
};
