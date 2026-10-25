// PSBT editor UI (BIP-174, v0) — the bip174.org-style full-fidelity editor.
// All parsing, typed decoding and re-serialization run in the rust-bitcoin
// WebAssembly module (src/js/psbt-wasm.js); this module only renders the
// inspection document, applies edits to it, and asks the WASM to rebuild.
//
// Editing model: the document returned by psbtInspectDoc is the editable
// state, and editing is live: every keystroke, pair change and structural
// edit rebuilds through the WASM on the spot, and the tables re-render from
// rust-bitcoin's fresh decode (focus returns to the field being typed).
// While the current fields do not build, the error shows and the last valid
// build is kept below, marked stale. The unsigned transaction pair (global
// key 00) is regenerated from the transaction section on every build, so it
// is never edited directly.
import { addressQrButtonHtml } from "./address-qr.js";
import { addressFromScript } from "./addresses.js";
import { hodlNeutralizeControls } from "./i18n-sanitize.js";
import { psbtInspectDoc, psbtBuildBytes, psbtWasmReady } from "./psbt-wasm.js";
import { comparePsbtDocs } from "./psbt-diff.js";
import { copyText, showCopiedIcon } from "./clipboard.js";
import { privateCopyButtonHtml } from "./private-data.js";
import { publicValueHtml } from "./public-data.js";
import { expandableHtml, EXPAND_LIMIT, initExpandable } from "./expandable.js";
import { psbtOutputNotesHtml, psbtVizHtml, PSBT_RENDER_LIMIT, renderBudget } from "./psbt-viz.js";
import { parseOpReturn } from "./opreturn.js";
import { buildOutputScript } from "./script-builder.js";
import { hodlUrEncodePsbt } from "./psbt-ur.js";

const hexToBytes = (hex) => {
  if (!/^(?:[0-9a-f]{2})*$/i.test(hex)) throw new Error("Invalid hexadecimal input.");
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
};
const bytesToHex = (bytes) => [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
const isHex = (text) => /^(?:[0-9a-f]{2})*$/i.test(text);

const base64Encode = (bytes) => {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary);
};

// Accepts base64 or hex with the same rules and bounds as the PSBT / Nonce
// inspector (5 MB decoded, 7 MB of base64 text).
export const psbtBytesFromText = (raw) => {
  const value = String(raw ?? "").trim(), compact = value.replace(/\s/g, "");
  if (!value) throw new Error("Paste a PSBT (v0 or v2).");
  if (compact.length > 7e6) throw new Error("This PSBT is too large to edit safely.");
  let bytes;
  if (/^[0-9a-fA-F]+$/.test(compact) && compact.length % 2 === 0 && compact.length >= 10) bytes = hexToBytes(compact.toLowerCase());
  else {
    let binary;
    try {
      binary = atob(compact);
    } catch {
      throw new Error("That does not look like a PSBT in base64 or hex.");
    }
    bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  }
  if (bytes.length > 5e6) throw new Error("This PSBT is too large to edit safely.");
  return bytes;
};

// Accepts the raw bytes of an uploaded file. Wallets (Sparrow, Coldcard, …)
// save a PSBT as a binary .psbt file, which starts with the "psbt\xff" magic;
// a text export ("Copy PSBT" or a hex dump saved to disk) decodes through
// the same rules and bounds as the paste box.
export const psbtBytesFromUpload = (bytes) => {
  if (!(bytes instanceof Uint8Array) || !bytes.length) throw new Error("Choose a PSBT file to upload.");
  if (bytes.length > 5e6) throw new Error("This PSBT is too large to edit safely.");
  const PSBT_MAGIC = [0x70, 0x73, 0x62, 0x74, 0xff]; // "psbt\xff"
  if (bytes.length >= PSBT_MAGIC.length && PSBT_MAGIC.every((byte, index) => bytes[index] === byte)) return bytes;
  return psbtBytesFromText(new TextDecoder().decode(bytes));
};

export const satsToBtc = (sats) => {
  let value = BigInt(sats), negative = value < 0n;
  if (negative) value = -value;
  const whole = value / 100000000n, fraction = value % 100000000n;
  return (negative ? "-" : "") + whole.toString() + "." + fraction.toString().padStart(8, "0");
};

// How the edited PSBT is shown as a QR: small files fit one static code
// carrying the base64 text; larger ones become an animated ur:crypto-psbt
// sequence (BCR-2020-005 with BCR-2024-001 fixed-rate MUR fragments —
// Sparrow, SeedSigner and Coldcard Q scan those).
// The UR fragments are uppercased so the QR encodes in the denser
// alphanumeric mode; UR parsing lowercases before decoding.
export const PSBT_QR_STATIC_MAX_BYTES = 800;
export const psbtQrPlan = (bytes) => {
  if (bytes.length <= PSBT_QR_STATIC_MAX_BYTES) return { mode: "static", text: base64Encode(bytes) };
  return { mode: "ur", parts: hodlUrEncodePsbt(bytes, { maxBytes: 200 }).map((part) => part.toUpperCase()) };
};


const escapeHtml = (text) =>
  String(text).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");

const shorten = (hex, head = 10, tail = 6) => {
  const text = String(hex ?? "");
  return text.length > head + tail + 2 ? text.slice(0, head) + "…" + text.slice(-tail) : text;
};

// Script → address rendering goes through rust-bitcoin (the same
// addressFromScript the inspector uses), so the editor, the diagram, and the
// inspector never diverge on exotic witness programs (issue #354); unknown
// templates return null and the caller falls back to the script hex/asm.
const addressFor = (scriptHex, network) => {
  try {
    return addressFromScript(hexToBytes(scriptHex), network);
  } catch {
    return null;
  }
};

// One-line decode of a data-carrier (OP_RETURN) output for its row in the
// transaction table: payload as UTF-8 text when it decodes, hex otherwise,
// plus the protocol hint the inspector also reports. Invalid hex (a field
// being typed) and non-OP_RETURN scripts return null, leaving the row's
// usual address/asm fallback untouched. A non-zero value on a data-carrier
// output burns those sats; the row says so and takes the warning tone.
export const opReturnSummary = (scriptHex, valueSats = 0) => {
  let parsed;
  try {
    parsed = parseOpReturn(hexToBytes(scriptHex));
  } catch {
    return null;
  }
  if (!parsed) return null;
  const burn = Number(valueSats) > 0;
  const parts = [
    parsed.error
      ? `OP_RETURN · malformed: ${parsed.error}`
      : `OP_RETURN · ${parsed.payloadBytes} byte${parsed.payloadBytes === 1 ? "" : "s"}`,
  ];
  if (parsed.hint) parts.push(parsed.hint);
  if (!parsed.error && parsed.payloadBytes) {
    let text = null;
    try {
      text = new TextDecoder("utf-8", { fatal: true }).decode(parsed.payload);
    } catch {
      // Not UTF-8: the hex branch below shows the payload.
    }
    // The payload is untrusted text: neutralize bidi/invisible codepoints so
    // the quote cannot reorder the row around it. The script itself is raw.
    parts.push(text !== null ? `“${hodlNeutralizeControls(text.length > 80 ? `${text.slice(0, 80)}…` : text)}”` : `hex ${bytesToHex(parsed.payload.slice(0, 40))}${parsed.payloadBytes > 40 ? "…" : ""}`);
  }
  if (burn) parts.push(`burns ${valueSats} sats — unspendable`);
  return { text: parts.join(" · "), burn };
};

// Per-map key types offered by the "add pair" control: [type byte, name,
// keydata hint]. "Custom" (empty type) is always appended and allows any type
// byte + keydata.
const PAIR_TYPES = {
  global: [
    ["01", "PSBT_GLOBAL_XPUB", "78-byte xpub (keydata)"],
    ["fb", "PSBT_GLOBAL_VERSION", "empty"],
    ["fc", "PSBT_GLOBAL_PROPRIETARY", "prefix len + prefix + subtype + keydata"],
  ],
  input: [
    ["00", "PSBT_IN_NON_WITNESS_UTXO", "empty"],
    ["01", "PSBT_IN_WITNESS_UTXO", "empty"],
    ["02", "PSBT_IN_PARTIAL_SIG", "33-byte pubkey"],
    ["03", "PSBT_IN_SIGHASH_TYPE", "empty"],
    ["04", "PSBT_IN_REDEEM_SCRIPT", "empty"],
    ["05", "PSBT_IN_WITNESS_SCRIPT", "empty"],
    ["06", "PSBT_IN_BIP32_DERIVATION", "33-byte pubkey"],
    ["07", "PSBT_IN_FINAL_SCRIPTSIG", "empty"],
    ["08", "PSBT_IN_FINAL_SCRIPTWITNESS", "empty"],
    ["0a", "PSBT_IN_RIPEMD160", "20-byte hash"],
    ["0b", "PSBT_IN_SHA256", "32-byte hash"],
    ["0c", "PSBT_IN_HASH160", "20-byte hash"],
    ["0d", "PSBT_IN_HASH256", "32-byte hash"],
    ["13", "PSBT_IN_TAP_KEY_SIG", "empty"],
    ["14", "PSBT_IN_TAP_SCRIPT_SIG", "32-byte xonly + 32-byte leaf hash"],
    ["15", "PSBT_IN_TAP_LEAF_SCRIPT", "control block"],
    ["16", "PSBT_IN_TAP_BIP32_DERIVATION", "32-byte xonly key"],
    ["17", "PSBT_IN_TAP_INTERNAL_KEY", "empty"],
    ["18", "PSBT_IN_TAP_MERKLE_ROOT", "empty"],
    ["fc", "PSBT_IN_PROPRIETARY", "prefix len + prefix + subtype + keydata"],
  ],
  output: [
    ["00", "PSBT_OUT_REDEEM_SCRIPT", "empty"],
    ["01", "PSBT_OUT_WITNESS_SCRIPT", "empty"],
    ["02", "PSBT_OUT_BIP32_DERIVATION", "33-byte pubkey"],
    ["05", "PSBT_OUT_TAP_INTERNAL_KEY", "empty"],
    ["06", "PSBT_OUT_TAP_TREE", "empty"],
    ["07", "PSBT_OUT_TAP_BIP32_DERIVATION", "32-byte xonly key"],
    ["fc", "PSBT_OUT_PROPRIETARY", "prefix len + prefix + subtype + keydata"],
  ],
};

// One-line plain-text summary of a decoded pair, shown next to the raw value.
const describePair = (pair, network) => {
  if (pair.decodeError) return { text: `Not decodable: ${pair.decodeError}`, tone: "bad" };
  const d = pair.decoded;
  if (!d) return { text: "Unknown key — raw bytes shown.", tone: "muted" };
  const addr = d.scriptPubKey ? addressFor(d.scriptPubKey, network) : null;
  switch (pair.name) {
    case "PSBT_GLOBAL_UNSIGNED_TX":
      return { text: d.note || "Edited in the transaction section.", tone: "muted" };
    case "PSBT_GLOBAL_XPUB":
      return { text: `${d.xpub} · fingerprint ${d.fingerprint} · path ${d.path}`, tone: "" };
    case "PSBT_GLOBAL_VERSION":
      return { text: `PSBT version ${d.version}`, tone: d.version === 0 ? "" : "warn" };
    case "PSBT_GLOBAL_PROPRIETARY":
    case "PSBT_IN_PROPRIETARY":
    case "PSBT_OUT_PROPRIETARY":
      // The prefix text is the counterparty's: neutralize bidi/invisible
      // codepoints so it cannot reorder or hide the rest of the line.
      return { text: `prefix ${d.prefixText ? JSON.stringify(hodlNeutralizeControls(d.prefixText)) : d.prefix} · subtype ${d.subtype}${d.keydata ? ` · keydata ${shorten(d.keydata)}` : ""}`, tone: "" };
    case "PSBT_IN_NON_WITNESS_UTXO": {
      const prev = d.prevout ? ` · prevout ${d.prevout.vout}: ${d.prevout.value} sats ${addressFor(d.prevout.scriptPubKey, network) || shorten(d.prevout.scriptPubKey)}` : "";
      return { text: `txid ${d.txid} · ${d.outputCount} outputs${prev}`, tone: "" };
    }
    case "PSBT_IN_WITNESS_UTXO":
      return { text: `${d.value} sats${addr ? ` · ${addr}` : ""} · ${d.asm}`, tone: "" };
    case "PSBT_IN_PARTIAL_SIG":
      return { text: `pubkey ${shorten(d.pubkey)} · sig ${shorten(d.signature)} · ${d.sighash}`, tone: "" };
    case "PSBT_IN_SIGHASH_TYPE":
      return { text: `${d.sighash} (0x${Number(d.sighashType).toString(16)})`, tone: d.sighashType === 1 ? "" : "warn" };
    case "PSBT_IN_REDEEM_SCRIPT":
    case "PSBT_IN_WITNESS_SCRIPT":
    case "PSBT_OUT_REDEEM_SCRIPT":
    case "PSBT_OUT_WITNESS_SCRIPT":
    case "PSBT_IN_FINAL_SCRIPTSIG":
      return { text: d.asm || "(empty script)", tone: "" };
    case "PSBT_IN_FINAL_SCRIPTWITNESS":
      return { text: `${d.items.length} witness item(s): ${d.items.map((item) => shorten(item)).join(", ")}`, tone: "" };
    case "PSBT_IN_BIP32_DERIVATION":
    case "PSBT_OUT_BIP32_DERIVATION":
      return { text: `pubkey ${shorten(d.pubkey)} · fingerprint ${d.fingerprint} · path ${d.path}`, tone: "" };
    case "PSBT_IN_RIPEMD160":
    case "PSBT_IN_SHA256":
    case "PSBT_IN_HASH160":
    case "PSBT_IN_HASH256":
      return { text: `hash ${shorten(d.hash)} · preimage ${shorten(d.preimage)}`, tone: "" };
    case "PSBT_IN_TAP_KEY_SIG":
      return { text: `sig ${shorten(d.signature)} · ${d.sighash}`, tone: "" };
    case "PSBT_IN_TAP_SCRIPT_SIG":
      return { text: `xonly ${shorten(d.xonly)} · leaf ${shorten(d.leafHash)} · sig ${shorten(d.signature)} · ${d.sighash}`, tone: "" };
    case "PSBT_IN_TAP_LEAF_SCRIPT":
      return { text: `version ${d.leafVersion} · ${d.asm} · control block ${shorten(d.controlBlock)}`, tone: "" };
    case "PSBT_IN_TAP_BIP32_DERIVATION":
    case "PSBT_OUT_TAP_BIP32_DERIVATION":
      return { text: `xonly ${shorten(d.xonly)} · fingerprint ${d.fingerprint} · path ${d.path} · ${d.leafHashes.length} leaf hash(es)`, tone: "" };
    case "PSBT_IN_TAP_INTERNAL_KEY":
    case "PSBT_OUT_TAP_INTERNAL_KEY":
      return { text: `xonly ${d.xonly}`, tone: "" };
    case "PSBT_IN_TAP_MERKLE_ROOT":
      return { text: `root ${d.merkleRoot}`, tone: "" };
    case "PSBT_OUT_TAP_TREE":
      return { text: `${d.leaves.length} leaf/leaves: ${d.leaves.map((leaf) => `depth ${leaf.depth} ${leaf.asm}`).join(" · ")}`, tone: "" };
    default:
      return { text: "", tone: "muted" };
  }
};

// Only the decoder's typed public fields get direct copy actions. Unknown
// or proprietary pair bytes can contain private material and retain the
// deliberate clipboard-only expandable readout.
const pairNoteHtml = (pair, network, copyIcon) => {
  const d = pair.decodeError ? null : pair.decoded;
  const pub = (value, label, preview = value) => publicValueHtml(value, { label, preview, copyIcon });
  const origin = () => `${pub(d.fingerprint, "fingerprint")} · path ${publicValueHtml(d.path, { clipboard: false })}`;
  if (d) switch (pair.name) {
    case "PSBT_GLOBAL_XPUB":
      return `${pub(d.xpub, "xpub", shorten(d.xpub))} · ${origin()}`;
    case "PSBT_IN_PARTIAL_SIG":
      return `${pub(d.pubkey, "pubkey", shorten(d.pubkey))} · sig ${escapeHtml(shorten(d.signature))} · ${escapeHtml(d.sighash)}`;
    case "PSBT_IN_BIP32_DERIVATION":
    case "PSBT_OUT_BIP32_DERIVATION":
      return `${pub(d.pubkey, "pubkey", shorten(d.pubkey))} · ${origin()}`;
    case "PSBT_IN_TAP_SCRIPT_SIG":
      return `${pub(d.xonly, "xonly", shorten(d.xonly))} · leaf ${escapeHtml(shorten(d.leafHash))} · sig ${escapeHtml(shorten(d.signature))} · ${escapeHtml(d.sighash)}`;
    case "PSBT_IN_TAP_BIP32_DERIVATION":
    case "PSBT_OUT_TAP_BIP32_DERIVATION":
      return `${pub(d.xonly, "xonly", shorten(d.xonly))} · ${origin()} · ${d.leafHashes.length} leaf hash(es)`;
    case "PSBT_IN_TAP_INTERNAL_KEY":
    case "PSBT_OUT_TAP_INTERNAL_KEY":
      return pub(d.xonly, "xonly");
    case "PSBT_IN_WITNESS_UTXO": {
      const address = addressFor(d.scriptPubKey, network);
      if (address) return `${escapeHtml(String(d.value))} sats · ${pub(address, "Address")} · ${expandableHtml(d.asm, { label: "scriptPubKey" })}`;
      break;
    }
    case "PSBT_IN_NON_WITNESS_UTXO": {
      const address = d.prevout && addressFor(d.prevout.scriptPubKey, network);
      if (address) return `txid ${escapeHtml(d.txid)} · ${d.outputCount} outputs · prevout ${d.prevout.vout}: ${escapeHtml(String(d.prevout.value))} sats ${pub(address, "Address")}`;
      break;
    }
  }
  return expandableHtml(describePair(pair, network).text, { label: `${pair.name || "pair"} — decoded` });
};

// The editable document is the inspect document; the WASM ignores the
// decorative fields (name/decoded) on build and reads key/value hex only.
export const psbtEditorBuildDoc = (doc) => ({
  tx: {
    version: doc.tx.version,
    locktime: doc.tx.locktime,
    inputs: doc.tx.inputs.map((input) => ({ txid: input.txid, vout: input.vout, scriptSig: input.scriptSig, sequence: input.sequence })),
    outputs: doc.tx.outputs.map((output) => ({ value: output.value, scriptPubKey: output.scriptPubKey })),
  },
  globals: doc.globals.map((pair) => ({ key: pair.key, value: pair.value })),
  inputs: doc.inputs.map((map) => map.map((pair) => ({ key: pair.key, value: pair.value }))),
  outputs: doc.outputs.map((map) => map.map((pair) => ({ key: pair.key, value: pair.value }))),
});

// Input-map key types whose values commit to the unsigned transaction:
// partial signatures (0x02), final scriptSig (0x07), final witness (0x08),
// Taproot key/script signatures (0x13/0x14), and the MuSig2 signing-session
// material (BIP-373): public nonces (0x1b) and partial signatures (0x1c) are
// bound to the message like any signature. Any edit to the transaction
// changes every digest those values commit to, so keeping them would leave a
// rebuilt PSBT looking signed while its signatures are invalid (issues #325,
// #360). Sighash-type hints (0x03), MuSig2 participant pubkeys (0x1a —
// message-independent), and UTXO claims are not signatures and stay; the
// UTXO claims join the signing anchor below instead.
const SIGNING_KEY_TYPES = new Set(["02", "07", "08", "13", "14", "1b", "1c"]);

// Drops every signing/finalization pair from the document's input maps, in
// place. Called by the editor when the transaction section is about to be
// rebuilt with different bytes than the pairs were inspected against.
export const dropSigningPairs = (doc) => {
  let dropped = 0;
  for (const map of doc.inputs) {
    for (let i = map.length - 1; i >= 0; i--) {
      if (SIGNING_KEY_TYPES.has(map[i].key.slice(0, 2))) {
        map.splice(i, 1);
        dropped += 1;
      }
    }
  }
  return dropped;
};

// Input-map key types whose *contents* signatures commit to without being
// signatures themselves: the UTXO declarations (non-witness 0x00, witness
// 0x01). BIP-143 commits to the spent output's amount and scriptCode; BIP-341
// commits to every input's amount and scriptPubKey. Editing a declaration in
// the pair table changes those digests exactly like a transaction edit, so
// the declarations join the rebuild anchor and stale signatures drop the same
// way (issue #325).
const UTXO_CLAIM_TYPES = new Set(["00", "01"]);

// Everything the input maps' signatures commit to, as one comparable string:
// the unsigned transaction plus each input's UTXO declarations. Both sides
// pass through the build projection — psbtEditorBuildDoc's tx, key/value-only
// pairs — so presentation fields (output asm, pair name/decoded) cannot move
// the anchor without changing a byte the builder would write.
export const signingAnchor = (doc) =>
  JSON.stringify([
    psbtEditorBuildDoc(doc).tx,
    doc.inputs.map((map) => map.filter((pair) => UTXO_CLAIM_TYPES.has(pair.key.slice(0, 2))).map((pair) => [pair.key, pair.value])),
  ]);

// --- Comparison report -----------------------------------------------------
// Rendering for comparePsbtDocs output (psbt-diff.js). Pure string building,
// unit-tested under Node; every interpolated value passes escapeHtml or
// expandableHtml. The report is descriptive: git-style +/−/~ marks name the
// kind of difference, and the summary lines carry the only tones.

const DIFF_MARK = {
  added: ["+", "ok", "added in the pasted PSBT"],
  removed: ["−", "bad", "removed in the pasted PSBT"],
  changed: ["~", "warn", "changed in the pasted PSBT"],
};

const capitalize = (text) => text.slice(0, 1).toUpperCase() + text.slice(1);

const formatSats = (value) => {
  try {
    return `${value} sats (${satsToBtc(value)} BTC)`;
  } catch {
    return String(value ?? "");
  }
};

// One-line presentation of an output script, the same fallback chain as the
// editor's output rows: address, OP_RETURN summary, ASM, else raw hex.
const scriptCell = (scriptHex, asm, network, copyIcon) => {
  const address = addressFor(scriptHex, network);
  if (address) return publicValueHtml(address, { label: "Address", copyIcon });
  const text = opReturnSummary(scriptHex)?.text || asm || String(scriptHex ?? "");
  return expandableHtml(text, { label: "scriptPubKey" });
};

const emDash = '<span class="muted">—</span>';

const diffRow = (change, fieldHtml, beforeHtml, afterHtml) => {
  const [mark, tone, label] = DIFF_MARK[change.kind];
  return `<tr><td class="psbted-diff-mark psbted-note-${tone}" title="${label}">${mark}</td><td>${fieldHtml}</td><td>${beforeHtml}</td><td>${afterHtml}</td></tr>`;
};

const diffTable = (rows) =>
  rows.length
    ? `<table class="psbted-pairs psbted-diff">
      <thead><tr><th class="psbted-col-mark"></th><th>Field</th><th>Before</th><th>After</th></tr></thead>
      <tbody>${rows.join("")}</tbody>
    </table>`
    : "";

// The transaction-section rows: version/locktime, per-input and per-output
// fields, and whole inputs/outputs appearing or disappearing.
const txDiffRows = (changes, before, after, network, copyIcon) =>
  changes
    .filter((change) => change.category === "transaction")
    .map((change) => {
      if (!change.field) {
        const element = change.kind === "added" ? change.after : change.before;
        const cell =
          change.scope === "input"
            ? `<span class="psbted-hex">${expandableHtml(String(element.txid), { label: `Input ${change.index} previous txid` })}</span> : ${escapeHtml(String(element.vout))}`
            : `${escapeHtml(formatSats(element.value))}<br>${scriptCell(element.scriptPubKey, element.asm, network, copyIcon)}`;
        return diffRow(change, escapeHtml(`${capitalize(change.scope)} ${change.index}`), change.kind === "added" ? emDash : cell, change.kind === "added" ? cell : emDash);
      }
      const name = change.field.split(".").pop();
      const label = change.scope === "transaction" ? capitalize(name) : `${capitalize(change.scope)} ${change.index} · ${{ txid: "previous txid", vout: "prevout index", value: "value", scriptPubKey: "scriptPubKey" }[name] || name}`;
      const side = (value, doc) => {
        if (name === "value") return escapeHtml(formatSats(value));
        if (name === "scriptPubKey") return scriptCell(value, doc?.tx?.outputs?.[change.index]?.asm, network, copyIcon);
        if (name === "txid") return `<span class="psbted-hex">${expandableHtml(String(value), { label })}</span>`;
        return escapeHtml(String(value ?? ""));
      };
      return diffRow(change, escapeHtml(label), side(change.before, before), side(change.after, after));
    });

// One key-value pair cell of a map diff: the typed one-line decode when the
// pair has one, otherwise (or when undecodable) the raw value hex — the same
// two presentations the editor's pair tables use.
const pairCell = (pair, network, copyIcon) => {
  if (!pair) return emDash;
  const name = pair.name || "pair";
  const note = describePair(pair, network);
  const parts = [];
  if (note.text) parts.push(`<span${note.tone ? ` class="psbted-note-${note.tone}"` : ""}>${pairNoteHtml(pair, network, copyIcon)}</span>`);
  if (!pair.decoded || !note.text) parts.push(`<span class="psbted-hex">${expandableHtml(pair.value, { label: `${name} — value (hex)` })}</span>`);
  return parts.join("<br>");
};

const mapDiffRows = (changes, scope, index, before, after, network, copyIcon) =>
  changes
    .filter((change) => change.scope === scope && change.index === index)
    .map((change) => {
      const mapOf = (doc) => (scope === "global" ? doc.globals : scope === "input-map" ? doc.inputs?.[index] : doc.outputs?.[index]) || [];
      // Duplicate keys make a bare key lookup ambiguous, so the change
      // carries each side's occurrence ordinal within its key group
      // (psbt-diff.js); the row must show that exact pair, not the first.
      const withKey = (doc) => mapOf(doc).filter((pair) => pair.key === change.key);
      const beforePair = change.beforeOrdinal == null ? null : withKey(before)[change.beforeOrdinal] || null;
      const afterPair = change.afterOrdinal == null ? null : withKey(after)[change.afterOrdinal] || null;
      const field = change.name ? `<span class="psbted-hex">${escapeHtml(change.name)}</span>` : escapeHtml(`Unknown pair (type 0x${change.key.slice(0, 2)})`);
      return diffRow(change, field, pairCell(beforePair, network, copyIcon), pairCell(afterPair, network, copyIcon));
    });

// A document rust-bitcoin rejects, whose unsigned transaction is
// consensus-invalid, or whose duplicate-key sanitize family is in problem
// state is not one the decoded comparison can vouch for: the views it
// compared are already suspect (audit B2). Equality verdicts are withheld
// while either compared document is in that state.
const docBlocksEqualityClaims = (doc) =>
  Boolean(doc?.rustBitcoinError || doc?.txSanityError) || doc?.sanitize?.duplicateKeys?.state === "problem";

export const psbtDiffHtml = (diff, before, after, network, { copyIcon = () => "", beforeLabel = "the PSBT in the editor", afterLabel = "the pasted PSBT" } = {}) => {
  const blocked = docBlocksEqualityClaims(before) || docBlocksEqualityClaims(after);
  if (diff.equal && !blocked) return `<p class="psbted-note-ok">Semantically identical — the underlying transaction, the signing state, and the metadata all match.</p>`;
  const summary = [
    ...(blocked
      ? [`<p class="psbted-note-warn">⚠ At least one compared PSBT is invalid (rust-bitcoin rejected it, its unsigned transaction would not be accepted by a node, or it carries duplicate keys) — equality cannot be claimed for an invalid document; the lines below describe only what the decode could read.</p>`]
      : []),
    diff.transactionChanged
      ? `<p class="psbted-note-bad">✕ The underlying transaction changed — review every input and output before using either PSBT.</p>`
      : `<p class="psbted-note-ok">✓ The underlying transaction is unchanged.</p>`,
    diff.signingChanged
      ? `<p class="psbted-note-warn">⚠ Signing state changed (signatures, sighash types, final scripts).</p>`
      : blocked
        ? `<p class="psbted-note-warn">⚠ Signing state cannot be confirmed unchanged — equality cannot be claimed for an invalid document.</p>`
        : `<p class="muted">Signing state unchanged.</p>`,
    diff.metadataChanged
      ? `<p class="psbted-note-warn">⚠ PSBT metadata changed (key-value pairs outside the transaction).</p>`
      : `<p class="muted">PSBT metadata unchanged.</p>`,
  ];
  // The fee is derived from the compared fields (claimed input amounts minus
  // outputs), so a fee change always accompanies rows above; this line states
  // the bottom line directly.
  const feeOf = (doc) => (doc.fee?.known && doc.fee.sats !== null ? doc.fee.sats : null);
  const feeBefore = feeOf(before), feeAfter = feeOf(after);
  if (feeBefore !== null && feeAfter !== null && feeBefore !== feeAfter)
    summary.push(`<p class="psbted-note-warn">Fee (from PSBT-claimed input amounts): ${escapeHtml(formatSats(feeBefore))} → ${escapeHtml(formatSats(feeAfter))}.</p>`);

  const sections = [];
  // Rendered rows and sections are capped at PSBT_RENDER_LIMIT each, and the
  // whole view shares one render budget: a crafted pair of PSBTs differs in
  // more elements than the DOM survives, and nested lists multiply — 500
  // capped sections of 200 changes are still 100,000 rows (red-team F7).
  // The verdict and the summary lines above still cover every change; each
  // list the cap stops notes how many changes were elided, and once the
  // budget is spent one line notes every section and change not rendered
  // from that point on.
  const moreChanges = (count) => `<p class="muted">…and ${count} more changes (not rendered).</p>`;
  const budget = renderBudget();
  let budgetElided = 0; // changes not rendered because the budget ran out
  // Pushes one section (1 budget unit) and up to PSBT_RENDER_LIMIT of its
  // rows while the budget allows; returns false when the budget refused the
  // section, leaving its rows to the caller's budget line. Rows the per-list
  // cap elides get the section's own line; rows the budget cuts join the
  // view's single budget line.
  const pushSection = (title, rows) => {
    if (budgetElided || budget.take(1) !== 1) return false;
    const shown = budget.take(Math.min(rows.length, PSBT_RENDER_LIMIT));
    if (budget.spent) budgetElided += rows.length - shown;
    sections.push(`<section class="psbted-map"><h3>${title}</h3>${diffTable(rows.slice(0, shown))}${rows.length > shown && !budget.spent ? moreChanges(rows.length - shown) : ""}</section>`);
    return true;
  };
  const txRows = txDiffRows(diff.changes, before, after, network, copyIcon);
  if (txRows.length && !pushSection("Transaction", txRows)) budgetElided += txRows.length;
  const mapSections = (scope, title) => {
    const indexes = [...new Set(diff.changes.filter((change) => change.scope === scope).map((change) => change.index))].sort((a, b) => a - b);
    const capped = new Set(indexes.slice(0, PSBT_RENDER_LIMIT));
    const accounted = new Set(); // indexes whose changes rendered or joined the budget line
    for (const index of capped) {
      if (budgetElided) break; // the budget is spent: the rest joins the line below
      const rows = mapDiffRows(diff.changes, scope, index, before, after, network, copyIcon);
      if (!rows.length) continue;
      if (pushSection(`${title} ${index} key-value map`, rows)) accounted.add(index);
      else {
        budgetElided += rows.length;
        accounted.add(index);
        break;
      }
    }
    if (budgetElided) {
      // The budget stopped the rendering: every change whose map never
      // rendered joins the single budget line. The unrendered maps
      // themselves are sections, not changes, so a line that says "changes"
      // must not count them (red-team F7 round 6 follow-up).
      budgetElided += diff.changes.filter((change) => change.scope === scope && !accounted.has(change.index)).length;
    } else if (indexes.length > capped.size) {
      sections.push(moreChanges(diff.changes.filter((change) => change.scope === scope && !capped.has(change.index)).length));
    }
  };
  mapSections("input-map", "Input");
  mapSections("output-map", "Output");
  const globalRows = mapDiffRows(diff.changes, "global", null, before, after, network, copyIcon);
  if (globalRows.length && !pushSection("Global key-value map", globalRows)) budgetElided += globalRows.length;
  if (budgetElided) sections.push(moreChanges(budgetElided));

  return `<p class="muted">before = ${escapeHtml(beforeLabel)} · after = ${escapeHtml(afterLabel)}. Only differences are listed.</p>${summary.join("")}${sections.join("")}`;
};

// Sanitize banner (inspect + compare footer). Three-state per issue #217:
// complete / problem / incomplete. Duplicate keys are a format fact; origin
// derivation is a consistency fact. Neither is a safety verdict.
const sanitizeFamilyLabel = {
  complete: ["Completed", "ok"],
  problem: ["Problem found", "bad"],
  incomplete: ["Incomplete", "warn"],
};

const sanitizeFindingText = (finding) => {
  const where =
    finding.scope === "global"
      ? "global map"
      : finding.index == null
        ? finding.scope
        : `${finding.scope} ${finding.index}`;
  const name = finding.name || "key";
  if (finding.code === "duplicate_key") return `duplicate ${name} in ${where}`;
  if (finding.code === "xpub_derives_child") {
    const fp = finding.fingerprint ? ` fingerprint ${finding.fingerprint}` : "";
    const reason =
      finding.reason === "mismatch"
        ? "does not derive from the matching global xpub"
        : finding.reason === "hardened_gap"
          ? "not checked (hardened gap on the remaining path)"
          : finding.reason === "malformed"
            ? "origin field is malformed"
            : finding.reason === "malformed_key"
              ? "key is not valid for this record type (not checked)"
              : finding.reason === "budget_exhausted"
                ? "not checked (analysis budget exhausted)"
                : "not checked (no applicable global xpub)";
    return `${name} on ${where}${fp}: ${reason}`;
  }
  return name;
};

export const psbtSanitizeHtml = (doc, title = "") => {
  const s = doc?.sanitize;
  if (!s) return "";
  const dup = s.duplicateKeys || { state: "incomplete", findings: [] };
  const orig = s.xpubDerivesChild || { state: "incomplete", findings: [] };
  const problem = dup.state === "problem" || orig.state === "problem";
  // Anything that is not a known pass/problem is incomplete — an unknown
  // state must never render as success.
  const incomplete = [dup, orig].some((f) => f.state !== "complete" && f.state !== "problem");
  const overall = problem && incomplete
    ? "ISSUES FOUND — ANALYSIS ALSO INCOMPLETE"
    : problem
      ? "ISSUES FOUND"
      : incomplete
        ? "ANALYSIS INCOMPLETE"
        : "LISTED CHECKS COMPLETE";
  const tone = problem ? "bad" : incomplete ? "warn" : "ok";
  const row = (label, family) => {
    const [word, cls] = sanitizeFamilyLabel[family.state] || sanitizeFamilyLabel.incomplete;
    const extra = family.truncated ? " (report truncated)" : "";
    // One dash-marked line per finding — a "; "-joined run-in reads as one
    // giant line once a family has several.
    const findings = (family.findings || []).slice(0, 8);
    const list = findings.length ? `<ul>${findings.map((finding) => `<li>${escapeHtml(sanitizeFindingText(finding))}</li>`).join("")}</ul>` : "";
    return `<li><span class="label">${escapeHtml(label)}</span> — <span class="psbted-note-${cls}">${word}</span>${extra}${list}</li>`;
  };
  const heading = title ? `${escapeHtml(title)} — ` : "";
  return `<section class="psbted-sanitize psbt-analysis-summary" aria-label="${title ? escapeHtml(title) + " " : ""}PSBT format and origin checks">
    <p class="label">PSBT format and origin checks</p>
    <p class="psbted-note-${tone}"><strong>${heading}${overall}</strong></p>
    <ul>${row("Duplicate keys", dup)}${row("Origin derivation", orig)}</ul>
    <p class="edge-note is-muted">Format and origin-consistency facts from this file. Not a safety verdict.</p>
  </section>`;
};

// The consensus layer's findings (verify.rs in the WASM crate), rendered as
// a flat list in the sanitize section's style. Error-severity problems are
// what the build gate refuses — with Insane editing off the build cannot
// succeed while any are listed, so the note says which mode the list speaks
// from. Every string is escaped here; messages name pair types and verdicts
// but never echo raw signature bytes to the DOM.
export const psbtProblemsHtml = (doc, insane = false) => {
  const problems = doc?.problems;
  if (!problems) return "";
  // Severity totals come from the untruncated counts when the doc carries
  // them: the visible list is capped, and a truncated list must never read
  // as "no consensus violations" while an error was dropped (audit C3-4).
  const listed = problems.filter((problem) => problem.severity === "error").length;
  const truncated = Boolean(doc.problemsTruncated);
  const total = doc.problemCount ?? problems.length;
  const errorTotal = doc.errorCount ?? listed;
  const totalsUnknown = truncated && doc.problemCount === undefined;
  const tone = errorTotal ? "bad" : total ? "warn" : "ok";
  const heading = !total
    ? "No consensus or signing problems found"
    : errorTotal
      ? `${errorTotal} consensus/signing problem(s)${total > errorTotal ? ` and ${total - errorTotal} warning(s)` : ""}${truncated ? " (list truncated)" : ""}`
      : totalsUnknown
        ? `${problems.length} warning(s) shown; the list is truncated, so error-severity problems may be hidden`
        : `${total} warning(s), no consensus violations`;
  const gate = errorTotal
    ? insane
      ? "Insane editing is on — these did not block the build."
      : "Errors block the build and export until fixed (Insane editing above disables this layer)."
    : totalsUnknown
      ? "The build gate re-checks the full, untruncated list."
      : "";
  const items = problems
    .map(
      (problem) =>
        `<li><span class="psbted-note-${problem.severity === "error" ? "bad" : "warn"}">${escapeHtml(problem.scope)}</span> — ${escapeHtml(problem.message)}</li>`,
    )
    .join("");
  return `<section class="psbted-sanitize psbt-analysis-summary" aria-label="PSBT consensus and signing problems">
    <p class="label">PSBT consensus and signing problems</p>
    <p class="psbted-note-${tone}"><strong>${escapeHtml(heading)}</strong>${gate ? ` — ${escapeHtml(gate)}` : ""}</p>
    ${items ? `<ul>${items}</ul>` : ""}
    ${doc.problemsTruncated ? `<p class="muted">List truncated; more problems exist than are shown.</p>` : ""}
    <p class="edge-note is-muted">Checked against Bitcoin's consensus rules and BIP-174's signer checks, using the PSBT's own UTXO claims — amounts and scripts are not verified against the chain.</p>
  </section>`;
};

// The editor has no network control of its own: addresses decode against the
// header network picker's choice, read through the `networkDefault` getter
// (mainnet/testnet), and re-decoded live when the picker changes it (the
// "hodl:network-default" document event).
export const initPsbtEditor = ({ networkDefault = () => "mainnet", copiedIcon = () => "", copyIcon = () => "", journalLog = () => {} } = {}) => {
  const load = document.getElementById("psbted-load");
  if (!load) return;
  const $ = (id) => document.getElementById(id);
  const out = $("psbted-out"), error = $("psbted-error"), text = $("psbted-text");
  const network = networkDefault;

  let doc = null; // inspect document being edited; null when nothing is loaded
  // Pairs added through the Add Pair form, keyed "kind:mapIndex". In an
  // over-cap map the add lands past the rendered rows; pairRows renders this
  // many of the map's last pairs after the capped rows, so the add is never
  // invisible (red-team F7 round 4). Cleared when another document loads.
  const addedPairs = new Map();
  // The keys are map positions, so deleting an input or output shifts every
  // later map of that kind down one index and the counts would point at the
  // wrong maps: the added pair is elided again and the map now at the old
  // index renders an extra overflow row (red-team F7 round 5). Re-key on the
  // delete — option (a): the editor has no reorder operation (adds append,
  // only deletes shift indices), so re-keying on delete covers every shift,
  // and tracking pair identity instead would add bookkeeping for no extra
  // case. The deleted map's count goes with it; clearing everything would
  // make the other maps' added pairs invisible.
  const shiftAddedPairs = (kind, removed) => {
    // Build the new map from a snapshot: re-keying in place, in insertion
    // order, can overwrite a lower key before it moves ("input:2" landing
    // on "input:1" erases that map's own count), losing an added pair
    // (red-team F7 round 6).
    const shifted = new Map();
    for (const [key, count] of addedPairs) {
      const [keyKind, keyIndex] = key.split(":");
      if (keyKind !== kind) {
        shifted.set(key, count);
        continue;
      }
      const index = Number(keyIndex);
      if (index > removed) shifted.set(`${kind}:${index - 1}`, count);
      else if (index < removed) shifted.set(key, count);
      // index === removed: the deleted map's count is dropped with it.
    }
    addedPairs.clear();
    for (const [key, count] of shifted) addedPairs.set(key, count);
  };
  let resultBytes = null; // last successfully built PSBT
  let stale = false; // true while the current fields do not build; resultBytes is then the last valid build
  let pristineTx = null; // signingAnchor of the document the current signing pairs commit to; null while unknown
  let insane = $("psbted-insane")?.checked ?? false; // insane editing: the consensus layer reports but does not gate
  // Clears the highlight a diagram box leaves on the section it jumps to.
  let anchorTimer = null;

  initExpandable({ copy: copyIcon, copied: copiedIcon });
  // Edits saved in the expandable editor window are field edits, exactly
  // like typing in the plain value inputs: they rebuild live.
  out.addEventListener("expandable:apply", (event) => {
    if (!doc) return;
    const { kind, map, pair } = event.target.dataset;
    if (kind === undefined || pair === undefined) return;
    (kind === "global" ? doc.globals : kind === "input" ? doc.inputs[map] : doc.outputs[map])[Number(pair)].value = event.detail.text.trim();
    liveRebuild();
  });

  const setError = (message) => {
    error.textContent = message || "";
  };

  // Actions stay disabled until there is something to act on: Load waits on
  // pasted text, End Session on anything loaded or typed, Compare on a loaded
  // PSBT plus a pasted second one, Clear Comparison on any comparison input.
  const setEnabled = (button, on) => {
    button.disabled = !on;
    button.setAttribute("aria-disabled", String(!on));
  };
  const syncActions = () => {
    const compareInput = $("psbted-compare-text").value.trim();
    setEnabled(load, Boolean(text.value.trim()));
    setEnabled($("psbted-wipe"), Boolean(doc || text.value.trim() || compareInput));
    setEnabled($("psbted-compare-go"), Boolean(doc && compareInput));
    setEnabled($("psbted-compare-clear"), Boolean(compareInput || $("psbted-compare-out").innerHTML || $("psbted-compare-error").textContent));
  };

  // Narrow screens stack each table row into a block, so every cell carries
  // its column's name as a label that only shows there (the header row is
  // what sighted desktop readers use; the label is aria-hidden to avoid a
  // double announcement). Explicit table roles keep the semantics when the
  // stacked layout drops the table display.
  const cellLabel = (text) => `<span class="psbted-cell-label" aria-hidden="true">${text}</span>`;
  const KV_COLUMNS = { field: "Field", key: "Key (hex)", value: "Value (hex)", decoded: "Decoded" };
  const TXIN_COLUMNS = { txid: "Previous txid", vout: "vout", seq: "sequence" };
  const TXOUT_COLUMNS = { value: "Value (sats)", script: "scriptPubKey" };

  const pairRows = (kind, map, mapIndex, budget = null, overflow = 0) => {
    // Rows are capped at PSBT_RENDER_LIMIT per table and spend from the
    // view's render budget when one is passed: a crafted PSBT passes the
    // load gates with more pairs in one map than the DOM survives, and
    // nested lists multiply (red-team F7). The document keeps every pair;
    // the elided count is noted under the table — by this table's own line
    // when the per-list cap elided it, or by the view's single budget line
    // when the budget ran out. Pairs added through the form while the map
    // was over the cap are the map's last pairs: `overflow` of them render
    // after the capped rows, so an add is never invisible.
    const cap = Math.min(map.length, PSBT_RENDER_LIMIT);
    const shown = budget ? budget.take(cap) : cap;
    const overflowStart = Math.max(shown, map.length - overflow);
    const shownOverflow = budget ? budget.take(map.length - overflowStart) : map.length - overflowStart;
    const rendered = [...Array(shown).keys(), ...Array.from({ length: shownOverflow }, (_, offset) => map.length - shownOverflow + offset)];
    const rows = rendered
      .map((pairIndex) => {
        const pair = map[pairIndex];
        const locked = kind === "global" && pair.key === "00";
        const note = describePair(pair, network());
        const tone = note.tone ? ` class="psbted-note-${note.tone}"` : "";
        const name = pair.name || "pair";
        // Long fields collapse to the standard truncated cell; activating it
        // opens the full text in the expandable editor window. A long value
        // stays editable there, so the write path matches the plain input's.
        const valueCell = pair.value.length > EXPAND_LIMIT
          ? expandableHtml(pair.value, { label: `Value bytes for ${name} (hex)`, editAttrs: `data-kind="${kind}" data-map="${mapIndex}" data-pair="${pairIndex}"` })
          : `<input class="psbted-value" data-kind="${kind}" data-map="${mapIndex}" data-pair="${pairIndex}" value="${escapeHtml(pair.value)}" spellcheck="false" autocomplete="off" autocapitalize="off" aria-label="Value bytes for ${escapeHtml(name)} (hex)">`;
        return `<tr role="row">
          <td role="cell" class="psbted-name">${escapeHtml(pair.name || "Unvalidated pair")}<br><span class="muted">type 0x${escapeHtml(pair.key.slice(0, 2))}</span></td>
          <td role="cell" class="psbted-hex">${cellLabel(KV_COLUMNS.key)}${expandableHtml(pair.key, { label: `Key bytes for ${name} (hex)` })}</td>
          <td role="cell">${cellLabel(KV_COLUMNS.value)}${locked ? `<span class="muted">managed by the transaction section</span>` : valueCell}</td>
          <td role="cell"${tone}>${cellLabel(KV_COLUMNS.decoded)}${pairNoteHtml(pair, network(), copyIcon)}</td>
          <td role="cell" class="psbted-del-cell">${locked ? "" : `<button type="button" class="btn red psbted-del" data-kind="${kind}" data-map="${mapIndex}" data-pair="${pairIndex}" aria-label="Delete ${escapeHtml(pair.name || "pair")}">×</button>`}</td>
        </tr>`;
      })
      .join("");
    const elided = map.length - shown - shownOverflow;
    const options = PAIR_TYPES[kind]
      .map(([type, name, hint]) => `<option value="${type}" title="keydata: ${escapeHtml(hint)}">${name}</option>`)
      .join("");
    // A table the budget cut stays silent: the view's single budget line
    // counts its elided pairs (the caller reads them off the budget).
    const morePairs = elided > 0 && (!budget || !budget.spent) ? `<p class="muted">…and ${elided} more pairs (not rendered).</p>` : "";
    return `<table class="psbted-pairs psbted-kv psbted-stack" role="table">
      <thead role="rowgroup"><tr role="row"><th role="columnheader" class="psbted-col-field">${KV_COLUMNS.field}</th><th role="columnheader">${KV_COLUMNS.key}</th><th role="columnheader">${KV_COLUMNS.value}</th><th role="columnheader">${KV_COLUMNS.decoded}</th><th role="columnheader" class="psbted-col-del"></th></tr></thead>
      <tbody role="rowgroup">${map.length ? rows : `<tr role="row"><td role="cell" colspan="5" class="muted">No pairs in this map.</td></tr>`}</tbody>
    </table>
    ${morePairs}<div class="psbted-add">
      <select data-add-type="${kind}:${mapIndex}" aria-label="New pair type">${options}<option value="" title="keydata field takes the full key: one type byte, then keydata">Custom type…</option></select>
      <input data-add-key="${kind}:${mapIndex}" placeholder="keydata (hex)" spellcheck="false" autocomplete="off" autocapitalize="off" aria-label="New pair keydata (hex)">
      <input data-add-val="${kind}:${mapIndex}" placeholder="value (hex)" spellcheck="false" autocomplete="off" autocapitalize="off" aria-label="New pair value (hex)">
      <button type="button" class="btn secondary" data-add="${kind}:${mapIndex}">Add Pair</button>
    </div>`;
  };

  const render = () => {
    // The result box is recreated here, so any running QR animation dies
    // with it; renderResult restarts it for the current build.
    syncActions();
    if (!doc) {
      out.innerHTML = "";
      return;
    }
    const tx = doc.tx;
    // sats null with every input claimed marks an invalid fee: the document's
    // error string says why (negative fee, u64 overflow, or past MAX_MONEY).
    const fee = doc.fee?.known
      ? doc.fee.sats === null
        ? `<span class="psbted-note-bad">${escapeHtml(doc.fee.error || "outputs exceed claimed inputs")}</span>`
        : `${escapeHtml(String(doc.fee.sats))} sats (${satsToBtc(doc.fee.sats)} BTC, from PSBT-claimed input amounts)`
      : doc.fee?.error
        ? `<span class="psbted-note-bad">${escapeHtml(doc.fee.error)}</span>`
        : "unknown — some inputs carry no claimed previous-output amount";
    // rust-bitcoin's PSBT module is v0-only (deprecated upstream); v2 files
    // are validated by the crate's own BIP-370 reader, and the verdict says so
    // instead of borrowing rust-bitcoin's name (issue #358).
    const verdict = doc.psbtVersion === 2
      ? `<span class="psbted-note-ok">PSBT v2 (BIP-370) — decoded by EntropyLab's own reader (rust-bitcoin checks v0 only)</span>`
      : doc.rustBitcoinError
        ? `<span class="psbted-note-warn">rust-bitcoin reports: ${escapeHtml(doc.rustBitcoinError)}</span>`
        : `<span class="psbted-note-ok">PSBT structure parses under rust-bitcoin</span>`;
    // Structural validity and consensus validity are separate facts: name the
    // transaction's sanity state explicitly so "parses" never reads as
    // "accepted by Bitcoin" (issues #322, #361).
    const sanity = doc.txSanityError
      ? `<span class="psbted-note-bad">unsigned transaction is consensus-invalid (${escapeHtml(doc.txSanityError)}) — ${insane ? "insane editing is on, so the build is not blocked" : "export is blocked"}</span>`
      : `<span class="psbted-note-ok">unsigned transaction passes consensus sanity checks</span>`;

    // The last remaining input carries no delete control: a zero-input
    // unsigned transaction cannot round-trip through BIP-174 serialization,
    // so rust-bitcoin would reject the rebuild.
    // Rendering is capped at PSBT_RENDER_LIMIT entries per list (a crafted
    // PSBT passes the load gates with more elements than the DOM survives),
    // and the whole view shares one render budget, so nested lists cannot
    // multiply past it (red-team F7 round 4). The document, totals, fee and
    // every analysis still cover all elements; each list the cap stops notes
    // its elided count after the last row, and once the budget is spent one
    // muted line notes everything not rendered from that point on.
    const budget = renderBudget();
    let budgetElided = 0; // sections and rows not rendered because the budget ran out
    // The summary's per-output notes spend from the same view budget, in
    // document order (they render above the tables): a crafted PSBT with a
    // note on every output cannot push the view past the budget (red-team
    // F7 round 6).
    const outputNotes = psbtOutputNotesHtml(doc, budget);
    // An input or output added while its list was over the cap is the list's
    // last element: like an added pair, it renders after the capped rows
    // (with its map section below), so an add is never invisible (red-team
    // F7 round 6). Stale counts after deletes are harmless — the overflow
    // never starts before the capped rows.
    const txIndices = (elements, kind) => {
      const shown = budget.take(Math.min(elements.length, PSBT_RENDER_LIMIT));
      const overflow = Math.min(addedPairs.get(`tx:${kind}`) || 0, elements.length);
      const overflowStart = Math.max(shown, elements.length - overflow);
      const shownOverflow = budget.take(elements.length - overflowStart);
      return [...Array(shown).keys(), ...Array.from({ length: shownOverflow }, (_, offset) => elements.length - shownOverflow + offset)];
    };
    const inputIndices = txIndices(tx.inputs, "input");
    const inputRows = inputIndices
      .map(
        (index) => {
          const input = tx.inputs[index];
          return `<tr role="row">
          <td role="cell">${cellLabel("Input")}${index}</td>
          <td role="cell">${cellLabel(TXIN_COLUMNS.txid)}<input class="psbted-txid" data-txin="${index}" value="${escapeHtml(input.txid)}" spellcheck="false" autocomplete="off" autocapitalize="off" aria-label="Input ${index} previous txid (hex)"></td>
          <td role="cell">${cellLabel(TXIN_COLUMNS.vout)}<input class="psbted-num" data-txin-vout="${index}" value="${escapeHtml(String(input.vout))}" inputmode="numeric" aria-label="Input ${index} prevout index"></td>
          <td role="cell">${cellLabel(TXIN_COLUMNS.seq)}<input class="psbted-num" data-txin-seq="${index}" value="${escapeHtml(String(input.sequence))}" inputmode="numeric" aria-label="Input ${index} sequence"></td>
          <td role="cell" class="psbted-del-cell">${tx.inputs.length > 1 ? `<button type="button" class="btn red psbted-del" data-txin-del="${index}" aria-label="Delete input ${index}">×</button>` : ""}</td>
        </tr>`;
        }
      )
      .join("");
    const outputIndices = txIndices(tx.outputs, "output");
    const outputRows = outputIndices
      .map((index) => {
        const output = tx.outputs[index];
        const addr = addressFor(output.scriptPubKey, network());
        const opret = addr ? null : opReturnSummary(output.scriptPubKey, output.value);
        return `<tr role="row">
          <td role="cell">${cellLabel("Output")}${index}</td>
          <td role="cell">${cellLabel(TXOUT_COLUMNS.value)}<input class="psbted-num" data-txout-val="${index}" value="${escapeHtml(String(output.value))}" inputmode="numeric" aria-label="Output ${index} value in sats"></td>
          <td role="cell">${cellLabel(TXOUT_COLUMNS.script)}<input class="psbted-txid" data-txout-script="${index}" value="${escapeHtml(output.scriptPubKey)}" spellcheck="false" autocomplete="off" autocapitalize="off" aria-label="Output ${index} scriptPubKey (hex)">
            <span class="${opret?.burn ? "psbted-note-warn" : "muted"} psbted-addr">${addr ? publicValueHtml(addr, { label: "Address", copyIcon }) : escapeHtml(opret?.text || output.asm || "")}</span>
            <span class="psbted-build"><input data-build-script="${index}" placeholder="address · OP_… ASM · 0x raw hex · text" spellcheck="false" autocomplete="off" autocapitalize="off" aria-label="Build output ${index} scriptPubKey from an address, ASM, or OP_RETURN text"><select data-build-mode="${index}" aria-label="Output ${index} script builder mode"><option value="auto" selected>Auto-detect</option><option value="opreturn-text">OP_RETURN text</option><option value="opreturn-hex">OP_RETURN hex</option><option value="asm">Script ASM</option></select><button type="button" class="btn secondary" data-build-apply="${index}">Set Script</button></span></td>
          <td role="cell" class="psbted-del-cell"><button type="button" class="btn red psbted-del" data-txout-del="${index}" aria-label="Delete output ${index}">×</button></td>
        </tr>`;
      })
      .join("");
    // Hidden inputs and outputs are still in the transaction (TC's review of
    // #1031): the note says so, as a warning, one or many.
    const moreInputsNote = tx.inputs.length > inputIndices.length ? `<p class="psbted-note-warn">${tx.inputs.length - inputIndices.length === 1 ? "1 more input not shown, still included in this transaction." : `${tx.inputs.length - inputIndices.length} more inputs not shown, still included in this transaction.`}</p>` : "";
    const moreOutputsNote = tx.outputs.length > outputIndices.length ? `<p class="psbted-note-warn">${tx.outputs.length - outputIndices.length === 1 ? "1 more output not shown, still included in this transaction." : `${tx.outputs.length - outputIndices.length} more outputs not shown, still included in this transaction.`}</p>` : "";

    // One map section per PSBT part; a diagram box jumps to its own section.
    const mapSection = (kind, index) => {
      const map = kind === "input" ? doc.inputs[index] : doc.outputs[index];
      const sub =
        kind === "input"
          ? `Spends <span class="psbt-address">${escapeHtml(tx.inputs[index].txid)}:${escapeHtml(String(tx.inputs[index].vout))}</span>`
          : `Pays <span class="psbt-amount">${escapeHtml(String(tx.outputs[index].value))} sats</span>${addressFor(tx.outputs[index].scriptPubKey, network()) ? ` to ${publicValueHtml(addressFor(tx.outputs[index].scriptPubKey, network()), { copyIcon, className: "psbted-out-address" })}` : ""}`;
      return `<section class="psbted-map" data-psbted-section="${kind}:${index}" tabindex="-1"><h3 class="psbted-section-label">${kind === "input" ? "Input" : "Output"} ${index} key-value map</h3><p class="muted label-description">${sub}</p>${pairRows(kind, map, index, budget, addedPairs.get(`${kind}:${index}`) || 0)}</section>`;
    };
    // The unsigned-transaction section, rendered either inline (the default)
    // or inside the detail panel when the diagram's transaction box is open.
    const txSection = () => `<section class="psbted-map" data-psbted-section="tx" tabindex="-1"><p class="label psbted-section-label">Unsigned transaction</p>
        <div class="psbted-txhead">
          <label>Version <input class="psbted-num" id="psbted-tx-version" value="${escapeHtml(String(tx.version))}" inputmode="numeric"></label>
          <label>Locktime <input class="psbted-num" id="psbted-tx-locktime" value="${escapeHtml(String(tx.locktime))}" inputmode="numeric"></label>
        </div>
        <p class="label psbted-section-label">Inputs</p>
        <table class="psbted-pairs psbted-txins psbted-stack" role="table"><thead role="rowgroup"><tr role="row"><th role="columnheader" class="psbted-idx">#</th><th role="columnheader">${TXIN_COLUMNS.txid}</th><th role="columnheader" class="psbted-col-vout">${TXIN_COLUMNS.vout}</th><th role="columnheader" class="psbted-col-seq">${TXIN_COLUMNS.seq}</th><th role="columnheader" class="psbted-col-del"></th></tr></thead><tbody role="rowgroup">${inputRows}</tbody></table>
        ${moreInputsNote}
        <div class="psbted-add-el"><button type="button" class="btn secondary" data-tx-add="input">Add Input</button></div>
        <p class="label psbted-section-label">Outputs</p>
        <table class="psbted-pairs psbted-txouts psbted-stack" role="table"><thead role="rowgroup"><tr role="row"><th role="columnheader" class="psbted-idx">#</th><th role="columnheader" class="psbted-col-val">${TXOUT_COLUMNS.value}</th><th role="columnheader">${TXOUT_COLUMNS.script}</th><th role="columnheader" class="psbted-col-del"></th></tr></thead><tbody role="rowgroup">${outputRows}</tbody></table>
        ${moreOutputsNote}
        <div class="psbted-add-el"><button type="button" class="btn secondary" data-tx-add="output">Add Output</button></div>
      </section>`;
    // The global map's section and then one section per map, in document
    // order, while the per-list section cap and the view budget allow. A
    // list the cap stops gets its own muted line naming the maps ("input
    // maps" / "output maps", so it cannot read as a duplicate of the
    // transaction table's inputs/outputs line); once the budget is spent no
    // further section renders, and every later map's section and pairs are
    // counted into the view's single budget line.
    let globalSection = "";
    if (budget.take(1) === 1) {
      const leftBefore = budget.left;
      globalSection = `<section class="psbted-map"><h3 class="psbted-section-label">Global key-value map</h3>${pairRows("global", doc.globals, 0, budget, addedPairs.get("global:0") || 0)}</section>`;
      if (budget.spent) budgetElided += doc.globals.length - (leftBefore - budget.left);
    } else {
      budgetElided += 1 + doc.globals.length;
    }
    const mapSections = (kind, maps, noun) => {
      const parts = [];
      const capped = Math.min(maps.length, PSBT_RENDER_LIMIT);
      // The maps whose section rendered. Before the overflow sections this
      // is [0, shown); once they render it is two ranges, so the budget
      // line below counts by membership, not from `shown` (red-team F7
      // round 7).
      const rendered = new Set();
      let shown = 0;
      while (shown < capped && budget.take(1) === 1) {
        const leftBefore = budget.left;
        parts.push(mapSection(kind, shown));
        rendered.add(shown);
        shown++;
        // If the budget ran out inside this map's pair table, the pairs it
        // did not render join the budget line (pairRows stays silent then).
        if (budget.spent) budgetElided += maps[shown - 1].length - (leftBefore - budget.left);
      }
      // An element added while the list was over the cap has its map at the
      // end: its section renders after the capped ones, like its table row
      // above, so the user can edit it (red-team F7 round 6).
      const overflow = Math.min(addedPairs.get(`tx:${kind}`) || 0, maps.length);
      const overflowStart = Math.max(shown, maps.length - overflow);
      for (let index = overflowStart; index < maps.length; index++) {
        if (budget.take(1) !== 1) break;
        const leftBefore = budget.left;
        parts.push(mapSection(kind, index));
        rendered.add(index);
        shown++;
        if (budget.spent) budgetElided += maps[index].length - (leftBefore - budget.left);
      }
      if (shown < maps.length) {
        if (budget.spent) {
          for (let index = 0; index < maps.length; index++) {
            if (!rendered.has(index)) budgetElided += 1 + maps[index].length;
          }
        } else {
          parts.push(`<p class="muted">…and ${maps.length - shown} more ${noun} (not rendered).</p>`);
        }
      }
      return parts.join("");
    };
    const inputSections = mapSections("input", doc.inputs, "input maps");
    const outputSections = mapSections("output", doc.outputs, "output maps");
    const budgetLine = budgetElided ? `<p class="muted">…and ${budgetElided} more items (not rendered).</p>` : "";

    out.innerHTML = `
      <p class="edge-note ${stale ? "is-private" : "is-muted"}" id="psbted-status" aria-live="polite">${stale ? "The fields do not build right now — see the error above; the result below is the last valid build." : "Every edit rebuilds the PSBT immediately; the fields show rust-bitcoin's decode of the current build."}</p>
      <p class="edge-note is-public">Fees and input amounts shown here are unverified PSBT claims; the editor does not check them against previous transactions or the blockchain. Nothing is signed or broadcast.</p>
      <p class="psbt-kv"><strong>PSBT v${escapeHtml(String(doc.psbtVersion))}</strong> · ${tx.inputs.length} input(s) · ${tx.outputs.length} output(s)<br><span class="psbt-amount">fee ${fee}</span><br>${verdict}<br>${sanity}${outputNotes}</p>

      ${psbtVizHtml(doc, network(), { copyIcon })}

      ${txSection()}

      ${globalSection}
      ${inputSections}
      ${outputSections}
      ${budgetLine}

      ${psbtProblemsHtml(doc, insane)}
      ${psbtSanitizeHtml(doc)}

      <div id="psbted-result"></div>`;

    bind();
  };

  const renderResult = () => {
    const box = document.getElementById("psbted-result");
    if (!box) return;
    if (!resultBytes) {
      box.innerHTML = "";
      return;
    }
    const b64 = base64Encode(resultBytes);
    const hex = bytesToHex(resultBytes);
    box.classList.toggle("psbted-stale", stale);
    // While the displayed fields do not build, the last valid build must not
    // cross an export boundary: every copy/download/reload control and the QR
    // are disabled — and the byte text is blanked, because a disabled,
    // readonly textarea's content is still selectable and copyable in Firefox
    // (issue #320).
    const gated = stale ? " disabled" : "";
    // Name the gate that actually ran: rust-bitcoin's PSBT type is v0-only,
    // so a v2 build is closed-loop-checked by the crate's own BIP-370 reader
    // (lib.rs build_v2) — crediting rust-bitcoin here would be a lie, the
    // same distinction the header verdict makes (issue #358). Under insane
    // editing the consensus layer did not gate the build, and the line must
    // not claim otherwise.
    const gate = doc.psbtVersion === 2
      ? "Rebuilt PSBT v2 round-trips through EntropyLab's own BIP-370 reader (rust-bitcoin checks v0 only)"
      : "Rebuilt PSBT parses under rust-bitcoin";
    const knownErrors = (doc.problems ?? []).filter((problem) => problem.severity === "error").length;
    const verdictLine = insane
      ? `<p class="psbted-note-warn">${gate} (${resultBytes.length} bytes) — built with Insane editing on: consensus and signing checks reported above did not gate this build${knownErrors ? ` (${knownErrors} error-level problem(s) ignored)` : ""}.</p>`
      : `<p class="psbt-ok">${gate}; its unsigned transaction passes consensus sanity checks (${resultBytes.length} bytes).</p>`;
    box.innerHTML = `
      ${stale ? `<p class="psbted-note-warn" id="psbted-stale-note">The fields do not build right now — this is the last valid build. Export is unavailable until they build again.</p>` : ""}
      ${verdictLine}
      <p class="label copy-field-label" id="psbted-result-b64-label">Edited PSBT (base64)${stale ? "" : addressQrButtonHtml(b64, "Edited PSBT (base64)", { animate: "psbt" })}${privateCopyButtonHtml(copyIcon, { id: "psbted-copy-b64", disabled: stale, attribute: "data-psbt-result-copy" })}</p>
      <div class="psbted-result-value" id="psbted-result-b64" data-private-value data-i18n-skip translate="no" aria-labelledby="psbted-result-b64-label">${stale ? "" : escapeHtml(b64)}</div>
      <p class="label copy-field-label" id="psbted-result-hex-label">Edited PSBT (hex)${stale ? "" : addressQrButtonHtml(hex, "Edited PSBT (hex)", { animate: "psbt" })}${privateCopyButtonHtml(copyIcon, { id: "psbted-copy-hex", disabled: stale, attribute: "data-psbt-result-copy" })}</p>
      <div class="psbted-result-value" id="psbted-result-hex" data-private-value data-i18n-skip translate="no" aria-labelledby="psbted-result-hex-label">${stale ? "" : escapeHtml(hex)}</div>
      <div class="row psbt-actions tool-actions">
        <button class="btn secondary" id="psbted-download" type="button"${gated}>Download Edited .psbt</button>
      </div>
`;
    if (stale) return;
    // Every handler re-checks stale: the keystroke path only disables these
    // buttons, and a synthetic dispatchEvent still fires a disabled button's
    // handlers, which close over the last valid build's bytes (issue #320).
    // The clipboard briefly becomes a checkmark after a successful copy.
    const confirmCopy = (id) => {
      const button = $(id);
      if (button) showCopiedIcon(button, { copyIcon: copyIcon(), copiedIcon: copiedIcon() });
    };
    $("psbted-copy-b64").onclick = () => {
      if (stale) return;
      copyText(b64).then((copied) => { if (copied) confirmCopy("psbted-copy-b64"); });
    };
    $("psbted-copy-hex").onclick = () => {
      if (stale) return;
      copyText(hex).then((copied) => { if (copied) confirmCopy("psbted-copy-hex"); });
    };
    // The binary download round-trips with wallet software: Sparrow and
    // Coldcard read the .psbt file this produces.
    $("psbted-download").onclick = () => {
      if (stale) return;
      const url = URL.createObjectURL(new Blob([resultBytes], { type: "application/octet-stream" }));
      const link = document.createElement("a");
      link.href = url;
      link.download = "edited.psbt";
      link.click();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    };
  };

  // Marks the intact result panel as the last valid build — used when a
  // keystroke left the fields in a state that does not build. The export
  // controls and QR are disabled and the byte text is blanked: stale bytes
  // must not cross an export boundary while the fields say something else,
  // and a disabled, readonly textarea's content is still selectable and
  // copyable in Firefox, so disabling alone is not a boundary (issue #320).
  const markResultStale = () => {
    // The status line is rendered by render(), which a stale keystroke never
    // reaches, so the red state is painted here instead of only in the template.
    const status = document.getElementById("psbted-status");
    if (status) {
      status.className = "edge-note is-private";
      status.textContent = "The fields do not build right now — see the error above; the result below is the last valid build.";
    }
    const box = document.getElementById("psbted-result");
    if (!box || !resultBytes) return;
    box.classList.add("psbted-stale");
    const note = document.getElementById("psbted-stale-note");
    if (note) note.textContent = "The fields do not build right now — this is the last valid build. Export is unavailable until they build again.";
    else box.insertAdjacentHTML("afterbegin", '<p class="psbted-note-warn" id="psbted-stale-note">The fields do not build right now — this is the last valid build. Export is unavailable until they build again.</p>');
    for (const id of ["psbted-copy-b64", "psbted-copy-hex", "psbted-download"]) {
      document.getElementById(id)?.setAttribute("disabled", "");
    }
    for (const id of ["psbted-result-b64", "psbted-result-hex"]) {
      const area = document.getElementById(id);
      if (area) {
        // The readout holds the bytes as node text; clearing value too keeps
        // the wipe complete if these ever go back to being fields.
        area.value = "";
        area.textContent = "";
      }
    }
    // The QR button carries the payload in a data attribute, so a stale build
    // must lose the button too — otherwise the old bytes stay both scannable
    // and present in the document (issue #320's boundary).
    for (const id of ["psbted-result-b64-label", "psbted-result-hex-label"]) {
      document.getElementById(id)?.querySelector("[data-address-qr]")?.remove();
    }
  };

  // The mempool.space-style connectors: a bezier from every input box into
  // the transaction box and from there out to every output box, drawn into
  // the diagram's (initially empty) SVG layer once the boxes have layout.
  const drawViz = () => {
    const viz = out.querySelector(".psbted-viz");
    const svg = viz?.querySelector(".psbted-viz-svg");
    if (!viz || !svg || !svg.clientWidth) return; // no diagram, or the stacked layout hides the layer
    const boxRect = viz.getBoundingClientRect();
    const txRect = viz.querySelector(".psbted-viz-tx").getBoundingClientRect();
    const origin = { x: boxRect.left, y: boxRect.top };
    const edge = (rect, side) => ({
      x: (side === "right" ? rect.right : rect.left) - origin.x,
      y: rect.top - origin.y + rect.height / 2,
    });
    const paths = [];
    const link = (from, to, cls) => {
      // Horizontal S-curve (the mempool.space flow look); the bend spans
      // half the gap so the line leaves and arrives level.
      const bend = Math.max(24, Math.abs(to.x - from.x) / 2);
      const d = `M ${from.x} ${from.y} C ${from.x + bend} ${from.y}, ${to.x - bend} ${to.y}, ${to.x} ${to.y}`;
      paths.push(`<path class="psbted-viz-line ${cls}" d="${d}"/>`);
    };
    const boxFor = (kind, index) => viz.querySelector(`[data-viz="${kind}:${index}"]`)?.closest(".psbted-viz-box");
    const txIn = edge(txRect, "left");
    doc.tx.inputs.slice(0, PSBT_RENDER_LIMIT).forEach((_, index) => {
      const rect = boxFor("input", index)?.getBoundingClientRect();
      if (rect) link(edge(rect, "right"), txIn, "psbted-viz-line-in");
    });
    const txOut = edge(txRect, "right");
    doc.tx.outputs.slice(0, PSBT_RENDER_LIMIT).forEach((_, index) => {
      const rect = boxFor("output", index)?.getBoundingClientRect();
      if (rect) link(txOut, edge(rect, "left"), "psbted-viz-line-out");
    });
    svg.setAttribute("viewBox", `0 0 ${boxRect.width} ${boxRect.height}`);
    svg.innerHTML = paths.join("");
  };
  window.addEventListener("resize", () => {
    if (doc) drawViz();
  });

  // Builds + re-inspects the working document. On success the editor is
  // re-rendered from rust-bitcoin's fresh decode; when the rebuild was
  // triggered by typing (restoreFocus), focus and the caret return to the
  // field being edited, so a successful keystroke never interrupts typing.
  const rebuild = ({ restoreFocus = false } = {}) => {
    const focus = restoreFocus ? captureFocus() : null;
    // An edit to anything a signature commits to — the transaction itself or
    // an input's UTXO declaration — invalidates every signature and final
    // script the maps carry: drop them before the rebuild so the result never
    // looks signed with stale material (issues #325, #360).
    if (pristineTx !== null && signingAnchor(doc) !== pristineTx) {
      dropSigningPairs(doc);
      pristineTx = null; // pairs and transaction agree again (or are gone)
    }
    const fresh = psbtBuildBytes(psbtEditorBuildDoc(doc), { insane });
    const decoded = psbtInspectDoc(fresh);
    doc = decoded;
    resultBytes = fresh;
    stale = false;
    pristineTx = signingAnchor(doc);
    setError("");
    render();
    renderResult();
    if (focus) restoreFocusState(focus);
  };

  // The live path for field edits: every keystroke attempts a rebuild. On
  // failure the working document and the rendered fields stay exactly as
  // they are (typing continues undisturbed), the error shows, and the last
  // valid build below is marked stale.
  const liveRebuild = () => {
    try {
      rebuild({ restoreFocus: true });
      return true;
    } catch (exception) {
      stale = resultBytes !== null;
      setError(exception.message || String(exception));
      markResultStale();
      return false;
    }
  };

  // Identifies the field being edited across a re-render: its id, its
  // pair-value coordinates, or its data-attribute, plus the caret.
  const captureFocus = () => {
    const el = document.activeElement;
    if (!el || !out.contains(el)) return null;
    let selector = null;
    if (el.id) selector = `#${el.id}`;
    else if (el.classList?.contains("psbted-value")) selector = `input[data-kind="${el.dataset.kind}"][data-map="${el.dataset.map}"][data-pair="${el.dataset.pair}"]`;
    else {
      for (const attr of ["data-txin", "data-txin-vout", "data-txin-seq", "data-txout-val", "data-txout-script", "data-build-script", "data-build-mode", "data-add-type", "data-add-key", "data-add-val"]) {
        const value = el.getAttribute?.(attr);
        if (value !== null && value !== undefined) {
          selector = `[${attr}="${value}"]`;
          break;
        }
      }
    }
    if (!selector) return null;
    // The output sats field exists twice per output — in the diagram box and
    // in the transaction table row — so a bare data-attribute selector is
    // ambiguous and querySelector would always return the diagram's field,
    // stealing focus mid-edit. Qualify a duplicated selector by the edited
    // element's classes.
    if (out.querySelectorAll(selector).length > 1) {
      const classes = [...el.classList];
      if (classes.length) selector = `${el.tagName.toLowerCase()}.${classes.join(".")}${selector}`;
    }
    return { selector, start: el.selectionStart, end: el.selectionEnd };
  };

  const restoreFocusState = (focus) => {
    const el = out.querySelector(focus.selector);
    if (!el) return;
    el.focus();
    try {
      // The rebuilt decode may have normalized the value (007 → 7); clamp
      // the caret into the new length.
      el.setSelectionRange(Math.min(focus.start, el.value.length), Math.min(focus.end, el.value.length));
    } catch {
      // Not a text input: focus alone is enough.
    }
  };

  const showBuildError = (exception) => {
    stale = resultBytes !== null;
    setError(exception.message || String(exception));
    renderResult(); // no valid build yet clears the box; otherwise it shows the last valid build as stale
  };

  const loadFromText = () => {
    journalLog("load-request", "editor-text", "psbt");
    setError("");
    clearCompareReport(); // a different editor PSBT invalidates an old report
    addedPairs.clear(); // a different document invalidates the add counts
    try {
      doc = psbtInspectDoc(psbtBytesFromText(text.value));
    } catch (exception) {
      doc = null;
      resultBytes = null;
      stale = false;
      pristineTx = null;
      render();
      setError(exception.message || String(exception));
      journalLog("load-error", "editor-text", "psbt");
      return;
    }
    resultBytes = null;
    stale = false;
    pristineTx = null; // the fresh document's pairs commit to its own transaction
    // The loaded PSBT builds at once, so the result text and QR appear
    // without an extra click.
    try {
      rebuild();
      journalLog("load", "editor-text", "psbt");
    } catch (exception) {
      render();
      showBuildError(exception);
      journalLog("load-error", "editor-text", "psbt");
    }
  };

  // Structural edits (add/remove pair) validate immediately: apply to a copy,
  // rebuild, and only keep the change when rust-bitcoin accepts the result.
  const mutate = (fn) => {
    const backup = doc, backupAnchor = pristineTx, wasStale = stale;
    const draft = structuredClone(doc);
    try {
      fn(draft);
      doc = draft;
      rebuild();
    } catch (exception) {
      // Roll back the whole pre-edit state, not just the document. rebuild()
      // cleared the signing anchor before its build failed, but the restored
      // document still carries its signing pairs — without the anchor the
      // next accepted transaction edit would keep pairs committing to the
      // pre-edit transaction (issues #325, #360). The restored fields are
      // exactly the last valid build (or the poison they already were), so
      // the rejection must not mark them stale either.
      doc = backup;
      pristineTx = backupAnchor;
      stale = wasStale;
      render();
      setError(exception.message || String(exception));
      renderResult();
    }
  };

  const bind = () => {
    // Transaction fields update the working document and rebuild on every
    // keystroke; a state that does not build keeps the fields as they are
    // (partial hex never loses focus mid-edit) and shows the error live.
    $("psbted-tx-version").addEventListener("input", (event) => {
      doc.tx.version = event.target.value.trim();
      liveRebuild();
    });
    $("psbted-tx-locktime").addEventListener("input", (event) => {
      doc.tx.locktime = event.target.value.trim();
      liveRebuild();
    });
    out.querySelectorAll("[data-txin]").forEach((input) =>
      input.addEventListener("input", () => {
        doc.tx.inputs[Number(input.dataset.txin)].txid = input.value.trim();
        liveRebuild();
      })
    );
    out.querySelectorAll("[data-txin-vout]").forEach((input) =>
      input.addEventListener("input", () => {
        doc.tx.inputs[Number(input.dataset.txinVout)].vout = input.value.trim();
        liveRebuild();
      })
    );
    out.querySelectorAll("[data-txin-seq]").forEach((input) =>
      input.addEventListener("input", () => {
        doc.tx.inputs[Number(input.dataset.txinSeq)].sequence = input.value.trim();
        liveRebuild();
      })
    );
    out.querySelectorAll("[data-txout-val]").forEach((input) =>
      input.addEventListener("input", () => {
        doc.tx.outputs[Number(input.dataset.txoutVal)].value = input.value.trim();
        liveRebuild();
      })
    );
    out.querySelectorAll("[data-txout-script]").forEach((input) =>
      input.addEventListener("input", () => {
        doc.tx.outputs[Number(input.dataset.txoutScript)].scriptPubKey = input.value.trim();
        liveRebuild();
      })
    );

    // Structural edits to the transaction itself: an added input/output gets
    // its (empty) key-value map at the same index, so the document the WASM
    // checks always has one map per tx element. Like pair add/remove, the
    // change round-trips through rust-bitcoin immediately; on rejection the
    // working document is kept. The detail panel closes because box indices
    // may shift.
    out.querySelectorAll("[data-tx-add]").forEach((button) =>
      button.addEventListener("click", () => {
        setError("");
        const kind = button.dataset.txAdd;
        const before = doc;
        mutate((draft) => {
          if (kind === "input") {
            draft.tx.inputs.push({ txid: "0".repeat(64), vout: 0, scriptSig: "", sequence: 4294967295 });
            draft.inputs.push([]);
          } else {
            draft.tx.outputs.push({ value: "0", scriptPubKey: "" });
            draft.outputs.push([]);
          }
        });
        // In an over-cap list the add landed past the rendered rows: count
        // it like an added pair so its table row and map section render
        // after the capped ones (red-team F7 round 6). mutate already
        // re-rendered from the stale counts, so render again — the same
        // re-render the Add Pair handler does.
        if (doc !== before) {
          addedPairs.set(`tx:${kind}`, (addedPairs.get(`tx:${kind}`) || 0) + 1);
          render();
          renderResult();
        }
      })
    );
    out.querySelectorAll("[data-txin-del]").forEach((button) =>
      button.addEventListener("click", () => {
        const index = Number(button.dataset.txinDel);
        const before = doc;
        mutate((draft) => {
          draft.tx.inputs.splice(index, 1);
          draft.inputs.splice(index, 1);
        });
        // An accepted delete shifted every later input map down one index:
        // re-key the added-pair counts so each stays on its map, and
        // re-render — mutate's render used the stale keys. A rejected delete
        // restored the document, so the keys still match.
        if (doc !== before) {
          shiftAddedPairs("input", index);
          render();
          renderResult();
        }
      })
    );
    out.querySelectorAll("[data-txout-del]").forEach((button) =>
      button.addEventListener("click", () => {
        const index = Number(button.dataset.txoutDel);
        const before = doc;
        mutate((draft) => {
          draft.tx.outputs.splice(index, 1);
          draft.outputs.splice(index, 1);
        });
        // Same re-key for the output maps.
        if (doc !== before) {
          shiftAddedPairs("output", index);
          render();
          renderResult();
        }
      })
    );

    // The output-script builder writes its result into the output's
    // scriptPubKey field — exactly as if the user had typed the hex — and
    // the live rebuild validates it on the spot. Builder errors (bad
    // address, unknown ASM token) show inline.
    const applyBuiltScript = (index) => {
      journalLog("editor-set-request", "output-script", "psbt");
      const text = out.querySelector(`[data-build-script="${index}"]`)?.value ?? "";
      const mode = out.querySelector(`[data-build-mode="${index}"]`)?.value ?? "auto";
      try {
        const built = buildOutputScript(text, { network: network(), mode });
        doc.tx.outputs[Number(index)].scriptPubKey = built.scriptHex;
        journalLog(liveRebuild() ? "editor-set" : "editor-set-error", "output-script", "psbt");
      } catch (exception) {
        setError(exception.message || String(exception));
        journalLog("editor-set-error", "output-script", "psbt");
      }
    };
    out.querySelectorAll("[data-build-apply]").forEach((button) => button.addEventListener("click", () => applyBuiltScript(button.dataset.buildApply)));
    out.querySelectorAll("[data-build-script]").forEach((input) =>
      input.addEventListener("keydown", (event) => {
        if (event.key === "Enter") {
          event.preventDefault();
          applyBuiltScript(input.dataset.buildScript);
        }
      })
    );

    // Flow-diagram boxes are links into the sections below: the fields never
    // move, the section is scrolled to, focused, and briefly highlighted so
    // the eye lands on the part the box named.
    out.querySelectorAll("[data-viz]").forEach((button) =>
      button.addEventListener("click", () => {
        const section = out.querySelector(`[data-psbted-section="${button.dataset.viz}"]`);
        if (!section) return;
        clearTimeout(anchorTimer);
        out.querySelectorAll(".is-anchored").forEach((el) => el.classList.remove("is-anchored"));
        section.scrollIntoView({ behavior: "smooth", block: "start" });
        section.classList.add("is-anchored");
        section.focus({ preventScroll: true });
        anchorTimer = setTimeout(() => section.classList.remove("is-anchored"), 2400);
      })
    );

    out.querySelectorAll(".psbted-value").forEach((input) =>
      input.addEventListener("input", () => {
        const { kind, map, pair } = input.dataset;
        (kind === "global" ? doc.globals : kind === "input" ? doc.inputs[map] : doc.outputs[map])[Number(pair)].value = input.value.trim();
        liveRebuild();
      })
    );
    // Pair-delete buttons only: the tx-element deletes and the diagram close
    // button share the psbted-del styling class but carry no data-kind and
    // have their own handlers — binding them here double-fires a pair delete
    // with no kind (a TypeError surfaces as a spurious error banner and the
    // fresh build is falsely marked stale).
    out.querySelectorAll(".psbted-del[data-kind]").forEach((button) =>
      button.addEventListener("click", () => {
        const { kind, map, pair } = button.dataset;
        mutate((draft) => {
          const target = kind === "global" ? draft.globals : kind === "input" ? draft.inputs[map] : draft.outputs[map];
          target.splice(Number(pair), 1);
        });
      })
    );
    out.querySelectorAll("[data-add]").forEach((button) =>
      button.addEventListener("click", () => {
        const [kind, map] = button.dataset.add.split(":");
        const type = out.querySelector(`[data-add-type="${kind}:${map}"]`).value.trim().toLowerCase();
        const keydata = out.querySelector(`[data-add-key="${kind}:${map}"]`).value.trim().toLowerCase();
        const value = out.querySelector(`[data-add-val="${kind}:${map}"]`).value.trim().toLowerCase();
        setError("");
        // For a known type the key is type byte + keydata; for "Custom
        // type…" the keydata field carries the full key (type byte first).
        const key = type === "" ? keydata : type + keydata;
        if (!isHex(key) || key.length < 2) {
          setError(type === ""
            ? "Enter the full key (one type byte plus keydata) as hex."
            : "Keydata must be hex (an even number of 0-9/a-f digits).");
          return;
        }
        if (!isHex(value)) {
          setError("Value must be hex (an even number of 0-9/a-f digits).");
          return;
        }
        const before = doc;
        mutate((draft) => {
          const target = kind === "global" ? draft.globals : kind === "input" ? draft.inputs[map] : draft.outputs[map];
          target.push({ key, value });
        });
        // mutate keeps the change only when rust-bitcoin accepted it (the
        // working document is replaced on success, restored on failure). In
        // an over-cap map the add landed past the rendered rows: count it so
        // pairRows renders it after the capped rows, and re-render to show it.
        if (doc !== before) {
          addedPairs.set(`${kind}:${map}`, (addedPairs.get(`${kind}:${map}`) || 0) + 1);
          render();
          renderResult();
        }
      })
    );

    drawViz(); // the boxes exist now; draw the connectors over the layout
  };

  load.onclick = () => {
    psbtWasmReady.then(loadFromText).catch((exception) => setError(exception.message || String(exception)));
  };
  // Insane editing (checkbox above the editor output): flips the build
  // policy for the current fields. Toggling re-runs the build — turning it
  // off can revoke a build that only passed insanely (the fields then show
  // the consensus layer's rejection), turning it on rescues one.
  $("psbted-insane")?.addEventListener("change", (event) => {
    insane = event.target.checked;
    if (doc) liveRebuild();
  });
  // File upload is a second load path for the same loader: Sparrow & co. save
  // the PSBT as raw binary; a text export decodes through the paste rules.
  // The textarea mirrors the upload (as base64) so the loaded bytes and the
  // "edited PSBT" reload path stay visible.
  const file = $("psbted-file");
  $("psbted-upload").onclick = () => file.click();
  file.addEventListener("change", () => {
    const chosen = file.files?.[0];
    file.value = ""; // picking the same file again must fire change again
    if (!chosen) return;
    psbtWasmReady
      .then(async () => {
        text.value = base64Encode(psbtBytesFromUpload(new Uint8Array(await chosen.arrayBuffer())));
        syncActions();
        loadFromText();
      })
      .catch((exception) => setError(exception.message || String(exception)));
  });
  // Semantic comparison against a second, pasted PSBT (engine: psbt-diff.js).
  // The compare section lives outside #psbted-out, so the editor's live
  // re-renders never touch the pasted text or the report.
  const compareText = $("psbted-compare-text"), compareOut = $("psbted-compare-out"), compareError = $("psbted-compare-error");
  const setCompareError = (message) => {
    compareError.textContent = message || "";
  };
  const clearCompareReport = () => {
    compareOut.innerHTML = "";
    setCompareError("");
  };
  $("psbted-wipe").onclick = () => {
    doc = null;
    addedPairs.clear();
    resultBytes = null;
    stale = false;
    pristineTx = null;
    text.value = "";
    setError("");
    compareText.value = "";
    clearCompareReport();
    render();
    // The overlays live outside this panel; a wipe must release what they
    // still show (a PSBT's proprietary fields can carry an xprv).
    document.dispatchEvent(new Event("hodl:conceal"));
  };
  $("psbted-compare-go").addEventListener("click", () => {
    psbtWasmReady
      .then(() => {
        clearCompareReport();
        if (!doc) return; // Compare is disabled until a PSBT is loaded
        let beforeDoc;
        try {
          // Both sides are compared as rust-bitcoin decodes of accepted
          // PSBTs. The working document is rebuilt first so mid-edit field
          // text (an amount field holds a string while typed) cannot fake a
          // difference; a state that does not build refuses to compare
          // instead of guessing. The insane-editing policy applies here too:
          // a document the editor is holding insanely compares as it builds.
          beforeDoc = psbtInspectDoc(psbtBuildBytes(psbtEditorBuildDoc(doc), { insane }));
        } catch (exception) {
          setCompareError(`The editor fields do not build right now: ${exception.message || exception}`);
          return;
        }
        let afterDoc;
        try {
          afterDoc = psbtInspectDoc(psbtBytesFromText(compareText.value));
        } catch (exception) {
          setCompareError(exception.message || String(exception));
          return;
        }
        compareOut.innerHTML = `${psbtDiffHtml(comparePsbtDocs(beforeDoc, afterDoc), beforeDoc, afterDoc, network(), { copyIcon })}
        <footer class="psbted-sanitize-compare">${psbtSanitizeHtml(beforeDoc, "Editor PSBT")}${psbtSanitizeHtml(afterDoc, "Pasted PSBT")}</footer>`;
      })
      .catch((exception) => setCompareError(exception.message || String(exception)));
  });
  $("psbted-compare-clear").addEventListener("click", () => {
    compareText.value = "";
    clearCompareReport();
    syncActions();
  });
  text.addEventListener("input", syncActions);
  compareText.addEventListener("input", syncActions);
  syncActions();
  // The header network picker broadcasts its choice; re-decode addresses.
  document.addEventListener("hodl:network-default", () => {
    if (doc) {
      render();
      renderResult();
    }
  });
};
