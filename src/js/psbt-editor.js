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
import { Address as BtcAddress, NETWORK as BTC_MAINNET, TEST_NETWORK as BTC_TESTNET, OutScript } from "@scure/btc-signer";
import { renderSVG as renderQrSvg } from "uqr";
import { psbtInspectDoc, psbtBuildBytes, psbtWasmReady } from "./psbt-wasm.js";
import { comparePsbtDocs } from "./psbt-diff.js";
import { expandableHtml, EXPAND_LIMIT, initExpandable } from "./expandable.js";
import { psbtVizHtml } from "./psbt-viz.js";
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
  if (!value) throw new Error("Paste a PSBT v0.");
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
// sequence (BCR-2020-005 — Sparrow, SeedSigner and Coldcard Q scan those).
// The UR fragments are uppercased so the QR encodes in the denser
// alphanumeric mode; UR parsing lowercases before decoding.
export const PSBT_QR_STATIC_MAX_BYTES = 800;
export const psbtQrPlan = (bytes) => {
  if (bytes.length <= PSBT_QR_STATIC_MAX_BYTES) return { mode: "static", text: base64Encode(bytes) };
  return { mode: "ur", parts: hodlUrEncodePsbt(bytes, { maxBytes: 200 }).map((part) => part.toUpperCase()) };
};

const QR_OPTIONS = { ecc: "M", border: 4, pixelSize: 4, blackColor: "#111111", whiteColor: "#ffffff" };

const escapeHtml = (text) =>
  String(text).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");

const shorten = (hex, head = 10, tail = 6) => {
  const text = String(hex ?? "");
  return text.length > head + tail + 2 ? text.slice(0, head) + "…" + text.slice(-tail) : text;
};

const addressFor = (scriptHex, network) => {
  try {
    return BtcAddress(network === "testnet" ? BTC_TESTNET : BTC_MAINNET).encode(OutScript.decode(hexToBytes(scriptHex)));
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
    parts.push(text !== null ? `“${text.length > 80 ? `${text.slice(0, 80)}…` : text}”` : `hex ${bytesToHex(parsed.payload.slice(0, 40))}${parsed.payloadBytes > 40 ? "…" : ""}`);
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
      return { text: `prefix ${d.prefixText ? JSON.stringify(d.prefixText) : d.prefix} · subtype ${d.subtype}${d.keydata ? ` · keydata ${shorten(d.keydata)}` : ""}`, tone: "" };
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
const scriptCell = (scriptHex, asm, network) => {
  const text = addressFor(scriptHex, network) || opReturnSummary(scriptHex)?.text || asm || String(scriptHex ?? "");
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
const txDiffRows = (changes, before, after, network) =>
  changes
    .filter((change) => change.category === "transaction")
    .map((change) => {
      if (!change.field) {
        const element = change.kind === "added" ? change.after : change.before;
        const cell =
          change.scope === "input"
            ? `<span class="psbted-hex">${expandableHtml(String(element.txid), { label: `Input ${change.index} previous txid` })}</span> : ${escapeHtml(String(element.vout))}`
            : `${escapeHtml(formatSats(element.value))}<br>${scriptCell(element.scriptPubKey, element.asm, network)}`;
        return diffRow(change, escapeHtml(`${capitalize(change.scope)} ${change.index}`), change.kind === "added" ? emDash : cell, change.kind === "added" ? cell : emDash);
      }
      const name = change.field.split(".").pop();
      const label = change.scope === "transaction" ? capitalize(name) : `${capitalize(change.scope)} ${change.index} · ${{ txid: "previous txid", vout: "prevout index", value: "value", scriptPubKey: "scriptPubKey" }[name] || name}`;
      const side = (value, doc) => {
        if (name === "value") return escapeHtml(formatSats(value));
        if (name === "scriptPubKey") return scriptCell(value, doc?.tx?.outputs?.[change.index]?.asm, network);
        if (name === "txid") return `<span class="psbted-hex">${expandableHtml(String(value), { label })}</span>`;
        return escapeHtml(String(value ?? ""));
      };
      return diffRow(change, escapeHtml(label), side(change.before, before), side(change.after, after));
    });

// One key-value pair cell of a map diff: the typed one-line decode when the
// pair has one, otherwise (or when undecodable) the raw value hex — the same
// two presentations the editor's pair tables use.
const pairCell = (pair, network) => {
  if (!pair) return emDash;
  const name = pair.name || "pair";
  const note = describePair(pair, network);
  const parts = [];
  if (note.text) parts.push(`<span${note.tone ? ` class="psbted-note-${note.tone}"` : ""}>${expandableHtml(note.text, { label: `${name} — decoded` })}</span>`);
  if (!pair.decoded || !note.text) parts.push(`<span class="psbted-hex">${expandableHtml(pair.value, { label: `${name} — value (hex)` })}</span>`);
  return parts.join("<br>");
};

const mapDiffRows = (changes, scope, index, before, after, network) =>
  changes
    .filter((change) => change.scope === scope && change.index === index)
    .map((change) => {
      const mapOf = (doc) => (scope === "global" ? doc.globals : scope === "input-map" ? doc.inputs?.[index] : doc.outputs?.[index]) || [];
      const beforePair = mapOf(before).find((pair) => pair.key === change.key) || null;
      const afterPair = mapOf(after).find((pair) => pair.key === change.key) || null;
      const field = change.name ? `<span class="psbted-hex">${escapeHtml(change.name)}</span>` : escapeHtml(`Unknown pair (type 0x${change.key.slice(0, 2)})`);
      return diffRow(change, field, pairCell(beforePair, network), pairCell(afterPair, network));
    });

export const psbtDiffHtml = (diff, before, after, network) => {
  if (diff.equal) return `<p class="psbted-note-ok">Semantically identical — the underlying transaction, the signing state, and the metadata all match.</p>`;
  const summary = [
    diff.transactionChanged
      ? `<p class="psbted-note-bad">✕ The underlying transaction changed — review every input and output before using either PSBT.</p>`
      : `<p class="psbted-note-ok">✓ The underlying transaction is unchanged.</p>`,
    diff.signingChanged
      ? `<p class="psbted-note-warn">⚠ Signing state changed (signatures, sighash types, final scripts).</p>`
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
  const txRows = txDiffRows(diff.changes, before, after, network);
  if (txRows.length) sections.push(`<section class="psbted-map"><h3>Transaction</h3>${diffTable(txRows)}</section>`);
  const mapSections = (scope, title) => {
    const indexes = [...new Set(diff.changes.filter((change) => change.scope === scope).map((change) => change.index))].sort((a, b) => a - b);
    for (const index of indexes) {
      const rows = mapDiffRows(diff.changes, scope, index, before, after, network);
      if (rows.length) sections.push(`<section class="psbted-map"><h3>${title} ${index} key-value map</h3>${diffTable(rows)}</section>`);
    }
  };
  mapSections("input-map", "Input");
  mapSections("output-map", "Output");
  const globalRows = mapDiffRows(diff.changes, "global", null, before, after, network);
  if (globalRows.length) sections.push(`<section class="psbted-map"><h3>Global key-value map</h3>${diffTable(globalRows)}</section>`);

  return `<p class="muted">before = the PSBT in the editor · after = the pasted PSBT. Only differences are listed.</p>${summary.join("")}${sections.join("")}`;
};

// The editor has no network control of its own: addresses decode against the
// header network picker's choice, read through the `networkDefault` getter
// (mainnet/testnet), and re-decoded live when the picker changes it (the
// "hodl:network-default" document event).
export const initPsbtEditor = ({ networkDefault = () => "mainnet" } = {}) => {
  const load = document.getElementById("psbted-load");
  if (!load) return;
  const $ = (id) => document.getElementById(id);
  const out = $("psbted-out"), error = $("psbted-error"), text = $("psbted-text");
  const network = networkDefault;

  let doc = null; // inspect document being edited; null when nothing is loaded
  let resultBytes = null; // last successfully built PSBT
  let stale = false; // true while the current fields do not build; resultBytes is then the last valid build
  let qrTimer = null; // animation timer of the UR fragment QR, when running
  // Which flow-diagram part is open ({ kind: "input"|"output", index } for a
  // box or { kind: "tx" } for the middle transaction box); its fields render
  // in the panel under the diagram instead of inline.
  let selected = null;

  initExpandable();
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

  const pairRows = (kind, map, mapIndex) => {
    const rows = map
      .map((pair, pairIndex) => {
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
        return `<tr>
          <td class="psbted-name">${escapeHtml(pair.name || "Unvalidated pair")}<br><span class="muted">type 0x${escapeHtml(pair.key.slice(0, 2))}</span></td>
          <td class="psbted-hex">${expandableHtml(pair.key, { label: `Key bytes for ${name} (hex)` })}</td>
          <td>${locked ? `<span class="muted">managed by the transaction section</span>` : valueCell}</td>
          <td${tone}>${expandableHtml(note.text, { label: `${name} — decoded` })}</td>
          <td>${locked ? "" : `<button type="button" class="psbted-del" data-kind="${kind}" data-map="${mapIndex}" data-pair="${pairIndex}" aria-label="Delete ${escapeHtml(pair.name || "pair")}">×</button>`}</td>
        </tr>`;
      })
      .join("");
    const options = PAIR_TYPES[kind]
      .map(([type, name, hint]) => `<option value="${type}" title="keydata: ${escapeHtml(hint)}">${name}</option>`)
      .join("");
    return `<table class="psbted-pairs psbted-kv">
      <thead><tr><th class="psbted-col-field">Field</th><th>Key (hex)</th><th>Value (hex)</th><th>Decoded</th><th class="psbted-col-del"></th></tr></thead>
      <tbody>${rows || `<tr><td colspan="5" class="muted">No pairs in this map.</td></tr>`}</tbody>
    </table>
    <div class="psbted-add">
      <select data-add-type="${kind}:${mapIndex}" aria-label="New pair type">${options}<option value="" title="keydata field takes the full key: one type byte, then keydata">Custom type…</option></select>
      <input data-add-key="${kind}:${mapIndex}" placeholder="keydata (hex)" spellcheck="false" autocomplete="off" autocapitalize="off" aria-label="New pair keydata (hex)">
      <input data-add-val="${kind}:${mapIndex}" placeholder="value (hex)" spellcheck="false" autocomplete="off" autocapitalize="off" aria-label="New pair value (hex)">
      <button type="button" class="btn secondary" data-add="${kind}:${mapIndex}">Add pair</button>
    </div>`;
  };

  const render = () => {
    // The result box is recreated here, so any running QR animation dies
    // with it; renderResult restarts it for the current build.
    clearInterval(qrTimer);
    qrTimer = null;
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
      : "unknown — some inputs carry no claimed previous-output amount";
    const verdict = doc.rustBitcoinError
      ? `<span class="psbted-note-warn">rust-bitcoin reports: ${escapeHtml(doc.rustBitcoinError)}</span>`
      : `<span class="psbted-note-ok">parses under rust-bitcoin</span>`;

    // The last remaining input carries no delete control: a zero-input
    // unsigned transaction cannot round-trip through BIP-174 serialization,
    // so rust-bitcoin would reject the rebuild.
    const inputRows = tx.inputs
      .map(
        (input, index) => `<tr>
          <td>${index}</td>
          <td><input class="psbted-txid" data-txin="${index}" value="${escapeHtml(input.txid)}" spellcheck="false" autocomplete="off" autocapitalize="off" aria-label="Input ${index} previous txid (hex)"></td>
          <td><input class="psbted-num" data-txin-vout="${index}" value="${escapeHtml(String(input.vout))}" inputmode="numeric" aria-label="Input ${index} prevout index"></td>
          <td><input class="psbted-num" data-txin-seq="${index}" value="${escapeHtml(String(input.sequence))}" inputmode="numeric" aria-label="Input ${index} sequence"></td>
          <td>${tx.inputs.length > 1 ? `<button type="button" class="psbted-del" data-txin-del="${index}" aria-label="Delete input ${index}">×</button>` : ""}</td>
        </tr>`
      )
      .join("");
    const outputRows = tx.outputs
      .map((output, index) => {
        const addr = addressFor(output.scriptPubKey, network());
        const opret = addr ? null : opReturnSummary(output.scriptPubKey, output.value);
        return `<tr>
          <td>${index}</td>
          <td><input class="psbted-num" data-txout-val="${index}" value="${escapeHtml(String(output.value))}" inputmode="numeric" aria-label="Output ${index} value in sats"></td>
          <td><input class="psbted-txid" data-txout-script="${index}" value="${escapeHtml(output.scriptPubKey)}" spellcheck="false" autocomplete="off" autocapitalize="off" aria-label="Output ${index} scriptPubKey (hex)">
            <span class="${opret?.burn ? "psbted-note-warn" : "muted"} psbted-addr">${escapeHtml(addr || opret?.text || output.asm || "")}</span>
            <span class="psbted-build"><input data-build-script="${index}" placeholder="address · OP_… ASM · 0x raw hex · text" spellcheck="false" autocomplete="off" autocapitalize="off" aria-label="Build output ${index} scriptPubKey from an address, ASM, or OP_RETURN text"><select data-build-mode="${index}" aria-label="Output ${index} script builder mode"><option value="auto" selected>Auto-detect</option><option value="opreturn-text">OP_RETURN text</option><option value="opreturn-hex">OP_RETURN hex</option><option value="asm">Script ASM</option></select><button type="button" class="btn secondary" data-build-apply="${index}">Set script</button></span></td>
          <td><button type="button" class="psbted-del" data-txout-del="${index}" aria-label="Delete output ${index}">×</button></td>
        </tr>`;
      })
      .join("");

    // One map section, rendered either inline (the default) or inside the
    // flow diagram's detail panel when its box is selected there.
    const mapSection = (kind, index) => {
      const map = kind === "input" ? doc.inputs[index] : doc.outputs[index];
      const sub =
        kind === "input"
          ? `Spends ${escapeHtml(tx.inputs[index].txid)}:${escapeHtml(String(tx.inputs[index].vout))}`
          : `Pays ${escapeHtml(String(tx.outputs[index].value))} sats${addressFor(tx.outputs[index].scriptPubKey, network()) ? ` to ${escapeHtml(addressFor(tx.outputs[index].scriptPubKey, network()))}` : ""}`;
      return `<section class="psbted-map"><h3>${kind === "input" ? "Input" : "Output"} ${index} key-value map</h3><p class="muted">${sub}</p>${pairRows(kind, map, index)}</section>`;
    };
    // The unsigned-transaction section, rendered either inline (the default)
    // or inside the detail panel when the diagram's transaction box is open.
    const txSection = () => `<section class="psbted-map"><h3>Unsigned transaction</h3>
        <div class="psbted-txhead">
          <label>Version <input class="psbted-num" id="psbted-tx-version" value="${escapeHtml(String(tx.version))}" inputmode="numeric"></label>
          <label>Locktime <input class="psbted-num" id="psbted-tx-locktime" value="${escapeHtml(String(tx.locktime))}" inputmode="numeric"></label>
        </div>
        <table class="psbted-pairs psbted-txins"><thead><tr><th class="psbted-idx">#</th><th>Previous txid</th><th class="psbted-col-vout">vout</th><th class="psbted-col-seq">sequence</th><th class="psbted-col-del"></th></tr></thead><tbody>${inputRows}</tbody></table>
        <div class="psbted-add-el"><button type="button" class="btn secondary" data-tx-add="input">Add input</button></div>
        <table class="psbted-pairs psbted-txouts"><thead><tr><th class="psbted-idx">#</th><th class="psbted-col-val">Value (sats)</th><th>scriptPubKey</th><th class="psbted-col-del"></th></tr></thead><tbody>${outputRows}</tbody></table>
        <div class="psbted-add-el"><button type="button" class="btn secondary" data-tx-add="output">Add output</button></div>
      </section>`;
    const isSelected = (kind, index) => selected && selected.kind === kind && (kind === "tx" || selected.index === index);
    const inputSections = doc.inputs.map((_, index) => (isSelected("input", index) ? "" : mapSection("input", index))).join("");
    const outputSections = doc.outputs.map((_, index) => (isSelected("output", index) ? "" : mapSection("output", index))).join("");
    const detail = selected
      ? `<div class="psbted-viz-detail" id="psbted-viz-detail">
          <div class="psbted-viz-detail-bar">
            <p class="muted">Fields of ${selected.kind === "tx" ? "the unsigned transaction" : `${selected.kind} ${selected.index}`}, moved here from below. Activate its box again (or ×) to put them back.</p>
            <button type="button" class="psbted-del" data-viz-close aria-label="Close the ${selected.kind === "tx" ? "unsigned transaction" : `${selected.kind} ${selected.index}`} fields">×</button>
          </div>
          ${selected.kind === "tx" ? txSection() : mapSection(selected.kind, selected.index)}
        </div>`
      : "";

    out.innerHTML = `
      <p class="psbt-kv"><strong>PSBT v${escapeHtml(String(doc.psbtVersion))}</strong> · ${tx.inputs.length} input(s) · ${tx.outputs.length} output(s) · fee ${fee} · ${verdict}</p>
      <p class="muted" id="psbted-status" aria-live="polite">${stale ? "The fields do not build right now — see the error above; the result below is the last valid build." : "Every edit rebuilds the PSBT immediately; the fields show rust-bitcoin's decode of the current build."}</p>

      ${psbtVizHtml(doc, network(), selected)}
      ${detail}

      ${isSelected("tx") ? "" : txSection()}

      <section class="psbted-map"><h3>Global key-value map</h3>${pairRows("global", doc.globals, 0)}</section>
      ${inputSections}
      ${outputSections}

      <div id="psbted-result"></div>`;

    bind();
  };

  const renderResult = () => {
    const box = document.getElementById("psbted-result");
    if (!box) return;
    clearInterval(qrTimer);
    qrTimer = null;
    if (!resultBytes) {
      box.innerHTML = "";
      return;
    }
    const b64 = base64Encode(resultBytes);
    const hex = bytesToHex(resultBytes);
    box.classList.toggle("psbted-stale", stale);
    box.innerHTML = `
      ${stale ? `<p class="psbted-note-warn" id="psbted-stale-note">The fields do not build right now — this is the last valid build.</p>` : ""}
      <p class="psbt-ok">Rebuilt PSBT is accepted by rust-bitcoin (${resultBytes.length} bytes).</p>
      <label class="field">Edited PSBT (base64)<textarea id="psbted-result-b64" readonly spellcheck="false">${escapeHtml(b64)}</textarea></label>
      <div class="row psbt-actions">
        <button class="btn secondary" id="psbted-copy-b64" type="button">Copy base64</button>
        <button class="btn secondary" id="psbted-copy-hex" type="button">Copy hex</button>
        <button class="btn secondary" id="psbted-download" type="button">Download .psbt</button>
        <button class="btn secondary" id="psbted-reload" type="button">Load edited PSBT into the editor</button>
      </div>
      <label class="field">Edited PSBT (hex)<textarea id="psbted-result-hex" readonly spellcheck="false">${escapeHtml(hex)}</textarea></label>
      <div class="psbted-qr-block">
        <div class="qr psbted-qr" id="psbted-qr-code"></div>
        <p class="muted" id="psbted-qr-note"></p>
      </div>`;
    $("psbted-copy-b64").onclick = () => navigator.clipboard?.writeText(b64).catch(() => {});
    $("psbted-copy-hex").onclick = () => navigator.clipboard?.writeText(hex).catch(() => {});
    $("psbted-reload").onclick = () => {
      text.value = b64;
      loadFromText();
    };
    // The binary download round-trips with wallet software: Sparrow and
    // Coldcard read the .psbt file this produces.
    $("psbted-download").onclick = () => {
      const url = URL.createObjectURL(new Blob([resultBytes], { type: "application/octet-stream" }));
      const link = document.createElement("a");
      link.href = url;
      link.download = "edited.psbt";
      link.click();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    };
    setupQr();
  };

  // The QR under the result: one static code for small PSBTs, an animated
  // ur:crypto-psbt sequence (cycled here) for larger ones.
  const setupQr = () => {
    const target = document.getElementById("psbted-qr-code");
    const note = document.getElementById("psbted-qr-note");
    if (!target || !note || !resultBytes) return;
    const plan = psbtQrPlan(resultBytes);
    if (plan.mode === "static") {
      target.innerHTML = renderQrSvg(plan.text, QR_OPTIONS);
      target.setAttribute("aria-label", "Edited PSBT as a base64 QR code");
      note.textContent = "Static QR: the edited PSBT as base64.";
      return;
    }
    let frame = 0;
    const draw = () => {
      target.innerHTML = renderQrSvg(plan.parts[frame], QR_OPTIONS);
      note.textContent = `Animated UR crypto-psbt · part ${frame + 1} of ${plan.parts.length} — Sparrow, SeedSigner and Coldcard Q scan these.`;
      frame = (frame + 1) % plan.parts.length;
    };
    target.setAttribute("aria-label", "Edited PSBT as an animated UR crypto-psbt QR sequence");
    draw();
    qrTimer = setInterval(draw, 600);
  };

  // Marks the intact result panel as the last valid build — used when a
  // keystroke left the fields in a state that does not build, so the QR and
  // text of the last good build stay visible instead of vanishing.
  const markResultStale = () => {
    const box = document.getElementById("psbted-result");
    if (!box || !resultBytes) return;
    box.classList.add("psbted-stale");
    if (!document.getElementById("psbted-stale-note"))
      box.insertAdjacentHTML("afterbegin", '<p class="psbted-note-warn" id="psbted-stale-note">The fields do not build right now — this is the last valid build.</p>');
  };

  // The mempool.space-style connectors: a bezier from every input box into
  // the transaction box and from there out to every output box, drawn into
  // the diagram's (initially empty) SVG layer once the boxes have layout.
  // The selected box's line comes to the front, like its accent border.
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
    const link = (from, to, cls, open) => {
      // Horizontal S-curve (the mempool.space flow look); the bend spans
      // half the gap so the line leaves and arrives level.
      const bend = Math.max(24, Math.abs(to.x - from.x) / 2);
      const d = `M ${from.x} ${from.y} C ${from.x + bend} ${from.y}, ${to.x - bend} ${to.y}, ${to.x} ${to.y}`;
      paths.push(`<path class="psbted-viz-line ${cls}${open ? " is-open" : ""}" d="${d}"/>`);
    };
    const boxFor = (kind, index) => viz.querySelector(`[data-viz="${kind}:${index}"]`)?.closest(".psbted-viz-box");
    const txIn = edge(txRect, "left");
    doc.tx.inputs.forEach((_, index) => {
      const rect = boxFor("input", index)?.getBoundingClientRect();
      if (rect) link(edge(rect, "right"), txIn, "psbted-viz-line-in", selected?.kind === "input" && selected.index === index);
    });
    const txOut = edge(txRect, "right");
    doc.tx.outputs.forEach((_, index) => {
      const rect = boxFor("output", index)?.getBoundingClientRect();
      if (rect) link(txOut, edge(rect, "left"), "psbted-viz-line-out", selected?.kind === "output" && selected.index === index);
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
    const fresh = psbtBuildBytes(psbtEditorBuildDoc(doc));
    const decoded = psbtInspectDoc(fresh);
    doc = decoded;
    resultBytes = fresh;
    stale = false;
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
    } catch (exception) {
      stale = resultBytes !== null;
      setError(exception.message || String(exception));
      markResultStale();
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
    setError("");
    selected = null;
    clearCompareReport(); // a different editor PSBT invalidates an old report
    try {
      doc = psbtInspectDoc(psbtBytesFromText(text.value));
    } catch (exception) {
      doc = null;
      resultBytes = null;
      stale = false;
      render();
      setError(exception.message || String(exception));
      return;
    }
    resultBytes = null;
    stale = false;
    // The loaded PSBT builds at once, so the result text and QR appear
    // without an extra click.
    try {
      rebuild();
    } catch (exception) {
      render();
      showBuildError(exception);
    }
  };

  // Structural edits (add/remove pair) validate immediately: apply to a copy,
  // rebuild, and only keep the change when rust-bitcoin accepts the result.
  const mutate = (fn) => {
    const backup = doc;
    const draft = structuredClone(doc);
    try {
      fn(draft);
      doc = draft;
      rebuild();
    } catch (exception) {
      doc = backup;
      render();
      showBuildError(exception);
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
        selected = null;
        mutate((draft) => {
          if (button.dataset.txAdd === "input") {
            draft.tx.inputs.push({ txid: "0".repeat(64), vout: 0, scriptSig: "", sequence: 4294967295 });
            draft.inputs.push([]);
          } else {
            draft.tx.outputs.push({ value: 0, scriptPubKey: "" });
            draft.outputs.push([]);
          }
        });
      })
    );
    out.querySelectorAll("[data-txin-del]").forEach((button) =>
      button.addEventListener("click", () => {
        const index = Number(button.dataset.txinDel);
        selected = null;
        mutate((draft) => {
          draft.tx.inputs.splice(index, 1);
          draft.inputs.splice(index, 1);
        });
      })
    );
    out.querySelectorAll("[data-txout-del]").forEach((button) =>
      button.addEventListener("click", () => {
        const index = Number(button.dataset.txoutDel);
        selected = null;
        mutate((draft) => {
          draft.tx.outputs.splice(index, 1);
          draft.outputs.splice(index, 1);
        });
      })
    );

    // The output-script builder writes its result into the output's
    // scriptPubKey field — exactly as if the user had typed the hex — and
    // the live rebuild validates it on the spot. Builder errors (bad
    // address, unknown ASM token) show inline.
    const applyBuiltScript = (index) => {
      const text = out.querySelector(`[data-build-script="${index}"]`)?.value ?? "";
      const mode = out.querySelector(`[data-build-mode="${index}"]`)?.value ?? "auto";
      try {
        const built = buildOutputScript(text, { network: network(), mode });
        doc.tx.outputs[Number(index)].scriptPubKey = built.scriptHex;
        liveRebuild();
      } catch (exception) {
        setError(exception.message || String(exception));
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

    // Flow-diagram boxes (and the middle transaction box) toggle the detail
    // panel under the diagram; the part's fields render there (and out of
    // the sections list) while open.
    const vizTarget = (part) => (part.kind === "tx" ? "tx" : `${part.kind}:${part.index}`);
    out.querySelectorAll("[data-viz]").forEach((button) =>
      button.addEventListener("click", () => {
        const [kind, indexText] = button.dataset.viz.split(":");
        const part = kind === "tx" ? { kind } : { kind, index: Number(indexText) };
        const closing = selected && selected.kind === part.kind && (part.kind === "tx" || selected.index === part.index);
        selected = closing ? null : part;
        render();
        renderResult();
        // Keep focus on the control that reflects the new state.
        (closing ? out.querySelector(`[data-viz="${vizTarget(part)}"]`) : out.querySelector("[data-viz-close]"))?.focus();
      })
    );
    out.querySelector("[data-viz-close]")?.addEventListener("click", () => {
      const focusBack = selected ? `[data-viz="${vizTarget(selected)}"]` : null;
      selected = null;
      render();
      renderResult();
      if (focusBack) out.querySelector(focusBack)?.focus();
    });

    out.querySelectorAll(".psbted-value").forEach((input) =>
      input.addEventListener("input", () => {
        const { kind, map, pair } = input.dataset;
        (kind === "global" ? doc.globals : kind === "input" ? doc.inputs[map] : doc.outputs[map])[Number(pair)].value = input.value.trim();
        liveRebuild();
      })
    );
    out.querySelectorAll(".psbted-del").forEach((button) =>
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
        mutate((draft) => {
          const target = kind === "global" ? draft.globals : kind === "input" ? draft.inputs[map] : draft.outputs[map];
          target.push({ key, value });
        });
      })
    );

    drawViz(); // the boxes exist now; draw the connectors over the layout
  };

  load.onclick = () => {
    psbtWasmReady.then(loadFromText).catch((exception) => setError(exception.message || String(exception)));
  };
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
    resultBytes = null;
    stale = false;
    selected = null;
    text.value = "";
    setError("");
    compareText.value = "";
    clearCompareReport();
    render();
  };
  $("psbted-compare-go").addEventListener("click", () => {
    psbtWasmReady
      .then(() => {
        clearCompareReport();
        if (!doc) {
          setCompareError("Load a PSBT above first.");
          return;
        }
        let beforeDoc;
        try {
          // Both sides are compared as rust-bitcoin decodes of accepted
          // PSBTs. The working document is rebuilt first so mid-edit field
          // text (an amount field holds a string while typed) cannot fake a
          // difference; a state that does not build refuses to compare
          // instead of guessing.
          beforeDoc = psbtInspectDoc(psbtBuildBytes(psbtEditorBuildDoc(doc)));
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
        compareOut.innerHTML = psbtDiffHtml(comparePsbtDocs(beforeDoc, afterDoc), beforeDoc, afterDoc, network());
      })
      .catch((exception) => setCompareError(exception.message || String(exception)));
  });
  $("psbted-compare-clear").addEventListener("click", () => {
    compareText.value = "";
    clearCompareReport();
  });
  // The header network picker broadcasts its choice; re-decode addresses.
  document.addEventListener("hodl:network-default", () => {
    if (doc) {
      render();
      renderResult();
    }
  });
};
