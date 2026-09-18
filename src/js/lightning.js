// Lightning node identity tool for EntropyLab: derives the node pubkey a
// Lightning implementation would announce from a user-supplied seed phrase.
//
// Two seed schemes, two derivations:
//
// * aezeed (LND). The 24-word cipher seed deciphers (aezeed.js) to 16 bytes
//   of entropy that LND feeds DIRECTLY to BIP32 as the master seed (no BIP39
//   PBKDF2). The node identity key sits at m/1017'/coinType'/6'/0/0
//   (BIP43 purpose 1017, key family 6 = node key; coin type 0 on mainnet,
//   1 on testnet), per lnd/keychain/derivation.go.
//
// * BIP-39 (LDK, ldk-node convention). ldk-node turns the mnemonic into the
//   standard 64-byte BIP39 seed, takes the BIP32 master key's own 32-byte
//   private key, and hands that to LDK's KeysManager, which re-seeds a
//   second BIP32 master from it and derives the node secret at m/0'
//   (hardened), per ldk-node/src/builder.rs and rust-lightning's
//   sign::KeysManager. The result is network-independent.
//
// Deterministic transformations of user input only: nothing here generates
// entropy, and derived key material stays in page memory until wiped.
import { HDKey, HARDENED_OFFSET } from "./hdkey.js";
import { mnemonicToSeedSync, validateMnemonic } from "./bip39.js";
import { aezeedDecode, BITCOIN_GENESIS_TIMESTAMP } from "./aezeed.js";
import { wordlist as bip39English } from "./bip39-english.js";
import { hex } from "./coders.js";
import { t } from "./i18n.js";
import { bolt11Decode } from "./bolt11.js";
import { bolt12Decode, bolt12PathCount, bolt12RecipientVisibility } from "./bolt12.js";

// ── Derivations (DOM-free, unit-tested directly) ────────────────────────────

// The aezeed internal (key-derivation) version this tool understands: LND
// writes version 0 and rejects anything else; guggero's cryptography-toolkit
// also emits version 1. Deriving a node key from an unknown internal version
// would print a key no Lightning implementation would ever use.
export const isKnownInternalVersion = (version) => version === 0 || version === 1;

// LND: the aezeed entropy is the BIP32 seed; node key at
// m/1017'/coinType'/6'/0/0. Returns the compressed pubkey hex, the path, and
// the root xprv (what chantools showrootkey prints; importable into wallets).
export const deriveLndNode = (entropy16, coinType) => {
  if (!(entropy16 instanceof Uint8Array) || entropy16.length !== 16) {
    throw new Error("aezeed entropy must be 16 bytes.");
  }
  if (coinType !== 0 && coinType !== 1) throw new Error("Coin type must be 0 (mainnet) or 1 (testnet).");
  const path = `m/1017'/${coinType}'/6'/0/0`;
  const master = HDKey.fromMasterSeed(entropy16);
  let node = null;
  try {
    node = master.derive(path);
    return { nodePubKey: hex.encode(node.publicKey), path, rootXprv: master.privateExtendedKey };
  } finally {
    if (node) node.wipePrivateData();
    master.wipePrivateData();
  }
};

// LDK (ldk-node): BIP39 seed -> master xprv -> its raw private key re-seeds
// a second master -> node secret at m/0'. The root xprv returned is the
// first-stage master (the on-chain wallet root ldk-node uses).
export const deriveLdkNode = (mnemonic, passphrase = "") => {
  const seed64 = mnemonicToSeedSync(mnemonic, passphrase);
  let master1 = null, master2 = null, node = null, key32 = null;
  try {
    master1 = HDKey.fromMasterSeed(seed64);
    key32 = master1.privateKey;
    master2 = HDKey.fromMasterSeed(key32);
    node = master2.deriveChild(0 + HARDENED_OFFSET);
    return { nodePubKey: hex.encode(node.publicKey), path: "m/0'", rootXprv: master1.privateExtendedKey };
  } finally {
    seed64.fill(0);
    if (key32) key32.fill(0);
    if (node) node.wipePrivateData();
    if (master2) master2.wipePrivateData();
    if (master1) master1.wipePrivateData();
  }
};

// ── Tool wiring (markup in src/shell.html, #ln-card) ────────────────────────

const escapeHtml = (value) => String(value).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

let hodlLnLast = null; // last successful derivation, kept for the reveal toggle
let hodlLnReveal = false;
let hodlLnJournalLog = () => {};

const hodlLnNote = "No node key derived. Enter a seed phrase and derive.";

export function hodlLnWipeMem() {
  if (hodlLnLast) {
    if (hodlLnLast.entropy) hodlLnLast.entropy.fill(0);
    if (hodlLnLast.salt) hodlLnLast.salt.fill(0);
    // The xprv and pubkey strings are immutable JS values; dropping the
    // references is the best effort available (same limit as the other
    // tools' extended-key display).
  }
  hodlLnLast = null;
  hodlLnReveal = false;
}

const hodlLnFormat = () => (document.getElementById("ln-format")?.value === "bip39" ? "bip39" : "aezeed");
const hodlLnCoinType = () => (document.getElementById("ln-network")?.value === "testnet" ? 1 : 0);

const hodlLnNormalize = (text) => String(text || "").trim().toLowerCase().replace(/[^a-z\s]/g, " ").split(/\s+/).filter(Boolean);

const hodlLnBirthdayIso = (timestamp) => new Date(timestamp * 1000).toISOString().slice(0, 10);

const hodlLnCopyButton = (target, label) => `<button type="button" class="btn secondary psbt-copy" data-ln-copy="${target}">${escapeHtml(label)}</button>`;

function hodlLnValidateBip39(words) {
  if (words.length === 0) throw Object.assign(new Error("Type or paste your seed phrase."), { key: "Type or paste your seed phrase." });
  if (![12, 15, 18, 21, 24].includes(words.length)) {
    throw Object.assign(new Error("A seed phrase is 12, 15, 18, 21, or 24 words. You entered {n}."), { key: "A seed phrase is 12, 15, 18, 21, or 24 words. You entered {n}.", vars: { n: words.length } });
  }
  const unknown = words.map((word, index) => ({ word, index })).filter(({ word }) => !bip39English.includes(word));
  if (unknown.length > 0) {
    throw Object.assign(new Error("Unknown word"), { key: "Word {n} (“{word}”) is not on the BIP39 English list.", vars: { n: unknown[0].index + 1, word: unknown[0].word } });
  }
  const phrase = words.join(" ");
  if (!validateMnemonic(phrase)) {
    throw Object.assign(new Error("Bad checksum"), { key: "The BIP39 checksum does not match. A word is likely mistyped, missing, or swapped." });
  }
  return phrase;
}

function hodlLnRender() {
  const output = document.getElementById("ln-out");
  if (!output) return;
  if (!hodlLnLast) {
    output.innerHTML = "";
    return;
  }
  const r = hodlLnLast;
  const secrets = hodlLnReveal;
  const aezeed = r.format === "aezeed";
  const implementation = aezeed ? "LND" : "LDK (ldk-node)";
  output.innerHTML = `
    <div class="ln-result">
      <p class="label">${escapeHtml(implementation)} node identity public key</p>
      <p class="psbt-kv" id="ln-node-pubkey">${escapeHtml(r.nodePubKey)}</p>
      ${hodlLnCopyButton("ln-node-pubkey", "Copy node pubkey")}
      <p class="muted">Identity key path <code>${escapeHtml(r.path)}</code>${aezeed ? ` · coin type ${r.coinType} (${r.coinType === 1 ? "testnet" : "mainnet"})` : " · the LDK node identity does not depend on the network"}</p>
      ${aezeed ? `<p class="muted">Internal (key-derivation) version ${r.internalVersion} · wallet birthday day ${r.birthdayDays} (${escapeHtml(hodlLnBirthdayIso(r.birthdayTimestamp))} UTC, day 0 = Bitcoin genesis). Rescans from the birthday recover on-chain funds; channel funds need the node's channel backup.</p>` : `<p class="muted">Derived the ldk-node way: BIP39 seed → master key → its private key re-seeds a second BIP32 tree → node secret at <code>m/0'</code>.</p>`}
      <label class="choice"><input type="checkbox" id="ln-reveal" ${secrets ? "checked" : ""}> <span>Reveal the root private key${aezeed ? " and decoded entropy" : ""}</span></label>
      ${secrets ? `
        ${aezeed ? `<p class="label">Decoded entropy (the BIP32 master seed)</p>
        <p class="psbt-kv" id="ln-entropy">${hex.encode(r.entropy)}</p>
        ${hodlLnCopyButton("ln-entropy", "Copy entropy")}
        <p class="label">Salt</p>
        <p class="psbt-kv">${hex.encode(r.salt)}</p>` : ""}
        <p class="label">BIP32 root private key (xprv)</p>
        <p class="psbt-kv" id="ln-root-xprv">${escapeHtml(r.rootXprv)}</p>
        ${hodlLnCopyButton("ln-root-xprv", "Copy root xprv")}
        <p class="muted">The root xprv can spend the node's on-chain wallet. Reveal it only while this file runs offline on an air-gapped computer.</p>` : `<p class="muted">Private material stays hidden until you reveal it.</p>`}
    </div>`;
  document.getElementById("ln-reveal")?.addEventListener("change", (event) => {
    hodlLnReveal = event.target.checked;
    hodlLnRender();
  });
}

function hodlRunLn() {
  const error = document.getElementById("ln-error");
  const session = document.getElementById("ln-session");
  error.textContent = "";
  hodlLnWipeMem();
  const format = hodlLnFormat();
  try {
    const words = hodlLnNormalize(document.getElementById("ln-seed").value);
    const passphrase = document.getElementById("ln-pass").value;
    if (format === "aezeed") {
      const decoded = aezeedDecode(words, passphrase);
      const coinType = hodlLnCoinType();
      try {
        if (!isKnownInternalVersion(decoded.internalVersion)) {
          throw Object.assign(new Error("Unsupported internal version"), {
            key: "This cipher seed uses internal (key-derivation) version {v}, which no current Lightning implementation understands. Refusing to derive from it.",
            vars: { v: decoded.internalVersion },
            code: "internal-version",
          });
        }
        const derived = deriveLndNode(decoded.entropy, coinType);
        hodlLnLast = { format, coinType, ...decoded, ...derived };
      } catch (exception) {
        decoded.entropy.fill(0);
        decoded.salt.fill(0);
        throw exception;
      }
    } else {
      const phrase = hodlLnValidateBip39(words);
      const derived = deriveLdkNode(phrase, passphrase);
      hodlLnLast = { format, ...derived };
    }
    hodlLnRender();
    session.textContent = "Node key derived. Decoded key material stays in page memory until you clear it.";
    hodlLnJournalLog("derive", `${format} ${hodlLnLast.nodePubKey.slice(0, 8)}`, "ln");
  } catch (exception) {
    hodlLnWipeMem();
    hodlLnRender();
    // Keyed errors (aezeed.js taxonomy, the validations above) format and
    // translate through t(); anything else shows its raw message.
    error.textContent = exception && typeof exception.key === "string"
      ? t(exception.key, exception.vars)
      : exception instanceof Error ? exception.message : String(exception);
    hodlLnJournalLog("derive-error", format, "ln");
  }
}

function hodlLnSyncFormat() {
  const aezeed = hodlLnFormat() === "aezeed";
  const network = document.getElementById("ln-network-field");
  if (network) network.hidden = !aezeed;
  const note = document.getElementById("ln-seed-help");
  if (note) {
    note.textContent = aezeed
      ? "The 24-word cipher seed LND printed at wallet creation."
      : "A 12 to 24 word BIP-39 seed phrase, as used by ldk-node.";
  }
}

// ── BOLT11/BOLT12 invoice decoder ──────────────────────────────────────────
// DOM-free decoding lives in bolt11.js and bolt12.js; this section only
// renders results. Decode-only by design: no invoice creation, no payment,
// no network — an offer's blinded paths are counted, never followed.

let hodlLnInvLast = null; // last successful decode { decoded, raw, pageNetwork }
let hodlLnInvReveal = false;
let hodlLnInvQrSvg = null;
let hodlLnInvNetworkChoice = () => "mainnet";

export function hodlLnInvWipeMem() {
  // Decoded strings (payment secret, payment hash, node id) are immutable JS
  // values; dropping the references is the best effort available (same limit
  // as the other tools' displayed keys).
  hodlLnInvLast = null;
  hodlLnInvReveal = false;
}

const hodlLnInvAmount = (msat) => {
  if (msat === null || msat === undefined) return null;
  const ms = BigInt(msat);
  const whole = ms / 10n ** 11n;
  const frac = (ms % 10n ** 11n).toString().padStart(11, "0").replace(/0+$/, "");
  return `${whole}${frac ? "." + frac : ""} BTC (${ms.toString()} msat)`;
};

const hodlLnInvIso = (timestamp) => new Date(timestamp * 1000).toISOString().replace(".000Z", " UTC");

const hodlLnInvRow = (label, value, copyId) => `
      <p class="label">${escapeHtml(label)}</p>
      <p class="psbt-kv"${copyId ? ` id="${copyId}"` : ""}>${escapeHtml(value)}</p>
      ${copyId ? hodlLnCopyButton(copyId, `Copy ${label.toLowerCase()}`) : ""}`;

function hodlLnInvRender() {
  const output = document.getElementById("ln-inv-out");
  if (!output) return;
  const r = hodlLnInvLast;
  if (!r) {
    output.innerHTML = "";
    return;
  }
  const d = r.decoded;
  const wrongNetwork = d.kind === "bolt11" && d.network !== r.pageNetwork;
  const states = `
      <ul class="ln-inv-states">
        <li class="psbt-ok">Present — the checksum verifies.</li>
        <li class="psbt-ok">Structurally valid — required fields are present and well-formed.</li>
        ${d.kind === "bolt11"
          ? `<li class="psbt-ok">Signature valid — verifies against the recovered node id.</li>`
          : `<li class="muted">Signature not checked — this tool never marks BOLT12 data as verified.</li>`}
      </ul>`;
  const warning = wrongNetwork
    ? `<p class="warn">This invoice is for Bitcoin ${escapeHtml(d.network)}, but the page network is ${escapeHtml(r.pageNetwork)}. It does not belong to the selected chain.</p>`
    : "";
  let rows = "";
  if (d.kind === "bolt11") {
    rows = `
      ${d.amountMsat !== null ? hodlLnInvRow("Amount", hodlLnInvAmount(d.amountMsat)) : `<p class="muted">No amount set — the payer chooses.</p>`}
      ${d.description ? hodlLnInvRow("Description", d.description) : ""}
      ${d.descriptionHash ? hodlLnInvRow("Description hash", d.descriptionHash) : ""}
      ${hodlLnInvRow("Payment hash", d.paymentHash, "ln-inv-payment-hash")}
      ${hodlLnInvRow("Node id (recovered from the signature)", d.nodeId, "ln-inv-node-id")}
      ${hodlLnInvRow("Created", hodlLnInvIso(d.timestamp))}
      ${hodlLnInvRow("Expiry", d.expiry !== null ? `${d.expiry} seconds` : "not set (3600 seconds by default)")}
      ${d.minFinalCltvExpiry !== null ? hodlLnInvRow("Minimum final CLTV delta", String(d.minFinalCltvExpiry)) : ""}
      ${d.fallbacks.length ? hodlLnInvRow("Fallback addresses", d.fallbacks.map((f) => `version ${f.version}: ${f.program}`).join(" · ")) : ""}
      ${d.routeHintHops ? hodlLnInvRow("Route hints", `${d.routeHintHops} hop${d.routeHintHops === 1 ? "" : "s"} (not resolved)`) : ""}
      ${d.features ? hodlLnInvRow("Feature bits", d.features) : ""}
      ${d.unknownOddTags.length ? hodlLnInvRow("Unknown fields skipped", d.unknownOddTags.map((tag) => `tag ${tag}`).join(", ")) : ""}
      <label class="choice"><input type="checkbox" id="ln-inv-reveal" ${hodlLnInvReveal ? "checked" : ""}> <span>Reveal the payment secret</span></label>
      ${hodlLnInvReveal
        ? hodlLnInvRow("Payment secret", d.paymentSecret, "ln-inv-payment-secret")
        : `<p class="muted">The payment secret stays hidden until you reveal it.</p>`}`;
  } else {
    const names = { lno: "BOLT12 offer", lnr: "BOLT12 invoice request", lni: "BOLT12 invoice" };
    const fields = d.fields || {};
    const noun = names[d.hrp] || "BOLT12 data";
    const pathCount = bolt12PathCount(fields);
    const visibility = bolt12RecipientVisibility(fields);
    const offerAmount = () => {
      if (fields.invoiceAmount != null) return hodlLnInvAmount(fields.invoiceAmount);
      if (fields.amountMsat != null) return hodlLnInvAmount(fields.amountMsat);
      if (fields.amount == null) return null;
      if (fields.currency) return `${fields.amount} ${fields.currency}`;
      return hodlLnInvAmount(fields.amount);
    };
    const amountText = offerAmount();
    const honesty = visibility.kind === "blinded"
      ? `<p class="muted">Recipient node id is not in this ${escapeHtml(noun.toLowerCase())} (blinded paths). The issuer signing key is not the destination.</p>`
      : visibility.kind === "published"
        ? `<p class="warn">No blinded path. This ${escapeHtml(noun.toLowerCase())} publishes the issuer pubkey in the clear — that is a signing key, not a hidden destination.</p>`
        : "";
    const fieldRows = [
      ["description", "Description", (v) => v],
      ["currency", "Currency", (v) => v],
      ["issuer", "Issuer", (v) => v],
      ["issuerId", "Issuer signing key (not the destination)", (v) => v],
      ["nodeId", "Invoice node id (signing key, not a route destination)", (v) => v],
      ["payerId", "Payer id", (v) => v],
      ["payerNote", "Payer note", (v) => v],
      ["paymentHash", "Payment hash", (v) => v],
      ["absoluteExpiry", "Expires", (v) => hodlLnInvIso(Number(v))],
      ["createdAt", "Created", (v) => hodlLnInvIso(Number(v))],
      ["quantityMax", "Maximum quantity", (v) => String(v)],
      ["chains", "Chains", (v) => (Array.isArray(v) ? v.join(" · ") : String(v))],
    ];
    rows = `
      <p class="label">${escapeHtml(noun)}</p>
      ${honesty}
      ${pathCount ? hodlLnInvRow("Blinded paths", `${pathCount} (counted, never followed)`) : ""}
      ${amountText ? hodlLnInvRow("Amount", amountText) : ""}
      ${fieldRows.filter(([key]) => fields[key] !== undefined && fields[key] !== null)
        .map(([key, label, format]) => hodlLnInvRow(label, format(fields[key]), key === "issuerId" ? "ln-inv-issuer-id" : key === "nodeId" ? "ln-inv-invoice-node-id" : undefined)).join("")}
      ${d.unknownOddTypes && d.unknownOddTypes.length ? hodlLnInvRow("Unknown fields skipped", d.unknownOddTypes.map((type) => `type ${type}`).join(", ")) : ""}`;
  }
  output.innerHTML = `
    <div class="ln-result">
      ${states}
      ${warning}
      ${rows}
      ${r.qrSvg ? `<div class="qr">${r.qrSvg(r.raw)}</div>` : ""}
    </div>`;
  document.getElementById("ln-inv-reveal")?.addEventListener("change", (event) => {
    hodlLnInvReveal = event.target.checked;
    hodlLnInvRender();
  });
}

function hodlRunLnInv() {
  const error = document.getElementById("ln-inv-error");
  error.textContent = "";
  hodlLnInvWipeMem();
  try {
    const raw = String(document.getElementById("ln-inv-input").value || "").trim();
    if (!raw) throw Object.assign(new Error("empty"), { key: "Paste an invoice or offer first." });
    // lnb* is BOLT11 (lnbc/lntb/lntbs/lnbcrt); lno/lnr/lni are BOLT12. Each
    // decoder hard-rejects the other's strings as well.
    const decoded = raw.slice(0, 3).toLowerCase() === "lnb" ? bolt11Decode(raw) : bolt12Decode(raw);
    hodlLnInvLast = { decoded, raw, pageNetwork: hodlLnInvNetworkChoice(), qrSvg: hodlLnInvQrSvg };
    hodlLnInvRender();
    hodlLnJournalLog("invoice-decode", decoded.kind, "ln");
  } catch (exception) {
    hodlLnInvWipeMem();
    hodlLnInvRender();
    error.textContent = exception && typeof exception.key === "string"
      ? t(exception.key, exception.vars)
      : exception instanceof Error ? exception.message : String(exception);
    hodlLnJournalLog("invoice-decode-error", "", "ln");
  }
}

// Wires the Lightning card. `journalLog` is the app's hodlJournalLog; the
// module takes it as an option instead of importing app.js (same shape as
// initPsbtEditor's options object).
export function hodlInitLn({ journalLog, qrSvg, networkChoice } = {}) {
  const go = document.getElementById("ln-go");
  if (!go) return;
  if (typeof journalLog === "function") hodlLnJournalLog = journalLog;
  if (typeof qrSvg === "function") hodlLnInvQrSvg = qrSvg;
  if (typeof networkChoice === "function") hodlLnInvNetworkChoice = networkChoice;
  go.onclick = hodlRunLn;
  const invDecode = document.getElementById("ln-inv-decode");
  if (invDecode) {
    invDecode.onclick = hodlRunLnInv;
    document.getElementById("ln-inv-clear").onclick = () => {
      hodlLnInvWipeMem();
      const field = document.getElementById("ln-inv-input");
      if (field) field.value = "";
      document.getElementById("ln-inv-out").innerHTML = "";
      document.getElementById("ln-inv-error").textContent = "";
    };
    document.getElementById("ln-inv-out").addEventListener("click", (event) => {
      const button = event.target.closest?.("[data-ln-copy]");
      if (!button) return;
      const node = document.getElementById(button.dataset.lnCopy);
      if (!node) return;
      navigator.clipboard?.writeText(node.textContent || "").catch(() => {});
    });
  }
  document.getElementById("ln-wipe").onclick = () => {
    hodlLnWipeMem();
    for (const id of ["ln-seed", "ln-pass"]) {
      const field = document.getElementById(id);
      if (field) field.value = "";
    }
    document.getElementById("ln-out").innerHTML = "";
    document.getElementById("ln-error").textContent = "";
    document.getElementById("ln-session").textContent = "Session ended and accessible fields were cleared (best effort).";
  };
  for (const id of ["ln-format", "ln-network"]) {
    document.getElementById(id)?.addEventListener("change", () => {
      // A stale result next to a flipped select is how a correct seed looks
      // wrong (a mainnet pubkey beside "Testnet"): wipe and re-render on any
      // format or network change.
      hodlLnWipeMem();
      hodlLnRender();
      hodlLnSyncFormat();
    });
  }
  document.getElementById("ln-out").addEventListener("click", (event) => {
    const button = event.target.closest?.("[data-ln-copy]");
    if (!button) return;
    const node = document.getElementById(button.dataset.lnCopy);
    if (!node) return;
    navigator.clipboard?.writeText(node.textContent || "").catch(() => {});
  });
  document.getElementById("ln-session").textContent = hodlLnNote;
  hodlLnSyncFormat();
}
