// BIP-47 payment-code card UI (markup in src/shell.html, #bip47-card).
// All DOM-free derivation lives in ./bip47.js; this file wires fields,
// renders results, and owns the session state (reveal flags, cached private
// bytes) that hodlBip47Wipe() clears. app.js gives it the SP session root
// through injected callbacks at init — the module never imports app.js.
//
// BigInt residue: pair and ECDH scalars are BigInts and cannot be wiped.
// Every Uint8Array owned here (notification private key, receive-row
// private keys, the pasted designated-input key) is filled with zeros in
// wipe() and in finally blocks; this is best-effort cleanup.
import {
  PAIR_ROW_COUNT,
  bip47AccountNode,
  bip47AccountPath,
  bip47BlindNotification,
  bip47ChildPublic,
  bip47DecodeNotificationTx,
  bip47NotificationAddress,
  bip47OutpointFromDisplay,
  bip47PairRows,
  bip47Payload,
  bytesToHex,
  decodePaymentCode,
  encodePaymentCode,
  equalBytes,
} from "./bip47.js";
import { tHtml as hodlT } from "./i18n.js";

const escapeHtml = (value) => String(value).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const el = (id) => document.getElementById(id);

let bip47RevealSelf = false;
let bip47RevealPairs = false;
let bip47LastSelf = null; // { …public fields, notificationPriv: Uint8Array }
let bip47LastPairs = null; // { direction, rows (receive rows hold privateKey), skipped, coinType, network }
let bip47Deps = {}; // ensureHd, getHd, coinType, network, parsePrivateKey
let bip47JournalLog = () => {};

// ── Availability (pure: which controls run) ──────────────────────────────────

export function hodlBip47Availability({ hasSession, hasCode, hasPairCode, hasTx, hasBlindKey, hasBlindOutpoint, hasBlindCode }) {
  return {
    "bip47-self-go": !hasSession,
    "bip47-decode-go": !hasCode,
    "bip47-send-go": !(hasSession && hasPairCode),
    "bip47-receive-go": !(hasSession && hasPairCode),
    "bip47-tx-go": !(hasSession && hasTx),
    "bip47-blind-go": !(hasSession && hasBlindKey && hasBlindOutpoint && hasBlindCode),
    "bip47-blind-key": !hasSession,
    "bip47-blind-outpoint": !hasSession,
    "bip47-blind-code": !hasSession,
    "bip47-tx": !hasSession,
    "bip47-tx-manual": !hasSession,
    "bip47-pair-code": !hasSession,
    "bip47-pair-start": !hasSession,
  };
}

function hodlBip47SyncAvailability() {
  if (!el("bip47-card")) return;
  const hasSession = Boolean(bip47Deps.getHd?.()?.privateKey);
  const text = (id) => String(el(id)?.value || "").trim();
  const map = hodlBip47Availability({
    hasSession,
    hasCode: Boolean(text("bip47-code-input")),
    hasPairCode: Boolean(text("bip47-pair-code")),
    hasTx: Boolean(text("bip47-tx")),
    hasBlindKey: Boolean(text("bip47-blind-key")),
    hasBlindOutpoint: Boolean(text("bip47-blind-outpoint")),
    hasBlindCode: Boolean(text("bip47-blind-code")),
  });
  for (const [id, disabled] of Object.entries(map)) {
    const node = el(id);
    if (node) node.disabled = disabled;
  }
}

// ── Wipe ─────────────────────────────────────────────────────────────────────

// Called from hodlSpWipeKeys() (SP key change or wipe) and from the card's
// own Clear action. Drops every cached private byte and resets reveal flags;
// the private-key input field is cleared too.
export function hodlBip47Wipe() {
  if (bip47LastSelf?.notificationPriv) bip47LastSelf.notificationPriv.fill(0);
  if (bip47LastPairs?.rows) for (const row of bip47LastPairs.rows) if (row.privateKey) row.privateKey.fill(0);
  bip47LastSelf = null;
  bip47LastPairs = null;
  bip47RevealSelf = false;
  bip47RevealPairs = false;
  const blindKey = el("bip47-blind-key");
  if (blindKey) blindKey.value = "";
  const out = el("bip47-out");
  if (out) out.innerHTML = "";
  const error = el("bip47-error");
  if (error) error.textContent = "";
  hodlBip47SyncAvailability();
}

// ── Shared render parts (pure builders) ───────────────────────────────────────

const networkLabel = (network) => (network === "testnet" ? hodlT("Testnet (practice)") : hodlT("Bitcoin mainnet"));
const testnetWarning = (network) => (network === "testnet" ? `<p class="psbt-warn">${hodlT("Testnet (practice): this is a test network; the addresses below have no value.")}</p>` : "");
const networkNote = (network) => `<p class="muted">${hodlT("Payment codes don't say which network they're for. Addresses below are for {network}.", { network: networkLabel(network) })}</p>`;
const notificationWarning = `<p class="psbt-warn">${hodlT("The notification address is public and reused: anyone who pays it, and anyone watching the chain, can see it. It is not a silent or stealth address.")}</p>`;

const copyButton = (id, label) => `<button type="button" class="btn secondary psbt-copy" data-bip47-copy="${escapeHtml(id)}">${escapeHtml(label)}</button>`;
const kvLine = (id, value) => `<p class="psbt-kv" id="${escapeHtml(id)}">${escapeHtml(value)}</p>${copyButton(id, hodlT("Copy"))}`;

const notificationAddressBlock = (address, network) => `
  <p class="label">${hodlT("Notification address")}</p>
  ${kvLine("bip47-notify-address", address)}
  ${testnetWarning(network)}
  ${notificationWarning}
  ${networkNote(network)}`;

// A reveal checkbox that re-renders through a caller-supplied render and
// rebinds itself after every render (render returns fresh markup each time).
const bindReveal = (toggleId, apply) => {
  const wire = () => {
    const toggle = el(toggleId);
    if (!toggle) return;
    toggle.onchange = (event) => {
      apply(event.target.checked);
      wire();
    };
  };
  wire();
};

// ── Section renders (pure: values in, markup out) ────────────────────────────

export function hodlBip47RenderSelf(result, { reveal = false } = {}) {
  return `<div class="sp-result">
    <p class="label">${hodlT("Your BIP-47 payment code")}</p>
    ${kvLine("bip47-code-value", result.code)}
    <p class="muted">${hodlT("Version {version} · account path {path}.", { version: result.version, path: result.accountPath })}</p>
    <p class="muted">${hodlT("Features byte 0x{features} — bit 0 (Bitmessage) is not used by this card.", { features: result.features.toString(16).padStart(2, "0") })}</p>
    ${notificationAddressBlock(result.notificationAddress, result.network)}
    <label class="choice"><input type="checkbox" id="bip47-self-reveal"${reveal ? " checked" : ""}> <span>${hodlT("Reveal the notification private key")}</span></label>
    ${reveal
      ? `<p class="label">${hodlT("Notification private key (hex)")}</p>${kvLine("bip47-notif-priv", result.notificationPrivHex)}<p class="muted">${hodlT("Private material stays in page memory until you clear it.")}</p>`
      : `<p class="muted">${hodlT("Private material stays hidden until you reveal it.")}</p>`}
  </div>`;
}

export function hodlBip47RenderDecoded({ code, decoded, network }) {
  if (decoded.supported !== true) {
    return `<div class="sp-result"><p class="muted">${hodlT("Payload version {version} is not derived in this card. This card derives version 1 only.", { version: decoded.version })}</p>${networkNote(network)}</div>`;
  }
  const address = bip47NotificationAddress(bip47ChildPublic(decoded.publicKey, decoded.chainCode, 0), network);
  return `<div class="sp-result">
    <p class="label">${hodlT("Decoded payment code")}</p>
    ${kvLine("bip47-decoded-code", code)}
    <p class="muted">${hodlT("Version 1 · features byte 0x{features} — bit 0 (Bitmessage) is not used by this card.", { features: decoded.features.toString(16).padStart(2, "0") })}</p>
    ${decoded.warnings.map((warning) => `<p class="psbt-warn">${hodlT(warning)}</p>`).join("")}
    ${notificationAddressBlock(address, network)}
  </div>`;
}

export function hodlBip47RenderPairs({ rows, skipped, direction, coinType, network }, { reveal = false } = {}) {
  const skippedNote = skipped.length
    ? `<p class="muted">${hodlT("Skipped indices (invalid shared secret or tweak): {indices}. Nothing is renumbered.", { indices: skipped.join(", ") })}</p>`
    : "";
  const pathOf = (row) => (direction === "receive"
    ? hodlT("your child {index}", { index: row.index })
    : hodlT("their child {index}", { index: row.index }));
  const rowMarkup = (row) => `<div class="sp-output"><p class="label">${hodlT("Pair index {index}", { index: row.index })}</p>
    <p class="muted">${pathOf(row)}</p>
    <p class="psbt-kv" id="bip47-pair-${row.index}">${escapeHtml(row.address)}</p>
    ${copyButton(`bip47-pair-${row.index}`, hodlT("Copy address"))}
    ${direction === "receive" && reveal ? `<p class="psbt-kv">${escapeHtml(bytesToHex(row.privateKey))}</p>` : ""}</div>`;
  const heading = direction === "send" ? hodlT("Send pair addresses (us → them)") : hodlT("Receive pair addresses (them → us)");
  return `<div class="sp-result">
    <p class="label">${heading}</p>
    ${skippedNote}
    ${rows.map(rowMarkup).join("")}
    ${direction === "receive" ? `<label class="choice"><input type="checkbox" id="bip47-pairs-reveal"${reveal ? " checked" : ""}> <span>${hodlT("Reveal receive private keys")}</span></label>` : ""}
    ${testnetWarning(network)}
    ${networkNote(network)}
  </div>`;
}

export function hodlBip47RenderTx(result, { network } = {}) {
  const stop = (message) => `<div class="sp-result"><p class="psbt-warn">${hodlT(message)}</p></div>`;
  if (result.status === "no-payload") return stop("No OP_RETURN output carries an 80-byte payload in this transaction.");
  if (result.status === "unsupported-version") return `<div class="sp-result"><p class="psbt-warn">${hodlT("The notification payload is version {version} — not derived in this card. This card derives version 1 only.", { version: result.version })}</p></div>`;
  if (result.status === "manual-needed") return stop("The first input that could expose a public key is not a supported form here (P2PK, multisig, or another script shape). Paste the designated public key into the manual field — BIP-47 allows this fallback; scanning never skips ahead to a later input.");
  if (result.status === "manual-invalid") return stop("The manual designated public key does not parse as a 33- or 65-byte point.");
  const kindFull = {
    manual: hodlT("manual field"),
    p2pkh: hodlT("P2PKH scriptSig"),
    p2wpkh: hodlT("P2WPKH witness (common practice, not in the BIP-47 text)"),
    "p2sh-p2wpkh": hodlT("P2SH-P2WPKH witness (common practice, not in the BIP-47 text)"),
  }[result.kind];
  const proveNote = result.paysOurNotification
    ? `<p class="psbt-ok">${hodlT("This transaction pays a BIP-47 notification address of yours.")}</p>`
    : `<p class="psbt-warn">${hodlT("This decode doesn't prove the transaction was meant for you.")}</p>`;
  if (result.status === "undecodable") {
    return `<div class="sp-result"><p class="psbt-warn">${hodlT("The unblinded payload does not validate as a version 1 payment code. Wrong key, or the transaction was not meant for you.")}</p>${proveNote}</div>`;
  }
  return `<div class="sp-result">
    <p class="label">${hodlT("Recovered sender payment code")}</p>
    ${kvLine("bip47-code-value", result.code)}
    <p class="muted">${hodlT("Designated input {index} ({kind}).", { index: result.inputIndex, kind: kindFull })}</p>
    <p class="psbt-kv">${escapeHtml(result.publicKeyHex)}</p>
    ${proveNote}
    ${networkNote(network)}
  </div>`;
}

export function hodlBip47RenderBlind(payload) {
  return `<div class="sp-result">
    <p class="label">${hodlT("Blinded notification payload (80 bytes)")}</p>
    <p class="psbt-kv" id="bip47-blind-out">${escapeHtml(bytesToHex(payload))}</p>
    ${copyButton("bip47-blind-out", hodlT("Copy hex"))}
    <p class="muted">${hodlT("This page builds the blinded payload only — no OP_RETURN script, transaction, or PSBT.")}</p>
  </div>`;
}

// ── Handler helpers ──────────────────────────────────────────────────────────

const failInto = (handler, entry) => {
  try {
    handler();
    bip47JournalLog("calculate", entry, "bip47");
  } catch (exception) {
    el("bip47-error").textContent = exception instanceof Error ? exception.message : String(exception);
    bip47JournalLog("calculate-error", entry, "bip47");
  }
};

// Derives the account node and its child-0 notification node. The caller
// wipes scope.account/scope.notif in its own finally (scope.notifPriv is
// intentionally kept by the self section's reveal cache or wiped there too).
const notificationKeyOf = (root, coinType) => {
  const account = bip47AccountNode(root, coinType);
  const notif = account.deriveChild(0);
  return { account, notif, notifPriv: notif.privateKey, path: bip47AccountPath(coinType) };
};
const notificationKeyDrop = ({ account, notif, notifPriv }) => {
  if (notifPriv) notifPriv.fill(0);
  if (notif) notif.wipePrivateData();
  account.wipePrivateData();
};

function runSelf() {
  if (bip47LastSelf?.notificationPriv) bip47LastSelf.notificationPriv.fill(0);
  bip47LastSelf = null;
  const network = bip47Deps.network();
  bip47Deps.ensureHd();
  const coinType = bip47Deps.coinType();
  const key = notificationKeyOf(bip47Deps.getHd(), coinType);
  try {
    bip47LastSelf = {
      code: encodePaymentCode(key.account.publicKey, key.account.chainCode),
      version: 1,
      features: 0,
      accountPath: key.path,
      coinType,
      network,
      notificationAddress: bip47NotificationAddress(key.notif.publicKey, network),
      notificationPriv: key.notifPriv,
      notificationPrivHex: bytesToHex(key.notifPriv),
    };
  } finally {
    // The node's own copies are wiped; the cached notifPriv survives for the
    // reveal toggle and is zeroed by the next runSelf/wipe.
    key.account.wipePrivateData();
    key.notif.wipePrivateData();
  }
  const render = () => {
    el("bip47-out").innerHTML = hodlBip47RenderSelf(bip47LastSelf, { reveal: bip47RevealSelf });
  };
  render();
  bindReveal("bip47-self-reveal", (checked) => {
    bip47RevealSelf = checked;
    render();
  });
}

function runDecode() {
  const network = bip47Deps.network();
  const text = el("bip47-code-input").value;
  const decoded = decodePaymentCode(text);
  el("bip47-out").innerHTML = hodlBip47RenderDecoded({ code: text.trim(), decoded, network });
}

function runPairs(direction) {
  if (bip47LastPairs?.rows) for (const row of bip47LastPairs.rows) if (row.privateKey) row.privateKey.fill(0);
  bip47LastPairs = null;
  const network = bip47Deps.network();
  const decoded = decodePaymentCode(el("bip47-pair-code").value);
  if (decoded.supported !== true) throw new Error("Pair derivation needs a version 1 payment code.");
  const startText = el("bip47-pair-start").value;
  const start = startText.trim() === "" ? 0 : Number(startText);
  if (!Number.isInteger(start) || start < 0) throw new Error("Pair start index must be a non-negative integer.");
  bip47Deps.ensureHd();
  const root = bip47Deps.getHd();
  const coinType = bip47Deps.coinType();
  const account = bip47AccountNode(root, coinType);
  let notifNode = null, notifPriv = null;
  try {
    let own = account;
    if (direction === "send") {
      notifNode = account.deriveChild(0);
      notifPriv = notifNode.privateKey;
      own = notifPriv;
    }
    const options = { own, publicKey: decoded.publicKey, chainCode: decoded.chainCode };
    bip47LastPairs = { ...bip47PairRows(direction, options, start, PAIR_ROW_COUNT, network), direction, coinType, network };
  } finally {
    if (notifPriv) notifPriv.fill(0);
    if (notifNode) notifNode.wipePrivateData();
    account.wipePrivateData();
  }
  const render = () => {
    el("bip47-out").innerHTML = hodlBip47RenderPairs(bip47LastPairs, { reveal: bip47RevealPairs });
  };
  render();
  if (direction === "receive") {
    bindReveal("bip47-pairs-reveal", (checked) => {
      bip47RevealPairs = checked;
      render();
    });
  }
}

function runTx() {
  const network = bip47Deps.network();
  bip47Deps.ensureHd();
  const coinType = bip47Deps.coinType();
  const key = notificationKeyOf(bip47Deps.getHd(), coinType);
  try {
    const manual = String(el("bip47-tx-manual")?.value || "").trim();
    const result = bip47DecodeNotificationTx(el("bip47-tx").value, key.notifPriv, { designatedPub: manual || null });
    el("bip47-out").innerHTML = hodlBip47RenderTx(result, { network });
  } finally {
    notificationKeyDrop(key);
  }
}

function runBlind() {
  const decoded = decodePaymentCode(el("bip47-blind-code").value);
  if (decoded.supported !== true) throw new Error("Blinding needs a version 1 payment code.");
  bip47Deps.ensureHd();
  const coinType = bip47Deps.coinType();
  const key = notificationKeyOf(bip47Deps.getHd(), coinType);
  let designated = null;
  try {
    designated = bip47Deps.parsePrivateKey(el("bip47-blind-key").value);
    if (equalBytes(designated, key.notifPriv)) throw new Error("The designated input key is the same as your notification key — pick a different input.");
    const ourPayload = bip47Payload(key.account.publicKey, key.account.chainCode);
    const theirChild0 = bip47ChildPublic(decoded.publicKey, decoded.chainCode, 0);
    const outpoint = bip47OutpointFromDisplay(el("bip47-blind-outpoint").value);
    const blinded = bip47BlindNotification(ourPayload, designated, theirChild0, outpoint);
    el("bip47-out").innerHTML = hodlBip47RenderBlind(blinded);
  } finally {
    if (designated) designated.fill(0); // Lightning pattern: wipe in finally
    notificationKeyDrop(key);
  }
}

// ── Init ─────────────────────────────────────────────────────────────────────

export function hodlInitBip47({ ensureHd, getHd, coinType, network, parsePrivateKey, journalLog } = {}) {
  if (!el("bip47-card")) return;
  bip47Deps = { ensureHd, getHd, coinType, network, parsePrivateKey };
  if (typeof journalLog === "function") bip47JournalLog = journalLog;
  const modes = ["self", "decode", "pairs", "tx", "blind"];
  const panels = { self: "bip47-self", decode: "bip47-decode", pairs: "bip47-pairs", tx: "bip47-txdecode", blind: "bip47-blind" };
  document.querySelectorAll("#bip47-modes [data-bip47-mode]").forEach((button) => {
    button.onclick = () => {
      for (const mode of modes) {
        const panel = el(panels[mode]);
        if (panel) panel.hidden = mode !== button.dataset.bip47Mode;
      }
      document.querySelectorAll("#bip47-modes [data-bip47-mode]").forEach((peer) => {
        const active = peer === button;
        peer.classList.toggle("active", active);
        peer.setAttribute("aria-pressed", String(active));
      });
      el("bip47-out").innerHTML = "";
      el("bip47-error").textContent = "";
    };
  });
  const wire = (id, handler, entry) => {
    const node = el(id);
    if (!node) return;
    node.onclick = () => {
      el("bip47-error").textContent = "";
      el("bip47-out").innerHTML = "";
      failInto(handler, entry);
    };
  };
  wire("bip47-self-go", runSelf, "self");
  wire("bip47-decode-go", runDecode, "decode");
  wire("bip47-send-go", () => runPairs("send"), "pairs:send");
  wire("bip47-receive-go", () => runPairs("receive"), "pairs:receive");
  wire("bip47-tx-go", runTx, "notification-tx");
  wire("bip47-blind-go", runBlind, "blind");
  const wipe = el("bip47-wipe");
  if (wipe) {
    wipe.onclick = () => {
      hodlBip47Wipe();
      for (const id of ["bip47-code-input", "bip47-pair-code", "bip47-pair-start", "bip47-tx", "bip47-tx-manual", "bip47-blind-outpoint", "bip47-blind-code"]) {
        const field = el(id);
        if (field) field.value = "";
      }
    };
  }
  for (const id of ["bip47-code-input", "bip47-pair-code", "bip47-pair-start", "bip47-tx", "bip47-tx-manual", "bip47-blind-key", "bip47-blind-outpoint", "bip47-blind-code"]) {
    el(id)?.addEventListener("input", hodlBip47SyncAvailability);
  }
  el("bip47-out").addEventListener("click", (event) => {
    const button = event.target.closest?.("[data-bip47-copy]");
    if (!button) return;
    const node = el(button.dataset.bip47Copy);
    if (!node) return;
    navigator.clipboard?.writeText(node.textContent || "").catch(() => {});
  });
  hodlBip47SyncAvailability();
}
