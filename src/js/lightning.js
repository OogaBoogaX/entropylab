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
import { t, tHtml as hodlT } from "./i18n.js";
import { privateCopyButtonHtml } from "./private-data.js";
import { publicFieldHtml, publicValueHtml } from "./public-data.js";
import { bolt11Decode } from "./bolt11.js";
import { bolt12Decode, bolt12RecipientVisibility } from "./bolt12.js";

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

// A BIP39 passphrase is UTF-8 text: a lone surrogate would silently encode
// as U+FFFD and derive a wallet that is not the one the user typed (the
// calculator's BIP39 path refuses the same, #1015). JS strings are UTF-16,
// so the check is a scan for unpaired surrogates.
const isWellFormedUtf16 = (text) => {
  for (let i = 0; i < text.length; i++) {
    const code = text.charCodeAt(i);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = text.charCodeAt(i + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return false;
      i++;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      return false;
    }
  }
  return true;
};

// LDK (ldk-node): BIP39 seed -> master xprv -> its raw private key re-seeds
// a second master -> node secret at m/0'. The root xprv returned is the
// first-stage master (the on-chain wallet root ldk-node uses).
export const deriveLdkNode = (mnemonic, passphrase = "") => {
  if (!isWellFormedUtf16(passphrase)) {
    // The wrong side was the message: the guard fired, but its fallback text
    // ("not well-formed Unicode") dropped the actionable word the key and
    // the refusal tests carry — "surrogate", an invisible pasted character
    // the user must retype rather than paste.
    throw Object.assign(new Error("The passphrase contains an unpaired surrogate."), {
      key: "The passphrase contains an unpaired surrogate, which cannot be encoded as UTF-8. Retype the passphrase instead of pasting it.",
      code: "passphrase-utf8",
    });
  }
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
let hodlLnCopyIcon = () => "";

// A 24-word seed phrase is a few hundred characters; past this bound the
// text is a mispaste (a whole file, not a phrase), refused before any
// normalizing or deriving.
const LN_SEED_MAX_LENGTH = 4096;

export function hodlLnKeyWipeMem() {
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

// The full wipe: key material and the pasted invoice. Clear, End Session
// and pagehide call this; a format, network or coin-type change only wipes
// the key side (hodlLnKeyWipeMem), so a pasted invoice survives it.
export function hodlLnWipeMem() {
  hodlLnKeyWipeMem();
  hodlLnInvWipeMem();
}

const hodlLnFormat = () => (document.getElementById("ln-format")?.value === "bip39" ? "bip39" : "aezeed");
const hodlLnCoinType = () => (document.getElementById("ln-network")?.value === "testnet" ? 1 : 0);

const hodlLnNormalize = (text) => String(text || "").trim().toLowerCase().replace(/[^a-z\s]/g, " ").split(/\s+/).filter(Boolean);

const hodlLnBirthdayIso = (timestamp) => new Date(timestamp * 1000).toISOString().slice(0, 10);

const hodlLnPrivateField = (id, label, value) => `<div class="private-field is-revealed" data-private-field><p class="label copy-field-label">${escapeHtml(label)}${privateCopyButtonHtml(hodlLnCopyIcon)}</p><p class="psbt-kv" id="${id}" data-private-value data-i18n-skip translate="no">${escapeHtml(value)}</p></div>`;

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
  // Every translated string is computed ahead of the template with the
  // helper for its sink (AGENTS.md): hodlT for HTML element content, t for
  // the labels hodlLnPrivateField escapes itself.
  const nodeKeyLabel = hodlT("{implementation} node identity public key", { implementation });
  const pathLabel = hodlT("Identity key path");
  const networkName = aezeed ? (r.coinType === 1 ? t("testnet") : t("mainnet")) : "";
  const pathNote = aezeed
    ? ` · ${hodlT("coin type {coinType} ({network})", { coinType: r.coinType, network: networkName })}`
    : ` · ${hodlT("the LDK node identity does not depend on the network")}`;
  const detailNote = aezeed
    ? `<p class="muted">${hodlT("Internal (key-derivation) version {v} · wallet birthday day {days} ({date} UTC, day 0 = Bitcoin genesis). Rescans from the birthday recover on-chain funds; channel funds need the node's channel backup.", { v: r.internalVersion, days: r.birthdayDays, date: hodlLnBirthdayIso(r.birthdayTimestamp) })}</p>`
    : `<p class="muted">${hodlT("Derived the ldk-node way: BIP39 seed → master key → its private key re-seeds a second BIP32 tree → node secret at")} <code>m/0'</code>.</p>`;
  const revealLabel = aezeed ? hodlT("Reveal the root private key and decoded entropy") : hodlT("Reveal the root private key");
  const entropyLabel = t("Decoded entropy (the BIP32 master seed)");
  const saltLabel = t("Salt");
  const rootXprvLabel = t("BIP32 root private key (xprv)");
  const privateNote = hodlT("The root xprv can spend the node's on-chain wallet. Reveal it only while this file runs offline on an air-gapped computer.");
  const hiddenNote = hodlT("Private material stays hidden until you reveal it.");
  output.innerHTML = `
    <div class="ln-result">
      ${publicFieldHtml(nodeKeyLabel, r.nodePubKey, { id: "ln-node-pubkey", copyIcon: hodlLnCopyIcon })}
      <p class="muted">${pathLabel} ${publicValueHtml(r.path, { clipboard: false })}${pathNote}</p>
      ${detailNote}
      <label class="choice"><input type="checkbox" id="ln-reveal" data-private-reveal ${secrets ? "checked" : ""}> <span>${revealLabel}</span></label>
      ${secrets ? `
        ${aezeed ? `${hodlLnPrivateField("ln-entropy", entropyLabel, hex.encode(r.entropy))}
        ${hodlLnPrivateField("ln-salt", saltLabel, hex.encode(r.salt))}` : ""}
        ${hodlLnPrivateField("ln-root-xprv", rootXprvLabel, r.rootXprv)}
        <p class="muted">${privateNote}</p>` : `<p class="muted">${hiddenNote}</p>`}
    </div>`;
  // The switch reads its own state, not event.target: the conceal-on-leave
  // sweep unticks every switch by replaying a change through this handler.
  // Set the checked property on every render instead of trusting the markup
  // attribute to seed it: the sweep reads the property (and skips a switch
  // whose property is unset), so a re-created switch must always carry a
  // boolean state.
  const revealToggle = document.getElementById("ln-reveal");
  if (revealToggle) {
    revealToggle.checked = hodlLnReveal;
    revealToggle.addEventListener("change", () => {
      hodlLnReveal = revealToggle.checked;
      hodlLnRender();
    });
  }
}

function hodlRunLn() {
  const error = document.getElementById("ln-error");
  const session = document.getElementById("ln-session");
  error.textContent = "";
  hodlLnKeyWipeMem();
  const format = hodlLnFormat();
  try {
    const text = String(document.getElementById("ln-seed").value || "");
    if (text.length > LN_SEED_MAX_LENGTH) {
      throw Object.assign(new Error("Seed text too long."), {
        key: "That seed text is too long ({n} characters). No seed phrase is longer than {max} characters.",
        vars: { n: text.length, max: LN_SEED_MAX_LENGTH },
        code: "seed-too-long",
      });
    }
    const words = hodlLnNormalize(text);
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
    session.textContent = t("Node key derived. Decoded key material stays in page memory until you clear it.");
    hodlLnJournalLog("derive", `${format} ${hodlLnLast.nodePubKey.slice(0, 8)}`, "ln");
  } catch (exception) {
    hodlLnKeyWipeMem();
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
      ? t("The 24-word cipher seed LND printed at wallet creation.")
      : t("A 12 to 24 word BIP-39 seed phrase, as used by ldk-node.");
  }
}

// ── Invoice / offer card (#ln-inv-card) ─────────────────────────────────────

let hodlLnInvLast = null;
let hodlLnInvReveal = false;
let hodlLnInvQrSvg = () => "";

// BOLT12 has no checksum and no length cap; bound the paste so a mispaste
// (a whole file) is refused before any parsing.
const LN_INV_MAX_LENGTH = 100000;

// Genesis block hashes in BOLT12's byte order (the reverse of the displayed
// hash), for the BOLT12 chain warning.
const reverseHex = (value) => value.match(/../g).reverse().join("");
const LN_INV_CHAIN_HASHES = {
  mainnet: reverseHex("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"),
  testnet: reverseHex("000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943"),
  signet: reverseHex("00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6"),
  regtest: reverseHex("0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"),
};

const lnInvChainName = (hash) => {
  for (const [name, known] of Object.entries(LN_INV_CHAIN_HASHES)) if (known === hash) return name;
  return hash;
};

// The page's network, injected by app.js (hodlInspectorNetwork). The LND
// coin-type select is a derivation setting, not the page network: reading it
// here made a signet or regtest page look like mainnet, and a signet or
// regtest invoice look like a mismatch.
let hodlLnInvPageNetwork = () => "mainnet";

const LN_INV_NETWORKS = ["mainnet", "testnet", "signet", "regtest"];

const lnInvPageNetwork = () => {
  let value;
  try {
    value = hodlLnInvPageNetwork();
  } catch {
    return "mainnet";
  }
  return LN_INV_NETWORKS.includes(value) ? value : "mainnet";
};

// The decoder names the network the invoice is for; the page names its own.
// Both use the same vocabulary (mainnet, testnet, signet, regtest), but a
// decoder that returns an alias (bitcoin, bc, tb, tbs, bcrt) must not make a
// matching invoice look wrong. Normalize, and fail closed (warn) on unknown.
const LN_INV_NETWORK_ALIASES = {
  bitcoin: "mainnet",
  bc: "mainnet",
  mainnet: "mainnet",
  testnet: "testnet",
  tb: "testnet",
  signet: "signet",
  tbs: "signet",
  regtest: "regtest",
  bcrt: "regtest",
};
export const lnInvNetworkName = (value) => LN_INV_NETWORK_ALIASES[value] || String(value);

const lnInvFormatMsat = (msat) => {
  const value = BigInt(msat);
  const btc = value / 100000000000n;
  const frac = (value % 100000000000n).toString().padStart(11, "0").replace(/0+$/, "");
  return frac ? `${btc}.${frac} BTC` : `${btc} BTC`;
};

const lnInvFormatUtc = (seconds) => {
  const date = new Date(Number(seconds) * 1000);
  return Number.isNaN(date.getTime()) ? String(seconds) : date.toISOString().replace(".000Z", "Z");
};

const lnInvRow = (label, valueHtml) => `<p class="psbt-kv"><span class="label">${label}</span> ${valueHtml}</p>`;

const lnInvCopy = (id, value) => `<button type="button" class="btn" id="${id}" data-copy="${escapeHtml(value)}" aria-label="${escapeHtml(t("Copy"))}">${hodlLnCopyIcon()}</button>`;

// Drops the decoded result and its rendering. The pasted text belongs to the
// caller: a decode keeps it, Clear and the session wipe empty it too.
function hodlLnInvReset() {
  hodlLnInvLast = null;
  hodlLnInvReveal = false;
  const out = document.getElementById("ln-inv-out");
  if (out) out.innerHTML = "";
  const error = document.getElementById("ln-inv-error");
  if (error) error.textContent = "";
}

// Clear, End Session and pagehide all land here: the pasted invoice is a
// payment request and must not outlive the session.
function hodlLnInvWipeMem() {
  hodlLnInvReset();
  const input = document.getElementById("ln-inv-input");
  if (input) input.value = "";
}

function hodlLnInvRender() {
  const out = document.getElementById("ln-inv-out");
  if (!out) return;
  if (!hodlLnInvLast) {
    out.innerHTML = "";
    return;
  }
  const r = hodlLnInvLast;
  const pageNetwork = lnInvPageNetwork();
  const parts = [];
  if (r.kind === "bolt11") {
    parts.push(`<div class="edge-note ln-inv-states" data-ln-inv-kind="invoice">
      <p data-ln-inv-state="checksum">${hodlT("Present — checksum verifies.")}</p>
      <p data-ln-inv-state="structure">${hodlT("Structurally valid — required fields present.")}</p>
      ${r.signatureValid ? `<p class="ok" data-ln-inv-state="signature">${hodlT("Signature valid — verifies against recovered node id.")}</p>` : ""}
    </div>`);
    if (lnInvNetworkName(r.network) !== pageNetwork) {
      parts.push(`<p class="warn" data-ln-inv-warning="network">${hodlT("This invoice is for Bitcoin {network}, but page network is {pageNetwork}.", { network: lnInvNetworkName(r.network), pageNetwork })}</p>`);
    }
    parts.push(lnInvRow(hodlT("Amount"), r.amountMsat === null
      ? hodlT("No amount set — payer chooses.")
      : `${escapeHtml(lnInvFormatMsat(r.amountMsat))} (${escapeHtml(r.amountMsat)} msat)`));
    if (r.description !== null) parts.push(lnInvRow(hodlT("Description"), escapeHtml(r.description)));
    if (r.descriptionHash) parts.push(lnInvRow(hodlT("Description hash"), `<code>${escapeHtml(r.descriptionHash)}</code>`));
    parts.push(lnInvRow(hodlT("Payment hash"), `<code>${escapeHtml(r.paymentHash)}</code> ${lnInvCopy("ln-inv-payment-hash", r.paymentHash)}`));
    parts.push(lnInvRow(hodlT("Node id (recovered)"), `<code>${escapeHtml(r.nodeId)}</code> ${lnInvCopy("ln-inv-node-id", r.nodeId)}`));
    parts.push(lnInvRow(hodlT("Created (UTC)"), escapeHtml(lnInvFormatUtc(r.timestamp))));
    parts.push(lnInvRow(hodlT("Expiry"), r.expiry === null ? "—" : `${escapeHtml(String(r.expiry))} s`));
    parts.push(lnInvRow(hodlT("Min final CLTV delta"), r.minFinalCltvExpiry === null ? "—" : escapeHtml(String(r.minFinalCltvExpiry))));
    parts.push(lnInvRow(hodlT("Fallback addresses"), r.fallbacks.length
      ? r.fallbacks.map((f) => escapeHtml(`${f.kind} ${f.program}`)).join("<br>")
      : "—"));
    parts.push(lnInvRow(hodlT("Route hints"), `${escapeHtml(String(r.routeHintHops))} ${hodlT("hop(s) (not resolved)")}`));
    parts.push(lnInvRow(hodlT("Feature bits"), r.features ? `<code>${escapeHtml(r.features)}</code>` : "—"));
    parts.push(lnInvRow(hodlT("Unknown fields skipped"), r.unknownTags.length ? escapeHtml(r.unknownTags.join(", ")) : "—"));
    if (r.paymentSecret) {
      parts.push(`<label class="choice"><input type="checkbox" id="ln-inv-reveal" data-private-reveal ${hodlLnInvReveal ? "checked" : ""}> <span>${hodlT("Reveal the payment secret")}</span></label>`);
      if (hodlLnInvReveal) {
        parts.push(`<p class="psbt-kv">${hodlT("Payment secret")} <code data-private-value data-i18n-skip translate="no">${escapeHtml(r.paymentSecret)}</code> ${lnInvCopy("ln-inv-payment-secret", r.paymentSecret)}</p>`);
      } else {
        parts.push(`<p class="muted">${hodlT("The payment secret stays hidden until you reveal it.")}</p>`);
      }
    }
  } else {
    const kindKey = r.hrp === "lno" ? "offer" : r.hrp === "lnr" ? "invoice-request" : "invoice";
    const kindNoun = r.hrp === "lno" ? t("Offer") : r.hrp === "lnr" ? t("Invoice request") : t("Invoice");
    parts.push(`<div class="edge-note ln-inv-states" data-ln-inv-kind="${kindKey}">
      <p data-ln-inv-state="checksum">${hodlT("Present — no checksum (BOLT12 omits it).")}</p>
      <p data-ln-inv-state="structure">${hodlT("Structurally valid — required fields present.")}</p>
      <p class="muted" data-ln-inv-state="signature">${hodlT("Signature not checked — never marks BOLT12 verified.")}</p>
    </div>`);
    // BOLT12: an absent offer_chains means the offer is for bitcoin
    // (mainnet) only. Treat "no chain field" as the mainnet chain so a
    // chainless offer warns on a testnet page.
    const chains = r.fields.chains || (r.fields.chain ? [r.fields.chain] : [LN_INV_CHAIN_HASHES.mainnet]);
    if (!chains.includes(LN_INV_CHAIN_HASHES[pageNetwork])) {
      parts.push(`<p class="warn" data-ln-inv-warning="chain">${hodlT("This invoice is for Bitcoin {network}, but page network is {pageNetwork}.", { network: chains.map(lnInvChainName).join(", "), pageNetwork })}</p>`);
    }
    parts.push(lnInvRow(hodlT("Kind"), escapeHtml(kindNoun)));
    const visibility = bolt12RecipientVisibility(r.fields);
    if (visibility.kind === "blinded") {
      parts.push(`<p class="edge-note" data-ln-inv-visibility="blinded">${hodlT("Recipient node id is not in this {kind} (blinded paths).", { kind: kindNoun })}</p>`);
    } else if (visibility.kind === "published") {
      parts.push(`<p class="warn" data-ln-inv-warning="published-key" data-ln-inv-visibility="published">${hodlT("No blinded path — this {kind} publishes its signing key in the clear. That is a signing key, not a destination.", { kind: kindNoun })}</p>`);
    } else {
      parts.push(`<p class="muted" data-ln-inv-visibility="none">${hodlT("No recipient information in this {kind}.", { kind: kindNoun })}</p>`);
    }
    parts.push(lnInvRow(hodlT("Blinded paths"), `${escapeHtml(String(visibility.pathCount))} ${hodlT("(counted, never followed)")}`));
    if (r.fields.amount !== undefined) parts.push(lnInvRow(hodlT("Amount"), `${escapeHtml(r.fields.amount)} msat`));
    if (r.fields.description !== undefined) parts.push(lnInvRow(hodlT("Description"), escapeHtml(r.fields.description)));
    if (r.fields.currency !== undefined) parts.push(lnInvRow(hodlT("Currency"), escapeHtml(r.fields.currency)));
    if (r.fields.issuer !== undefined) parts.push(lnInvRow(hodlT("Issuer"), escapeHtml(r.fields.issuer)));
    if (r.fields.issuerId !== undefined) parts.push(lnInvRow(hodlT("Issuer signing key"), `<code>${escapeHtml(r.fields.issuerId)}</code> ${lnInvCopy("ln-inv-issuer-id", r.fields.issuerId)}`));
    if (r.fields.nodeId !== undefined) parts.push(lnInvRow(hodlT("Invoice node id"), `<code>${escapeHtml(r.fields.nodeId)}</code> ${lnInvCopy("ln-inv-invoice-node-id", r.fields.nodeId)}`));
    if (r.fields.payerId !== undefined) parts.push(lnInvRow(hodlT("Payer id"), `<code>${escapeHtml(r.fields.payerId)}</code>`));
    if (r.fields.payerNote !== undefined) parts.push(lnInvRow(hodlT("Payer note"), escapeHtml(r.fields.payerNote)));
    if (r.fields.paymentHash !== undefined) parts.push(lnInvRow(hodlT("Payment hash"), `<code>${escapeHtml(r.fields.paymentHash)}</code>`));
    if (r.fields.absoluteExpiry !== undefined) parts.push(lnInvRow(hodlT("Expires"), escapeHtml(lnInvFormatUtc(r.fields.absoluteExpiry))));
    if (r.fields.relativeExpiry !== undefined) parts.push(lnInvRow(hodlT("Expires"), `${escapeHtml(r.fields.relativeExpiry)} s`));
    if (r.fields.createdAt !== undefined) parts.push(lnInvRow(hodlT("Created (UTC)"), escapeHtml(lnInvFormatUtc(r.fields.createdAt))));
    if (r.fields.quantityMax !== undefined) parts.push(lnInvRow(hodlT("Maximum quantity"), escapeHtml(r.fields.quantityMax)));
    if (r.fields.chains !== undefined) parts.push(lnInvRow(hodlT("Chains"), r.fields.chains.map((c) => escapeHtml(lnInvChainName(c))).join("<br>")));
    if (r.fields.chain !== undefined) parts.push(lnInvRow(hodlT("Chain"), escapeHtml(lnInvChainName(r.fields.chain))));
    if (r.unknownOddTypes.length) parts.push(lnInvRow(hodlT("Unknown fields skipped"), escapeHtml(r.unknownOddTypes.join(", "))));
  }
  try {
    const svg = hodlLnInvQrSvg(r.text);
    if (svg) parts.push(`<div class="qr">${svg}</div>`);
  } catch {
    // The QR is a convenience; a renderer failure must never fail the decode.
  }
  out.innerHTML = parts.join("");
  const reveal = document.getElementById("ln-inv-reveal");
  if (reveal) {
    reveal.checked = hodlLnInvReveal;
    reveal.addEventListener("change", () => {
      hodlLnInvReveal = reveal.checked;
      hodlLnInvRender();
    });
  }
}

function hodlRunLnInv() {
  const error = document.getElementById("ln-inv-error");
  const input = document.getElementById("ln-inv-input");
  const text = String(input?.value || "").trim();
  hodlLnInvReset();
  if (!text) {
    if (error) error.textContent = t("Paste an invoice or offer first.");
    return;
  }
  if (text.length > LN_INV_MAX_LENGTH) {
    if (error) error.textContent = t("That string is too long to be an invoice or offer.");
    return;
  }
  try {
    const lower = text.toLowerCase();
    let result;
    if (/^ln(bc|tb|tbs|bcrt)/.test(lower)) {
      result = bolt11Decode(text);
    } else if (/^ln[ori]/.test(lower)) {
      result = bolt12Decode(text);
    } else {
      throw { key: "This is not a Lightning invoice or offer (expected lnbc, lntb, lntbs, lnbcrt, lno, lnr, or lni)." };
    }
    hodlLnInvLast = { ...result, text };
    hodlLnInvRender();
  } catch (exception) {
    hodlLnInvReset();
    if (error) {
      error.textContent = exception && typeof exception.key === "string"
        ? t(exception.key, exception.vars)
        : t("This invoice or offer could not be decoded.");
    }
  }
}

// Wires the Lightning card. `journalLog` is the app's hodlJournalLog; the
// module takes it as an option instead of importing app.js (same shape as
// initPsbtEditor's options object).
export function hodlInitLn({ journalLog, copyIcon = () => "", qrSvg = () => "", pageNetwork = () => "mainnet" } = {}) {
  if (typeof journalLog === "function") hodlLnJournalLog = journalLog;
  hodlLnCopyIcon = copyIcon;
  hodlLnInvQrSvg = typeof qrSvg === "function" ? qrSvg : () => "";
  hodlLnInvPageNetwork = typeof pageNetwork === "function" ? pageNetwork : () => "mainnet";
  const decode = document.getElementById("ln-inv-decode");
  if (decode) decode.onclick = hodlRunLnInv;
  const clear = document.getElementById("ln-inv-clear");
  if (clear) clear.onclick = () => hodlLnInvWipeMem();
  const go = document.getElementById("ln-go");
  if (!go) return;
  go.onclick = hodlRunLn;
  document.getElementById("ln-wipe").onclick = () => {
    hodlLnWipeMem();
    for (const id of ["ln-seed", "ln-pass"]) {
      const field = document.getElementById(id);
      if (field) field.value = "";
    }
    document.getElementById("ln-out").innerHTML = "";
    document.getElementById("ln-error").textContent = "";
    document.getElementById("ln-session").textContent = t("Accessible fields were cleared (best effort).");
  };
  for (const id of ["ln-format", "ln-network"]) {
    document.getElementById(id)?.addEventListener("change", () => {
      // A stale result next to a flipped select is how a correct seed looks
      // wrong (a mainnet pubkey beside "Testnet"): wipe and re-render on any
      // format or network change. The invoice card is not key material: it
      // survives, and is re-rendered so its network warning matches the page.
      hodlLnKeyWipeMem();
      hodlLnRender();
      hodlLnSyncFormat();
      hodlLnInvRender();
    });
  }
  document.getElementById("ln-session").textContent = t("No node key derived. Enter a seed phrase and derive.");
  hodlLnSyncFormat();
}
