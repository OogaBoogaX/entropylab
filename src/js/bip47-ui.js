// Pure render helpers for the BIP-47 station (preview only). No DOM lookups
// and no state: every value is escaped, and the caller owns the data.
//
// Translated text is hoisted out of the HTML templates and escaped here, so
// no `t()` call ever sits inside a template literal (the i18n attribute guard
// refuses that: a catalog value must never reach markup unescaped).
import { t } from "./i18n.js";
import { hodlEscapeHtmlText } from "./i18n-sanitize.js";
import { publicFieldHtml, publicValueHtml } from "./public-data.js";
import { addressQrButtonHtml } from "./address-qr.js";
import { Bip47Error, bip47NotificationAddress, bytesToHex } from "./bip47.js";

const escape = (value) => hodlEscapeHtmlText(String(value ?? ""));
const copyIconOf = (icons) => icons?.copy ?? (() => "");
const hexByte = (value) => `0x${Number(value).toString(16).padStart(2, "0")}`;

// The payment code and its notification address are public readouts. The QR
// button takes the label clipboard's place, and the code is shown in full:
// an ellipsis would hide bytes the user is meant to hand over.
export const bip47OwnHtml = ({ code, notificationAddress, network, path } = {}, icons = {}) => {
  const copyIcon = copyIconOf(icons);
  const codeName = t("Payment code");
  const addressName = t("Notification address");
  const notice = t("Used only for BIP-47 notification transactions, which leave an on-chain link to this address. Use the derived payment addresses for ordinary payments.");
  const codeLabel = escape(codeName) + (path ? ` <code>${escape(path)}</code>` : "");
  const addressLabel = `${escape(addressName)} <span class="muted">${escape(network)}</span>`;
  const codeQr = addressQrButtonHtml(code, codeName);
  const addressQr = addressQrButtonHtml(notificationAddress, addressName);
  return [
    `<div data-bip47-value="code">${publicFieldHtml(codeLabel, code, { copyIcon, qrHtml: codeQr })}</div>`,
    `<div data-bip47-value="notification-address">${publicFieldHtml(addressLabel, notificationAddress, { copyIcon, qrHtml: addressQr })}</div>`,
    `<p class="edge-note is-info">${escape(notice)}</p>`,
  ].join("");
};

// A decoded contact code: parse validity, derivation eligibility and the
// notification address for the selected network. The address is asked of the
// engine, so a code it will not derive shows none rather than a guess.
export const bip47ContactHtml = (decoded, network, icons = {}) => {
  const copyIcon = copyIconOf(icons);
  const derivable = decoded?.derivable === true;
  let notificationAddress = "";
  if (derivable) {
    try { notificationAddress = bip47NotificationAddress(decoded, network); } catch { notificationAddress = ""; }
  }
  const yes = t("Yes"), no = t("No");
  const validName = t("Valid"), derivableName = t("Derivable"), addressName = t("Notification address");
  const detailsName = t("Payment code details");
  const fact = (name, status, labelHtml, valueHtml) =>
    `<div data-bip47-fact="${name}" data-bip47-status="${status}"><p class="label">${labelHtml}</p>${valueHtml}</div>`;
  const addressValue = notificationAddress
    ? publicFieldHtml(`${escape(addressName)} <span class="muted">${escape(network)}</span>`, notificationAddress, { copyIcon, qrHtml: addressQrButtonHtml(notificationAddress, addressName) })
    : `<p class="mono">${escape("\u2014")}</p>`;
  const rows = [];
  if (decoded?.publicKey instanceof Uint8Array) rows.push([t("Public key"), bytesToHex(decoded.publicKey)]);
  if (decoded?.chainCode instanceof Uint8Array) rows.push([t("Chain code"), bytesToHex(decoded.chainCode)]);
  if (Number.isInteger(decoded?.version)) rows.push([t("Version"), hexByte(decoded.version)]);
  if (Number.isInteger(decoded?.features)) rows.push([t("Features"), hexByte(decoded.features)]);
  if (decoded?.reservedBytes instanceof Uint8Array) rows.push([t("Reserved bytes"), bytesToHex(decoded.reservedBytes)]);
  const details = rows.length
    ? `<details class="derivation-advanced"><summary>${escape(detailsName)}</summary><dl>${rows.map(([label, value]) => `<dt>${escape(label)}</dt><dd><code>${escape(value)}</code></dd>`).join("")}</dl></details>`
    : "";
  return [
    fact("valid", "yes", escape(validName), `<p class="mono">${escape(yes)}</p>`),
    fact("derivable", derivable ? "yes" : "no", escape(derivableName), `<p class="mono">${escape(derivable ? yes : no)}</p>`),
    // The readout carries its own label (with the network and QR), so the fact
    // adds none; without an address, the plain label and a dash stand in.
    notificationAddress
      ? `<div data-bip47-fact="notification-address" data-bip47-status="yes">${addressValue}</div>`
      : fact("notification-address", "no", escape(addressName), addressValue),
    details,
  ].join("");
};

// A Bip47Error code (or the engine's own message) is shown as text, never as
// markup, and never as a claim about what the code is.
export const bip47ErrorHtml = (code) => {
  // A translation may put {code} mid-sentence: keep the text on both sides.
  const [lead, tail = ""] = t("This payment code could not be read: {code}", { code: "\u0000" }).split("\u0000");
  return `<p class="err" role="alert">${escape(lead)}<code>${escape(code)}</code>${escape(tail)}</p>`;
};

// One row builder for both directions. Rows keep their real derivation index;
// skipped indexes are listed, never renumbered. Receive rows can reveal one
// spending key at a time, built by the app's private helpers (passed in, so
// this module stays pure and never holds key material itself).
export const bip47RowsHtml = ({ direction, rows = [], skipped = [], budgetExhausted = false, revealed = null } = {}, icons = {}) => {
  const copyIcon = copyIconOf(icons);
  const privateValue = typeof icons?.privateValue === "function" ? icons.privateValue : () => "";
  const privateCopy = typeof icons?.privateCopy === "function" ? icons.privateCopy : () => "";
  const dir = direction === "receive" ? "receive" : "send";
  const indexName = t("Index");
  const skippedName = t("Skipped indexes: {list}", { list: skipped.join(", ") });
  const budgetName = t("Too many indexes were skipped in a row. Try a later start index.");
  const keysName = t("Spending keys");
  const showKeyName = t("Show key");
  const hideKeyName = t("Hide key");
  // The payment code is the account's public key and chain code, and the
  // payer knows this row's shared secret: with this key they could rebuild
  // the BIP-47 account key, so the note says plainly not to share it
  // (owner-approved wording, 2026-10-28).
  const privateNote = t("This private key can spend funds sent to this receive address. Never share it: the person who paid you here can combine it with your payment code to rebuild your BIP-47 account key and spend every BIP-47 payment you have received. Hiding it does not clear your clipboard.");
  const revealedIndex = revealed && Number.isInteger(revealed.index) ? revealed.index : null;
  // The standard field pattern: the index label with its QR, the address
  // under it, so the QR never wraps away from the address on a phone.
  const rowHtml = (row) => {
    const index = Number(row?.index);
    const address = String(row?.address ?? "");
    const label = `${indexName} ${index}`;
    return `<div class="bip47-row" data-row-index="${escape(index)}" data-direction="${dir}">`
      + publicFieldHtml(escape(label), address, { copyIcon, qrHtml: addressQrButtonHtml(address, label) })
      + `</div>`;
  };
  // Each key control names its row's index, so it is clear which key it shows.
  const keyHtml = (row) => {
    const index = Number(row?.index);
    const label = `${indexName} ${index}`;
    if (revealedIndex === index && revealed.wif) {
      const copyLabel = t("Copy {label}", { label });
      return `<div data-bip47-key-index="${escape(index)}">`
        + `<p class="private-field is-revealed" data-private-field><span class="label copy-field-label">${escape(label)}${privateCopy({ label: copyLabel })}</span>${privateValue(revealed.wif, "secret private-field-value", true)}</p>`
        + `<button class="btn" type="button" data-bip47-conceal>${escape(hideKeyName)}</button>`
        + `</div>`;
    }
    return `<div class="row" data-bip47-key-index="${escape(index)}"><span class="label">${escape(label)}</span>`
      + `<button class="btn" type="button" data-bip47-reveal="${escape(index)}">${escape(showKeyName)}</button></div>`;
  };
  const skippedHtml = skipped.length
    ? `<p class="field-note" data-bip47-skipped>${escape(skippedName)}</p>`
    : "";
  const budgetHtml = budgetExhausted
    ? `<p class="err" data-bip47-budget>${escape(budgetName)}</p>`
    : "";
  const keysHtml = dir === "receive"
    ? `<details class="derivation-advanced" data-bip47-keys${revealedIndex !== null ? " open" : ""}><summary>${escape(keysName)}</summary>`
      + `<p class="edge-note is-private">${escape(privateNote)}</p>`
      + rows.map(keyHtml).join("")
      + `</details>`
    : "";
  return rows.map(rowHtml).join("") + skippedHtml + budgetHtml + keysHtml;
};

// The manual override's input picker: one option per parsed input, its value
// the zero-based index and its text the display-order outpoint. Nothing is
// selected, so the engine's input-0 fallback is never reached by accident.
export const bip47NotifyInputsHtml = (inputs = []) => (Array.isArray(inputs) ? inputs : []).map((input, index) => {
  const txid = bytesToHex((input?.txid instanceof Uint8Array ? input.txid : new Uint8Array(32)).slice().reverse());
  const vout = Number.isInteger(input?.vout) ? input.vout : 0;
  const text = `${index}: ${txid}:${vout}`;
  return `<option value="${escape(index)}">${escape(text)}</option>`;
}).join("");

// The notification check's report. Two independent result rows, never merged
// into a success banner: a recovered code with no matching output stays
// unverified, and neither result establishes ownership, intent, confirmation
// or validity. A manual report is wrapped so every value it shows is marked
// unverified.
export const bip47NotifyHtml = (result = {}, { manual = false } = {}) => {
  const status = result?.status;
  const manualNote = t("Unverified override: this check uses the public key and input you selected. It does not verify that the key belongs to that input.");
  const wrap = (html) => (manual ? `<div data-bip47-manual><p class="edge-note is-info">${escape(manualNote)}</p>${html}</div>` : html);
  const errorHtml = (name, message) => `<p class="err" data-bip47-notify-error="${escape(name)}">${escape(message)}</p>`;
  if (status === "manual-needed") {
    return wrap(errorHtml("manual-needed", t("No input exposing a public key was found. Use the manual override.")));
  }
  if (status === "manual-invalid") {
    return wrap(errorHtml("manual-invalid", t("The manual public key is not a valid public key.")));
  }
  if (status === "unsupported-version") {
    return wrap(errorHtml("unsupported-version", t("Unsupported payment code version {version}.", { version: String(result?.version ?? "") })));
  }
  if (status !== "ok" && status !== "undecodable") return "";
  const inputName = t("Input");
  const outpointName = t("Outpoint");
  const pubkeyName = t("Public key");
  const methodName = t("Method");
  const codeName = t("Payment code");
  const recoveredName = t("Valid code recovered");
  const paysName = t("Output to this notification address");
  const yes = t("Yes"), no = t("No"), present = t("Present"), absent = t("Absent");
  const useName = t("Use as contact");
  const limit = t("These results describe the pasted transaction only. They do not establish ownership, the intended recipient, confirmation or transaction validity.");
  const fact = (name, label, value) =>
    `<div data-bip47-fact="${name}"><p class="label">${escape(label)}</p><p class="mono">${escape(value)}</p></div>`;
  const codeRecovered = result?.codeRecovered === true;
  const pays = result?.hasOutputToNotificationAddress === true;
  const outpoint = `${String(result?.designatedDisplayTxid ?? "")}:${String(result?.designatedVout ?? "")}`;
  const facts = [
    fact("input", inputName, String(result?.inputIndex ?? "")),
    fact("outpoint", outpointName, outpoint),
    fact("pubkey", pubkeyName, String(result?.publicKeyHex ?? "")),
    fact("method", methodName, String(result?.kind ?? "")),
  ].join("");
  const rows = [
    `<p data-result="code-recovered" data-status="${codeRecovered ? "yes" : "no"}">${escape(recoveredName)}: ${escape(codeRecovered ? yes : no)}</p>`,
    `<p data-result="pays-notification-address" data-status="${pays ? "present" : "absent"}">${escape(paysName)}: ${escape(pays ? present : absent)}</p>`,
  ].join("");
  const codeHtml = result?.code
    ? `<div data-bip47-notify-code>${publicValueHtml(result.code, { label: codeName, copyIcon: () => "", clipboard: false })}<button class="btn" type="button" data-bip47-use-code>${escape(useName)}</button></div>`
    : "";
  return wrap(facts + rows + codeHtml + `<p class="field-note">${escape(limit)}</p>`);
};

// A failed check: an ambiguous payload has its own message, anything else (a
// parse error, BAD_INDEX) the generic one. The raw transaction and the
// engine's own message are never echoed; the hook names the code, or "parse".
export const bip47NotifyErrorHtml = (error) => {
  const raw = error instanceof Bip47Error ? error.code : "";
  const code = typeof raw === "string" && /^[A-Z][A-Z0-9_]*$/.test(raw) ? raw : "parse";
  const message = code === "AMBIGUOUS_PAYLOAD"
    ? t("This transaction does not carry exactly one 80-byte payment-code payload.")
    : t("This transaction could not be read.");
  return `<p class="err" data-bip47-notify-error="${escape(code)}">${escape(message)}</p>`;
};
