import { sha256 as hodlSha256 } from "./hashes.js";
// secp256k1 operations run in the libsecp256k1 WebAssembly module; the facade
// is a drop-in for the noble/curves surface this file uses (see
// src/js/secp256k1.js). App boot waits for the module to be ready.
import { secp256k1 as hodlSecp256k1, secp256k1Ready } from "./secp256k1.js";
import {
  createLabeledSilentPaymentAddress,
  createSilentPaymentOutputs,
  decodeSilentPaymentAddress,
  encodeSilentPaymentAddress,
  encodeSpscan,
  encodeSpspend,
  formatSpDescriptor,
  hrpForNetwork as hodlSpHrp,
  p2trAddressFromXonly,
  scanSilentPaymentOutputs,
  spendPrivForOutput,
  bytesToHex as hodlSpBytesToHex,
} from "./bip352.js";
import {
  bip353Lookup,
  encodeBitcoinUri,
  encodeBip353Txt,
  parseRecipientLines,
} from "./bip321.js";
import { inspectPsbtInscriptions, describeEnvelope } from "./inscription.js";
import { parseOpReturn, describeOpReturn } from "./opreturn.js";
import { parseRawTx, extractEcdsaSignatures, inscriptionHints, isPsbtMagic, serializeTx } from "./tx.js";
import { wasmExports as hodlWasm, withInput as hodlWasmIn, withOutput as hodlWasmOut } from "./entropylab-wasm.js";
import { indexHdKey, indexSingleKey, matchOwnership, pathLabel } from "./ownership.js";
import { hex as hodlHex } from "./coders.js";
import { addressFor, addressFromScript, descriptorDerive, p2shP2wpkhScript, p2shScript, p2trKeyScript, p2wshScript } from "./addresses.js";
import { base58checkDecode, base58checkEncode } from "./base58.js";
import { HDKey as hodlHDKey } from "./hdkey.js";
import { entropyToMnemonic as hodlEntropyToMnemonic, mnemonicToEntropy as hodlMnemonicToEntropy, mnemonicToSeedSync as hodlMnemonicToSeed, validateMnemonic as hodlIsValidMnemonic } from "./bip39.js";
import { wordlist as bip39English } from "./bip39-english.js";
// The PSBT editor (its own workspace tab) drives the rust-bitcoin WASM
// bindings in psbt-wasm.js; heavy lifting lives in psbt-editor.js.
import { initPsbtEditor } from "./psbt-editor.js";
import { initQrReferences } from "./qr-references.js";
import { renderSVG as hodlUqrRenderSvg } from "uqr";
import { BIP39_LANGUAGE_ENGLISH, BIP85_APPS, bip85Path, deriveApplication, parseChildIndex, wipeBip85Result, wipeBytes as hodlWipeBytes } from "./bip85.js";
import { VANITY_HARDENED, VANITY_MAX_INDEX, VANITY_METHODS, VANITY_SCRIPTS, VanityGrinder, estimateVanityWork, validateVanityIndexRange, validateVanityMnemonic, validateVanityPassphrase, validateVanityPrefix, validateVanityRange, vanityBenchmark, vanityPathIndexes, vanityPathString } from "./vanity.js";
import { tHtml as hodlT, t as hodlTText, tAttr as hodlTAttr, hodlInitLocale, hodlFillLocaleSelect, hodlGetLocale } from "./i18n.js";
import { hodlSanitizeCatalogHtml } from "./i18n-sanitize.js";
import hodlShellHtml from "../shell.html";
import { hodlKeyModeLabels, hodlNetworkNames, hodlHexFormatLabels, hodlScriptBeginnerTexts, hodlFairnessVerdictLabels } from "./i18n-labels.js";
import {
  METHOD_LABELS as hodlJournalMethodLabels,
  PASSWORD_MIN_LENGTH as hodlJournalPasswordMinLength,
  addEntry as hodlJournalAddEntry,
  appendLog as hodlJournalAppend,
  createDocument as hodlJournalCreateDocument,
  createJournal,
  defaultJournalPageStyle as hodlJournalDefaultPageStyle,
  formatLog as hodlJournalFormatLog,
  formatNotebook as hodlJournalFormatNotebook,
  formatStamp as hodlJournalStamp,
  openDocument as hodlJournalOpenDocument,
  openExport as hodlJournalOpenExport,
  removeEntry as hodlJournalRemoveEntry,
  replaceEntry as hodlJournalReplaceEntry,
  searchEntries as hodlJournalSearch,
  sealDocument as hodlJournalSealDocument,
  sealExport as hodlJournalSealExport,
  snapshotFromKeyState as hodlJournalKeySnapshot,
  snapshotSession as hodlJournalSnapshot,
  wipeBytes as hodlJournalWipeBytes,
  wipeDocument as hodlJournalWipeDocument,
  journalFromPlainText as hodlJournalFromPlainText,
  journalKeyReferenceToken as hodlJournalKeyReferenceToken,
  journalNotebookRuns as hodlJournalNotebookRuns,
  normalizeJournalPageStyle as hodlNormalizeJournalPageStyle,
  parseNotebook as hodlParseNotebook,
  serializeNotebook as hodlSerializeNotebook,
  wipeJournal,
} from "./journal.js";
import { keyVaultIdentity, parseKeyVault, serializeKeyVault } from "./keymanager.js";
const hodlBip39Wordlist = Object.freeze(bip39English);
function hodlNote(key, vars) {
  return vars == null ? { key } : { key, vars };
}
function hodlNoteKey(message) {
  return message && typeof message === "object" ? String(message.key || "") : "";
}
function hodlFormatNote(message) {
  if (message == null) return "";
  if (typeof message === "string") return message;
  if (typeof message !== "object" || typeof message.key !== "string") return String(message);
  let vars = message.vars;
  if (vars) {
    let formatted = {};
    for (let name of Object.keys(vars)) {
      let value = vars[name];
      formatted[name] = value && typeof value === "object" && typeof value.key === "string" ? hodlFormatNote(value) : value;
    }
    vars = formatted;
  }
  return hodlTText(message.key, vars);
}
function hodlError(key, vars) {
  let err = new Error(hodlTText(key, vars));
  err.hodlSpec = vars == null ? { key } : { key, vars };
  return err;
}
function hodlErrorSpecFrom(error, fallbackKey) {
  if (error && error.hodlSpec && typeof error.hodlSpec.key === "string") return error.hodlSpec;
  if (error && typeof error === "object" && typeof error.key === "string") return error.vars == null ? { key: error.key } : { key: error.key, vars: error.vars };
  if (error == null) return fallbackKey ? { key: fallbackKey } : null;
  return { raw: error instanceof Error ? error.message : String(error) };
}
function hodlFormatErrorSpec(spec) {
  if (!spec) return "";
  if (spec.key) return hodlTText(spec.key, spec.vars);
  return spec.raw || "";
}
var hodlKeyErrorSpec = null, hodlMsigErrorSpec = null;
function hodlSetWorkspaceError(kind, spec) {
  if (kind === "msig") hodlMsigErrorSpec = spec || null;
  else hodlKeyErrorSpec = spec || null;
  let el = document.getElementById(kind === "msig" ? "msig-error" : "error");
  if (el) el.textContent = hodlFormatErrorSpec(spec);
}
function hodlRefreshWorkspaceErrors() {
  hodlSetWorkspaceError("key", hodlKeyErrorSpec);
  hodlSetWorkspaceError("msig", hodlMsigErrorSpec);
}
function hodlDiceEntropyBits(e) {
  return e <= 0 ? 0 : e * Math.log2(6);
}
function hodlSplitDiceString(e) {
  let t = [], r = "";
  for (let n of e) /\s|,|;|\|/.test(n) || (n >= "1" && n <= "6" ? t.push(n) : r += n);
  return { rolls: t, leftover: r };
}
function hodlBitBoxLookupWord(e, t) {
  let r = 0;
  for (let n of e) r = r * 4 + (n - 1);
  return r = r * 2 + t, hodlBip39Wordlist[r];
}
function hodlNormalizeMnemonicText(e) {
  return e.trim().toLowerCase().replace(/[^a-z\s]/g, " ").split(/\s+/).filter(Boolean).join(" ");
}
function hodlValidateMnemonic(e) {
  let t = hodlNormalizeMnemonicText(e).split(" ").filter(Boolean), r = t.map((o, i) => ({ index: i, word: o })).filter(({ word: o }) => !hodlBip39Wordlist.includes(o));
  if (t.length === 0) return { ok: false, words: t, error: { key: "Type or paste your seed phrase." }, unknown: r };
  if (![12, 15, 18, 21, 24].includes(t.length)) return { ok: false, words: t, unknown: r, error: { key: "A seed phrase is 12, 15, 18, 21, or 24 words. You entered {n}.", vars: { n: t.length } } };
  if (r.length > 0) return { ok: false, words: t, unknown: r, error: { key: "Word {n} (“{word}”) is not on the BIP39 English list.", vars: { n: r[0].index + 1, word: r[0].word } } };
  let n = t.join(" ");
  return hodlIsValidMnemonic(n, hodlBip39Wordlist) ? { ok: true, words: t, unknown: r } : { ok: false, words: t, unknown: r, error: { key: "Words are on the list, but the checksum does not match. One of the words is wrong, or this is not a BIP39 phrase." } };
}
function hodlLastWordCandidates(e) {
  let t = hodlNormalizeMnemonicText(e).split(" ").filter(Boolean), n = { 11: 12, 14: 15, 17: 18, 20: 21, 23: 24 }[t.length];
  if (!n) return null;
  let o = t.filter((s) => !hodlBip39Wordlist.includes(s));
  if (o.length > 0) return { partialCount: t.length, completeCount: n, candidates: [], error: `\u201C${o[0]}\u201D is not on the BIP39 English list.` };
  let i = [];
  for (let s of hodlBip39Wordlist) hodlIsValidMnemonic([...t, s].join(" "), hodlBip39Wordlist) && i.push(s);
  return { partialCount: t.length, completeCount: n, candidates: i };
}
var hodlBase58Check = { encode: base58checkEncode, decode: base58checkDecode }, hodlSecp256k1Order = BigInt("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"), hodlScriptTypes = [{ id: "bip44", bip: "BIP44", label: "Legacy", short: "Legacy 1\u2026", beginner: hodlScriptBeginnerTexts.bip44, script: "p2pkh", purpose: 44, slip: "x" }, { id: "bip49", bip: "BIP49", label: "Nested SegWit", short: "Nested 3\u2026", beginner: hodlScriptBeginnerTexts.bip49, script: "p2sh-p2wpkh", purpose: 49, slip: "y" }, { id: "bip84", bip: "BIP84", label: "Native SegWit", short: "SegWit bc1q\u2026", beginner: hodlScriptBeginnerTexts.bip84, script: "p2wpkh", purpose: 84, slip: "z" }, { id: "bip86", bip: "BIP86", label: "Taproot", short: "Taproot bc1p\u2026", beginner: hodlScriptBeginnerTexts.bip86, script: "p2tr", purpose: 86, slip: "x" }], hodlExtendedKeyVersions = { mainnet: { x: { pub: 76067358, prv: 76066276, pubName: "xpub", prvName: "xprv" }, y: { pub: 77429938, prv: 77428856, pubName: "ypub", prvName: "yprv" }, z: { pub: 78792518, prv: 78791436, pubName: "zpub", prvName: "zprv" } }, testnet: { x: { pub: 70617039, prv: 70615956, pubName: "tpub", prvName: "tprv" }, y: { pub: 71979618, prv: 71978536, pubName: "upub", prvName: "uprv" }, z: { pub: 73342198, prv: 73341116, pubName: "vpub", prvName: "vprv" } } };
function hodlWifVersionByte(e) {
  return e === "mainnet" ? 128 : 239;
}
function hodlCoinTypeFromNetwork(e) {
  let index = Number(e);
  return Number.isSafeInteger(index) && index >= 0 && index <= 2147483647 ? index : e === "mainnet" ? 0 : 1;
}
function hodlPathComponent(value, hardened = false) {
  return `${value}${hardened ? "'" : ""}`;
}
function hodlOriginPathComponent(value, hardened = false) {
  return `${value}${hardened ? "h" : ""}`;
}
function hodlDefaultHardening() {
  return { purpose: true, coinType: true, account: true, script: true, branch: false, address: false };
}
function hodlReadHardening(prefix = "") {
  let defaults = hodlDefaultHardening(), read = (name) => document.getElementById(`${prefix}${name}-harden`)?.checked;
  return {
    purpose: read("purpose") ?? defaults.purpose,
    coinType: read("network") ?? defaults.coinType,
    account: read("account") ?? defaults.account,
    script: defaults.script,
    branch: read("branch-start") ?? defaults.branch,
    address: read("address-start") ?? defaults.address
  };
}
function hodlHardeningFromFields(fields = {}) {
  return {
    purpose: fields.purposeHarden !== false,
    coinType: fields.coinTypeHarden !== false,
    account: fields.accountHarden !== false,
    script: true,
    branch: Boolean(fields.branchHarden),
    address: Boolean(fields.addressHarden)
  };
}
function hodlSyncDerivationPrime(input) {
  let prime = input?.parentElement?.querySelector(".derivation-index-prime");
  if (prime) prime.dataset.indexValue = String(input.value ?? "");
}
function hodlSyncDerivationPrimes(root = document) {
  root.querySelectorAll(".derivation-index-value > input").forEach(hodlSyncDerivationPrime);
}
function hodlSetHardeningControls(prefix = "", hardening = hodlDefaultHardening()) {
  [["purpose", "purpose"], ["network", "coinType"], ["account", "account"], ["branch-start", "branch"], ["address-start", "address"]].forEach(([id, key]) => {
    let input = document.getElementById(`${prefix}${id}-harden`);
    if (input) {
      input.checked = Boolean(hardening[key]);
      if (!prefix) {
        let valueInput = document.getElementById(id), parsed = hodlParseDerivationIndexText(valueInput?.value);
        if (valueInput && parsed) valueInput.value = `${parsed.value}${input.checked ? "'" : ""}`;
      }
    }
  });
  hodlSyncDerivationPrimes();
}
function hodlParseCustomDerivationPath(value) {
  let raw = String(value ?? "").trim();
  if (!/^m(?:\/[^/]+)*$/.test(raw)) throw new Error("Derivation path must start with m and contain slash-separated BIP32 indexes.");
  let components = raw === "m" ? [] : raw.slice(2).split("/").map((part) => {
    let match = /^(\d+)([hH']?)$/.exec(part), index = Number(match?.[1]);
    if (!match || !Number.isSafeInteger(index) || index < 0 || index > 2147483647) throw new Error("Each derivation path index must be a whole number from 0 to 2,147,483,647, optionally followed by h or '.");
    return { index, hardened: Boolean(match[2]) };
  });
  return {
    components,
    path: `m${components.map((entry) => `/${hodlPathComponent(entry.index, entry.hardened)}`).join("")}`,
    originPath: components.map((entry) => hodlOriginPathComponent(entry.index, entry.hardened)).join("/"),
    hasHardened: components.some((entry) => entry.hardened)
  };
}
function hodlParseDerivationIndexText(value) {
  let match = /^(\d+)([hH']?)$/.exec(String(value ?? "").trim()), index = Number(match?.[1]);
  if (!match || !Number.isSafeInteger(index) || index < 0 || index > 2147483647) return null;
  return { value: index, hardened: Boolean(match[2]) };
}
function hodlSanitizeDerivationIndexDraft(value) {
  let result = "", hardened = false;
  for (let character of String(value ?? "")) {
    if (/\d/.test(character) && !hardened) result += character;
    else if ((character === "'" || character === "h" || character === "H") && !hardened) {
      result += "'";
      hardened = true;
    }
  }
  return result;
}
function hodlDefaultAdvancedDerivationIndex(id) {
  if (id === "purpose") return `${hodlScriptDefinition(hodlSelectedScriptType()).purpose}'`;
  if (id === "network" || id === "account") return "0'";
  return "0";
}
function hodlRestoreAdvancedDerivationIndex(input) {
  let draft = hodlSanitizeDerivationIndexDraft(input?.value);
  if (!input || draft !== "" && draft !== "'") return false;
  input.value = draft === "'" ? "0'" : hodlDefaultAdvancedDerivationIndex(input.id);
  input.dispatchEvent(new Event("input", { bubbles: true }));
  return true;
}
function hodlReadDerivationIndex(input, label, mark = true) {
  let parsed = hodlParseDerivationIndexText(input?.value), valid = Boolean(parsed);
  if (mark) {
    input?.classList.toggle("bad", !valid);
    input?.setAttribute("aria-invalid", String(!valid));
  }
  if (!valid) throw new Error(`${label} must be a whole number from 0 to 2,147,483,647.`);
  return parsed.value;
}
function hodlDerivationPathDisplay(accountPath, branchWindow, addressWindow, hardening = hodlDefaultHardening()) {
  if (branchWindow.range > 1) return accountPath;
  let branchPath = `${accountPath}/${hodlPathComponent(branchWindow.start, hardening.branch)}`;
  if (addressWindow.range > 1) return branchPath;
  return `${branchPath}/${hodlPathComponent(addressWindow.start, hardening.address)}`;
}
function hodlDerivationPathRangeMessage(branchWindow, addressWindow) {
  if (branchWindow.range > 1 && addressWindow.range > 1) return "Multiple address branches and indexes selected · path shown through the account level.";
  if (branchWindow.range > 1) return "Multiple address branches selected · path shown through the account level.";
  if (addressWindow.range > 1) return "Multiple address indexes selected · path shown through the address branch.";
  return "Exact BIP32 address path · edit directly to use a custom path";
}
function hodlReadVisibleDerivationPath(mark = true) {
  let input = document.getElementById("derivation-path"), parsed;
  try {
    parsed = hodlParseCustomDerivationPath(input?.value);
    let branchWindow = hodlReadBranchWindow("", false), addressWindow = hodlReadAddressWindow("", false), suffixCount = branchWindow.range > 1 ? 0 : addressWindow.range > 1 ? 1 : 2;
    if (parsed.components.length < 3 + suffixCount) throw new Error("Derivation path must include purpose, network, and account plus every address component shown.");
    let accountComponents = suffixCount ? parsed.components.slice(0, -suffixCount) : parsed.components.slice(), branch = suffixCount >= 1 ? parsed.components.at(-suffixCount) : null, address = suffixCount === 2 ? parsed.components.at(-1) : null;
    if (accountComponents.length < 3) throw new Error("Derivation path must include purpose, network, and account indexes.");
    if (mark) {
      input?.classList.remove("bad");
      input?.setAttribute("aria-invalid", "false");
    }
    return { parsed, accountComponents, branch, address, branchWindow, addressWindow };
  } catch (error) {
    if (mark) {
      input?.classList.add("bad");
      input?.setAttribute("aria-invalid", "true");
    }
    throw error;
  }
}
function hodlReadDerivationPlan(mark = true) {
  [["purpose", "Purpose"], ["network", "Coin type"], ["account", "Account"]].forEach(([id, label]) => {
    hodlReadDerivationIndex(document.getElementById(id), label, mark);
  });
  let visible = hodlReadVisibleDerivationPath(mark), parts = visible.accountComponents, purpose = parts[0].index, coinType = parts[1].index, accountIndex = parts[2].index, hardening = { ...hodlReadHardening(), purpose: parts[0].hardened, coinType: parts[1].hardened, account: parts[2].hardened, branch: visible.branch?.hardened ?? hodlReadHardening().branch, address: visible.address?.hardened ?? hodlReadHardening().address };
  return {
    network: hodlNetworkFromCoinType(coinType),
    coinType,
    accountIndex,
    purpose,
    accountPath: `m${parts.map((entry) => `/${hodlPathComponent(entry.index, entry.hardened)}`).join("")}`,
    originPath: parts.map((entry) => hodlOriginPathComponent(entry.index, entry.hardened)).join("/"),
    hasHardenedPrefix: parts.some((entry) => entry.hardened),
    hardening
  };
}
function hodlAccountPath(e, t, r = 0, hardening = hodlDefaultHardening()) {
  return `m/${hodlPathComponent(e.purpose, hardening.purpose)}/${hodlPathComponent(hodlCoinTypeFromNetwork(t), hardening.coinType)}/${hodlPathComponent(r, hardening.account)}`;
}
function hodlFingerprintHex(e) {
  return (e >>> 0).toString(16).padStart(8, "0");
}
function hodlReversionExtendedKey(e, t) {
  let r = hodlBase58Check.decode(e), n = new Uint8Array(r);
  return n[0] = t >>> 24 & 255, n[1] = t >>> 16 & 255, n[2] = t >>> 8 & 255, n[3] = t & 255, hodlBase58Check.encode(n);
}
function hodlReadExtendedKeyVersion(e) {
  let t = hodlBase58Check.decode(e.trim());
  return (t[0] << 24 | t[1] << 16 | t[2] << 8 | t[3]) >>> 0;
}
var hodlExtendedKeyPrefixTable = [];
function hodlEncodeWif(e, t, r) {
  let n = new Uint8Array([hodlWifVersionByte(r)]), o = t ? hodlConcatBytes(n, e, new Uint8Array([1])) : hodlConcatBytes(n, e);
  return hodlBase58Check.encode(o);
}
function hodlDecodeWif(e) {
  let t = hodlBase58Check.decode(e.trim());
  if (t.length !== 33 && t.length !== 34) throw hodlError("WIF decoded to an unexpected length.");
  let r = t[0], n;
  if (r === 128) n = "mainnet";
  else if (r === 239) n = "testnet";
  else throw hodlError("WIF prefix is not Bitcoin mainnet (5/K/L) or testnet (9/c).");
  if (t.length === 34) {
    if (t[33] !== 1) throw hodlError("Compressed WIF is missing the 0x01 suffix.");
    return { priv: t.slice(1, 33), compressed: true, network: n };
  }
  return { priv: t.slice(1), compressed: false, network: n };
}
function hodlConcatBytes(...e) {
  let t = e.reduce((o, i) => o + i.length, 0), r = new Uint8Array(t), n = 0;
  for (let o of e) r.set(o, n), n += o.length;
  return r;
}
function hodlAssertPrivateKey(e) {
  if (e.length !== 32) throw new Error("Private key must be 32 bytes.");
  let t = BigInt("0x" + hodlHex.encode(e));
  if (t === 0n || t >= hodlSecp256k1Order) throw hodlError("Private key is out of the secp256k1 range.");
  hodlSecp256k1.getPublicKey(e, true);
}
function hodlAddressOrThrow(e, t, r) {
  switch (e) {
    case "p2pkh": {
      let o = addressFor("p2pkh", t, r);
      if (!o) throw new Error("Failed to build legacy address");
      return o;
    }
    case "p2sh-p2wpkh": {
      let o = addressFor("p2sh-p2wpkh", t, r);
      if (!o) throw new Error("Failed to build nested SegWit address");
      return o;
    }
    case "p2wpkh": {
      let o = addressFor("p2wpkh", t, r);
      if (!o) throw new Error("Failed to build SegWit address");
      return o;
    }
    case "p2tr": {
      let o = addressFor("p2tr", t, r);
      if (!o) throw new Error("Failed to build Taproot address");
      return o;
    }
  }
}
function hodlDerivedAddressRow(node, accountPath, script, network, branchOrRole, index, addressHardened = false, branchHardened = false) {
  let chain = Number.isSafeInteger(branchOrRole) ? branchOrRole : branchOrRole === "receive" ? 0 : 1, branchStep = hodlPathComponent(chain, branchHardened), indexStep = hodlPathComponent(index, addressHardened), child = node.derive(`m/${branchStep}/${indexStep}`), publicKey = child.publicKey;
  if (!publicKey) throw new Error("Missing public key");
  let privateKey = child.privateKey;
  let row = { index, role: hodlAddressBranchRole(chain), branch: chain, branchHardened, path: `${accountPath}/${branchStep}/${indexStep}`, address: hodlAddressOrThrow(script, publicKey, network), wif: privateKey ? hodlEncodeWif(privateKey, true, network) : null, pubkey: hodlHex.encode(publicKey), privHex: privateKey ? hodlHex.encode(privateKey) : null };
  child.wipePrivateData();
  if (privateKey) privateKey.fill(0); // the getter copy; the row keeps its strings
  return row;
}
function hodlDeriveAddressRows(node, accountPath, script, network, count, branchOrRole, startIndex = 0, addressHardened = false, branchHardened = false) {
  let rows = [];
  for (let index = startIndex; index < startIndex + count; index++) rows.push(hodlDerivedAddressRow(node, accountPath, script, network, branchOrRole, index, addressHardened, branchHardened));
  return rows;
}
var hodlDescriptorInputCharset = "0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`JKLMNOPQRSTUVWXYZ", hodlBech32Charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
function hodlDescriptorSymbolValues(e) {
  let t = [], r = [];
  for (let n of e) {
    let o = hodlDescriptorInputCharset.indexOf(n);
    if (o < 0) throw new Error(`Invalid descriptor character: ${n}`);
    r.push(o & 31), t.push(o >> 5), t.length === 3 && (r.push(t[0] * 9 + t[1] * 3 + t[2]), t.length = 0);
  }
  return t.length === 1 ? r.push(t[0]) : t.length === 2 && r.push(t[0] * 3 + t[1]), r;
}
function hodlDescriptorPolymod(e) {
  let t = [0xf5dee51989n, 0xa9fdca3312n, 0x1bab10e32dn, 0x3706b1677an, 0x644d626ffdn], r = 1n;
  for (let n of e) {
    let o = r >> 35n;
    r = (r & 0x7ffffffffn) << 5n ^ BigInt(n);
    for (let i = 0; i < 5; i++) (o >> BigInt(i) & 1n) !== 0n && (r ^= t[i]);
  }
  return r;
}
function hodlDescriptorChecksum(e) {
  let t = hodlDescriptorSymbolValues(e).concat([0, 0, 0, 0, 0, 0, 0, 0]), r = hodlDescriptorPolymod(t) ^ 1n, n = "";
  for (let o = 0; o < 8; o++) {
    let i = Number(r >> BigInt(5 * (7 - o)) & 31n);
    n += hodlBech32Charset[i];
  }
  return n;
}
function hodlDescriptorWithChecksum(e) {
  return `${e}#${hodlDescriptorChecksum(e)}`;
}
function hodlScriptDescriptor(e, t) {
  switch (e) {
    case "p2pkh":
      return `pkh(${t})`;
    case "p2sh-p2wpkh":
      return `sh(wpkh(${t}))`;
    case "p2wpkh":
      return `wpkh(${t})`;
    case "p2tr":
      return `tr(${t})`;
  }
}
function hodlIsMiniKey(e) {
  let t = e.trim();
  return !t.startsWith("S") || t.length !== 22 && t.length !== 30 || !/^[A-Za-z0-9]+$/.test(t) ? false : hodlSha256(new TextEncoder().encode(t + "?"))[0] === 0;
}
function hodlDecodeMiniKey(e) {
  if (!hodlIsMiniKey(e)) throw hodlError("Not a valid Casascius mini private key.");
  return hodlSha256(new TextEncoder().encode(e.trim()));
}
function hodlBrainWalletPassphrase(value, trimBoundaryWhitespace = false) {
  let passphrase = String(value ?? ""), normalized = trimBoundaryWhitespace ? passphrase.trim() : passphrase;
  if (!normalized.length) throw hodlError(trimBoundaryWhitespace && passphrase.length ? "Trimming boundary whitespace leaves an empty brain-wallet recovery passphrase." : "Enter the brain-wallet recovery passphrase.");
  return normalized;
}
function hodlBrainWalletPrivateKey(value, trimBoundaryWhitespace = false) {
  return hodlSha256(new TextEncoder().encode(hodlBrainWalletPassphrase(value, trimBoundaryWhitespace)));
}
function hodlBrainLabEntropy(value) {
  let text = String(value ?? ""), notes = [], warnings = [];
  if (!text.length) return { ok: false, error: { key: "Enter the brain-wallet lab text." }, notes, warnings };
  let bytes = hodlSha256(new TextEncoder().encode(text)), hex = hodlHex.encode(bytes);
  notes.push(hodlNote("SHA-256 of the exact UTF-8 text is 32 bytes of BIP39 entropy (256 bits → 24 words)."));
  warnings.push(hodlNote("Lab only. Strength is the entropy of this text, not the 24-word count."));
  warnings.push(hodlNote("SHA-256(text) is unsalted and fast. Anyone who can guess the text recovers the wallet."));
  warnings.push(hodlNote("This is not a BIP39 passphrase, and it is not a Bitcoin Core hdseed or address-key backup."));
  warnings.push(hodlNote("A valid mnemonic does not mean it is the same wallet as hashing the text as a Core private key."));
  return { ok: true, bytes, hex, bits: 256, sourceBits: 256, method: "brain-lab", notes, warnings };
}
function hodlSingleKeyWallet(e, t, r, trimBrainWallet = false) {
  let n = [], o = [], i, s = null, c = t, a = r === "brain" ? hodlBrainWalletPassphrase(e, trimBrainWallet) : e.trim();
  if (r === "brain") {
    o.push(hodlNote("Brain wallets are dangerous. Humans pick guessable phrases. Anyone who guesses the phrase takes the coins. Prefer dice or a hardware-verified seed.")), i = hodlBrainWalletPrivateKey(e, trimBrainWallet), n.push(hodlNote(trimBrainWallet ? "Brain wallet recovery: SHA-256 used the passphrase after trimming leading and trailing whitespace." : "Brain wallet recovery: SHA-256 used the passphrase exactly as entered."));
  } else if (r === "minikey" || hodlIsMiniKey(a)) i = hodlDecodeMiniKey(a), s = a, n.push(hodlNote("Casascius mini private key decoded via SHA-256."));
  else if (/^[5KL9c][1-9A-HJ-NP-Za-km-z]{50,51}$/.test(a)) {
    let E = hodlDecodeWif(a);
    i = E.priv, c = E.network, n.push(hodlNote(E.compressed ? "Decoded a compressed WIF private key (starts with K or L on mainnet)." : "Decoded an uncompressed WIF private key (starts with 5 on mainnet)."));
  } else {
    let E = a.replace(/\s/g, "").replace(/^0x/i, "");
    if (!/^[0-9a-fA-F]{64}$/.test(E)) throw hodlError("Enter a WIF key (5/K/L…), a 64-character hex private key, or a Casascius mini key (S…).");
    i = hodlHex.decode(E.toLowerCase()), n.push(hodlNote("Decoded a 32-byte hex private key."));
  }
  hodlAssertPrivateKey(i);
  let f = hodlSecp256k1.getPublicKey(i, true), d = hodlSecp256k1.getPublicKey(i, false), l = addressFor("p2pkh", d, c), u = addressFor("p2pkh", f, c), p = addressFor("p2sh-p2wpkh", f, c), b = addressFor("p2wpkh", f, c), w = addressFor("p2tr", f, c);
  let wallet = { kind: "single", network: c, warnings: o, notes: n, privHex: hodlHex.encode(i), wifCompressed: hodlEncodeWif(i, true, c), wifUncompressed: hodlEncodeWif(i, false, c), pubkeyCompressed: hodlHex.encode(f), pubkeyUncompressed: hodlHex.encode(d), p2pkhUncompressed: l, p2pkhCompressed: u, p2shP2wpkh: p, p2wpkh: b, p2tr: w, minikey: s };
  i.fill(0); // the decoded private key bytes; the result keeps its hex/WIF strings
  return wallet;
}
function hodlQrSvg(e, t = "#111111", r = "#ffffff") {
  return hodlUqrRenderSvg(e, { ecc: "M", border: 2, pixelSize: 4, blackColor: t, whiteColor: r });
}
// Test-only bridge for the browser suite (test/browser-suite.html), armed
// solely when the injected instrumentation is present. The release build
// defines __ENTROPYLAB_TEST_HOOKS__ as false (scripts/build.mjs), so the
// minifier drops this statement and no test code ships in entropylab.html;
// the browser harness stages a --test-hooks variant instead.
if (__ENTROPYLAB_TEST_HOOKS__ && globalThis.__entropyLabTest) globalThis.__entropyLabCrypto = { entropyToMnemonic: (hex) => hodlEntropyToMnemonic(hodlHex.decode(hex), hodlBip39Wordlist), mnemonicToEntropy: (mnemonic) => hodlHex.encode(hodlMnemonicToEntropy(mnemonic, hodlBip39Wordlist)), mnemonicToSeed: (mnemonic, passphrase) => hodlHex.encode(hodlMnemonicToSeed(mnemonic, passphrase)), validateMnemonic: (mnemonic) => hodlValidateMnemonic(mnemonic).ok, masterXprv: (mnemonic, passphrase) => hodlHDKey.fromMasterSeed(hodlMnemonicToSeed(mnemonic, passphrase)).privateExtendedKey, privateKeyInputIsValid: () => hodlPrivateKeyInputIsValid(), computeTargetLastWords: (words, targetWords) => hodlComputeTargetLastWords(words, targetWords), clearLastWordCache: () => hodlLastWordCache.clear(), validateTargetMnemonic: (value, targetWords) => hodlValidateTargetMnemonic(value, targetWords), bruteTargetLastWords: (value) => hodlLastWordCandidates(value) };
if (__ENTROPYLAB_TEST_HOOKS__ && globalThis.__entropyLabTest) globalThis.__entropyLabI18n = { sanitizeCatalogHtml: hodlSanitizeCatalogHtml, tHtml: hodlT, tAttr: hodlTAttr };
var hodlRootEl = document.getElementById("btc-calc");
if (!hodlRootEl) throw new Error("#app missing");
hodlRootEl.innerHTML = hodlShellHtml;if (/^(www\.)?entropylab\.online$/i.test(location.hostname)) document.getElementById("online-warning")?.removeAttribute("hidden");
var hodlKeyModes = ["dice", "cards", "hex", "seed", "key"], hodlBrainLabAck = { scalar: false, hd: false }, hodlCardRanks = ["A", "2", "3", "4", "5", "6", "7", "8", "9", "T", "J", "Q", "K"], hodlDirectCardRanks = ["A", "2", "3", "4", "5", "6", "7", "8"], hodlCardSuits = [{ code: "S", symbol: "♠", label: "Spades", red: false }, { code: "H", symbol: "♥", label: "Hearts", red: true }, { code: "C", symbol: "♣", label: "Clubs", red: false }, { code: "D", symbol: "♦", label: "Diamonds", red: true }], hodlCardSuit = "", hodlCardRank = "", hodlCardMethod = "hashed", hodlSeedMethod = "words", hodlSeedZeroIndexed = false, hodlCardColemanSymbols = false, hodlKeyMode = "dice", hodlDiceMethod = "coldcard", hodlTargetWordCount = 24, hodlEntropyFormat = "hex", hodlDiceCoinPositions = [], hodlPickedLastWord = "", hodlWalletResult = null, hodlRevealPrivate = false, hodlWalletDatBirthday = "genesis", hodlModesEl = hodlElement("#modes"), hodlFormEl = hodlElement("#form"), hodlOutEl = hodlElement("#out");
var hodlManualCalculationsOpen = false;
function hodlCreateKeyMethodIcon(mode) {
  let ns = "http://www.w3.org/2000/svg", span = document.createElement("span"), svg = document.createElementNS(ns, "svg");
  let add = (tag, attributes) => {
    let node = document.createElementNS(ns, tag);
    Object.entries(attributes).forEach(([name, value]) => node.setAttribute(name, value));
    svg.appendChild(node);
  };
  span.className = "key-method-icon";
  span.setAttribute("aria-hidden", "true");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("fill", "none");
  svg.setAttribute("stroke", "currentColor");
  svg.setAttribute("stroke-width", "1.8");
  svg.setAttribute("stroke-linecap", "round");
  svg.setAttribute("stroke-linejoin", "round");
  svg.setAttribute("focusable", "false");
  svg.setAttribute("aria-hidden", "true");
  if (mode === "dice") {
    add("rect", { x: "3.5", y: "3.5", width: "17", height: "17", rx: "3.2" });
    [[8, 8], [16, 8], [12, 12], [8, 16], [16, 16]].forEach(([cx, cy]) => add("circle", { cx: String(cx), cy: String(cy), r: "1.15", fill: "currentColor", stroke: "none" }));
  } else if (mode === "cards") {
    add("rect", { x: "7.5", y: "3", width: "12.5", height: "16.5", rx: "2.1" });
    add("rect", { x: "3.5", y: "5.5", width: "12.5", height: "16", rx: "2.1", fill: "var(--key-method-card-bg)", "data-part": "card-front" });
    add("path", { d: "M9.75 10.5 12.5 13l-2.75 2.5L7 13l2.75-2.5Z", fill: "currentColor", stroke: "none" });
  } else if (mode === "hex") {
    add("rect", { x: "3.5", y: "4.5", width: "7", height: "15", rx: "3.5" });
    add("path", { d: "m14.5 8 3-3v14m-3.5 0h7" });
  } else if (mode === "seed") {
    [7, 12, 17].forEach((y) => {
      add("circle", { cx: "5", cy: String(y), r: "1", fill: "currentColor", stroke: "none" });
      add("path", { d: `M9 ${y}h10` });
    });
  } else {
    add("circle", { cx: "7.5", cy: "7.5", r: "4.2" });
    add("path", { d: "m10.5 10.5 9.7 9.7m-3.1-3.1 2.2-2.2m-5.1-.9 2.2-2.2" });
  }
  span.appendChild(svg);
  return span;
}
// The method picker is a dropdown at every width, wearing the Script type
// control's chrome: enhanced-inputs.js upgrades it and asks
// entropylabOptionIcon for each method's mark.
var hodlKeyModeSelectEl = document.createElement("select");
hodlKeyModeSelectEl.id = "key-mode-select";
hodlKeyModeSelectEl.setAttribute("aria-labelledby", "key-method-label");
hodlKeyModes.forEach((mode) => {
  let option = document.createElement("option");
  option.value = mode;
  option.textContent = hodlTText(hodlKeyModeLabels[mode]);
  option.selected = mode === hodlKeyMode;
  hodlKeyModeSelectEl.appendChild(option);
});
hodlKeyModeSelectEl.entropylabOptionIcon = (value) => hodlCreateKeyMethodIcon(value);
hodlKeyModeSelectEl.onchange = () => {
  if (hodlKeyModeSelectEl.value !== hodlKeyMode) hodlSetMode(hodlKeyModeSelectEl.value);
};
hodlModesEl.appendChild(hodlKeyModeSelectEl);
// Every path that changes the method moves the control with it. Sync, not
// change: change would come straight back through onchange.
function hodlSyncKeyModeSelect() {
  if (hodlKeyModeSelectEl.value === hodlKeyMode) return;
  hodlKeyModeSelectEl.value = hodlKeyMode;
  hodlKeyModeSelectEl.dispatchEvent(new Event("entropylab:sync-select"));
}
var hodlSeedLengthSelectEl = hodlElement("#seed-length-select");
hodlSeedLengthSelectEl.onchange = () => hodlSetSeedLength(Number(hodlSeedLengthSelectEl.value));
hodlElement("#go").onclick = () => hodlHandleDerivationButton("key", hodlCalculateKey);
hodlElement("#wipe").onclick = hodlWipeActiveKey;
function hodlElement(e) {
  let t = e.startsWith("#") ? e.slice(1) : e, r = document.getElementById(t);
  if (!r) throw new Error(t);
  return r;
}
function hodlRenderKeyResult() {
  if (!hodlWalletResult) {
    hodlOutEl.innerHTML = "";
    return;
  }
  if (hodlWalletResult.kind === "single") {
    let t = hodlWalletResult;
    hodlOutEl.innerHTML = `<div class="key-result">${hodlSingleWalletData(t)}</div>`;
  } else {
    let t = hodlWalletResult, r = t.accounts.find((o) => o.def.id === hodlAccountId) ?? t.accounts.find((o) => o.def.id === "bip84") ?? t.accounts[0];
    hodlOutEl.innerHTML = `
      <div class="key-result">
        ${hodlHdWalletData(t)}
        <p class="key-result-scripts-label" id="acct-tabs-label">Script type</p>
        <div class="account-tabs no-print" id="acct-tabs" role="tablist" aria-labelledby="acct-tabs-label"></div>
        <div id="acct" role="tabpanel"></div>
      </div>
    `;
    let n = hodlElement("#acct-tabs");
    t.accounts.forEach((o) => {
      let i = document.createElement("button");
      i.type = "button", i.id = `account-tab-${o.def.id}`, i.className = "tab account-tab" + (o.def.id === r.def.id ? " active" : ""), i.dataset.account = o.def.id, i.textContent = hodlScriptUiLabel(o.def), i.setAttribute("role", "tab"), i.setAttribute("aria-controls", "acct"), i.setAttribute("aria-selected", String(o.def.id === r.def.id)), i.tabIndex = o.def.id === r.def.id ? 0 : -1, i.onclick = () => hodlShowAccount(o.def.id), n.appendChild(i);
    }), n.onkeydown = hodlAccountTabsKeydown, hodlShowAccount(r.def.id);
  }
  let e = document.getElementById("reveal");
  e && (e.onchange = () => {
    hodlRevealPrivate = e.checked, hodlRefreshKeyResult();
  }), document.getElementById("save")?.addEventListener("click", () => {
    if (!hodlWalletResult) return;
    let t = new Blob([hodlFormatRecoverySheet(hodlRecoverySheetText(hodlWalletResult, hodlRevealPrivate))], { type: "text/plain" }), r = document.createElement("a");
    r.href = URL.createObjectURL(t), r.download = "bitcoin-recovery-sheet.txt", r.click();
  });
}
var hodlMultisigKeyVersions = [
  { network: "mainnet", family: "y", scope: "multisig", private: false, ver: 43365439, name: "Ypub" },
  { network: "mainnet", family: "y", scope: "multisig", private: true, ver: 43364357, name: "Yprv" },
  { network: "mainnet", family: "z", scope: "multisig", private: false, ver: 44728019, name: "Zpub" },
  { network: "mainnet", family: "z", scope: "multisig", private: true, ver: 44726937, name: "Zprv" },
  { network: "testnet", family: "y", scope: "multisig", private: false, ver: 37915119, name: "Upub" },
  { network: "testnet", family: "y", scope: "multisig", private: true, ver: 37914037, name: "Uprv" },
  { network: "testnet", family: "z", scope: "multisig", private: false, ver: 39277699, name: "Vpub" },
  { network: "testnet", family: "z", scope: "multisig", private: true, ver: 39276616, name: "Vprv" }
];
for (let [network, families] of Object.entries(hodlExtendedKeyVersions)) for (let [family, entry] of Object.entries(families)) {
  hodlExtendedKeyPrefixTable.push({ network, family, scope: "singlesig", private: false, ver: entry.pub, name: entry.pubName });
  hodlExtendedKeyPrefixTable.push({ network, family, scope: "singlesig", private: true, ver: entry.prv, name: entry.prvName });
}
hodlExtendedKeyPrefixTable.push(...hodlMultisigKeyVersions);
var hodlParseExtendedKey = function(value) {
  let input = String(value ?? "").trim(), payload = hodlBase58Check.decode(input), version = hodlReadExtendedKeyVersion(input), entry = hodlExtendedKeyPrefixTable.find((candidate) => candidate.ver === version);
  if (!entry) throw hodlError("Not a recognized extended key. Use xpub/xprv, tpub/tprv, ypub/yprv, zpub/zprv, upub/uprv, vpub/vprv, or a supported multisig export.");
  if (payload.length !== 78) throw hodlError("The extended key payload has an unexpected length.");
  let normalized = hodlReversionExtendedKey(input, entry.private ? hodlExtendedKeyVersions.mainnet.x.prv : hodlExtendedKeyVersions.mainnet.x.pub), node = hodlHDKey.fromExtendedKey(normalized);
  if (Boolean(node.privateKey) !== entry.private) throw hodlError("The extended-key prefix does not match its key payload.");
  let depth = payload[4], childNumber = new DataView(payload.buffer, payload.byteOffset + 9, 4).getUint32(0, false);
  if (node.depth !== depth) throw hodlError("The extended-key depth does not match its serialized payload.");
  return { xkey: normalized, isPrivate: entry.private, network: entry.network, family: entry.family, scope: entry.scope, prefix: entry.name, version: entry.ver, node, depth, childNumber };
};
function hodlAccountExportFamily(definition, options = {}) {
  if (definition.id === "bip86") return "x";
  if (options.imported) {
    if (options.importedFamily === "y" && definition.id === "bip49") return "y";
    if (options.importedFamily === "z" && definition.id === "bip84") return "z";
    return "x";
  }
  if (definition.id === "bip49" && definition.purpose === 49) return "y";
  if (definition.id === "bip84" && definition.purpose === 84) return "z";
  return "x";
}
function hodlSerializeExtendedKey(value, network, family, isPrivate) {
  return value ? hodlReversionExtendedKey(value, hodlExtendedKeyVersions[network][family][isPrivate ? "prv" : "pub"]) : null;
}
function hodlBuildMultisigCosignerExports(root, network, accountIndex, masterFingerprint, coinType = hodlCoinTypeFromNetwork(network)) {
  return [{
      accountId: "bip44",
      kind: "p2sh",
      standard: "bip45",
      label: "Legacy \xB7 BIP45 \xB7 No account",
      family: "x",
      accountPath: "m/45'",
      originPath: "45h"
    },
    {
      accountId: "bip44",
      kind: "p2sh",
      standard: "bip87",
      label: `Legacy \xB7 BIP87 \xB7 Account ${accountIndex}`,
      family: "x",
      accountPath: `m/87'/${coinType}'/${accountIndex}'`,
      originPath: `87h/${coinType}h/${accountIndex}h`
    },
    {
      accountId: "bip49",
      kind: "p2sh-p2wsh",
      label: "Nested SegWit \xB7 BIP48",
      family: "x",
      scriptIndex: 1
    },
    {
      accountId: "bip84",
      kind: "p2wsh",
      label: "Native SegWit \xB7 BIP48",
      family: "x",
      scriptIndex: 2
    },
    {
      accountId: "bip86",
      kind: "p2tr",
      label: "Taproot \xB7 BIP86",
      family: "x",
      accountPath: `m/86'/${coinType}'/${accountIndex}'`,
      originPath: `86h/${coinType}h/${accountIndex}h`
    }
  ].map(definition => {
    let accountPath = definition.accountPath || `m/48'/${coinType}'/${accountIndex}'/${definition.scriptIndex}'`,
      originPath = definition.originPath || `48h/${coinType}h/${accountIndex}h/${definition.scriptIndex}h`;
    let node = root.derive(accountPath),
      publicKey = hodlSerializeExtendedKey(node.publicExtendedKey, network, "x", !1);
    let prefix = hodlExtendedKeyVersions[network].x.pubName;
    return {
      ...definition,
      accountPath,
      originPath,
      prefix,
      value: `[${masterFingerprint}/${originPath}]${publicKey}`
    }
  })
}
function hodlStripDescriptorChecksum(descriptor) {
  let text = String(descriptor ?? ""), hash = text.lastIndexOf("#");
  return hash >= 0 ? text.slice(0, hash) : text;
}
function hodlAddressBranchRole(branch) {
  return branch === 0 ? "receive" : branch === 1 ? "change" : "custom";
}
function hodlAddressBranchLabel(branch) {
  return branch === 0 ? "Receive" : branch === 1 ? "Change" : `Custom branch ${branch}`;
}
function hodlWatchOnlyMultipathDescriptor(receiveDescriptor, branches = [0, 1]) {
  let body = hodlStripDescriptorChecksum(receiveDescriptor);
  if (!body) return "";
  let selected = [...new Set(branches)].filter(Number.isSafeInteger);
  if (!selected.length) return "";
  if (selected.length === 1) return hodlDescriptorWithChecksum(body);
  let first = selected[0], pattern = new RegExp(`/${first}/\\*`, "g");
  if (!pattern.test(body)) return "";
  return hodlDescriptorWithChecksum(body.replace(pattern, `/<${selected.join(";")}>/*`));
}
function hodlDescriptorQrSvg(payload) {
  return hodlUqrRenderSvg(payload, { ecc: "M", border: 4, pixelSize: 4, blackColor: "#111111", whiteColor: "#ffffff" });
}
function hodlWatchOnlyDescriptorExport(receiveDescriptor, changeDescriptor, addressBranches = null) {
  let branches = (addressBranches?.length ? addressBranches : [
    { branch: 0, label: "Receive", publicDescriptor: receiveDescriptor },
    { branch: 1, label: "Change", publicDescriptor: changeDescriptor }
  ]).filter((entry) => entry.publicDescriptor), first = branches[0], multipath = first ? branches.length === 1 ? first.publicDescriptor : hodlWatchOnlyMultipathDescriptor(first.publicDescriptor, branches.map((entry) => entry.branch)) : "", qr = "";
  if (multipath) {
    try {
      if (multipath.length > 1e3) throw new Error("Descriptor too long for a static QR.");
      qr = `<div class="watch-only-qr"><div class="qr qr-descriptor" aria-label="${hodlTAttr("Watch-only wallet descriptor QR code")}">${hodlDescriptorQrSvg(multipath)}</div><p class="muted">${hodlT("Import this output descriptor into Sparrow or another wallet.")}</p></div>`;
    } catch (error) {
      qr = `<p class="muted">${hodlEscapeHtml(error.message || "Descriptor too long for a static QR.")} Copy the text instead, or import the selected branch descriptors separately.</p>`;
    }
  }
  let details = branches.map((entry) => hodlPublicFieldHtml(`Watch-only ${hodlAddressBranchLabel(entry.branch).toLowerCase()} descriptor`, entry.publicDescriptor)).join("");
  return `${hodlPublicFieldHtml("Watch-only wallet descriptor", multipath || "\u2014")}${qr}<details class="wallet-advanced"><summary>Address branch descriptors</summary>${details}</details>`;
}
function hodlAccountResult(node, definition, network, count, options = {}) {
  let rawPublic = node.publicExtendedKey, rawPrivate = node.privateKey ? node.privateExtendedKey : null, family = hodlAccountExportFamily(definition, options), primaryConfig = hodlExtendedKeyVersions[network][family] || hodlExtendedKeyVersions[network].x, genericConfig = hodlExtendedKeyVersions[network].x;
  let genericPublic = hodlSerializeExtendedKey(rawPublic, network, "x", false), genericPrivate = hodlSerializeExtendedKey(rawPrivate, network, "x", true);
  let primaryPublic = hodlSerializeExtendedKey(rawPublic, network, family, false), primaryPrivate = hodlSerializeExtendedKey(rawPrivate, network, family, true);
  let origin = options.originFingerprint && options.originPath ? `[${options.originFingerprint}/${options.originPath}]` : "", branchHardened = Boolean(options.branchHardened), addressHardened = Boolean(options.addressHardened), wildcard = addressHardened ? "*'" : "*", branchStart = options.branchStart ?? 0, branchRange = options.branchRange ?? 2;
  let addressBranches = Array.from({ length: branchRange }, (_, offset) => {
    let branch = branchStart + offset, branchStep = hodlPathComponent(branch, branchHardened), branchOrigin = options.originFingerprint && options.originPath ? `[${options.originFingerprint}/${options.originPath}/${hodlOriginPathComponent(branch, branchHardened)}]` : "", branchNode = branchHardened && node.privateKey ? node.derive(`m/${branchStep}`) : null, branchPublic = branchNode ? hodlSerializeExtendedKey(branchNode.publicExtendedKey, network, "x", false) : null;
    let publicToken = addressHardened ? null : branchHardened ? branchPublic ? `${branchOrigin}${branchPublic}/${wildcard}` : null : `${origin}${genericPublic}/${branchStep}/${wildcard}`, privateToken = genericPrivate ? `${origin}${genericPrivate}/${branchStep}/${wildcard}` : null;
    let result = {
      branch,
      branchHardened,
      role: hodlAddressBranchRole(branch),
      label: hodlAddressBranchLabel(branch),
      publicDescriptor: publicToken ? hodlDescriptorWithChecksum(hodlScriptDescriptor(definition.script, publicToken)) : null,
      privateDescriptor: privateToken ? hodlDescriptorWithChecksum(hodlScriptDescriptor(definition.script, privateToken)) : null,
      rows: options.addressBranches?.find((entry) => entry.branch === branch)?.rows ?? hodlDeriveAddressRows(node, options.accountPath ?? "Imported account key", definition.script, network, count, branch, options.addressStart ?? 0, addressHardened, branchHardened)
    };
    if (branchNode) branchNode.wipePrivateData(); // only its xpub string is kept
    return result;
  });
  let receiveBranch = addressBranches.find((entry) => entry.branch === 0), changeBranch = addressBranches.find((entry) => entry.branch === 1);
  let accountPath = options.accountPath ?? "Imported account key";
  return {
    def: definition,
    network,
    accountPath,
    accountIndex: options.accountIndex ?? null,
    originKnown: Boolean(origin),
    originFingerprint: options.originFingerprint || null,
    originPath: options.originPath || null,
    imported: Boolean(options.imported),
    importedFamily: options.importedFamily || null,
    importedValue: options.importedValue || null,
    masterFingerprint: options.masterFingerprint ?? null,
    parentFingerprint: options.parentFingerprint ?? null,
    nodeFingerprint: options.nodeFingerprint ?? null,
    primaryFamily: family,
    primaryPublic,
    primaryPrivate,
    primaryPublicLabel: primaryConfig.pubName,
    primaryPrivateLabel: primaryConfig.prvName,
    genericPublic,
    genericPrivate,
    genericPublicLabel: genericConfig.pubName,
    genericPrivateLabel: genericConfig.prvName,
    hasAlternateExport: family !== "x",
    publicExports: [{ name: primaryConfig.pubName, value: primaryPublic }],
    privateExports: primaryPrivate ? [{ name: primaryConfig.prvName, value: primaryPrivate }] : [],
    xpub: genericPublic,
    xprv: genericPrivate,
    ypub: family === "y" ? primaryPublic : null,
    yprv: family === "y" ? primaryPrivate : null,
    zpub: family === "z" ? primaryPublic : null,
    zprv: family === "z" ? primaryPrivate : null,
    vpub: null,
    vprv: null,
    addressBranches,
    branchStart,
    branchRange,
    receiveDescriptor: receiveBranch?.publicDescriptor ?? null,
    changeDescriptor: changeBranch?.publicDescriptor ?? null,
    walletDescriptor: addressBranches[0]?.publicDescriptor ? addressBranches.length === 1 ? addressBranches[0].publicDescriptor : hodlWatchOnlyMultipathDescriptor(addressBranches[0].publicDescriptor, addressBranches.map((entry) => entry.branch)) : null,
    receiveDescriptorPriv: receiveBranch?.privateDescriptor ?? null,
    changeDescriptorPriv: changeBranch?.privateDescriptor ?? null,
    branchHardened,
    addressHardened,
    receive: receiveBranch?.rows ?? [],
    change: changeBranch?.rows ?? []
  };
}
function hodlRootWalletResult(root, network, source, accountIndex, masterFingerprint, accounts, coinType = hodlCoinTypeFromNetwork(network)) {
  return {
    kind: "hd",
    network,
    coinType,
    mnemonic: source.mnemonic,
    passphraseUsed: source.passphraseUsed,
    passphrase: source.passphrase ?? "",
    entropyHex: source.entropyHex,
    seedHex: source.seedHex,
    rootXprv: hodlSerializeExtendedKey(root.privateKey ? root.privateExtendedKey : null, network, "x", true),
    rootXpub: hodlSerializeExtendedKey(root.publicExtendedKey, network, "x", false),
    rootPrivateLabel: hodlExtendedKeyVersions[network].x.prvName,
    rootPublicLabel: hodlExtendedKeyVersions[network].x.pubName,
    masterFingerprint,
    multisigCosignerExports: root.privateKey ? hodlBuildMultisigCosignerExports(root, network, accountIndex, masterFingerprint, coinType) : [],
    imported: false,
    notes: source.notes,
    warnings: source.warnings,
    accounts
  };
}
function hodlImportedScriptDefinition(parsed) {
  if (parsed.family === "y") return hodlScriptTypes.find((definition) => definition.id === "bip49");
  if (parsed.family === "z") return hodlScriptTypes.find((definition) => definition.id === "bip84");
  return hodlScriptDefinition(hodlSelectedScriptType());
}
function hodlSinglesigScriptMismatch(parsed, selectedScriptId) {
  let expectedId = parsed?.family === "y" ? "bip49" : parsed?.family === "z" ? "bip84" : "";
  if (!expectedId || expectedId === selectedScriptId) return "";
  let expected = hodlScriptTypes.find((definition) => definition.id === expectedId), selected = hodlScriptTypes.find((definition) => definition.id === selectedScriptId);
  if (!expected || !selected) return "";
  return hodlNote("{prefix} indicates {expected} ({expectedBip}), but you selected {selected} ({selectedBip}). EntropyLab will derive {expected} from the {prefix} prefix. Change Script type to {expected} to make the settings agree.", { prefix: parsed.prefix, expected: hodlScriptUiLabel(expected), expectedBip: expected.bip, selected: hodlScriptUiLabel(selected), selectedBip: selected.bip });
}
async function hodlAddressRowsWithProgress(node, accountPath, script, network, count, branchOrRole, addressStart, tracker, addressHardened = false, branchHardened = false) {
  let rows = [];
  for (let index = addressStart; index < addressStart + count; index++) {
    rows.push(hodlDerivedAddressRow(node, accountPath, script, network, branchOrRole, index, addressHardened, branchHardened));
    let pause = tracker.step();
    if (pause) await pause;
  }
  return rows;
}
async function hodlAccountResultWithProgress(node, definition, network, count, options, tracker) {
  let accountPath = options.accountPath ?? "Imported account key";
  let branchStart = options.branchStart ?? 0, branchRange = options.branchRange ?? 2, addressBranches = [];
  for (let branch = branchStart; branch < branchStart + branchRange; branch++) {
    addressBranches.push({ branch, rows: await hodlAddressRowsWithProgress(node, accountPath, definition.script, network, count, branch, options.addressStart ?? 0, tracker, options.addressHardened, options.branchHardened) });
  }
  return hodlAccountResult(node, definition, network, count, { ...options, addressBranches });
}
async function hodlRootWalletWithProgress(root, network, count, source, accountIndex, addressStart, tracker, purposeIndex, coinType = hodlCoinTypeFromNetwork(network), hardening = hodlDefaultHardening(), branchStart = 0, branchRange = 2, derivationPlan = null) {
  let addressCount = Math.min(Math.max(count, 1), hodlMaxAddressRange), masterFingerprint = hodlFingerprintHex(root.fingerprint), accounts = [];
  tracker.setTotal(addressCount * hodlScriptTypes.length * branchRange);
  for (let definition of hodlScriptTypes) {
    let derivedDefinition = { ...definition, purpose: purposeIndex, purposeHardened: hardening.purpose }, accountPath = derivationPlan?.accountPath || hodlAccountPath(derivedDefinition, coinType, accountIndex, hardening), node = root.derive(accountPath), originPath = derivationPlan?.originPath ?? `${hodlOriginPathComponent(purposeIndex, hardening.purpose)}/${hodlOriginPathComponent(coinType, hardening.coinType)}/${hodlOriginPathComponent(accountIndex, hardening.account)}`;
    let account = await hodlAccountResultWithProgress(node, derivedDefinition, network, addressCount, { accountPath, accountIndex, masterFingerprint, originFingerprint: masterFingerprint, originPath, addressStart, branchHardened: hardening.branch, addressHardened: hardening.address, branchStart, branchRange }, tracker);
    node.wipePrivateData(); // the account keeps its extended-key strings, not the node
    accounts.push(account);
  }
  return hodlRootWalletResult(root, network, source, accountIndex, masterFingerprint, accounts, coinType);
}
async function hodlMnemonicWalletWithProgress(value, passphrase, network, count, source, accountIndex, addressStart, tracker, purposeIndex, coinType = hodlCoinTypeFromNetwork(network), hardening = hodlDefaultHardening(), branchStart = 0, branchRange = 2, derivationPlan = null) {
  let validation = hodlValidateMnemonic(value);
  if (!validation.ok) throw validation.error?.key ? hodlError(validation.error.key, validation.error.vars) : hodlError("Invalid seed phrase");
  let mnemonic = validation.words.join(" "), seed = hodlMnemonicToSeed(mnemonic, passphrase), root, seedHex;
  try {
    root = hodlHDKey.fromMasterSeed(seed);
    seedHex = hodlHex.encode(seed);
  } finally {
    seed.fill(0); // the 64-byte seed is dead once the root node exists
  }
  let entropyHex = source?.entropyHex ?? hodlHex.encode(hodlMnemonicToEntropy(mnemonic, hodlBip39Wordlist)), warnings = [...source?.warnings ?? []];
  if (passphrase.length > 0) warnings.push("A passphrase is in use. The same words without this passphrase are a different wallet. Do not store the passphrase with the words.");
  try {
    return await hodlRootWalletWithProgress(root, network, count, { mnemonic, passphraseUsed: passphrase.length > 0, passphrase, entropyHex, seedHex, notes: source?.notes ?? [], warnings }, accountIndex, addressStart, tracker, purposeIndex, coinType, hardening, branchStart, branchRange, derivationPlan);
  } finally {
    root.wipePrivateData(); // the result keeps its extended-key strings, not the root
  }
}
async function hodlEntropyWalletWithProgress(entropy, passphrase, network, count, accountIndex, addressStart, tracker, purposeIndex, coinType = hodlCoinTypeFromNetwork(network), hardening = hodlDefaultHardening(), branchStart = 0, branchRange = 2, derivationPlan = null) {
  try {
    return await hodlMnemonicWalletWithProgress(hodlEntropyToMnemonic(entropy.bytes, hodlBip39Wordlist), passphrase, network, count, { entropyHex: entropy.hex, notes: entropy.notes, warnings: entropy.warnings }, accountIndex, addressStart, tracker, purposeIndex, coinType, hardening, branchStart, branchRange, derivationPlan);
  } finally {
    entropy.bytes.fill(0); // the entropy bytes are dead once the mnemonic exists
  }
}
async function hodlImportedWalletWithProgress(value, network, count, accountIndex, addressStart, tracker, purposeIndex, coinType = hodlCoinTypeFromNetwork(network), hardening = hodlDefaultHardening(), branchStart = 0, branchRange = 2, derivationPlan = null) {
  let importedValue = String(value ?? "").trim(), parsed = hodlParseExtendedKey(importedValue);
  if (parsed.scope !== "singlesig") throw hodlError("{prefix} is a multisig extended key. Use it in Multi Signature, not Key Derivation.", { prefix: parsed.prefix });
  if (parsed.network !== network) throw hodlError("This {prefix} belongs to Bitcoin {network}. Change Network to {network} before deriving it.", { prefix: parsed.prefix, network: parsed.network });
  let node = parsed.node, mismatch = hodlSinglesigScriptMismatch(parsed, hodlSelectedScriptType()), notes = [hodlNote(parsed.isPrivate ? "Imported an extended private key. Addresses and WIF keys are derived from it." : "Imported an extended public key. This is watch-only: it can derive addresses but cannot spend.")];
  if (node.depth === 0) {
    if (!parsed.isPrivate && (derivationPlan ? derivationPlan.hasHardenedPrefix || hardening.branch || hardening.address : Object.values(hardening).some(Boolean))) throw hodlError("A root extended public key cannot derive the selected hardened path. Turn every Harden option off, import an account-level public key, or use the root xprv/tprv offline.");
    if (parsed.family !== "x") throw hodlError("A BIP32 root private key must use the generic xprv/tprv prefix.");
    try {
      return await hodlRootWalletWithProgress(node, network, count, { mnemonic: null, passphraseUsed: false, passphrase: "", entropyHex: null, seedHex: null, notes, warnings: [] }, accountIndex, addressStart, tracker, purposeIndex, coinType, hardening, branchStart, branchRange, derivationPlan);
    } finally {
      node.wipePrivateData(); // the imported root is dead once the result strings exist
    }
  }
  if (node.depth !== 3) throw hodlError("This extended key is depth {depth}. Key Derivation accepts a BIP32 root private key (depth 0) or an account-level extended key (depth 3).", { depth: node.depth });
  if ((hardening.branch || hardening.address) && !parsed.isPrivate) throw hodlError(hardening.branch ? "Hardened address branches cannot be derived from an account extended public key. Turn off Harden or import the matching extended private key offline." : "Hardened address indexes cannot be derived from an account extended public key. Turn off Harden or import the matching extended private key offline.");
  let definition = hodlImportedScriptDefinition(parsed), addressCount = Math.min(Math.max(count, 1), hodlMaxAddressRange), parentFingerprint = hodlFingerprintHex(node.parentFingerprint), nodeFingerprint = hodlFingerprintHex(node.fingerprint);
  tracker.setTotal(addressCount * branchRange);
  let account = await hodlAccountResultWithProgress(node, definition, network, addressCount, { accountPath: "Imported account key", accountIndex: null, imported: true, importedFamily: parsed.family, importedValue, parentFingerprint, nodeFingerprint, addressStart, branchHardened: hardening.branch, addressHardened: hardening.address, branchStart, branchRange }, tracker);
  node.wipePrivateData(); // the account result keeps its strings, not the imported node
  return {
    kind: "hd",
    network,
    mnemonic: null,
    passphraseUsed: false,
    passphrase: "",
    entropyHex: null,
    seedHex: null,
    rootXprv: null,
    rootXpub: null,
    importedPrivateKey: parsed.isPrivate ? importedValue : null,
    importedPublicKey: parsed.isPrivate ? null : importedValue,
    importedPrivateLabel: parsed.isPrivate ? parsed.prefix : null,
    importedPublicLabel: parsed.isPrivate ? null : parsed.prefix,
    masterFingerprint: null,
    parentFingerprint,
    nodeFingerprint,
    imported: true,
    notes,
    warnings: [...parsed.isPrivate ? [] : [hodlNote("Watch-only. This key contains no private key material.")], ...(mismatch ? [mismatch] : []), hodlNote("The imported account key did not include a master fingerprint or origin path, so descriptors intentionally omit a fabricated key origin.")],
    accounts: [account]
  };
}
function hodlAccountHasPrivate(account) {
  return Boolean(account.primaryPrivate || hodlAccountAddressBranches(account).some((branch) => branch.privateDescriptor || branch.rows.some((row) => row.wif)));
}
function hodlAccountAddressBranches(account) {
  if (account?.addressBranches?.length) return account.addressBranches;
  return [
    { branch: 0, role: "receive", label: "Receive", rows: account?.receive || [], publicDescriptor: account?.receiveDescriptor, privateDescriptor: account?.receiveDescriptorPriv },
    { branch: 1, role: "change", label: "Change", rows: account?.change || [], publicDescriptor: account?.changeDescriptor, privateDescriptor: account?.changeDescriptorPriv }
  ].filter((entry) => entry.rows.length || entry.publicDescriptor || entry.privateDescriptor);
}
function hodlAddressBranchDescriptorFields(branches, isPrivate = false) {
  return branches.map((branch) => {
    let descriptor = isPrivate ? branch.privateDescriptor : branch.publicDescriptor;
    if (!descriptor) return "";
    let label = `${isPrivate ? "Spending" : "Watch-only"} ${hodlAddressBranchLabel(branch.branch).toLowerCase()} descriptor`;
    return isPrivate ? hodlPrivateFieldHtml(label, descriptor) : hodlPublicFieldHtml(label, descriptor);
  }).join("");
}
function hodlAddressBranchKey(prefix, branch) {
  return `${prefix}-${branch === 0 ? "receive" : branch === 1 ? "change" : `branch-${branch}`}`;
}
function hodlAddressBranchTables(branches, includeWif, prefix) {
  return branches.map((branch) => {
    let label = hodlAddressBranchLabel(branch.branch), key = hodlAddressBranchKey(prefix, branch.branch);
    return `<h4 class="wallet-data-subtitle">${hodlEscapeHtml(label)}</h4>${hodlAddressTable(branch.rows, `${label} addresses`, includeWif, key)}`;
  }).join("");
}
function hodlAddressBranchVirtualConfigs(branches, includeWif, prefix) {
  return branches.map((branch) => ({ key: hodlAddressBranchKey(prefix, branch.branch), rows: branch.rows, includeWif }));
}
function hodlAccountAdvancedExports(account, includePrivate = false) {
  if (!account.hasAlternateExport) return "";
  let privateExport = includePrivate && account.genericPrivate ? hodlPrivateFieldHtml("Generic {name} for descriptor compatibility", account.genericPrivate, { name: account.genericPrivateLabel }) : "";
  let publicExport = !includePrivate && account.genericPublic ? hodlPublicFieldHtml("Generic {name} for descriptor compatibility", account.genericPublic, { name: account.genericPublicLabel }) : "";
  if (!privateExport && !publicExport) return "";
  if (includePrivate) return `<div class="wallet-advanced">${privateExport}</div>`;
  return `<details class="wallet-advanced"><summary>${hodlT("Advanced watch-only export")}</summary>${publicExport}</details>`;
}
function hodlImportedCoreRecoveryData(wallet, account) {
  if (!wallet?.importedPublicKey || !account?.imported || !["y", "z"].includes(account.primaryFamily) || !account.genericPublic || !account.def?.script) return null;
  return {
    importedLabel: `Imported ${wallet.importedPublicLabel || "extended public key"}`,
    importedKey: wallet.importedPublicKey,
    coreLabel: `Core ${account.genericPublicLabel}`,
    coreKey: account.genericPublic,
    descriptorLabel: "Bitcoin Core descriptor",
    descriptor: hodlDescriptorWithChecksum(hodlScriptDescriptor(account.def.script, `${account.genericPublic}/<0;1>/*`))
  };
}
function hodlImportedCoreRecoveryExport(wallet, account) {
  let data = hodlImportedCoreRecoveryData(wallet, account);
  if (!data) return "";
  return `<div class="wallet-data-fields imported-core-recovery"><h4 class="wallet-data-subtitle">Bitcoin Core recovery export</h4><p class="muted">The SLIP-132 prefix records the script type. The Core key above is the same payload with generic version bytes; this descriptor keeps the script type explicit and stays on the conventional receive/change branches for Bitcoin Core.</p>${hodlPublicFieldHtml(data.descriptorLabel, data.descriptor)}</div>`;
}
function hodlRenderMultisigCosignerExport(exports, accountId) {
  let items = Array.isArray(exports) ? exports.filter((candidate) => candidate.accountId === accountId) : [];
  return items.map((item) => hodlPublicFieldHtml("Multisig co-signer {prefix} · {label}", item.value, { prefix: item.prefix, label: item.label })).join("");
}
function hodlNormalizeAddressCheck(value){
  let text=String(value??"").trim();
  if(!text)return"";
  text=text.replace(/^bitcoin:/i,"").replace(/\?.*$/,"").trim();
  if(/^(bc1|tb1|bcrt1)/i.test(text)){
    if(/[A-Z]/.test(text)&&/[a-z]/.test(text))return text;
    return text.toLowerCase();
  }
  return text
}
function hodlAddressesEqual(left,right){
  if(!left||!right)return!1;
  if(/^(bc1|tb1|bcrt1)/i.test(left)|| /^(bc1|tb1|bcrt1)/i.test(right))return left.toLowerCase()===right.toLowerCase();
  return left===right
}
function hodlMatchDerivedAddress(raw,receive=[],change=[]){
  let address=hodlNormalizeAddressCheck(raw);
  if(!address)return{state:"empty"};
  let find=(rows,chain)=>{
    for(let row of rows||[])if(hodlAddressesEqual(address,String(row.address||"")))return{state:"match",chain,index:row.index,path:row.path,address:row.address};
    return null
  };
  return find(receive,"receive")||find(change,"change")||{state:"miss",receiveCount:(receive||[]).length,changeCount:(change||[]).length}
}
function hodlMatchAddressBranches(raw, branches = []) {
  let address = hodlNormalizeAddressCheck(raw);
  if (!address) return { state: "empty" };
  for (let branch of branches) for (let row of branch.rows || []) if (hodlAddressesEqual(address, String(row.address || ""))) return { state: "match", chain: branch.role, branch: branch.branch, index: row.index, path: row.path, address: row.address };
  return { state: "miss", shownCount: Math.max(0, ...branches.map((branch) => branch.rows?.length || 0)) };
}
function hodlAddressCheckRows(){
  if(hodlWalletResult?.kind==="msig")return{receive:hodlWalletResult.receive||[],change:hodlWalletResult.change||[],branches:hodlAccountAddressBranches(hodlWalletResult)};
  if(hodlWalletResult?.kind==="hd"){
    let id=hodlSelectedScriptType(),account=hodlWalletResult.accounts.find(candidate=>candidate.def.id===id)||hodlWalletResult.accounts[0];
    return{receive:account?.receive||[],change:account?.change||[],branches:hodlAccountAddressBranches(account)}
  }
  return{receive:[],change:[],branches:[]}
}
function hodlAddressMatchMarkup(){
  return `<label class="field address-match-field">Check an address
    <input id="address-match" autocomplete="off" spellcheck="false" placeholder="Paste bc1\u2026 or a 1\u2026 / 3\u2026 address">
    <span class="field-note">Paste an address shown by another wallet. A match means that wallet computed the same selected branch and derivation, even if the index is beyond the table above.</span>
    <span class="hint" id="address-match-status" role="status"></span>
  </label>`
}
var hodlAddressSearchLimit = 1000;

function hodlMatchHdAddressBeyond(address, account, start) {
  let extendedKey = account?.branchHardened ? account?.xprv || account?.genericPrivate : account?.xpub || account?.genericPublic;
  if (!extendedKey || !account?.def) return {
    state: "miss",
    searchedTo: start
  };
  let node = hodlHDKey.fromExtendedKey(extendedKey),
    network = account.network || hodlWalletResult.network,
    script = account.def.script,
    base = account.accountPath || "m";
  let searchEnd = Math.min(hodlMaxAddressIndex + 1, start + hodlAddressSearchLimit);
  for (let index = start; index < searchEnd; index++) {
    for (let branch of hodlAccountAddressBranches(account)) {
      let chain = branch.branch, role = branch.role, branchStep = hodlPathComponent(chain, account.branchHardened), indexStep = hodlPathComponent(index, account.addressHardened);
      let child = node.derive(`m/${branchStep}/${indexStep}`),
        pk = child.publicKey;
      if (!pk) continue;
      if (hodlAddressesEqual(address, hodlAddressOrThrow(script, pk, network))) return {
        state: "match",
        chain: role,
        branch: chain,
        index,
        path: `${base}/${branchStep}/${indexStep}`,
        beyond: !0
      }
    }
  }
  return {
    state: "miss",
    searchedTo: searchEnd - 1
  }
}

function hodlMatchMsigAddressBeyond(address, start) {
  let nodes = hodlWalletResult?.nodes;
  if (!nodes?.length) return {
    state: "miss",
    searchedTo: start
  };
  let bip45 = hodlWalletResult.script === "p2sh" && hodlWalletResult.scriptStandard === "bip45";
  let searchEnd = Math.min(hodlMaxAddressIndex + 1, start + hodlAddressSearchLimit);
  for (let index = start; index < searchEnd; index++) {
    for (let branch of hodlAccountAddressBranches(hodlWalletResult)) {
      let path = bip45 ? `m/0/${branch.branch}/` : `m/${branch.branch}/`, keys = nodes.map(node => {
        let key = node.derive(path + index).publicKey;
        if (!key) throw new Error("Could not derive a public key");
        return key;
      });
      if (hodlAddressesEqual(address, hodlMsigAddr(keys, hodlWalletResult.m, hodlWalletResult.network, hodlWalletResult.script, hodlWalletResult.sorted !== !1).address)) return { state: "match", chain: branch.role, branch: branch.branch, index, path: path.slice(1) + index, beyond: !0 };
    }
  }
  return {
    state: "miss",
    searchedTo: searchEnd - 1
  }
}

function hodlBindAddressMatch() {
  let input = document.getElementById("address-match"),
    status = document.getElementById("address-match-status");
  if (!input || !status) return;
  let update = () => {
    let rows = hodlAddressCheckRows(),
      shown = Math.max(0, ...rows.branches.map((branch) => branch.rows.length)), firstShown = Math.min(...rows.branches.map((branch) => branch.rows[0]?.index ?? Infinity)), lastShown = Math.max(...rows.branches.map((branch) => branch.rows.at(-1)?.index ?? -1)), nextIndex = lastShown + 1,
      result = hodlMatchAddressBranches(input.value, rows.branches);
    if (result.state === "empty") {
      status.textContent = "";
      status.className = "hint";
      return
    }
    let showMatch = hit => {
      let chain = hodlAddressBranchLabel(hit.branch ?? (hit.chain === "receive" ? 0 : 1)),
        extra = hit.beyond ? ` (beyond the ${shown} shown)` : "";
      status.textContent = `${chain} address #${hit.index} of this wallet \xB7 ${hodlDisplayDerivationPath(hit.path)}${extra}`;
      status.className = "hint ok"
    };
    if (result.state === "match") {
      showMatch(result);
      return
    }
    let address = hodlNormalizeAddressCheck(input.value);
    status.textContent = hodlTText("Not in the {n} shown addresses. Checking further indices", { n: shown });
    status.className = "hint";
    let beyond = {
      state: "miss",
      searchedTo: lastShown
    };
    try {
      if (hodlWalletResult?.kind === "hd") {
        let id = hodlSelectedScriptType(),
          account = hodlWalletResult.accounts.find(candidate => candidate.def.id === id) || hodlWalletResult.accounts[0];
        beyond = hodlMatchHdAddressBeyond(address, account, nextIndex)
      } else if (hodlWalletResult?.kind === "msig") beyond = hodlMatchMsigAddressBeyond(address, nextIndex)
    } catch (error) {
      beyond = {
        state: "miss",
        searchedTo: lastShown
      }
    }
    if (beyond.state === "match") {
      showMatch(beyond);
      return
    }
    status.textContent = `No match in ${hodlAddressBranchSummary(rows.branches.map((branch) => branch.branch)).toLowerCase()} indices ${Number.isFinite(firstShown) ? firstShown : 0}\u2013${beyond.searchedTo ?? lastShown} of this derivation.`;
    status.className = "hint bad"
  };
  input.oninput = update;
  update()
}
var hodlAddressVirtualThreshold = 24, hodlAddressVirtualRowHeight = 34, hodlAddressVirtualOverscan = 6;
function hodlAddressTableRows(rows, includeWif = false, rowOffset = 0) {
  return rows.map((row, offset) => `<tr aria-rowindex="${rowOffset + offset + 2}"><th scope="row">${row.index}</th><td>${hodlEscapeHtml(hodlDisplayDerivationPath(row.path))}</td><td>${hodlEscapeHtml(row.address)}</td>${includeWif ? `<td>${hodlPrivateValue(row.wif, "mono table-private-field-value")}</td>` : ""}</tr>`).join("");
}
function hodlAddressVirtualSpacer(height, columns) {
  return height > 0 ? `<tr class="address-virtual-spacer" aria-hidden="true"><td colspan="${columns}" style="height:${height}px"></td></tr>` : "";
}
function hodlAddressVirtualRows(rows, includeWif, start, end) {
  let columns = includeWif ? 4 : 3, top = start * hodlAddressVirtualRowHeight, bottom = (rows.length - end) * hodlAddressVirtualRowHeight;
  return `${hodlAddressVirtualSpacer(top, columns)}${hodlAddressTableRows(rows.slice(start, end), includeWif, start)}${hodlAddressVirtualSpacer(bottom, columns)}`;
}
function hodlAddressTable(rows, label = "Addresses", includeWif = false, tableKey = "addresses") {
  let rawLabel = includeWif ? hodlTText("{label} with WIF private keys", { label }) : label, safeLabel = hodlEscapeHtml(rawLabel), tableClass = includeWif ? "wallet-table-private" : "wallet-table-public", virtual = rows.length > hodlAddressVirtualThreshold;
  let wifHeading = includeWif ? '<th scope="col">WIF</th>' : "", safeKey = hodlEscapeHtml(tableKey), initialEnd = virtual ? Math.min(rows.length, hodlAddressVirtualThreshold) : rows.length;
  let body = virtual ? hodlAddressVirtualRows(rows, includeWif, 0, initialEnd) : hodlAddressTableRows(rows, includeWif);
  return `<div class="wallet-address-table" data-address-table="${safeKey}"><div class="wallet-table ${tableClass}" role="region" tabindex="0" aria-label="${hodlTAttr("{label} table; scroll continuously for more rows or columns", { label: rawLabel })}"><table aria-rowcount="${rows.length + 1}"><caption class="sr-only">${safeLabel}</caption><thead><tr aria-rowindex="1"><th scope="col">#</th><th scope="col">${hodlT("Path")}</th><th scope="col">${hodlT("Address")}</th>${wifHeading}</tr></thead><tbody>${body}</tbody></table></div></div>`;
}
function hodlBindAddressVirtualization(configs = []) {
  document.querySelectorAll("[data-address-table]").forEach((container) => {
    let config = configs.find((candidate) => candidate.key === container.dataset.addressTable), scroller = container.querySelector(".wallet-table"), body = container.querySelector("tbody");
    if (!config || !scroller || !body || config.rows.length <= hodlAddressVirtualThreshold) return;
    let frame = 0, renderedStart = -1, renderedEnd = -1;
    let render = () => {
      frame = 0;
      let headerHeight = scroller.querySelector("thead")?.offsetHeight || 0;
      let viewportRows = Math.ceil(Math.max(hodlAddressVirtualRowHeight, scroller.clientHeight - headerHeight) / hodlAddressVirtualRowHeight);
      let firstVisible = Math.floor(Math.max(0, scroller.scrollTop - headerHeight) / hodlAddressVirtualRowHeight);
      let start = Math.max(0, firstVisible - hodlAddressVirtualOverscan), end = Math.min(config.rows.length, firstVisible + viewportRows + hodlAddressVirtualOverscan);
      if (start === renderedStart && end === renderedEnd) return;
      renderedStart = start;
      renderedEnd = end;
      body.innerHTML = hodlAddressVirtualRows(config.rows, Boolean(config.includeWif), start, end);
    };
    scroller.addEventListener("scroll", () => {
      if (!frame) frame = requestAnimationFrame(render);
    }, { passive: true });
    render();
  });
}
function hodlSlip132Fields(account, wallet, isPrivate = false) {
  let pasted = isPrivate ? (wallet?.importedPrivateKey || "") : (wallet?.importedPublicKey || "");
  let core = (isPrivate ? account.genericPrivate : account.genericPublic) || "";
  let coreLabel = isPrivate ? account.genericPrivateLabel : account.genericPublicLabel;
  let slip = account.hasAlternateExport ? (isPrivate ? account.primaryPrivate : account.primaryPublic) : "";
  let slipLabel = isPrivate ? account.primaryPrivateLabel : account.primaryPublicLabel;
  let field = isPrivate ? hodlPrivateFieldHtml : hodlPublicFieldHtml, parts = [];
  if (pasted) parts.push(field("As pasted", pasted));
  if (core && core !== pasted) parts.push(field(`Bitcoin Core ${coreLabel}`, core));
  if (slip && slip !== pasted && slip !== core) parts.push(field(`SLIP-132 ${slipLabel}`, slip));
  if (!parts.length && core) parts.push(field(`Account ${coreLabel}`, core));
  if (!isPrivate) parts.push(`<p class="muted slip132-note">Prefix swap only (same payload, new version bytes and checksum). Script lives in the descriptor, not the prefix. x = legacy, y = nested BIP49, z = native BIP84, Y = nested BIP48 nested-msig, Z = native BIP48 native-msig. Testnet: t / u / v / U / V. No Taproot SLIP prefix.</p>`);
  return parts.join("");
}
function hodlSlip132WatchFields(account, wallet) {
  return hodlSlip132Fields(account, wallet, false);
}
function hodlShowAccount(id) {
  if (!hodlWalletResult || hodlWalletResult.kind !== "hd") return;
  let account = hodlWalletResult.accounts.find((candidate) => candidate.def.id === id);
  if (!account) return;
  hodlSetSelectedScriptType(id);
  hodlSyncAccountTabs(id);
  let branches = hodlAccountAddressBranches(account), firstBranch = branches[0], firstAddress = firstBranch?.rows[0], firstIndex = firstAddress?.index ?? 0, firstLabel = firstBranch ? hodlAddressBranchLabel(firstBranch.branch) : "Address", hasPrivate = hodlAccountHasPrivate(account), purposeLabel = account.imported ? account.def.bip : `Purpose ${hodlPathComponent(account.def.purpose, account.def.purposeHardened !== false)}`;
  let privateSection = hasPrivate ? `
    <section class="account-result-section account-private-section" aria-labelledby="account-private-heading">
      <div class="wallet-data-section-head">
        <h3 id="account-private-heading">${hodlT("Private account material")}</h3>
        <p class="muted">${hodlT("These exports can spend from this account. They are shown only for a seed or extended private-key source.")}</p>
      </div>
      ${hodlSlip132Fields(account, hodlWalletResult, true)}
      ${hodlAddressBranchDescriptorFields(branches, true)}
      ${hodlAccountAdvancedExports(account, true)}
      <p class="account-private-warning">${hodlT("<strong>Keep these exports together only in secure offline backups.</strong> An account extended public key combined with any non-hardened descendant private key, including a WIF shown in the address tables below, can reconstruct that account's extended private key.")}</p>
    </section>` : "";
  hodlElement("#acct").innerHTML = `
    <div class="key-result-main">
      <div class="kicker">${hodlEscapeHtml(purposeLabel)} \xB7 ${hodlEscapeHtml(hodlWalletResult.network)}</div>
      <h2>${hodlEscapeHtml(account.def.label)}</h2>
      <p class="muted">${hodlEscapeHtml(account.def.beginner)}</p>
      ${privateSection}
      <section class="account-result-section account-watch-section" aria-labelledby="account-watch-heading">
        <div class="wallet-data-section-head">
          <h3 id="account-watch-heading">${hodlT("Watch-only wallet data")}</h3>
          <p class="watch-only-note">${hodlT("<strong>Cannot spend:</strong> these exports can monitor every address and reveal this account's transaction history and balance. Treat them as privacy-sensitive.")}</p>
        </div>
        ${hodlSlip132WatchFields(account, hodlWalletResult)}
        ${hodlImportedCoreRecoveryExport(hodlWalletResult, account)}
        ${hodlRenderMultisigCosignerExport(hodlWalletResult.multisigCosignerExports, account.def.id)}
        ${hodlWatchOnlyDescriptorExport(account.receiveDescriptor, account.changeDescriptor, branches)}
        ${hodlAccountAdvancedExports(account, false)}
      </section>
      <section class="account-result-section account-address-section" aria-labelledby="account-address-heading">
        <div class="wallet-data-section-head">
          <h3 id="account-address-heading">Addresses</h3>
          <p class="muted">Verify the first selected address on another trusted wallet or signing device before accepting bitcoin.</p>
        </div>
        ${firstAddress ? `<div class="account-address-lead"><h4 class="wallet-data-subtitle">${hodlEscapeHtml(firstLabel)} address #${firstIndex}</h4><div class="qr" aria-label="${hodlEscapeHtml(firstLabel)} address ${firstIndex} QR code">${hodlQrSvg(firstAddress.address)}</div><p class="mono">${hodlEscapeHtml(firstAddress.address)}</p><p class="muted mono">${hodlEscapeHtml(hodlDisplayDerivationPath(firstAddress.path))}</p></div>` : ""}
        ${hodlAddressBranchTables(branches, hasPrivate, "hd")}
        ${hodlAddressMatchMarkup()}
      </section>
    </div>`;
  hodlBindAddressVirtualization(hodlAddressBranchVirtualConfigs(branches, hasPrivate, "hd"));
  hodlBindAddressMatch();
  hodlBindWalletResultActions();
}
// The field helpers own their labels end to end: pass the English source (and
// optional placeholder values); the helper translates with the text view and
// escapes for its HTML slot. That keeps raw translation calls out of template
// interpolations and keeps the literals extractable by scripts/i18n-sync.mjs.
function hodlPublicFieldHtml(label, value, vars) {
  let labelHtml = hodlEscapeHtml(hodlTText(label, vars));
  return `<p><span class="muted">${labelHtml}</span><br><span class="mono">${hodlEscapeHtml(value ?? "\u2014")}</span></p>`;
}
function hodlPrivateValue(value, className = "secret private-field-value") {
  let mask = "************", text = String(value ?? "\u2014");
  if (hodlRevealPrivate) return `<span class="${className}">${hodlEscapeHtml(text)}</span>`;
  let bullets = "\u2022".repeat(Math.max(Array.from(text).length, mask.length));
  return `<span class="${className} secret-placeholder"><span class="secret-placeholder-mask" aria-hidden="true">${bullets}</span><span class="secret-placeholder-message" aria-hidden="true">${mask}</span><span class="secret-placeholder-label">${hodlT("Private value hidden")}</span></span>`;
}
function hodlPrivateFieldHtml(label, value, vars) {
  let labelHtml = hodlEscapeHtml(hodlTText(label, vars));
  return `<p class="private-field"><span class="muted">${labelHtml}</span>${hodlPrivateValue(value)}</p>`;
}
function hodlDisplayDerivationPath(value) {
  return String(value ?? "").replace(/(^|\/)(\d+)[hH](?=\/|$)/g, "$1$2'");
}
function hodlEscapeHtml(value) {
  let entities = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };
  return Array.from(String(value ?? ""), (character) => entities[character] ?? character).join("");
}
function hodlPrivateDataControls(descriptionId, scope = "wallet") {
  let privateSheet = hodlRevealPrivate, downloadLabel = privateSheet ? hodlT("Save unencrypted private sheet") : hodlT("Save watch-only sheet");
  let disclosure = privateSheet ? scope === "wallet" ? hodlT("The downloaded plain-text file is unencrypted and includes all available root and account private recovery material across every script type.") : hodlT("The downloaded plain-text file is unencrypted and includes every private key shown in this section.") : hodlT("The downloaded sheet omits all private recovery material.");
  return `<div class="wallet-data-actions no-print">
    <label class="reveal-private-toggle">
      <input type="checkbox" id="reveal" ${hodlRevealPrivate ? "checked" : ""} aria-describedby="${descriptionId} recovery-sheet-disclosure" />
      <span>${hodlT("Show private recovery material")} <span class="reveal-private-toggle-note">${hodlT("(air-gap only)")}</span></span>
    </label>
    <button class="btn secondary save-recovery-sheet" id="save" type="button" aria-describedby="recovery-sheet-disclosure">${downloadLabel}</button>
    ${hodlWalletDatControl(privateSheet)}
    <p class="recovery-download-disclosure" id="recovery-sheet-disclosure"><strong>${privateSheet ? hodlT("Private export:") : hodlT("Watch-only export:")}</strong> ${disclosure}</p>
  </div>`;
}
function hodlWalletDatControl(includePrivate) {
  if (!hodlWalletExport.hasDescriptors(hodlWalletResult)) return "";
  // Bitcoin Core starts its automatic scan at the wallet birthday stored in
  // the descriptor records. Recovery needs genesis (creation time 0) so
  // transactions predating this export are found; "now" is only safe for
  // keys created at this moment and skips past history (faster, and reveals
  // no older activity to anyone who later sees the file). If a loaded wallet
  // looks empty, repair it with Bitcoin Core's `rescanblockchain 0`.
  return `<label class="wallet-dat-birthday">${hodlT("Wallet birthday")} <select data-wallet-dat-birthday aria-describedby="wallet-dat-birthday-help"><option value="genesis"${hodlWalletDatBirthday === "genesis" ? " selected" : ""}>${hodlT("Recovering keys · scan from genesis")}</option><option value="now"${hodlWalletDatBirthday === "now" ? " selected" : ""}>${hodlT("New keys · created today")}</option></select></label><button class="btn secondary save-wallet-dat" id="download-wallet-dat" type="button" aria-describedby="recovery-sheet-disclosure wallet-dat-birthday-help">${hodlWalletExport.walletDatButtonLabel(includePrivate)}</button><p class="muted wallet-dat-birthday-help" id="wallet-dat-birthday-help">${hodlT("Bitcoin Core only auto-scans history back to the birthday. Choose “New keys” only for entropy created right now; recovering older keys with today's birthday can look empty until you run <code>rescanblockchain 0</code> in Bitcoin Core.")}</p>`;
}
function hodlSaveRecoveryControl() {
  return `<div class="wallet-data-actions no-print"><button class="btn secondary save-recovery-sheet" id="save" type="button">${hodlT("Save watch-only sheet")}</button>${hodlWalletDatControl(false)}</div>`;
}
function hodlWalletMessages(wallet, idPrefix) {
  let warnings = [...wallet.warnings || []].filter((message) => !wallet.passphraseUsed || hodlNoteKey(message) !== "note.passphraseInUse"), notes = [...wallet.notes || []];
  if (wallet.passphraseUsed) warnings.unshift(hodlNote("A BIP39 passphrase is in use. It creates a different wallet, is not printed in the recovery sheet, and must be preserved separately to recover this wallet."));
  if (!warnings.length && !notes.length) return "";
  let items = [...warnings.map((message) => `<li class="is-warning">${hodlEscapeHtml(hodlFormatNote(message))}</li>`), ...notes.map((message) => `<li>${hodlEscapeHtml(hodlFormatNote(message))}</li>`)].join("");
  return `<section class="wallet-result-messages" aria-labelledby="${idPrefix}-safety-heading"><h3 id="${idPrefix}-safety-heading">Safety notes</h3><ul>${items}</ul></section>`;
}
function hodlSingleWalletData(wallet) {
  let miniKey = wallet.minikey ? hodlPrivateFieldHtml("Mini private key", wallet.minikey) : "";
  return `<section class="card wallet-data-card">
    <div class="wallet-data-intro">
      <div class="kicker">${hodlT("Single-key wallet data")}</div>
      <h2 tabindex="-1">${hodlT("Key recovery details")}</h2>
      <p class="muted">${hodlT("Review the private key and addresses derived from this input. Sensitive recovery material is grouped first; public wallet data appears below.")}</p>
      ${hodlWalletMessages(wallet, "single")}
    </div>
    <section class="wallet-data-section wallet-private-section" aria-labelledby="single-private-heading">
      <div class="wallet-data-section-head">
        <h3 id="single-private-heading">${hodlT("Private key material")}</h3>
        <p class="muted" id="single-private-description">${hodlT("These values can spend the bitcoin held by the addresses below. Reveal them only while this file is running offline on an air-gapped computer.")}</p>
      </div>
      ${hodlPrivateDataControls("single-private-description", "single")}
      <div class="wallet-data-fields">
        ${hodlPrivateFieldHtml("WIF compressed", wallet.wifCompressed)}
        ${hodlPrivateFieldHtml("WIF uncompressed", wallet.wifUncompressed)}
        ${hodlPrivateFieldHtml("Hex private key", wallet.privHex)}
        ${miniKey}
      </div>
    </section>
    <section class="wallet-data-section wallet-public-section" aria-labelledby="single-public-heading">
      <div class="wallet-data-section-head">
        <h3 id="single-public-heading">${hodlT("Public keys & addresses")}</h3>
        <p class="muted">${hodlT("Use these values for verification or watch-only monitoring. They do not reveal the private key.")}</p>
      </div>
      <div class="wallet-data-fields">
        ${hodlPublicFieldHtml("Compressed public key", wallet.pubkeyCompressed)}
        ${hodlPublicFieldHtml("Uncompressed public key", wallet.pubkeyUncompressed)}
        <h4 class="wallet-data-subtitle">${hodlT("Addresses")}</h4>
        ${hodlPublicFieldHtml("Legacy uncompressed", wallet.p2pkhUncompressed)}
        ${hodlPublicFieldHtml("Legacy compressed", wallet.p2pkhCompressed)}
        ${hodlPublicFieldHtml("Nested SegWit", wallet.p2shP2wpkh)}
        ${hodlPublicFieldHtml("Native SegWit", wallet.p2wpkh)}
        ${hodlPublicFieldHtml("Taproot", wallet.p2tr)}
        <h4 class="wallet-data-subtitle">${hodlT("Native SegWit QR code")}</h4>
        <div class="qr" aria-label="${hodlTAttr("Native SegWit address QR code")}">${hodlQrSvg(wallet.p2wpkh)}</div>
      </div>
    </section>
  </section>`;
}
function hodlHdWalletData(wallet) {
  let privateFields = [];
  if (wallet.mnemonic) privateFields.push(hodlSeedPhraseField(`Your seed phrase \xB7 ${wallet.mnemonic.trim().split(/\s+/).length} words`, wallet.mnemonic), hodlSeedQrExport(wallet.mnemonic, { passphraseUsed: wallet.passphraseUsed, entropyHex: wallet.entropyHex }));
  // The passphrase sits right under the words it belongs to: without it the
  // words recover a different wallet, so it is recovery material too.
  if (wallet.mnemonic && wallet.passphraseUsed && wallet.passphrase) privateFields.push(hodlPrivateFieldHtml("BIP39 passphrase", wallet.passphrase));
  if (wallet.entropyHex) privateFields.push(hodlPrivateFieldHtml("BIP39 entropy hex", wallet.entropyHex));
  if (wallet.seedHex) privateFields.push(hodlPrivateFieldHtml("Master seed hex", wallet.seedHex));
  if (wallet.rootXprv) privateFields.push(hodlPrivateFieldHtml(`Root ${wallet.rootPrivateLabel || hodlExtendedKeyVersions[wallet.network].x.prvName}`, wallet.rootXprv));
  if (wallet.importedPrivateKey) privateFields.push(hodlPrivateFieldHtml(`Imported ${wallet.importedPrivateLabel || "extended private key"}`, wallet.importedPrivateKey));
  let hasAccountPrivate = wallet.accounts.some(hodlAccountHasPrivate), hasPrivate = privateFields.length > 0 || hasAccountPrivate;
  let privateContent = privateFields.length ? privateFields.join("") : `<p class="muted">Private account material is available in the selected script panel below; no BIP32 root private key was supplied.</p>`;
  let intro = wallet.mnemonic ? "Review the root material derived from this seed. Private recovery data is grouped first; watch-only data appears below." : "Review the material available from this imported extended key. Private data, when present, is grouped first; watch-only data appears below.";
  let source = wallet.mnemonic ? "" : `<p><span class="muted">Source</span><br><span>Imported extended ${hasPrivate ? "private" : "public"} key; no seed phrase was entered.</span></p>`;
  let privateSection = hasPrivate ? `<section class="wallet-data-section wallet-private-section" aria-labelledby="wallet-private-heading">
      <div class="wallet-data-section-head">
        <h3 id="wallet-private-heading">${hodlT("Private recovery material")}</h3>
        <p class="muted" id="wallet-private-description">${hodlT("These values can recreate or spend from the wallet. Reveal them only while this file is running offline on an air-gapped computer.")}</p>
      </div>
      ${hodlPrivateDataControls("wallet-private-description")}
      <div class="wallet-data-fields">${privateContent}</div>
    </section>` : "";
  let fingerprint = wallet.masterFingerprint ? hodlPublicFieldHtml("Master fingerprint", wallet.masterFingerprint) : "";
  let parentFingerprint = !wallet.masterFingerprint && wallet.parentFingerprint ? hodlPublicFieldHtml("Encoded parent fingerprint (not a master fingerprint)", wallet.parentFingerprint) : "";
  let nodeFingerprint = !wallet.masterFingerprint && wallet.nodeFingerprint ? hodlPublicFieldHtml("Imported key fingerprint (not a master fingerprint)", wallet.nodeFingerprint) : "";
  let rootPublic = wallet.rootXpub ? hodlPublicFieldHtml("Root {name}", wallet.rootXpub, { name: wallet.rootPublicLabel || hodlExtendedKeyVersions[wallet.network].x.pubName }) : "";
  let importedPublic = wallet.importedPublicKey ? hodlPublicFieldHtml("Imported {name}", wallet.importedPublicKey, { name: wallet.importedPublicLabel || hodlTText("extended public key") }) : "";
  return `<section class="card wallet-data-card">
    <div class="wallet-data-intro">
      <div class="kicker">${hodlT("Wallet data")}</div>
      <h2 tabindex="-1">${hodlT("Wallet recovery details")}</h2>
      <p class="muted">${intro}</p>
      ${hodlWalletMessages(wallet, "wallet")}
    </div>
    ${privateSection}
    <section class="wallet-data-section wallet-public-section" aria-labelledby="wallet-public-heading">
      <div class="wallet-data-section-head">
        <h3 id="wallet-public-heading">${hodlT("Watch-only wallet data")}</h3>
        <p class="muted">${hodlT("These values identify the wallet or enable watch-only use, but do not authorize spending. Treat them as privacy-sensitive because extended public keys and descriptors can reveal wallet addresses, balances, and transaction history.")}</p>
      </div>
      ${hasPrivate ? "" : hodlSaveRecoveryControl()}
      <div class="wallet-data-fields">
        ${fingerprint}
        ${parentFingerprint}
        ${nodeFingerprint}
        ${rootPublic}
        ${importedPublic}
        ${source}
      </div>
    </section>
  </section>`;
}
// Stamp the recovery sheet with the build version (substituted by the build).
function hodlFormatRecoverySheet(text) {
  const lines = text.split("\n");
  if (lines[1] !== "ENTROPYLAB V{{VERSION}}") lines.splice(1, 0, "ENTROPYLAB V{{VERSION}}");
  return lines.join("\n");
}
function hodlDownloadRecoverySheet() {
  if (!hodlWalletResult) return;
  let blob = new Blob([hodlFormatRecoverySheet(hodlRecoverySheetText(hodlWalletResult, hodlRevealPrivate))], { type: "text/plain" }), url = URL.createObjectURL(blob), link = document.createElement("a");
  link.href = url;
  link.download = "bitcoin-recovery-sheet.txt";
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1e3);
}
function hodlWalletDatDeps() {
  return {
    sha256: (bytes) => hodlSha256(bytes),
    checksum: hodlDescriptorChecksum,
    base58Decode: (text) => hodlBase58Check.decode(text),
    deriveBranchBody: (extendedKeyText, branch) => {
      // Any SLIP-132 prefix is accepted; it is re-versioned to plain xpub here.
      let node = hodlHDKey.fromExtendedKey(hodlReversionExtendedKey(extendedKeyText, hodlExtendedKeyVersions.mainnet.x.pub)).deriveChild(branch), body = new Uint8Array(74), view = new DataView(body.buffer);
      body[0] = node.depth;
      view.setUint32(1, node.parentFingerprint >>> 0, false);
      view.setUint32(5, node.index >>> 0, false);
      body.set(node.chainCode, 9);
      body.set(node.publicKey, 41);
      return body;
    },
    publicKeyForPrivate: (secret) => hodlSecp256k1.getPublicKey(secret, true)
  };
}
function hodlDownloadWalletDat() {
  if (!hodlWalletResult || !hodlWalletExport.hasDescriptors(hodlWalletResult)) return;
  // Recovery default is a genesis birthday so Core scans from the start;
  // "now" is written only when the user confirms the keys are new (issue
  // #95).
  let creationTime = hodlWalletDatBirthday === "now" ? Math.floor(Date.now() / 1000) : 0;
  let bytes = hodlWalletExport.buildWalletDat(hodlWalletResult, hodlRevealPrivate, hodlWalletDatDeps(), creationTime), blob = new Blob([bytes], { type: "application/octet-stream" }), url = URL.createObjectURL(blob), link = document.createElement("a");
  link.href = url;
  link.download = hodlWalletExport.walletDatFilename(hodlWalletResult, hodlRevealPrivate);
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1e3);
}
function hodlBindWalletResultActions() {
  let reveal = document.getElementById("reveal");
  if (reveal) reveal.onchange = () => {
    hodlRevealPrivate = reveal.checked;
    let state = hodlKeys[hodlActiveKey];
    if (state) state.reveal = hodlRevealPrivate;
    hodlRefreshKeyResult();
    requestAnimationFrame(() => document.getElementById("reveal")?.focus({ preventScroll: true }));
  };
  let save = document.getElementById("save");
  if (save) {
    let clean = save.cloneNode(true);
    save.replaceWith(clean);
    clean.addEventListener("click", hodlDownloadRecoverySheet);
  }
  let walletDat = document.getElementById("download-wallet-dat");
  if (walletDat) {
    let clean = walletDat.cloneNode(true);
    walletDat.replaceWith(clean);
    clean.addEventListener("click", hodlDownloadWalletDat);
  }
  document.querySelectorAll("[data-wallet-dat-birthday]").forEach((select) => {
    select.value = hodlWalletDatBirthday;
    select.onchange = () => {
      hodlWalletDatBirthday = select.value === "now" ? "now" : "genesis";
    };
  });
  hodlBindAddressMatch();
}
function hodlFocusWalletResult() {
  requestAnimationFrame(() => (hodlWorkspace === "msig" ? document.getElementById("msig-summary-policy") || document.querySelector("#msig-out h2") : document.getElementById("key-summary-fingerprint") || hodlOutEl.querySelector(".account-address-lead, .wallet-data-intro h2"))?.focus?.({ preventScroll: false }));
}
function hodlRefreshKeyResult() {
  hodlRenderKeyResult();
  hodlBindWalletResultActions();
}
function hodlSheetWarnings(lines, wallet) {
  for (let note of wallet.notes || []) lines.push(`Note: ${hodlFormatNote(note)}`);
  for (let warning of wallet.warnings || []) lines.push(`Warning: ${hodlFormatNote(warning)}`);
}
function hodlSheetAddressRows(lines, label, rows) {
  lines.push(label.toUpperCase());
  for (let row of rows) lines.push(`  ${row.index}  ${hodlDisplayDerivationPath(row.path)}  ${row.address}`);
}
function hodlSheetWifRows(lines, label, rows) {
  let privateRows = rows.filter((row) => row.wif);
  if (!privateRows.length) return;
  lines.push(label.toUpperCase());
  for (let row of privateRows) lines.push(`  ${row.index}  ${hodlDisplayDerivationPath(row.path)}  ${row.wif}`);
}
var hodlRecoverySheetText = function(wallet, revealPrivate) {
  let lines = ["ENTROPYLAB \u2014 RECOVERY SHEET", "This file was computed locally. The calculator never generated wallet entropy.", ""];
  lines.push(`Network: ${wallet.network}`);
  if (wallet.passphraseUsed) lines.push("Passphrase: YES (not printed)");
  hodlSheetWarnings(lines, wallet);
  lines.push("");
  if (wallet.kind === "single") {
    if (revealPrivate) {
      lines.push("PRIVATE RECOVERY MATERIAL", `WIF compressed:   ${wallet.wifCompressed ?? ""}`, `WIF uncompressed: ${wallet.wifUncompressed ?? ""}`, `Hex private key:  ${wallet.privHex ?? ""}`);
      if (wallet.minikey) lines.push(`Mini key: ${wallet.minikey}`);
    } else lines.push("PRIVATE RECOVERY MATERIAL OMITTED", "Private values were not saved because Show private recovery material was off.");
    lines.push("", "PUBLIC KEYS AND ADDRESSES", `Compressed public key:   ${wallet.pubkeyCompressed}`, `Uncompressed public key: ${wallet.pubkeyUncompressed}`, `Legacy uncompressed: ${wallet.p2pkhUncompressed}`, `Legacy compressed:   ${wallet.p2pkhCompressed}`, `Nested SegWit:       ${wallet.p2shP2wpkh}`, `Native SegWit:       ${wallet.p2wpkh}`, `Taproot:             ${wallet.p2tr}`);
    return lines.join("\n");
  }
  let hasPrivate = Boolean(wallet.mnemonic || wallet.entropyHex || wallet.seedHex || wallet.rootXprv || wallet.importedPrivateKey || wallet.accounts.some(hodlAccountHasPrivate));
  if (hasPrivate && revealPrivate) {
    lines.push("PRIVATE RECOVERY MATERIAL");
    if (wallet.mnemonic) {
      lines.push("", "YOUR SEED PHRASE", wallet.mnemonic);
      let seedQrDigits = hodlSeedQrDigits(wallet.mnemonic);
      if (seedQrDigits) lines.push("", "SEEDQR DIGITS", seedQrDigits);
    }
    if (wallet.entropyHex) lines.push("", "BIP39 ENTROPY HEX", wallet.entropyHex);
    if (wallet.seedHex) lines.push("", "MASTER SEED HEX (BIP39 PBKDF2, 512 bits)", wallet.seedHex);
    if (wallet.rootXprv) lines.push("", `BIP32 ROOT ${(wallet.rootPrivateLabel || hodlExtendedKeyVersions[wallet.network].x.prvName).toUpperCase()}`, wallet.rootXprv);
    if (wallet.importedPrivateKey) lines.push("", `IMPORTED ${(wallet.importedPrivateLabel || "EXTENDED PRIVATE KEY").toUpperCase()}`, wallet.importedPrivateKey);
    for (let account of wallet.accounts) {
      if (!hodlAccountHasPrivate(account)) continue;
      lines.push("", `-- ${account.def.label} (${account.imported ? account.def.bip : `Purpose ${hodlPathComponent(account.def.purpose, account.def.purposeHardened !== false)}`}) PRIVATE ACCOUNT MATERIAL --`);
      if (account.primaryPrivate) lines.push(`${account.primaryPrivateLabel}: ${account.primaryPrivate}`);
      if (account.hasAlternateExport && account.genericPrivate) lines.push(`Advanced ${account.genericPrivateLabel} descriptor export: ${account.genericPrivate}`);
      for (let branch of hodlAccountAddressBranches(account)) if (branch.privateDescriptor) lines.push(`Spending ${hodlAddressBranchLabel(branch.branch).toLowerCase()} descriptor: ${branch.privateDescriptor}`);
      lines.push("Warning: An account extended public key plus a non-hardened descendant private key can reconstruct the account extended private key.");
      for (let branch of hodlAccountAddressBranches(account)) hodlSheetWifRows(lines, `${hodlAddressBranchLabel(branch.branch)}-address private keys (WIF)`, branch.rows);
    }
  } else if (hasPrivate) {
    lines.push("PRIVATE RECOVERY MATERIAL OMITTED", "Private values were not saved because Show private recovery material was off.");
  } else {
    lines.push("NO PRIVATE RECOVERY MATERIAL", "This source was watch-only; no private keys were available to save.");
  }
  lines.push("", "WATCH-ONLY WALLET DATA", "Privacy note: Extended public keys and descriptors cannot spend, but can reveal wallet history and balances.");
  if (wallet.masterFingerprint) lines.push(`Master fingerprint: ${wallet.masterFingerprint}`);
  if (wallet.parentFingerprint && !wallet.masterFingerprint) lines.push(`Encoded parent fingerprint (not a master fingerprint): ${wallet.parentFingerprint}`);
  if (wallet.nodeFingerprint && !wallet.masterFingerprint) lines.push(`Imported key fingerprint (not a master fingerprint): ${wallet.nodeFingerprint}`);
  if (wallet.rootXpub) lines.push(`BIP32 root ${(wallet.rootPublicLabel || hodlExtendedKeyVersions[wallet.network].x.pubName).toUpperCase()}: ${wallet.rootXpub}`);
  if (wallet.multisigCosignerExports?.length) {
    lines.push("", "MULTISIG CO-SIGNER EXPORTS", "Paste one complete value into a co-signer input. Legacy offers BIP45 without accounts and BIP87 with standardized accounts; use the same standard and account policy for every co-signer.");
    for (let item of wallet.multisigCosignerExports) lines.push(`${item.label} (${item.prefix}): ${item.value}`);
  }
  if (wallet.importedPublicKey) lines.push(`Imported ${(wallet.importedPublicLabel || "extended public key").toUpperCase()}: ${wallet.importedPublicKey}`);
  for (let account of wallet.accounts) {
    lines.push("", `=== ${account.def.label} (${account.imported ? account.def.bip : `Purpose ${hodlPathComponent(account.def.purpose, account.def.purposeHardened !== false)}`}) ===`, account.def.beginner, `Network: ${wallet.network}`, `Account: ${account.imported ? "Imported account key" : account.accountIndex ?? 0}`, `Account path: ${hodlDisplayDerivationPath(account.accountPath)}`);
    if (account.masterFingerprint || wallet.masterFingerprint) lines.push(`Master fingerprint: ${account.masterFingerprint || wallet.masterFingerprint}`);
    else if (account.parentFingerprint) lines.push(`Encoded parent fingerprint (not a master fingerprint): ${account.parentFingerprint}`);
    if (!account.masterFingerprint && !wallet.masterFingerprint && account.nodeFingerprint) lines.push(`Imported key fingerprint (not a master fingerprint): ${account.nodeFingerprint}`);
    lines.push("WATCH-ONLY EXPORTS", `${account.primaryPublicLabel}: ${account.primaryPublic}`, ...account.walletDescriptor ? [`Watch-only wallet descriptor: ${account.walletDescriptor}`] : []);
    for (let branch of hodlAccountAddressBranches(account)) if (branch.publicDescriptor) lines.push(`Watch-only ${hodlAddressBranchLabel(branch.branch).toLowerCase()} descriptor: ${branch.publicDescriptor}`);
    if (account.hasAlternateExport) lines.push(`Advanced ${account.genericPublicLabel} descriptor export: ${account.genericPublic}`);
    lines.push("ADDRESSES");
    for (let branch of hodlAccountAddressBranches(account)) hodlSheetAddressRows(lines, hodlAddressBranchLabel(branch.branch), branch.rows);
  }
  return lines.join("\n");
};
var hodlMaxPurpose = 2147483647, hodlMaxCoinType = 2147483647, hodlMaxAccount = 2147483647;
function hodlScriptDefinition(id) {
  return hodlScriptTypes.find((definition) => definition.id === id) || hodlScriptTypes.find((definition) => definition.id === "bip84") || hodlScriptTypes[0];
}
function hodlScriptUiLabel(definition) {
  return definition.id === "bip44" ? hodlT("Legacy") : definition.id === "bip49" ? hodlT("Nested SegWit") : definition.id === "bip84" ? hodlT("Native SegWit") : definition.id === "bip86" ? hodlT("Taproot") : definition.label;
}
function hodlScriptBeginner(definition) {
  return hodlT(hodlScriptBeginnerTexts[definition.id]);
}
function hodlReadPurpose(mark = true) {
  return hodlReadDerivationIndex(document.getElementById("purpose"), "Purpose", mark);
}
function hodlSetPurpose(value) {
  let purpose = Number(value), input = document.getElementById("purpose");
  if (!Number.isSafeInteger(purpose) || purpose < 0 || purpose > hodlMaxPurpose) purpose = 84;
  if (input) {
    input.value = `${purpose}${document.getElementById("purpose-harden")?.checked === false ? "" : "'"}`;
    hodlSyncDerivationPrime(input);
  }
  let state = hodlKeys[hodlActiveKey];
  if (state) {
    state.fields.purpose = input?.value || String(purpose);
    state.fields.purposeHarden = document.getElementById("purpose-harden")?.checked !== false;
  }
  return purpose;
}
function hodlReadCoinType(input = document.getElementById("network"), mark = true) {
  return hodlReadDerivationIndex(input, "Coin type", mark);
}
function hodlNetworkFromCoinType(coinType) {
  return Number(coinType) === 1 ? "testnet" : "mainnet";
}
function hodlCoinTypeNetworkLabel(coinType) {
  return Number(coinType) === 1 ? hodlT("Testnet") : Number(coinType) === 0 ? hodlT("Mainnet") : hodlT("Custom · Mainnet addresses");
}
function hodlUpdateCoinTypeHelp(input = document.getElementById("network"), help = document.getElementById("network-help")) {
  if (!help) return;
  let label = "Custom";
  try {
    label = hodlCoinTypeNetworkLabel(hodlReadCoinType(input, false));
  } catch {
  }
  let prefix = input?.id?.startsWith("msig-") ? "msig-" : "", hardened = hodlReadHardening(prefix).coinType;
  help.textContent = `Coin type index · ${label} · ${hardened ? "Hardened" : "Unhardened"} · 0 to 2,147,483,647`;
}
function hodlUpdateHardeningHelp(prefix = "") {
  let hardening = hodlReadHardening(prefix), purpose = document.getElementById(`${prefix}purpose-help`), account = document.getElementById(`${prefix}account-help`), branch = document.getElementById(`${prefix}branch-start-help`), start = document.getElementById(`${prefix}address-start-help`);
  if (purpose) purpose.textContent = `Purpose index · ${hardening.purpose ? "Hardened" : "Unhardened"} · 0 to 2,147,483,647`;
  if (account && !(prefix && document.getElementById(`${prefix}account`)?.dataset.state === "not-applicable")) account.textContent = prefix ? `Account index · ${hardening.account ? "Hardened" : "Unhardened"} · Derived from co-signer key origins.` : `Account index · ${hardening.account ? "Hardened" : "Unhardened"} · 0 to 2,147,483,647`;
  if (branch) branch.textContent = `First address branch to derive · 0 is Receive · 1 is Change · ${hardening.branch ? "Hardened" : "Unhardened"} · 0 to 2,147,483,647`;
  if (start) start.textContent = `First address index to derive · ${hardening.address ? "Hardened" : "Unhardened"} · 0 to 2,147,483,647`;
  hodlUpdateCoinTypeHelp(document.getElementById(`${prefix}network`), document.getElementById(`${prefix}network-help`));
}
function hodlSelectedScriptType() {
  let value = document.getElementById("script-type")?.value || hodlAccountId || "bip84";
  return hodlScriptDefinition(value).id;
}
function hodlSetSelectedScriptType(value, resetPurpose = false) {
  let definition = hodlScriptDefinition(value), id = definition.id;
  hodlAccountId = id;
  hodlSyncSelect(document.getElementById("script-type"), id);
  if (resetPurpose) {
    let purposeHarden = document.getElementById("purpose-harden");
    if (purposeHarden) purposeHarden.checked = true;
    hodlSetPurpose(definition.purpose);
    hodlUpdateVisibleDerivationPathFromAdvanced();
  }
  let state = hodlKeys[hodlActiveKey];
  if (state) {
    state.accountId = id;
    state.fields.script = id;
  }
  hodlUpdateDerivationPathPreview();
  return id;
}
function hodlSetAdvancedDerivationIndex(id, component) {
  if (!component) return;
  let input = document.getElementById(id), checkbox = document.getElementById(`${id}-harden`);
  if (input) input.value = `${component.index}${component.hardened ? "'" : ""}`;
  if (checkbox) checkbox.checked = component.hardened;
}
function hodlApplyVisibleDerivationPath() {
  let visible = hodlReadVisibleDerivationPath(), input = document.getElementById("derivation-path"), accountPath = `m${visible.accountComponents.map((entry) => `/${hodlPathComponent(entry.index, entry.hardened)}`).join("")}`;
  if (input) input.dataset.accountPath = accountPath;
  hodlSetAdvancedDerivationIndex("purpose", visible.accountComponents[0]);
  hodlSetAdvancedDerivationIndex("network", visible.accountComponents[1]);
  hodlSetAdvancedDerivationIndex("account", visible.accountComponents[2]);
  if (visible.branch) hodlSetAdvancedDerivationIndex("branch-start", visible.branch);
  if (visible.address) hodlSetAdvancedDerivationIndex("address-start", visible.address);
  let state = hodlKeys[hodlActiveKey];
  if (state) state.fields.derivationAccountPath = accountPath;
  hodlUpdateHardeningHelp();
  hodlUpdateAddressEstimate();
  return visible;
}
function hodlUpdateVisibleDerivationPathFromAdvanced() {
  let input = document.getElementById("derivation-path");
  if (!input) return;
  try {
    let existing;
    try {
      existing = hodlParseCustomDerivationPath(input.dataset.accountPath || "m/84'/0'/0'").components;
    } catch {
      existing = [];
    }
    let purpose = hodlParseDerivationIndexText(document.getElementById("purpose")?.value), network = hodlParseDerivationIndexText(document.getElementById("network")?.value), account = hodlParseDerivationIndexText(document.getElementById("account")?.value);
    if (!purpose || !network || !account) throw new Error("Complete the purpose, network, and account indexes.");
    let accountComponents = [{ index: purpose.value, hardened: purpose.hardened }, { index: network.value, hardened: network.hardened }, { index: account.value, hardened: account.hardened }, ...existing.slice(3)], accountPath = `m${accountComponents.map((entry) => `/${hodlPathComponent(entry.index, entry.hardened)}`).join("")}`, branchWindow = hodlReadBranchWindow("", false), addressWindow = hodlReadAddressWindow("", false), hardening = hodlReadHardening();
    input.dataset.accountPath = accountPath;
    input.value = hodlDerivationPathDisplay(accountPath, branchWindow, addressWindow, hardening);
    input.classList.remove("bad");
    input.setAttribute("aria-invalid", "false");
    let help = document.getElementById("derivation-path-help");
    if (help) help.textContent = hodlDerivationPathRangeMessage(branchWindow, addressWindow);
    let state = hodlKeys[hodlActiveKey];
    if (state) {
      state.fields.derivationPath = input.value;
      state.fields.derivationAccountPath = accountPath;
    }
  } catch (error) {
    input.classList.add("bad");
    input.setAttribute("aria-invalid", "true");
    let help = document.getElementById("derivation-path-help");
    if (help) help.textContent = error.message || "Enter a valid BIP32 derivation path.";
  }
}
function hodlSyncAccountTabs(id) {
  let box = document.getElementById("acct-tabs"), panel = document.getElementById("acct");
  if (!box) return;
  let buttons = [...box.querySelectorAll("[data-account]")], activeIndex = -1;
  buttons.forEach((button, index) => {
    let active2 = button.dataset.account === id;
    button.classList.toggle("active", active2);
    button.setAttribute("aria-selected", String(active2));
    button.tabIndex = active2 ? 0 : -1;
    if (active2) activeIndex = index;
  });
  let active = activeIndex >= 0 ? buttons[activeIndex] : null;
  if (panel && active) panel.setAttribute("aria-labelledby", active.id);
  if (activeIndex >= 0) hodlRevealTab(box, activeIndex);
}
function hodlAccountTabsKeydown(event) {
  let current = event.target instanceof Element ? event.target.closest(".account-tab") : null, box = event.currentTarget;
  if (!current || !box) return;
  let buttons = [...box.querySelectorAll(".account-tab")], index = buttons.indexOf(current), next = null;
  if (event.key === "ArrowRight") next = (index + 1) % buttons.length;
  else if (event.key === "ArrowLeft") next = (index - 1 + buttons.length) % buttons.length;
  else if (event.key === "Home") next = 0;
  else if (event.key === "End") next = buttons.length - 1;
  if (next === null) return;
  event.preventDefault();
  buttons[next].click();
  buttons[next].focus();
}
var hodlMaxAddressIndex = 2147483647, hodlMaxAddressRange = 10000, hodlAddressBenchmarkMs = null;
function hodlSyncBranchRangeLimit(prefix = "") {
  let startInput = document.getElementById(`${prefix}branch-start`), rangeInput = document.getElementById(`${prefix}branch-range`);
  if (!rangeInput) return 2;
  let startRaw = String(startInput?.value ?? "").trim(), parsed = hodlParseDerivationIndexText(startRaw), start = parsed?.value, startValid = Boolean(parsed);
  let maximum = startValid ? Math.min(2, hodlMaxAddressIndex - start + 1) : 2;
  rangeInput.max = String(maximum);
  let rangeRaw = String(rangeInput.value ?? "").trim(), range = Number(rangeRaw);
  if (/^\d+$/.test(rangeRaw) && Number.isSafeInteger(range) && range > maximum) rangeInput.value = String(maximum);
  return maximum;
}
function hodlReadBranchWindow(prefix = "", mark = true) {
  let startInput = document.getElementById(`${prefix}branch-start`), rangeInput = document.getElementById(`${prefix}branch-range`), startRaw = String(startInput?.value ?? "").trim(), rangeRaw = String(rangeInput?.value ?? "").trim();
  let parsed = hodlParseDerivationIndexText(startRaw), start = parsed?.value, range = Number(rangeRaw), startValid = Boolean(parsed);
  let maximum = startValid ? Math.min(2, hodlMaxAddressIndex - start + 1) : 2;
  let rangeValid = /^\d+$/.test(rangeRaw) && Number.isSafeInteger(range) && range >= 1 && range <= maximum, endValid = startValid && rangeValid && start + range - 1 <= hodlMaxAddressIndex;
  if (mark) {
    startInput?.classList.toggle("bad", !startValid);
    startInput?.setAttribute("aria-invalid", String(!startValid));
    rangeInput?.classList.toggle("bad", !rangeValid || !endValid);
    rangeInput?.setAttribute("aria-invalid", String(!rangeValid || !endValid));
  }
  if (!startValid) throw new Error("Starting address branch index must be a whole number from 0 to 2,147,483,647.");
  if (!rangeValid) throw new Error(`Address branch range must be a whole number from 1 to ${maximum}.`);
  if (!endValid) throw new Error("The address branch range extends beyond the maximum BIP32 child index of 2,147,483,647.");
  return { start, range, end: start + range - 1, branches: Array.from({ length: range }, (_, offset) => start + offset) };
}
function hodlAddressBranchSummary(branches) {
  return branches.map(hodlAddressBranchLabel).join(" and ");
}
function hodlSyncAddressRangeLimit(prefix = "") {
  let startInput = document.getElementById(`${prefix}address-start`), rangeInput = document.getElementById(`${prefix}address-range`);
  if (!rangeInput) return hodlMaxAddressRange;
  let startRaw = String(startInput?.value ?? "").trim(), parsed = hodlParseDerivationIndexText(startRaw), start = parsed?.value, startValid = Boolean(parsed);
  let maximum = startValid ? Math.min(hodlMaxAddressRange, hodlMaxAddressIndex - start + 1) : hodlMaxAddressRange;
  rangeInput.max = String(maximum);
  let rangeRaw = String(rangeInput.value ?? "").trim(), range = Number(rangeRaw);
  if (/^\d+$/.test(rangeRaw) && Number.isSafeInteger(range) && range > maximum) rangeInput.value = String(maximum);
  return maximum;
}
function hodlReadAddressWindow(prefix = "", mark = true) {
  let startInput = document.getElementById(`${prefix}address-start`), rangeInput = document.getElementById(`${prefix}address-range`), startRaw = String(startInput?.value ?? "").trim(), rangeRaw = String(rangeInput?.value ?? "").trim();
  let parsed = hodlParseDerivationIndexText(startRaw), start = parsed?.value, range = Number(rangeRaw), startValid = Boolean(parsed);
  let maximum = startValid ? Math.min(hodlMaxAddressRange, hodlMaxAddressIndex - start + 1) : hodlMaxAddressRange;
  let rangeValid = /^\d+$/.test(rangeRaw) && Number.isSafeInteger(range) && range >= 1 && range <= maximum;
  let endValid = startValid && rangeValid && start + range - 1 <= hodlMaxAddressIndex;
  if (mark) {
    startInput?.classList.toggle("bad", !startValid);
    startInput?.setAttribute("aria-invalid", String(!startValid));
    rangeInput?.classList.toggle("bad", !rangeValid || !endValid);
    rangeInput?.setAttribute("aria-invalid", String(!rangeValid || !endValid));
  }
  if (!startValid) throw new Error("Starting address index must be a whole number from 0 to 2,147,483,647.");
  if (!rangeValid) throw new Error(`Address range must be a whole number from 1 to ${maximum.toLocaleString()}.`);
  if (!endValid) throw new Error("The address range extends beyond the maximum BIP32 child index of 2,147,483,647.");
  return { start, range, end: start + range - 1 };
}
function hodlFormatAddressEstimate(milliseconds) {
  if (!Number.isFinite(milliseconds) || milliseconds < 100) return hodlTText("under 0.1 seconds");
  if (milliseconds < 10000) return hodlTText("about {n} seconds", { n: (milliseconds / 1000).toFixed(1) });
  if (milliseconds < 60000) return hodlTText("about {n} seconds", { n: Math.round(milliseconds / 1000) });
  return hodlTText("about {n} minutes", { n: Math.ceil(milliseconds / 60000) });
}
function hodlUpdateAddressEstimate(prefix = "") {
  let estimate = document.getElementById(`${prefix}address-estimate`), help = document.getElementById(`${prefix}address-range-help`), startHelp = document.getElementById(`${prefix}address-start-help`), branchHelp = document.getElementById(`${prefix}branch-range-help`);
  if (!estimate || !help || !startHelp || !branchHelp) return;
  let maximum = hodlSyncAddressRangeLimit(prefix), branchMaximum = hodlSyncBranchRangeLimit(prefix);
  try {
    let { range } = hodlReadAddressWindow(prefix, false), { branches } = hodlReadBranchWindow(prefix, false), hardening = hodlReadHardening(prefix), keyCount = prefix ? Math.max(1, Number(document.getElementById("msig-n")?.value) || 1) : (hodlImportedExtendedKeyDepth() ?? 0) > 0 ? 1 : 4;
    let branchLabels = hodlAddressBranchSummary(branches), addressCopies = branches.map((branch) => `${range.toLocaleString()} ${hodlAddressBranchLabel(branch).toLowerCase()}`).join(" and ");
    branchHelp.textContent = `Derives ${branchLabels} ${hardening.branch ? "hardened " : ""}${branches.length === 1 ? "branch" : "branches"} · Max ${branchMaximum}`;
    startHelp.textContent = `First ${branchLabels.toLowerCase()} index to derive · ${hardening.address ? "Hardened" : "Unhardened"} · 0 to 2,147,483,647`;
    help.textContent = `Derives ${addressCopies} ${range * branches.length === 1 ? "address" : "addresses"} · Max ${maximum.toLocaleString()}`;
    estimate.textContent = hodlAddressBenchmarkMs == null ? "Measuring this device\u2026" : `Estimated derivation time on this device: ${hodlFormatAddressEstimate(hodlAddressBenchmarkMs * range * branches.length * keyCount)}.`;
  } catch (error) {
    branchHelp.textContent = "Choose one or two valid address branches.";
    help.textContent = "Choose a valid address range.";
    estimate.textContent = error.message;
  }
}
function hodlInitAddressBenchmark() {
  let run = () => {
    try {
      let node = hodlHDKey.fromMasterSeed(new Uint8Array(32)).derive("m/84'/0'/0'"), samples = 32, started = performance.now();
      hodlDeriveAddressRows(node, "m/84h/0h/0h", "p2wpkh", "mainnet", samples, "receive", 0);
      hodlAddressBenchmarkMs = Math.max((performance.now() - started) / samples, .01);
    } catch {
      hodlAddressBenchmarkMs = .25;
    }
    hodlUpdateAddressEstimate();
    hodlUpdateAddressEstimate("msig-");
  };
  hodlUpdateAddressEstimate();
  hodlUpdateAddressEstimate("msig-");
  if ("requestIdleCallback" in window) requestIdleCallback(run, { timeout: 750 });
  else setTimeout(run, 0);
  document.addEventListener("input", (event) => {
    if (["branch-start", "branch-start-harden", "branch-range", "address-start", "address-range", "seed"].includes(event.target?.id)) hodlUpdateAddressEstimate();
    if (["msig-branch-start", "msig-branch-start-harden", "msig-branch-range", "msig-address-start", "msig-address-range", "msig-m-number", "msig-n-number", "msig-m", "msig-n"].includes(event.target?.id)) hodlUpdateAddressEstimate("msig-");
  });
}
class HodlDerivationCancelledError extends Error {
  constructor() {
    super("Wallet derivation stopped.");
    this.name = "HodlDerivationCancelledError";
  }
}
var hodlActiveDerivation = null;
function hodlDerivationButton(kind) {
  return document.getElementById(kind === "msig" ? "msig-go" : "go");
}
function hodlSetDerivationButtonState(kind, state) {
  let button = hodlDerivationButton(kind);
  if (!button) return;
  if (state === "running") {
    if (!button.dataset.derivationWidth) {
      let width = button.getBoundingClientRect().width;
      if (width > 0) {
        button.dataset.derivationWidth = String(width);
        button.style.width = `${width}px`;
      }
    }
    button.textContent = hodlTText("Stop");
    button.disabled = false;
    button.setAttribute("aria-disabled", "false");
    button.setAttribute("aria-label", kind === "msig" ? hodlTText("Stop deriving multisig") : hodlTText("Stop deriving key"));
    button.dataset.derivationState = "running";
  } else if (state === "stopping") {
    button.textContent = hodlTText("Stopping…");
    button.disabled = true;
    button.setAttribute("aria-disabled", "true");
    button.setAttribute("aria-label", kind === "msig" ? hodlTText("Stopping multisig derivation") : hodlTText("Stopping key derivation"));
    button.dataset.derivationState = "stopping";
  } else {
    button.textContent = kind === "msig" ? hodlTText("Derive Multisig") : hodlTText("Derive Key");
    button.removeAttribute("aria-label");
    delete button.dataset.derivationState;
    delete button.dataset.derivationWidth;
    button.style.removeProperty("width");
  }
}
function hodlResetDerivationProgress(kind, hide = true) {
  let progress = document.getElementById(kind === "msig" ? "msig-derive-progress" : "derive-progress"), bar = progress?.querySelector(".derive-progress-bar"), label = progress?.querySelector(".derive-progress-label");
  if (!progress) return;
  progress.classList.remove("is-complete");
  progress.setAttribute("aria-valuenow", "0");
  progress.setAttribute("aria-valuetext", "0% complete");
  if (bar) bar.style.width = "0%";
  if (label) label.textContent = "0%";
  progress.hidden = hide;
}
function hodlDerivationPause() {
  return new Promise((resolve) => {
    let settled = false, finish = () => {
      if (settled) return;
      settled = true;
      resolve();
    };
    if ("requestAnimationFrame" in window) requestAnimationFrame(finish);
    setTimeout(finish, 100);
  });
}
function hodlCreateDerivationTracker(progress, control) {
  let total = 1, completed = 0, lastPercent = -1, lastYield = performance.now();
  let ensureActive = () => {
    if (control.cancelled) throw new HodlDerivationCancelledError();
  };
  let render = (percent) => {
    if (percent === lastPercent) return;
    lastPercent = percent;
    let bar = progress?.querySelector(".derive-progress-bar"), label = progress?.querySelector(".derive-progress-label");
    if (bar) bar.style.width = `${percent}%`;
    if (label) label.textContent = `${percent}%`;
    progress?.setAttribute("aria-valuenow", String(percent));
    progress?.setAttribute("aria-valuetext", `${percent}% complete`);
  };
  return {
    setTotal(value) {
      ensureActive();
      total = Math.max(1, Number(value) || 1);
      completed = 0;
      render(0);
    },
    step(amount = 1) {
      ensureActive();
      completed = Math.min(total, completed + amount);
      render(Math.min(99, Math.floor(completed / total * 100)));
      if (performance.now() - lastYield < 16) return null;
      return hodlDerivationPause().then(() => {
        lastYield = performance.now();
        ensureActive();
      });
    },
    complete() {
      ensureActive();
      completed = total;
      render(100);
      progress?.classList.add("is-complete");
      progress?.setAttribute("aria-valuetext", hodlTText("Done"));
      let label = progress?.querySelector(".derive-progress-label");
      if (label) label.innerHTML = `${hodlCopiedIconMarkup()}<span>${hodlT("Done")}</span>`;
    }
  };
}
function hodlStopDerivation(kind) {
  if (!hodlActiveDerivation || hodlActiveDerivation.kind !== kind || hodlActiveDerivation.cancelled) return;
  hodlActiveDerivation.cancelled = true;
  hodlSetDerivationButtonState(kind, "stopping");
}
function hodlHandleDerivationButton(kind, derive) {
  if (hodlActiveDerivation) {
    hodlStopDerivation(kind);
    return;
  }
  return hodlDeriveWithProgress(kind, derive);
}
async function hodlDeriveWithProgress(kind, derive) {
  if (hodlActiveDerivation) return;
  let multisig = kind === "msig", progress = document.getElementById(multisig ? "msig-derive-progress" : "derive-progress");
  let control = { kind, cancelled: false };
  hodlActiveDerivation = control;
  hodlResetDerivationProgress(kind, false);
  hodlSetDerivationButtonState(kind, "running");
  (multisig ? hodlSyncDeriveButton : hodlSyncMsigDeriveButton)();
  try {
    await hodlDerivationPause();
    await hodlDerivationPause();
    if (control.cancelled) throw new HodlDerivationCancelledError();
    let tracker = hodlCreateDerivationTracker(progress, control), succeeded = await derive(tracker);
    if (succeeded === false) hodlResetDerivationProgress(kind);
    else tracker.complete();
  } catch (error) {
    if (error instanceof HodlDerivationCancelledError) hodlResetDerivationProgress(kind);
    else throw error;
  } finally {
    if (hodlActiveDerivation === control) hodlActiveDerivation = null;
    hodlSetDerivationButtonState(kind, "idle");
    hodlSyncDeriveButton();
    hodlSyncMsigDeriveButton();
  }
}
function hodlImportedExtendedKeyDepth() {
  if (hodlKeyMode !== "seed") return null;
  let value = document.getElementById("seed")?.value.trim() || "";
  if (!hodlLooksExtendedKey(value)) return null;
  try {
    let normalized = hodlParseExtendedKey(value);
    return hodlHDKey.fromExtendedKey(normalized.xkey).depth;
  } catch {
    return null;
  }
}
function hodlUpdateKeyModeControls() {
  let singleKey = hodlKeyMode === "key", hdBrain = hodlBrainHdActive() && hodlBrainAcked("hd"), settings = document.getElementById("key-settings");
  ["passphrase-field", "master-fingerprint-preview", "script-type-field", "derivation-path-field", "derivation-advanced"].forEach((id) => {
    let element = document.getElementById(id);
    // The HD brain output is a wallet, not a single key: it needs these fields.
    // The fingerprint preview stays hidden so nothing is shown before Derive.
    if (element) element.hidden = id === "master-fingerprint-preview" ? singleKey : singleKey && !hdBrain;
  });
  settings?.classList.toggle("single-key-mode", singleKey && !hdBrain);
}
function hodlUpdateDerivationPathPreview() {
  hodlUpdateKeyModeControls();
  let input = document.getElementById("derivation-path"), help = document.getElementById("derivation-path-help");
  if (!input || hodlKeyMode === "key" && !hodlBrainHdActive()) return;
  try {
    let visible = hodlReadVisibleDerivationPath();
    input.dataset.accountPath = `m${visible.accountComponents.map((entry) => `/${hodlPathComponent(entry.index, entry.hardened)}`).join("")}`;
    if (help) help.textContent = hodlDerivationPathRangeMessage(visible.branchWindow, visible.addressWindow);
  } catch (error) {
    if (help) help.textContent = error.message || "Enter a valid BIP32 derivation path.";
  }

}
function hodlSyncAdvancedDerivationHardening(input) {
  if (input) input.value = hodlSanitizeDerivationIndexDraft(input.value);
  let parsed = hodlParseDerivationIndexText(input?.value);
  input?.classList.toggle("bad", !parsed);
  input?.setAttribute("aria-invalid", String(!parsed));
  if (!parsed) return false;
  input.value = `${parsed.value}${parsed.hardened ? "'" : ""}`;
  let checkbox = document.getElementById(`${input.id}-harden`);
  if (checkbox) checkbox.checked = parsed.hardened;
  return true;
}
function hodlInitDerivationControls() {
  let panel = document.getElementById("calc-card");
  if (!panel) return;
  hodlSyncDerivationPrimes();
  let advancedIds = ["purpose", "network", "account", "branch-start", "address-start"], advancedInputs = advancedIds.map((id) => document.getElementById(id));
  advancedInputs.forEach((input) => {
    input?.addEventListener("input", () => hodlSyncAdvancedDerivationHardening(input));
    input?.addEventListener("blur", () => hodlRestoreAdvancedDerivationIndex(input));
    input?.addEventListener("keydown", (event) => {
      if (["e", "E", "+", "-", "."].includes(event.key)) event.preventDefault();
    });
    input?.addEventListener("paste", (event) => {
      if (!/^(?:\d+)?[hH']?$/.test((event.clipboardData?.getData("text") ?? "").trim())) event.preventDefault();
    });
  });
  panel.addEventListener("input", (event) => {
    let target = event.target;
    if (!(target instanceof Element)) return;
    if (target.id === "derivation-path") {
      let state = hodlKeys[hodlActiveKey];
      if (state) state.fields.derivationPath = target.value;
      try {
        hodlApplyVisibleDerivationPath();
      } catch {
        hodlUpdateDerivationPathPreview();
      }
      hodlInvalidateLiveKeyResult();
      hodlSyncKeyClearButton();
      hodlSyncDeriveButton();
      return;
    }
    if ([...advancedIds, "branch-range", "address-range", "purpose-harden", "network-harden", "account-harden", "branch-start-harden", "address-start-harden"].includes(target.id)) {
      if (target.id.endsWith("-harden")) {
        let input = document.getElementById(target.id.slice(0, -7)), parsed = hodlParseDerivationIndexText(input?.value);
        if (input && parsed) input.value = `${parsed.value}${target.checked ? "'" : ""}`;
      } else if (advancedIds.includes(target.id)) hodlSyncAdvancedDerivationHardening(target);
      if (target.id === "branch-start" || target.id === "branch-range") hodlSyncBranchRangeLimit();
      if (target.id === "address-start" || target.id === "address-range") hodlSyncAddressRangeLimit();
      let state = hodlKeys[hodlActiveKey];
      if (state) {
        let hardeningField = { "purpose-harden": "purposeHarden", "network-harden": "coinTypeHarden", "account-harden": "accountHarden", "branch-start-harden": "branchHarden", "address-start-harden": "addressHarden" }[target.id];
        if (hardeningField) state.fields[hardeningField] = target.checked;
        else state.fields[target.id === "network" ? "coinType" : target.id === "branch-start" ? "branchStart" : target.id === "branch-range" ? "branchRange" : target.id === "address-start" ? "addressStart" : target.id === "address-range" ? "addressRange" : target.id] = target.value;
      }
      if (target.id.endsWith("-harden")) hodlUpdateHardeningHelp();
      if (target.id === "network") {
        hodlUpdateCoinTypeHelp(target);
        try {
          if (state) state.fields.network = hodlSelectedNetwork(target);
        } catch {
        }
      }
      hodlInvalidateLiveKeyResult();
      let error = document.getElementById("error");
      if (error) error.textContent = "";
      hodlUpdateVisibleDerivationPathFromAdvanced();
      hodlUpdateAddressEstimate();
      if (target.id === "network") {
        let seed = document.getElementById("seed"), key = document.getElementById("key");
        if (seed) seed.dispatchEvent(new Event("input"));
        if (key) key.dispatchEvent(new Event("input"));
      }
      hodlSyncKeyClearButton();
      hodlSyncDeriveButton();
      return;
    }
    if (target.id === "seed") hodlUpdateDerivationPathPreview();
  });
  panel.addEventListener("change", (event) => {
    let target = event.target;
    if (!(target instanceof Element)) return;
    if (target.id === "script-type") {
      let id = hodlSetSelectedScriptType(target.value, true);
      let purpose = hodlReadPurpose(false);
      if (hodlWalletResult?.kind === "hd") {
        if (hodlWalletResult.accounts.some((account) => account.def.id === id && account.def.purpose === purpose)) hodlShowAccount(id);
        else hodlInvalidateLiveKeyResult();
      }
      let seed = document.getElementById("seed");
      if (seed) seed.dispatchEvent(new Event("input"));
      return;
    }
  });
  try {
    hodlApplyVisibleDerivationPath();
  } catch {
    hodlUpdateDerivationPathPreview();
  }
}
function hodlSeedPhraseTokens(value, mask = false) {
  return String(value ?? "").trim().split(/\s+/).filter(Boolean).map((word) => `<span class="seed-phrase-word">${mask ? "\u2022".repeat(Array.from(word).length) : hodlEscapeHtml(word)}</span>`).join(" ");
}
function hodlSeedPhraseField(label, value) {
  let text = String(value ?? "\u2014");
  if (hodlRevealPrivate) return `<p class="private-field seed-phrase-field"><span class="muted">${hodlEscapeHtml(label)}</span><span class="secret private-field-value seed-phrase-value">${hodlSeedPhraseTokens(text)}</span></p>`;
  return `<p class="private-field seed-phrase-field"><span class="muted">${hodlEscapeHtml(label)}</span><span class="secret private-field-value secret-placeholder seed-phrase-value"><span class="secret-placeholder-mask" aria-hidden="true">${hodlSeedPhraseTokens(text, true)}</span><span class="secret-placeholder-message" aria-hidden="true">************</span><span class="secret-placeholder-label">${hodlT("Private value hidden")}</span></span></p>`;
}
function hodlSeedQrDigits(mnemonic) {
  let words = String(mnemonic ?? "").trim().split(/\s+/).filter(Boolean);
  if (words.length !== 12 && words.length !== 24) return "";
  let digits = "";
  for (let word of words) {
    let index = hodlBip39Wordlist.indexOf(word);
    if (index < 0) return "";
    digits += String(index).padStart(4, "0");
  }
  return digits;
}
function hodlCompactSeedQrBytes(entropyHex) {
  let hex = String(entropyHex ?? "").replace(/\s/g, "").toLowerCase();
  if (hex.length !== 32 && hex.length !== 64) return null;
  return Array.from(hodlHex.decode(hex));
}
function hodlSeedQrExport(mnemonic, options = {}) {
  let words = String(mnemonic ?? "").trim().split(/\s+/).filter(Boolean);
  if (!words.length || !hodlRevealPrivate) return "";
  if (words.length !== 12 && words.length !== 24) return `<details class="wallet-advanced"><summary>${hodlT("SeedQR")}</summary><p class="muted">${hodlT("SeedQR is defined for 12 and 24 word phrases. Type this {n}-word seed on the signer.", { n: words.length })}</p></details>`;
  let digits = hodlSeedQrDigits(mnemonic);
  if (!digits) return "";
  let passNote = options.passphraseUsed ? hodlT(" This QR is the seed only. Enter the passphrase on the signer after scanning.") : "";
  let compact = "";
  try {
    let bytes = hodlCompactSeedQrBytes(options.entropyHex);
    if (bytes) compact = `<div class="watch-only-qr seed-qr"><div class="qr qr-seed" aria-label="CompactSeedQR">${hodlUqrRenderSvg(bytes, { ecc: "L", border: 4, pixelSize: 4, blackColor: "#111111", whiteColor: "#ffffff" })}</div><p class="muted">${hodlT("CompactSeedQR. Same seed, smaller binary code.")}</p><p class="muted">${hodlT("Compatible with: SeedSigner, Krux, Jade, Passport.")}</p></div>`;
  } catch {
  }
  return `<details class="wallet-advanced"><summary>${hodlT("SeedQR")}</summary><p class="muted">${hodlT("Scan into a camera signer. This is the seed.")}${passNote}</p><div class="seed-qr-pair"><div class="watch-only-qr seed-qr"><div class="qr qr-seed" aria-label="SeedQR">${hodlUqrRenderSvg(digits, { ecc: "L", border: 4, pixelSize: 4, blackColor: "#111111", whiteColor: "#ffffff" })}</div><p class="muted">${hodlT("SeedQR. Numeric.")}</p><p class="muted">${hodlT("Compatible with: SeedSigner, Krux, Jade, Passport, Coldcard Q.")}</p><p class="muted mono">${hodlEscapeHtml(digits)}</p></div>${compact}</div></details>`;
}
var hodlSeedLengths = Object.freeze({
  12: Object.freeze({ words: 12, bits: 128, bytes: 16, hexChars: 32, hashRolls: 50, partialWords: 11, candidates: 128 }),
  15: Object.freeze({ words: 15, bits: 160, bytes: 20, hexChars: 40, hashRolls: 62, partialWords: 14, candidates: 64 }),
  18: Object.freeze({ words: 18, bits: 192, bytes: 24, hexChars: 48, hashRolls: 75, partialWords: 17, candidates: 32 }),
  21: Object.freeze({ words: 21, bits: 224, bytes: 28, hexChars: 56, hashRolls: 87, partialWords: 20, candidates: 16 }),
  24: Object.freeze({ words: 24, bits: 256, bytes: 32, hexChars: 64, hashRolls: 99, partialWords: 23, candidates: 8 })
});
var hodlEntropyFormats = Object.freeze({
  bin: Object.freeze({ id: "bin", base: 2, bitsPerDigit: 1, alphabet: "01", ...hodlHexFormatLabels.bin, method: "binary" }),
  base4: Object.freeze({ id: "base4", base: 4, bitsPerDigit: 2, alphabet: "0123", ...hodlHexFormatLabels.base4, method: "base4" }),
  base8: Object.freeze({ id: "base8", base: 8, bitsPerDigit: 3, alphabet: "01234567", ...hodlHexFormatLabels.base8, method: "base8" }),
  hex: Object.freeze({ id: "hex", base: 16, bitsPerDigit: 4, alphabet: "0123456789ABCDEF", ...hodlHexFormatLabels.hex, method: "hex" }),
  base32: Object.freeze({ id: "base32", base: 32, bitsPerDigit: 5, alphabet: "0123456789ABCDEFGHJKMNPQRSTVWXYZ", ...hodlHexFormatLabels.base32, method: "base32", binaryRemainder: true }),
  base64: Object.freeze({ id: "base64", base: 64, bitsPerDigit: 6, alphabet: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", ...hodlHexFormatLabels.base64, method: "base64", binaryRemainder: true })
});
var hodlBip39WordSet = new Set(hodlBip39Wordlist), hodlBip39WordIndex = new Map(hodlBip39Wordlist.map((word, index) => [word, index])), hodlLastWordCache = /* @__PURE__ */ new Map();
var hodlOnScreenKeyboardOpen = false;
function hodlSeedConfig(words = hodlTargetWordCount) {
  return hodlSeedLengths[Number(words)] || hodlSeedLengths[24];
}
function hodlNormalizeEntropyFormat(format) {
  return Object.hasOwn(hodlEntropyFormats, String(format ?? "")) ? String(format) : "bin";
}
function hodlEntropyFormatConfig(format, targetWords = hodlTargetWordCount) {
  let definition = hodlEntropyFormats[hodlNormalizeEntropyFormat(format)], seed = hodlSeedConfig(targetWords), fullDigits = Math.floor(seed.bits / definition.bitsPerDigit), remainderBits = seed.bits % definition.bitsPerDigit, digits = fullDigits + (remainderBits ? definition.binaryRemainder ? remainderBits : 1 : 0), finalBase = remainderBits ? 2 ** remainderBits : definition.base, finalCharacters = remainderBits ? definition.binaryRemainder ? "01" : definition.alphabet.slice(0, finalBase) : definition.alphabet;
  return { ...definition, digits, fullDigits, remainderBits, finalBase, finalCharacters, seed };
}
function hodlLooksExtendedKey(value) {
  return /^[xtyzuvYZUV][A-Za-z0-9]+$/.test(value.trim()) && value.trim().length > 80;
}
function hodlSinglesigImportStatus(value, network) {
  try {
    let parsed = hodlParseExtendedKey(value), depth = parsed.node.depth, hardening = hodlReadHardening(), plan = hodlKeyMode === "key" ? null : hodlReadDerivationPlan(false), hardenedPrefix = plan ? plan.hasHardenedPrefix : hardening.purpose || hardening.coinType || hardening.account;
    if (parsed.scope !== "singlesig") return { ok: false, message: `${parsed.prefix} is a multisig export \xB7 use Multi Signature` };
    if (parsed.network !== network) return { ok: false, message: `${parsed.prefix} is for ${parsed.network} \xB7 change Network to ${parsed.network}` };
    if (depth === 0 && !parsed.isPrivate && (hardenedPrefix || hardening.branch || hardening.address)) return { ok: false, message: "Root extended public keys cannot derive the selected hardened path \xB7 turn every Harden option off or import a private root key offline" };
    if (depth === 0 && parsed.family !== "x") return { ok: false, message: "A root private key must use an xprv/tprv prefix" };
    if (depth !== 0 && depth !== 3) return { ok: false, message: `Depth ${depth} extended key \xB7 use a root private key or depth-3 account key` };
    if (depth === 3 && !parsed.isPrivate && (hardening.branch || hardening.address)) return { ok: false, message: `Account extended public keys cannot derive hardened ${hardening.branch ? "address branches" : "address indexes"} \xB7 turn off the corresponding Harden option` };
    let definition = depth === 3 ? hodlImportedScriptDefinition(parsed) : null, detail = definition ? ` \xB7 ${hodlScriptUiLabel(definition)} ${definition.bip}` : "", mismatch = hodlSinglesigScriptMismatch(parsed, hodlSelectedScriptType());
    return { ok: true, warning: Boolean(mismatch), message: mismatch ? `\u26A0\uFE0F ${hodlFormatNote(mismatch)}` : hodlTText(parsed.isPrivate ? "{prefix} private key detected · {network}{detail} · ready to derive" : "{prefix} watch-only key detected · {network}{detail} · ready to derive", { prefix: parsed.prefix, network, detail }) };
  } catch (error) {
    return { ok: false, message: error.message || "Invalid extended key" };
  }
}
function hodlUsableSinglesigImport(value, network) {
  return hodlSinglesigImportStatus(value, network).ok;
}

// The D++ checksum-word pick ends its transcript with the fewest rolls that
// cover the candidate count: one D16 (21 words), one D8 (24), two D8s (15),
// a D8 and a D16 (12), or a D16 and a coin flip (18). Every pick consumes
// its roll results left to right, the high bits first.
var hodlDPlusFinalSpecs = Object.freeze({
  12: Object.freeze(["d8", "d16"]),
  15: Object.freeze(["d8", "d8"]),
  18: Object.freeze(["d16", "coin"]),
  21: Object.freeze(["d16"]),
  24: Object.freeze(["d8"])
});
function hodlDPlusStepBits(step) {
  return step === "d8" ? 3 : step === "d16" ? 4 : 1;
}
function hodlDPlusStepLabel(step) {
  return step === "d8" ? "D8" : step === "d16" ? "D16" : hodlT("a coin flip");
}
function hodlDPlusStepValue(step, face) {
  if (step === "d8") return /^[1-8]$/.test(face) ? Number(face) - 1 : null;
  if (step === "d16") return hodlDPlusD16Value(face);
  return /^[1-8]$/.test(face) ? (Number(face) >= 5 ? 1 : 0) : null;
}
function hodlDPlusFinalSteps(words = hodlTargetWordCount) {
  let config = hodlSeedConfig(words);
  return hodlDPlusFinalSpecs[config.words] || hodlDPlusFinalSpecs[24];
}
function hodlDPlusStepNoteLabel(step) {
  return step === "d8" ? "D8" : step === "d16" ? "D16" : hodlNote("a coin flip");
}
function hodlDPlusFinalNote(words = hodlTargetWordCount) {
  let steps = hodlDPlusFinalSteps(words), labels = steps.map(hodlDPlusStepNoteLabel);
  if (steps.length === 1) return hodlNote("roll the {die} once more", { die: labels[0] });
  if (steps[0] === steps[1]) return hodlNote("roll a final {die} twice", { die: labels[0] });
  return hodlNote("roll a final {a} and {b}", { a: labels[0], b: labels[1] });
}
function hodlDPlusFinalDescription(words = hodlTargetWordCount) {
  return hodlFormatNote(hodlDPlusFinalNote(words));
}
function hodlDPlusFinalHelp(words = hodlTargetWordCount) {
  let steps = hodlDPlusFinalSteps(words), labels = steps.map((step) => step === "coin" ? hodlT("coin flip") : hodlDPlusStepLabel(step));
  let coin = steps.includes("coin") ? hodlT(" The final D8 is interpreted as a coin flip: 1–4 is Heads, 5–8 is Tails. Or flip a real coin!") : "";
  if (steps.length === 1) return hodlTText("One final {die} roll selects the checksum word.", { die: labels[0] });
  if (labels[0] === labels[1]) return hodlTText("Two final {die} rolls select the checksum word.", { die: labels[0] });
  return hodlTText("One final {a} roll and one final {b} roll select the checksum word.{coin}", { a: labels[0], b: labels[1], coin });
}
function hodlDPlusStepChecksumLabel(step) {
  return step === "coin" ? hodlT("the final coin flip") : hodlT("the final {die} checksum roll", { die: hodlDPlusStepLabel(step) });
}
// The roll turns each position in the final-word spec into a numbered pick:
// d8 carries three bits (faces 1-8), hexadecimal d16 four bits (faces 0-F), and a
// coin one bit (faces 1-4 Heads, 5-8 Tails).
function hodlDPlusD16Value(face) {
  let normalized = String(face ?? "").toUpperCase();
  return /^[0-9A-F]$/.test(normalized) ? Number.parseInt(normalized, 16) : null
}
// Single tokenizer shared by the parser and the input sanitiser so the two can
// never disagree about where one roll ends and the next begins.
function hodlDPlusTokens(value) {
  let text = String(value ?? ""),
    entries = [],
    index = 0;
  while (index < text.length) {
    let character = String.fromCodePoint(text.codePointAt(index));
    if (/[\s,;|]/.test(character)) {
      index += character.length;
      continue
    }
    entries.push({
      face: character.toUpperCase(),
      start: index,
      end: index + character.length
    });
    index += character.length
  }
  return entries
}
function hodlDPlusRolls(value, targetWords = hodlTargetWordCount) {
  let config = hodlSeedConfig(targetWords),
    rolledTarget = config.partialWords,
    rolledCharacterTarget = rolledTarget * 3,
    entries, invalidRanges = [],
    rejectedD8 = 0,
    rejectedD16 = 0,
    acceptedCharacters = [];
  entries = hodlDPlusTokens(value);
  let rolledEntries = entries.slice(0, rolledCharacterTarget),
    wordSlots = Array(rolledTarget).fill(""),
    groups = [],
    invalidRequiredCount = 0,
    firstInvalid = null,
    bits = 0;
  for (let groupIndex = 0; groupIndex < rolledTarget; groupIndex++) {
    let tokens = rolledEntries.slice(groupIndex * 3, groupIndex * 3 + 3);
    if (!tokens.length) break;
    let validity = tokens.map((token, position) => position === 0 ? /^[1-8]$/.test(token.face) : hodlDPlusD16Value(token.face) !== null);
    tokens.forEach((token, position) => {
      if (validity[position]) {
        acceptedCharacters.push(token.face);
        bits += [3, 4, 4][position];
        return;
      }
      invalidRanges.push([token.start, token.end]);
      invalidRequiredCount += 1;
      if (position === 0) rejectedD8 += 1;
      else rejectedD16 += 1;
      if (!firstInvalid) firstInvalid = { groupIndex, position, face: token.face, start: token.start, end: token.end, final: false };
    });
    let complete = tokens.length === 3, valid = complete && validity.every(Boolean), word = "";
    if (valid) {
      let wordIndex = (Number(tokens[0].face) - 1) * 256 + hodlDPlusD16Value(tokens[1].face) * 16 + hodlDPlusD16Value(tokens[2].face);
      word = hodlBip39Wordlist[wordIndex];
      wordSlots[groupIndex] = word;
    }
    groups.push({
      groupIndex,
      faces: tokens.map(token => token.face),
      complete,
      valid,
      word,
      validity
    })
  }
  let completedGroups = Math.min(rolledTarget, Math.floor(rolledEntries.length / 3)),
    validWordCount = wordSlots.filter(Boolean).length,
    allRolledComplete = rolledEntries.length === rolledCharacterTarget,
    rolledInvalidCount = invalidRequiredCount,
    allRolledValid = allRolledComplete && rolledInvalidCount === 0 && validWordCount === rolledTarget;
  // The checksum pick uses the spec's fixed roll sequence: each entry maps
  // through its step and contributes the high bits of the selection.
  let finalSteps = hodlDPlusFinalSteps(config.words),
    finalInfo = finalSteps.map((step, position) => {
      let entry = entries[rolledCharacterTarget + position] || null, value = "";
      if (entry) {
        let picked = hodlDPlusStepValue(step, entry.face);
        if (picked !== null) {
          value = entry.face;
          acceptedCharacters.push(entry.face);
          bits += hodlDPlusStepBits(step);
        } else {
          invalidRanges.push([entry.start, entry.end]);
          invalidRequiredCount += 1;
          if (step === "d8") rejectedD8 += 1;
          else if (step === "d16") rejectedD16 += 1;
          if (!firstInvalid) firstInvalid = { groupIndex: rolledTarget, position, face: entry.face, start: entry.start, end: entry.end, final: true };
        }
      }
      return { step, entry, value };
    });
  let expectedCharacters = rolledCharacterTarget + finalSteps.length,
    extraEntries = entries.slice(expectedCharacters),
    extraAfter = extraEntries.length;
  extraEntries.forEach(token => invalidRanges.push([token.start, token.end]));
  let finalOptions = allRolledValid ? hodlTargetLastWords(wordSlots.join(" "), config.words) : null,
    candidates = finalOptions && !finalOptions.error ? finalOptions.candidates : [],
    finalIndex = 0,
    complete = false,
    waiting;
  if (allRolledValid) {
    for (let position = 0; position < finalSteps.length; position++) {
      let info = finalInfo[position];
      if (!info.entry) { waiting = `checksum-${info.step}`; break; }
      if (info.value === "") { waiting = "correction"; break; }
      finalIndex = finalIndex * (info.step === "d8" ? 8 : info.step === "d16" ? 16 : 2) + hodlDPlusStepValue(info.step, info.entry.face);
      if (position === finalSteps.length - 1) { waiting = "complete"; complete = true; }
    }
  }
  let currentPosition = rolledEntries.length < rolledCharacterTarget ? rolledEntries.length % 3 : null,
    activeGroupIndex = rolledEntries.length < rolledCharacterTarget ? Math.floor(rolledEntries.length / 3) : rolledTarget - 1;
  if (!allRolledComplete) waiting = currentPosition === 0 ? "d8" : currentPosition === 1 ? "d16-first" : "d16-second";
  else if (!allRolledValid) waiting = "correction";
  let finalWord = complete ? candidates[finalIndex] || "" : "";
  let partialLength = rolledEntries.length % 3,
    group = partialLength ? rolledEntries.slice(-partialLength).map(token => token.face) : [],
    words = wordSlots.filter(Boolean),
    notes = [hodlNote("D++: {groups} of {target} positional D8 + D16 + D16 groups entered; {valid} valid ({have} of {need} required results).", { groups: completedGroups, target: rolledTarget, valid: validWordCount, have: rolledEntries.length, need: rolledCharacterTarget })],
    warnings = [];
  notes.push(hodlNote("D++ D16 results use the hexadecimal faces 0 through F exactly as shown on the dice."));
  if (complete && finalWord) {
    let details = finalInfo.map((info) => info.step === "coin" ? hodlNote(Number(info.value) >= 5 ? "D8 result {value} read as Heads" : "D8 result {value} read as Tails", { value: info.value }) : hodlNote("{die} result {value}", { die: hodlDPlusStepLabel(info.step), value: info.value }));
    notes.push(details.length === 1 ? hodlNote("Final {detail} selected checksum option {n} of {total}: {word}.", { detail: details[0], n: finalIndex + 1, total: candidates.length, word: finalWord }) : hodlNote("Final {a} and {b} selected checksum option {n} of {total}: {word}.", { a: details[0], b: details[1], n: finalIndex + 1, total: candidates.length, word: finalWord }));
  }
  if (waiting === "last-word") notes.push(hodlNote("Choose 1 of {n} checksum-valid final words to complete the {words}-word seed.", { n: config.candidates, words: config.words }));
  if (rejectedD8) notes.push(hodlNote(rejectedD8 === 1 ? "Rejected {n} result that cannot be used for a D8 roll." : "Rejected {n} results that cannot be used for a D8 roll.", { n: rejectedD8 }));
  if (rejectedD16) notes.push(hodlNote(rejectedD16 === 1 ? "Rejected {n} result that is not a hexadecimal D16 face (0–F)." : "Rejected {n} results that are not a hexadecimal D16 face (0–F).", { n: rejectedD16 }));
  if (extraAfter) warnings.push(hodlNote(extraAfter === 1 ? "{n} extra input was ignored after {final}." : "{n} extra inputs were ignored after {final}.", { n: extraAfter, final: hodlDPlusFinalNote(config.words) }));
  return {
    words,
    wordSlots,
    groups,
    group,
    entries,
    finalWord,
    candidates,
    waiting,
    currentPosition,
    activeGroupIndex,
    completedGroups,
    validWordCount,
    allRolledComplete,
    allRolledValid,
    bits,
    notes,
    warnings,
    invalidRanges,
    invalidCount: invalidRanges.length,
    invalidRequiredCount,
    rolledInvalidCount,
    needsCorrection: invalidRequiredCount > 0,
    firstInvalid,
    rejectedD8,
    rejectedD16,
    extraAfter,
    acceptedCharacters,
    targetWords: config.words,
    neededPartial: rolledTarget,
    complete: complete && Boolean(finalWord)
  }
}

function hodlAnalyzeDiceInput(value, method = hodlDiceMethod, targetWords = hodlTargetWordCount, coinPositions = hodlDiceCoinPositions) {
  if (method === "dplus") {
    let parsed = hodlDPlusRolls(value, targetWords);
    return { invalidRanges: parsed.invalidRanges, invalidCount: parsed.invalidCount, coinDerivedCount: 0, acceptedRolls: parsed.acceptedCharacters, words: parsed.validWordCount, diceInWord: parsed.currentPosition ?? 0, mappedBits: parsed.bits, totalMappedBits: parsed.bits, complete: parsed.complete, coinTurn: false, dplus: parsed };
  }
  let config = hodlSeedConfig(targetWords), invalidRanges = [], acceptedRolls = [], coinPositionSet = new Set(coinPositions || []), words = 0, diceInWord = 0, mappedBits = 0, totalMappedBits = 0;
  for (let index = 0; index < value.length; ) {
    let character = String.fromCodePoint(value.codePointAt(index)), end = index + character.length, normalized = character.toLowerCase();
    if (/\s|,|;|\|/.test(character)) {
      index = end;
      continue;
    }
    let isDie = normalized >= "1" && normalized <= "6", isCoin = normalized === "h" || normalized === "t", valid = false;
    if (method === "coldcard" || method === "coleman") {
      valid = isDie && !coinPositionSet.has(index);
      if (valid) acceptedRolls.push(normalized);
    } else if (words < config.partialWords) {
      if (diceInWord < 5) {
        if (isDie && Number(normalized) <= 4) {
          valid = true;
          diceInWord += 1;
        }
      } else if (isDie || isCoin) {
        valid = true;
        words += 1;
        diceInWord = 0;
      }
    }
    if (!valid) invalidRanges.push([index, end]);
    index = end;
  }
  let coinDerivedCount = [...coinPositionSet].filter((index) => index >= 0 && index < value.length).length;
  return { invalidRanges, invalidCount: invalidRanges.length, coinDerivedCount, acceptedRolls, words, diceInWord, mappedBits, totalMappedBits, complete: method === "bitbox" && words >= config.partialWords, coinTurn: method === "bitbox" && words < config.partialWords && diceInWord === 5 };
}
var hodlLanczosGamma = [0.99999999999980993, 676.5203681218851, -1259.1392167224028, 771.32342877765313, -176.61502916214059, 12.507343278686905, -0.13857109526572012, 9.9843695780195716e-6, 1.5056327351493116e-7];
function hodlLogGamma(z) {
  let value = Number(z);
  if (!(value > 0) || !Number.isFinite(value)) return Number.POSITIVE_INFINITY;
  if (value < 0.5) return Math.log(Math.PI / Math.sin(Math.PI * value)) - hodlLogGamma(1 - value);
  let x = hodlLanczosGamma[0], shifted = value - 1;
  for (let index = 1; index < hodlLanczosGamma.length; index++) x += hodlLanczosGamma[index] / (shifted + index);
  let t = shifted + 7.5;
  return 0.5 * Math.log(2 * Math.PI) + (shifted + 0.5) * Math.log(t) - t + Math.log(x);
}
function hodlLowerRegularizedGamma(s, x) {
  let shape = Number(s), xx = Number(x);
  if (!(shape > 0) || !Number.isFinite(shape) || !Number.isFinite(xx) || xx <= 0) return 0;
  let logPrefactor = -xx + shape * Math.log(xx) - hodlLogGamma(shape);
  if (xx < shape + 1) {
    let term = 1 / shape, sum = term;
    for (let n = 1; n < 200; n++) {
      term *= xx / (shape + n);
      sum += term;
      if (Math.abs(term) < Math.abs(sum) * 1e-15) break;
    }
    if (logPrefactor < -745) return 0;
    return Math.min(1, Math.max(0, Math.exp(logPrefactor) * sum));
  }
  let b = xx + 1 - shape, c = 1 / 1e-300, d = 1 / b, h = d;
  for (let i = 1; i <= 200; i++) {
    let an = -i * (i - shape);
    b += 2;
    d = an * d + b;
    if (Math.abs(d) < 1e-300) d = 1e-300;
    c = b + an / c;
    if (Math.abs(c) < 1e-300) c = 1e-300;
    d = 1 / d;
    let del = d * c;
    h *= del;
    if (Math.abs(del - 1) < 1e-12) break;
  }
  if (logPrefactor < -745) return 1;
  return Math.min(1, Math.max(0, 1 - Math.exp(logPrefactor) * h));
}
function hodlChiSquaredCdf(chiSq, df) {
  let x = Number(chiSq), degrees = Number(df);
  if (!(x >= 0) || !Number.isFinite(x) || !(degrees >= 1) || !Number.isFinite(degrees)) return 0;
  return hodlLowerRegularizedGamma(degrees / 2, x / 2);
}
function hodlDiceMinimumRolls(sides) {
  return 5 * Math.max(0, Number(sides) || 0);
}
function hodlFormatFairnessNumber(value) {
  let locale = "en";
  try { locale = hodlGetLocale() || "en"; } catch {}
  return new Intl.NumberFormat(locale, { maximumSignificantDigits: 5 }).format(Number(value) || 0);
}
function hodlDiceFairnessVerdict(cdf, enough) {
  if (!enough) return { id: "need-more", tone: "muted" };
  if (cdf < 0.8) return { id: "fair", tone: "ok" };
  if (cdf < 0.9) return { id: "unsure", tone: "warn" };
  return { id: "biased", tone: "danger" };
}
function hodlDiceFairnessFaceLabel(label) {
  if (label === "Heads") return hodlTText("Heads");
  if (label === "Tails") return hodlTText("Tails");
  return String(label ?? "");
}
function hodlDiceFairnessAssess(rolls, labels, title) {
  let faces = Array.isArray(labels) && labels.length ? labels.map((label) => String(label)) : [], n = (rolls || []).length, sides = faces.length, minimum = hodlDiceMinimumRolls(sides);
  let counts = faces.map((label) => ({ label, count: 0 })), indexByLabel = new Map(faces.map((label, index) => [label, index]));
  for (let roll of rolls || []) {
    let index = indexByLabel.get(String(roll));
    if (index != null) counts[index].count += 1;
  }
  let expected = sides && n ? n / sides : 0, chi = 0;
  if (expected > 0) for (let face of counts) chi += (face.count - expected) ** 2 / expected;
  let df = Math.max(1, sides - 1), cdf = expected > 0 ? hodlChiSquaredCdf(chi, df) : 0, enough = n >= minimum && minimum > 0, verdict = n ? hodlDiceFairnessVerdict(cdf, enough) : { id: "empty", label: "", tone: "muted" };
  return { title: title || "Die", sides, n, minimum, remaining: Math.max(0, minimum - n), expected, chi, cdf, df, counts, enough, verdict };
}
function hodlDiceFairnessSamples(value, method, targetWords = hodlTargetWordCount) {
  if (method === "dplus") {
    let parsed = hodlDPlusRolls(value, targetWords), d8 = [], d16 = [], coins = [];
    for (let group of parsed.groups) group.faces.forEach((face, position) => {
      if (group.validity[position]) (position === 0 ? d8 : d16).push(face);
    });
    hodlDPlusFinalSteps(targetWords).forEach((step, index) => {
      let face = (parsed.entries || [])[hodlSeedConfig(targetWords).partialWords * 3 + index]?.face;
      if (!face) return;
      if (step === "d8" && /^[1-8]$/.test(face)) d8.push(face);
      else if (step === "d16" && hodlDPlusD16Value(face) !== null) d16.push(face);
      else if (step === "coin" && /^[1-8]$/.test(face)) coins.push(Number(face) >= 5 ? "Tails" : "Heads");
    });
    return [
      { id: "d8", title: "D8", rolls: d8, labels: ["1", "2", "3", "4", "5", "6", "7", "8"] },
      { id: "d16", title: "D16 (0–F)", rolls: d16, labels: ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "A", "B", "C", "D", "E", "F"] },
      { id: "coin", title: "Coin", rolls: coins, labels: ["Heads", "Tails"] }
    ];
  }
  if (method === "bitbox") {
    let config = hodlSeedConfig(targetWords), d4 = [], coins = [], diceInWord = [], words = 0;
    for (let character of String(value ?? "")) {
      if (/\s|,|;|\|/.test(character)) continue;
      let input = character.toLowerCase(), isDie = input >= "1" && input <= "6", isCoin = input === "h" || input === "t";
      if (!isDie && !isCoin) continue;
      if (words >= config.partialWords) continue;
      if (diceInWord.length < 5) {
        if (isCoin) continue;
        let face = Number(input);
        if (face >= 5) continue;
        d4.push(String(face));
        diceInWord.push(face);
        continue;
      }
      coins.push(input === "h" || input === "1" || input === "2" || input === "3" ? "Heads" : "Tails");
      words += 1;
      diceInWord = [];
    }
    return [
      { id: "d4", title: "D4 (1–4)", rolls: d4, labels: ["1", "2", "3", "4"] },
      { id: "coin", title: "Coin", rolls: coins, labels: ["Heads", "Tails"] }
    ];
  }
  return [{ id: "d6", title: "D6", rolls: hodlAnalyzeDiceInput(value, method, targetWords).acceptedRolls, labels: ["1", "2", "3", "4", "5", "6"] }];
}
function hodlDiceFairnessReports(value, method, targetWords = hodlTargetWordCount) {
  return hodlDiceFairnessSamples(value, method, targetWords).map((sample) => hodlDiceFairnessAssess(sample.rolls, sample.labels, sample.title));
}
function hodlDiceFairnessTone(reports) {
  let rank = { danger: 3, warn: 2, ok: 1, muted: 0 }, tone = "muted";
  for (let report of reports || []) if ((rank[report.verdict.tone] || 0) > rank[tone]) tone = report.verdict.tone;
  return tone;
}
function hodlDiceFairnessNote(report) {
  if (!report.n) return "";
  let title = report.title === "Coin" ? hodlTText("Coin") : report.title;
  if (!report.enough) return hodlTText("{n} of {minimum} minimum {title} rolls for Pearson’s χ² test · {remaining} more needed.", { n: report.n, minimum: report.minimum, title, remaining: report.remaining });
  let robust = report.minimum * 2, quality = report.n >= robust ? hodlTText("Enough rolls to reasonably assess fairness.") : hodlTText("Minimum reached. {n} more would make the estimate more robust.", { n: robust - report.n });
  return hodlTText("A fair {title} would score χ² below {chi} in {percent}% of tests. {quality}", { title, chi: hodlFormatFairnessNumber(report.chi), percent: hodlFormatFairnessNumber(report.cdf * 100), quality });
}
function hodlDiceFairnessMarkup(reports) {
  return (reports || []).filter((report) => report.n > 0).map((report) => {
    let peak = Math.max(report.expected, ...report.counts.map((face) => face.count), 1);
    let faces = report.counts.map((face) => {
      let hot = report.enough && report.expected > 0 && Math.abs(face.count - report.expected) >= 2 * Math.sqrt(report.expected);
      return `<div class="dice-fairness-face${hot ? " is-hot" : ""}"><span class="dice-fairness-label">${hodlEscapeHtml(hodlDiceFairnessFaceLabel(face.label))}</span><span class="dice-fairness-track"><span class="dice-fairness-bar" style="width:${(face.count / peak * 100).toFixed(1)}%"></span>${report.expected > 0 ? `<span class="dice-fairness-expected" style="left:${(report.expected / peak * 100).toFixed(1)}%"></span>` : ""}</span><span class="dice-fairness-count">${face.count}</span></div>`;
    }).join("");
    return `<section class="dice-fairness-test" data-tone="${report.verdict.tone}"><div class="dice-fairness-head"><strong>${hodlEscapeHtml(hodlTText(hodlFairnessVerdictLabels[report.verdict.id] || ""))}</strong><span>${hodlEscapeHtml(hodlTText(report.n === 1 ? "χ² {chi} · {df} df · {n} roll" : "χ² {chi} · {df} df · {n} rolls", { chi: hodlFormatFairnessNumber(report.chi), df: report.df, n: report.n }))}</span></div><p class="dice-fairness-note">${hodlEscapeHtml(hodlDiceFairnessNote(report))}</p><div class="dice-fairness-faces" data-sides="${report.sides}">${faces}</div></section>`;
  }).join("");
}
function hodlDiceFairnessIsOpen() {
  return Boolean(hodlKeys[hodlActiveKey]?.showDiceFairness);
}
function hodlDiceFairnessToggleMarkup(open) {
  let expanded = Boolean(open);
  return `<button type="button" class="dice-fairness-toggle" id="dice-fairness-toggle" aria-controls="dice-fairness" aria-expanded="${expanded}" aria-label="${expanded ? hodlT("Hide die distribution / fairness analysis") : hodlT("Show die distribution / fairness analysis")}"><span data-dice-fairness-glyph aria-hidden="true">${expanded ? "\u25BE" : "\u25B8"}</span> ${hodlT("Die Distribution / Fairness Analysis")}</button>`;
}
function hodlSetDiceFairnessOpen(open) {
  let expanded = Boolean(open), state = hodlKeys[hodlActiveKey], toggle = document.getElementById("dice-fairness-toggle"), glyph = toggle?.querySelector("[data-dice-fairness-glyph]");
  if (state) state.showDiceFairness = expanded;
  if (toggle) {
    toggle.setAttribute("aria-expanded", String(expanded));
    toggle.setAttribute("aria-label", expanded ? hodlTText("Hide die distribution / fairness analysis") : hodlTText("Show die distribution / fairness analysis"));
  }
  if (glyph) glyph.textContent = expanded ? "\u25BE" : "\u25B8";
  let input = document.getElementById("dice");
  hodlRenderDiceFairness(input?.value || "", hodlDiceMethod, hodlSeedConfig().words);
  hodlSyncKeyClearButton();
}
function hodlRenderDiceFairness(value, method, targetWords = hodlTargetWordCount) {
  let panel = document.getElementById("dice-fairness");
  if (!panel) return;
  let reports = hodlDiceFairnessReports(value, method, targetWords), markup = hodlDiceFairnessMarkup(reports), open = hodlDiceFairnessIsOpen();
  panel.hidden = !open;
  panel.dataset.tone = open ? hodlDiceFairnessTone(reports) : "muted";
  panel.innerHTML = open ? (markup ? `${markup}<p class="dice-fairness-caveat">${hodlT("Pearson’s χ² goodness-of-fit. A lucky streak can look biased, and a biased die can look fair until more rolls arrive. This check does not block derivation.")}</p>` : `<p class="dice-fairness-note">${hodlT("Enter rolls to run Pearson’s χ² test.")}</p>`) : "";
  panel.setAttribute("aria-label", hodlTText("Die Distribution / Fairness Analysis"));
}
function hodlDiceControlValue(button) {
  return button.dataset.d || "";
}
function hodlNormalizeDiceCoinPositions(positions) {
  return [...new Set((positions || []).filter(Number.isInteger).filter((index) => index >= 0))].sort((a, b) => a - b);
}
function hodlRebaseDiceCoinPositions(start, end, insertedLength, markInserted = false) {
  let shift = insertedLength - (end - start), next = [];
  hodlDiceCoinPositions.forEach((index) => {
    if (index < start) next.push(index);
    else if (index >= end) next.push(index + shift);
  });
  if (markInserted) for (let index = 0; index < insertedLength; index++) next.push(start + index);
  hodlDiceCoinPositions = hodlNormalizeDiceCoinPositions(next);
}
function hodlRememberDiceBeforeInput(input, event) {
  input.hodlDiceBeforeInput = { value: input.value, start: input.selectionStart ?? input.value.length, end: input.selectionEnd ?? input.selectionStart ?? input.value.length, inputType: event.inputType || "" };
}
function hodlResolveDiceInputEdit(previous, current, pending) {
  if (!pending || pending.value !== previous) return null;
  let start = Math.max(0, Math.min(previous.length, pending.start)), end = Math.max(start, Math.min(previous.length, pending.end)), removedLength = previous.length - current.length;
  if (start === end && removedLength > 0 && pending.inputType.startsWith("delete")) {
    if (pending.inputType.endsWith("Backward")) start = Math.max(0, start - removedLength);
    else if (pending.inputType.endsWith("Forward")) end = Math.min(previous.length, end + removedLength);
    else return null;
  }
  let insertedLength = current.length - (previous.length - (end - start));
  if (insertedLength < 0 || previous.slice(0, start) !== current.slice(0, start) || previous.slice(end) !== current.slice(start + insertedLength)) return null;
  return { start, end, insertedLength };
}
function hodlTrackDiceInputEdit(input) {
  let previous = input.dataset.previousValue ?? "", current = input.value, pending = input.hodlDiceBeforeInput;
  delete input.hodlDiceBeforeInput;
  let resolved = hodlResolveDiceInputEdit(previous, current, pending);
  if (resolved) hodlRebaseDiceCoinPositions(resolved.start, resolved.end, resolved.insertedLength, false);
  else {
    let prefix = 0;
    while (prefix < previous.length && prefix < current.length && previous[prefix] === current[prefix]) prefix += 1;
    let previousEnd = previous.length, currentEnd = current.length;
    while (previousEnd > prefix && currentEnd > prefix && previous[previousEnd - 1] === current[currentEnd - 1]) {
      previousEnd -= 1;
      currentEnd -= 1;
    }
    hodlRebaseDiceCoinPositions(prefix, previousEnd, currentEnd - prefix, false);
  }
  input.dataset.previousValue = current;
}
function hodlSanitizeDiceInput(input, method = hodlDiceMethod, targetWords = hodlTargetWordCount) {
  if (method === "dplus") return hodlSanitizeDPlusInput(input, targetWords);
  let raw = input.value, selectionStart = input.selectionStart ?? raw.length, selectionEnd = input.selectionEnd ?? selectionStart, selectionDirection = input.selectionDirection || "none", positions = new Set(hodlDiceCoinPositions), digits = [];
  for (let index = 0; index < raw.length; index++) if (raw[index] >= "1" && raw[index] <= "6") digits.push({ value: raw[index], coin: positions.has(index) });
  let config = hodlSeedConfig(targetWords), clean = "", nextPositions = [], digitEnds = [0], words = 0, diceInWord = 0, separateNext = false;
  digits.forEach((digit) => {
    if (method === "bitbox" && separateNext) {
      clean += " ";
      separateNext = false;
    }
    if (digit.coin) nextPositions.push(clean.length);
    clean += digit.value;
    if (method === "bitbox" && words < config.partialWords) {
      if (diceInWord < 5) {
        if (Number(digit.value) <= 4) diceInWord += 1;
      } else {
        words += 1;
        diceInWord = 0;
        separateNext = true;
      }
    }
    digitEnds.push(clean.length);
  });
  let countDigits = (value) => value.replace(/[^1-6]/g, "").length, cleanSelectionStart = digitEnds[Math.min(countDigits(raw.slice(0, selectionStart)), digits.length)] ?? clean.length, cleanSelectionEnd = digitEnds[Math.min(countDigits(raw.slice(0, selectionEnd)), digits.length)] ?? clean.length, changed = raw !== clean;
  hodlDiceCoinPositions = hodlNormalizeDiceCoinPositions(nextPositions);
  input.dataset.previousValue = clean;
  delete input.hodlDiceBeforeInput;
  if (!changed) return false;
  input.value = clean;
  input.setSelectionRange(cleanSelectionStart, cleanSelectionEnd, selectionDirection);
  return true;
}
// Characters that can ever be part of the canonical D++ transcript.
function hodlDPlusAllowedCharacters() {
  return new RegExp("[0-9A-Fa-f]")
}

function hodlDPlusSeparator(index, seed) {
  if (index === 0) return "";
  let rolled = seed.partialWords * 3,
    wordBoundary = index < rolled ? index % 3 === 0 : index === rolled;
  return wordBoundary ? " " : ""
}

function hodlSanitizeDPlusInput(input, targetWords = hodlTargetWordCount) {
  let raw = input.value,
    selectionStart = input.selectionStart ?? raw.length,
    selectionEnd = input.selectionEnd ?? selectionStart,
    selectionDirection = input.selectionDirection || "none";
  let seed = hodlSeedConfig(targetWords),
    allowed = hodlDPlusAllowedCharacters(),
    kept = "";
  for (let character of raw)
    if (allowed.test(character) || /[\s,;|]/.test(character)) kept += character;
  let tokens = hodlDPlusTokens(kept).map(entry => entry.face);
  // significantEnds[k] is the offset in `clean` just after its k-th roll character,
  // which is how the caret is carried across reformatting.
  let clean = "",
    significantEnds = [0];
  tokens.forEach((token, index) => {
    clean += hodlDPlusSeparator(index, seed);
    for (let character of token) {
      clean += character;
      significantEnds.push(clean.length)
    }
  });
  let countSignificant = value => {
      let count = 0;
      for (let character of String(value))
        if (allowed.test(character)) count += 1;
      return count
    },
    total = significantEnds.length - 1;
  let cleanSelectionStart = significantEnds[Math.min(countSignificant(raw.slice(0, selectionStart)), total)] ?? clean.length;
  let cleanSelectionEnd = significantEnds[Math.min(countSignificant(raw.slice(0, selectionEnd)), total)] ?? clean.length;
  let changed = raw !== clean;
  input.dataset.previousValue = clean;
  delete input.hodlDiceBeforeInput;
  if (!changed) return false;
  input.value = clean;
  input.setSelectionRange(cleanSelectionStart, cleanSelectionEnd, selectionDirection);
  return true;
}
function hodlBindKeypadPointer(buttons, getInput) {
  buttons.forEach((button) => button.addEventListener("pointerdown", (event) => {
    event.preventDefault();
    if (event.pointerType === "mouse") getInput()?.focus({ preventScroll: true });
  }));
}
function hodlPlaceCaret(input, start, end = start) {
  if (document.activeElement === input) input.setSelectionRange(start, end);
}
function hodlInsertDiceControl(input, button, update = hodlUpdateDice) {
  let inserted;
  try {
    inserted = hodlDiceControlValue(button);
  } catch (error) {
    hodlSetWorkspaceError("key", hodlErrorSpecFrom(error));
    return;
  }
  let start = Number.isInteger(input.selectionStart) ? input.selectionStart : input.value.length, end = Number.isInteger(input.selectionEnd) ? input.selectionEnd : start;
  delete input.hodlDiceBeforeInput;
  if (hodlDiceMethod !== "dplus") hodlRebaseDiceCoinPositions(start, end, inserted.length, Boolean(button.dataset.coin));
  input.value = input.value.slice(0, start) + inserted + input.value.slice(end);
  input.dataset.previousValue = input.value;
  hodlPlaceCaret(input, start + inserted.length);
  hodlSanitizeDiceInput(input);
  update();
}
function hodlInsertEntropyControl(input, button) {
  let inserted = button.dataset.entropyDigit || "";
  if (!input || !inserted) return;
  let start = Number.isInteger(input.selectionStart) ? input.selectionStart : input.value.length, end = Number.isInteger(input.selectionEnd) ? input.selectionEnd : start;
  input.setRangeText(inserted, start, end, "end");
  input.dispatchEvent(new InputEvent("input", { bubbles: true, inputType: "insertText", data: inserted }));
}
function hodlSyncDiceHighlight(input) {
  let highlight = input.closest(".dice-input-shell")?.querySelector(".dice-input-highlight");
  if (!highlight) return;
  highlight.scrollTop = input.scrollTop;
  highlight.scrollLeft = input.scrollLeft;
}
function hodlRenderInputHighlight(input, ranges = []) {
  let highlight = input.closest(".dice-input-shell")?.querySelector(".dice-input-highlight");
  if (!highlight) return;
  let fragment = document.createDocumentFragment(),
    cursor = 0,
    normalized = ranges.map(range => [Math.max(0, Number(range[0]) || 0), Math.min(input.value.length, Number(range[1]) || 0), range[2] || "dice-roll-invalid"]).filter(([start, end]) => end > start).sort((a, b) => a[0] - b[0]);
  normalized.forEach(([rangeStart, rangeEnd, className]) => {
    let start = Math.max(cursor, rangeStart),
      end = Math.max(start, rangeEnd);
    if (start > cursor) fragment.appendChild(document.createTextNode(input.value.slice(cursor, start)));
    if (end > start) {
      let span = document.createElement("span");
      span.className = className;
      span.textContent = input.value.slice(start, end);
      fragment.appendChild(span);
      cursor = end;
    }
  });
  if (cursor < input.value.length) fragment.appendChild(document.createTextNode(input.value.slice(cursor)));
  highlight.dataset.trailingNewline = String(input.value.endsWith("\n"));
  highlight.replaceChildren(fragment);
  hodlSyncDiceHighlight(input);
  requestAnimationFrame(() => hodlSyncDiceHighlight(input));
}
function hodlRenderDiceInputHighlight(input, analysis) {
  hodlRenderInputHighlight(input, analysis.invalidRanges);
}
function hodlBinaryDigits(value) {
  return String(value ?? "").replace(/[^01]/g, "");
}
function hodlNormalizeEntropyCharacter(character, format) {
  let id = hodlNormalizeEntropyFormat(format), normalized = String(character ?? "");
  if (id === "base64") return normalized;
  normalized = normalized.toUpperCase();
  if (id === "base32") {
    if (normalized === "O") return "0";
    if (normalized === "I" || normalized === "L") return "1";
  }
  return normalized;
}
function hodlFilterNumberBase(value, format) {
  let meta = hodlEntropyFormatConfig(format), filtered = "";
  for (let character of String(value ?? "")) {
    if (/\s/.test(character)) {
      filtered += character;
      continue;
    }
    let normalized = hodlNormalizeEntropyCharacter(character, meta.id);
    if (meta.alphabet.includes(normalized)) filtered += normalized;
  }
  return filtered;
}
function hodlEntropyDigitEntries(value, format) {
  let meta = hodlEntropyFormatConfig(format), entries = [], invalidEntries = [];
  for (let index = 0; index < String(value ?? "").length; ) {
    let character = String.fromCodePoint(String(value).codePointAt(index)), end = index + character.length;
    if (!/\s/.test(character)) {
      let normalized = hodlNormalizeEntropyCharacter(character, meta.id), digit = meta.alphabet.indexOf(normalized), entry = { character, normalized, digit, start: index, end };
      if (digit < 0) invalidEntries.push(entry);
      else entries.push(entry);
    }
    index = end;
  }
  return { entries, invalidEntries };
}
function hodlEntropyDigits(value, format) {
  return hodlEntropyDigitEntries(value, format).entries.map((entry) => entry.normalized).join("");
}
function hodlNumberBaseBits(value, format, targetWords = hodlTargetWordCount) {
  let meta = hodlEntropyFormatConfig(format, targetWords), digits = hodlEntropyDigits(value, meta.id).slice(0, meta.digits);
  return Array.from(digits, (character, index) => {
    if (meta.binaryRemainder && index >= meta.fullDigits) return character;
    let width = meta.remainderBits && index === meta.digits - 1 ? meta.remainderBits : meta.bitsPerDigit;
    return meta.alphabet.indexOf(character).toString(2).padStart(width, "0");
  }).join("").slice(0, meta.seed.bits);
}
function hodlNumberBaseValueFromBytes(bytes, format, targetWords = hodlTargetWordCount) {
  let meta = hodlEntropyFormatConfig(format, targetWords), bits = Array.from(bytes, (byte) => byte.toString(2).padStart(8, "0")).join(""), value = "";
  for (let index = 0; index < meta.fullDigits; index++) {
    let start = index * meta.bitsPerDigit;
    value += meta.alphabet[Number.parseInt(bits.slice(start, start + meta.bitsPerDigit), 2)];
  }
  if (meta.remainderBits) {
    let finalBits = bits.slice(meta.fullDigits * meta.bitsPerDigit);
    value += meta.binaryRemainder ? finalBits : meta.alphabet[Number.parseInt(finalBits, 2)];
  }
  return meta.id === "bin" ? hodlGroupedBinary(value) : value;
}
function hodlGroupedBinary(value) {
  let digits = hodlBinaryDigits(value), groups = digits.match(/.{1,11}/g);
  return groups ? groups.join(" ") : "";
}
function hodlBinarySelectionOffset(bitCount, totalBits) {
  let separators = totalBits > 0 ? Math.floor((totalBits - 1) / 11) : 0;
  return bitCount + Math.min(Math.floor(bitCount / 11), separators);
}
function hodlFormatBinaryInput(input) {
  let raw = input.value, grouped = hodlGroupedBinary(raw);
  if (grouped === raw) return false;
  let start = input.selectionStart ?? raw.length, end = input.selectionEnd ?? start, direction = input.selectionDirection || "none", startBits = hodlBinaryDigits(raw.slice(0, start)).length, endBits = hodlBinaryDigits(raw.slice(0, end)).length, totalBits = hodlBinaryDigits(raw).length;
  input.value = grouped;
  input.setSelectionRange(hodlBinarySelectionOffset(startBits, totalBits), hodlBinarySelectionOffset(endBits, totalBits), direction);
  return true;
}
function hodlHandleGroupedSeparatorDelete(input, event) {
  if (input.selectionStart !== input.selectionEnd) return;
  let caret = input.selectionStart ?? 0, start = caret, end = caret;
  if (event.inputType === "deleteContentBackward" && caret > 1 && input.value[caret - 1] === " ") start = caret - 2;
  else if (event.inputType === "deleteContentForward" && input.value[caret] === " " && caret + 1 < input.value.length) end = caret + 2;
  else return;
  event.preventDefault();
  input.setRangeText("", start, end, "end");
  input.dispatchEvent(new InputEvent("input", { bubbles: true, inputType: event.inputType }));
}
function hodlHandleBinarySeparatorDelete(input, event) {
  hodlHandleGroupedSeparatorDelete(input, event);
}
function hodlAnalyzeEntropyInput(value, format, targetWords = hodlTargetWordCount) {
  let meta = hodlEntropyFormatConfig(format, targetWords), { entries, invalidEntries } = hodlEntropyDigitEntries(value, meta.id), excessEntries = entries.slice(meta.digits), remainderEntries = meta.binaryRemainder ? entries.slice(meta.fullDigits, meta.digits) : entries.slice(meta.digits - 1, meta.digits), finalInvalidEntries = meta.remainderBits ? remainderEntries.filter((entry) => !meta.finalCharacters.includes(entry.normalized)) : [], finalInvalid = finalInvalidEntries.length > 0, invalidRanges = [...invalidEntries.map((entry) => [entry.start, entry.end]), ...excessEntries.map((entry) => [entry.start, entry.end]), ...finalInvalidEntries.map((entry) => [entry.start, entry.end])];
  return { count: entries.length, limit: meta.digits, excessCount: Math.max(0, entries.length - meta.digits), invalidCharacterCount: invalidEntries.length, finalInvalid, finalInvalidEntries, invalidRanges, entries, meta, ready: entries.length === meta.digits && !invalidEntries.length && !excessEntries.length && !finalInvalid };
}
function hodlRenderEntropyInputState(input, format, targetWords = hodlTargetWordCount) {
  let analysis = hodlAnalyzeEntropyInput(input.value, format, targetWords), invalid = analysis.invalidRanges.length > 0;
  input.classList.toggle("bad", invalid);
  input.setAttribute("aria-invalid", String(invalid));
  hodlRenderInputHighlight(input, analysis.invalidRanges);
  return analysis;
}
function hodlUpdateDiceButtons(input, analysis) {
  let pad = input.closest("#form")?.querySelector(".dice-input-pad");
  if (!pad) return;
  pad.querySelectorAll("button[data-d]").forEach((button) => {
    let disabled = false, reason = "", face = Number(button.dataset.d);
    if (hodlDiceMethod === "dplus") {
      let turn = analysis.dplus?.waiting || "d8",
        isD8 = turn === "d8" || turn === "checksum-d8",
        coinTurn = turn === "checksum-coin",
        correcting = turn === "correction",
        value = String(button.dataset.d || "").toUpperCase();
      disabled = turn === "complete" || turn === "last-word" || correcting || (coinTurn || isD8 ? !/^[1-8]$/.test(value) : hodlDPlusD16Value(value) === null);
      if (turn === "complete") reason = "The rolled words and final checksum rolls are complete.";
      else if (turn === "last-word") reason = `All ${hodlSeedConfig().partialWords} rolled words are complete. Choose the final checksum word below.`;
      else if (correcting) reason = "Correct the highlighted invalid result in its existing D++ position before continuing.";
      else if (coinTurn && disabled) reason = "The final D8 is interpreted as a coin flip: 1\u20134 is Heads, 5\u20138 is Tails.";
      else if (coinTurn) reason = "Final D8, interpreted as a coin flip: 1\u20134 is Heads, 5\u20138 is Tails.";
      else if (disabled) reason = "This roll needs the D8, so use a result from 1 through 8.";

      else reason = isD8 ? (turn === "checksum-d8" ? "Final D8: choose checksum option 1 through 8." : "D8 roll: choose result 1 through 8.") : "Hexadecimal D16 roll: choose the face shown from 0 through F.";
    } else if (hodlDiceMethod === "bitbox") {
      if (analysis.complete) {
        disabled = true;
        reason = "All lookup-table words are complete.";
      } else if (!analysis.coinTurn && face >= 5) {
        disabled = true;
        reason = "Reroll a 5 or 6 during the first five BitBox rolls.";
      }
    }
    if (hodlDiceMethod === "dplus") {
      // A coin-flip step reads a D8 as one bit. On that turn the eight D8
      // keys collapse into one Heads key and one Tails key, each naming the
      // faces it stands for. Tapping enters the first face of its range; the
      // range is what decides the bit, so any face in it derives the same word,
      // and the actual roll can still be typed.
      // Only a D8 face can be rolled here, so the D16-only keys (0 and 9-F) are
      // hidden rather than left greyed around the two that are live.
      let coinTurn = analysis.dplus?.waiting === "checksum-coin",
        leads = coinTurn && (face === 1 || face === 5);
      button.hidden = coinTurn && !leads;
      button.classList.toggle("dice-key-wide", leads);
      if (leads) {
        let side = face === 1 ? "Heads" : "Tails",
          range = face === 1 ? "1 – 4" : "5 – 8",
          caption = document.createElement("span");
        caption.className = "dice-key-caption";
        caption.textContent = range;
        button.replaceChildren(document.createTextNode(side), caption);
      } else if (!coinTurn && button.querySelector(".dice-key-caption")) {
        button.replaceChildren(document.createTextNode(String(button.dataset.d || "")));
      }
      button.classList.toggle("has-caption", leads);
    }
    if (hodlDiceMethod === "bitbox") {
      // The sixth roll is the coin, so on that turn the six keys become two:
      // Heads over 1-3 and Tails over 4-6, matching the BitBox lookup table
      // column labels. Tapping enters the first face of its range; the range is
      // what decides the bit, so any face in it builds the same word, and the
      // actual roll can still be typed rather than tapped.
      let flipping = analysis.coinTurn && face >= 1 && face <= 6,
        leads = face === 1 || face === 4;
      button.hidden = flipping && !leads;
      button.classList.toggle("dice-key-wide", flipping && leads);
      if (flipping && leads) {
        let side = face === 1 ? "Heads" : "Tails",
          range = face === 1 ? "1 – 3" : "4 – 6",
          caption = document.createElement("span");
        caption.className = "dice-key-caption";
        caption.textContent = range;
        button.replaceChildren(document.createTextNode(side), caption);
      } else {
        button.replaceChildren(document.createTextNode(String(button.dataset.d || "")));
      }
      button.classList.toggle("has-caption", flipping && leads);
    }
    button.disabled = disabled;
    button.title = reason;
  });
}
function hodlRenderDiceInputState(input) {
  let analysis = hodlAnalyzeDiceInput(input.value, hodlDiceMethod, hodlTargetWordCount);
  input.setAttribute("aria-invalid", String(analysis.invalidCount > 0));
  hodlRenderDiceInputHighlight(input, analysis);
  hodlUpdateDiceButtons(input, analysis);
  return analysis;
}
function hodlIanColemanDiceString(rolls) {
  return rolls.map((face) => face === "6" ? "0" : face).join("");
}
function hodlDiceEntropy(value, method, targetWords = hodlTargetWordCount) {
  let config = hodlSeedConfig(targetWords), notes = [], warnings = [];
    if (method === "dplus") return { ok: false, error: { key: "D++ directly selects {partial} BIP39 words; {final} to finish with the final checksum word.", vars: { partial: config.partialWords, final: hodlDPlusFinalDescription(config.words) } }, notes, warnings };
  let parsed = hodlSplitDiceString(value), rolls = parsed.rolls;
  if (method === "bitbox") return { ok: false, error: { key: "BitBox diceware uses {partial} lookup-table words and a final checksum pick for a {words}-word seed.", vars: { partial: config.partialWords, words: config.words } }, notes, warnings };
  if (parsed.leftover.length) return { ok: false, error: { key: "Dice must be faces 1–6. Ignored characters: {chars}", vars: { chars: JSON.stringify(parsed.leftover.slice(0, 24)) } }, notes, warnings };
  if (!rolls.length) return { ok: false, error: { key: "Enter at least one dice roll (faces 1–6)." }, notes, warnings };
  let sourceBits = hodlDiceEntropyBits(rolls.length);
  notes.push(hodlNote("{n} rolls of a fair six-sided die ≈ {bits} bits.", { n: rolls.length, bits: sourceBits.toFixed(1) }));
  if (rolls.length < config.hashRolls) warnings.push(hodlNote("Only {have} of {need} recommended fair-die rolls were entered. The {words}-word phrase is deterministic, but its security cannot exceed the approximately {bits} bits supplied. Use only for testing until the recommendation is met.", { have: rolls.length, need: config.hashRolls, words: config.words, bits: sourceBits.toFixed(1) }));
  else if (rolls.length > config.hashRolls) notes.push(hodlNote("All {n} rolls, including {extra} beyond the recommendation, are included in the hash.", { n: rolls.length, extra: rolls.length - config.hashRolls }));
  let hashInput = method === "coleman" ? hodlIanColemanDiceString(rolls) : rolls.join(""), digest = hodlSha256(new TextEncoder().encode(hashInput)), bytes = digest.slice(0, config.bytes);
  if (method === "coleman") notes.push(hodlNote("Hashed rolls / Dice [1-6]: convert every 6 to 0, SHA-256 hash the complete mapped digit string, then use the first {bits} bits for the selected {words}-word seed. This matches the method used by Keystone.", { bits: config.bits, words: config.words }));
  else notes.push(hodlNote("Hashed rolls / Base 10 [0-9]: SHA-256 hash the complete original dice digit string, then use the first {bits} bits for the selected {words}-word seed. This matches COLDCARD and SeedSigner.", { bits: config.bits, words: config.words }));
  return { ok: true, bytes, hex: hodlHex.encode(bytes), bits: config.bits, sourceBits, method: method === "coleman" ? "ian-coleman-dice-sha256" : "coldcard-sha256", notes, warnings };
}
function hodlNumberBaseEntropy(value, format, targetWords = hodlTargetWordCount) {
  let meta = hodlEntropyFormatConfig(format, targetWords), analysis = hodlAnalyzeEntropyInput(value, meta.id, meta.seed.words), notes = [], warnings = [];
  if (!analysis.count) return { ok: false, error: { key: "Enter exactly {digits} {unit} for a {words}-word seed.", vars: { digits: meta.digits, unit: hodlT(meta.unit), words: meta.seed.words } }, notes, warnings };
  if (analysis.invalidCharacterCount) return { ok: false, error: { key: analysis.invalidCharacterCount === 1 ? "{label} entropy contains {n} invalid character." : "{label} entropy contains {n} invalid characters.", vars: { label: hodlT(meta.shortLabel), n: analysis.invalidCharacterCount } }, notes, warnings };
  if (analysis.finalInvalid) return { ok: false, error: meta.binaryRemainder ? { key: meta.remainderBits === 1 ? "The final {n} {label} entropy bit must each be 0 or 1." : "The final {n} {label} entropy bits must each be 0 or 1.", vars: { n: meta.remainderBits, label: hodlT(meta.shortLabel) } } : { key: meta.remainderBits === 1 ? "The final {label} character contributes only {n} bit and must be one of {chars}." : "The final {label} character contributes only {n} bits and must be one of {chars}.", vars: { label: hodlT(meta.shortLabel), n: meta.remainderBits, chars: [...meta.finalCharacters].join(", ") } }, notes, warnings };
  if (analysis.count !== meta.digits) return { ok: false, error: { key: "The selected {words}-word seed needs exactly {digits} {unit} ({bits} bits). You entered {have}.", vars: { words: meta.seed.words, digits: meta.digits, unit: hodlT(meta.unit), bits: meta.seed.bits, have: analysis.count } }, notes, warnings };
  let bits = hodlNumberBaseBits(value, meta.id, meta.seed.words), bytes = new Uint8Array(meta.seed.bytes);
  for (let index = 0; index < bytes.length; index++) bytes[index] = Number.parseInt(bits.slice(index * 8, index * 8 + 8), 2);
  notes.push(hodlNote("{digits} {unit} = {bits} bits of {label} entropy.", { digits: meta.digits, unit: hodlNote(meta.unit), bits: meta.seed.bits, label: hodlNote(`hex.short.${meta.id}`) }));
  if (meta.remainderBits) notes.push(meta.binaryRemainder ? hodlNote(meta.remainderBits === 1 ? "{full} complete {label} characters are followed by {n} individual coin-flip entropy bit." : "{full} complete {label} characters are followed by {n} individual coin-flip entropy bits.", { full: meta.fullDigits, label: hodlNote(`hex.short.${meta.id}`), n: meta.remainderBits }) : hodlNote(meta.remainderBits === 1 ? "The final character is mixed-radix: it contributes the remaining {n} entropy bit and must be one of {chars}." : "The final character is mixed-radix: it contributes the remaining {n} entropy bits and must be one of {chars}.", { n: meta.remainderBits, chars: [...meta.finalCharacters].join(", ") }));
  notes.push(hodlNote("BIP39 entropy length: {bits} bits → {words}-word seed.", { bits: meta.seed.bits, words: meta.seed.words }));
  return { ok: true, bytes, hex: hodlHex.encode(bytes), bits: meta.seed.bits, sourceBits: meta.seed.bits, method: meta.method, notes, warnings };
}
function hodlCardNeeded(targetWords = hodlTargetWordCount) {
  // Derived from the selected BIP39 entropy target, not policy constants:
  // the smallest without-replacement deal whose entropy reaches the target.
  // One deck tops out at ~225.6 bits, so a 256-bit seed finishes with extra
  // cards from a second shuffled deck.
  let bits = hodlSeedConfig(targetWords).bits;
  for (let first = 1; first <= 52; first++) if (hodlCardWithoutReplacementBits(first) >= bits) return { first, extra: 0 };
  for (let extra = 1; extra <= 52; extra++) if (hodlCardWithoutReplacementBits(52) + hodlCardWithoutReplacementBits(extra) >= bits) return { first: 52, extra };
  return { first: 52, extra: 52 };
}
function hodlCardWithoutReplacementBits(count) {
  let bits = 0, n = Math.min(Math.max(0, Number(count) || 0), 52);
  for (let i = 0; i < n; i++) bits += Math.log2(52 - i);
  return bits;
}
function hodlNormalizeCardToken(token) {
  let value = String(token ?? "").trim().toUpperCase().replace(/\u2660/g, "S").replace(/\u2665/g, "H").replace(/\u2666/g, "D").replace(/\u2663/g, "C");
  if (value.startsWith("10")) value = "T" + value.slice(2);
  return /^[A2-9TJQK][CDHS]$/.test(value) ? value : "";
}
function hodlParseCards(raw, targetWords = hodlTargetWordCount) {
  let needed = hodlCardNeeded(targetWords), text = String(raw ?? "").toUpperCase().replace(/\u2660/g, "S").replace(/\u2665/g, "H").replace(/\u2666/g, "D").replace(/\u2663/g, "C");
  let entries = [...text.matchAll(/[^\s,.;:_|/-]+/g)].map((match) => ({ token: match[0], start: match.index, end: match.index + match[0].length })), cards = [], invalid = [], duplicates = [], invalidEntries = [], duplicateEntries = [];
  for (let entry of entries) {
    let card = hodlNormalizeCardToken(entry.token);
    entry.card = card;
    if (!card) {
      invalid.push(entry.token);
      invalidEntries.push(entry);
      continue;
    }
    let pool = cards.length < needed.first ? cards : cards.slice(needed.first);
    if (pool.includes(card)) {
      entry.duplicate = true;
      duplicates.push(card);
      duplicateEntries.push(entry);
    } else cards.push(card);
  }
  let firstCount = Math.min(cards.length, needed.first), extraCount = Math.max(0, cards.length - needed.first);
  let bits = hodlCardWithoutReplacementBits(firstCount);
  for (let i = 0; i < extraCount; i++) bits += Math.log2(52 - i);
  return { cards, invalid, duplicates, entries, invalidEntries, duplicateEntries, bits, needed, hashInput: hodlCardsHashInput(cards) };
}
function hodlCardsHashInput(cards, coleman = false) {
  let transcript = (cards || []).map((card) => card.slice(0, -1) + card.slice(-1).toLowerCase()).join(" ");
  if (!coleman) return transcript;
  return transcript.replace(/c/g, "\u2663").replace(/d/g, "\u2666").replace(/h/g, "\u2665").replace(/s/g, "\u2660");
}
function hodlCardTokenCanContinue(token) {
  return /^(?:[A2-9TJQK]|1|10)$/i.test(String(token ?? ""));
}
function hodlFilterCards(value, coleman = false) {
  let text = String(value ?? "").toUpperCase().replace(/\u2660/g, "S").replace(/\u2665/g, "H").replace(/\u2666/g, "D").replace(/\u2663/g, "C");
  if (coleman) {
    text = text.replace(/10(?=[CDHS])/g, "T");
    text = text.replace(/([A2-9TJQK])([CDHS])[\s,.;:_|/-]*/g, (_, rank, suit) => rank + ({ C: "\u2663", D: "\u2666", H: "\u2665", S: "\u2660" })[suit] + " ");
    return text.replace(/[^0-9A-Z\s,.;:_|/\-\u2660\u2663\u2665\u2666]/g, "").replace(/[\s,.;:_|/-]+/g, " ");
  }
  text = text.replace(/[^0-9A-Z\s,.;:_|/-]/g, "").replace(/[\s,.;:_|/-]+/g, " ").replace(/10(?=[CDHS])/g, "T");
  return text.replace(/([A2-9TJQK])([CDHS])[\s,.;:_|/-]*/g, (_, rank, suit) => rank + suit.toLowerCase() + " ");
}
function hodlCardTypedCharactersAllowed(value) {
  return [...String(value ?? "")].every((character) => /[A2-9TJQKCDHS10\s,.;:_|/\-\u2660\u2663\u2665\u2666]/i.test(character));
}
function hodlAnalyzeCardInput(input, targetWords = hodlTargetWordCount) {
  let parsed = hodlParseCards(input?.value ?? "", targetWords), pending = null, lastInvalid = parsed.invalidEntries.at(-1), caret = input?.selectionStart ?? -1;
  if (lastInvalid && document.activeElement === input && input.selectionStart === input.selectionEnd && caret === lastInvalid.end && !/[\s,.;:_|/-]$/.test(input.value) && hodlCardTokenCanContinue(lastInvalid.token)) pending = lastInvalid;
  let invalidRanges = [...parsed.invalidEntries.filter((entry) => entry !== pending), ...parsed.duplicateEntries].map((entry) => [entry.start, entry.end]);
  return { ...parsed, pending, invalidRanges };
}
function hodlRenderCardInputState(input, targetWords = hodlTargetWordCount) {
  let analysis = hodlAnalyzeCardInput(input, targetWords), invalid = analysis.invalidRanges.length > 0;
  input.classList.toggle("bad", invalid);
  input.setAttribute("aria-invalid", String(invalid));
  hodlRenderInputHighlight(input, analysis.invalidRanges);
  return analysis;
}
function hodlCardSuitMeta(code) {
  return hodlCardSuits.find((suit) => suit.code === code) || hodlCardSuits[0];
}
function hodlDealtCardMarkup(card) {
  let rank = card.slice(0, -1), suit = hodlCardSuitMeta(card.slice(-1));
  return `<span class="dealt-card${suit.red ? " is-red" : ""}" title="${rank} of ${suit.label}"><span class="dealt-rank">${hodlEscapeHtml(rank === "T" ? "10" : rank)}</span><span class="dealt-suit">${suit.symbol}</span></span>`;
}
function hodlCardsEntropy(value, targetWords = hodlTargetWordCount, coleman = false) {
  let config = hodlSeedConfig(targetWords), notes = [], warnings = [], parsed = hodlParseCards(value, config.words);
  if (parsed.invalid.length) return { ok: false, error: { key: "Cards use rank then suit, like AS, 10H, or TD. Ignored: {ignored}", vars: { ignored: parsed.invalid.slice(0, 8).join(" ") } }, notes, warnings, parsed };
  if (parsed.duplicates.length) return { ok: false, error: { key: "Do not repeat a card in the same shuffle. Repeated: {card}.", vars: { card: parsed.duplicates[0] } }, notes, warnings, parsed };
  if (!parsed.cards.length) return { ok: false, error: { key: "Deal at least one card from a shuffled deck." }, notes, warnings, parsed };
  let required = parsed.needed.first + parsed.needed.extra, hashInput = hodlCardsHashInput(parsed.cards, coleman);
  notes.push(hodlNote(parsed.cards.length === 1 ? "{n} card ≈ {bits} bits." : "{n} cards ≈ {bits} bits.", { n: parsed.cards.length, bits: parsed.bits.toFixed(1) }));
  notes.push(hodlNote(coleman ? "SHA-256 hashes Ian Coleman's suit-symbol transcript (A♠ 2♣ T♦), then the first {bits} bits become the selected {words}-word seed. One shuffled deck is about 225.6 bits." : "SHA-256 hashes the ASCII transcript (AS 2C TD), then the first {bits} bits become the selected {words}-word seed. One shuffled deck is about 225.6 bits.", { bits: config.bits, words: config.words }));
  if (parsed.cards.length < required) warnings.push(hodlNote("Only {have} of {need} recommended cards were entered. The {words}-word phrase is deterministic, but its security cannot exceed the approximately {bits} bits supplied. Use only for testing until the recommendation is met.", { have: parsed.cards.length, need: required, words: config.words, bits: parsed.bits.toFixed(1) }));
  if (parsed.cards.length > required) notes.push(hodlNote("All {n} cards, including extras, are included in the hash.", { n: parsed.cards.length }));
  let digest = hodlSha256(new TextEncoder().encode(hashInput)), bytes = digest.slice(0, config.bytes);
  return { ok: true, bytes, hex: hodlHex.encode(bytes), bits: config.bits, sourceBits: parsed.bits, method: coleman ? "ian-coleman-cards-sha256" : "cards-sha256", notes, warnings, parsed, hashInput };
}
function hodlCardSelectionState(cards, needed, selectedSuit = "", selectedRank = "") {
  let currentShuffle = cards.length < needed.first ? cards : cards.slice(needed.first), used = new Set(currentShuffle), available = [];
  for (let suit of hodlCardSuits) for (let rank of hodlCardRanks) {
    let card = rank + suit.code;
    if (!used.has(card)) available.push(card);
  }
  let availableSuits = hodlCardSuits.map((suit) => suit.code).filter((suit) => available.some((card) => card.endsWith(suit))), availableRanks = hodlCardRanks.filter((rank) => available.some((card) => card.startsWith(rank)));
  let suit = availableSuits.includes(selectedSuit) ? selectedSuit : "", rank = availableRanks.includes(selectedRank) ? selectedRank : "";
  if (suit && rank && !available.includes(rank + suit)) suit = rank = "";
  if (!suit && availableSuits.length === 1) suit = availableSuits[0];
  if (!rank && availableRanks.length === 1) rank = availableRanks[0];
  let compatibleSuits = rank ? availableSuits.filter((code) => available.includes(rank + code)) : availableSuits.slice(), compatibleRanks = suit ? availableRanks.filter((value) => available.includes(value + suit)) : availableRanks.slice();
  if (suit && !rank && compatibleRanks.length === 1) rank = compatibleRanks[0];
  if (rank && !suit && compatibleSuits.length === 1) suit = compatibleSuits[0];
  compatibleSuits = rank ? availableSuits.filter((code) => available.includes(rank + code)) : availableSuits.slice();
  compatibleRanks = suit ? availableRanks.filter((value) => available.includes(value + suit)) : availableRanks.slice();
  let card = suit && rank && available.includes(rank + suit) ? rank + suit : "";
  return { suit, rank, card, used, available, availableSuits, availableRanks, compatibleSuits, compatibleRanks };
}
function hodlToggleCardChoice(current, selected) {
  return current === selected ? "" : selected;
}
function hodlCommitCardSelection(input, card) {
  input.value = input.value.trim() ? `${input.value.trim()} ${card}` : card;
  hodlCardSuit = "";
  hodlCardRank = "";
  input.dispatchEvent(new Event("input"));
}
function hodlDirectCardFinalRadices(targetWords = hodlTargetWordCount) {
  return { 12: [8, 8, 2], 15: [8, 8], 18: [8, 4], 21: [8, 2], 24: [8] }[hodlSeedConfig(targetWords).words];
}
function hodlDirectCardSteps(targetWords = hodlTargetWordCount) {
  let config = hodlSeedConfig(targetWords), steps = [];
  for (let index = 0; index < config.partialWords; index++) steps.push(8, 8, 8, 4);
  return steps.concat(hodlDirectCardFinalRadices(config.words));
}
function hodlDirectCardRankValue(rank) {
  let normalized = String(rank ?? "").trim().toUpperCase();
  return normalized === "A" ? 0 : /^[2-8]$/.test(normalized) ? Number(normalized) - 1 : -1;
}
function hodlDirectCardSeparator(index, targetWords = hodlTargetWordCount) {
  if (index === 0) return "";
  let config = hodlSeedConfig(targetWords), fullWordDraws = config.partialWords * 4, finalDraws = hodlDirectCardFinalRadices(config.words).length;
  if (index < fullWordDraws) return index % 4 === 0 ? " " : "";
  return index === fullWordDraws || index === fullWordDraws + finalDraws ? " " : "";
}
function hodlFilterDirectCards(value, targetWords = hodlTargetWordCount) {
  let characters = String(value ?? "").toUpperCase().match(/[0-9A-Z]/g) || "", clean = "";
  for (let index = 0; index < characters.length; index++) clean += hodlDirectCardSeparator(index, targetWords) + characters[index];
  return clean;
}
function hodlParseDirectCards(raw, targetWords = hodlTargetWordCount) {
  let config = hodlSeedConfig(targetWords), steps = hodlDirectCardSteps(config.words), text = String(raw ?? "").toUpperCase(), entries = [...text.matchAll(/[^\s,.;:_|/-]/g)].map((match, position) => ({ token: match[0], start: match.index, end: match.index + 1, position })), invalidEntries = [], extraEntries = [], values = [], ranks = [];
  for (let entry of entries) {
    let max = steps[entry.position], value = hodlDirectCardRankValue(entry.token);
    entry.max = max;
    entry.value = value;
    if (max === void 0) {
      entry.extra = true;
      extraEntries.push(entry);
      continue;
    }
    if (value < 0 || value >= max) {
      entry.invalid = true;
      invalidEntries.push(entry);
      values.push(null);
      ranks.push(entry.token);
      continue;
    }
    values.push(value);
    ranks.push(entry.token);
  }
  let wordSlots = Array(config.partialWords).fill(""), allPartialValid = values.length >= config.partialWords * 4;
  for (let wordIndex = 0; wordIndex < config.partialWords; wordIndex++) {
    let group = values.slice(wordIndex * 4, wordIndex * 4 + 4);
    if (group.length < 4 || group.some((value) => value === null)) {
      allPartialValid = false;
      continue;
    }
    let index = (((group[0] * 8) + group[1]) * 8 + group[2]) * 4 + group[3];
    wordSlots[wordIndex] = hodlBip39Wordlist[index];
  }
  let candidates = allPartialValid ? hodlTargetLastWords(wordSlots.join(" "), config.words)?.candidates || [] : [], finalValues = values.slice(config.partialWords * 4), finalRadices = hodlDirectCardFinalRadices(config.words), finalIndex = 0, finalValid = finalValues.length === finalRadices.length && finalValues.every((value) => value !== null);
  if (finalValid) finalValues.forEach((value, index) => finalIndex = finalIndex * finalRadices[index] + value);
  let finalWord = finalValid ? candidates[finalIndex] || "" : "", complete = entries.length === steps.length && !invalidEntries.length && !extraEntries.length && Boolean(finalWord), expectedMax = steps[Math.min(entries.length, steps.length - 1)], words = finalWord ? [...wordSlots, finalWord] : wordSlots;
  return { entries, invalidEntries, extraEntries, invalidRanges: [...invalidEntries, ...extraEntries].map((entry) => [entry.start, entry.end]), values, ranks, steps, wordSlots, words, candidates, finalWord, finalIndex, complete, expectedMax, config };
}
function hodlDirectCardsEntropy(value, targetWords = hodlTargetWordCount) {
  let parsed = hodlParseDirectCards(value, targetWords), config = parsed.config, notes = [], warnings = [];
  if (parsed.invalidEntries.length) return { ok: false, error: { key: "Correct the highlighted rank. This draw allows only Ace through {max}.", vars: { max: parsed.invalidEntries[0].max } }, notes, warnings, parsed };
  if (parsed.extraEntries.length) return { ok: false, error: { key: parsed.extraEntries.length === 1 ? "The {words}-word seed is complete. Remove {n} extra card." : "The {words}-word seed is complete. Remove {n} extra cards.", vars: { words: config.words, n: parsed.extraEntries.length } }, notes, warnings, parsed };
  if (!parsed.complete) return { ok: false, error: { key: parsed.steps.length - parsed.entries.length === 1 ? "Enter {n} more rank-only draw." : "Enter {n} more rank-only draws.", vars: { n: parsed.steps.length - parsed.entries.length } }, notes, warnings, parsed };
  let mnemonic = [...parsed.wordSlots, parsed.finalWord].join(" ");
  if (!hodlIsValidMnemonic(mnemonic, hodlBip39Wordlist)) return { ok: false, error: { key: "The direct card sequence did not produce a valid BIP39 checksum." }, notes, warnings, parsed };
  let bytes = hodlMnemonicToEntropy(mnemonic, hodlBip39Wordlist);
  notes.push(hodlNote("{draws} independent rank-only card draws directly selected {partial} BIP39 words and 1 of {candidates} checksum-valid final words.", { draws: parsed.steps.length, partial: config.partialWords, candidates: config.candidates }));
  notes.push(hodlNote("Every draw is made after shuffling the indicated A–8, A–4, or A–2 card set; suits are ignored."));
  return { ok: true, bytes, hex: hodlHex.encode(bytes), bits: config.bits, sourceBits: config.bits, method: "cards-direct", notes, warnings, parsed, mnemonic };
}
function hodlDirectCardSetLabel(max) {
  return `A\u2013${max}`;
}
function hodlDirectCardStepStatus(parsed) {
  if (parsed.complete) return hodlTText("All {n} rank draws entered · checksum-valid {words}-word seed ready to derive", { n: parsed.steps.length, words: parsed.config.words });
  let position = Math.min(parsed.entries.length, parsed.steps.length - 1), max = parsed.steps[position], partialDraws = parsed.config.partialWords * 4;
  if (position < partialDraws) return hodlTText(position ? "Word {word} of {words} · draw {draw} of 4 from {set} after shuffling" : "Word {word} of {words} · draw {draw} of 4 from {set}", { word: Math.floor(position / 4) + 1, words: parsed.config.words, draw: position % 4 + 1, set: hodlDirectCardSetLabel(max) });
  return hodlTText("Final word · draw {draw} of {need} from {set} after shuffling", { draw: position - partialDraws + 1, need: hodlDirectCardFinalRadices(parsed.config.words).length, set: hodlDirectCardSetLabel(max) });
}
function hodlDirectCardInstruction(parsed) {
  if (parsed.complete) return "";
  return hodlT(parsed.entries.length ? "Shuffle {set} (any suit) before the next draw." : "Shuffle {set} (any suit) before the first draw.", { set: hodlDirectCardSetLabel(parsed.expectedMax) });
}
function hodlHashedCardInstruction(parsed) {
  let required = parsed.needed.first + parsed.needed.extra;
  if (parsed.cards.length >= required) return "";
  if (!parsed.cards.length) return hodlT("Shuffle a standard 52-card deck before the first draw.");
  if (parsed.needed.extra && parsed.cards.length === parsed.needed.first) return hodlT("Shuffle the full 52-card deck again before the next draw.");
  if (parsed.needed.extra && parsed.cards.length > parsed.needed.first) return hodlT("Deal the next card without replacement from the second shuffle.");
  return hodlT("Deal the next card without replacement from the shuffled deck.");
}
function hodlDealtDirectCardMarkup(rank) {
  return `<span class="dealt-card dealt-card-rank-only" title="${hodlT("Rank {rank}", { rank: hodlEscapeHtml(rank) })}"><span class="dealt-rank">${hodlEscapeHtml(rank)}</span></span>`;
}
function hodlUpdateDirectCards() {
  let input = document.getElementById("direct-cards");
  if (!input) return;
  let parsed = hodlParseDirectCards(input.value, hodlTargetWordCount), invalid = parsed.invalidRanges.length > 0, showCards = document.getElementById("show-cards")?.checked === true;
  input.classList.toggle("bad", invalid);
  input.setAttribute("aria-invalid", String(invalid));
  hodlRenderInputHighlight(input, parsed.invalidRanges);
  let dealt = document.getElementById("dealt-cards");
  if (dealt) {
    dealt.hidden = !showCards;
    dealt.innerHTML = parsed.ranks.length ? `<p class="dealt-shuffle-label">${hodlT("Rank-only draws · {have} of {need}", { have: parsed.ranks.length, need: parsed.steps.length })}</p>${parsed.ranks.map(hodlDealtDirectCardMarkup).join("")}` : `<p class="dealt-shuffle-label">${hodlT("Rank-only draws · No cards yet")}</p><span class="dealt-card dealt-card-placeholder" aria-hidden="true"></span>`;
  }
  let reshuffle = document.getElementById("cards-reshuffle");
  if (reshuffle) {
    let instruction = hodlDirectCardInstruction(parsed);
    reshuffle.hidden = !instruction;
    reshuffle.innerHTML = instruction ? `<strong>${instruction}</strong>` : "";
  }
  hodlRenderDiceWordGrid(document.getElementById("dice-words"), parsed.words, parsed.config.words, !parsed.complete);
  hodlRenderManualCalculations("cards-manual-calculations", "cards", input.value, parsed.config.words);
  let status = parsed.complete ? `${parsed.entries.length} of ${parsed.steps.length} rank draws entered \xB7 checksum-valid ${parsed.config.words}-word seed ready to derive` : `${parsed.entries.length} of ${parsed.steps.length} rank draws entered \xB7 ${hodlDirectCardStepStatus(parsed)}`;
  if (parsed.invalidEntries.length) status += ` \xB7 ${parsed.invalidEntries.length} invalid rank${parsed.invalidEntries.length === 1 ? "" : "s"} highlighted`;
  if (parsed.extraEntries.length) status += ` \xB7 ${parsed.extraEntries.length} extra card${parsed.extraEntries.length === 1 ? "" : "s"} highlighted`;
  let meta = hodlElement("#cards-meta");
  meta.textContent = status;
  meta.className = "muted" + (invalid ? " err" : parsed.complete ? " ok" : "");
  document.querySelectorAll("[data-direct-card-rank]").forEach((button) => {
    button.disabled = hodlDirectCardRankValue(button.dataset.directCardRank) >= parsed.expectedMax || parsed.complete;
  });
  let undo = document.getElementById("card-undo");
  if (undo) undo.disabled = !parsed.entries.length && !String(input.value || "").trim();
  hodlQueueMasterFingerprintPreview();
}
function hodlSelectedCardsEntropy(targetWords = hodlTargetWordCount) {
  let input = document.getElementById(hodlCardMethod === "direct" ? "direct-cards" : "cards");
  if (!input) return { ok: false, error: { key: "Card input is unavailable." } };
  return hodlCardMethod === "direct" ? hodlDirectCardsEntropy(input.value, targetWords) : hodlCardsEntropy(input.value, targetWords, hodlCardColemanSymbols);
}
function hodlUpdateCards() {
  let input = document.getElementById("cards");
  if (!input) return;
  let config = hodlSeedConfig(), parsed = hodlRenderCardInputState(input, config.words), required = parsed.needed.first + parsed.needed.extra, entropy = hodlCardsEntropy(input.value, config.words, hodlCardColemanSymbols), showCards = document.getElementById("show-cards")?.checked === true;
  let selection = hodlCardSelectionState(parsed.cards, parsed.needed, hodlCardSuit, hodlCardRank);
  hodlCardSuit = selection.suit;
  hodlCardRank = selection.rank;
  if (selection.card && !parsed.invalidRanges.length) {
    hodlCommitCardSelection(input, selection.card);
    return true;
  }
  let dealt = document.getElementById("dealt-cards");
  if (dealt) {
    dealt.hidden = !showCards;
    let firstTarget = parsed.needed.first, first = parsed.cards.slice(0, firstTarget), extra2 = parsed.cards.slice(firstTarget);
    if (!parsed.cards.length) dealt.innerHTML = `<p class="dealt-shuffle-label">${hodlT("First shuffle · No cards yet")}</p><span class="dealt-card dealt-card-placeholder" aria-hidden="true"></span>`;
    else dealt.innerHTML = `<p class="dealt-shuffle-label">${hodlT("First shuffle · {have} of {need}", { have: first.length, need: firstTarget })}</p>${first.map(hodlDealtCardMarkup).join("")}` + (config.words === 24 && first.length >= firstTarget ? `<p class="dealt-shuffle-label">${hodlT("Second shuffle · {have} of {need}", { have: extra2.length, need: parsed.needed.extra })}</p>${extra2.map(hodlDealtCardMarkup).join("")}` : "");
  }
  let reshuffle = document.getElementById("cards-reshuffle");
  if (reshuffle) {
    let instruction = hodlHashedCardInstruction(parsed);
    reshuffle.hidden = !instruction;
    reshuffle.innerHTML = instruction ? `<strong>${instruction}</strong>` : "";
  }
  let wordsBox = document.getElementById("dice-words"), preview = [];
  try {
    if (parsed.cards.length && !parsed.invalid.length && !parsed.duplicates.length && !parsed.pending) preview = hodlEntropyToMnemonic(hodlSha256(new TextEncoder().encode(hodlCardsHashInput(parsed.cards, hodlCardColemanSymbols))).slice(0, config.bytes), hodlBip39Wordlist).split(" ");
  } catch {
  }
  hodlRenderDiceWordGrid(wordsBox, preview, config.words, parsed.cards.length < required);
  let meta = hodlElement("#cards-meta"), missing = Math.max(0, required - parsed.cards.length), extra = Math.max(0, parsed.cards.length - required), status = !parsed.cards.length ? hodlT("0 of {need} recommended cards · 0.0 bits estimated · Hashed card transcript", { need: required }) : missing ? hodlT("{have} of {need} recommended cards · {bits} bits estimated · seed available for testing · {missing} more recommended", { have: parsed.cards.length, need: required, bits: parsed.bits.toFixed(1), missing }) : hodlT(parsed.cards.length === 1 ? "{n} card · {bits} bits estimated · ready to derive" : "{n} cards · {bits} bits estimated · ready to derive", { n: parsed.cards.length, bits: parsed.bits.toFixed(1) }) + (extra ? " \xB7 " + hodlT(extra === 1 ? "all {n} extra card is included" : "all {n} extra cards are included", { n: extra }) : "");
  if (config.words === 24 && parsed.cards.length >= 52 && missing) status += " \xB7 " + (parsed.cards.length === 52 ? hodlT("shuffle again, then deal 6 more") : hodlT("second shuffle {have} of 6", { have: parsed.cards.length - 52 }));
  if (parsed.pending) status += " \xB7 " + hodlT("finish {token} with a suit", { token: parsed.pending.token });
  if (parsed.invalidEntries.length - (parsed.pending ? 1 : 0) > 0) {
    let count = parsed.invalidEntries.length - (parsed.pending ? 1 : 0);
    status += " \xB7 " + hodlT(count === 1 ? "{n} invalid card highlighted · use AS, 10H, or TD" : "{n} invalid cards highlighted · use AS, 10H, or TD", { n: count });
  }
  if (parsed.duplicateEntries.length) status += " \xB7 " + hodlT("repeated {card} highlighted · deal a different card", { card: parsed.duplicateEntries[0].card });
  let invalid = parsed.invalidRanges.length > 0;
  meta.textContent = status;
  meta.className = "muted" + (invalid ? " err" : !missing && entropy.ok ? " ok" : "");
  document.querySelectorAll("[data-card-suit]").forEach((button) => {
    let suit = button.getAttribute("data-card-suit"), active = suit === hodlCardSuit, exhausted = !selection.availableSuits.includes(suit), incompatible = Boolean(hodlCardRank) && !selection.compatibleSuits.includes(suit), locked = Boolean(hodlCardSuit) && !active;
    button.classList.toggle("active", active);
    button.setAttribute("aria-pressed", String(active));
    button.disabled = exhausted || incompatible || locked;
    button.title = exhausted ? hodlTText("Every card in this suit has already been dealt in this shuffle.") : incompatible ? hodlTText("The {rank} of this suit has already been dealt.", { rank: hodlCardRank === "T" ? "10" : hodlCardRank }) : locked ? hodlTText("Finish the selected card using the rank row.") : active ? hodlTText("Suit selected. Click again to clear it, or choose an available rank.") : hodlTText("Select this suit first.");
  });
  document.querySelectorAll("[data-card-rank]").forEach((button) => {
    let rank = button.getAttribute("data-card-rank"), active = rank === hodlCardRank, exhausted = !selection.availableRanks.includes(rank), incompatible = Boolean(hodlCardSuit) && !selection.compatibleRanks.includes(rank), locked = Boolean(hodlCardRank) && !active;
    button.classList.toggle("active", active);
    button.setAttribute("aria-pressed", String(active));
    button.disabled = exhausted || incompatible || locked;
    button.title = exhausted ? hodlTText("Every {rank} has already been dealt in this shuffle.", { rank: rank === "T" ? "10" : rank }) : incompatible ? hodlTText("The {rank} of the selected suit has already been dealt.", { rank: rank === "T" ? "10" : rank }) : locked ? hodlTText("Finish the selected card using the suit row.") : active ? hodlTText("Rank selected. Click again to clear it, or choose an available suit.") : hodlTText("Select this rank first.");
  });
  let undo = document.getElementById("card-undo");
  if (undo) undo.disabled = !parsed.cards.length && !String(input.value || "").trim();
  hodlQueueMasterFingerprintPreview();
  return false;
}
function hodlSetInputValueAtEnd(input, value) {
  input.value = value;
  hodlPlaceCaret(input, input.value.length);
}
function hodlUndoCard() {
  let input = document.getElementById(hodlCardMethod === "direct" ? "direct-cards" : "cards");
  if (!input) return;
  hodlCardSuit = "";
  hodlCardRank = "";
  let value = hodlCardMethod === "direct" ? hodlFilterDirectCards(input.value.replace(/[^0-9A-Z]/gi, "").slice(0, -1), hodlTargetWordCount) : input.value.trim().split(/[\s,]+/).slice(0, -1).join(" ");
  hodlSetInputValueAtEnd(input, value);
  input.dispatchEvent(new Event("input"));
}
function hodlSeedCountStatus(count, targetWords = hodlTargetWordCount) {
  let config = hodlSeedConfig(targetWords), entered = Math.max(0, Number(count) || 0);
  return entered <= config.words ? hodlT("{entered} of {words} BIP39 words entered", { entered, words: config.words }) : hodlT("{entered} entered · {words} required BIP39 words", { entered, words: config.words });
}
function hodlValidateTargetMnemonic(value, targetWords = hodlTargetWordCount) {
  let words = hodlNormalizeMnemonicText(value).split(" ").filter(Boolean), config = hodlSeedConfig(targetWords);
  if (!words.length) return { ok: false, words, error: { key: "{entered} of {words} BIP39 words entered · {n} remaining", vars: { entered: 0, words: config.words, n: config.words } }, unknown: [] };
  if (words.length !== config.words) {
    let difference = config.words - words.length;
    return difference > 0 ? { ok: false, words, error: { key: "{entered} of {words} BIP39 words entered · {n} remaining", vars: { entered: words.length, words: config.words, n: difference } }, unknown: [] } : { ok: false, words, error: { key: difference === -1 ? "{entered} entered · {words} required BIP39 words · {n} extra word must be removed" : "{entered} entered · {words} required BIP39 words · {n} extra words must be removed", vars: { entered: words.length, words: config.words, n: -difference } }, unknown: [] };
  }
  let result = hodlValidateMnemonic(words.join(" "));
  if (result.ok) return result;
  if (result.unknown?.length) return { ...result, error: { key: "Word {n} (“{word}”) is not on the BIP39 English list.", vars: { n: result.unknown[0].index + 1, word: result.unknown[0].word } } };
  return { ...result, error: { key: "Words are on the list, but the checksum does not match. One of the words is wrong, or this is not a BIP39 phrase." } };
}
function hodlNormalizeSeedMethod(method) {
  return method === "numbers" ? "numbers" : "words";
}
function hodlFilterSeedNumbers(value, zeroIndexed = false) {
  let clean = String(value ?? "").replace(/[^0-9\s]/g, "").replace(/\s+/g, " ");
  if (zeroIndexed) return clean;
  return clean.replace(/(^| )0+(?=\d)/g, "$1").replace(/(^| )0(?= |$)/g, "$1").replace(/ {2,}/g, " ").replace(/^ /, "");
}
function hodlParseSeedNumbers(value, targetWords = hodlTargetWordCount, zeroIndexed = hodlSeedZeroIndexed) {
  let config = hodlSeedConfig(targetWords), text = String(value ?? ""), entries = [...text.matchAll(/\d+/g)].map((match, position) => {
    let number = Number(match[0]), index = zeroIndexed ? number : number - 1, valid = !/^0\d+/.test(match[0]) && Number.isSafeInteger(number) && index >= 0 && index < hodlBip39Wordlist.length;
    return { token: match[0], number, index, valid, position, start: match.index, end: match.index + match[0].length };
  }), invalidEntries = entries.filter((entry) => !entry.valid), extraEntries = entries.slice(config.words), wordSlots = entries.slice(0, config.words).map((entry) => entry.valid ? hodlBip39Wordlist[entry.index] : ""), phrase = wordSlots.length === config.words && wordSlots.every(Boolean) ? wordSlots.join(" ") : "", checksumInvalid = Boolean(phrase && !hodlIsValidMnemonic(phrase, hodlBip39Wordlist)), invalidRanges = [...invalidEntries, ...extraEntries].map((entry) => [entry.start, entry.end]);
  if (checksumInvalid && entries[config.words - 1]) invalidRanges.push([entries[config.words - 1].start, entries[config.words - 1].end]);
  return { entries, invalidEntries, extraEntries, invalidRanges, wordSlots, phrase, checksumInvalid, complete: Boolean(phrase && !checksumInvalid && !extraEntries.length), config, zeroIndexed: Boolean(zeroIndexed), minimum: zeroIndexed ? 0 : 1, maximum: zeroIndexed ? 2047 : 2048 };
}
function hodlSeedWordsToNumbers(value, zeroIndexed = hodlSeedZeroIndexed) {
  if (hodlLooksExtendedKey(value)) return "";
  let words = hodlNormalizeMnemonicText(value).split(" ").filter(Boolean), indices = words.map((word) => hodlBip39WordIndex.get(word));
  return words.length && indices.every((index) => Number.isInteger(index)) ? indices.map((index) => index + (zeroIndexed ? 0 : 1)).join(" ") : "";
}
function hodlSeedNumbersToWords(value, zeroIndexed = hodlSeedZeroIndexed, targetWords = hodlTargetWordCount) {
  let parsed = hodlParseSeedNumbers(value, targetWords, zeroIndexed);
  return parsed.entries.length && !parsed.invalidEntries.length && !parsed.extraEntries.length ? parsed.wordSlots.join(" ") : "";
}
function hodlTranslateSeedNumberIndex(value, toZeroIndexed) {
  let oldMinimum = toZeroIndexed ? 1 : 0, oldMaximum = toZeroIndexed ? 2048 : 2047;
  return String(value ?? "").replace(/\d+/g, (token) => {
    let number = Number(token);
    return Number.isSafeInteger(number) && number >= oldMinimum && number <= oldMaximum ? String(number + (toZeroIndexed ? -1 : 1)) : token;
  });
}
function hodlSelectedSeedInput(targetWords = hodlTargetWordCount) {
  if (hodlSeedMethod === "numbers") {
    let input = document.getElementById("seed-numbers"), parsed = hodlParseSeedNumbers(input?.value ?? "", targetWords, hodlSeedZeroIndexed);
    return { value: parsed.phrase, extended: false, parsed };
  }
  let value = document.getElementById("seed")?.value.trim() || "";
  return { value, extended: hodlLooksExtendedKey(value), parsed: null };
}
function hodlTargetLastWords(value, targetWords = hodlTargetWordCount) {
  let words = hodlNormalizeMnemonicText(value).split(" ").filter(Boolean), config = hodlSeedConfig(targetWords);
  if (words.length !== config.partialWords) return null;
  return hodlComputeTargetLastWords(words, config.words);
}
function hodlComputeTargetLastWords(words, targetWords = hodlTargetWordCount) {
  let config = hodlSeedConfig(targetWords), normalized = words.map((word) => String(word ?? "").toLowerCase()), invalid = normalized.find((word) => !hodlBip39WordSet.has(word));
  if (normalized.length !== config.partialWords) return null;
  if (invalid) return { partialCount: normalized.length, completeCount: config.words, candidates: [], error: `\u201C${invalid}\u201D is not on the BIP39 English list.` };
  let cacheKey = `${config.words}:${normalized.join(" ")}`, cached = hodlLastWordCache.get(cacheKey);
  if (cached) return cached;
  let prefixBits = normalized.map((word) => hodlBip39WordIndex.get(word).toString(2).padStart(11, "0")).join(""), checksumBits = config.bits / 32, missingEntropyBits = config.bits - prefixBits.length, candidates = [];
  for (let suffix = 0; suffix < 2 ** missingEntropyBits; suffix++) {
    let entropyBits = prefixBits + suffix.toString(2).padStart(missingEntropyBits, "0"), bytes = new Uint8Array(config.bytes);
    for (let index = 0; index < bytes.length; index++) bytes[index] = Number.parseInt(entropyBits.slice(index * 8, index * 8 + 8), 2);
    let checksum = hodlSha256(bytes)[0] >> 8 - checksumBits, wordIndex = suffix * 2 ** checksumBits + checksum;
    candidates.push(hodlBip39Wordlist[wordIndex]);
  }
  let result = { partialCount: normalized.length, completeCount: config.words, candidates };
  if (hodlLastWordCache.size >= 32) hodlLastWordCache.delete(hodlLastWordCache.keys().next().value);
  hodlLastWordCache.set(cacheKey, result);
  return result;
}
function hodlSeedFinalWordContext(value, targetWords = hodlTargetWordCount) {
  let config = hodlSeedConfig(targetWords), tokens = [...String(value ?? "").matchAll(/\S+/g)].map((match) => ({ word: match[0].toLowerCase(), start: match.index, end: match.index + match[0].length }));
  if (tokens.length < config.partialWords || tokens.length > config.words) return null;
  let baseTokens = tokens.slice(0, config.partialWords);
  if (baseTokens.some((token) => !hodlBip39WordSet.has(token.word))) return null;
  let result = hodlComputeTargetLastWords(baseTokens.map((token) => token.word), config.words);
  if (!result || result.error || result.completeCount !== config.words) return null;
  let finalToken = tokens[config.partialWords] ?? null, prefix = finalToken?.word ?? "", matchingCandidates = prefix ? result.candidates.filter((word) => word.startsWith(prefix)) : result.candidates.slice();
  return { baseWords: baseTokens.map((token) => token.word), candidates: result.candidates, finalToken, prefix, matchingCandidates, selected: result.candidates.includes(prefix) ? prefix : "", targetWords: config.words };
}
function hodlAnalyzeSeedInput(input, targetWords = hodlTargetWordCount) {
  let value = input.value, config = hodlSeedConfig(targetWords);
  if (hodlLooksExtendedKey(value)) return { tokens: [], invalidRanges: [], invalidWords: [], excessCount: 0, checksumInvalid: false, extendedKey: true, finalContext: null };
  let tokens = [...value.matchAll(/\S+/g)].map((match) => ({ word: match[0].toLowerCase(), start: match.index, end: match.index + match[0].length })), invalidRanges = [], invalidWords = [], excessCount = 0, lastIndex = tokens.length - 1, last = tokens[lastIndex], activePrefix = Boolean(last && document.activeElement === input && !/\s$/.test(value) && input.selectionStart === input.selectionEnd && input.selectionStart === last.end);
  let finalContext = hodlSeedFinalWordContext(value, config.words);
  tokens.forEach((token, index) => {
    let listed = hodlBip39WordSet.has(token.word), options = index === config.partialWords && finalContext ? finalContext.candidates : hodlBip39Wordlist, viablePrefix = activePrefix && index === lastIndex && token.word.length > 0 && options.some((word) => word.startsWith(token.word));
    if (index >= config.words) {
      invalidRanges.push([token.start, token.end]);
      excessCount += 1;
    } else if (!listed && !viablePrefix) {
      invalidRanges.push([token.start, token.end]);
      invalidWords.push({ index, word: token.word });
    }
  });
  let checksumInvalid = false, allListed = tokens.length === config.words && tokens.every((token) => hodlBip39WordSet.has(token.word)), finalCanContinue = Boolean(activePrefix && finalContext?.prefix && finalContext.matchingCandidates.some((word) => word !== finalContext.prefix));
  if (allListed && !hodlIsValidMnemonic(tokens.map((token) => token.word).join(" "), hodlBip39Wordlist) && !finalCanContinue) {
    checksumInvalid = true;
    let final = tokens[tokens.length - 1];
    invalidRanges.push([final.start, final.end]);
  }
  return { tokens, invalidRanges, invalidWords, excessCount, checksumInvalid, extendedKey: false, finalContext };
}
function hodlRenderSeedInputState(input, targetWords = hodlTargetWordCount) {
  let analysis = hodlAnalyzeSeedInput(input, targetWords);
  input.setAttribute("aria-invalid", String(analysis.invalidRanges.length > 0));
  hodlRenderInputHighlight(input, analysis.invalidRanges);
  return analysis;
}
function hodlPassphraseBip39Enabled() {
  let toggle = document.getElementById("passphrase-bip39-words");
  if (toggle) return toggle.checked;
  return Boolean(hodlKeys[hodlActiveKey]?.passphraseBip39Words);
}
function hodlPassphraseAutocompleteEnabled() {
  let toggle = document.getElementById("passphrase-autocomplete");
  if (toggle) return toggle.checked;
  return hodlKeys[hodlActiveKey]?.passphraseAutocomplete !== false;
}
function hodlAnalyzeBip39Passphrase(value, activeCaret = null) {
  value = String(value ?? "");
  let tokens = [...value.matchAll(/\S+/g)].map((match) => ({
    word: match[0],
    start: match.index,
    end: match.index + match[0].length
  })), invalidRanges = [], incomplete = false, completeWords = 0;
  tokens.forEach((token, index) => {
    let listed = hodlBip39WordSet.has(token.word), active = activeCaret !== null && token.start < activeCaret && activeCaret <= token.end,
      prefix = active && /^[a-z]+$/.test(token.word) && hodlBip39Wordlist.some((word) => word.startsWith(token.word));
    if (listed) completeWords += 1;
    else if (prefix) incomplete = true;
    else invalidRanges.push([token.start, token.end]);
    let gapStart = index ? tokens[index - 1].end : 0, gap = value.slice(gapStart, token.start);
    if (gap && (index === 0 || gap !== " ")) invalidRanges.push([gapStart, token.start]);
  });
  let suffixStart = tokens.at(-1)?.end ?? 0, suffix = value.slice(suffixStart), trailingSeparator = suffix === " ";
  if (suffix && !(tokens.length && suffix === " " && completeWords === tokens.length)) invalidRanges.push([suffixStart, value.length]);
  return { tokens, invalidRanges, incomplete, completeWords, trailingSeparator };
}
function hodlRenderPassphraseInputState(input, enabled = hodlPassphraseBip39Enabled()) {
  if (!input) return null;
  let caret = enabled && document.activeElement === input ? input.selectionStart ?? input.value.length : null,
    analysis = enabled ? hodlAnalyzeBip39Passphrase(input.value, caret) : { tokens: [], invalidRanges: [], incomplete: false, completeWords: 0 },
    invalid = enabled && analysis.invalidRanges.length > 0, status = document.getElementById("passphrase-bip39-status");
  input.classList.toggle("bad", invalid);
  input.setAttribute("aria-invalid", String(invalid));
  input.setAttribute("autocapitalize", enabled ? "off" : "sentences");
  hodlRenderInputHighlight(input, analysis.invalidRanges);
  if (status) {
    status.hidden = !enabled;
    if (enabled) {
      if (invalid) {
        status.textContent = hodlTText(analysis.invalidRanges.length === 1 ? "{n} passphrase inconsistency highlighted · use complete lowercase English BIP39 words separated by single spaces" : "{n} passphrase inconsistencies highlighted · use complete lowercase English BIP39 words separated by single spaces", { n: analysis.invalidRanges.length });
        status.className = "muted passphrase-bip39-status err";
      } else if (analysis.incomplete) {
        status.textContent = hodlTText(analysis.completeWords === 1 ? "{n} complete BIP39 word · finish the current word" : "{n} complete BIP39 words · finish the current word", { n: analysis.completeWords });
        status.className = "muted passphrase-bip39-status";
      } else if (analysis.trailingSeparator) {
        status.textContent = hodlTText(analysis.completeWords === 1 ? "{n} complete BIP39 word · start the next word or remove the final space" : "{n} complete BIP39 words · start the next word or remove the final space", { n: analysis.completeWords });
        status.className = "muted passphrase-bip39-status";
      } else if (input.value) {
        status.textContent = hodlTText(analysis.completeWords === 1 ? "{n} lowercase BIP39 passphrase word entered" : "{n} lowercase BIP39 passphrase words entered", { n: analysis.completeWords });
        status.className = "muted passphrase-bip39-status ok";
      } else {
        status.textContent = hodlTText("Use complete lowercase English BIP39 words separated by single spaces.");
        status.className = "muted passphrase-bip39-status";
      }
    }
  }
  return analysis;
}
function hodlRenderSeedNumberInputState(input, targetWords = hodlTargetWordCount, zeroIndexed = hodlSeedZeroIndexed) {
  let parsed = hodlParseSeedNumbers(input?.value ?? "", targetWords, zeroIndexed), invalid = parsed.invalidRanges.length > 0;
  input.classList.toggle("bad", invalid);
  input.setAttribute("aria-invalid", String(invalid));
  hodlRenderInputHighlight(input, parsed.invalidRanges);
  return parsed;
}
function hodlApplyFilteredInput(input, filter) {
  let value = input.value, clean = filter(value);
  if (clean === value) return false;
  let start = input.selectionStart ?? value.length, end = input.selectionEnd ?? start, direction = input.selectionDirection || "none";
  input.value = clean;
  input.setSelectionRange(filter(value.slice(0, start)).length, filter(value.slice(0, end)).length, direction);
  return true;
}
function hodlAutocompleteSeedInput(input, event, completeExisting = false, wholeWordlist = false, enabledOverride = null) {
  let toggle = document.getElementById("seed-autocomplete"),
    enabled = enabledOverride ?? (toggle ? toggle.checked : Boolean(hodlKeys[hodlActiveKey]?.seedAutocomplete));
  if (!enabled || !completeExisting && (event?.inputType !== "insertText" || event.isComposing) || input.selectionStart !== input.selectionEnd) return false;
  let caret = input.selectionStart ?? input.value.length, suffix = input.value.slice(caret);
  if (suffix && !/^\s/.test(suffix)) return false;
  let match = input.value.slice(0, caret).match(/([A-Za-z]+)$/);
  if (!match) return false;
  let prefix = match[1].toLowerCase(), start = caret - match[1].length, finalContext = wholeWordlist ? null : hodlSeedFinalWordContext(input.value, hodlTargetWordCount), isFinalPrefix = Boolean(finalContext?.finalToken && finalContext.finalToken.start === start && finalContext.finalToken.end === caret), options = isFinalPrefix ? finalContext.candidates : hodlBip39Wordlist, minimumLength = isFinalPrefix ? 1 : 2;
  if (prefix.length < minimumLength) return false;
  let matches = options.filter((word) => word.startsWith(prefix));
  if (matches.length !== 1) return false;
  let replacement = matches[0] + (suffix ? "" : " ");
  input.setRangeText(replacement, start, caret, "end");
  return true;
}
function hodlAutocompletePassphraseInput(input, event, completeExisting = false) {
  return hodlPassphraseBip39Enabled() && hodlAutocompleteSeedInput(input, event, completeExisting, true, hodlPassphraseAutocompleteEnabled());
}
function hodlKeyboardToggleMarkup(id, label, controls = "seed-keyboard") {
  return `<button type="button" class="seed-keyboard-toggle" id="${id}" data-on-screen-keyboard-toggle aria-label="${hodlOnScreenKeyboardOpen ? `Hide ${label}` : `Show ${label}`}" aria-controls="${controls}" aria-expanded="${hodlOnScreenKeyboardOpen}"><svg viewBox="0 0 64 44" aria-hidden="true" focusable="false"><rect class="seed-keyboard-icon-case" x="3" y="6" width="58" height="32" rx="4"/><g class="seed-keyboard-icon-keys"><rect x="9" y="10" width="4" height="5" rx=".5"/><rect x="15" y="10" width="4" height="5" rx=".5"/><rect x="21" y="10" width="4" height="5" rx=".5"/><rect x="27" y="10" width="4" height="5" rx=".5"/><rect x="33" y="10" width="4" height="5" rx=".5"/><rect x="39" y="10" width="4" height="5" rx=".5"/><rect x="45" y="10" width="4" height="5" rx=".5"/><rect x="51" y="10" width="4" height="5" rx=".5"/><rect x="12" y="18" width="4" height="5" rx=".5"/><rect x="18" y="18" width="4" height="5" rx=".5"/><rect x="24" y="18" width="4" height="5" rx=".5"/><rect x="30" y="18" width="4" height="5" rx=".5"/><rect x="36" y="18" width="4" height="5" rx=".5"/><rect x="42" y="18" width="4" height="5" rx=".5"/><rect x="48" y="18" width="4" height="5" rx=".5"/><rect x="17" y="28" width="30" height="5" rx=".75"/></g></svg></button>`;
}
function hodlSeedKeyboardToggleMarkup() {
  return hodlKeyboardToggleMarkup("seed-keyboard-toggle", "on-screen seed keyboard");
}
function hodlPassphraseKeyboardToggleMarkup() {
  return hodlKeyboardToggleMarkup("passphrase-keyboard-toggle", "on-screen passphrase keyboard", "passphrase-keyboard");
}
function hodlPassphraseBip39ToggleMarkup(checked = hodlPassphraseBip39Enabled()) {
  let autocomplete = hodlPassphraseAutocompleteEnabled();
  return `<div class="passphrase-bip39-options"><label class="seed-autocomplete-toggle passphrase-bip39-toggle"><input type="checkbox" id="passphrase-bip39-words" ${checked ? "checked" : ""} /><span><strong>Build passphrase from BIP39 words</strong> <span class="seed-autocomplete-note">(lowercase words separated by single spaces)</span></span></label><label class="seed-autocomplete-toggle passphrase-autocomplete-toggle" id="passphrase-autocomplete-control"${checked ? "" : " hidden"}><input type="checkbox" id="passphrase-autocomplete" ${autocomplete ? "checked" : ""} /><span><strong>Autocomplete BIP39 words</strong></span></label></div>`;
}
function hodlBrainWalletTrimEnabled() {
  return Boolean(document.getElementById("brain-wallet-trim")?.checked);
}
function hodlBrainWalletTrimToggleMarkup(checked = Boolean(hodlKeys[hodlActiveKey]?.brainWalletTrim)) {
  return `<label class="seed-autocomplete-toggle brain-wallet-trim-toggle" data-brain-wallet-trim-control hidden><input type="checkbox" id="brain-wallet-trim" ${checked ? "checked" : ""} /><span><strong>Trim leading and trailing whitespace</strong></span></label>`;
}
function hodlPrivateKeyKeyboardToggleMarkup() {
  return `<div class="passphrase-keyboard-tools">${hodlKeyboardToggleMarkup("private-keyboard-toggle", "on-screen private key keyboard", "private-keyboard")}${hodlBrainWalletTrimToggleMarkup()}</div>`;
}
function hodlBase64KeyboardToggleMarkup() {
  return hodlKeyboardToggleMarkup("base64-keyboard-toggle", "on-screen Base64 keyboard", "base64-keyboard");
}
var hodlSeedKeyboardLayouts = { lower: ["abcdefghij", "klmnopqrs", "tuvwxyz"], upper: ["ABCDEFGHIJ", "KLMNOPQRS", "TUVWXYZ"], number: ["1234567890", "!@#$%^&*()", "-_+=/?\\"] };
function hodlKeyboardMarkup(passphraseOnly = false, inputName = passphraseOnly ? "passphrase" : "seed phrase", keyboardId = "seed-keyboard", privateInitialOptions = false) {
  let letters = hodlSeedKeyboardLayouts.lower.map((row, index) => `<div class="seed-keyboard-row" data-seed-keyboard-row="${index + 1}">${Array.from({ length: hodlSeedKeyboardLayouts.number[index].length }, (_, keyIndex) => {
    let letter = row[keyIndex];
    return `<button type="button" class="seed-keyboard-key" data-seed-character-key${letter ? ` data-seed-key="${letter}" aria-label="Enter ${letter}"` : ` hidden disabled aria-hidden="true"`}>${letter || ""}</button>`;
  }).join("")}${index === 2 ? `<button type="button" class="seed-keyboard-key seed-keyboard-delete" data-seed-delete aria-label="Delete previous character"><svg viewBox="0 0 24 18" aria-hidden="true" focusable="false"><path d="M9 2h11a2 2 0 0 1 2 2v10a2 2 0 0 1-2 2H9L2 9l7-7Z"/><path d="m12 6 6 6m0-6-6 6"/></svg></button>` : ""}</div>`).join("");
  let initialOptions = privateInitialOptions ? `<div class="seed-keyboard-initial-row" data-private-key-initial-row aria-label="Valid first characters" hidden>${Array.from({ length: 3 }, () => `<button type="button" class="seed-keyboard-key" data-seed-character-key data-private-key-initial disabled hidden></button>`).join("")}</div>` : "";
  let hexKeypad = privateInitialOptions ? `<div class="private-key-hex-keypad" data-private-key-hex-keypad aria-label="Hexadecimal keypad" hidden><div class="private-key-hex-row" aria-label="Hexadecimal numbers">${[..."0123456789"].map((character) => `<button type="button" class="seed-keyboard-key" data-seed-character-key data-private-key-hex-character data-seed-key="${character}" aria-label="Enter ${character}">${character}</button>`).join("")}</div><div class="private-key-hex-row" aria-label="Hexadecimal letters">${[..."abcdef"].map((character) => `<button type="button" class="seed-keyboard-key" data-seed-character-key data-private-key-hex-character data-seed-key="${character}" aria-label="Enter ${character}">${character}</button>`).join("")}<button type="button" class="seed-keyboard-key seed-keyboard-delete" data-seed-delete data-private-key-hex-delete aria-label="Delete previous character"><svg viewBox="0 0 24 18" aria-hidden="true" focusable="false"><path d="M9 2h11a2 2 0 0 1 2 2v10a2 2 0 0 1-2 2H9L2 9l7-7Z"/><path d="m12 6 6 6m0-6-6 6"/></svg></button></div></div>` : "";
  return `<div class="seed-keyboard" id="${keyboardId}" data-on-screen-keyboard role="group" aria-label="On-screen lowercase ${inputName} keyboard" data-seed-keyboard-layout="lower"${hodlOnScreenKeyboardOpen ? "" : " hidden"}>${initialOptions}${letters}${hexKeypad}<div class="seed-keyboard-space-row"><button type="button" class="seed-keyboard-mode" data-seed-keyboard-mode="lower" aria-label="${passphraseOnly ? `Change ${inputName} character mode` : "Character mode switching is available for the passphrase"}"${passphraseOnly ? "" : " disabled"}>aA1</button><button type="button" class="seed-keyboard-space" data-seed-key=" " aria-label="Enter space">space</button></div></div>`;
}
function hodlSeedKeyboardMarkup() {
  return hodlKeyboardMarkup(false);
}
function hodlPassphraseKeyboardMarkup() {
  return hodlKeyboardMarkup(true, "passphrase", "passphrase-keyboard");
}
function hodlPrivateKeyKeyboardMarkup() {
  return hodlKeyboardMarkup(true, "private key", "private-keyboard", true);
}
function hodlBase64KeyboardMarkup() {
  return hodlKeyboardMarkup(true, "Base64 entropy", "base64-keyboard");
}
function hodlSetOnScreenKeyboardOpen(open) {
  hodlOnScreenKeyboardOpen = Boolean(open);
  document.querySelectorAll("[data-on-screen-keyboard-toggle]").forEach((toggle) => {
    toggle.setAttribute("aria-expanded", String(hodlOnScreenKeyboardOpen));
    let target = toggle.id === "passphrase-keyboard-toggle" ? "passphrase" : toggle.id === "private-keyboard-toggle" ? "private key" : toggle.id === "base64-keyboard-toggle" ? "Base64" : "seed";
    toggle.setAttribute("aria-label", `${hodlOnScreenKeyboardOpen ? "Hide" : "Show"} on-screen ${target} keyboard`);
  });
  document.querySelectorAll("[data-on-screen-keyboard]").forEach((keyboard) => {
    keyboard.hidden = !hodlOnScreenKeyboardOpen;
  });
}
function hodlSetSeedKeyboardLayout(keyboard, button, next) {
  if (!keyboard || !button || !hodlSeedKeyboardLayouts[next]) return;
  let layout = hodlSeedKeyboardLayouts[next];
  keyboard.querySelectorAll("[data-seed-keyboard-row]").forEach((row, index) => {
    let keys = row.querySelectorAll("[data-seed-character-key]"), characters = [...layout[index]];
    keys.forEach((key, keyIndex) => {
      let character = characters[keyIndex];
      key.hidden = !character;
      if (character) {
        key.dataset.seedKey = character;
        key.textContent = character;
        key.setAttribute("aria-label", `Enter ${character}`);
        key.removeAttribute("aria-hidden");
      } else {
        delete key.dataset.seedKey;
        key.textContent = "";
        key.disabled = true;
        key.removeAttribute("aria-label");
        key.setAttribute("aria-hidden", "true");
      }
    });
  });
  button.dataset.seedKeyboardMode = next;
  keyboard.dataset.seedKeyboardLayout = next;
  keyboard.setAttribute("aria-label", next === "lower" ? "On-screen lowercase seed phrase keyboard" : next === "upper" ? "On-screen uppercase keyboard" : "On-screen number and symbol keyboard");
}
function hodlCycleSeedKeyboardLayout(keyboard, button) {
  if (!keyboard || !button) return;
  let order = ["lower", "upper", "number"], current = button.dataset.seedKeyboardMode || "lower", next = order[(order.indexOf(current) + 1) % order.length];
  hodlSetSeedKeyboardLayout(keyboard, button, next);
}
function hodlSeedKeyboardCanEnterCharacter(input, key, targetWords = hodlTargetWordCount) {
  let character = String(key ?? "").toLowerCase();
  if (!/^[a-z]$/.test(character)) return false;
  let start = input.selectionStart ?? input.value.length, end = input.selectionEnd ?? start, value = input.value.slice(0, start) + character + input.value.slice(end), caret = start + character.length, config = hodlSeedConfig(targetWords);
  if (hodlLooksExtendedKey(value)) return false;
  let tokens = [...value.matchAll(/\S+/g)].map((match) => ({ word: match[0].toLowerCase(), start: match.index, end: match.index + match[0].length }));
  if (tokens.length > config.words) return false;
  let tokenIndex = tokens.findIndex((token2) => token2.start < caret && caret <= token2.end);
  if (tokenIndex < 0 || tokenIndex >= config.words || tokens.slice(0, tokenIndex).some((token2) => !hodlBip39WordSet.has(token2.word))) return false;
  let token = tokens[tokenIndex], options = hodlBip39Wordlist;
  if (tokenIndex === config.partialWords) {
    let context = hodlSeedFinalWordContext(value, config.words);
    if (!context) return false;
    options = context.candidates;
  }
  return options.some((word) => word.startsWith(token.word));
}
function hodlSeedKeyboardCanEnterSpace(input, targetWords = hodlTargetWordCount) {
  let start = input.selectionStart ?? input.value.length, end = input.selectionEnd ?? start, config = hodlSeedConfig(targetWords);
  if (start !== end || end !== input.value.length || !end || /\s$/.test(input.value)) return false;
  let words = input.value.trim().toLowerCase().split(/\s+/).filter(Boolean);
  return words.length < config.words && words.every((word) => hodlBip39WordSet.has(word));
}
function hodlUpdateSeedKeyboardKeys(input, targetWords = hodlTargetWordCount) {
  let keyboard = document.getElementById("seed-keyboard");
  if (!keyboard || !input) return;
  keyboard.querySelectorAll("[data-seed-character-key]").forEach((button) => {
    button.disabled = !hodlSeedKeyboardCanEnterCharacter(input, button.dataset.seedKey, targetWords);
  });
  let space = keyboard.querySelector(".seed-keyboard-space");
  if (space) space.disabled = !hodlSeedKeyboardCanEnterSpace(input, targetWords);
  let remove = keyboard.querySelector("[data-seed-delete]"), start = input.selectionStart ?? input.value.length, end = input.selectionEnd ?? start;
  if (remove) remove.disabled = start === end && start === 0;
}
function hodlPassphraseBip39CanEnterCharacter(input, key) {
  let character = String(key ?? "");
  if (!/^[a-z]$/.test(character)) return false;
  let start = input.selectionStart ?? input.value.length, end = input.selectionEnd ?? start,
    value = input.value.slice(0, start) + character + input.value.slice(end), caret = start + 1,
    analysis = hodlAnalyzeBip39Passphrase(value, caret);
  return analysis.invalidRanges.length === 0;
}
function hodlPassphraseBip39CanEnterSpace(input) {
  let start = input.selectionStart ?? input.value.length, end = input.selectionEnd ?? start,
    value = input.value.slice(0, start) + " " + input.value.slice(end), analysis = hodlAnalyzeBip39Passphrase(value);
  return analysis.invalidRanges.length === 0 && analysis.tokens.length > 0 && analysis.completeWords === analysis.tokens.length;
}
function hodlUpdatePassphraseKeyboardKeys(input, keyboardId = "passphrase-keyboard") {
  let keyboard = document.getElementById(keyboardId);
  if (!keyboard || !input) return;
  let constrained = hodlPassphraseBip39Enabled(), modeButton = keyboard.querySelector("[data-seed-keyboard-mode]");
  if (constrained && modeButton && keyboard.dataset.seedKeyboardLayout !== "lower") hodlSetSeedKeyboardLayout(keyboard, modeButton, "lower");
  if (modeButton) {
    modeButton.disabled = constrained;
    modeButton.setAttribute("aria-label", constrained ? "Character mode switching is unavailable while building a passphrase from BIP39 words" : "Change passphrase character mode");
  }
  keyboard.querySelectorAll("[data-seed-character-key]").forEach((button) => {
    button.disabled = constrained ? !hodlPassphraseBip39CanEnterCharacter(input, button.dataset.seedKey) : false;
  });
  let space = keyboard.querySelector(".seed-keyboard-space");
  if (space) space.disabled = constrained ? !hodlPassphraseBip39CanEnterSpace(input) : false;
  let remove = keyboard.querySelector("[data-seed-delete]"), start = input.selectionStart ?? input.value.length, end = input.selectionEnd ?? start;
  if (remove) remove.disabled = start === end && start === 0;
  hodlRenderPassphraseInputState(input, constrained);
}
function hodlUpdateBase64KeyboardKeys(input) {
  let keyboard = document.getElementById("base64-keyboard");
  if (!keyboard || !input) return;
  let analysis = hodlAnalyzeEntropyInput(input.value, "base64", hodlTargetWordCount), definition = analysis.meta;
  keyboard.querySelectorAll("[data-seed-character-key]").forEach((button) => {
    let character = button.dataset.seedKey || "", remainder = definition.remainderBits && analysis.count >= definition.fullDigits, invalid = !definition.alphabet.includes(character) || analysis.count >= definition.digits || remainder && !definition.finalCharacters.includes(character);
    button.disabled = invalid;
  });
  let space = keyboard.querySelector(".seed-keyboard-space");
  if (space) space.disabled = !input.value || /\s$/.test(input.value) || analysis.count >= definition.digits;
  let remove = keyboard.querySelector("[data-seed-delete]"), start = input.selectionStart ?? input.value.length, end = input.selectionEnd ?? start;
  if (remove) remove.disabled = start === end && start === 0;
}
function hodlKeyboardValueAfterInsert(input, key) {
  let start = input.selectionStart ?? input.value.length, end = input.selectionEnd ?? start;
  return input.value.slice(0, start) + String(key ?? "") + input.value.slice(end);
}
function hodlHexPrivateKeyPrefix(value) {
  let candidate = String(value ?? ""), prefixed = /^0[xX]/.test(candidate), body = prefixed ? candidate.slice(2) : candidate;
  if (!prefixed && /[xX]/.test(candidate) || !/^[0-9a-fA-F]*$/.test(body) || body.length > 64) return false;
  if (body.length < 64) return true;
  try {
    hodlAssertPrivateKey(hodlHex.decode(body.toLowerCase()));
    return true;
  } catch {
    return false;
  }
}
function hodlWifPrivateKeyPrefix(value, network) {
  let candidate = String(value ?? ""), first = candidate[0] || "", prefixes = network === "testnet" ? ["9", "c"] : ["5", "K", "L"];
  if (!prefixes.includes(first) || !/^[1-9A-HJ-NP-Za-km-z]+$/.test(candidate)) return false;
  let expected = first === "5" || first === "9" ? 51 : 52;
  if (candidate.length > expected) return false;
  if (candidate.length < expected) return true;
  try {
    let decoded = hodlDecodeWif(candidate);
    return decoded.network === network && Boolean(decoded.priv);
  } catch {
    return false;
  }
}
function hodlMiniPrivateKeyPrefix(value) {
  let candidate = String(value ?? "");
  if (candidate.length > 30 || !/^S[1-9A-HJ-NP-Za-km-z]*$/.test(candidate)) return false;
  if (candidate.length < 30) return true;
  return hodlIsMiniKey(candidate);
}
function hodlDetectPrivateKeyKind(value) {
  let candidate = String(value ?? "").trim(), compact = candidate.replace(/\s/g, "").replace(/^0x/i, "");
  if (/^S(?:[1-9A-HJ-NP-Za-km-z]{21}|[1-9A-HJ-NP-Za-km-z]{29})$/.test(candidate)) return "minikey";
  if (/^[5KL9c][1-9A-HJ-NP-Za-km-z]{50,51}$/.test(candidate)) return "wif";
  if (/^[0-9a-fA-F]{64}$/.test(compact)) return "hex-key";
  return null;
}
function hodlNormalizePrivateKeyKind(kind, value = "") {
  if (["wif", "hex-key", "minikey", "brain"].includes(kind)) return kind;
  if (kind === "wif-or-hex") return hodlDetectPrivateKeyKind(value) === "hex-key" ? "hex-key" : "wif";
  return "wif";
}
function hodlPrivateKeyPlaceholder(kind, network = "mainnet") {
  if (kind === "hex-key") return hodlTText("64 hexadecimal characters");
  if (kind === "minikey") return hodlTText("S… (22 or 30 Base58 characters)");
  if (kind === "brain") return hodlTText("Text to hash");
  return network === "testnet" ? hodlT("9… / c…") : hodlT("5… / K… / L…");
}
function hodlBrainWalletText(value, trim = hodlBrainWalletTrimEnabled()) {
  try {
    return hodlBrainWalletPassphrase(value, trim);
  } catch {
    return "";
  }
}
function hodlBrainAcked(output) {
  return Boolean(hodlBrainLabAck[output || hodlBrainWalletOutput()]);
}
function hodlBrainHdActive() {
  if (hodlKeyMode !== "key") return false;
  let input = document.getElementById("key");
  if (!input) return false;
  return hodlNormalizePrivateKeyKind(document.querySelector('input[name="kk"]:checked')?.value, input.value) === "brain" && hodlBrainWalletOutput() === "hd";
}
function hodlBrainWalletOutput() {
  return document.querySelector('input[name="bo"]:checked')?.value === "hd" ? "hd" : "scalar";
}
// The same SHA-256 digest can be used two ways, and they are different wallets:
// as the private-key scalar, or as 256-bit BIP39 entropy for a 24-word seed.
// Both live under Brain wallet so the choice is explicit rather than a separate
// place to land in by accident.
function hodlBrainOutputMarkup(output = "scalar", acked = hodlBrainAcked(output)) {
  let hd = output === "hd";
  return `<div class="brain-output" id="brain-output" hidden>
    <p class="label">Brain wallet output</p>
    <div class="choice-grid">
      <label class="choice"><input type="radio" name="bo" value="scalar" ${hd ? "" : "checked"} /><span><strong>Single key pair</strong><span class="desc">The digest is the private key. One address, the original brain-wallet behaviour.</span></span></label>
      <label class="choice"><input type="radio" name="bo" value="hd" ${hd ? "checked" : ""} /><span><strong>HD wallet with seed phrase</strong><span class="desc">The digest is 256-bit BIP39 entropy for a 24-word seed. Not the same wallet as the single key pair.</span></span></label>
    </div>
    <div class="wallet-result-messages" id="brain-warning" role="alert">
      <h3>Brain wallet warning — read before use</h3>
      <ul>
        <li class="is-warning">SHA-256(text) is unsalted and fast. Guessable phrases are stolen coins.</li>
        <li class="is-warning">Strength is the entropy of this text, nothing more.</li>
        <li class="is-warning">This is not a BIP39 passphrase.</li>
        <li class="is-warning">This is not a Bitcoin Core hdseed or address-key backup of the same wallet.</li>
        <li class="is-warning" data-brain-hd-warning ${hd ? "" : "hidden"}>The 24-word count is not the strength; the text is.</li>
        <li class="is-warning" data-brain-hd-warning ${hd ? "" : "hidden"}>A valid mnemonic does not mean it is the same wallet as hashing the text as a private-key scalar.</li>
      </ul>
    </div>
    <label class="choice"><input type="checkbox" id="brain-lab-ack" ${acked ? "checked" : ""} /><span><strong>I understand</strong><span class="desc">Required once this session, in page memory only.</span></span></label>
    <div id="brain-lab-zone" ${hd ? "" : "hidden"}>
      <p class="muted" id="brain-lab-help">UTF-8 text is hashed with SHA-256. The 32-byte digest is BIP39 entropy for a 24-word seed. Nothing is derived until you press Derive Key.</p>
      <p class="muted" id="brain-lab-hex" aria-live="polite">SHA-256 hex appears here. 24 words appear only after Derive Key.</p>
    </div>
  </div>`;
}
function hodlSyncBrainOutput() {
  let zone = document.getElementById("brain-output"), input = document.getElementById("key");
  if (!zone || !input) return;
  let kind = hodlNormalizePrivateKeyKind(document.querySelector('input[name="kk"]:checked')?.value, input.value),
    brain = kind === "brain", output = hodlBrainWalletOutput(), lab = document.getElementById("brain-lab-zone");
  zone.hidden = !brain;
  // Nothing to type into until the warning is acknowledged.
  let entry = document.getElementById("private-key-entry"), acked = hodlBrainAcked(output), ackBox = document.getElementById("brain-lab-ack");
  // The checkbox shows the acknowledgement for the selected output, not the other.
  if (ackBox) ackBox.checked = acked;
  if (entry) entry.hidden = brain && !acked;
  if (lab) lab.hidden = output !== "hd" || !acked;
  zone.querySelectorAll("[data-brain-hd-warning]").forEach((item) => {
    item.hidden = output !== "hd";
  });
  let trimControl = document.querySelector("[data-brain-wallet-trim-control]");
  if (trimControl) trimControl.hidden = !brain;
  let hex = document.getElementById("brain-lab-hex");
  if (!hex || !brain || output !== "hd") return;
  if (!acked) {
    hex.textContent = hodlTText("Acknowledge the lab warning, then enter text. {derive} is still required.", { derive: hodlTText("Derive Key") });
    hex.className = "muted";
    return;
  }
  if (!input.value.length) {
    hex.textContent = hodlTText("SHA-256 hex appears here. 24 words appear only after {derive}.", { derive: hodlTText("Derive Key") });
    hex.className = "muted";
    return;
  }
  let entropy = hodlBrainLabEntropy(hodlBrainWalletText(input.value));
  hex.textContent = entropy.ok ? hodlTText("SHA-256 {hex} · 24 words appear only after {derive}.", { hex: entropy.hex, derive: hodlTText("Derive Key") }) : hodlFormatNote(entropy.error);
  hex.className = "muted" + (entropy.ok ? " ok" : " err");
}
function hodlUpdatePrivateKeyInputPresentation() {
  let input = document.getElementById("key");
  if (!input) return;
  let kind = hodlNormalizePrivateKeyKind(document.querySelector('input[name="kk"]:checked')?.value, input.value), network = hodlSelectedNetwork(document.getElementById("network"));
  hodlSyncBrainOutput();
  input.placeholder = hodlPrivateKeyPlaceholder(kind, network);
  input.setAttribute("inputmode", kind === "hex-key" ? "text" : "text");
  input.setAttribute("autocapitalize", "off");
  input.setAttribute("autocomplete", "off");
  input.setAttribute("spellcheck", "false");
}
function hodlPrivateKeyboardCanEnterCharacter(input, key) {
  let candidate = hodlKeyboardValueAfterInsert(input, key), kind = hodlNormalizePrivateKeyKind(document.querySelector('input[name="kk"]:checked')?.value, input.value);
  if (kind === "brain") return true;
  if (kind === "minikey") return hodlMiniPrivateKeyPrefix(candidate);
  if (kind === "hex-key") return hodlHexPrivateKeyPrefix(candidate);
  return hodlWifPrivateKeyPrefix(candidate, hodlSelectedNetwork(document.getElementById("network")));
}
function hodlPrivateKeyInitialCharacters(kind, network) {
  if (kind === "wif") return network === "testnet" ? ["9", "c"] : ["5", "K", "L"];
  if (kind === "minikey") return ["S"];
  return [];
}
function hodlUpdatePrivateKeyInitialKeys(keyboard, input, kind, network) {
  let row = keyboard.querySelector("[data-private-key-initial-row]");
  if (!row) return false;
  let options = input.value.length ? [] : hodlPrivateKeyInitialCharacters(kind, network), show = options.length > 0, wasShowing = keyboard.classList.contains("private-key-initial-options"), modeButton = keyboard.querySelector("[data-seed-keyboard-mode]");
  if (!show && wasShowing && input.value && modeButton) {
    let first = input.value[0], layout = /^[A-Z]$/.test(first) ? "upper" : /^[0-9]$/.test(first) ? "number" : "lower";
    if (modeButton.dataset.seedKeyboardMode !== layout) hodlSetSeedKeyboardLayout(keyboard, modeButton, layout);
  }
  row.hidden = !show;
  keyboard.classList.toggle("private-key-initial-options", show);
  keyboard.querySelectorAll("[data-seed-keyboard-row],.seed-keyboard-space-row").forEach((section) => {
    section.hidden = show;
  });
  row.querySelectorAll("[data-private-key-initial]").forEach((button, index) => {
    let character = options[index] || "";
    button.hidden = !character;
    button.disabled = !character;
    if (character) {
      button.setAttribute("data-seed-character-key", "");
      button.dataset.seedKey = character;
      button.textContent = character;
      button.setAttribute("aria-label", `Enter ${character}`);
      button.removeAttribute("aria-hidden");
    } else {
      button.removeAttribute("data-seed-character-key");
      delete button.dataset.seedKey;
      button.textContent = "";
      button.removeAttribute("aria-label");
      button.setAttribute("aria-hidden", "true");
    }
  });
  if (show) keyboard.setAttribute("aria-label", `Choose the first ${kind === "wif" ? "WIF" : "Mini key"} character`);
  return show;
}
function hodlUpdatePrivateKeyKeyboardKeys(input, keyboardId = "private-keyboard") {
  let keyboard = document.getElementById(keyboardId);
  if (!keyboard || !input) return;
  let kind = hodlNormalizePrivateKeyKind(document.querySelector('input[name="kk"]:checked')?.value, input.value), network = hodlSelectedNetwork(document.getElementById("network")), initialOnly = hodlUpdatePrivateKeyInitialKeys(keyboard, input, kind, network);
  let hexKeypad = keyboard.querySelector("[data-private-key-hex-keypad]"), hexOnly = kind === "hex-key";
  if (hexKeypad) hexKeypad.hidden = !hexOnly;
  keyboard.classList.toggle("private-key-hex-options", hexOnly);
  if (hexOnly) keyboard.querySelectorAll("[data-seed-keyboard-row],.seed-keyboard-space-row").forEach((section) => {
    section.hidden = true;
  });
  else if (!initialOnly) keyboard.querySelectorAll("[data-seed-keyboard-row],.seed-keyboard-space-row").forEach((section) => {
    section.hidden = false;
  });
  keyboard.querySelectorAll("[data-seed-keyboard-row] [data-seed-character-key],[data-private-key-hex-character]").forEach((button) => {
    button.disabled = !hodlPrivateKeyboardCanEnterCharacter(input, button.dataset.seedKey);
  });
  let space = keyboard.querySelector(".seed-keyboard-space");
  if (space) space.disabled = kind !== "brain";
  let start = input.selectionStart ?? input.value.length, end = input.selectionEnd ?? start;
  keyboard.querySelectorAll("[data-seed-delete]").forEach((remove) => {
    remove.disabled = start === end && start === 0;
  });
  if (hexOnly) keyboard.setAttribute("aria-label", "On-screen hexadecimal private key keyboard");
  else if (!initialOnly) keyboard.setAttribute("aria-label", `On-screen ${keyboard.dataset.seedKeyboardLayout || "lower"} private key keyboard`);
}
function hodlApplySeedKeyboardKey(input, key, deleteBackward = false) {
  if (!input) return;
  let start = input.selectionStart ?? input.value.length, end = input.selectionEnd ?? start, inputType = "insertText", data = key;
  if (deleteBackward) {
    inputType = "deleteContentBackward";
    data = null;
    if (start === end && start > 0) start -= 1;
    input.setRangeText("", start, end, "end");
  } else input.setRangeText(String(key ?? ""), start, end, "end");
  let event = typeof InputEvent === "function" ? new InputEvent("input", { bubbles: true, inputType, data }) : new Event("input", { bubbles: true });
  input.dispatchEvent(event);
}
function hodlApplySeedNumberPadKey(input, key, deleteBackward = false) {
  if (!input) return;
  if (deleteBackward && input.selectionStart === input.selectionEnd) {
    let caret = input.selectionStart ?? input.value.length;
    if (caret > 1 && input.value[caret - 1] === " ") {
      input.setSelectionRange(caret - 2, caret - 1);
    }
  }
  hodlApplySeedKeyboardKey(input, key, deleteBackward);
}
function hodlSeedNumberCanInsertDigit(input, digit, zeroIndexed = hodlSeedZeroIndexed) {
  if (!input || !/^\d$/.test(String(digit))) return false;
  if (zeroIndexed || String(digit) !== "0") return true;
  let start = input.selectionStart ?? input.value.length;
  return !/(?:^|\s)$/.test(input.value.slice(0, start));
}
function hodlAutocompleteSeedNumberInput(input, event, targetWords = hodlTargetWordCount, zeroIndexed = hodlSeedZeroIndexed) {
  if (!input || event?.inputType !== "insertText" || !/^\d+$/.test(event.data || "") || input.selectionStart !== input.selectionEnd) return false;
  let caret = input.selectionStart ?? input.value.length, suffix = input.value.slice(caret);
  if (suffix && /^\s/.test(suffix) || /^\d/.test(suffix)) return false;
  let match = input.value.slice(0, caret).match(/(\d+)$/);
  if (!match) return false;
  let number = Number(match[1]), maximum = zeroIndexed ? 2047 : 2048, priorCount = (input.value.slice(0, caret - match[1].length).match(/\d+/g) || []).length;
  if (number <= 204 || number > maximum || priorCount >= hodlSeedConfig(targetWords).words - 1) return false;
  input.setRangeText(" ", caret, caret, "end");
  return true;
}
function hodlHandleSeedNumberSeparatorDelete(input, event) {
  if (input.selectionStart !== input.selectionEnd) return;
  let caret = input.selectionStart ?? 0, start = caret, end = caret;
  if (event.inputType === "deleteContentBackward" && caret > 1 && input.value[caret - 1] === " ") {
    start = caret - 2;
    end = caret - 1;
  } else if (event.inputType === "deleteContentForward" && input.value[caret] === " " && caret + 1 < input.value.length) {
    start = caret + 1;
    end = caret + 2;
  } else return;
  event.preventDefault();
  input.setRangeText("", start, end, "end");
  input.dispatchEvent(new InputEvent("input", { bubbles: true, inputType: event.inputType }));
}
function hodlUpdateSeedNumberPad(input, parsed = hodlParseSeedNumbers(input?.value ?? "", hodlTargetWordCount, hodlSeedZeroIndexed)) {
  let pad = document.querySelector(".seed-number-pad"), start = input?.selectionStart ?? 0, end = input?.selectionEnd ?? start;
  if (!pad || !input) return;
  let deleteButton = pad.querySelector("[data-seed-number-delete]"), nextButton = pad.querySelector("[data-seed-number-space]"), last = parsed.entries.at(-1), canFinishWord = Boolean(last?.valid && parsed.entries.length < parsed.config.words && !/\s$/.test(input.value));
  if (deleteButton) deleteButton.disabled = start === end && start === 0;
  if (nextButton) nextButton.disabled = !canFinishWord;
  pad.querySelectorAll("[data-seed-number-digit]").forEach((button) => {
    button.disabled = parsed.entries.length >= parsed.config.words && /\s$/.test(input.value) || !hodlSeedNumberCanInsertDigit(input, button.dataset.seedNumberDigit || "", hodlSeedZeroIndexed);
  });
}
function hodlBindSeedNumberPad(input, update) {
  let pad = document.querySelector(".seed-number-pad");
  if (!pad || !input) return;
  hodlBindKeypadPointer(pad.querySelectorAll("button"), () => input);
  pad.querySelectorAll("[data-seed-number-digit]").forEach((button) => {
    button.onclick = () => {
      let digit = button.dataset.seedNumberDigit || "";
      if (hodlSeedNumberCanInsertDigit(input, digit, hodlSeedZeroIndexed)) hodlApplySeedNumberPadKey(input, digit);
    };
  });
  let next = pad.querySelector("[data-seed-number-space]");
  if (next) next.onclick = () => hodlApplySeedNumberPadKey(input, " ");
  let remove = pad.querySelector("[data-seed-number-delete]");
  if (remove) hodlBindSeedKeyboardDelete(() => input, remove, hodlApplySeedNumberPadKey);
  ["focus", "click", "keyup", "select"].forEach((type) => input.addEventListener(type, () => {
    let parsed = update();
    hodlUpdateSeedNumberPad(input, parsed);
  }));
}
function hodlBindSeedKeyboardDelete(getInput, button, applyDelete = hodlApplySeedKeyboardKey) {
  if (typeof getInput !== "function" || !button) return;
  let holdTimer = null, repeatTimer = null, repeated = false, pointerId = null;
  let stop = () => {
    if (holdTimer !== null) {
      clearTimeout(holdTimer);
      holdTimer = null;
    }
    if (repeatTimer !== null) {
      clearInterval(repeatTimer);
      repeatTimer = null;
    }
    let captured = pointerId;
    pointerId = null;
    try {
      if (captured !== null && button.hasPointerCapture?.(captured)) button.releasePointerCapture(captured);
    } catch {
    }
  };
  let remove = () => {
    let input = getInput();
    if (!input || button.disabled) {
      stop();
      return;
    }
    applyDelete(input, "", true);
  };
  button.addEventListener("pointerdown", (event) => {
    if (event.button !== 0 || button.disabled) return;
    stop();
    repeated = false;
    pointerId = event.pointerId;
    try {
      button.setPointerCapture?.(event.pointerId);
    } catch {
    }
    holdTimer = setTimeout(() => {
      holdTimer = null;
      repeated = true;
      remove();
      if (!button.disabled) repeatTimer = setInterval(remove, 69);
    }, 420);
  });
  ["pointerup", "pointercancel", "pointerleave", "lostpointercapture"].forEach((type) => button.addEventListener(type, stop));
  button.addEventListener("click", (event) => {
    if (repeated) {
      event.preventDefault();
      repeated = false;
      return;
    }
    remove();
  });
}
function hodlBindSeedKeyboard(input, targetWords = hodlTargetWordCount) {
  let toggle = document.getElementById("seed-keyboard-toggle"), keyboard = document.getElementById("seed-keyboard"), modeButton = keyboard?.querySelector("[data-seed-keyboard-mode]"), passphrase = document.getElementById("pass");
  if (!toggle || !keyboard || !input) return;
  let activeInput = input, passphraseField = () => document.getElementById("pass") || passphrase, isPassphrase = () => {
    let field = passphraseField();
    return Boolean(field && activeInput === field);
  }, refresh = () => {
    if (isPassphrase()) hodlUpdatePassphraseKeyboardKeys(activeInput, "seed-keyboard");
    else hodlUpdateSeedKeyboardKeys(input, targetWords);
  };
  let activate = (target) => {
    activeInput = target;
    let pass = isPassphrase();
    if (modeButton) {
      if (!pass && modeButton.dataset.seedKeyboardMode !== "lower") hodlSetSeedKeyboardLayout(keyboard, modeButton, "lower");
      modeButton.disabled = !pass;
      modeButton.setAttribute("aria-label", pass ? "Change passphrase character mode" : "Character mode switching is available for the passphrase");
    }
    keyboard.setAttribute("aria-label", pass ? `On-screen ${keyboard.dataset.seedKeyboardLayout || "lower"} passphrase keyboard` : "On-screen lowercase seed phrase keyboard");
    refresh();
  };
  toggle.onclick = () => {
    hodlSetOnScreenKeyboardOpen(!hodlOnScreenKeyboardOpen);
    refresh();
  };
  hodlBindKeypadPointer(keyboard.querySelectorAll("button"), () => activeInput);
  keyboard.querySelectorAll("[data-seed-character-key],.seed-keyboard-space").forEach((button) => {
    button.onclick = () => hodlApplySeedKeyboardKey(activeInput, button.dataset.seedKey || "");
  });
  keyboard.querySelectorAll("[data-seed-delete]").forEach((button) => hodlBindSeedKeyboardDelete(() => activeInput, button));
  if (modeButton) modeButton.onclick = () => {
    hodlCycleSeedKeyboardLayout(keyboard, modeButton);
    keyboard.setAttribute("aria-label", `On-screen ${keyboard.dataset.seedKeyboardLayout} passphrase keyboard`);
    refresh();
  };
  input.onfocus = () => activate(input);
  // Delegated so the passphrase field is found whenever it renders, and stored on
  // the keyboard so re-binding replaces the handler rather than stacking another.
  // Typing and clicking retarget as well as focus, because a headless browser
  // does not always deliver focus events to a document that is not foremost.
  let activityEvents = ["focusin", "input", "click", "keyup", "select"];
  if (keyboard.hodlKeyboardActivity) activityEvents.forEach((type) => document.removeEventListener(type, keyboard.hodlKeyboardActivity));
  keyboard.hodlKeyboardActivity = (event) => {
    let field = passphraseField();
    if (field && event.target === field) activate(field);
    else if (event.target === input) activate(input);
  };
  activityEvents.forEach((type) => document.addEventListener(type, keyboard.hodlKeyboardActivity));
  activate(input);
}
function hodlBindPassphraseKeyboard(inputId = "pass", toggleId = "passphrase-keyboard-toggle", inputName = "passphrase", keyboardId = "passphrase-keyboard") {
  let toggle = document.getElementById(toggleId), keyboard = document.getElementById(keyboardId), input = document.getElementById(inputId), modeButton = keyboard?.querySelector("[data-seed-keyboard-mode]");
  if (!toggle || !keyboard || !input) return;
  let privateKey = inputId === "key", activeInput = input,
    // Resolved on demand: the passphrase field is not always in the document
    // when this binds, and it is only a target while it is actually shown.
    passphraseTarget = () => {
      let field = document.getElementById("passphrase-field"), element = document.getElementById("pass");
      return privateKey && element && field && !field.hidden ? element : null;
    },
    onPassphrase = () => {
      let target = passphraseTarget();
      return Boolean(target) && activeInput === target;
    },
    refresh = () => onPassphrase() ? hodlUpdatePassphraseKeyboardKeys(activeInput, keyboardId) : privateKey ? hodlUpdatePrivateKeyKeyboardKeys(input, keyboardId) : hodlUpdatePassphraseKeyboardKeys(input, keyboardId);
  toggle.onclick = () => {
    hodlSetOnScreenKeyboardOpen(!hodlOnScreenKeyboardOpen);
    refresh();
  };
  hodlBindKeypadPointer(keyboard.querySelectorAll("button"), () => activeInput);
  keyboard.querySelectorAll("[data-seed-character-key],.seed-keyboard-space").forEach((button) => {
    button.onclick = () => hodlApplySeedKeyboardKey(activeInput, button.dataset.seedKey || "");
  });
  keyboard.querySelectorAll("[data-seed-delete]").forEach((button) => hodlBindSeedKeyboardDelete(() => activeInput, button));
  if (modeButton) {
    modeButton.disabled = false;
    modeButton.onclick = () => {
      hodlCycleSeedKeyboardLayout(keyboard, modeButton);
      keyboard.setAttribute("aria-label", `On-screen ${keyboard.dataset.seedKeyboardLayout} ${inputName} keyboard`);
      refresh();
    };
  }
  ["input", "focus", "blur", "click", "keyup", "select"].forEach((type) => input.addEventListener(type, () => {
    activeInput = input;
    refresh();
  }));
  if (privateKey) {
    document.querySelectorAll('input[name="kk"]').forEach((radio) => radio.addEventListener("change", refresh));
    document.getElementById("network")?.addEventListener("change", refresh);
    // Delegated so a passphrase field that renders later is still picked up, and
    // stored on the keyboard so re-binding replaces the handler.
    let events = ["focusin", "input", "click", "keyup", "select"];
    if (keyboard.hodlKeyboardActivity) events.forEach((type) => document.removeEventListener(type, keyboard.hodlKeyboardActivity));
    keyboard.hodlKeyboardActivity = (event) => {
      let target = passphraseTarget();
      if (target && event.target === target) activeInput = target;
      else if (event.target === input) activeInput = input;
      else return;
      // Announce the field it is actually typing into.
      keyboard.setAttribute("aria-label", `On-screen ${keyboard.dataset.seedKeyboardLayout || "lower"} ${onPassphrase() ? "passphrase" : inputName} keyboard`);
      refresh();
    };
    events.forEach((type) => document.addEventListener(type, keyboard.hodlKeyboardActivity));
  }
  refresh();
}
function hodlBindPassphraseOptions(keyboardId = "passphrase-keyboard") {
  let input = document.getElementById("pass"), bip39Toggle = document.getElementById("passphrase-bip39-words"), autocompleteToggle = document.getElementById("passphrase-autocomplete"), autocompleteControl = document.getElementById("passphrase-autocomplete-control"), keyboard = document.getElementById(keyboardId), modeButton = keyboard?.querySelector("[data-seed-keyboard-mode]");
  if (!input || !bip39Toggle || !autocompleteToggle || !autocompleteControl) return;
  let refresh = () => {
    autocompleteControl.hidden = !bip39Toggle.checked;
    hodlRenderPassphraseInputState(input, bip39Toggle.checked);
    hodlUpdatePassphraseKeyboardKeys(input, keyboardId);
  };
  bip39Toggle.onchange = () => {
    let state = hodlKeys[hodlActiveKey];
    if (state) state.passphraseBip39Words = bip39Toggle.checked;
    if (bip39Toggle.checked && modeButton) hodlSetSeedKeyboardLayout(keyboard, modeButton, "lower");
    refresh();
    hodlSyncKeyClearButton();
    hodlSyncDeriveButton();
  };
  autocompleteToggle.onchange = () => {
    let state = hodlKeys[hodlActiveKey];
    if (state) state.passphraseAutocomplete = autocompleteToggle.checked;
    if (autocompleteToggle.checked && hodlAutocompletePassphraseInput(input, null, true)) input.dispatchEvent(new InputEvent("input", { bubbles: true, inputType: "insertReplacementText" }));
    refresh();
    hodlSyncKeyClearButton();
  };
  refresh();
}
function hodlBindBase64Keyboard(input) {
  let toggle = document.getElementById("base64-keyboard-toggle"), keyboard = document.getElementById("base64-keyboard"), modeButton = keyboard?.querySelector("[data-seed-keyboard-mode]");
  if (!toggle || !keyboard || !input) return;
  let refresh = () => hodlUpdateBase64KeyboardKeys(input);
  toggle.onclick = () => {
    hodlSetOnScreenKeyboardOpen(!hodlOnScreenKeyboardOpen);
    refresh();
  };
  hodlBindKeypadPointer(keyboard.querySelectorAll("button"), () => input);
  keyboard.querySelectorAll("[data-seed-character-key],.seed-keyboard-space").forEach((button) => {
    button.onclick = () => hodlApplySeedKeyboardKey(input, button.dataset.seedKey || "");
  });
  keyboard.querySelectorAll("[data-seed-delete]").forEach((button) => hodlBindSeedKeyboardDelete(() => input, button));
  if (modeButton) {
    modeButton.disabled = false;
    modeButton.onclick = () => {
      hodlCycleSeedKeyboardLayout(keyboard, modeButton);
      keyboard.setAttribute("aria-label", `On-screen ${keyboard.dataset.seedKeyboardLayout} Base64 entropy keyboard`);
      refresh();
    };
  }
  ;
  ["input", "focus", "click", "keyup", "select"].forEach((type) => input.addEventListener(type, refresh));
  refresh();
}
function hodlRenderPassphraseKeyboard() {
  let host = document.getElementById(hodlKeyMode === "key" ? "private-keyboard-host" : "passphrase-keyboard-host"), toggleHost = document.getElementById("passphrase-keyboard-toggle-host"),
    keyMode = hodlKeyMode === "key", hdBrain = hodlBrainHdActive(),
    // The HD brain output needs the passphrase controls, but its keyboard is
    // still the private-key one, which now follows focus into the passphrase.
    privateKey = keyMode, passphrase = !keyMode || hdBrain;
  // One on-screen keyboard per section: the seed keyboard already serves both
  // fields, and in key mode the private-key keyboard does, so neither case adds
  // a second keyboard or a second toggle.
  let shared = passphrase && Boolean(document.getElementById("seed-keyboard")),
    ownToggle = passphrase && !shared && !hdBrain,
    enabled = !shared;
  if (toggleHost) {
    toggleHost.hidden = !passphrase;
    toggleHost.innerHTML = passphrase ? (ownToggle ? hodlPassphraseKeyboardToggleMarkup() : "") + hodlPassphraseBip39ToggleMarkup() : "";
  }
  if (!host) return;
  host.hidden = !enabled;
  host.innerHTML = enabled ? privateKey ? hodlPrivateKeyKeyboardMarkup() : hodlPassphraseKeyboardMarkup() : "";
  if (enabled) hodlBindPassphraseKeyboard(privateKey ? "key" : "pass", privateKey ? "private-keyboard-toggle" : "passphrase-keyboard-toggle", privateKey ? "private key" : "passphrase", privateKey ? "private-keyboard" : "passphrase-keyboard");
  else hodlRenderPassphraseInputState(document.getElementById("pass"));
  if (passphrase) hodlBindPassphraseOptions(shared ? "seed-keyboard" : "passphrase-keyboard");
}
function hodlReplaceSeedFinalWord(input, context, word) {
  if (!input || !context) return;
  input.value = [...context.baseWords, ...word ? [word] : []].join(" ");
  input.setSelectionRange(input.value.length, input.value.length);
  input.dispatchEvent(new InputEvent("input", { bubbles: true, inputType: "insertReplacementText", data: word || null }));
}
function hodlBitBoxRolls(value, targetWords = hodlTargetWordCount) {
  let config = hodlSeedConfig(targetWords), words = [], skippedHigh = 0, leftover = "", extraAfter = 0, diceInWord = [], notes = [], warnings = [];
  for (let character of value) {
    if (/\s|,|;|\|/.test(character)) continue;
    let input = character.toLowerCase(), isDie = input >= "1" && input <= "6";
    if (!isDie) {
      leftover += character;
      continue;
    }
    if (words.length >= config.partialWords) {
      extraAfter += 1;
      continue;
    }
    if (diceInWord.length < 5) {
      let face = Number(input);
      if (face >= 5) {
        skippedHigh += 1;
        continue;
      }
      diceInWord.push(face);
      continue;
    }
    // The sixth roll is the coin: 1-3 is Heads, 4-6 is Tails (BitBox lookup
    // table columns: "1 2 3 heads" is the +0 column, "4 5 6 tails" is +1).
    let coin = input === "1" || input === "2" || input === "3" ? 0 : 1;
    words.push(hodlBitBoxLookupWord(diceInWord, coin));
    diceInWord = [];
  }
  let waiting = words.length >= config.partialWords ? "last-word" : diceInWord.length === 5 ? "coin" : "dice", bits = words.length * 11;
  notes.push(hodlNote("BitBox diceware: {have} of {need} lookup-table words ({bits} encoded bits). Then choose the final checksum word.", { have: words.length, need: config.partialWords, bits }));
  if (skippedHigh) notes.push(hodlNote(skippedHigh === 1 ? "Skipped {n} face of 5 or 6 on the first five dice of a word (reroll)." : "Skipped {n} faces of 5 or 6 on the first five dice of a word (reroll).", { n: skippedHigh }));
  if (extraAfter) warnings.push(hodlNote("Extra rolls after the final lookup-table word are ignored. The checksum word is a separate pick, not another roll."));
  if (leftover.length) warnings.push(hodlNote("Ignored characters: {chars}", { chars: JSON.stringify(leftover.slice(0, 24)) }));
  return { words, targetWords: config.words, neededPartial: config.partialWords, skippedHigh, leftover, extraAfter, waiting, diceInWord: diceInWord.length, bits, notes, warnings };
}
function hodlDicePreviewWords(value, method, targetWords = hodlTargetWordCount) {
  let config = hodlSeedConfig(targetWords);
  if (method === "dplus") {
    let parsed2 = hodlDPlusRolls(value, targetWords);
    return [...parsed2.wordSlots, ...parsed2.finalWord ? [parsed2.finalWord] : []];
  }
  let parsed = hodlSplitDiceString(value), analysis = hodlAnalyzeDiceInput(value, method, targetWords);
  if (parsed.leftover.length || analysis.coinDerivedCount || !parsed.rolls.length) return [];
  let bytes;
  if (method === "coldcard") bytes = hodlSha256(new TextEncoder().encode(parsed.rolls.join(""))).slice(0, config.bytes);
  else if (method === "coleman") bytes = hodlSha256(new TextEncoder().encode(hodlIanColemanDiceString(parsed.rolls))).slice(0, config.bytes);
  else return [];
  try {
    return hodlEntropyToMnemonic(bytes, hodlBip39Wordlist).split(" ");
  } catch {
    return [];
  }
}
function hodlNumberBasePreviewWords(value, format, targetWords = hodlTargetWordCount) {
  let config = hodlSeedConfig(targetWords), analysis = hodlAnalyzeEntropyInput(value, format, config.words);
  if (!analysis.count || analysis.invalidCharacterCount || analysis.finalInvalid) return [];
  let bits = hodlNumberBaseBits(value, format, config.words).slice(0, config.bits);
  if (analysis.ready) {
    let bytes = new Uint8Array(config.bytes);
    for (let index = 0; index < bytes.length; index++) bytes[index] = Number.parseInt(bits.slice(index * 8, index * 8 + 8), 2);
    try {
      return hodlEntropyToMnemonic(bytes, hodlBip39Wordlist).split(" ");
    } catch {
      return [];
    }
  }
  let words = [], completeGroups = Math.min(config.partialWords, Math.floor(bits.length / 11));
  for (let index = 0; index < completeGroups; index++) words.push(hodlBip39Wordlist[Number.parseInt(bits.slice(index * 11, index * 11 + 11), 2)]);
  return words;
}
function hodlBinaryPreviewWords(value, targetWords = hodlTargetWordCount) {
  return hodlNumberBasePreviewWords(value, "bin", targetWords);
}
function hodlNumberBaseCalculationRows(value, format, targetWords = hodlTargetWordCount) {
  let bits = hodlNumberBaseBits(value, format, targetWords), words = hodlNumberBasePreviewWords(value, format, targetWords), groups = bits.match(/.{11}/g) || [];
  if (words.length > groups.length) {
    let finalIndex = hodlBip39Wordlist.indexOf(words[groups.length]);
    if (finalIndex >= 0) groups.push(finalIndex.toString(2).padStart(11, "0"));
  }
  return groups.map((group, index) => {
    let terms = Array.from(group, (bit, bitIndex) => ({ bit, place: 2 ** (10 - bitIndex), value: bit === "1" ? 2 ** (10 - bitIndex) : 0 }));
    return { number: index + 1, terms, index: Number.parseInt(group, 2), word: words[index] || "" };
  });
}
function hodlBinaryCalculationRows(value, targetWords = hodlTargetWordCount) {
  return hodlNumberBaseCalculationRows(value, "bin", targetWords);
}
function hodlNumberBaseBinaryConversionMarkup(value, meta) {
  if (meta.id === "bin") return "";
  let values = [...meta.alphabet].map((character, index) => `<span class="number-base-conversion-cell"><strong>${character}</strong><b>→</b><span>${index.toString(2).padStart(meta.bitsPerDigit, "0")}</span></span>`).join("");
  return `<div class="number-base-binary-conversion"><p class="label">${meta.shortLabel} digit values</p><p class="muted">Each ${meta.shortLabel} digit uses the binary value shown below before the 11-bit BIP39 calculations.</p><div class="number-base-conversion-list">${values}</div></div>`;
}
function hodlManualCalculationMarkup(method, value, targetWords = hodlTargetWordCount) {
  let config = hodlSeedConfig(targetWords), cards = method === "cards" ? hodlParseDirectCards(value, targetWords) : null, dplus = method === "dplus" ? hodlDPlusRolls(value, targetWords) : null, rows = [];
  if (cards) cards.wordSlots.forEach((word, index) => {
    let group = cards.values.slice(index * 4, index * 4 + 4);
    if (group.length === 4 && group.every((entry) => entry !== null)) {
      let indexValue = (((group[0] * 8) + group[1]) * 8 + group[2]) * 4 + group[3], stages = [{ label: "Draw 1", face: cards.ranks[index * 4], value: group[0], multiplier: 256 }, { label: "Draw 2", face: cards.ranks[index * 4 + 1], value: group[1], multiplier: 32 }, { label: "Draw 3", face: cards.ranks[index * 4 + 2], value: group[2], multiplier: 4 }, { label: "Draw 4", face: cards.ranks[index * 4 + 3], value: group[3], multiplier: 1 }];
      rows.push({ number: index + 1, values: group, stages, formula: `(((${group[0]} × 8 + ${group[1]}) × 8 + ${group[2]}) × 4 + ${group[3]})`, index: indexValue, word });
    }
  });
  if (dplus) dplus.groups.forEach((group, index) => {
    if (!group.valid) return;
    let values = [Number(group.faces[0]) - 1, hodlDPlusD16Value(group.faces[1]), hodlDPlusD16Value(group.faces[2])], stages = [{ label: "D8", face: group.faces[0], value: values[0], multiplier: 256 }, { label: "D16", face: group.faces[1], value: values[1], multiplier: 16 }, { label: "D16", face: group.faces[2], value: values[2], multiplier: 1 }], indexValue = values[0] * 256 + values[1] * 16 + values[2];
    rows.push({ number: index + 1, values: group.faces, stages, formula: `${values[0]} × 256 + ${values[1]} × 16 + ${values[2]}`, index: indexValue, word: group.word });
  });
  if (method === "bitbox") {
    let faces = [...String(value)].filter((face) => /^[1-6]$/.test(face)), position = 0;
    for (let number = 1; number <= config.partialWords; number++) {
      let dice = [];
      while (dice.length < 5 && position < faces.length) {
        let face = Number(faces[position++]);
        if (face <= 4) dice.push(face - 1);
      }
      if (dice.length < 5 || position >= faces.length) break;
      let coinFace = faces[position++], coin = Number(coinFace) <= 3 ? 0 : 1, indexValue = dice.reduce((total, value) => total * 4 + value, 0) * 2 + coin, stages = dice.map((value, index) => ({ label: `Die ${index + 1}`, face: value + 1, value, multiplier: [512, 128, 32, 8, 2][index] }));
      stages.push({ label: "Coin bit", face: coinFace, value: coin, multiplier: 1 });
      rows.push({ number, values: [...dice, coin], stages, formula: `(((((${dice[0]} × 4 + ${dice[1]}) × 4 + ${dice[2]}) × 4 + ${dice[3]}) × 4 + ${dice[4]}) × 2 + ${coin}`, index: indexValue, word: hodlBip39Wordlist[indexValue] });
    }
  }
  if (!rows.length) return "";
  let title = method === "cards" ? "Direct card calculations" : method === "dplus" ? "D++ calculations" : "BitBox diceware calculations", note = method === "cards" ? "Ranks are mapped to zero-based values (A=0 through 8=7), then combined with radices 8, 8, 8, and 4." : method === "dplus" ? "D8 contributes 8 values and each hexadecimal D16 contributes 16 values, giving 8 × 16 × 16 = 2048 possible indices." : "Each D4 contributes one base-4 value and the final die contributes the coin bit, giving 4⁵ × 2 = 2048 possible indices.";
  return `<div class="manual-calculation-panel"><p class="label">${title}</p><p class="muted">${note}</p><div class="manual-calculation-list">${rows.map((row) => method === "dplus" || method === "cards" || method === "bitbox" ? `<div class="manual-calculation-row dplus-calculation-row"><div class="manual-calculation-heading"><span>Word ${row.number}</span><strong>${row.word || "incomplete"}</strong></div><div class="dplus-calculation-stages">${row.stages.map((stage) => `<div class="dplus-calculation-stage"><span>${stage.label}</span><strong>${stage.face}</strong><small>&rarr; ${stage.value} &times; ${stage.multiplier}</small><b>= ${stage.value * stage.multiplier}</b></div>`).join("")}</div><div class="dplus-calculation-sum"><span>${row.stages.map((stage) => stage.value * stage.multiplier).join(" + ")}</span><b>= BIP39 index ${row.index} &middot; word number ${row.index + 1}</b></div></div>` : `<div class="manual-calculation-row"><span>Word ${row.number}</span><strong>${row.word || "incomplete"}</strong><code>${row.formula}</code><b>BIP39 index ${row.index} · word number ${row.index + 1}</b></div>`).join("")}</div></div>`;
}
function hodlRenderManualCalculations(id, method, value, targetWords = hodlTargetWordCount) {
  let panel = document.getElementById(id);
  if (!panel) return;
  let markup = hodlManualCalculationsOpen ? hodlManualCalculationMarkup(method, value, targetWords) : "";
  panel.hidden = !markup;
  panel.innerHTML = markup;
}
function hodlRenderNumberBaseCalculations(value, format = "bin", targetWords = hodlTargetWordCount) {
  let panel = document.getElementById("number-base-calculations"), toggle = document.getElementById("show-number-base-calculations");
  if (!panel || !toggle) return;
  let meta = hodlEntropyFormatConfig(format, targetWords), rows = toggle.checked ? hodlNumberBaseCalculationRows(value, meta.id, targetWords) : [], conversion = toggle.checked ? hodlNumberBaseBinaryConversionMarkup(value, meta) : "";
  panel.hidden = !toggle.checked || !rows.length && !conversion;
  if (!rows.length) {
    panel.innerHTML = conversion;
    return;
  }
  panel.innerHTML = `<p class="label">${meta.label} calculations</p><p class="muted">Each 11-bit group is interpreted as a big-endian binary integer. Multiply each bit by its bit weight, then sum the contributions to get the zero-based BIP39 index. The corresponding word number is the index plus 1.</p><div class="number-base-calculation-list">${rows.map((row) => `<div class="number-base-calculation" data-calculation-word="${row.number}"><div class="number-base-calculation-title"><span>Word ${row.number}</span><strong>${row.word || "incomplete"}</strong></div><div class="number-base-calculation-row"><span class="number-base-calculation-label">Bit weight</span><div class="number-base-calculation-powers">${row.terms.map((term) => `<span>${term.place}</span>`).join("")}</div></div><div class="number-base-calculation-row"><span class="number-base-calculation-label">Bit</span><div class="number-base-calculation-bits">${row.terms.map((term) => `<span>${term.bit}</span>`).join("")}</div></div><div class="number-base-calculation-row"><span class="number-base-calculation-label">Contribution</span><div class="number-base-calculation-products">${row.terms.map((term) => `<span>${term.value}</span>`).join("")}</div></div><div class="number-base-calculation-sum"><span>${row.terms.map((term) => term.value).join(" + ")} <b>=</b></span><span>BIP39 index <strong>${row.index}</strong></span><span>word number <strong>${row.index + 1}</strong></span></div></div>`).join("")}</div>`;
  let list = panel.querySelector(".number-base-calculation-list");
  if (list && conversion) {
    let wrapper = document.createElement("div");
    wrapper.innerHTML = conversion;
    panel.insertBefore(wrapper.firstElementChild, list);
  }
}
function hodlHexPreviewWords(value, targetWords = hodlTargetWordCount) {
  return hodlNumberBasePreviewWords(value, "hex", targetWords);
}
function hodlBitsFromBytes(bytes) {
  return Array.from(bytes || [], (byte) => byte.toString(2).padStart(8, "0")).join("");
}
function hodlBytesFromBits(bits) {
  let complete = String(bits ?? "").slice(0, Math.floor(String(bits ?? "").length / 8) * 8), bytes = new Uint8Array(complete.length / 8);
  for (let index = 0; index < bytes.length; index++) bytes[index] = Number.parseInt(complete.slice(index * 8, index * 8 + 8), 2);
  return bytes;
}
function hodlGlobalSyncIsHashedMode() {
  if (hodlKeyMode === "dice") return hodlDiceMethod === "coldcard" || hodlDiceMethod === "coleman";
  if (hodlKeyMode === "cards") return hodlCardMethod === "hashed";
  if (hodlKeyMode === "key") {
    let kind = hodlNormalizePrivateKeyKind(document.querySelector('input[name="kk"]:checked')?.value || hodlKeys[hodlActiveKey]?.fields?.keyKind, "");
    return kind === "minikey" || kind === "brain";
  }
  return false;
}
function hodlGlobalSyncSourceId() {
  if (hodlKeyMode === "dice") return `dice:${hodlDiceMethod}`;
  if (hodlKeyMode === "cards") return `cards:${hodlCardMethod}`;
  if (hodlKeyMode === "hex") return `number:${hodlEntropyFormat}`;
  if (hodlKeyMode === "seed") return `seed:${hodlSeedMethod}`;
  let kind = hodlNormalizePrivateKeyKind(document.querySelector('input[name="kk"]:checked')?.value || hodlKeys[hodlActiveKey]?.fields?.keyKind, "");
  return `key:${kind}`;
}
function hodlGlobalSyncCurrentValue() {
  let state = hodlKeys[hodlActiveKey], fields = state?.fields || {};
  if (hodlKeyMode === "dice") return document.getElementById("dice")?.value ?? (hodlDiceMethod === "dplus" ? fields.dplusDice : hodlDiceMethod === "bitbox" ? fields.bitboxDice : fields.dice) ?? "";
  if (hodlKeyMode === "cards") return document.getElementById(hodlCardMethod === "direct" ? "direct-cards" : "cards")?.value ?? fields[hodlCardMethod === "direct" ? "directCards" : "cards"] ?? "";
  if (hodlKeyMode === "hex") return document.getElementById(hodlEntropyFormat)?.value ?? fields[hodlEntropyFormat] ?? "";
  if (hodlKeyMode === "seed") return document.getElementById(hodlSeedMethod === "numbers" ? "seed-numbers" : "seed")?.value ?? fields[hodlSeedMethod === "numbers" ? "seedNumbers" : "seed"] ?? "";
  let values = hodlPrivateKeyValues(fields), kind = hodlNormalizePrivateKeyKind(document.querySelector('input[name="kk"]:checked')?.value || fields.keyKind, "");
  return document.getElementById("key")?.value ?? values[kind] ?? "";
}
function hodlGlobalSyncWordBits(words) {
  let bits = "";
  for (let word of words || []) {
    let index = hodlBip39WordIndex.get(String(word || "").toLowerCase());
    if (!Number.isInteger(index)) break;
    bits += index.toString(2).padStart(11, "0");
  }
  return bits;
}
function hodlGlobalSyncDPlusBits(value, targetWords = hodlTargetWordCount) {
  let config = hodlSeedConfig(targetWords), entries = hodlDPlusTokens(value), widths = [], steps = [];
  for (let index = 0; index < config.partialWords; index++) {
    widths.push(3, 4, 4);
    steps.push("d8", "d16", "d16");
  }
  for (let step of hodlDPlusFinalSteps(config.words)) {
    widths.push(hodlDPlusStepBits(step));
    steps.push(step);
  }
  let bits = "";
  for (let index = 0; index < Math.min(entries.length, steps.length); index++) {
    let value2 = hodlDPlusStepValue(steps[index], entries[index].face);
    if (value2 === null) break;
    bits += value2.toString(2).padStart(widths[index], "0");
  }
  return bits.slice(0, config.bits);
}
function hodlGlobalSyncDirectCardBits(value, targetWords = hodlTargetWordCount) {
  let parsed = hodlParseDirectCards(value, targetWords), bits = "";
  for (let index = 0; index < Math.min(parsed.entries.length, parsed.steps.length); index++) {
    let value2 = parsed.values[index], width = Math.log2(parsed.steps[index]);
    if (!Number.isInteger(value2) || value2 < 0) break;
    bits += value2.toString(2).padStart(width, "0");
  }
  return bits.slice(0, parsed.config.bits);
}
function hodlGlobalSyncBitBoxBits(value, targetWords = hodlTargetWordCount) {
  let config = hodlSeedConfig(targetWords), bits = "", position = 0, words = 0;
  for (let character of String(value ?? "")) {
    if (/\s|,|;|\|/.test(character)) continue;
    if (!/^[1-6]$/.test(character) || words >= config.partialWords) break;
    let face = Number(character);
    if (position < 5) {
      if (face > 4) continue;
      bits += (face - 1).toString(2).padStart(2, "0");
      position += 1;
    } else {
      bits += face <= 3 ? "0" : "1";
      position = 0;
      words += 1;
    }
  }
  return bits.slice(0, config.bits);
}
const hodlGlobalSyncUnknownBits = "unknown";
function hodlGlobalSyncSourceBits(targetWords = hodlTargetWordCount) {
  let value = hodlGlobalSyncCurrentValue(), config = hodlSeedConfig(targetWords);
  if (!String(value).length) return null;
  try {
    if (hodlKeyMode === "dice") {
      let entropy = hodlDiceEntropy(value, hodlDiceMethod, config.words);
      if (entropy?.ok && Number.isFinite(entropy.sourceBits)) return entropy.sourceBits;
      return null;
    }
    if (hodlKeyMode === "cards") {
      let entropy = hodlCardsEntropy(value, config.words, hodlCardColemanSymbols);
      if (entropy?.ok && Number.isFinite(entropy.sourceBits)) return entropy.sourceBits;
      return null;
    }
    if (hodlKeyMode === "key") {
      let kind = hodlNormalizePrivateKeyKind(document.querySelector('input[name="kk"]:checked')?.value, String(value));
      // A brain wallet is only as strong as the text.
      if (kind === "brain") return hodlGlobalSyncUnknownBits;
      // A minikey is a SHA-256 hash too: its strength is bounded by its 21- or
      // 29-character base58 payload (58^n), not by the 256-bit digest.
      if (kind === "minikey") {
        let payload = String(value).trim().length - 1;
        return payload > 0 ? payload * Math.log2(58) : null;
      }
      return 256;
    }
  } catch {
  }
  return null;
}
function hodlGlobalSyncCurrentBits(targetWords = hodlTargetWordCount) {
  let value = hodlGlobalSyncCurrentValue(), config = hodlSeedConfig(targetWords), hashed = hodlGlobalSyncIsHashedMode();
  if (!String(value).length) return "";
  try {
    if (hodlKeyMode === "dice") {
      if (hashed) {
        let entropy = hodlDiceEntropy(value, hodlDiceMethod, config.words);
        return entropy.ok ? hodlBitsFromBytes(entropy.bytes) : null;
      }
      if (hodlDiceMethod === "dplus") {
        let parsed = hodlDPlusRolls(value, config.words);
        if (parsed.complete) return hodlBitsFromBytes(hodlMnemonicToEntropy([...parsed.wordSlots, parsed.finalWord].join(" "), hodlBip39Wordlist));
        return hodlGlobalSyncDPlusBits(value, config.words);
      }
      let parsed = hodlBitBoxRolls(value, config.words);
      if (parsed.waiting === "last-word" && hodlPickedLastWord) {
        let mnemonic = [...parsed.words, hodlPickedLastWord].join(" ");
        if (hodlIsValidMnemonic(mnemonic, hodlBip39Wordlist)) return hodlBitsFromBytes(hodlMnemonicToEntropy(mnemonic, hodlBip39Wordlist));
      }
      return hodlGlobalSyncBitBoxBits(value, config.words);
    }
    if (hodlKeyMode === "cards") {
      if (hodlCardMethod === "hashed") {
        let entropy = hodlCardsEntropy(value, config.words, hodlCardColemanSymbols);
        return entropy.ok ? hodlBitsFromBytes(entropy.bytes) : null;
      }
      let parsed = hodlParseDirectCards(value, config.words);
      if (parsed.complete) return hodlBitsFromBytes(hodlMnemonicToEntropy([...parsed.wordSlots, parsed.finalWord].join(" "), hodlBip39Wordlist));
      return hodlGlobalSyncDirectCardBits(value, config.words);
    }
    if (hodlKeyMode === "hex") {
      let analysis = hodlAnalyzeEntropyInput(value, hodlEntropyFormat, config.words);
      return analysis.invalidRanges.length ? null : hodlNumberBaseBits(value, hodlEntropyFormat, config.words);
    }
    if (hodlKeyMode === "seed") {
      let words;
      if (hodlSeedMethod === "numbers") words = hodlParseSeedNumbers(value, config.words, hodlSeedZeroIndexed).wordSlots;
      else if (!hodlLooksExtendedKey(value)) {
        words = [];
        for (let word of hodlNormalizeMnemonicText(value).split(" ").filter(Boolean)) {
          if (!hodlBip39WordSet.has(word)) break;
          words.push(word);
        }
      }
      else return null;
      let mnemonic = words.length === config.words ? words.join(" ") : "";
      if (mnemonic) return hodlIsValidMnemonic(mnemonic, hodlBip39Wordlist) ? hodlBitsFromBytes(hodlMnemonicToEntropy(mnemonic, hodlBip39Wordlist)) : null;
      return hodlGlobalSyncWordBits(words);
    }
    let kind = hodlNormalizePrivateKeyKind(document.querySelector('input[name="kk"]:checked')?.value || "wif", value);
    if (kind === "hex-key") {
      let bits = "";
      for (let digit of value.replace(/\s/g, "").replace(/^0x/i, "").slice(0, 64)) {
        if (!/^[0-9a-fA-F]$/.test(digit)) break;
        bits += Number.parseInt(digit, 16).toString(2).padStart(4, "0");
      }
      return bits;
    }
    if (kind === "wif") return hodlBitsFromBytes(hodlDecodeWif(value.trim()).priv);
    if (kind === "minikey") return hodlBitsFromBytes(hodlDecodeMiniKey(value.trim()));
    return hodlBitsFromBytes(hodlBrainWalletPrivateKey(value, hodlBrainWalletTrimEnabled()));
  } catch {
    return null;
  }
}
function hodlGlobalSyncNumberValue(bits, format, targetWords = hodlTargetWordCount) {
  let meta = hodlEntropyFormatConfig(format, targetWords), source = String(bits ?? "").slice(0, meta.seed.bits), value = "", offset = 0;
  while (offset + meta.bitsPerDigit <= source.length && value.length < meta.fullDigits) {
    value += meta.alphabet[Number.parseInt(source.slice(offset, offset + meta.bitsPerDigit), 2)];
    offset += meta.bitsPerDigit;
  }
  if (value.length === meta.fullDigits && meta.remainderBits && source.length - offset >= meta.remainderBits) {
    let finalBits = source.slice(offset, offset + meta.remainderBits);
    value += meta.binaryRemainder ? finalBits : meta.alphabet[Number.parseInt(finalBits, 2)];
  }
  return meta.id === "bin" ? hodlGroupedBinary(value) : value;
}
function hodlGlobalSyncMnemonic(bits, targetWords = hodlTargetWordCount) {
  let config = hodlSeedConfig(targetWords), source = String(bits ?? "");
  if (source.length < config.bits) return null;
  return hodlEntropyToMnemonic(hodlBytesFromBits(source.slice(0, config.bits)), hodlBip39Wordlist);
}
function hodlGlobalSyncWordIndices(bits, limit = Infinity) {
  let source = String(bits ?? ""), count = Math.min(limit, Math.floor(source.length / 11)), indices = [];
  for (let index = 0; index < count; index++) indices.push(Number.parseInt(source.slice(index * 11, index * 11 + 11), 2));
  return indices;
}
function hodlGlobalSyncDPlusValue(bits, targetWords = hodlTargetWordCount) {
  let config = hodlSeedConfig(targetWords), source = String(bits ?? "").slice(0, config.bits), widths = [], steps = [];
  for (let index = 0; index < config.partialWords; index++) {
    widths.push(3, 4, 4);
    steps.push("d8", "d16", "d16");
  }
  for (let step of hodlDPlusFinalSteps(config.words)) {
    widths.push(hodlDPlusStepBits(step));
    steps.push(step);
  }
  let tokens = [], offset = 0;
  for (let index = 0; index < steps.length && offset + widths[index] <= source.length; index++) {
    let value2 = Number.parseInt(source.slice(offset, offset + widths[index]), 2), step = steps[index];
    tokens.push(step === "coin" ? value2 ? "5" : "1" : step === "d8" ? String(value2 + 1) : value2.toString(16).toUpperCase());
    offset += widths[index];
  }
  let groups = [], partialTokens = tokens.slice(0, config.partialWords * 3);
  for (let index = 0; index < partialTokens.length; index += 3) groups.push(partialTokens.slice(index, index + 3).join(""));
  let finalTokens = tokens.slice(config.partialWords * 3);
  if (finalTokens.length) groups.push(finalTokens.join(""));
  return groups.filter(Boolean).join(" ");
}
function hodlGlobalSyncDirectCardsValue(bits, targetWords = hodlTargetWordCount) {
  let config = hodlSeedConfig(targetWords), source = String(bits ?? "").slice(0, config.bits), steps = hodlDirectCardSteps(config.words), tokens = [], offset = 0;
  for (let index = 0; index < steps.length; index++) {
    let width = Math.log2(steps[index]);
    if (offset + width > source.length) break;
    tokens.push(hodlDirectCardRanks[Number.parseInt(source.slice(offset, offset + width), 2)]);
    offset += width;
  }
  let value = "";
  tokens.forEach((token, index) => value += hodlDirectCardSeparator(index, config.words) + token);
  return value;
}
function hodlGlobalSyncBitBoxValue(bits, targetWords = hodlTargetWordCount) {
  let config = hodlSeedConfig(targetWords), source = String(bits ?? "").slice(0, config.bits), tokens = [], offset = 0;
  for (let word = 0; word < config.partialWords; word++) {
    for (let position = 0; position < 6; position++) {
      let width = position < 5 ? 2 : 1;
      if (offset + width > source.length) return tokens.map((token, index) => `${index && index % 6 === 0 ? " " : ""}${token}`).join("");
      let value2 = Number.parseInt(source.slice(offset, offset + width), 2);
      tokens.push(position < 5 ? String(value2 + 1) : value2 ? "4" : "1");
      offset += width;
    }
  }
  return tokens.map((token, index) => `${index && index % 6 === 0 ? " " : ""}${token}`).join("");
}
function hodlApplyGlobalSync(bits, sourceId = hodlGlobalSyncSourceId()) {
  let state = hodlKeys[hodlActiveKey];
  if (!state) return false;
  let config = hodlSeedConfig(state.targetWords), source = String(bits ?? "").slice(0, config.bits), sourceValue = String(hodlGlobalSyncCurrentValue()), fields = state.fields, privateKeys = hodlPrivateKeyValues(fields), mnemonic = hodlGlobalSyncMnemonic(source, config.words), words = mnemonic ? mnemonic.split(" ") : hodlGlobalSyncWordIndices(source, config.partialWords).map((index) => hodlBip39Wordlist[index]);
  Object.keys(hodlEntropyFormats).forEach((format) => fields[format] = hodlGlobalSyncNumberValue(source, format, config.words));
  fields.seed = words.join(" ");
  fields.seedNumbers = words.map((word) => String(hodlBip39WordIndex.get(word) + (state.seedZeroIndexed ? 0 : 1))).join(" ");
  fields.dplusDice = hodlGlobalSyncDPlusValue(source, config.words);
  fields.directCards = hodlGlobalSyncDirectCardsValue(source, config.words);
  fields.bitboxDice = hodlGlobalSyncBitBoxValue(source, config.words);
  state.lastWord = mnemonic ? words.at(-1) : "";
  privateKeys["hex-key"] = source.slice(0, 256).match(/.{4}/g)?.map((chunk) => Number.parseInt(chunk, 2).toString(16)).join("") || "";
  privateKeys.wif = "";
  if (source.length >= 256) {
    let bytes = hodlBytesFromBits(source.slice(0, 256));
    try {
      hodlAssertPrivateKey(bytes);
      let coinType = hodlParseDerivationIndexText(fields.coinType ?? "0'")?.value ?? 0, network = hodlNetworkFromCoinType(coinType);
      privateKeys.wif = hodlEncodeWif(bytes, true, network);
    } catch {
    }
  }
  if (sourceId.startsWith("number:")) fields[sourceId.slice(7)] = sourceValue;
  else if (sourceId === "seed:words") fields.seed = sourceValue;
  else if (sourceId === "seed:numbers") fields.seedNumbers = sourceValue;
  else if (sourceId === "dice:dplus") fields.dplusDice = sourceValue;
  else if (sourceId === "dice:bitbox") fields.bitboxDice = sourceValue;
  else if (sourceId === "cards:direct") fields.directCards = sourceValue;
  else if (sourceId === "key:hex-key") privateKeys["hex-key"] = sourceValue;
  else if (sourceId === "key:wif") privateKeys.wif = sourceValue;
  state.globalSyncSource = sourceId;
  state.globalSyncBitCount = source.length;
  state.globalSyncSourceBits = hodlGlobalSyncSourceBits();
  return true;
}
function hodlGlobalSyncFromCurrentInput() {
  let state = hodlKeys[hodlActiveKey];
  if (!state?.globalSync) {
    hodlRenderGlobalSyncControl();
    return false;
  }
  if (hodlGlobalSyncIsHashedMode() && !String(hodlGlobalSyncCurrentValue()).length) {
    hodlRenderGlobalSyncControl();
    return false;
  }
  let bits = hodlGlobalSyncCurrentBits(state.targetWords);
  if (bits === null) {
    state.globalSyncBitCount = 0;
    hodlRenderGlobalSyncControl();
    return false;
  }
  hodlApplyGlobalSync(bits);
  hodlRenderGlobalSyncControl();
  return true;
}
function hodlGlobalSyncControlMarkup(state) {
  // Two rows: the switch and its title, then the explanation beneath. The
  // explanation describes the checkbox rather than naming it, so it stays out
  // of the accessible name and stays reachable through aria-describedby.
  let syncBits = state?.globalSyncBitCount || 0,
    reported = state?.globalSyncSourceBits,
    sourceBits = Number.isFinite(reported) ? Math.floor(reported) : null,
    effectiveBits = sourceBits === null ? syncBits : Math.min(syncBits, sourceBits),
    syncUnknown = Boolean(syncBits) && reported === hodlGlobalSyncUnknownBits,
    syncShort = Boolean(syncBits) && !syncUnknown && effectiveBits < hodlGlobalSyncMinimumBits(),
    caution = syncUnknown ? hodlT("entropy unknown · only as strong as the text") : hodlT("{n} bits of entropy · under {min}", { n: effectiveBits, min: hodlGlobalSyncMinimumBits() });
  return `<div class="global-sync-row"><div class="global-sync-head"><label class="seed-autocomplete-toggle global-sync-toggle"><input type="checkbox" id="global-entropy-sync" aria-describedby="global-sync-note" ${state?.globalSync ? "checked" : ""} /><span class="label">${hodlT("Sync entropy across methods")}</span></label><span class="global-sync-status" id="global-sync-status" aria-live="polite" ${state?.globalSync && syncBits ? "" : "hidden"}>${hodlCopiedIconMarkup()}<span>${hodlT("Key synced")}</span>${syncShort || syncUnknown ? `<span class="global-sync-shortfall">${hodlSyncWarningIconMarkup()}<span>${caution}</span></span>` : ""}</span></div><p class="seed-autocomplete-note global-sync-note" id="global-sync-note">${hodlT("(Keeps non-hashed methods synchronized. Hashed inputs update them one way and are never overwritten.)")}</p></div>`;
}
function hodlRenderGlobalSyncControl() {
  let host = document.getElementById("global-sync-host"), state = hodlKeys[hodlActiveKey];
  if (!host || !state) return;
  host.innerHTML = hodlGlobalSyncControlMarkup(state);
  let toggle = document.getElementById("global-entropy-sync");
  if (toggle) toggle.onchange = () => {
    state.globalSync = toggle.checked;
    if (!toggle.checked) {
      state.globalSyncBitCount = 0;
      state.globalSyncSource = "";
      hodlRenderGlobalSyncControl();
      hodlSyncKeyClearButton();
      return;
    }
    hodlGlobalSyncFromCurrentInput();
    hodlSyncKeyClearButton();
  };
}
function hodlSeedPhraseCopyText(words, targetWords = hodlTargetWordCount) {
  let needed = hodlSeedConfig(targetWords).words, source = Array.isArray(words) ? words : [], values = Array.from({ length: needed }, (_, index) => String(source[index] || "").trim()), firstMissing = values.findIndex((word) => !word);
  if (firstMissing < 0) return values.join(" ");
  if (values.slice(firstMissing + 1).some(Boolean)) return "";
  return values.slice(0, firstMissing).join(" ");
}
function hodlClipboardIconMarkup() {
  return `<svg viewBox="0 0 24 24" aria-hidden="true" focusable="false"><rect class="seed-copy-icon-clip" x="8" y="2" width="8" height="4" rx="1"/><path class="seed-copy-icon-board" d="M16 4h2a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h2"/></svg>`;
}
function hodlSyncWarningIconMarkup() {
  return `<svg viewBox="0 0 24 24" aria-hidden="true" focusable="false"><path class="seed-copy-icon-board" d="M12 4 2.5 20h19L12 4Z"/><path class="seed-copy-icon-board" d="M12 10v4"/><path class="seed-copy-icon-board" d="M12 17.2v.1"/></svg>`;
}
function hodlGlobalSyncMinimumBits() {
  return 128;
}
function hodlCopiedIconMarkup() {
  return `<svg viewBox="0 0 24 24" aria-hidden="true" focusable="false"><path class="seed-copy-icon-board" d="M20 6 9 17l-5-5"/></svg>`;
}
function hodlSeedMetaRowMarkup(metaId, live = false) {
  return `<div class="seed-word-meta"><p class="muted" id="${metaId}"${live ? ' aria-live="polite"' : ""}></p></div>`;
}
function hodlSeedCopyRowMarkup(leading = "") {
  return `<div class="seed-word-copy-row">${leading}<span class="seed-phrase-copied" aria-live="polite"></span><button type="button" class="seed-phrase-copy" data-copy-seed-phrase disabled aria-label="${hodlT("Copy seed phrase")}" title="${hodlT("Copy seed phrase")}">${hodlClipboardIconMarkup()}</button></div>`;
}
function hodlShowSeedPhraseCopied(button) {
  if (!button) return;
  let note = button.closest(".seed-word-copy-row")?.querySelector(".seed-phrase-copied");
  if (note) note.textContent = hodlTText("Copied");
  button.classList.add("is-copied");
  button.innerHTML = hodlCopiedIconMarkup();
  button.setAttribute("aria-label", button.dataset.copiedLabel || hodlTText("Seed phrase copied"));
  button.title = hodlTText("Copied");
  clearTimeout(button.hodlCopiedTimer);
  button.hodlCopiedTimer = setTimeout(() => {
    if (!button.isConnected) return;
    let phrase = button.dataset.phrase;
    button.classList.remove("is-copied");
    button.innerHTML = hodlClipboardIconMarkup();
    let copyLabel = button.dataset.copyLabel || hodlT("Copy seed phrase");
    button.setAttribute("aria-label", phrase ? copyLabel : hodlTText("Seed phrase unavailable"));
    button.title = phrase ? copyLabel : hodlTText("Seed phrase unavailable");
    if (note) note.textContent = "";
  }, 1600);
}
function hodlCopySeedPhraseButton(button) {
  let phrase = button?.dataset.phrase;
  if (!phrase || button.disabled) return;
  let done = () => hodlShowSeedPhraseCopied(button);
  let fallback = () => {
    let field = document.createElement("textarea");
    field.value = phrase;
    field.setAttribute("readonly", "");
    field.style.position = "fixed";
    field.style.left = "-9999px";
    document.body.appendChild(field);
    field.select();
    try {
      document.execCommand("copy");
      done();
    } finally {
      field.remove();
    }
  };
  if (navigator.clipboard && typeof navigator.clipboard.writeText === "function") navigator.clipboard.writeText(phrase).then(done).catch(fallback);
  else fallback();
}
function hodlRenderDiceWordGrid(container, words, targetWords = hodlTargetWordCount, provisional = false) {
  if (!container) return;
  let config = hodlSeedConfig(targetWords), values = Array.isArray(words) ? words : [], fragment = document.createDocumentFragment();
  container.innerHTML = "";
  container.style.setProperty("--dice-word-rows-wide", String(Math.ceil(config.words / 3)));
  container.style.setProperty("--dice-word-rows-narrow", String(Math.ceil(config.words / 2)));
  container.setAttribute("aria-label", `${config.words} seed-word slots${provisional ? ", provisional preview" : ""}`);
  container.dataset.provisional = String(provisional);
  for (let index = 0; index < config.words; index++) {
    let word = values[index] || "", slot = document.createElement("div"), number = document.createElement("span"), value = document.createElement("span");
    slot.className = "dice-word-slot" + (word ? "" : " empty");
    slot.dataset.wordSlot = String(index + 1);
    number.className = "dice-word-number";
    number.textContent = `${index + 1}.`;
    value.className = "dice-word-value";
    value.dataset.word = "";
    value.textContent = word || "\u2014";
    slot.append(number, value);
    fragment.appendChild(slot);
  }
  container.appendChild(fragment);
  let copy = container.closest("#form")?.querySelector("[data-copy-seed-phrase]"), phrase = hodlSeedPhraseCopyText(values, config.words);
  if (copy) {
    copy.disabled = !phrase;
    copy.dataset.phrase = phrase;
    if (!copy.classList.contains("is-copied")) {
      copy.setAttribute("aria-label", phrase ? hodlTText("Copy seed phrase") : hodlTText("Seed phrase unavailable"));
      copy.title = phrase ? hodlTText("Copy seed phrase") : hodlTText("Seed phrase unavailable");
    }
    if (!copy.hodlCopyBound) {
      copy.onclick = () => hodlCopySeedPhraseButton(copy);
      copy.hodlCopyBound = true;
    }
  }
}
function hodlUpdateEntropyInput(input, format, targetWords = hodlTargetWordCount) {
  let config = hodlSeedConfig(targetWords), analysis = hodlRenderEntropyInputState(input, format, config.words), definition = analysis.meta, meta = document.getElementById("entropy-meta"), words = hodlNumberBasePreviewWords(input.value, definition.id, config.words), wordsBox = document.getElementById("entropy-words"), coinPhase = Boolean(definition.binaryRemainder && definition.remainderBits && analysis.count >= definition.fullDigits), coinFlipsEntered = coinPhase ? Math.min(definition.remainderBits, Math.max(0, analysis.count - definition.fullDigits)) : 0, status = coinPhase ? analysis.ready ? `${definition.fullDigits} ${definition.shortLabel} characters complete \xB7 ${coinFlipsEntered} of ${definition.remainderBits} coin flips entered` : `${definition.fullDigits} ${definition.shortLabel} characters complete \xB7 coin flip ${Math.min(definition.remainderBits, coinFlipsEntered + 1)} of ${definition.remainderBits} \xB7 Heads (0) or Tails (1)` : `${analysis.count} of ${analysis.limit} ${definition.unit} \xB7 ${words.length} of ${config.words} seed words filled`;
  if (analysis.invalidCharacterCount) status += ` \xB7 ${analysis.invalidCharacterCount} invalid character${analysis.invalidCharacterCount === 1 ? "" : "s"} highlighted`;
  if (analysis.finalInvalid) status += definition.binaryRemainder ? ` \xB7 final ${definition.remainderBits} entropy bits must each be 0 or 1` : ` \xB7 final ${definition.remainderBits}-bit character must be one of ${[...definition.finalCharacters].join(", ")}`;
  if (analysis.excessCount) status += ` \xB7 ${analysis.excessCount} extra highlighted \xB7 remove to continue`;
  if (analysis.ready) status += " \xB7 ready to derive";
  if (meta) {
    meta.textContent = status;
    meta.className = "muted" + (analysis.ready ? " ok" : analysis.invalidRanges.length ? " err" : "");
  }
  hodlRenderDiceWordGrid(wordsBox, words, config.words, false);
  hodlRenderNumberBaseCalculations(input.value, definition.id, config.words);
  let entropyPad = input.closest("#form")?.querySelector(".entropy-keypad");
  if (entropyPad) entropyPad.classList.toggle("coin-phase", coinPhase);
  input.closest("#form")?.querySelectorAll("[data-entropy-digit]").forEach((button) => {
    let digit = button.dataset.entropyDigit, binary = digit === "0" || digit === "1", mixedFinalPhase = Boolean(!definition.binaryRemainder && definition.remainderBits && analysis.count === definition.digits - 1), finalRestricted = (coinPhase || mixedFinalPhase) && !definition.finalCharacters.includes(digit);
    button.disabled = Boolean(finalRestricted);
    button.hidden = Boolean(coinPhase && !binary);
    button.classList.toggle("coin-button", coinPhase && binary);
    button.textContent = coinPhase && binary ? digit === "0" ? hodlTText("Heads (0)") : hodlTText("Tails (1)") : digit;
    button.setAttribute("aria-label", coinPhase && binary ? digit === "0" ? hodlTText("Enter Heads as binary 0") : hodlTText("Enter Tails as binary 1") : hodlTText("Enter {shortLabel} {character}", { shortLabel: hodlTText(definition.shortLabel), character: digit }));
    button.title = finalRestricted ? coinPhase ? hodlTText("The remaining {n} entropy bit(s) must use 0 or 1.", { n: definition.remainderBits }) : hodlTText("The final character must be one of {chars}.", { chars: [...definition.finalCharacters].join(", ") }) : "";
  });
  return analysis;
}
function hodlRenderLastWordPicker(container, candidates, selected, onPick, settings = {}) {
  if (!container) return;
  container.innerHTML = "";
  if (!candidates || !candidates.length) return;
  if (candidates.length <= 16 && !settings.forceSelect) {
    container.innerHTML = candidates.map((word) => `<button type="button" class="tab${word === selected ? " active" : ""}" data-lw="${word}" aria-pressed="${word === selected}">${word}</button>`).join("");
    container.querySelectorAll("[data-lw]").forEach((button) => {
      button.onclick = () => onPick(button.dataset.lw || "");
    });
    return;
  }
  let targetWords = Number(settings.targetWords) || hodlTargetWordCount, label = document.createElement("label"), select = document.createElement("select"), placeholderValue = "__entropylab_placeholder__";
  label.className = "field last-word-field";
  label.textContent = hodlTText("Valid final word ({n} choices)", { n: candidates.length });
  select.setAttribute("aria-label", hodlTText("Valid final word for {n}-word seed", { n: targetWords }));
  if (!selected) {
    let placeholder = document.createElement("option");
    placeholder.value = placeholderValue;
    placeholder.textContent = settings.placeholder || hodlTText("Choose a confirmed final word");
    placeholder.disabled = true;
    placeholder.selected = true;
    placeholder.dataset.customSelectPlaceholder = "true";
    select.appendChild(placeholder);
  }
  candidates.forEach((word) => {
    let option = document.createElement("option");
    option.value = word;
    option.textContent = word;
    option.selected = word === selected;
    select.appendChild(option);
  });
  select.onchange = () => {
    if (select.value !== placeholderValue) onPick(select.value);
  };
  label.appendChild(select);
  container.appendChild(label);
}

function hodlUpdateSeedLengthControl() {
  let section = document.getElementById("seed-length");
  if (!section) return;
  let config = hodlSeedConfig();
  section.hidden = hodlKeyMode === "key";
  // Sync, not change: change would come straight back through onchange.
  if (hodlSeedLengthSelectEl.value !== String(config.words)) {
    hodlSeedLengthSelectEl.value = String(config.words);
    hodlSeedLengthSelectEl.dispatchEvent(new Event("entropylab:sync-select"));
  }
  let help = document.getElementById("seed-length-help");
  if (!help) return;
  if (hodlKeyMode === "hex") {
    let format = hodlEntropyFormatConfig(hodlEntropyFormat, config.words);
    let extra = "";
    if (format.remainderBits) extra = format.binaryRemainder
      ? hodlT(" Enter {fullDigits} complete {shortLabel} characters followed by {n} coin flip(s), using Heads (0) or Tails (1).", { fullDigits: format.fullDigits, shortLabel: format.shortLabel, n: format.remainderBits })
      : hodlT(" The final character contributes {n} bit(s) and must be one of {chars}.", { n: format.remainderBits, chars: [...format.finalCharacters].join(", ") });
    help.textContent = hodlTText("{words} words require exactly {digits} {unit}.", { words: config.words, digits: format.digits, unit: format.unit }) + extra;
    return;
  }
  help.textContent = hodlKeyMode === "seed" ? hodlSeedMethod === "numbers" ? hodlTText("Enter exactly {words} BIP39 word numbers using {range}.", { words: config.words, range: hodlTText(hodlSeedZeroIndexed ? "0 through 2047" : "1 through 2048") }) : hodlTText("Enter exactly {words} BIP39 words. Extended keys ignore this selection.", { words: config.words }) : hodlKeyMode === "cards" ? hodlCardMethod === "direct" ? hodlTText("{words} words use {partial} complete 11-bit rank selections plus {final} final rank draw(s).", { words: config.words, partial: config.partialWords, final: hodlDirectCardFinalRadices(config.words).length }) : config.words === 24 ? hodlTText("24 words need 256 bits. One deck is about 225.6 bits, so deal 52 unique cards, shuffle again, then deal 6 more.") : hodlTText("{words} words need {bits} bits. Deal {first} unique cards from one shuffled deck.", { words: config.words, bits: config.bits, first: hodlCardNeeded(config.words).first }) : hodlTText("{words} words use {bits} bits of BIP39 entropy.", { words: config.words, bits: config.bits });
}
function hodlInvalidateActiveKeyOutput() {
  hodlWalletResult = null;
  hodlRevealPrivate = false;
  hodlPickedLastWord = "";
  hodlOutEl.innerHTML = "";
  hodlSetWorkspaceError("key", null);
  let state = hodlKeys[hodlActiveKey];
  if (state) {
    state.result = null;
    state.reveal = false;
    state.lastWord = "";
    state.dplusLastWord = "";
    state.error = "";
    state.errorSpec = null;
  }
}
function hodlSetSeedLength(words) {
  let config = hodlSeedLengths[Number(words)];
  if (!config) return;
  if (hodlTargetWordCount === config.words) {
    hodlUpdateSeedLengthControl();
    hodlQueueMasterFingerprintPreview(0);
    return;
  }
  hodlCaptureKey();
  let state = hodlKeys[hodlActiveKey];
  hodlTargetWordCount = config.words;
  hodlInvalidateActiveKeyOutput();
  if (state) {
    state.targetWords = config.words;
    state.diceMethod = hodlDiceMethod;
    state.lastWord = "";
    state.dplusLastWord = "";
    state.result = null;
    state.reveal = false;
    state.error = "";
    state.errorSpec = null;
  }
  hodlRenderKeyForm();
  hodlRestoreFormFields(state);
  hodlUpdateSeedLengthControl();
  hodlQueueMasterFingerprintPreview(0);
}
function hodlRenderKeyForm() {
  let config = hodlSeedConfig(), keyboardHost = document.getElementById("passphrase-keyboard-host"), toggleHost = document.getElementById("passphrase-keyboard-toggle-host");
  if (keyboardHost) {
    keyboardHost.hidden = true;
    keyboardHost.innerHTML = "";
  }
  if (toggleHost) {
    toggleHost.hidden = true;
    toggleHost.innerHTML = "";
  }
  hodlUpdateSeedLengthControl();
  hodlRenderGlobalSyncControl();
  if (hodlKeyMode === "dice") {
    let dplusFaces = ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "A", "B", "C", "D", "E", "F"],
      dplusPad = dplusFaces.map(face => `<button type="button" data-d="${face}" aria-label="${hodlT("Hexadecimal D16 result {face}", { face })}">${face}</button>`).join("");
    let diceLabel = hodlDiceMethod === "dplus" ? hodlT("D++ rolls (D8, D16, D16; then {final})", { final: hodlDPlusFinalDescription(config.words) }) : hodlDiceMethod === "bitbox" ? hodlT("Dice rolls (1–4, then a 6th die interpreted as a coin flip)") : hodlT("Dice rolls (faces 1–6 only)");
    let diceHelp = hodlDiceMethod === "dplus" ? hodlT("Enter the D8 face from 1–8, then both hexadecimal D16 faces from 0–F exactly as shown on the dice. For example, 100 selects abandon and 8FF selects zoo. {finalHelp}", { finalHelp: hodlDPlusFinalHelp(config.words) }) : hodlDiceMethod === "bitbox" ? hodlT("{partialWords} lookup-table words fill one slot at a time, then choose a confirmed final checksum word. Use 1–4 for the first five rolls (if you get 5 or 6, roll again). The sixth roll is treated as the coin: 1–3 is Heads, 4–6 is Tails. Or flip a real coin!", { partialWords: config.partialWords }) : hodlDiceMethod === "coleman" ? hodlT("Every rolled 6 becomes 0 before the complete digit string is hashed with SHA-256. This Dice [1-6] method matches the method used by Keystone. Any nonempty count produces a phrase, but use at least {hashRolls} fair rolls before relying on it.", { hashRolls: config.hashRolls }) : hodlT("The original dice digit string is hashed with SHA-256. This Base 10 [0-9] method matches COLDCARD and SeedSigner. Any nonempty count produces a phrase, but use at least {hashRolls} fair rolls before relying on it.", { hashRolls: config.hashRolls });
    let dicePlaceholder = hodlDiceMethod === "dplus" ? "100 2AF…" : hodlDiceMethod === "bitbox" ? "111111 222224\u2026" : "415263415263\u2026";
    let dicePad = hodlDiceMethod === "dplus" ? `<div class="dice-input-pad dplus">${dplusPad}</div>` : `<div class="dice-input-pad faces-1-6">${[1,2,3,4,5,6].map(face=>`<button type="button" data-d="${face}">${face}</button>`).join("")}</div>`;
    hodlFormEl.innerHTML = `
      <p class="label">${hodlT("How to turn rolls into a {words}-word seed", { words: config.words })}</p>
      <div class="choice-grid">
      <label class="choice"><input type="radio" name="dm" value="coldcard" ${hodlDiceMethod === "coldcard" ? "checked" : ""} />
        <span><strong>${hodlT("Hashed rolls / Base 10 [0-9] (recommended)")}</strong><span class="desc">${hodlT("SHA-256 of the original dice digit string, matching the method used by COLDCARD and SeedSigner. The first {bits} bits become the selected {words}-word seed; {hashRolls} rolls are recommended, and every entered roll is included.", { bits: config.bits, words: config.words, hashRolls: config.hashRolls })}</span></span>
      </label>
      <label class="choice"><input type="radio" name="dm" value="coleman" ${hodlDiceMethod === "coleman" ? "checked" : ""} />
        <span><strong>${hodlT("Hashed rolls / Dice [1-6]")}</strong><span class="desc">${hodlT("Convert each 6 to 0 and SHA-256 the complete mapped digit string, matching the method used by Keystone. Use the first {bits} bits; {hashRolls} rolls are recommended, and every entered roll is included.", { bits: config.bits, words: config.words, hashRolls: config.hashRolls })}</span></span>
      </label>
      <label class="choice"><input type="radio" name="dm" value="bitbox" ${hodlDiceMethod === "bitbox" ? "checked" : ""} />
        <span><strong>${hodlT("BitBox diceware / Direct word selection")}</strong><span class="desc">${hodlT("Use five dice showing 1–4, then a coin (or 6th die: 1–3 heads, 4–6 tails). Build {partialWords} lookup-table words, then choose 1 of {candidates} valid final checksum words.", { partialWords: config.partialWords, candidates: config.candidates })}</span></span>
      </label>
      <label class="choice"><input type="radio" name="dm" value="dplus" ${hodlDiceMethod==="dplus"?"checked":""} />
        <span><strong>${hodlT("D++ / Direct word selection")}</strong><span class="desc">${hodlT("Roll one D8 labeled 1–8 and two hexadecimal D16 dice labeled 0–F for each of the first {partialWords} words, then {final} to select the valid checksum final word.", { partialWords: config.partialWords, final: hodlDPlusFinalDescription(config.words) })}</span></span>
      </label>
      </div>
      <p class="label" id="dice-label">${diceLabel}</p>
      <p class="muted" id="dice-help">${diceHelp}</p>
      <div class="dice-input-shell"><pre class="dice-input-highlight" id="dice-highlight" aria-hidden="true"></pre><textarea id="dice" placeholder="${dicePlaceholder}" aria-describedby="dice-help dice-meta"></textarea></div>
      ${hodlSeedMetaRowMarkup("dice-meta", true)}
      ${dicePad}
      ${hodlDiceMethod === "bitbox" || hodlDiceMethod === "dplus" ? `<label class="seed-autocomplete-toggle manual-calculations-toggle"><input type="checkbox" id="show-manual-calculations" ${hodlManualCalculationsOpen ? "checked" : ""} /><span><strong>${hodlT("Show calculations")}</strong> <span class="seed-autocomplete-note">${hodlT("(show how direct word selection produces each BIP39 index)")}</span></span></label><div id="dice-manual-calculations" class="manual-calculations-container" hidden></div>` : ""}
      ${hodlSeedCopyRowMarkup(hodlDiceFairnessToggleMarkup(hodlKeys[hodlActiveKey]?.showDiceFairness))}
      <aside id="dice-fairness" class="dice-fairness" hidden role="status" aria-live="polite"></aside>
      <div id="dice-words" class="dice-word-grid" aria-label="${hodlT("{n} seed-word slots", { n: config.words })}"></div><div id="last-words" class="row" style="margin-top:8px"></div>`;
    let input = document.getElementById("dice");
    input.dataset.previousValue = input.value;
    let fairnessToggle = document.getElementById("dice-fairness-toggle");
    if (fairnessToggle) fairnessToggle.onclick = () => hodlSetDiceFairnessOpen(!hodlDiceFairnessIsOpen());
    let manualToggle = document.getElementById("show-manual-calculations");
    if (manualToggle) manualToggle.onchange = () => {
      hodlManualCalculationsOpen = manualToggle.checked;
      hodlUpdateDice();
    };
    hodlBindKeypadPointer(hodlFormEl.querySelectorAll("[data-d]"), () => input);
    hodlFormEl.querySelectorAll("[data-d]").forEach((button) => {
      button.onclick = () => hodlInsertDiceControl(input, button);
    });
    input.oninput = () => {
      if (hodlDiceMethod !== "dplus") hodlTrackDiceInputEdit(input);
      else delete input.hodlDiceBeforeInput;
      hodlSanitizeDiceInput(input);
      hodlUpdateDice();
    };
    input.onscroll = () => hodlSyncDiceHighlight(input);
    hodlFormEl.querySelectorAll("input[name=dm]").forEach(radio => {
      radio.onchange = () => {
        let raw = input.value, lastWord = hodlPickedLastWord, previousMethod = hodlDiceMethod, state = hodlKeys[hodlActiveKey];
        if (state) {
          if (previousMethod === "dplus") {
            state.fields.dplusDice = raw;
            state.dplusLastWord = lastWord;
          } else {
            state.fields[previousMethod === "bitbox" ? "bitboxDice" : "dice"] = raw;
            state.diceCoinPositions = hodlDiceCoinPositions.slice();
            if (previousMethod === "bitbox") state.lastWord = lastWord;
          }
        }
        hodlDiceMethod = radio.value;
        hodlManualCalculationsOpen = false;
        if (state) {
          state.diceMethod = hodlDiceMethod;
          hodlPickedLastWord = hodlDiceMethod === "dplus" ? state.dplusLastWord || "" : hodlDiceMethod === "bitbox" ? state.lastWord || "" : "";
        } else hodlPickedLastWord = previousMethod === hodlDiceMethod ? lastWord : "";
        hodlRenderKeyForm();
        let replacement = document.getElementById("dice"), replacementValue = state ? hodlDiceMethod === "dplus" ? state.fields.dplusDice || "" : hodlDiceMethod === "bitbox" ? state.fields.bitboxDice || "" : state.fields.dice || "" : previousMethod === hodlDiceMethod ? raw : "";
        if (replacement) {
          replacement.value = replacementValue;
          replacement.dataset.previousValue = replacementValue;
          replacement.setSelectionRange(replacementValue.length, replacementValue.length);
          hodlSanitizeDiceInput(replacement);
        }
        hodlUpdateDice();
        hodlQueueMasterFingerprintPreview(0);
      };
    });
    hodlBindKeyFields();
    hodlRenderPassphraseKeyboard();
    return;
  }
  if (hodlKeyMode === "cards") {
    let state = hodlKeys[hodlActiveKey], needed = hodlCardNeeded(config.words), showCards = Boolean(state?.showCards), direct = hodlCardMethod === "direct";
    let hashedRecommended = config.words === 24 ? hodlT("58 cards across two shuffles are recommended") : hodlT("{n} cards are recommended", { n: needed.first });
    if (!direct) hodlCardSuit = hodlCardRank = "";
    let suitPad = hodlCardSuits.map((suit) => `<button type="button" class="card-suit${suit.red ? " is-red" : ""}" data-card-suit="${suit.code}" aria-label="${suit.label}" aria-pressed="false">${suit.symbol}</button>`).join("");
    let rankPad = direct ? hodlDirectCardRanks.map((rank) => `<button type="button" data-direct-card-rank="${rank}" aria-label="Enter rank ${rank}">${rank}</button>`).join("") : hodlCardRanks.map((rank) => `<button type="button" data-card-rank="${rank}" aria-label="${rank === "T" ? "10" : rank}">${rank === "T" ? "10" : rank}</button>`).join("");
    let inputId = direct ? "direct-cards" : "cards", inputLabel = direct ? "Rank-only draw transcript" : "Card transcript", inputHelp = direct ? `For each of the first ${config.partialWords} words, shuffle and draw from A\u20138 three times, then A\u20134 once. Each four-character group selects one word; spaces separate the groups. The shorter final group supplies the remaining entropy bits, and EntropyLab calculates the BIP39 checksum bits.` : `Each valid card updates a deterministic test seed. For real security, ${config.words === 24 ? "deal all 52 unique cards, shuffle again, then deal 6 more" : `deal ${needed.first} unique cards without putting them back`}. SHA-256 hashes the ASCII transcript (As 2c Td).`, placeholder = direct ? "A284 37A2 \u2026" : hodlCardColemanSymbols ? "A\u2660 2\u2663 T\u2665 T\u2666\u2026" : "As 2c Th Td\u2026";
    hodlFormEl.innerHTML = `
      <p class="label">${hodlT("How to turn cards into a {words}-word seed", { words: config.words })}</p>
      <div class="choice-grid">
        <label class="choice"><input type="radio" name="card-method" value="hashed" ${direct ? "" : "checked"} /><span><strong>${hodlT("Hashed card transcript")}</strong><span class="desc">${hodlT("Deal unique rank-and-suit cards without replacement. SHA-256 hashes the complete transcript; {recommended}.", { recommended: hashedRecommended })}</span></span></label>
        <label class="choice"><input type="radio" name="card-method" value="direct" ${direct ? "checked" : ""} /><span><strong>${hodlT("Direct word selection")}</strong><span class="desc">${hodlT("Ignore suits. Reshuffle and draw A–8, A–8, A–8, then A–4 for each full word. Finish with the shorter rank sequence shown for the checksum-valid final word.")}</span></span></label>
      </div>
      <p class="muted" id="cards-help">${inputHelp}</p>
      ${direct ? "" : `<label class="seed-autocomplete-toggle seed-zero-index-toggle"><input type="checkbox" id="cards-ian-coleman" ${hodlCardColemanSymbols ? "checked" : ""} /><span><strong>Match Ian Coleman method</strong> <span class="seed-autocomplete-note">(show and hash A\u2660 2\u2663 instead of As 2c)</span></span></label>`}
      <label class="field" id="cards-input-label" for="${inputId}">${inputLabel}</label>
      <div class="dice-input-shell cards-input-shell"><pre class="dice-input-highlight" id="cards-highlight" aria-hidden="true"></pre><textarea id="${inputId}" placeholder="${placeholder}" autocomplete="off" spellcheck="false" autocapitalize="off" aria-labelledby="cards-input-label" aria-describedby="cards-help cards-meta"></textarea></div>
      ${hodlSeedMetaRowMarkup("cards-meta")}
      ${direct ? "" : `<div class="card-suit-pad" role="group" aria-label="${hodlT("Suit")}">${suitPad}</div>`}
      <div class="card-rank-pad dice-input-pad${direct ? " direct-card-rank-pad" : ""}" role="group" aria-label="${hodlT(direct ? "Rank-only draw" : "Rank")}">${rankPad}</div>
      <div class="card-controls-row"><button class="card-undo-button seed-keyboard-delete" id="card-undo" type="button" aria-label="${hodlT("Undo last card")}" title="${hodlT("Undo last card")}" disabled><svg viewBox="0 0 24 18" aria-hidden="true" focusable="false"><path d="M9 2h11a2 2 0 0 1 2 2v10a2 2 0 0 1-2 2H9L2 9l7-7Z"/><path d="m12 6 6 6m0-6-6 6"/></svg></button><label class="seed-autocomplete-toggle card-visibility-toggle"><input type="checkbox" id="show-cards" aria-controls="dealt-cards" ${showCards ? "checked" : ""} /><span>${hodlT("Show cards")}</span></label></div>
      <aside class="cards-reshuffle" id="cards-reshuffle" hidden></aside>
      <div class="dealt-cards" id="dealt-cards" aria-live="polite"${showCards ? "" : " hidden"}></div>
      ${direct ? `<label class="seed-autocomplete-toggle manual-calculations-toggle"><input type="checkbox" id="show-manual-calculations" ${hodlManualCalculationsOpen ? "checked" : ""} /><span><strong>${hodlT("Show calculations")}</strong> <span class="seed-autocomplete-note">${hodlT("(show how direct card selection produces each BIP39 index)")}</span></span></label><div id="cards-manual-calculations" class="manual-calculations-container" hidden></div>` : ""}
      ${hodlSeedCopyRowMarkup()}
      <div id="dice-words" class="dice-word-grid" aria-label="${hodlT("{n} seed-word slots", { n: config.words })}"></div>
    `;
    let input = document.getElementById(inputId);
    input.onbeforeinput = direct ? (event) => hodlHandleGroupedSeparatorDelete(input, event) : (event) => {
      if (event.inputType === "insertText" && event.data && !hodlCardTypedCharactersAllowed(event.data)) event.preventDefault();
      else hodlHandleGroupedSeparatorDelete(input, event);
    };
    input.oninput = () => {
      if (!direct) hodlCardSuit = hodlCardRank = "";
      hodlApplyFilteredInput(input, direct ? hodlFilterDirectCards : (value) => hodlFilterCards(value, hodlCardColemanSymbols));
      direct ? hodlUpdateDirectCards() : hodlUpdateCards();
    };
    input.onscroll = () => hodlSyncDiceHighlight(input);
    hodlFormEl.querySelectorAll('input[name="card-method"]').forEach((radio) => {
      radio.onchange = () => {
        if (state) {
          state.fields[direct ? "directCards" : "cards"] = input.value;
          state.cardMethod = radio.value;
        }
        hodlCardMethod = radio.value;
        hodlManualCalculationsOpen = false;
        hodlInvalidateLiveKeyResult();
        hodlRenderKeyForm();
        hodlRestoreFormFields(state);
        hodlQueueMasterFingerprintPreview(0);
      };
    });
    let cardPadCommitting = false;
    hodlFormEl.querySelectorAll("[data-card-suit]").forEach((button) => {
      button.onclick = () => {
        if (cardPadCommitting) return;
        hodlCardSuit = hodlToggleCardChoice(hodlCardSuit, button.getAttribute("data-card-suit"));
        if (hodlUpdateCards()) {
          cardPadCommitting = true;
          queueMicrotask(() => cardPadCommitting = false);
        }
      };
    });
    hodlFormEl.querySelectorAll("[data-card-rank]").forEach((button) => {
      button.onclick = () => {
        if (cardPadCommitting) return;
        hodlCardRank = hodlToggleCardChoice(hodlCardRank, button.getAttribute("data-card-rank"));
        if (hodlUpdateCards()) {
          cardPadCommitting = true;
          queueMicrotask(() => cardPadCommitting = false);
        }
      };
    });
    hodlBindKeypadPointer(hodlFormEl.querySelectorAll("[data-direct-card-rank], #card-undo"), () => input);
    hodlFormEl.querySelectorAll("[data-direct-card-rank]").forEach((button) => {
      button.onclick = () => {
        let rank = button.getAttribute("data-direct-card-rank");
        let start = Number.isInteger(input.selectionStart) ? input.selectionStart : input.value.length, end = Number.isInteger(input.selectionEnd) ? input.selectionEnd : start;
        input.setRangeText(rank, start, end, "end");
        input.dispatchEvent(new InputEvent("input", { bubbles: true, inputType: "insertText", data: rank }));
      };
    });
    document.getElementById("card-undo").onclick = hodlUndoCard;
    document.getElementById("show-cards").onchange = (event) => {
      let visible = event.currentTarget.checked, state = hodlKeys[hodlActiveKey], dealt = document.getElementById("dealt-cards");
      if (state) state.showCards = visible;
      if (dealt) dealt.hidden = !visible;
    };
    let manualToggle = document.getElementById("show-manual-calculations");
    if (manualToggle) manualToggle.onchange = () => {
      hodlManualCalculationsOpen = manualToggle.checked;
      hodlUpdateDirectCards();
    };
    let colemanToggle = document.getElementById("cards-ian-coleman");
    if (colemanToggle) colemanToggle.onchange = () => {
      hodlCardColemanSymbols = colemanToggle.checked;
      input.value = hodlFilterCards(input.value, hodlCardColemanSymbols);
      input.placeholder = hodlCardColemanSymbols ? "A\u2660 2\u2663 T\u2665 T\u2666\u2026" : "As 2c Th Td\u2026";
      input.setSelectionRange(input.value.length, input.value.length);
      if (state) {
        state.cardColemanSymbols = hodlCardColemanSymbols;
        state.fields.cards = input.value;
      }
      hodlInvalidateLiveKeyResult();
      hodlUpdateCards();
    };
    hodlBindKeyFields();
    hodlRenderPassphraseKeyboard();
    direct ? hodlUpdateDirectCards() : hodlUpdateCards();
    return;
  }
  if (hodlKeyMode === "hex") {
    let state = hodlKeys[hodlActiveKey], format = hodlEntropyFormatConfig(hodlEntropyFormat, config.words), inputId = format.id;
    let formatChoices = ["bin", "base4", "base8", "hex", "base32", "base64"].map((id) => {
      return `<label class="choice"><input type="radio" name="entropy-format" value="${id}" ${format.id === id ? "checked" : ""} /><span><strong>${hodlT(hodlHexFormatLabels[id].label)}</strong><span class="desc">${hodlT(hodlHexFormatLabels[id].desc)}</span></span></label>`;
    }).join("");
    let formatLabel = hodlT(format.label), formatShort = hodlT(format.shortLabel), formatUnit = hodlT(format.unit);
    let entropyPad = format.id === "base64" ? "" : `<div class="dice-input-pad entropy-keypad entropy-keypad-${format.id}" role="group" aria-label="${hodlT("{label} keypad", { label: formatLabel })}">${[...format.alphabet].map((character) => `<button type="button"${format.id === "bin" ? ' class="coin-button"' : ""} data-entropy-digit="${character}" aria-label="${format.id === "bin" ? character === "0" ? hodlT("Enter Heads as binary 0") : hodlT("Enter Tails as binary 1") : hodlT("Enter {shortLabel} {character}", { shortLabel: formatShort, character })}">${format.id === "bin" ? character === "0" ? hodlT("Heads (0)") : hodlT("Tails (1)") : character}</button>`).join("")}</div>`;
    let remainderHelp = format.remainderBits ? format.binaryRemainder ? hodlT(" Enter {fullDigits} complete {shortLabel} characters; the controls and progress message then switch to {n} coin flip(s), using Heads (0) or Tails (1).", { fullDigits: format.fullDigits, shortLabel: formatShort, n: format.remainderBits }) : hodlT(" The final character is mixed-radix: it contributes only {n} bit(s) and must be one of {chars}.", { n: format.remainderBits, chars: [...format.finalCharacters].join(", ") }) : "", base64Tools = format.id === "base64" ? `<div class="seed-entry-tools base64-entry-tools">${hodlBase64KeyboardToggleMarkup()}</div>` : "", base64Keyboard = format.id === "base64" ? hodlBase64KeyboardMarkup() : "";
    hodlFormEl.innerHTML = `
      <p class="label">${hodlT("Number base")}</p>
      <div class="choice-grid entropy-format-grid">${formatChoices}</div>
      ${["bin", "base4", "base8", "hex"].includes(format.id) ? `<label class="seed-autocomplete-toggle number-base-calculations-toggle"><input type="checkbox" id="show-number-base-calculations" ${state?.showNumberBaseCalculations ? "checked" : ""} /><span><strong>${hodlT("Show calculations")}</strong> <span class="seed-autocomplete-note">${hodlT("(show how each BIP39 word number is calculated)")}</span></span></label>` : ""}
      <p class="label" id="entropy-input-label">${format.label} entropy for a ${config.words}-word seed</p>
      <p class="muted" id="entropy-input-help">Each complete ${format.shortLabel} character contributes ${format.bitsPerDigit} bit${format.bitsPerDigit === 1 ? "" : "s"}${format.binaryRemainder ? "" : " except for a mixed-radix final character when needed"}. Seed-word cards fill as enough bits arrive; the checksum-derived final word appears when all ${format.digits} characters are entered.${format.id === "bin" ? " Spaces are added every 11 bits." : ""}${remainderHelp} No generator \u2014 enter entropy you already created.</p>
      ${base64Tools}
      <div class="dice-input-shell entropy-input-shell"><pre class="dice-input-highlight" id="entropy-input-highlight" aria-hidden="true"></pre><textarea id="${inputId}" placeholder="${hodlT("Exactly {digits} {unit}", { digits: format.digits, unit: formatUnit })}" aria-labelledby="entropy-input-label" aria-describedby="entropy-input-help entropy-meta" autocomplete="off" spellcheck="false" autocapitalize="${format.id === "base64" ? "off" : format.base > 10 ? "characters" : "off"}"></textarea></div>
      ${hodlSeedMetaRowMarkup("entropy-meta", true)}
      ${base64Keyboard}
      ${entropyPad}
      <div id="number-base-calculations" class="number-base-calculations-panel" hidden></div>
      ${hodlSeedCopyRowMarkup()}
      <div id="entropy-words" class="dice-word-grid" aria-label="${hodlT("{n} seed-word slots", { n: config.words })}"></div>`;
    hodlFormEl.querySelectorAll('input[name="entropy-format"]').forEach((radio) => {
      radio.onchange = () => {
        let state2 = hodlKeys[hodlActiveKey], previous = document.getElementById(hodlEntropyFormat);
        if (state2 && previous) state2.fields[hodlEntropyFormat] = previous.value;
        hodlEntropyFormat = hodlNormalizeEntropyFormat(radio.value);
        if (state2) state2.entropyFormat = hodlEntropyFormat;
        hodlInvalidateLiveKeyResult();
        hodlSetWorkspaceError("key", null);
        hodlRenderKeyForm();
        hodlRestoreFormFields(state2);
        hodlUpdateSeedLengthControl();
        hodlQueueMasterFingerprintPreview(0);
      };
    });
    let calculationsToggle = document.getElementById("show-number-base-calculations");
    if (calculationsToggle) calculationsToggle.onchange = () => {
      if (state) state.showNumberBaseCalculations = calculationsToggle.checked;
      let input = document.getElementById(inputId);
      if (input) hodlRenderNumberBaseCalculations(input.value, format.id, config.words);
    };
    hodlBindKeyFields();
    let entropyInput = document.getElementById(inputId);
    if (entropyInput) {
      hodlBindKeypadPointer(hodlFormEl.querySelectorAll("[data-entropy-digit]"), () => entropyInput);
      hodlFormEl.querySelectorAll("[data-entropy-digit]").forEach((button) => {
        button.onclick = () => hodlInsertEntropyControl(entropyInput, button);
      });
      if (format.id === "base64") hodlBindBase64Keyboard(entropyInput);
    }
    hodlRenderPassphraseKeyboard();
    return;
  }
  if (hodlKeyMode === "seed") {
    let state = hodlKeys[hodlActiveKey], autocompleteEnabled = Boolean(state?.seedAutocomplete), numbers = hodlSeedMethod === "numbers", choices = `<p class="label">${hodlT("How to enter a seed phrase")}</p><div class="choice-grid seed-method-grid"><label class="choice"><input type="radio" name="seed-method" value="words" ${numbers ? "" : "checked"} /><span><strong>${hodlT("Direct word entry")}</strong><span class="desc">${hodlT("Type or paste the English BIP39 words themselves.")}</span></span></label><label class="choice"><input type="radio" name="seed-method" value="numbers" ${numbers ? "checked" : ""} /><span><strong>${hodlT("BIP39 word numbers")}</strong><span class="desc">${hodlT("Enter each word's position in the standard English list, using 1 through 2048 by default.")}</span></span></label></div>`;
    let bindMethodChoices = (input) => hodlFormEl.querySelectorAll('input[name="seed-method"]').forEach((radio) => {
      radio.onchange = () => {
        if (!radio.checked) return;
        let next = hodlNormalizeSeedMethod(radio.value), currentValue = input.value;
        if (state) {
          if (numbers) state.fields.seedNumbers = currentValue;
          else state.fields.seed = currentValue;
          if (next === "numbers") {
            let converted = hodlSeedWordsToNumbers(currentValue, hodlSeedZeroIndexed);
            if (converted || !currentValue.trim()) state.fields.seedNumbers = converted;
          } else {
            let converted = hodlSeedNumbersToWords(currentValue, hodlSeedZeroIndexed, config.words);
            if (converted || !currentValue.trim()) state.fields.seed = converted;
          }
          state.seedMethod = next;
        }
        hodlSeedMethod = next;
        hodlInvalidateActiveKeyOutput();
        hodlRenderKeyForm();
        hodlRestoreFormFields(state);
        hodlUpdateSeedLengthControl();
        hodlQueueMasterFingerprintPreview(0);
      };
    });
    if (numbers) {
      let range = hodlT(hodlSeedZeroIndexed ? "0 through 2047" : "1 through 2048");
      hodlFormEl.innerHTML = `${choices}<p class="label" id="seed-number-label">${hodlT("Your {words} BIP39 word numbers", { words: config.words })}</p><p class="muted" id="seed-number-help">${hodlT("Enter one {range} number for each word, separated by spaces. The corresponding BIP39 words appear below.", { range })}</p><label class="seed-autocomplete-toggle seed-zero-index-toggle"><input type="checkbox" id="seed-zero-index" ${hodlSeedZeroIndexed ? "checked" : ""} /><span><strong>${hodlT("Use zero-indexed word numbers")}</strong> <span class="seed-autocomplete-note">${hodlT("(0–2047 instead of the default 1–2048)")}</span></span></label><div class="dice-input-shell seed-number-input-shell"><pre class="dice-input-highlight" id="seed-number-highlight" aria-hidden="true"></pre><textarea id="seed-numbers" inputmode="numeric" placeholder="${hodlT(hodlSeedZeroIndexed ? "0 1 2 …" : "1 2 3 …")}" aria-labelledby="seed-number-label" aria-describedby="seed-number-help seed-number-meta" autocomplete="off" spellcheck="false"></textarea></div>${hodlSeedMetaRowMarkup("seed-number-meta", true)}<div class="dice-input-pad seed-number-pad" role="group" aria-label="${hodlT("BIP39 word number keypad")}">${[0, 1, 2, 3, 4, 5, 6, 7, 8, 9].map((digit) => `<button type="button" data-seed-number-digit="${digit}" aria-label="${hodlT("Enter {n}", { n: digit })}">${digit}</button>`).join("")}<button type="button" class="seed-keyboard-delete seed-number-delete" data-seed-number-delete aria-label="${hodlT("Delete previous digit")}"><svg viewBox="0 0 24 18" aria-hidden="true" focusable="false"><path d="M9 2h11a2 2 0 0 1 2 2v10a2 2 0 0 1-2 2H9L2 9l7-7Z"/><path d="m12 6 6 6m0-6-6 6"/></svg></button><button type="button" class="seed-number-next" data-seed-number-space>${hodlT("Next word")}</button></div>${hodlSeedCopyRowMarkup()}<div id="seed-number-words" class="dice-word-grid" aria-label="${hodlT("{n} seed-word slots", { n: config.words })}"></div>`;
      let input = document.getElementById("seed-numbers"), update = () => {
        let parsed = hodlRenderSeedNumberInputState(input, config.words, hodlSeedZeroIndexed), meta = hodlElement("#seed-number-meta"), entered = parsed.entries.length, progress = hodlT("{entered} of {words} BIP39 word numbers entered", { entered, words: config.words }), remaining = Math.max(0, config.words - entered);
        hodlRenderDiceWordGrid(document.getElementById("seed-number-words"), parsed.wordSlots, config.words, false);
        if (parsed.extraEntries.length) {
          meta.textContent = hodlTText("{entered} entered · {words} required · {n} extra highlighted · remove to continue", { entered, words: config.words, n: parsed.extraEntries.length });
          meta.className = "muted err";
        } else if (parsed.invalidEntries.length) {
          let invalid = parsed.invalidEntries[0];
          meta.textContent = hodlTText("{progress} · Word {n} number “{token}” is outside {min}–{max} · correct to continue", { progress, n: invalid.position + 1, token: invalid.token, min: parsed.minimum, max: parsed.maximum });
          meta.className = "muted err";
        } else if (parsed.checksumInvalid) {
          meta.textContent = hodlTText("{progress} · BIP39 checksum invalid · final word number highlighted", { progress });
          meta.className = "muted err";
        } else if (parsed.complete) {
          meta.textContent = hodlTText("{progress} · checksum valid · ready to derive", { progress });
          meta.className = "muted ok";
        } else {
          meta.textContent = hodlTText("{progress} · {remaining} remaining · valid range {min}–{max}", { progress, remaining, min: parsed.minimum, max: parsed.maximum });
          meta.className = "muted";
        }
        hodlUpdateSeedNumberPad(input, parsed);
        hodlQueueMasterFingerprintPreview();
        return parsed;
      };
      let zeroToggle = document.getElementById("seed-zero-index");
      zeroToggle.onchange = () => {
        hodlSeedZeroIndexed = zeroToggle.checked;
        input.value = hodlTranslateSeedNumberIndex(input.value, hodlSeedZeroIndexed);
        input.setSelectionRange(input.value.length, input.value.length);
        if (state) {
          state.seedZeroIndexed = hodlSeedZeroIndexed;
          state.fields.seedNumbers = input.value;
        }
        document.getElementById("seed-number-help").textContent = hodlTText("Enter one {range} number for each word, separated by spaces. The corresponding BIP39 words appear below.", { range: hodlTText(hodlSeedZeroIndexed ? "0 through 2047" : "1 through 2048") });
        input.placeholder = hodlTText(hodlSeedZeroIndexed ? "0 1 2 …" : "1 2 3 …");
        hodlUpdateSeedLengthControl();
        update();
      };
      input.onbeforeinput = (event) => {
        if (event.inputType === "insertText" && event.data === "0" && !hodlSeedNumberCanInsertDigit(input, event.data, hodlSeedZeroIndexed)) event.preventDefault();
        else hodlHandleSeedNumberSeparatorDelete(input, event);
      };
      input.oninput = (event) => {
        hodlApplyFilteredInput(input, (value) => hodlFilterSeedNumbers(value, hodlSeedZeroIndexed));
        hodlAutocompleteSeedNumberInput(input, event, config.words, hodlSeedZeroIndexed);
        update();
      };
      input.onscroll = () => hodlSyncDiceHighlight(input);
      bindMethodChoices(input);
      hodlBindSeedNumberPad(input, update);
      hodlBindKeyFields();
      hodlRenderPassphraseKeyboard();
      update();
      return;
    }
    hodlFormEl.innerHTML = `${choices}<p class="label">Your ${config.words}-word seed phrase</p><p class="muted" id="seed-help">Enter exactly ${config.words} English BIP39 words. You can also paste an extended key here; the selected phrase length does not apply to extended keys. With ${config.partialWords} compatible diceware words, choose the final checksum word below.</p><div class="seed-entry-tools">${hodlSeedKeyboardToggleMarkup()}<label class="seed-autocomplete-toggle"><input type="checkbox" id="seed-autocomplete" ${autocompleteEnabled ? "checked" : ""} /><span>Autocomplete BIP39 words</span></label></div><div class="dice-input-shell seed-input-shell"><pre class="dice-input-highlight" id="seed-highlight" aria-hidden="true"></pre><textarea id="seed" placeholder="Enter exactly ${config.words} BIP39 words" aria-describedby="seed-help seed-meta" autocomplete="off" spellcheck="false" autocapitalize="off"></textarea></div><p class="muted" id="seed-meta" aria-live="polite"></p>${hodlSeedKeyboardMarkup()}<div id="last-words" class="row" style="margin-top:8px"></div>`;
    let input = document.getElementById("seed"), update = () => {
      let rawValue = input.value, value = rawValue.trim(), meta = hodlElement("#seed-meta"), picker = hodlElement("#last-words"), analysis = hodlRenderSeedInputState(input, config.words);
      if (hodlLooksExtendedKey(value)) {
        let status = hodlSinglesigImportStatus(value, hodlSelectedKeyNetwork());
        picker.innerHTML = "";
        meta.textContent = status.message;
        meta.className = "muted " + (status.ok ? status.warning ? "err" : "ok" : "err");
        return;
      }
      let finalContext = analysis.finalContext, validation = hodlValidateTargetMnemonic(value, config.words), entered = analysis.tokens.length, progress = hodlSeedCountStatus(entered, config.words), remaining = Math.max(0, config.words - entered);
      if (finalContext) {
        hodlRenderLastWordPicker(picker, finalContext.candidates, finalContext.selected, (word) => hodlReplaceSeedFinalWord(input, finalContext, word), { forceSelect: true, resettable: true, targetWords: config.words, placeholder: hodlTText("Choose {article} {n}th word", { article: hodlTText(config.words === 18 ? "an" : "a"), n: config.words }) });
        if (!finalContext.finalToken) {
          meta.textContent = hodlTText("{progress} · choose the final checksum word · {n} valid choices", { progress, n: finalContext.candidates.length });
          meta.className = "muted ok";
          return;
        }
        if (validation.ok) {
          meta.textContent = hodlTText("{progress} · checksum valid · ready to derive", { progress });
          meta.className = "muted ok";
          return;
        }
        if (!finalContext.matchingCandidates.length) {
          meta.textContent = hodlTText("{progress} · No valid checksum word starts with \"{prefix}\".", { progress, prefix: finalContext.prefix });
          meta.className = "muted err";
          return;
        }
        meta.textContent = hodlTText("{progress} · {n} valid checksum word(s) start with \"{prefix}\".", { progress, n: finalContext.matchingCandidates.length, prefix: finalContext.prefix });
        meta.className = "muted";
        return;
      }
      picker.innerHTML = "";
      let invalidWord = analysis.invalidWords[0];
      if (analysis.excessCount) {
        meta.textContent = hodlTText("{entered} entered · {words} required BIP39 words · {n} extra highlighted · remove to continue", { entered, words: config.words, n: analysis.excessCount });
        meta.className = "muted err";
        return;
      }
      if (invalidWord) {
        meta.textContent = hodlTText("{progress} · Word {n} (“{word}”) is not on the BIP39 English list · correct to continue", { progress, n: invalidWord.index + 1, word: invalidWord.word });
        meta.className = "muted err";
        return;
      }
      if (validation.ok) {
        meta.textContent = hodlTText("{progress} · checksum valid · ready to derive", { progress });
        meta.className = "muted ok";
        return;
      }
      meta.textContent = hodlTText("{progress} · {remaining} remaining", { progress, remaining });
      meta.className = "muted";
    };
    let toggle = document.getElementById("seed-autocomplete");
    toggle.onchange = () => {
      let state = hodlKeys[hodlActiveKey];
      if (state) state.seedAutocomplete = toggle.checked;
      input.focus({ preventScroll: true });
      if (toggle.checked && hodlAutocompleteSeedInput(input, null, true)) {
        let event = typeof InputEvent === "function" ? new InputEvent("input", { bubbles: true, inputType: "insertReplacementText", data: null }) : new Event("input", { bubbles: true });
        input.dispatchEvent(event);
      } else update();
    };
    input.oninput = (event) => {
      hodlApplyFilteredInput(input, hodlFilterSeed);
      hodlAutocompleteSeedInput(input, event);
      update();
    };
    input.onscroll = () => hodlSyncDiceHighlight(input);
    input.onfocus = update;
    input.onblur = (event) => {
      if (!event.relatedTarget?.closest?.("#seed-keyboard,.seed-autocomplete-toggle")) update();
    };
    bindMethodChoices(input);
    hodlBindSeedKeyboard(input, config.words);
    hodlBindKeyFields();
    hodlRenderPassphraseKeyboard();
    update();
    return;
  }
  hodlFormEl.innerHTML = `
    <p class="label">${hodlT("Private key format")}</p>
    <div class="choice-grid">
    <label class="choice"><input type="radio" name="kk" value="wif" checked /><span><strong>${hodlT("WIF")}</strong><span class="desc">${hodlT("Bitcoin wallet import format (Base58Check).")}</span></span></label>
    <label class="choice"><input type="radio" name="kk" value="hex-key" /><span><strong>${hodlT("Private key hex")}</strong><span class="desc">${hodlT("Raw 32-byte private key as 64 hexadecimal characters.")}</span></span></label>
    <label class="choice"><input type="radio" name="kk" value="minikey" /><span><strong>${hodlT("Mini key")}</strong><span class="desc">${hodlT("Casascius-style short key.")}</span></span></label>
    <label class="choice"><input type="radio" name="kk" value="brain" /><span><strong>${hodlT("Brain wallet")}</strong><span class="desc">${hodlT("Unsafe. SHA-256 of your text, as a single key pair or a 24-word seed.")}</span></span></label>
    </div>
    ${hodlBrainOutputMarkup(hodlKeys[hodlActiveKey]?.brainWalletOutput || "scalar")}
    <div id="private-key-entry">
    <p class="label" id="private-key-input-label">${hodlT("Private key or recovery passphrase")}</p>
    <p class="muted" id="private-key-input-help">${hodlT("Enter the value matching the selected format. Brain wallet text is hashed with SHA-256.")}</p>
    ${hodlPrivateKeyKeyboardToggleMarkup()}
    <div class="dice-input-shell private-key-input-shell"><pre class="dice-input-highlight" id="private-key-highlight" aria-hidden="true"></pre><textarea id="key" placeholder="${hodlT("5… / K… / L…")}" aria-labelledby="private-key-input-label" aria-describedby="private-key-input-help private-key-meta"></textarea></div><p class="muted" id="private-key-meta" aria-live="polite"></p><div class="passphrase-keyboard-host" id="private-keyboard-host" hidden></div></div>`;
  hodlBindKeyFields();
  hodlRenderPassphraseKeyboard();
}
function hodlUpdateDice() {
  let input = document.getElementById("dice");
  if (!input) return;
  let wordsBox = document.getElementById("dice-words"), picker = document.getElementById("last-words"), config = hodlSeedConfig(), inputState = hodlRenderDiceInputState(input), invalidStatus = inputState.invalidCount ? hodlT(" · {n} invalid input(s) highlighted", { n: inputState.invalidCount }) : "";
  if (hodlDiceMethod !== "bitbox" && inputState.coinDerivedCount) invalidStatus += hodlT(" · coin-button digits are BitBox-only");
  if (hodlDiceMethod === "dplus") {
    let result = inputState.dplus || hodlDPlusRolls(input.value, config.words),
      status = "",
      selectingFinal = result.waiting === "last-word",
      d16Range = "0\u2013F";
    if (hodlPickedLastWord && (!selectingFinal || !result.candidates.includes(hodlPickedLastWord))) {
      hodlPickedLastWord = "";
      let state = hodlKeys[hodlActiveKey];
      if (state) state.dplusLastWord = "";
    }
    let selectedFinal = selectingFinal ? hodlPickedLastWord : "",
      complete = result.complete || Boolean(selectedFinal);
    let rollPhrase = "",
      rollRange = "",
      groupsEntered = `Group ${result.completedGroups} of ${config.partialWords} \xB7 word ${result.activeGroupIndex+1}`,
      rollsComplete = `${config.partialWords} of ${config.partialWords} word rolls complete`;
    if (result.waiting === "d8") {
      status = groupsEntered;
      rollPhrase = hodlT("D8 roll");
      rollRange = hodlT(" (1–8)");
    } else if (result.waiting === "d16-first") {
      status = groupsEntered;
      rollPhrase = hodlT("first D16 roll");
      rollRange = hodlT(" (0–F)");
    } else if (result.waiting === "d16-second") {
      status = groupsEntered;
      rollPhrase = hodlT("second D16 roll");
      rollRange = hodlT(" (0–F)");
    } else if (result.waiting === "correction") {
      let invalid = result.firstInvalid,
        specSteps = hodlDPlusFinalSteps(config.words),
        position = invalid?.final ? hodlDPlusStepChecksumLabel(specSteps[invalid.position]) : `word ${(invalid?.groupIndex??0)+1}'s ${invalid?.position===0?"D8":invalid?.position===1?"first D16":"second D16"} roll`;
      status = `Group ${result.completedGroups} of ${config.partialWords} \xB7 correct ${result.invalidRequiredCount} highlighted invalid result${result.invalidRequiredCount===1?"":"s"}, starting with ${position}`
    } else if (selectingFinal) status = selectedFinal ? `${config.words} of ${config.words} seed words \xB7 checksum valid \xB7 ready to derive` : `${rollsComplete} \xB7 choose the final checksum word`;
    else if (result.waiting === "checksum-d8") {
      status = rollsComplete;
      rollPhrase = hodlT("final D8 checksum roll");
      rollRange = hodlT(" (1–8)");
    } else if (result.waiting === "checksum-d16") {
      status = rollsComplete;
      rollPhrase = hodlT("final D16 checksum roll");
      rollRange = hodlT(" (0–F)");
    } else if (result.waiting === "checksum-coin") {
      status = rollsComplete;
      rollPhrase = hodlT("final D8 as a coin flip");
      rollRange = hodlT(" (1–4 Heads, 5–8 Tails)");
    } else status = hodlT("{words} of {words} seed words · checksum valid · ready to derive", { words: config.words });
    let statusTail = result.extraAfter ? hodlT(" · {n} extra input(s) ignored", { n: result.extraAfter }) : "";
    let displayWords = result.wordSlots.slice();
    if (result.finalWord) displayWords.push(result.finalWord);
    else if (selectedFinal) displayWords.push(selectedFinal);
    hodlRenderDiceWordGrid(wordsBox, displayWords, config.words, false);
    hodlRenderManualCalculations("dice-manual-calculations", "dplus", input.value, config.words);
    hodlRenderLastWordPicker(picker, selectingFinal ? result.candidates : [], selectedFinal, (word) => {
      hodlPickedLastWord = word;
      let state = hodlKeys[hodlActiveKey];
      if (state) state.dplusLastWord = hodlPickedLastWord;
      hodlUpdateDice();
    }, { forceSelect: true, targetWords: config.words, placeholder: hodlT("Choose {article} {n}th word", { article: hodlT(config.words === 18 ? "an" : "a"), n: config.words }) });
    let meta = hodlElement("#dice-meta");
    meta.replaceChildren(document.createTextNode(status));
    // The next roll is the one thing to act on, so it carries the weight.
    if (rollPhrase) {
      let emphasis = document.createElement("strong");
      emphasis.textContent = rollPhrase;
      let accessibleRange = document.createElement("span");
      accessibleRange.className = "sr-only";
      accessibleRange.textContent = rollRange;
      meta.append(document.createTextNode(" \xB7 "), emphasis, accessibleRange)
    }
    meta.append(document.createTextNode(statusTail + invalidStatus));
    meta.className = "muted" + (complete && !result.invalidCount ? " ok" : result.invalidCount ? " err" : "");
    hodlRenderDiceFairness(input.value, hodlDiceMethod, config.words);
    hodlQueueMasterFingerprintPreview();
    return;
  }
  if (hodlDiceMethod === "bitbox") {
    let result = hodlBitBoxRolls(input.value, config.words), status = result.waiting === "last-word" ? hodlT("{n} words · choose the final checksum word", { n: result.words.length }) : result.waiting === "coin" ? hodlT("Word {word} of {partial} · 6th die (interpreted as a coin flip)", { word: result.words.length + 1, partial: result.neededPartial }) : hodlT("Word {word} of {partial} · die {die} of 5 (faces 1–4)", { word: result.words.length + 1, partial: result.neededPartial, die: result.diceInWord + 1 });
    if (result.extraAfter) status += hodlT(" · {n} extra input(s) ignored", { n: result.extraAfter });
    let last = result.waiting === "last-word" ? hodlTargetLastWords(result.words.join(" "), config.words) : null;
    if (last && !last.error && !last.candidates.includes(hodlPickedLastWord)) hodlPickedLastWord = "";
    if (!last || last.error) hodlPickedLastWord = "";
    let displayWords = result.words.slice();
    if (result.waiting === "last-word" && last && !last.error && hodlPickedLastWord) displayWords.push(hodlPickedLastWord);
    hodlElement("#dice-meta").textContent = status + invalidStatus;
    hodlRenderDiceWordGrid(wordsBox, displayWords, config.words, false);
    hodlRenderManualCalculations("dice-manual-calculations", "bitbox", input.value, config.words);
    hodlRenderLastWordPicker(picker, last && !last.error ? last.candidates : [], hodlPickedLastWord, (word) => {
      hodlPickedLastWord = word;
      let state = hodlKeys[hodlActiveKey];
      if (state) state.lastWord = hodlPickedLastWord;
      hodlUpdateDice();
    }, { forceSelect: true, targetWords: config.words, placeholder: hodlT("Choose {article} {n}th word", { article: hodlT(config.words === 18 ? "an" : "a"), n: config.words }) });
    hodlRenderDiceFairness(input.value, hodlDiceMethod, config.words);
    hodlQueueMasterFingerprintPreview();
    return;
  }
  if (picker) picker.innerHTML = "";
  let rolls = inputState.acceptedRolls, words = hodlDicePreviewWords(input.value, hodlDiceMethod, config.words);
  let missing = Math.max(0, config.hashRolls - rolls.length), provisional = rolls.length > 0 && missing > 0, extra = Math.max(0, rolls.length - config.hashRolls), methodLabel = hodlDiceMethod === "coleman" ? hodlT("Hashed rolls / Dice [1-6]") : hodlT("Hashed rolls / Base 10 [0-9]");
  hodlRenderDiceWordGrid(wordsBox, words, config.words, provisional);
  hodlElement("#dice-meta").textContent = (!rolls.length ? hodlTText("0 of {n} recommended rolls · 0.0 bits estimated · {method}", { n: config.hashRolls, method: methodLabel }) : missing ? hodlTText("{have} of {n} recommended rolls · {bits} bits estimated · seed available for testing · {missing} more recommended", { have: rolls.length, n: config.hashRolls, bits: hodlDiceEntropyBits(rolls.length).toFixed(1), missing }) : hodlTText("{have} roll(s) · {bits} bits estimated · ready to derive", { have: rolls.length, bits: hodlDiceEntropyBits(rolls.length).toFixed(1) }) + (extra ? hodlTText(" · all {n} extra roll(s) included", { n: extra }) : "")) + invalidStatus;
  hodlRenderDiceFairness(input.value, hodlDiceMethod, config.words);
  hodlQueueMasterFingerprintPreview();
}
function hodlPrivateKeyCharacterEntries(value) {
  let entries = [];
  for (let index = 0; index < String(value ?? "").length; ) {
    let character = String.fromCodePoint(String(value).codePointAt(index)), end = index + character.length;
    if (!/\s/.test(character)) entries.push({ character, start: index, end });
    index = end;
  }
  return entries;
}
function hodlPrivateKeyInputAnalysis(value, kind, network, trimBrainWallet = hodlBrainWalletTrimEnabled()) {
  let selected = hodlNormalizePrivateKeyKind(kind, value), entries = hodlPrivateKeyCharacterEntries(value), invalidRanges = [], ready = false, status = "", first = entries[0], last = entries.at(-1), markAll = () => {
    if (first && last) invalidRanges.push([first.start, last.end]);
  };
  if (selected === "brain") {
    let exact = String(value ?? ""), hasBoundaryWhitespace = exact !== exact.trim();
    try {
      hodlBrainWalletPassphrase(exact, trimBrainWallet);
      ready = true;
    } catch {
      ready = false;
    }
    let convention = trimBrainWallet ? hasBoundaryWhitespace ? "boundary whitespace will be trimmed" : "trim enabled; no boundary whitespace present" : hasBoundaryWhitespace ? "exact text will be used, including boundary whitespace" : "exact text will be used";
    let status = exact.length ? ready ? `Text entered \xB7 ${convention} \xB7 brain wallets are unsafe` : "Boundary whitespace trimming leaves an empty passphrase \xB7 enter non-whitespace text or turn trimming off" : "No text entered \xB7 brain wallets are unsafe";
    return { invalidRanges, ready, status, kind: selected };
  }
  if (selected === "hex-key") {
    let prefixed = entries[0]?.character === "0" && /^x$/i.test(entries[1]?.character || ""), characters = entries.slice(prefixed ? 2 : 0), valid = characters.filter((entry) => /^[0-9a-fA-F]$/.test(entry.character)), invalid2 = characters.filter((entry) => !/^[0-9a-fA-F]$/.test(entry.character)), excess2 = valid.slice(64);
    invalidRanges.push(...invalid2.map((entry) => [entry.start, entry.end]), ...excess2.map((entry) => [entry.start, entry.end]));
    let count2 = valid.length, remaining = Math.max(0, 64 - count2), parts2 = [count2 > 64 ? `${count2} hexadecimal characters entered \xB7 64 required` : `${count2} of 64 hexadecimal characters entered \xB7 ${remaining} remaining`];
    if (invalid2.length) parts2.push(`${invalid2.length} invalid character${invalid2.length === 1 ? "" : "s"} highlighted \xB7 use only 0\u20139 and a\u2013f`);
    if (excess2.length) parts2.push(`${excess2.length} extra highlighted \xB7 remove to continue`);
    if (!invalid2.length && !excess2.length && count2 === 64) try {
      hodlAssertPrivateKeyKind(value, network, selected);
      ready = true;
      parts2 = ["64 of 64 hexadecimal characters entered", "valid secp256k1 private key", "ready to derive"];
    } catch (error) {
      markAll();
      parts2.push(error.message || "Invalid private key");
    }
    status = parts2.join(" \xB7 ");
    return { invalidRanges, ready, status, kind: selected, count: count2, required: 64, remaining };
  }
  if (selected === "wif") {
    let alphabet = /^[1-9A-HJ-NP-Za-km-z]$/, prefixes = network === "testnet" ? ["9", "c"] : ["5", "K", "L"], invalid2 = entries.filter((entry) => !alphabet.test(entry.character));
    if (first && !prefixes.includes(first.character) && !invalid2.includes(first)) invalid2.push(first);
    let required2 = first && ["5", "9"].includes(first.character) ? 51 : first && ["K", "L", "c"].includes(first.character) ? 52 : null, count2 = entries.length, excess2 = required2 ? entries.slice(required2) : [];
    invalidRanges.push(...invalid2.map((entry) => [entry.start, entry.end]), ...excess2.map((entry) => [entry.start, entry.end]));
    let parts2 = [required2 ? count2 > required2 ? `${count2} WIF characters entered \xB7 ${required2} required` : `${count2} of ${required2} WIF characters entered \xB7 ${Math.max(0, required2 - count2)} remaining` : `${count2} of 51 or 52 WIF characters entered \xB7 starts with ${network === "testnet" ? "9 or c" : "5, K, or L"}`];
    if (invalid2.length) parts2.push(`${invalid2.length} invalid character${invalid2.length === 1 ? "" : "s"} highlighted \xB7 use ${network} Base58 WIF characters`);
    if (excess2.length) parts2.push(`${excess2.length} extra highlighted \xB7 remove to continue`);
    if (required2 && count2 === required2 && !invalid2.length && !excess2.length) try {
      hodlAssertPrivateKeyKind(value, network, selected);
      ready = true;
      parts2 = [`${required2} of ${required2} WIF characters entered`, `${network} checksum valid`, `ready to derive`];
    } catch (error) {
      markAll();
      parts2.push(error.message || "Invalid WIF checksum");
    }
    status = parts2.join(" \xB7 ");
    return { invalidRanges, ready, status, kind: selected, count: count2, required: required2, remaining: required2 ? Math.max(0, required2 - count2) : null };
  }
  let invalid = entries.filter((entry, index) => index === 0 ? entry.character !== "S" : !/^[1-9A-HJ-NP-Za-km-z]$/.test(entry.character)), count = entries.length, required = count <= 22 ? 22 : 30, excess = entries.slice(30);
  invalidRanges.push(...invalid.map((entry) => [entry.start, entry.end]), ...excess.map((entry) => [entry.start, entry.end]));
  let parts = [count > 30 ? `${count} Mini-key characters entered \xB7 30 maximum` : `${count} of ${required} Mini-key characters entered \xB7 ${Math.max(0, required - count)} remaining`];
  if (!count) parts = ["0 of 22 or 30 Mini-key characters entered \xB7 must start with S"];
  if (invalid.length) parts.push(`${invalid.length} invalid character${invalid.length === 1 ? "" : "s"} highlighted \xB7 use S followed by Bitcoin Base58 characters`);
  if (excess.length) parts.push(`${excess.length} extra highlighted \xB7 remove to continue`);
  if ((count === 22 || count === 30) && !invalid.length && !excess.length) try {
    hodlAssertPrivateKeyKind(value, network, selected);
    ready = true;
    parts = [`${count} of ${count} Mini-key characters entered`, `checksum valid`, `ready to derive`];
  } catch (error) {
    markAll();
    parts.push(error.message || "Invalid Mini-key checksum");
  }
  status = parts.join(" \xB7 ");
  return { invalidRanges, ready, status, kind: selected, count, required, remaining: Math.max(0, required - count) };
}
function hodlRenderPrivateKeyInputState(input) {
  if (!input) return null;
  let kind = hodlNormalizePrivateKeyKind(document.querySelector('input[name="kk"]:checked')?.value, input.value), network = hodlSelectedNetwork(document.getElementById("network")), analysis = hodlPrivateKeyInputAnalysis(input.value, kind, network), meta = document.getElementById("private-key-meta"), invalid = analysis.invalidRanges.length > 0;
  input.classList.toggle("bad", invalid);
  input.setAttribute("aria-invalid", String(invalid));
  hodlRenderInputHighlight(input, analysis.invalidRanges);
  if (meta) {
    meta.textContent = analysis.status;
    meta.className = "muted" + (analysis.ready ? " ok" : invalid || kind === "brain" && input.value.length ? " err" : "");
  }
  return analysis;
}
function hodlBindKeyFields() {
  let dice = document.getElementById("dice");
  if (dice) {
    dice.setAttribute("inputmode", hodlDiceMethod === "dplus" ? "text" : "numeric");
    dice.setAttribute("autocapitalize", hodlDiceMethod === "dplus" ? "characters" : "off");
    dice.setAttribute("autocomplete", "off");
    dice.setAttribute("spellcheck", "false");
    dice.onbeforeinput = (event) => {
      if (hodlDiceMethod === "dplus") hodlHandleGroupedSeparatorDelete(dice, event);
      else hodlRememberDiceBeforeInput(dice, event);
    };
  }
  let format = hodlNormalizeEntropyFormat(hodlEntropyFormat), entropy = document.getElementById(format);
  if (entropy) {
    let definition = hodlEntropyFormats[format], update = () => {
      hodlApplyFilteredInput(entropy, (value) => hodlFilterNumberBase(value, format));
      if (format === "bin") hodlFormatBinaryInput(entropy);
      hodlUpdateEntropyInput(entropy, format, hodlTargetWordCount);
    };
    entropy.setAttribute("inputmode", definition.base <= 10 ? "numeric" : "text");
    entropy.setAttribute("spellcheck", "false");
    if (format === "bin") entropy.onbeforeinput = (event) => hodlHandleBinarySeparatorDelete(entropy, event);
    entropy.oninput = () => update();
    entropy.onscroll = () => hodlSyncDiceHighlight(entropy);
    update("");
  }
  let key = document.getElementById("key");
  if (key) {
    let state = hodlKeys[hodlActiveKey], values = hodlPrivateKeyValues(state?.fields || {}), selected = document.querySelector("input[name=kk]:checked"), initialKind = hodlNormalizePrivateKeyKind(selected?.value, "");
    key.dataset.privateKeyKind = initialKind;
    key.value = values[initialKind] || "";
    let apply = (event) => {
      let selected2 = document.querySelector("input[name=kk]:checked"), kind = hodlNormalizePrivateKeyKind(selected2?.value, key.value), pasted = event?.inputType === "insertFromPaste";
      if (pasted && kind !== "brain") {
        let detected = hodlDetectPrivateKeyKind(key.value);
        if (detected && detected !== kind) {
          let radio = document.querySelector(`input[name="kk"][value="${detected}"]`);
          if (radio) {
            radio.checked = true;
            kind = detected;
          }
        }
      }
      if (kind !== "brain") key.value = hodlFilterKey(key.value, kind);
      key.dataset.privateKeyKind = kind;
      values[kind] = key.value;
      if (state) {
        state.fields.keyKind = kind;
        state.fields.key = "";
      }
      hodlUpdatePrivateKeyInputPresentation();
      hodlRenderPrivateKeyInputState(key);
      hodlUpdatePrivateKeyKeyboardKeys(key);
    };
    let change = (event) => {
      if (!event.currentTarget.checked) return;
      let previousKind = hodlNormalizePrivateKeyKind(key.dataset.privateKeyKind || "wif", key.value), nextKind = hodlNormalizePrivateKeyKind(event.currentTarget.value, "");
      values[previousKind] = key.value;
      key.dataset.privateKeyKind = nextKind;
      key.value = values[nextKind] || "";
      apply();
      key.setSelectionRange(key.value.length, key.value.length);
    };
    key.oninput = apply;
    key.onscroll = () => hodlSyncDiceHighlight(key);
    document.querySelectorAll("input[name=kk]").forEach((radio) => {
      radio.addEventListener("input", change);
      radio.addEventListener("change", change);
    });
    let refreshBrain = () => {
      hodlSyncBrainOutput();
      hodlUpdateKeyModeControls();
      hodlRenderPassphraseKeyboard();
      hodlUpdateDerivationPathPreview();
      hodlRenderPrivateKeyInputState(key);
      hodlSyncKeyClearButton();
      hodlSyncDeriveButton();
    };
    document.querySelectorAll('input[name="bo"]').forEach((radio) => radio.addEventListener("change", () => {
      if (state) state.brainWalletOutput = hodlBrainWalletOutput();
      hodlInvalidateLiveKeyResult();
      refreshBrain();
    }));
    let ack = document.getElementById("brain-lab-ack");
    if (ack) ack.onchange = () => {
      let output = hodlBrainWalletOutput();
      hodlBrainLabAck[output] = ack.checked;
      if (!ack.checked) hodlRetractBrainWalletResults(output);
      hodlInvalidateLiveKeyResult();
      refreshBrain();
    };
    document.getElementById("network")?.addEventListener("change", apply);
    let trim = document.getElementById("brain-wallet-trim");
    if (trim) trim.onchange = () => {
      if (state) state.brainWalletTrim = trim.checked;
      hodlSyncBrainOutput();
      hodlRenderPrivateKeyInputState(key);
      hodlSyncKeyClearButton();
      hodlSyncDeriveButton();
    };
    apply();
  }
}
function hodlSelectedEntropy(targetWords = hodlTargetWordCount) {
  let format = hodlNormalizeEntropyFormat(hodlEntropyFormat), value = document.getElementById(format)?.value.trim() || "";
  return hodlNumberBaseEntropy(value, format, targetWords);
}
function hodlPrivateKeyInputIsValid() {
  let input = document.getElementById("key"), value = input?.value ?? "";
  if (!value.length) return false;
  let kind = hodlNormalizePrivateKeyKind(document.querySelector("input[name=kk]:checked")?.value, value);
  try {
    hodlAssertPrivateKeyKind(value, hodlSelectedNetwork(document.getElementById("network")), kind, hodlBrainWalletTrimEnabled());
    return true;
  } catch {
    return false;
  }
}
function hodlCanDeriveCurrentKey() {
  try {
    let derivationPlan = null;
    if (hodlKeyMode !== "key") {
      derivationPlan = hodlReadDerivationPlan();
      hodlReadBranchWindow();
      hodlReadAddressWindow();
      let passphrase = document.getElementById("pass");
      if (hodlPassphraseBip39Enabled() && passphrase?.value) {
        let passphraseAnalysis = hodlAnalyzeBip39Passphrase(passphrase.value);
        if (passphraseAnalysis.invalidRanges.length || passphraseAnalysis.incomplete || passphraseAnalysis.trailingSeparator) return false;
      }
    } else hodlReadCoinType(document.getElementById("network"));
    if (hodlKeyMode === "dice") {
      let input = document.getElementById("dice");
      if (!input) return false;
      let analysis = hodlAnalyzeDiceInput(input.value, hodlDiceMethod, hodlTargetWordCount);
      if (analysis.invalidCount || analysis.coinDerivedCount) return false;
      if (hodlDiceMethod === "dplus") {
        let rollsFinalWord = !0,
          parsed = analysis.dplus || hodlDPlusRolls(input.value, hodlTargetWordCount),
          finalWord = rollsFinalWord ? parsed.finalWord : hodlPickedLastWord;
        if (rollsFinalWord) {
          if (!parsed.complete) return !1
        } else if (!parsed.allRolledValid || parsed.waiting !== "last-word" || !parsed.candidates.includes(finalWord)) return !1;
        return hodlValidateTargetMnemonic([...parsed.wordSlots, finalWord].join(" "), hodlTargetWordCount).ok
      }
      if (hodlDiceMethod === "bitbox") {
        let parsed = hodlBitBoxRolls(input.value, hodlTargetWordCount);
        if (parsed.leftover || parsed.extraAfter || parsed.waiting !== "last-word" || !hodlPickedLastWord) return false;
        let possible = hodlTargetLastWords(parsed.words.join(" "), hodlTargetWordCount);
        if (!possible?.candidates.includes(hodlPickedLastWord)) return false;
        return hodlValidateTargetMnemonic([...parsed.words, hodlPickedLastWord].join(" "), hodlTargetWordCount).ok;
      }
      return hodlDiceEntropy(input.value, hodlDiceMethod, hodlTargetWordCount).ok;
    }
    if (hodlKeyMode === "cards") {
      return hodlSelectedCardsEntropy(hodlTargetWordCount).ok;
    }
    if (hodlKeyMode === "hex") return hodlSelectedEntropy().ok;
    if (hodlKeyMode === "seed") {
      let selected = hodlSelectedSeedInput(hodlTargetWordCount), value = selected.value;
      if (!value) return false;
      if (selected.extended) {
        if (!hodlUsableSinglesigImport(value, derivationPlan?.network ?? hodlSelectedNetwork(document.getElementById("network")))) return false;
        let parsed = hodlParseExtendedKey(value);
        if (parsed.node.depth === 0 && !parsed.isPrivate && (derivationPlan?.hasHardenedPrefix || derivationPlan?.hardening.branch || derivationPlan?.hardening.address)) return false;
        if (hodlReadHardening().address && parsed.node.depth > 0 && !parsed.isPrivate) return false;
        return true;
      }
      return hodlValidateTargetMnemonic(value, hodlTargetWordCount).ok;
    }
    if (hodlKeyMode === "key" && hodlNormalizePrivateKeyKind(document.querySelector('input[name="kk"]:checked')?.value, document.getElementById("key")?.value || "") === "brain") {
      if (!hodlBrainAcked()) return false;
      if (hodlBrainWalletOutput() === "hd") return hodlBrainLabEntropy(hodlBrainWalletText(document.getElementById("key")?.value)).ok;
    }
    return hodlPrivateKeyInputIsValid();
  } catch {
    return false;
  }
}
function hodlSyncDeriveButton() {
  let button = document.getElementById("go");
  if (!button) return;
  if (hodlActiveDerivation) {
    if (hodlActiveDerivation.kind === "key") {
      hodlSetDerivationButtonState("key", hodlActiveDerivation.cancelled ? "stopping" : "running");
      return;
    }
    hodlSetDerivationButtonState("key", "idle");
    button.disabled = true;
    button.setAttribute("aria-disabled", "true");
    button.title = hodlTText("A derivation is already running.");
    return;
  }
  hodlSetDerivationButtonState("key", "idle");
  button.disabled = !hodlCanDeriveCurrentKey();
  button.title = "";
  button.setAttribute("aria-disabled", String(button.disabled));
}
var hodlMasterFingerprintTimer = 0, hodlMasterFingerprintRevision = 0;
function hodlFingerprintMnemonic() {
  try {
    if (hodlKeyMode === "dice") {
      let input = document.getElementById("dice");
      if (!input) return null;
      if (hodlDiceMethod === "dplus") {
        let rollsFinalWord = !0,
          parsed = hodlDPlusRolls(input.value, hodlTargetWordCount),
          finalWord = rollsFinalWord ? parsed.finalWord : hodlPickedLastWord;
        if (!parsed.allRolledValid || parsed.invalidRequiredCount || (rollsFinalWord ? !parsed.complete : parsed.waiting !== "last-word" || !parsed.candidates.includes(finalWord))) return null;
        let validation = hodlValidateTargetMnemonic([...parsed.wordSlots, finalWord].join(" "), hodlTargetWordCount);
        return validation.ok ? validation.words.join(" ") : null;
      }
      if (hodlDiceMethod === "bitbox") {
        let parsed = hodlBitBoxRolls(input.value, hodlTargetWordCount);
        if (parsed.leftover || parsed.waiting !== "last-word" || !hodlPickedLastWord) return null;
        let possible = hodlTargetLastWords(parsed.words.join(" "), hodlTargetWordCount);
        if (!possible?.candidates.includes(hodlPickedLastWord)) return null;
        let validation = hodlValidateTargetMnemonic([...parsed.words, hodlPickedLastWord].join(" "), hodlTargetWordCount);
        return validation.ok ? validation.words.join(" ") : null;
      }
      if (hodlAnalyzeDiceInput(input.value, hodlDiceMethod, hodlTargetWordCount).coinDerivedCount) return null;
      let entropy = hodlDiceEntropy(input.value, hodlDiceMethod, hodlTargetWordCount);
      return entropy.ok ? hodlEntropyToMnemonic(entropy.bytes, hodlBip39Wordlist) : null;
    }
    if (hodlKeyMode === "cards") {
      let entropy = hodlSelectedCardsEntropy(hodlTargetWordCount);
      return entropy.ok ? hodlEntropyToMnemonic(entropy.bytes, hodlBip39Wordlist) : null;
    }
    if (hodlKeyMode === "hex") {
      let entropy = hodlSelectedEntropy();
      return entropy.ok ? hodlEntropyToMnemonic(entropy.bytes, hodlBip39Wordlist) : null;
    }
    if (hodlKeyMode === "seed") {
      let selected = hodlSelectedSeedInput(hodlTargetWordCount), value = selected.value;
      if (!value || selected.extended) return null;
      let validation = hodlValidateTargetMnemonic(value, hodlTargetWordCount);
      return validation.ok ? validation.words.join(" ") : null;
    }
  } catch {
  }
  return null;
}
function hodlMasterFingerprint(mnemonic, passphrase = "") {
  let seed = hodlMnemonicToSeed(mnemonic, passphrase);
  try {
    return hodlFingerprintHex(hodlHDKey.fromMasterSeed(seed).fingerprint);
  } finally {
    seed.fill(0);
  }
}
function hodlSetMasterFingerprintCard(card, valueNode, value, imageNode) {
  let available = typeof value === "string" && value.length > 0, label = `${card.querySelector(".master-fingerprint-label")?.textContent.trim() || ""} master fingerprint`.trim();
  valueNode.textContent = available ? value : "";
  if (imageNode) {
    imageNode.hidden = true;
    imageNode.removeAttribute("src");
    if (available) {
      // LifeHash is deterministic per fingerprint; show it only once resolved.
      hodlLifeHash.fromFingerprint(value).then((url) => {
        if (valueNode.textContent === value) {
          imageNode.src = url;
          imageNode.hidden = false;
        }
      }).catch(() => { imageNode.hidden = true; });
    }
  }
  card.classList.toggle("is-disabled", !available);
  card.dataset.state = available ? "ready" : "unavailable";
  card.setAttribute("aria-label", available ? `${label}: ${value}` : `${label} unavailable`);
  return available;
}
function hodlRenderMasterFingerprintPreview(revision = hodlMasterFingerprintRevision) {
  if (revision !== hodlMasterFingerprintRevision) return;
  let preview = document.getElementById("master-fingerprint-preview"), baseCard = document.getElementById("base-master-fingerprint-card"), base = document.getElementById("base-master-fingerprint"), baseImage = document.getElementById("base-master-fingerprint-lifehash"), arrow = document.getElementById("master-fingerprint-arrow"), passphraseCard = document.getElementById("passphrase-master-fingerprint-card"), passphraseValue = document.getElementById("passphrase-master-fingerprint"), passphraseImage = document.getElementById("passphrase-master-fingerprint-lifehash"), pass = document.getElementById("pass");
  if (!preview || !baseCard || !base || !arrow || !passphraseCard || !passphraseValue || !pass) return;
  if (hodlKeyMode === "key") {
    preview.hidden = true;
    return;
  }
  preview.hidden = false;
  arrow.hidden = false;
  passphraseCard.hidden = false;
  let clear = () => {
    hodlSetMasterFingerprintCard(baseCard, base, "", baseImage);
    hodlSetMasterFingerprintCard(passphraseCard, passphraseValue, "", passphraseImage);
    arrow.classList.add("is-disabled");
  };
  let mnemonic = hodlFingerprintMnemonic();
  if (!mnemonic) {
    clear();
    return;
  }
  try {
    hodlSetMasterFingerprintCard(baseCard, base, hodlMasterFingerprint(mnemonic), baseImage);
  } catch {
    clear();
    return;
  }
  let value = "";
  if (pass.value.length > 0) try {
    value = hodlMasterFingerprint(mnemonic, pass.value);
  } catch {
  }
  let available = hodlSetMasterFingerprintCard(passphraseCard, passphraseValue, value, passphraseImage);
  arrow.classList.toggle("is-disabled", !available);
}
function hodlQueueMasterFingerprintPreview(delay = 90) {
  let revision = ++hodlMasterFingerprintRevision;
  clearTimeout(hodlMasterFingerprintTimer);
  if (delay <= 0) {
    hodlRenderMasterFingerprintPreview(revision);
    return;
  }
  hodlMasterFingerprintTimer = setTimeout(() => hodlRenderMasterFingerprintPreview(revision), delay);
}
function hodlInvalidateLiveKeyResult() {
  let state = hodlKeys[hodlActiveKey];
  if (!state) return;
  state.result = null;
  state.reveal = false;
  hodlWalletResult = null;
  hodlRevealPrivate = false;
  hodlOutEl.innerHTML = "";
  hodlStopDerivation("key");
  hodlResetDerivationProgress("key");
}
// Revoking the acknowledgement retracts every wallet it authorised. Committed
// key tabs re-render their stored result without asking again, so the material
// has to leave those slots too, not just the lab that produced it.
function hodlRetractBrainWalletResults(output) {
  for (let state of hodlKeys) {
    if (state?.result?.brainWalletOutput !== output) continue;
    state.result = null;
    state.reveal = false;
  }
}
function hodlInitMasterFingerprintPreview() {
  let panel = document.getElementById("calc-card"), pass = document.getElementById("pass");
  if (!panel || !pass) return;
  panel.addEventListener("input", (event) => {
    let id = event.target?.id;
    if (!["pass", "dice", "hex", "bin", "base4", "base8", "base32", "base64", "seed", "seed-numbers", "cards", "direct-cards", "brain-lab", "key"].includes(id)) return;
    if (id === "pass") {
      let state = hodlKeys[hodlActiveKey];
      hodlAutocompletePassphraseInput(pass, event);
      if (state) state.fields.pass = pass.value;
      hodlRenderPassphraseInputState(pass);
    }
    if (id !== "pass" && !event.target?.hodlRestoring) hodlGlobalSyncFromCurrentInput();
    hodlInvalidateLiveKeyResult();
    hodlQueueMasterFingerprintPreview();
  });
  panel.addEventListener("keydown", (event) => {
  });
  ["focus", "blur"].forEach((type) => pass.addEventListener(type, () => hodlRenderPassphraseInputState(pass)));
  panel.addEventListener("change", (event) => {
    let target = event.target;
    if (!(target instanceof Element) || !target.matches('input[name="dm"], input[name="card-method"], input[name="seed-method"], input[name="kk"], #seed-zero-index, input[name="entropy-format"], select[aria-label^="Valid final word"]')) return;
    hodlInvalidateLiveKeyResult();
    hodlRenderGlobalSyncControl();
    hodlQueueMasterFingerprintPreview();
  });
  panel.addEventListener("click", event => {
    let target = event.target instanceof Element ? event.target.closest("#modes .custom-select-option, #seed-length .custom-select-option, [data-d], [data-lw], [data-card-suit], [data-card-rank], [data-direct-card-rank], #card-undo") : null;
    if (!target) return;
    // Pads and pickers that mutate an input without a bubbling "input" event
    // still re-run the sync: [data-d] writes the dice textarea directly,
    // #card-undo trims the card transcript, and [data-lw] picks the checksum
    // word. Seed-length buttons are excluded on purpose: they only change the
    // bit width, and re-syncing there could clear every destination when the
    // active method (e.g. an empty direct transcript) has nothing to publish.
    if (target.matches("[data-lw], [data-d], #card-undo")) hodlGlobalSyncFromCurrentInput();
    hodlInvalidateLiveKeyResult();
    hodlQueueMasterFingerprintPreview();
  });
  hodlQueueMasterFingerprintPreview(0);
}
function hodlThrowIfFailed(result) {
  if (result?.ok) return;
  let error = result.error;
  if (error && typeof error === "object" && typeof error.key === "string") throw hodlError(error.key, error.vars);
  throw new Error(typeof error === "string" && error ? error : hodlT("Could not calculate"));
}
async function hodlCalculateKey(progress) {
  hodlSetWorkspaceError("key", null);
  // A fresh derivation restores the safe wallet.dat birthday default (scan
  // from genesis) so a previous "new keys" choice cannot leak into a
  // recovery export.
  hodlWalletDatBirthday = "genesis";
  try {
    let derivationPlan = hodlKeyMode === "key" && !hodlBrainHdActive() ? null : hodlReadDerivationPlan(), coinType = derivationPlan?.coinType ?? hodlReadCoinType(document.getElementById("network")), network = derivationPlan?.network ?? hodlNetworkFromCoinType(coinType), addressWindow = hodlKeyMode === "key" ? { start: 0, range: 1 } : hodlReadAddressWindow(), branchWindow = hodlKeyMode === "key" ? { start: 0, range: 2 } : hodlReadBranchWindow(), count = addressWindow.range, addressStart = addressWindow.start, branchStart = branchWindow.start, branchRange = branchWindow.range, passphrase = document.getElementById("pass").value, scriptType = hodlSelectedScriptType(), purpose = derivationPlan?.purpose ?? 84, account = derivationPlan?.accountIndex ?? 0, hardening = derivationPlan?.hardening ?? hodlDefaultHardening();
    if ((hodlKeyMode !== "key" || hodlBrainHdActive()) && hodlPassphraseBip39Enabled() && passphrase) {
      let passphraseAnalysis = hodlAnalyzeBip39Passphrase(passphrase);
      if (passphraseAnalysis.invalidRanges.length || passphraseAnalysis.incomplete || passphraseAnalysis.trailingSeparator) throw hodlError("Correct the highlighted BIP39-word passphrase inconsistencies before deriving.");
    }
    if (hodlKeyMode === "dice") {
      if (hodlDiceMethod === "dplus") {
        let parsed = hodlDPlusRolls(document.getElementById("dice").value, hodlTargetWordCount);
        if (parsed.firstInvalid) {
          let invalid = parsed.firstInvalid,
            specSteps = hodlDPlusFinalSteps(hodlTargetWordCount),
            position = invalid.final ? hodlDPlusStepChecksumLabel(specSteps[invalid.position]) : hodlT("word {n}'s {roll} roll", { n: invalid.groupIndex + 1, roll: invalid.position === 0 ? "D8" : invalid.position === 1 ? "first D16" : "second D16" });
          throw hodlError("Correct the highlighted invalid result in {position}. Each D++ word keeps its original three-character group.", { position })
        }
        if (parsed.waiting === "d8") throw hodlError("Complete word {n}: roll the D8, then both D16 dice.", { n: parsed.activeGroupIndex + 1 });
        if (parsed.waiting === "d16-first") throw hodlError("Complete word {n}: enter the first D16 roll.", { n: parsed.activeGroupIndex + 1 });
        if (parsed.waiting === "d16-second") throw hodlError("Complete word {n}: enter the second D16 roll.", { n: parsed.activeGroupIndex + 1 });
        if (parsed.waiting === "checksum-d8") throw hodlError("Roll the final D8 to select the checksum word.");
        if (parsed.waiting === "checksum-d16") throw hodlError(hodlDPlusFinalSteps(hodlTargetWordCount).length > 1 ? "Roll the final D16 to continue the checksum pick." : "Roll the final D16 to select the checksum pick.");
        if (parsed.waiting === "checksum-coin") throw hodlError("Roll the final D8 to finish selecting the checksum word: 1–4 is Heads, 5–8 is Tails.");
        let rollsFinalWord = !0,
          finalWord = rollsFinalWord ? parsed.finalWord : hodlPickedLastWord;
        if (!rollsFinalWord && (!finalWord || !parsed.candidates.includes(finalWord))) throw hodlError("Choose one of the {n} valid final checksum words before deriving the wallet.", { n: hodlSeedConfig().candidates });
        if (rollsFinalWord && !parsed.complete) throw hodlError("Complete all D++ rolls before deriving the wallet.");
        let phrase = [...parsed.wordSlots, finalWord].join(" "),
          validation = hodlValidateTargetMnemonic(phrase, hodlTargetWordCount);
        hodlThrowIfFailed(validation);
        let notes = parsed.notes.slice();
        if (!rollsFinalWord) notes.push(`Selected checksum-valid final word: ${finalWord}.`);
        hodlWalletResult = await hodlMnemonicWalletWithProgress(phrase, passphrase, network, count, {
          notes,
          warnings: parsed.warnings
        }, account, addressStart, progress, purpose, coinType, hardening, branchStart, branchRange, derivationPlan)
      } else if (hodlDiceMethod === "bitbox") {
        let parsed = hodlBitBoxRolls(document.getElementById("dice").value, hodlTargetWordCount);
        if (parsed.leftover) throw hodlError("Invalid characters: {chars}", { chars: parsed.leftover });
        if (parsed.waiting !== "last-word") throw hodlError("Need {need} lookup-table words for a {words}-word seed. You have {have}.", { need: parsed.neededPartial, words: hodlTargetWordCount, have: parsed.words.length });
        let possible = hodlTargetLastWords(parsed.words.join(" "), hodlTargetWordCount);
        if (!hodlPickedLastWord || !possible?.candidates.includes(hodlPickedLastWord)) throw hodlError("Choose one of the {n} valid final checksum words before deriving the wallet.", { n: hodlSeedConfig().candidates });
        let phrase = [...parsed.words, hodlPickedLastWord].join(" "), validation = hodlValidateTargetMnemonic(phrase, hodlTargetWordCount);
        hodlThrowIfFailed(validation);
        hodlWalletResult = await hodlMnemonicWalletWithProgress(phrase, passphrase, network, count, { notes: parsed.notes, warnings: parsed.warnings }, account, addressStart, progress, purpose, coinType, hardening, branchStart, branchRange, derivationPlan);
      } else {
        let diceValue = document.getElementById("dice").value;
        if (hodlAnalyzeDiceInput(diceValue, hodlDiceMethod, hodlTargetWordCount).coinDerivedCount) throw hodlError("Coin-button digits are entropy-equivalent only in BitBox mode. Clear them and enter fair die rolls for this conversion method.");
        let entropy = hodlDiceEntropy(diceValue, hodlDiceMethod, hodlTargetWordCount);
        hodlThrowIfFailed(entropy);
        hodlWalletResult = await hodlEntropyWalletWithProgress(entropy, passphrase, network, count, account, addressStart, progress, purpose, coinType, hardening, branchStart, branchRange, derivationPlan);
      }
    } else if (hodlKeyMode === "cards") {
      let entropy = hodlSelectedCardsEntropy(hodlTargetWordCount);
      hodlThrowIfFailed(entropy);
      hodlWalletResult = await hodlEntropyWalletWithProgress(entropy, passphrase, network, count, account, addressStart, progress, purpose, coinType, hardening, branchStart, branchRange, derivationPlan);
    } else if (hodlKeyMode === "hex") {
      let entropy = hodlSelectedEntropy();
      hodlThrowIfFailed(entropy);
      hodlWalletResult = await hodlEntropyWalletWithProgress(entropy, passphrase, network, count, account, addressStart, progress, purpose, coinType, hardening, branchStart, branchRange, derivationPlan);
    } else if (hodlKeyMode === "seed") {
      let selected = hodlSelectedSeedInput(hodlTargetWordCount), value = selected.value;
      if (selected.extended) hodlWalletResult = await hodlImportedWalletWithProgress(value, network, count, account, addressStart, progress, purpose, coinType, hardening, branchStart, branchRange, derivationPlan);
      else {
        if (hodlSeedMethod === "numbers" && !selected.parsed?.complete) throw selected.parsed?.invalidEntries.length ? hodlError("Word numbers must be between {min} and {max}.", { min: selected.parsed.minimum, max: selected.parsed.maximum }) : selected.parsed?.extraEntries.length ? hodlError("Enter exactly {words} BIP39 word numbers.", { words: hodlTargetWordCount }) : selected.parsed?.checksumInvalid ? hodlError("The entered word numbers do not have a valid BIP39 checksum.") : hodlError("Enter exactly {words} BIP39 word numbers before deriving the wallet.", { words: hodlTargetWordCount });
        let validation = hodlValidateTargetMnemonic(value, hodlTargetWordCount);
        hodlThrowIfFailed(validation);
        hodlWalletResult = await hodlMnemonicWalletWithProgress(validation.words.join(" "), passphrase, network, count, void 0, account, addressStart, progress, purpose, coinType, hardening, branchStart, branchRange, derivationPlan);
      }
    } else {
      let value = document.getElementById("key").value, kind = hodlNormalizePrivateKeyKind(document.querySelector("input[name=kk]:checked")?.value, value);
      if (kind === "brain" && !hodlBrainAcked()) throw hodlError("Acknowledge the lab warning before deriving.");
      if (kind === "brain" && hodlBrainWalletOutput() === "hd") {
        // The digest becomes BIP39 entropy rather than the private key itself,
        // which is a different wallet from the same text.
        if (passphrase && document.getElementById("passphrase-field")?.hidden) throw hodlError("A passphrase is set but not visible for this output. Show it and confirm it, or clear it, before deriving.");
        let entropy = hodlBrainLabEntropy(hodlBrainWalletPassphrase(value, hodlBrainWalletTrimEnabled()));
        hodlThrowIfFailed(entropy);
        hodlWalletResult = await hodlEntropyWalletWithProgress(entropy, passphrase, network, count, account, addressStart, progress, purpose, coinType, hardening, branchStart, branchRange, derivationPlan);
      } else {
        let trimBrainWallet = hodlBrainWalletTrimEnabled();
        hodlAssertPrivateKeyKind(value, network, kind, trimBrainWallet);
        progress.setTotal(1);
        hodlWalletResult = hodlSingleKeyWallet(value, network, kind, trimBrainWallet);
        progress.step();
      }
      // Mark brain-derived results so a revoked acknowledgement can retract
      // them from every key slot, not just the lab that produced them.
      if (kind === "brain") hodlWalletResult.brainWalletOutput = hodlBrainWalletOutput();
    }
    if (hodlWalletResult?.network !== network) throw hodlError("The supplied key is for {have}, but Network is set to {want}.", { have: hodlWalletResult.network, want: network });
    hodlRevealPrivate = false;
    hodlSetSelectedScriptType(scriptType);
    hodlCaptureKey();
    hodlJournalLog("derive", hodlWalletResult?.masterFingerprint || hodlWalletResult?.kind || "key");
    hodlSnapshotKeySummary();
    hodlCommitDerivedKey();
    hodlFocusWalletResult();
    return true;
  } catch (error) {
    if (error instanceof HodlDerivationCancelledError) throw error;
    hodlWalletResult = null;
    hodlSetWorkspaceError("key", hodlErrorSpecFrom(error, "Could not derive key"));
    hodlOutEl.innerHTML = "";
    hodlCaptureKey();
    hodlJournalLog("derive-error");
    return false;
  }
}
function hodlFilterHex(e) {
  return e.replace(/[^0-9a-fA-F\s]/g, "");
}
function hodlFilterBin(e) {
  return e.replace(/[^01\s]/g, "");
}
function hodlFilterSeed(e) {
  let value = String(e ?? "").replace(/[^a-zA-Z0-9\s]/g, "");
  return hodlLooksExtendedKey(value) ? value : value.toLowerCase();
}
function hodlFilterKey(e, t) {
  return t === "brain" ? e : e.replace(/[^0-9A-Za-z\s]/g, "");
}
function hodlDecodeMiniPrivateKey(value) {
  let candidate = String(value ?? "").trim();
  if (!/^S(?:[1-9A-HJ-NP-Za-km-z]{21}|[1-9A-HJ-NP-Za-km-z]{29})$/.test(candidate)) throw hodlError("Mini keys must start with S and contain 22 or 30 Bitcoin Base58 characters.");
  return hodlDecodeMiniKey(candidate);
}
function hodlAssertPrivateKeyKind(value, network, kind, trimBrainWallet = false) {
  let raw = String(value ?? ""), selected = hodlNormalizePrivateKeyKind(kind, raw);
  if (selected === "brain") return hodlBrainWalletPassphrase(raw, trimBrainWallet);
  let candidate = raw.trim();
  if (!candidate) throw hodlError("Enter a private key.");
  if (selected === "minikey") {
    hodlAssertPrivateKey(hodlDecodeMiniPrivateKey(candidate));
    return candidate;
  }
  if (selected === "hex-key") {
    let compact = candidate.replace(/\s/g, "").replace(/^0x/i, "");
    if (!/^[0-9a-fA-F]{64}$/.test(compact)) throw hodlError("Enter exactly 64 hexadecimal characters (0–9 and a–f).");
    hodlAssertPrivateKey(hodlHex.decode(compact.toLowerCase()));
    return compact.toLowerCase();
  }
  let decoded;
  try {
    decoded = hodlDecodeWif(candidate);
  } catch {
    throw hodlError("Enter a valid {network} WIF private key ({hint}).", { network, hint: network === "testnet" ? "9\u2026 or c\u2026" : "5\u2026, K\u2026, or L\u2026" });
  }
  if (decoded.network !== network) throw hodlError("This WIF is for {have}; Network is set to {want}.", { have: decoded.network, want: network });
  hodlAssertPrivateKey(decoded.priv);
  return candidate;
}
function hodlFilterXpub(e) {
  // < > ; are kept so a pasted multipath step (<0;1>) reaches the parser
  // intact — stripping them would mangle /<0;1> into /01, and with trailing
  // paths honored the mangled digits would silently derive through a
  // made-up numeric path instead of reading as the branch position.
  return String(e ?? "").replace(/[^A-Za-z0-9[\]/'*<>;]/g, "");
}
function hodlNormalizeOriginPath(path) {
  return String(path ?? "").trim().replace(/^m\//i, "").replace(/'/g, "h").replace(/H/g, "h");
}
function hodlParseKeyOrigin(raw) {
  let input = String(raw ?? "").trim();
  let match = input.match(/^\[([0-9a-fA-F]{8})\/([0-9A-Za-z/']+)\](.+)$/);
  if (!match) return { origin: null, key: input };
  let fingerprint = match[1].toLowerCase(), path = hodlNormalizeOriginPath(match[2]), rest = String(match[3] || "").trim().replace(/\/+$/, "");
  // The extended key carries no "/", so the first slash splits the key from
  // a trailing descriptor key-expression path. The path is honored in full:
  // the co-signer's public keys derive through it, so one account key can
  // serve again under a different path, and a deep signer export keeps every
  // step — xpub…/0/0/20/* exports as xpub…/0/0/20/<0;1>/* (a multipath step
  // is legal at any position, BIP389). The only decoration is the branch
  // marker itself: a sole numeric step ahead of the wildcard (/0/*), the
  // multipath form (/<0;1>/*), and the BIP45 cosigner step.
  let slash = rest.indexOf("/"), key = slash < 0 ? rest : rest.slice(0, slash);
  let tokens = slash < 0 ? [] : rest.slice(slash + 1).split("/").filter((token) => token !== "");
  for (let token of tokens) {
    if (!/^(?:\*|<\d+(?:;\d+)*>|\d+[hH']?)$/.test(token)) throw hodlError("Trailing path steps must be numbers, a wildcard *, or a multipath step like <0;1>.");
  }
  if (tokens.includes("*") && tokens[tokens.length - 1] !== "*") throw hodlError("A wildcard * is only allowed as the last trailing path step.");
  let hadWildcard = tokens[tokens.length - 1] === "*";
  if (hadWildcard) tokens.pop();
  // BIP45 account keys carry their cosigner branch (always 0 here) as the
  // first trailing step; the descriptor compose re-adds it, so it is
  // decoration like the branch marker.
  if (/^45h?$/.test(path.split("/")[0] || "") && tokens.length && /^\d+[hH']?$/.test(tokens[0])) tokens.shift();
  if (tokens.filter((token) => token.startsWith("<")).length > 1) throw hodlError("Only one multipath step like <0;1> is supported in a trailing path.");
  let multipathAt = tokens.findIndex((token) => token.startsWith("<"));
  if (multipathAt > 0 && tokens.slice(0, multipathAt).some((token) => !/^\d+[hH']?$/.test(token))) throw hodlError("A multipath step like <0;1> must follow plain number steps.");
  if (multipathAt >= 0 && multipathAt !== tokens.length - 1) throw hodlError("A multipath step like <0;1> must be the last trailing path step.");
  // Steps ahead of a multipath step are honored; the multipath step itself
  // is the branch position. Without one, a sole step ahead of the wildcard
  // is the branch marker and every other shape is honored as written.
  let honoredTokens = multipathAt >= 0 ? tokens.slice(0, multipathAt) : hadWildcard && tokens.length === 1 ? [] : tokens;
  let derivationPath = honoredTokens.map((token) => {
    let step = token.match(/^(\d+)([hH']?)$/); // shape guaranteed by the validation above
    let index = Number(step[1]);
    return (Number.isSafeInteger(index) ? String(index) : step[1]) + (step[2] ? "h" : "");
  }).join("/");
  if (fingerprint === "00000000") throw hodlError("Key origin fingerprint 00000000 is not a real master fingerprint.");
  if (!/^(?:\d+h?)(?:\/\d+h?)*$/.test(path)) throw hodlError("Key origin path must look like 48h/0h/0h/2h.");
  if (!key) throw hodlError("Key origin is missing the extended public key.");
  return { origin: { fingerprint, path }, key, derivationPath };
}
function hodlOriginPathIndexes(path) {
  return hodlNormalizeOriginPath(path).split("/").filter(Boolean).map((step) => {
    let hardened = step.endsWith("h"), index = Number(hardened ? step.slice(0, -1) : step);
    if (!Number.isInteger(index) || index < 0 || index > 2147483647) throw hodlError("Key origin path has an invalid index.");
    return hardened ? 2147483648 + index : index;
  });
}
function hodlOriginMatchesParsedKey(origin, parsed) {
  let indexes = hodlOriginPathIndexes(origin.path);
  if (indexes.length !== parsed.depth) return hodlNote("Key origin path has {have} steps, but this extended key is depth {want}.", { have: indexes.length, want: parsed.depth });
  if (indexes[indexes.length - 1] !== parsed.childNumber) return hodlNote("Key origin path does not end at this extended key.");
  return "";
}
function hodlMultisigPurposeIndex(origin) {
  let first = hodlNormalizeOriginPath(origin?.path).split("/").filter(Boolean)[0], match = first?.match(/^(\d+)h?$/);
  if (!match) throw new Error("The purpose index in the key origin is missing or invalid.");
  let purpose = Number(match[1]);
  if (!Number.isSafeInteger(purpose) || purpose < 0 || purpose > hodlMaxPurpose) throw hodlError("The purpose index in the key origin is out of range.");
  return purpose;
}
function hodlReadMsigPurpose(mark = true) {
  let input = document.getElementById("msig-purpose"), raw = String(input?.value ?? "").trim(), value = Number(raw), valid = /^\d+$/.test(raw) && Number.isSafeInteger(value) && value >= 0 && value <= hodlMaxPurpose;
  if (mark) {
    input?.classList.toggle("bad", !valid);
    input?.setAttribute("aria-invalid", String(!valid));
  }
  if (!valid) throw hodlError("Purpose must be a whole number from 0 to 2,147,483,647.");
  return value;
}
function hodlSetMsigPurpose(value) {
  let purpose = Number(value), input = document.getElementById("msig-purpose");
  if (!Number.isSafeInteger(purpose) || purpose < 0 || purpose > hodlMaxPurpose) purpose = 48;
  if (input) {
    input.value = String(purpose);
    hodlSyncDerivationPrime(input);
  }
  let state = hodlMsigs[hodlActiveMsig];
  if (state) state.fields.purpose = String(purpose);
  return purpose;
}
function hodlStandardMsigPurpose(kind = hodlScriptKind()) {
  // Taproot has no BIP48 script-type child to select, so it is always BIP87.
  // Every other script type chooses between BIP87 and its own standard.
  if (kind === "p2tr") return 87;
  if (document.getElementById("msig-legacy-bip87")?.checked) return 87;
  if (kind === "p2sh") return 45;
  return 48;
}
function hodlMultisigScriptLabel(kind) {
  return kind === "p2sh" ? hodlT("Legacy") : kind === "p2sh-p2wsh" ? hodlT("Nested SegWit") : kind === "p2wsh" ? hodlT("Native SegWit") : kind === "p2tr" ? hodlT("Taproot") : hodlT("Unknown")
}
function hodlOriginScriptError(origin, kind, network, purpose, coinType = hodlCoinTypeFromNetwork(network), hardening = { purpose: true, coinType: true, account: true, address: false }) {
  let steps = hodlNormalizeOriginPath(origin.path).split("/");
  let expectedPurpose = `${purpose}${hardening.purpose ? "h" : ""}`;
  if (steps[0] !== expectedPurpose) return `This key origin uses purpose ${steps[0] || "none"}; the selected Purpose is ${expectedPurpose}.`;
  if (kind === "p2tr" || purpose === 87) {
    let coin = `${coinType}${hardening.coinType ? "h" : ""}`;
    if (steps[1] !== coin) return `This key origin should use ${coin} as the selected coin type.`;
    if (steps.length !== 3) return `${purpose === 87 ? "A BIP87" : "A Taproot"} origin must contain purpose, coin type, and account.`;
    if (!new RegExp(`^\\d+${hardening.account ? "h" : ""}$`).test(steps[2])) return `The account index must be ${hardening.account ? "hardened" : "unhardened"}.`;
    return ""
  }
  // BIP44/49/84 account keys double as co-signers in their script type's
  // multisig standard: the purpose determines the script type. The 4-step
  // BIP48-style form keeps working and falls through to the checks below.
  if ((purpose === 44 || purpose === 49 || purpose === 84) && steps.length !== 4) {
    let mapped = purpose === 44 ? "p2sh" : purpose === 49 ? "p2sh-p2wsh" : "p2wsh";
    if (kind !== mapped) return `A BIP${purpose} origin belongs to ${hodlMultisigScriptLabel(mapped)} multisig; the selected script type is ${hodlMultisigScriptLabel(kind)}.`;
    let coin = `${coinType}${hardening.coinType ? "h" : ""}`;
    if (steps[1] !== coin) return `This key origin should use ${coin} as the selected coin type.`;
    if (steps.length !== 3) return `A BIP${purpose} origin must contain purpose, coin type, and account.`;
    if (!new RegExp(`^\\d+${hardening.account ? "h" : ""}$`).test(steps[2])) return `The account index must be ${hardening.account ? "hardened" : "unhardened"}.`;
    return "";
  }
  if (kind === "p2wsh" || kind === "p2sh-p2wsh") {
    let coin = `${coinType}${hardening.coinType ? "h" : ""}`;
    if (steps[1] !== coin) return `This key origin should use ${coin} as the selected coin type.`;
    if (steps.length !== 4) return "SegWit multisig origin must contain purpose, coin type, account, and script type.";
    if (!new RegExp(`^\\d+${hardening.account ? "h" : ""}$`).test(steps[2])) return `The account index must be ${hardening.account ? "hardened" : "unhardened"}.`;
    let last = kind === "p2wsh" ? "2h" : "1h";
    if (steps[3] !== last) return hodlNote("This script type's origin must end in {last}.", { last });
    return "";
  }
  if (purpose !== 45) {
    let coin = `${coinType}${hardening.coinType ? "h" : ""}`;
    if (steps[1] !== coin) return `This key origin should use ${coin} as the selected coin type.`;
    if (steps.length !== 3) return "Account-based Legacy origin must contain purpose, coin type, and account.";
    if (!new RegExp(`^\\d+${hardening.account ? "h" : ""}$`).test(steps[2])) return `The account index must be ${hardening.account ? "hardened" : "unhardened"}.`;
    return "";
  }
  if (steps.length !== 1) return `Legacy purpose 45 uses the BIP45 purpose key at m/${expectedPurpose} without an account.`;
  return "";
}
function hodlMultisigAccountNumber(origin, kind, purpose, accountHardened = true) {
  let steps = hodlNormalizeOriginPath(origin?.path).split("/");
  if (kind === "p2sh" && purpose === 45) return null;
  let match = steps[2]?.match(new RegExp(`^(\\d+)${accountHardened ? "h" : ""}$`));
  if (!match) throw new Error(`The account index must be ${accountHardened ? "hardened" : "unhardened"}.`);
  let account = Number(match[1]);
  if (!Number.isSafeInteger(account) || account < 0 || account > 2147483647) throw hodlError("The account index is out of range.");
  return account;
}
function hodlSummarizeMultisigAccounts(accountNumbers) {
  let accounts = [...new Set(accountNumbers.filter((account) => Number.isSafeInteger(account) && account >= 0 && account <= 2147483647))].sort((a, b) => a - b);
  let mixed = accounts.length > 1;
  return { account: accounts.length === 1 ? accounts[0] : null, accounts, consistent: !mixed, mixed };
}
function hodlMultisigAccountWarning(summary) {
  return summary.consistent ? "" : hodlNote("Co-signer account numbers do not match ({accounts}). The Account field is shown as Mixed.", { accounts: summary.accounts.join(", ") });
}
function hodlMultisigOriginScriptKind(origin) {
  let steps = hodlNormalizeOriginPath(origin?.path).split("/").filter(Boolean);
  if (steps.length === 1) return "p2sh";
  let purpose = steps[0].replace(/h$/, "");
  // Three-step account origins determine the script type from the purpose:
  // the singlesig BIPs map to their multisig counterpart, 86 is Taproot,
  // 87 is deliberately script-agnostic, and anything else is a custom
  // purpose that selects no script type.
  if (steps.length === 3) {
    if (purpose === "86") return "p2tr";
    if (purpose === "84") return "p2wsh";
    if (purpose === "49") return "p2sh-p2wsh";
    if (purpose === "44") return "p2sh";
    return null;
  }
  if (purpose !== "48" || steps.length !== 4) return null;
  if (steps[3] === "1h") return "p2sh-p2wsh";
  if (steps[3] === "2h") return "p2wsh";
  return null;
}
function hodlMultisigScriptEvidence(parsed) {
  let prefixKind = parsed?.scope === "multisig" ? parsed.family === "y" ? "p2sh-p2wsh" : parsed.family === "z" ? "p2wsh" : null : null;
  return { prefixKind, originKind: hodlMultisigOriginScriptKind(parsed?.origin) };
}
function hodlSummarizeMultisigScriptKinds(kinds) {
  let supported = ["p2sh", "p2sh-p2wsh", "p2wsh", "p2tr"],
    unique = [...new Set((kinds || []).filter(kind => supported.includes(kind)))];
  return {
    kind: unique.length > 1 ? "mixed" : unique[0] || null,
    kinds: unique,
    mixed: unique.length > 1
  }
}
// Co-signer fields also accept a pasted output descriptor (issue #175): the
// field only needs one key origin plus extended public key, so a descriptor
// is reduced to its key expressions. A descriptor that carries exactly one
// co-signer key (a single-sig wrapper, or one key inside multi) parses
// through with the key expression kept whole, its trailing path honored
// exactly as if it were typed by hand; a full multisig descriptor lists
// every co-signer and must not be silently reduced to an arbitrary position,
// so it fails with directions.
function hodlDescriptorKeyExpressions(raw) {
  let text = hodlStripDescriptorChecksum(String(raw ?? "").trim());
  if (!text.includes("(")) return null;
  let pattern = /(\[[0-9a-fA-F]{8}\/[0-9A-Za-z/'hH]+\])?((?:[xyztuv]pub|[YZUV]pub)[1-9A-HJ-NP-Za-km-z]{20,})(?:\/(?:<\d+(?:;\d+)*>|\d+))*(?:\/\*(?:<\d+(?:;\d+)>)?)?/g, expressions = [];
  for (let match of text.matchAll(pattern)) expressions.push({ origin: match[1] || null, key: match[2], expression: match[0] });
  return expressions;
}
function hodlParseMultisigCosigner(raw) {
  let text = String(raw ?? "").trim(), expressions = hodlDescriptorKeyExpressions(text);
  if (expressions) {
    if (!expressions.length) throw new Error("This descriptor does not contain an extended public key. Paste the co-signer's extended public key, for example [fingerprint/48h/0h/0h/2h]Zpub….");
    if (expressions.length > 1) throw new Error(`This descriptor lists ${expressions.length} co-signer keys. Paste one key per co-signer field so the signing order stays explicit.`);
    // With an origin the whole expression goes through, its trailing path
    // honored like a typed value; without one the bare key is all the field
    // can take, so the descriptor's derivation suffix stays behind.
    text = expressions[0].origin ? expressions[0].expression : expressions[0].key;
  }
  let parsedOrigin = hodlParseKeyOrigin(text), parsed = hodlParseExtendedKey(parsedOrigin.key);
  parsed.origin = parsedOrigin.origin;
  parsed.derivationPath = parsedOrigin.derivationPath || "";
  if (parsed.derivationPath) {
    if (!/^\d+(?:\/\d+)*$/.test(parsed.derivationPath)) throw new Error("The derivation path after the extended key must be unhardened (like /1); hardened steps cannot be derived from an extended public key.");
    if (parsed.derivationPath.split("/").some((step) => Number(step) > 2147483647)) throw new Error("A derivation path index after the extended key is out of range (0 to 2,147,483,647).");
  }
  return parsed;
}
// The Paste descriptor panel imports a whole multisig descriptor at once
// (the full-descriptor counterpart of issue #175): the wrapper picks the
// script type, multi/sortedmulti picks the key order, and the threshold and
// one key expression per co-signer fill the quorum and the fields. The
// #checksum is verified when present and every key is validated by the same
// path a hand-pasted co-signer key takes. Anything the form cannot reproduce
// — a fixed derivation path after a key, an extended private key, a Taproot
// internal key other than the BIP341 NUMS point — is refused with directions.
function hodlSplitDescriptorArgs(text) {
  let args = [], depth = 0, start = 0;
  for (let i = 0; i < text.length; i++) {
    let ch = text[i];
    if (ch === "(") depth++;
    else if (ch === ")") depth--;
    else if (ch === "," && depth === 0) {
      args.push(text.slice(start, i));
      start = i + 1;
    }
  }
  args.push(text.slice(start));
  return args.map((arg) => arg.trim());
}
function hodlUnwrapDescriptor(text, name) {
  let prefix = name + "(", body = String(text ?? "").trim();
  if (body.length <= prefix.length || !body.toLowerCase().startsWith(prefix) || !body.endsWith(")")) return null;
  let depth = 0;
  for (let i = prefix.length; i < body.length - 1; i++) {
    if (body[i] === "(") depth++;
    else if (body[i] === ")") {
      depth--;
      if (depth < 0) return null;
    }
  }
  return depth === 0 ? body.slice(prefix.length, -1) : null;
}
function hodlMsigDescriptorKeyText(expr, index) {
  let text = String(expr ?? "").trim(), label = "Co-signer " + (index + 1) + ": ";
  if (!text) throw new Error(label + "the descriptor has an empty key position.");
  let depth = 0, cut = -1;
  for (let i = 0; i < text.length; i++) {
    let ch = text[i];
    if (ch === "[") depth++;
    else if (ch === "]") depth--;
    else if (ch === "/" && depth === 0) {
      cut = i;
      break;
    }
  }
  let key = cut < 0 ? text : text.slice(0, cut), steps = cut < 0 ? [] : text.slice(cut + 1).split("/");
  if (steps.length) {
    if (steps[steps.length - 1] !== "*") throw new Error(label + "the descriptor derives this key through a fixed path (/" + steps.join("/") + "). The tool derives the receive and change branches itself — paste the account-level key instead.");
    if (steps.slice(0, -1).some((step) => !/^(?:\d+|<\d+(?:;\d+)*>)$/.test(step))) throw new Error(label + "the derivation path after the extended key is not readable.");
  }
  let parsed = hodlParseMultisigCosigner(key);
  if (parsed.isPrivate) throw new Error(label + "this descriptor carries an extended private key. This tool is watch-only — export the public descriptor from the wallet instead.");
  return key;
}
function hodlParseMsigDescriptor(raw) {
  let text = String(raw ?? "").trim();
  if (!text) throw new Error("Paste a multisig output descriptor first.");
  let hash = text.lastIndexOf("#");
  if (hash >= 0) {
    if (hodlDescriptorWithChecksum(text.slice(0, hash)) !== text) throw new Error("The descriptor checksum does not match. Re-copy the descriptor from the wallet that exported it.");
    text = text.slice(0, hash);
  }
  let kind = null, body = text, sh = hodlUnwrapDescriptor(body, "sh"), wsh = hodlUnwrapDescriptor(body, "wsh"), tr = hodlUnwrapDescriptor(body, "tr");
  if (sh) {
    let nested = hodlUnwrapDescriptor(sh, "wsh");
    kind = nested ? "p2sh-p2wsh" : "p2sh";
    body = nested ?? sh;
  } else if (wsh) {
    kind = "p2wsh";
    body = wsh;
  } else if (tr) {
    kind = "p2tr";
    let parts = hodlSplitDescriptorArgs(tr);
    if (parts.length !== 2) throw new Error("A Taproot multisig descriptor needs one internal key and one script path.");
    if (parts[0].replace(/^\[[^\]]*\]/, "") !== "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0") throw new Error("This Taproot descriptor spends with its own internal key. The multisig tool builds Taproot over the BIP341 NUMS point, so this descriptor cannot be reproduced here.");
    if (/[{}]/.test(parts[1])) throw new Error("This Taproot descriptor has several script paths. The multisig tool builds a single multisig leaf.");
    body = parts[1];
  }
  let sorted = true, inner = null;
  for (let name of kind === "p2tr" ? ["sortedmulti_a", "multi_a"] : ["sortedmulti", "multi"]) {
    let candidate = hodlUnwrapDescriptor(body, name);
    if (candidate) {
      inner = candidate;
      sorted = name.startsWith("sorted");
      break;
    }
  }
  if (inner === null) throw new Error("This is not a multisig descriptor. Expected multi(…) or sortedmulti(…) — a single-key descriptor can be pasted straight into a co-signer field.");
  let args = hodlSplitDescriptorArgs(inner);
  if (!/^\d+$/.test(args[0] || "") || Number(args[0]) < 1) throw new Error("The multisig threshold is missing or is not a whole number.");
  let m = Number(args[0]), exprs = args.slice(1);
  if (exprs.length > hodlMsigSliderLimit) throw new Error("This descriptor lists " + exprs.length + " keys; the tool builds at most " + hodlMsigSliderLimit + ".");
  if (m > exprs.length) throw new Error("The threshold of " + m + " exceeds the " + exprs.length + " keys listed.");
  return { m, n: exprs.length, sorted, kind, keys: exprs.map(hodlMsigDescriptorKeyText) };
}
// The Import button only runs on a fresh form: it stays disabled while any
// co-signer field holds text (importing would have to overwrite it) or the
// descriptor field is empty. A green/red import result keeps showing until
// the user edits the descriptor or a co-signer field; the neutral "clear the
// fields" hint is the only message this sync writes itself.
function hodlSyncMsigDescriptorImport(fromFields = false) {
  let button = document.getElementById("msig-descriptor-import"), field = document.getElementById("msig-descriptor"), status = document.getElementById("msig-descriptor-status");
  if (!button) return;
  let occupied = hodlReadMsigXpubs().some((value) => String(value).trim()), empty = !String(field?.value ?? "").trim();
  button.disabled = occupied || empty;
  button.setAttribute("aria-disabled", String(button.disabled));
  if (!status) return;
  if (fromFields) delete status.dataset.result;
  if (status.dataset.result) return;
  status.textContent = occupied ? "Clear the co-signer fields to import a descriptor." : "";
  status.className = "hint";
  status.hidden = !occupied;
}
function hodlImportMsigDescriptor() {
  let status = document.getElementById("msig-descriptor-status"), show = (ok, msg) => {
    if (!status) return;
    status.textContent = msg;
    status.className = "hint " + (ok ? "ok" : "bad");
    status.hidden = !msg;
    status.dataset.result = "1";
  };
  try {
    let imported = hodlParseMsigDescriptor(document.getElementById("msig-descriptor")?.value);
    if (hodlReadMsigXpubs().some((value) => String(value).trim())) throw new Error("Co-signer fields already hold keys. Clear them before importing a descriptor.");
    let script = document.getElementById("msig-script-type"), keyOrder = document.getElementById("msig-key-order");
    if (imported.kind && script) {
      hodlSyncSelect(script, imported.kind);
      script.dispatchEvent(new Event("change"));
    }
    if (keyOrder) {
      hodlSyncSelect(keyOrder, imported.sorted ? "sorted" : "listed");
      keyOrder.dispatchEvent(new Event("change"));
    }
    hodlChangeMsigThreshold("n", String(imported.n), true);
    hodlChangeMsigThreshold("m", String(imported.m), true);
    hodlFillKeys(imported.keys);
    // A co-signer whose fingerprint matches a Key Lab session key shows its
    // lifehash and pressed chip, exactly as if the key was picked by hand.
    hodlRefreshMsigSessionPickers();
    hodlValidatedMsigInputs();
    show(true, "Imported a " + imported.m + "-of-" + imported.n + " descriptor: " + (imported.kind ? hodlMultisigScriptLabel(imported.kind) : "kept the selected script type") + ", " + (imported.sorted ? "sorted" : "as listed") + " key order. Review the co-signers, then derive.");
  } catch (error) {
    show(false, error.message || "The descriptor could not be imported.");
  }
}
function hodlDetectMsigScriptSummary(values = hodlReadMsigXpubs()) {
  let kinds = [];
  for (let raw of values) {
    if (!String(raw ?? "").trim()) continue;
    try {
      let evidence = hodlMultisigScriptEvidence(hodlParseMultisigCosigner(raw));
      if (evidence.prefixKind) kinds.push(evidence.prefixKind);
      if (evidence.originKind) kinds.push(evidence.originKind);
    } catch {
    }
  }
  return hodlSummarizeMultisigScriptKinds(kinds);
}
function hodlSelectedLegacyMultisigStandard() {
  let purpose;
  try {
    purpose = hodlReadMsigPurpose(false);
  } catch {
    return "custom";
  }
  return purpose === 45 ? "bip45" : purpose === 87 ? "bip87" : "custom";
}
function hodlUpdateMsigLegacyControls() {
  let checkbox = document.getElementById("msig-legacy-bip87"), toggle = document.getElementById("msig-legacy-account-toggle"), kind = hodlScriptKind(), purpose;
  try {
    purpose = hodlReadMsigPurpose(false);
  } catch {
    purpose = null;
  }
  if (toggle) toggle.hidden = kind === "p2tr";
  if (checkbox) checkbox.checked = purpose === 87;
}
function hodlMultisigKeyPlaceholder(kind, network, purpose, coinType = hodlCoinTypeFromNetwork(network), hardening = { purpose: true, coinType: true, account: true, address: false }) {
  let testnet = network === "testnet",
    coin = `${coinType}${hardening.coinType ? "h" : ""}`, purposeStep = `${purpose}${hardening.purpose ? "h" : ""}`, account = `0${hardening.account ? "h" : ""}`;
  if (kind === "p2sh" && purpose === 45) return `[fingerprint/${purposeStep}]${testnet?"tpub":"xpub"}\u2026`;
  if (kind === "p2sh" || purpose === 87) return `[fingerprint/${purposeStep}/${coin}/${account}]${testnet?"tpub":"xpub"}\u2026`;
  if (kind === "p2sh-p2wsh") return `[fingerprint/${purposeStep}/${coin}/${account}/1h]${testnet?"tpub":"xpub"}\u2026`;
  if (kind === "p2wsh") return `[fingerprint/${purposeStep}/${coin}/${account}/2h]${testnet?"tpub":"xpub"}\u2026`;
  if (kind === "p2tr") return `[fingerprint/${purposeStep}/${coin}/${account}]${testnet?"tpub":"xpub"}\u2026`;
  return "Use matching multisig extended public keys"
}

function hodlUpdateMsigKeyPlaceholders() {
  let kind = hodlScriptKind(), coinTypeInput = document.getElementById("msig-network"), coinType, network, purpose;
  try {
    coinType = hodlReadCoinType(coinTypeInput, false);
  } catch {
    coinType = 0;
  }
  network = hodlNetworkFromCoinType(coinType);
  try {
    purpose = hodlReadMsigPurpose(false);
  } catch {
    purpose = hodlStandardMsigPurpose(kind);
  }
  let placeholder = hodlMultisigKeyPlaceholder(kind, network, purpose, coinType, hodlReadHardening("msig-"));
  document.querySelectorAll("#msig-keys textarea").forEach((textarea) => {
    textarea.placeholder = placeholder;
  });
}
function hodlUpdateMsigPurposeDetection() {
  let input = document.getElementById("msig-purpose"), warning = document.getElementById("msig-purpose-warning"), purposes = [];
  if (!input) return { purposes, mixed: false, purpose: null };
  for (let raw of hodlReadMsigXpubs()) {
    if (!String(raw ?? "").trim()) continue;
    try {
      let parsed = hodlParseMultisigCosigner(raw);
      if (parsed.origin) purposes.push(hodlMultisigPurposeIndex(parsed.origin));
    } catch {
    }
  }
  purposes = [...new Set(purposes)].sort((left, right) => left - right);
  let mixed = purposes.length > 1, purpose = purposes.length === 1 ? purposes[0] : null;
  if (purpose != null) hodlSetMsigPurpose(purpose);
  let message = mixed ? hodlT("Co-signer purpose indexes do not match ({purposes}).", { purposes: purposes.map(value => `${value}h`).join(", ") }) : "";
  input.classList.toggle("bad", mixed);
  input.setAttribute("aria-invalid", String(mixed));
  if (warning) {
    warning.textContent = message;
    warning.hidden = !message;
  }
  hodlUpdateMsigLegacyControls();
  return { purposes, mixed, purpose };
}
function hodlSyncMsigDeriveButton() {
  let button = document.getElementById("msig-go");
  if (!button) return;
  if (hodlActiveDerivation) {
    if (hodlActiveDerivation.kind === "msig") {
      hodlSetDerivationButtonState("msig", hodlActiveDerivation.cancelled ? "stopping" : "running");
      return;
    }
    hodlSetDerivationButtonState("msig", "idle");
    button.disabled = true;
    button.setAttribute("aria-disabled", "true");
    button.title = hodlTText("A derivation is already running.");
    return;
  }
  hodlSetDerivationButtonState("msig", "idle");
  let ready = false, reason = "";
  try {
    hodlValidatedMsigInputs();
    ready = true;
  } catch (error) {
    reason = error.message || hodlT("Complete every multisig field.");
  }
  button.disabled = !ready;
  button.setAttribute("aria-disabled", String(!ready));
  button.title = ready ? "" : reason;
}
function hodlUpdateMsigScriptDetection() {
  let select = document.getElementById("msig-script-type");
  if (!select) return hodlSummarizeMultisigScriptKinds([]);
  let summary = hodlDetectMsigScriptSummary(), desired = summary.mixed ? "mixed" : summary.kind;
  if (desired === "mixed") {
    if (select.value !== "mixed") select.dataset.lastConcrete = select.value;
    hodlSyncSelect(select, "mixed");
  } else if (desired) {
    select.dataset.lastConcrete = desired;
    hodlSyncSelect(select, desired);
  } else if (select.value === "mixed") {
    hodlSyncSelect(select, select.dataset.lastConcrete || "p2wsh");
  } else select.dataset.lastConcrete = select.value;
  hodlUpdateMsigPurposeDetection();
  hodlUpdateMsigLegacyControls();
  let warning = document.getElementById("msig-script-warning"), labels = summary.kinds.map(hodlMultisigScriptLabel), message = summary.mixed ? hodlT("Co-signer exports indicate different script types ({labels}). A Mixed selection does not define one multisig output policy; export every key for the same script type before deriving.", { labels: labels.join(" and ") }) : "";
  if (warning) {
    warning.textContent = message;
    warning.hidden = !message;
  }
  hodlUpdateMsigKeyPlaceholders();
  hodlSyncMsigDeriveButton();
  return summary;
}
function hodlMultisigKeyToken(parsed, network) {
  let canonical = hodlSerializeExtendedKey(parsed.node.publicExtendedKey, network, "x", false);
  if (!parsed.origin) throw hodlError("Paste the complete key origin and extended public key so a signer can recognize it.");
  return `[${parsed.origin.fingerprint}/${parsed.origin.path}]${canonical}${parsed.derivationPath ? "/" + parsed.derivationPath : ""}`;
}
function hodlHint(el, ok, msg) {
  if (!el) return;
  el.classList.toggle("bad", !ok && !!msg);
  let anchor = el.closest(".dice-input-shell") || el, h = anchor.nextElementSibling;
  if (!h || !h.classList.contains("hint")) {
    h = document.createElement("p");
    h.className = "hint";
    anchor.insertAdjacentElement("afterend", h);
  }
  h.textContent = msg || "";
  h.className = "hint " + (ok ? "ok" : msg ? "bad" : "");
}
var hodlWorkspace = "calc", hodlWorkspaceScrollFrame = 0;
function hodlReadMsigXpubs() {
  return [...document.querySelectorAll("#msig-keys textarea")].map((ta) => ta.value);
}
function hodlMergeMsigXpubs(state, values) {
  let cached = Array.isArray(state?.fields?.xpubs) ? state.fields.xpubs.slice() : [];
  (values || hodlReadMsigXpubs()).forEach((value, index) => {
    cached[index] = value;
  });
  if (state) state.fields.xpubs = cached;
  return cached;
}
function hodlUpdateMsigAccount() {
  let field = document.getElementById("msig-account");
  if (!field) return hodlSummarizeMultisigAccounts([]);
  let kind = hodlScriptKind(), purpose, hardening = hodlReadHardening("msig-"), help = document.getElementById("msig-account-help"), warning = document.getElementById("msig-account-warning");
  try {
    purpose = hodlReadMsigPurpose(false);
  } catch {
    purpose = hodlStandardMsigPurpose(kind);
  }
  if (kind === "p2sh" && purpose === 45) {
    field.value = "";
    hodlSyncDerivationPrime(field);
    field.placeholder = "Not applicable";
    field.dataset.state = "not-applicable";
    if (help) help.textContent = hodlTText("BIP45 purpose keys do not contain an account number.");
    if (warning) {
      warning.textContent = "";
      warning.hidden = true;
    }
    return hodlSummarizeMultisigAccounts([]);
  }
  let accountNumbers = [];
  for (let raw of hodlReadMsigXpubs()) {
    if (!raw.trim()) continue;
    try {
      let parsed = hodlParseMultisigCosigner(raw.trim());
      if (parsed.origin) accountNumbers.push(hodlMultisigAccountNumber(parsed.origin, kind, purpose, hardening.account));
    } catch {
    }
  }
  let summary = hodlSummarizeMultisigAccounts(accountNumbers), message = hodlMultisigAccountWarning(summary);
  field.value = summary.mixed ? "Mixed" : summary.account == null ? "" : String(summary.account);
  hodlSyncDerivationPrime(field);
  field.placeholder = "Derived from keys";
  field.dataset.state = summary.mixed ? "mixed" : summary.account == null ? "empty" : "account";
  if (help) {
    let mode = hardening.account ? "Hardened" : "Unhardened";
    help.textContent = summary.mixed ? `Account index · ${mode} · Co-signer key origins use different account numbers.` : summary.account == null ? `Account index · ${mode} · Derived from co-signer key origins.` : `Account index · ${mode} · Derived from the co-signer account paths.`;
  }
  if (warning) {

    warning.hidden = !message;
    warning.textContent = message || "";
  }
  return summary;
}
function hodlInvalidateMsig() {
  let state = hodlMsigs[hodlActiveMsig];
  if (state) {
    state.result = null;
    state.error = "";
    state.errorSpec = null;
  }
  hodlWalletResult = null;
  hodlClearMsigOut();
  let err = document.getElementById("msig-error");
  if (err) err.textContent = "";
  hodlStopDerivation("msig");
  hodlResetDerivationProgress("msig");
  hodlUpdateMsigAccount();
  hodlSyncMsigDeriveButton();
}
function hodlUpdateMsigHint() {
  let n = Number(document.getElementById("msig-n").value || 3), m = document.getElementById("msig-m").value || "2", hint = document.getElementById("msig-hint");
  if (hint) {
    hint.textContent = n === 1 ? hodlTText("Spending will need this key. Receiving needs none of the private keys.") : hodlTText("Spending will need {m} of these {n} keys. Receiving needs none of the private keys.", { m, n });
    hint.className = "hint ok";
  }
}
var hodlMsigSliderBaseMax = 9, hodlMsigSliderLimit = 15;
function hodlClampMsigThreshold(value, min, max) {
  let number = Number(value);
  return Math.min(max, Math.max(min, Number.isFinite(number) ? Math.round(number) : min));
}
function hodlRenderMsigThreshold() {
  let mInput = document.getElementById("msig-m"), nInput = document.getElementById("msig-n"), slider = document.getElementById("msig-threshold-slider"), ticks = document.getElementById("msig-threshold-ticks");
  if (!mInput || !nInput || !slider || !ticks) return;
  let m = Number(mInput.value), n = Number(nInput.value), visibleMax = Math.max(hodlMsigSliderBaseMax, n), span = Math.max(1, visibleMax - 1);
  slider.style.setProperty("--msig-m-position", (m - 1) / span * 100 + "%");
  slider.style.setProperty("--msig-n-position", (n - 1) / span * 100 + "%");
  slider.dataset.sliderMax = String(visibleMax);
  slider.dataset.overlap = String(m === n);
  let mNumber = document.getElementById("msig-m-number"), nNumber = document.getElementById("msig-n-number");
  if (mNumber) {
    mNumber.value = String(m);
    mNumber.min = "1";
    mNumber.max = String(hodlMsigSliderLimit);
  }
  if (nNumber) {
    nNumber.value = String(n);
    nNumber.min = "1";
    nNumber.max = String(hodlMsigSliderLimit);
  }
  mInput.setAttribute("aria-valuetext", m + " signature" + (m === 1 ? "" : "s") + " needed");
  nInput.setAttribute("aria-valuetext", n + " total signing key" + (n === 1 ? "" : "s"));
  let fragment = document.createDocumentFragment();
  for (let value = 1; value <= visibleMax; value++) {
    let tick = document.createElement("span");
    tick.textContent = String(value);
    tick.style.setProperty("--msig-tick-position", (value - 1) / span * 100 + "%");
    fragment.appendChild(tick);
  }
  ticks.replaceChildren(fragment);
}
function hodlSetMsigThresholds(mValue, nValue, changed, moveOther) {
  let mInput = document.getElementById("msig-m"), nInput = document.getElementById("msig-n");
  if (!mInput || !nInput) return { m: 2, n: 3 };
  let n = hodlClampMsigThreshold(nValue, 1, hodlMsigSliderLimit), m = hodlClampMsigThreshold(mValue, 1, hodlMsigSliderLimit);
  if (moveOther) {
    if (changed === "m") n = Math.max(n, m);
    else if (changed === "n") m = Math.min(m, n);
  } else if (changed === "n") n = Math.max(n, m);
  else m = Math.min(m, n);
  mInput.value = String(m);
  nInput.value = String(n);
  hodlRenderMsigThreshold();
  hodlUpdateMsigHint();
  return { m, n };
}
function hodlChangeMsigThreshold(handle, value, moveOther) {
  let mInput = document.getElementById("msig-m"), nInput = document.getElementById("msig-n"), previousN = document.querySelectorAll("#msig-keys textarea").length || Number(nInput.value || 3), state = hodlMsigs[hodlActiveMsig];
  let saved = state ? hodlMergeMsigXpubs(state) : hodlReadMsigXpubs(), next = hodlSetMsigThresholds(handle === "m" ? value : mInput.value, handle === "n" ? value : nInput.value, handle, moveOther);
  if (next.n !== previousN) hodlFillKeys(saved);
  else hodlUpdateMsigHint();
  hodlInvalidateMsig();
}
function hodlMsigThresholdPointerValue(clientX, rect, visibleMax) {
  let ratio = Math.min(1, Math.max(0, (clientX - rect.left) / Math.max(1, rect.width)));
  return Math.round(1 + ratio * (visibleMax - 1));
}
function hodlBindMsigThresholdSlider() {
  let slider = document.getElementById("msig-threshold-slider"), mInput = document.getElementById("msig-m"), nInput = document.getElementById("msig-n"), mNumber = document.getElementById("msig-m-number"), nNumber = document.getElementById("msig-n-number");
  if (!slider || !mInput || !nInput) return;
  let drag = null, setActive = (handle, value) => {
    slider.dataset.activeHandle = handle;
    document.getElementById("msig-" + handle)?.focus({ preventScroll: true });
    hodlChangeMsigThreshold(handle, value, true);
  };
  mInput.addEventListener("input", () => hodlChangeMsigThreshold("m", mInput.value, true));
  nInput.addEventListener("input", () => hodlChangeMsigThreshold("n", nInput.value, true));
  mInput.addEventListener("focus", () => {
    slider.dataset.activeHandle = "m";
  });
  nInput.addEventListener("focus", () => {
    slider.dataset.activeHandle = "n";
  });
  let bindNumber = (input, handle) => {
    if (!input) return;
    let apply = (commit) => {
      let raw = input.value.trim();
      if (!raw) {
        if (commit) hodlRenderMsigThreshold();
        return;
      }
      hodlChangeMsigThreshold(handle, raw, true);
    };
    input.addEventListener("input", () => apply(false));
    input.addEventListener("change", () => apply(true));
    input.addEventListener("blur", () => apply(true));
    input.addEventListener("focus", () => input.select());
    input.addEventListener("keydown", (event) => {
      if (["e", "E", "+", "-", "."].includes(event.key)) event.preventDefault();
      if (event.key === "Enter") {
        event.preventDefault();
        apply(true);
        input.select();
      }
    });
  };
  bindNumber(mNumber, "m");
  bindNumber(nNumber, "n");
  slider.addEventListener("pointerdown", (event) => {
    if (event.button !== 0) return;
    event.preventDefault();
    let rect = slider.getBoundingClientRect(), m = Number(mInput.value), n = Number(nInput.value), visibleMax = Math.max(hodlMsigSliderBaseMax, n), point = hodlMsigThresholdPointerValue(event.clientX, rect, visibleMax), handle = m === n ? null : Math.abs(point - m) <= Math.abs(point - n) ? "m" : "n";
    drag = { pointerId: event.pointerId, startX: event.clientX, rect, visibleMax, handle };
    slider.setPointerCapture(event.pointerId);
    if (handle) setActive(handle, point);
  });
  slider.addEventListener("pointermove", (event) => {
    if (!drag || event.pointerId !== drag.pointerId) return;
    event.preventDefault();
    if (!drag.handle) {
      let delta = event.clientX - drag.startX;
      if (Math.abs(delta) < 3) return;
      drag.handle = delta < 0 ? "m" : "n";
    }
    let value = drag.handle === "n" && event.clientX > drag.rect.right ? Math.min(hodlMsigSliderLimit, drag.visibleMax + Math.ceil((event.clientX - drag.rect.right) / 28)) : hodlMsigThresholdPointerValue(event.clientX, drag.rect, drag.visibleMax);
    setActive(drag.handle, value);
  });
  let finish = (event) => {
    if (!drag || event.pointerId !== drag.pointerId) return;
    if (!drag.handle) {
      slider.dataset.activeHandle = "n";
      nInput.focus({ preventScroll: true });
    }
    drag = null;
  };
  slider.addEventListener("pointerup", finish);
  slider.addEventListener("pointercancel", finish);
  slider.addEventListener("lostpointercapture", () => {
    drag = null;
  });
}

function hodlMsigKeysSorted() {
  return document.getElementById("msig-key-order")?.value !== "listed"
}

function hodlMsigPolicyOp(kind, sorted) {
  return kind === "p2tr" ? sorted ? "sortedmulti_a" : "multi_a" : sorted ? "sortedmulti" : "multi"
}

function hodlMsigInnerDescriptor(kind, m, inner, sorted) {
  let core = `${hodlMsigPolicyOp(kind,sorted)}(${m},${inner})`;
  if (kind === "p2tr") return `tr(50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0,${core})`;
  if (kind === "p2wsh") return `wsh(${core})`;
  if (kind === "p2sh-p2wsh") return `sh(wsh(${core}))`;
  return `sh(${core})`
}

function hodlUpdateMsigKeyOrderStatus() {
  let status = document.getElementById("msig-key-order-status");
  if (!status) return;
  let sorted = hodlMsigKeysSorted();
  status.hidden = sorted;
  if (sorted) {
    status.textContent = "";
    status.className = "hint";
    return
  }
  let op = hodlMsigPolicyOp(hodlScriptKind(), !1);
  let parts = [...document.querySelectorAll("#msig-keys textarea")].map((ta, index) => {
    let raw = ta.value.trim();
    if (!raw) return "position " + (index + 1);
    try {
      let parsed = hodlParseMultisigCosigner(raw);
      if (parsed.origin?.fingerprint) return "position " + (index + 1) + " " + parsed.origin.fingerprint + (parsed.derivationPath ? "/" + parsed.derivationPath : "")
    } catch {}
    return "position " + (index + 1)
  });
  status.textContent = op + " uses this order: " + parts.join(", ") + ". Use Move up or Move down to change a position.";
  status.className = "hint ok"
}

function hodlSyncMsigKeyMoveButtons() {
  let rows = [...document.querySelectorAll("#msig-keys .msig-key-row")];
  rows.forEach((row, index) => {
    let up = row.querySelector('[data-msig-move="-1"]'),
      down = row.querySelector('[data-msig-move="1"]');
    if (up) {
      up.disabled = index === 0;
      up.setAttribute("aria-label", "Move co-signer " + (index + 1) + " up to position " + index)
    }
    if (down) {
      down.disabled = index === rows.length - 1;
      down.setAttribute("aria-label", "Move co-signer " + (index + 1) + " down to position " + (index + 2))
    }
  })
}

function hodlReindexMsigKeys() {
  [...document.querySelectorAll("#msig-keys .msig-key-row")].forEach((row, index) => {
    let ta = row.querySelector("textarea"),
      pos = row.querySelector(".msig-key-position"),
      lab = row.querySelector("label.field");
    if (ta) ta.id = "msig-x-" + index;
    if (pos) pos.textContent = hodlTText("Position {n}", { n: index + 1 });
    row.querySelector(".msig-session-keys")?.setAttribute("aria-label", hodlTText("Key Station keys for co-signer {n}", { n: index + 1 }));
    row.querySelector(".msig-key-reuse-path")?.setAttribute("aria-label", hodlTText("Derivation path for co-signer {n}", { n: index + 1 }));
    if (lab) {
      let title = lab.childNodes[0];
      if (title && title.nodeType === 3) title.textContent = hodlTText("Co-signer {n} multisig extended public key", { n: index + 1 })
    }
  });
  hodlSyncMsigKeyMoveButtons();
  hodlUpdateMsigKeyPlaceholders();
  hodlUpdateMsigKeyOrderStatus()
}

function hodlMoveMsigKeyRow(row, offset) {
  let box = document.getElementById("msig-keys"),
    rows = [...box.querySelectorAll(".msig-key-row")],
    index = rows.indexOf(row),
    next = index + offset;
  if (index < 0 || next < 0 || next >= rows.length) return;
  if (offset < 0) box.insertBefore(row, rows[next]);
  else box.insertBefore(row, rows[next].nextSibling);
  hodlReindexMsigKeys();
  hodlRefreshMsigSessionPickers();
  hodlInvalidateMsig();
  hodlSyncMsigClearButton(!0)
}

function hodlBindMsigKeyReorder(box) {
  if (box.dataset.reorderBound) return;
  box.dataset.reorderBound = "1";
  box.addEventListener("click", event => {
    if (hodlMsigKeysSorted()) return;
    let button = event.target.closest("[data-msig-move]");
    if (!button || button.disabled) return;
    hodlMoveMsigKeyRow(button.closest(".msig-key-row"), Number(button.dataset.msigMove))
  })
}

function hodlMsigScriptOrder(keyTokens) {
  return keyTokens.map((token, index) => {
    let match = String(token).match(/^\[([0-9a-f]{8})\/([^\]]+)\][1-9A-HJ-NP-Za-km-z]+((?:\/\d+)*)$/i);
    return {
      position: index + 1,
      fingerprint: match ? match[1] : "",
      path: match ? match[2] + (match[3] || "") : ""
    }
  })
}

function hodlSessionMsigKeys() {
  return hodlKeys.filter((state) => !state.isLab && state.result?.multisigCosignerExports?.length);
}
function hodlSessionHdRootKeys() {
  return hodlKeys.filter((state) => !state.isLab && state.result?.kind === "hd" && (state.result.mnemonic || state.result.rootXprv));
}
function hodlFillStationKeyPicker(id, selectedSource, onSelect, keys = hodlSessionHdRootKeys()) {
  let box = document.getElementById(id);
  if (!box) return;
  box.replaceChildren();
  box.hidden = !keys.length;
  keys.forEach((state) => {
    let fingerprint = state.result?.masterFingerprint || state.name || "Key " + state.number, button = document.createElement("button"), image = document.createElement("img"), label = document.createElement("span"), selected = selectedSource === "key:" + state.id;
    button.type = "button";
    button.className = "session-key-option" + (selected ? " active" : "");
    button.dataset.keyId = String(state.id);
    button.setAttribute("aria-pressed", String(selected));
    button.setAttribute("aria-label", "Bring in Key Station key " + fingerprint);
    image.className = "key-tab-lifehash";
    image.width = 22;
    image.height = 22;
    image.alt = "";
    image.hidden = true;
    hodlFillKeyTabLifehash(image, fingerprint);
    label.textContent = fingerprint;
    // The selected chip carries a check mark as well as its accent border,
    // so the selection reads without relying on colour alone.
    let check = document.createElement("span");
    check.className = "session-key-check";
    check.setAttribute("aria-hidden", "true");
    check.innerHTML = hodlCopiedIconMarkup();
    button.append(image, label, check);
    button.onclick = () => onSelect(state);
    box.appendChild(button);
  });
}
function hodlRefreshStationKeyPickers() {
  hodlFillStationKeyPicker("bip85-session-keys", hodlBip85Source, hodlPickBip85SessionKey);
  hodlFillStationKeyPicker("sp-session-keys", hodlSpSource, hodlPickSpSessionKey);
  hodlFillStationKeyPicker("vanity-session-keys", hodlVanitySource, hodlPickVanitySessionKey, hodlVanitySourceKeys());
  // The selected key's passphrase and path may have changed on the Keys tab.
  hodlVanitySyncSource();
}
function hodlMatchingMsigExport(result) {
  if (!result?.multisigCosignerExports?.length) return "";
  let kind = hodlScriptKind(), purpose = hodlReadMsigPurpose(), exports = result.multisigCosignerExports;
  let match = exports.find((item) => item.kind === kind) || exports.find((item) => String(item.originPath || "").startsWith(String(purpose) + "h")) || exports[0];
  return match?.value || "";
}
function hodlMsigKeyOriginFingerprint(value) {
  try {
    return hodlParseMultisigCosigner(String(value || "").trim()).origin?.fingerprint || "";
  } catch {
    return "";
  }
}
function hodlSyncMsigKeyAvatar(row) {
  if (!row) return;
  let ta = row.querySelector("textarea"), ident = row.querySelector(".msig-key-ident"), image = ident?.querySelector("img"), code = ident?.querySelector("code"), fingerprint = hodlMsigKeyOriginFingerprint(ta?.value);
  row.querySelectorAll(".msig-session-key").forEach((button) => {
    button.classList.toggle("active", Boolean(fingerprint) && button.dataset.fingerprint === fingerprint);
    button.setAttribute("aria-pressed", String(button.classList.contains("active")));
  });
  if (ident) ident.hidden = !fingerprint;
  if (code) code.textContent = fingerprint;
  if (image) {
    image.hidden = true;
    image.removeAttribute("src");
    if (fingerprint) hodlFillKeyTabLifehash(image, fingerprint);
  }
}
var hodlMsigKeyTarget = null;
function hodlMsigNextKeyRow() {
  let rows = [...document.querySelectorAll("#msig-keys .msig-key-row")];
  if (hodlMsigKeyTarget?.isConnected) {
    let selected = hodlMsigKeyTarget.closest(".msig-key-row");
    if (selected && rows.includes(selected)) return selected;
  }
  return rows.find((row) => !row.querySelector("textarea")?.value.trim()) || null;
}
function hodlMsigSessionKeyOption(state) {
  try {
    let value = hodlMatchingMsigExport(state.result), parsed = hodlParseMultisigCosigner(value);
    return { state, value, baseId: hodlMsigBaseKeyId(parsed) };
  } catch {
    return { state, value: "", baseId: "" };
  }
}
function hodlMsigUsedBaseKeyIds(exceptRow = null) {
  let used = new Set();
  document.querySelectorAll("#msig-keys .msig-key-row").forEach((row) => {
    if (row === exceptRow) return;
    let parsed = hodlParseMsigRowKey(row);
    if (parsed) used.add(hodlMsigBaseKeyId(parsed));
  });
  return used;
}
function hodlCreateMsigSessionKeyButton(option, className, active, onSelect, ariaLabel) {
  let { state } = option, fingerprint = state.result?.masterFingerprint || state.name, button = document.createElement("button"), image = document.createElement("img"), label = document.createElement("span");
  button.type = "button";
  button.className = className + (active ? " active" : "");
  button.dataset.keyId = String(state.id);
  button.dataset.fingerprint = fingerprint;
  button.setAttribute("aria-pressed", String(active));
  button.setAttribute("aria-label", ariaLabel(fingerprint));
  image.className = "key-tab-lifehash";
  image.width = 22;
  image.height = 22;
  image.alt = "";
  image.hidden = true;
  if (fingerprint) hodlFillKeyTabLifehash(image, fingerprint);
  label.textContent = fingerprint;
  button.append(image, label);
  button.onclick = onSelect;
  return button;
}
function hodlPickMsigSessionKey(state, row = hodlMsigNextKeyRow()) {
  let ta = row?.querySelector("textarea"), status = document.getElementById("msig-session-key-status");
  if (!ta) {
    if (status) status.textContent = "All co-signer inputs are filled. Focus or clear an input before choosing another key.";
    return;
  }
  let value = hodlMatchingMsigExport(state.result);
  if (!value) {
    hodlHint(ta, false, "That Key Station key has no compatible multisig export for the selected script type.");
    return;
  }
  hodlMsigKeyTarget = ta;
  ta.value = value;
  ta.dispatchEvent(new Event("input"));
  let position = [...document.querySelectorAll("#msig-keys .msig-key-row")].indexOf(row) + 1;
  if (status) status.textContent = `Added ${state.result?.masterFingerprint || state.name} to co-signer ${position}.`;
}
function hodlStripMsigKeyPath(value) {
  return String(value ?? "").trim().replace(/\/(?:<\d+(?:;\d+)*>|\d+)\/\*$/, "").replace(/(\/\d+[hH']?)+$/, "");
}
function hodlParseMsigRowKey(row) {
  try {
    return hodlParseMultisigCosigner(row.querySelector("textarea")?.value.trim() || "");
  } catch {
    return null;
  }
}
function hodlMsigBaseKeyId(parsed) {
  // The plain account key, ignoring any derivation path after it: this is
  // what "select the same key again" means.
  return hodlHex.encode(parsed.node.publicKey) + ":" + hodlHex.encode(parsed.node.chainCode);
}
function hodlMsigSuggestedDerivationPath(parsed, row) {
  let used = new Set();
  document.querySelectorAll("#msig-keys .msig-key-row").forEach((other) => {
    if (other === row) return;
    let otherParsed = hodlParseMsigRowKey(other);
    if (otherParsed) used.add(hodlCanonicalMultisigKey(otherParsed));
  });
  for (let index = 1; index <= 2147483647; index++) {
    if (!used.has(hodlCanonicalMultisigKey({ node: parsed.node, derivationPath: String(index) }))) return String(index);
  }
  return "1";
}
function hodlSyncMsigKeyReuse(row) {
  let panel = row?.querySelector(".msig-key-reuse"), ta = row?.querySelector("textarea");
  if (!panel || !ta) return;
  let note = panel.querySelector(".msig-key-reuse-note"), pathInput = panel.querySelector(".msig-key-reuse-path"), clear = panel.querySelector(".msig-key-reuse-clear"), parsed = hodlParseMsigRowKey(row), base = parsed ? hodlMsigBaseKeyId(parsed) : "", twinIndex = -1, twinPath = "", collides = false;
  if (base) [...document.querySelectorAll("#msig-keys .msig-key-row")].forEach((other, index) => {
    if (other === row) return;
    let otherParsed = hodlParseMsigRowKey(other);
    if (!otherParsed || hodlMsigBaseKeyId(otherParsed) !== base) return;
    if (twinIndex < 0) {
      twinIndex = index;
      twinPath = otherParsed.derivationPath || "";
    }
    if (hodlCanonicalMultisigKey(otherParsed) === hodlCanonicalMultisigKey(parsed)) collides = true;
  });
  panel.hidden = twinIndex < 0;
  if (twinIndex < 0) return;
  let current = parsed.derivationPath || "";
  if (collides) {
    note.textContent = `Co-signer ${twinIndex + 1} uses the same extended public key${current ? " and derivation path" : ""}. Append a different derivation path so this co-signer derives a different public key in the descriptor.`;
    if (pathInput && document.activeElement !== pathInput) pathInput.value = hodlMsigSuggestedDerivationPath(parsed, row);
  } else if (current) {
    note.textContent = `This reuses co-signer ${twinIndex + 1}'s extended key with derivation path /${current}, so its public keys stay distinct.`;
    if (pathInput && document.activeElement !== pathInput) pathInput.value = current;
  } else {
    note.textContent = `Co-signer ${twinIndex + 1} reuses this extended key with derivation path /${twinPath}, so each co-signer derives a different public key.`;
    if (pathInput && document.activeElement !== pathInput) pathInput.value = "";
  }
  if (clear) clear.hidden = !current;
}
function hodlRefreshMsigSessionPickers() {
  let options = hodlSessionMsigKeys().map(hodlMsigSessionKeyOption), reuse = Boolean(document.getElementById("msig-reuse-session-keys")?.checked), used = hodlMsigUsedBaseKeyIds(), globalBox = document.getElementById("msig-session-keys"), status = document.getElementById("msig-session-key-status");
  if (globalBox) {
    let available = reuse ? options : options.filter((option) => !option.baseId || !used.has(option.baseId));
    globalBox.replaceChildren();
    globalBox.hidden = !available.length;
    available.forEach((option) => {
      globalBox.appendChild(hodlCreateMsigSessionKeyButton(option, "session-key-option", Boolean(option.baseId) && used.has(option.baseId), () => hodlPickMsigSessionKey(option.state), (fingerprint) => `Add Key Station key ${fingerprint} to the next co-signer input`));
    });
    if (status && !status.textContent && options.length && !available.length) status.textContent = "All compatible Key Station keys are assigned. Enable key reuse to keep them available.";
    if (status && (!options.length || available.length) && status.textContent.startsWith("All compatible")) status.textContent = "";
  }
  document.querySelectorAll("#msig-keys .msig-key-row").forEach((row) => {
    let box = row.querySelector(".msig-session-keys"), parsed = hodlParseMsigRowKey(row), currentBaseId = parsed ? hodlMsigBaseKeyId(parsed) : "", usedElsewhere = hodlMsigUsedBaseKeyIds(row);
    if (!box) return;
    let available = reuse ? options : options.filter((option) => option.baseId === currentBaseId || !option.baseId || !usedElsewhere.has(option.baseId));
    box.replaceChildren();
    box.hidden = !available.length;
    available.forEach((option) => {
      box.appendChild(hodlCreateMsigSessionKeyButton(option, "msig-session-key", Boolean(option.baseId) && option.baseId === currentBaseId, () => hodlPickMsigSessionKey(option.state, row), (fingerprint) => `Use Key Station key ${fingerprint} for this co-signer`));
    });
    hodlSyncMsigKeyAvatar(row);
    hodlSyncMsigKeyReuse(row);
  });
}
function hodlFillKeys(values) {
  let n = Number(document.getElementById("msig-n").value || 3),
    saved = Array.isArray(values) ? values : hodlReadMsigXpubs(),
    box = document.getElementById("msig-keys"),
    listed = !hodlMsigKeysSorted();
  box.classList.toggle("msig-keys-listed", listed);
  box.innerHTML = "";
  for (let i = 0; i < n; i++) {
    let row = document.createElement("div");
    row.className = "msig-key-row";
    if (listed) {
      let head = document.createElement("div");
      head.className = "msig-key-row-head";
      let pos = document.createElement("span");
      pos.className = "msig-key-position";
      pos.textContent = hodlTText("Position {n}", { n: i + 1 });
      let moves = document.createElement("div");
      moves.className = "msig-key-move";
      let up = document.createElement("button");
      up.type = "button";
      up.className = "btn secondary msig-key-move-btn";
      up.dataset.msigMove = "-1";
      up.textContent = hodlTText("Move up");
      let down = document.createElement("button");
      down.type = "button";
      down.className = "btn secondary msig-key-move-btn";
      down.dataset.msigMove = "1";
      down.textContent = hodlTText("Move down");
      moves.append(up, down);
      head.append(pos, moves);
      row.appendChild(head)
    }
    let lab = document.createElement("label");
    lab.className = "field";
    lab.textContent = hodlTText("Co-signer {n} multisig extended public key", { n: i + 1 });
    let ta = document.createElement("textarea");
    ta.id = "msig-x-" + i;
    ta.autocomplete = "off";
    ta.spellcheck = false;
    ta.value = saved[i] || "";
    let chips = document.createElement("div");
    chips.className = "msig-session-keys";
    chips.hidden = true;
    chips.setAttribute("role", "group");
    chips.setAttribute("aria-label", "Key Station keys for co-signer " + (i + 1));
    let ident = document.createElement("div");
    ident.className = "msig-key-ident";
    ident.hidden = true;
    let identImage = document.createElement("img");
    identImage.className = "key-tab-lifehash";
    identImage.width = 22;
    identImage.height = 22;
    identImage.alt = "";
    identImage.hidden = true;
    let identFp = document.createElement("code");
    identFp.className = "msig-key-ident-fp";
    ident.append(identImage, identFp);
    lab.append(ident, ta);
    let reuse = document.createElement("div");
    reuse.className = "msig-key-reuse";
    reuse.hidden = true;
    let reuseNote = document.createElement("p");
    reuseNote.className = "field-note msig-key-reuse-note";
    let reuseControl = document.createElement("label");
    reuseControl.className = "msig-key-reuse-control";
    reuseControl.textContent = "Derivation path";
    let reusePath = document.createElement("input");
    reusePath.className = "msig-key-reuse-path";
    reusePath.type = "text";
    reusePath.inputMode = "numeric";
    reusePath.autocomplete = "off";
    reusePath.spellcheck = false;
    reusePath.placeholder = "1";
    reusePath.setAttribute("aria-label", `Derivation path for co-signer ${i + 1}`);
    let reuseApply = document.createElement("button");
    reuseApply.type = "button";
    reuseApply.className = "btn secondary msig-key-reuse-apply";
    reuseApply.textContent = "Apply path";
    let reuseClear = document.createElement("button");
    reuseClear.type = "button";
    reuseClear.className = "btn secondary msig-key-reuse-clear";
    reuseClear.textContent = "Remove path";
    reuseControl.append(reusePath);
    reuse.append(reuseNote, reuseControl, reuseApply, reuseClear);
    reuseApply.onclick = () => {
      let steps = reusePath.value.trim().replace(/'/g, "h").replace(/H/g, "h");
      if (!/^\d+(?:\/\d+)*$/.test(steps) || steps.split("/").some((step) => Number(step) > 2147483647)) {
        reusePath.classList.add("bad");
        reusePath.setAttribute("aria-invalid", "true");
        hodlHint(ta, false, "Enter an unhardened derivation path like 1 (each step 0 to 2,147,483,647).");
        return;
      }
      reusePath.classList.remove("bad");
      reusePath.removeAttribute("aria-invalid");
      ta.value = hodlStripMsigKeyPath(ta.value) + "/" + steps;
      ta.dispatchEvent(new Event("input"));
    };
    reusePath.addEventListener("keydown", (event) => {
      if (event.key === "Enter") {
        event.preventDefault();
        reuseApply.click();
      }
    });
    reuseClear.onclick = () => {
      ta.value = hodlStripMsigKeyPath(ta.value);
      ta.dispatchEvent(new Event("input"));
    };
    row.append(chips, lab, reuse);
    box.appendChild(row);
    ta.oninput = () => {
      ta.value = hodlFilterXpub(ta.value);
      hodlUpdateMsigScriptDetection();
      document.querySelectorAll("#msig-keys textarea").forEach(hodlCheckXpub);
      hodlUpdateMsigKeyOrderStatus();
      hodlInvalidateMsig();
      hodlSyncMsigKeyAvatar(row);
      hodlRefreshMsigSessionPickers();
      hodlSyncMsigDescriptorImport(true);
    };
    ta.addEventListener("focus", () => {
      hodlMsigKeyTarget = ta;
      let status = document.getElementById("msig-session-key-status");
      if (status) status.textContent = `The next selected Key Station key will fill co-signer ${i + 1}.`;
    });
  }
  hodlBindMsigKeyReorder(box);
  hodlSyncMsigKeyMoveButtons();
  hodlUpdateMsigScriptDetection();
  box.querySelectorAll("textarea").forEach((ta) => {
    if (ta.value) hodlCheckXpub(ta);
  });
  hodlUpdateMsigHint();
  hodlUpdateMsigAccount();
  hodlSyncMsigDescriptorImport();
  hodlUpdateMsigKeyOrderStatus();
  hodlRefreshMsigSessionPickers();
}
function hodlMultisigPrefixCompatible(parsed, kind, purpose) {
  if (kind === "p2tr" || purpose === 87) return parsed.family === "x";
  // BIP44/49/84 co-signers are singlesig account keys: generic xpub/tpub.
  if ((purpose === 44 || purpose === 49 || purpose === 84) && parsed.depth === 3) return parsed.family === "x";
  if (parsed.scope === "singlesig") return parsed.family === "x";
  if (kind === "p2sh-p2wsh") return parsed.family === "y";
  if (kind === "p2wsh") return parsed.family === "z";
  return false;
}
function hodlMultisigAccountKeyError(parsed, kind, purpose, hardening = { purpose: true, coinType: true, account: true, address: false }) {
  if (kind === "p2tr" || purpose === 87 || ((purpose === 44 || purpose === 49 || purpose === 84) && parsed.depth === 3)) {
    let standard = purpose === 87 ? "BIP87" : kind === "p2tr" ? "Taproot" : `BIP${purpose}`;
    if (parsed.depth !== 3) return `${standard} requires a depth-3 account key at m/purposeh/coinh/accounth; this key is depth ${parsed.depth}.`;
    if ((parsed.childNumber >= 0x80000000) !== hardening.account) return `The account index must be ${hardening.account ? "hardened" : "unhardened"}.`;
    return ""
  }
  if (kind === "p2wsh" || kind === "p2sh-p2wsh") {
    let scriptIndex = kind === "p2wsh" ? 2 : 1, label = kind === "p2wsh" ? "Native SegWit" : "Nested SegWit", expected = 2147483648 + scriptIndex;
    if (parsed.depth !== 4) return hodlNote("{label} requires a depth-4 script-account key ending in /{script}h; this key is depth {depth}.", { label, script: scriptIndex, depth: parsed.depth });
    if (parsed.childNumber !== expected) return hodlNote("{label} requires a script-account key whose final hardened child is {script}h.", { label, script: scriptIndex });
    return "";
  }
  if (purpose !== 45) {
    if (parsed.depth !== 3) return `Account-based Legacy derivation requires a depth-3 key at m/purposeh/coinh/accounth; this key is depth ${parsed.depth}.`;
    if ((parsed.childNumber >= 2147483648) !== hardening.account) return `The account index must be ${hardening.account ? "hardened" : "unhardened"}.`;
    return "";
  }
  if (parsed.depth !== 1) return `Legacy P2SH requires the depth-1 BIP45 purpose key at m/45h; this key is depth ${parsed.depth}.`;
  let expected = hardening.purpose ? 2147483648 + 45 : 45; // 45h when hardened
  if (parsed.childNumber !== expected) return `Legacy P2SH requires the ${hardening.purpose ? "hardened" : "unhardened"} BIP45 purpose child at m/${hodlPathComponent(45, hardening.purpose)}.`;
  return "";
}
function hodlMsigDerivedNode(parsed) {
  // The node a co-signer's public keys actually come from: the extended key
  // followed by any derivation path appended after it.
  return parsed.derivationPath ? parsed.node.derive("m/" + parsed.derivationPath) : parsed.node;
}
function hodlCanonicalMultisigKey(parsed) {
  // Co-signer identity is the derivation authority: the compressed public
  // key plus chain code after any appended derivation path. Version bytes
  // and the unauthenticated parent fingerprint in the extended-key
  // serialization are metadata; mutating only those bytes must not let one
  // key pass as two distinct co-signers.
  let node = hodlMsigDerivedNode(parsed);
  return hodlHex.encode(node.publicKey) + ":" + hodlHex.encode(node.chainCode);
}
function hodlDuplicateMultisigKey(ta, parsed) {
  let canonical = hodlCanonicalMultisigKey(parsed);
  for (let other of document.querySelectorAll("#msig-keys textarea")) {
    if (other === ta || !other.value.trim()) continue;
    try {
      if (hodlCanonicalMultisigKey(hodlParseMultisigCosigner(other.value.trim())) === canonical) return true;
    } catch {
    }
  }
  return false;
}
function hodlCheckXpub(ta) {
  let value = ta.value.trim();
  if (!value) {
    hodlHint(ta, true, "");
    return;
  }
  try {
    let parsed = hodlParseMultisigCosigner(value), coinType = hodlReadCoinType(document.getElementById("msig-network")), network = hodlNetworkFromCoinType(coinType), kind = hodlScriptKind(), purpose = hodlReadMsigPurpose(), hardening = hodlReadHardening("msig-");
    if (kind === "mixed") throw new Error("These keys do not define one compatible multisig policy. Use one script type.");
    if (parsed.isPrivate) throw new Error("Paste an extended public key, never an extended private key.");
    if (parsed.network !== network) throw new Error(`${parsed.prefix} is for ${parsed.network}; the multisig is set to ${network}.`);
    if (!hodlMultisigPrefixCompatible(parsed, kind, purpose)) throw new Error(parsed.scope === "singlesig" ? "Use a generic xpub/tpub here, or a proper uppercase multisig SLIP-132 export." : `${parsed.prefix} does not match the selected multisig script type.`);
    let accountError = hodlMultisigAccountKeyError(parsed, kind, purpose, hardening);
    if (accountError) throw new Error(accountError);
    if (!parsed.origin) throw new Error(`Paste ${hodlMultisigKeyPlaceholder(kind, network, purpose, coinType, hardening)} so a signer can recognize this key.`);
    let originError = hodlOriginMatchesParsedKey(parsed.origin, parsed);
    if (originError) throw new Error(originError);
    let scriptOriginError = hodlOriginScriptError(parsed.origin, kind, network, purpose, coinType, hardening);
    if (scriptOriginError) throw new Error(scriptOriginError);
    if (hodlDuplicateMultisigKey(ta, parsed)) throw new Error("This duplicates another co-signer. Append a derivation path (like /1) after the extended key so its public keys differ.");
    hodlHint(ta, true, parsed.derivationPath ? `${parsed.prefix} origin, checksum, and derivation path look valid · branches and indexes derive below the path /${parsed.derivationPath}` : `${parsed.prefix} origin, checksum, and derivation path look valid`);
  } catch (error) {
    hodlHint(ta, false, error.message || hodlT("Not a valid multisig extended public key"));
  }
}
function hodlResetMsigForm() {
  hodlSetMsigThresholds(2, 3);
  hodlSyncSelect(document.getElementById("msig-script-type"), "p2wsh");
  hodlSetMsigPurpose(48);
  let legacy = document.getElementById("msig-legacy-bip87");
  if (legacy) legacy.checked = false;
  let reuseSessionKeys = document.getElementById("msig-reuse-session-keys"), sessionStatus = document.getElementById("msig-session-key-status");
  if (reuseSessionKeys) reuseSessionKeys.checked = false;
  if (sessionStatus) sessionStatus.textContent = "";
  hodlMsigKeyTarget = null;
  hodlUpdateMsigLegacyControls();
  hodlSyncSelect(document.getElementById("msig-key-order"), "sorted");
  let advanced = document.getElementById("msig-advanced");
  if (advanced) advanced.open = !1;
  let coinType = document.getElementById("msig-network");
  if (coinType) coinType.value = String(hodlDefaultCoinType());
  hodlUpdateCoinTypeHelp(coinType, document.getElementById("msig-network-help"));
  let branchStart = document.getElementById("msig-branch-start"), branchRange = document.getElementById("msig-branch-range"), addressStart = document.getElementById("msig-address-start"), addressRange = document.getElementById("msig-address-range");
  if (branchStart) branchStart.value = "0";
  if (branchRange) branchRange.value = "2";
  if (addressStart) addressStart.value = "0";
  if (addressRange) addressRange.value = "5";
  hodlSetHardeningControls("msig-");
  hodlUpdateHardeningHelp("msig-");
  hodlUpdateAddressEstimate("msig-");
  hodlFillKeys([]);
  hodlSetWorkspaceError("msig", null);
  let descriptor = document.getElementById("msig-descriptor"), descriptorStatus = document.getElementById("msig-descriptor-status"), descriptorPanel = document.getElementById("msig-import");
  if (descriptor) descriptor.value = "";
  if (descriptorStatus) {
    delete descriptorStatus.dataset.result;
    descriptorStatus.textContent = "";
    descriptorStatus.hidden = true;
  }
  if (descriptorPanel) descriptorPanel.open = false;
}
function hodlInitMsig() {
  hodlBindMsigThresholdSlider();
  let recheck = () => {
      hodlUpdateMsigScriptDetection();
      hodlInvalidateMsig();
      document.querySelectorAll("#msig-keys textarea").forEach(hodlCheckXpub);
      hodlUpdateMsigKeyOrderStatus();
      hodlRefreshMsigSessionPickers();
    },
    script = document.getElementById("msig-script-type"),
    purpose = document.getElementById("msig-purpose"),
    coinType = document.getElementById("msig-network"),
    branchStartInput = document.getElementById("msig-branch-start"),
    addressStartInput = document.getElementById("msig-address-start"),
    legacy = document.getElementById("msig-legacy-bip87"),
    reuseSessionKeys = document.getElementById("msig-reuse-session-keys"),
    keyOrder = document.getElementById("msig-key-order");
  reuseSessionKeys?.addEventListener("change", () => {
    let status = document.getElementById("msig-session-key-status");
    if (status) status.textContent = reuseSessionKeys.checked ? "Selected Key Station keys remain available for every co-signer input." : "Each selected Key Station key is removed from the other co-signer choices.";
    hodlRefreshMsigSessionPickers();
    hodlSyncMsigClearButton(true);
  });
  script.addEventListener("change", () => {
    if (script.value !== "mixed") script.dataset.lastConcrete = script.value;
    hodlSetMsigPurpose(hodlStandardMsigPurpose(script.value));
    recheck();
  });
  [purpose, coinType, branchStartInput, addressStartInput].forEach((input) => {
    input?.addEventListener("keydown", (event) => {
      if (["e", "E", "+", "-", "."].includes(event.key)) event.preventDefault();
    });
    input?.addEventListener("paste", (event) => {
      if (!/^\d+$/.test(event.clipboardData?.getData("text") ?? "")) event.preventDefault();
    });
  });
  purpose?.addEventListener("input", () => {
    try {
      hodlReadMsigPurpose();
    } catch {
    }
    hodlUpdateMsigLegacyControls();
    hodlUpdateMsigKeyPlaceholders();
    hodlInvalidateMsig();
    document.querySelectorAll("#msig-keys textarea").forEach(hodlCheckXpub);
    hodlSyncMsigClearButton(true);
  });
  if (legacy) legacy.addEventListener("change", () => {
    hodlSetMsigPurpose(hodlStandardMsigPurpose());
    hodlUpdateMsigLegacyControls();
    hodlUpdateMsigKeyPlaceholders();
    hodlInvalidateMsig();
    document.querySelectorAll("#msig-keys textarea").forEach(hodlCheckXpub);
    hodlSyncMsigClearButton(true);
  });
  if (keyOrder) keyOrder.addEventListener("change", () => {
    let advanced = document.getElementById("msig-advanced");
    if (keyOrder.value === "listed" && advanced) advanced.open = !0;
    hodlFillKeys();
    hodlInvalidateMsig();
    hodlSyncMsigClearButton(!0)
  });
  coinType?.addEventListener("input", () => {
    hodlUpdateCoinTypeHelp(coinType, document.getElementById("msig-network-help"));
    recheck();
    hodlSyncMsigClearButton(true);
  });
  ["msig-purpose-harden", "msig-network-harden", "msig-account-harden", "msig-branch-start-harden", "msig-address-start-harden"].forEach((id) => document.getElementById(id)?.addEventListener("change", () => {
    hodlUpdateHardeningHelp("msig-");
    hodlUpdateMsigKeyPlaceholders();
    hodlUpdateMsigAccount();
    recheck();
    hodlSyncMsigClearButton(true);
  }));
  ["msig-branch-start", "msig-branch-range"].forEach((id) => document.getElementById(id)?.addEventListener("input", () => {
    hodlSyncBranchRangeLimit("msig-");
    hodlInvalidateMsig();
  }));
  ["msig-address-start", "msig-address-range"].forEach((id) => document.getElementById(id)?.addEventListener("input", () => {
    hodlSyncAddressRangeLimit("msig-");
    hodlInvalidateMsig();
  }));
  hodlResetMsigForm();
  hodlElement("#msig-go").onclick = () => hodlHandleDerivationButton("msig", hodlBuildMsig);
  hodlElement("#msig-wipe").onclick = hodlWipeActiveMsig;
  document.getElementById("msig-descriptor-import")?.addEventListener("click", hodlImportMsigDescriptor);
  document.getElementById("msig-descriptor")?.addEventListener("input", () => {
    let status = document.getElementById("msig-descriptor-status");
    if (status) {
      delete status.dataset.result;
      status.textContent = "";
      status.hidden = true;
    }
    hodlSyncMsigDescriptorImport();
  });
}
function hodlScriptKind() {
  return document.getElementById("msig-script-type")?.value || "p2wsh";
}

function hodlTaprootNumsKey() {
  return hodlHex.decode("50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0")
}

function hodlXOnlyPubkey(pubkey) {
  if (!pubkey || pubkey.length < 32) throw new Error("Could not derive a public key");
  return pubkey.length === 33 ? pubkey.slice(1) : pubkey.slice(0, 32)
}

// Multisig scripts and addresses are evaluated by rust-miniscript in the
// WASM crate: the keys become a descriptor (sortedmulti/multi, or
// sortedmulti_a/multi_a under a BIP341 NUMS internal key for Taproot) and the
// crate derives the output. Sorting is the descriptor's job, as BIP67 and
// BIP386 intend — multi keeps the listed order, sortedmulti ignores it.
function hodlMsigAddr(pubkeys, m, network, kind, sorted = !0) {
  let op = kind === "p2tr" ? sorted ? "sortedmulti_a" : "multi_a" : sorted ? "sortedmulti" : "multi";
  let inner = `${op}(${m},${pubkeys.map((key) => hodlHex.encode(kind === "p2tr" ? hodlXOnlyPubkey(key) : key)).join(",")})`;
  let descriptor = kind === "p2tr" ? `tr(${hodlHex.encode(hodlTaprootNumsKey())},${inner})` : kind === "p2wsh" ? `wsh(${inner})` : kind === "p2sh-p2wsh" ? `sh(wsh(${inner}))` : `sh(${inner})`;
  let derived = descriptorDerive(descriptor, 0, network);
  if (!derived.address) throw new Error("Failed to build the multisig address");
  return { address: derived.address, scriptHex: derived.scriptHex, kind };
}
function hodlValidatedMsigInputs() {
  let coinType = hodlReadCoinType(document.getElementById("msig-network")), network = hodlNetworkFromCoinType(coinType), addressWindow = hodlReadAddressWindow("msig-"), branchWindow = hodlReadBranchWindow("msig-"), count = addressWindow.range, addressStart = addressWindow.start, branchStart = branchWindow.start, branchRange = branchWindow.range, hardening = hodlReadHardening("msig-"), n = Number(document.getElementById("msig-n")?.value), m = Number(document.getElementById("msig-m")?.value);
  if (hardening.branch) throw new Error("Hardened address branches cannot be derived from the supplied multisig extended public keys. Turn off Harden for Starting address branch index.");
  if (hardening.address) throw new Error("Hardened address indexes cannot be derived from multisig extended public keys. Turn off Harden for Starting address index.");
  if (!(m >= 1 && n >= 1 && m <= n && n <= 15)) throw new Error("Pick how many signatures out of how many keys.");
  let kind = hodlScriptKind(), purpose = hodlReadMsigPurpose(), legacyStandard = hodlSelectedLegacyMultisigStandard(), nodes = [], xpubs = [], keyTokens = [], accountNumbers = [], purposeIndexes = [];
  if (kind === "mixed") throw hodlError("Co-signer keys indicate different script types. Export every key for the same multisig script type before deriving.");
  for (let index = 0; index < n; index++) {
    let field = document.getElementById("msig-x-" + index), raw = field?.value.trim() || "";
    if (!raw) throw hodlError("Paste an origin and extended public key for co-signer {n}.", { n: index + 1 });
    let parsed = hodlParseMultisigCosigner(raw);
    if (parsed.isPrivate) throw new Error("Co-signer " + (index + 1) + " is an extended private key. Paste only an extended public key.");
    if (parsed.network !== network) throw new Error(`Co-signer ${index + 1}'s ${parsed.prefix} is for ${parsed.network}, but this multisig is set to ${network}.`);
    if (!hodlMultisigPrefixCompatible(parsed, kind, purpose)) throw new Error(parsed.scope === "singlesig" ? `Co-signer ${index + 1} uses a singlesig ${parsed.prefix}. Use a generic ${hodlExtendedKeyVersions[network].x.pubName}, or the proper uppercase multisig export for this script type.` : `Co-signer ${index + 1}'s ${parsed.prefix} does not match the selected multisig script type.`);
    let accountError = hodlMultisigAccountKeyError(parsed, kind, purpose, hardening);
    if (accountError) throw new Error(`Co-signer ${index + 1}: ${accountError}`);
    if (!parsed.origin) throw new Error(`Co-signer ${index + 1} needs a key origin so a signer can recognize this key. Paste ${hodlMultisigKeyPlaceholder(kind, network, purpose, coinType, hardening)} as exported by the device.`);
    purposeIndexes.push(hodlMultisigPurposeIndex(parsed.origin));
    let originError = hodlOriginMatchesParsedKey(parsed.origin, parsed);
    if (originError) throw new Error(`Co-signer ${index + 1}: ${originError}`);
    let scriptOriginError = hodlOriginScriptError(parsed.origin, kind, network, purpose, coinType, hardening);
    if (scriptOriginError) throw new Error(`Co-signer ${index + 1}: ${scriptOriginError}`);
    let accountNumber = hodlMultisigAccountNumber(parsed.origin, kind, purpose, hardening.account);
    if (accountNumber != null) accountNumbers.push(accountNumber);
    let node = hodlMsigDerivedNode(parsed), canonical = hodlCanonicalMultisigKey(parsed);
    if (xpubs.includes(canonical)) throw hodlError("Co-signer {n} duplicates an earlier co-signer. Every slot must derive distinct public keys; append a derivation path (like /1) after the extended key to reuse it.", { n: index + 1 });
    nodes.push(node);
    xpubs.push(canonical);
    keyTokens.push(hodlMultisigKeyToken(parsed, network));
  }
  let uniquePurposes = [...new Set(purposeIndexes)];
  if (uniquePurposes.length !== 1 || uniquePurposes[0] !== purpose) throw hodlError("Every co-signer purpose index must match the selected Purpose.");
  let accountSummary = hodlSummarizeMultisigAccounts(accountNumbers), accountWarning = hodlMultisigAccountWarning(accountSummary);
  return { network, coinType, count, addressStart, branchStart, branchRange, hardening, n, m, kind, purpose, legacyStandard, nodes, xpubs, keyTokens, accountSummary, accountWarning };
}
async function hodlBuildMsig(progress) {
  let error = document.getElementById("msig-error");
  hodlSetWorkspaceError("msig", null);
  try {
    let {
      network,
      coinType,
      count,
      addressStart,
      branchStart,
      branchRange,
      n,
      m,
      kind,
      purpose,
      hardening,
      legacyStandard,
      nodes,
      xpubs,
      keyTokens,
      accountSummary,
      accountWarning
    } = hodlValidatedMsigInputs(), bip45 = kind === "p2sh" && legacyStandard === "bip45";
    let sorted = hodlMsigKeysSorted(), addressBranches = [];
    progress.setTotal(count * branchRange);
    for (let branch = branchStart; branch < branchStart + branchRange; branch++) {
      let suffix = bip45 ? `/0/${branch}/*` : `/${branch}/*`, path = bip45 ? `m/0/${branch}/` : `m/${branch}/`, inner = keyTokens.map(key => key + suffix).join(","), descriptor = hodlMsigInnerDescriptor(kind, m, inner, sorted), rows = [];
      for (let index = addressStart; index < addressStart + count; index++) {
        // The branch descriptor is the source of truth: rust-miniscript
        // derives the address from it, so what is shown here cannot drift
        // from the watch-only descriptor exported below.
        let derived = descriptorDerive(descriptor, index, network), publicKeys = derived.pubkeys.map((key) => hodlHex.decode(key));
        if (!derived.address) throw new Error("Could not derive a multisig address");
        // Final defense behind the co-signer identity check: never emit a
        // script whose public keys repeat, whatever the supplied encodings were.
        if (new Set(publicKeys.map(hodlHex.encode)).size !== publicKeys.length) throw new Error("Two co-signers derive the same public key. Every co-signer must use a distinct extended public key.");
        rows.push(Object.assign({ index, branch, role: hodlAddressBranchRole(branch), path: path.slice(1) + index }, { address: derived.address, scriptHex: derived.scriptHex, kind }));
        let pause = progress.step();
        if (pause) await pause;
      }
      addressBranches.push({ branch, role: hodlAddressBranchRole(branch), label: hodlAddressBranchLabel(branch), publicDescriptor: hodlDescriptorWithChecksum(descriptor), privateDescriptor: null, rows });
    }
    let receiveBranch = addressBranches.find((entry) => entry.branch === 0), changeBranch = addressBranches.find((entry) => entry.branch === 1);
    let notes = ["This is watch-only. Private keys never entered this calculator.", "Each key origin lets a signer match its seed to one co-signer.", "A signer is only needed when you spend."];
    if (bip45) notes.push("Legacy BIP45 addresses use co-signer branch 0 before the selected address branch.");
    if (kind === "p2sh" && legacyStandard === "bip87") notes.push("Legacy P2SH uses the selected BIP87 account paths. Keep the descriptor with every seed backup.");
    if (kind === "p2tr") notes.push("Taproot script-path multisig. The internal key is the BIP341 NUMS point, so spending is only possible through the " + (sorted ? "sortedmulti_a" : "multi_a") + " script path.");
    if (!sorted) notes.push("This wallet uses " + hodlMsigPolicyOp(kind, !1) + ", so the listed co-signer order is part of the script. Reordering keys changes addresses.");
    hodlWalletResult = {
      kind: "msig",
      network,
      coinType,
      m,
      n,
      script: kind,
      purpose,
      hardening,
      sorted,
      scriptOrder: hodlMsigScriptOrder(keyTokens),
      scriptStandard: legacyStandard,
      account: accountSummary.account,
      accountMixed: accountSummary.mixed,
      addressStart,
      addressRange: count,
      branchStart,
      branchRange,
      nodes,
      xpubs,
      addressBranches,
      receiveDescriptor: receiveBranch?.publicDescriptor ?? null,
      changeDescriptor: changeBranch?.publicDescriptor ?? null,
      walletDescriptor: hodlWatchOnlyMultipathDescriptor(addressBranches[0].publicDescriptor, addressBranches.map((entry) => entry.branch)),
      receive: receiveBranch?.rows ?? [],
      change: changeBranch?.rows ?? [],
      notes,
      warnings: accountWarning ? [accountWarning] : []
    };
    hodlCaptureMsig();
    hodlJournalLog("derive", hodlWalletResult.m && hodlWalletResult.n ? `${hodlWalletResult.m}-of-${hodlWalletResult.n}` : "msig");
    hodlSnapshotMsigSummary();
    hodlCommitDerivedMsig();
    hodlFocusWalletResult();
    return true;
  } catch (exception) {
    if (exception instanceof HodlDerivationCancelledError) throw exception;
    hodlWalletResult = null;
    hodlClearMsigOut();
    error.textContent = exception.message || String(exception);
    hodlSetWorkspaceError("msig", hodlErrorSpecFrom(exception));
    hodlCaptureMsig();
    hodlJournalLog("derive-error");
    return false;
  }
}
function hodlClearMsigOut() {
  let out = document.getElementById("msig-out");
  if (out) out.innerHTML = "";
}
function hodlShowMsig() {
  if (!hodlWalletResult || hodlWalletResult.kind !== "msig") return;
  hodlRevealPrivate = false;
  let out = document.getElementById("msig-out");
  if (!out) return;
  let accountLabel = hodlWalletResult.accountMixed ? " \xB7 Account Mixed" : hodlWalletResult.account == null ? "" : ` \xB7 Account ${hodlWalletResult.account}`, purposeLabel = Number.isSafeInteger(hodlWalletResult.purpose) ? ` \xB7 Purpose ${hodlPathComponent(hodlWalletResult.purpose, hodlWalletResult.hardening?.purpose !== false)}` : "", branches = hodlAccountAddressBranches(hodlWalletResult), firstBranch = branches[0], firstAddress = firstBranch?.rows[0], firstIndex = firstAddress?.index ?? 0, firstLabel = firstBranch ? hodlAddressBranchLabel(firstBranch.branch) : "Address";
  out.innerHTML = `
    <section class="card account-result-card">
      <div class="kicker">${hodlWalletResult.m}-of-${hodlWalletResult.n} multisig${purposeLabel}${hodlWalletResult.sorted===!1?" \xB7 listed order":""} \xB7 ${hodlWalletResult.network}${accountLabel}</div>
      <h2 tabindex="-1">Your multisig wallet</h2>
      <p class="muted">${hodlT("Anyone can pay these addresses. Spending later needs {m} signature(s) from the configured {n} signing key(s). This screen has no private keys.", { m: hodlWalletResult.m, n: hodlWalletResult.n })}</p>
      ${hodlWalletMessages(hodlWalletResult,"multisig")}
      ${hodlWalletResult.sorted===!1&&hodlWalletResult.scriptOrder?.length?`<section class="account-result-section" aria-labelledby="multisig-order-heading"><div class="wallet-data-section-head"><h3 id="multisig-order-heading">${hodlT("Script key order")}</h3><p class="muted">${hodlT("{op} uses the co-signers in this order. Changing the order creates a different wallet.", { op: hodlMsigPolicyOp(hodlWalletResult.script,!1) })}</p></div><ol class="msig-script-order">${hodlWalletResult.scriptOrder.map(item=>`<li><span class="msig-script-order-position">${hodlT("Position {n}", { n: item.position })}</span><code>${hodlEscapeHtml(item.fingerprint?item.fingerprint+"/"+item.path:item.fingerprint||"")}</code></li>`).join("")}</ol></section>`:""}
      <section class="account-result-section account-watch-section" aria-labelledby="multisig-watch-heading">
        <div class="wallet-data-section-head">
          <h3 id="multisig-watch-heading">Watch-only wallet data</h3>
          <p class="muted">These descriptors reveal every address in the selected branches for this multisig, but cannot authorize spending.</p>
        </div>
        ${hodlWatchOnlyDescriptorExport(hodlWalletResult.receiveDescriptor, hodlWalletResult.changeDescriptor, branches)}
      </section>
      <section class="account-result-section account-address-section" aria-labelledby="multisig-address-heading">
        <div class="wallet-data-section-head">
          <h3 id="multisig-address-heading">Addresses</h3>
          <p class="muted">Verify the first selected address on every signing device before accepting bitcoin.</p>
        </div>
        ${firstAddress ? `<div class="account-address-lead"><h4 class="wallet-data-subtitle">${hodlEscapeHtml(firstLabel)} address #${firstIndex}</h4><div class="qr" aria-label="Multisig ${hodlEscapeHtml(firstLabel.toLowerCase())} address ${firstIndex} QR code">${hodlQrSvg(firstAddress.address)}</div><p class="mono">${hodlEscapeHtml(firstAddress.address)}</p><p class="muted mono">${hodlEscapeHtml(firstAddress.path)}</p></div>` : ""}
        ${hodlAddressBranchTables(branches, false, "msig")}
        ${hodlAddressMatchMarkup()}
      </section>
      <p class="muted">${hodlT("Import the watch-only wallet descriptor into Sparrow or another wallet.")}</p>
    </section>`;
  hodlBindAddressVirtualization(hodlAddressBranchVirtualConfigs(branches, false, "msig"));
  hodlBindAddressMatch()
}
var hodlPsbtPriv = null, hodlPsbtHd = null, hodlPsbtSource = "", hodlPsbtSessionSpec = { key: "No session key. Inspect-only mode." }, hodlPsbtLast = null, hodlPsbtErrorSpec = null;
function hodlPsbtSessionText() {
  return hodlTText(hodlPsbtSessionSpec.key, hodlPsbtSessionSpec.vars);
}
function hodlSetPsbtError(spec) {
  hodlPsbtErrorSpec = spec || null;
  let error = document.getElementById("psbt-error");
  if (!error) return;
  error.textContent = !spec ? "" : spec.key ? hodlTText(spec.key, spec.vars) : spec.raw || "";
}
function hodlRefreshPsbtLocale() {
  let session = document.getElementById("psbt-session");
  if (session) session.textContent = hodlPsbtSessionText();
  if (hodlPsbtErrorSpec) hodlSetPsbtError(hodlPsbtErrorSpec);
  if (hodlPsbtLast) {
    let output = document.getElementById("psbt-out");
    if (output) output.innerHTML = hodlRenderPsbt(hodlPsbtLast);
  }
}
function hodlPsbtNeed(bytes, offset, length, message) {
  if (!Number.isSafeInteger(offset) || !Number.isSafeInteger(length) || offset < 0 || length < 0 || offset + length > bytes.length) throw new Error(message || "PSBT ended early.");
}
function hodlR32(bytes, offset) {
  hodlPsbtNeed(bytes, offset, 4, "PSBT ended inside a 32-bit value.");
  return new DataView(bytes.buffer, bytes.byteOffset + offset, 4).getUint32(0, true);
}
function hodlR64(bytes, offset) {
  hodlPsbtNeed(bytes, offset, 8, "PSBT ended inside a 64-bit value.");
  let value = 0n;
  for (let i = 0; i < 8; i++) value |= BigInt(bytes[offset + i]) << BigInt(8 * i);
  return value;
}
function hodlVarInt(bytes, offset) {
  hodlPsbtNeed(bytes, offset, 1);
  let marker = bytes[offset];
  if (marker < 253) return [marker, offset + 1];
  if (marker === 253) {
    hodlPsbtNeed(bytes, offset + 1, 2);
    let value2 = bytes[offset + 1] | bytes[offset + 2] << 8;
    if (value2 < 253) throw new Error("Non-canonical compact integer.");
    return [value2, offset + 3];
  }
  if (marker === 254) {
    let value2 = hodlR32(bytes, offset + 1);
    if (value2 <= 65535) throw new Error("Non-canonical compact integer.");
    return [value2, offset + 5];
  }
  let value = hodlR64(bytes, offset + 1);
  if (value <= 0xffffffffn) throw new Error("Non-canonical compact integer.");
  if (value > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error("PSBT field is too large for EntropyLab.");
  return [Number(value), offset + 9];
}
function hodlEq(a, b) {
  if (!a || !b || a.length !== b.length) return false;
  let difference = 0;
  for (let i = 0; i < a.length; i++) difference |= a[i] ^ b[i];
  return difference === 0;
}
function hodlHexRev(bytes) {
  let copy = new Uint8Array(bytes);
  copy.reverse();
  return hodlHex.encode(copy);
}
function hodlB64(value) {
  let binary = atob(value), bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}
function hodlPsbtBytes(raw) {
  let value = raw.trim(), compact = value.replace(/\s/g, "");
  if (!value) throw new Error("Paste a PSBT v0 or a raw Bitcoin transaction.");
  if (compact.length > 7e6) throw new Error("This file is too large to inspect safely.");
  let bytes;
  if (/^[0-9a-fA-F]+$/.test(compact) && compact.length % 2 === 0 && compact.length >= 10) bytes = hodlHex.decode(compact.toLowerCase());
  else try {
    bytes = hodlB64(compact);
  } catch {
    throw new Error("That does not look like a PSBT or raw transaction in base64 or hex.");
  }
  if (bytes.length > 5e6) throw new Error("This file is too large to inspect safely.");
  return bytes;
}
function hodlReadMap(bytes, offset) {
  let entries = [], keys = /* @__PURE__ */ new Set();
  for (; ; ) {
    if (entries.length >= 1e4) throw new Error("PSBT map has too many entries to inspect safely.");
    let [keyLength, keyStart] = hodlVarInt(bytes, offset);
    if (keyLength === 0) return { entries, next: keyStart };
    hodlPsbtNeed(bytes, keyStart, keyLength, "PSBT ended inside a key.");
    let key = bytes.slice(keyStart, keyStart + keyLength), keyHex = hodlHex.encode(key);
    if (keys.has(keyHex)) throw new Error("PSBT contains a duplicate key.");
    keys.add(keyHex);
    offset = keyStart + keyLength;
    let [valueLength, valueStart] = hodlVarInt(bytes, offset);
    hodlPsbtNeed(bytes, valueStart, valueLength, "PSBT ended inside a value.");
    let value = bytes.slice(valueStart, valueStart + valueLength);
    offset = valueStart + valueLength;
    entries.push({ type: key[0], keydata: key.slice(1), key, val: value });
  }
}
function hodlTx(bytes) {
  // The consensus decode runs on rust-bitcoin's Transaction in the WASM
  // module (src/js/tx.js); the BIP174 unsigned-transaction rules (no witness
  // marker, empty scriptSigs) are enforced here.
  //
  // The marker is checked on the raw bytes before the decode: rust-bitcoin
  // rejects a marker whose witness stacks are all empty, so asking the parsed
  // transaction would report that hostile PSBT as a generic truncation. The
  // decoder's own failures still collapse to one message — naming which byte
  // ran out would need distinct return codes from el_tx_parse.
  hodlPsbtNeed(bytes, 4, 2, "Unsigned transaction ended early.");
  if (bytes[4] === 0 && bytes[5] === 1) throw new Error("The PSBT v0 unsigned transaction must not contain a witness marker.");
  let tx;
  try {
    tx = parseRawTx(bytes);
  } catch (error) {
    const message = String((error && error.message) || "");
    if (message.includes("trailing")) throw new Error("Unsigned transaction contains trailing bytes.");
    if (message.includes("too many inputs")) throw new Error("Unsigned transaction has too many inputs.");
    if (message.includes("too many outputs")) throw new Error("Unsigned transaction has too many outputs.");
    throw new Error("Unsigned transaction ended early.");
  }
  for (const input of tx.inputs) {
    if (input.scriptSig.length) throw new Error("PSBT v0 unsigned transaction inputs must have empty scriptSigs.");
  }
  return {
    version: tx.version,
    inputs: tx.inputs.map((input) => ({ txid: input.txid, vout: input.vout, script: input.scriptSig, sequence: input.sequence })),
    outputs: tx.outputs,
    locktime: tx.locktime,
    raw: tx.raw
  };
}
function hodlParsePsbt(bytes) {
  if (bytes.length < 5 || bytes[0] !== 112 || bytes[1] !== 115 || bytes[2] !== 98 || bytes[3] !== 116 || bytes[4] !== 255) throw new Error("Not a PSBT. Bitcoin PSBTs start with the bytes psbt followed by ff.");
  let offset = 5, globalMap = hodlReadMap(bytes, offset);
  offset = globalMap.next;
  let versionEntry = globalMap.entries.find((entry) => entry.type === 251 && entry.keydata.length === 0);
  if (versionEntry) {
    if (versionEntry.val.length !== 4 || hodlR32(versionEntry.val, 0) !== 0) throw new Error("EntropyLab currently supports PSBT v0 only.");
  }
  let unsignedEntries = globalMap.entries.filter((entry) => entry.type === 0 && entry.keydata.length === 0);
  if (unsignedEntries.length !== 1) throw new Error("This PSBT must contain exactly one unsigned transaction.");
  let tx = hodlTx(unsignedEntries[0].val), inputs = [], outputs = [];
  for (let i = 0; i < tx.inputs.length; i++) {
    if (offset >= bytes.length) throw new Error("PSBT is missing an input map.");
    let map = hodlReadMap(bytes, offset);
    offset = map.next;
    inputs.push(map.entries);
  }
  for (let i = 0; i < tx.outputs.length; i++) {
    if (offset >= bytes.length) throw new Error("PSBT is missing an output map.");
    let map = hodlReadMap(bytes, offset);
    offset = map.next;
    outputs.push(map.entries);
  }
  if (offset !== bytes.length) throw new Error("PSBT contains trailing data or extra maps.");
  return { tx, global: globalMap.entries, inputs, outputs };
}
function hodlSats(number) {
  let value = typeof number === "bigint" ? number : BigInt(number), negative = value < 0n;
  if (negative) value = -value;
  let whole = value / 100000000n, fraction = value % 100000000n;
  return (negative ? "-" : "") + whole.toString() + "." + fraction.toString().padStart(8, "0");
}
function hodlAddr(script, network) {
  try {
    let address = addressFromScript(script, network);
    if (address) return address;
  } catch {
  }
  return "script " + hodlHex.encode(script);
}
function hodlFind(entries, type) {
  return entries.filter((entry) => entry.type === type);
}
function hodlWitUtxo(entries) {
  let entry = hodlFind(entries, 1).find((item) => item.keydata.length === 0);
  if (!entry) return null;
  if (entry.val.length < 9) throw new Error("A witness UTXO field is truncated.");
  let amount = hodlR64(entry.val, 0), parsed = hodlVarInt(entry.val, 8), scriptLength = parsed[0], scriptStart = parsed[1];
  hodlPsbtNeed(entry.val, scriptStart, scriptLength, "A witness UTXO script is truncated.");
  if (scriptStart + scriptLength !== entry.val.length) throw new Error("A witness UTXO contains trailing bytes.");
  return { amount, script: entry.val.slice(scriptStart) };
}
function hodlPartialSigs(entries) {
  return hodlFind(entries, 2).map((entry) => {
    let signature = entry.val;
    if (signature.length < 2) return { pubkey: entry.keydata, der: new Uint8Array(), sighash: 0, raw: signature };
    return { pubkey: entry.keydata, der: signature.slice(0, -1), sighash: signature[signature.length - 1], raw: signature };
  });
}
function hodlTapSigs(entries) {
  return hodlFind(entries, 19).concat(hodlFind(entries, 20));
}
// PSBT_IN_SIGHASH_TYPE (input type 0x03): empty keydata, four-byte
// little-endian policy. It must be decoded before signing, and shown even
// without a session key.
function hodlSighashPolicy(entries) {
  let declarations = hodlFind(entries, 3).filter((entry) => entry.keydata.length === 0);
  if (!declarations.length) return null;
  if (declarations[0].val.length !== 4) throw new Error("A sighash policy field is malformed.");
  return new DataView(declarations[0].val.buffer, declarations[0].val.byteOffset, 4).getUint32(0, true);
}
// The base type occupies the low seven bits; bit 0x80 marks ANYONECANPAY.
function hodlSighashLabel(policy) {
  let base = policy & 0x7f, baseName = base === 1 ? "SIGHASH_ALL" : base === 2 ? "SIGHASH_NONE" : base === 3 ? "SIGHASH_SINGLE" : "unknown 0x" + base.toString(16);
  return baseName + ((policy & 0x80) ? " | ANYONECANPAY" : "") + " (0x" + policy.toString(16) + ")";
}
// Exact SIGHASH_ALL is the only policy that commits to every displayed
// output. Anything else, or a disagreement between the PSBT field and a
// signature's appended byte, is blocking — no session key required.
function hodlSighashProblems(declared, suffix) {
  let problems = [], tr = hodlT;
  if (declared !== null && declared !== 1) {
    let policy = hodlSighashLabel(declared);
    problems.push(tr("The PSBT requests {policy}, which does not commit to all shown outputs.", { policy }));
  }
  if (suffix !== null && suffix !== 1) {
    let policy = hodlSighashLabel(suffix);
    problems.push(tr("This signature uses {policy}, which does not commit to all shown outputs.", { policy }));
  }
  if (declared !== null && suffix !== null && declared !== suffix) problems.push(tr("The PSBT-declared policy and the signature's appended sighash byte disagree."));
  return problems;
}
function hodlFinalized(entries) {
  return entries.some((entry) => entry.type === 7 || entry.type === 8);
}
// Finalized inputs carry ECDSA signatures in PSBT_IN_FINAL_SCRIPTSIG (0x07)
// or PSBT_IN_FINAL_SCRIPTWITNESS (0x08) instead of partial-signature
// records. Both are decoded with strict size and item-count bounds so
// finalized signatures still participate in repeated-nonce analysis; a
// signature that cannot be decoded or associated must block a clean verdict
// rather than pass silently (issue #87).
function hodlScriptPushes(script) {
  let items = [], offset = 0;
  while (offset < script.length) {
    let opcode = script[offset++], length;
    if (opcode > 78) continue; // not a push opcode: no data to extract
    if (opcode <= 75) length = opcode;
    else if (opcode === 76) {
      hodlPsbtNeed(script, offset, 1, "A final script push is truncated.");
      length = script[offset++];
    } else if (opcode === 77) {
      hodlPsbtNeed(script, offset, 2, "A final script push is truncated.");
      length = script[offset] | script[offset + 1] << 8;
      offset += 2;
    } else {
      hodlPsbtNeed(script, offset, 4, "A final script push is truncated.");
      length = hodlR32(script, offset);
      offset += 4;
    }
    hodlPsbtNeed(script, offset, length, "A final script push is truncated.");
    items.push(script.slice(offset, offset + length));
    offset += length;
  }
  return items;
}
function hodlWitnessStackItems(value) {
  let [count, offset] = hodlVarInt(value, 0);
  if (count > 100) throw new Error("A final witness stack has too many items.");
  let items = [];
  for (let index = 0; index < count; index++) {
    let [length, start] = hodlVarInt(value, offset);
    hodlPsbtNeed(value, start, length, "A final witness item is truncated.");
    items.push(value.slice(start, start + length));
    offset = start + length;
  }
  if (offset !== value.length) throw new Error("A final witness stack has trailing bytes.");
  return items;
}
function hodlLooksPubkey(item) {
  return (item.length === 33 && (item[0] === 2 || item[0] === 3)) || (item.length === 65 && item[0] === 4);
}
function hodlLooksSignature(item) {
  // DER sequence plus the appended sighash byte: 9 to 73 bytes.
  return item.length >= 9 && item.length <= 73 && item[0] === 48;
}
function hodlFinalSigs(entries, witnessUtxo, tx, index) {
  let items = [], candidates = [], malformed = false;
  for (let entry of hodlFind(entries, 7)) {
    if (entry.keydata.length) { malformed = true; continue; }
    try {
      items.push(...hodlScriptPushes(entry.val));
    } catch {
      malformed = true;
    }
  }
  for (let entry of hodlFind(entries, 8)) {
    if (entry.keydata.length) { malformed = true; continue; }
    try {
      items.push(...hodlWitnessStackItems(entry.val));
    } catch {
      malformed = true;
    }
  }
  for (let item of items) if (hodlLooksPubkey(item)) candidates.push(item);
  // Multisig co-signer keys live in the redeem/witness script, not the stack.
  for (let scriptEntry of hodlFind(entries, 4).concat(hodlFind(entries, 5))) {
    try {
      for (let push of hodlScriptPushes(scriptEntry.val)) if (hodlLooksPubkey(push)) candidates.push(push);
    } catch {
    }
  }
  let signatures = [], uninspected = 0, scriptCode = hodlInputScriptCode(entries, witnessUtxo);
  for (let item of items) {
    if (!hodlLooksSignature(item)) continue;
    let signature = { pubkey: null, der: item.slice(0, -1), sighash: item[item.length - 1], raw: item };
    // Ownership is established by cryptographic verification, never by stack
    // position. Without a reconstructable digest, only a single unambiguous
    // candidate key can claim the signature.
    let sighash = witnessUtxo && scriptCode ? hodlBip143(tx, index, scriptCode, witnessUtxo.amount, signature.sighash) : null;
    if (sighash) for (let candidate of candidates) {
      try {
        if (hodlSecp256k1.verify(signature.der, sighash, candidate, { prehash: false, format: "der", lowS: false })) {
          signature.pubkey = candidate;
          break;
        }
      } catch {
      }
    }
    if (!signature.pubkey) {
      let unique = [];
      for (let candidate of candidates) if (!unique.some((seen) => hodlEq(seen, candidate))) unique.push(candidate);
      if (unique.length === 1) signature.pubkey = unique[0];
    }
    if (signature.pubkey) signatures.push(signature);
    else uninspected += 1;
  }
  return { signatures, uninspected, malformed };
}
function hodlBip32(entries, pubkey) {
  return hodlFind(entries, 6).filter((entry) => !pubkey || hodlEq(entry.keydata, pubkey)).map((entry) => {
    if (entry.val.length < 4 || (entry.val.length - 4) % 4) throw new Error("A BIP32 derivation path is malformed.");
    let path = [];
    for (let i = 4; i < entry.val.length; i += 4) path.push(new DataView(entry.val.buffer, entry.val.byteOffset + i, 4).getUint32(0, true));
    return { pubkey: entry.keydata, fingerprint: entry.val.slice(0, 4), path };
  });
}
function hodlInputScriptCode(entries, witnessUtxo) {
  if (!witnessUtxo) return null;
  let outputScript = witnessUtxo.script, redeem = (hodlFind(entries, 4).find((entry) => entry.keydata.length === 0) || {}).val, witnessScript = (hodlFind(entries, 5).find((entry) => entry.keydata.length === 0) || {}).val;
  try {
    let isP2sh = outputScript.length === 23 && outputScript[0] === 169 && outputScript[1] === 20 && outputScript[22] === 135;
    if (isP2sh) {
      if (!redeem || !hodlEq(p2shScript(redeem), outputScript)) return null;
      outputScript = redeem;
    }
    if (outputScript.length === 22 && outputScript[0] === 0 && outputScript[1] === 20) return hodlConcatBytes(Uint8Array.of(118, 169, 20), outputScript.slice(2), Uint8Array.of(136, 172));
    if (outputScript.length === 34 && outputScript[0] === 0 && outputScript[1] === 32 && witnessScript) {
      let committed = p2wshScript(witnessScript);
      return hodlEq(committed, outputScript) ? witnessScript : null;
    }
  } catch {
  }
  return null;
}
function hodlBip143(tx, index, scriptCode, amount, sighashType) {
  if (sighashType !== 1) return null;
  // BIP143 SegWit v0 digest, computed by rust-bitcoin's SighashCache in the
  // WASM module. The RFC 6979 comparison re-derives exactly this digest.
  const raw = tx.raw ?? serializeTx(tx);
  return hodlWasmIn(raw, (txPtr) =>
    hodlWasmIn(scriptCode, (scPtr) => hodlWasmOut(32, (out) => hodlWasm().el_sighash_segwit_v0(txPtr, raw.length, index, scPtr, scriptCode.length, amount, out)))
  ) ?? null;
}
function hodlSigParts(der) {
  try {
    let compact = hodlSecp256k1.Signature.fromBytes(der, "der").toBytes("compact");
    return { r: compact.slice(0, 32), s: compact.slice(32) };
  } catch {
    return null;
  }
}

function hodlCompressedPubkey(pubkey) {
  try {
    try {
      return hodlPointBytes(hodlPointFrom(pubkey), !0)
    } catch {}
    if (pubkey && pubkey.length === 33 && (pubkey[0] === 2 || pubkey[0] === 3)) return pubkey;
    if (pubkey && pubkey.length === 65 && pubkey[0] === 4) {
      let compressed = new Uint8Array(33);
      compressed[0] = pubkey[64] & 1 ? 3 : 2;
      compressed.set(pubkey.slice(1, 33), 1);
      return compressed
    }
  } catch {}
  return pubkey
}

function hodlDerRLoose(der) {
  if (!der || der.length < 8 || der[0] !== 0x30 || der[1] >= 0x80 || 2 + der[1] > der.length) return null;
  let offset = 2,
    end = 2 + der[1],
    values = [];
  while (offset < end) {
    if (der[offset] !== 2 || offset + 2 > end) return null;
    let len = der[offset + 1];
    if (len < 1 || len > 33 || offset + 2 + len > end) return null;
    let raw = der.slice(offset + 2, offset + 2 + len);
    while (raw.length > 1 && raw[0] === 0) raw = raw.slice(1);
    if (!raw.length || raw.length > 32 || raw.every(b => b === 0)) return null;
    let out = new Uint8Array(32);
    out.set(raw, 32 - raw.length);
    values.push(out);
    offset += 2 + len;
  }
  return values.length === 2 ? values[0] : null
}

function hodlCompareNonces(rValues) {
  let reused = [],
    possible = [];
  for (let first = 0; first < rValues.length; first++)
    for (let second = first + 1; second < rValues.length; second++) {
      let a = rValues[first],
        b = rValues[second];
      if (!hodlEq(a.pubkey, b.pubkey) || !hodlEq(a.r, b.r)) continue;
      if (a.valid && b.valid && a.sighash && b.sighash && !hodlEq(a.sighash, b.sighash)) reused.push([a, b]);
      else if (a.input !== b.input) possible.push([a, b]);
    }
  return {
    reused,
    possible
  }
}

// Last inspect-only nonce verdict for the Journal session snapshot.
// Never stores r values, signatures, or keys — counts and a short state only.
var hodlPsbtNonceVerdict = "", hodlPsbtNonceVerdictKind = "";
// `incomplete` is the same coverage predicate the on-screen Nonce-analysis
// summary uses (unreadable sigs, Taproot/Schnorr sigs, or unsupported checks),
// so the journal can never say "clean" while the summary says "Incomplete".
function hodlJournalNonceVerdict(kind, reused, possible, incomplete, comparable) {
  let detail = `${kind} · ${comparable} comparable · ${reused.length} reuse · ${possible.length} possible · ${incomplete} unreadable`;
  hodlPsbtNonceVerdictKind = kind;
  if (reused.length) {
    hodlPsbtNonceVerdict = "reuse";
    hodlJournalLog("inspect-nonce-reuse", detail, "psbt");
    return;
  }
  if (possible.length) {
    hodlPsbtNonceVerdict = "possible";
    hodlJournalLog("inspect-nonce-possible", detail, "psbt");
    return;
  }
  if (incomplete || comparable < 2) {
    hodlPsbtNonceVerdict = "incomplete";
    if (incomplete) hodlJournalLog("inspect-nonce-incomplete", detail, "psbt");
    return;
  }
  hodlPsbtNonceVerdict = "clean";
}
function hodlPrivForPub(pubkey) {
  if (hodlPsbtPriv) {
    let compressed = hodlSecp256k1.getPublicKey(hodlPsbtPriv, true), uncompressed = hodlSecp256k1.getPublicKey(hodlPsbtPriv, false);
    if (hodlEq(compressed, pubkey) || hodlEq(uncompressed, pubkey)) return hodlPsbtPriv;
  }
  if (hodlPsbtHd) {
    try {
      let rootPubkey = hodlPsbtHd.publicKey;
      if (rootPubkey && hodlEq(rootPubkey, pubkey)) return hodlPsbtHd.privateKey;
    } catch {
    }
  }
  return null;
}
function hodlPrivFromPath(entries, pubkey) {
  if (!hodlPsbtHd) return null;
  let rootFingerprint = hodlFingerprintHex(hodlPsbtHd.fingerprint);
  for (let derivation of hodlBip32(entries, pubkey)) {
    if (hodlHex.encode(derivation.fingerprint) !== rootFingerprint) continue;
    try {
      let node = hodlPsbtHd;
      for (let index of derivation.path) {
        let next = node.deriveChild(index);
        if (node !== hodlPsbtHd) node.wipePrivateData(); // dead intermediate
        node = next;
      }
      if (node.publicKey && hodlEq(node.publicKey, pubkey)) {
        let privateKey = node.privateKey; // a copy; the caller signs with it
        if (node !== hodlPsbtHd) node.wipePrivateData();
        return privateKey;
      }
      if (node !== hodlPsbtHd) node.wipePrivateData();
    } catch {
    }
  }
  return null;
}
function hodlPsbtWipeMem() {
  if (hodlPsbtPriv) try {
    hodlPsbtPriv.fill(0);
  } catch {
  }
  hodlPsbtPriv = null;
  if (hodlPsbtHd) try {
    hodlPsbtHd.wipePrivateData();
  } catch {
  }
  hodlPsbtHd = null;
  hodlPsbtSource = "";
  hodlPsbtSessionSpec = { key: "No session key. Inspect-only mode." };
  hodlPsbtNonceVerdict = "";
  hodlPsbtNonceVerdictKind = "";
}
function hodlLoadPsbtKey(text, passphrase) {
  hodlPsbtWipeMem();
  let value = text.trim(), hex = value.replace(/\s/g, "").replace(/^0x/i, "");
  if (!value) return;
  if (/^[5KL9c][1-9A-HJ-NP-Za-km-z]{50,51}$/.test(value)) {
    let decoded = hodlDecodeWif(value);
    hodlPsbtPriv = decoded.priv;
    hodlAssertPrivateKey(hodlPsbtPriv);
    hodlPsbtSessionSpec = { key: "Session key: {network} WIF. Kept in page memory only.", vars: { network: decoded.network } };
  } else if (/^[0-9a-fA-F]{64}$/.test(hex)) {
    hodlPsbtPriv = hodlHex.decode(hex.toLowerCase());
    hodlAssertPrivateKey(hodlPsbtPriv);
    hodlPsbtSessionSpec = { key: "Session key: 32-byte private key. Kept in page memory only." };
  } else {
    try {
      let parsed = hodlParseExtendedKey(value);
      if (parsed && parsed.isPrivate && parsed.node) {
        hodlPsbtHd = parsed.node;
        hodlPsbtSessionSpec = { key: "Session key: {prefix}. Kept in page memory only.", vars: { prefix: parsed.prefix || "xprv" } };
        hodlPsbtSource = "manual";
        return;
      }
    } catch {
    }
    let mnemonic = hodlValidateMnemonic(value);
    if (!mnemonic.ok) {
      if (mnemonic.error?.key) throw hodlError(mnemonic.error.key, mnemonic.error.vars);
      throw hodlError("Enter a BIP39 seed phrase, root xprv/tprv, WIF, or 64-character hex key.");
    }
    let seed = hodlMnemonicToSeed(mnemonic.words.join(" "), passphrase || "");
    try {
      hodlPsbtHd = hodlHDKey.fromMasterSeed(seed);
    } finally {
      seed.fill(0);
    }
    hodlPsbtSessionSpec = { key: passphrase ? "Session key: BIP39 seed + passphrase. Kept in page memory only." : "Session key: BIP39 seed. Kept in page memory only." };
  }
  hodlPsbtSource = "manual";
}
function hodlUseActiveKeyForPsbt() {
  let state = hodlKeys[hodlActiveKey];
  if (!state || !state.result) {
    hodlPsbtErrorSpec = { key: "Generate an active key first, then return to PSBT / Nonce." };
    throw new Error(hodlTText("Generate an active key first, then return to PSBT / Nonce."));
  }
  let result = state.result;
  hodlPsbtWipeMem();
  if (result.kind === "hd" && result.mnemonic) {
    let seed = hodlMnemonicToSeed(result.mnemonic, state.fields.pass || "");
    try {
      hodlPsbtHd = hodlHDKey.fromMasterSeed(seed);
    } finally {
      seed.fill(0);
    }
  } else if (result.kind === "hd" && result.rootXprv) hodlPsbtHd = hodlHDKey.fromExtendedKey(hodlParseExtendedKey(result.rootXprv).xkey);
  else if (result.kind === "hd" && result.importedPrivateKey) {
    hodlPsbtErrorSpec = { key: "The active key is an account-level extended private key. PSBT session signing needs origin-aware relative paths, which this version does not infer. Use the original seed or root xprv/tprv instead." };
    throw new Error(hodlTText("The active key is an account-level extended private key. PSBT session signing needs origin-aware relative paths, which this version does not infer. Use the original seed or root xprv/tprv instead."));
  }
  else if (result.kind === "single" && result.privHex) {
    hodlPsbtPriv = hodlHex.decode(result.privHex);
    hodlAssertPrivateKey(hodlPsbtPriv);
  } else {
    hodlPsbtErrorSpec = { key: "The active key has no private material available for a session check." };
    throw new Error(hodlTText("The active key has no private material available for a session check."));
  }
  hodlPsbtSource = "active";
  hodlPsbtSessionSpec = state.name ? { key: "Session key from {name}. Kept in page memory only.", vars: { name: state.name } } : { key: "Session key from the active key. Kept in page memory only." };
}
function hodlInitPsbt() {
  let go = document.getElementById("psbt-go");
  if (!go) return;
  go.onclick = hodlRunPsbt;
  document.getElementById("psbt-use-calc").onclick = () => {
    hodlSetPsbtError(null);
    try {
      hodlUseActiveKeyForPsbt();
      document.getElementById("psbt-key").value = "";
      document.getElementById("psbt-pass").value = "";
      document.getElementById("psbt-session").textContent = hodlPsbtSessionText();
    } catch (exception) {
      if (!hodlPsbtErrorSpec) hodlSetPsbtError({ raw: exception.message || String(exception) });
      else hodlSetPsbtError(hodlPsbtErrorSpec);
    }
  };
  document.getElementById("psbt-wipe").onclick = () => {
    hodlPsbtWipeMem();
    hodlPsbtLast = null;
    hodlPsbtSessionSpec = { key: "Session ended and accessible fields were cleared (best effort)." };
    document.getElementById("psbt-key").value = "";
    document.getElementById("psbt-pass").value = "";
    document.getElementById("psbt-text").value = "";
    let ax = document.getElementById("psbt-ax-transcript");
    if (ax) ax.value = "";
    document.getElementById("psbt-out").innerHTML = "";
    hodlSetPsbtError(null);
    document.getElementById("psbt-session").textContent = hodlPsbtSessionText();
  };
  let clearSecretFields = () => {
    hodlPsbtWipeMem();
    let key = document.getElementById("psbt-key"), pass = document.getElementById("psbt-pass");
    if (key) key.value = "";
    if (pass) pass.value = "";
  };
  addEventListener("pagehide", clearSecretFields);
  addEventListener("pageshow", (event) => {
    if (event.persisted) clearSecretFields();
  });
}
var hodlBip85Root = null, hodlBip85Note = "No parent loaded. Choose a Key Station key, or paste a root xprv.", hodlBip85Source = "", hodlBip85Result = null, hodlBip85Reveal = false, hodlBip85Testnet = false, hodlBip85Children = [], hodlActiveBip85 = -1, hodlNextBip85ChildId = 1;
function hodlBip85WipeParent() {
  if (hodlBip85Root) try {
    hodlBip85Root.wipePrivateData();
  } catch {
  }
  hodlBip85Root = null;
  hodlBip85Source = "";
  hodlBip85Testnet = false;
  hodlBip85Note = "No parent loaded. Choose a Key Station key, or paste a root xprv.";
}
function hodlBip85WipeMem() {
  let wiped = /* @__PURE__ */ new Set();
  for (let state of hodlBip85Children) {
    if (!state.result || wiped.has(state.result)) continue;
    wipeBip85Result(state.result);
    wiped.add(state.result);
  }
  if (hodlBip85Result && !wiped.has(hodlBip85Result)) wipeBip85Result(hodlBip85Result);
  hodlBip85Result = null;
  hodlBip85Reveal = false;
  hodlBip85Children = [hodlNewBip85BenchState()];
  hodlActiveBip85 = 0;
  hodlNextBip85ChildId = 1;
  if (hodlBip85Root) try {
    hodlBip85Root.wipePrivateData();
  } catch {
  }
  hodlBip85Root = null;
  hodlBip85Source = "";
  hodlBip85Testnet = false;
  hodlBip85Note = "No parent loaded. Choose a Key Station key, or paste a root xprv.";
}
function hodlNewBip85BenchState() {
  return { isLab: true, id: 0, name: "BIP-85 Station", result: null, reveal: false, fingerprint: "", fingerprintKind: "" };
}
function hodlBip85ActiveState() {
  return hodlBip85Children[hodlActiveBip85] || null;
}
function hodlBip85AppLabel(app) {
  if (app === "bip39") return "BIP-39";
  if (app === "wif") return "WIF";
  if (app === "xprv") return "XPRV";
  if (app === "hex") return "HEX";
  if (app === "pwd-base64") return "Base64 password";
  if (app === "pwd-base85") return "Base85 password";
  return "BIP-85 child";
}
function hodlBip85ChildFingerprint(result) {
  let seed = null, node = null, payload = null, privateKey = null, digest = null;
  try {
    if (result.app === "bip39") {
      seed = hodlMnemonicToSeed(result.secret, "");
      node = hodlHDKey.fromMasterSeed(seed);
      return { value: hodlFingerprintHex(node.fingerprint), kind: "master" };
    }
    if (result.app === "xprv") {
      node = hodlHDKey.fromExtendedKey(hodlParseExtendedKey(result.secret).xkey);
      return { value: hodlFingerprintHex(node.fingerprint), kind: "master" };
    }
    if (result.app === "wif") {
      payload = hodlBase58Check.decode(result.secret);
      privateKey = payload.slice(1, 33);
      node = new hodlHDKey({ privateKey });
      return { value: hodlFingerprintHex(node.fingerprint), kind: "key" };
    }
    digest = hodlSha256(result.entropy);
    return { value: hodlHex.encode(digest.slice(0, 4)), kind: "child" };
  } finally {
    if (node) try {
      node.wipePrivateData();
    } catch {
    }
    hodlWipeBytes(seed);
    hodlWipeBytes(payload);
    hodlWipeBytes(privateKey);
    hodlWipeBytes(digest);
  }
}
function hodlBip85PrivateValue(value) {
  let mask = "************", text = String(value ?? "\u2014");
  if (hodlBip85Reveal) return `<span class="secret private-field-value">${hodlEscapeHtml(text)}</span>`;
  let bullets = "\u2022".repeat(Math.max(Array.from(text).length, mask.length));
  return `<span class="secret private-field-value secret-placeholder"><span class="secret-placeholder-mask" aria-hidden="true">${bullets}</span><span class="secret-placeholder-message" aria-hidden="true">${mask}</span><span class="secret-placeholder-label">${hodlT("Private value hidden")}</span></span>`;
}
function hodlBip85SecretField(label, value) {
  return `<p class="private-field"><span class="muted">${hodlEscapeHtml(label)}</span>${hodlBip85PrivateValue(value)}</p>`;
}
function hodlBip85Spec() {
  let app = document.getElementById("bip85-app")?.value || "bip39";
  let index = document.getElementById("bip85-index")?.value || "0";
  return { app, index, words: Number(document.getElementById("bip85-words")?.value || 24), numBytes: Number(document.getElementById("bip85-bytes")?.value || 32), length: Number(document.getElementById("bip85-pwdlen")?.value || (app === "pwd-base85" ? 12 : 21)), testnet: hodlBip85Testnet };
}
function hodlBip85CurrentPath() {
  try {
    let spec = hodlBip85Spec(), index = parseChildIndex(spec.index);
    if (spec.app === "bip39") return bip85Path(BIP85_APPS.BIP39, BIP39_LANGUAGE_ENGLISH, spec.words, index);
    if (spec.app === "wif") return bip85Path(BIP85_APPS.WIF, index);
    if (spec.app === "xprv") return bip85Path(BIP85_APPS.XPRV, index);
    if (spec.app === "hex") return bip85Path(BIP85_APPS.HEX, spec.numBytes, index);
    if (spec.app === "pwd-base64") return bip85Path(BIP85_APPS.PWD_BASE64, spec.length, index);
    if (spec.app === "pwd-base85") return bip85Path(BIP85_APPS.PWD_BASE85, spec.length, index);
  } catch {
  }
  return "";
}
function hodlBip85SyncOptions() {
  let app = document.getElementById("bip85-app")?.value || "bip39";
  let wordsField = document.getElementById("bip85-words-field"), bytesField = document.getElementById("bip85-bytes-field"), pwdField = document.getElementById("bip85-pwdlen-field"), pwd = document.getElementById("bip85-pwdlen");
  if (wordsField) wordsField.hidden = app !== "bip39";
  if (bytesField) bytesField.hidden = app !== "hex";
  if (pwdField) pwdField.hidden = app !== "pwd-base64" && app !== "pwd-base85";
  if (pwd) {
    if (app === "pwd-base64") {
      pwd.min = "20";
      pwd.max = "86";
      if (Number(pwd.value) < 20 || Number(pwd.value) > 86) pwd.value = "21";
    } else if (app === "pwd-base85") {
      pwd.min = "10";
      pwd.max = "80";
      if (Number(pwd.value) < 10 || Number(pwd.value) > 80) pwd.value = "12";
    }
  }
  let path = document.getElementById("bip85-path");
  if (path) path.textContent = hodlBip85CurrentPath() || "\u2014";
}
function hodlBip85LoadXprv(text) {
  let value = String(text || "").trim(), { xkey, isPrivate } = hodlParseExtendedKey(value);
  if (!isPrivate) throw new Error("BIP-85 needs a private root (xprv/tprv), not an extended public key.");
  let node = hodlHDKey.fromExtendedKey(xkey);
  if (node.depth !== 0) throw new Error("BIP-85 starts at the BIP32 root. This extended key is not depth 0.");
  hodlBip85WipeParent();
  hodlBip85Root = node;
  hodlBip85Testnet = /^[tuvn]prv/i.test(value);
  hodlBip85Source = "manual";
  hodlBip85Note = "Parent: pasted root " + (hodlBip85Testnet ? "tprv" : "xprv") + ". Kept in page memory only.";
}
function hodlUseKeyForBip85(state) {
  if (!state || !state.result) throw new Error("Derive a key in Key Station first, then return to BIP-85 Station.");
  let result = state.result;
  hodlBip85WipeParent();
  if (result.kind === "hd" && result.mnemonic) {
    let seed = hodlMnemonicToSeed(result.mnemonic, state.fields.pass || "");
    try {
      hodlBip85Root = hodlHDKey.fromMasterSeed(seed);
    } finally {
      hodlWipeBytes(seed);
    }
    hodlBip85Testnet = false;
    hodlBip85Note = "Parent: " + (state.name || "Key Station key") + (result.passphraseUsed || (state.fields.pass || "").length ? " with BIP-39 passphrase (COLDCARD does the same \u2014 children differ without it)." : ".") + " Kept in page memory only.";
  } else if (result.kind === "hd" && result.rootXprv) {
    hodlBip85Root = hodlHDKey.fromExtendedKey(hodlParseExtendedKey(result.rootXprv).xkey);
    hodlBip85Testnet = result.network === "testnet";
    hodlBip85Note = "Parent: root xprv from " + (state.name || "Key Station key") + ". Kept in page memory only.";
  } else if (result.kind === "hd") throw new Error("This Key Station key is not a BIP32 root. Import the original seed or root xprv.");
  else throw new Error("BIP-85 needs an HD root. This Key Station key is a single private key.");
  hodlBip85Source = "key:" + state.id;
}
function hodlPickBip85SessionKey(state) {
  let error = document.getElementById("bip85-error");
  if (error) error.textContent = "";
  try {
    hodlUseKeyForBip85(state);
    let rootXprv = state.result?.rootXprv || hodlBip85Root?.privateExtendedKey;
    if (!rootXprv) throw new Error("This Key Station key does not expose a BIP32 root xprv/tprv.");
    document.getElementById("bip85-key").value = rootXprv;
    document.getElementById("bip85-session").textContent = hodlBip85Note;
  } catch (exception) {
    if (error) error.textContent = exception.message || String(exception);
  }
  hodlRefreshStationKeyPickers();
}
function hodlCopyBip85Child(button) {
  let phrase = button?.dataset.phrase;
  if (!phrase || button.disabled) return;
  let done = () => {
    button.textContent = "Copied derived child";
    clearTimeout(button.hodlCopiedTimer);
    button.hodlCopiedTimer = setTimeout(() => {
      if (button.isConnected) button.textContent = "Copy derived child";
    }, 1600);
  };
  let fallback = () => {
    let field = document.createElement("textarea");
    field.value = phrase;
    field.setAttribute("readonly", "");
    field.style.position = "fixed";
    field.style.left = "-9999px";
    document.body.appendChild(field);
    field.select();
    try {
      document.execCommand("copy");
      done();
    } finally {
      field.remove();
    }
  };
  if (navigator.clipboard && typeof navigator.clipboard.writeText === "function") navigator.clipboard.writeText(phrase).then(done).catch(fallback);
  else fallback();
}
function hodlRenderBip85Out() {
  let box = document.getElementById("bip85-out");
  if (!box) return;
  let state = hodlBip85ActiveState();
  hodlBip85Result = state?.result || null;
  if (!hodlBip85Result || state?.isLab) {
    box.innerHTML = "";
    return;
  }
  let derived = hodlBip85Result, notes = [...derived.notes || [], ...derived.warnings || []].map((message) => `<li>${hodlEscapeHtml(message)}</li>`).join("");
  let fingerprintLabel = state.fingerprintKind === "master" ? "Master fingerprint" : state.fingerprintKind === "key" ? "Key fingerprint" : "Child fingerprint";
  box.innerHTML = `<section class="wallet-data-section wallet-private-section" aria-labelledby="bip85-private-heading">
      <div class="wallet-data-section-head">
        <h3 id="bip85-private-heading">Derived child</h3>
        <p class="muted" id="bip85-private-description">This child is derived from your seed. Anyone with the parent, application, and index can reproduce it.</p>
      </div>
      <div class="wallet-data-actions no-print">
        <label class="reveal-private-toggle">
          <input type="checkbox" id="bip85-reveal" ${hodlBip85Reveal ? "checked" : ""} aria-describedby="bip85-private-description">
          <span>Show derived child <span class="reveal-private-toggle-note">(air-gap only)</span></span>
        </label>
        <button class="btn secondary" id="bip85-copy" type="button">Copy derived child</button>
      </div>
      <div class="wallet-data-fields">
        ${hodlPublicFieldHtml("Path", derived.path)}
        ${hodlPublicFieldHtml(fingerprintLabel, state.fingerprint)}
        ${hodlBip85SecretField(derived.secretLabel, derived.secret)}
        ${hodlBip85SecretField("Derived entropy", derived.entropyHex)}
      </div>
      ${notes ? `<ul class="bip85-notes">${notes}</ul>` : ""}
    </section>`;
  document.getElementById("bip85-reveal")?.addEventListener("change", (event) => {
    hodlBip85Reveal = event.target.checked;
    state.reveal = hodlBip85Reveal;
    hodlRenderBip85Out();
    requestAnimationFrame(() => document.getElementById("bip85-reveal")?.focus({ preventScroll: true }));
  });
  let copy = document.getElementById("bip85-copy");
  if (copy) {
    copy.dataset.phrase = derived.secret;
    copy.onclick = () => hodlCopyBip85Child(copy);
  }
}
function hodlCreateBip85Tab(index) {
  let state = hodlBip85Children[index], active = index === hodlActiveBip85, button = document.createElement("button"), label = document.createElement("span"), name = state.isLab ? "BIP-85 Station" : state.fingerprint;
  button.type = "button";
  button.id = state.isLab ? "bip85-tab-lab" : "bip85-tab-" + state.id;
  button.className = "tab key-tab bip85-tab" + (state.isLab ? " is-lab" : "") + (active ? " active" : "");
  label.className = "key-tab-label";
  label.textContent = name;
  if (state.isLab) button.append(hodlCreateBip85BenchIcon(), label);
  else {
    let image = document.createElement("img");
    image.className = "key-tab-lifehash";
    image.width = 22;
    image.height = 22;
    image.alt = "";
    image.hidden = true;
    hodlFillKeyTabLifehash(image, state.fingerprint);
    button.append(image, label);
  }
  button.setAttribute("role", "tab");
  button.setAttribute("aria-controls", "bip85-card");
  button.setAttribute("aria-selected", String(active));
  if (state.isLab) {
    button.setAttribute("aria-label", "BIP-85 Station" + (active ? ", selected" : ". Activate to derive a BIP-85 child."));
    button.title = "Derive a BIP-85 child";
  } else {
    let kind = state.fingerprintKind === "master" ? "master fingerprint" : state.fingerprintKind === "key" ? "key fingerprint" : "child fingerprint";
    button.setAttribute("aria-label", `${hodlBip85AppLabel(state.result?.app)} ${kind} ${name}${active ? ", selected" : ". Activate to select."}`);
    button.title = `${hodlBip85AppLabel(state.result?.app)} · ${state.result?.path || ""}`;
  }
  button.onclick = () => hodlSelectBip85(index);
  button.tabIndex = active ? 0 : -1;
  button.onkeydown = (event) => hodlBip85TabKeydown(event, index);
  return button;
}
function hodlSyncBip85DeleteButton() {
  let button = document.getElementById("delete-bip85"), state = hodlBip85ActiveState();
  if (!button) return;
  button.disabled = !state || state.isLab;
  button.setAttribute("aria-disabled", String(button.disabled));
}
function hodlRenderBip85Tabs() {
  let box = document.getElementById("bip85-tabs"), panel = document.getElementById("bip85-card");
  if (!box || !panel) return;
  box.innerHTML = "";
  panel.removeAttribute("aria-labelledby");
  hodlBip85Children.forEach((state, index) => {
    let button = hodlCreateBip85Tab(index);
    box.appendChild(button);
    if (index === hodlActiveBip85) panel.setAttribute("aria-labelledby", button.id);
  });
  hodlRevealTab(box, hodlActiveBip85);
  hodlSyncBip85DeleteButton();
}
function hodlSyncBip85View() {
  let state = hodlBip85ActiveState(), bench = document.getElementById("bip85-bench"), card = document.getElementById("bip85-card");
  if (bench) bench.hidden = !state?.isLab;
  if (card) card.classList.toggle("is-result-view", Boolean(state && !state.isLab));
  hodlBip85Result = state?.result || null;
  hodlBip85Reveal = Boolean(state?.reveal);
  hodlRenderBip85Out();
}
function hodlSelectBip85(index) {
  if (!hodlBip85Children[index]) return;
  hodlActiveBip85 = index;
  hodlRenderBip85Tabs();
  hodlSyncBip85View();
  hodlJournalLog("station-select", hodlBip85Children[index].isLab ? "station" : "child", "bip85");
}
function hodlSelectBip85Bench() {
  let index = hodlBip85Children.findIndex((state) => state.isLab);
  if (index < 0) {
    hodlBip85Children.unshift(hodlNewBip85BenchState());
    index = 0;
    if (hodlActiveBip85 >= 0) hodlActiveBip85 += 1;
  }
  hodlSelectBip85(index);
}
function hodlDeleteActiveBip85() {
  let state = hodlBip85ActiveState();
  if (!state || state.isLab) {
    hodlSyncBip85DeleteButton();
    return;
  }
  let deletedIndex = hodlActiveBip85;
  hodlBip85Result = null;
  wipeBip85Result(state.result);
  hodlBip85Children.splice(deletedIndex, 1);
  if (!hodlBip85Children.length) hodlBip85Children.push(hodlNewBip85BenchState());
  hodlActiveBip85 = Math.min(deletedIndex, hodlBip85Children.length - 1);
  hodlRenderBip85Tabs();
  hodlSyncBip85View();
  hodlJournalLog("station-delete", "child", "bip85");
  document.getElementById("bip85-tabs")?.children[hodlActiveBip85]?.focus();
}
function hodlBip85TabKeydown(event, index) {
  let next = null, length = hodlBip85Children.length;
  if (event.key === "ArrowRight") next = (index + 1) % length;
  else if (event.key === "ArrowLeft") next = (index - 1 + length) % length;
  else if (event.key === "Home") next = 0;
  else if (event.key === "End") next = length - 1;
  if (next === null) return;
  event.preventDefault();
  hodlSelectBip85(next);
  document.getElementById("bip85-tabs")?.children[next]?.focus();
}
function hodlRunBip85() {
  let error = document.getElementById("bip85-error"), session = document.getElementById("bip85-session"), manual = document.getElementById("bip85-key")?.value || "";
  let result = null;
  if (error) error.textContent = "";
  try {
    if (manual.trim()) {
      if (!hodlBip85Root || !hodlBip85Source.startsWith("key:")) hodlBip85LoadXprv(manual);
    } else if (!hodlBip85Root) throw new Error("Choose a compatible Key Station key, or paste a root xprv/tprv.");
    result = deriveApplication(hodlBip85Root, hodlBip85Spec());
    let fingerprint = hodlBip85ChildFingerprint(result);
    let state = { isLab: false, id: hodlNextBip85ChildId++, name: fingerprint.value, result, reveal: false, fingerprint: fingerprint.value, fingerprintKind: fingerprint.kind };
    hodlBip85Children.push(state);
    hodlActiveBip85 = hodlBip85Children.length - 1;
    hodlBip85Result = state.result;
    result = null;
    hodlBip85Reveal = false;
    hodlJournalLog("derive", fingerprint.value);
    if (session) session.textContent = hodlBip85Note;
    hodlRenderBip85Tabs();
    hodlSyncBip85View();
  } catch (exception) {
    wipeBip85Result(result);
    if (error) error.textContent = exception.message || String(exception);
    hodlJournalLog("derive-error", "", "bip85");
  }
  hodlRefreshStationKeyPickers();
}
function hodlInitBip85() {
  let go = document.getElementById("bip85-go");
  if (!go) return;
  if (!hodlBip85Children.length) {
    hodlBip85Children.push(hodlNewBip85BenchState());
    hodlActiveBip85 = 0;
  }
  document.getElementById("add-bip85").onclick = hodlSelectBip85Bench;
  document.getElementById("delete-bip85").onclick = hodlDeleteActiveBip85;
  hodlInitTabDrag(document.getElementById("bip85-tabs"));
  hodlRenderBip85Tabs();
  hodlSyncBip85View();
  hodlRefreshStationKeyPickers();
  document.getElementById("bip85-key").addEventListener("input", () => {
    if (!hodlBip85Source.startsWith("key:")) return;
    hodlBip85WipeParent();
    hodlBip85Source = document.getElementById("bip85-key").value.trim() ? "manual" : "";
    document.getElementById("bip85-session").textContent = hodlBip85Source ? "Manual root key entered. It will be validated when you derive a child." : hodlBip85Note;
    hodlRefreshStationKeyPickers();
  });
  go.onclick = hodlRunBip85;
  document.getElementById("bip85-wipe").onclick = () => {
    hodlBip85WipeParent();
    document.getElementById("bip85-key").value = "";
    document.getElementById("bip85-error").textContent = "";
    document.getElementById("bip85-session").textContent = "Parent session cleared (best effort). Derived child tabs remain until deleted.";
    hodlRefreshStationKeyPickers();
  };
  for (let id of ["bip85-app", "bip85-index", "bip85-words", "bip85-bytes", "bip85-pwdlen"]) {
    document.getElementById(id)?.addEventListener("input", hodlBip85SyncOptions);
    document.getElementById(id)?.addEventListener("change", hodlBip85SyncOptions);
  }
  hodlBip85SyncOptions();
}
function hodlRunPsbt() {
  let output = document.getElementById("psbt-out"), manual = document.getElementById("psbt-key").value;
  hodlSetPsbtError(null);
  hodlPsbtLast = null;
  // Invalidate the journal nonce verdict so a failed or pending re-inspect
  // can never be reported against a stale prior payload.
  hodlPsbtNonceVerdict = "";
  hodlPsbtNonceVerdictKind = "";
  output.innerHTML = "";
  try {
    if (manual.trim()) {
      hodlLoadPsbtKey(manual, document.getElementById("psbt-pass").value);
      document.getElementById("psbt-key").value = "";
      document.getElementById("psbt-pass").value = "";
    }
    document.getElementById("psbt-session").textContent = hodlPsbtSessionText();
    let bytes = hodlPsbtBytes(document.getElementById("psbt-text").value);
    let kind = isPsbtMagic(bytes) ? "psbt" : "transaction";
    if (kind === "psbt") output.innerHTML = hodlRenderPsbt(hodlParsePsbt(bytes));
    else output.innerHTML = hodlRenderRawTx(parseRawTx(bytes));
    hodlJournalLog("inspect", kind, "psbt");
  } catch (exception) {
    hodlPsbtLast = null;
    hodlPsbtNonceVerdict = "";
    hodlPsbtNonceVerdictKind = "";
    if (!hodlPsbtErrorSpec) hodlSetPsbtError({ raw: exception instanceof Error ? exception.message : String(exception) });
    else hodlSetPsbtError(hodlPsbtErrorSpec);
    hodlJournalLog("inspect-error", "", "psbt");
  }
}

var hodlSpHd = null, hodlSpKeys = null, hodlSpNote = "No session key. Receive and verify need a seed or root xprv.", hodlSpMode = "receive", hodlSpReveal = false, hodlSpSource = "";
function hodlSpWipeKeys() {
  if (hodlSpKeys) {
    try { hodlSpKeys.scanPriv && hodlSpKeys.scanPriv.fill(0); } catch {}
    try { hodlSpKeys.spendPriv && hodlSpKeys.spendPriv.fill(0); } catch {}
  }
  hodlSpKeys = null;
  if (hodlSpHd) {
    try { hodlSpHd.wipePrivateData(); } catch {}
  }
  hodlSpHd = null;
  hodlSpSource = "";
  hodlSpNote = "No session key. Receive and verify need a seed or root xprv.";
}
function hodlSpWipeMem() {
  hodlSpWipeKeys();
  hodlSpReveal = false;
}
function hodlSpNetwork() {
  return document.getElementById("sp-network")?.value === "testnet" ? "testnet" : "mainnet";
}
function hodlSpAccount() {
  let value = Number(document.getElementById("sp-account")?.value || 0);
  if (!Number.isInteger(value) || value < 0 || value > 0x7fffffff) throw new Error("Account index must be an integer between 0 and 2147483647.");
  return value;
}
function hodlSpCoinType() {
  return hodlSpNetwork() === "mainnet" ? 0 : 1;
}
function hodlSpLoadKey(text, passphrase) {
  hodlSpWipeKeys();
  let value = String(text || "").trim();
  if (!value) throw new Error("Paste a BIP39 seed phrase or a BIP32 root xprv/tprv.");
  if (/^[xt]prv[1-9A-HJ-NP-Za-km-z]+$/.test(value.replace(/\s/g, ""))) {
    let parsed = hodlParseExtendedKey(value.replace(/\s/g, ""));
    if (!parsed.isPrivate) throw new Error("Watch-only extended keys cannot derive BIP-352 scan/spend paths.");
    if (parsed.node.depth !== 0) throw new Error("Silent Payments needs a BIP32 root private key (depth 0), not an account xprv.");
    hodlSpHd = parsed.node;
    hodlSpSource = "manual";
    hodlSpNote = `Session key: root ${parsed.prefix}. Kept in page memory only.`;
    return;
  }
  let mnemonic = hodlValidateMnemonic(value);
  if (!mnemonic.ok) {
    if (mnemonic.error?.key) throw hodlError(mnemonic.error.key, mnemonic.error.vars);
    throw hodlError("Enter a BIP39 seed phrase or a BIP32 root xprv/tprv.");
  }
  let seed = hodlMnemonicToSeed(mnemonic.words.join(" "), passphrase || "");
  try {
    hodlSpHd = hodlHDKey.fromMasterSeed(seed);
  } finally {
    seed.fill(0);
  }
  hodlSpSource = "manual";
  hodlSpNote = "Session key: BIP39 seed" + (passphrase ? " + passphrase" : "") + ". Kept in page memory only.";
}
function hodlSpUseKey(state) {
  if (!state || !state.result) throw new Error("Derive a key in Key Station first, then return to SP Station.");
  let result = state.result;
  hodlSpWipeKeys();
  if (result.kind === "hd" && result.mnemonic) {
    let seed = hodlMnemonicToSeed(result.mnemonic, state.fields.pass || "");
    try { hodlSpHd = hodlHDKey.fromMasterSeed(seed); } finally { seed.fill(0); }
    hodlSpNote = "Session key from " + (state.name || "Key Station key") + " (BIP39 seed). Kept in page memory only.";
  } else if (result.kind === "hd" && result.rootXprv) {
    hodlSpHd = hodlHDKey.fromExtendedKey(hodlParseExtendedKey(result.rootXprv).xkey);
    hodlSpNote = "Session key from " + (state.name || "Key Station key") + " (root xprv). Kept in page memory only.";
  } else throw new Error("SP Station needs the Key Station key's seed or root xprv. Account-level and single keys cannot derive m/352'.");
  hodlSpSource = "key:" + state.id;
}
function hodlPickSpSessionKey(state) {
  let error = document.getElementById("sp-error");
  if (error) error.textContent = "";
  try {
    hodlSpUseKey(state);
    document.getElementById("sp-key").value = state.result?.mnemonic || state.result?.rootXprv || "";
    document.getElementById("sp-pass").value = state.result?.mnemonic ? state.fields?.pass || "" : "";
    document.getElementById("sp-session").textContent = hodlSpNote;
  } catch (exception) {
    if (error) error.textContent = exception.message || String(exception);
  }
  hodlRefreshStationKeyPickers();
}
function hodlSpEnsureHd() {
  let manual = document.getElementById("sp-key")?.value;
  if (manual && manual.trim()) {
    if (!hodlSpHd || !hodlSpSource.startsWith("key:")) hodlSpLoadKey(manual, document.getElementById("sp-pass")?.value);
    hodlRefreshStationKeyPickers();
  }
  if (!hodlSpHd || !hodlSpHd.privateKey) throw new Error("Choose a compatible Key Station key, or enter a BIP39 seed or root xprv.");
  document.getElementById("sp-session").textContent = hodlSpNote;
}
function hodlSpDeriveSessionKeys() {
  hodlSpEnsureHd();
  if (hodlSpKeys) {
    try { hodlSpKeys.scanPriv && hodlSpKeys.scanPriv.fill(0); } catch {}
    try { hodlSpKeys.spendPriv && hodlSpKeys.spendPriv.fill(0); } catch {}
  }
  let root = hodlSpHd;
  let scanPath = `m/352'/${hodlSpCoinType()}'/${hodlSpAccount()}'/1'/0`;
  let spendPath = `m/352'/${hodlSpCoinType()}'/${hodlSpAccount()}'/0'/0`;
  let scanNode = root.derive(scanPath);
  let spendNode = root.derive(spendPath);
  if (!scanNode.privateKey || !spendNode.privateKey) throw new Error("BIP-352 child keys are missing private material.");
  hodlSpKeys = {
    scanPath,
    spendPath,
    scanPriv: scanNode.privateKey.slice(),
    spendPriv: spendNode.privateKey.slice(),
    scanPub: hodlSecp256k1.getPublicKey(scanNode.privateKey, true),
    spendPub: hodlSecp256k1.getPublicKey(spendNode.privateKey, true),
    fingerprint: hodlFingerprintHex(root.fingerprint),
  };
  // The session owns the slices above; the derivation nodes are dead copies.
  scanNode.wipePrivateData();
  spendNode.wipePrivateData();
}
function hodlSpParseVins(text) {
  let raw = String(text || "").trim();
  if (!raw) throw new Error("Paste BIP-352 vin JSON.");
  let parsed = JSON.parse(raw);
  if (parsed && Array.isArray(parsed.vin)) parsed = parsed.vin;
  if (!Array.isArray(parsed) || !parsed.length) throw new Error("Vin JSON must be a non-empty array.");
  return parsed;
}
function hodlSpParseRecipients(text) {
  return parseRecipientLines(text);
}
function hodlSpParseOutputs(text) {
  let raw = String(text || "").trim();
  if (!raw) throw new Error("Paste at least one 32-byte x-only taproot output key.");
  if (raw.startsWith("[")) {
    let parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) throw new Error("Output JSON must be an array of hex strings.");
    return parsed.map(String);
  }
  return raw.split(/\s+/).map((item) => item.replace(/^0x/i, "")).filter(Boolean);
}
function hodlSpParseLabels(text) {
  let raw = String(text || "").trim();
  if (!raw) return [];
  return raw.split(/[,\s]+/).filter(Boolean).map((item) => {
    let value = Number(item);
    if (!Number.isInteger(value) || value < 0 || value > 0xffffffff) throw new Error(`Invalid label: ${item}`);
    return value;
  });
}
function hodlSpSetMode(mode) {
  hodlSpMode = mode;
  ["receive", "send", "verify"].forEach((id) => {
    let panel = document.getElementById(`sp-${id}`);
    if (panel) panel.hidden = id !== mode;
  });
  document.querySelectorAll("#sp-modes [data-sp-mode]").forEach((button) => {
    let active = button.dataset.spMode === mode;
    button.classList.toggle("active", active);
    button.setAttribute("aria-pressed", String(active));
  });
}
function hodlSpEscape(value) {
  return String(value).replace(/[&<>"']/g, (ch) => {
    if (ch === "&") return "&amp;";
    if (ch === "<") return "&lt;";
    if (ch === ">") return "&gt;";
    if (ch === '"') return "&quot;";
    return "&#39;";
  });
}
function hodlSpCopyButton(id, label) {
  return `<button type="button" class="btn secondary sp-copy" data-sp-copy="${id}">${label}</button>`;
}
function hodlRenderSpReceive() {
  hodlSpDeriveSessionKeys();
  let hrp = hodlSpHrp(hodlSpNetwork());
  let labelField = document.getElementById("sp-label")?.value;
  let labeled = String(labelField ?? "").trim() !== "";
  let m = labeled ? Number(labelField) : null;
  if (labeled && (!Number.isInteger(m) || m < 0 || m > 0xffffffff)) throw new Error("Label m must be an integer between 0 and 4294967295.");
  let scanPoint = hodlSecp256k1.Point.fromBytes(hodlSpKeys.scanPub);
  let spendPoint = hodlSecp256k1.Point.fromBytes(hodlSpKeys.spendPub);
  let address = labeled ? createLabeledSilentPaymentAddress(hodlSpKeys.scanPriv, spendPoint, m, hrp) : encodeSilentPaymentAddress(scanPoint, spendPoint, hrp);
  let uri = encodeBitcoinUri(address);
  let txt = encodeBip353Txt(address);
  let named = bip353Lookup(document.getElementById("sp-payname")?.value);
  let spscan = encodeSpscan(hodlSpKeys.scanPriv, hodlSpKeys.spendPub, hodlSpNetwork());
  let spspend = encodeSpspend(hodlSpKeys.scanPriv, hodlSpKeys.spendPriv, hodlSpNetwork());
  let origin = `${hodlSpKeys.fingerprint}/352h/${hodlSpCoinType()}h/${hodlSpAccount()}h`;
  let qr = hodlQrSvg(address);
  let secrets = hodlSpReveal;
  document.getElementById("sp-out").innerHTML = `
    <div class="sp-result">
      <p class="label">Reusable silent payment address${labeled ? ` · label m = ${m}${m === 0 ? " (change)" : ""}` : ""}</p>
      <div class="sp-qr">${qr}</div>
      <p class="psbt-kv" id="sp-address-value">${hodlSpEscape(address)}</p>
      ${hodlSpCopyButton("sp-address-value", "Copy address")}
      <p class="label">BIP-321 URI</p>
      <p class="psbt-kv" id="sp-bip321-uri">${hodlSpEscape(uri)}</p>
      ${hodlSpCopyButton("sp-bip321-uri", "Copy URI")}
      <p class="label">BIP-353 DNS TXT</p>
      <p class="psbt-kv" id="sp-bip353-txt">${hodlSpEscape(txt)}</p>
      ${hodlSpCopyButton("sp-bip353-txt", "Copy TXT")}
      <p class="muted">${named ? `Create a TXT record at <code>${hodlSpEscape(named.lookup)}</code> for <code>${hodlSpEscape(named.name)}</code>.` : "Name the record <code>you@yourdomain</code> above and this prints its lookup, e.g. <code>you.user._bitcoin-payment.yourdomain</code>."} This page does not resolve DNS.</p>
      <p class="muted">Scan path <code>${hodlSpKeys.scanPath}</code> · Spend path <code>${hodlSpKeys.spendPath}</code></p>
      <p class="label">Scan public key</p>
      <p class="psbt-kv" id="sp-scan-pub">${hodlSpBytesToHex(hodlSpKeys.scanPub)}</p>
      <p class="label">Spend public key</p>
      <p class="psbt-kv" id="sp-spend-pub">${hodlSpBytesToHex(hodlSpKeys.spendPub)}</p>
      <label class="choice"><input type="checkbox" id="sp-reveal" ${secrets ? "checked" : ""}> <span>Reveal scan/spend private material and BIP-392 descriptors</span></label>
      ${secrets ? `<p class="label">BIP-392 watch-only <code>spscan</code></p><p class="psbt-kv" id="sp-spscan">${hodlSpEscape(formatSpDescriptor(spscan, origin))}</p>
        <p class="label">BIP-392 spend <code>spspend</code></p><p class="psbt-kv" id="sp-spspend">${hodlSpEscape(formatSpDescriptor(spspend, origin))}</p>
        <p class="label">Scan private key</p><p class="psbt-kv" id="sp-scan-priv">${hodlSpBytesToHex(hodlSpKeys.scanPriv)}</p>
        <p class="label">Spend private key</p><p class="psbt-kv" id="sp-spend-priv">${hodlSpBytesToHex(hodlSpKeys.spendPriv)}</p>` : `<p class="muted">Private scan/spend material stays hidden until you reveal it.</p>`}
    </div>`;
  document.getElementById("sp-reveal")?.addEventListener("change", (event) => {
    hodlSpReveal = event.target.checked;
    try { hodlRenderSpReceive(); } catch (error) { document.getElementById("sp-error").textContent = error.message || String(error); }
  });
}
function hodlRenderSpSend() {
  let parsed = hodlSpParseRecipients(document.getElementById("sp-recipients")?.value);
  let recipients = parsed.recipients;
  let hrp = hodlSpHrp(hodlSpNetwork());
  for (const recipient of recipients) decodeSilentPaymentAddress(recipient.address, hrp);
  let result = createSilentPaymentOutputs(hodlSpParseVins(document.getElementById("sp-send-vins")?.value), recipients, { hrp });
  if (!result.outputs.length) {
    document.getElementById("sp-out").innerHTML = `<p class="psbt-warn">No silent payment outputs. Eligible inputs may be missing, the private-key sum may be zero, or a scan-key group exceeded K<sub>max</sub> = 2323.</p>`;
    return;
  }
  let network = hodlSpNetwork();
  document.getElementById("sp-out").innerHTML = `<p class="psbt-ok">${result.outputs.length} unique taproot output${result.outputs.length === 1 ? "" : "s"}.</p>` + (parsed.lightning ? `<p class="muted">Lightning parameters in the URI were ignored. This page does not pay invoices or offers.</p>` : "") + result.outputs.map((xonly, index) => {
    let address = p2trAddressFromXonly(xonly, network);
    return `<div class="sp-output"><p class="label">Output ${index + 1}</p><p class="psbt-kv" id="sp-out-addr-${index}">${hodlSpEscape(address)}</p><p class="psbt-kv" id="sp-out-xonly-${index}">${hodlSpEscape(xonly)}</p>${hodlSpCopyButton(`sp-out-addr-${index}`, "Copy P2TR")}</div>`;
  }).join("");
}
function hodlRenderSpVerify() {
  hodlSpDeriveSessionKeys();
  let labels = hodlSpParseLabels(document.getElementById("sp-verify-labels")?.value);
  let result = scanSilentPaymentOutputs({
    scanPriv: hodlSpKeys.scanPriv,
    spendPub: hodlSpKeys.spendPub,
    vins: hodlSpParseVins(document.getElementById("sp-verify-vins")?.value),
    outputs: hodlSpParseOutputs(document.getElementById("sp-verify-outputs")?.value),
    labels,
  });
  if (!result.outputs.length) {
    document.getElementById("sp-out").innerHTML = `<p class="muted">No matching silent payment outputs for this scan key and label set.</p>`;
    return;
  }
  let network = hodlSpNetwork();
  document.getElementById("sp-out").innerHTML = `<p class="psbt-ok">${result.outputs.length} matching output${result.outputs.length === 1 ? "" : "s"}.</p>` + result.outputs.map((row, index) => {
    let address = p2trAddressFromXonly(row.pub_key, network);
    let spend = hodlSpReveal ? hodlSpBytesToHex(spendPrivForOutput(hodlSpKeys.spendPriv, row.priv_key_tweak)) : "";
    let labelNote = row.label === null ? "" : ` · label m = ${row.label}${row.label === 0 ? " (change)" : ""}`;
    return `<div class="sp-output"><p class="label">Match ${index + 1}${labelNote}</p><p class="psbt-kv">${hodlSpEscape(address)}</p><p class="psbt-kv">tweak ${hodlSpEscape(row.priv_key_tweak)}</p>${hodlSpReveal ? `<p class="psbt-kv">spend key ${hodlSpEscape(spend)}</p>` : ""}</div>`;
  }).join("") + `<label class="choice"><input type="checkbox" id="sp-reveal" ${hodlSpReveal ? "checked" : ""}> <span>Reveal spend private keys for matches</span></label>`;
  document.getElementById("sp-reveal")?.addEventListener("change", (event) => {
    hodlSpReveal = event.target.checked;
    try { hodlRenderSpVerify(); } catch (error) { document.getElementById("sp-error").textContent = error.message || String(error); }
  });
}
function hodlRunSp() {
  let error = document.getElementById("sp-error"), output = document.getElementById("sp-out");
  error.textContent = "";
  output.innerHTML = "";
  try {
    if (hodlSpMode === "send") hodlRenderSpSend();
    else if (hodlSpMode === "verify") hodlRenderSpVerify();
    else hodlRenderSpReceive();
    hodlJournalLog("calculate", hodlSpMode, "sp");
  } catch (exception) {
    error.textContent = exception instanceof Error ? exception.message : String(exception);
    hodlJournalLog("calculate-error", hodlSpMode, "sp");
  }
}
function hodlInitSp() {
  if (!document.getElementById("sp-card")) return;
  hodlRefreshStationKeyPickers();
  let detachStationKey = () => {
    if (!hodlSpSource.startsWith("key:")) return;
    hodlSpWipeKeys();
    hodlSpSource = document.getElementById("sp-key").value.trim() ? "manual" : "";
    document.getElementById("sp-session").textContent = hodlSpSource ? "Manual session key entered. It will be validated when you use this Station." : hodlSpNote;
    hodlRefreshStationKeyPickers();
  };
  document.getElementById("sp-key").addEventListener("input", detachStationKey);
  document.getElementById("sp-pass").addEventListener("input", detachStationKey);
  document.querySelectorAll("#sp-modes [data-sp-mode]").forEach((button) => {
    button.onclick = () => { hodlSpSetMode(button.dataset.spMode); document.getElementById("sp-out").innerHTML = ""; document.getElementById("sp-error").textContent = ""; };
  });
  document.getElementById("sp-derive").onclick = () => { hodlSpMode = "receive"; hodlRunSp(); };
  document.getElementById("sp-send-go").onclick = () => { hodlSpMode = "send"; hodlRunSp(); };
  document.getElementById("sp-verify-go").onclick = () => { hodlSpMode = "verify"; hodlRunSp(); };
  document.getElementById("sp-wipe").onclick = () => {
    hodlSpWipeMem();
    ["sp-key", "sp-pass", "sp-recipients", "sp-send-vins", "sp-verify-vins", "sp-verify-outputs", "sp-label", "sp-payname"].forEach((id) => {
      let field = document.getElementById(id);
      if (field) field.value = "";
    });
    let labels = document.getElementById("sp-verify-labels");
    if (labels) labels.value = "0";
    let account = document.getElementById("sp-account");
    if (account) account.value = "0";
    document.getElementById("sp-out").innerHTML = "";
    document.getElementById("sp-error").textContent = "";
    document.getElementById("sp-session").textContent = "Session ended and accessible fields were cleared (best effort).";
    hodlRefreshStationKeyPickers();
  };
  document.getElementById("sp-out").addEventListener("click", (event) => {
    let button = event.target.closest?.("[data-sp-copy]");
    if (!button) return;
    let node = document.getElementById(button.dataset.spCopy);
    if (!node) return;
    navigator.clipboard?.writeText(node.textContent || "").catch(() => {});
  });
  hodlSpSetMode("receive");
}
function hodlTaggedSha256(tag, ...chunks) {
  let tagHash = hodlSha256(new TextEncoder().encode(tag)), total = 64;
  for (let chunk of chunks) total += chunk.length;
  let bytes = new Uint8Array(total);
  bytes.set(tagHash, 0);
  bytes.set(tagHash, 32);
  let offset = 64;
  for (let chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.length;
  }
  return hodlSha256(bytes);
}
function hodlBytesToBig(bytes) {
  return BigInt("0x" + hodlHex.encode(bytes));
}
function hodlPointFrom(bytes) {
  let Point = hodlSecp256k1.Point;
  if (typeof Point.fromBytes === "function") return Point.fromBytes(bytes);
  if (typeof Point.fromHex === "function") return Point.fromHex(hodlHex.encode(bytes));
  throw new Error("Unsupported curve point parsing.");
}
function hodlPointBytes(point, compressed = true) {
  if (typeof point.toBytes === "function") return point.toBytes(compressed);
  if (typeof point.toRawBytes === "function") return point.toRawBytes(compressed);
  throw new Error("Unsupported curve point encoding.");
}
function hodlParseAntiExfil(raw) {
  if (!raw || !String(raw).trim()) return null;
  let text = String(raw).replace(/0x/gi, ""), tokens = text.split(/[^0-9a-fA-F]+/).filter((token) => token.length), host = null, openings = [];
  for (let token of tokens) {
    if (token.length === 64) {
      if (host) throw new Error("Paste one 32-byte Jade host nonce.");
      host = hodlHex.decode(token.toLowerCase());
    } else if (token.length === 66) {
      let opening = hodlHex.decode(token.toLowerCase());
      if (opening[0] !== 2 && opening[0] !== 3) throw new Error("Jade opening R must be a compressed secp256k1 point.");
      openings.push(opening);
    } else if (token.length === 130) {
      if (host || openings.length) throw new Error("Paste the host nonce and opening once, or as separate hex values.");
      host = hodlHex.decode(token.slice(0, 64).toLowerCase());
      let opening = hodlHex.decode(token.slice(64).toLowerCase());
      if (opening[0] !== 2 && opening[0] !== 3) throw new Error("Jade opening R must be a compressed secp256k1 point.");
      openings.push(opening);
    } else if (token.length < 64) continue;
    else throw new Error("Jade anti-exfil transcript wants a 32-byte host nonce \u03C1 and a 33-byte compressed opening R, as hex.");
  }
  if (!host || !openings.length) throw new Error("Jade anti-exfil needs both the host nonce \u03C1 and the signer opening R.");
  return { host, openings };
}
function hodlAntiExfilCommitOk(r, opening, host) {
  const n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n;
  let tweak = hodlTaggedSha256("s2c/ecdsa/point", opening, host), tweakInt = hodlBytesToBig(tweak);
  if (tweakInt >= n || tweakInt === 0n) return false;
  let committed = hodlPointFrom(opening).add(hodlSecp256k1.Point.BASE.multiply(tweakInt)), xBytes = hodlPointBytes(committed, true).slice(1);
  return hodlBytesToBig(r) % n === hodlBytesToBig(xBytes) % n;
}
function hodlLe32Counter(n) {
  let b = new Uint8Array(32);
  b[0] = n & 255;
  b[1] = n >>> 8 & 255;
  b[2] = n >>> 16 & 255;
  b[3] = n >>> 24 & 255;
  return b;
}
function hodlIsLowR(r) {
  return !!(r && r.length && r[0] < 128);
}
function hodlRfc6979Compare(sighash, privateKey, r) {
  let plain = hodlSecp256k1.sign(sighash, privateKey, { prehash: false, extraEntropy: false });
  if (hodlEq(plain.slice(0, 32), r)) {
    return hodlIsLowR(r) ? { ok: true, className: "psbt-ok", message: hodlT("Matches RFC 6979 (plain deterministic nonce).") } : { ok: true, className: "psbt-ok", message: hodlT("Matches RFC 6979 (plain deterministic nonce). r is high; Bitcoin Core would grind this one.") };
  }
  for (let n = 1; n <= 64; n++) {
    let expected = hodlSecp256k1.sign(sighash, privateKey, { prehash: false, extraEntropy: hodlLe32Counter(n) });
    if (hodlEq(expected.slice(0, 32), r)) {
      return { ok: true, className: "psbt-ok", message: hodlT("Matches RFC 6979 with Bitcoin Core-style low-r grind (retry {n}). Saves one byte. Not a leak.", { n }) };
    }
  }
  let zeros = hodlSecp256k1.sign(sighash, privateKey, { prehash: false, extraEntropy: new Uint8Array(32) });
  if (hodlEq(zeros.slice(0, 32), r)) {
    return { ok: true, className: "psbt-ok", message: hodlT("Matches RFC 6979 with 32 zero extra-entropy bytes (some libraries mix this in).") };
  }
  return { ok: false, className: "psbt-warn", message: hodlT("Does not match plain RFC 6979 or Bitcoin Core-style low-r grind. Honest signers may add other auxiliary randomness. A mismatch alone is not evidence of compromise. Reused r on two different messages is the real alarm.") };
}
function hodlSessionOwnership(network) {
  if (hodlPsbtHd) return indexHdKey(hodlPsbtHd, network);
  if (hodlPsbtPriv) return indexSingleKey(hodlPsbtPriv, network, (key, compressed) => hodlSecp256k1.getPublicKey(key, compressed));
  return new Map();
}
function hodlDeclaredOutput(entries, script, network) {
  if (!hodlPsbtHd || !entries || !script) return null;
  let fingerprint = hodlFingerprintHex(hodlPsbtHd.fingerprint), declared = null;
  for (let entry of hodlFind(entries, 2)) {
    if (entry.val.length < 4 || (entry.val.length - 4) % 4) continue;
    let fp = hodlHex.encode(entry.val.slice(0, 4));
    let path = [];
    for (let i = 4; i < entry.val.length; i += 4) path.push(new DataView(entry.val.buffer, entry.val.byteOffset + i, 4).getUint32(0, true));
    let label = "m/" + pathLabel(path);
    // A foreign-fingerprint record says nothing about this wallet, and an
    // output map may carry several records (multisig cosigners) in an order
    // the PSBT creator chose. Scan every record so the verdict cannot depend
    // on that order: only a record naming this wallet settles ownership, and
    // every such claim is verified (issue #194).
    if (fp !== fingerprint) {
      if (!declared) declared = { state: "other-wallet", path: label, fingerprint: fp };
      continue;
    }
    try {
      let node = hodlPsbtHd;
      for (let index of path) node = node.deriveChild(index);
      if (!node.publicKey || !hodlEq(node.publicKey, entry.keydata)) return { state: "lie", path: label };
      let address = hodlAddr(script, network);
      let encoded = false;
      for (let scriptType of ["p2pkh", "p2sh-p2wpkh", "p2wpkh", "p2tr"]) {
        try {
          if (hodlAddressesEqual(address, hodlAddressOrThrow(scriptType, node.publicKey, network))) encoded = true;
        } catch {
        }
      }
      if (!encoded) return { state: "lie", path: label };
      let chain = path.length >= 2 ? path[path.length - 2] : null;
      declared = { state: "ours", path: label, role: chain === 1 ? "change" : chain === 0 ? "receive" : "key" };
    } catch {
      return { state: "lie", path: label };
    }
  }
  return declared;
}
function hodlRenderOutputHtml(output, index, network, map, entries) {
  let opReturn = parseOpReturn(output.script);
  if (opReturn) {
    let amount = typeof output.amount === "bigint" ? output.amount : BigInt(output.amount || 0);
    let lines = describeOpReturn({ ...opReturn, amount, burned: amount !== 0n });
    return "<p class='" + (opReturn.ok ? "psbt-warn" : "psbt-bad") + "'><strong>Output " + index + "</strong> \xB7 " + hodlSats(output.amount) + " BTC<br>" + lines.map(hodlEscapeHtml).join("<br>") + "</p>";
  }
  let scan = matchOwnership(map, output.script);
  let address = hodlAddr(output.script, network);
  if (scan.state !== "ours") scan = matchOwnership(map, address);
  if (scan.state === "ours" && address.startsWith("script ") && scan.address) address = scan.address;
  let declared = null;
  try {
    declared = hodlDeclaredOutput(entries, output.script, network);
  } catch {
  }
  let extra = "", className = "psbt-kv";
  if (declared && declared.state === "lie") {
    extra = "<br><strong>PSBT lies:</strong> claims " + hodlEscapeHtml(declared.path) + " but this session key does not produce this output. Do not sign.";
    className = "psbt-bad";
  } else if (scan.state === "ours") {
    let label = scan.role === "change" ? "change" : scan.role === "receive" ? "receive (this wallet)" : "this session key";
    extra = "<br>" + hodlEscapeHtml(label + " \xB7 " + scan.path);
    className = scan.role === "change" || scan.role === "key" ? "psbt-ok" : "psbt-kv";
  } else if (declared && declared.state === "ours") {
    extra = "<br>" + hodlEscapeHtml((declared.role === "change" ? "change" : "this wallet") + " \xB7 " + declared.path + " (verified)");
    className = "psbt-ok";
  } else if (scan.state === "external") {
    extra = "<br>not in this wallet (accounts 0\u20132, 50 receive + 50 change, four script types)";
  } else if (scan.state === "no-session") {
    extra = "<br><span class='muted'>Load a session key to see if this output is yours.</span>";
  }
  return "<p class='" + className + "'><strong>Output " + index + "</strong> \xB7 " + hodlSats(output.amount) + " BTC<br>" + hodlEscapeHtml(address) + extra + "</p>";
}
function hodlOwnershipWarning(outputs, network, map) {
  if (!map || !map.size) return "";
  let ours = outputs.some((output) => matchOwnership(map, output.script).state === "ours" || matchOwnership(map, hodlAddr(output.script, network)).state === "ours");
  if (ours) return "<p class='muted'>Session key: outputs compared against " + map.size + " derived scripts (accounts 0\u20132, 50 receive + 50 change, four types).</p>";
  if (outputs.length < 2) return "<p class='muted'>This output is not in the session wallet (accounts 0\u20132, 50 receive + 50 change, four script types).</p>";
  return "<p class='psbt-bad'><strong>No output belongs to this session wallet.</strong> If you expected change, do not sign. A destination-swap can replace both the payment and the change.</p>";
}
function hodlPsbtAnalysisSummary(checks) {
  let incomplete = checks.some((check) => check.state === "incomplete"),
    problem = checks.some((check) => check.state === "problem"),
    overall = problem && incomplete ? "ISSUES FOUND — ANALYSIS ALSO INCOMPLETE" : problem ? "ISSUES FOUND" : incomplete ? "ANALYSIS INCOMPLETE" : "LISTED CHECKS COMPLETE",
    overallClass = problem ? "psbt-bad" : incomplete ? "psbt-warn" : "psbt-ok";
  let rows = checks.map((check) => {
    let label = check.state === "complete" ? "Completed" : check.state === "problem" ? "Problem found" : "Incomplete",
      className = check.state === "complete" ? "psbt-ok" : check.state === "problem" ? "psbt-bad" : "psbt-warn";
    return "<li><strong>" + hodlEscapeHtml(check.label) + "</strong> — <span class='" + className + "'>" + label + "</span><br><span class='muted'>" + hodlEscapeHtml(check.detail) + "</span></li>";
  }).join("");
  return "<section class='psbt-analysis-summary' aria-label='PSBT security analysis status'><p class='label'>PSBT security analysis</p><p class='" + overallClass + "'><strong>" + overall + "</strong></p><ul>" + rows + "</ul><p class='muted'>Completed means only that the named check ran on the information available here. It does not prove that the PSBT claims are true or that the transaction is safe to sign.</p></section>";
}
function hodlPsbtNonceCheck(reused, possible, nonceIncomplete) {
  if (reused.length) return { label: "Nonce analysis", state: "problem", detail: "A repeated ECDSA nonce was detected; see the blocking warning below." };
  if (possible.length) return { label: "Nonce analysis", state: "incomplete", detail: "A possible repeated ECDSA nonce for the same public key could not be confirmed from this file; see the warning below and verify the signatures independently." };
  if (nonceIncomplete) return { label: "Nonce analysis", state: "incomplete", detail: "Coverage is partial: unreadable signatures, fewer than two comparable ECDSA signatures, missing key/digest data, unsupported scripts, or Taproot/Schnorr signatures prevented one or more nonce checks." };
  return { label: "Nonce analysis", state: "complete", detail: "All ECDSA signatures in this PSBT had comparable nonce values; no repeated r was found for the same key within this file." };
}
function hodlRenderPsbt(psbt) {
  // The inspector follows the header network picker (mainnet/testnet); there
  // is no per-tool network control.
  let network = hodlNetworkDefault,
    transcript = null,
    transcriptError = "",
    tx = psbt.tx,
    inputSum = 0n,
    knownInputs = 0,
    html = [],
    rValues = [],
    rows = [],
    tapSignatureCount = 0,
    ecdsaIndex = 0,
    uninspected = 0,
    policyProblems = 0,
    policyIncomplete = 0,
    unsupportedNonceChecks = 0;
  let inscriptionReport = { inputs: [], envelopes: [] }, inscriptionScanIncomplete = false;
  try {
    inscriptionReport = inspectPsbtInscriptions(psbt);
  } catch {
    inscriptionReport = { inputs: [], envelopes: [] };
    inscriptionScanIncomplete = true;
  }
  try {
    transcript = hodlParseAntiExfil(document.getElementById("psbt-ax-transcript")?.value || "");
  } catch (exception) {
    transcriptError = exception.message || String(exception);
  }
  html.push("<p class='label'>Where this transaction sends bitcoin</p>");
  let ownershipMap = hodlSessionOwnership(network);
  tx.outputs.forEach((output, index) => {
    html.push(hodlRenderOutputHtml(output, index, network, ownershipMap, psbt.outputs[index]));
  });
  html.push(hodlOwnershipWarning(tx.outputs, network, ownershipMap));
  psbt.inputs.forEach((entries, index) => {
    let witnessUtxo = hodlWitUtxo(entries);
    if (witnessUtxo) {
      inputSum += witnessUtxo.amount;
      knownInputs++;
    }
    let declaredSighash = null, declaredSighashError = "";
    try {
      declaredSighash = hodlSighashPolicy(entries);
    } catch (exception) {
      declaredSighashError = exception.message || String(exception);
    }
    let declaredLabel = declaredSighashError ? "" : declaredSighash === null ? "SIGHASH_ALL (default)" : hodlSighashLabel(declaredSighash);
    let previous = tx.inputs[index], destination = witnessUtxo ? hodlAddr(witnessUtxo.script, network) : "(previous output details unavailable)", signatures = hodlPartialSigs(entries), tapSignatures = hodlTapSigs(entries), finalized = hodlFinalized(entries);
    if (finalized) {
      // Finalized signatures moved into the final script fields must not
      // escape repeated-nonce analysis (issue #87).
      let finalMaterial = hodlFinalSigs(entries, witnessUtxo, tx, index);
      // A finalized input whose fields yield no analyzable ECDSA signature
      // (for example a Taproot-only witness) never yields a clean or
      // no-signatures verdict.
      if (!signatures.length && !finalMaterial.signatures.length && !finalMaterial.uninspected) finalMaterial.uninspected = 1;
      signatures = signatures.concat(finalMaterial.signatures);
      uninspected += finalMaterial.uninspected + (finalMaterial.malformed ? 1 : 0);
    }
    tapSignatureCount += tapSignatures.length;
    html.push("<p class='psbt-kv'><strong>Input " + index + "</strong> \xB7 " + hodlHexRev(previous.txid) + " : " + previous.vout + (witnessUtxo ? " \xB7 " + hodlSats(witnessUtxo.amount) + " BTC claimed" : "") + "<br>" + hodlEscapeHtml(destination) + "<br>" + (signatures.length + tapSignatures.length ? signatures.length + tapSignatures.length + " signature(s) present" : finalized ? "Finalized input data present" : "Not signed yet") + (declaredSighashError ? "<br>Declared sighash policy unreadable: " + hodlEscapeHtml(declaredSighashError) : "<br>Signature policy: " + hodlEscapeHtml(declaredLabel)) + "</p>");
    let inputEnvelopes = (inscriptionReport.inputs[index] && inscriptionReport.inputs[index].envelopes) || [];
    inputEnvelopes.forEach((envelope) => {
      let className = envelope.unrecognizedEven || envelope.bodyBytes > 100000 ? "psbt-bad" : "psbt-warn";
      html.push("<p class='" + className + "'><strong>Inscription envelope</strong> \xB7 input " + index + " \xB7 #" + envelope.envelopeIndex + " \xB7 " + hodlEscapeHtml(envelope.source) + "<br>" + describeEnvelope(envelope).map(hodlEscapeHtml).join("<br>") + "</p>");
    });
    if (declaredSighashError) {
      policyProblems++;
      html.push("<p class='psbt-bad'><strong>Policy problem:</strong> input " + index + " declares a malformed sighash policy. Do not sign until its policy is known.</p>");
    } else if (declaredSighash !== null && declaredSighash !== 1) {
      policyProblems++;
      html.push("<p class='psbt-bad'><strong>Policy problem:</strong> input " + index + " requests " + hodlEscapeHtml(declaredLabel) + "; that policy does not commit to all shown outputs. Do not accept the displayed outputs as what a signature will authorize.</p>");
    }
    if (tapSignatures.length || (finalized && !signatures.length)) policyIncomplete++;
    signatures.forEach(signature => {
      let parts = hodlSigParts(signature.der),
        looseR = parts ? parts.r : hodlDerRLoose(signature.der),
        scriptCode = hodlInputScriptCode(entries, witnessUtxo),
        sighash = witnessUtxo && scriptCode ? hodlBip143(tx, index, scriptCode, witnessUtxo.amount, signature.sighash) : null,
        signatureValid = parts && sighash ? hodlSecp256k1.verify(signature.der, sighash, signature.pubkey, {
          prehash: !1,
          format: "der",
          lowS: !1
        }) : null,
        privateKey = hodlPrivForPub(signature.pubkey) || hodlPrivFromPath(entries, signature.pubkey),
        message = hodlT("Need the matching key in this session to check RFC 6979 and low-r grind."),
        className = "muted";
      let suffixForPolicy = signature.raw.length >= 2 ? signature.sighash : null,
        sighashProblems = hodlSighashProblems(declaredSighash, suffixForPolicy);
      if (sighashProblems.length) policyProblems++;
      if (!parts && !looseR) {
        uninspected += 1;
        policyIncomplete += 1;
        message = hodlT("Signature is not DER and its nonce cannot be inspected.");
        className = "psbt-warn";
        if (sighashProblems.length) {
          message = hodlT("Signature policy problem: {problems}", { problems: sighashProblems.join(" ") });
          className = "psbt-bad";
        }
      } else {
        rValues.push({
          input: index,
          r: looseR,
          hex: hodlHex.encode(looseR),
          pubkey: hodlCompressedPubkey(signature.pubkey),
          sighash,
          valid: parts ? signatureValid : null
        });
        if (sighashProblems.length) {
          // An unsafe or conflicting sighash policy blocks every other check.
          message = hodlT("Signature policy problem: {problems}", { problems: sighashProblems.join(" ") });
          className = "psbt-bad";
        } else if (!parts) {
          message = hodlT("Signature is not strict DER. Its r value is still compared for nonce reuse.");
          className = "psbt-warn"
        } else if (signatureValid === !1) {
          message = hodlT("This signature does not verify against the reconstructed input digest.");
          className = "psbt-warn";
        } else if (transcript) {
          let opening = transcript.openings.length === 1 ? transcript.openings[0] : transcript.openings[ecdsaIndex];
          if (!opening) {
            message = hodlT("No Jade opening R was provided for this signature.");
            className = "psbt-warn";
          } else try {
            if (hodlAntiExfilCommitOk(parts.r, opening, transcript.host)) {
              message = hodlT("Matches Jade anti-exfil (sign-to-contract). Host entropy mixed into the nonce. Not a leak.");
              className = "psbt-ok";
            } else {
              message = hodlT("Does not match this Jade anti-exfil transcript. Signature r is not R + H(R||ρ)G.");
              className = "psbt-warn";
              if (privateKey && sighash) try {
                let cmp = hodlRfc6979Compare(sighash, privateKey, parts.r);
                if (cmp.ok) {
                  message += " " + cmp.message;
                  className = cmp.className;
                } else message += " " + hodlT("Also does not match RFC 6979 or low-r grind.");
              } catch (exception) {
                message += " " + (exception.message || String(exception));
              }
            }
          } catch (exception) {
            message = hodlT("Could not verify Jade anti-exfil: {error}", { error: exception.message || String(exception) });
            className = "psbt-warn";
          }
        } else if (privateKey && sighash) try {
          let cmp = hodlRfc6979Compare(sighash, privateKey, parts.r);
          message = cmp.message;
          className = cmp.className;
        } catch (exception) {
          message = hodlT("Could not recompute this signature: {error}", { error: exception.message || String(exception) });
          className = "psbt-warn";
          unsupportedNonceChecks += 1;
        }
        else if (privateKey && !scriptCode) {
          message = hodlT("Matching key found, but this input script is not yet supported for RFC 6979 comparison.");
          className = "psbt-warn";
          unsupportedNonceChecks += 1;
        } else if (!privateKey || !sighash) {
          unsupportedNonceChecks += 1;
        }
      }
      ecdsaIndex += 1;
      rows.push({ input: index, message, className, pubkey: hodlHex.encode(signature.pubkey) });
    });
  });
  if (knownInputs === tx.inputs.length) {
    let outputSum = tx.outputs.reduce((sum, output) => sum + output.amount, 0n), fee = inputSum - outputSum;
    if (fee >= 0n) html.push("<p class='psbt-kv'><strong>Unverified fee (PSBT witness UTXO claims)</strong> \xB7 " + hodlSats(fee) + " BTC</p>");
    else html.push("<p class='psbt-bad'><strong>Inconsistent claimed amounts:</strong> outputs exceed claimed inputs by " + hodlSats(-fee) + " BTC.</p>");
  } else html.push("<p class='muted'>Fee unknown — some inputs do not include a claimed witness UTXO amount.</p>");
  html.push("<p class='muted'>Input amounts and any fee are unverified PSBT claims. This tool does not check them against previous transactions or the blockchain.</p>");
  if (inscriptionReport.envelopes.length) {
    html.push("<p class='psbt-warn'><strong>" + inscriptionReport.envelopes.length + " inscription envelope" + (inscriptionReport.envelopes.length === 1 ? "" : "s") + " in this PSBT.</strong> This is what the file reveals in witness or tap-leaf scripts. EntropyLab does not number sats, fetch content from the chain, or render binary payloads.</p>");
  }
  html.push("<p class='label'>ECDSA nonce check</p>");
  if (transcriptError) html.push("<p class='psbt-warn'><strong>Jade anti-exfil transcript not used:</strong> " + hodlEscapeHtml(transcriptError) + "</p>");
  let {
    reused,
    possible
  } = hodlCompareNonces(rValues);
  if (reused.length) html.push("<p class='psbt-bad'><strong>Reused nonce detected for the same public key.</strong> The same r value appears on different message digests. If both signatures are valid, the private key can be recovered. Do not broadcast this transaction.</p>");
  else if (possible.length) html.push("<p class='psbt-warn'><strong>Possible repeated nonce for the same public key.</strong> The message digests could not both be reconstructed, so verify these signatures independently before treating this as a key leak.</p>");
  else if (uninspected) html.push("<p class='psbt-warn'><strong>Incomplete nonce coverage.</strong> Some ECDSA signatures could not be inspected, so this is not a clean verdict.</p>");
  else if (rValues.length >= 2) html.push("<p class='psbt-ok'>No repeated ECDSA nonce r values were found for the same public key in this PSBT.</p>");
  else if (rValues.length === 1) html.push("<p class='muted'>Only one ECDSA signature with a readable r is present. Nonce reuse cannot be judged from this file alone.</p>");
  else html.push("<p class='muted'>No ECDSA signatures with a readable r value are present, so there is no nonce to compare yet.</p>");
  if (rValues.length) html.push("<p class='psbt-kv'>r values:<br>" + rValues.map(value => hodlEscapeHtml(value.hex) + " (input " + value.input + ")").join("<br>") + "</p>");
  rows.forEach(row => html.push("<p class='" + row.className + "'><strong>Input " + row.input + "</strong> pubkey " + hodlEscapeHtml(row.pubkey.slice(0, 18)) + "\u2026 \u2014 " + hodlEscapeHtml(row.message) + "</p>"));
  if (tapSignatureCount) html.push("<p class='muted'>This PSBT also contains " + tapSignatureCount + " Taproot / Schnorr signature(s). They are counted but their BIP340 nonces are not analyzed in this version.</p>");
  html.push("<p class='muted'>RFC 6979 comparison currently covers SegWit v0 P2WPKH and P2WSH signatures using SIGHASH_ALL, including Bitcoin Core-style low-r grinding. Jade anti-exfil is secp256k1-zkp sign-to-contract and needs the USB host nonce plus signer opening; QR / sign_psbt Jade does not run it yet. BitBox anti-klepto is a different construction. Nonce reuse detection compares r values for the same secp256k1 point, including signatures carried by finalized scriptSig/witness fields, compressed and uncompressed encodings, and recoverable non-strict DER. A clean verdict is not issued when a signature cannot be inspected. Inscription detection reads OP_FALSE OP_IF \"ord\" envelopes in tap-leaf scripts and finalized witnesses; it does not number sats. Output ownership is derived from the session key: accounts 0\u20132, 50 receive + 50 change, all four script types. It does not talk to the chain.</p>");
  let nonceIncomplete = uninspected || tapSignatureCount || unsupportedNonceChecks || rValues.length < 2;
  // Journal logging runs after every warning banner is pushed and is wrapped
  // so a logging failure can never suppress the on-screen nonce verdict.
  try {
    hodlJournalNonceVerdict("psbt", reused, possible, nonceIncomplete, rValues.length);
  } catch {
  }
  let checks = [
    {
      label: "Previous outputs and fee",
      state: "incomplete",
      detail: knownInputs === tx.inputs.length
        ? "Amounts and fee were calculated from PSBT-provided witness UTXO claims, but those claims were not checked against previous transactions or the blockchain."
        : "One or more inputs have no witness UTXO amount, and available PSBT claims were not checked against previous transactions or the blockchain.",
    },
    {
      label: "SIGHASH policy",
      state: policyProblems ? "problem" : policyIncomplete ? "incomplete" : "complete",
      detail: policyProblems
        ? "At least one malformed, unsafe, or conflicting policy was found; see the blocking warning below."
        : policyIncomplete
          ? "Some finalized, Taproot, or undecodable signature data could not be evaluated by this check."
          : "Every policy declaration and readable ECDSA signature suffix available to this report commits to all displayed outputs.",
    },
    {
      label: "Output ownership / derivation",
      state: "incomplete",
      detail: ownershipMap.size
        ? "Compared with the loaded session key only within accounts 0–2, 50 receive and 50 change addresses, and four supported script types; outputs outside that range remain unclassified."
        : "No session key was loaded, so output ownership and change derivation were not checked.",
    },
    hodlPsbtNonceCheck(reused, possible, nonceIncomplete),
    {
      label: "Taproot inscription scan",
      state: inscriptionScanIncomplete ? "incomplete" : "complete",
      detail: inscriptionScanIncomplete
        ? "Tap-leaf or finalized-witness data could not be fully decoded, so inscription-envelope coverage is incomplete."
        : "Tap-leaf scripts and finalized witnesses were scanned for recognizable inscription envelopes; this does not number sats or inspect chain data.",
    },
  ];
  html.unshift(hodlPsbtAnalysisSummary(checks));
  return html.join("")
}
function hodlRenderRawTx(tx) {
  // The inspector follows the header network picker (mainnet/testnet); there
  // is no per-tool network control.
  let network = hodlNetworkDefault,
    html = [],
    map = hodlSessionOwnership(network),
    signatures = extractEcdsaSignatures(tx),
    rValues = [],
    uninspected = 0;
  html.push("<p class='psbt-warn'><strong>Raw Bitcoin transaction.</strong> Not a PSBT. Input amounts and fee are unknown without previous outputs. RFC 6979 cannot be checked here. This is the last look before broadcast.</p>");
  html.push("<p class='label'>Where this transaction sends bitcoin</p>");
  tx.outputs.forEach((output, index) => {
    html.push(hodlRenderOutputHtml(output, index, network, map, null));
  });
  html.push(hodlOwnershipWarning(tx.outputs, network, map));
  tx.inputs.forEach((input, index) => {
    html.push("<p class='psbt-kv'><strong>Input " + index + "</strong> \xB7 " + hodlHexRev(input.txid) + " : " + input.vout + "<br>sequence " + hodlEscapeHtml("0x" + input.sequence.toString(16)) + (input.sequence < 0xfffffffe ? " \xB7 RBF-capable" : "") + "</p>");
  });
  inscriptionHints(tx).forEach((hint) => {
    html.push("<p class='psbt-warn'><strong>Inscription envelope</strong> in input " + hint.input + " (" + hint.scriptBytes + " bytes of script/witness). This transaction reveals OP_FALSE OP_IF \"ord\" data.</p>");
  });
  html.push("<p class='muted'>Version " + tx.version + " \xB7 locktime " + tx.locktime + (tx.segwit ? " \xB7 segwit" : "") + ". Fee unknown \u2014 previous output amounts are not in a raw transaction.</p>");
  html.push("<p class='label'>ECDSA nonce check</p>");
  signatures.forEach((signature) => {
    let parts = hodlSigParts(signature.der), looseR = parts ? parts.r : hodlDerRLoose(signature.der);
    if (!looseR || !signature.pubkey) {
      if (signature.der) uninspected += 1;
      return;
    }
    rValues.push({
      input: signature.input,
      r: looseR,
      hex: hodlHex.encode(looseR),
      pubkey: hodlCompressedPubkey(signature.pubkey),
      sighash: null,
      valid: null
    });
  });
  let { reused, possible } = hodlCompareNonces(rValues);
  if (reused.length || possible.length) html.push("<p class='psbt-bad'><strong>Repeated nonce r for the same public key.</strong> Message digests cannot be rebuilt from a raw transaction without prevouts, so treat this as a warning and do not broadcast until the signatures are checked independently.</p>");
  else if (uninspected) html.push("<p class='psbt-warn'><strong>Incomplete nonce coverage.</strong> Some ECDSA signatures could not be inspected.</p>");
  else if (rValues.length >= 2) html.push("<p class='psbt-ok'>No repeated ECDSA nonce r values were found for the same public key in this transaction.</p>");
  else if (rValues.length === 1) html.push("<p class='muted'>Only one ECDSA signature with a readable r is present. Nonce reuse cannot be judged from this file alone.</p>");
  else html.push("<p class='muted'>No ECDSA signatures with a readable r and public key were found.</p>");
  if (rValues.length) html.push("<p class='psbt-kv'>r values:<br>" + rValues.map((value) => hodlEscapeHtml(value.hex) + " (input " + value.input + ")").join("<br>") + "</p>");
  html.push("<p class='muted'>Raw-transaction inspect does not reconstruct sighashes. Paste the PSBT when you still can; use this path for a fully signed hex dump from a hardware wallet or Bitcoin Core.</p>");
  // Journal logging runs after every warning banner is pushed and is wrapped
  // so a logging failure can never suppress the on-screen nonce verdict.
  try {
    hodlJournalNonceVerdict("transaction", reused, possible, uninspected || rValues.length < 2, rValues.length);
  } catch {
  }
  return html.join("");
}
var hodlAccountId = "bip84",
  hodlNextKeyId = 1,
  hodlNextKeyNumber = 1,
  hodlKeys = [],
  hodlActiveKey = -1;
var hodlKeyManagerIds = new Set(), hodlKeyManagerIgnored = [], hodlKeyManagerPending = [], hodlKeyManagerActiveId = "";

function hodlKeyColor(id) {
  let hue = Math.round((Number(id) * 137.508 + 19) % 360);
  return `oklch(61% 0.08 ${hue})`;
}
var hodlPrivateKeyKinds = ["wif", "hex-key", "minikey", "brain"];
function hodlPrivateKeyValues(fields) {
  if (!fields.privateKeys || typeof fields.privateKeys !== "object") fields.privateKeys = {};
  hodlPrivateKeyKinds.forEach((kind) => {
    if (typeof fields.privateKeys[kind] !== "string") fields.privateKeys[kind] = "";
  });
  let legacy = String(fields.key ?? "");
  if (legacy) {
    let kind = hodlNormalizePrivateKeyKind(fields.keyKind, legacy);
    if (!fields.privateKeys[kind]) fields.privateKeys[kind] = legacy;
    fields.key = "";
  }
  return fields.privateKeys;
}
function hodlNewKeyState(name, keyId, keyNumber) {
  let id = keyId ?? hodlNextKeyId++, number = keyNumber ?? hodlNextKeyNumber++;
  return { id, number, createdAt: new Date().toISOString(), color: hodlKeyColor(id), name: name || hodlDefaultKeyName(number), mode: "dice", diceMethod: "coldcard", cardMethod: "hashed", seedMethod: "words", seedZeroIndexed: false, cardColemanSymbols: false, entropyFormat: "bin", globalSync: false, globalSyncSource: "", globalSyncBitCount: 0, seedAutocomplete: true, passphraseBip39Words: false, brainWalletOutput: "scalar", passphraseAutocomplete: true, brainWalletTrim: false, showCards: false, showDiceFairness: false, targetWords: 24, diceCoinPositions: [], lastWord: "", dplusLastWord: "", result: null, reveal: false, accountId: "bip84", error: "", fields: { pass: "", script: "bip84", derivationPath: `m/84'/${hodlDefaultCoinType()}'/0'/0/0`, derivationAccountPath: `m/84'/${hodlDefaultCoinType()}'/0'`, purpose: "84'", purposeHarden: true, coinType: `${hodlDefaultCoinType()}'`, coinTypeHarden: true, network: hodlNetworkDefault, account: "0'", accountHarden: true, branchStart: "0", branchHarden: false, branchRange: "1", addressStart: "0", addressHarden: false, addressRange: "1", dice: "", bitboxDice: "", dplusDice: "", hex: "", bin: "", base4: "", base8: "", base32: "", base64: "", cards: "", directCards: "", seed: "", seedNumbers: "", brainLab: "", key: "", keyKind: "wif", privateKeys: { wif: "", "hex-key": "", minikey: "", brain: "" } } };
}
function hodlNewLabState() {
  let state = hodlNewKeyState("Key Station", 0, 0);
  state.isLab = true;
  return state;
}
function hodlKeyManagerStatus(message, error = false) {
  let status = document.getElementById("journal-keymanager-status");
  if (!status) return;
  status.textContent = message || "";
  status.dataset.state = error ? "error" : "";
}
function hodlKeyManagerStates() {
  let states = [], identities = new Set();
  [...hodlKeys.filter((state) => !state.isLab && state.result), ...hodlKeyManagerPending].forEach((state) => {
    let identity = keyVaultIdentity(state);
    if (!identity || identities.has(identity)) return;
    identities.add(identity);
    states.push(state);
  });
  return states;
}
function hodlKeyManagerEntry(state) {
  let copy = JSON.parse(JSON.stringify(state));
  delete copy.isLab;
  copy.reveal = false;
  copy.error = "";
  delete copy.errorSpec;
  return copy;
}
function hodlKeyManagerNameTaken(name, state) {
  let normalized = hodlNormalizeKeyName(name);
  return normalized && hodlKeyManagerStates().some((candidate) => candidate !== state && hodlNormalizeKeyName(candidate.name) === normalized);
}
function hodlKeyManagerRename(state, input) {
  let name = String(input.value || "").trim().replace(/\s+/g, " ");
  if (!name || hodlKeyManagerNameTaken(name, state)) {
    input.value = state.name || "";
    if (name) hodlKeyManagerStatus("That key name is already in use.", true);
    return;
  }
  state.name = name;
  input.value = name;
  if (hodlKeys.includes(state)) hodlRenderKeyTabs();
  hodlKeyManagerRender();
  hodlKeyManagerStatus("Key name updated in memory. Download the key file to keep the change.");
  hodlJournalLog("key-manager-rename", keyVaultIdentity(state), "journal");
}
function hodlKeyManagerDetails(state) {
  let result = state.result || {};
  return [
    ["Created", state.createdAt ? new Date(state.createdAt).toLocaleString() : "Not available"],
    ["Master fingerprint", result.masterFingerprint || "Not available"],
    ["Method", hodlKeySummaryMethod(state) || "Unknown"],
    ["Network", result.network || state.fields?.network || "Unknown"],
    ["Derivation path", state.fields?.derivationPath || state.createdPath || "Not available"],
    ["Public root key", result.rootXpub || result.xpub || result.importedPublicKey || "Not available"],
    ["Private material", result.rootXprv || result.importedPrivateKey || result.accounts?.some((account) => account.primaryPrivate) ? "Present in encrypted key file" : "Not present"],
  ];
}
function hodlKeyManagerRenderIgnored() {
  let section = document.getElementById("journal-keymanager-ignored"), list = document.getElementById("journal-keymanager-ignored-list");
  if (!section || !list) return;
  section.hidden = !hodlKeyManagerIgnored.length;
  list.replaceChildren();
  hodlKeyManagerIgnored.forEach((entry) => {
    let row = document.createElement("div"), copy = document.createElement("div"), name = document.createElement("strong"), fingerprint = document.createElement("span"), restore = document.createElement("button");
    row.className = "journal-keymanager-ignored-row";
    copy.className = "journal-keymanager-ignored-copy";
    name.textContent = entry.name || "Unnamed key";
    fingerprint.textContent = entry.result?.masterFingerprint || "No fingerprint";
    copy.append(name, fingerprint);
    restore.className = "btn secondary";
    restore.type = "button";
    restore.textContent = "Restore";
    restore.onclick = () => hodlKeyManagerRestoreIgnored(entry);
    row.append(copy, restore);
    list.appendChild(row);
  });
}
function hodlKeyManagerRender() {
  let tabs = document.getElementById("journal-keymanager-tabs"), panel = document.getElementById("journal-keymanager-panel");
  if (!tabs || !panel) return;
  let states = hodlKeyManagerStates();
  tabs.replaceChildren();
  panel.replaceChildren();
  if (!states.length) {
    let empty = document.createElement("p");
    empty.className = "journal-keymanager-empty";
    empty.textContent = "No derived keys are available. Derive a key in Key Station or upload an encrypted .elkeys file.";
    panel.appendChild(empty);
    hodlKeyManagerRenderIgnored();
    return;
  }
  let active = states.find((state) => keyVaultIdentity(state) === hodlKeyManagerActiveId) || states[0];
  hodlKeyManagerActiveId = keyVaultIdentity(active);
  states.forEach((state, index) => {
    let identity = keyVaultIdentity(state), activeTab = state === active, button = document.createElement("button"), image = document.createElement("img"), label = document.createElement("span");
    button.className = "tab key-tab journal-keymanager-key-tab" + (activeTab ? " active" : "");
    button.id = `journal-keymanager-key-${index + 1}`;
    button.type = "button";
    button.setAttribute("role", "tab");
    button.setAttribute("aria-selected", String(activeTab));
    button.setAttribute("aria-controls", "journal-keymanager-panel");
    button.tabIndex = activeTab ? 0 : -1;
    image.className = "key-tab-lifehash";
    image.width = 28;
    image.height = 28;
    image.alt = "";
    image.hidden = true;
    hodlFillKeyTabLifehash(image, state.result?.masterFingerprint || "");
    label.className = "key-tab-label";
    label.textContent = state.name || state.result?.masterFingerprint || "Unnamed key";
    button.append(image, label);
    button.onclick = () => {
      hodlKeyManagerActiveId = identity;
      hodlKeyManagerRender();
    };
    button.onkeydown = (event) => {
      let next = null;
      if (event.key === "ArrowRight") next = (index + 1) % states.length;
      else if (event.key === "ArrowLeft") next = (index - 1 + states.length) % states.length;
      else if (event.key === "Home") next = 0;
      else if (event.key === "End") next = states.length - 1;
      if (next === null) return;
      event.preventDefault();
      hodlKeyManagerActiveId = keyVaultIdentity(states[next]);
      hodlKeyManagerRender();
      document.getElementById("journal-keymanager-tabs")?.children[next]?.focus();
    };
    tabs.appendChild(button);
  });
  panel.setAttribute("aria-labelledby", tabs.querySelector(".active")?.id || "");
  let included = hodlKeyManagerIds.has(hodlKeyManagerActiveId), heading = document.createElement("div"), title = document.createElement("h3"), badge = document.createElement("span");
  heading.className = "journal-keymanager-heading";
  title.textContent = active.name || active.result?.masterFingerprint || "Unnamed key";
  badge.className = "journal-keymanager-badge" + (included ? " is-included" : "");
  badge.textContent = included ? "Included in key file" : "Not included";
  heading.append(title, badge);
  panel.appendChild(heading);
  let name = document.createElement("input"), nameLabel = document.createElement("label");
  nameLabel.className = "field journal-keymanager-name";
  nameLabel.append("Key name");
  name.type = "text";
  name.value = active.name || "";
  name.maxLength = 120;
  name.autocomplete = "off";
  name.onchange = () => hodlKeyManagerRename(active, name);
  nameLabel.appendChild(name);
  panel.appendChild(nameLabel);
  let details = document.createElement("dl");
  details.className = "journal-keymanager-details";
  hodlKeyManagerDetails(active).forEach(([term, value]) => {
    let dt = document.createElement("dt"), dd = document.createElement("dd");
    dt.textContent = term;
    dd.textContent = value;
    details.append(dt, dd);
  });
  panel.appendChild(details);
  let actions = document.createElement("div"), include = document.createElement("button"), use = document.createElement("button"), ignore = document.createElement("button");
  actions.className = "row psbt-actions journal-keymanager-entry-actions";
  include.className = included ? "btn secondary" : "btn primary";
  include.type = "button";
  include.textContent = included ? "Remove from key file" : "Include in key file";
  include.onclick = () => hodlKeyManagerToggle(active);
  use.className = "btn secondary";
  use.type = "button";
  use.textContent = hodlKeys.includes(active) ? "Open in Key Station" : "Use in Key Station";
  use.onclick = () => hodlKeyManagerUseInStation(active);
  ignore.className = "btn clear-current-action journal-keymanager-ignore";
  ignore.type = "button";
  ignore.textContent = "Ignore key";
  ignore.onclick = () => hodlKeyManagerIgnore(active);
  actions.append(include, use, ignore);
  panel.appendChild(actions);
  hodlKeyManagerRenderIgnored();
}
function hodlKeyManagerToggle(state) {
  let identity = keyVaultIdentity(state);
  if (hodlKeyManagerIds.has(identity)) {
    hodlKeyManagerIds.delete(identity);
    hodlKeyManagerStatus("Key removed from the next key-file download.");
    hodlJournalLog("key-manager-exclude", identity, "journal");
  } else {
    hodlKeyManagerIds.add(identity);
    hodlKeyManagerStatus("Key included in the next key-file download.");
    hodlJournalLog("key-manager-include", identity, "journal");
  }
  hodlKeyManagerRender();
}
function hodlKeyManagerImportedState(entry) {
  let state = hodlNewKeyState(String(entry.name || "Imported key"), hodlNextKeyId++, hodlNextKeyNumber++);
  Object.assign(state, entry, {
    isLab: false,
    id: state.id,
    number: state.number,
    color: hodlKeyColor(state.id),
    createdAt: entry.createdAt || state.createdAt,
    fields: { ...state.fields, ...entry.fields, ...(entry.fields?.privateKeys ? { privateKeys: { ...state.fields.privateKeys, ...entry.fields.privateKeys } } : {}) },
    reveal: false,
    error: "",
    errorSpec: null,
  });
  return state;
}
function hodlKeyManagerUseInStation(state) {
  let identity = keyVaultIdentity(state), existing = hodlKeys.find((candidate) => !candidate.isLab && keyVaultIdentity(candidate) === identity);
  if (existing) hodlActiveKey = hodlKeys.indexOf(existing);
  else {
    let pending = hodlKeyManagerPending.indexOf(state);
    if (pending < 0) return;
    hodlKeyManagerPending.splice(pending, 1);
    hodlKeys.push(state);
    hodlActiveKey = hodlKeys.length - 1;
  }
  hodlRenderKeyTabs();
  hodlJournalLog("key-manager-use", identity, "journal");
  hodlShowWorkspace("calc");
}
function hodlKeyManagerIgnore(state) {
  let identity = keyVaultIdentity(state), station = hodlKeys.indexOf(state), pending = hodlKeyManagerPending.indexOf(state);
  if (station >= 0) {
    hodlKeys.splice(station, 1);
    if (hodlActiveKey > station) hodlActiveKey--;
    else if (hodlActiveKey === station) hodlActiveKey = Math.min(station, hodlKeys.length - 1);
    hodlRenderKeyTabs();
  } else if (pending >= 0) hodlKeyManagerPending.splice(pending, 1);
  hodlKeyManagerIgnored = hodlKeyManagerIgnored.filter((entry) => keyVaultIdentity(entry) !== identity);
  hodlKeyManagerIgnored.push(hodlKeyManagerEntry(state));
  hodlKeyManagerIds.delete(identity);
  hodlKeyManagerActiveId = "";
  hodlKeyManagerRender();
  hodlKeyManagerStatus("Key moved to Ignored keys.");
  hodlJournalLog("key-manager-ignore", identity, "journal");
}
function hodlKeyManagerRestoreIgnored(entry) {
  let identity = keyVaultIdentity(entry), state = hodlKeyManagerStates().find((candidate) => keyVaultIdentity(candidate) === identity);
  if (!state) {
    state = hodlKeyManagerImportedState(entry);
    hodlKeyManagerPending.push(state);
  }
  hodlKeyManagerIgnored = hodlKeyManagerIgnored.filter((candidate) => keyVaultIdentity(candidate) !== identity);
  hodlKeyManagerIds.add(keyVaultIdentity(state));
  hodlKeyManagerActiveId = keyVaultIdentity(state);
  hodlKeyManagerRender();
  hodlKeyManagerStatus("Key restored and included in the next key-file download.");
  hodlJournalLog("key-manager-restore", identity, "journal");
}
function hodlKeyManagerDetachFromStation(state) {
  let identity = keyVaultIdentity(state), index = hodlKeys.indexOf(state);
  if (index < 0) return;
  hodlCaptureKey();
  hodlKeys.splice(index, 1);
  if (!hodlKeyManagerPending.some((candidate) => keyVaultIdentity(candidate) === identity)) hodlKeyManagerPending.push(state);
  if (hodlActiveKey > index) hodlActiveKey--;
  else if (hodlActiveKey === index) hodlActiveKey = Math.min(index, hodlKeys.length - 1);
  hodlRenderKeyTabs();
  hodlRestoreKey();
  hodlKeyManagerStatus("Key removed from Key Station. It remains available in Key manager.");
  hodlJournalLog("station-delete", `key-${state.number}`, "calc");
  (hodlActiveKey >= 0 ? hodlElement("#key-tabs").children[hodlActiveKey] : hodlElement("#add-key"))?.focus();
}
function hodlKeyManagerWipeValue(value, seen = new Set()) {
  if (!value || typeof value !== "object" || seen.has(value)) return;
  seen.add(value);
  if (value instanceof Uint8Array) {
    value.fill(0);
    return;
  }
  Object.values(value).forEach((entry) => hodlKeyManagerWipeValue(entry, seen));
}
function hodlKeyManagerReset() {
  hodlKeyManagerPending.forEach((state) => hodlKeyManagerWipeValue(state));
  hodlKeyManagerIgnored.forEach((state) => hodlKeyManagerWipeValue(state));
  hodlKeyManagerIds.clear();
  hodlKeyManagerIgnored = [];
  hodlKeyManagerPending = [];
  hodlKeyManagerActiveId = "";
  let file = document.getElementById("journal-keymanager-file");
  if (file) file.value = "";
  hodlKeyManagerStatus("");
  hodlKeyManagerRender();
}
function hodlCloneDerivedKey(source, existing) {
  let state = existing ? { ...existing, fields: { ...existing.fields, ...(existing.fields.privateKeys ? { privateKeys: { ...existing.fields.privateKeys } } : {}) } } : hodlNewKeyState();
  let fingerprint = source.result?.masterFingerprint || "";
  Object.assign(state, {
    isLab: false,
    name: fingerprint || state.name,
    mode: source.mode,
    diceMethod: source.diceMethod,
    cardMethod: source.cardMethod,
    seedMethod: source.seedMethod,
    seedZeroIndexed: source.seedZeroIndexed,
    cardColemanSymbols: source.cardColemanSymbols,
    entropyFormat: source.entropyFormat,
    globalSync: source.globalSync,
    globalSyncSource: source.globalSyncSource,
    globalSyncBitCount: source.globalSyncBitCount,
    // The entropy verdict must travel with the sync it describes, or a cloned
    // key falls back to reporting its digest length as counted entropy.
    globalSyncSourceBits: source.globalSyncSourceBits,
    seedAutocomplete: source.seedAutocomplete,
    passphraseBip39Words: source.passphraseBip39Words,
    brainWalletOutput: source.brainWalletOutput,
    passphraseAutocomplete: source.passphraseAutocomplete,
    brainWalletTrim: source.brainWalletTrim,
    showCards: source.showCards,
    showDiceFairness: source.showDiceFairness,
    showNumberBaseCalculations: source.showNumberBaseCalculations,
    targetWords: source.targetWords,
    diceCoinPositions: Array.isArray(source.diceCoinPositions) ? source.diceCoinPositions.slice() : [],
    lastWord: source.lastWord,
    dplusLastWord: source.dplusLastWord,
    result: source.result,
    reveal: source.reveal,
    accountId: source.accountId,
    createdScript: source.createdScript,
    createdPath: source.createdPath,
    error: source.error,
    fields: { ...source.fields, ...(source.fields?.privateKeys ? { privateKeys: { ...source.fields.privateKeys } } : {}) }
  });
  return state;
}
function hodlCommitDerivedKey() {
  let lab = hodlKeys[hodlActiveKey];
  if (!lab?.isLab || !lab.result) {
    hodlRenderKeyTabs();
    hodlRestoreKey();
    return hodlActiveKey;
  }
  let fingerprint = lab.result.masterFingerprint || "";
  let existing = fingerprint ? hodlKeys.findIndex((state) => !state.isLab && state.result?.masterFingerprint === fingerprint) : -1;
  if (existing >= 0) {
    hodlKeys[existing] = hodlCloneDerivedKey(lab, hodlKeys[existing]);
    hodlKeys[hodlActiveKey] = hodlNewLabState();
    hodlActiveKey = existing;
  } else {
    let derived = hodlCloneDerivedKey(lab);
    hodlKeys[hodlActiveKey] = hodlNewLabState();
    hodlKeys.push(derived);
    hodlActiveKey = hodlKeys.length - 1;
  }
  hodlRenderKeyTabs();
  hodlRestoreKey();
  return hodlActiveKey;
}
function hodlSelectLab() {
  let lab = hodlKeys.findIndex((state) => state.isLab);
  if (lab < 0) {
    hodlCaptureKey();
    hodlKeys.unshift(hodlNewLabState());
    lab = 0;
    if (hodlActiveKey >= 0) hodlActiveKey += 1;
  }
  if (lab === hodlActiveKey) return;
  hodlSelectKey(lab);
}
function hodlFillLabFromKey(source) {
  let labIndex = hodlKeys.findIndex((state) => state.isLab);
  let existing = labIndex >= 0 ? hodlKeys[labIndex] : hodlNewLabState();
  let lab = hodlCloneDerivedKey(source, existing);
  Object.assign(lab, { isLab: true, name: "Key Station", result: null, error: "", reveal: false, createdScript: "", createdPath: "" });
  if (labIndex < 0) {
    hodlKeys.unshift(lab);
    labIndex = 0;
    if (hodlActiveKey >= 0) hodlActiveKey += 1;
  } else hodlKeys[labIndex] = lab;
  return labIndex;
}
function hodlEditKeyInputs() {
  let source = hodlKeys[hodlActiveKey];
  if (!source || source.isLab) {
    hodlSelectLab();
    return;
  }
  hodlCaptureKey();
  hodlSelectKey(hodlFillLabFromKey(hodlKeys[hodlActiveKey]));
}
function hodlKeyHasResult(state = hodlKeys[hodlActiveKey]) {
  return Boolean(state && !state.isLab && state.result);
}
function hodlKeySummaryMethod(state) {
  if (!state) return "";
  if (state.mode === "dice") return "Dice rolls";
  if (state.mode === "cards") return "Cards";
  if (state.mode === "hex") return "Number bases";
  if (state.mode === "seed") return "Seed phrase";
  if (state.mode === "key") return "Private key";
  return "";
}
function hodlKeySummaryScript(state) {
  let id = state?.accountId || state?.fields?.script || "bip84";
  let def = typeof hodlScriptDefinition === "function" ? hodlScriptDefinition(id) : null;
  return def?.label || id;
}
function hodlKeySummaryPath(state) {
  return hodlDisplayDerivationPath(state?.fields?.derivationPath || "");
}
function hodlSnapshotKeySummary(state = hodlKeys[hodlActiveKey]) {
  if (!state) return;
  state.createdScript = hodlKeySummaryScript(state);
  state.createdPath = hodlKeySummaryPath(state);
}
function hodlFillKeyTabLifehash(image, fingerprint) {
  // The LifeHash module is a later parser-inserted script, and the boot
  // promise can settle between scripts (the footer waits for full load for
  // the same reason): `hodlLifeHash?.` alone still throws on an undeclared
  // identifier, so the plain typeof guard has to come first.
  if (!image || !fingerprint || typeof hodlLifeHash === "undefined" || typeof hodlLifeHash.fromFingerprint !== "function") return;
  // The render is asynchronous; when the same image is refilled for a new
  // fingerprint before the old one lands (Update key re-fingerprints a key),
  // only the latest request may paint.
  image.dataset.fingerprint = fingerprint;
  hodlLifeHash.fromFingerprint(fingerprint).then((url) => {
    if (!image.isConnected || image.dataset.fingerprint !== fingerprint) return;
    image.src = url;
    image.hidden = false;
  });
}
function hodlPaintKeySummary() {
  let state = hodlKeys[hodlActiveKey], fingerprint = state?.result?.masterFingerprint || "", node = document.getElementById("key-summary-fingerprint"), method = document.getElementById("key-summary-method"), script = document.getElementById("key-summary-script"), path = document.getElementById("key-summary-path"), image = document.getElementById("key-summary-lifehash"), edit = document.getElementById("key-edit-inputs");
  if (node) {
    node.textContent = fingerprint;
    node.tabIndex = -1;
  }
  if (method) method.textContent = hodlKeySummaryMethod(state);
  if (script) script.textContent = state?.createdScript || hodlKeySummaryScript(state);
  if (path) {
    path.textContent = state?.createdPath || hodlKeySummaryPath(state);
    path.hidden = !path.textContent;
  }
  if (image) {
    image.hidden = true;
    image.removeAttribute("src");
    if (fingerprint) hodlFillKeyTabLifehash(image, fingerprint);
  }
  if (edit) edit.onclick = hodlEditKeyInputs;
}
function hodlSyncKeyResultView() {
  let card = document.getElementById("calc-card"), lab = document.getElementById("key-lab"), summary = document.getElementById("key-summary"), result = hodlKeyHasResult();
  if (card) card.classList.toggle("is-result-view", result);
  if (lab) lab.hidden = result;
  if (summary) summary.hidden = !result;
  hodlPaintKeySummary();
}
function hodlRestoreFormFields(state) {
  if (!state) return;
  let privateKeys = hodlPrivateKeyValues(state.fields), restoredKeyKind = hodlNormalizePrivateKeyKind(state.fields.keyKind, privateKeys[state.fields.keyKind] || "");
  state.fields.keyKind = restoredKeyKind;
  document.querySelectorAll("input[name=kk]").forEach((input) => {
    input.checked = input.value === restoredKeyKind;
  });
  let globalSync = document.getElementById("global-entropy-sync");
  if (globalSync) globalSync.checked = Boolean(state.globalSync);
  let showNumberBaseCalculations = document.getElementById("show-number-base-calculations");
  if (showNumberBaseCalculations) showNumberBaseCalculations.checked = Boolean(state.showNumberBaseCalculations);
  let seedAutocomplete = document.getElementById("seed-autocomplete");
  if (seedAutocomplete) seedAutocomplete.checked = Boolean(state.seedAutocomplete);
  document.querySelectorAll('input[name="bo"]').forEach((radio) => {
    radio.checked = radio.value === (state.brainWalletOutput || "scalar");
  });
  hodlSyncBrainOutput();
  ["dice", "hex", "bin", "base4", "base8", "base32", "base64", "seed", "seed-numbers", "key", "cards", "direct-cards"].forEach(id => {
    let el = document.getElementById(id);
    if (el) {
      el.value = id === "dice" ? hodlDiceMethod === "dplus" ? state.fields.dplusDice || "" : hodlDiceMethod === "bitbox" ? state.fields.bitboxDice || "" : state.fields.dice || "" : id === "key" ? privateKeys[restoredKeyKind] || "" : id === "direct-cards" ? state.fields.directCards || "" : id === "seed-numbers" ? state.fields.seedNumbers || "" : state.fields[id] || "";
      if (id === "key") el.dataset.privateKeyKind = restoredKeyKind;
      if (id === "dice") {
        el.dataset.previousValue = el.value;
        el.setSelectionRange(el.value.length, el.value.length);
      }
      el.hodlRestoring = true;
      el.dispatchEvent(new Event("input"));
      delete el.hodlRestoring;
    }
  });
}
function hodlSetMode(mode) {
  hodlCaptureKey();
  let state = hodlKeys[hodlActiveKey];
  if (state) state.mode = mode;
  hodlKeyMode = mode;
  hodlSeedMethod = hodlNormalizeSeedMethod(state?.seedMethod);
  hodlSeedZeroIndexed = Boolean(state?.seedZeroIndexed);
  hodlEntropyFormat = hodlNormalizeEntropyFormat(state?.entropyFormat);
  hodlSyncKeyModeSelect();
  hodlRenderKeyForm();
  hodlRestoreFormFields(state);
  hodlUpdateSeedLengthControl();
  hodlUpdateDerivationPathPreview();
  hodlQueueSegmentedControlSync();
}
function hodlKeyStateNeedsClear(state) {
  if (!state) return false;
  let fields = state.fields || {}, privateKeys = hodlPrivateKeyValues(fields), hasText = (id) => String(fields[id] ?? "").length > 0;
  return String(state.mode ?? "dice") !== "dice" || String(state.diceMethod ?? "coldcard") !== "coldcard" || String(state.cardMethod ?? "hashed") !== "hashed" || String(state.seedMethod ?? "words") !== "words" || Boolean(state.seedZeroIndexed) || Boolean(state.cardColemanSymbols) || String(state.entropyFormat ?? "bin") !== "bin" || Boolean(state.globalSync) || state.seedAutocomplete === false || Boolean(state.passphraseBip39Words) || state.passphraseAutocomplete === false || Boolean(state.brainWalletTrim) || Boolean(state.showCards) || Boolean(state.showDiceFairness) || Number(state.targetWords ?? 24) !== 24 || Array.isArray(state.diceCoinPositions) && state.diceCoinPositions.length > 0 || String(state.lastWord ?? "").length > 0 || String(state.dplusLastWord ?? "").length > 0 || Boolean(state.result) || Boolean(state.reveal) || String(state.error ?? "").length > 0 || String(state.accountId ?? "bip84") !== "bip84" || String(fields.script ?? "bip84") !== "bip84" || String(fields.derivationPath ?? "m/84'/0'/0'/0/0") !== "m/84'/0'/0'/0/0" || String(fields.purpose ?? "84'") !== "84'" || fields.purposeHarden === false || String(fields.coinType ?? (fields.network === "testnet" ? "1'" : "0'")) !== "0'" || fields.coinTypeHarden === false || String(fields.account ?? "0'") !== "0'" || fields.accountHarden === false || String(fields.branchStart ?? "0") !== "0" || Boolean(fields.branchHarden) || String(fields.branchRange ?? "1") !== "1" || String(fields.addressStart ?? "0") !== "0" || Boolean(fields.addressHarden) || String(fields.addressRange ?? fields.count ?? "1") !== "1" || hodlNormalizePrivateKeyKind(fields.keyKind, privateKeys[fields.keyKind] || "") !== "wif" || ["pass", "dice", "bitboxDice", "dplusDice", "hex", "bin", "base4", "base8", "base32", "base64", "cards", "directCards", "seed", "seedNumbers", "brainLab", "key"].some(hasText) || hodlPrivateKeyKinds.some((kind) => privateKeys[kind].length > 0);
}
function hodlSyncKeyClearButton(capture = false) {
  if (capture) hodlCaptureKey();
  let button = document.getElementById("wipe");
  if (!button) return;
  button.disabled = !hodlKeyStateNeedsClear(hodlKeys[hodlActiveKey]);
  button.setAttribute("aria-disabled", String(button.disabled));
}
function hodlWipeActiveKey() {
  if (hodlActiveKey < 0 || !hodlKeys[hodlActiveKey]) return;
  let state = hodlKeys[hodlActiveKey];
  hodlKeys[hodlActiveKey] = state.isLab ? hodlNewLabState() : hodlNewKeyState(state.name, state.id, state.number);
  hodlRestoreKey();
  hodlJournalLog("clear", `key-${state.number}`, "calc");
}
function hodlCaptureKey() {
  if (hodlActiveKey < 0 || !hodlKeys[hodlActiveKey]) return;
  let state = hodlKeys[hodlActiveKey];
  state.mode = hodlKeyMode;
  state.diceMethod = hodlDiceMethod;
  state.cardMethod = hodlCardMethod;
  state.seedMethod = hodlSeedMethod;
  state.seedZeroIndexed = Boolean(hodlSeedZeroIndexed);
  state.cardColemanSymbols = Boolean(hodlCardColemanSymbols);
  state.entropyFormat = hodlEntropyFormat;
  let globalSync = document.getElementById("global-entropy-sync");
  if (globalSync) state.globalSync = globalSync.checked;
  let showNumberBaseCalculations = document.getElementById("show-number-base-calculations");
  if (showNumberBaseCalculations) state.showNumberBaseCalculations = showNumberBaseCalculations.checked;
  let seedAutocomplete = document.getElementById("seed-autocomplete");
  if (seedAutocomplete) state.seedAutocomplete = seedAutocomplete.checked;
  let passphraseBip39Words = document.getElementById("passphrase-bip39-words");
  if (passphraseBip39Words) state.passphraseBip39Words = passphraseBip39Words.checked;
  let passphraseAutocomplete = document.getElementById("passphrase-autocomplete");
  if (passphraseAutocomplete) state.passphraseAutocomplete = passphraseAutocomplete.checked;
  let brainWalletTrim = document.getElementById("brain-wallet-trim");
  if (brainWalletTrim) state.brainWalletTrim = brainWalletTrim.checked;
  let showCards = document.getElementById("show-cards");
  if (showCards) state.showCards = showCards.checked;
  let fairnessToggle = document.getElementById("dice-fairness-toggle");
  if (fairnessToggle) state.showDiceFairness = fairnessToggle.getAttribute("aria-expanded") === "true";
  state.targetWords = hodlTargetWordCount;
  state.diceCoinPositions = hodlDiceCoinPositions.slice();
  if (hodlDiceMethod === "dplus") state.dplusLastWord = hodlPickedLastWord;
  else if (hodlDiceMethod === "bitbox") state.lastWord = hodlPickedLastWord;
  state.result = hodlWalletResult;
  state.reveal = hodlRevealPrivate;
  state.accountId = hodlSelectedScriptType();
  state.fields.script = state.accountId;
  state.errorSpec = hodlKeyErrorSpec;
  state.error = hodlFormatErrorSpec(hodlKeyErrorSpec);
  ["pass", "derivation-path", "purpose", "account", "branch-start", "branch-range", "address-start", "address-range", "hex", "bin", "base4", "base8", "base32", "base64", "seed", "cards"].forEach((id) => {
    let el = document.getElementById(id);
    if (el) state.fields[id === "derivation-path" ? "derivationPath" : id === "branch-start" ? "branchStart" : id === "branch-range" ? "branchRange" : id === "address-start" ? "addressStart" : id === "address-range" ? "addressRange" : id] = el.value;
  });
  let directCards = document.getElementById("direct-cards");
  if (directCards) state.fields.directCards = directCards.value;
  let seedNumbers = document.getElementById("seed-numbers");
  if (seedNumbers) state.fields.seedNumbers = seedNumbers.value;
  if (document.querySelector('input[name="bo"]')) state.brainWalletOutput = hodlBrainWalletOutput();
  state.fields.coinType = document.getElementById("network")?.value || "0";
  state.fields.derivationAccountPath = document.getElementById("derivation-path")?.dataset.accountPath || state.fields.derivationAccountPath || "m/84'/0'/0'";
  let hardening = hodlReadHardening();
  state.fields.purposeHarden = hardening.purpose;
  state.fields.coinTypeHarden = hardening.coinType;
  state.fields.accountHarden = hardening.account;
  state.fields.branchHarden = hardening.branch;
  state.fields.addressHarden = hardening.address;
  try {
    state.fields.network = hodlSelectedNetwork(document.getElementById("network"));
  } catch {
  }
  let dice = document.getElementById("dice");
  if (dice) state.fields[hodlDiceMethod === "dplus" ? "dplusDice" : hodlDiceMethod === "bitbox" ? "bitboxDice" : "dice"] = dice.value;
  let key = document.getElementById("key"), privateKeys = hodlPrivateKeyValues(state.fields), checkedKeyKind = document.querySelector("input[name=kk]:checked")?.value || state.fields.keyKind, keyKind = hodlNormalizePrivateKeyKind(key?.dataset.privateKeyKind || checkedKeyKind, key?.value || "");
  if (key) privateKeys[keyKind] = key.value;
  state.fields.keyKind = keyKind;
  state.fields.key = "";
}
function hodlSyncSelect(select, value) {
  if (!select) return;
  select.value = value;
  select.dispatchEvent(new Event("entropylab:sync-select"));
}
function hodlSelectedNetwork(select) {
  return hodlNetworkFromCoinType(hodlReadCoinType(select, false));
}
function hodlSelectedKeyNetwork() {
  return hodlSelectedNetwork(document.getElementById("network"));
}
function hodlRestoreKey() {
  let state = hodlKeys[hodlActiveKey];
  if (!state) {
    hodlKeyMode = "dice";
    hodlDiceMethod = "coldcard";
    hodlCardMethod = "hashed";
    hodlSeedMethod = "words";
    hodlSeedZeroIndexed = false;
    hodlCardColemanSymbols = false;
    hodlEntropyFormat = "bin";
    hodlTargetWordCount = 24;
    hodlDiceCoinPositions = [];
    hodlPickedLastWord = "";
    hodlWalletResult = null;
    hodlRevealPrivate = false;
    hodlAccountId = "bip84";
    hodlSyncKeyModeSelect();
    hodlRenderKeyForm();
    let pass2 = document.getElementById("pass");
    if (pass2) {
      pass2.value = "";
      hodlRenderPassphraseInputState(pass2, false);
    }
    hodlSyncSelect(document.getElementById("script-type"), "bip84");
    hodlSetPurpose(84);
    let network2 = document.getElementById("network");
    if (network2) network2.value = String(hodlDefaultCoinType());
    hodlUpdateCoinTypeHelp(network2);
    let account2 = document.getElementById("account");
    if (account2) account2.value = "0";
    let derivationPath2 = document.getElementById("derivation-path");
    if (derivationPath2) {
      derivationPath2.value = `m/84'/${hodlDefaultCoinType()}'/0'/0/0`;
      derivationPath2.dataset.accountPath = `m/84'/${hodlDefaultCoinType()}'/0'`;
    }
    let branchStart2 = document.getElementById("branch-start"), branchRange2 = document.getElementById("branch-range"), addressStart2 = document.getElementById("address-start"), addressRange2 = document.getElementById("address-range");
    if (branchStart2) branchStart2.value = "0";
    if (branchRange2) branchRange2.value = "1";
    if (addressStart2) addressStart2.value = "0";
    if (addressRange2) addressRange2.value = "1";
    hodlSetHardeningControls();
    hodlUpdateVisibleDerivationPathFromAdvanced();
    hodlUpdateHardeningHelp();
    hodlUpdateAddressEstimate();
    hodlSetWorkspaceError("key", null);
    hodlOutEl.innerHTML = "";
    document.getElementById("calc-card").hidden = true;
    hodlSyncKeyResultView();
    hodlQueueMasterFingerprintPreview(0);
    hodlUpdateDerivationPathPreview();
    hodlSyncKeyClearButton();
    hodlSyncDeriveButton();
    return;
  }
  hodlKeyMode = state.mode;
  hodlDiceMethod = state.diceMethod;
  hodlCardMethod = state.cardMethod === "direct" ? "direct" : "hashed";
  hodlSeedMethod = hodlNormalizeSeedMethod(state.seedMethod);
  hodlSeedZeroIndexed = Boolean(state.seedZeroIndexed);
  hodlCardColemanSymbols = Boolean(state.cardColemanSymbols);
  hodlEntropyFormat = hodlNormalizeEntropyFormat(state.entropyFormat);
  hodlTargetWordCount = hodlSeedLengths[Number(state.targetWords)] ? Number(state.targetWords) : 24;
  hodlDiceCoinPositions = hodlNormalizeDiceCoinPositions(state.diceCoinPositions);
  hodlPickedLastWord = hodlDiceMethod === "dplus" ? state.dplusLastWord || "" : hodlDiceMethod === "bitbox" ? state.lastWord || "" : "";
  hodlSyncKeyModeSelect();
  hodlRenderKeyForm();
  let pass = document.getElementById("pass");
  if (pass) {
    pass.value = state.fields.pass || "";
    hodlRenderPassphraseInputState(pass, Boolean(state.passphraseBip39Words));
  }
  hodlAccountId = state.accountId || state.fields.script || "bip84";
  hodlSyncSelect(document.getElementById("script-type"), hodlAccountId);
  state.fields.coinType = String(state.fields.coinType ?? (state.fields.network === "testnet" ? "1'" : "0'"));
  let purpose = document.getElementById("purpose");
  if (purpose) purpose.value = state.fields.purpose ?? `${hodlScriptDefinition(hodlAccountId).purpose}'`;
  let network = document.getElementById("network");
  if (network) network.value = state.fields.coinType;
  hodlUpdateCoinTypeHelp(network);
  let account = document.getElementById("account");
  if (account) account.value = state.fields.account ?? "0'";
  let derivationPath = document.getElementById("derivation-path");
  if (derivationPath) {
    derivationPath.value = state.fields.derivationPath ?? "m/84'/0'/0'/0/0";
    derivationPath.dataset.accountPath = state.fields.derivationAccountPath ?? "m/84'/0'/0'";
  }
  let branchStart = document.getElementById("branch-start"), branchRange = document.getElementById("branch-range"), addressStart = document.getElementById("address-start"), addressRange = document.getElementById("address-range");
  if (branchStart) branchStart.value = state.fields.branchStart ?? "0";
  if (branchRange) branchRange.value = state.fields.branchRange ?? "1";
  if (addressStart) addressStart.value = state.fields.addressStart ?? "0";
  if (addressRange) addressRange.value = state.fields.addressRange ?? state.fields.count ?? "1";
  hodlSetHardeningControls("", hodlHardeningFromFields(state.fields));
  hodlUpdateVisibleDerivationPathFromAdvanced();
  hodlUpdateHardeningHelp();
  hodlUpdateAddressEstimate();
  hodlRestoreFormFields(state);
  hodlWalletResult = state.result;
  hodlRevealPrivate = state.reveal;
  document.getElementById("calc-card").hidden = false;
  hodlSetWorkspaceError("key", state.errorSpec || (state.error ? { raw: state.error } : null));
  hodlRefreshKeyResult();
  hodlSyncKeyResultView();
  hodlQueueMasterFingerprintPreview(0);
  hodlUpdateDerivationPathPreview();
  hodlSyncKeyClearButton();
  hodlSyncDeriveButton();
}
function hodlKeyTabKeydown(event, index) {
  if (event.key === "F2") {
    if (hodlKeys[index]?.isLab) return;
    event.preventDefault();
    if (index === hodlActiveKey) hodlBeginKeyRename(index);
    return;
  }
  let next = null, length = hodlKeys.length;
  if (event.key === "ArrowRight") next = (index + 1) % length;
  else if (event.key === "ArrowLeft") next = (index - 1 + length) % length;
  else if (event.key === "Home") next = 0;
  else if (event.key === "End") next = length - 1;
  if (next === null) return;
  event.preventDefault();
  hodlSelectKey(next);
  hodlElement("#key-tabs").children[next]?.focus();
}
var hodlKeySilhouette = "M512 176c0 97.2-78.8 176-176 176-11.2 0-22.2-1.1-32.8-3.1l-24 27c-4.4 4.9-10.8 8.1-17.9 8.1H224v40c0 13.3-10.7 24-24 24h-40v40c0 13.3-10.7 24-24 24H24c-13.3 0-24-10.7-24-24v-78.1c0-6.4 2.5-12.5 7-17l161.8-161.8c-5.7-17.4-8.8-35.9-8.8-55.2C160 78.8 238.8 0 336 0s176 78.8 176 176zM374 112a54 54 0 1 0 0 108 54 54 0 1 0 0-108z";
function hodlCreateMsigIcon(monochrome = false) {
  let ns = "http://www.w3.org/2000/svg", darkest = monochrome ? "currentColor" : "#4b4f55", middle = monochrome ? "currentColor" : "#888d94", span = document.createElement("span"), svg = document.createElementNS(ns, "svg"), assembly = document.createElementNS(ns, "g"), keys = document.createElementNS(ns, "g");
  span.className = "multisig-tab-icon" + (monochrome ? " bench-tab-icon" : "");
  span.setAttribute("aria-hidden", "true");
  svg.setAttribute("viewBox", monochrome ? "0 0 21 24" : "0 -4 49 40");
  svg.setAttribute("focusable", "false");
  svg.setAttribute("aria-hidden", "true");
  svg.setAttribute("data-keyhole-cx", "34");
  svg.setAttribute("data-keyhole-cy", "10.5");
  svg.setAttribute("data-keyhole-r", "2.808");
  if (monochrome) assembly.setAttribute("transform", "translate(-1.8 4.65) scale(.431)");
  keys.setAttribute("data-part", "key-cluster");
  let ring = document.createElementNS(ns, "path");
  ring.setAttribute("data-part", "keychain-ring");
  ring.setAttribute("d", "M32.14 7.53 A7.78 7.78 0 1 1 36.97 12.36");
  ring.setAttribute("fill", "none");
  ring.setAttribute("stroke", middle);
  ring.setAttribute("stroke-width", "1.7");
  ring.setAttribute("stroke-linecap", "round");
  ring.setAttribute("stroke-linejoin", "round");
  assembly.appendChild(ring);
  [["key-back", darkest, -28, monochrome ? ".52" : "1"], ["key-middle", middle, 0, monochrome ? ".76" : "1"], ["key-front", monochrome ? "currentColor" : "#d1d4d8", 28, "1"]].forEach(([part, fill, angle, opacity]) => {
    let path = document.createElementNS(ns, "path");
    path.setAttribute("data-part", part);
    path.setAttribute("d", hodlKeySilhouette);
    path.setAttribute("fill", fill);
    path.setAttribute("fill-rule", "evenodd");
    path.setAttribute("clip-rule", "evenodd");
    path.setAttribute("opacity", opacity);
    path.setAttribute("transform", "translate(34 10.5) rotate(" + angle + ") scale(.052) translate(-374 -166)");
    keys.appendChild(path);
  });
  assembly.appendChild(keys);
  let thread = document.createElementNS(ns, "path");
  thread.setAttribute("data-part", "keychain-thread");
  thread.setAttribute("d", "M36.97 12.36 A7.78 7.78 0 0 0 45 10.5");
  thread.setAttribute("fill", "none");
  thread.setAttribute("stroke", middle);
  thread.setAttribute("stroke-width", "1.7");
  thread.setAttribute("stroke-linecap", "round");
  thread.setAttribute("stroke-linejoin", "round");
  assembly.appendChild(thread);
  svg.appendChild(assembly);
  span.appendChild(svg);
  return span;
}
function hodlCreateLabIcon() {
  let ns = "http://www.w3.org/2000/svg", span = document.createElement("span"), svg = document.createElementNS(ns, "svg"), path = document.createElementNS(ns, "path");
  span.className = "key-tab-icon key-tab-lab-icon bench-tab-icon";
  span.setAttribute("aria-hidden", "true");
  svg.setAttribute("viewBox", "0 0 512 512");
  svg.setAttribute("fill", "currentColor");
  svg.setAttribute("focusable", "false");
  svg.setAttribute("aria-hidden", "true");
  path.setAttribute("fill-rule", "evenodd");
  path.setAttribute("clip-rule", "evenodd");
  path.setAttribute("d", hodlKeySilhouette);
  svg.appendChild(path);
  span.appendChild(svg);
  return span;
}
function hodlCreateBip85BenchIcon() {
  let ns = "http://www.w3.org/2000/svg", span = document.createElement("span"), svg = document.createElementNS(ns, "svg");
  span.className = "key-tab-icon key-tab-lab-icon bip85-bench-icon bench-tab-icon";
  span.setAttribute("aria-hidden", "true");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("fill", "currentColor");
  svg.setAttribute("focusable", "false");
  svg.setAttribute("aria-hidden", "true");
  [
    ["seed", "M12 1.75c1.78 0 3.22 1.5 3.22 3.35S13.78 8.45 12 8.45 8.78 6.95 8.78 5.1 10.22 1.75 12 1.75Z"],
    ["left-leaf", "M10.92 21.75C5.47 20.99 2.25 17.03 2.25 9.2c5.48.85 8.67 4.89 8.67 12.55Z"],
    ["right-leaf", "M13.08 21.75c5.45-.76 8.67-4.72 8.67-12.55-5.48.85-8.67 4.89-8.67 12.55Z"]
  ].forEach(([part, data]) => {
    let path = document.createElementNS(ns, "path");
    path.setAttribute("data-part", part);
    path.setAttribute("d", data);
    svg.appendChild(path);
  });
  span.appendChild(svg);
  return span;
}
function hodlCreateSilentPaymentsIcon() {
  let ns = "http://www.w3.org/2000/svg", span = document.createElement("span"), svg = document.createElementNS(ns, "svg");
  span.className = "key-tab-icon key-tab-lab-icon silent-payments-icon bench-tab-icon";
  span.setAttribute("aria-hidden", "true");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("fill", "none");
  svg.setAttribute("focusable", "false");
  svg.setAttribute("aria-hidden", "true");
  let coin = document.createElementNS(ns, "g");
  coin.setAttribute("data-part", "coin");
  coin.setAttribute("transform", "rotate(14 8 14.5)");
  let rim = document.createElementNS(ns, "path");
  rim.setAttribute("data-part", "coin-rim");
  rim.setAttribute("d", "M1.85 14.4v1.65c0 2.4 2.75 4.35 6.15 4.35s6.15-1.95 6.15-4.35V14.4c0 2.4-2.75 4.35-6.15 4.35S1.85 16.8 1.85 14.4Z");
  rim.setAttribute("fill", "currentColor");
  rim.setAttribute("fill-opacity", ".45");
  rim.setAttribute("stroke", "currentColor");
  rim.setAttribute("stroke-width", "1.1");
  coin.appendChild(rim);
  ["M3.35 17.3v1.25", "M5.45 18.15v1.4", "M7.8 18.45v1.45", "M10.15 18.15v1.35", "M12.2 17.3v1.15"].forEach((data) => {
    let ridge = document.createElementNS(ns, "path");
    ridge.setAttribute("data-part", "coin-ridge");
    ridge.setAttribute("d", data);
    ridge.setAttribute("stroke", "currentColor");
    ridge.setAttribute("stroke-width", ".8");
    ridge.setAttribute("stroke-linecap", "round");
    coin.appendChild(ridge);
  });
  let face = document.createElementNS(ns, "ellipse");
  face.setAttribute("cx", "8");
  face.setAttribute("cy", "14.4");
  face.setAttribute("rx", "6.15");
  face.setAttribute("ry", "4.2");
  face.setAttribute("fill", "currentColor");
  face.setAttribute("stroke", "currentColor");
  face.setAttribute("stroke-width", "1.25");
  coin.appendChild(face);
  svg.appendChild(coin);
  [["signal-inner", "M14.25 9.15a4.65 4.65 0 0 1 3.55 3.6"], ["signal-outer", "M14.7 4.25a9.2 9.2 0 0 1 7.05 7.2"]].forEach(([part, data]) => {
    let path = document.createElementNS(ns, "path");
    path.setAttribute("data-part", part);
    path.setAttribute("d", data);
    path.setAttribute("stroke", "currentColor");
    path.setAttribute("stroke-width", "1.8");
    path.setAttribute("stroke-linecap", "round");
    svg.appendChild(path);
  });
  span.appendChild(svg);
  return span;
}
function hodlCreateKeyTab(index) {
  let state = hodlKeys[index], active = index === hodlActiveKey, button = document.createElement("button"), fingerprint = state.result?.masterFingerprint || "", name = state.isLab ? "Key Station" : state.name || fingerprint || hodlT("Key {n}", { n: state.number }), label = document.createElement("span");
  button.type = "button";
  button.id = state.isLab ? "key-tab-lab" : "key-tab-" + (index + 1);
  button.className = "tab key-tab" + (state.isLab ? " is-lab" : "") + (active ? " active" : "");
  button.style.setProperty("--key-color", state.color);
  label.className = "key-tab-label";
  label.textContent = name;
  if (state.isLab) button.append(hodlCreateLabIcon(), label);
  else if (fingerprint) {
    let image = document.createElement("img");
    image.className = "key-tab-lifehash";
    image.width = 22;
    image.height = 22;
    image.alt = "";
    image.hidden = true;
    hodlFillKeyTabLifehash(image, fingerprint);
    button.append(image, label);
  } else button.append(label);
  button.dataset.keyNumber = String(state.number);
  button.setAttribute("role", "tab");
  button.setAttribute("aria-controls", "calc-card");
  button.setAttribute("aria-selected", String(active));
  if (state.isLab) {
    button.setAttribute("aria-label", "Key Station" + (active ? ", selected" : ". Activate to derive a key."));
    button.title = "Derive a key";
    button.onclick = () => hodlSelectKey(index);
  } else {
    button.setAttribute("aria-label", name + (active ? ", selected. Activate or press F2 to rename." : ". Activate to select."));
    button.title = active ? "Click again or press F2 to rename" : "Click to select";
    button.onclick = () => index === hodlActiveKey ? hodlBeginKeyRename(index) : hodlSelectKey(index);
  }
  button.tabIndex = active ? 0 : -1;
  button.onkeydown = (event) => hodlKeyTabKeydown(event, index);
  return button;
}
function hodlSizeKeyTabEditor(input) {
  input.style.width = "1px";
  input.style.width = Math.max(72, input.scrollWidth + 2) + "px";
}
function hodlNormalizeKeyName(name) {
  return String(name || "").trim().replace(/\s+/g, " ").toLowerCase();
}
function hodlKeyNameTaken(name, index) {
  let normalized = hodlNormalizeKeyName(name);
  return !!normalized && hodlKeys.some((state, stateIndex) => stateIndex !== index && hodlNormalizeKeyName(state.name) === normalized);
}
function hodlDefaultKeyName(number) {
  let base = hodlT("Key {n}", { n: number }), name = base, suffix = 2;
  while (hodlKeyNameTaken(name, -1)) {
    name = hodlT("Key {n} ({suffix})", { n: number, suffix });
    suffix++;
  }
  return name;
}
function hodlBeginKeyRename(index) {
  if (index !== hodlActiveKey || !hodlKeys[index] || hodlKeys[index].isLab) return;
  let box = hodlElement("#key-tabs"), tab = box.children[index];
  if (!tab || tab.classList.contains("key-tab-editing")) return;
  let state = hodlKeys[index], editor = document.createElement("div"), input = document.createElement("input"), previous = state.name || hodlT("Key {n}", { n: state.number });
  editor.id = "key-tab-" + (index + 1);
  editor.className = "key-tab key-tab-editing active";
  editor.style.setProperty("--key-color", state.color);
  editor.dataset.keyNumber = String(state.number);
  editor.setAttribute("role", "tab");
  editor.setAttribute("aria-selected", "true");
  editor.setAttribute("aria-controls", "calc-card");
  input.type = "text";
  input.className = "key-tab-name-input";
  input.value = previous;
  input.maxLength = 120;
  input.setAttribute("aria-label", "Rename " + previous);
  input.setAttribute("aria-controls", "calc-card");
  let finish = (commit, focus) => {
    if (!editor.isConnected) return;
    let name = input.value.trim().replace(/\s+/g, " ");
    let renamed = commit && name && name !== previous && !hodlKeyNameTaken(name, index);
    if (renamed) {
      state.name = name;
      hodlJournalLog("station-rename", `key-${state.number}`, "calc");
    }
    let button = hodlCreateKeyTab(index);
    editor.replaceWith(button);
    if (focus) button.focus();
  };
  input.oninput = () => hodlSizeKeyTabEditor(input);
  input.onkeydown = (event) => {
    if (event.key === "Enter") {
      event.preventDefault();
      finish(true, true);
    } else if (event.key === "Escape") {
      event.preventDefault();
      finish(false, true);
    }
  };
  input.onblur = () => finish(true, false);
  let lifehash = tab.querySelector(".key-tab-lifehash");
  if (lifehash) editor.append(lifehash.cloneNode(true), input);
  else editor.append(input);
  tab.replaceWith(editor);
  hodlSizeKeyTabEditor(input);
  input.focus();
  input.select();
}
function hodlRevealTab(box, index) {
  let tab = box.children[index];
  if (!tab) return;
  let start = tab.offsetLeft, end = start + tab.offsetWidth, left = box.scrollLeft, right = left + box.clientWidth, target = left;
  if (start < left) target = start;
  else if (end > right) target = end - box.clientWidth;
  if (target !== left) box.scrollTo({ left: target, behavior: "smooth" });
}
function hodlSyncKeyDeleteButton() {
  let button = hodlElement("#delete-key"), state = hodlKeys[hodlActiveKey];
  if (!button) return;
  button.disabled = !state || state.isLab;
  button.setAttribute("aria-disabled", String(button.disabled));
}
function hodlRenderKeyTabs() {
  let box = hodlElement("#key-tabs"), panel = hodlElement("#calc-card");
  box.innerHTML = "";
  panel.removeAttribute("aria-labelledby");
  box.setAttribute("role", "tablist");
  hodlKeys.forEach((state, index) => {
    let button = hodlCreateKeyTab(index);
    box.appendChild(button);
    if (index === hodlActiveKey) panel.setAttribute("aria-labelledby", button.id);
  });
  hodlRevealTab(box, hodlActiveKey);
  hodlSyncKeyDeleteButton();
  hodlRefreshMsigSessionPickers();
  hodlRefreshStationKeyPickers();
  hodlRefreshJournalKeyPicker();
}
function hodlSelectKey(index) {
  if (index === hodlActiveKey || !hodlKeys[index]) return;
  hodlCaptureKey();
  hodlActiveKey = index;
  hodlRenderKeyTabs();
  hodlRestoreKey();
  hodlJournalLog("station-select", `key-${hodlKeys[index].number}`, "calc");
}
function hodlAddKey() {
  hodlSelectLab();
}
function hodlDeleteActiveKey() {
  let state = hodlKeys[hodlActiveKey];
  if (!state || state.isLab) {
    hodlSyncKeyDeleteButton();
    return;
  }
  if (hodlJournalUnlocked()) {
    hodlKeyManagerDetachFromStation(state);
    return;
  }
  let deletedIndex = hodlActiveKey, deletedState = state;
  hodlKeys.splice(deletedIndex, 1);
  hodlNextKeyNumber = hodlKeys.length ? hodlKeys.reduce((latest, state) => Math.max(latest, state.number), 0) + 1 : deletedState.number;
  if (!hodlKeys.length) {
    hodlKeys.push(hodlNewLabState());
    hodlActiveKey = 0;
  } else hodlActiveKey = Math.min(deletedIndex, hodlKeys.length - 1);
  hodlRenderKeyTabs();
  hodlRestoreKey();
  hodlJournalLog("station-delete", `key-${deletedState.number}`, "calc");
  (hodlActiveKey >= 0 ? hodlElement("#key-tabs").children[hodlActiveKey] : hodlElement("#add-key"))?.focus();
}
var hodlNextMsigId = 1, hodlNextMsigNumber = 1, hodlMsigs = [], hodlActiveMsig = -1;
function hodlNewMsigState(name, msigId, msigNumber) {
  let id = msigId ?? hodlNextMsigId++,
    number = msigNumber ?? hodlNextMsigNumber++;
  return {
    id,
    number,
    name: name || hodlDefaultMsigName(number),
    result: null,
    error: "",
    fields: {
      m: "2",
      n: "3",
      script: "p2wsh",
      purpose: "48",
      purposeHarden: true,
      legacyBip87: !1,
      keyOrder: "sorted",
      reuseSessionKeys: false,
      xpubs: ["", "", ""],
      coinType: String(hodlDefaultCoinType()),
      coinTypeHarden: true,
      network: hodlNetworkDefault,
      accountHarden: true,
      branchStart: "0",
      branchHarden: false,
      branchRange: "2",
      addressStart: "0",
      addressHarden: false,
      addressRange: "5"
    }
  }
}
function hodlNewMsigLabState() {
  let state = hodlNewMsigState("MS Station", 0, 0);
  state.isLab = true;
  return state;
}
function hodlMsigScriptLabel(kind) {
  if (kind === "p2sh") return "Legacy";
  if (kind === "p2sh-p2wsh") return "Nested SegWit";
  if (kind === "p2wsh") return "Native SegWit";
  if (kind === "p2tr") return "Taproot";
  return kind || "";
}
function hodlMsigPolicyName(result) {
  if (!result) return "";
  return `${result.m}-of-${result.n}`;
}
function hodlSnapshotMsigSummary(state = hodlMsigs[hodlActiveMsig]) {
  if (!state?.result || state.result.kind !== "msig") return;
  state.createdPolicy = hodlMsigPolicyName(state.result);
  state.createdScript = hodlMsigScriptLabel(state.result.script);
  state.createdNetwork = state.result.network || "";
}
function hodlMsigHasResult(state = hodlMsigs[hodlActiveMsig]) {
  return Boolean(state && !state.isLab && state.result?.kind === "msig");
}
function hodlPaintMsigSummary() {
  let state = hodlMsigs[hodlActiveMsig], policy = document.getElementById("msig-summary-policy"), script = document.getElementById("msig-summary-script"), network = document.getElementById("msig-summary-network"), edit = document.getElementById("msig-edit-inputs");
  if (policy) {
    policy.textContent = state?.createdPolicy || hodlMsigPolicyName(state?.result);
    policy.tabIndex = -1;
  }
  if (script) script.textContent = state?.createdScript || hodlMsigScriptLabel(state?.result?.script);
  if (network) network.textContent = state?.createdNetwork || state?.result?.network || "";
  if (edit) edit.onclick = hodlEditMsigInputs;
}
function hodlSyncMsigResultView() {
  let card = document.getElementById("msig-card"), lab = document.getElementById("msig-lab"), summary = document.getElementById("msig-summary"), result = hodlMsigHasResult();
  if (card) card.classList.toggle("is-result-view", result);
  if (lab) lab.hidden = result;
  if (summary) summary.hidden = !result;
  hodlPaintMsigSummary();
}
function hodlCloneDerivedMsig(source, existing) {
  let state = existing ? { ...existing, fields: { ...existing.fields, xpubs: (existing.fields.xpubs || []).slice() } } : hodlNewMsigState();
  let name = source.createdPolicy || hodlMsigPolicyName(source.result) || state.name;
  Object.assign(state, {
    isLab: false,
    name,
    result: source.result,
    error: source.error,
    createdPolicy: source.createdPolicy,
    createdScript: source.createdScript,
    createdNetwork: source.createdNetwork,
    fields: { ...source.fields, xpubs: (source.fields.xpubs || []).slice() }
  });
  let skip = existing ? hodlMsigs.indexOf(existing) : -1;
  if (hodlMsigNameTaken(state.name, skip)) state.name = hodlUniqueMsigName(state.name, skip);
  return state;
}
function hodlUniqueMsigName(base, index) {
  let name = base, suffix = 2;
  while (hodlMsigNameTaken(name, index)) {
    name = base + " (" + suffix + ")";
    suffix++;
  }
  return name;
}
function hodlMsigIdentity(state) {
  let fields = state?.fields || {};
  return [fields.m, fields.n, fields.script, ...(Array.isArray(fields.xpubs) ? fields.xpubs : [])].join("|");
}
function hodlCommitDerivedMsig() {
  let lab = hodlMsigs[hodlActiveMsig];
  if (!lab?.isLab || !lab.result || lab.result.kind !== "msig") {
    hodlRenderMsigTabs();
    hodlRestoreMsig();
    return hodlActiveMsig;
  }
  let identity = hodlMsigIdentity(lab);
  let existing = hodlMsigs.findIndex((state) => !state.isLab && hodlMsigIdentity(state) === identity);
  if (existing >= 0) {
    hodlMsigs[existing] = hodlCloneDerivedMsig(lab, hodlMsigs[existing]);
    hodlMsigs[hodlActiveMsig] = hodlNewMsigLabState();
    hodlActiveMsig = existing;
  } else {
    let derived = hodlCloneDerivedMsig(lab);
    hodlMsigs[hodlActiveMsig] = hodlNewMsigLabState();
    hodlMsigs.push(derived);
    hodlActiveMsig = hodlMsigs.length - 1;
  }
  hodlRenderMsigTabs();
  hodlRestoreMsig();
  return hodlActiveMsig;
}
function hodlSelectMsigLab() {
  let lab = hodlMsigs.findIndex((state) => state.isLab);
  if (lab < 0) {
    hodlCaptureMsig();
    hodlMsigs.unshift(hodlNewMsigLabState());
    lab = 0;
    if (hodlActiveMsig >= 0) hodlActiveMsig += 1;
  }
  if (lab === hodlActiveMsig) return;
  hodlSelectMsig(lab);
}
function hodlFillMsigLabFromWallet(source) {
  let labIndex = hodlMsigs.findIndex((state) => state.isLab);
  let existing = labIndex >= 0 ? hodlMsigs[labIndex] : hodlNewMsigLabState();
  let lab = hodlCloneDerivedMsig(source, existing);
  Object.assign(lab, { isLab: true, name: "MS Station", result: null, error: "", createdPolicy: "", createdScript: "", createdNetwork: "" });
  if (labIndex < 0) {
    hodlMsigs.unshift(lab);
    labIndex = 0;
    if (hodlActiveMsig >= 0) hodlActiveMsig += 1;
  } else hodlMsigs[labIndex] = lab;
  return labIndex;
}
function hodlEditMsigInputs() {
  let source = hodlMsigs[hodlActiveMsig];
  if (!source || source.isLab) {
    hodlSelectMsigLab();
    return;
  }
  hodlCaptureMsig();
  hodlSelectMsig(hodlFillMsigLabFromWallet(hodlMsigs[hodlActiveMsig]));
}
function hodlMsigStateNeedsClear(state) {
  if (!state) return !1;
  let fields = state.fields || {},
    xpubs = Array.isArray(fields.xpubs) ? fields.xpubs : [];
  return Boolean(state.result) || String(state.error ?? "").length > 0 || xpubs.some(value => String(value ?? "").length > 0) ||
    String(fields.m ?? "2") !== "2" || String(fields.n ?? "3") !== "3" || String(fields.script ?? "p2wsh") !== "p2wsh" || String(fields.purpose ?? "48") !== "48" || fields.purposeHarden === false || Boolean(fields.legacyBip87) || String(fields.keyOrder ?? "sorted") !== "sorted" || Boolean(fields.reuseSessionKeys) || String(fields.coinType ?? (fields.network === "testnet" ? "1" : "0")) !== "0" || fields.coinTypeHarden === false || fields.accountHarden === false || String(fields.branchStart ?? "0") !== "0" || Boolean(fields.branchHarden) || String(fields.branchRange ?? "2") !== "2" || String(fields.addressStart ?? "0") !== "0" || Boolean(fields.addressHarden) || String(fields.addressRange ?? fields.count ?? "5") !== "5"
}

function hodlSyncMsigClearButton(capture = !1) {
  if (capture) hodlCaptureMsig();
  let button = document.getElementById("msig-wipe");
  if (!button) return;
  button.disabled = !hodlMsigStateNeedsClear(hodlMsigs[hodlActiveMsig]);
  button.setAttribute("aria-disabled", String(button.disabled));
}
function hodlCaptureMsig() {
  if (hodlActiveMsig < 0 || !hodlMsigs[hodlActiveMsig]) return;
  let state = hodlMsigs[hodlActiveMsig];
  state.fields.n = document.getElementById("msig-n").value || "3";
  state.fields.m = document.getElementById("msig-m").value || "2";
  state.fields.script = hodlScriptKind();
  state.fields.purpose = document.getElementById("msig-purpose")?.value || "48";
  state.fields.legacyBip87 = hodlSelectedLegacyMultisigStandard() === "bip87";
  state.fields.keyOrder = hodlMsigKeysSorted() ? "sorted" : "listed";
  state.fields.reuseSessionKeys = Boolean(document.getElementById("msig-reuse-session-keys")?.checked);
  hodlMergeMsigXpubs(state);
  state.fields.coinType = document.getElementById("msig-network")?.value || "0";
  let hardening = hodlReadHardening("msig-");
  state.fields.purposeHarden = hardening.purpose;
  state.fields.coinTypeHarden = hardening.coinType;
  state.fields.accountHarden = hardening.account;
  state.fields.branchHarden = hardening.branch;
  state.fields.addressHarden = hardening.address;
  try {
    state.fields.network = hodlSelectedNetwork(document.getElementById("msig-network"));
  } catch {
  }
  state.fields.addressStart = document.getElementById("msig-address-start")?.value ?? "0";
  state.fields.addressRange = document.getElementById("msig-address-range")?.value ?? "5";
  state.fields.branchStart = document.getElementById("msig-branch-start")?.value ?? "0";
  state.fields.branchRange = document.getElementById("msig-branch-range")?.value ?? "2";
  state.result = hodlWalletResult && hodlWalletResult.kind === "msig" ? hodlWalletResult : null;
  state.errorSpec = hodlMsigErrorSpec;
  state.error = hodlFormatErrorSpec(hodlMsigErrorSpec);
}
function hodlRestoreMsig() {
  let state = hodlMsigs[hodlActiveMsig], panel = document.getElementById("msig-card");
  if (!state) {
    hodlWalletResult = null;
    hodlRevealPrivate = false;
    hodlResetMsigForm();
    hodlClearMsigOut();
    panel.hidden = true;
    hodlSyncMsigResultView();
    hodlSyncMsigClearButton();
    return;
  }
  hodlSetMsigThresholds(state.fields.m || "2", state.fields.n || "3");
  let legacy = document.getElementById("msig-legacy-bip87");
  hodlSyncSelect(document.getElementById("msig-script-type"), state.fields.script || "p2wsh");
  hodlSetMsigPurpose(state.fields.purpose ?? (state.fields.legacyBip87 ? 87 : hodlStandardMsigPurpose(state.fields.script || "p2wsh")));
  if (legacy) legacy.checked = hodlReadMsigPurpose(false) === 87;
  hodlUpdateMsigLegacyControls();
  state.fields.keyOrder = state.fields.keyOrder === "listed" ? "listed" : "sorted";
  hodlSyncSelect(document.getElementById("msig-key-order"), state.fields.keyOrder);
  let reuseSessionKeys = document.getElementById("msig-reuse-session-keys"), sessionStatus = document.getElementById("msig-session-key-status");
  if (reuseSessionKeys) reuseSessionKeys.checked = Boolean(state.fields.reuseSessionKeys);
  if (sessionStatus) sessionStatus.textContent = "";
  hodlMsigKeyTarget = null;
  let advanced = document.getElementById("msig-advanced");
  if (advanced) advanced.open = state.fields.keyOrder === "listed";
  state.fields.coinType = String(state.fields.coinType ?? (state.fields.network === "testnet" ? 1 : 0));
  let coinType = document.getElementById("msig-network");
  if (coinType) coinType.value = state.fields.coinType;
  state.fields.network = hodlNetworkFromCoinType(state.fields.coinType);
  hodlUpdateCoinTypeHelp(coinType, document.getElementById("msig-network-help"));
  let branchStart = document.getElementById("msig-branch-start"), branchRange = document.getElementById("msig-branch-range"), addressStart = document.getElementById("msig-address-start"), addressRange = document.getElementById("msig-address-range");
  if (branchStart) branchStart.value = state.fields.branchStart ?? "0";
  if (branchRange) branchRange.value = state.fields.branchRange ?? "2";
  if (addressStart) addressStart.value = state.fields.addressStart ?? "0";
  if (addressRange) addressRange.value = state.fields.addressRange ?? state.fields.count ?? "5";
  hodlSetHardeningControls("msig-", hodlHardeningFromFields(state.fields));
  hodlUpdateHardeningHelp("msig-");
  hodlUpdateAddressEstimate("msig-");
  hodlFillKeys(state.fields.xpubs || []);
  hodlSetWorkspaceError("msig", state.errorSpec || (state.error ? { raw: state.error } : null));
  hodlWalletResult = state.result;
  hodlRevealPrivate = false;
  panel.hidden = false;
  if (hodlWalletResult && hodlWalletResult.kind === "msig") hodlShowMsig();
  else hodlClearMsigOut();
  hodlSyncMsigResultView();
  hodlSyncMsigClearButton();
}
function hodlWipeActiveMsig() {
  if (hodlActiveMsig < 0 || !hodlMsigs[hodlActiveMsig]) return;
  let state = hodlMsigs[hodlActiveMsig];
  hodlMsigs[hodlActiveMsig] = state.isLab ? hodlNewMsigLabState() : hodlNewMsigState(state.name, state.id, state.number);
  hodlRestoreMsig();
  hodlJournalLog("clear", `multisig-${state.number}`, "msig");
}
function hodlMsigTabKeydown(event, index) {
  if (event.key === "F2") {
    if (hodlMsigs[index]?.isLab) return;
    event.preventDefault();
    if (index === hodlActiveMsig) hodlBeginMsigRename(index);
    return;
  }
  let next = null, length = hodlMsigs.length;
  if (event.key === "ArrowRight") next = (index + 1) % length;
  else if (event.key === "ArrowLeft") next = (index - 1 + length) % length;
  else if (event.key === "Home") next = 0;
  else if (event.key === "End") next = length - 1;
  if (next === null) return;
  event.preventDefault();
  hodlSelectMsig(next);
  hodlElement("#msig-tabs").children[next]?.focus();
}
function hodlCreateMsigTab(index) {
  let state = hodlMsigs[index], active = index === hodlActiveMsig, button = document.createElement("button"), name = state.isLab ? "MS Station" : state.createdPolicy || state.name || "Multisig " + state.number, label = document.createElement("span");
  button.type = "button";
  button.id = state.isLab ? "msig-tab-lab" : "msig-tab-" + (index + 1);
  button.className = "tab key-tab msig-tab" + (state.isLab ? " is-lab" : "") + (active ? " active" : "");
  button.dataset.msigNumber = String(state.number);
  label.className = "key-tab-label";
  label.textContent = name;
  button.append(hodlCreateMsigIcon(state.isLab), label);
  button.setAttribute("role", "tab");
  button.setAttribute("aria-controls", "msig-card");
  button.setAttribute("aria-selected", String(active));
  if (state.isLab) {
    button.setAttribute("aria-label", "MS Station" + (active ? ", selected" : ". Activate to derive a multisig."));
    button.title = "Derive a multisig";
    button.onclick = () => hodlSelectMsig(index);
  } else {
    button.setAttribute("aria-label", name + (active ? ", selected. Activate or press F2 to rename." : ". Activate to select."));
    button.title = active ? "Click again or press F2 to rename" : "Click to select";
    button.onclick = () => index === hodlActiveMsig ? hodlBeginMsigRename(index) : hodlSelectMsig(index);
  }
  button.tabIndex = active ? 0 : -1;
  button.onkeydown = (event) => hodlMsigTabKeydown(event, index);
  return button;
}
function hodlNormalizeMsigName(name) {
  return String(name || "").trim().replace(/\s+/g, " ").toLowerCase();
}
function hodlMsigNameTaken(name, index) {
  let normalized = hodlNormalizeMsigName(name);
  return !!normalized && hodlMsigs.some((state, stateIndex) => stateIndex !== index && hodlNormalizeMsigName(state.name) === normalized);
}
function hodlDefaultMsigName(number) {
  let base = hodlT("Multisig {n}", { n: number }), name = base, suffix = 2;
  while (hodlMsigNameTaken(name, -1)) {
    name = hodlT("Multisig {n} ({suffix})", { n: number, suffix });
    suffix++;
  }
  return name;
}
function hodlBeginMsigRename(index) {
  if (index !== hodlActiveMsig || !hodlMsigs[index] || hodlMsigs[index].isLab) return;
  let box = hodlElement("#msig-tabs"), tab = box.children[index];
  if (!tab || tab.classList.contains("key-tab-editing")) return;
  let state = hodlMsigs[index], editor = document.createElement("div"), input = document.createElement("input"), previous = state.name || hodlT("Multisig {n}", { n: state.number });
  editor.id = "msig-tab-" + (index + 1);
  editor.className = "key-tab key-tab-editing msig-tab active";
  editor.dataset.msigNumber = String(state.number);
  editor.setAttribute("role", "tab");
  editor.setAttribute("aria-selected", "true");
  editor.setAttribute("aria-controls", "msig-card");
  input.type = "text";
  input.className = "key-tab-name-input msig-tab-name-input";
  input.value = previous;
  input.maxLength = 120;
  input.setAttribute("aria-label", "Rename " + previous);
  input.setAttribute("aria-controls", "msig-card");
  let finish = (commit, focus) => {
    if (!editor.isConnected) return;
    let name = input.value.trim().replace(/\s+/g, " ");
    let renamed = commit && name && name !== previous && !hodlMsigNameTaken(name, index);
    if (renamed) {
      state.name = name;
      hodlJournalLog("station-rename", `multisig-${state.number}`, "msig");
    }
    let button = hodlCreateMsigTab(index);
    editor.replaceWith(button);
    if (focus) button.focus();
  };
  input.oninput = () => hodlSizeKeyTabEditor(input);
  input.onkeydown = (event) => {
    if (event.key === "Enter") {
      event.preventDefault();
      finish(true, true);
    } else if (event.key === "Escape") {
      event.preventDefault();
      finish(false, true);
    }
  };
  input.onblur = () => finish(true, false);
  editor.append(hodlCreateMsigIcon(), input);
  tab.replaceWith(editor);
  hodlSizeKeyTabEditor(input);
  input.focus();
  input.select();
}
function hodlSyncMsigDeleteButton() {
  let button = hodlElement("#delete-msig"), state = hodlMsigs[hodlActiveMsig];
  if (!button) return;
  button.disabled = !state || state.isLab;
  button.setAttribute("aria-disabled", String(button.disabled));
}
function hodlRenderMsigTabs() {
  let box = hodlElement("#msig-tabs"), panel = hodlElement("#msig-card");
  box.innerHTML = "";
  panel.removeAttribute("aria-labelledby");
  box.setAttribute("role", "tablist");
  hodlMsigs.forEach((state, index) => {
    let button = hodlCreateMsigTab(index);
    box.appendChild(button);
    if (index === hodlActiveMsig) panel.setAttribute("aria-labelledby", button.id);
  });
  hodlRevealTab(box, hodlActiveMsig);
  hodlSyncMsigDeleteButton();
}
function hodlSelectMsig(index) {
  if (index === hodlActiveMsig || !hodlMsigs[index]) return;
  hodlCaptureMsig();
  hodlActiveMsig = index;
  hodlRenderMsigTabs();
  hodlRestoreMsig();
  hodlJournalLog("station-select", `multisig-${hodlMsigs[index].number}`, "msig");
}
function hodlAddMsig() {
  hodlSelectMsigLab();
}
function hodlDeleteActiveMsig() {
  let state = hodlMsigs[hodlActiveMsig];
  if (!state || state.isLab) {
    hodlSyncMsigDeleteButton();
    return;
  }
  let deletedIndex = hodlActiveMsig, deletedState = state;
  hodlMsigs.splice(deletedIndex, 1);
  hodlNextMsigNumber = hodlMsigs.length ? hodlMsigs.reduce((latest, state) => Math.max(latest, state.number), 0) + 1 : deletedState.number;
  if (!hodlMsigs.length) {
    hodlMsigs.push(hodlNewMsigLabState());
    hodlActiveMsig = 0;
  } else hodlActiveMsig = Math.min(deletedIndex, hodlMsigs.length - 1);
  hodlRenderMsigTabs();
  hodlRestoreMsig();
  hodlJournalLog("station-delete", `multisig-${deletedState.number}`, "msig");
  (hodlActiveMsig >= 0 ? hodlElement("#msig-tabs").children[hodlActiveMsig] : hodlElement("#add-msig"))?.focus();
}
function hodlShowWorkspace(id) {
  if (id === hodlWorkspace) return;
  let preservedTop = window.scrollY, preservedLeft = window.scrollX;
  if (hodlWorkspace === "calc") hodlCaptureKey();
  else if (hodlWorkspace === "msig") hodlCaptureMsig();
  else if (hodlWorkspace === "vanity") hodlVanityCancel();
  hodlWorkspace = id;
  [...hodlElement("#workspace-tabs").querySelectorAll("[data-workspace]")].forEach((button) => {
    let active = button.dataset.workspace === id;
    button.classList.toggle("active", active);
    button.setAttribute("aria-selected", String(active));
    if (active) hodlRevealTab(hodlElement("#workspace-tabs"), [...hodlElement("#workspace-tabs").children].indexOf(button));
  });

  document.getElementById("key-manager").hidden = id !== "calc";
  document.getElementById("bip85-manager").hidden = id !== "bip85";
  document.getElementById("msig-manager").hidden = id !== "msig";
  document.getElementById("sp-manager").hidden = id !== "sp";
  document.getElementById("calc-card").hidden = true;
  document.getElementById("msig-card").hidden = true;
  document.getElementById("bip85-card").hidden = id !== "bip85";
  document.getElementById("sp-card").hidden = id !== "sp";
  document.getElementById("vanity-card").hidden = id !== "vanity";
  // The context block sits outside its tool's card, so it is shown and hidden
  // with the card rather than by it.
  ["bip85", "sp", "msig", "calc", "vanity"].forEach((tool) => {
    document.getElementById(`${tool}-tool-intro`).hidden = id !== tool;
  });
  hodlSyncPsbtTool();
  hodlSyncJournalTool();
  hodlJournalLog("workspace", id);
  hodlWalletResult = null;
  hodlRevealPrivate = false;
  hodlOutEl.innerHTML = "";
  if (id === "calc") {
    hodlRenderKeyTabs();
    hodlRestoreKey();
  } else if (id === "msig") {
    hodlRenderMsigTabs();
    hodlRestoreMsig();
  } else if (id === "bip85") {
    hodlRenderBip85Tabs();
    hodlSyncBip85View();
    hodlBip85SyncOptions();
  } else if (id === "vanity") {
    // Keys may have been derived, renamed, or re-passphrased since the picker last filled.
    hodlFillStationKeyPicker("vanity-session-keys", hodlVanitySource, hodlPickVanitySessionKey, hodlVanitySourceKeys());
    hodlVanitySyncSource();
    hodlVanityStartBenchmark();
  }
  if (hodlWorkspaceScrollFrame) cancelAnimationFrame(hodlWorkspaceScrollFrame);
  window.scrollTo(preservedLeft, preservedTop);
  hodlWorkspaceScrollFrame = requestAnimationFrame(() => {
    window.scrollTo(preservedLeft, preservedTop);
    hodlQueueSegmentedControlSync();
    hodlWorkspaceScrollFrame = 0;
  });
}
function hodlInitTabDrag(box) {
  let pointerId = null, startX = 0, startScroll = 0, moved = false, suppressClick = false;
  box.addEventListener("pointerdown", (event) => {
    if (!event.isPrimary || event.button !== 0 || event.pointerType === "touch" || event.target.closest?.(".key-tab-editing")) return;
    pointerId = event.pointerId;
    startX = event.clientX;
    startScroll = box.scrollLeft;
    moved = false;
  });
  let move = (event) => {
    if (event.pointerId !== pointerId) return;
    let distance = event.clientX - startX;
    if (!moved && Math.abs(distance) > 5) {
      moved = true;
      box.classList.add("dragging");
      box.setPointerCapture?.(pointerId);
    }
    if (moved) {
      box.scrollLeft = startScroll - distance;
      event.preventDefault();
    }
  };
  let end = (event) => {
    if (event.pointerId !== pointerId) return;
    let id = pointerId, didMove = moved;
    pointerId = null;
    moved = false;
    box.classList.remove("dragging");
    if (box.hasPointerCapture?.(id)) box.releasePointerCapture(id);
    if (didMove) {
      suppressClick = true;
      setTimeout(() => {
        suppressClick = false;
      }, 0);
    }
  };
  window.addEventListener("pointermove", move, { passive: false });
  window.addEventListener("pointerup", end);
  window.addEventListener("pointercancel", end);
  box.addEventListener("lostpointercapture", end);
  box.addEventListener("click", (event) => {
    if (!suppressClick) return;
    event.preventDefault();
    event.stopImmediatePropagation();
  }, true);
  box.addEventListener("dragstart", (event) => event.preventDefault());
}
function hodlInitKeyManager() {
  hodlElement("#add-key").onclick = hodlAddKey;
  hodlElement("#delete-key").onclick = hodlDeleteActiveKey;
  hodlRenderKeyTabs();
  hodlInitTabDrag(hodlElement("#key-tabs"));
  if (hodlWorkspace === "calc") hodlRestoreKey();
  else document.getElementById("calc-card").hidden = true;
}
function hodlInitMsigManager() {
  hodlElement("#add-msig").onclick = hodlAddMsig;
  hodlElement("#delete-msig").onclick = hodlDeleteActiveMsig;
  hodlRenderMsigTabs();
  hodlInitTabDrag(hodlElement("#msig-tabs"));
  if (hodlWorkspace === "msig") hodlRestoreMsig();
  else document.getElementById("msig-card").hidden = true;
}
function hodlInitSpBench() {
  let tabs = document.getElementById("sp-tabs");
  if (!tabs) return;
  let button = document.createElement("button"), label = document.createElement("span");
  button.type = "button";
  button.id = "sp-tab-bench";
  button.className = "tab key-tab is-lab active";
  button.setAttribute("role", "tab");
  button.setAttribute("aria-selected", "true");
  button.setAttribute("aria-controls", "sp-card");
  button.setAttribute("aria-label", "SP Station, selected");
  label.className = "key-tab-label";
  label.textContent = "SP Station";
  button.append(hodlCreateSilentPaymentsIcon(), label);
  tabs.replaceChildren(button);
}
function hodlInitDefaultTabStates() {
  if (!hodlKeys.length) {
    hodlKeys.push(hodlNewLabState());
    hodlActiveKey = 0;
  }
  if (!hodlMsigs.length) {
    hodlMsigs.push(hodlNewMsigLabState());
    hodlActiveMsig = 0;
  }
}
// Each tool carries a full name and a short one. Narrow screens show the
// short form so more tools stay on screen instead of off the right edge.
var hodlWorkspaceTabs = [["calc", "Keys", "Keys"], ["vanity", "Vanity", "Vanity"], ["bip85", "BIP-85", "BIP85"], ["msig", "Multi Signature", "MultiSig"], ["sp", "Silent Payments", "SP"], ["psbt", "PSBT", "PSBT"], ["journal", "Journal", "Journal"]];
var hodlPsbtTool = "nonce";
function hodlSyncPsbtTool() {
  let visible = hodlWorkspace === "psbt",
      intros = document.getElementById("psbt-tool-intros"),
      manager = document.getElementById("psbt-manager"),
      tabs = document.getElementById("psbt-tool-tabs");
  if (intros) intros.hidden = !visible;
  if (manager) manager.hidden = !visible;
  if (tabs) {
    tabs.querySelectorAll("[data-psbt-tool]").forEach((button) => {
      let active = button.dataset.psbtTool === hodlPsbtTool;
      button.classList.toggle("active", active);
      button.setAttribute("aria-selected", String(active));
      button.tabIndex = active ? 0 : -1;
    });
  }
  let nonceIntro = document.getElementById("psbt-tool-intro"),
      editorIntro = document.getElementById("psbted-tool-intro");
  nonceIntro.classList.toggle("active", visible && hodlPsbtTool === "nonce");
  nonceIntro.setAttribute("aria-hidden", String(!visible || hodlPsbtTool !== "nonce"));
  document.getElementById("psbt-card").hidden = !visible || hodlPsbtTool !== "nonce";
  editorIntro.classList.toggle("active", visible && hodlPsbtTool === "editor");
  editorIntro.setAttribute("aria-hidden", String(!visible || hodlPsbtTool !== "editor"));
  document.getElementById("psbted-card").hidden = !visible || hodlPsbtTool !== "editor";
}
function hodlShowPsbtTool(id, focus = false) {
  let next = id === "editor" ? "editor" : "nonce", changed = next !== hodlPsbtTool;
  hodlPsbtTool = next;
  hodlSyncPsbtTool();
  if (changed) hodlJournalLog("tool-tab", hodlPsbtTool, "psbt");
  if (focus) document.querySelector(`#psbt-tool-tabs [data-psbt-tool="${hodlPsbtTool}"]`)?.focus();
}
function hodlInitPsbtToolTabs() {
  let buttons = [...document.querySelectorAll("#psbt-tool-tabs [data-psbt-tool]")];
  buttons.forEach((button, index) => {
    button.onclick = () => hodlShowPsbtTool(button.dataset.psbtTool);
    button.onkeydown = (event) => {
      let next = null;
      if (event.key === "ArrowRight") next = (index + 1) % buttons.length;
      else if (event.key === "ArrowLeft") next = (index - 1 + buttons.length) % buttons.length;
      else if (event.key === "Home") next = 0;
      else if (event.key === "End") next = buttons.length - 1;
      if (next === null) return;
      event.preventDefault();
      hodlShowPsbtTool(buttons[next].dataset.psbtTool, true);
    };
  });
  hodlInitTabDrag(document.getElementById("psbt-tool-tabs"));
  hodlSyncPsbtTool();
}
var hodlJournal = createJournal();
var hodlJournalTool = "book";
var hodlJournalEncryptDownloads = true;
var hodlJournalStateRefreshQueued = false;
function hodlJournalActivePage() {
  return hodlJournal.pages[hodlJournal.activePage];
}
function hodlJournalRenderVisual(field = document.getElementById("journal-notes-text")) {
  let render = document.getElementById("journal-notes-render");
  if (!field || !render) return;
  render.replaceChildren();
  for (let run of hodlJournalNotebookRuns(field.value)) {
    if (run.type === "text") {
      render.appendChild(document.createTextNode(run.text));
      continue;
    }
    let reference = document.createElement("span"), slot = document.createElement("span"), image = document.createElement("img"), end = document.createElement("span");
    reference.className = "journal-inline-key";
    let repeatedFingerprint = run.name.trim().toLowerCase() === run.fingerprint;
    reference.title = repeatedFingerprint ? run.fingerprint : `${run.name} · ${run.fingerprint}`;
    slot.className = "journal-inline-key-lifehash-slot";
    slot.textContent = "◆◆";
    image.className = "journal-inline-key-lifehash";
    image.width = 22;
    image.height = 22;
    image.alt = "";
    image.hidden = true;
    slot.appendChild(image);
    end.className = "journal-inline-key-end";
    end.textContent = "◆";
    reference.append(slot, document.createTextNode(repeatedFingerprint ? ` [${run.fingerprint}] ` : ` ${run.name} [${run.fingerprint}] `), end);
    render.appendChild(reference);
    hodlFillKeyTabLifehash(image, run.fingerprint);
  }
  hodlJournalSyncPendingPrompt(field);
  hodlJournalSyncCopyButton(field);
}
function hodlJournalSyncCopyButton(field, button = document.getElementById("journal-notes-copy")) {
  if (!field || !button) return;
  let phrase = hodlJournalFormatNotebook(field.value), empty = phrase === "No notes.";
  button.disabled = empty;
  if (empty) delete button.dataset.phrase;
  else button.dataset.phrase = phrase;
}
function hodlJournalRevealCopyButton(button, delay = 1100) {
  if (!button) return;
  clearTimeout(button.hodlJournalHideTimer);
  button.classList.add("is-visible");
  button.hodlJournalHideTimer = setTimeout(() => button.classList.remove("is-visible"), delay);
}
function hodlJournalActivePageStyle() {
  let page = hodlJournalActivePage();
  if (!page) return hodlJournalDefaultPageStyle();
  page.style = hodlNormalizeJournalPageStyle(page.style);
  return page.style;
}
function hodlJournalApplyPageStyle() {
  let style = hodlJournalActivePageStyle(), wrap = document.getElementById("journal-page-panel");
  if (wrap) {
    wrap.dataset.font = style.font;
    wrap.dataset.size = style.size;
    wrap.dataset.spacing = style.spacing;
  }
  hodlSyncSelect(document.getElementById("journal-font"), style.font);
  hodlSyncSelect(document.getElementById("journal-size"), style.size);
  hodlSyncSelect(document.getElementById("journal-spacing"), style.spacing);
  hodlJournalSyncPendingPrompt(document.getElementById("journal-notes-text"));
}
function hodlJournalSetPageStyle(property, value) {
  let page = hodlJournalActivePage();
  if (!page) return;
  page.style = hodlNormalizeJournalPageStyle({ ...page.style, [property]: value });
  hodlJournalApplyPageStyle();
}
function hodlJournalStoreNotesText(field) {
  hodlJournal.notesText = field.value;
  let page = hodlJournalActivePage();
  if (page) page.notesText = field.value;
  hodlJournalRenderVisual(field);
}
function hodlJournalNormalizePageName(name) {
  return String(name || "").trim().replace(/\s+/g, " ").toLowerCase();
}
function hodlJournalPageNameTaken(name, index) {
  let normalized = hodlJournalNormalizePageName(name);
  return !!normalized && hodlJournal.pages.some((page, pageIndex) => pageIndex !== index && hodlJournalNormalizePageName(page.name) === normalized);
}
function hodlJournalDefaultPageName(number) {
  let name = `Page ${number}`, suffix = 2;
  while (hodlJournalPageNameTaken(name, -1)) {
    name = `Page ${number} (${suffix})`;
    suffix++;
  }
  return name;
}
function hodlCreateJournalPageTab(index) {
  let page = hodlJournal.pages[index], active = index === hodlJournal.activePage, defaultName = `Page ${page.number}`,
      button = document.createElement("button"), fullLabel = document.createElement("span"), shortLabel = document.createElement("span");
  button.type = "button";
  button.id = `journal-page-tab-${page.id}`;
  button.className = "tab key-tab journal-page-tab" + (page.name === defaultName ? " is-default" : "") + (active ? " active" : "");
  button.dataset.journalPage = String(index);
  button.setAttribute("role", "tab");
  button.setAttribute("aria-controls", "journal-page-panel");
  button.setAttribute("aria-selected", String(active));
  button.setAttribute("aria-label", page.name + (active ? ", selected. Activate or press F2 to rename." : ". Activate to select."));
  button.title = active ? "Click again or press F2 to rename" : "Click to select";
  button.tabIndex = active ? 0 : -1;
  fullLabel.className = "key-tab-label journal-page-tab-full";
  fullLabel.textContent = page.name;
  shortLabel.className = "key-tab-label journal-page-tab-short";
  shortLabel.textContent = page.name === defaultName ? `P${page.number}` : page.name;
  button.append(fullLabel, shortLabel);
  button.onclick = () => index === hodlJournal.activePage ? hodlBeginJournalPageRename(index) : hodlSelectJournalPage(index);
  button.onkeydown = (event) => hodlJournalPageTabKeydown(event, index);
  return button;
}
function hodlBeginJournalPageRename(index) {
  if (index !== hodlJournal.activePage || !hodlJournal.pages[index]) return;
  let box = document.getElementById("journal-page-tabs"), tab = box?.children[index];
  if (!tab || tab.classList.contains("key-tab-editing")) return;
  let page = hodlJournal.pages[index], editor = document.createElement("div"), input = document.createElement("input"), previous = page.name;
  editor.id = `journal-page-tab-${page.id}`;
  editor.className = "key-tab key-tab-editing journal-page-tab active";
  editor.setAttribute("role", "tab");
  editor.setAttribute("aria-selected", "true");
  editor.setAttribute("aria-controls", "journal-page-panel");
  input.type = "text";
  input.className = "key-tab-name-input";
  input.value = previous;
  input.maxLength = 120;
  input.setAttribute("aria-label", "Rename " + previous);
  input.setAttribute("aria-controls", "journal-page-panel");
  let finish = (commit, focus) => {
    if (!editor.isConnected) return;
    let name = input.value.trim().replace(/\s+/g, " ");
    let renamed = commit && name && name !== previous && !hodlJournalPageNameTaken(name, index);
    if (renamed) {
      page.name = name;
      hodlJournalLog("page-rename", `page-${page.number}`, "journal");
    }
    let button = hodlCreateJournalPageTab(index);
    editor.replaceWith(button);
    document.getElementById("journal-page-panel")?.setAttribute("aria-labelledby", button.id);
    if (focus) button.focus();
  };
  input.oninput = () => hodlSizeKeyTabEditor(input);
  input.onkeydown = (event) => {
    if (event.key === "Enter") {
      event.preventDefault();
      finish(true, true);
    } else if (event.key === "Escape") {
      event.preventDefault();
      finish(false, true);
    }
  };
  input.onblur = () => finish(true, false);
  editor.append(input);
  tab.replaceWith(editor);
  hodlSizeKeyTabEditor(input);
  input.focus();
  input.select();
}
function hodlJournalPageTabKeydown(event, index) {
  if (event.key === "F2") {
    event.preventDefault();
    if (index === hodlJournal.activePage) hodlBeginJournalPageRename(index);
    return;
  }
  let next = null, length = hodlJournal.pages.length;
  if (event.key === "ArrowRight") next = (index + 1) % length;
  else if (event.key === "ArrowLeft") next = (index - 1 + length) % length;
  else if (event.key === "Home") next = 0;
  else if (event.key === "End") next = length - 1;
  if (next === null) return;
  event.preventDefault();
  hodlSelectJournalPage(next);
  document.getElementById("journal-page-tabs")?.children[next]?.focus();
}
function hodlSyncJournalPageDeleteButton() {
  let button = document.getElementById("delete-journal-page");
  if (!button) return;
  button.disabled = hodlJournal.pages.length <= 1;
  button.setAttribute("aria-disabled", String(button.disabled));
}
function hodlRenderJournalPageTabs() {
  let box = document.getElementById("journal-page-tabs"), panel = document.getElementById("journal-page-panel");
  if (!box || !panel) return;
  box.innerHTML = "";
  panel.removeAttribute("aria-labelledby");
  hodlJournal.pages.forEach((page, index) => {
    let button = hodlCreateJournalPageTab(index);
    box.appendChild(button);
    if (index === hodlJournal.activePage) panel.setAttribute("aria-labelledby", button.id);
  });
  hodlRevealTab(box, hodlJournal.activePage);
  hodlSyncJournalPageDeleteButton();
}
function hodlJournalRestorePage(field = document.getElementById("journal-notes-text")) {
  if (!field) return;
  let page = hodlJournalActivePage();
  hodlJournal.notesText = page?.notesText || "";
  field.value = hodlJournal.notesText;
  hodlJournalApplyPageStyle();
  hodlJournalRenderVisual(field);
  hodlJournalFinishPendingNote(field);
  let lines = field.value.split("\n"), pending = lines.findIndex((line) => hodlJournalNoteStampPattern.test(line) && !line.replace(hodlJournalNoteStampPattern, "").trim());
  if (!field.value) hodlJournalResetPendingNote(field, "Add new note");
  else if (pending >= 0) {
    field.dataset.pendingNote = "Add new note";
    field.dataset.pendingNoteMode = "line";
    field.dataset.pendingNoteLine = String(pending);
    hodlJournalRefreshPendingNote(field);
  } else field.setSelectionRange(field.value.length, field.value.length);
}
function hodlSelectJournalPage(index) {
  if (index === hodlJournal.activePage || !hodlJournal.pages[index]) return;
  let field = document.getElementById("journal-notes-text");
  if (field) hodlJournalStoreNotesText(field);
  hodlJournal.activePage = index;
  hodlRenderJournalPageTabs();
  hodlJournalRestorePage(field);
  hodlJournalLog("page-select", `page-${hodlJournal.pages[index].number}`, "journal");
}
function hodlAddJournalPage() {
  let field = document.getElementById("journal-notes-text");
  if (field) hodlJournalStoreNotesText(field);
  let style = { ...hodlJournalActivePageStyle() };
  let number = hodlJournal.nextPageNumber++;
  hodlJournal.pages.push({ id: hodlJournal.nextPageId++, number, name: hodlJournalDefaultPageName(number), notesText: "", style });
  hodlJournal.activePage = hodlJournal.pages.length - 1;
  hodlRenderJournalPageTabs();
  hodlJournalRestorePage(field);
  hodlJournalLog("page-add", `page-${number}`, "journal");
  document.getElementById("journal-page-tabs")?.children[hodlJournal.activePage]?.focus();
}
function hodlDeleteActiveJournalPage() {
  if (hodlJournal.pages.length <= 1) {
    hodlSyncJournalPageDeleteButton();
    return;
  }
  let field = document.getElementById("journal-notes-text"), deletedIndex = hodlJournal.activePage, deletedNumber = hodlJournal.pages[deletedIndex].number;
  if (field) hodlJournalStoreNotesText(field);
  hodlJournal.pages.splice(deletedIndex, 1);
  hodlJournal.nextPageNumber = hodlJournal.pages.reduce((latest, page) => Math.max(latest, page.number), 0) + 1;
  hodlJournal.activePage = Math.min(deletedIndex, hodlJournal.pages.length - 1);
  hodlRenderJournalPageTabs();
  hodlJournalRestorePage(field);
  hodlJournalLog("page-delete", `page-${deletedNumber}`, "journal");
  document.getElementById("journal-page-tabs")?.children[hodlJournal.activePage]?.focus();
}
function hodlJournalLog(action, detail = "", tool = hodlWorkspace) {
  hodlJournalAppend(hodlJournal, { tool, action, detail });
  hodlScheduleJournalStateRefresh();
  if (hodlWorkspace === "journal" && hodlJournalTool === "log") hodlRenderJournalLog();
}
var hodlJournalAuditedClicks = {
  "key-edit-inputs": ["calc", "edit-input", "current-key"],
  "bip85-wipe": ["bip85", "clear", "parent-session"],
  "bip85-copy": ["bip85", "copy", "derived-child"],
  "msig-edit-inputs": ["msig", "edit-input", "current-multisig"],
  "msig-descriptor-import": ["msig", "import", "descriptor"],
  "sp-wipe": ["sp", "clear", "session"],
  "psbt-use-calc": ["psbt", "use-session-key", "active-key"],
  "psbt-wipe": ["psbt", "clear", "session"],
  "psbted-load": ["psbt", "load", "editor-text"],
  "psbted-upload": ["psbt", "upload", "psbt-file"],
  "psbted-wipe": ["psbt", "clear", "editor"],
  "psbted-copy-b64": ["psbt", "copy", "edited-psbt-base64"],
  "psbted-copy-hex": ["psbt", "copy", "edited-psbt-hex"],
  "psbted-download": ["psbt", "download", "edited-psbt"],
  "psbted-reload": ["psbt", "load", "edited-psbt"],
  "journal-notes-copy": ["journal", "copy", "notepad-page"],
  "journal-notes-download": ["journal", "download", "notebook"],
  "journal-notes-upload": ["journal", "upload", "notebook"],
  "journal-keymanager-download": ["journal", "download", "key-manager"],
  "journal-keymanager-upload": ["journal", "upload", "key-manager"],
  "journal-state-download": ["journal", "download", "session-state"],
  "journal-log-copy": ["journal", "copy", "session-log"],
  "journal-log-download": ["journal", "download", "session-log"],
  "beta-warning-dismiss": ["app", "dismiss", "beta-warning"],
};
var hodlJournalActionAuditReady = false, hodlJournalSuppressSettingAudit = false;
function hodlJournalControlTool(control) {
  let id = control?.id || "";
  if (id.startsWith("journal-")) return "journal";
  if (id.startsWith("psbt-") || id.startsWith("psbted-")) return "psbt";
  if (id.startsWith("bip85-")) return "bip85";
  if (id.startsWith("msig-")) return "msig";
  if (id.startsWith("sp-")) return "sp";
  if (control?.closest?.("#journal-manager, #journal-notes-card, #journal-keymanager-card, #journal-state-card, #journal-log-card")) return "journal";
  if (control?.closest?.("#psbt-manager, #psbt-card, #psbted-card")) return "psbt";
  if (control?.closest?.("#bip85-manager, #bip85-card")) return "bip85";
  if (control?.closest?.("#msig-manager, #msig-card")) return "msig";
  if (control?.closest?.("#sp-manager, #sp-card")) return "sp";
  if (control?.closest?.("#key-manager, #calc-card")) return "calc";
  return "app";
}
function hodlJournalAuditedClick(control) {
  let mapped = hodlJournalAuditedClicks[control.id];
  if (mapped) return mapped;
  if (control.id === "save") return [hodlJournalControlTool(control), "download", "recovery-sheet"];
  if (control.id === "download-wallet-dat") return [hodlJournalControlTool(control), "download", "wallet-dat"];
  if (control.matches('a[download="entropylab.html"]')) return ["app", "download", "application"];
  if (control.matches("[data-copy-seed-phrase]")) return ["calc", "copy", "seed-phrase"];
  if (control.matches("[data-sp-mode]")) return ["sp", "mode", control.dataset.spMode];
  if (control.matches("[data-sp-copy]")) return ["sp", "copy", "result"];
  if (control.matches(".session-key-option, .msig-session-key")) return [hodlJournalControlTool(control), "use-session-key", "key-station"];
  if (control.matches("[data-msig-move]")) return ["msig", "reorder", control.dataset.msigMove === "-1" ? "up" : "down"];
  if (control.matches(".msig-key-reuse-apply")) return ["msig", "apply", "cosigner-path"];
  if (control.matches(".msig-key-reuse-clear")) return ["msig", "clear", "cosigner-path"];
  if (control.matches("[data-tx-add]")) return ["psbt", "editor-add", control.dataset.txAdd];
  if (control.matches("[data-txin-del]")) return ["psbt", "editor-delete", "input"];
  if (control.matches("[data-txout-del]")) return ["psbt", "editor-delete", "output"];
  if (control.matches("[data-build-apply]")) return ["psbt", "editor-set", "output-script"];
  if (control.matches("[data-add]")) return ["psbt", "editor-add", `${control.dataset.add.split(":")[0]}-pair`];
  if (control.matches(".psbted-del[data-kind]")) return ["psbt", "editor-delete", `${control.dataset.kind}-pair`];
  if (control.matches("[data-viz]")) return ["psbt", "editor-view", control.dataset.viz.split(":")[0]];
  if (control.matches(".account-tab")) return ["calc", "result-tab", control.dataset.account || "script"];
  return null;
}
function hodlJournalSettingDetail(control) {
  let name = control.id || control.name || control.dataset.buildMode || control.dataset.addType || (control.hasAttribute("data-wallet-dat-birthday") ? "wallet-birthday" : "");
  if (!name) return "";
  if (control.type === "radio" && !control.checked) return "";
  let value = control.type === "checkbox" ? control.checked ? "on" : "off" : String(control.value ?? "").slice(0, 80);
  return `${name}=${value}`;
}
function hodlInitJournalActionAudit() {
  if (hodlJournalActionAuditReady) return;
  hodlJournalActionAuditReady = true;
  document.addEventListener("click", (event) => {
    let control = event.target.closest?.("button, a");
    if (!control || control.disabled || control.dataset.journalSilent === "true") return;
    let audited = hodlJournalAuditedClick(control);
    if (audited) hodlJournalLog(audited[1], audited[2], audited[0]);
  }, true);
  document.addEventListener("change", (event) => {
    if (hodlJournalSuppressSettingAudit) return;
    let control = event.target;
    if (!(control instanceof HTMLSelectElement || control instanceof HTMLInputElement || control instanceof HTMLTextAreaElement)) return;
    if (control.id === "journal-key-insert" || control.type === "file") return;
    if (control instanceof HTMLTextAreaElement) {
      if (control.closest("#psbted-card")) hodlJournalLog("editor-edit", "field", "psbt");
      return;
    }
    let safeTextIds = new Set(["purpose", "network", "account", "branch-start", "address-start", "derivation-path", "msig-account"]);
    if (control.type && !["checkbox", "radio", "number", "range"].includes(control.type) && !safeTextIds.has(control.id) && !(control instanceof HTMLSelectElement)) return;
    let detail = hodlJournalSettingDetail(control);
    if (detail) hodlJournalLog("setting", detail, hodlJournalControlTool(control));
  }, true);
}
function hodlSyncJournalTool() {
  let visible = hodlWorkspace === "journal",
      intro = document.getElementById("journal-tool-intro"),
      manager = document.getElementById("journal-manager"),
      tabs = document.getElementById("journal-tool-tabs"),
      unlocked = hodlJournalUnlocked();
  if (intro) intro.hidden = !visible;
  if (manager) manager.hidden = !visible;
  if (tabs) {
    tabs.querySelectorAll("[data-journal-tool]").forEach((button) => {
      let active = unlocked && button.dataset.journalTool === hodlJournalTool;
      button.disabled = !unlocked;
      button.classList.toggle("active", active);
      button.setAttribute("aria-selected", String(active));
      button.setAttribute("aria-disabled", String(!unlocked));
      button.tabIndex = unlocked && active ? 0 : -1;
    });
  }
  document.getElementById("journal-card").hidden = !visible || hodlJournalTool !== "book";
  document.getElementById("journal-notes-card").hidden = !visible || !unlocked || hodlJournalTool !== "notes";
  document.getElementById("journal-keymanager-card").hidden = !visible || !unlocked || hodlJournalTool !== "keymanager";
  document.getElementById("journal-state-card").hidden = !visible || !unlocked || hodlJournalTool !== "state";
  document.getElementById("journal-log-card").hidden = !visible || !unlocked || hodlJournalTool !== "log";
  if (visible && hodlJournalTool === "book") {
    hodlJournalFillWallets();
    hodlJournalShowWork();
  }
  if (visible && hodlJournalTool === "notes") hodlRenderJournalNotes();
  if (visible && hodlJournalTool === "keymanager") hodlKeyManagerRender();
  if (visible && hodlJournalTool === "state") hodlJournalRefreshSessionState();
  if (visible && hodlJournalTool === "log") hodlRenderJournalLog();
}
function hodlShowJournalTool(id, focus = false) {
  let next = ["book", "notes", "keymanager", "state", "log"].includes(id) ? id : "book";
  if (next !== "book" && !hodlJournalUnlocked()) return;
  let changed = next !== hodlJournalTool;
  hodlJournalTool = next;
  hodlSyncJournalTool();
  if (changed) hodlJournalLog("tool-tab", hodlJournalTool, "journal");
  if (focus) document.querySelector(`#journal-tool-tabs [data-journal-tool="${hodlJournalTool}"]`)?.focus();
}
function hodlRefreshJournalKeyPicker() {
  let select = document.getElementById("journal-key-insert");
  if (!select) return;
  let placeholder = document.createElement("option"), keys = (hodlKeys || []).filter((state) => !state.isLab && /^[0-9a-f]{8}$/i.test(state.result?.masterFingerprint || ""));
  placeholder.value = "";
  placeholder.textContent = "Insert key";
  placeholder.selected = true;
  placeholder.dataset.customSelectPlaceholder = "true";
  select.replaceChildren(placeholder);
  if (!keys.length) {
    let empty = document.createElement("option");
    empty.value = "";
    empty.textContent = "No derived keys yet";
    empty.disabled = true;
    select.appendChild(empty);
  } else keys.forEach((state) => {
    let option = document.createElement("option"), fingerprint = state.result.masterFingerprint.toLowerCase();
    option.value = String(state.id);
    let keyName = state.name || `Key ${state.number}`;
    option.textContent = keyName.trim().toLowerCase() === fingerprint ? fingerprint : `${keyName} · ${fingerprint}`;
    option.dataset.keyName = keyName;
    option.dataset.fingerprint = fingerprint;
    select.appendChild(option);
  });
  select.entropylabOptionIcon = (value) => {
    let option = [...select.options].find((item) => item.value === value && item.dataset.fingerprint);
    if (!option) return null;
    let image = document.createElement("img");
    image.className = "journal-key-option-lifehash";
    image.width = 22;
    image.height = 22;
    image.alt = "";
    image.hidden = true;
    hodlFillKeyTabLifehash(image, option.dataset.fingerprint);
    return image;
  };
  select.value = "";
  select.dispatchEvent(new Event("entropylab:sync-select"));
}
function hodlJournalInsertKey(select, field) {
  let option = select?.selectedOptions?.[0], fingerprint = option?.dataset.fingerprint;
  if (!field || !fingerprint) return;
  let token = hodlJournalKeyReferenceToken(option.dataset.keyName, fingerprint), start = field.selectionStart, end = field.selectionEnd;
  let prefix = start > 0 && !/\s$/.test(field.value.slice(0, start)) ? " " : "";
  let suffix = end < field.value.length && !/^\s/.test(field.value.slice(end)) ? " " : "";
  field.setRangeText(prefix + token + suffix, start, end, "end");
  field.dispatchEvent(new InputEvent("input", { bubbles: true, inputType: "insertText", data: token }));
  select.value = "";
  select.dispatchEvent(new Event("entropylab:sync-select"));
  field.focus({ preventScroll: true });
  hodlJournalLog("key-insert", fingerprint.toLowerCase(), "journal");
}
function hodlJournalSetStatus(message, isError = false) {
  let status = document.getElementById("journal-notes-status");
  if (!status) return;
  status.textContent = message;
  status.classList.toggle("err", isError);
}
function hodlJournalSyncEncryptDownloads(source) {
  if (source) hodlJournalEncryptDownloads = source.checked;
  document.querySelectorAll(".journal-encrypt-download").forEach((checkbox) => {
    checkbox.checked = hodlJournalEncryptDownloads;
  });
}
async function hodlJournalDownloadContent(kind, filename, text, type = "text/plain;charset=utf-8") {
  if (!hodlJournalEncryptDownloads) {
    hodlJournalDownload(filename, text, type);
    return;
  }
  let file = await hodlJournalSealExport(kind, text, hodlJournalKeys);
  let encryptedName = filename.replace(/\.[^.]+$/, "") + ".encrypted.json";
  hodlJournalDownload(encryptedName, JSON.stringify(file, null, 2) + "\n", "application/json;charset=utf-8");
}
async function hodlJournalImportFile(file) {
  if (!file) return;
  if (file.size > 2 * 1024 * 1024) {
    hodlJournalLog("notebook-import-error", "too-large", "journal");
    hodlJournalSetStatus("That notebook is larger than the 2 MiB import limit.", true);
    return;
  }
  try {
    let text = await file.text(), encryptedNotebook = false;
    let outer;
    try { outer = JSON.parse(text); } catch { outer = null; }
    if (outer?.entropylabJournalExport) {
      let decrypted = await hodlJournalOpenExport(outer, hodlJournalKeys);
      if (decrypted.kind !== "notebook") throw new Error("That encrypted file is not a notepad export.");
      text = decrypted.content;
      encryptedNotebook = true;
    }
    let imported = !encryptedNotebook && /\.txt$/i.test(file.name) ? hodlJournalFromPlainText(text) : hodlParseNotebook(text);
    hodlJournal.pages = imported.pages;
    hodlJournal.activePage = imported.activePage;
    hodlJournal.nextPageId = imported.nextPageId;
    hodlJournal.nextPageNumber = imported.nextPageNumber;
    hodlJournal.notesText = imported.notesText;
    hodlRenderJournalPageTabs();
    hodlJournalRestorePage(document.getElementById("journal-notes-text"));
    hodlJournalLog("notebook-import", `${imported.pages.length} page${imported.pages.length === 1 ? "" : "s"}`);
    hodlJournalSetStatus(`Imported ${imported.pages.length} page${imported.pages.length === 1 ? "" : "s"} from ${file.name}.`);
  } catch (error) {
    hodlJournalLog("notebook-import-error", "invalid-file", "journal");
    hodlJournalSetStatus(error?.message || "The notebook could not be imported.", true);
  }
}
async function hodlKeyManagerDownload() {
  try {
    if (!hodlJournalUnlocked()) throw new Error("Create or open a journal first.");
    let states = hodlKeyManagerStates().filter((state) => hodlKeyManagerIds.has(keyVaultIdentity(state)));
    if (!states.length) {
      states = hodlKeyManagerStates();
      states.forEach((state) => hodlKeyManagerIds.add(keyVaultIdentity(state)));
    }
    if (!states.length) throw new Error("Derive or import a key before downloading a key file.");
    let content = serializeKeyVault(states.map(hodlKeyManagerEntry), hodlKeyManagerIgnored);
    let file = await hodlJournalSealExport("key-manager", content, hodlJournalKeys);
    hodlJournalDownload("entropylab-keys.elkeys", JSON.stringify(file, null, 2) + "\n", "application/json;charset=utf-8");
    hodlKeyManagerRender();
  } catch (error) {
    hodlKeyManagerStatus(error?.message || "The key file could not be downloaded.", true);
    hodlJournalLog("key-manager-download-error", "", "journal");
  }
}
async function hodlKeyManagerImportFile(file) {
  if (!file) return;
  if (file.size > 2 * 1024 * 1024) {
    hodlKeyManagerStatus("That key file is larger than the 2 MiB import limit.", true);
    hodlJournalLog("key-manager-import-error", "too-large", "journal");
    return;
  }
  try {
    if (!hodlJournalUnlocked()) throw new Error("Create or open a journal first.");
    let opened = await hodlJournalOpenExport(await file.text(), hodlJournalKeys);
    if (opened.kind !== "key-manager") throw new Error("That encrypted file is not a Key Manager export.");
    let imported = parseKeyVault(opened.content), added = 0, duplicates = 0;
    imported.keys.forEach((entry) => {
      let identity = keyVaultIdentity(entry), existing = identity && hodlKeyManagerStates().find((state) => keyVaultIdentity(state) === identity);
      if (existing) {
        hodlKeyManagerIds.add(identity);
        duplicates++;
        return;
      }
      let state = hodlKeyManagerImportedState(entry);
      hodlKeyManagerPending.push(state);
      hodlKeyManagerIds.add(keyVaultIdentity(state));
      added++;
    });
    imported.ignoredKeys.forEach((entry) => {
      let identity = keyVaultIdentity(entry);
      if (!identity || hodlKeyManagerStates().some((state) => keyVaultIdentity(state) === identity) || hodlKeyManagerIgnored.some((state) => keyVaultIdentity(state) === identity)) return;
      hodlKeyManagerIgnored.push(entry);
    });
    hodlKeyManagerActiveId = hodlKeyManagerActiveId || keyVaultIdentity(hodlKeyManagerStates()[0]);
    hodlKeyManagerRender();
    hodlKeyManagerStatus(`${added} new key${added === 1 ? "" : "s"} imported${duplicates ? `; ${duplicates} duplicate${duplicates === 1 ? "" : "s"} kept unchanged` : ""}. Use “Use in Key Station” to load one.`);
    hodlJournalLog("key-manager-import", `${added} keys; ${duplicates} duplicates`, "journal");
  } catch (error) {
    hodlKeyManagerStatus(error?.message || "The key file could not be imported.", true);
    hodlJournalLog("key-manager-import-error", "invalid-file", "journal");
  }
}
function hodlInitJournalToolTabs() {
  let buttons = [...document.querySelectorAll("#journal-tool-tabs [data-journal-tool]")];
  buttons.forEach((button, index) => {
    button.onclick = () => hodlShowJournalTool(button.dataset.journalTool);
    button.onkeydown = (event) => {
      let next = null;
      if (event.key === "ArrowRight") next = (index + 1) % buttons.length;
      else if (event.key === "ArrowLeft") next = (index - 1 + buttons.length) % buttons.length;
      else if (event.key === "Home") next = 0;
      else if (event.key === "End") next = buttons.length - 1;
      if (next === null) return;
      event.preventDefault();
      hodlShowJournalTool(buttons[next].dataset.journalTool, true);
    };
  });
  hodlInitTabDrag(document.getElementById("journal-tool-tabs"));
  hodlJournalAppend(hodlJournal, { tool: "app", action: "boot" });
  hodlInitJournalActionAudit();
  let notesText = document.getElementById("journal-notes-text");
  let notesCopy = document.getElementById("journal-notes-copy");
  if (notesText) {
    hodlRenderJournalPageTabs();
    hodlJournalRestorePage(notesText);
    setInterval(() => hodlJournalRefreshPendingNote(notesText), 1e3);
    notesText.addEventListener("input", (event) => hodlJournalUpdateNotesText(notesText, event));
    notesText.addEventListener("keydown", (event) => hodlJournalNotesKeydown(event, notesText));
    notesText.addEventListener("scroll", () => hodlJournalSyncPendingPrompt(notesText));
    notesText.addEventListener("click", () => hodlJournalNotesClick(notesText));
    notesText.addEventListener("mousemove", () => hodlJournalRevealCopyButton(notesCopy));
    if (typeof ResizeObserver === "function") new ResizeObserver(() => hodlJournalSyncPendingPrompt(notesText)).observe(notesText);
  }
  if (notesCopy) {
    notesCopy.onclick = () => {
      hodlJournalSyncCopyButton(notesText, notesCopy);
      if (notesCopy.disabled) return;
      hodlCopySeedPhraseButton(notesCopy);
      hodlJournalRevealCopyButton(notesCopy, 1900);
    };
    notesCopy.onfocus = () => {
      clearTimeout(notesCopy.hodlJournalHideTimer);
      notesCopy.classList.add("is-visible");
    };
    notesCopy.onblur = () => notesCopy.classList.remove("is-visible");
  }
  hodlInitTabDrag(document.getElementById("journal-page-tabs"));
  let addPage = document.getElementById("add-journal-page");
  if (addPage) addPage.onclick = hodlAddJournalPage;
  let deletePage = document.getElementById("delete-journal-page");
  if (deletePage) deletePage.onclick = hodlDeleteActiveJournalPage;
  hodlRefreshJournalKeyPicker();
  let keyInsert = document.getElementById("journal-key-insert");
  if (keyInsert) keyInsert.onchange = () => hodlJournalInsertKey(keyInsert, notesText);
  for (let [id, property] of [["journal-font", "font"], ["journal-size", "size"], ["journal-spacing", "spacing"]]) {
    let select = document.getElementById(id);
    if (select) select.onchange = () => hodlJournalSetPageStyle(property, select.value);
  }
  document.querySelectorAll(".journal-encrypt-download").forEach((checkbox) => {
    checkbox.addEventListener("change", () => hodlJournalSyncEncryptDownloads(checkbox));
  });
  hodlJournalSyncEncryptDownloads();
  let notesDownload = document.getElementById("journal-notes-download");
  if (notesDownload) notesDownload.onclick = async () => {
    if (notesText) hodlJournalStoreNotesText(notesText);
    await hodlJournalDownloadContent("notebook", "entropylab-notebook.json", hodlSerializeNotebook(hodlJournal), "application/json;charset=utf-8");
  };
  let notesFile = document.getElementById("journal-notes-file"), notesUpload = document.getElementById("journal-notes-upload");
  if (notesUpload && notesFile) notesUpload.onclick = () => notesFile.click();
  if (notesFile) notesFile.onchange = async () => {
    await hodlJournalImportFile(notesFile.files?.[0]);
    notesFile.value = "";
  };
  hodlInitTabDrag(document.getElementById("journal-keymanager-tabs"));
  let keyManagerDownload = document.getElementById("journal-keymanager-download");
  if (keyManagerDownload) keyManagerDownload.onclick = hodlKeyManagerDownload;
  let keyManagerFile = document.getElementById("journal-keymanager-file"), keyManagerUpload = document.getElementById("journal-keymanager-upload");
  if (keyManagerUpload && keyManagerFile) keyManagerUpload.onclick = () => keyManagerFile.click();
  if (keyManagerFile) keyManagerFile.onchange = async () => {
    await hodlKeyManagerImportFile(keyManagerFile.files?.[0]);
    keyManagerFile.value = "";
  };
  let stateDownload = document.getElementById("journal-state-download");
  if (stateDownload) stateDownload.onclick = async () => {
    hodlJournalRefreshSessionState();
    await hodlJournalDownloadContent("session-state", "entropylab-session.txt", hodlJournal.stateText);
  };
  let logDownload = document.getElementById("journal-log-download");
  if (logDownload) logDownload.onclick = () => hodlJournalDownloadContent("session-log", "entropylab-session-log.txt", hodlJournalFormatLog(hodlJournal.log));
  let logOut = document.getElementById("journal-log-out"), logCopy = document.getElementById("journal-log-copy");
  if (logOut && logCopy) logCopy.onclick = () => {
    logCopy.dataset.phrase = logOut.textContent || "";
    hodlCopySeedPhraseButton(logCopy);
  };
  let logClear = document.getElementById("journal-log-clear");
  if (logClear) logClear.onclick = () => {
    hodlJournal.log.length = 0;
    hodlJournalLog("clear", "session-log", "journal");
  };
  hodlSyncJournalTool();
}
function hodlJournalDownload(filename, text, type = "text/plain;charset=utf-8") {
  let blob = new Blob([text], { type }), url = URL.createObjectURL(blob), link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1e3);
}
function hodlRenderJournalNotes() {
  let field = document.getElementById("journal-notes-text");
  if (!field) return;
  hodlRenderJournalPageTabs();
  hodlJournalApplyPageStyle();
  if (!hodlJournal.notesText) {
    if (!field.dataset.pendingNote) hodlJournalResetPendingNote(field, "Add new note");
    return;
  }
  if (field.value !== hodlJournal.notesText) field.value = hodlJournal.notesText;
  hodlJournalRenderVisual(field);
  if (field.dataset.pendingNote) hodlJournalRenderPendingPrompt(field);
}
var hodlJournalNoteStampPattern = /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}  /;
function hodlJournalLineIndexAt(value, offset) {
  return value.slice(0, offset).split("\n").length - 1;
}
function hodlJournalLineStartAt(value, index) {
  return value.split("\n").slice(0, index).reduce((start, line) => start + line.length + 1, 0);
}
function hodlJournalPendingLineIndex(field) {
  let index = Number(field.dataset.pendingNoteLine);
  return field.dataset.pendingNoteMode === "line" && Number.isInteger(index) && index >= 0 && index < field.value.split("\n").length ? index : -1;
}
function hodlJournalPendingLineStart(field) {
  let index = hodlJournalPendingLineIndex(field);
  return index < 0 ? -1 : hodlJournalLineStartAt(field.value, index);
}
function hodlJournalSyncPendingPrompt(field) {
  if (!field) return;
  let render = document.getElementById("journal-notes-render"), prompt = document.getElementById("journal-notes-prompt");
  if (render) {
    render.style.width = `${field.clientWidth}px`;
    render.style.height = `${field.clientHeight}px`;
    render.scrollTop = field.scrollTop;
    render.scrollLeft = field.scrollLeft;
  }
  if (!prompt || prompt.hidden) return;
  prompt.style.width = `${field.clientWidth}px`;
  prompt.style.height = `${field.clientHeight}px`;
  prompt.scrollTop = field.scrollTop;
  prompt.scrollLeft = field.scrollLeft;
}
function hodlJournalRenderPendingPrompt(field) {
  let prompt = document.getElementById("journal-notes-prompt"), before = document.getElementById("journal-notes-prompt-before"), text = document.getElementById("journal-notes-prompt-text");
  if (!prompt || !before || !text) return;
  let lineStart = hodlJournalPendingLineStart(field), lineEnd = field.value.indexOf("\n", lineStart);
  if (lineStart < 0) return;
  before.textContent = field.value.slice(0, lineEnd < 0 ? field.value.length : lineEnd);
  text.textContent = field.dataset.pendingNote;
  field.setAttribute("aria-placeholder", field.dataset.pendingNote);
  prompt.hidden = false;
  hodlJournalSyncPendingPrompt(field);
}
function hodlJournalFinishPendingNote(field) {
  delete field.dataset.pendingNote;
  delete field.dataset.pendingNoteMode;
  delete field.dataset.pendingNoteLine;
  let prompt = document.getElementById("journal-notes-prompt");
  if (prompt) prompt.hidden = true;
}
function hodlJournalRefreshPendingNote(field) {
  let index = hodlJournalPendingLineIndex(field);
  if (index < 0) return;
  let lines = field.value.split("\n"), stamp = `${hodlJournalStamp()}  `;
  lines[index] = stamp;
  field.value = lines.join("\n");
  let caret = hodlJournalLineStartAt(field.value, index) + stamp.length;
  field.setSelectionRange(caret, caret);
  hodlJournalStoreNotesText(field);
  hodlJournalRenderPendingPrompt(field);
}
function hodlJournalResetPendingNote(field, label, lineIndex = field.value.split("\n").length - 1) {
  let lines = field.value.split("\n");
  lineIndex = Math.max(0, Math.min(lineIndex, lines.length - 1));
  lines[lineIndex] = "";
  field.value = lines.join("\n");
  field.dataset.pendingNote = label;
  field.dataset.pendingNoteMode = "line";
  field.dataset.pendingNoteLine = String(lineIndex);
  hodlJournalRefreshPendingNote(field);
}
function hodlJournalDeletePendingLine(field) {
  let index = hodlJournalPendingLineIndex(field);
  if (index <= 0) return false;
  let lines = field.value.split("\n"), stamp = lines[index];
  if (!lines[index - 1].trim()) {
    lines[index - 1] = stamp;
    lines.splice(index, 1);
    field.dataset.pendingNoteLine = String(index - 1);
  } else {
    lines.splice(index, 1);
    hodlJournalFinishPendingNote(field);
  }
  field.value = lines.join("\n");
  let caretLine = field.dataset.pendingNote ? index - 1 : Math.min(index - 1, lines.length - 1);
  let caret = hodlJournalLineStartAt(field.value, caretLine) + lines[caretLine].length;
  field.setSelectionRange(caret, caret);
  hodlJournalStoreNotesText(field);
  if (field.dataset.pendingNote) hodlJournalRenderPendingPrompt(field);
  return true;
}
function hodlJournalNotesClick(field) {
  let start = field.selectionStart, end = field.selectionEnd;
  if (start !== end) return;
  let lines = field.value.split("\n"), clicked = hodlJournalLineIndexAt(field.value, start);
  let pending = hodlJournalPendingLineIndex(field);
  if (clicked === pending) {
    let caret = hodlJournalLineStartAt(field.value, pending) + lines[pending].length;
    field.setSelectionRange(caret, caret);
    return;
  }
  if (lines[clicked].trim()) {
    if (pending >= 0) {
      let removedLength = lines[pending].length;
      lines[pending] = "";
      field.value = lines.join("\n");
      if (pending < clicked) {
        start -= removedLength;
        end -= removedLength;
      }
      hodlJournalFinishPendingNote(field);
      field.setSelectionRange(start, end);
      hodlJournalStoreNotesText(field);
    }
    return;
  }
  let stamp = pending >= 0 ? lines[pending] : `${hodlJournalStamp()}  `;
  if (pending >= 0) lines[pending] = "";
  lines[clicked] = stamp;
  field.value = lines.join("\n");
  field.dataset.pendingNote = "Add new note";
  field.dataset.pendingNoteMode = "line";
  field.dataset.pendingNoteLine = String(clicked);
  let caret = hodlJournalLineStartAt(field.value, clicked) + stamp.length;
  field.setSelectionRange(caret, caret);
  hodlJournalStoreNotesText(field);
  hodlJournalRenderPendingPrompt(field);
}
function hodlJournalNoteCount(text) {
  return String(text).split("\n").filter((line) => hodlJournalNoteStampPattern.test(line) && line.replace(hodlJournalNoteStampPattern, "").trim()).length;
}
function hodlJournalUpdateNotesText(field, event) {
  let previousCount = hodlJournalNoteCount(hodlJournal.notesText), start = field.selectionStart, end = field.selectionEnd;
  let cursor = 0, stamp = `${hodlJournalStamp()}  `, addedBeforeStart = 0, addedBeforeEnd = 0;
  let lines = field.value.split("\n").map((line) => {
    let lineStart = cursor, shouldStamp = line.trim().length > 0 && !hodlJournalNoteStampPattern.test(line);
    cursor += line.length + 1;
    if (!shouldStamp) return line;
    if (lineStart <= start) addedBeforeStart += stamp.length;
    if (lineStart <= end) addedBeforeEnd += stamp.length;
    return stamp + line;
  });
  let value = lines.join("\n");
  if (value !== field.value) {
    field.value = value;
    field.setSelectionRange(start + addedBeforeStart, end + addedBeforeEnd);
  }
  let deleting = event?.inputType?.startsWith("delete");
  let pending = hodlJournalPendingLineIndex(field);
  let active = deleting ? hodlJournalLineIndexAt(field.value, field.selectionStart) : pending >= 0 ? pending : hodlJournalLineIndexAt(field.value, field.selectionStart);
  let lineStart = hodlJournalLineStartAt(field.value, active), lineEnd = field.value.indexOf("\n", lineStart);
  let line = field.value.slice(lineStart, lineEnd < 0 ? field.value.length : lineEnd);
  let emptyStampedLine = hodlJournalNoteStampPattern.test(line) && !line.replace(hodlJournalNoteStampPattern, "").trim();
  if (!field.value) hodlJournalResetPendingNote(field, "Add new note");
  else if (emptyStampedLine || deleting && !line.trim()) {
    hodlJournalResetPendingNote(field, "Add new note", active);
  } else hodlJournalFinishPendingNote(field);
  hodlJournalStoreNotesText(field);
  let nextCount = hodlJournalNoteCount(field.value);
  for (let count = previousCount; count < nextCount; count++) hodlJournalLog("note-add", "", "journal");
  for (let count = nextCount; count < previousCount; count++) hodlJournalLog("note-delete", "", "journal");
}
function hodlJournalNotesKeydown(event, field) {
  let pendingIndex = hodlJournalPendingLineIndex(field), pendingStart = hodlJournalPendingLineStart(field);
  if (pendingStart >= 0 && hodlJournalLineIndexAt(field.value, field.selectionStart) === pendingIndex) {
    if (event.key === "Enter") {
      event.preventDefault();
      let lines = field.value.split("\n");
      lines[pendingIndex] = "";
      lines.splice(pendingIndex + 1, 0, "");
      field.value = lines.join("\n");
      hodlJournalResetPendingNote(field, "Add new note", pendingIndex + 1);
      return;
    }
    if (event.key === "Backspace" || event.key === "Delete") {
      event.preventDefault();
      hodlJournalDeletePendingLine(field);
      return;
    }
  }
  if (event.key !== "Enter" || event.altKey || event.ctrlKey || event.metaKey) return;
  let start = field.selectionStart, end = field.selectionEnd, value = field.value;
  let currentLine = hodlJournalLineIndexAt(value, start);
  let lineStart = value.lastIndexOf("\n", start - 1) + 1, nextBreak = value.indexOf("\n", end);
  let lineEnd = nextBreak < 0 ? value.length : nextBreak, line = value.slice(lineStart, lineEnd);
  if (!line.trim()) return;
  event.preventDefault();
  let hasSuffix = value.slice(end, lineEnd).length > 0;
  let stamp = `${hodlJournalStamp()}  `;
  field.setRangeText(`\n${stamp}`, start, end, "end");
  if (!hasSuffix) {
    field.dataset.pendingNote = "Add new note";
    field.dataset.pendingNoteMode = "line";
    field.dataset.pendingNoteLine = String(currentLine + 1);
    hodlJournalRenderPendingPrompt(field);
  }
  hodlJournalStoreNotesText(field);
}
function hodlRenderJournalLog() {
  let out = document.getElementById("journal-log-out");
  if (out) out.textContent = hodlJournalFormatLog(hodlJournal.log);
}
function hodlJournalRefreshSessionState() {
  let includePrivate = Boolean(document.getElementById("journal-state-private")?.checked);
  let build = document.querySelector(".page-footer-build");
  let commit = document.getElementById("page-footer-lifehash")?.dataset.commit || "";
  let keys = (hodlKeys || []).map((state) => {
    if (!state.result) return { name: state.name, isLab: state.isLab, mode: state.mode, derived: false };
    let sheet = "";
    try { sheet = hodlRecoverySheetText(state.result, includePrivate); } catch (e) { sheet = ""; }
    return {
      name: state.name,
      isLab: state.isLab,
      mode: state.mode,
      derived: true,
      fingerprint: state.result.masterFingerprint || "",
      sheet,
    };
  });
  let msigs = (hodlMsigs || []).map((state) => {
    if (!state.result) return { name: state.name, derived: false };
    let sheet = "";
    try { sheet = hodlRecoverySheetText(state.result, includePrivate); } catch (e) { sheet = ""; }
    let summary = state.result.m && state.result.n ? `${state.result.m}-of-${state.result.n}` : "";
    return { name: state.name, derived: true, summary, sheet };
  });
  let bip85 = (hodlBip85Children || []).filter((state) => !state.isLab && state.result).map((state) => ({
    name: state.name,
    fingerprint: state.fingerprint || "",
    app: state.result.app || "",
    secret: includePrivate ? (state.result.secret || "") : "",
  }));
  let sp = { derived: Boolean(hodlSpKeys?.fingerprint), fingerprint: hodlSpKeys?.fingerprint || "", address: "" };
  let addressEl = document.getElementById("sp-address");
  if (addressEl) sp.address = addressEl.textContent || addressEl.value || "";
  let psbt = {
    loaded: Boolean((document.getElementById("psbt-text")?.value || "").trim() || (document.getElementById("psbted-text")?.value || "").trim()),
    nonce: hodlPsbtNonceVerdict,
    nonceKind: hodlPsbtNonceVerdictKind,
  };
  let text = hodlJournalSnapshot({
    capturedAt: hodlJournalStamp(),
    version: build?.textContent?.match(/v[\d.]+/)?.[0] || "",
    commit: commit.slice(0, 7),
    includePrivate,
    keys,
    msigs,
    bip85,
    sp,
    psbt,
  });
  hodlJournal.stateText = text;
  let field = document.getElementById("journal-state-text");
  if (field) field.value = text;
}
function hodlScheduleJournalStateRefresh() {
  if (hodlJournalStateRefreshQueued) return;
  hodlJournalStateRefreshQueued = true;
  queueMicrotask(() => {
    hodlJournalStateRefreshQueued = false;
    if (hodlJournalUnlocked()) hodlJournalRefreshSessionState();
  });
}
// The encrypted entropy notebook gates the Journal tools and keeps its
// document and Web Crypto keys apart from the session notepad.
var hodlJournalKeys = null, hodlJournalDoc = null, hodlJournalFileText = "", hodlJournalDirty = false, hodlJournalGate = "create", hodlJournalReveal = false, hodlJournalEditingId = null, hodlJournalDeleteArmed = false;
function hodlJournalError(message) {
  let error = document.getElementById("journal-error");
  if (error) error.textContent = message || "";
}
function hodlJournalWipeNotebook() {
  hodlJournalWipeDocument(hodlJournalDoc);
  hodlJournalDoc = null;
  // The AES-GCM and HMAC CryptoKeys are non-extractable, so the only wipeable
  // bytes are the verify digest; nulling dereferences the keys themselves.
  if (hodlJournalKeys) hodlJournalWipeBytes(hodlJournalKeys.verify);
  hodlJournalKeys = null;
  hodlJournalFileText = "";
  hodlJournalDirty = false;
  hodlJournalReveal = false;
  hodlJournalEditingId = null;
  hodlJournalDeleteArmed = false;
}
function hodlJournalCopy(button, label) {
  let phrase = button?.dataset.phrase;
  if (phrase == null || button.disabled) return;
  let done = () => {
    button.textContent = "Copied";
    clearTimeout(button.hodlCopiedTimer);
    button.hodlCopiedTimer = setTimeout(() => {
      if (button.isConnected) button.textContent = label;
    }, 1600);
  };
  let fallback = () => {
    let field = document.createElement("textarea");
    field.value = phrase;
    field.setAttribute("readonly", "");
    field.style.position = "fixed";
    field.style.left = "-9999px";
    document.body.appendChild(field);
    field.select();
    try {
      document.execCommand("copy");
      done();
    } finally {
      field.remove();
    }
  };
  if (navigator.clipboard && typeof navigator.clipboard.writeText === "function") navigator.clipboard.writeText(phrase).then(done).catch(fallback);
  else fallback();
}
function hodlJournalClearFields() {
  for (let id of ["journal-create-password", "journal-create-confirm", "journal-open-password", "journal-input", "journal-phrase", "journal-label", "journal-entry-notes", "journal-search"]) {
    let field = document.getElementById(id);
    if (field) field.value = "";
  }
  let file = document.getElementById("journal-file");
  if (file) file.value = "";
  let list = document.getElementById("journal-list"), view = document.getElementById("journal-view"), error = document.getElementById("journal-error");
  if (list) list.innerHTML = "";
  if (view) view.innerHTML = "";
  if (error) error.textContent = "";
}
function hodlJournalSetPasswordValidation(input, status, valid, message) {
  if (!input || !status) return;
  status.hidden = !message;
  status.textContent = message;
  status.classList.toggle("is-valid", Boolean(message && valid));
  status.classList.toggle("is-invalid", Boolean(message && !valid));
  input.setAttribute("aria-invalid", String(Boolean(message && !valid)));
}
function hodlSyncJournalCreatePasswordValidation() {
  let password = document.getElementById("journal-create-password"),
      confirm = document.getElementById("journal-create-confirm"),
      passwordStatus = document.getElementById("journal-create-password-status"),
      confirmStatus = document.getElementById("journal-create-confirm-status"),
      ready = document.getElementById("journal-create-ready");
  if (!password || !confirm) return;
  let passwordValue = password.value,
      passwordLongEnough = Array.from(passwordValue).length >= hodlJournalPasswordMinLength;
  hodlJournalSetPasswordValidation(
    password,
    passwordStatus,
    passwordLongEnough,
    !passwordValue ? "" : passwordLongEnough ? "\u2713 Password is long enough" : "Password has too few characters",
  );
  let confirmValue = confirm.value,
      passwordsMatch = confirmValue === passwordValue;
  hodlJournalSetPasswordValidation(
    confirm,
    confirmStatus,
    passwordsMatch,
    !confirmValue ? "" : passwordsMatch ? "\u2713 Passwords match" : "Passwords do not match",
  );
  if (ready) ready.hidden = !(passwordLongEnough && confirmValue && passwordsMatch);
}
function hodlJournalSetGate(mode) {
  hodlJournalGate = mode === "open" ? "open" : "create";
  document.querySelectorAll("#journal-gate-modes [data-journal-gate]").forEach((button) => {
    let active = button.dataset.journalGate === hodlJournalGate;
    button.classList.toggle("active", active);
    button.setAttribute("aria-pressed", String(active));
  });
  let create = document.getElementById("journal-create-panel"), open = document.getElementById("journal-open-panel");
  if (create) create.hidden = hodlJournalGate !== "create";
  if (open) open.hidden = hodlJournalGate !== "open";
  hodlSyncJournalCreatePasswordValidation();
}
function hodlJournalUnlocked() {
  return Boolean(hodlJournalKeys && hodlJournalDoc);
}
function hodlJournalNoteText() {
  if (!hodlJournalDoc) return "Create a journal or open an encrypted file.";
  let n = hodlJournalDoc.entries.length;
  let unsaved = hodlJournalDirty ? " Unsaved changes \u2014 save the encrypted file before locking." : "";
  if (!n) return "No entries yet. Save the encrypted file after you add one." + unsaved;
  return `${n} ${n === 1 ? "entry" : "entries"} in this page only.${unsaved}`;
}
function hodlJournalFillLifehash(image, digest) {
  if (!image) return;
  if (!(digest instanceof Uint8Array) || typeof hodlLifeHash?.fromDigest !== "function") {
    image.hidden = true;
    image.removeAttribute("src");
    return;
  }
  hodlLifeHash.fromDigest(digest).then((url) => {
    if (!image.isConnected) return;
    image.src = url;
    image.hidden = false;
  }).catch(() => {
    image.hidden = true;
  });
}
function hodlJournalFillFingerprint(image, fingerprint) {
  if (!image) return;
  if (!fingerprint || typeof hodlLifeHash?.fromFingerprint !== "function") {
    image.hidden = true;
    image.removeAttribute("src");
    return;
  }
  hodlLifeHash.fromFingerprint(fingerprint).then((url) => {
    if (!image.isConnected) return;
    image.src = url;
    image.hidden = false;
  }).catch(() => {
    image.hidden = true;
  });
}
function hodlJournalFillWallets(selected) {
  let select = document.getElementById("journal-wallet");
  if (!select) return;
  let current = selected == null ? select.value : String(selected);
  select.innerHTML = "";
  let none = document.createElement("option");
  none.value = "";
  none.textContent = "None";
  select.append(none);
  hodlKeys.filter((state) => !state.isLab).forEach((state) => {
    let option = document.createElement("option");
    option.value = String(state.id);
    option.textContent = state.name || `Key ${state.number}`;
    select.append(option);
  });
  select.value = [...select.options].some((option) => option.value === current) ? current : "";
}
function hodlJournalShowWork() {
  let locked = document.getElementById("journal-locked-panel"), work = document.getElementById("journal-work-panel");
  let unlocked = hodlJournalUnlocked();
  if (locked) locked.hidden = unlocked;
  if (work) work.hidden = !unlocked;
  for (let id of ["journal-global-download", "journal-global-clear"]) {
    let button = document.getElementById(id);
    if (!button) continue;
    button.disabled = !unlocked;
    button.setAttribute("aria-disabled", String(!unlocked));
  }
  let note = document.getElementById("journal-status-note");
  if (note) note.textContent = hodlJournalNoteText();
  hodlJournalFillLifehash(document.getElementById("journal-lifehash"), hodlJournalKeys?.verify);
  hodlJournalRenderList();
}
function hodlJournalRenderList() {
  let box = document.getElementById("journal-list");
  if (!box) return;
  if (!hodlJournalDoc) {
    box.innerHTML = "";
    return;
  }
  let entries = hodlJournalSearch(hodlJournalDoc, document.getElementById("journal-search")?.value || "");
  if (!entries.length) {
    box.innerHTML = `<p class="journal-empty">${hodlJournalDoc.entries.length ? "No labels match that search." : "No entries yet."}</p>`;
    return;
  }
  box.innerHTML = entries.map((entry) => `<button type="button" class="journal-item" data-journal-id="${entry.id}">
      <img class="journal-item-lifehash" alt="" width="32" height="32" hidden>
      <span class="journal-item-label">${hodlEscapeHtml(entry.label)}</span>
      <span class="journal-item-meta">${hodlEscapeHtml(hodlJournalMethodLabels[entry.method] || entry.method)} \xB7 ${hodlEscapeHtml(String(entry.created).slice(0, 10))}</span>
    </button>`).join("");
  [...box.querySelectorAll(".journal-item")].forEach((button, index) => {
    let entry = entries[index];
    hodlJournalFillFingerprint(button.querySelector(".journal-item-lifehash"), entry.fingerprint);
    button.onclick = () => hodlJournalOpenView(entry.id);
  });
}
function hodlJournalHideEditor() {
  hodlJournalEditingId = null;
  let editor = document.getElementById("journal-editor"), view = document.getElementById("journal-view"), list = document.getElementById("journal-list");
  if (editor) editor.hidden = true;
  if (view) {
    view.hidden = true;
    view.innerHTML = "";
  }
  if (list) list.hidden = false;
  for (let id of ["journal-input", "journal-phrase", "journal-label", "journal-entry-notes"]) {
    let field = document.getElementById(id);
    if (field) field.value = "";
  }
  let method = document.getElementById("journal-method");
  if (method) method.value = "dice";
  hodlJournalFillWallets("");
}
function hodlJournalApplySnapshot(snapshot) {
  if (!snapshot) throw new Error("Derive a key first, then return to the journal.");
  let method = document.getElementById("journal-method");
  if (method) method.value = snapshot.method;
  let input = document.getElementById("journal-input");
  if (input) input.value = snapshot.input;
  let phrase = document.getElementById("journal-phrase");
  if (phrase) phrase.value = snapshot.phrase;
  let label = document.getElementById("journal-label");
  if (label && !label.value.trim()) label.value = snapshot.label;
  let notes = document.getElementById("journal-entry-notes");
  if (notes && !notes.value.trim()) notes.value = snapshot.notes;
  hodlJournalFillWallets(snapshot.walletId ?? "");
}
function hodlJournalShowEditor(entry) {
  if (!hodlJournalUnlocked()) throw new Error("Create or open a journal first.");
  hodlJournalEditingId = entry?.id ?? null;
  hodlJournalDeleteArmed = false;
  document.getElementById("journal-list").hidden = true;
  document.getElementById("journal-view").hidden = true;
  document.getElementById("journal-view").innerHTML = "";
  document.getElementById("journal-editor").hidden = false;
  document.getElementById("journal-method").value = entry?.method || "dice";
  document.getElementById("journal-input").value = entry?.input || "";
  document.getElementById("journal-phrase").value = entry?.phrase || "";
  document.getElementById("journal-label").value = entry?.label || "";
  document.getElementById("journal-entry-notes").value = entry?.notes || "";
  hodlJournalFillWallets(entry?.walletId ?? "");
}
function hodlJournalPrivateValue(value) {
  let mask = "************", text = String(value ?? "\u2014");
  if (hodlJournalReveal) return `<span class="secret private-field-value">${hodlEscapeHtml(text)}</span>`;
  let bullets = "\u2022".repeat(Math.max(Array.from(text).length, mask.length));
  return `<span class="secret private-field-value secret-placeholder"><span class="secret-placeholder-mask" aria-hidden="true">${bullets}</span><span class="secret-placeholder-message" aria-hidden="true">${mask}</span><span class="secret-placeholder-label">Private value hidden</span></span>`;
}
function hodlJournalOpenView(id) {
  let entry = hodlJournalDoc?.entries.find((item) => item.id === id);
  if (!entry) return;
  // Only a different entry re-masks the seed: the reveal toggle re-renders
  // this same view, and resetting here would undo it before the paint.
  if (hodlJournalEditingId !== id) hodlJournalReveal = false;
  hodlJournalEditingId = id;
  hodlJournalDeleteArmed = false;
  document.getElementById("journal-editor").hidden = true;
  document.getElementById("journal-list").hidden = true;
  let view = document.getElementById("journal-view");
  view.hidden = false;
  let wallet = entry.walletName || (entry.walletId != null ? `Key ${entry.walletId}` : "");
  view.innerHTML = `<section class="wallet-data-section wallet-private-section" aria-labelledby="journal-entry-heading">
      <div class="wallet-data-section-head">
        <h3 id="journal-entry-heading">${hodlEscapeHtml(entry.label)}</h3>
        <p class="muted" id="journal-private-description">Anyone with the journal file and the journal password can read this entry.</p>
      </div>
      <div class="wallet-data-actions no-print">
        <label class="reveal-private-toggle">
          <input type="checkbox" id="journal-reveal" ${hodlJournalReveal ? "checked" : ""} aria-describedby="journal-private-description">
          <span>Show seed <span class="reveal-private-toggle-note">(air-gap only)</span></span>
        </label>
        <button class="btn secondary" id="journal-copy-input" type="button">Copy input</button>
        <button class="btn secondary" id="journal-copy-phrase" type="button">Copy seed</button>
        <button class="btn secondary" id="journal-edit" type="button">Edit</button>
        <button class="btn secondary" id="journal-delete" type="button">Delete</button>
        <button class="btn secondary" id="journal-back" type="button">Back</button>
      </div>
      <div class="wallet-data-fields">
        ${hodlPublicFieldHtml("Method", hodlJournalMethodLabels[entry.method] || entry.method)}
        ${hodlPublicFieldHtml("Recorded", entry.created)}
        ${wallet ? hodlPublicFieldHtml("Session wallet", wallet) : ""}
        ${entry.fingerprint ? hodlPublicFieldHtml("Master fingerprint", entry.fingerprint) : ""}
        ${hodlPublicFieldHtml("Raw input", entry.input || "\u2014")}
        <p class="private-field"><span class="muted">BIP39 seed or passphrase</span>${hodlJournalPrivateValue(entry.phrase)}</p>
        ${entry.notes ? hodlPublicFieldHtml("Notes", entry.notes) : ""}
      </div>
    </section>`;
  document.getElementById("journal-reveal")?.addEventListener("change", (event) => {
    hodlJournalReveal = event.target.checked;
    hodlJournalOpenView(id);
    requestAnimationFrame(() => document.getElementById("journal-reveal")?.focus({ preventScroll: true }));
  });
  let copyInput = document.getElementById("journal-copy-input");
  if (copyInput) {
    copyInput.dataset.phrase = entry.input;
    copyInput.onclick = () => hodlJournalCopy(copyInput, "Copy input");
  }
  let copyPhrase = document.getElementById("journal-copy-phrase");
  if (copyPhrase) {
    copyPhrase.dataset.phrase = entry.phrase;
    copyPhrase.onclick = () => hodlJournalCopy(copyPhrase, "Copy seed");
  }
  document.getElementById("journal-edit").onclick = () => hodlJournalShowEditor(entry);
  document.getElementById("journal-back").onclick = () => {
    hodlJournalHideEditor();
    hodlJournalRenderList();
  };
  document.getElementById("journal-delete").onclick = () => {
    if (!hodlJournalDeleteArmed) {
      hodlJournalDeleteArmed = true;
      document.getElementById("journal-delete").textContent = "Confirm delete";
      return;
    }
    hodlJournalRemoveEntry(hodlJournalDoc, id);
    hodlJournalDirty = true;
    hodlJournalLog("entry-delete", entry.fingerprint || entry.label.slice(0, 60));
    hodlJournalHideEditor();
    hodlJournalShowWork();
  };
}
async function hodlJournalCreate() {
  hodlJournalError("");
  try {
    let created = await hodlJournalCreateDocument(document.getElementById("journal-create-password")?.value || "", document.getElementById("journal-create-confirm")?.value || "");
    hodlKeyManagerReset();
    hodlJournalWipeNotebook();
    hodlJournalKeys = created.keys;
    hodlJournalDoc = created.doc;
    hodlJournalDirty = true;
    document.getElementById("journal-create-password").value = "";
    document.getElementById("journal-create-confirm").value = "";
    hodlJournalHideEditor();
    hodlJournalShowWork();
    hodlShowJournalTool("notes");
    hodlJournalLog("journal-create");
  } catch (exception) {
    hodlJournalError(exception.message || String(exception));
  }
}
async function hodlJournalUnlock() {
  hodlJournalError("");
  try {
    if (!hodlJournalFileText) throw new Error("Choose an encrypted journal file first.");
    let opened = await hodlJournalOpenDocument(hodlJournalFileText, document.getElementById("journal-open-password")?.value || "");
    hodlKeyManagerReset();
    hodlJournalWipeNotebook();
    hodlJournalKeys = opened.keys;
    hodlJournalDoc = opened.doc;
    hodlJournalDirty = false;
    document.getElementById("journal-open-password").value = "";
    document.getElementById("journal-file").value = "";
    hodlJournalFileText = "";
    hodlJournalHideEditor();
    hodlJournalShowWork();
    hodlShowJournalTool("notes");
    hodlJournalLog("journal-unlock", `${opened.doc.entries.length} entries`);
  } catch (exception) {
    hodlJournalError(exception.message || String(exception));
  }
}
async function hodlJournalSaveFile() {
  hodlJournalError("");
  try {
    if (!hodlJournalUnlocked()) throw new Error("Create or open a journal first.");
    let file = await hodlJournalSealDocument(hodlJournalDoc, hodlJournalKeys);
    let blob = new Blob([JSON.stringify(file, null, 2) + "\n"], { type: "application/json" }), url = URL.createObjectURL(blob), link = document.createElement("a");
    link.href = url;
    link.download = "entropylab-journal.json";
    link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1e3);
    hodlJournalDirty = false;
    hodlJournalShowWork();
    hodlJournalLog("journal-save", `${hodlJournalDoc.entries.length} entries`);
  } catch (exception) {
    hodlJournalError(exception.message || String(exception));
  }
}
function hodlJournalCommit() {
  hodlJournalError("");
  try {
    if (!hodlJournalUnlocked()) throw new Error("Create or open a journal first.");
    let wallet = document.getElementById("journal-wallet");
    let walletId = wallet?.value ? Number(wallet.value) : null;
    let state = walletId == null ? null : hodlKeys.find((item) => item.id === walletId);
    let fields = {
      method: document.getElementById("journal-method")?.value || "dice",
      input: document.getElementById("journal-input")?.value || "",
      phrase: document.getElementById("journal-phrase")?.value || "",
      label: document.getElementById("journal-label")?.value || "",
      notes: document.getElementById("journal-entry-notes")?.value || "",
      walletId,
      walletName: state?.name || "",
      fingerprint: state?.result?.masterFingerprint || "",
    };
    if (hodlJournalEditingId) hodlJournalReplaceEntry(hodlJournalDoc, hodlJournalEditingId, fields);
    else hodlJournalAddEntry(hodlJournalDoc, fields);
    hodlJournalDirty = true;
    hodlJournalLog(hodlJournalEditingId ? "entry-edit" : "entry-add", fields.fingerprint || fields.label.slice(0, 60));
    hodlJournalHideEditor();
    hodlJournalShowWork();
  } catch (exception) {
    hodlJournalError(exception.message || String(exception));
  }
}
function hodlJournalUseActiveKey() {
  hodlJournalError("");
  try {
    if (hodlWorkspace === "calc") hodlCaptureKey();
    hodlJournalApplySnapshot(hodlJournalKeySnapshot(hodlKeys[hodlActiveKey]));
  } catch (exception) {
    hodlJournalError(exception.message || String(exception));
  }
}
function hodlJournalLock() {
  hodlKeyManagerReset();
  hodlJournalWipeNotebook();
  hodlJournalClearFields();
  hodlJournalHideEditor();
  hodlJournalSetGate("create");
  hodlJournalTool = "book";
  hodlJournalShowWork();
  hodlSyncJournalTool();
  hodlJournalLog("journal-lock");
  document.getElementById("journal-status-note").textContent = "Journal locked. Password and entries were cleared (best effort).";
}
function hodlInitJournalNotebook() {
  if (!document.getElementById("journal-create")) return;
  for (let id of ["journal-create-password", "journal-create-confirm"]) {
    document.getElementById(id)?.addEventListener("input", hodlSyncJournalCreatePasswordValidation);
  }
  document.querySelectorAll("#journal-gate-modes [data-journal-gate]").forEach((button) => {
    button.onclick = () => hodlJournalSetGate(button.dataset.journalGate);
  });
  document.getElementById("journal-create")?.addEventListener("click", hodlJournalCreate);
  document.getElementById("journal-unlock")?.addEventListener("click", hodlJournalUnlock);
  document.getElementById("journal-file")?.addEventListener("change", async (event) => {
    hodlJournalError("");
    let file = event.target.files?.[0];
    hodlJournalFileText = file ? await file.text() : "";
  });
  document.getElementById("journal-add")?.addEventListener("click", () => {
    hodlJournalError("");
    try { hodlJournalShowEditor(null); } catch (exception) { hodlJournalError(exception.message || String(exception)); }
  });
  document.getElementById("journal-save")?.addEventListener("click", hodlJournalSaveFile);
  document.getElementById("journal-lock")?.addEventListener("click", hodlJournalLock);
  document.getElementById("journal-global-download")?.addEventListener("click", hodlJournalSaveFile);
  document.getElementById("journal-global-clear")?.addEventListener("click", hodlJournalWipeMem);
  document.getElementById("journal-commit")?.addEventListener("click", hodlJournalCommit);
  document.getElementById("journal-use-calc")?.addEventListener("click", hodlJournalUseActiveKey);
  document.getElementById("journal-cancel")?.addEventListener("click", () => {
    hodlJournalHideEditor();
    hodlJournalRenderList();
  });
  document.getElementById("journal-search")?.addEventListener("input", hodlJournalRenderList);
  let open = document.getElementById("journal-open");
  if (open) open.onclick = () => {
    if (hodlWorkspace === "calc") hodlCaptureKey();
    hodlShowWorkspace("journal");
    hodlShowJournalTool("book");
    hodlJournalError("");
    try {
      if (!hodlJournalUnlocked()) {
        hodlJournalError("Create or open a journal, then save this key into it.");
        return;
      }
      hodlJournalShowEditor(null);
      hodlJournalUseActiveKey();
    } catch (exception) {
      hodlJournalError(exception.message || String(exception));
    }
  };
  hodlJournalSetGate("create");
  hodlJournalShowWork();
}
function hodlJournalWipeMem() {
  wipeJournal(hodlJournal);
  hodlKeyManagerReset();
  hodlJournalWipeNotebook();
  hodlJournalClearFields();
  hodlJournalHideEditor();
  hodlJournalSetGate("create");
  hodlJournalTool = "book";
  hodlJournalEncryptDownloads = true;
  hodlJournalSyncEncryptDownloads();
  hodlJournalShowWork();
  hodlSyncJournalTool();
  let field = document.getElementById("journal-state-text");
  if (field) field.value = "";
  let privateBox = document.getElementById("journal-state-private");
  if (privateBox) privateBox.checked = false;
  let notes = document.getElementById("journal-notes-text");
  if (notes) {
    notes.value = "";
    hodlJournalResetPendingNote(notes, "Add new note");
  }
  hodlRenderJournalPageTabs();
  hodlJournalApplyPageStyle();
  hodlJournalSetStatus("");
  let log = document.getElementById("journal-log-out");
  if (log) log.textContent = "No events yet.";
}
// The switcher keeps every tool on screen as a folder-tab strip that scrolls
// when it must, in the shape the Keys section uses for its own tabs.
function hodlWorkspaceTabKeydown(event, index) {
  let next = null, length = hodlWorkspaceTabs.length;
  if (event.key === "ArrowRight") next = (index + 1) % length;
  else if (event.key === "ArrowLeft") next = (index - 1 + length) % length;
  else if (event.key === "Home") next = 0;
  else if (event.key === "End") next = length - 1;
  if (next === null) return;
  event.preventDefault();
  hodlShowWorkspace(hodlWorkspaceTabs[next][0]);
  hodlElement("#workspace-tabs").querySelectorAll("[data-workspace]")[next]?.focus();
}
function hodlSyncWorkspaceOverflow() {
  let strip = document.getElementById("workspace-tabs"), hint = document.getElementById("workspace-more");
  if (!strip || !hint) return;
  hint.hidden = strip.scrollWidth - strip.clientWidth - strip.scrollLeft <= 1;
}
// ── Vanity grinder (workspace tab) ─────────────────────────────────────────
// The engine (src/js/vanity.js + vanity-wasm) is a calculator over one Key
// Station key: the passphrase grind extends the key's BIP39 passphrase with
// counter characters, the derivation grind steps through account indexes with
// the passphrase fixed, and every candidate is derived the standard way
// (PBKDF2 seed → BIP32 path → address). A match therefore names a passphrase
// or an account index of a wallet the user already holds, and Update key
// writes it back to that key through the same Edit input → Derive path the
// Keys tab uses by hand.
var hodlVanityGrinder = null, hodlVanityMatches = [], hodlVanityFound = 0, hodlVanityRunning = false, hodlVanityReveal = false, hodlVanityDisplayLimit = 100, hodlVanitySource = "", hodlVanityRun = null, hodlVanityApplying = false, hodlVanityStopFirst = false, hodlVanityBench = null, hodlVanityBenchPending = false, hodlVanityLiveRate = 0;
// Only derived HD-root keys are listed — the same set the BIP-85 and Silent
// Payments pickers offer. The Key Station lab tab is a work surface, not a
// key, so it never appears as a chip.
function hodlVanitySourceKeys() {
  return hodlSessionHdRootKeys();
}
function hodlVanitySourceState() {
  let state = hodlKeys.find((candidate) => "key:" + candidate.id === hodlVanitySource);
  return state && hodlVanitySourceKeys().includes(state) ? state : null;
}
function hodlVanityKeyLabel(state) {
  return state ? state.result?.masterFingerprint || state.name || "Key " + state.number : "";
}
function hodlPickVanitySessionKey(state) {
  let error = document.getElementById("vanity-error");
  if (error) error.textContent = "";
  if (!state) return;
  if (hodlVanitySource !== "key:" + state.id) {
    // Results belong to the key they were ground on.
    hodlVanityCancel();
    hodlVanityClearResults();
  }
  hodlVanitySource = "key:" + state.id;
  hodlVanitySyncSource();
  hodlRefreshStationKeyPickers();
}
function hodlVanityMethod() {
  let value = document.getElementById("vanity-method")?.value;
  return VANITY_METHODS[value] ? value : "passphrase";
}
function hodlVanityScriptId() {
  let value = document.getElementById("vanity-script")?.value;
  return VANITY_SCRIPTS[value] ? value : "p2wpkh";
}
function hodlVanityScript() {
  return VANITY_SCRIPTS[hodlVanityScriptId()];
}
function hodlVanityFormatCount(value) {
  return BigInt(value).toLocaleString("en-US");
}
function hodlFilterVanityPrefix(value, meta = hodlVanityScript()) {
  let text = String(value ?? "");
  if (meta.bech32) {
    let allowed = new Set((meta.prefix + "bc1qpzry9x8gf2tvdw0s3jn54khce6mua7l").split(""));
    return [...text.toLowerCase()].filter((character) => !/\s/.test(character) && allowed.has(character)).join("");
  }
  return [...text].filter((character) => !/\s/.test(character) && "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".includes(character)).join("");
}
function hodlVanitySyncScriptNote() {
  let meta = hodlVanityScript(), help = document.getElementById("vanity-prefix-help"), input = document.getElementById("vanity-prefix");
  if (help) {
    help.textContent = meta.firstFree
      ? `${meta.label} code, starts with “${meta.prefix}”; the next character is one of ${[...meta.firstFree].join(" ")} (the scan key's parity). Live-filtered to lowercase bech32 characters; each further free character multiplies the work by ~32.`
      : meta.bech32
        ? `${meta.label} prefix, starts with “${meta.prefix}”. Live-filtered to lowercase bech32 characters; each free character multiplies the work by ~32.`
        : `${meta.label} prefix, starts with “${meta.prefix}”. Live-filtered to base58 characters; each free character multiplies the work by ~58.`;
  }
  if (input) input.placeholder = `${meta.prefix}…`;
}
// The source panel names the selected key and shows its passphrase exactly as
// entered on the Keys tab: the passphrase grind extends that text, the
// derivation grind uses it as-is, and either way a match is a setting of this
// key. A root-xprv key has no words to stretch, so only the derivation grind
// is offered for it.
function hodlVanitySyncSource() {
  let panel = document.getElementById("vanity-source"), note = document.getElementById("vanity-session-note");
  if (!panel) return;
  let state = hodlVanitySourceState();
  if (!state) hodlVanitySource = "";
  if (note) {
    note.textContent = hodlVanitySourceKeys().length
      ? "Pick the key to grind. Its passphrase and derivation settings come along exactly as set on the Keys tab: a key with seed words supports both methods, a root-xprv key the derivation grind only."
      : "Derive a key on the Keys tab first — the grinder searches that key's passphrase or account index. A key with seed words supports both methods; a root-xprv key supports the derivation grind only.";
  }
  panel.hidden = !state;
  let methodSelect = document.getElementById("vanity-method"), passphraseOption = methodSelect?.querySelector('option[value="passphrase"]');
  if (state) {
    let label = hodlVanityKeyLabel(state), pass = String(state.fields?.pass ?? ""), hasMnemonic = Boolean(state.result?.mnemonic);
    let name = document.getElementById("vanity-source-name"), kind = document.getElementById("vanity-source-kind"), image = document.getElementById("vanity-source-lifehash"), from = document.getElementById("vanity-pass-from"), field = document.getElementById("vanity-pass"), passNote = document.getElementById("vanity-pass-note");
    if (name) name.textContent = label;
    if (kind) kind.textContent = `${hasMnemonic ? "BIP39 seed words" : "Root xprv"}${state.name && state.name !== label ? ` · ${state.name}` : ""} · ${hodlDisplayDerivationPath(state.fields?.derivationPath || "")}`;
    if (image) {
      image.hidden = true;
      hodlFillKeyTabLifehash(image, state.result?.masterFingerprint || "");
    }
    if (from) from.textContent = `· from key ${label}`;
    if (field) field.value = pass;
    if (passNote) {
      passNote.textContent = !hasMnemonic
        ? `Key ${label} was imported as a root xprv: it has no seed words, so its passphrase cannot be extended — only the derivation grind is available.`
        : pass.length
          ? `Copied verbatim from key ${label}'s Optional BIP39 passphrase on the Keys tab. Passphrase grind: candidates are this text followed by the counter characters. Derivation grind: this exact passphrase, with the account index changing.`
          : `Key ${label} has no passphrase. Passphrase grind: candidates are the counter characters alone. Derivation grind: no passphrase, with the account index changing.`;
    }
    if (passphraseOption) passphraseOption.disabled = !hasMnemonic;
    if (!hasMnemonic && methodSelect && methodSelect.value === "passphrase") methodSelect.value = "derivation";
  } else if (passphraseOption) passphraseOption.disabled = false;
  hodlVanitySyncMethod();
  hodlVanitySyncControls();
}
// The method decides which dial the counter turns, so it swaps the range
// fields (odometer counters vs. account indexes) and the help copy.
function hodlVanitySyncMethod() {
  let method = hodlVanityMethod(), help = document.getElementById("vanity-method-help");
  document.querySelectorAll("#vanity-card [data-vanity-method]").forEach((field) => {
    field.hidden = field.dataset.vanityMethod !== method;
  });
  if (help) {
    help.textContent = method === "derivation"
      ? "The passphrase stays as it is; each candidate is the next BIP32 account index at the key's path. A match is an account index holding the vanity address — Update key sets it on the key."
      : "Each candidate is the starting passphrase followed by the counter characters, stretched into a seed (2,048 PBKDF2 rounds) and derived at the key's path. A match is a new passphrase for this key.";
  }
  hodlVanityEstimate();
}
// A short timing sample on tab entry — fixed published constants, never the
// session's keys — measures this device so the estimate can say how long a
// match should take. It runs once per session and only when no grind is on.
function hodlVanityStartBenchmark() {
  if (hodlVanityBench || hodlVanityBenchPending || hodlVanityRunning) return;
  hodlVanityBenchPending = true;
  hodlVanityEstimate();
  vanityBenchmark().then((rates) => {
    hodlVanityBench = rates;
  }).catch(() => {
    hodlVanityBench = null;
  }).finally(() => {
    hodlVanityBenchPending = false;
    hodlVanityEstimate();
  });
}
function hodlVanityFormatDuration(seconds) {
  if (!Number.isFinite(seconds)) return "";
  if (seconds < 1) return "under a second";
  if (seconds < 90) return `${Math.round(seconds)} second${Math.round(seconds) === 1 ? "" : "s"}`;
  let minutes = seconds / 60;
  if (minutes < 90) return `${Math.round(minutes)} minutes`;
  let hours = minutes / 60;
  if (hours < 48) return `${Math.round(hours)} hours`;
  let days = hours / 24;
  if (days < 730) return `${Math.round(days)} days`;
  return `${Math.round(days / 365).toLocaleString("en-US")} years`;
}
// Candidates per second for the current method and address type: the live
// rate while a grind runs, otherwise the benchmark scaled by the worker count.
function hodlVanityExpectedRate() {
  if (hodlVanityRunning && hodlVanityLiveRate > 0) return hodlVanityLiveRate;
  if (!hodlVanityBench) return 0;
  let method = hodlVanityMethod(), sample = method === "derivation" ? (hodlVanityScriptId() === "sp" ? "sp" : "derivation") : "passphrase";
  let workers = Math.max(1, Math.min(64, Number(document.getElementById("vanity-workers")?.value) || 1));
  return (hodlVanityBench[sample] || 0) * workers;
}
function hodlVanityEstimate() {
  let estimateEl = document.getElementById("vanity-estimate"), input = document.getElementById("vanity-prefix"), scriptId = hodlVanityScriptId(), method = hodlVanityMethod();
  if (!estimateEl || !input) return;
  try {
    let prefix = validateVanityPrefix(input.value, scriptId), work = estimateVanityWork(prefix, scriptId), rate = hodlVanityExpectedRate();
    let timing = rate > 0
      ? `At about ${hodlVanityFormatCount(Math.round(rate))} candidates/s${hodlVanityRunning ? "" : ` on ${Math.max(1, Math.min(64, Number(document.getElementById("vanity-workers")?.value) || 1))} worker${Number(document.getElementById("vanity-workers")?.value) === 1 ? "" : "s"}`}, expect a match roughly every ${hodlVanityFormatDuration(Number(work) / rate)}.`
      : hodlVanityBenchPending ? "Measuring this device…" : method === "derivation" ? "Derivation grind: each candidate is a few BIP32 child steps." : "Passphrase grind: each candidate is a full BIP39 seed stretch.";
    estimateEl.textContent = `Prefix “${prefix}” matches about 1 in ${hodlVanityFormatCount(work)} ${hodlVanityScript().label} candidates on average. ${timing}`;
  } catch {
    estimateEl.textContent = "";
  }
}
function hodlVanityToggleStopFirst() {
  hodlVanityStopFirst = !hodlVanityStopFirst;
  hodlVanitySyncControls();
}
// Turns the key's Keys-tab settings into the grind plan: the concrete
// derivation path (the key's own purpose, coin type, account, branch, and
// address index — or the BIP-352 account path for Silent Payments), plus the
// seed words the passphrase grind stretches or the parent node the derivation
// grind hangs account indexes below. Matching is mainnet only, so the key's
// coin type must be 0.
function hodlVanityPlan(state, method, scriptId) {
  if (!state) throw new Error("Pick a Key Station key first — the grinder searches that key's passphrase or account index.");
  let result = state.result || {}, fields = state.fields || {}, label = hodlVanityKeyLabel(state);
  let accountComponents = vanityPathIndexes(fields.derivationAccountPath || "m/84'/0'/0'");
  if (accountComponents.length < 3) throw new Error(`Key ${label}'s derivation path needs purpose, coin type, and account components.`);
  if ((accountComponents[1] & VANITY_MAX_INDEX) !== 0) throw new Error(`Vanity matching is Bitcoin mainnet: key ${label} derives coin type ${accountComponents[1] & VANITY_MAX_INDEX}. Pick a mainnet key (coin type 0).`);
  let index = (text, hardened) => {
    let value = Number(String(text ?? "0").trim().replace(/['hH]$/, ""));
    if (!Number.isInteger(value) || value < 0 || value > VANITY_MAX_INDEX) throw new Error(`Key ${label}'s branch and address indexes must be whole numbers from 0 to 2,147,483,647.`);
    return hardened ? value + VANITY_HARDENED : value;
  };
  let path = scriptId === "sp"
    ? [352 + VANITY_HARDENED, VANITY_HARDENED, (accountComponents[2] & VANITY_MAX_INDEX) + VANITY_HARDENED]
    : [...accountComponents, index(fields.branchStart, Boolean(fields.branchHarden)), index(fields.addressStart, Boolean(fields.addressHarden))];
  let passphrase = validateVanityPassphrase(fields.pass ?? "");
  let plan = { method, script: scriptId, sourceId: state.id, sourceLabel: label, passphrase, accountHardened: path[2] >= VANITY_HARDENED };
  if (method === "passphrase") {
    if (!result.mnemonic) throw new Error(`Key ${label} has no seed words (root xprv), so its passphrase cannot be extended — switch to the derivation grind.`);
    return { ...plan, mnemonic: validateVanityMnemonic(result.mnemonic), path, pathPrefix: [], counterSlot: 0 };
  }
  // Derivation grind: the node above the account is derived once, here, and
  // the workers receive only that node.
  let root;
  if (result.mnemonic) {
    let seed = hodlMnemonicToSeed(result.mnemonic, passphrase);
    try {
      root = hodlHDKey.fromMasterSeed(seed);
    } finally {
      seed.fill(0);
    }
  } else if (result.rootXprv) root = hodlHDKey.fromExtendedKey(hodlParseExtendedKey(result.rootXprv).xkey);
  else throw new Error(`Key ${label} carries neither seed words nor a root xprv.`);
  let parent = null;
  try {
    parent = root.derive(vanityPathString(path.slice(0, 2)));
    if (!parent.privateKey) throw new Error(`Key ${label} is watch-only; the derivation grind needs private material.`);
    let node = new Uint8Array(64);
    node.set(parent.privateKey, 0);
    node.set(parent.chainCode, 32);
    return { ...plan, node, path: path.slice(2), pathPrefix: path.slice(0, 2), counterSlot: 0 };
  } finally {
    parent?.wipePrivateData();
    root.wipePrivateData();
  }
}
function hodlVanityParseInputs() {
  let method = hodlVanityMethod(), scriptId = hodlVanityScriptId();
  let prefix = validateVanityPrefix(document.getElementById("vanity-prefix").value, scriptId);
  let parseCounter = (id, label) => {
    let raw = document.getElementById(id).value.trim();
    if (!/^\d+$/.test(raw)) throw new Error(`${label} is a whole number (digits only).`);
    return BigInt(raw);
  };
  let workers = Math.max(1, Math.min(64, Number(document.getElementById("vanity-workers").value) || 1));
  let plan = hodlVanityPlan(hodlVanitySourceState(), method, scriptId);
  if (method === "derivation") {
    let range = validateVanityIndexRange(parseCounter("vanity-account-start", "The start account"), parseCounter("vanity-account-count", "The account range"));
    return { ...plan, prefix, workers, ...range, passLen: 0 };
  }
  let passLen = Number(document.getElementById("vanity-length").value);
  return { ...plan, prefix, workers, ...validateVanityRange(passLen, parseCounter("vanity-start", "The start counter"), parseCounter("vanity-count", "The range size")) };
}
function hodlCopyVanityValue(button, value, label) {
  if (!value || !button || button.disabled) return;
  let done = () => {
    let note = button.closest(".vanity-secret")?.querySelector(".vanity-copied");
    button.classList.add("is-copied");
    button.innerHTML = hodlCopiedIconMarkup();
    button.setAttribute("aria-label", "Copied");
    button.title = "Copied";
    if (note) note.textContent = "Copied";
    clearTimeout(button.hodlCopiedTimer);
    button.hodlCopiedTimer = setTimeout(() => {
      if (!button.isConnected) return;
      button.classList.remove("is-copied");
      button.innerHTML = hodlClipboardIconMarkup();
      button.setAttribute("aria-label", label);
      button.title = label;
      if (note) note.textContent = "";
    }, 1600);
  };
  let fallback = () => {
    let field = document.createElement("textarea");
    field.value = value;
    field.setAttribute("readonly", "");
    field.style.position = "fixed";
    field.style.left = "-9999px";
    document.body.appendChild(field);
    field.select();
    try {
      document.execCommand("copy");
      done();
    } finally {
      field.remove();
    }
  };
  if (navigator.clipboard && typeof navigator.clipboard.writeText === "function") navigator.clipboard.writeText(value).then(done).catch(fallback);
  else fallback();
}
// The master fingerprint the key will carry once a match is applied: a new
// passphrase is a new seed, so each passphrase-grind row is its own
// fingerprint (computed once from the key's words); an account change keeps
// the key's fingerprint. Rendered with its LifeHash so the row shows the
// identity Update key will leave behind.
function hodlVanityMatchFingerprint(match, run) {
  if (match.fingerprint) return match.fingerprint;
  if (run.method !== "passphrase") return (match.fingerprint = run.sourceLabel);
  let state = hodlKeys.find((candidate) => candidate.id === run.sourceId), mnemonic = state?.result?.mnemonic;
  if (!mnemonic) return "";
  let seed = hodlMnemonicToSeed(mnemonic, match.passphrase), root = null;
  try {
    root = hodlHDKey.fromMasterSeed(seed);
    return (match.fingerprint = hodlFingerprintHex(root.fingerprint));
  } finally {
    seed.fill(0);
    root?.wipePrivateData();
  }
}
function hodlVanityKeyMarkup(fingerprint) {
  if (!fingerprint) return "";
  return `<span class="vanity-key"><img class="key-tab-lifehash" width="22" height="22" alt="" hidden data-vanity-lifehash="${hodlEscapeHtml(fingerprint)}"><code>${hodlEscapeHtml(fingerprint)}</code></span>`;
}
function hodlRenderVanityOut() {
  let box = document.getElementById("vanity-out");
  if (!box) return;
  if (!hodlVanityMatches.length || !hodlVanityRun) {
    box.innerHTML = "";
    return;
  }
  let run = hodlVanityRun, derivation = run.method === "derivation", meta = VANITY_SCRIPTS[run.script] ?? VANITY_SCRIPTS.p2wpkh, label = hodlEscapeHtml(run.sourceLabel);
  let copyMarkup = (attribute, index, title) => `<button type="button" class="seed-phrase-copy" ${attribute}="${index}" aria-label="${title}" title="${title}">${hodlClipboardIconMarkup()}</button><span class="vanity-copied muted" aria-live="polite"></span>`;
  let keyCell = (match) => `<td class="vanity-key-cell">${hodlVanityKeyMarkup(hodlVanityMatchFingerprint(match, run))}</td>`;
  let applyMarkup = (match, index) => match.savedTo
    ? `<span class="vanity-saved" role="status">${hodlCopiedIconMarkup()}Saved to key ${hodlEscapeHtml(match.savedTo)}</span>`
    : `<button type="button" class="btn secondary vanity-apply" data-vanity-apply="${index}" ${hodlVanityApplying ? "disabled" : ""} title="Write this ${derivation ? "account index" : "passphrase"} to key ${label} and re-derive it">${hodlVanityApplying ? "Updating…" : "Update key"}</button>`;
  // Passphrases are private key material: masked until the reveal toggle, and
  // copied from match state (never a DOM attribute) so the wipe drops them.
  let rows = hodlVanityMatches.map((match, index) => {
    let address = `<td><span class="vanity-secret"><span class="mono">${hodlEscapeHtml(match.address)}</span>${copyMarkup("data-vanity-copy-address", index, "Copy address")}</span></td>`;
    if (derivation) {
      return `<tr><th scope="row">${index + 1}</th><td class="mono">${match.index}${run.accountHardened ? "'" : ""}</td><td class="mono">${hodlEscapeHtml(hodlDisplayDerivationPath(match.path))}</td>${address}${keyCell(match)}<td class="vanity-apply-cell">${applyMarkup(match, index)}</td></tr>`;
    }
    let secret = hodlVanityReveal
      ? `<span class="mono">${hodlEscapeHtml(match.passphrase)}</span>`
      : `<span class="mono" aria-hidden="true">${hodlEscapeHtml("•".repeat(12))}</span><span class="sr-only">Passphrase hidden — tick Show passphrases to reveal</span>`;
    return `<tr><th scope="row">${index + 1}</th><td class="mono">${match.counter.toString()}</td><td><span class="vanity-secret">${secret}${copyMarkup("data-vanity-copy", index, "Copy passphrase")}</span></td>${address}${keyCell(match)}<td class="vanity-apply-cell">${applyMarkup(match, index)}</td></tr>`;
  }).join("");
  let overflow = hodlVanityFound > hodlVanityMatches.length ? `<p class="muted">Only the first ${hodlVanityMatches.length} matches are listed; ${hodlVanityFormatCount(hodlVanityFound)} found in total.</p>` : "";
  let where = meta.code === 4
    ? `the BIP-352 Silent Payment code of that account (scan ${hodlEscapeHtml(hodlDisplayDerivationPath(run.pathText))}/1h/0, spend …/0h/0)`
    : `the ${hodlEscapeHtml(meta.label)} address at ${hodlEscapeHtml(hodlDisplayDerivationPath(run.pathText))}`;
  let description = derivation
    ? `Each row is a BIP32 account index of key ${label} — with its passphrase unchanged, ${where} starts with the prefix. Update key sets that account on the key and re-derives it, so the Keys tab, its exports, and the Journal show this wallet.`
    : `Each row is a new BIP39 passphrase for key ${label}: the starting passphrase followed by the counter characters. With this key's seed words it derives ${where}. Update key writes the passphrase to the key and re-derives it, so the Keys tab, its exports, and the Journal show this wallet. Anyone holding the words and this passphrase holds the coins.`;
  let reveal = derivation ? "" : `<div class="wallet-data-actions no-print">
        <label class="reveal-private-toggle">
          <input type="checkbox" id="vanity-reveal" ${hodlVanityReveal ? "checked" : ""} aria-describedby="vanity-matches-description">
          <span>Show passphrases <span class="reveal-private-toggle-note">(air-gap only)</span></span>
        </label>
      </div>`;
  let head = derivation
    ? `<th scope="col">#</th><th scope="col">Account</th><th scope="col">Path</th><th scope="col">Address</th><th scope="col">Key</th><th scope="col"><span class="sr-only">Update key</span></th>`
    : `<th scope="col">#</th><th scope="col">Counter</th><th scope="col">Passphrase (keep it secret)</th><th scope="col">Address</th><th scope="col">Key after update</th><th scope="col"><span class="sr-only">Update key</span></th>`;
  box.innerHTML = `<section class="wallet-data-section wallet-private-section" aria-labelledby="vanity-matches-heading">
      <div class="wallet-data-section-head"><h3 id="vanity-matches-heading">Matching ${derivation ? "accounts" : "passphrases"}</h3>
      <p class="muted" id="vanity-matches-description">${description}</p></div>
      ${reveal}
      <div class="wallet-address-table"><div class="wallet-table wallet-table-public" role="region" tabindex="0" aria-label="Matching vanity addresses table"><table aria-rowcount="${hodlVanityMatches.length + 1}"><caption class="sr-only">Matching vanity addresses</caption><thead><tr>${head}</tr></thead><tbody>${rows}</tbody></table></div></div>
      ${overflow}</section>`;
  // LifeHash images render asynchronously from the fingerprint in the cell.
  box.querySelectorAll("img[data-vanity-lifehash]").forEach((image) => hodlFillKeyTabLifehash(image, image.dataset.vanityLifehash));
}
function hodlVanitySyncControls() {
  let go = document.getElementById("vanity-go"), stop = document.getElementById("vanity-stop"), wipe = document.getElementById("vanity-wipe"), progress = document.getElementById("vanity-progress");
  let source = hodlVanitySourceState();
  if (go) {
    let blocked = hodlVanityRunning || hodlVanityApplying || !source;
    go.disabled = blocked;
    go.setAttribute("aria-disabled", String(blocked));
    go.textContent = hodlVanityRunning ? "Grinding…" : "Start grinding";
    go.title = source ? "" : "Pick a Key Station key first";
  }
  if (stop) stop.disabled = !hodlVanityRunning;
  let first = document.getElementById("vanity-first");
  if (first) {
    first.setAttribute("aria-pressed", String(hodlVanityStopFirst));
    first.classList.toggle("is-pressed", hodlVanityStopFirst);
    first.textContent = hodlVanityStopFirst ? "Stop on first find: on" : "Stop on first find";
  }
  let dirty = hodlVanityFound > 0 && !hodlVanityRunning && !hodlVanityApplying;
  if (wipe) {
    wipe.disabled = !dirty;
    wipe.setAttribute("aria-disabled", String(!dirty));
  }
  if (progress) progress.hidden = !hodlVanityRunning;
}
function hodlVanitySetStatus(text) {
  let status = document.getElementById("vanity-status");
  if (status) status.textContent = text;
}
function hodlVanityStop() {
  if (hodlVanityGrinder && hodlVanityRunning) hodlVanityGrinder.stop();
}
function hodlVanityCancel() {
  let wasRunning = hodlVanityRunning;
  if (hodlVanityGrinder) hodlVanityGrinder.cancel();
  hodlVanityRunning = false;
  hodlVanityLiveRate = 0;
  if (wasRunning) hodlVanitySetStatus("Stopped.");
  hodlVanitySyncControls();
}
function hodlVanityClearResults(status = "Idle. No range has been ground this session.") {
  hodlVanityMatches = [];
  hodlVanityFound = 0;
  hodlVanityReveal = false;
  hodlVanityRun = null;
  hodlRenderVanityOut();
  hodlVanitySetStatus(status);
  hodlVanitySyncControls();
}
function hodlVanityScriptChanged() {
  hodlVanityCancel();
  let input = document.getElementById("vanity-prefix");
  if (input) hodlApplyFilteredInput(input, (value) => hodlFilterVanityPrefix(value));
  hodlVanityClearResults();
  hodlVanitySyncScriptNote();
  hodlVanityEstimate();
}
function hodlVanityMethodChanged() {
  hodlVanityCancel();
  hodlVanityClearResults();
  hodlVanitySyncMethod();
}
function hodlRunVanity() {
  let error = document.getElementById("vanity-error");
  if (error) error.textContent = "";
  let inputs;
  try {
    inputs = hodlVanityParseInputs();
  } catch (exception) {
    if (error) error.textContent = exception.message || String(exception);
    return;
  }
  hodlVanityMatches = [];
  hodlVanityFound = 0;
  // The run's key, method, and passphrase are fixed at start; snapshot them
  // so the results (and Update key) cannot drift if the form changes mid-grind.
  hodlVanityRun = { method: inputs.method, script: inputs.script, sourceId: inputs.sourceId, sourceLabel: inputs.sourceLabel, passphrase: inputs.passphrase, accountHardened: inputs.accountHardened, pathText: vanityPathString([...inputs.pathPrefix, ...inputs.path]) };
  hodlRenderVanityOut();
  hodlVanityRunning = true;
  hodlVanitySyncControls();
  hodlVanitySetStatus(inputs.method === "derivation" ? `Starting workers — stepping through account indexes of key ${inputs.sourceLabel}…` : `Starting workers — extending key ${inputs.sourceLabel}'s passphrase with the counter characters…`);
  let progressBar = document.getElementById("vanity-progress");
  hodlVanityGrinder = new VanityGrinder({
    onProgress: ({ done, total, rate }) => {
      let percent = total > 0n ? Number((done * 10000n) / total) / 100 : 0;
      if (progressBar) {
        progressBar.setAttribute("aria-valuenow", String(Math.floor(percent)));
        progressBar.setAttribute("aria-valuetext", `${percent.toFixed(1)}% complete`);
        let fill = progressBar.querySelector(".derive-progress-bar"), label = progressBar.querySelector(".derive-progress-label");
        if (fill) fill.style.width = `${percent}%`;
        if (label) label.textContent = `${percent.toFixed(1)}%`;
      }
      hodlVanitySetStatus(`${hodlVanityFormatCount(done)} / ${hodlVanityFormatCount(total)} candidates · ${hodlVanityFormatCount(Math.round(rate))}/s · ${hodlVanityFound} match${hodlVanityFound === 1 ? "" : "es"}`);
      // The live rate is the best estimate while the grind runs.
      if (rate > 0 && Math.abs(rate - hodlVanityLiveRate) / rate > 0.05) {
        hodlVanityLiveRate = rate;
        hodlVanityEstimate();
      }
    },
    onMatch: (match) => {
      hodlVanityFound += 1;
      if (hodlVanityMatches.length < hodlVanityDisplayLimit) {
        hodlVanityMatches.push(match);
        hodlRenderVanityOut();
      }
      if (hodlVanityStopFirst && hodlVanityRunning) hodlVanityStop();
    },
    onDone: ({ done, stopped }) => {
      hodlVanityRunning = false;
      hodlVanityLiveRate = 0;
      // The next run resumes where this range ended; the start field is the
      // durable record of what has been ground.
      let nextStart = inputs.start + done;
      let startField = document.getElementById(inputs.method === "derivation" ? "vanity-account-start" : "vanity-start");
      if (startField) startField.value = nextStart.toString();
      hodlVanitySetStatus(`${stopped ? (hodlVanityStopFirst && hodlVanityFound > 0 ? "Stopped at first match" : "Stopped") : "Range complete"}: ${hodlVanityFormatCount(done)} candidates, ${hodlVanityFound} match${hodlVanityFound === 1 ? "" : "es"}. Next ${inputs.method === "derivation" ? "account" : "counter"}: ${nextStart.toString()}.`);
      hodlVanitySyncControls();
      hodlVanityEstimate();
    },
    onError: (message) => {
      if (error) error.textContent = message;
    },
  });
  hodlVanityGrinder.start(inputs);
  // The grinder copied the parent node for its workers; this copy is dead.
  if (inputs.node) inputs.node.fill(0);
}
// Update key: write the match back to its key and re-derive, through the same
// Edit input → Derive path the Keys tab uses by hand. The key keeps its tab
// (id, colour, custom name) even when a new passphrase gives it a new
// fingerprint; the lab tab gets back whatever the user had in it.
async function hodlVanityApplyMatch(index) {
  let error = document.getElementById("vanity-error"), match = hodlVanityMatches[index], run = hodlVanityRun;
  if (error) error.textContent = "";
  if (!match || !run || hodlVanityApplying || match.savedTo) return;
  let state = hodlKeys.find((candidate) => candidate.id === run.sourceId && !candidate.isLab);
  if (!state) {
    if (error) error.textContent = `Key ${run.sourceLabel} is no longer in Key Station, so there is nothing to update.`;
    return;
  }
  if (hodlActiveDerivation) {
    if (error) error.textContent = hodlTText("A derivation is already running on the Keys tab — wait for it to finish.");
    return;
  }
  hodlVanityApplying = true;
  hodlRenderVanityOut();
  hodlVanitySyncControls();
  let before = new Set(hodlKeys.map((candidate) => candidate.id)), lab = hodlKeys.find((candidate) => candidate.isLab) || null;
  try {
    let labIndex = hodlFillLabFromKey(state), draft = hodlKeys[labIndex];
    draft.fields.pass = match.passphrase;
    if (match.index !== null) {
      draft.fields.account = `${match.index}${run.accountHardened ? "'" : ""}`;
      draft.fields.accountHarden = run.accountHardened;
    }
    hodlActiveKey = labIndex;
    hodlRenderKeyTabs();
    hodlRestoreKey();
    document.getElementById("calc-card").hidden = hodlWorkspace !== "calc";
    await hodlDeriveWithProgress("key", hodlCalculateKey);
    let active = hodlKeys[hodlActiveKey];
    if (!active || active.isLab || !active.result) throw new Error(active?.error || "Deriving the updated key failed.");
    if (!before.has(active.id)) {
      // A changed passphrase means a new fingerprint, which the Keys tab files
      // as a new key; fold it back into the tab it came from.
      let target = hodlKeys.findIndex((candidate) => candidate.id === state.id), fresh = hodlActiveKey;
      if (target >= 0) {
        hodlKeys[target] = { ...active, id: state.id, number: state.number, color: state.color, name: state.name && state.name !== hodlVanityKeyLabel(state) ? state.name : active.name };
        hodlKeys.splice(fresh, 1);
        hodlActiveKey = target > fresh ? target - 1 : target;
      }
    }
    let updated = hodlKeys[hodlActiveKey];
    match.savedTo = hodlVanityKeyLabel(updated);
    // A tool that had this key loaded is holding the old seed: reload it so
    // its chip, fingerprint, and LifeHash follow the key.
    if (hodlSpSource === "key:" + updated.id) hodlPickSpSessionKey(updated);
    if (hodlBip85Source === "key:" + updated.id) hodlPickBip85SessionKey(updated);
    hodlVanitySetStatus(`Saved to key ${match.savedTo}: ${match.index !== null ? `account ${match.index}` : "the new passphrase"} is now on the key${run.sourceLabel !== match.savedTo ? ` — its master fingerprint and LifeHash changed from ${run.sourceLabel} to ${match.savedTo}` : ""}. Open the Keys tab to review and export it.`);
  } catch (exception) {
    if (error) error.textContent = exception.message || String(exception);
  } finally {
    if (lab) {
      let current = hodlKeys.findIndex((candidate) => candidate.isLab);
      if (current >= 0 && hodlKeys[current] !== lab) hodlKeys[current] = lab;
    }
    hodlVanityApplying = false;
    hodlRenderKeyTabs();
    hodlRestoreKey();
    // The Keys panel opened for the derive; this tab stays where it is.
    document.getElementById("calc-card").hidden = hodlWorkspace !== "calc";
    hodlVanitySyncSource();
    hodlRenderVanityOut();
    hodlVanitySyncControls();
  }
}
function hodlInitVanity() {
  let go = document.getElementById("vanity-go");
  if (!go) return;
  let workersField = document.getElementById("vanity-workers");
  if (workersField && navigator.hardwareConcurrency) workersField.value = String(Math.max(1, Math.min(64, navigator.hardwareConcurrency)));
  go.onclick = hodlRunVanity;
  document.getElementById("vanity-stop").onclick = hodlVanityStop;
  document.getElementById("vanity-first").onclick = hodlVanityToggleStopFirst;
  document.getElementById("vanity-wipe").onclick = () => hodlVanityClearResults();
  workersField?.addEventListener("input", hodlVanityEstimate);
  let prefix = document.getElementById("vanity-prefix");
  prefix.addEventListener("input", () => {
    hodlApplyFilteredInput(prefix, (value) => hodlFilterVanityPrefix(value));
    hodlVanityEstimate();
  });
  document.getElementById("vanity-script")?.addEventListener("change", hodlVanityScriptChanged);
  document.getElementById("vanity-method")?.addEventListener("change", hodlVanityMethodChanged);
  for (let id of ["vanity-length", "vanity-start", "vanity-count", "vanity-account-start", "vanity-account-count", "vanity-workers"]) {
    let input = document.getElementById(id);
    input?.addEventListener("input", () => hodlApplyFilteredInput(input, (value) => String(value ?? "").replace(/\D/g, "")));
  }
  // Copy and Update key buttons carry the match index, never the secret; the
  // click reads the live match list, so wiped state cannot be copied back.
  let out = document.getElementById("vanity-out");
  out?.addEventListener("click", (event) => {
    let secretButton = event.target.closest("[data-vanity-copy]");
    if (secretButton) {
      let match = hodlVanityMatches[Number(secretButton.dataset.vanityCopy)];
      if (match) hodlCopyVanityValue(secretButton, match.passphrase, "Copy passphrase");
      return;
    }
    let addressButton = event.target.closest("[data-vanity-copy-address]");
    if (addressButton) {
      let match = hodlVanityMatches[Number(addressButton.dataset.vanityCopyAddress)];
      if (match) hodlCopyVanityValue(addressButton, match.address, "Copy address");
      return;
    }
    let applyButton = event.target.closest("[data-vanity-apply]");
    if (applyButton && !applyButton.disabled) hodlVanityApplyMatch(Number(applyButton.dataset.vanityApply));
  });
  out?.addEventListener("change", (event) => {
    if (event.target?.id === "vanity-reveal") {
      hodlVanityReveal = event.target.checked;
      hodlRenderVanityOut();
    }
  });
  hodlVanitySyncScriptNote();
  hodlVanitySyncMethod();
  hodlVanitySyncControls();
  // No picker fill here: the chips carry LifeHash images, and the LifeHash
  // module is a later classic script tag — the WASM-ready promise can settle
  // between parser-inserted scripts, so boot must not touch it (the footer
  // stamp waits for full load for the same reason). The picker fills on tab
  // entry and on every station-key refresh instead.
}
function hodlInitWorkspace() {
  let box = hodlElement("#workspace");
  box.innerHTML = "";
  // Every tool stays on screen. The strip scrolls rather than collapsing, so
  // adding tools later widens the row instead of hiding them behind a control
  // the user has to know to open.
  let hint = document.createElement("button");
  hint.type = "button";
  hint.className = "workspace-more";
  hint.id = "workspace-more";
  hint.setAttribute("aria-controls", "workspace-tabs");
  hint.setAttribute("aria-label", "Scroll the tool list to see more tools");
  hint.hidden = true;
  hint.innerHTML = `More tools<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M5 12h13M13 6l6 6-6 6"/></svg>`;
  let strip = document.createElement("div");
  strip.className = "workspace-tabs";
  strip.id = "workspace-tabs";
  strip.setAttribute("role", "tablist");
  strip.setAttribute("aria-label", "Tool");
  hodlWorkspaceTabs.forEach(([id, label, short], index) => {
    let button = document.createElement("button"), active = hodlWorkspace === id;
    button.type = "button";
    button.className = "workspace-tab" + (active ? " active" : "");
    button.dataset.workspace = id;
    button.setAttribute("role", "tab");
    button.setAttribute("aria-selected", String(active));
    let fullLabel = document.createElement("span"), shortLabel = document.createElement("span");
    fullLabel.className = "workspace-tab-full";
    shortLabel.className = "workspace-tab-short";
    fullLabel.textContent = hodlTText(label);
    shortLabel.textContent = hodlTText(short);
    button.append(fullLabel, shortLabel);
    // The short form is display:none at wide widths and the full one is hidden
    // at narrow ones, and hidden text is not in the accessibility tree — so the
    // name is stated outright rather than left to whichever span is showing.
    button.setAttribute("aria-label", hodlTText(label));
    button.onclick = () => hodlShowWorkspace(id);
    button.onkeydown = (event) => hodlWorkspaceTabKeydown(event, index);
    strip.appendChild(button);
  });
  box.append(hint, strip);
  hodlInitTabDrag(strip);
  // The hint points at tools that are off the right edge, so it answers "is
  // there more that way": it goes once the end is reached, and one click
  // finishes the journey rather than stopping part of the way.
  hint.onclick = () => strip.scrollTo({
    left: strip.scrollWidth,
    behavior: matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth",
  });
  hodlSyncWorkspaceOverflow();
  strip.addEventListener("scroll", hodlSyncWorkspaceOverflow, { passive: true });
  addEventListener("resize", hodlSyncWorkspaceOverflow);
  new ResizeObserver(hodlSyncWorkspaceOverflow).observe(strip);
  hodlInitPsbtToolTabs();
  hodlInitJournalToolTabs();
  hodlInitJournalNotebook();
  hodlInitMsig();
  hodlInitPsbt();
  initPsbtEditor({ networkDefault: () => hodlNetworkDefault });
  hodlInitBip85();
  hodlInitVanity();
  hodlInitSp();
}
var hodlKeyClearSyncQueued = false, hodlMsigClearSyncQueued = false, hodlDeriveSyncQueued = false;
function hodlQueueKeyClearButtonSync() {
  if (hodlKeyClearSyncQueued) return;
  hodlKeyClearSyncQueued = true;
  queueMicrotask(() => {
    hodlKeyClearSyncQueued = false;
    hodlSyncKeyClearButton(true);
  });
}
function hodlQueueMsigClearButtonSync() {
  if (hodlMsigClearSyncQueued) return;
  hodlMsigClearSyncQueued = true;
  queueMicrotask(() => {
    hodlMsigClearSyncQueued = false;
    hodlSyncMsigClearButton(true);
  });
}
function hodlQueueDeriveButtonSync() {
  if (hodlDeriveSyncQueued) return;
  hodlDeriveSyncQueued = true;
  queueMicrotask(() => {
    hodlDeriveSyncQueued = false;
    hodlSyncDeriveButton();
  });
}
function hodlInitClearActionState() {
  let keyPanel = document.getElementById("calc-card"), msigPanel = document.getElementById("msig-card");
  ["input", "change", "click"].forEach((type) => {
    keyPanel.addEventListener(type, hodlQueueKeyClearButtonSync);
    keyPanel.addEventListener(type, hodlQueueDeriveButtonSync);
    msigPanel.addEventListener(type, hodlQueueMsigClearButtonSync);
  });
  hodlSyncKeyClearButton();
  hodlSyncMsigClearButton();
  hodlSyncDeriveButton();
}
var hodlSegmentedControlFrame = 0, hodlSegmentedResizeObserver = null, hodlSegmentedControlWidths = /* @__PURE__ */ new WeakMap();
function hodlSyncSegmentedControls() {
  hodlSegmentedControlFrame = 0;
  document.querySelectorAll(".segmented-control").forEach((group) => {
    if (!group.getClientRects().length) return;
    let buttons = [...group.children].filter((child) => child.matches(".tab"));
    group.classList.remove("is-stacked");
    if (buttons.length < 2) return;
    let firstTop = buttons[0].offsetTop, wrapped = buttons.some((button) => Math.abs(button.offsetTop - firstTop) > 1);
    group.classList.toggle("is-stacked", wrapped);
  });
}
function hodlQueueSegmentedControlSync() {
  if (hodlSegmentedControlFrame) return;
  hodlSegmentedControlFrame = requestAnimationFrame(hodlSyncSegmentedControls);
}
function hodlInitSegmentedControls() {
  let groups = [...document.querySelectorAll(".segmented-control")];
  if ("ResizeObserver" in window) {
    hodlSegmentedResizeObserver = new ResizeObserver((entries) => {
      let changed = false;
      entries.forEach((entry) => {
        let width = entry.contentRect.width, previous = hodlSegmentedControlWidths.get(entry.target);
        if (previous === void 0 || Math.abs(previous - width) > 0.5) {
          hodlSegmentedControlWidths.set(entry.target, width);
          changed = true;
        }
      });
      if (changed) hodlQueueSegmentedControlSync();
    });
    groups.forEach((group) => hodlSegmentedResizeObserver.observe(group));
  }
  window.addEventListener("resize", hodlQueueSegmentedControlSync, { passive: true });
  hodlQueueSegmentedControlSync();
}
// The toggle is two-state. Which of the two a first visit opens in is the
// operating system's call, so an unset store means "ask the system" rather
// than "dark" — which is why both modes are now written explicitly, where
// dark used to be encoded as the absence of the key. A store left over from
// the old third state reads as unset, so those users keep following the
// system until they touch the toggle.
var hodlThemeModes = ["dark", "light"], hodlThemeStorageKey = "entropylab-theme", hodlThemeLightQuery = matchMedia("(prefers-color-scheme: light)");
function hodlStoredThemeMode() {
  try {
    let mode = localStorage.getItem(hodlThemeStorageKey);
    return hodlThemeModes.includes(mode) ? mode : null;
  } catch (e) {
    return null;
  }
}
function hodlReadThemeMode() {
  return hodlStoredThemeMode() || (hodlThemeLightQuery.matches ? "light" : "dark");
}
function hodlApplyTheme(mode) {
  if (!hodlThemeModes.includes(mode)) mode = "dark";
  let light = mode === "light";
  if (light) document.documentElement.dataset.theme = "light";
  else delete document.documentElement.dataset.theme;
  let toggle = document.getElementById("theme-toggle");
  if (toggle) {
    toggle.dataset.themeMode = mode;
    toggle.setAttribute("aria-label", hodlTText(light ? "Theme: light. Switch to dark" : "Theme: dark. Switch to light"));
  }
  let meta = document.querySelector('meta[name="theme-color"]');
  if (meta) meta.content = light ? "#ffffff" : "#000000";
}
// The dismissal is remembered in localStorage, the same site-settings store as
// the theme and the beta disclaimer, keyed to this build's version: every new
// release warns again. When storage is unavailable (file:// origins, private
// modes) the banner simply returns on every load, which is the safe direction
// for a wallet tool. Re-hiding it on a later visit belongs to the inline head
// script, which runs before first paint; boot is far too late to avoid a
// flash, so this only has to handle the click.
var hodlBetaBannerStorageKey = "entropylab-beta-banner-dismissed";
function hodlInitBetaWarningDismiss() {
  let banner = document.getElementById("beta-warning");
  let dismiss = document.getElementById("beta-warning-dismiss");
  if (!banner || !dismiss) return;
  dismiss.onclick = () => {
    try {
      localStorage.setItem(hodlBetaBannerStorageKey, "{{VERSION}}");
    } catch (e) {
    }
    banner.hidden = true;
  };
}
// The session-wide Bitcoin network, chosen from the header picker. It never
// connects anything anywhere — it only sets which address formats, extended
// key versions, WIF prefixes, and coin-type indexes new work defaults to.
// Not persisted: every load starts on mainnet, the safe direction for a
// wallet tool. A tool's own advanced fields can still override it per item.
// The picker offers Bitcoin Core's four networks, but signet and regtest
// share the testnet versions (coin type 1', tb1… addresses, tpub keys, 9/c
// WIF), so the tools themselves only ever see the binary choice.
var hodlNetworkChoice = "mainnet"; // what the picker shows: mainnet, testnet, signet, or regtest
var hodlNetworkDefault = "mainnet"; // what the tools derive with: mainnet or testnet
function hodlDefaultCoinType() {
  return hodlNetworkDefault === "testnet" ? 1 : 0;
}
// Pushing the choice into each tool's own network control — and letting the
// control's ordinary input/change handlers run — keeps every downstream
// consumer (help text, path preview, key-prefix checks, result invalidation,
// the custom select chrome) in step without a second code path. The PSBT
// tools have no control of their own: the inspectors read hodlNetworkDefault
// at render time, and the editor hears the change through the document event.
function hodlApplyNetworkDefault(network) {
  hodlNetworkChoice = ["testnet", "signet", "regtest"].includes(network) ? network : "mainnet";
  hodlNetworkDefault = hodlNetworkChoice === "mainnet" ? "mainnet" : "testnet";
  let coinType = document.getElementById("network");
  if (coinType) {
    let hardened = document.getElementById("network-harden")?.checked !== false;
    coinType.value = `${hodlDefaultCoinType()}${hardened ? "'" : ""}`;
    coinType.dispatchEvent(new Event("input", { bubbles: true }));
    hodlJournalSuppressSettingAudit = true;
    try {
      coinType.dispatchEvent(new Event("change", { bubbles: true }));
    } finally {
      hodlJournalSuppressSettingAudit = false;
    }
  }
  let msigCoinType = document.getElementById("msig-network");
  if (msigCoinType) {
    msigCoinType.value = String(hodlDefaultCoinType());
    msigCoinType.dispatchEvent(new Event("input", { bubbles: true }));
  }
  for (let id of ["sp-network"]) {
    let select = document.getElementById(id);
    if (!select) continue;
    hodlSyncSelect(select, hodlNetworkDefault);
    hodlJournalSuppressSettingAudit = true;
    try {
      select.dispatchEvent(new Event("change", { bubbles: true }));
    } finally {
      hodlJournalSuppressSettingAudit = false;
    }
  }
  document.dispatchEvent(new CustomEvent("hodl:network-default"));
}
var hodlNetworkPickerRender = null;
function hodlInitNetworkPicker() {
  let root = document.getElementById("network-picker"), button = document.getElementById("network-picker-button"), menu = document.getElementById("network-picker-menu"), label = document.getElementById("network-picker-label");
  if (!root || !button || !menu || !label) return;
  let options = [...menu.querySelectorAll("[data-network]")];
  let render = () => {
    let key = ["mainnet", "testnet", "signet", "regtest"].includes(hodlNetworkChoice) ? hodlNetworkChoice : "mainnet";
    let name = hodlTText(hodlNetworkNames[key]);
    root.dataset.network = hodlNetworkChoice;
    label.textContent = name;
    button.setAttribute("aria-label", hodlTText("Bitcoin network: {network}. Change the network the tools derive and check for", { network: name }));
    options.forEach((option) => option.setAttribute("aria-checked", String(option.dataset.network === hodlNetworkChoice)));
  };
  let close = () => {
    menu.hidden = true;
    button.setAttribute("aria-expanded", "false");
  };
  let open = () => {
    menu.hidden = false;
    button.setAttribute("aria-expanded", "true");
  };
  button.addEventListener("click", () => menu.hidden ? open() : close());
  button.addEventListener("keydown", (event) => {
    if (!["ArrowDown", "Enter", " "].includes(event.key)) return;
    event.preventDefault();
    open();
    (options.find((option) => option.getAttribute("aria-checked") === "true") || options[0])?.focus();
  });
  menu.addEventListener("keydown", (event) => {
    let index = options.indexOf(document.activeElement);
    if (event.key === "ArrowDown") {
      event.preventDefault();
      options[Math.min(index + 1, options.length - 1)]?.focus();
    } else if (event.key === "ArrowUp") {
      event.preventDefault();
      options[Math.max(index - 1, 0)]?.focus();
    }
  });
  root.addEventListener("keydown", (event) => {
    if (event.key !== "Escape") return;
    close();
    button.focus({ preventScroll: true });
  });
  options.forEach((option) => option.addEventListener("click", () => {
    hodlApplyNetworkDefault(option.dataset.network);
    hodlJournalLog("network", hodlNetworkChoice, "app");
    render();
    close();
    button.focus({ preventScroll: true });
  }));
  document.addEventListener("pointerdown", (event) => {
    if (!root.contains(event.target)) close();
  });
  hodlNetworkPickerRender = render;
  render();
}
function hodlInitTheme() {
  hodlApplyTheme(hodlReadThemeMode());
  let toggle = document.getElementById("theme-toggle");
  if (toggle) toggle.onclick = () => {
    let mode = hodlReadThemeMode() === "light" ? "dark" : "light";
    try {
      localStorage.setItem(hodlThemeStorageKey, mode);
    } catch (e) {
    }
    hodlApplyTheme(mode);
    hodlJournalLog("theme", mode, "app");
  };
  // Until the toggle is used the system still leads, so a mid-session change
  // to its setting follows along without pinning a choice the user never made.
  hodlThemeLightQuery.addEventListener("change", () => {
    if (!hodlStoredThemeMode()) hodlApplyTheme(hodlReadThemeMode());
  });
}
function hodlInitSecretFieldAutoClear() {
  let clearSecretFields = () => {
    hodlPsbtWipeMem();
    hodlBip85WipeMem();
    hodlSpWipeMem();
    hodlJournalWipeMem();
    hodlKeys = hodlKeys.map((state) => {
      let fields = state.fields || {}, privateKeys = fields.privateKeys;
      if (privateKeys) Object.keys(privateKeys).forEach((kind) => {
        privateKeys[kind] = "";
      });
      Object.keys(fields).forEach((id) => {
        if (id !== "privateKeys") fields[id] = "";
      });
      if (Array.isArray(state.diceCoinPositions)) state.diceCoinPositions.length = 0;
      state.lastWord = "";
      state.dplusLastWord = "";
      state.result = null;
      state.reveal = false;
      state.error = "";
      state.errorSpec = null;
      return state.isLab ? hodlNewLabState() : hodlNewKeyState(state.name, state.id, state.number);
    });
    hodlWalletResult = null;
    hodlRevealPrivate = false;
    hodlPickedLastWord = "";
    hodlDiceCoinPositions = [];
    for (let id of ["dice", "hex", "bin", "base4", "base8", "base32", "base64", "seed", "seed-numbers", "key", "pass", "cards", "direct-cards"]) {
      let field = document.getElementById(id);
      if (field) field.value = "";
    }
    let psbtKey = document.getElementById("psbt-key"), psbtPass = document.getElementById("psbt-pass");
    if (psbtKey) psbtKey.value = "";
    if (psbtPass) psbtPass.value = "";
    let psbtText = document.getElementById("psbt-text"), psbtAxTranscript = document.getElementById("psbt-ax-transcript");
    if (psbtText) psbtText.value = "";
    if (psbtAxTranscript) psbtAxTranscript.value = "";
    let bip85Key = document.getElementById("bip85-key"), bip85Out = document.getElementById("bip85-out"), bip85Error = document.getElementById("bip85-error"), bip85Session = document.getElementById("bip85-session");
    if (bip85Key) bip85Key.value = "";
    if (bip85Out) bip85Out.innerHTML = "";
    if (bip85Error) bip85Error.textContent = "";
    if (bip85Session) bip85Session.textContent = hodlBip85Note;
    hodlRenderBip85Tabs();
    hodlSyncBip85View();
    let spKey = document.getElementById("sp-key"), spPass = document.getElementById("sp-pass");
    if (spKey) spKey.value = "";
    if (spPass) spPass.value = "";
    let spVins = document.getElementById("sp-send-vins");
    if (spVins) spVins.value = "";
    let spOut = document.getElementById("sp-out"), spError = document.getElementById("sp-error"), spSession = document.getElementById("sp-session");
    if (spOut) spOut.innerHTML = "";
    if (spError) spError.textContent = "";
    if (spSession) spSession.textContent = hodlSpNote;
    let spRecipients = document.getElementById("sp-recipients"), spVerifyVins = document.getElementById("sp-verify-vins"), spVerifyOutputs = document.getElementById("sp-verify-outputs"), spLabel = document.getElementById("sp-label"), spPayname = document.getElementById("sp-payname");
    if (spRecipients) spRecipients.value = "";
    if (spVerifyVins) spVerifyVins.value = "";
    if (spVerifyOutputs) spVerifyOutputs.value = "";
    if (spLabel) spLabel.value = "";
    if (spPayname) spPayname.value = "";
    // Found vanity passphrases and the brought-in salt are private key
    // material; stop the grinder and drop them too.
    hodlVanityCancel();
    hodlVanityMatches = [];
    hodlVanityFound = 0;
    hodlVanityReveal = false;
    hodlVanityRun = null;
    hodlVanitySource = "";
    hodlVanityApplying = false;
    let vanityPass = document.getElementById("vanity-pass"), vanityOut = document.getElementById("vanity-out"), vanityError = document.getElementById("vanity-error"), vanityStatus = document.getElementById("vanity-status");
    if (vanityPass) vanityPass.value = "";
    if (vanityOut) vanityOut.innerHTML = "";
    if (vanityError) vanityError.textContent = "";
    if (vanityStatus) vanityStatus.textContent = "Idle. No range has been ground this session.";
    hodlVanitySyncSource();
    hodlVanitySyncControls();
    // The keys above were just reset, so their passphrases (and thus the
    // vanity picker's chips) are gone too.
    hodlRefreshStationKeyPickers();
    // The <pre> mirrors behind each input hold a second live copy of whatever
    // was typed (dice rolls, seed words, passphrase, private key).
    document.querySelectorAll(".dice-input-highlight").forEach((highlight) => {
      highlight.textContent = "";
    });
    // Copy buttons keep the phrase/child secret in a data attribute.
    document.querySelectorAll("[data-phrase]").forEach((button) => button.removeAttribute("data-phrase"));
    hodlLastWordCache.clear(); // cached partial mnemonic phrases
    let out = document.getElementById("out");
    if (out) out.innerHTML = "";
    hodlSetWorkspaceError("key", null);
    // The PSBT editor holds the loaded document in module state; its own wipe
    // button drops it. Last, so a failure there cannot skip the clears above.
    let psbtEditorWipe = document.getElementById("psbted-wipe");
    if (psbtEditorWipe) try {
      psbtEditorWipe.dataset.journalSilent = "true";
      psbtEditorWipe.click();
    } catch {} finally {
      delete psbtEditorWipe.dataset.journalSilent;
    }
  };
  addEventListener("pagehide", clearSecretFields);
  addEventListener("pageshow", (event) => {
    if (event.persisted) clearSecretFields();
  });
}
// The footer stamps the build — version, commit, and a LifeHash of the
// commit — so a downloaded page identifies its exact source revision. The
// LifeHash renders from the stamped data-commit; a snapshot build stamped
// "unknown" leaves the image hidden.
function hodlInitFooterBuild() {
  document.querySelectorAll(".page-footer-lifehash").forEach((image) => {
    const commit = image.dataset.commit || "";
    if (!/^[0-9a-f]{40}$/.test(commit)) return;
    if (typeof hodlLifeHash === "undefined" || typeof hodlLifeHash.fromFingerprint !== "function") return;
    hodlLifeHash
      .fromFingerprint(commit)
      .then((url) => {
        image.src = url;
        image.hidden = false;
      })
      .catch(() => {});
  });
}
// Boot can run before the later classic script tags execute (the WASM-ready
// promise may settle between parser-inserted scripts), so the stamp waits
// for the full page load: the footer markup and the LifeHash module are both
// guaranteed by then. The page is self-contained, so load follows parse.
addEventListener("load", hodlInitFooterBuild);
function hodlApplyLocale() {
  document.querySelectorAll("#workspace-tabs [data-workspace]").forEach((button) => {
    let entry = hodlWorkspaceTabs.find(([id]) => id === button.dataset.workspace);
    if (!entry) return;
    let [, label, short] = entry;
    if (button.firstChild) button.firstChild.textContent = hodlTText(label);
    if (button.lastChild) button.lastChild.textContent = hodlTText(short);
    button.setAttribute("aria-label", hodlTText(label));
  });
  [...hodlKeyModeSelectEl.options].forEach((option) => {
    option.textContent = hodlTText(hodlKeyModeLabels[option.value]);
  });
  hodlKeyModeSelectEl.dispatchEvent(new Event("entropylab:sync-select"));
  if (hodlNetworkPickerRender) hodlNetworkPickerRender();
  let state = hodlKeys[hodlActiveKey];
  if (state) hodlCaptureKey();
  hodlRenderKeyForm();
  if (state) hodlRestoreFormFields(state);
  hodlUpdateSeedLengthControl();
  hodlUpdateAddressEstimate();
  hodlUpdateAddressEstimate("msig-");
  hodlUpdateCoinTypeHelp();
  hodlUpdateCoinTypeHelp(document.getElementById("msig-network"), document.getElementById("msig-network-help"));
  hodlUpdateDerivationPathPreview();
  hodlUpdateMsigHint();
  hodlUpdateMsigScriptDetection();
  hodlUpdateMsigAccount();
  if (hodlWalletResult?.kind === "msig") hodlShowMsig();
  else if (hodlWalletResult) hodlRefreshKeyResult();
  hodlRefreshPsbtLocale();
  hodlApplyTheme(hodlReadThemeMode());
  hodlRefreshWorkspaceErrors();
  document.querySelectorAll("#msig-keys textarea").forEach((ta) => {
    if (ta.value) hodlCheckXpub(ta);
  });
}
function hodlBoot() {
  hodlInitWorkspace();
  hodlInitDefaultTabStates();
  hodlInitKeyManager();
  hodlInitMsigManager();
  hodlInitSpBench();
  hodlInitClearActionState();
  hodlInitSecretFieldAutoClear();
  hodlInitNetworkPicker();
  hodlInitTheme();
  hodlInitBetaWarningDismiss();
  hodlInitMasterFingerprintPreview();
  hodlInitDerivationControls();
  hodlInitAddressBenchmark();
  hodlInitSegmentedControls();
  initQrReferences();
  hodlInitLocale(hodlApplyLocale);
}
// Curve operations need the WebAssembly module instantiated first (async in
// browsers; already resolved synchronously under Node for the test suite).
// If the engine cannot boot — a CSP or browser that refuses the inline
// module, a corrupted copy — the page is killed like a failed browser-check
// barrage, because output from a broken secp256k1 engine cannot be trusted.
const hodlCurveFailure = () => {
  if (!document.body) return;
  const rows = `<tr><td>secp256k1 WebAssembly module</td><td>Failed</td></tr>`;
  document.body.innerHTML = `
<main class="sanity-failure">
  <div class="sanity-failure-card" role="alert">
    <svg class="sanity-failure-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><circle cx="12" cy="12" r="9.5"></circle><path d="M8.5 8.5l7 7M15.5 8.5l-7 7"></path></svg>
    <h1 class="sanity-failure-title">Host failed basic sanity checks</h1>
    <p class="sanity-failure-message">This page should not be used until checks passed.</p>
    <table class="sanity-failure-table">
      <thead><tr><th>Startup sanity check</th><th>Result</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>
    <p class="sanity-failure-advice">iPhone, iPad, and Mac Lockdown Mode block WebAssembly. This calculator needs it for secp256k1.</p>
    <p class="sanity-failure-advice">In Safari: tap the page-menu button in the address bar, tap More, turn off Lockdown Mode for this website, then reload. Or open the saved HTML in Firefox on a trusted air-gapped computer. Do not enter seed material until every check passes.</p>
  </div>
</main>`;
};
secp256k1Ready.then(hodlBoot).catch(() => hodlCurveFailure());
