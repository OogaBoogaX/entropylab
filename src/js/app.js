import { sha256 as Z } from "./hashes.js";
// secp256k1 operations run in the libsecp256k1 WebAssembly module; the facade
// is a drop-in for the noble/curves surface this file uses (see
// src/js/secp256k1.js). App boot waits for the module to be ready.
import { secp256k1 as xe, secp256k1Ready } from "./secp256k1.js";
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
import { inspectPsbtInscriptions, describeEnvelope } from "./inscription.js";
import { parseOpReturn, describeOpReturn } from "./opreturn.js";
import { parseRawTx, extractEcdsaSignatures, inscriptionHints, isPsbtMagic, serializeTx } from "./tx.js";
import { wasmExports as hodlWasm, withInput as hodlWasmIn, withOutput as hodlWasmOut } from "./entropylab-wasm.js";
import { indexHdKey, indexSingleKey, matchOwnership, pathLabel } from "./ownership.js";
import { hex as M } from "./coders.js";
import { addressFor, addressFromScript, multisigScript, multisigTrScript, p2shP2wpkhScript, p2shScript, p2trKeyScript, p2trLeafScript, p2wshScript } from "./addresses.js";
import { base58checkDecode, base58checkEncode } from "./base58.js";
import { HDKey as Gt } from "./hdkey.js";
import { entropyToMnemonic as bi, mnemonicToEntropy as Er, mnemonicToSeedSync as wi, validateMnemonic as Pn } from "./bip39.js";
import { wordlist as bip39English } from "./bip39-english.js";
// The PSBT editor (its own workspace tab) drives the rust-bitcoin WASM
// bindings in psbt-wasm.js; heavy lifting lives in psbt-editor.js.
import { initPsbtEditor } from "./psbt-editor.js";
import { renderSVG as Xs } from "uqr";
import { BIP39_LANGUAGE_ENGLISH, BIP85_APPS, bip85Path, deriveApplication, parseHardenedIndex, wipeBip85Result, wipeBytes as hodlWipeBytes } from "./bip85.js";
const Ae = Object.freeze(bip39English);
const tr = Z;
const Yr = (privateKey, compressed) => xe.getPublicKey(privateKey, compressed);
var vr = [16, 20, 24, 28, 32], Rc = { 0: "00", 1: "01", 2: "10", 3: "11", 4: "0", 5: "1" };
function kr(e) {
  return e <= 0 ? 0 : e * Math.log2(6);
}
function Br(e) {
  let t = [], r = "";
  for (let n of e) /\s|,|;|\|/.test(n) || (n >= "1" && n <= "6" ? t.push(n) : r += n);
  return { rolls: t, leftover: r };
}
function mi(e, t) {
  let r = 0;
  for (let n of e) r = r * 4 + (n - 1);
  return r = r * 2 + t, Ae[r];
}
function Sr(e, t = 24) {
  let r = t === 12 ? 11 : 23, n = [], o = 0, i = "", s = 0, c = [], a = [], f = [];
  for (let l of e) {
    if (/\s|,|;|\|/.test(l)) continue;
    let u = l.toLowerCase(), p = u >= "1" && u <= "6", b = u === "h" || u === "t";
    if (!p && !b) {
      i += l;
      continue;
    }
    if (n.length >= r) {
      s += 1;
      continue;
    }
    if (c.length < 5) {
      if (b) {
        i += l;
        continue;
      }
      let E = Number(u);
      if (E >= 5) {
        o += 1;
        continue;
      }
      c.push(E);
      continue;
    }
    let w;
    u === "h" || u === "1" || u === "2" || u === "3" ? w = 0 : w = 1, n.push(mi(c, w)), c = [];
  }
  let d = n.length >= r ? "last-word" : c.length === 5 ? "coin" : "dice", h = n.length * 11;
  return a.push(`BitBox diceware: ${n.length} of ${r} lookup-table words (${h} bits). Then pick the checksum word.`), o > 0 && a.push(`Skipped ${o} face${o === 1 ? "" : "s"} of 5 or 6 on the first five dice of a word (BitBox reroll).`), s > 0 && f.push("Extra rolls after the last lookup-table word are ignored. The checksum word is a pick, not another roll."), i.length > 0 && f.push(`Ignored characters: ${JSON.stringify(i.slice(0, 24))}`), { words: n, targetWords: t, neededPartial: r, skippedHigh: o, leftover: i, extraAfter: s, waiting: d, diceInWord: c.length, bits: h, notes: a, warnings: f };
}
function $n(e, t) {
  if (t === "bitbox") return { ok: false, error: "BitBox diceware is not a hash of the digit string. Stay in BitBox-style mode and pick the checksum word after 23 lookup-table words.", notes: [], warnings: [] };
  let r = [], n = [], { rolls: o, leftover: i } = Br(e);
  if (i.length > 0) return { ok: false, error: `Dice must be faces 1\u20136. Ignored characters: ${JSON.stringify(i.slice(0, 24))}`, notes: r, warnings: n };
  if (o.length === 0) return { ok: false, error: "Enter at least one dice roll (faces 1\u20136).", notes: r, warnings: n };
  let s = kr(o.length);
  if (r.push(`${o.length} rolls of a fair six-sided die \u2248 ${s.toFixed(1)} bits.`), t === "coldcard") {
    let a = new TextEncoder().encode(o.join("")), f = Z(a);
    return o.length < 50 ? n.push("Fewer than 50 rolls. They still hash to 24 words, but real entropy is under 128 bits. Use 99 rolls for a full 256-bit 24-word seed.") : o.length < 99 && n.push("Fewer than 99 rolls. You have at least 128 bits; 99 rolls is the full 256-bit target."), r.push("Hash the rolls: SHA-256 of the digit string. Same math Coldcard shows on its dice check."), { ok: true, bytes: f, hex: M.encode(f), bits: 256, sourceBits: s, method: "coldcard-sha256", notes: r, warnings: n };
  }
  let c = o.map((a) => a === "6" ? "0" : a).map((a) => Rc[a] ?? "").join("");
  return r.push("Ian Coleman-style: each face is mapped through a prefix-free bit table (6 becomes 0). This is not the same as hashing the rolls."), xi(c, s, "coleman-dice", r, n);
}
function In(e) {
  let t = [], r = [], n = e.replace(/\s|_/g, "").replace(/^0x/i, "").toLowerCase();
  if (!n) return { ok: false, error: "Paste hexadecimal entropy (0-9, a-f).", notes: t, warnings: r };
  if (!/^[0-9a-f]+$/.test(n)) return { ok: false, error: "Hex entropy may only contain 0-9 and a-f.", notes: t, warnings: r };
  if (n.length % 2 !== 0) return { ok: false, error: "Hex entropy must have an even number of characters (whole bytes).", notes: t, warnings: r };
  let o = M.decode(n), i = o.length * 8;
  t.push(`${o.length} bytes = ${i} bits of hex entropy.`);
  let s = Uc(o, t, r);
  return s.ok ? { ok: true, bytes: s.bytes, hex: M.encode(s.bytes), bits: s.bytes.length * 8, sourceBits: i, method: "hex", notes: t, warnings: r } : s;
}
function On(e) {
  let t = [], r = [], n = e.replace(/\s/g, "");
  return n ? /^[01]+$/.test(n) ? (t.push(`${n.length} coin-flip bits.`), xi(n, n.length, "binary", t, r)) : { ok: false, error: "Binary entropy may only contain 0 and 1.", notes: t, warnings: r } : { ok: false, error: "Enter a string of 0s and 1s.", notes: t, warnings: r };
}
function _n(e) {
  return bi(e, Ae);
}
function Rn(e) {
  return e.trim().toLowerCase().replace(/[^a-z\s]/g, " ").split(/\s+/).filter(Boolean).join(" ");
}
function Mt(e) {
  let t = Rn(e).split(" ").filter(Boolean), r = t.map((o, i) => ({ index: i, word: o })).filter(({ word: o }) => !Ae.includes(o));
  if (t.length === 0) return { ok: false, words: t, error: "Type or paste your seed phrase.", unknown: r };
  if (![12, 15, 18, 21, 24].includes(t.length)) return { ok: false, words: t, unknown: r, error: `A seed phrase is 12, 15, 18, 21, or 24 words. You entered ${t.length}.` };
  if (r.length > 0) return { ok: false, words: t, unknown: r, error: `Word ${r[0].index + 1} (\u201C${r[0].word}\u201D) is not on the BIP39 English list.` };
  let n = t.join(" ");
  return Pn(n, Ae) ? { ok: true, words: t, unknown: r } : { ok: false, words: t, unknown: r, error: "Words are on the list, but the checksum does not match. One of the words is wrong, or this is not a BIP39 phrase." };
}
function Tr(e) {
  let t = Rn(e).split(" ").filter(Boolean), n = { 11: 12, 14: 15, 17: 18, 20: 21, 23: 24 }[t.length];
  if (!n) return null;
  let o = t.filter((s) => !Ae.includes(s));
  if (o.length > 0) return { partialCount: t.length, completeCount: n, candidates: [], error: `\u201C${o[0]}\u201D is not on the BIP39 English list.` };
  let i = [];
  for (let s of Ae) Pn([...t, s].join(" "), Ae) && i.push(s);
  return { partialCount: t.length, completeCount: n, candidates: i };
}
function xi(e, t, r, n, o) {
  let s = vr.map((d) => d * 8).filter((d) => d <= e.length).pop();
  if (!s) return { ok: false, error: `Need at least 128 bits for a 12-word seed. This input is ${e.length} bits.`, notes: n, warnings: o };
  e.length > s && o.push(`Using the first ${s} bits of ${e.length}. Extra bits are not mixed in.`);
  let c = e.slice(0, s), a = new Uint8Array(s / 8);
  for (let d = 0; d < a.length; d++) a[d] = Number.parseInt(c.slice(d * 8, d * 8 + 8), 2);
  n.push(`BIP39 entropy length: ${s} bits \u2192 ${s / 32 + s / 11} wait`);
  let f = s / 32 * 3;
  return n[n.length - 1] = `BIP39 entropy length: ${s} bits \u2192 ${f}-word seed.`, { ok: true, bytes: a, hex: M.encode(a), bits: s, sourceBits: t, method: r, notes: n, warnings: o };
}
function Uc(e, t, r) {
  let n = e.length;
  if (vr.includes(n)) return { ok: true, bytes: e, hex: M.encode(e), bits: n * 8, sourceBits: n * 8, method: "hex", notes: t, warnings: r };
  let o = [...vr].filter((s) => s < e.length).pop();
  if (!o) return { ok: false, error: `Need 16, 20, 24, 28, or 32 bytes of entropy (128\u2013256 bits). Got ${e.length} bytes.`, notes: t, warnings: r };
  r.push(`Took the first ${o} bytes (${o * 8} bits) of ${e.length}. Extra bytes were not mixed in.`);
  let i = e.slice(0, o);
  return { ok: true, bytes: i, hex: M.encode(i), bits: o * 8, sourceBits: e.length * 8, method: "hex", notes: t, warnings: r };
}
function Pr(e, t, r = () => {
}) {
  if (!Array.isArray(e)) throw new TypeError(`"${t}" expected array, got type=${typeof e}`);
  for (let n = 0; n < e.length; n++) r(e[n], `${t}[${n}]`);
  return e;
}
var sr = { encode: base58checkEncode, decode: base58checkDecode }, ff = BigInt("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"), To = [{ id: "bip44", bip: "BIP44", label: "Legacy", short: "Legacy 1\u2026", beginner: "Addresses that start with 1. Oldest type. Bitcoin Core can import these with importprivkey.", script: "p2pkh", purpose: 44, slip: "x" }, { id: "bip49", bip: "BIP49", label: "Nested SegWit", short: "Nested 3\u2026", beginner: "Addresses that start with 3. A SegWit script wrapped so older wallets can still send to it.", script: "p2sh-p2wpkh", purpose: 49, slip: "y" }, { id: "bip84", bip: "BIP84", label: "Native SegWit", short: "SegWit bc1q\u2026", beginner: "Addresses that start with bc1q. The default in Bitcoin Core, Sparrow, and Electrum today.", script: "p2wpkh", purpose: 84, slip: "z" }, { id: "bip86", bip: "BIP86", label: "Taproot", short: "Taproot bc1p\u2026", beginner: "Addresses that start with bc1p. Newest type. Use this if your wallet speaks Taproot.", script: "p2tr", purpose: 86, slip: "v" }], cr = { mainnet: { x: { pub: 76067358, prv: 76066276, pubName: "xpub", prvName: "xprv" }, y: { pub: 77429938, prv: 77428856, pubName: "ypub", prvName: "yprv" }, z: { pub: 78792518, prv: 78791436, pubName: "zpub", prvName: "zprv" }, v: { pub: 73342198, prv: 73341116, pubName: "vpub", prvName: "vprv" } }, testnet: { x: { pub: 70617039, prv: 70615956, pubName: "tpub", prvName: "tprv" }, y: { pub: 71979618, prv: 71978536, pubName: "upub", prvName: "uprv" }, z: { pub: 73342198, prv: 73341116, pubName: "vpub", prvName: "vprv" }, v: { pub: 39277699, prv: 39276616, pubName: "npub", prvName: "nprv" } } };
function df(e) {
  return e === "mainnet" ? 128 : 239;
}
function Rs(e) {
  let index = Number(e);
  return Number.isSafeInteger(index) && index >= 0 && index <= 2147483647 ? index : e === "mainnet" ? 0 : 1;
}
function hodlPathIndex(value, hardened = false) {
  return `${value}${hardened ? "'" : ""}`;
}
function hodlOriginPathIndex(value, hardened = false) {
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
    path: `m${components.map((entry) => `/${hodlPathIndex(entry.index, entry.hardened)}`).join("")}`,
    originPath: components.map((entry) => hodlOriginPathIndex(entry.index, entry.hardened)).join("/"),
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
  let branchPath = `${accountPath}/${hodlPathIndex(branchWindow.start, hardening.branch)}`;
  if (addressWindow.range > 1) return branchPath;
  return `${branchPath}/${hodlPathIndex(addressWindow.start, hardening.address)}`;
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
    accountPath: `m${parts.map((entry) => `/${hodlPathIndex(entry.index, entry.hardened)}`).join("")}`,
    originPath: parts.map((entry) => hodlOriginPathIndex(entry.index, entry.hardened)).join("/"),
    hasHardenedPrefix: parts.some((entry) => entry.hardened),
    hardening
  };
}
function Ao(e, t, r = 0, hardening = hodlDefaultHardening()) {
  return `m/${hodlPathIndex(e.purpose, hardening.purpose)}/${hodlPathIndex(Rs(t), hardening.coinType)}/${hodlPathIndex(r, hardening.account)}`;
}
function Us(e) {
  return (e >>> 0).toString(16).padStart(8, "0");
}
function le(e, t) {
  let r = sr.decode(e), n = new Uint8Array(r);
  return n[0] = t >>> 24 & 255, n[1] = t >>> 16 & 255, n[2] = t >>> 8 & 255, n[3] = t & 255, sr.encode(n);
}
function lf(e) {
  let t = sr.decode(e.trim());
  return (t[0] << 24 | t[1] << 16 | t[2] << 8 | t[3]) >>> 0;
}
var So = [];
for (let e of Object.values(cr)) for (let t of Object.values(e)) So.push({ ver: t.prv, private: true }), So.push({ ver: t.pub, private: false });
function uf(e) {
  let t = lf(e), r = So.find((o) => o.ver === t);
  if (!r) throw new Error("Not a recognized extended key (xprv/xpub/ypub/zpub/vpub).");
  let n = r.private ? cr.mainnet.x.prv : cr.mainnet.x.pub;
  return { xkey: le(e, n), isPrivate: r.private };
}
function rn(e, t, r) {
  let n = new Uint8Array([df(r)]), o = t ? Os(n, e, new Uint8Array([1])) : Os(n, e);
  return sr.encode(o);
}
function Ls(e) {
  let t = sr.decode(e.trim());
  if (t.length !== 33 && t.length !== 34) throw new Error("WIF decoded to an unexpected length.");
  let r = t[0], n;
  if (r === 128) n = "mainnet";
  else if (r === 239) n = "testnet";
  else throw new Error("WIF prefix is not Bitcoin mainnet (5/K/L) or testnet (9/c).");
  if (t.length === 34) {
    if (t[33] !== 1) throw new Error("Compressed WIF is missing the 0x01 suffix.");
    return { priv: t.slice(1, 33), compressed: true, network: n };
  }
  return { priv: t.slice(1), compressed: false, network: n };
}
function Os(...e) {
  let t = e.reduce((o, i) => o + i.length, 0), r = new Uint8Array(t), n = 0;
  for (let o of e) r.set(o, n), n += o.length;
  return r;
}
function hf(e) {
  if (e.length !== 32) throw new Error("Private key must be 32 bytes.");
  let t = BigInt("0x" + M.encode(e));
  if (t === 0n || t >= ff) throw new Error("Private key is out of the secp256k1 range.");
  xe.getPublicKey(e, true);
}
function pf(e, t, r) {
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
function hodlDerivedAddressRow(node, accountPath, script, network, role, index, addressHardened = false, branchHardened = false) {
  let chain = Number.isSafeInteger(role) ? role : role === "receive" ? 0 : 1, branchStep = hodlPathIndex(chain, branchHardened), indexStep = hodlPathIndex(index, addressHardened), child = node.derive(`m/${branchStep}/${indexStep}`), publicKey = child.publicKey;
  if (!publicKey) throw new Error("Missing public key");
  let privateKey = child.privateKey;
  let row = { index, role: hodlAddressBranchRole(chain), branch: chain, branchHardened, path: `${accountPath}/${branchStep}/${indexStep}`, address: pf(script, publicKey, network), wif: privateKey ? rn(privateKey, true, network) : null, pubkey: M.encode(publicKey), privHex: privateKey ? M.encode(privateKey) : null };
  child.wipePrivateData();
  if (privateKey) privateKey.fill(0); // the getter copy; the row keeps its strings
  return row;
}
function nn(e, t, r, n, o, i, startIndex = 0, addressHardened = false, branchHardened = false) {
  let rows = [];
  for (let index = startIndex; index < startIndex + o; index++) rows.push(hodlDerivedAddressRow(e, t, r, n, i, index, addressHardened, branchHardened));
  return rows;
}
var gf = "0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`JKLMNOPQRSTUVWXYZ", yf = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
function bf(e) {
  let t = [], r = [];
  for (let n of e) {
    let o = gf.indexOf(n);
    if (o < 0) throw new Error(`Invalid descriptor character: ${n}`);
    r.push(o & 31), t.push(o >> 5), t.length === 3 && (r.push(t[0] * 9 + t[1] * 3 + t[2]), t.length = 0);
  }
  return t.length === 1 ? r.push(t[0]) : t.length === 2 && r.push(t[0] * 3 + t[1]), r;
}
function wf(e) {
  let t = [0xf5dee51989n, 0xa9fdca3312n, 0x1bab10e32dn, 0x3706b1677an, 0x644d626ffdn], r = 1n;
  for (let n of e) {
    let o = r >> 35n;
    r = (r & 0x7ffffffffn) << 5n ^ BigInt(n);
    for (let i = 0; i < 5; i++) (o >> BigInt(i) & 1n) !== 0n && (r ^= t[i]);
  }
  return r;
}
function Cs(e) {
  let t = bf(e).concat([0, 0, 0, 0, 0, 0, 0, 0]), r = wf(t) ^ 1n, n = "";
  for (let o = 0; o < 8; o++) {
    let i = Number(r >> BigInt(5 * (7 - o)) & 31n);
    n += yf[i];
  }
  return n;
}
function Le(e) {
  return `${e}#${Cs(e)}`;
}
function Ye(e, t) {
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
function tn(e, t, r, n, o, s = 0) {
  let i = Rs(r);
  return `[${e}/${t.purpose}h/${i}h/${s}h]${n}/${o}/*`;
}
function mf(e, t, r, n, o, q = 0, addressStart = 0) {
  let i = Ao(t, r, q), s = e.derive(i), c = s.publicExtendedKey, a = s.privateExtendedKey ?? null, f = cr[r], d = le(c, f.y.pub), h = le(c, f.z.pub), l = le(c, f.v.pub), u = a ? le(a, f.y.prv) : null, p = a ? le(a, f.z.prv) : null, b = a ? le(a, f.v.prv) : null, w = tn(o, t, r, c, 0, q), E = tn(o, t, r, c, 1, q), A = a ? tn(o, t, r, a, 0, q) : null, C = a ? tn(o, t, r, a, 1, q) : null;
  return { def: t, accountPath: i, xprv: a, xpub: c, ypub: d, yprv: u, zpub: h, zprv: p, vpub: l, vprv: b, receiveDescriptor: Le(Ye(t.script, w)), changeDescriptor: Le(Ye(t.script, E)), receiveDescriptorPriv: A ? Le(Ye(t.script, A)) : null, changeDescriptorPriv: C ? Le(Ye(t.script, C)) : null, receive: nn(s, i, t.script, r, n, "receive", addressStart), change: nn(s, i, t.script, r, n, "change", addressStart) };
}
function Hs(e, t, r, n, o = 0, addressStart = 0) {
  let i = Math.min(Math.max(r, 1), 10000), s = Us(e.fingerprint), c = To.map((a) => mf(e, a, t, i, s, o, addressStart));
  return { kind: "hd", network: t, mnemonic: n.mnemonic, passphraseUsed: n.passphraseUsed, entropyHex: n.entropyHex, seedHex: n.seedHex, rootXprv: e.privateExtendedKey ?? null, rootXpub: e.publicExtendedKey, masterFingerprint: s, notes: n.notes, warnings: n.warnings, accounts: c };
}
function on(e, t, r, n, o = 0, addressStart = 0) {
  let i = _n(e.bytes);
  try {
    return ar(i, t, r, n, { entropyHex: e.hex, notes: e.notes, warnings: e.warnings }, o, addressStart);
  } finally {
    e.bytes.fill(0); // the entropy bytes are dead once the mnemonic exists
  }
}
function ar(e, t, r, n, o, p = 0, addressStart = 0) {
  let i = Mt(e);
  if (!i.ok) throw new Error(i.error ?? "Invalid seed phrase");
  let s = i.words.join(" "), c = wi(s, t);
  try {
    let a = Gt.fromMasterSeed(c), f = o?.entropyHex ?? null;
    f || (f = M.encode(Er(s, Ae)));
    let d = [...o?.warnings ?? []];
    t.length > 0 && d.push("A passphrase is in use. The same words without this passphrase are a different wallet. Do not store the passphrase with the words.");
    let wallet = Hs(a, r, n, { mnemonic: s, passphraseUsed: t.length > 0, entropyHex: f, seedHex: M.encode(c), notes: o?.notes ?? [], warnings: d }, p, addressStart);
    a.wipePrivateData();
    return wallet;
  } finally {
    c.fill(0); // the 64-byte seed is dead once the root node exists
  }
}
function Po(e, t, r, q = 0) {
  let n = e.trim(), { xkey: o, isPrivate: i } = uf(n), s = Gt.fromExtendedKey(o), c = [i ? "Imported an extended private key. Addresses and WIF keys are derived from it." : "Imported an extended public key. This is watch-only: addresses can be generated, spending keys cannot."];
  try {
    if (s.depth === 0) return Hs(s, t, r, { mnemonic: null, passphraseUsed: false, entropyHex: null, seedHex: null, notes: c, warnings: i ? [] : ["Watch-only. Private keys are not in this key."] }, q);
    let a = Us(s.parentFingerprint || s.fingerprint), f = Math.min(Math.max(r, 1), 50), d = To.map((h) => {
      let l = s.publicExtendedKey, u = i ? s.privateExtendedKey : null, p = cr[t], b = `imported/${h.id}`, w = `[${a}]${l}/0/*`, E = `[${a}]${l}/1/*`, A = u ? `[${a}]${u}/0/*` : null, C = u ? `[${a}]${u}/1/*` : null;
      return { def: h, accountPath: b, xprv: u, xpub: l, ypub: le(l, p.y.pub), yprv: u ? le(u, p.y.prv) : null, zpub: le(l, p.z.pub), zprv: u ? le(u, p.z.prv) : null, vpub: le(l, p.v.pub), vprv: u ? le(u, p.v.prv) : null, receiveDescriptor: Le(Ye(h.script, w)), changeDescriptor: Le(Ye(h.script, E)), receiveDescriptorPriv: A ? Le(Ye(h.script, A)) : null, changeDescriptorPriv: C ? Le(Ye(h.script, C)) : null, receive: nn(s, b, h.script, t, f, "receive"), change: nn(s, b, h.script, t, f, "change") };
    });
    return { kind: "hd", network: t, mnemonic: null, passphraseUsed: false, entropyHex: null, seedHex: null, rootXprv: i && s.depth === 0 ? s.privateExtendedKey ?? null : null, rootXpub: s.depth === 0 ? s.publicExtendedKey : null, masterFingerprint: a, notes: c, warnings: [...i ? [] : ["Watch-only. Private keys are not in this key."], `This extended key is not the BIP32 root. The imported node is reused directly; Account ${q} cannot select a different hardened sibling.`], accounts: d };
  } finally {
    s.wipePrivateData(); // the imported node is dead once the result strings exist
  }
}
function $o(e) {
  let t = e.trim();
  return !t.startsWith("S") || t.length !== 22 && t.length !== 30 || !/^[A-Za-z0-9]+$/.test(t) ? false : Z(new TextEncoder().encode(t + "?"))[0] === 0;
}
function Ns(e) {
  if (!$o(e)) throw new Error("Not a valid Casascius mini private key.");
  return Z(new TextEncoder().encode(e.trim()));
}
function hodlBrainWalletPassphrase(value, trimBoundaryWhitespace = false) {
  let passphrase = String(value ?? ""), normalized = trimBoundaryWhitespace ? passphrase.trim() : passphrase;
  if (!normalized.length) throw new Error(trimBoundaryWhitespace && passphrase.length ? "Trimming boundary whitespace leaves an empty brain-wallet recovery passphrase." : "Enter the brain-wallet recovery passphrase.");
  return normalized;
}
function hodlBrainWalletPrivateKey(value, trimBoundaryWhitespace = false) {
  return Z(new TextEncoder().encode(hodlBrainWalletPassphrase(value, trimBoundaryWhitespace)));
}
function hodlBrainLabEntropy(value) {
  let text = String(value ?? ""), notes = [], warnings = [];
  if (!text.length) return { ok: false, error: "Enter the brain-wallet lab text.", notes, warnings };
  let bytes = Z(new TextEncoder().encode(text)), hex = M.encode(bytes);
  notes.push("SHA-256 of the exact UTF-8 text is 32 bytes of BIP39 entropy (256 bits → 24 words).");
  warnings.push("Lab only. Strength is the entropy of this text, not the 24-word count.");
  warnings.push("SHA-256(text) is unsalted and fast. Anyone who can guess the text recovers the wallet.");
  warnings.push("This is not a BIP39 passphrase, and it is not a Bitcoin Core hdseed or address-key backup.");
  warnings.push("A valid mnemonic does not mean it is the same wallet as hashing the text as a Core private key.");
  return { ok: true, bytes, hex, bits: 256, sourceBits: 256, method: "brain-lab", notes, warnings };
}
function Io(e, t, r, trimBrainWallet = false) {
  let n = [], o = [], i, s = null, c = t, a = r === "brain" ? hodlBrainWalletPassphrase(e, trimBrainWallet) : e.trim();
  if (r === "brain") {
    o.push("Brain wallets are dangerous. Humans pick guessable phrases. Anyone who guesses the phrase takes the coins. Prefer dice or a hardware-verified seed."), i = hodlBrainWalletPrivateKey(e, trimBrainWallet), n.push(trimBrainWallet ? "Brain wallet recovery: SHA-256 used the passphrase after trimming leading and trailing whitespace." : "Brain wallet recovery: SHA-256 used the passphrase exactly as entered.");
  } else if (r === "minikey" || $o(a)) i = Ns(a), s = a, n.push("Casascius mini private key decoded via SHA-256.");
  else if (/^[5KL9c][1-9A-HJ-NP-Za-km-z]{50,51}$/.test(a)) {
    let E = Ls(a);
    i = E.priv, c = E.network, n.push(E.compressed ? "Decoded a compressed WIF private key (starts with K or L on mainnet)." : "Decoded an uncompressed WIF private key (starts with 5 on mainnet).");
  } else {
    let E = a.replace(/\s/g, "").replace(/^0x/i, "");
    if (!/^[0-9a-fA-F]{64}$/.test(E)) throw new Error("Enter a WIF key (5/K/L\u2026), a 64-character hex private key, or a Casascius mini key (S\u2026).");
    i = M.decode(E.toLowerCase()), n.push("Decoded a 32-byte hex private key.");
  }
  hf(i);
  let f = Yr(i, true), d = Yr(i, false), l = addressFor("p2pkh", d, c), u = addressFor("p2pkh", f, c), p = addressFor("p2sh-p2wpkh", f, c), b = addressFor("p2wpkh", f, c), w = addressFor("p2tr", f, c);
  let wallet = { kind: "single", network: c, warnings: o, notes: n, privHex: M.encode(i), wifCompressed: rn(i, true, c), wifUncompressed: rn(i, false, c), pubkeyCompressed: M.encode(f), pubkeyUncompressed: M.encode(d), p2pkhUncompressed: l, p2pkhCompressed: u, p2shP2wpkh: p, p2wpkh: b, p2tr: w, minikey: s };
  i.fill(0); // the decoded private key bytes; the result keeps its hex/WIF strings
  return wallet;
}
function Oo(e, t) {
  let r = [];
  if (r.push("ENTROPYLAB \u2014 RECOVERY SHEET"), r.push("This file was computed locally. The calculator never generated wallet entropy."), r.push(""), e.kind === "single") {
    r.push(`Network: ${e.network}`);
    for (let n of e.notes) r.push(`Note: ${n}`);
    for (let n of e.warnings) r.push(`Warning: ${n}`);
    return r.push(""), r.push("ADDRESSES"), r.push(`Legacy uncompressed: ${e.p2pkhUncompressed}`), r.push(`Legacy compressed:   ${e.p2pkhCompressed}`), r.push(`Nested SegWit:       ${e.p2shP2wpkh}`), r.push(`Native SegWit:       ${e.p2wpkh}`), r.push(`Taproot:             ${e.p2tr}`), r.push(`Compressed public key:   ${e.pubkeyCompressed}`), r.push(`Uncompressed public key: ${e.pubkeyUncompressed}`), t ? (r.push(""), r.push("YOUR BITCOIN CORE PRIVATE KEY (WIF, compressed \u2014 use this with importprivkey)"), r.push(e.wifCompressed ?? ""), r.push("WIF uncompressed: " + (e.wifUncompressed ?? "")), r.push("Hex private key:  " + (e.privHex ?? "")), e.minikey && r.push("Mini key: " + e.minikey)) : (r.push(""), r.push("Private keys hidden. Reveal them on an air-gapped computer.")), r.join(`
`);
  }
  r.push(`Network: ${e.network}`), r.push(`Master fingerprint: ${e.masterFingerprint}`), e.passphraseUsed && r.push("Passphrase: YES (not printed)");
  for (let n of e.notes) r.push(`Note: ${n}`);
  for (let n of e.warnings) r.push(`Warning: ${n}`);
  r.push(""), e.mnemonic && (r.push("YOUR SEED PHRASE"), r.push(e.mnemonic), r.push("")), t && e.seedHex && (r.push("MASTER SEED HEX (BIP39 PBKDF2, 512 bits)"), r.push(e.seedHex), r.push("")), t && e.entropyHex && (r.push("BIP39 ENTROPY HEX"), r.push(e.entropyHex), r.push("")), r.push("BIP32 ROOT XPUB"), r.push(e.rootXpub), t && e.rootXprv && (r.push("BIP32 ROOT XPRV"), r.push(e.rootXprv)), r.push("");
  for (let n of e.accounts) {
    r.push(`=== ${n.def.label} (${n.def.bip}) ${hodlDisplayDerivationPath(n.accountPath)} ===`), r.push(n.def.beginner), r.push(`xpub: ${n.xpub}`), r.push(`ypub: ${n.ypub}`), r.push(`zpub: ${n.zpub}`), r.push(`vpub: ${n.vpub}`), t && (n.xprv && r.push(`xprv: ${n.xprv}`), n.yprv && r.push(`yprv: ${n.yprv}`), n.zprv && r.push(`zprv: ${n.zprv}`), n.vprv && r.push(`vprv: ${n.vprv}`)), r.push(`Watch-only receive descriptor: ${n.receiveDescriptor}`), r.push(`Watch-only change descriptor:  ${n.changeDescriptor}`), t && (n.receiveDescriptorPriv && r.push(`Spending receive descriptor: ${n.receiveDescriptorPriv}`), n.changeDescriptorPriv && r.push(`Spending change descriptor:  ${n.changeDescriptorPriv}`)), r.push("RECEIVE");
    for (let o of n.receive) {
      let i = t && o.wif ? `  WIF ${o.wif}` : "";
      r.push(`  ${o.index}  ${hodlDisplayDerivationPath(o.path)}  ${o.address}${i}`);
    }
    r.push("CHANGE");
    for (let o of n.change) {
      let i = t && o.wif ? `  WIF ${o.wif}` : "";
      r.push(`  ${o.index}  ${hodlDisplayDerivationPath(o.path)}  ${o.address}${i}`);
    }
    r.push("");
  }
  return r.join(`
`);
}
function an(e, t = "#111111", r = "#ffffff") {
  return Xs(e, { ecc: "M", border: 2, pixelSize: 4, blackColor: t, whiteColor: r });
}
if (globalThis.__entropyLabTest) globalThis.__entropyLabCrypto = { entropyToMnemonic: (hex) => _n(M.decode(hex)), mnemonicToEntropy: (mnemonic) => M.encode(Er(mnemonic, Ae)), mnemonicToSeed: (mnemonic, passphrase) => M.encode(wi(mnemonic, passphrase)), validateMnemonic: (mnemonic) => Mt(mnemonic).ok, masterXprv: (mnemonic, passphrase) => Gt.fromMasterSeed(wi(mnemonic, passphrase)).privateExtendedKey, privateKeyInputIsValid: () => hodlPrivateKeyInputIsValid(), computeTargetLastWords: (words, targetWords) => hodlComputeTargetLastWords(words, targetWords), clearLastWordCache: () => hodlLastWordCache.clear(), validateTargetMnemonic: (value, targetWords) => hodlValidateTargetMnemonic(value, targetWords), bruteTargetLastWords: (value) => Tr(value) };
var ec = document.getElementById("btc-calc");
if (!ec) throw new Error("#app missing");
ec.innerHTML = `
  <div class="site-header no-print">
    <div class="site-header-inner">
      <span class="site-logo" aria-hidden="true"></span>
      <span class="site-title">EntropyLab</span>
      <span class="site-version"><span class="site-version-number">v{{VERSION}}</span> <span class="site-version-tag">(Latest)</span></span>
      <span class="network-status" id="network-status" data-state="online" role="status" aria-label="Network status: online">Online</span>
      <div class="download-controls">
        <a class="btn secondary download-html header-button" href="entropylab.html" download="entropylab.html" aria-label="Download EntropyLab"><svg class="download-mark" viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M12 3v12M7 11l5 5 5-5M5 21h14"/></svg><span class="control-label">Download</span></a>
        <a class="btn secondary github-repo-link header-button" href="https://github.com/w-s-bitcoin/entropylab" target="_blank" rel="noopener noreferrer" aria-label="View the EntropyLab GitHub repository in a new tab"><svg class="github-mark" viewBox="0 0 16 16" width="18" height="18" aria-hidden="true" focusable="false"><path fill="currentColor" d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z"/></svg><span class="control-label">GitHub</span></a>
<button type="button" class="seed-keyboard-toggle theme-toggle header-button" id="theme-toggle" data-theme-mode="dark" aria-label="Theme: dark. Switch to light"><svg class="theme-icon-dark" viewBox="0 0 24 24" aria-hidden="true" focusable="false"><path d="M20 14.5A8 8 0 0 1 9.5 4a8 8 0 1 0 10.5 10.5z"/></svg><svg class="theme-icon-light" viewBox="0 0 24 24" aria-hidden="true" focusable="false"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/></svg></button>
      </div>
    </div>
  </div>
  <div class="wrap">
    <aside class="beta-warning no-print" id="beta-warning" role="alert">
      <div class="beta-warning-text"><strong>Beta software</strong> EntropyLab is experimental and should only be used for testing and educational purposes.</div>
      <button type="button" class="beta-warning-dismiss" id="beta-warning-dismiss" aria-label="Dismiss the beta software warning"><svg viewBox="0 0 24 24" width="24" height="24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M18 6 6 18M6 6l12 12"/></svg></button>
    </aside>
    <aside class="online-warning no-print" id="online-warning" role="alert" hidden>
      <div class="online-warning-text"><strong>Online version</strong> Do not enter seed phrases, private keys, or other wallet secrets on an internet-connected device. <a href="entropylab.html" download="entropylab.html">Download EntropyLab</a> and run the HTML file offline on a trusted, air-gapped computer. On iPhone, Safari users can choose Share → Add to Home Screen → Open as Web App; after the first load, disconnect all networks before reopening it. Cached availability is not proof of an air gap.</div>
    </aside>
    <!-- TODO: This copy is being kept for the network-detected modal that will
         replace the banner. Verbatim, with the lead-in as the modal's title:
         "Network detected:" / "This computer has an active network adapter — it
         is online and possibly connected to the internet. Do not enter wallet
         secrets here; disconnect from all networks (Wi-Fi and Ethernet) and use
         this file on an air-gapped computer." -->
    <section class="card">
      <div class="kicker">Run Offline \xB7 Bring your own entropy</div>
      <h1>Hold or receive bitcoin without a signing device.</h1>
      <ul class="pitch-list muted">
        <li>Save this air-gapped bitcoin calculator to a removable drive and open it on a computer that never goes online.</li>
        <li>Turn dice rolls or a seed you already have into receive addresses.</li>
        <li>Export an xpub and load into Bitcoin Core or any watch-only wallet, and get paid.</li>
        <li>Keep your private keys offline.</li>
      </ul>
    </section>
    <nav class="workspace no-print" id="workspace"></nav>
      <div class="workspace-panel" id="workspace-panel">
      <div class="tool-intro" id="calc-tool-intro">
        <div class="kicker">Your entropy enters the lab</div>
        <h2>Create. Derive. Verify.</h2>
        <p class="muted calc-intro">Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat.</p>
      </div>
      <section class="key-manager no-print" id="key-manager">
      <div class="key-tab-strip"><div class="key-tabs" id="key-tabs" role="tablist" aria-label="Keys"></div><div class="add-item-control"><button class="add-key" id="add-key" type="button" aria-label="Open the lab to derive another key" aria-describedby="add-key-tooltip">+</button><span class="add-item-tooltip" id="add-key-tooltip" role="tooltip">Open the lab to derive another key</span></div><div class="add-item-control"><button class="add-key remove-key" id="delete-key" type="button" aria-label="Delete current key" aria-describedby="delete-key-tooltip" disabled>−</button><span class="add-item-tooltip" id="delete-key-tooltip" role="tooltip">Delete this key</span></div></div>
    </section>
    <section class="card no-print" id="calc-card" role="tabpanel" hidden>
      <div class="row segmented-control" id="modes" role="group" aria-label="Key input mode"></div>
      <div class="key-summary" id="key-summary" hidden>
        <img class="key-summary-lifehash" id="key-summary-lifehash" width="48" height="48" alt="" hidden>
        <div class="key-summary-text">
          <code class="key-summary-fingerprint" id="key-summary-fingerprint"></code>
          <p class="key-summary-meta" id="key-summary-method"></p>
          <p class="key-summary-meta" id="key-summary-script"></p>
          <p class="key-summary-meta key-summary-path" id="key-summary-path"></p>
        </div>
        <button class="btn secondary" id="key-edit-inputs" type="button">Edit input</button>
      </div>
      <div class="key-lab" id="key-lab">
      <div class="global-sync-host" id="global-sync-host"></div>
      <section class="seed-length-control" id="seed-length" aria-labelledby="seed-length-label">
        <p class="label" id="seed-length-label">Seed phrase length</p>
        <div class="row seed-length-options segmented-control" role="group" aria-label="Seed phrase length">
          <button type="button" class="tab" data-seed-words="12" aria-pressed="false">12 words</button>
          <button type="button" class="tab" data-seed-words="15" aria-pressed="false">15 words</button>
          <button type="button" class="tab" data-seed-words="18" aria-pressed="false">18 words</button>
          <button type="button" class="tab" data-seed-words="21" aria-pressed="false">21 words</button>
          <button type="button" class="tab active" data-seed-words="24" aria-pressed="true">24 words</button>
        </div>
        <p class="muted" id="seed-length-help">24 words use 256 bits of BIP39 entropy.</p>
      </section>
      <div id="form" class="key-form"></div>
      <div class="passphrase-field" id="passphrase-field">
        <label for="pass">Optional BIP39 passphrase</label>
        <div class="passphrase-keyboard-tools" id="passphrase-keyboard-toggle-host" hidden></div>
        <div class="dice-input-shell passphrase-input-shell"><pre class="dice-input-highlight" id="passphrase-highlight" aria-hidden="true"></pre><input id="pass" autocomplete="off" spellcheck="false" placeholder="Enter a BIP39 passphrase, or leave blank for none" aria-describedby="passphrase-bip39-status" /></div>
        <p class="muted passphrase-bip39-status" id="passphrase-bip39-status" aria-live="polite" hidden></p>
      </div>
      <div class="master-fingerprint-preview" id="master-fingerprint-preview" role="status" aria-live="polite" aria-atomic="true">
        <p class="label master-fingerprint-heading">Master fingerprint</p>
        <div class="master-fingerprint-card is-disabled" id="base-master-fingerprint-card" role="group" data-state="unavailable" aria-label="Base seed master fingerprint unavailable">
          <span class="master-fingerprint-lifehash-frame" aria-hidden="true"><img class="master-fingerprint-lifehash" id="base-master-fingerprint-lifehash" alt="" width="96" height="96" hidden /></span>
          <span class="master-fingerprint-label">Base seed</span>
          <code class="master-fingerprint-value" id="base-master-fingerprint"></code>
        </div>
        <span class="master-fingerprint-arrow is-disabled" id="master-fingerprint-arrow" aria-hidden="true">\u2192</span>
        <div class="master-fingerprint-card master-fingerprint-derived is-disabled" id="passphrase-master-fingerprint-card" role="group" data-state="unavailable" aria-label="With passphrase master fingerprint unavailable">
          <span class="master-fingerprint-lifehash-frame" aria-hidden="true"><img class="master-fingerprint-lifehash" id="passphrase-master-fingerprint-lifehash" alt="" width="96" height="96" hidden /></span>
          <span class="master-fingerprint-label">With passphrase</span>
          <code class="master-fingerprint-value" id="passphrase-master-fingerprint"></code>
        </div>
      </div>
      <div class="passphrase-keyboard-host" id="passphrase-keyboard-host" hidden></div>
      <div class="key-settings" id="key-settings">
        <div class="key-settings-row">
          <label class="field" id="script-type-field">Script type
            <select id="script-type"><option value="bip44">Legacy</option><option value="bip49">Nested SegWit</option><option value="bip84" selected>Native SegWit</option><option value="bip86">Taproot</option></select>
          </label>
          <label class="field derivation-path-field" id="derivation-path-field">Derivation path
            <input id="derivation-path" type="text" value="m/84'/0'/0'/0/0" autocomplete="off" autocapitalize="off" spellcheck="false" aria-describedby="derivation-path-help">
            <span class="field-note" id="derivation-path-help">Exact BIP32 address path · edit directly to use a custom path</span>
          </label>
        </div>
        <details class="derivation-advanced" id="derivation-advanced">
          <summary>Advanced entry</summary>
          <div class="derivation-advanced-fields">
            <div class="key-settings-row" id="purpose-network-settings">
              <div class="field" id="purpose-field"><label for="purpose">Purpose</label>
                <div class="derivation-index-control"><span class="derivation-index-value"><input id="purpose" type="text" inputmode="numeric" value="84'" aria-describedby="purpose-help"></span><label class="derivation-harden"><input id="purpose-harden" type="checkbox" checked><span>Harden</span></label></div>
                <span class="field-note" id="purpose-help">Purpose index \xB7 Hardened \xB7 0 to 2,147,483,647</span>
              </div>
              <div class="field network-field"><label for="network">Network</label>
                <div class="derivation-index-control"><span class="derivation-index-value"><input id="network" type="text" inputmode="numeric" value="0'" aria-describedby="network-help"></span><label class="derivation-harden"><input id="network-harden" type="checkbox" checked><span>Harden</span></label></div>
                <span class="field-note" id="network-help">Coin type index \xB7 Mainnet \xB7 Hardened \xB7 0 to 2,147,483,647</span>
              </div>
            </div>
            <div class="key-settings-row" id="account-address-settings">
              <div class="field" id="account-field"><label for="account">Account</label>
                <div class="derivation-index-control"><span class="derivation-index-value"><input id="account" type="text" inputmode="numeric" value="0'" aria-describedby="account-help"></span><label class="derivation-harden"><input id="account-harden" type="checkbox" checked><span>Harden</span></label></div>
                <span class="field-note" id="account-help">Account index \xB7 Hardened \xB7 0 to 2,147,483,647</span>
              </div>
            </div>
            <div class="key-settings-row address-branch-settings" id="address-branch-settings">
              <div class="field"><label for="branch-start" id="branch-start-label">Starting address branch</label>
                <div class="derivation-index-control"><span class="derivation-index-value"><input id="branch-start" type="text" inputmode="numeric" value="0" aria-describedby="branch-start-help"></span><label class="derivation-harden"><input id="branch-start-harden" type="checkbox"><span>Harden</span></label></div>
                <span class="field-note" id="branch-start-help">First address branch to derive \xB7 0 is Receive \xB7 1 is Change \xB7 Unhardened \xB7 0 to 2,147,483,647</span>
              </div>
              <label class="field">Address branch range
                <input id="branch-range" type="number" min="1" max="2" step="1" inputmode="numeric" value="1" aria-describedby="branch-range-help">
                <span class="field-note" id="branch-range-help">Derives Receive branch \xB7 Max 2</span>
              </label>
            </div>
            <div class="key-settings-row address-range-settings" id="address-range-settings">
              <div class="field"><label for="address-start" id="address-start-label">Starting address index</label>
                <div class="derivation-index-control"><span class="derivation-index-value"><input id="address-start" type="text" inputmode="numeric" value="0" aria-describedby="address-start-help"></span><label class="derivation-harden"><input id="address-start-harden" type="checkbox"><span>Harden</span></label></div>
                <span class="field-note" id="address-start-help">First receive index to derive \xB7 Unhardened \xB7 0 to 2,147,483,647</span>
              </div>
              <label class="field">Address range
                <input id="address-range" type="number" min="1" max="10000" step="1" inputmode="numeric" value="1" aria-describedby="address-range-help">
                <span class="field-note" id="address-range-help">Derives 1 receive address \xB7 Max 10,000</span>
              </label>
            </div>
          </div>
        </details>
      </div>
      <p class="field-note address-estimate derivation-estimate" id="address-estimate" role="status">Measuring this device\u2026</p>
      <div class="row key-action-row current-item-actions">
        <button class="btn primary" id="go" disabled aria-disabled="true">Derive Wallet</button>
        <div class="derive-progress" id="derive-progress" role="progressbar" aria-label="Wallet derivation progress" aria-valuemin="0" aria-valuemax="100" aria-valuenow="0" aria-valuetext="0% complete" hidden><span class="derive-progress-track"><span class="derive-progress-bar"></span></span><span class="derive-progress-label">0%</span></div>
        <button class="btn secondary" id="bip85-open" type="button">Derive BIP-85 child</button>
        <button class="btn clear-current-action" id="wipe" type="button" disabled aria-disabled="true">Clear Current Key</button>
      </div>
      <p class="err" id="error"></p>
      </div>
      <div id="out"></div>
    </section>
    <div class="tool-intro" id="bip85-tool-intro" hidden>
        <div class="kicker">One seed. Many children.</div>
        <h2>Derive BIP-85 child entropy</h2>
        <p class="muted bip85-intro">Deterministic child seeds, keys, and passwords from the active key's BIP32 root. Same parent, application, and index always reproduce the same child. This does not invent entropy \u2014 it is a calculator. English BIP-39 children match COLDCARD.</p>
      </div>
      <section class="card no-print" id="bip85-card" role="tabpanel" hidden>
      <label class="field">Optional root xprv (leave blank to use the active key)
        <textarea id="bip85-key" placeholder="xprv\u2026 or leave blank to use the active key" spellcheck="false" autocomplete="off" autocapitalize="off"></textarea>
      </label>
      <div class="bip85-grid">
        <label class="field">Application
          <select id="bip85-app">
            <option value="bip39" selected>BIP-39 mnemonic (English)</option>
            <option value="wif">HD-seed WIF</option>
            <option value="xprv">XPRV (BIP-32)</option>
            <option value="hex">HEX</option>
            <option value="pwd-base64">Password \xB7 Base64</option>
            <option value="pwd-base85">Password \xB7 Base85</option>
          </select>
        </label>
        <label class="field">Index
          <input id="bip85-index" type="number" min="0" max="2147483647" step="1" inputmode="numeric" value="0" aria-describedby="bip85-index-help">
          <span class="field-note" id="bip85-index-help">Hardened child index \xB7 0 to 2,147,483,647. COLDCARD defaults to 0\u20139,999.</span>
        </label>
      </div>
      <div class="bip85-grid" id="bip85-app-options">
        <label class="field" id="bip85-words-field">Word count
          <select id="bip85-words">
            <option value="12">12 words \xB7 128 bits</option>
            <option value="15">15 words \xB7 160 bits</option>
            <option value="18">18 words \xB7 192 bits</option>
            <option value="21">21 words \xB7 224 bits</option>
            <option value="24" selected>24 words \xB7 256 bits</option>
          </select>
          <span class="field-note">English wordlist only (language 0'). COLDCARD menus offer 12, 18, and 24.</span>
        </label>
        <label class="field" id="bip85-bytes-field" hidden>Hex bytes
          <input id="bip85-bytes" type="number" min="16" max="64" step="1" inputmode="numeric" value="32" aria-describedby="bip85-bytes-help">
          <span class="field-note" id="bip85-bytes-help">16 to 64 bytes. COLDCARD offers 32 and 64.</span>
        </label>
        <label class="field" id="bip85-pwdlen-field" hidden>Password length
          <input id="bip85-pwdlen" type="number" min="10" max="86" step="1" inputmode="numeric" value="21" aria-describedby="bip85-pwdlen-help">
          <span class="field-note" id="bip85-pwdlen-help">Base64: 20\u201386. Base85: 10\u201380.</span>
        </label>
      </div>
      <p class="muted bip85-path-row">Path <code id="bip85-path">m/83696968'/39'/0'/24'/0'</code></p>
      <div class="row bip85-actions">
        <button class="btn primary" id="bip85-go" type="button">Derive child</button>
        <button class="btn secondary" id="bip85-use-calc" type="button">Use active key</button>
        <button class="btn secondary" id="bip85-wipe" type="button">Clear derived child</button>
      </div>
      <p class="muted" id="bip85-session" aria-live="polite">No parent loaded. Derive a key first, or paste a root xprv.</p>
      <p class="err" id="bip85-error" role="alert"></p>
      <div id="bip85-out" aria-live="polite"></div>
      <p class="muted">Derived children remain in this page only. Anyone with the parent seed, passphrase, application, and index can reproduce them. Memory clearing is best-effort; close the page before reconnecting the computer.</p>
    </section>
      <div class="tool-intro" id="msig-tool-intro" hidden>
        <div class="kicker">Multiple keys, one wallet</div>
        <h2>Derive a multisig wallet</h2>
        <p class="muted msig-intro">Combine extended public keys into a multisignature wallet. Paste each key origin and extended public key as exported by its signer: <span class="mono">[fingerprint/48h/0h/0h/2h]xpub\u2026</span>. Private keys are not needed. The derived addresses can receive bitcoin, and spending requires the configured number of signatures.</p>
      </div>
      <section class="key-manager no-print" id="msig-manager" hidden>
      <div class="key-tab-strip"><div class="key-tabs" id="msig-tabs" role="tablist" aria-label="Multisigs"></div><div class="add-item-control"><button class="add-key" id="add-msig" type="button" aria-label="Open the lab to derive another multisig" aria-describedby="add-msig-tooltip">+</button><span class="add-item-tooltip" id="add-msig-tooltip" role="tooltip">Open the lab to derive another multisig</span></div><div class="add-item-control"><button class="add-key remove-key" id="delete-msig" type="button" aria-label="Delete current multisig" aria-describedby="delete-msig-tooltip" disabled>−</button><span class="add-item-tooltip" id="delete-msig-tooltip" role="tooltip">Delete this multisig</span></div></div>
    </section>
    <section class="card no-print" id="msig-card" role="tabpanel" hidden>
      <div class="key-summary" id="msig-summary" hidden>
        <div class="key-summary-text">
          <code class="key-summary-fingerprint" id="msig-summary-policy"></code>
          <p class="key-summary-meta" id="msig-summary-script"></p>
          <p class="key-summary-meta" id="msig-summary-network"></p>
        </div>
        <button class="btn secondary" id="msig-edit-inputs" type="button">Edit input</button>
      </div>
      <div class="msig-lab" id="msig-lab">
      <div class="msig-threshold-labels">
        <label for="msig-m-number"><span>Signatures needed to spend (m)</span><input class="msig-threshold-number" id="msig-m-number" type="number" min="1" max="15" step="1" value="2" inputmode="numeric" aria-describedby="msig-threshold-help"></label>
        <label for="msig-n-number"><span>Total signing keys (n)</span><input class="msig-threshold-number" id="msig-n-number" type="number" min="1" max="15" step="1" value="3" inputmode="numeric" aria-describedby="msig-threshold-help"></label>
      </div>
      <fieldset class="msig-threshold-control">
        <legend class="sr-only">Multisig signature threshold</legend>
        <div class="msig-threshold-slider" id="msig-threshold-slider" style="--msig-m-position:12.5%;--msig-n-position:25%" data-slider-max="9">
          <div class="msig-threshold-track" aria-hidden="true"><span></span></div>
          <span class="msig-threshold-thumb msig-threshold-thumb-m" aria-hidden="true"></span>
          <span class="msig-threshold-thumb msig-threshold-thumb-n" aria-hidden="true"></span>
          <input class="msig-threshold-range" id="msig-m" type="range" min="1" max="15" step="1" value="2" aria-label="Signatures needed to spend (m)" aria-describedby="msig-threshold-help">
          <input class="msig-threshold-range" id="msig-n" type="range" min="1" max="15" step="1" value="3" aria-label="Total signing keys (n)" aria-describedby="msig-threshold-help">
        </div>
        <div class="msig-threshold-ticks" id="msig-threshold-ticks" aria-hidden="true"><span style="--msig-tick-position:0%">1</span><span style="--msig-tick-position:12.5%">2</span><span style="--msig-tick-position:25%">3</span><span style="--msig-tick-position:37.5%">4</span><span style="--msig-tick-position:50%">5</span><span style="--msig-tick-position:62.5%">6</span><span style="--msig-tick-position:75%">7</span><span style="--msig-tick-position:87.5%">8</span><span style="--msig-tick-position:100%">9</span></div>
        <p class="field-note msig-threshold-help" id="msig-threshold-help">Enter values, drag either handle, or use the arrow keys. Editing one value past the other moves both.</p>
      </fieldset>
      <div id="msig-keys" class="msig-keys"></div>
      <p class="hint" id="msig-key-order-status" hidden></p>
      <p class="hint" id="msig-hint"></p>
      <div class="key-settings msig-output-settings">
        <label class="choice msig-legacy-account-toggle" id="msig-legacy-account-toggle" hidden>
          <input id="msig-legacy-bip87" type="checkbox" aria-describedby="msig-legacy-bip87-help">
          <span><strong>Use standardized BIP87 accounts</strong><span class="desc" id="msig-legacy-bip87-help">Uses <span class="mono">m/87h/coinh/accounth</span> with this descriptor. BIP87 account keys are script-agnostic, so one account key serves any script type. Leave unchecked for this script type's own standard: BIP45 for Legacy, BIP48 for SegWit. Taproot multisig always uses BIP87.</span></span>
        </label>
        <div class="key-settings-row">
          <label class="field">Script type
            <select id="msig-script-type" aria-describedby="msig-script-warning"><option value="p2sh">Legacy</option><option value="p2sh-p2wsh">Nested SegWit</option><option value="p2wsh" selected>Native SegWit</option><option value="p2tr">Taproot</option><option value="mixed" disabled data-custom-select-placeholder="true">Mixed \xB7 incompatible keys</option></select>
            <span class="field-note msig-script-warning" id="msig-script-warning" role="status" hidden></span>
          </label>
          <div class="field"><label for="msig-purpose">Purpose</label>
            <div class="derivation-index-control"><span class="derivation-index-value"><input id="msig-purpose" type="number" min="0" max="2147483647" step="1" inputmode="numeric" value="48" aria-describedby="msig-purpose-help msig-purpose-warning"><span class="derivation-index-prime" aria-hidden="true">'</span></span><label class="derivation-harden"><input id="msig-purpose-harden" type="checkbox" checked><span>Harden</span></label></div>
            <span class="field-note" id="msig-purpose-help">Purpose index \xB7 Hardened \xB7 0 to 2,147,483,647</span>
            <span class="field-note msig-purpose-warning" id="msig-purpose-warning" role="status" hidden></span>
          </div>
        </div>
        <div class="key-settings-row">
          <div class="field"><label for="msig-network">Network</label>
            <div class="derivation-index-control"><span class="derivation-index-value"><input id="msig-network" type="number" min="0" max="2147483647" step="1" inputmode="numeric" value="0" aria-describedby="msig-network-help"><span class="derivation-index-prime" aria-hidden="true">'</span></span><label class="derivation-harden"><input id="msig-network-harden" type="checkbox" checked><span>Harden</span></label></div>
            <span class="field-note" id="msig-network-help">Coin type index \xB7 Mainnet \xB7 Hardened \xB7 0 to 2,147,483,647</span>
          </div>
          <div class="field"><label for="msig-account">Account</label>
            <div class="derivation-index-control"><span class="derivation-index-value"><input id="msig-account" type="text" value="" placeholder="Derived from keys" disabled aria-describedby="msig-account-help msig-account-warning"><span class="derivation-index-prime" aria-hidden="true">'</span></span><label class="derivation-harden"><input id="msig-account-harden" type="checkbox" checked><span>Harden</span></label></div>
            <span class="field-note" id="msig-account-help">Account index \xB7 Hardened \xB7 Derived from co-signer key origins.</span>
            <span class="field-note msig-account-warning" id="msig-account-warning" role="status" hidden></span>
          </div>
        </div>
        <div class="key-settings-row address-branch-settings">
          <div class="field"><label for="msig-branch-start">Starting address branch index</label>
            <div class="derivation-index-control"><span class="derivation-index-value"><input id="msig-branch-start" type="number" min="0" max="2147483647" step="1" inputmode="numeric" value="0" aria-describedby="msig-branch-start-help"><span class="derivation-index-prime" aria-hidden="true">'</span></span><label class="derivation-harden"><input id="msig-branch-start-harden" type="checkbox"><span>Harden</span></label></div>
            <span class="field-note" id="msig-branch-start-help">First address branch to derive · 0 is Receive · 1 is Change · Unhardened · 0 to 2,147,483,647</span>
          </div>
          <label class="field">Address branch range
            <input id="msig-branch-range" type="number" min="1" max="2" step="1" inputmode="numeric" value="2" aria-describedby="msig-branch-range-help">
            <span class="field-note" id="msig-branch-range-help">Derives Receive and Change branches · Max 2</span>
          </label>
        </div>
        <div class="key-settings-row address-range-settings">
          <div class="field"><label for="msig-address-start">Starting address index</label>
            <div class="derivation-index-control"><span class="derivation-index-value"><input id="msig-address-start" type="number" min="0" max="2147483647" step="1" inputmode="numeric" value="0" aria-describedby="msig-address-start-help"><span class="derivation-index-prime" aria-hidden="true">'</span></span><label class="derivation-harden"><input id="msig-address-start-harden" type="checkbox"><span>Harden</span></label></div>
            <span class="field-note" id="msig-address-start-help">First receive and change index to derive \xB7 Unhardened \xB7 0 to 2,147,483,647</span>
          </div>
          <label class="field">Address range
            <input id="msig-address-range" type="number" min="1" max="10000" step="1" inputmode="numeric" value="5" aria-describedby="msig-address-range-help">
            <span class="field-note" id="msig-address-range-help">Derives 5 receive and 5 change addresses · Max 10,000</span>
          </label>
        </div>
        <details class="msig-advanced" id="msig-advanced">
          <summary>Advanced</summary>
          <label class="field">Key order
            <select id="msig-key-order">
              <option value="sorted" selected>Sorted \xB7 sortedmulti</option>
              <option value="listed">As listed \xB7 multi</option>
            </select>
            <span class="field-note" id="msig-key-order-help">Sorted is the default. Addresses stay the same no matter which co-signer you paste first. As listed uses multi: the order of the fields is part of the wallet. Taproot uses sortedmulti_a or multi_a.</span>
          </label>
        </details>
      </div>
      <p class="field-note address-estimate derivation-estimate" id="msig-address-estimate" role="status">Measuring this device\u2026</p>
      <div class="row current-item-actions">
        <button class="btn primary" id="msig-go" type="button" aria-describedby="msig-script-warning" disabled aria-disabled="true">Derive Multisig</button>
        <div class="derive-progress" id="msig-derive-progress" role="progressbar" aria-label="Multisig derivation progress" aria-valuemin="0" aria-valuemax="100" aria-valuenow="0" aria-valuetext="0% complete" hidden><span class="derive-progress-track"><span class="derive-progress-bar"></span></span><span class="derive-progress-label">0%</span></div>
        <button class="btn clear-current-action" id="msig-wipe" type="button" disabled aria-disabled="true">Clear Current Multisig</button>
      </div>
      <p class="err" id="msig-error"></p>
      </div>
      <div id="msig-out"></div>
    </section>
    <div class="tool-intro" id="sp-tool-intro" hidden>
        <div class="kicker">BIP-352 · reusable address, unique outputs</div>
        <h2>Silent Payments</h2>
        <p class="muted psbt-intro">A calculator, not a chain scanner. Derive a reusable <code>sp1q…</code> address from your seed, compute the unique taproot output a sender must pay, or check pasted outputs against your scan key. Nothing here talks to the network.</p>
      </div>
      <section class="card no-print" id="sp-card" role="tabpanel" hidden>
      <div class="row no-print segmented-control" id="sp-modes">
        <button class="tab active" type="button" data-sp-mode="receive" aria-pressed="true">Receive</button>
        <button class="tab" type="button" data-sp-mode="send" aria-pressed="false">Send</button>
        <button class="tab" type="button" data-sp-mode="verify" aria-pressed="false">Verify</button>
      </div>
      <div class="psbt-grid">
        <label class="field">Session key (BIP39 seed phrase or root xprv/tprv)
          <textarea id="sp-key" placeholder="Leave blank and use the active key, or paste a seed / root xprv" spellcheck="false" autocomplete="off" autocapitalize="off"></textarea>
        </label>
        <div>
          <label class="field">Optional BIP39 passphrase
            <input id="sp-pass" autocomplete="off" placeholder="Enter a BIP39 passphrase, or leave blank for none">
          </label>
          <label class="field">Address network
            <select id="sp-network"><option value="mainnet" selected>Bitcoin mainnet</option><option value="testnet">Testnet (practice)</option></select>
          </label>
          <label class="field">Account
            <input id="sp-account" type="number" min="0" max="2147483647" step="1" inputmode="numeric" value="0">
          </label>
        </div>
      </div>
      <div class="row psbt-actions">
        <button class="btn secondary" id="sp-use-calc" type="button">Use active key this session</button>
        <button class="btn secondary" id="sp-wipe" type="button">End session / clear fields</button>
      </div>
      <p class="muted" id="sp-session" aria-live="polite">No session key. Receive and verify need a seed or root xprv.</p>
      <div id="sp-receive">
        <label class="field">Label <code>m</code>
          <input id="sp-label" type="number" min="0" max="4294967295" step="1" inputmode="numeric" placeholder="blank = unlabeled · 0 = change (do not hand out)">
          <span class="field-note">Unlabeled is the reusable address you publish. <code>m = 0</code> is reserved for change. <code>m ≥ 1</code> is an extra labeled code from the same scan key.</span>
        </label>
        <div class="row psbt-actions">
          <button class="btn primary" id="sp-derive" type="button">Derive silent payment address</button>
        </div>
      </div>
      <div id="sp-send" hidden>
        <label class="field">Recipients (one <code>sp1q…</code> / <code>tsp1q…</code> per line; optional count)
          <textarea id="sp-recipients" placeholder="sp1qqgste7k9hx0q…&#10;sp1qqgste7k9hx0q… 2" spellcheck="false" autocomplete="off" autocapitalize="off"></textarea>
        </label>
        <label class="field">Inputs (BIP-352 vin JSON)
          <textarea id="sp-send-vins" placeholder='[{"txid":"\u2026","vout":0,"scriptSig":"\u2026","txinwitness":"","prevout":{"scriptPubKey":{"hex":"\u2026"}},"private_key":"\u2026"}]' spellcheck="false" autocomplete="off" autocapitalize="off"></textarea>
          <span class="field-note">Same shape as the published BIP-352 send vectors. Each eligible input needs its private key. P2TR / P2WPKH / P2SH-P2WPKH / P2PKH only.</span>
        </label>
        <div class="row psbt-actions">
          <button class="btn primary" id="sp-send-go" type="button">Compute taproot outputs</button>
        </div>
      </div>
      <div id="sp-verify" hidden>
        <label class="field">Inputs (BIP-352 vin JSON, private keys optional)
          <textarea id="sp-verify-vins" placeholder='[{"txid":"\u2026","vout":0,"scriptSig":"\u2026","txinwitness":"","prevout":{"scriptPubKey":{"hex":"\u2026"}}}]' spellcheck="false" autocomplete="off" autocapitalize="off"></textarea>
        </label>
        <label class="field">Taproot output keys (32-byte x-only hex, one per line)
          <textarea id="sp-verify-outputs" placeholder="3e9fce73d4e77a4809908e3c3a2e54ee147b9312dc5044a193d1fc85de46e3c1" spellcheck="false" autocomplete="off" autocapitalize="off"></textarea>
        </label>
        <label class="field">Labels to scan
          <input id="sp-verify-labels" placeholder="0, 1, 2" value="0">
          <span class="field-note"><code>m = 0</code> is change and should stay in this list. Add any labeled codes you handed out.</span>
        </label>
        <div class="row psbt-actions">
          <button class="btn primary" id="sp-verify-go" type="button">Scan pasted outputs</button>
        </div>
      </div>
      <p class="err" id="sp-error" role="alert"></p>
      <div id="sp-out" aria-live="polite"></div>
      <p class="muted">Session keys remain in this page only and are never intentionally stored or sent. Memory clearing is best-effort because browsers may retain internal copies; close the page before reconnecting the computer.</p>
    </section>
    <div class="tool-intro" id="psbt-tool-intro" hidden>
        <div class="kicker">Inspect first. Sign elsewhere.</div>
        <h2>Read a PSBT or a signed transaction.</h2>
        <p class="muted psbt-intro">Inspecting a PSBT v0 or a raw Bitcoin transaction does not require a private key. EntropyLab can show outputs, PSBT-provided input amounts and fees, signatures, and repeated ECDSA nonce values. Optional Jade anti-exfil transcripts (host nonce \u03C1 and signer opening R) are checked without a key. Finalized taproot witnesses and tap-leaf scripts are scanned for inscription envelopes (OP_FALSE OP_IF "ord"); this does not number sats or fetch content from the chain. Loading a matching key additionally labels which outputs belong to this wallet (change vs receive vs not yours) and checks whether supported signatures match plain RFC 6979 or Bitcoin Core-style low-r grinding; a mismatch alone is not evidence of a compromised signer.</p>
      </div>
      <section class="card no-print" id="psbt-card" role="tabpanel" hidden>
      <label class="field">PSBT v0 or raw transaction (base64 or hex)
        <textarea id="psbt-text" placeholder="cHNidP8B\u2026 or 020000000001\u2026" spellcheck="false" autocomplete="off" autocapitalize="off"></textarea>
      </label>
      <div class="psbt-grid">
        <label class="field">Optional session key (BIP39 seed phrase, root xprv/tprv, WIF, or 64-character hex)
          <textarea id="psbt-key" placeholder="Leave blank for inspect-only mode" spellcheck="false" autocomplete="off" autocapitalize="off"></textarea>
        </label>
        <div>
          <label class="field">Optional BIP39 passphrase
            <input id="psbt-pass" autocomplete="off" placeholder="Enter a BIP39 passphrase, or leave blank for none">
          </label>
          <label class="field">Address network
            <select id="psbt-network"><option value="mainnet" selected>Bitcoin mainnet</option><option value="testnet">Testnet (practice)</option></select>
          </label>
        </div>
      </div>
      <label class="field">Optional Jade anti-exfil transcript
        <textarea id="psbt-ax-transcript" placeholder="32-byte host nonce \u03C1, then 33-byte compressed opening R, as hex" spellcheck="false" autocomplete="off" autocapitalize="off"></textarea>
        <span class="field-note">USB Jade only (Green host nonce + opening). QR / sign_psbt does not run anti-exfil yet. BitBox anti-klepto is a different mix \u2014 do not paste it here.</span>
      </label>
      <div class="row psbt-actions">
        <button class="btn primary" id="psbt-go" type="button">Inspect</button>
        <button class="btn secondary" id="psbt-use-calc" type="button">Use active key this session</button>
        <button class="btn secondary" id="psbt-wipe" type="button">End session / clear fields</button>
      </div>
      <p class="muted" id="psbt-session" aria-live="polite">No session key. Inspect-only mode.</p>
      <p class="err" id="psbt-error" role="alert"></p>
      <div id="psbt-out" aria-live="polite"></div>
      <p class="muted">Session keys remain in this page only and are never intentionally stored or sent. Memory clearing is best-effort because browsers may retain internal copies; close the page before reconnecting the computer.</p>
    </section>
    <div class="tool-intro" id="psbted-tool-intro" hidden>
        <div class="kicker">Full-fidelity editor. Sign elsewhere.</div>
        <h2>Edit a PSBT, field by field.</h2>
        <p class="muted psbt-intro">A BIP-174 editor in the spirit of bip174.org, backed by rust-bitcoin compiled to WebAssembly. Every key-value pair of the global, per-input and per-output maps is shown with a typed decode (BIP-174 and BIP-371 taproot fields) and stays editable as raw hex, and the unsigned transaction's version, locktime, input prevouts/sequences and output amounts/scripts get structured fields. Every edit rebuilds the file through rust-bitcoin as you type — the fields always show its decode of the current build — and the result follows live as base64, hex, a downloadable .psbt and a QR code (a single static code, or an animated ur:crypto-psbt sequence for larger files). A binary .psbt file as saved by Sparrow, Coldcard or another wallet uploads directly. PSBT v0 only; unknown and proprietary pairs round-trip untouched. Editing never signs anything.</p>
      </div>
      <section class="card no-print" id="psbted-card" role="tabpanel" hidden>
      <label class="field">PSBT v0 (base64 or hex)
        <textarea id="psbted-text" placeholder="cHNidP8B..." spellcheck="false" autocomplete="off" autocapitalize="off"></textarea>
      </label>
      <div class="row psbt-actions psbted-actions">
        <button class="btn primary" id="psbted-load" type="button">Load PSBT</button>
        <button class="btn secondary" id="psbted-upload" type="button">Upload .psbt file</button>
        <input type="file" id="psbted-file" accept=".psbt,.txt,.hex" hidden>
        <button class="btn secondary" id="psbted-wipe" type="button">Clear editor</button>
        <label class="field psbted-network-field">Address network
          <select id="psbted-network"><option value="mainnet" selected>Bitcoin mainnet</option><option value="testnet">Testnet (practice)</option></select>
        </label>
      </div>
      <p class="err" id="psbted-error" role="alert"></p>
      <div id="psbted-out" aria-live="polite"></div>
      <p class="muted">Fees and input amounts shown here are unverified PSBT claims; the editor does not check them against previous transactions or the blockchain. Nothing is signed or broadcast.</p>
    </section>
    </div>
    <section class="card muted sources">
      <h3 class="sources-heading">Sources</h3>
      <p>Ian Coleman BIP39: <a href="https://github.com/iancoleman/bip39" target="_blank" rel="noopener noreferrer">github.com/iancoleman/bip39</a> \u2014 pull <code>bip39-standalone.html</code> from Releases, or <code>src/js/index.js</code>, <code>entropy.js</code>, <code>jsbip39.js</code>, <code>wordlist_english.js</code>.</p>
      <p>bitaddress.org: <a href="https://github.com/pointbiz/bitaddress.org" target="_blank" rel="noopener noreferrer">github.com/pointbiz/bitaddress.org</a> \u2014 pull <code>bitaddress.org.html</code>, or <code>src/ninja.key.js</code>, <code>ninja.detailwallet.js</code>, <code>ninja.paperwallet.js</code>, <code>bitcoinjs-lib.eckey.js</code>.</p>
      <p>BitBox02 diceware: <a href="https://blog.bitbox.swiss/en/roll-the-dice-generate-your-own-seed/" target="_blank" rel="noopener noreferrer">roll-the-dice-generate-your-own-seed</a> \u2014 lookup table is the BIP39 English list in order.</p>
      <p>D++ D8 &amp; D16 method: <a href="https://thesimplestbitcoinbook.net/wp-content/uploads/2023/09/Roll-Your-Own-Seed-Phrase-PDF.pdf" target="_blank" rel="noopener noreferrer">Roll Your Own Bitcoin Seed Phrase</a> \u2014 the published 24-word workflow uses one D8 labeled 1\u20138 and two hexadecimal D16 dice labeled 0\u2013F per word, then a final D8.</p>
      <p>Jade anti-exfil (sign-to-contract): <a href="https://blog.blockstream.com/anti-exfil-stopping-key-exfiltration/" target="_blank" rel="noopener noreferrer">Anti-Exfil: Stopping Key Exfiltration</a> \u2014 secp256k1-zkp <code>ecdsa_s2c</code> / <code>anti_exfil_host_verify</code>.</p>
      <p>BIP-85 deterministic entropy: <a href="https://github.com/bitcoin/bips/blob/master/bip-0085.mediawiki" target="_blank" rel="noopener noreferrer">bip-0085.mediawiki</a> — HMAC-SHA512 of a fully hardened child; English BIP-39 / WIF / XPRV / HEX / password applications match COLDCARD.</p>
      <p>BIP-352 Silent Payments: <a href="https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki" target="_blank" rel="noopener noreferrer">bips/bip-0352</a> — reusable <code>sp1q…</code> addresses and unique taproot outputs. Descriptors: <a href="https://github.com/bitcoin/bips/blob/master/bip-0392.mediawiki" target="_blank" rel="noopener noreferrer">BIP-392</a>.</p>
      <p>Inscription envelopes: <a href="https://docs.ordinals.com/inscriptions.html" target="_blank" rel="noopener noreferrer">docs.ordinals.com/inscriptions</a> — <code>OP_FALSE OP_IF "ord"</code> parser only. This tool does not create inscriptions or number sats.</p>
    </section>
    <footer class="page-footer muted no-print"><div>Team Ooga Booga</div><div class="page-footer-emoji">🪨 🔥 🎲 🍌</div><div>Since 964013 · <span class="page-footer-build">v{{VERSION}} · commit <code>{{COMMIT_SHORT}}</code> <img class="page-footer-lifehash" id="page-footer-lifehash" data-commit="{{COMMIT}}" width="20" height="20" alt="LifeHash of the build commit" hidden></span></div></footer>
  </div>
`;
if (/^(www\.)?entropylab\.online$/i.test(location.hostname)) document.getElementById("online-warning")?.removeAttribute("hidden");
var hodlKeyModes = ["dice", "cards", "hex", "seed", "key"], hodlBrainLabAck = false, hodlCardRanks = ["A", "2", "3", "4", "5", "6", "7", "8", "9", "T", "J", "Q", "K"], hodlDirectCardRanks = ["A", "2", "3", "4", "5", "6", "7", "8"], hodlCardSuits = [{ code: "S", symbol: "♠", label: "Spades", red: false }, { code: "H", symbol: "♥", label: "Hearts", red: true }, { code: "C", symbol: "♣", label: "Clubs", red: false }, { code: "D", symbol: "♦", label: "Diamonds", red: true }], hodlCardSuit = "", hodlCardRank = "", hodlCardMethod = "hashed", hodlSeedMethod = "words", hodlSeedZeroIndexed = false, hodlCardColemanSymbols = false, Ne = "dice", ge = "coldcard", Pt = 24, hodlEntropyFormat = "hex", hodlDiceCoinPositions = [], ft = "", re = null, Ge = false, hodlWalletDatBirthday = "genesis", Zs = W("#modes"), at = W("#form"), dr = W("#out");
var hodlManualCalculationsOpen = false;
hodlKeyModes.forEach((e) => {
  let t = document.createElement("button"), active = e === Ne;
  t.type = "button";
  t.className = "tab" + (active ? " active" : "");
  t.setAttribute("aria-pressed", String(active));
  t.textContent = e === "dice" ? "Dice rolls" : e === "cards" ? "Cards" : e === "hex" ? "Number bases" : e === "seed" ? "Seed phrase" : "Private key";
  t.onclick = () => hodlSetMode(e);
  Zs.appendChild(t);
});
document.querySelectorAll("#seed-length [data-seed-words]").forEach((button) => {
  button.onclick = () => hodlSetSeedLength(Number(button.dataset.seedWords));
});
W("#go").onclick = () => hodlHandleDerivationButton("key", hodlCalculateKey);
W("#wipe").onclick = hodlWipeActiveKey;
function W(e) {
  let t = e.startsWith("#") ? e.slice(1) : e, r = document.getElementById(t);
  if (!r) throw new Error(t);
  return r;
}
function lr() {
  if (Ne === "dice") {
    at.innerHTML = `
      <p class="label">How to turn rolls into a seed</p>
      <label class="choice"><input type="radio" name="dm" value="coldcard" ${ge === "coldcard" ? "checked" : ""} />
        <span><strong>Hashed rolls / Base 10 [0-9] (recommended)</strong>
        <span class="desc">SHA-256 of the original dice digit string, matching the method used by COLDCARD and SeedSigner. Every entered roll is included.</span></span>
      </label>
      <label class="choice"><input type="radio" name="dm" value="bitbox" ${ge === "bitbox" ? "checked" : ""} />
        <span><strong>BitBox diceware / Direct word selection</strong>
        <span class="desc">Same as the BitBox02 lookup table: five dice showing 1\u20134, then a coin (or 6th die: 1\u20133 tails, 4\u20136 heads). 5 and 6 on the first five dice of a word are skipped (reroll). After 23 words, pick one of the 8 checksum words.</span></span>
      </label>
      <label class="choice"><input type="radio" name="dm" value="coleman" ${ge === "coleman" ? "checked" : ""} />
        <span><strong>Hashed rolls / Dice [1-6]</strong>
        <span class="desc">Convert every 6 to 0, then SHA-256 hash the complete mapped digit string, matching the method used by Keystone.</span></span>
      </label>
      <div id="bitbox-extra" ${ge === "bitbox" ? "" : "hidden"}>
        <div class="row" style="margin-top:12px">
          <button type="button" class="tab${Pt === 24 ? " active" : ""}" data-bt="24">24 words</button>
          <button type="button" class="tab${Pt === 12 ? " active" : ""}" data-bt="12">12 words</button>
        </div>
      </div>
      <p class="label" id="dice-label">${ge === "bitbox" ? "Dice rolls (1\u20134, then a 6th die interpreted as a coin flip)" : "Dice rolls (faces 1\u20136 only)"}</p>
      <p class="muted" id="dice-help">${ge === "bitbox" ? `${Pt === 24 ? 23 : 11} lookup-table words, then a checksum pick. Type rolls, tap 1\u20134, then the 6th die (1\u20133 / 4\u20136).` : ge === "coleman" ? "Every 6 becomes 0 before SHA-256 hashing, matching the method used by Keystone." : "SHA-256 hashes the original digit string, matching the Base 10 [0-9] method used by COLDCARD and SeedSigner."}</p>
      <div class="dice-input-shell"><pre class="dice-input-highlight" id="dice-highlight" aria-hidden="true"></pre><textarea id="dice" placeholder="${ge === "bitbox" ? "111111222224\u2026" : "415263415263\u2026"}" aria-describedby="dice-help dice-meta"></textarea></div>
      <div class="dice-input-pad faces-1-6">${[1, 2, 3, 4, 5, 6].map((t) => `<button type="button" data-d="${t}">${t}</button>`).join("")}</div>
      <p class="muted" id="dice-meta"></p>
      <div id="bitbox-words" class="wordlist"></div>
      <div id="last-words" class="row" style="margin-top:8px"></div>
    `;
    let e = document.getElementById("dice");
    e.dataset.previousValue = e.value;
    hodlBindKeypadPointer(at.querySelectorAll("[data-d]"), () => e), at.querySelectorAll("[data-d]").forEach((t) => {
      t.onclick = () => hodlInsertDiceControl(e, t, At);
    }), e.oninput = () => {
      hodlTrackDiceInputEdit(e);
      hodlSanitizeDiceInput(e);
      At();
    }, e.onscroll = () => hodlSyncDiceHighlight(e), at.querySelectorAll("input[name=dm]").forEach((t) => {
      t.onchange = () => {
        ge = t.value, ft = "";
        let r = e.value;
        lr();
        let n = document.getElementById("dice");
        n && (n.value = r, n.dataset.previousValue = r, n.setSelectionRange(r.length, r.length)), At();
      };
    }), at.querySelectorAll("[data-bt]").forEach((t) => {
      t.onclick = () => {
        Pt = Number(t.dataset.bt) === 12 ? 12 : 24, ft = "";
        let r = e.value;
        lr();
        let n = document.getElementById("dice");
        n && (n.value = r, n.dataset.previousValue = r, n.setSelectionRange(r.length, r.length)), At();
      };
    }), At();
    hodlBindFields();
  } else if (Ne === "hex") {
    at.innerHTML = `
      <p class="label">Hexadecimal entropy</p>
      <p class="muted">32 hex characters = 12 words. 64 hex characters = 24 words. No generator \u2014 paste what you already rolled, hashed, or wrote down.</p>
      <textarea id="hex" placeholder="64 hex characters for a 24-word seed"></textarea>
      <p class="label">Or binary (coin flips)</p>
      <textarea id="bin" placeholder="At least 128 zeros and ones"></textarea>
    `;
    hodlBindFields();
  } else if (Ne === "seed") {
    at.innerHTML = `
      <p class="label">Your seed phrase</p>
      <p class="muted">12 or 24 English BIP39 words. You can also paste an xprv / xpub / zpub here. If you have 23 words from BitBox diceware, paste them and pick the checksum word below.</p>
      <textarea id="seed" placeholder="word1 word2 word3 \u2026"></textarea>
      <p class="muted" id="seed-meta"></p>
      <div id="last-words" class="row" style="margin-top:8px"></div>
    `;
    let e = document.getElementById("seed"), t = () => {
      let r = Mt(e.value), n = Tr(e.value);
      n && !n.error ? (W("#seed-meta").textContent = n.partialCount === 23 ? "BitBox-style: pick the 24th checksum word" : `${n.candidates.length} valid last words \u2014 type the one you confirmed on the device, then Calculate`, W("#seed-meta").className = "muted ok", n.candidates.length <= 16 ? (W("#last-words").innerHTML = n.candidates.map((o) => `<button type="button" class="tab" data-lw="${o}">${o}</button>`).join(" "), W("#last-words").querySelectorAll("[data-lw]").forEach((o) => {
        o.onclick = () => {
          e.value = `${e.value.trim()} ${o.dataset.lw}`, t();
        };
      })) : W("#last-words").innerHTML = "") : (W("#last-words").innerHTML = "", W("#seed-meta").textContent = e.value.trim() ? r.ok ? `${r.words.length} words, checksum valid` : r.error ?? "" : "", W("#seed-meta").className = "muted " + (r.ok ? "ok" : "err"));
    };
    e.oninput = () => {
      e.value = hodlFilterSeed(e.value);
      t();
    };
    hodlBindFields();
  } else at.innerHTML = `
      <p class="label">Your Bitcoin Core private key</p>
      <p class="muted">WIF, hex, mini key, or brain-wallet text (unsafe).</p>
      <textarea id="key" placeholder="5\u2026 / K\u2026 / L\u2026"></textarea>
      <label class="choice"><input type="radio" name="kk" value="wif" checked /><span><strong>WIF</strong><span class="desc">Bitcoin wallet import format (Base58Check).</span></span></label>
      <label class="choice"><input type="radio" name="kk" value="hex-key" /><span><strong>Private key hex</strong><span class="desc">Raw 32-byte private key as 64 hexadecimal characters.</span></span></label>
      <label class="choice"><input type="radio" name="kk" value="minikey" /><span><strong>Mini key</strong><span class="desc">Casascius-style short key.</span></span></label>
      <label class="choice"><input type="radio" name="kk" value="brain" /><span><strong>Brain wallet</strong><span class="desc">Unsafe. SHA-256 of your text, as a single key pair or a 24-word seed.</span></span></label>
    `;
  hodlBindFields();
}
function At() {
  let e = document.getElementById("dice");
  if (!e) return;
  hodlRenderDiceInputState(e);
  let t = document.getElementById("bitbox-words"), r = document.getElementById("last-words");
  if (ge === "bitbox") {
    let o = Sr(e.value, Pt), i = o.waiting === "last-word" ? `${o.words.length} words \xB7 pick the checksum word` : o.waiting === "coin" ? `Word ${o.words.length + 1} of ${o.neededPartial} \xB7 6th die (interpreted as a coin flip)` : `Word ${o.words.length + 1} of ${o.neededPartial} \xB7 die ${o.diceInWord + 1} of 5 (faces 1\u20134)`;
    W("#dice-meta").textContent = i, t && (t.innerHTML = o.words.length ? o.words.map((c, a) => `<div><span>${a + 1}.</span>${c}</div>`).join("") : "");
    let s = o.waiting === "last-word" ? Tr(o.words.join(" ")) : null;
    r && s && !s.error && s.candidates.length <= 16 ? (r.innerHTML = s.candidates.map((c) => `<button type="button" class="tab${c === ft ? " active" : ""}" data-lw="${c}">${c}</button>`).join(""), r.querySelectorAll("[data-lw]").forEach((c) => {
      c.onclick = () => {
        ft = c.dataset.lw ?? "", At();
      };
    })) : r && (r.innerHTML = "");
    return;
  }
  t && (t.innerHTML = ""), r && (r.innerHTML = "");
  let { rolls: n } = Br(e.value);
  W("#dice-meta").textContent = `${n.length} rolls \xB7 ${kr(n.length).toFixed(1)} bits \xB7 99 rolls for 256-bit 24-word seed`;
  hodlDiceCompare();
}
function Ff() {
  W("#error").textContent = "";
  try {
    let e = document.getElementById("network").value, t = hodlReadAddressWindow().range, r = document.getElementById("pass").value;
    if (Ne === "dice") if (ge === "bitbox") {
      let n = Sr(document.getElementById("dice").value, Pt);
      if (n.leftover) throw new Error(`Invalid characters: ${n.leftover}`);
      if (n.waiting !== "last-word") throw new Error(`Need ${n.neededPartial} lookup-table words. You have ${n.words.length}.`);
      if (!ft) throw new Error("Pick one of the checksum words, then Calculate.");
      re = ar([...n.words, ft].join(" "), r, e, t, { notes: n.notes, warnings: n.warnings });
    } else {
      let n = $n(document.getElementById("dice").value, ge);
      if (!n.ok) throw new Error(n.error);
      re = on(n, r, e, t);
    }
    else if (Ne === "hex") {
      let n = document.getElementById("hex").value.trim(), o = document.getElementById("bin").value.trim(), i = n ? In(n) : On(o);
      if (!i.ok) throw new Error(i.error);
      re = on(i, r, e, t);
    } else if (Ne === "seed") {
      let n = document.getElementById("seed").value.trim();
      re = /^[xtyYzZvVun][A-Za-z0-9]+$/.test(n) && n.length > 80 ? Po(n, e, t) : ar(n, r, e, t);
    } else {
      let n = document.querySelector("input[name=kk]:checked")?.value || "wif-or-hex";
      re = Io(document.getElementById("key").value, e, n, hodlBrainWalletTrimEnabled());
    }
    Ge = false, hodlAccountId = null, tc();
  } catch (e) {
    re = null, hodlAccountId = null, W("#error").textContent = e instanceof Error ? e.message : "Could not calculate", dr.innerHTML = "";
  }
}
function tc() {
  if (!re) {
    dr.innerHTML = "";
    return;
  }
  if (re.kind === "single") {
    let t = re;
    dr.innerHTML = `<div class="key-result">${hodlSingleWalletData(t)}</div>`;
  } else {
    let t = re, r = t.accounts.find((o) => o.def.id === hodlAccountId) ?? t.accounts.find((o) => o.def.id === "bip84") ?? t.accounts[0];
    dr.innerHTML = `
      <div class="key-result">
        ${hodlHdWalletData(t)}
        <p class="key-result-scripts-label" id="acct-tabs-label">Script type</p>
        <div class="account-tabs no-print" id="acct-tabs" role="tablist" aria-labelledby="acct-tabs-label"></div>
        <div id="acct" role="tabpanel"></div>
      </div>
    `;
    let n = W("#acct-tabs");
    t.accounts.forEach((o) => {
      let i = document.createElement("button");
      i.type = "button", i.id = `account-tab-${o.def.id}`, i.className = "tab account-tab" + (o.def.id === r.def.id ? " active" : ""), i.dataset.account = o.def.id, i.textContent = o.def.label, i.setAttribute("role", "tab"), i.setAttribute("aria-controls", "acct"), i.setAttribute("aria-selected", String(o.def.id === r.def.id)), i.tabIndex = o.def.id === r.def.id ? 0 : -1, i.onclick = () => Qs(o.def.id), n.appendChild(i);
    }), n.onkeydown = hodlAccountTabsKeydown, Qs(r.def.id);
  }
  let e = document.getElementById("reveal");
  e && (e.onchange = () => {
    Ge = e.checked, tc();
  }), document.getElementById("save")?.addEventListener("click", () => {
    if (!re) return;
    let t = new Blob([hodlFormatRecoverySheet(Oo(re, Ge))], { type: "text/plain" }), r = document.createElement("a");
    r.href = URL.createObjectURL(t), r.download = "bitcoin-recovery-sheet.txt", r.click();
  });
}
To = To.map((definition) => definition.id === "bip86" ? { ...definition, slip: "x" } : definition);
cr = {
  mainnet: {
    x: { pub: 76067358, prv: 76066276, pubName: "xpub", prvName: "xprv" },
    y: { pub: 77429938, prv: 77428856, pubName: "ypub", prvName: "yprv" },
    z: { pub: 78792518, prv: 78791436, pubName: "zpub", prvName: "zprv" }
  },
  testnet: {
    x: { pub: 70617039, prv: 70615956, pubName: "tpub", prvName: "tprv" },
    y: { pub: 71979618, prv: 71978536, pubName: "upub", prvName: "uprv" },
    z: { pub: 73342198, prv: 73341116, pubName: "vpub", prvName: "vprv" }
  }
};
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
So = [];
for (let [network, families] of Object.entries(cr)) for (let [family, entry] of Object.entries(families)) {
  So.push({ network, family, scope: "singlesig", private: false, ver: entry.pub, name: entry.pubName });
  So.push({ network, family, scope: "singlesig", private: true, ver: entry.prv, name: entry.prvName });
}
So.push(...hodlMultisigKeyVersions);
uf = function(value) {
  let input = String(value ?? "").trim(), payload = sr.decode(input), version = lf(input), entry = So.find((candidate) => candidate.ver === version);
  if (!entry) throw new Error("Not a recognized extended key. Use xpub/xprv, tpub/tprv, ypub/yprv, zpub/zprv, upub/uprv, vpub/vprv, or a supported multisig export.");
  if (payload.length !== 78) throw new Error("The extended key payload has an unexpected length.");
  let normalized = le(input, entry.private ? cr.mainnet.x.prv : cr.mainnet.x.pub), node = Gt.fromExtendedKey(normalized);
  if (Boolean(node.privateKey) !== entry.private) throw new Error("The extended-key prefix does not match its key payload.");
  let depth = payload[4], childNumber = new DataView(payload.buffer, payload.byteOffset + 9, 4).getUint32(0, false);
  if (node.depth !== depth) throw new Error("The extended-key depth does not match its serialized payload.");
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
  return value ? le(value, cr[network][family][isPrivate ? "prv" : "pub"]) : null;
}
function hodlSerializeMultisigExtendedKey(value, network, family) {
  let version = hodlMultisigKeyVersions.find((entry) => entry.network === network && entry.family === family && !entry.private);
  return value && version ? le(value, version.ver) : null;
}
function hodlBuildMultisigCosignerExports(root, network, accountIndex, masterFingerprint, coinType = Rs(network)) {
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
      family: "y",
      scriptIndex: 1
    },
    {
      accountId: "bip84",
      kind: "p2wsh",
      label: "Native SegWit \xB7 BIP48",
      family: "z",
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
      publicKey = definition.family === "x" ? hodlSerializeExtendedKey(node.publicExtendedKey, network, "x", !1) : hodlSerializeMultisigExtendedKey(node.publicExtendedKey, network, definition.family);
    let prefix = definition.family === "x" ? cr[network].x.pubName : hodlMultisigKeyVersions.find(entry => entry.network === network && entry.family === definition.family && !entry.private)?.name || "extended public key";
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
  if (selected.length === 1) return Le(body);
  let first = selected[0], pattern = new RegExp(`/${first}/\\*`, "g");
  if (!pattern.test(body)) return "";
  return Le(body.replace(pattern, `/<${selected.join(";")}>/*`));
}
function hodlDescriptorQrSvg(payload) {
  return Xs(payload, { ecc: "M", border: 4, pixelSize: 4, blackColor: "#111111", whiteColor: "#ffffff" });
}
function hodlWatchOnlyDescriptorExport(receiveDescriptor, changeDescriptor, addressBranches = null) {
  let branches = (addressBranches?.length ? addressBranches : [
    { branch: 0, label: "Receive", publicDescriptor: receiveDescriptor },
    { branch: 1, label: "Change", publicDescriptor: changeDescriptor }
  ]).filter((entry) => entry.publicDescriptor), first = branches[0], multipath = first ? branches.length === 1 ? first.publicDescriptor : hodlWatchOnlyMultipathDescriptor(first.publicDescriptor, branches.map((entry) => entry.branch)) : "", qr = "";
  if (multipath) {
    try {
      if (multipath.length > 1e3) throw new Error("Descriptor too long for a static QR.");
      qr = `<div class="watch-only-qr"><div class="qr qr-descriptor" aria-label="Watch-only wallet descriptor QR code">${hodlDescriptorQrSvg(multipath)}</div><p class="muted">Import this output descriptor into Sparrow or another wallet.</p></div>`;
    } catch (error) {
      qr = `<p class="muted">${$t(error.message || "Descriptor too long for a static QR.")} Copy the text instead, or import the selected branch descriptors separately.</p>`;
    }
  }
  let details = branches.map((entry) => ye(`Watch-only ${hodlAddressBranchLabel(entry.branch).toLowerCase()} descriptor`, entry.publicDescriptor)).join("");
  return `${ye("Watch-only wallet descriptor", multipath || "\u2014")}${qr}<details class="wallet-advanced"><summary>Address branch descriptors</summary>${details}</details>`;
}
function hodlAccountResult(node, definition, network, count, options = {}) {
  let rawPublic = node.publicExtendedKey, rawPrivate = node.privateKey ? node.privateExtendedKey : null, family = hodlAccountExportFamily(definition, options), primaryConfig = cr[network][family] || cr[network].x, genericConfig = cr[network].x;
  let genericPublic = hodlSerializeExtendedKey(rawPublic, network, "x", false), genericPrivate = hodlSerializeExtendedKey(rawPrivate, network, "x", true);
  let primaryPublic = hodlSerializeExtendedKey(rawPublic, network, family, false), primaryPrivate = hodlSerializeExtendedKey(rawPrivate, network, family, true);
  let origin = options.originFingerprint && options.originPath ? `[${options.originFingerprint}/${options.originPath}]` : "", branchHardened = Boolean(options.branchHardened), addressHardened = Boolean(options.addressHardened), wildcard = addressHardened ? "*'" : "*", branchStart = options.branchStart ?? 0, branchRange = options.branchRange ?? 2;
  let addressBranches = Array.from({ length: branchRange }, (_, offset) => {
    let branch = branchStart + offset, branchStep = hodlPathIndex(branch, branchHardened), branchOrigin = options.originFingerprint && options.originPath ? `[${options.originFingerprint}/${options.originPath}/${hodlOriginPathIndex(branch, branchHardened)}]` : "", branchNode = branchHardened && node.privateKey ? node.derive(`m/${branchStep}`) : null, branchPublic = branchNode ? hodlSerializeExtendedKey(branchNode.publicExtendedKey, network, "x", false) : null;
    let publicToken = addressHardened ? null : branchHardened ? branchPublic ? `${branchOrigin}${branchPublic}/${wildcard}` : null : `${origin}${genericPublic}/${branchStep}/${wildcard}`, privateToken = genericPrivate ? `${origin}${genericPrivate}/${branchStep}/${wildcard}` : null;
    let result = {
      branch,
      branchHardened,
      role: hodlAddressBranchRole(branch),
      label: hodlAddressBranchLabel(branch),
      publicDescriptor: publicToken ? Le(Ye(definition.script, publicToken)) : null,
      privateDescriptor: privateToken ? Le(Ye(definition.script, privateToken)) : null,
      rows: options.addressBranches?.find((entry) => entry.branch === branch)?.rows ?? nn(node, options.accountPath ?? "Imported account key", definition.script, network, count, branch, options.addressStart ?? 0, addressHardened, branchHardened)
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
mf = function(root, definition, network, count, masterFingerprint, accountIndex = 0, addressStart = 0, coinType = Rs(network)) {
  let accountPath = Ao(definition, coinType, accountIndex), node = root.derive(accountPath), originPath = `${definition.purpose}h/${coinType}h/${accountIndex}h`;
  let account = hodlAccountResult(node, definition, network, count, { accountPath, accountIndex, masterFingerprint, originFingerprint: masterFingerprint, originPath, addressStart });
  node.wipePrivateData(); // the account keeps its extended-key strings, not the node
  return account;
};
function hodlRootWalletResult(root, network, source, accountIndex, masterFingerprint, accounts, coinType = Rs(network)) {
  return {
    kind: "hd",
    network,
    coinType,
    mnemonic: source.mnemonic,
    passphraseUsed: source.passphraseUsed,
    entropyHex: source.entropyHex,
    seedHex: source.seedHex,
    rootXprv: hodlSerializeExtendedKey(root.privateKey ? root.privateExtendedKey : null, network, "x", true),
    rootXpub: hodlSerializeExtendedKey(root.publicExtendedKey, network, "x", false),
    rootPrivateLabel: cr[network].x.prvName,
    rootPublicLabel: cr[network].x.pubName,
    masterFingerprint,
    multisigCosignerExports: root.privateKey ? hodlBuildMultisigCosignerExports(root, network, accountIndex, masterFingerprint, coinType) : [],
    imported: false,
    notes: source.notes,
    warnings: source.warnings,
    accounts
  };
}
Hs = function(root, network, count, source, accountIndex = 0, addressStart = 0, coinType = Rs(network)) {
  let addressCount = Math.min(Math.max(count, 1), 10000), masterFingerprint = Us(root.fingerprint), accounts = To.map((definition) => mf(root, definition, network, addressCount, masterFingerprint, accountIndex, addressStart, coinType));
  return hodlRootWalletResult(root, network, source, accountIndex, masterFingerprint, accounts, coinType);
};
function hodlImportedScriptDefinition(parsed) {
  if (parsed.family === "y") return To.find((definition) => definition.id === "bip49");
  if (parsed.family === "z") return To.find((definition) => definition.id === "bip84");
  return hodlScriptDefinition(hodlSelectedScriptType());
}
function hodlSinglesigScriptMismatch(parsed, selectedScriptId) {
  let expectedId = parsed?.family === "y" ? "bip49" : parsed?.family === "z" ? "bip84" : "";
  if (!expectedId || expectedId === selectedScriptId) return "";
  let expected = To.find((definition) => definition.id === expectedId), selected = To.find((definition) => definition.id === selectedScriptId);
  if (!expected || !selected) return "";
  return `${parsed.prefix} indicates ${expected.label} (${expected.bip}), but you selected ${selected.label} (${selected.bip}). EntropyLab will derive ${expected.label} from the ${parsed.prefix} prefix. Change Script type to ${expected.label} to make the settings agree.`;
}
Po = function(value, network, count, accountIndex = 0, addressStart = 0) {
  let importedValue = String(value ?? "").trim(), parsed = uf(importedValue);
  if (parsed.scope !== "singlesig") throw new Error(`${parsed.prefix} is a multisig extended key. Use it in Multi Signature, not Key Derivation.`);
  if (parsed.network !== network) throw new Error(`This ${parsed.prefix} belongs to Bitcoin ${parsed.network}. Change Network to ${parsed.network} before deriving it.`);
  let node = parsed.node, mismatch = hodlSinglesigScriptMismatch(parsed, hodlSelectedScriptType()), notes = [parsed.isPrivate ? "Imported an extended private key. Addresses and WIF keys are derived from it." : "Imported an extended public key. This is watch-only: it can derive addresses but cannot spend."];
  if (node.depth === 0) {
    if (!parsed.isPrivate) throw new Error("A root extended public key cannot derive the hardened BIP44/49/84/86 account paths. Import an account-level extended public key, or use the root xprv/tprv offline.");
    if (parsed.family !== "x") throw new Error("A BIP32 root private key must use the generic xprv/tprv prefix.");
    return Hs(node, network, count, { mnemonic: null, passphraseUsed: false, entropyHex: null, seedHex: null, notes, warnings: [] }, accountIndex, addressStart);
  }
  if (node.depth !== 3) throw new Error(`This extended key is depth ${node.depth}. Key Derivation accepts a BIP32 root private key (depth 0) or an account-level extended key (depth 3).`);
  let definition = hodlImportedScriptDefinition(parsed), addressCount = Math.min(Math.max(count, 1), 10000), parentFingerprint = Us(node.parentFingerprint), nodeFingerprint = Us(node.fingerprint);
  let account = hodlAccountResult(node, definition, network, addressCount, { accountPath: "Imported account key", accountIndex: null, imported: true, importedFamily: parsed.family, importedValue, parentFingerprint, nodeFingerprint, addressStart });
  return {
    kind: "hd",
    network,
    mnemonic: null,
    passphraseUsed: false,
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
    warnings: [...parsed.isPrivate ? [] : ["Watch-only. This key contains no private key material."], ...(mismatch ? [mismatch] : []), "The imported account key did not include a master fingerprint or origin path, so descriptors intentionally omit a fabricated key origin."],
    accounts: [account]
  };
};
async function hodlAddressRowsWithProgress(node, accountPath, script, network, count, role, addressStart, tracker, addressHardened = false, branchHardened = false) {
  let rows = [];
  for (let index = addressStart; index < addressStart + count; index++) {
    rows.push(hodlDerivedAddressRow(node, accountPath, script, network, role, index, addressHardened, branchHardened));
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
async function hodlRootWalletWithProgress(root, network, count, source, accountIndex, addressStart, tracker, purposeIndex, coinType = Rs(network), hardening = hodlDefaultHardening(), branchStart = 0, branchRange = 2, derivationPlan = null) {
  let addressCount = Math.min(Math.max(count, 1), hodlMaxAddressRange), masterFingerprint = Us(root.fingerprint), accounts = [];
  tracker.setTotal(addressCount * To.length * branchRange);
  for (let definition of To) {
    let derivedDefinition = { ...definition, purpose: purposeIndex, purposeHardened: hardening.purpose }, accountPath = derivationPlan?.accountPath || Ao(derivedDefinition, coinType, accountIndex, hardening), node = root.derive(accountPath), originPath = derivationPlan?.originPath ?? `${hodlOriginPathIndex(purposeIndex, hardening.purpose)}/${hodlOriginPathIndex(coinType, hardening.coinType)}/${hodlOriginPathIndex(accountIndex, hardening.account)}`;
    let account = await hodlAccountResultWithProgress(node, derivedDefinition, network, addressCount, { accountPath, accountIndex, masterFingerprint, originFingerprint: masterFingerprint, originPath, addressStart, branchHardened: hardening.branch, addressHardened: hardening.address, branchStart, branchRange }, tracker);
    node.wipePrivateData(); // the account keeps its extended-key strings, not the node
    accounts.push(account);
  }
  return hodlRootWalletResult(root, network, source, accountIndex, masterFingerprint, accounts, coinType);
}
async function hodlMnemonicWalletWithProgress(value, passphrase, network, count, source, accountIndex, addressStart, tracker, purposeIndex, coinType = Rs(network), hardening = hodlDefaultHardening(), branchStart = 0, branchRange = 2, derivationPlan = null) {
  let validation = Mt(value);
  if (!validation.ok) throw new Error(validation.error ?? "Invalid seed phrase");
  let mnemonic = validation.words.join(" "), seed = wi(mnemonic, passphrase), root, seedHex;
  try {
    root = Gt.fromMasterSeed(seed);
    seedHex = M.encode(seed);
  } finally {
    seed.fill(0); // the 64-byte seed is dead once the root node exists
  }
  let entropyHex = source?.entropyHex ?? M.encode(Er(mnemonic, Ae)), warnings = [...source?.warnings ?? []];
  if (passphrase.length > 0) warnings.push("A passphrase is in use. The same words without this passphrase are a different wallet. Do not store the passphrase with the words.");
  try {
    return await hodlRootWalletWithProgress(root, network, count, { mnemonic, passphraseUsed: passphrase.length > 0, entropyHex, seedHex, notes: source?.notes ?? [], warnings }, accountIndex, addressStart, tracker, purposeIndex, coinType, hardening, branchStart, branchRange, derivationPlan);
  } finally {
    root.wipePrivateData(); // the result keeps its extended-key strings, not the root
  }
}
async function hodlEntropyWalletWithProgress(entropy, passphrase, network, count, accountIndex, addressStart, tracker, purposeIndex, coinType = Rs(network), hardening = hodlDefaultHardening(), branchStart = 0, branchRange = 2, derivationPlan = null) {
  try {
    return await hodlMnemonicWalletWithProgress(_n(entropy.bytes), passphrase, network, count, { entropyHex: entropy.hex, notes: entropy.notes, warnings: entropy.warnings }, accountIndex, addressStart, tracker, purposeIndex, coinType, hardening, branchStart, branchRange, derivationPlan);
  } finally {
    entropy.bytes.fill(0); // the entropy bytes are dead once the mnemonic exists
  }
}
async function hodlImportedWalletWithProgress(value, network, count, accountIndex, addressStart, tracker, purposeIndex, coinType = Rs(network), hardening = hodlDefaultHardening(), branchStart = 0, branchRange = 2, derivationPlan = null) {
  let importedValue = String(value ?? "").trim(), parsed = uf(importedValue);
  if (parsed.scope !== "singlesig") throw new Error(`${parsed.prefix} is a multisig extended key. Use it in Multi Signature, not Key Derivation.`);
  if (parsed.network !== network) throw new Error(`This ${parsed.prefix} belongs to Bitcoin ${parsed.network}. Change Network to ${parsed.network} before deriving it.`);
  let node = parsed.node, mismatch = hodlSinglesigScriptMismatch(parsed, hodlSelectedScriptType()), notes = [parsed.isPrivate ? "Imported an extended private key. Addresses and WIF keys are derived from it." : "Imported an extended public key. This is watch-only: it can derive addresses but cannot spend."];
  if (node.depth === 0) {
    if (!parsed.isPrivate && (derivationPlan ? derivationPlan.hasHardenedPrefix || hardening.branch || hardening.address : Object.values(hardening).some(Boolean))) throw new Error("A root extended public key cannot derive the selected hardened path. Turn every Harden option off, import an account-level public key, or use the root xprv/tprv offline.");
    if (parsed.family !== "x") throw new Error("A BIP32 root private key must use the generic xprv/tprv prefix.");
    try {
      return await hodlRootWalletWithProgress(node, network, count, { mnemonic: null, passphraseUsed: false, entropyHex: null, seedHex: null, notes, warnings: [] }, accountIndex, addressStart, tracker, purposeIndex, coinType, hardening, branchStart, branchRange, derivationPlan);
    } finally {
      node.wipePrivateData(); // the imported root is dead once the result strings exist
    }
  }
  if (node.depth !== 3) throw new Error(`This extended key is depth ${node.depth}. Key Derivation accepts a BIP32 root private key (depth 0) or an account-level extended key (depth 3).`);
  if ((hardening.branch || hardening.address) && !parsed.isPrivate) throw new Error(`Hardened ${hardening.branch ? "address branches" : "address indexes"} cannot be derived from an account extended public key. Turn off Harden or import the matching extended private key offline.`);
  let definition = hodlImportedScriptDefinition(parsed), addressCount = Math.min(Math.max(count, 1), hodlMaxAddressRange), parentFingerprint = Us(node.parentFingerprint), nodeFingerprint = Us(node.fingerprint);
  tracker.setTotal(addressCount * branchRange);
  let account = await hodlAccountResultWithProgress(node, definition, network, addressCount, { accountPath: "Imported account key", accountIndex: null, imported: true, importedFamily: parsed.family, importedValue, parentFingerprint, nodeFingerprint, addressStart, branchHardened: hardening.branch, addressHardened: hardening.address, branchStart, branchRange }, tracker);
  node.wipePrivateData(); // the account result keeps its strings, not the imported node
  return {
    kind: "hd",
    network,
    mnemonic: null,
    passphraseUsed: false,
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
    warnings: [...parsed.isPrivate ? [] : ["Watch-only. This key contains no private key material."], ...(mismatch ? [mismatch] : []), "The imported account key did not include a master fingerprint or origin path, so descriptors intentionally omit a fabricated key origin."],
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
    return isPrivate ? Ee(label, descriptor) : ye(label, descriptor);
  }).join("");
}
function hodlAddressBranchKey(prefix, branch) {
  return `${prefix}-${branch === 0 ? "receive" : branch === 1 ? "change" : `branch-${branch}`}`;
}
function hodlAddressBranchTables(branches, includeWif, prefix) {
  return branches.map((branch) => {
    let label = hodlAddressBranchLabel(branch.branch), key = hodlAddressBranchKey(prefix, branch.branch);
    return `<h4 class="wallet-data-subtitle">${$t(label)}</h4>${hodlAddressTable(branch.rows, `${label} addresses`, includeWif, key)}`;
  }).join("");
}
function hodlAddressBranchVirtualConfigs(branches, includeWif, prefix) {
  return branches.map((branch) => ({ key: hodlAddressBranchKey(prefix, branch.branch), rows: branch.rows, includeWif }));
}
function hodlAccountAdvancedExports(account, includePrivate = false) {
  if (!account.hasAlternateExport) return "";
  let privateExport = includePrivate && account.genericPrivate ? Ee(`Generic ${account.genericPrivateLabel} for descriptor compatibility`, account.genericPrivate) : "";
  let publicExport = !includePrivate && account.genericPublic ? ye(`Generic ${account.genericPublicLabel} for descriptor compatibility`, account.genericPublic) : "";
  if (!privateExport && !publicExport) return "";
  if (includePrivate) return `<div class="wallet-advanced">${privateExport}</div>`;
  return `<details class="wallet-advanced"><summary>Advanced watch-only export</summary>${publicExport}</details>`;
}
function hodlImportedCoreRecoveryData(wallet, account) {
  if (!wallet?.importedPublicKey || !account?.imported || !["y", "z"].includes(account.primaryFamily) || !account.genericPublic || !account.def?.script) return null;
  return {
    importedLabel: `Imported ${wallet.importedPublicLabel || "extended public key"}`,
    importedKey: wallet.importedPublicKey,
    coreLabel: `Core ${account.genericPublicLabel}`,
    coreKey: account.genericPublic,
    descriptorLabel: "Bitcoin Core descriptor",
    descriptor: Le(Ye(account.def.script, `${account.genericPublic}/<0;1>/*`))
  };
}
function hodlImportedCoreRecoveryExport(wallet, account) {
  let data = hodlImportedCoreRecoveryData(wallet, account);
  if (!data) return "";
  return `<div class="wallet-data-fields imported-core-recovery"><h4 class="wallet-data-subtitle">Bitcoin Core recovery export</h4><p class="muted">The SLIP-132 prefix records the script type. The Core key above is the same payload with generic version bytes; this descriptor keeps the script type explicit and stays on the conventional receive/change branches for Bitcoin Core.</p>${ye(data.descriptorLabel, data.descriptor)}</div>`;
}
function hodlRenderMultisigCosignerExport(exports, accountId) {
  let items = Array.isArray(exports) ? exports.filter((candidate) => candidate.accountId === accountId) : [];
  return items.map((item) => ye(`Multisig co-signer ${item.prefix} \xB7 ${item.label}`, item.value)).join("");
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
  if(re?.kind==="msig")return{receive:re.receive||[],change:re.change||[],branches:hodlAccountAddressBranches(re)};
  if(re?.kind==="hd"){
    let id=hodlSelectedScriptType(),account=re.accounts.find(candidate=>candidate.def.id===id)||re.accounts[0];
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
  let node = Gt.fromExtendedKey(extendedKey),
    network = account.network || re.network,
    script = account.def.script,
    base = account.accountPath || "m";
  let searchEnd = Math.min(hodlMaxAddressIndex + 1, start + hodlAddressSearchLimit);
  for (let index = start; index < searchEnd; index++) {
    for (let branch of hodlAccountAddressBranches(account)) {
      let chain = branch.branch, role = branch.role, branchStep = hodlPathIndex(chain, account.branchHardened), indexStep = hodlPathIndex(index, account.addressHardened);
      let child = node.derive(`m/${branchStep}/${indexStep}`),
        pk = child.publicKey;
      if (!pk) continue;
      if (hodlAddressesEqual(address, pf(script, pk, network))) return {
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
  let nodes = re?.nodes;
  if (!nodes?.length) return {
    state: "miss",
    searchedTo: start
  };
  let bip45 = re.script === "p2sh" && re.scriptStandard === "bip45";
  let searchEnd = Math.min(hodlMaxAddressIndex + 1, start + hodlAddressSearchLimit);
  for (let index = start; index < searchEnd; index++) {
    for (let branch of hodlAccountAddressBranches(re)) {
      let path = bip45 ? `m/0/${branch.branch}/` : `m/${branch.branch}/`, keys = nodes.map(node => {
        let key = node.derive(path + index).publicKey;
        if (!key) throw new Error("Could not derive a public key");
        return key;
      });
      if (hodlAddressesEqual(address, hodlMsigAddr(keys, re.m, re.network, re.script, re.sorted !== !1).address)) return { state: "match", chain: branch.role, branch: branch.branch, index, path: path.slice(1) + index, beyond: !0 };
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
    status.textContent = `Not in the ${shown} shown addresses. Checking further indices `;
    status.className = "hint";
    let beyond = {
      state: "miss",
      searchedTo: lastShown
    };
    try {
      if (re?.kind === "hd") {
        let id = hodlSelectedScriptType(),
          account = re.accounts.find(candidate => candidate.def.id === id) || re.accounts[0];
        beyond = hodlMatchHdAddressBeyond(address, account, nextIndex)
      } else if (re?.kind === "msig") beyond = hodlMatchMsigAddressBeyond(address, nextIndex)
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
  return rows.map((row, offset) => `<tr aria-rowindex="${rowOffset + offset + 2}"><th scope="row">${row.index}</th><td>${$t(hodlDisplayDerivationPath(row.path))}</td><td>${$t(row.address)}</td>${includeWif ? `<td>${hodlPrivateValue(row.wif, "mono table-private-field-value")}</td>` : ""}</tr>`).join("");
}
function hodlAddressVirtualSpacer(height, columns) {
  return height > 0 ? `<tr class="address-virtual-spacer" aria-hidden="true"><td colspan="${columns}" style="height:${height}px"></td></tr>` : "";
}
function hodlAddressVirtualRows(rows, includeWif, start, end) {
  let columns = includeWif ? 4 : 3, top = start * hodlAddressVirtualRowHeight, bottom = (rows.length - end) * hodlAddressVirtualRowHeight;
  return `${hodlAddressVirtualSpacer(top, columns)}${hodlAddressTableRows(rows.slice(start, end), includeWif, start)}${hodlAddressVirtualSpacer(bottom, columns)}`;
}
function hodlAddressTable(rows, label = "Addresses", includeWif = false, tableKey = "addresses") {
  let safeLabel = $t(includeWif ? `${label} with WIF private keys` : label), tableClass = includeWif ? "wallet-table-private" : "wallet-table-public", virtual = rows.length > hodlAddressVirtualThreshold;
  let wifHeading = includeWif ? '<th scope="col">WIF</th>' : "", safeKey = $t(tableKey), initialEnd = virtual ? Math.min(rows.length, hodlAddressVirtualThreshold) : rows.length;
  let body = virtual ? hodlAddressVirtualRows(rows, includeWif, 0, initialEnd) : hodlAddressTableRows(rows, includeWif);
  return `<div class="wallet-address-table" data-address-table="${safeKey}"><div class="wallet-table ${tableClass}" role="region" tabindex="0" aria-label="${safeLabel} table; scroll continuously for more rows or columns"><table aria-rowcount="${rows.length + 1}"><caption class="sr-only">${safeLabel}</caption><thead><tr aria-rowindex="1"><th scope="col">#</th><th scope="col">Path</th><th scope="col">Address</th>${wifHeading}</tr></thead><tbody>${body}</tbody></table></div></div>`;
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
  let field = isPrivate ? Ee : ye, parts = [];
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
function Qs(id) {
  if (!re || re.kind !== "hd") return;
  let account = re.accounts.find((candidate) => candidate.def.id === id);
  if (!account) return;
  hodlSetSelectedScriptType(id);
  hodlSyncAccountTabs(id);
  let branches = hodlAccountAddressBranches(account), firstBranch = branches[0], firstAddress = firstBranch?.rows[0], firstIndex = firstAddress?.index ?? 0, firstLabel = firstBranch ? hodlAddressBranchLabel(firstBranch.branch) : "Address", hasPrivate = hodlAccountHasPrivate(account), purposeLabel = account.imported ? account.def.bip : `Purpose ${hodlOriginPathIndex(account.def.purpose, account.def.purposeHardened !== false)}`;
  let privateSection = hasPrivate ? `
    <section class="account-result-section account-private-section" aria-labelledby="account-private-heading">
      <div class="wallet-data-section-head">
        <h3 id="account-private-heading">Private account material</h3>
        <p class="muted">These exports can spend from this account. They are shown only for a seed or extended private-key source.</p>
      </div>
      ${hodlSlip132Fields(account, re, true)}
      ${hodlAddressBranchDescriptorFields(branches, true)}
      ${hodlAccountAdvancedExports(account, true)}
      <p class="account-private-warning"><strong>Keep these exports together only in secure offline backups.</strong> An account extended public key combined with any non-hardened descendant private key, including a WIF shown in the address tables below, can reconstruct that account's extended private key.</p>
    </section>` : "";
  W("#acct").innerHTML = `
    <div class="key-result-main">
      <div class="kicker">${$t(purposeLabel)} \xB7 ${$t(re.network)}</div>
      <h2>${$t(account.def.label)}</h2>
      <p class="muted">${$t(account.def.beginner)}</p>
      ${privateSection}
      <section class="account-result-section account-watch-section" aria-labelledby="account-watch-heading">
        <div class="wallet-data-section-head">
          <h3 id="account-watch-heading">Watch-only wallet data</h3>
          <p class="watch-only-note"><strong>Cannot spend:</strong> these exports can monitor every address and reveal this account's transaction history and balance. Treat them as privacy-sensitive.</p>
        </div>
        ${hodlSlip132WatchFields(account, re)}
        ${hodlImportedCoreRecoveryExport(re, account)}
        ${hodlRenderMultisigCosignerExport(re.multisigCosignerExports, account.def.id)}
        ${hodlWatchOnlyDescriptorExport(account.receiveDescriptor, account.changeDescriptor, branches)}
        ${hodlAccountAdvancedExports(account, false)}
      </section>
      <section class="account-result-section account-address-section" aria-labelledby="account-address-heading">
        <div class="wallet-data-section-head">
          <h3 id="account-address-heading">Addresses</h3>
          <p class="muted">Verify the first selected address on another trusted wallet or signing device before accepting bitcoin.</p>
        </div>
        ${firstAddress ? `<div class="account-address-lead"><h4 class="wallet-data-subtitle">${$t(firstLabel)} address #${firstIndex}</h4><div class="qr" aria-label="${$t(firstLabel)} address ${firstIndex} QR code">${an(firstAddress.address)}</div><p class="mono">${$t(firstAddress.address)}</p><p class="muted mono">${$t(hodlDisplayDerivationPath(firstAddress.path))}</p></div>` : ""}
        ${hodlAddressBranchTables(branches, hasPrivate, "hd")}
        ${hodlAddressMatchMarkup()}
      </section>
    </div>`;
  hodlBindAddressVirtualization(hodlAddressBranchVirtualConfigs(branches, hasPrivate, "hd"));
  hodlBindAddressMatch();
  hodlBindWalletResultActions();
}
function ye(label, value) {
  return `<p><span class="muted">${$t(label)}</span><br><span class="mono">${$t(value ?? "\u2014")}</span></p>`;
}
function hodlPrivateValue(value, className = "secret private-field-value") {
  let mask = "************", text = String(value ?? "\u2014");
  if (Ge) return `<span class="${className}">${$t(text)}</span>`;
  let bullets = "\u2022".repeat(Math.max(Array.from(text).length, mask.length));
  return `<span class="${className} secret-placeholder"><span class="secret-placeholder-mask" aria-hidden="true">${bullets}</span><span class="secret-placeholder-message" aria-hidden="true">${mask}</span><span class="secret-placeholder-label">Private value hidden</span></span>`;
}
function Ee(label, value) {
  return `<p class="private-field"><span class="muted">${$t(label)}</span>${hodlPrivateValue(value)}</p>`;
}
function hodlDisplayDerivationPath(value) {
  return String(value ?? "").replace(/(^|\/)(\d+)'(?=\/|$)/g, "$1$2h");
}
function Js(rows) {
  return hodlAddressTable(rows, "Addresses");
}
function $t(value) {
  let entities = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };
  return Array.from(String(value ?? ""), (character) => entities[character] ?? character).join("");
}
function hodlPrivateDataControls(descriptionId, scope = "wallet") {
  let privateSheet = Ge, downloadLabel = privateSheet ? "Save unencrypted private sheet" : "Save watch-only sheet";
  let disclosure = privateSheet ? scope === "wallet" ? "The downloaded plain-text file is unencrypted and includes all available root and account private recovery material across every script type." : "The downloaded plain-text file is unencrypted and includes every private key shown in this section." : "The downloaded sheet omits all private recovery material.";
  return `<div class="wallet-data-actions no-print">
    <label class="reveal-private-toggle">
      <input type="checkbox" id="reveal" ${Ge ? "checked" : ""} aria-describedby="${descriptionId} recovery-sheet-disclosure" />
      <span>Show private recovery material <span class="reveal-private-toggle-note">(air-gap only)</span></span>
    </label>
    <button class="btn secondary save-recovery-sheet" id="save" type="button" aria-describedby="recovery-sheet-disclosure">${downloadLabel}</button>
    ${hodlWalletDatControl(privateSheet)}
    <p class="recovery-download-disclosure" id="recovery-sheet-disclosure"><strong>${privateSheet ? "Private export:" : "Watch-only export:"}</strong> ${disclosure}</p>
  </div>`;
}
function hodlWalletDatControl(includePrivate) {
  if (!hodlWalletExport.hasDescriptors(re)) return "";
  // Bitcoin Core starts its automatic scan at the wallet birthday stored in
  // the descriptor records. Recovery needs genesis (creation time 0) so
  // transactions predating this export are found; "now" is only safe for
  // keys created at this moment and skips past history (faster, and reveals
  // no older activity to anyone who later sees the file). If a loaded wallet
  // looks empty, repair it with Bitcoin Core's `rescanblockchain 0`.
  return `<label class="wallet-dat-birthday">Wallet birthday <select data-wallet-dat-birthday aria-describedby="wallet-dat-birthday-help"><option value="genesis"${hodlWalletDatBirthday === "genesis" ? " selected" : ""}>Recovering keys \xB7 scan from genesis</option><option value="now"${hodlWalletDatBirthday === "now" ? " selected" : ""}>New keys \xB7 created today</option></select></label><button class="btn secondary save-wallet-dat" id="download-wallet-dat" type="button" aria-describedby="recovery-sheet-disclosure wallet-dat-birthday-help">${hodlWalletExport.walletDatButtonLabel(includePrivate)}</button><p class="muted wallet-dat-birthday-help" id="wallet-dat-birthday-help">Bitcoin Core only auto-scans history back to the birthday. Choose \u201CNew keys\u201D only for entropy created right now; recovering older keys with today's birthday can look empty until you run <code>rescanblockchain 0</code> in Bitcoin Core.</p>`;
}
function hodlSaveRecoveryControl() {
  return `<div class="wallet-data-actions no-print"><button class="btn secondary save-recovery-sheet" id="save" type="button">Save watch-only sheet</button>${hodlWalletDatControl(false)}</div>`;
}
function hodlWalletMessages(wallet, idPrefix) {
  let warnings = [...wallet.warnings || []].filter((message) => !wallet.passphraseUsed || !/\bpassphrase\b/i.test(message)), notes = [...wallet.notes || []];
  if (wallet.passphraseUsed) warnings.unshift("A BIP39 passphrase is in use. It creates a different wallet, is not printed in the recovery sheet, and must be preserved separately to recover this wallet.");
  if (!warnings.length && !notes.length) return "";
  let items = [...warnings.map((message) => `<li class="is-warning">${$t(message)}</li>`), ...notes.map((message) => `<li>${$t(message)}</li>`)].join("");
  return `<section class="wallet-result-messages" aria-labelledby="${idPrefix}-safety-heading"><h3 id="${idPrefix}-safety-heading">Safety notes</h3><ul>${items}</ul></section>`;
}
function hodlSingleWalletData(wallet) {
  let miniKey = wallet.minikey ? Ee("Mini private key", wallet.minikey) : "";
  return `<section class="card wallet-data-card">
    <div class="wallet-data-intro">
      <div class="kicker">Single-key wallet data</div>
      <h2 tabindex="-1">Key recovery details</h2>
      <p class="muted">Review the private key and addresses derived from this input. Sensitive recovery material is grouped first; public wallet data appears below.</p>
      ${hodlWalletMessages(wallet, "single")}
    </div>
    <section class="wallet-data-section wallet-private-section" aria-labelledby="single-private-heading">
      <div class="wallet-data-section-head">
        <h3 id="single-private-heading">Private key material</h3>
        <p class="muted" id="single-private-description">These values can spend the bitcoin held by the addresses below. Reveal them only while this file is running offline on an air-gapped computer.</p>
      </div>
      ${hodlPrivateDataControls("single-private-description", "single")}
      <div class="wallet-data-fields">
        ${Ee("WIF compressed", wallet.wifCompressed)}
        ${Ee("WIF uncompressed", wallet.wifUncompressed)}
        ${Ee("Hex private key", wallet.privHex)}
        ${miniKey}
      </div>
    </section>
    <section class="wallet-data-section wallet-public-section" aria-labelledby="single-public-heading">
      <div class="wallet-data-section-head">
        <h3 id="single-public-heading">Public keys &amp; addresses</h3>
        <p class="muted">Use these values for verification or watch-only monitoring. They do not reveal the private key.</p>
      </div>
      <div class="wallet-data-fields">
        ${ye("Compressed public key", wallet.pubkeyCompressed)}
        ${ye("Uncompressed public key", wallet.pubkeyUncompressed)}
        <h4 class="wallet-data-subtitle">Addresses</h4>
        ${ye("Legacy uncompressed", wallet.p2pkhUncompressed)}
        ${ye("Legacy compressed", wallet.p2pkhCompressed)}
        ${ye("Nested SegWit", wallet.p2shP2wpkh)}
        ${ye("Native SegWit", wallet.p2wpkh)}
        ${ye("Taproot", wallet.p2tr)}
        <h4 class="wallet-data-subtitle">Native SegWit QR code</h4>
        <div class="qr" aria-label="Native SegWit address QR code">${an(wallet.p2wpkh)}</div>
      </div>
    </section>
  </section>`;
}
function hodlHdRootRecovery(wallet) {
  let privateFields = [];
  if (wallet.mnemonic) privateFields.push(hodlSeedPhraseField(`Your seed phrase \xB7 ${wallet.mnemonic.trim().split(/\s+/).length} words`, wallet.mnemonic), hodlSeedQrExport(wallet.mnemonic, { passphraseUsed: wallet.passphraseUsed, entropyHex: wallet.entropyHex }));
  if (wallet.entropyHex) privateFields.push(Ee("BIP39 entropy hex", wallet.entropyHex));
  if (wallet.seedHex) privateFields.push(Ee("Master seed hex", wallet.seedHex));
  if (wallet.rootXprv) privateFields.push(Ee(`Root ${wallet.rootPrivateLabel || cr[wallet.network].x.prvName}`, wallet.rootXprv));
  if (wallet.importedPrivateKey) privateFields.push(Ee(`Imported ${wallet.importedPrivateLabel || "extended private key"}`, wallet.importedPrivateKey));
  return privateFields.length ? `<div class="wallet-data-fields">${privateFields.join("")}</div>` : "";
}
function hodlHdWalletData(wallet) {
  let privateFields = [];
  if (wallet.mnemonic) privateFields.push(hodlSeedPhraseField(`Your seed phrase \xB7 ${wallet.mnemonic.trim().split(/\s+/).length} words`, wallet.mnemonic), hodlSeedQrExport(wallet.mnemonic, { passphraseUsed: wallet.passphraseUsed, entropyHex: wallet.entropyHex }));
  if (wallet.entropyHex) privateFields.push(Ee("BIP39 entropy hex", wallet.entropyHex));
  if (wallet.seedHex) privateFields.push(Ee("Master seed hex", wallet.seedHex));
  if (wallet.rootXprv) privateFields.push(Ee(`Root ${wallet.rootPrivateLabel || cr[wallet.network].x.prvName}`, wallet.rootXprv));
  if (wallet.importedPrivateKey) privateFields.push(Ee(`Imported ${wallet.importedPrivateLabel || "extended private key"}`, wallet.importedPrivateKey));
  let hasAccountPrivate = wallet.accounts.some(hodlAccountHasPrivate), hasPrivate = privateFields.length > 0 || hasAccountPrivate;
  let privateContent = privateFields.length ? privateFields.join("") : `<p class="muted">Private account material is available in the selected script panel below; no BIP32 root private key was supplied.</p>`;
  let intro = wallet.mnemonic ? "Review the root material derived from this seed. Private recovery data is grouped first; watch-only data appears below." : "Review the material available from this imported extended key. Private data, when present, is grouped first; watch-only data appears below.";
  let source = wallet.mnemonic ? "" : `<p><span class="muted">Source</span><br><span>Imported extended ${hasPrivate ? "private" : "public"} key; no seed phrase was entered.</span></p>`;
  let privateSection = hasPrivate ? `<section class="wallet-data-section wallet-private-section" aria-labelledby="wallet-private-heading">
      <div class="wallet-data-section-head">
        <h3 id="wallet-private-heading">Private recovery material</h3>
        <p class="muted" id="wallet-private-description">These values can recreate or spend from the wallet. Reveal them only while this file is running offline on an air-gapped computer.</p>
      </div>
      ${hodlPrivateDataControls("wallet-private-description")}
      <div class="wallet-data-fields">${privateContent}</div>
    </section>` : "";
  let fingerprint = wallet.masterFingerprint ? ye("Master fingerprint", wallet.masterFingerprint) : "";
  let parentFingerprint = !wallet.masterFingerprint && wallet.parentFingerprint ? ye("Encoded parent fingerprint (not a master fingerprint)", wallet.parentFingerprint) : "";
  let nodeFingerprint = !wallet.masterFingerprint && wallet.nodeFingerprint ? ye("Imported key fingerprint (not a master fingerprint)", wallet.nodeFingerprint) : "";
  let rootPublic = wallet.rootXpub ? ye(`Root ${wallet.rootPublicLabel || cr[wallet.network].x.pubName}`, wallet.rootXpub) : "";
  let importedPublic = wallet.importedPublicKey ? ye(`Imported ${wallet.importedPublicLabel || "extended public key"}`, wallet.importedPublicKey) : "";
  return `<section class="card wallet-data-card">
    <div class="wallet-data-intro">
      <div class="kicker">Wallet data</div>
      <h2 tabindex="-1">Wallet recovery details</h2>
      <p class="muted">${intro}</p>
      ${hodlWalletMessages(wallet, "wallet")}
    </div>
    ${privateSection}
    <section class="wallet-data-section wallet-public-section" aria-labelledby="wallet-public-heading">
      <div class="wallet-data-section-head">
        <h3 id="wallet-public-heading">Watch-only wallet data</h3>
        <p class="muted">These values identify the wallet or enable watch-only use, but do not authorize spending. Treat them as privacy-sensitive because extended public keys and descriptors can reveal wallet addresses, balances, and transaction history.</p>
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
function hodlDownloadRecoverySheet() {
  if (!re) return;
  let blob = new Blob([hodlFormatRecoverySheet(Oo(re, Ge))], { type: "text/plain" }), url = URL.createObjectURL(blob), link = document.createElement("a");
  link.href = url;
  link.download = "bitcoin-recovery-sheet.txt";
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1e3);
}
function hodlWalletDatDeps() {
  return {
    sha256: (bytes) => tr(bytes),
    checksum: Cs,
    base58Decode: (text) => sr.decode(text),
    deriveBranchBody: (xpubText, branch) => {
      let node = Gt.fromExtendedKey(le(xpubText, cr.mainnet.x.pub)).deriveChild(branch), body = new Uint8Array(74), view = new DataView(body.buffer);
      body[0] = node.depth;
      view.setUint32(1, node.parentFingerprint >>> 0, false);
      view.setUint32(5, node.index >>> 0, false);
      body.set(node.chainCode, 9);
      body.set(node.publicKey, 41);
      return body;
    },
    publicKeyForPrivate: (secret) => xe.getPublicKey(secret, true)
  };
}
function hodlDownloadWalletDat() {
  if (!re || !hodlWalletExport.hasDescriptors(re)) return;
  // Recovery default is a genesis birthday so Core scans from the start;
  // "now" is written only when the user confirms the keys are new (issue
  // #95).
  let creationTime = hodlWalletDatBirthday === "now" ? Math.floor(Date.now() / 1000) : 0;
  let bytes = hodlWalletExport.buildWalletDat(re, Ge, hodlWalletDatDeps(), creationTime), blob = new Blob([bytes], { type: "application/octet-stream" }), url = URL.createObjectURL(blob), link = document.createElement("a");
  link.href = url;
  link.download = hodlWalletExport.walletDatFilename(re, Ge);
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1e3);
}
function hodlBindWalletResultActions() {
  let reveal = document.getElementById("reveal");
  if (reveal) reveal.onchange = () => {
    Ge = reveal.checked;
    let state = hodlKeys[hodlActiveKey];
    if (state) state.reveal = Ge;
    tc();
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
  requestAnimationFrame(() => (hodlWorkspace === "msig" ? document.getElementById("msig-summary-policy") || document.querySelector("#msig-out h2") : document.getElementById("key-summary-fingerprint") || dr.querySelector(".account-address-lead, .wallet-data-intro h2"))?.focus?.({ preventScroll: false }));
}
var hodlRenderWalletBase = tc;
tc = function() {
  hodlRenderWalletBase();
  hodlBindWalletResultActions();
};
function hodlSheetWarnings(lines, wallet) {
  for (let note of wallet.notes || []) lines.push(`Note: ${note}`);
  for (let warning of wallet.warnings || []) lines.push(`Warning: ${warning}`);
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
Oo = function(wallet, revealPrivate) {
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
    if (wallet.rootXprv) lines.push("", `BIP32 ROOT ${(wallet.rootPrivateLabel || cr[wallet.network].x.prvName).toUpperCase()}`, wallet.rootXprv);
    if (wallet.importedPrivateKey) lines.push("", `IMPORTED ${(wallet.importedPrivateLabel || "EXTENDED PRIVATE KEY").toUpperCase()}`, wallet.importedPrivateKey);
    for (let account of wallet.accounts) {
      if (!hodlAccountHasPrivate(account)) continue;
      lines.push("", `-- ${account.def.label} (${account.imported ? account.def.bip : `Purpose ${hodlOriginPathIndex(account.def.purpose, account.def.purposeHardened !== false)}`}) PRIVATE ACCOUNT MATERIAL --`);
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
  if (wallet.rootXpub) lines.push(`BIP32 root ${(wallet.rootPublicLabel || cr[wallet.network].x.pubName).toUpperCase()}: ${wallet.rootXpub}`);
  if (wallet.multisigCosignerExports?.length) {
    lines.push("", "MULTISIG CO-SIGNER EXPORTS", "Paste one complete value into a co-signer input. Legacy offers BIP45 without accounts and BIP87 with standardized accounts; use the same standard and account policy for every co-signer.");
    for (let item of wallet.multisigCosignerExports) lines.push(`${item.label} (${item.prefix}): ${item.value}`);
  }
  if (wallet.importedPublicKey) lines.push(`Imported ${(wallet.importedPublicLabel || "extended public key").toUpperCase()}: ${wallet.importedPublicKey}`);
  for (let account of wallet.accounts) {
    lines.push("", `=== ${account.def.label} (${account.imported ? account.def.bip : `Purpose ${hodlOriginPathIndex(account.def.purpose, account.def.purposeHardened !== false)}`}) ===`, account.def.beginner, `Network: ${wallet.network}`, `Account: ${account.imported ? "Imported account key" : account.accountIndex ?? 0}`, `Account path: ${hodlDisplayDerivationPath(account.accountPath)}`);
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
  return To.find((definition) => definition.id === id) || To.find((definition) => definition.id === "bip84") || To[0];
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
  return Number(coinType) === 1 ? "Testnet" : Number(coinType) === 0 ? "Mainnet" : "Custom · Mainnet addresses";
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
  let visible = hodlReadVisibleDerivationPath(), input = document.getElementById("derivation-path"), accountPath = `m${visible.accountComponents.map((entry) => `/${hodlPathIndex(entry.index, entry.hardened)}`).join("")}`;
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
    let accountComponents = [{ index: purpose.value, hardened: purpose.hardened }, { index: network.value, hardened: network.hardened }, { index: account.value, hardened: account.hardened }, ...existing.slice(3)], accountPath = `m${accountComponents.map((entry) => `/${hodlPathIndex(entry.index, entry.hardened)}`).join("")}`, branchWindow = hodlReadBranchWindow("", false), addressWindow = hodlReadAddressWindow("", false), hardening = hodlReadHardening();
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
function hodlReadAccount(mark = true) {
  return hodlReadDerivationIndex(document.getElementById("account"), "Account", mark);
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
  if (!Number.isFinite(milliseconds) || milliseconds < 100) return "under 0.1 seconds";
  if (milliseconds < 10000) return `about ${(milliseconds / 1000).toFixed(1)} seconds`;
  if (milliseconds < 60000) return `about ${Math.round(milliseconds / 1000)} seconds`;
  return `about ${Math.ceil(milliseconds / 60000)} minutes`;
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
      let node = Gt.fromMasterSeed(new Uint8Array(32)).derive("m/84'/0'/0'"), samples = 32, started = performance.now();
      nn(node, "m/84h/0h/0h", "p2wpkh", "mainnet", samples, "receive", 0);
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
    button.textContent = "Stop";
    button.disabled = false;
    button.setAttribute("aria-disabled", "false");
    button.setAttribute("aria-label", kind === "msig" ? "Stop deriving multisig" : "Stop deriving wallet");
    button.dataset.derivationState = "running";
  } else if (state === "stopping") {
    button.textContent = "Stopping…";
    button.disabled = true;
    button.setAttribute("aria-disabled", "true");
    button.setAttribute("aria-label", kind === "msig" ? "Stopping multisig derivation" : "Stopping wallet derivation");
    button.dataset.derivationState = "stopping";
  } else {
    button.textContent = kind === "msig" ? "Derive Multisig" : "Derive Wallet";
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
      progress?.setAttribute("aria-valuetext", "Done");
      let label = progress?.querySelector(".derive-progress-label");
      if (label) label.innerHTML = `${hodlCopiedIconMarkup()}<span>Done</span>`;
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
  if (Ne !== "seed") return null;
  let value = document.getElementById("seed")?.value.trim() || "";
  if (!hodlLooksExtendedKey(value)) return null;
  try {
    let normalized = uf(value);
    return Gt.fromExtendedKey(normalized.xkey).depth;
  } catch {
    return null;
  }
}
function hodlUpdateKeyModeControls() {
  let singleKey = Ne === "key", hdBrain = hodlBrainHdActive(), settings = document.getElementById("key-settings");
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
  if (!input || Ne === "key" && !hodlBrainHdActive()) return;
  try {
    let visible = hodlReadVisibleDerivationPath();
    input.dataset.accountPath = `m${visible.accountComponents.map((entry) => `/${hodlPathIndex(entry.index, entry.hardened)}`).join("")}`;
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
      if (re?.kind === "hd") {
        if (re.accounts.some((account) => account.def.id === id && account.def.purpose === purpose)) Qs(id);
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
  return String(value ?? "").trim().split(/\s+/).filter(Boolean).map((word) => `<span class="seed-phrase-word">${mask ? "\u2022".repeat(Array.from(word).length) : $t(word)}</span>`).join(" ");
}
function hodlSeedPhraseField(label, value) {
  let text = String(value ?? "\u2014");
  if (Ge) return `<p class="private-field seed-phrase-field"><span class="muted">${$t(label)}</span><span class="secret private-field-value seed-phrase-value">${hodlSeedPhraseTokens(text)}</span></p>`;
  return `<p class="private-field seed-phrase-field"><span class="muted">${$t(label)}</span><span class="secret private-field-value secret-placeholder seed-phrase-value"><span class="secret-placeholder-mask" aria-hidden="true">${hodlSeedPhraseTokens(text, true)}</span><span class="secret-placeholder-message" aria-hidden="true">************</span><span class="secret-placeholder-label">Private value hidden</span></span></p>`;
}
function hodlSeedQrDigits(mnemonic) {
  let words = String(mnemonic ?? "").trim().split(/\s+/).filter(Boolean);
  if (words.length !== 12 && words.length !== 24) return "";
  let digits = "";
  for (let word of words) {
    let index = Ae.indexOf(word);
    if (index < 0) return "";
    digits += String(index).padStart(4, "0");
  }
  return digits;
}
function hodlCompactSeedQrBytes(entropyHex) {
  let hex = String(entropyHex ?? "").replace(/\s/g, "").toLowerCase();
  if (hex.length !== 32 && hex.length !== 64) return null;
  return Array.from(M.decode(hex));
}
function hodlSeedQrExport(mnemonic, options = {}) {
  let words = String(mnemonic ?? "").trim().split(/\s+/).filter(Boolean);
  if (!words.length || !Ge) return "";
  if (words.length !== 12 && words.length !== 24) return `<details class="wallet-advanced"><summary>SeedQR</summary><p class="muted">SeedQR is defined for 12 and 24 word phrases. Type this ${words.length}-word seed on the signer.</p></details>`;
  let digits = hodlSeedQrDigits(mnemonic);
  if (!digits) return "";
  let passNote = options.passphraseUsed ? " This QR is the seed only. Enter the passphrase on the signer after scanning." : "";
  let compact = "";
  try {
    let bytes = hodlCompactSeedQrBytes(options.entropyHex);
    if (bytes) compact = `<div class="watch-only-qr seed-qr"><div class="qr qr-seed" aria-label="CompactSeedQR">${Xs(bytes, { ecc: "L", border: 4, pixelSize: 4, blackColor: "#111111", whiteColor: "#ffffff" })}</div><p class="muted">CompactSeedQR. Same seed, smaller binary code.</p><p class="muted">Compatible with: SeedSigner, Krux, Jade, Passport.</p></div>`;
  } catch {
  }
  return `<details class="wallet-advanced"><summary>SeedQR</summary><p class="muted">Scan into a camera signer. This is the seed.${passNote}</p><div class="seed-qr-pair"><div class="watch-only-qr seed-qr"><div class="qr qr-seed" aria-label="SeedQR">${Xs(digits, { ecc: "L", border: 4, pixelSize: 4, blackColor: "#111111", whiteColor: "#ffffff" })}</div><p class="muted">SeedQR. Numeric.</p><p class="muted">Compatible with: SeedSigner, Krux, Jade, Passport, Coldcard Q.</p><p class="muted mono">${$t(digits)}</p></div>${compact}</div></details>`;
}
var hodlSeedLengths = Object.freeze({
  12: Object.freeze({ words: 12, bits: 128, bytes: 16, hexChars: 32, hashRolls: 50, partialWords: 11, candidates: 128 }),
  15: Object.freeze({ words: 15, bits: 160, bytes: 20, hexChars: 40, hashRolls: 62, partialWords: 14, candidates: 64 }),
  18: Object.freeze({ words: 18, bits: 192, bytes: 24, hexChars: 48, hashRolls: 75, partialWords: 17, candidates: 32 }),
  21: Object.freeze({ words: 21, bits: 224, bytes: 28, hexChars: 56, hashRolls: 87, partialWords: 20, candidates: 16 }),
  24: Object.freeze({ words: 24, bits: 256, bytes: 32, hexChars: 64, hashRolls: 99, partialWords: 23, candidates: 8 })
});
var hodlEntropyFormats = Object.freeze({
  bin: Object.freeze({ id: "bin", base: 2, bitsPerDigit: 1, alphabet: "01", label: "Binary (Base 2)", shortLabel: "Binary", unit: "binary digits", method: "binary" }),
  base4: Object.freeze({ id: "base4", base: 4, bitsPerDigit: 2, alphabet: "0123", label: "Base 4", shortLabel: "Base 4", unit: "base-4 digits", method: "base4" }),
  base8: Object.freeze({ id: "base8", base: 8, bitsPerDigit: 3, alphabet: "01234567", label: "Octal (Base 8)", shortLabel: "Octal", unit: "octal digits", method: "base8" }),
  hex: Object.freeze({ id: "hex", base: 16, bitsPerDigit: 4, alphabet: "0123456789ABCDEF", label: "Hexadecimal (Base 16)", shortLabel: "Hexadecimal", unit: "hexadecimal characters", method: "hex" }),
  base32: Object.freeze({ id: "base32", base: 32, bitsPerDigit: 5, alphabet: "0123456789ABCDEFGHJKMNPQRSTVWXYZ", label: "Crockford Base32", shortLabel: "Base32", unit: "characters", method: "base32", binaryRemainder: true }),
  base64: Object.freeze({ id: "base64", base: 64, bitsPerDigit: 6, alphabet: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", label: "Base64 (RFC 4648 alphabet)", shortLabel: "Base64", unit: "characters", method: "base64", binaryRemainder: true })
});
var hodlBip39WordSet = new Set(Ae), hodlBip39WordIndex = new Map(Ae.map((word, index) => [word, index])), hodlLastWordCache = /* @__PURE__ */ new Map();
var hodlOnScreenKeyboardOpen = false;
function hodlSeedConfig(words = Pt) {
  return hodlSeedLengths[Number(words)] || hodlSeedLengths[24];
}
function hodlNormalizeEntropyFormat(format) {
  return Object.hasOwn(hodlEntropyFormats, String(format ?? "")) ? String(format) : "bin";
}
function hodlEntropyFormatConfig(format, targetWords = Pt) {
  let definition = hodlEntropyFormats[hodlNormalizeEntropyFormat(format)], seed = hodlSeedConfig(targetWords), fullDigits = Math.floor(seed.bits / definition.bitsPerDigit), remainderBits = seed.bits % definition.bitsPerDigit, digits = fullDigits + (remainderBits ? definition.binaryRemainder ? remainderBits : 1 : 0), finalBase = remainderBits ? 2 ** remainderBits : definition.base, finalCharacters = remainderBits ? definition.binaryRemainder ? "01" : definition.alphabet.slice(0, finalBase) : definition.alphabet;
  return { ...definition, digits, fullDigits, remainderBits, finalBase, finalCharacters, seed };
}
function hodlLooksExtendedKey(value) {
  return /^[xtyzuvYZUV][A-Za-z0-9]+$/.test(value.trim()) && value.trim().length > 80;
}
function hodlSinglesigImportStatus(value, network) {
  try {
    let parsed = uf(value), depth = parsed.node.depth, hardening = hodlReadHardening(), plan = Ne === "key" ? null : hodlReadDerivationPlan(false), hardenedPrefix = plan ? plan.hasHardenedPrefix : hardening.purpose || hardening.coinType || hardening.account;
    if (parsed.scope !== "singlesig") return { ok: false, message: `${parsed.prefix} is a multisig export \xB7 use Multi Signature` };
    if (parsed.network !== network) return { ok: false, message: `${parsed.prefix} is for ${parsed.network} \xB7 change Network to ${parsed.network}` };
    if (depth === 0 && !parsed.isPrivate && (hardenedPrefix || hardening.branch || hardening.address)) return { ok: false, message: "Root extended public keys cannot derive the selected hardened path \xB7 turn every Harden option off or import a private root key offline" };
    if (depth === 0 && parsed.family !== "x") return { ok: false, message: "A root private key must use an xprv/tprv prefix" };
    if (depth !== 0 && depth !== 3) return { ok: false, message: `Depth ${depth} extended key \xB7 use a root private key or depth-3 account key` };
    if (depth === 3 && !parsed.isPrivate && (hardening.branch || hardening.address)) return { ok: false, message: `Account extended public keys cannot derive hardened ${hardening.branch ? "address branches" : "address indexes"} \xB7 turn off the corresponding Harden option` };
    let definition = depth === 3 ? hodlImportedScriptDefinition(parsed) : null, detail = definition ? ` \xB7 ${definition.label} ${definition.bip}` : "", mismatch = hodlSinglesigScriptMismatch(parsed, hodlSelectedScriptType());
    return { ok: true, warning: Boolean(mismatch), message: mismatch ? `\u26A0\uFE0F ${mismatch}` : `${parsed.prefix} ${parsed.isPrivate ? "private" : "watch-only"} key detected \xB7 ${network}${detail} \xB7 ready to derive` };
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
  return step === "d8" ? "D8" : step === "d16" ? "D16" : "a coin flip";
}
function hodlDPlusStepValue(step, face) {
  if (step === "d8") return /^[1-8]$/.test(face) ? Number(face) - 1 : null;
  if (step === "d16") return hodlDPlusD16Value(face);
  return /^[1-8]$/.test(face) ? (Number(face) >= 5 ? 1 : 0) : null;
}
function hodlDPlusFinalSteps(words = Pt) {
  let config = hodlSeedConfig(words);
  return hodlDPlusFinalSpecs[config.words] || hodlDPlusFinalSpecs[24];
}
function hodlDPlusFinalDescription(words = Pt) {
  let steps = hodlDPlusFinalSteps(words), labels = steps.map(hodlDPlusStepLabel);
  if (steps.length === 1) return `roll the ${labels[0]} once more`;
  if (labels[0] === labels[1]) return `roll a final ${labels[0]} twice`;
  return `roll a final ${labels.join(" and ")}`;
}
function hodlDPlusFinalHelp(words = Pt) {
  let steps = hodlDPlusFinalSteps(words), labels = steps.map((step) => step === "coin" ? "coin flip" : hodlDPlusStepLabel(step));
  let coin = steps.includes("coin") ? " The final D8 is interpreted as a coin flip: 1\u20134 is Heads, 5\u20138 is Tails. Or flip a real coin!" : "";
  if (steps.length === 1) return `One final ${labels[0]} roll selects the checksum word.`;
  if (labels[0] === labels[1]) return `Two final ${labels[0]} rolls select the checksum word.`;
  return `One final ${labels[0]} roll and one final ${labels[1]} roll select the checksum word.${coin}`;
}
function hodlDPlusStepChecksumLabel(step) {
  return step === "coin" ? "the final coin flip" : `the final ${hodlDPlusStepLabel(step)} checksum roll`;
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
function hodlDPlusRolls(value, targetWords = Pt) {
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
      word = Ae[wordIndex];
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
    notes = [`D++: ${completedGroups} of ${rolledTarget} positional D8 + D16 + D16 groups entered; ${validWordCount} valid (${rolledEntries.length} of ${rolledCharacterTarget} required results).`],
    warnings = [];
  notes.push("D++ D16 results use the hexadecimal faces 0 through F exactly as shown on the dice.");
  if (complete && finalWord) {
    let labels = finalInfo.map((info) => info.step === "coin" ? `D8 result ${info.value} read as ${Number(info.value) >= 5 ? "Tails" : "Heads"}` : `${hodlDPlusStepLabel(info.step)} result ${info.value}`).join(" and ");
    notes.push(`Final ${labels} selected checksum option ${finalIndex + 1} of ${candidates.length}: ${finalWord}.`);
  }
  if (waiting === "last-word") notes.push(`Choose 1 of ${config.candidates} checksum-valid final words to complete the ${config.words}-word seed.`);
  if (rejectedD8) notes.push(`Rejected ${rejectedD8} result${rejectedD8===1?"":"s"} that cannot be used for a D8 roll.`);
  if (rejectedD16) notes.push(`Rejected ${rejectedD16} result${rejectedD16===1?"":"s"} that ${rejectedD16===1?"is":"are"} not a hexadecimal D16 face (0\u2013F).`);
  if (extraAfter) warnings.push(`${extraAfter} extra input${extraAfter===1?" was":"s were"} ignored after ${hodlDPlusFinalDescription(config.words)}.`);
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

function hodlAnalyzeDiceInput(value, method = ge, targetWords = Pt, coinPositions = hodlDiceCoinPositions) {
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
  return new Intl.NumberFormat(undefined, { maximumSignificantDigits: 5 }).format(Number(value) || 0);
}
function hodlDiceFairnessVerdict(cdf, enough) {
  if (!enough) return { id: "need-more", label: "Need more rolls", tone: "muted" };
  if (cdf < 0.8) return { id: "fair", label: "Looks pretty fair", tone: "ok" };
  if (cdf < 0.9) return { id: "unsure", label: "Not sure; roll some more", tone: "warn" };
  return { id: "biased", label: "Looks biased", tone: "danger" };
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
function hodlDiceFairnessSamples(value, method, targetWords = Pt) {
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
function hodlDiceFairnessReports(value, method, targetWords = Pt) {
  return hodlDiceFairnessSamples(value, method, targetWords).map((sample) => hodlDiceFairnessAssess(sample.rolls, sample.labels, sample.title));
}
function hodlDiceFairnessTone(reports) {
  let rank = { danger: 3, warn: 2, ok: 1, muted: 0 }, tone = "muted";
  for (let report of reports || []) if ((rank[report.verdict.tone] || 0) > rank[tone]) tone = report.verdict.tone;
  return tone;
}
function hodlDiceFairnessNote(report) {
  if (!report.n) return "";
  if (!report.enough) return `${report.n} of ${report.minimum} minimum ${report.title} rolls for Pearson’s χ² test · ${report.remaining} more needed.`;
  let robust = report.minimum * 2, cdfPercent = hodlFormatFairnessNumber(report.cdf * 100);
  let quality = report.n >= robust ? "Enough rolls to reasonably assess fairness." : `Minimum reached. ${robust - report.n} more would make the estimate more robust.`;
  return `A fair ${report.title} would score χ² below ${hodlFormatFairnessNumber(report.chi)} in ${cdfPercent}% of tests. ${quality}`;
}
function hodlDiceFairnessMarkup(reports) {
  return (reports || []).filter((report) => report.n > 0).map((report) => {
    let peak = Math.max(report.expected, ...report.counts.map((face) => face.count), 1);
    let faces = report.counts.map((face) => {
      let hot = report.enough && report.expected > 0 && Math.abs(face.count - report.expected) >= 2 * Math.sqrt(report.expected);
      return `<div class="dice-fairness-face${hot ? " is-hot" : ""}"><span class="dice-fairness-label">${$t(face.label)}</span><span class="dice-fairness-track"><span class="dice-fairness-bar" style="width:${(face.count / peak * 100).toFixed(1)}%"></span>${report.expected > 0 ? `<span class="dice-fairness-expected" style="left:${(report.expected / peak * 100).toFixed(1)}%"></span>` : ""}</span><span class="dice-fairness-count">${face.count}</span></div>`;
    }).join("");
    return `<section class="dice-fairness-test" data-tone="${report.verdict.tone}"><div class="dice-fairness-head"><strong>${$t(report.verdict.label)}</strong><span>χ² ${hodlFormatFairnessNumber(report.chi)} · ${report.df} df · ${report.n} roll${report.n === 1 ? "" : "s"}</span></div><p class="dice-fairness-note">${$t(hodlDiceFairnessNote(report))}</p><div class="dice-fairness-faces" data-sides="${report.sides}">${faces}</div></section>`;
  }).join("");
}
function hodlDiceFairnessIsOpen() {
  return Boolean(hodlKeys[hodlActiveKey]?.showDiceFairness);
}
function hodlDiceFairnessToggleMarkup(open) {
  let expanded = Boolean(open);
  return `<button type="button" class="dice-fairness-toggle" id="dice-fairness-toggle" aria-controls="dice-fairness" aria-expanded="${expanded}" aria-label="${expanded ? "Hide die distribution / fairness analysis" : "Show die distribution / fairness analysis"}"><span data-dice-fairness-glyph aria-hidden="true">${expanded ? "\u25BE" : "\u25B8"}</span> Die Distribution / Fairness Analysis</button>`;
}
function hodlSetDiceFairnessOpen(open) {
  let expanded = Boolean(open), state = hodlKeys[hodlActiveKey], toggle = document.getElementById("dice-fairness-toggle"), glyph = toggle?.querySelector("[data-dice-fairness-glyph]");
  if (state) state.showDiceFairness = expanded;
  if (toggle) {
    toggle.setAttribute("aria-expanded", String(expanded));
    toggle.setAttribute("aria-label", expanded ? "Hide die distribution / fairness analysis" : "Show die distribution / fairness analysis");
  }
  if (glyph) glyph.textContent = expanded ? "\u25BE" : "\u25B8";
  let input = document.getElementById("dice");
  hodlRenderDiceFairness(input?.value || "", ge, hodlSeedConfig().words);
  hodlSyncKeyClearButton();
}
function hodlRenderDiceFairness(value, method, targetWords = Pt) {
  let panel = document.getElementById("dice-fairness");
  if (!panel) return;
  let reports = hodlDiceFairnessReports(value, method, targetWords), markup = hodlDiceFairnessMarkup(reports), open = hodlDiceFairnessIsOpen();
  panel.hidden = !open;
  panel.dataset.tone = open ? hodlDiceFairnessTone(reports) : "muted";
  panel.innerHTML = open ? (markup ? `${markup}<p class="dice-fairness-caveat">Pearson’s χ² goodness-of-fit. A lucky streak can look biased, and a biased die can look fair until more rolls arrive. This check does not block derivation.</p>` : `<p class="dice-fairness-note">Enter rolls to run Pearson’s χ² test.</p>`) : "";
  panel.setAttribute("aria-label", "Die Distribution / Fairness Analysis");
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
function hodlSanitizeDiceInput(input, method = ge, targetWords = Pt) {
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

function hodlSanitizeDPlusInput(input, targetWords = Pt) {
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
    let target = document.getElementById("error");
    if (target) target.textContent = error instanceof Error ? error.message : String(error);
    return;
  }
  let start = Number.isInteger(input.selectionStart) ? input.selectionStart : input.value.length, end = Number.isInteger(input.selectionEnd) ? input.selectionEnd : start;
  delete input.hodlDiceBeforeInput;
  if (ge !== "dplus") hodlRebaseDiceCoinPositions(start, end, inserted.length, Boolean(button.dataset.coin));
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
function hodlNumberBaseBits(value, format, targetWords = Pt) {
  let meta = hodlEntropyFormatConfig(format, targetWords), digits = hodlEntropyDigits(value, meta.id).slice(0, meta.digits);
  return Array.from(digits, (character, index) => {
    if (meta.binaryRemainder && index >= meta.fullDigits) return character;
    let width = meta.remainderBits && index === meta.digits - 1 ? meta.remainderBits : meta.bitsPerDigit;
    return meta.alphabet.indexOf(character).toString(2).padStart(width, "0");
  }).join("").slice(0, meta.seed.bits);
}
function hodlNumberBaseValueFromBytes(bytes, format, targetWords = Pt) {
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
function hodlAnalyzeEntropyInput(value, format, targetWords = Pt) {
  let meta = hodlEntropyFormatConfig(format, targetWords), { entries, invalidEntries } = hodlEntropyDigitEntries(value, meta.id), excessEntries = entries.slice(meta.digits), remainderEntries = meta.binaryRemainder ? entries.slice(meta.fullDigits, meta.digits) : entries.slice(meta.digits - 1, meta.digits), finalInvalidEntries = meta.remainderBits ? remainderEntries.filter((entry) => !meta.finalCharacters.includes(entry.normalized)) : [], finalInvalid = finalInvalidEntries.length > 0, invalidRanges = [...invalidEntries.map((entry) => [entry.start, entry.end]), ...excessEntries.map((entry) => [entry.start, entry.end]), ...finalInvalidEntries.map((entry) => [entry.start, entry.end])];
  return { count: entries.length, limit: meta.digits, excessCount: Math.max(0, entries.length - meta.digits), invalidCharacterCount: invalidEntries.length, finalInvalid, finalInvalidEntries, invalidRanges, entries, meta, ready: entries.length === meta.digits && !invalidEntries.length && !excessEntries.length && !finalInvalid };
}
function hodlRenderEntropyInputState(input, format, targetWords = Pt) {
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
    if (ge === "dplus") {
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
    } else if (ge === "bitbox") {
      if (analysis.complete) {
        disabled = true;
        reason = "All lookup-table words are complete.";
      } else if (!analysis.coinTurn && face >= 5) {
        disabled = true;
        reason = "Reroll a 5 or 6 during the first five BitBox rolls.";
      }
    }
    if (ge === "dplus") {
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
    if (ge === "bitbox") {
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
  let analysis = hodlAnalyzeDiceInput(input.value, ge, Pt);
  input.setAttribute("aria-invalid", String(analysis.invalidCount > 0));
  hodlRenderDiceInputHighlight(input, analysis);
  hodlUpdateDiceButtons(input, analysis);
  return analysis;
}
function hodlIanColemanDiceString(rolls) {
  return rolls.map((face) => face === "6" ? "0" : face).join("");
}
function hodlBitsToTargetEntropy(bitString, sourceBits, method, notes, warnings, targetWords, allowExtra) {
  let config = hodlSeedConfig(targetWords);
  if (bitString.length < config.bits) return { ok: false, error: `Need ${config.bits} mapped bits for a ${config.words}-word seed. This input provides ${bitString.length}.`, notes, warnings };
  if (!allowExtra && bitString.length !== config.bits) return { ok: false, error: `The selected ${config.words}-word seed needs exactly ${config.bits} bits. You entered ${bitString.length}.`, notes, warnings };
  if (bitString.length > config.bits) warnings.push(`Using the first ${config.bits} mapped bits of ${bitString.length}. Extra bits are not mixed in.`);
  let selected = bitString.slice(0, config.bits), bytes = new Uint8Array(config.bytes);
  for (let index = 0; index < bytes.length; index++) bytes[index] = Number.parseInt(selected.slice(index * 8, index * 8 + 8), 2);
  notes.push(`BIP39 entropy length: ${config.bits} bits \u2192 ${config.words}-word seed.`);
  return { ok: true, bytes, hex: M.encode(bytes), bits: config.bits, sourceBits, method, notes, warnings };
}
function hodlDiceEntropy(value, method, targetWords = Pt) {
  let config = hodlSeedConfig(targetWords), notes = [], warnings = [];
    if (method === "dplus") return { ok: false, error: `D++ directly selects ${config.partialWords} BIP39 words; ${hodlDPlusFinalDescription(config.words)} to finish with the final checksum word.`, notes, warnings };
  let parsed = Br(value), rolls = parsed.rolls;
  if (method === "bitbox") return { ok: false, error: `BitBox diceware uses ${config.partialWords} lookup-table words and a final checksum pick for a ${config.words}-word seed.`, notes, warnings };
  if (parsed.leftover.length) return { ok: false, error: `Dice must be faces 1\u20136. Ignored characters: ${JSON.stringify(parsed.leftover.slice(0, 24))}`, notes, warnings };
  if (!rolls.length) return { ok: false, error: "Enter at least one dice roll (faces 1\u20136).", notes, warnings };
  let sourceBits = kr(rolls.length);
  notes.push(`${rolls.length} rolls of a fair six-sided die \u2248 ${sourceBits.toFixed(1)} bits.`);
  if (rolls.length < config.hashRolls) warnings.push(`Only ${rolls.length} of ${config.hashRolls} recommended fair-die rolls were entered. The ${config.words}-word phrase is deterministic, but its security cannot exceed the approximately ${sourceBits.toFixed(1)} bits supplied. Use only for testing until the recommendation is met.`);
  else if (rolls.length > config.hashRolls) notes.push(`All ${rolls.length} rolls, including ${rolls.length - config.hashRolls} beyond the recommendation, are included in the hash.`);
  let hashInput = method === "coleman" ? hodlIanColemanDiceString(rolls) : rolls.join(""), digest = Z(new TextEncoder().encode(hashInput)), bytes = digest.slice(0, config.bytes);
  if (method === "coleman") notes.push(`Hashed rolls / Dice [1-6]: convert every 6 to 0, SHA-256 hash the complete mapped digit string, then use the first ${config.bits} bits for the selected ${config.words}-word seed. This matches the method used by Keystone.`);
  else notes.push(`Hashed rolls / Base 10 [0-9]: SHA-256 hash the complete original dice digit string, then use the first ${config.bits} bits for the selected ${config.words}-word seed. This matches COLDCARD and SeedSigner.`);
  return { ok: true, bytes, hex: M.encode(bytes), bits: config.bits, sourceBits, method: method === "coleman" ? "ian-coleman-dice-sha256" : "coldcard-sha256", notes, warnings };
}
function hodlNumberBaseEntropy(value, format, targetWords = Pt) {
  let meta = hodlEntropyFormatConfig(format, targetWords), analysis = hodlAnalyzeEntropyInput(value, meta.id, meta.seed.words), notes = [], warnings = [];
  if (!analysis.count) return { ok: false, error: `Enter exactly ${meta.digits} ${meta.unit} for a ${meta.seed.words}-word seed.`, notes, warnings };
  if (analysis.invalidCharacterCount) return { ok: false, error: `${meta.shortLabel} entropy contains ${analysis.invalidCharacterCount} invalid character${analysis.invalidCharacterCount === 1 ? "" : "s"}.`, notes, warnings };
  if (analysis.finalInvalid) return { ok: false, error: meta.binaryRemainder ? `The final ${meta.remainderBits} ${meta.shortLabel} entropy bit${meta.remainderBits === 1 ? "" : "s"} must each be 0 or 1.` : `The final ${meta.shortLabel} character contributes only ${meta.remainderBits} bit${meta.remainderBits === 1 ? "" : "s"} and must be one of ${[...meta.finalCharacters].join(", ")}.`, notes, warnings };
  if (analysis.count !== meta.digits) return { ok: false, error: `The selected ${meta.seed.words}-word seed needs exactly ${meta.digits} ${meta.unit} (${meta.seed.bits} bits). You entered ${analysis.count}.`, notes, warnings };
  let bits = hodlNumberBaseBits(value, meta.id, meta.seed.words), bytes = new Uint8Array(meta.seed.bytes);
  for (let index = 0; index < bytes.length; index++) bytes[index] = Number.parseInt(bits.slice(index * 8, index * 8 + 8), 2);
  notes.push(`${meta.digits} ${meta.unit} = ${meta.seed.bits} bits of ${meta.shortLabel} entropy.`);
  if (meta.remainderBits) notes.push(meta.binaryRemainder ? `${meta.fullDigits} complete ${meta.shortLabel} characters are followed by ${meta.remainderBits} individual coin-flip entropy bit${meta.remainderBits === 1 ? "" : "s"}.` : `The final character is mixed-radix: it contributes the remaining ${meta.remainderBits} entropy bit${meta.remainderBits === 1 ? "" : "s"} and must be one of ${[...meta.finalCharacters].join(", ")}.`);
  notes.push(`BIP39 entropy length: ${meta.seed.bits} bits \u2192 ${meta.seed.words}-word seed.`);
  return { ok: true, bytes, hex: M.encode(bytes), bits: meta.seed.bits, sourceBits: meta.seed.bits, method: meta.method, notes, warnings };
}
function hodlHexEntropy(value, targetWords = Pt) {
  return hodlNumberBaseEntropy(value, "hex", targetWords);
}
function hodlBinaryEntropy(value, targetWords = Pt) {
  return hodlNumberBaseEntropy(value, "bin", targetWords);
}
function hodlCardNeeded(targetWords = Pt) {
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
function hodlParseCards(raw, targetWords = Pt) {
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
function hodlAnalyzeCardInput(input, targetWords = Pt) {
  let parsed = hodlParseCards(input?.value ?? "", targetWords), pending = null, lastInvalid = parsed.invalidEntries.at(-1), caret = input?.selectionStart ?? -1;
  if (lastInvalid && document.activeElement === input && input.selectionStart === input.selectionEnd && caret === lastInvalid.end && !/[\s,.;:_|/-]$/.test(input.value) && hodlCardTokenCanContinue(lastInvalid.token)) pending = lastInvalid;
  let invalidRanges = [...parsed.invalidEntries.filter((entry) => entry !== pending), ...parsed.duplicateEntries].map((entry) => [entry.start, entry.end]);
  return { ...parsed, pending, invalidRanges };
}
function hodlRenderCardInputState(input, targetWords = Pt) {
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
  return `<span class="dealt-card${suit.red ? " is-red" : ""}" title="${rank} of ${suit.label}"><span class="dealt-rank">${$t(rank === "T" ? "10" : rank)}</span><span class="dealt-suit">${suit.symbol}</span></span>`;
}
function hodlCardsEntropy(value, targetWords = Pt, coleman = false) {
  let config = hodlSeedConfig(targetWords), notes = [], warnings = [], parsed = hodlParseCards(value, config.words);
  if (parsed.invalid.length) return { ok: false, error: `Cards use rank then suit, like As, 10h, or Td. Ignored: ${parsed.invalid.slice(0, 8).join(" ")}`, notes, warnings, parsed };
  if (parsed.duplicates.length) return { ok: false, error: `Do not repeat a card in the same shuffle. Repeated: ${parsed.duplicates[0]}.`, notes, warnings, parsed };
  if (!parsed.cards.length) return { ok: false, error: "Deal at least one card from a shuffled deck.", notes, warnings, parsed };
  let required = parsed.needed.first + parsed.needed.extra, hashInput = hodlCardsHashInput(parsed.cards, coleman);
  notes.push(`${parsed.cards.length} card${parsed.cards.length === 1 ? "" : "s"} \u2248 ${parsed.bits.toFixed(1)} bits.`);
  notes.push(coleman ? "SHA-256 hashes Ian Coleman's suit-symbol transcript (A\u2660 2\u2663 T\u2666), then the first " + config.bits + " bits become the selected " + config.words + "-word seed. One shuffled deck is about 225.6 bits." : "SHA-256 hashes the ASCII transcript (As 2c Td), then the first " + config.bits + " bits become the selected " + config.words + "-word seed. One shuffled deck is about 225.6 bits.");
  if (parsed.cards.length < required) warnings.push(`Only ${parsed.cards.length} of ${required} recommended cards were entered. The ${config.words}-word phrase is deterministic, but its security cannot exceed the approximately ${parsed.bits.toFixed(1)} bits supplied. Use only for testing until the recommendation is met.`);
  if (parsed.cards.length > required) notes.push(`All ${parsed.cards.length} cards, including extras, are included in the hash.`);
  let digest = Z(new TextEncoder().encode(hashInput)), bytes = digest.slice(0, config.bytes);
  return { ok: true, bytes, hex: M.encode(bytes), bits: config.bits, sourceBits: parsed.bits, method: coleman ? "ian-coleman-cards-sha256" : "cards-sha256", notes, warnings, parsed, hashInput };
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
function hodlDirectCardFinalRadices(targetWords = Pt) {
  return { 12: [8, 8, 2], 15: [8, 8], 18: [8, 4], 21: [8, 2], 24: [8] }[hodlSeedConfig(targetWords).words];
}
function hodlDirectCardSteps(targetWords = Pt) {
  let config = hodlSeedConfig(targetWords), steps = [];
  for (let index = 0; index < config.partialWords; index++) steps.push(8, 8, 8, 4);
  return steps.concat(hodlDirectCardFinalRadices(config.words));
}
function hodlDirectCardRankValue(rank) {
  let normalized = String(rank ?? "").trim().toUpperCase();
  return normalized === "A" ? 0 : /^[2-8]$/.test(normalized) ? Number(normalized) - 1 : -1;
}
function hodlDirectCardSeparator(index, targetWords = Pt) {
  if (index === 0) return "";
  let config = hodlSeedConfig(targetWords), fullWordDraws = config.partialWords * 4, finalDraws = hodlDirectCardFinalRadices(config.words).length;
  if (index < fullWordDraws) return index % 4 === 0 ? " " : "";
  return index === fullWordDraws || index === fullWordDraws + finalDraws ? " " : "";
}
function hodlFilterDirectCards(value, targetWords = Pt) {
  let characters = String(value ?? "").toUpperCase().match(/[0-9A-Z]/g) || "", clean = "";
  for (let index = 0; index < characters.length; index++) clean += hodlDirectCardSeparator(index, targetWords) + characters[index];
  return clean;
}
function hodlParseDirectCards(raw, targetWords = Pt) {
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
    wordSlots[wordIndex] = Ae[index];
  }
  let candidates = allPartialValid ? hodlTargetLastWords(wordSlots.join(" "), config.words)?.candidates || [] : [], finalValues = values.slice(config.partialWords * 4), finalRadices = hodlDirectCardFinalRadices(config.words), finalIndex = 0, finalValid = finalValues.length === finalRadices.length && finalValues.every((value) => value !== null);
  if (finalValid) finalValues.forEach((value, index) => finalIndex = finalIndex * finalRadices[index] + value);
  let finalWord = finalValid ? candidates[finalIndex] || "" : "", complete = entries.length === steps.length && !invalidEntries.length && !extraEntries.length && Boolean(finalWord), expectedMax = steps[Math.min(entries.length, steps.length - 1)], words = finalWord ? [...wordSlots, finalWord] : wordSlots;
  return { entries, invalidEntries, extraEntries, invalidRanges: [...invalidEntries, ...extraEntries].map((entry) => [entry.start, entry.end]), values, ranks, steps, wordSlots, words, candidates, finalWord, finalIndex, complete, expectedMax, config };
}
function hodlDirectCardsEntropy(value, targetWords = Pt) {
  let parsed = hodlParseDirectCards(value, targetWords), config = parsed.config, notes = [], warnings = [];
  if (parsed.invalidEntries.length) return { ok: false, error: `Correct the highlighted rank. This draw allows only Ace through ${parsed.invalidEntries[0].max}.`, notes, warnings, parsed };
  if (parsed.extraEntries.length) return { ok: false, error: `The ${config.words}-word seed is complete. Remove ${parsed.extraEntries.length} extra card${parsed.extraEntries.length === 1 ? "" : "s"}.`, notes, warnings, parsed };
  if (!parsed.complete) return { ok: false, error: `Enter ${parsed.steps.length - parsed.entries.length} more rank-only draw${parsed.steps.length - parsed.entries.length === 1 ? "" : "s"}.`, notes, warnings, parsed };
  let mnemonic = [...parsed.wordSlots, parsed.finalWord].join(" ");
  if (!Pn(mnemonic, Ae)) return { ok: false, error: "The direct card sequence did not produce a valid BIP39 checksum.", notes, warnings, parsed };
  let bytes = Er(mnemonic, Ae);
  notes.push(`${parsed.steps.length} independent rank-only card draws directly selected ${config.partialWords} BIP39 words and 1 of ${config.candidates} checksum-valid final words.`);
  notes.push("Every draw is made after shuffling the indicated A\u20138, A\u20134, or A\u20132 card set; suits are ignored.");
  return { ok: true, bytes, hex: M.encode(bytes), bits: config.bits, sourceBits: config.bits, method: "cards-direct", notes, warnings, parsed, mnemonic };
}
function hodlDirectCardSetLabel(max) {
  return `A\u2013${max}`;
}
function hodlDirectCardStepStatus(parsed) {
  if (parsed.complete) return `All ${parsed.steps.length} rank draws entered \xB7 checksum-valid ${parsed.config.words}-word seed ready to derive`;
  let position = Math.min(parsed.entries.length, parsed.steps.length - 1), max = parsed.steps[position], partialDraws = parsed.config.partialWords * 4;
  if (position < partialDraws) return `Word ${Math.floor(position / 4) + 1} of ${parsed.config.words} \xB7 draw ${position % 4 + 1} of 4 from ${hodlDirectCardSetLabel(max)}${position ? " after shuffling" : ""}`;
  return `Final word \xB7 draw ${position - partialDraws + 1} of ${hodlDirectCardFinalRadices(parsed.config.words).length} from ${hodlDirectCardSetLabel(max)} after shuffling`;
}
function hodlDirectCardInstruction(parsed) {
  if (parsed.complete) return "";
  return `Shuffle ${hodlDirectCardSetLabel(parsed.expectedMax)} (any suit) before the ${parsed.entries.length ? "next" : "first"} draw.`;
}
function hodlHashedCardInstruction(parsed) {
  let required = parsed.needed.first + parsed.needed.extra;
  if (parsed.cards.length >= required) return "";
  if (!parsed.cards.length) return "Shuffle a standard 52-card deck before the first draw.";
  if (parsed.needed.extra && parsed.cards.length === parsed.needed.first) return "Shuffle the full 52-card deck again before the next draw.";
  if (parsed.needed.extra && parsed.cards.length > parsed.needed.first) return "Deal the next card without replacement from the second shuffle.";
  return "Deal the next card without replacement from the shuffled deck.";
}
function hodlDealtDirectCardMarkup(rank) {
  return `<span class="dealt-card dealt-card-rank-only" title="Rank ${$t(rank)}"><span class="dealt-rank">${$t(rank)}</span></span>`;
}
function hodlUpdateDirectCards() {
  let input = document.getElementById("direct-cards");
  if (!input) return;
  let parsed = hodlParseDirectCards(input.value, Pt), invalid = parsed.invalidRanges.length > 0, showCards = document.getElementById("show-cards")?.checked === true;
  input.classList.toggle("bad", invalid);
  input.setAttribute("aria-invalid", String(invalid));
  hodlRenderInputHighlight(input, parsed.invalidRanges);
  let dealt = document.getElementById("dealt-cards");
  if (dealt) {
    dealt.hidden = !showCards;
    dealt.innerHTML = parsed.ranks.length ? `<p class="dealt-shuffle-label">Rank-only draws \xB7 ${parsed.ranks.length} of ${parsed.steps.length}</p>${parsed.ranks.map(hodlDealtDirectCardMarkup).join("")}` : `<p class="dealt-shuffle-label">Rank-only draws \xB7 No cards yet</p><span class="dealt-card dealt-card-placeholder" aria-hidden="true"></span>`;
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
  let meta = W("#cards-meta");
  meta.textContent = status;
  meta.className = "muted" + (invalid ? " err" : parsed.complete ? " ok" : "");
  document.querySelectorAll("[data-direct-card-rank]").forEach((button) => {
    button.disabled = hodlDirectCardRankValue(button.dataset.directCardRank) >= parsed.expectedMax || parsed.complete;
  });
  let undo = document.getElementById("card-undo");
  if (undo) undo.disabled = !parsed.entries.length && !String(input.value || "").trim();
  hodlQueueMasterFingerprintPreview();
}
function hodlSelectedCardsEntropy(targetWords = Pt) {
  let input = document.getElementById(hodlCardMethod === "direct" ? "direct-cards" : "cards");
  if (!input) return { ok: false, error: "Card input is unavailable." };
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
    return;
  }
  let dealt = document.getElementById("dealt-cards");
  if (dealt) {
    dealt.hidden = !showCards;
    let firstTarget = parsed.needed.first, first = parsed.cards.slice(0, firstTarget), extra2 = parsed.cards.slice(firstTarget);
    if (!parsed.cards.length) dealt.innerHTML = `<p class="dealt-shuffle-label">First shuffle \xB7 No cards yet</p><span class="dealt-card dealt-card-placeholder" aria-hidden="true"></span>`;
    else dealt.innerHTML = `<p class="dealt-shuffle-label">First shuffle \xB7 ${first.length} of ${firstTarget}</p>${first.map(hodlDealtCardMarkup).join("")}` + (config.words === 24 && first.length >= firstTarget ? `<p class="dealt-shuffle-label">Second shuffle \xB7 ${extra2.length} of ${parsed.needed.extra}</p>${extra2.map(hodlDealtCardMarkup).join("")}` : "");
  }
  let reshuffle = document.getElementById("cards-reshuffle");
  if (reshuffle) {
    let instruction = hodlHashedCardInstruction(parsed);
    reshuffle.hidden = !instruction;
    reshuffle.innerHTML = instruction ? `<strong>${instruction}</strong>` : "";
  }
  let wordsBox = document.getElementById("dice-words"), preview = [];
  try {
    if (parsed.cards.length && !parsed.invalid.length && !parsed.duplicates.length && !parsed.pending) preview = _n(Z(new TextEncoder().encode(hodlCardsHashInput(parsed.cards, hodlCardColemanSymbols))).slice(0, config.bytes)).split(" ");
  } catch {
  }
  hodlRenderDiceWordGrid(wordsBox, preview, config.words, parsed.cards.length < required);
  let meta = W("#cards-meta"), missing = Math.max(0, required - parsed.cards.length), extra = Math.max(0, parsed.cards.length - required), status = !parsed.cards.length ? `0 of ${required} recommended cards \xB7 0.0 bits estimated \xB7 Hashed card transcript` : missing ? `${parsed.cards.length} of ${required} recommended cards \xB7 ${parsed.bits.toFixed(1)} bits estimated \xB7 seed available for testing \xB7 ${missing} more recommended` : `${parsed.cards.length} card${parsed.cards.length === 1 ? "" : "s"} \xB7 ${parsed.bits.toFixed(1)} bits estimated \xB7 ready to derive${extra ? ` \xB7 all ${extra} extra card${extra === 1 ? " is" : "s are"} included` : ""}`;
  if (config.words === 24 && parsed.cards.length >= 52 && missing) status += parsed.cards.length === 52 ? ` \xB7 shuffle again, then deal 6 more` : ` \xB7 second shuffle ${parsed.cards.length - 52} of 6`;
  if (parsed.pending) status += ` \xB7 finish ${parsed.pending.token} with a suit`;
  if (parsed.invalidEntries.length - (parsed.pending ? 1 : 0) > 0) {
    let count = parsed.invalidEntries.length - (parsed.pending ? 1 : 0);
    status += ` \xB7 ${count} invalid card${count === 1 ? "" : "s"} highlighted \xB7 use As, 10h, or Td`;
  }
  if (parsed.duplicateEntries.length) status += ` \xB7 repeated ${parsed.duplicateEntries[0].card} highlighted \xB7 deal a different card`;
  let invalid = parsed.invalidRanges.length > 0;
  meta.textContent = status;
  meta.className = "muted" + (invalid ? " err" : !missing && entropy.ok ? " ok" : "");
  document.querySelectorAll("[data-card-suit]").forEach((button) => {
    let suit = button.getAttribute("data-card-suit"), active = suit === hodlCardSuit, exhausted = !selection.availableSuits.includes(suit), incompatible = Boolean(hodlCardRank) && !selection.compatibleSuits.includes(suit), locked = Boolean(hodlCardSuit) && !active;
    button.classList.toggle("active", active);
    button.setAttribute("aria-pressed", String(active));
    button.disabled = exhausted || incompatible || locked;
    button.title = exhausted ? "Every card in this suit has already been dealt in this shuffle." : incompatible ? `The ${hodlCardRank === "T" ? "10" : hodlCardRank} of this suit has already been dealt.` : locked ? "Finish the selected card using the rank row." : active ? "Suit selected. Click again to clear it, or choose an available rank." : "Select this suit first.";
  });
  document.querySelectorAll("[data-card-rank]").forEach((button) => {
    let rank = button.getAttribute("data-card-rank"), active = rank === hodlCardRank, exhausted = !selection.availableRanks.includes(rank), incompatible = Boolean(hodlCardSuit) && !selection.compatibleRanks.includes(rank), locked = Boolean(hodlCardRank) && !active;
    button.classList.toggle("active", active);
    button.setAttribute("aria-pressed", String(active));
    button.disabled = exhausted || incompatible || locked;
    button.title = exhausted ? `Every ${rank === "T" ? "10" : rank} has already been dealt in this shuffle.` : incompatible ? `The ${rank === "T" ? "10" : rank} of the selected suit has already been dealt.` : locked ? "Finish the selected card using the suit row." : active ? "Rank selected. Click again to clear it, or choose an available suit." : "Select this rank first.";
  });
  let undo = document.getElementById("card-undo");
  if (undo) undo.disabled = !parsed.cards.length && !String(input.value || "").trim();
  hodlQueueMasterFingerprintPreview();
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
  let value = hodlCardMethod === "direct" ? hodlFilterDirectCards(input.value.replace(/[^0-9A-Z]/gi, "").slice(0, -1), Pt) : input.value.trim().split(/[\s,]+/).slice(0, -1).join(" ");
  hodlSetInputValueAtEnd(input, value);
  input.dispatchEvent(new Event("input"));
}
function hodlSeedCountStatus(count, targetWords = Pt) {
  let config = hodlSeedConfig(targetWords), entered = Math.max(0, Number(count) || 0);
  return entered <= config.words ? `${entered} of ${config.words} BIP39 words entered` : `${entered} entered \xB7 ${config.words} required BIP39 words`;
}
function hodlValidateTargetMnemonic(value, targetWords = Pt) {
  let words = Rn(value).split(" ").filter(Boolean), config = hodlSeedConfig(targetWords);
  if (!words.length) return { ok: false, words, error: `${hodlSeedCountStatus(0, config.words)} \xB7 ${config.words} remaining`, unknown: [] };
  if (words.length !== config.words) {
    let difference = config.words - words.length, error = difference > 0 ? `${hodlSeedCountStatus(words.length, config.words)} \xB7 ${difference} remaining` : `${hodlSeedCountStatus(words.length, config.words)} \xB7 ${-difference} extra word${difference === -1 ? "" : "s"} must be removed`;
    return { ok: false, words, error, unknown: [] };
  }
  return Mt(words.join(" "));
}
function hodlNormalizeSeedMethod(method) {
  return method === "numbers" ? "numbers" : "words";
}
function hodlFilterSeedNumbers(value, zeroIndexed = false) {
  let clean = String(value ?? "").replace(/[^0-9\s]/g, "").replace(/\s+/g, " ");
  if (zeroIndexed) return clean;
  return clean.replace(/(^| )0+(?=\d)/g, "$1").replace(/(^| )0(?= |$)/g, "$1").replace(/ {2,}/g, " ").replace(/^ /, "");
}
function hodlParseSeedNumbers(value, targetWords = Pt, zeroIndexed = hodlSeedZeroIndexed) {
  let config = hodlSeedConfig(targetWords), text = String(value ?? ""), entries = [...text.matchAll(/\d+/g)].map((match, position) => {
    let number = Number(match[0]), index = zeroIndexed ? number : number - 1, valid = !/^0\d+/.test(match[0]) && Number.isSafeInteger(number) && index >= 0 && index < Ae.length;
    return { token: match[0], number, index, valid, position, start: match.index, end: match.index + match[0].length };
  }), invalidEntries = entries.filter((entry) => !entry.valid), extraEntries = entries.slice(config.words), wordSlots = entries.slice(0, config.words).map((entry) => entry.valid ? Ae[entry.index] : ""), phrase = wordSlots.length === config.words && wordSlots.every(Boolean) ? wordSlots.join(" ") : "", checksumInvalid = Boolean(phrase && !Pn(phrase, Ae)), invalidRanges = [...invalidEntries, ...extraEntries].map((entry) => [entry.start, entry.end]);
  if (checksumInvalid && entries[config.words - 1]) invalidRanges.push([entries[config.words - 1].start, entries[config.words - 1].end]);
  return { entries, invalidEntries, extraEntries, invalidRanges, wordSlots, phrase, checksumInvalid, complete: Boolean(phrase && !checksumInvalid && !extraEntries.length), config, zeroIndexed: Boolean(zeroIndexed), minimum: zeroIndexed ? 0 : 1, maximum: zeroIndexed ? 2047 : 2048 };
}
function hodlSeedWordsToNumbers(value, zeroIndexed = hodlSeedZeroIndexed) {
  if (hodlLooksExtendedKey(value)) return "";
  let words = Rn(value).split(" ").filter(Boolean), indices = words.map((word) => hodlBip39WordIndex.get(word));
  return words.length && indices.every((index) => Number.isInteger(index)) ? indices.map((index) => index + (zeroIndexed ? 0 : 1)).join(" ") : "";
}
function hodlSeedNumbersToWords(value, zeroIndexed = hodlSeedZeroIndexed, targetWords = Pt) {
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
function hodlSelectedSeedInput(targetWords = Pt) {
  if (hodlSeedMethod === "numbers") {
    let input = document.getElementById("seed-numbers"), parsed = hodlParseSeedNumbers(input?.value ?? "", targetWords, hodlSeedZeroIndexed);
    return { value: parsed.phrase, extended: false, parsed };
  }
  let value = document.getElementById("seed")?.value.trim() || "";
  return { value, extended: hodlLooksExtendedKey(value), parsed: null };
}
function hodlTargetLastWords(value, targetWords = Pt) {
  let words = Rn(value).split(" ").filter(Boolean), config = hodlSeedConfig(targetWords);
  if (words.length !== config.partialWords) return null;
  return hodlComputeTargetLastWords(words, config.words);
}
function hodlComputeTargetLastWords(words, targetWords = Pt) {
  let config = hodlSeedConfig(targetWords), normalized = words.map((word) => String(word ?? "").toLowerCase()), invalid = normalized.find((word) => !hodlBip39WordSet.has(word));
  if (normalized.length !== config.partialWords) return null;
  if (invalid) return { partialCount: normalized.length, completeCount: config.words, candidates: [], error: `\u201C${invalid}\u201D is not on the BIP39 English list.` };
  let cacheKey = `${config.words}:${normalized.join(" ")}`, cached = hodlLastWordCache.get(cacheKey);
  if (cached) return cached;
  let prefixBits = normalized.map((word) => hodlBip39WordIndex.get(word).toString(2).padStart(11, "0")).join(""), checksumBits = config.bits / 32, missingEntropyBits = config.bits - prefixBits.length, candidates = [];
  for (let suffix = 0; suffix < 2 ** missingEntropyBits; suffix++) {
    let entropyBits = prefixBits + suffix.toString(2).padStart(missingEntropyBits, "0"), bytes = new Uint8Array(config.bytes);
    for (let index = 0; index < bytes.length; index++) bytes[index] = Number.parseInt(entropyBits.slice(index * 8, index * 8 + 8), 2);
    let checksum = Z(bytes)[0] >> 8 - checksumBits, wordIndex = suffix * 2 ** checksumBits + checksum;
    candidates.push(Ae[wordIndex]);
  }
  let result = { partialCount: normalized.length, completeCount: config.words, candidates };
  if (hodlLastWordCache.size >= 32) hodlLastWordCache.delete(hodlLastWordCache.keys().next().value);
  hodlLastWordCache.set(cacheKey, result);
  return result;
}
function hodlSeedFinalWordContext(value, targetWords = Pt) {
  let config = hodlSeedConfig(targetWords), tokens = [...String(value ?? "").matchAll(/\S+/g)].map((match) => ({ word: match[0].toLowerCase(), start: match.index, end: match.index + match[0].length }));
  if (tokens.length < config.partialWords || tokens.length > config.words) return null;
  let baseTokens = tokens.slice(0, config.partialWords);
  if (baseTokens.some((token) => !hodlBip39WordSet.has(token.word))) return null;
  let result = hodlComputeTargetLastWords(baseTokens.map((token) => token.word), config.words);
  if (!result || result.error || result.completeCount !== config.words) return null;
  let finalToken = tokens[config.partialWords] ?? null, prefix = finalToken?.word ?? "", matchingCandidates = prefix ? result.candidates.filter((word) => word.startsWith(prefix)) : result.candidates.slice();
  return { baseWords: baseTokens.map((token) => token.word), candidates: result.candidates, finalToken, prefix, matchingCandidates, selected: result.candidates.includes(prefix) ? prefix : "", targetWords: config.words };
}
function hodlAnalyzeSeedInput(input, targetWords = Pt) {
  let value = input.value, config = hodlSeedConfig(targetWords);
  if (hodlLooksExtendedKey(value)) return { tokens: [], invalidRanges: [], invalidWords: [], excessCount: 0, checksumInvalid: false, extendedKey: true, finalContext: null };
  let tokens = [...value.matchAll(/\S+/g)].map((match) => ({ word: match[0].toLowerCase(), start: match.index, end: match.index + match[0].length })), invalidRanges = [], invalidWords = [], excessCount = 0, lastIndex = tokens.length - 1, last = tokens[lastIndex], activePrefix = Boolean(last && document.activeElement === input && !/\s$/.test(value) && input.selectionStart === input.selectionEnd && input.selectionStart === last.end);
  let finalContext = hodlSeedFinalWordContext(value, config.words);
  tokens.forEach((token, index) => {
    let listed = hodlBip39WordSet.has(token.word), options = index === config.partialWords && finalContext ? finalContext.candidates : Ae, viablePrefix = activePrefix && index === lastIndex && token.word.length > 0 && options.some((word) => word.startsWith(token.word));
    if (index >= config.words) {
      invalidRanges.push([token.start, token.end]);
      excessCount += 1;
    } else if (!listed && !viablePrefix) {
      invalidRanges.push([token.start, token.end]);
      invalidWords.push({ index, word: token.word });
    }
  });
  let checksumInvalid = false, allListed = tokens.length === config.words && tokens.every((token) => hodlBip39WordSet.has(token.word)), finalCanContinue = Boolean(activePrefix && finalContext?.prefix && finalContext.matchingCandidates.some((word) => word !== finalContext.prefix));
  if (allListed && !Pn(tokens.map((token) => token.word).join(" "), Ae) && !finalCanContinue) {
    checksumInvalid = true;
    let final = tokens[tokens.length - 1];
    invalidRanges.push([final.start, final.end]);
  }
  return { tokens, invalidRanges, invalidWords, excessCount, checksumInvalid, extendedKey: false, finalContext };
}
function hodlRenderSeedInputState(input, targetWords = Pt) {
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
      prefix = active && /^[a-z]+$/.test(token.word) && Ae.some((word) => word.startsWith(token.word));
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
        status.textContent = `${analysis.invalidRanges.length} passphrase ${analysis.invalidRanges.length === 1 ? "inconsistency" : "inconsistencies"} highlighted \xB7 use complete lowercase English BIP39 words separated by single spaces`;
        status.className = "muted passphrase-bip39-status err";
      } else if (analysis.incomplete) {
        status.textContent = `${analysis.completeWords} complete BIP39 word${analysis.completeWords === 1 ? "" : "s"} \xB7 finish the current word`;
        status.className = "muted passphrase-bip39-status";
      } else if (analysis.trailingSeparator) {
        status.textContent = `${analysis.completeWords} complete BIP39 word${analysis.completeWords === 1 ? "" : "s"} \xB7 start the next word or remove the final space`;
        status.className = "muted passphrase-bip39-status";
      } else if (input.value) {
        status.textContent = `${analysis.completeWords} lowercase BIP39 passphrase word${analysis.completeWords === 1 ? "" : "s"} entered`;
        status.className = "muted passphrase-bip39-status ok";
      } else {
        status.textContent = "Use complete lowercase English BIP39 words separated by single spaces.";
        status.className = "muted passphrase-bip39-status";
      }
    }
  }
  return analysis;
}
function hodlRenderSeedNumberInputState(input, targetWords = Pt, zeroIndexed = hodlSeedZeroIndexed) {
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
  let prefix = match[1].toLowerCase(), start = caret - match[1].length, finalContext = wholeWordlist ? null : hodlSeedFinalWordContext(input.value, Pt), isFinalPrefix = Boolean(finalContext?.finalToken && finalContext.finalToken.start === start && finalContext.finalToken.end === caret), options = isFinalPrefix ? finalContext.candidates : Ae, minimumLength = isFinalPrefix ? 1 : 2;
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
function hodlSeedKeyboardCanEnterCharacter(input, key, targetWords = Pt) {
  let character = String(key ?? "").toLowerCase();
  if (!/^[a-z]$/.test(character)) return false;
  let start = input.selectionStart ?? input.value.length, end = input.selectionEnd ?? start, value = input.value.slice(0, start) + character + input.value.slice(end), caret = start + character.length, config = hodlSeedConfig(targetWords);
  if (hodlLooksExtendedKey(value)) return false;
  let tokens = [...value.matchAll(/\S+/g)].map((match) => ({ word: match[0].toLowerCase(), start: match.index, end: match.index + match[0].length }));
  if (tokens.length > config.words) return false;
  let tokenIndex = tokens.findIndex((token2) => token2.start < caret && caret <= token2.end);
  if (tokenIndex < 0 || tokenIndex >= config.words || tokens.slice(0, tokenIndex).some((token2) => !hodlBip39WordSet.has(token2.word))) return false;
  let token = tokens[tokenIndex], options = Ae;
  if (tokenIndex === config.partialWords) {
    let context = hodlSeedFinalWordContext(value, config.words);
    if (!context) return false;
    options = context.candidates;
  }
  return options.some((word) => word.startsWith(token.word));
}
function hodlSeedKeyboardCanEnterSpace(input, targetWords = Pt) {
  let start = input.selectionStart ?? input.value.length, end = input.selectionEnd ?? start, config = hodlSeedConfig(targetWords);
  if (start !== end || end !== input.value.length || !end || /\s$/.test(input.value)) return false;
  let words = input.value.trim().toLowerCase().split(/\s+/).filter(Boolean);
  return words.length < config.words && words.every((word) => hodlBip39WordSet.has(word));
}
function hodlUpdateSeedKeyboardKeys(input, targetWords = Pt) {
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
  let analysis = hodlAnalyzeEntropyInput(input.value, "base64", Pt), definition = analysis.meta;
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
    hf(M.decode(body.toLowerCase()));
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
    let decoded = Ls(candidate);
    return decoded.network === network && Boolean(decoded.priv);
  } catch {
    return false;
  }
}
function hodlMiniPrivateKeyPrefix(value) {
  let candidate = String(value ?? "");
  if (candidate.length > 30 || !/^S[1-9A-HJ-NP-Za-km-z]*$/.test(candidate)) return false;
  if (candidate.length < 30) return true;
  return $o(candidate);
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
  if (kind === "hex-key") return "64 hexadecimal characters";
  if (kind === "minikey") return "S\u2026 (22 or 30 Base58 characters)";
  if (kind === "brain") return "Text to hash";
  return network === "testnet" ? "9\u2026 / c\u2026" : "5\u2026 / K\u2026 / L\u2026";
}
function hodlBrainWalletText(value, trim = hodlBrainWalletTrimEnabled()) {
  try {
    return hodlBrainWalletPassphrase(value, trim);
  } catch {
    return "";
  }
}
function hodlBrainHdActive() {
  if (Ne !== "key") return false;
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
function hodlBrainOutputMarkup(output = "scalar", acked = Boolean(hodlBrainLabAck)) {
  let hd = output === "hd";
  return `<div class="brain-output" id="brain-output" hidden>
    <p class="label">Brain wallet output</p>
    <div class="choice-grid">
      <label class="choice"><input type="radio" name="bo" value="scalar" ${hd ? "" : "checked"} /><span><strong>Single key pair</strong><span class="desc">The digest is the private key. One address, the original brain-wallet behaviour.</span></span></label>
      <label class="choice"><input type="radio" name="bo" value="hd" ${hd ? "checked" : ""} /><span><strong>HD wallet with seed phrase</strong><span class="desc">The digest is 256-bit BIP39 entropy for a 24-word seed. Not the same wallet as the single key pair.</span></span></label>
    </div>
    <div class="wallet-result-messages" id="brain-warning" role="alert">
      <h3>Brain wallet warning — read before first use</h3>
      <ul>
        <li class="is-warning">SHA-256(text) is unsalted and fast. Guessable phrases are stolen coins.</li>
        <li class="is-warning">Strength is the entropy of this text, nothing more.</li>
        <li class="is-warning">This is not a BIP39 passphrase.</li>
        <li class="is-warning">This is not a Bitcoin Core hdseed or address-key backup of the same wallet.</li>
        <li class="is-warning" data-brain-hd-warning ${hd ? "" : "hidden"}>The 24-word count is not the strength; the text is.</li>
        <li class="is-warning" data-brain-hd-warning ${hd ? "" : "hidden"}>A valid mnemonic does not mean it is the same wallet as hashing the text as a private-key scalar.</li>
      </ul>
    </div>
    <label class="choice"><input type="checkbox" id="brain-lab-ack" ${acked ? "checked" : ""} /><span><strong>I understand</strong><span class="desc">Required once this session, in page memory only. Derive is still required.</span></span></label>
    <div id="brain-lab-zone" ${hd ? "" : "hidden"}>
      <p class="muted" id="brain-lab-help">UTF-8 text is hashed with SHA-256. The 32-byte digest is BIP39 entropy for a 24-word seed. Nothing is derived until you press Derive Wallet.</p>
      <p class="muted" id="brain-lab-hex" aria-live="polite">SHA-256 hex appears here. 24 words appear only after Derive Wallet.</p>
    </div>
  </div>`;
}
function hodlSyncBrainOutput() {
  let zone = document.getElementById("brain-output"), input = document.getElementById("key");
  if (!zone || !input) return;
  let kind = hodlNormalizePrivateKeyKind(document.querySelector('input[name="kk"]:checked')?.value, input.value),
    brain = kind === "brain", output = hodlBrainWalletOutput(), lab = document.getElementById("brain-lab-zone");
  zone.hidden = !brain;
  if (lab) lab.hidden = output !== "hd";
  zone.querySelectorAll("[data-brain-hd-warning]").forEach((item) => {
    item.hidden = output !== "hd";
  });
  let trimControl = document.querySelector("[data-brain-wallet-trim-control]");
  if (trimControl) trimControl.hidden = !brain;
  let hex = document.getElementById("brain-lab-hex");
  if (!hex || !brain || output !== "hd") return;
  if (!hodlBrainLabAck) {
    hex.textContent = "Acknowledge the lab warning, then enter text. Derive Wallet is still required.";
    hex.className = "muted";
    return;
  }
  if (!input.value.length) {
    hex.textContent = "SHA-256 hex appears here. 24 words appear only after Derive Wallet.";
    hex.className = "muted";
    return;
  }
  let entropy = hodlBrainLabEntropy(hodlBrainWalletText(input.value));
  hex.textContent = entropy.ok ? `SHA-256 ${entropy.hex} \xB7 24 words appear only after Derive Wallet.` : entropy.error;
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
function hodlAutocompleteSeedNumberInput(input, event, targetWords = Pt, zeroIndexed = hodlSeedZeroIndexed) {
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
function hodlUpdateSeedNumberPad(input, parsed = hodlParseSeedNumbers(input?.value ?? "", Pt, hodlSeedZeroIndexed)) {
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
function hodlBindSeedKeyboard(input, targetWords = Pt) {
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
  let host = document.getElementById(Ne === "key" ? "private-keyboard-host" : "passphrase-keyboard-host"), toggleHost = document.getElementById("passphrase-keyboard-toggle-host"),
    keyMode = Ne === "key", hdBrain = hodlBrainHdActive(),
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
function hodlBitBoxRolls(value, targetWords = Pt) {
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
    words.push(mi(diceInWord, coin));
    diceInWord = [];
  }
  let waiting = words.length >= config.partialWords ? "last-word" : diceInWord.length === 5 ? "coin" : "dice", bits = words.length * 11;
  notes.push(`BitBox diceware: ${words.length} of ${config.partialWords} lookup-table words (${bits} encoded bits). Then choose the final checksum word.`);
  if (skippedHigh) notes.push(`Skipped ${skippedHigh} face${skippedHigh === 1 ? "" : "s"} of 5 or 6 on the first five dice of a word (reroll).`);
  if (extraAfter) warnings.push("Extra rolls after the final lookup-table word are ignored. The checksum word is a separate pick, not another roll.");
  if (leftover.length) warnings.push(`Ignored characters: ${JSON.stringify(leftover.slice(0, 24))}`);
  return { words, targetWords: config.words, neededPartial: config.partialWords, skippedHigh, leftover, extraAfter, waiting, diceInWord: diceInWord.length, bits, notes, warnings };
}
function hodlDicePreviewWords(value, method, targetWords = Pt) {
  let config = hodlSeedConfig(targetWords);
  if (method === "dplus") {
    let parsed2 = hodlDPlusRolls(value, targetWords);
    return [...parsed2.wordSlots, ...parsed2.finalWord ? [parsed2.finalWord] : []];
  }
  let parsed = Br(value), analysis = hodlAnalyzeDiceInput(value, method, targetWords);
  if (parsed.leftover.length || analysis.coinDerivedCount || !parsed.rolls.length) return [];
  let bytes;
  if (method === "coldcard") bytes = Z(new TextEncoder().encode(parsed.rolls.join(""))).slice(0, config.bytes);
  else if (method === "coleman") bytes = Z(new TextEncoder().encode(hodlIanColemanDiceString(parsed.rolls))).slice(0, config.bytes);
  else return [];
  try {
    return _n(bytes).split(" ");
  } catch {
    return [];
  }
}
function hodlNumberBasePreviewWords(value, format, targetWords = Pt) {
  let config = hodlSeedConfig(targetWords), analysis = hodlAnalyzeEntropyInput(value, format, config.words);
  if (!analysis.count || analysis.invalidCharacterCount || analysis.finalInvalid) return [];
  let bits = hodlNumberBaseBits(value, format, config.words).slice(0, config.bits);
  if (analysis.ready) {
    let bytes = new Uint8Array(config.bytes);
    for (let index = 0; index < bytes.length; index++) bytes[index] = Number.parseInt(bits.slice(index * 8, index * 8 + 8), 2);
    try {
      return _n(bytes).split(" ");
    } catch {
      return [];
    }
  }
  let words = [], completeGroups = Math.min(config.partialWords, Math.floor(bits.length / 11));
  for (let index = 0; index < completeGroups; index++) words.push(Ae[Number.parseInt(bits.slice(index * 11, index * 11 + 11), 2)]);
  return words;
}
function hodlBinaryPreviewWords(value, targetWords = Pt) {
  return hodlNumberBasePreviewWords(value, "bin", targetWords);
}
function hodlNumberBaseCalculationRows(value, format, targetWords = Pt) {
  let bits = hodlNumberBaseBits(value, format, targetWords), words = hodlNumberBasePreviewWords(value, format, targetWords), groups = bits.match(/.{11}/g) || [];
  if (words.length > groups.length) {
    let finalIndex = Ae.indexOf(words[groups.length]);
    if (finalIndex >= 0) groups.push(finalIndex.toString(2).padStart(11, "0"));
  }
  return groups.map((group, index) => {
    let terms = Array.from(group, (bit, bitIndex) => ({ bit, place: 2 ** (10 - bitIndex), value: bit === "1" ? 2 ** (10 - bitIndex) : 0 }));
    return { number: index + 1, terms, index: Number.parseInt(group, 2), word: words[index] || "" };
  });
}
function hodlBinaryCalculationRows(value, targetWords = Pt) {
  return hodlNumberBaseCalculationRows(value, "bin", targetWords);
}
function hodlNumberBaseBinaryConversionMarkup(value, meta) {
  if (meta.id === "bin") return "";
  let values = [...meta.alphabet].map((character, index) => `<span class="number-base-conversion-cell"><strong>${character}</strong><b>→</b><span>${index.toString(2).padStart(meta.bitsPerDigit, "0")}</span></span>`).join("");
  return `<div class="number-base-binary-conversion"><p class="label">${meta.shortLabel} digit values</p><p class="muted">Each ${meta.shortLabel} digit uses the binary value shown below before the 11-bit BIP39 calculations.</p><div class="number-base-conversion-list">${values}</div></div>`;
}
function hodlManualCalculationMarkup(method, value, targetWords = Pt) {
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
      rows.push({ number, values: [...dice, coin], stages, formula: `(((((${dice[0]} × 4 + ${dice[1]}) × 4 + ${dice[2]}) × 4 + ${dice[3]}) × 4 + ${dice[4]}) × 2 + ${coin}`, index: indexValue, word: Ae[indexValue] });
    }
  }
  if (!rows.length) return "";
  let title = method === "cards" ? "Direct card calculations" : method === "dplus" ? "D++ calculations" : "BitBox diceware calculations", note = method === "cards" ? "Ranks are mapped to zero-based values (A=0 through 8=7), then combined with radices 8, 8, 8, and 4." : method === "dplus" ? "D8 contributes 8 values and each hexadecimal D16 contributes 16 values, giving 8 × 16 × 16 = 2048 possible indices." : "Each D4 contributes one base-4 value and the final die contributes the coin bit, giving 4⁵ × 2 = 2048 possible indices.";
  return `<div class="manual-calculation-panel"><p class="label">${title}</p><p class="muted">${note}</p><div class="manual-calculation-list">${rows.map((row) => method === "dplus" || method === "cards" || method === "bitbox" ? `<div class="manual-calculation-row dplus-calculation-row"><div class="manual-calculation-heading"><span>Word ${row.number}</span><strong>${row.word || "incomplete"}</strong></div><div class="dplus-calculation-stages">${row.stages.map((stage) => `<div class="dplus-calculation-stage"><span>${stage.label}</span><strong>${stage.face}</strong><small>&rarr; ${stage.value} &times; ${stage.multiplier}</small><b>= ${stage.value * stage.multiplier}</b></div>`).join("")}</div><div class="dplus-calculation-sum"><span>${row.stages.map((stage) => stage.value * stage.multiplier).join(" + ")}</span><b>= BIP39 index ${row.index} &middot; word number ${row.index + 1}</b></div></div>` : `<div class="manual-calculation-row"><span>Word ${row.number}</span><strong>${row.word || "incomplete"}</strong><code>${row.formula}</code><b>BIP39 index ${row.index} · word number ${row.index + 1}</b></div>`).join("")}</div></div>`;
}
function hodlRenderManualCalculations(id, method, value, targetWords = Pt) {
  let panel = document.getElementById(id);
  if (!panel) return;
  let markup = hodlManualCalculationsOpen ? hodlManualCalculationMarkup(method, value, targetWords) : "";
  panel.hidden = !markup;
  panel.innerHTML = markup;
}
function hodlRenderNumberBaseCalculations(value, format = "bin", targetWords = Pt) {
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
function hodlHexPreviewWords(value, targetWords = Pt) {
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
  if (Ne === "dice") return ge === "coldcard" || ge === "coleman";
  if (Ne === "cards") return hodlCardMethod === "hashed";
  if (Ne === "key") {
    let kind = hodlNormalizePrivateKeyKind(document.querySelector('input[name="kk"]:checked')?.value || hodlKeys[hodlActiveKey]?.fields?.keyKind, "");
    return kind === "minikey" || kind === "brain";
  }
  return false;
}
function hodlGlobalSyncSourceId() {
  if (Ne === "dice") return `dice:${ge}`;
  if (Ne === "cards") return `cards:${hodlCardMethod}`;
  if (Ne === "hex") return `number:${hodlEntropyFormat}`;
  if (Ne === "seed") return `seed:${hodlSeedMethod}`;
  let kind = hodlNormalizePrivateKeyKind(document.querySelector('input[name="kk"]:checked')?.value || hodlKeys[hodlActiveKey]?.fields?.keyKind, "");
  return `key:${kind}`;
}
function hodlGlobalSyncCurrentValue() {
  let state = hodlKeys[hodlActiveKey], fields = state?.fields || {};
  if (Ne === "dice") return document.getElementById("dice")?.value ?? (ge === "dplus" ? fields.dplusDice : ge === "bitbox" ? fields.bitboxDice : fields.dice) ?? "";
  if (Ne === "cards") return document.getElementById(hodlCardMethod === "direct" ? "direct-cards" : "cards")?.value ?? fields[hodlCardMethod === "direct" ? "directCards" : "cards"] ?? "";
  if (Ne === "hex") return document.getElementById(hodlEntropyFormat)?.value ?? fields[hodlEntropyFormat] ?? "";
  if (Ne === "seed") return document.getElementById(hodlSeedMethod === "numbers" ? "seed-numbers" : "seed")?.value ?? fields[hodlSeedMethod === "numbers" ? "seedNumbers" : "seed"] ?? "";
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
function hodlGlobalSyncDPlusBits(value, targetWords = Pt) {
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
function hodlGlobalSyncDirectCardBits(value, targetWords = Pt) {
  let parsed = hodlParseDirectCards(value, targetWords), bits = "";
  for (let index = 0; index < Math.min(parsed.entries.length, parsed.steps.length); index++) {
    let value2 = parsed.values[index], width = Math.log2(parsed.steps[index]);
    if (!Number.isInteger(value2) || value2 < 0) break;
    bits += value2.toString(2).padStart(width, "0");
  }
  return bits.slice(0, parsed.config.bits);
}
function hodlGlobalSyncBitBoxBits(value, targetWords = Pt) {
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
function hodlGlobalSyncCurrentBits(targetWords = Pt) {
  let value = hodlGlobalSyncCurrentValue(), config = hodlSeedConfig(targetWords), hashed = hodlGlobalSyncIsHashedMode();
  if (!String(value).length) return "";
  try {
    if (Ne === "dice") {
      if (hashed) {
        let entropy = hodlDiceEntropy(value, ge, config.words);
        return entropy.ok ? hodlBitsFromBytes(entropy.bytes) : null;
      }
      if (ge === "dplus") {
        let parsed = hodlDPlusRolls(value, config.words);
        if (parsed.complete) return hodlBitsFromBytes(Er([...parsed.wordSlots, parsed.finalWord].join(" "), Ae));
        return hodlGlobalSyncDPlusBits(value, config.words);
      }
      let parsed = hodlBitBoxRolls(value, config.words);
      if (parsed.waiting === "last-word" && ft) {
        let mnemonic = [...parsed.words, ft].join(" ");
        if (Pn(mnemonic, Ae)) return hodlBitsFromBytes(Er(mnemonic, Ae));
      }
      return hodlGlobalSyncBitBoxBits(value, config.words);
    }
    if (Ne === "cards") {
      if (hodlCardMethod === "hashed") {
        let entropy = hodlCardsEntropy(value, config.words, hodlCardColemanSymbols);
        return entropy.ok ? hodlBitsFromBytes(entropy.bytes) : null;
      }
      let parsed = hodlParseDirectCards(value, config.words);
      if (parsed.complete) return hodlBitsFromBytes(Er([...parsed.wordSlots, parsed.finalWord].join(" "), Ae));
      return hodlGlobalSyncDirectCardBits(value, config.words);
    }
    if (Ne === "hex") {
      let analysis = hodlAnalyzeEntropyInput(value, hodlEntropyFormat, config.words);
      return analysis.invalidRanges.length ? null : hodlNumberBaseBits(value, hodlEntropyFormat, config.words);
    }
    if (Ne === "seed") {
      let words;
      if (hodlSeedMethod === "numbers") words = hodlParseSeedNumbers(value, config.words, hodlSeedZeroIndexed).wordSlots;
      else if (!hodlLooksExtendedKey(value)) {
        words = [];
        for (let word of Rn(value).split(" ").filter(Boolean)) {
          if (!hodlBip39WordSet.has(word)) break;
          words.push(word);
        }
      }
      else return null;
      let mnemonic = words.length === config.words ? words.join(" ") : "";
      if (mnemonic) return Pn(mnemonic, Ae) ? hodlBitsFromBytes(Er(mnemonic, Ae)) : null;
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
    if (kind === "wif") return hodlBitsFromBytes(Ls(value.trim()).priv);
    if (kind === "minikey") return hodlBitsFromBytes(Ns(value.trim()));
    return hodlBitsFromBytes(hodlBrainWalletPrivateKey(value, hodlBrainWalletTrimEnabled()));
  } catch {
    return null;
  }
}
function hodlGlobalSyncNumberValue(bits, format, targetWords = Pt) {
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
function hodlGlobalSyncMnemonic(bits, targetWords = Pt) {
  let config = hodlSeedConfig(targetWords), source = String(bits ?? "");
  if (source.length < config.bits) return null;
  return _n(hodlBytesFromBits(source.slice(0, config.bits)));
}
function hodlGlobalSyncWordIndices(bits, limit = Infinity) {
  let source = String(bits ?? ""), count = Math.min(limit, Math.floor(source.length / 11)), indices = [];
  for (let index = 0; index < count; index++) indices.push(Number.parseInt(source.slice(index * 11, index * 11 + 11), 2));
  return indices;
}
function hodlGlobalSyncDPlusValue(bits, targetWords = Pt) {
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
function hodlGlobalSyncDirectCardsValue(bits, targetWords = Pt) {
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
function hodlGlobalSyncBitBoxValue(bits, targetWords = Pt) {
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
  let config = hodlSeedConfig(state.targetWords), source = String(bits ?? "").slice(0, config.bits), sourceValue = String(hodlGlobalSyncCurrentValue()), fields = state.fields, privateKeys = hodlPrivateKeyValues(fields), mnemonic = hodlGlobalSyncMnemonic(source, config.words), words = mnemonic ? mnemonic.split(" ") : hodlGlobalSyncWordIndices(source, config.partialWords).map((index) => Ae[index]);
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
      hf(bytes);
      let coinType = hodlParseDerivationIndexText(fields.coinType ?? "0'")?.value ?? 0, network = hodlNetworkFromCoinType(coinType);
      privateKeys.wif = rn(bytes, true, network);
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
  return `<div class="global-sync-row"><label class="seed-autocomplete-toggle global-sync-toggle"><input type="checkbox" id="global-entropy-sync" ${state?.globalSync ? "checked" : ""} /><span><strong>Sync entropy across methods</strong> <span class="seed-autocomplete-note">(Keeps non-hashed methods synchronized. Hashed inputs update them one way and are never overwritten.)</span></span></label><span class="global-sync-status" id="global-sync-status" aria-live="polite" ${state?.globalSync && state?.globalSyncBitCount ? "" : "hidden"}>${hodlCopiedIconMarkup()}<span>${state?.globalSyncBitCount || 0} bits synced</span></span></div>`;
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
function hodlSeedPhraseCopyText(words, targetWords = Pt) {
  let needed = hodlSeedConfig(targetWords).words, source = Array.isArray(words) ? words : [], values = Array.from({ length: needed }, (_, index) => String(source[index] || "").trim()), firstMissing = values.findIndex((word) => !word);
  if (firstMissing < 0) return values.join(" ");
  if (values.slice(firstMissing + 1).some(Boolean)) return "";
  return values.slice(0, firstMissing).join(" ");
}
function hodlClipboardIconMarkup() {
  return `<svg viewBox="0 0 24 24" aria-hidden="true" focusable="false"><rect class="seed-copy-icon-clip" x="8" y="2" width="8" height="4" rx="1"/><path class="seed-copy-icon-board" d="M16 4h2a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h2"/></svg>`;
}
function hodlCopiedIconMarkup() {
  return `<svg viewBox="0 0 24 24" aria-hidden="true" focusable="false"><path class="seed-copy-icon-board" d="M20 6 9 17l-5-5"/></svg>`;
}
function hodlSeedMetaRowMarkup(metaId, live = false) {
  return `<div class="seed-word-meta"><p class="muted" id="${metaId}"${live ? ' aria-live="polite"' : ""}></p></div>`;
}
function hodlSeedCopyRowMarkup(leading = "") {
  return `<div class="seed-word-copy-row">${leading}<span class="seed-phrase-copied" aria-live="polite"></span><button type="button" class="seed-phrase-copy" data-copy-seed-phrase disabled aria-label="Copy seed phrase" title="Copy seed phrase">${hodlClipboardIconMarkup()}</button></div>`;
}
function hodlShowSeedPhraseCopied(button) {
  if (!button) return;
  let note = button.closest(".seed-word-copy-row")?.querySelector(".seed-phrase-copied");
  if (note) note.textContent = "Copied";
  button.classList.add("is-copied");
  button.innerHTML = hodlCopiedIconMarkup();
  button.setAttribute("aria-label", "Seed phrase copied");
  button.title = "Copied";
  clearTimeout(button.hodlCopiedTimer);
  button.hodlCopiedTimer = setTimeout(() => {
    if (!button.isConnected) return;
    let phrase = button.dataset.phrase;
    button.classList.remove("is-copied");
    button.innerHTML = hodlClipboardIconMarkup();
    button.setAttribute("aria-label", phrase ? "Copy seed phrase" : "Seed phrase unavailable");
    button.title = phrase ? "Copy seed phrase" : "Seed phrase unavailable";
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
function hodlRenderDiceWordGrid(container, words, targetWords = Pt, provisional = false) {
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
      copy.setAttribute("aria-label", phrase ? "Copy seed phrase" : "Seed phrase unavailable");
      copy.title = phrase ? "Copy seed phrase" : "Seed phrase unavailable";
    }
    if (!copy.hodlCopyBound) {
      copy.onclick = () => hodlCopySeedPhraseButton(copy);
      copy.hodlCopyBound = true;
    }
  }
}
function hodlUpdateEntropyInput(input, format, targetWords = Pt) {
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
    button.textContent = coinPhase && binary ? digit === "0" ? "Heads (0)" : "Tails (1)" : digit;
    button.setAttribute("aria-label", coinPhase && binary ? digit === "0" ? "Enter Heads as binary 0" : "Enter Tails as binary 1" : `Enter ${definition.shortLabel} ${digit}`);
    button.title = finalRestricted ? coinPhase ? `The remaining ${definition.remainderBits} entropy bit${definition.remainderBits === 1 ? "" : "s"} must use 0 or 1.` : `The final character must be one of ${[...definition.finalCharacters].join(", ")}.` : "";
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
  let targetWords = Number(settings.targetWords) || Pt, label = document.createElement("label"), select = document.createElement("select"), placeholderValue = "__entropylab_placeholder__";
  label.className = "field last-word-field";
  label.textContent = `Valid final word (${candidates.length} choices)`;
  select.setAttribute("aria-label", `Valid final word for ${targetWords}-word seed`);
  if (!selected) {
    let placeholder = document.createElement("option");
    placeholder.value = placeholderValue;
    placeholder.textContent = settings.placeholder || "Choose a confirmed final word";
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
  section.hidden = Ne === "key";
  section.querySelectorAll("[data-seed-words]").forEach((button) => {
    let active = Number(button.dataset.seedWords) === config.words;
    button.classList.toggle("active", active);
    button.setAttribute("aria-pressed", String(active));
  });
  let help = document.getElementById("seed-length-help");
  if (!help) return;
  if (Ne === "hex") {
    let format = hodlEntropyFormatConfig(hodlEntropyFormat, config.words);
    help.textContent = `${config.words} words require exactly ${format.digits} ${format.unit}.${format.remainderBits ? format.binaryRemainder ? ` Enter ${format.fullDigits} complete ${format.shortLabel} characters followed by ${format.remainderBits} coin flip${format.remainderBits === 1 ? "" : "s"}, using Heads (0) or Tails (1).` : ` The final character contributes ${format.remainderBits} bit${format.remainderBits === 1 ? "" : "s"} and must be one of ${[...format.finalCharacters].join(", ")}.` : ""}`;
    return;
  }
  help.textContent = Ne === "seed" ? hodlSeedMethod === "numbers" ? `Enter exactly ${config.words} BIP39 word numbers using ${hodlSeedZeroIndexed ? "0 through 2047" : "1 through 2048"}.` : `Enter exactly ${config.words} BIP39 words. Extended keys ignore this selection.` : Ne === "cards" ? hodlCardMethod === "direct" ? `${config.words} words use ${config.partialWords} complete 11-bit rank selections plus ${hodlDirectCardFinalRadices(config.words).length} final rank draw${hodlDirectCardFinalRadices(config.words).length === 1 ? "" : "s"}.` : config.words === 24 ? "24 words need 256 bits. One deck is about 225.6 bits, so deal 52 unique cards, shuffle again, then deal 6 more." : `${config.words} words need ${config.bits} bits. Deal ${hodlCardNeeded(config.words).first} unique cards from one shuffled deck.` : `${config.words} words use ${config.bits} bits of BIP39 entropy.`;
}
function hodlInvalidateActiveKeyOutput() {
  re = null;
  Ge = false;
  ft = "";
  dr.innerHTML = "";
  let error = document.getElementById("error");
  if (error) error.textContent = "";
  let state = hodlKeys[hodlActiveKey];
  if (state) {
    state.result = null;
    state.reveal = false;
    state.lastWord = "";
    state.dplusLastWord = "";
    state.error = "";
  }
}
function hodlSetSeedLength(words) {
  let config = hodlSeedLengths[Number(words)];
  if (!config) return;
  if (Pt === config.words) {
    hodlUpdateSeedLengthControl();
    hodlQueueMasterFingerprintPreview(0);
    return;
  }
  hodlCaptureKey();
  let state = hodlKeys[hodlActiveKey];
  Pt = config.words;
  hodlInvalidateActiveKeyOutput();
  if (state) {
    state.targetWords = config.words;
    state.diceMethod = ge;
    state.lastWord = "";
    state.dplusLastWord = "";
    state.result = null;
    state.reveal = false;
    state.error = "";
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
  if (Ne === "dice") {
    let dplusFaces = ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "A", "B", "C", "D", "E", "F"],
      dplusPad = dplusFaces.map(face => `<button type="button" data-d="${face}" aria-label="Hexadecimal D16 result ${face}">${face}</button>`).join("");
    let diceLabel = ge === "dplus" ? `D++ rolls (D8 1\u20138, D16 0\u2013F, D16 0\u2013F; then ${hodlDPlusFinalDescription(config.words)})` : ge === "bitbox" ? "Dice rolls (1\u20134, then a 6th die interpreted as a coin flip)" : "Dice rolls (faces 1\u20136 only)";
    let diceHelp = ge === "dplus" ? `Enter the D8 face from 1\u20138, then both hexadecimal D16 faces from 0\u2013F exactly as shown on the dice. For example, 100 selects abandon and 8FF selects zoo. ${hodlDPlusFinalHelp(config.words)}` : ge === "bitbox" ? `${config.partialWords} lookup-table words fill one slot at a time, then choose a confirmed final checksum word. Use 1\u20134 for the first five rolls (if you get 5 or 6, roll again). The sixth roll is treated as the coin: 1–3 is Heads, 4–6 is Tails. Or flip a real coin!` : ge === "coleman" ? `Every rolled 6 becomes 0 before the complete digit string is hashed with SHA-256. This Dice [1-6] method matches the method used by Keystone. Any nonempty count produces a phrase, but use at least ${config.hashRolls} fair rolls before relying on it.` : `The original dice digit string is hashed with SHA-256. This Base 10 [0-9] method matches COLDCARD and SeedSigner. Any nonempty count produces a phrase, but use at least ${config.hashRolls} fair rolls before relying on it.`;
    let dicePlaceholder = ge === "dplus" ? "100 2AF…" : ge === "bitbox" ? "111111 222224\u2026" : "415263415263\u2026";
    let dicePad = ge === "dplus" ? `<div class="dice-input-pad dplus">${dplusPad}</div>` : `<div class="dice-input-pad faces-1-6">${[1,2,3,4,5,6].map(face=>`<button type="button" data-d="${face}">${face}</button>`).join("")}</div>`;
    at.innerHTML = `
      <p class="label">How to turn rolls into a ${config.words}-word seed</p>
      <div class="choice-grid">
      <label class="choice"><input type="radio" name="dm" value="coldcard" ${ge === "coldcard" ? "checked" : ""} />
        <span><strong>Hashed rolls / Base 10 [0-9] (recommended)</strong><span class="desc">SHA-256 of the original dice digit string, matching the method used by COLDCARD and SeedSigner. The first ${config.bits} bits become the selected ${config.words}-word seed; ${config.hashRolls} rolls are recommended, and every entered roll is included.</span></span>
      </label>
      <label class="choice"><input type="radio" name="dm" value="coleman" ${ge === "coleman" ? "checked" : ""} />
        <span><strong>Hashed rolls / Dice [1-6]</strong><span class="desc">Convert each 6 to 0 and SHA-256 the complete mapped digit string, matching the method used by Keystone. Use the first ${config.bits} bits; ${config.hashRolls} rolls are recommended, and every entered roll is included.</span></span>
      </label>
      <label class="choice"><input type="radio" name="dm" value="bitbox" ${ge === "bitbox" ? "checked" : ""} />
        <span><strong>BitBox diceware / Direct word selection</strong><span class="desc">Use five dice showing 1\u20134, then a coin (or 6th die: 1\u20133 heads, 4\u20136 tails). Build ${config.partialWords} lookup-table words, then choose 1 of ${config.candidates} valid final checksum words.</span></span>
      </label>
      <label class="choice"><input type="radio" name="dm" value="dplus" ${ge==="dplus"?"checked":""} />
        <span><strong>D++ / Direct word selection</strong><span class="desc">Roll one D8 labeled 1\u20138 and two hexadecimal D16 dice labeled 0\u2013F for each of the first ${config.partialWords} words, then ${hodlDPlusFinalDescription(config.words)} to select the valid checksum final word.</span></span>
      </label>
      </div>
      <p class="label" id="dice-label">${diceLabel}</p>
      <p class="muted" id="dice-help">${diceHelp}</p>
      <div class="dice-input-shell"><pre class="dice-input-highlight" id="dice-highlight" aria-hidden="true"></pre><textarea id="dice" placeholder="${dicePlaceholder}" aria-describedby="dice-help dice-meta"></textarea></div>
      ${hodlSeedMetaRowMarkup("dice-meta", true)}
      ${dicePad}
      ${ge === "bitbox" || ge === "dplus" ? `<label class="seed-autocomplete-toggle manual-calculations-toggle"><input type="checkbox" id="show-manual-calculations" ${hodlManualCalculationsOpen ? "checked" : ""} /><span><strong>Show calculations</strong> <span class="seed-autocomplete-note">(show how direct word selection produces each BIP39 index)</span></span></label><div id="dice-manual-calculations" class="manual-calculations-container" hidden></div>` : ""}
      ${hodlSeedCopyRowMarkup(hodlDiceFairnessToggleMarkup(hodlKeys[hodlActiveKey]?.showDiceFairness))}
      <aside id="dice-fairness" class="dice-fairness" hidden role="status" aria-live="polite"></aside>
      <div id="dice-words" class="dice-word-grid" aria-label="${config.words} seed-word slots"></div><div id="last-words" class="row" style="margin-top:8px"></div>`;
    let input = document.getElementById("dice");
    input.dataset.previousValue = input.value;
    let fairnessToggle = document.getElementById("dice-fairness-toggle");
    if (fairnessToggle) fairnessToggle.onclick = () => hodlSetDiceFairnessOpen(!hodlDiceFairnessIsOpen());
    let manualToggle = document.getElementById("show-manual-calculations");
    if (manualToggle) manualToggle.onchange = () => {
      hodlManualCalculationsOpen = manualToggle.checked;
      hodlUpdateDice();
    };
    hodlBindKeypadPointer(at.querySelectorAll("[data-d]"), () => input);
    at.querySelectorAll("[data-d]").forEach((button) => {
      button.onclick = () => hodlInsertDiceControl(input, button);
    });
    input.oninput = () => {
      if (ge !== "dplus") hodlTrackDiceInputEdit(input);
      else delete input.hodlDiceBeforeInput;
      hodlSanitizeDiceInput(input);
      hodlUpdateDice();
    };
    input.onscroll = () => hodlSyncDiceHighlight(input);
    at.querySelectorAll("input[name=dm]").forEach(radio => {
      radio.onchange = () => {
        let raw = input.value, lastWord = ft, previousMethod = ge, state = hodlKeys[hodlActiveKey];
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
        ge = radio.value;
        hodlManualCalculationsOpen = false;
        if (state) {
          state.diceMethod = ge;
          ft = ge === "dplus" ? state.dplusLastWord || "" : ge === "bitbox" ? state.lastWord || "" : "";
        } else ft = previousMethod === ge ? lastWord : "";
        hodlRenderKeyForm();
        let replacement = document.getElementById("dice"), replacementValue = state ? ge === "dplus" ? state.fields.dplusDice || "" : ge === "bitbox" ? state.fields.bitboxDice || "" : state.fields.dice || "" : previousMethod === ge ? raw : "";
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
  if (Ne === "cards") {
    let state = hodlKeys[hodlActiveKey], needed = hodlCardNeeded(config.words), showCards = Boolean(state?.showCards), direct = hodlCardMethod === "direct";
    if (!direct) hodlCardSuit = hodlCardRank = "";
    let suitPad = hodlCardSuits.map((suit) => `<button type="button" class="card-suit${suit.red ? " is-red" : ""}" data-card-suit="${suit.code}" aria-label="${suit.label}" aria-pressed="false">${suit.symbol}</button>`).join("");
    let rankPad = direct ? hodlDirectCardRanks.map((rank) => `<button type="button" data-direct-card-rank="${rank}" aria-label="Enter rank ${rank}">${rank}</button>`).join("") : hodlCardRanks.map((rank) => `<button type="button" data-card-rank="${rank}" aria-label="${rank === "T" ? "10" : rank}">${rank === "T" ? "10" : rank}</button>`).join("");
    let inputId = direct ? "direct-cards" : "cards", inputLabel = direct ? "Rank-only draw transcript" : "Card transcript", inputHelp = direct ? `For each of the first ${config.partialWords} words, shuffle and draw from A\u20138 three times, then A\u20134 once. Each four-character group selects one word; spaces separate the groups. The shorter final group supplies the remaining entropy bits, and EntropyLab calculates the BIP39 checksum bits.` : `Each valid card updates a deterministic test seed. For real security, ${config.words === 24 ? "deal all 52 unique cards, shuffle again, then deal 6 more" : `deal ${needed.first} unique cards without putting them back`}. SHA-256 hashes the ASCII transcript (As 2c Td).`, placeholder = direct ? "A284 37A2 \u2026" : hodlCardColemanSymbols ? "A\u2660 2\u2663 T\u2665 T\u2666\u2026" : "As 2c Th Td\u2026";
    at.innerHTML = `
      <p class="label">How to turn cards into a ${config.words}-word seed</p>
      <div class="choice-grid">
        <label class="choice"><input type="radio" name="card-method" value="hashed" ${direct ? "" : "checked"} /><span><strong>Hashed card transcript</strong><span class="desc">Deal unique rank-and-suit cards without replacement. SHA-256 hashes the complete transcript; ${config.words === 24 ? "58 cards across two shuffles are recommended" : `${needed.first} cards are recommended`}.</span></span></label>
        <label class="choice"><input type="radio" name="card-method" value="direct" ${direct ? "checked" : ""} /><span><strong>Direct word selection</strong><span class="desc">Ignore suits. Reshuffle and draw A\u20138, A\u20138, A\u20138, then A\u20134 for each full word. Finish with the shorter rank sequence shown for the checksum-valid final word.</span></span></label>
      </div>
      <p class="muted" id="cards-help">${inputHelp}</p>
      ${direct ? "" : `<label class="seed-autocomplete-toggle seed-zero-index-toggle"><input type="checkbox" id="cards-ian-coleman" ${hodlCardColemanSymbols ? "checked" : ""} /><span><strong>Match Ian Coleman method</strong> <span class="seed-autocomplete-note">(show and hash A\u2660 2\u2663 instead of As 2c)</span></span></label>`}
      <label class="field" id="cards-input-label" for="${inputId}">${inputLabel}</label>
      <div class="dice-input-shell cards-input-shell"><pre class="dice-input-highlight" id="cards-highlight" aria-hidden="true"></pre><textarea id="${inputId}" placeholder="${placeholder}" autocomplete="off" spellcheck="false" autocapitalize="off" aria-labelledby="cards-input-label" aria-describedby="cards-help cards-meta"></textarea></div>
      ${hodlSeedMetaRowMarkup("cards-meta")}
      ${direct ? "" : `<div class="card-suit-pad" role="group" aria-label="Suit">${suitPad}</div>`}
      <div class="card-rank-pad dice-input-pad${direct ? " direct-card-rank-pad" : ""}" role="group" aria-label="${direct ? "Rank-only draw" : "Rank"}">${rankPad}</div>
      <div class="card-controls-row"><button class="card-undo-button seed-keyboard-delete" id="card-undo" type="button" aria-label="Undo last card" title="Undo last card" disabled><svg viewBox="0 0 24 18" aria-hidden="true" focusable="false"><path d="M9 2h11a2 2 0 0 1 2 2v10a2 2 0 0 1-2 2H9L2 9l7-7Z"/><path d="m12 6 6 6m0-6-6 6"/></svg></button><label class="seed-autocomplete-toggle card-visibility-toggle"><input type="checkbox" id="show-cards" aria-controls="dealt-cards" ${showCards ? "checked" : ""} /><span>Show cards</span></label></div>
      <aside class="cards-reshuffle" id="cards-reshuffle" hidden></aside>
      <div class="dealt-cards" id="dealt-cards" aria-live="polite"${showCards ? "" : " hidden"}></div>
      ${direct ? `<label class="seed-autocomplete-toggle manual-calculations-toggle"><input type="checkbox" id="show-manual-calculations" ${hodlManualCalculationsOpen ? "checked" : ""} /><span><strong>Show calculations</strong> <span class="seed-autocomplete-note">(show how direct card selection produces each BIP39 index)</span></span></label><div id="cards-manual-calculations" class="manual-calculations-container" hidden></div>` : ""}
      ${hodlSeedCopyRowMarkup()}
      <div id="dice-words" class="dice-word-grid" aria-label="${config.words} seed-word slots"></div>
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
    at.querySelectorAll('input[name="card-method"]').forEach((radio) => {
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
    at.querySelectorAll("[data-card-suit]").forEach((button) => {
      button.onclick = () => {
        hodlCardSuit = hodlToggleCardChoice(hodlCardSuit, button.getAttribute("data-card-suit"));
        hodlUpdateCards();
      };
    });
    at.querySelectorAll("[data-card-rank]").forEach((button) => {
      button.onclick = () => {
        hodlCardRank = hodlToggleCardChoice(hodlCardRank, button.getAttribute("data-card-rank"));
        hodlUpdateCards();
      };
    });
    hodlBindKeypadPointer(at.querySelectorAll("[data-direct-card-rank], #card-undo"), () => input);
    at.querySelectorAll("[data-direct-card-rank]").forEach((button) => {
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
  if (Ne === "hex") {
    let state = hodlKeys[hodlActiveKey], format = hodlEntropyFormatConfig(hodlEntropyFormat, config.words), inputId = format.id;
    let descriptions = { bin: "Use one 0 or 1 for each coin flip.", base4: "Each digit contributes exactly two bits; useful with a fair four-sided source.", base8: "Each octal digit contributes three bits.", hex: "Each hexadecimal character contributes four bits.", base32: "Uses the unambiguous Crockford alphabet, then switches to coin flips for any remaining bits; O becomes 0 and I or L becomes 1.", base64: "Uses the case-sensitive RFC 4648 alphabet with + and /, then switches to coin flips for any remaining bits." };
    let formatChoices = ["bin", "base4", "base8", "hex", "base32", "base64"].map((id) => {
      let option = hodlEntropyFormats[id];
      return `<label class="choice"><input type="radio" name="entropy-format" value="${id}" ${format.id === id ? "checked" : ""} /><span><strong>${option.label}</strong><span class="desc">${descriptions[id]}</span></span></label>`;
    }).join("");
    let entropyPad = format.id === "base64" ? "" : `<div class="dice-input-pad entropy-keypad entropy-keypad-${format.id}" role="group" aria-label="${format.label} keypad">${[...format.alphabet].map((character) => `<button type="button"${format.id === "bin" ? ' class="coin-button"' : ""} data-entropy-digit="${character}" aria-label="${format.id === "bin" ? character === "0" ? "Enter Heads as binary 0" : "Enter Tails as binary 1" : `Enter ${format.shortLabel} ${character}`}">${format.id === "bin" ? character === "0" ? "Heads (0)" : "Tails (1)" : character}</button>`).join("")}</div>`;
    let remainderHelp = format.remainderBits ? format.binaryRemainder ? ` Enter ${format.fullDigits} complete ${format.shortLabel} characters; the controls and progress message then switch to ${format.remainderBits} coin flip${format.remainderBits === 1 ? "" : "s"}, using Heads (0) or Tails (1).` : ` The final character is mixed-radix: it contributes only ${format.remainderBits} bit${format.remainderBits === 1 ? "" : "s"} and must be one of ${[...format.finalCharacters].join(", ")}.` : "", base64Tools = format.id === "base64" ? `<div class="seed-entry-tools base64-entry-tools">${hodlBase64KeyboardToggleMarkup()}</div>` : "", base64Keyboard = format.id === "base64" ? hodlBase64KeyboardMarkup() : "";
    at.innerHTML = `
      <p class="label">Number base</p>
      <div class="choice-grid entropy-format-grid">${formatChoices}</div>
      ${["bin", "base4", "base8", "hex"].includes(format.id) ? `<label class="seed-autocomplete-toggle number-base-calculations-toggle"><input type="checkbox" id="show-number-base-calculations" ${state?.showNumberBaseCalculations ? "checked" : ""} /><span><strong>Show calculations</strong> <span class="seed-autocomplete-note">(show how each BIP39 word number is calculated)</span></span></label>` : ""}
      <p class="label" id="entropy-input-label">${format.label} entropy for a ${config.words}-word seed</p>
      <p class="muted" id="entropy-input-help">Each complete ${format.shortLabel} character contributes ${format.bitsPerDigit} bit${format.bitsPerDigit === 1 ? "" : "s"}${format.binaryRemainder ? "" : " except for a mixed-radix final character when needed"}. Seed-word cards fill as enough bits arrive; the checksum-derived final word appears when all ${format.digits} characters are entered.${format.id === "bin" ? " Spaces are added every 11 bits." : ""}${remainderHelp} No generator \u2014 enter entropy you already created.</p>
      ${base64Tools}
      <div class="dice-input-shell entropy-input-shell"><pre class="dice-input-highlight" id="entropy-input-highlight" aria-hidden="true"></pre><textarea id="${inputId}" placeholder="Exactly ${format.digits} ${format.unit}" aria-labelledby="entropy-input-label" aria-describedby="entropy-input-help entropy-meta" autocomplete="off" spellcheck="false" autocapitalize="${format.id === "base64" ? "off" : format.base > 10 ? "characters" : "off"}"></textarea></div>
      ${hodlSeedMetaRowMarkup("entropy-meta", true)}
      ${base64Keyboard}
      ${entropyPad}
      <div id="number-base-calculations" class="number-base-calculations-panel" hidden></div>
      ${hodlSeedCopyRowMarkup()}
      <div id="entropy-words" class="dice-word-grid" aria-label="${config.words} seed-word slots"></div>`;
    at.querySelectorAll('input[name="entropy-format"]').forEach((radio) => {
      radio.onchange = () => {
        let state2 = hodlKeys[hodlActiveKey], previous = document.getElementById(hodlEntropyFormat);
        if (state2 && previous) state2.fields[hodlEntropyFormat] = previous.value;
        hodlEntropyFormat = hodlNormalizeEntropyFormat(radio.value);
        if (state2) state2.entropyFormat = hodlEntropyFormat;
        hodlInvalidateLiveKeyResult();
        let error = document.getElementById("error");
        if (error) error.textContent = "";
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
      hodlBindKeypadPointer(at.querySelectorAll("[data-entropy-digit]"), () => entropyInput);
      at.querySelectorAll("[data-entropy-digit]").forEach((button) => {
        button.onclick = () => hodlInsertEntropyControl(entropyInput, button);
      });
      if (format.id === "base64") hodlBindBase64Keyboard(entropyInput);
    }
    hodlRenderPassphraseKeyboard();
    return;
  }
  if (Ne === "seed") {
    let state = hodlKeys[hodlActiveKey], autocompleteEnabled = Boolean(state?.seedAutocomplete), numbers = hodlSeedMethod === "numbers", choices = `<p class="label">How to enter a seed phrase</p><div class="choice-grid seed-method-grid"><label class="choice"><input type="radio" name="seed-method" value="words" ${numbers ? "" : "checked"} /><span><strong>Direct word entry</strong><span class="desc">Type or paste the English BIP39 words themselves.</span></span></label><label class="choice"><input type="radio" name="seed-method" value="numbers" ${numbers ? "checked" : ""} /><span><strong>BIP39 word numbers</strong><span class="desc">Enter each word's position in the standard English list, using 1 through 2048 by default.</span></span></label></div>`;
    let bindMethodChoices = (input) => at.querySelectorAll('input[name="seed-method"]').forEach((radio) => {
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
      let range = hodlSeedZeroIndexed ? "0 through 2047" : "1 through 2048";
      at.innerHTML = `${choices}<p class="label" id="seed-number-label">Your ${config.words} BIP39 word numbers</p><p class="muted" id="seed-number-help">Enter one ${range} number for each word, separated by spaces. The corresponding BIP39 words appear below.</p><label class="seed-autocomplete-toggle seed-zero-index-toggle"><input type="checkbox" id="seed-zero-index" ${hodlSeedZeroIndexed ? "checked" : ""} /><span><strong>Use zero-indexed word numbers</strong> <span class="seed-autocomplete-note">(0–2047 instead of the default 1–2048)</span></span></label><div class="dice-input-shell seed-number-input-shell"><pre class="dice-input-highlight" id="seed-number-highlight" aria-hidden="true"></pre><textarea id="seed-numbers" inputmode="numeric" placeholder="${hodlSeedZeroIndexed ? "0 1 2" : "1 2 3"} …" aria-labelledby="seed-number-label" aria-describedby="seed-number-help seed-number-meta" autocomplete="off" spellcheck="false"></textarea></div>${hodlSeedMetaRowMarkup("seed-number-meta", true)}<div class="dice-input-pad seed-number-pad" role="group" aria-label="BIP39 word number keypad">${[0, 1, 2, 3, 4, 5, 6, 7, 8, 9].map((digit) => `<button type="button" data-seed-number-digit="${digit}" aria-label="Enter ${digit}">${digit}</button>`).join("")}<button type="button" class="seed-keyboard-delete seed-number-delete" data-seed-number-delete aria-label="Delete previous digit"><svg viewBox="0 0 24 18" aria-hidden="true" focusable="false"><path d="M9 2h11a2 2 0 0 1 2 2v10a2 2 0 0 1-2 2H9L2 9l7-7Z"/><path d="m12 6 6 6m0-6-6 6"/></svg></button><button type="button" class="seed-number-next" data-seed-number-space>Next word</button></div>${hodlSeedCopyRowMarkup()}<div id="seed-number-words" class="dice-word-grid" aria-label="${config.words} seed-word slots"></div>`;
      let input = document.getElementById("seed-numbers"), update = () => {
        let parsed = hodlRenderSeedNumberInputState(input, config.words, hodlSeedZeroIndexed), meta = W("#seed-number-meta"), entered = parsed.entries.length, progress = `${entered} of ${config.words} BIP39 word numbers entered`, remaining = Math.max(0, config.words - entered);
        hodlRenderDiceWordGrid(document.getElementById("seed-number-words"), parsed.wordSlots, config.words, false);
        if (parsed.extraEntries.length) {
          meta.textContent = `${entered} entered · ${config.words} required · ${parsed.extraEntries.length} extra highlighted · remove to continue`;
          meta.className = "muted err";
        } else if (parsed.invalidEntries.length) {
          let invalid = parsed.invalidEntries[0];
          meta.textContent = `${progress} · Word ${invalid.position + 1} number “${invalid.token}” is outside ${parsed.minimum}–${parsed.maximum} · correct to continue`;
          meta.className = "muted err";
        } else if (parsed.checksumInvalid) {
          meta.textContent = `${progress} · BIP39 checksum invalid · final word number highlighted`;
          meta.className = "muted err";
        } else if (parsed.complete) {
          meta.textContent = `${progress} · checksum valid · ready to derive`;
          meta.className = "muted ok";
        } else {
          meta.textContent = `${progress} · ${remaining} remaining · valid range ${parsed.minimum}–${parsed.maximum}`;
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
        document.getElementById("seed-number-help").textContent = `Enter one ${hodlSeedZeroIndexed ? "0 through 2047" : "1 through 2048"} number for each word, separated by spaces. The corresponding BIP39 words appear below.`;
        input.placeholder = `${hodlSeedZeroIndexed ? "0 1 2" : "1 2 3"} …`;
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
    at.innerHTML = `${choices}<p class="label">Your ${config.words}-word seed phrase</p><p class="muted" id="seed-help">Enter exactly ${config.words} English BIP39 words. You can also paste an extended key here; the selected phrase length does not apply to extended keys. With ${config.partialWords} compatible diceware words, choose the final checksum word below.</p><div class="seed-entry-tools">${hodlSeedKeyboardToggleMarkup()}<label class="seed-autocomplete-toggle"><input type="checkbox" id="seed-autocomplete" ${autocompleteEnabled ? "checked" : ""} /><span>Autocomplete BIP39 words</span></label></div><div class="dice-input-shell seed-input-shell"><pre class="dice-input-highlight" id="seed-highlight" aria-hidden="true"></pre><textarea id="seed" placeholder="Enter exactly ${config.words} BIP39 words" aria-describedby="seed-help seed-meta" autocomplete="off" spellcheck="false" autocapitalize="off"></textarea></div><p class="muted" id="seed-meta" aria-live="polite"></p>${hodlSeedKeyboardMarkup()}<div id="last-words" class="row" style="margin-top:8px"></div>`;
    let input = document.getElementById("seed"), update = () => {
      let rawValue = input.value, value = rawValue.trim(), meta = W("#seed-meta"), picker = W("#last-words"), analysis = hodlRenderSeedInputState(input, config.words);
      if (hodlLooksExtendedKey(value)) {
        let status = hodlSinglesigImportStatus(value, hodlSelectedKeyNetwork());
        picker.innerHTML = "";
        meta.textContent = status.message;
        meta.className = "muted " + (status.ok ? status.warning ? "err" : "ok" : "err");
        return;
      }
      let finalContext = analysis.finalContext, validation = hodlValidateTargetMnemonic(value, config.words), entered = analysis.tokens.length, progress = hodlSeedCountStatus(entered, config.words), remaining = Math.max(0, config.words - entered);
      if (finalContext) {
        hodlRenderLastWordPicker(picker, finalContext.candidates, finalContext.selected, (word) => hodlReplaceSeedFinalWord(input, finalContext, word), { forceSelect: true, targetWords: config.words, placeholder: `Choose ${config.words === 18 ? "an" : "a"} ${config.words}th word` });
        if (!finalContext.finalToken) {
          meta.textContent = `${progress} \xB7 choose the final checksum word \xB7 ${finalContext.candidates.length} valid choices`;
          meta.className = "muted ok";
          return;
        }
        if (validation.ok) {
          meta.textContent = `${progress} \xB7 checksum valid \xB7 ready to derive`;
          meta.className = "muted ok";
          return;
        }
        if (!finalContext.matchingCandidates.length) {
          meta.textContent = `${progress} \xB7 No valid checksum word starts with "${finalContext.prefix.length > 24 ? finalContext.prefix.slice(0, 24) + "…" : finalContext.prefix}".`;
          meta.className = "muted err";
          return;
        }
        meta.textContent = `${progress} \xB7 ${finalContext.matchingCandidates.length} valid checksum word${finalContext.matchingCandidates.length === 1 ? "" : "s"} start${finalContext.matchingCandidates.length === 1 ? "s" : ""} with "${finalContext.prefix}".`;
        meta.className = "muted";
        return;
      }
      picker.innerHTML = "";
      let invalidWord = analysis.invalidWords[0];
      if (analysis.excessCount) {
        meta.textContent = `${entered} entered \xB7 ${config.words} required BIP39 words \xB7 ${analysis.excessCount} extra highlighted \xB7 remove to continue`;
        meta.className = "muted err";
        return;
      }
      if (invalidWord) {
        meta.textContent = `${progress} \xB7 Word ${invalidWord.index + 1} (\u201C${invalidWord.word}\u201D) is not on the BIP39 English list \xB7 correct to continue`;
        meta.className = "muted err";
        return;
      }
      if (validation.ok) {
        meta.textContent = `${progress} \xB7 checksum valid \xB7 ready to derive`;
        meta.className = "muted ok";
        return;
      }
      meta.textContent = `${progress} \xB7 ${remaining} remaining`;
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
  at.innerHTML = `
    <p class="label">Private key format</p>
    <div class="choice-grid">
    <label class="choice"><input type="radio" name="kk" value="wif" checked /><span><strong>WIF</strong><span class="desc">Bitcoin wallet import format (Base58Check).</span></span></label>
    <label class="choice"><input type="radio" name="kk" value="hex-key" /><span><strong>Private key hex</strong><span class="desc">Raw 32-byte private key as 64 hexadecimal characters.</span></span></label>
    <label class="choice"><input type="radio" name="kk" value="minikey" /><span><strong>Mini key</strong><span class="desc">Casascius-style short key.</span></span></label>
    <label class="choice"><input type="radio" name="kk" value="brain" /><span><strong>Brain wallet</strong><span class="desc">Unsafe. SHA-256 of your text, as a single key pair or a 24-word seed.</span></span></label>
    </div>
    ${hodlBrainOutputMarkup(hodlKeys[hodlActiveKey]?.brainWalletOutput || "scalar")}
    <p class="label" id="private-key-input-label">Private key or recovery passphrase</p>
    <p class="muted" id="private-key-input-help">Enter the value matching the selected format. Brain wallet text is hashed with SHA-256.</p>
    ${hodlPrivateKeyKeyboardToggleMarkup()}
    <div class="dice-input-shell private-key-input-shell"><pre class="dice-input-highlight" id="private-key-highlight" aria-hidden="true"></pre><textarea id="key" placeholder="5\u2026 / K\u2026 / L\u2026" aria-labelledby="private-key-input-label" aria-describedby="private-key-input-help private-key-meta"></textarea></div><p class="muted" id="private-key-meta" aria-live="polite"></p><div class="passphrase-keyboard-host" id="private-keyboard-host" hidden></div>`;
  hodlBindKeyFields();
  hodlRenderPassphraseKeyboard();
}
function hodlUpdateDice() {
  let input = document.getElementById("dice");
  if (!input) return;
  let wordsBox = document.getElementById("dice-words"), picker = document.getElementById("last-words"), config = hodlSeedConfig(), inputState = hodlRenderDiceInputState(input), invalidStatus = inputState.invalidCount ? ` \xB7 ${inputState.invalidCount} invalid input${inputState.invalidCount === 1 ? "" : "s"} highlighted` : "";
  if (ge !== "bitbox" && inputState.coinDerivedCount) invalidStatus += ` \xB7 coin-button digits are BitBox-only`;
  if (ge === "dplus") {
    let result = inputState.dplus || hodlDPlusRolls(input.value, config.words),
      status = "",
      selectingFinal = result.waiting === "last-word",
      d16Range = "0\u2013F";
    if (ft && (!selectingFinal || !result.candidates.includes(ft))) {
      ft = "";
      let state = hodlKeys[hodlActiveKey];
      if (state) state.dplusLastWord = "";
    }
    let selectedFinal = selectingFinal ? ft : "",
      complete = result.complete || Boolean(selectedFinal);
    let rollPhrase = "",
      rollRange = "",
      groupsEntered = `Group ${result.completedGroups} of ${config.partialWords} \xB7 word ${result.activeGroupIndex+1}`,
      rollsComplete = `${config.partialWords} of ${config.partialWords} word rolls complete`;
    if (result.waiting === "d8") {
      status = groupsEntered;
      rollPhrase = "D8 roll";
      rollRange = " (1\u20138)"
    } else if (result.waiting === "d16-first") {
      status = groupsEntered;
      rollPhrase = "first D16 roll";
      rollRange = ` (${d16Range})`
    } else if (result.waiting === "d16-second") {
      status = groupsEntered;
      rollPhrase = "second D16 roll";
      rollRange = ` (${d16Range})`
    } else if (result.waiting === "correction") {
      let invalid = result.firstInvalid,
        specSteps = hodlDPlusFinalSteps(config.words),
        position = invalid?.final ? hodlDPlusStepChecksumLabel(specSteps[invalid.position]) : `word ${(invalid?.groupIndex??0)+1}'s ${invalid?.position===0?"D8":invalid?.position===1?"first D16":"second D16"} roll`;
      status = `Group ${result.completedGroups} of ${config.partialWords} \xB7 correct ${result.invalidRequiredCount} highlighted invalid result${result.invalidRequiredCount===1?"":"s"}, starting with ${position}`
    } else if (selectingFinal) status = selectedFinal ? `${config.words} of ${config.words} seed words \xB7 checksum valid \xB7 ready to derive` : `${rollsComplete} \xB7 choose the final checksum word`;
    else if (result.waiting === "checksum-d8") {
      status = rollsComplete;
      rollPhrase = "final D8 checksum roll";
      rollRange = " (1\u20138)"
    } else if (result.waiting === "checksum-d16") {
      status = rollsComplete;
      rollPhrase = "final D16 checksum roll";
      rollRange = ` (${d16Range})`
    } else if (result.waiting === "checksum-coin") {
      status = rollsComplete;
      rollPhrase = "final D8 as a coin flip";
      rollRange = " (1\u20134 Heads, 5\u20138 Tails)"
    } else status = `${config.words} of ${config.words} seed words \xB7 checksum valid \xB7 ready to derive`;
    let statusTail = result.extraAfter ? ` \xB7 ${result.extraAfter} extra input${result.extraAfter===1?"":"s"} ignored` : "";
    let displayWords = result.wordSlots.slice();
    if (result.finalWord) displayWords.push(result.finalWord);
    else if (selectedFinal) displayWords.push(selectedFinal);
    hodlRenderDiceWordGrid(wordsBox, displayWords, config.words, false);
    hodlRenderManualCalculations("dice-manual-calculations", "dplus", input.value, config.words);
    hodlRenderLastWordPicker(picker, selectingFinal ? result.candidates : [], selectedFinal, (word) => {
      ft = word;
      let state = hodlKeys[hodlActiveKey];
      if (state) state.dplusLastWord = ft;
      hodlUpdateDice();
    }, { forceSelect: true, targetWords: config.words, placeholder: `Choose ${config.words === 18 ? "an" : "a"} ${config.words}th word` });
    let meta = W("#dice-meta");
    meta.replaceChildren(document.createTextNode(status));
    // The next roll is the one thing to act on, so it carries the weight.
    if (rollPhrase) {
      let emphasis = document.createElement("strong");
      emphasis.textContent = rollPhrase;
      meta.append(document.createTextNode(" \xB7 "), emphasis, document.createTextNode(rollRange))
    }
    meta.append(document.createTextNode(statusTail + invalidStatus));
    meta.className = "muted" + (complete && !result.invalidCount ? " ok" : result.invalidCount ? " err" : "");
    hodlRenderDiceFairness(input.value, ge, config.words);
    hodlQueueMasterFingerprintPreview();
    return;
  }
  if (ge === "bitbox") {
    let result = hodlBitBoxRolls(input.value, config.words), status = result.waiting === "last-word" ? `${result.words.length} words \xB7 choose the final checksum word` : result.waiting === "coin" ? `Word ${result.words.length + 1} of ${result.neededPartial} \xB7 6th die (interpreted as a coin flip)` : `Word ${result.words.length + 1} of ${result.neededPartial} \xB7 die ${result.diceInWord + 1} of 5 (faces 1\u20134)`;
    if (result.extraAfter) status += ` \xB7 ${result.extraAfter} extra input${result.extraAfter === 1 ? "" : "s"} ignored`;
    let last = result.waiting === "last-word" ? hodlTargetLastWords(result.words.join(" "), config.words) : null;
    if (last && !last.error && !last.candidates.includes(ft)) ft = "";
    if (!last || last.error) ft = "";
    let displayWords = result.words.slice();
    if (result.waiting === "last-word" && last && !last.error && ft) displayWords.push(ft);
    W("#dice-meta").textContent = status + invalidStatus;
    hodlRenderDiceWordGrid(wordsBox, displayWords, config.words, false);
    hodlRenderManualCalculations("dice-manual-calculations", "bitbox", input.value, config.words);
    hodlRenderLastWordPicker(picker, last && !last.error ? last.candidates : [], ft, (word) => {
      ft = word;
      let state = hodlKeys[hodlActiveKey];
      if (state) state.lastWord = ft;
      hodlUpdateDice();
    }, { forceSelect: true, targetWords: config.words, placeholder: `Choose ${config.words === 18 ? "an" : "a"} ${config.words}th word` });
    hodlRenderDiceFairness(input.value, ge, config.words);
    hodlQueueMasterFingerprintPreview();
    return;
  }
  if (picker) picker.innerHTML = "";
  let rolls = inputState.acceptedRolls, words = hodlDicePreviewWords(input.value, ge, config.words);
  let missing = Math.max(0, config.hashRolls - rolls.length), provisional = rolls.length > 0 && missing > 0, extra = Math.max(0, rolls.length - config.hashRolls), methodLabel = ge === "coleman" ? "Hashed rolls / Dice [1-6]" : "Hashed rolls / Base 10 [0-9]";
  hodlRenderDiceWordGrid(wordsBox, words, config.words, provisional);
  W("#dice-meta").textContent = (!rolls.length ? `0 of ${config.hashRolls} recommended rolls \xB7 0.0 bits estimated \xB7 ${methodLabel}` : missing ? `${rolls.length} of ${config.hashRolls} recommended rolls \xB7 ${kr(rolls.length).toFixed(1)} bits estimated \xB7 seed available for testing \xB7 ${missing} more recommended` : `${rolls.length} roll${rolls.length === 1 ? "" : "s"} \xB7 ${kr(rolls.length).toFixed(1)} bits estimated \xB7 ready to derive${extra ? ` \xB7 all ${extra} extra roll${extra === 1 ? " is" : "s are"} included` : ""}`) + invalidStatus;
  hodlRenderDiceFairness(input.value, ge, config.words);
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
    dice.setAttribute("inputmode", ge === "dplus" ? "text" : "numeric");
    dice.setAttribute("autocapitalize", ge === "dplus" ? "characters" : "off");
    dice.setAttribute("autocomplete", "off");
    dice.setAttribute("spellcheck", "false");
    dice.onbeforeinput = (event) => {
      if (ge === "dplus") hodlHandleGroupedSeparatorDelete(dice, event);
      else hodlRememberDiceBeforeInput(dice, event);
    };
  }
  let format = hodlNormalizeEntropyFormat(hodlEntropyFormat), entropy = document.getElementById(format);
  if (entropy) {
    let definition = hodlEntropyFormats[format], update = () => {
      hodlApplyFilteredInput(entropy, (value) => hodlFilterNumberBase(value, format));
      if (format === "bin") hodlFormatBinaryInput(entropy);
      hodlUpdateEntropyInput(entropy, format, Pt);
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
      refreshBrain();
    }));
    let ack = document.getElementById("brain-lab-ack");
    if (ack) ack.onchange = () => {
      hodlBrainLabAck = ack.checked;
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
function hodlSelectedEntropy(targetWords = Pt) {
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
    if (Ne !== "key") {
      derivationPlan = hodlReadDerivationPlan();
      hodlReadBranchWindow();
      hodlReadAddressWindow();
      let passphrase = document.getElementById("pass");
      if (hodlPassphraseBip39Enabled() && passphrase?.value) {
        let passphraseAnalysis = hodlAnalyzeBip39Passphrase(passphrase.value);
        if (passphraseAnalysis.invalidRanges.length || passphraseAnalysis.incomplete || passphraseAnalysis.trailingSeparator) return false;
      }
    } else hodlReadCoinType(document.getElementById("network"));
    if (Ne === "dice") {
      let input = document.getElementById("dice");
      if (!input) return false;
      let analysis = hodlAnalyzeDiceInput(input.value, ge, Pt);
      if (analysis.invalidCount || analysis.coinDerivedCount) return false;
      if (ge === "dplus") {
        let rollsFinalWord = !0,
          parsed = analysis.dplus || hodlDPlusRolls(input.value, Pt),
          finalWord = rollsFinalWord ? parsed.finalWord : ft;
        if (rollsFinalWord) {
          if (!parsed.complete) return !1
        } else if (!parsed.allRolledValid || parsed.waiting !== "last-word" || !parsed.candidates.includes(finalWord)) return !1;
        return hodlValidateTargetMnemonic([...parsed.wordSlots, finalWord].join(" "), Pt).ok
      }
      if (ge === "bitbox") {
        let parsed = hodlBitBoxRolls(input.value, Pt);
        if (parsed.leftover || parsed.extraAfter || parsed.waiting !== "last-word" || !ft) return false;
        let possible = hodlTargetLastWords(parsed.words.join(" "), Pt);
        if (!possible?.candidates.includes(ft)) return false;
        return hodlValidateTargetMnemonic([...parsed.words, ft].join(" "), Pt).ok;
      }
      return hodlDiceEntropy(input.value, ge, Pt).ok;
    }
    if (Ne === "cards") {
      return hodlSelectedCardsEntropy(Pt).ok;
    }
    if (Ne === "hex") return hodlSelectedEntropy().ok;
    if (Ne === "seed") {
      let selected = hodlSelectedSeedInput(Pt), value = selected.value;
      if (!value) return false;
      if (selected.extended) {
        if (!hodlUsableSinglesigImport(value, derivationPlan?.network ?? hodlSelectedNetwork(document.getElementById("network")))) return false;
        let parsed = uf(value);
        if (parsed.node.depth === 0 && !parsed.isPrivate && (derivationPlan?.hasHardenedPrefix || derivationPlan?.hardening.branch || derivationPlan?.hardening.address)) return false;
        if (hodlReadHardening().address && parsed.node.depth > 0 && !parsed.isPrivate) return false;
        return true;
      }
      return hodlValidateTargetMnemonic(value, Pt).ok;
    }
    if (Ne === "key" && hodlNormalizePrivateKeyKind(document.querySelector('input[name="kk"]:checked')?.value, document.getElementById("key")?.value || "") === "brain") {
      if (!hodlBrainLabAck) return false;
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
    button.title = "A derivation is already running.";
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
    if (Ne === "dice") {
      let input = document.getElementById("dice");
      if (!input) return null;
      if (ge === "dplus") {
        let rollsFinalWord = !0,
          parsed = hodlDPlusRolls(input.value, Pt),
          finalWord = rollsFinalWord ? parsed.finalWord : ft;
        if (!parsed.allRolledValid || parsed.invalidRequiredCount || (rollsFinalWord ? !parsed.complete : parsed.waiting !== "last-word" || !parsed.candidates.includes(finalWord))) return null;
        let validation = hodlValidateTargetMnemonic([...parsed.wordSlots, finalWord].join(" "), Pt);
        return validation.ok ? validation.words.join(" ") : null;
      }
      if (ge === "bitbox") {
        let parsed = hodlBitBoxRolls(input.value, Pt);
        if (parsed.leftover || parsed.waiting !== "last-word" || !ft) return null;
        let possible = hodlTargetLastWords(parsed.words.join(" "), Pt);
        if (!possible?.candidates.includes(ft)) return null;
        let validation = hodlValidateTargetMnemonic([...parsed.words, ft].join(" "), Pt);
        return validation.ok ? validation.words.join(" ") : null;
      }
      if (hodlAnalyzeDiceInput(input.value, ge, Pt).coinDerivedCount) return null;
      let entropy = hodlDiceEntropy(input.value, ge, Pt);
      return entropy.ok ? _n(entropy.bytes) : null;
    }
    if (Ne === "cards") {
      let entropy = hodlSelectedCardsEntropy(Pt);
      return entropy.ok ? _n(entropy.bytes) : null;
    }
    if (Ne === "hex") {
      let entropy = hodlSelectedEntropy();
      return entropy.ok ? _n(entropy.bytes) : null;
    }
    if (Ne === "seed") {
      let selected = hodlSelectedSeedInput(Pt), value = selected.value;
      if (!value || selected.extended) return null;
      let validation = hodlValidateTargetMnemonic(value, Pt);
      return validation.ok ? validation.words.join(" ") : null;
    }
  } catch {
  }
  return null;
}
function hodlMasterFingerprint(mnemonic, passphrase = "") {
  let seed = wi(mnemonic, passphrase);
  try {
    return Us(Gt.fromMasterSeed(seed).fingerprint);
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
  let preview = document.getElementById("master-fingerprint-preview"), baseCard = document.getElementById("base-master-fingerprint-card"), base = document.getElementById("base-master-fingerprint"), baseImage = document.getElementById("base-master-fingerprint-lifehash"), arrow = document.getElementById("master-fingerprint-arrow"), derivedCard = document.getElementById("passphrase-master-fingerprint-card"), derived = document.getElementById("passphrase-master-fingerprint"), derivedImage = document.getElementById("passphrase-master-fingerprint-lifehash"), pass = document.getElementById("pass");
  if (!preview || !baseCard || !base || !arrow || !derivedCard || !derived || !pass) return;
  if (Ne === "key") {
    preview.hidden = true;
    return;
  }
  preview.hidden = false;
  arrow.hidden = false;
  derivedCard.hidden = false;
  let clear = () => {
    hodlSetMasterFingerprintCard(baseCard, base, "", baseImage);
    hodlSetMasterFingerprintCard(derivedCard, derived, "", derivedImage);
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
  let available = hodlSetMasterFingerprintCard(derivedCard, derived, value, derivedImage);
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
  re = null;
  Ge = false;
  dr.innerHTML = "";
  hodlStopDerivation("key");
  hodlResetDerivationProgress("key");
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
    let target = event.target instanceof Element ? event.target.closest("#modes button, [data-seed-words], [data-d], [data-lw], [data-card-suit], [data-card-rank], [data-direct-card-rank], #card-undo") : null;
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
async function hodlCalculateKey(progress) {
  W("#error").textContent = "";
  // A fresh derivation restores the safe wallet.dat birthday default (scan
  // from genesis) so a previous "new keys" choice cannot leak into a
  // recovery export.
  hodlWalletDatBirthday = "genesis";
  try {
    let derivationPlan = Ne === "key" && !hodlBrainHdActive() ? null : hodlReadDerivationPlan(), coinType = derivationPlan?.coinType ?? hodlReadCoinType(document.getElementById("network")), network = derivationPlan?.network ?? hodlNetworkFromCoinType(coinType), addressWindow = Ne === "key" ? { start: 0, range: 1 } : hodlReadAddressWindow(), branchWindow = Ne === "key" ? { start: 0, range: 2 } : hodlReadBranchWindow(), count = addressWindow.range, addressStart = addressWindow.start, branchStart = branchWindow.start, branchRange = branchWindow.range, passphrase = document.getElementById("pass").value, scriptType = hodlSelectedScriptType(), purpose = derivationPlan?.purpose ?? 84, account = derivationPlan?.accountIndex ?? 0, hardening = derivationPlan?.hardening ?? hodlDefaultHardening();
    if ((Ne !== "key" || hodlBrainHdActive()) && hodlPassphraseBip39Enabled() && passphrase) {
      let passphraseAnalysis = hodlAnalyzeBip39Passphrase(passphrase);
      if (passphraseAnalysis.invalidRanges.length || passphraseAnalysis.incomplete || passphraseAnalysis.trailingSeparator) throw new Error("Correct the highlighted BIP39-word passphrase inconsistencies before deriving.");
    }
    if (Ne === "dice") {
      if (ge === "dplus") {
        let parsed = hodlDPlusRolls(document.getElementById("dice").value, Pt);
        if (parsed.firstInvalid) {
          let invalid = parsed.firstInvalid,
            specSteps = hodlDPlusFinalSteps(Pt),
            position = invalid.final ? hodlDPlusStepChecksumLabel(specSteps[invalid.position]) : `word ${invalid.groupIndex+1}'s ${invalid.position===0?"D8":invalid.position===1?"first D16":"second D16"} roll`;
          throw new Error(`Correct the highlighted invalid result in ${position}. Each D++ word keeps its original three-character group.`)
        }
        if (parsed.waiting === "d8") throw new Error(`Complete word ${parsed.activeGroupIndex + 1}: roll the D8, then both D16 dice.`);
        if (parsed.waiting === "d16-first") throw new Error(`Complete word ${parsed.activeGroupIndex + 1}: enter the first D16 roll.`);
        if (parsed.waiting === "d16-second") throw new Error(`Complete word ${parsed.activeGroupIndex + 1}: enter the second D16 roll.`);
        if (parsed.waiting === "checksum-d8") throw new Error(`Roll the final D8 to select the checksum word.`);
        if (parsed.waiting === "checksum-d16") throw new Error(`Roll the final D16 to ${hodlDPlusFinalSteps(Pt).length > 1 ? "continue" : "select"} the checksum pick.`);
        if (parsed.waiting === "checksum-coin") throw new Error("Roll the final D8 to finish selecting the checksum word: 1\u20134 is Heads, 5\u20138 is Tails.");
        let rollsFinalWord = !0,
          finalWord = rollsFinalWord ? parsed.finalWord : ft;
        if (!rollsFinalWord && (!finalWord || !parsed.candidates.includes(finalWord))) throw new Error(`Choose one of the ${hodlSeedConfig().candidates} valid final checksum words before deriving the wallet.`);
        if (rollsFinalWord && !parsed.complete) throw new Error("Complete all D++ rolls before deriving the wallet.");
        let phrase = [...parsed.wordSlots, finalWord].join(" "),
          validation = hodlValidateTargetMnemonic(phrase, Pt);
        if (!validation.ok) throw new Error(validation.error);
        let notes = parsed.notes.slice();
        if (!rollsFinalWord) notes.push(`Selected checksum-valid final word: ${finalWord}.`);
        re = await hodlMnemonicWalletWithProgress(phrase, passphrase, network, count, {
          notes,
          warnings: parsed.warnings
        }, account, addressStart, progress, purpose, coinType, hardening, branchStart, branchRange, derivationPlan)
      } else if (ge === "bitbox") {
        let parsed = hodlBitBoxRolls(document.getElementById("dice").value, Pt);
        if (parsed.leftover) throw new Error(`Invalid characters: ${parsed.leftover}`);
        if (parsed.waiting !== "last-word") throw new Error(`Need ${parsed.neededPartial} lookup-table words for a ${Pt}-word seed. You have ${parsed.words.length}.`);
        let possible = hodlTargetLastWords(parsed.words.join(" "), Pt);
        if (!ft || !possible?.candidates.includes(ft)) throw new Error(`Choose one of the ${hodlSeedConfig().candidates} valid final checksum words before deriving the wallet.`);
        let phrase = [...parsed.words, ft].join(" "), validation = hodlValidateTargetMnemonic(phrase, Pt);
        if (!validation.ok) throw new Error(validation.error);
        re = await hodlMnemonicWalletWithProgress(phrase, passphrase, network, count, { notes: parsed.notes, warnings: parsed.warnings }, account, addressStart, progress, purpose, coinType, hardening, branchStart, branchRange, derivationPlan);
      } else {
        let diceValue = document.getElementById("dice").value;
        if (hodlAnalyzeDiceInput(diceValue, ge, Pt).coinDerivedCount) throw new Error("Coin-button digits are entropy-equivalent only in BitBox mode. Clear them and enter fair die rolls for this conversion method.");
        let entropy = hodlDiceEntropy(diceValue, ge, Pt);
        if (!entropy.ok) throw new Error(entropy.error);
        re = await hodlEntropyWalletWithProgress(entropy, passphrase, network, count, account, addressStart, progress, purpose, coinType, hardening, branchStart, branchRange, derivationPlan);
      }
    } else if (Ne === "cards") {
      let entropy = hodlSelectedCardsEntropy(Pt);
      if (!entropy.ok) throw new Error(entropy.error);
      re = await hodlEntropyWalletWithProgress(entropy, passphrase, network, count, account, addressStart, progress, purpose, coinType, hardening, branchStart, branchRange, derivationPlan);
    } else if (Ne === "hex") {
      let entropy = hodlSelectedEntropy();
      if (!entropy.ok) throw new Error(entropy.error);
      re = await hodlEntropyWalletWithProgress(entropy, passphrase, network, count, account, addressStart, progress, purpose, coinType, hardening, branchStart, branchRange, derivationPlan);
    } else if (Ne === "seed") {
      let selected = hodlSelectedSeedInput(Pt), value = selected.value;
      if (selected.extended) re = await hodlImportedWalletWithProgress(value, network, count, account, addressStart, progress, purpose, coinType, hardening, branchStart, branchRange, derivationPlan);
      else {
        if (hodlSeedMethod === "numbers" && !selected.parsed?.complete) throw new Error(selected.parsed?.invalidEntries.length ? `Word numbers must be between ${selected.parsed.minimum} and ${selected.parsed.maximum}.` : selected.parsed?.extraEntries.length ? `Enter exactly ${Pt} BIP39 word numbers.` : selected.parsed?.checksumInvalid ? "The entered word numbers do not have a valid BIP39 checksum." : `Enter exactly ${Pt} BIP39 word numbers before deriving the wallet.`);
        let validation = hodlValidateTargetMnemonic(value, Pt);
        if (!validation.ok) throw new Error(validation.error);
        re = await hodlMnemonicWalletWithProgress(validation.words.join(" "), passphrase, network, count, void 0, account, addressStart, progress, purpose, coinType, hardening, branchStart, branchRange, derivationPlan);
      }
    } else {
      let value = document.getElementById("key").value, kind = hodlNormalizePrivateKeyKind(document.querySelector("input[name=kk]:checked")?.value, value);
      if (kind === "brain" && !hodlBrainLabAck) throw new Error("Acknowledge the lab warning before deriving.");
      if (kind === "brain" && hodlBrainWalletOutput() === "hd") {
        // The digest becomes BIP39 entropy rather than the private key itself,
        // which is a different wallet from the same text.
        if (passphrase && document.getElementById("passphrase-field")?.hidden) throw new Error("A passphrase is set but not visible for this output. Show it and confirm it, or clear it, before deriving.");
        let entropy = hodlBrainLabEntropy(hodlBrainWalletPassphrase(value, hodlBrainWalletTrimEnabled()));
        if (!entropy.ok) throw new Error(entropy.error);
        re = await hodlEntropyWalletWithProgress(entropy, passphrase, network, count, account, addressStart, progress, purpose, coinType, hardening, branchStart, branchRange, derivationPlan);
      } else {
        let trimBrainWallet = hodlBrainWalletTrimEnabled();
        hodlAssertPrivateKeyKind(value, network, kind, trimBrainWallet);
        progress.setTotal(1);
        re = Io(value, network, kind, trimBrainWallet);
        progress.step();
      }
    }
    if (re?.network !== network) throw new Error(`The supplied key is for ${re.network}, but Network is set to ${network}.`);
    Ge = false;
    hodlSetSelectedScriptType(scriptType);
    hodlCaptureKey();
    hodlSnapshotKeySummary();
    hodlCommitDerivedKey();
    hodlFocusWalletResult();
    return true;
  } catch (error) {
    if (error instanceof HodlDerivationCancelledError) throw error;
    re = null;
    W("#error").textContent = error instanceof Error ? error.message : "Could not derive wallet";
    dr.innerHTML = "";
    hodlCaptureKey();
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
  if (!/^S(?:[1-9A-HJ-NP-Za-km-z]{21}|[1-9A-HJ-NP-Za-km-z]{29})$/.test(candidate)) throw new Error("Mini keys must start with S and contain 22 or 30 Bitcoin Base58 characters.");
  return Ns(candidate);
}
function hodlAssertPrivateKeyKind(value, network, kind, trimBrainWallet = false) {
  let raw = String(value ?? ""), selected = hodlNormalizePrivateKeyKind(kind, raw);
  if (selected === "brain") return hodlBrainWalletPassphrase(raw, trimBrainWallet);
  let candidate = raw.trim();
  if (!candidate) throw new Error("Enter a private key.");
  if (selected === "minikey") {
    hf(hodlDecodeMiniPrivateKey(candidate));
    return candidate;
  }
  if (selected === "hex-key") {
    let compact = candidate.replace(/\s/g, "").replace(/^0x/i, "");
    if (!/^[0-9a-fA-F]{64}$/.test(compact)) throw new Error("Enter exactly 64 hexadecimal characters (0\u20139 and a\u2013f).");
    hf(M.decode(compact.toLowerCase()));
    return compact.toLowerCase();
  }
  let decoded;
  try {
    decoded = Ls(candidate);
  } catch {
    throw new Error(`Enter a valid ${network} WIF private key (${network === "testnet" ? "9\u2026 or c\u2026" : "5\u2026, K\u2026, or L\u2026"}).`);
  }
  if (decoded.network !== network) throw new Error(`This WIF is for ${decoded.network}; Network is set to ${network}.`);
  hf(decoded.priv);
  return candidate;
}
function hodlFilterXpub(e) {
  return String(e ?? "").replace(/[^A-Za-z0-9[\]/']/g, "");
}
function hodlNormalizeOriginPath(path) {
  return String(path ?? "").trim().replace(/^m\//i, "").replace(/'/g, "h").replace(/H/g, "h");
}
function hodlParseKeyOrigin(raw) {
  let input = String(raw ?? "").trim();
  let match = input.match(/^\[([0-9a-fA-F]{8})\/([0-9A-Za-z/']+)\](.+)$/);
  if (!match) return { origin: null, key: input };
  let fingerprint = match[1].toLowerCase(), path = hodlNormalizeOriginPath(match[2]), key = String(match[3] || "").trim().replace(/\/(?:<\d+(?:;\d+)*>|\d+)\/\*$/, "");
  if (fingerprint === "00000000") throw new Error("Key origin fingerprint 00000000 is not a real master fingerprint.");
  if (!/^(?:\d+h?)(?:\/\d+h?)*$/.test(path)) throw new Error("Key origin path must look like 48h/0h/0h/2h.");
  if (!key) throw new Error("Key origin is missing the extended public key.");
  return { origin: { fingerprint, path }, key };
}
function hodlOriginPathIndexes(path) {
  return hodlNormalizeOriginPath(path).split("/").filter(Boolean).map((step) => {
    let hardened = step.endsWith("h"), index = Number(hardened ? step.slice(0, -1) : step);
    if (!Number.isInteger(index) || index < 0 || index > 2147483647) throw new Error("Key origin path has an invalid index.");
    return hardened ? 2147483648 + index : index;
  });
}
function hodlOriginMatchesParsedKey(origin, parsed) {
  let indexes = hodlOriginPathIndexes(origin.path);
  if (indexes.length !== parsed.depth) return `Key origin path has ${indexes.length} steps, but this extended key is depth ${parsed.depth}.`;
  if (indexes[indexes.length - 1] !== parsed.childNumber) return "Key origin path does not end at this extended key.";
  return "";
}
function hodlMultisigPurposeIndex(origin) {
  let first = hodlNormalizeOriginPath(origin?.path).split("/").filter(Boolean)[0], match = first?.match(/^(\d+)h?$/);
  if (!match) throw new Error("The purpose index in the key origin is missing or invalid.");
  let purpose = Number(match[1]);
  if (!Number.isSafeInteger(purpose) || purpose < 0 || purpose > hodlMaxPurpose) throw new Error("The purpose index in the key origin is out of range.");
  return purpose;
}
function hodlReadMsigPurpose(mark = true) {
  let input = document.getElementById("msig-purpose"), raw = String(input?.value ?? "").trim(), value = Number(raw), valid = /^\d+$/.test(raw) && Number.isSafeInteger(value) && value >= 0 && value <= hodlMaxPurpose;
  if (mark) {
    input?.classList.toggle("bad", !valid);
    input?.setAttribute("aria-invalid", String(!valid));
  }
  if (!valid) throw new Error("Purpose must be a whole number from 0 to 2,147,483,647.");
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
function hodlOriginScriptError(origin, kind, network, purpose, coinType = Rs(network), hardening = { purpose: true, coinType: true, account: true, address: false }) {
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
  if (kind === "p2wsh" || kind === "p2sh-p2wsh") {
    let coin = `${coinType}${hardening.coinType ? "h" : ""}`;
    if (steps[1] !== coin) return `This key origin should use ${coin} as the selected coin type.`;
    if (steps.length !== 4) return "SegWit multisig origin must contain purpose, coin type, account, and script type.";
    if (!new RegExp(`^\\d+${hardening.account ? "h" : ""}$`).test(steps[2])) return `The account index must be ${hardening.account ? "hardened" : "unhardened"}.`;
    let last = kind === "p2wsh" ? "2h" : "1h";
    if (steps[3] !== last) return `This script type's origin must end in ${last}.`;
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
  if (!Number.isSafeInteger(account) || account < 0 || account > 2147483647) throw new Error("The account index is out of range.");
  return account;
}
function hodlSummarizeMultisigAccounts(accountNumbers) {
  let accounts = [...new Set(accountNumbers.filter((account) => Number.isSafeInteger(account) && account >= 0 && account <= 2147483647))].sort((a, b) => a - b);
  let mixed = accounts.length > 1;
  return { account: accounts.length === 1 ? accounts[0] : null, accounts, consistent: !mixed, mixed };
}
function hodlMultisigAccountWarning(summary) {
  return summary.consistent ? "" : `Co-signer account numbers do not match (${summary.accounts.join(", ")}). The Account field is shown as Mixed.`;
}
function hodlMultisigOriginScriptKind(origin) {
  let steps = hodlNormalizeOriginPath(origin?.path).split("/").filter(Boolean);
  if (steps.length === 1) return "p2sh";
  if (steps[0].replace(/h$/, "") === "86" && steps.length === 3) return "p2tr";
  if (steps[0].replace(/h$/, "") !== "48" || steps.length !== 4) return null;
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
function hodlParseMultisigCosigner(raw) {
  let parsedOrigin = hodlParseKeyOrigin(raw), parsed = uf(parsedOrigin.key);
  parsed.origin = parsedOrigin.origin;
  return parsed;
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
function hodlMultisigScriptLabel(kind) {
  return kind === "p2sh" ? "Legacy" : kind === "p2sh-p2wsh" ? "Nested SegWit" : kind === "p2wsh" ? "Native SegWit" : kind === "p2tr" ? "Taproot" : "Unknown"
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
function hodlMultisigKeyPlaceholder(kind, network, purpose, coinType = Rs(network), hardening = { purpose: true, coinType: true, account: true, address: false }) {
  let testnet = network === "testnet",
    coin = `${coinType}${hardening.coinType ? "h" : ""}`, purposeStep = `${purpose}${hardening.purpose ? "h" : ""}`, account = `0${hardening.account ? "h" : ""}`;
  if (kind === "p2sh" && purpose === 45) return `[fingerprint/${purposeStep}]${testnet?"tpub":"xpub"}\u2026`;
  if (kind === "p2sh" || purpose === 87) return `[fingerprint/${purposeStep}/${coin}/${account}]${testnet?"tpub":"xpub"}\u2026`;
  if (kind === "p2sh-p2wsh") return `[fingerprint/${purposeStep}/${coin}/${account}/1h]${testnet?"Upub":"Ypub"}\u2026`;
  if (kind === "p2wsh") return `[fingerprint/${purposeStep}/${coin}/${account}/2h]${testnet?"Vpub":"Zpub"}\u2026`;
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
  let message = mixed ? `Co-signer purpose indexes do not match (${purposes.map(value => `${value}h`).join(", ")}).` : "";
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
    button.title = "A derivation is already running.";
    return;
  }
  hodlSetDerivationButtonState("msig", "idle");
  let ready = false, reason = "";
  try {
    hodlValidatedMsigInputs();
    ready = true;
  } catch (error) {
    reason = error.message || "Complete every multisig field.";
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
  let warning = document.getElementById("msig-script-warning"), labels = summary.kinds.map(hodlMultisigScriptLabel), message = summary.mixed ? `Co-signer exports indicate different script types (${labels.join(" and ")}). A Mixed selection does not define one multisig output policy; export every key for the same script type before deriving.` : "";
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
  if (!parsed.origin) throw new Error("Paste the complete key origin and extended public key so a signer can recognize it.");
  return `[${parsed.origin.fingerprint}/${parsed.origin.path}]${canonical}`;
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
function hodlBindFields() {
  let d = document.getElementById("dice");
  if (d) {
    d.setAttribute("inputmode", "numeric");
    d.setAttribute("autocomplete", "off");
    d.setAttribute("spellcheck", "false");
  }
  let hx = document.getElementById("hex");
  if (hx) {
    hx.setAttribute("spellcheck", "false");
    hx.oninput = () => {
      hx.value = hodlFilterHex(hx.value);
      let n = hx.value.replace(/\s/g, "");
      let ok = !n || /^[0-9a-fA-F]+$/.test(n) && n.length % 2 === 0;
      let msg = !n ? "" : n.length === 32 ? "32 hex characters \xB7 12-word seed" : n.length === 64 ? "64 hex characters \xB7 24-word seed" : n.length < 32 ? "Need 32 hex characters for 12 words (or 64 for 24)" : n.length % 2 ? "Hex must be an even number of characters" : ok ? n.length * 4 + " bits" : "Not hex";
      hodlHint(hx, ok && (!n || n.length === 32 || n.length === 40 || n.length === 48 || n.length === 56 || n.length === 64), msg);
    };
  }
  let bn = document.getElementById("bin");
  if (bn) {
    bn.oninput = () => {
      bn.value = hodlFilterBin(bn.value);
      let n = bn.value.replace(/\s/g, "");
      hodlHint(bn, !n || n.length >= 128, n && n.length < 128 ? "Need at least 128 coin flips" : n ? n.length + " bits" : "");
    };
  }
  let ky = document.getElementById("key");
  if (ky) {
    let apply = () => {
      let kind = (document.querySelector("input[name=kk]:checked") || {}).value || "wif-or-hex";
      if (kind !== "brain") ky.value = hodlFilterKey(ky.value, kind);
      let v = ky.value.trim();
      if (!v) {
        hodlHint(ky, true, "");
        return;
      }
      if (kind === "brain") {
        hodlHint(ky, false, "Brain wallets are unsafe. Recovery only.");
        return;
      }
      if (kind === "minikey") {
        try {
          hodlDecodeMiniPrivateKey(v);
          hodlHint(ky, true, "Mini key checksum looks valid");
        } catch (err) {
          hodlHint(ky, false, err.message || "Not a valid mini key");
        }
        return;
      }
      if (/^[0-9a-fA-F]{64}$/.test(v)) {
        hodlHint(ky, true, "64-character hex private key");
        return;
      }
      try {
        Ls(v);
        hodlHint(ky, true, "WIF private key checksum looks valid");
      } catch (err) {
        hodlHint(ky, false, "Not a WIF key or 64-character hex");
      }
    };
    ky.oninput = apply;
    document.querySelectorAll("input[name=kk]").forEach((r) => {
      r.addEventListener("change", apply);
    });
  }
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
    if (help) help.textContent = "BIP45 purpose keys do not contain an account number.";
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
  }
  re = null;
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
    hint.textContent = n === 1 ? "Spending will need this key. Receiving needs none of the private keys." : `Spending will need ${m} of these ${n} keys. Receiving needs none of the private keys.`;
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
      if (parsed.origin?.fingerprint) return "position " + (index + 1) + " " + parsed.origin.fingerprint
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
    if (pos) pos.textContent = "Position " + (index + 1);
    if (lab) {
      let title = lab.childNodes[0];
      if (title && title.nodeType === 3) title.textContent = "Co-signer " + (index + 1) + " multisig extended public key"
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
    let match = String(token).match(/^\[([0-9a-f]{8})\/([^\]]+)\]/i);
    return {
      position: index + 1,
      fingerprint: match ? match[1] : "",
      path: match ? match[2] : ""
    }
  })
}

function hodlSessionMsigKeys() {
  return hodlKeys.filter((state) => !state.isLab && state.result?.multisigCosignerExports?.length);
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
function hodlRefreshMsigSessionPickers() {
  let keys = hodlSessionMsigKeys();
  document.querySelectorAll(".msig-key-row").forEach((row) => {
    let box = row.querySelector(".msig-session-keys"), ta = row.querySelector("textarea");
    if (!box) return;
    box.innerHTML = "";
    box.hidden = !keys.length;
    keys.forEach((state) => {
      let fingerprint = state.result?.masterFingerprint || state.name, button = document.createElement("button"), image = document.createElement("img"), label = document.createElement("span");
      button.type = "button";
      button.className = "msig-session-key";
      button.dataset.keyId = String(state.id);
      button.dataset.fingerprint = fingerprint;
      button.setAttribute("aria-pressed", "false");
      button.setAttribute("aria-label", "Use session key " + fingerprint);
      image.className = "key-tab-lifehash";
      image.width = 22;
      image.height = 22;
      image.alt = "";
      image.hidden = true;
      if (fingerprint) hodlFillKeyTabLifehash(image, fingerprint);
      label.textContent = fingerprint;
      button.append(image, label);
      button.onclick = () => {
        if (!ta) return;
        ta.value = hodlMatchingMsigExport(state.result);
        ta.dispatchEvent(new Event("input"));
      };
      box.appendChild(button);
    });
    hodlSyncMsigKeyAvatar(row);
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
      pos.textContent = "Position " + (i + 1);
      let moves = document.createElement("div");
      moves.className = "msig-key-move";
      let up = document.createElement("button");
      up.type = "button";
      up.className = "btn secondary msig-key-move-btn";
      up.dataset.msigMove = "-1";
      up.textContent = "Move up";
      let down = document.createElement("button");
      down.type = "button";
      down.className = "btn secondary msig-key-move-btn";
      down.dataset.msigMove = "1";
      down.textContent = "Move down";
      moves.append(up, down);
      head.append(pos, moves);
      row.appendChild(head)
    }
    let lab = document.createElement("label");
    lab.className = "field";
    lab.textContent = "Co-signer " + (i + 1) + " multisig extended public key";
    let ta = document.createElement("textarea");
    ta.id = "msig-x-" + i;
    ta.autocomplete = "off";
    ta.spellcheck = false;
    ta.value = saved[i] || "";
    let chips = document.createElement("div");
    chips.className = "msig-session-keys";
    chips.hidden = true;
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
    row.append(chips, lab);
    box.appendChild(row);
    ta.oninput = () => {
      ta.value = hodlFilterXpub(ta.value);
      hodlUpdateMsigScriptDetection();
      document.querySelectorAll("#msig-keys textarea").forEach(hodlCheckXpub);
      hodlUpdateMsigKeyOrderStatus();
      hodlInvalidateMsig();
      hodlSyncMsigKeyAvatar(row);
    }
  }
  hodlBindMsigKeyReorder(box);
  hodlSyncMsigKeyMoveButtons();
  hodlUpdateMsigScriptDetection();
  box.querySelectorAll("textarea").forEach((ta) => {
    if (ta.value) hodlCheckXpub(ta);
  });
  hodlUpdateMsigHint();
  hodlUpdateMsigAccount();
  hodlUpdateMsigKeyOrderStatus();
  hodlRefreshMsigSessionPickers();
}
function hodlMultisigPrefixCompatible(parsed, kind, purpose) {
  if (kind === "p2tr" || purpose === 87) return parsed.family === "x";
  if (parsed.scope === "singlesig") return parsed.family === "x";
  if (kind === "p2sh-p2wsh") return parsed.family === "y";
  if (kind === "p2wsh") return parsed.family === "z";
  return false;
}
function hodlMultisigAccountKeyError(parsed, kind, purpose, hardening = { purpose: true, coinType: true, account: true, address: false }) {
  if (kind === "p2tr" || purpose === 87) {
    if (parsed.depth !== 3) return `${purpose === 87 ? "BIP87" : "Taproot"} requires a depth-3 account key at m/purposeh/coinh/accounth; this key is depth ${parsed.depth}.`;
    if ((parsed.childNumber >= 0x80000000) !== hardening.account) return `The account index must be ${hardening.account ? "hardened" : "unhardened"}.`;
    return ""
  }
  if (kind === "p2wsh" || kind === "p2sh-p2wsh") {
    let scriptIndex = kind === "p2wsh" ? 2 : 1, label = kind === "p2wsh" ? "Native SegWit" : "Nested SegWit", expected = 2147483648 + scriptIndex;
    if (parsed.depth !== 4) return `${label} requires a depth-4 script-account key ending in /${scriptIndex}h; this key is depth ${parsed.depth}.`;
    if (parsed.childNumber !== expected) return `${label} requires a script-account key whose final hardened child is ${scriptIndex}h.`;
    return "";
  }
  if (purpose !== 45) {
    if (parsed.depth !== 3) return `Account-based Legacy derivation requires a depth-3 key at m/purposeh/coinh/accounth; this key is depth ${parsed.depth}.`;
    if ((parsed.childNumber >= 2147483648) !== hardening.account) return `The account index must be ${hardening.account ? "hardened" : "unhardened"}.`;
    return "";
  }
  if (parsed.depth !== 1) return `Legacy P2SH requires the depth-1 BIP45 purpose key at m/45h; this key is depth ${parsed.depth}.`;
  let expected = hardening.purpose ? 2147483693 : 45;
  if (parsed.childNumber !== expected) return `Legacy P2SH requires the ${hardening.purpose ? "hardened" : "unhardened"} BIP45 purpose child at m/${hodlPathIndex(45, hardening.purpose)}.`;
  return "";
}
function hodlCanonicalMultisigKey(parsed) {
  // Co-signer identity is the derivation authority: the compressed account
  // public key plus chain code. Version bytes and the unauthenticated parent
  // fingerprint in the extended-key serialization are metadata; mutating only
  // those bytes must not let one key pass as two distinct co-signers.
  return M.encode(parsed.node.publicKey) + ":" + M.encode(parsed.node.chainCode);
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
    if (hodlDuplicateMultisigKey(ta, parsed)) throw new Error("This duplicates another co-signer. Every co-signer must use a distinct extended public key.");
    hodlHint(ta, true, `${parsed.prefix} origin, checksum, and derivation path look valid`);
  } catch (error) {
    hodlHint(ta, false, error.message || "Not a valid multisig extended public key");
  }
}
function hodlResetMsigForm() {
  hodlSetMsigThresholds(2, 3);
  hodlSyncSelect(document.getElementById("msig-script-type"), "p2wsh");
  hodlSetMsigPurpose(48);
  let legacy = document.getElementById("msig-legacy-bip87");
  if (legacy) legacy.checked = false;
  hodlUpdateMsigLegacyControls();
  hodlSyncSelect(document.getElementById("msig-key-order"), "sorted");
  let advanced = document.getElementById("msig-advanced");
  if (advanced) advanced.open = !1;
  let coinType = document.getElementById("msig-network");
  if (coinType) coinType.value = "0";
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
  document.getElementById("msig-error").textContent = "";
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
    keyOrder = document.getElementById("msig-key-order");
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
  W("#msig-go").onclick = () => hodlHandleDerivationButton("msig", hodlBuildMsig);
  W("#msig-wipe").onclick = hodlWipeActiveMsig;
}
function hodlCmpBytes(a, b) {
  let n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) if (a[i] !== b[i]) return a[i] - b[i];
  return a.length - b.length;
}
function hodlScriptKind() {
  return document.getElementById("msig-script-type")?.value || "p2wsh";
}

function hodlTaprootNumsKey() {
  return M.decode("50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0")
}

function hodlXOnlyPubkey(pubkey) {
  if (!pubkey || pubkey.length < 32) throw new Error("Could not derive a public key");
  return pubkey.length === 33 ? pubkey.slice(1) : pubkey.slice(0, 32)
}

function hodlMsigAddr(pubkeys, m, network, kind, sorted = !0) {
  if (kind === "p2tr") {
    let xonly = [...pubkeys].map(hodlXOnlyPubkey);
    if (sorted) xonly.sort(hodlCmpBytes);
    let script = multisigTrScript(m, xonly),
      out = addressFromScript(p2trLeafScript(hodlTaprootNumsKey(), script), network);
    if (!out) throw new Error("Failed to build Taproot multisig address");
    return {
      address: out,
      scriptHex: M.encode(script),
      kind
    }
  }
  let keys = [...pubkeys];
  if (sorted) keys.sort(hodlCmpBytes);
  let ms = multisigScript(m, keys);
  if (kind === "p2wsh") {
    return { address: addressFromScript(p2wshScript(ms), network), scriptHex: M.encode(ms), kind };
  }
  if (kind === "p2sh-p2wsh") {
    return { address: addressFromScript(p2shScript(p2wshScript(ms)), network), scriptHex: M.encode(ms), kind };
  }
  return { address: addressFromScript(p2shScript(ms), network), scriptHex: M.encode(ms), kind };
}
function hodlValidatedMsigInputs() {
  let coinType = hodlReadCoinType(document.getElementById("msig-network")), network = hodlNetworkFromCoinType(coinType), addressWindow = hodlReadAddressWindow("msig-"), branchWindow = hodlReadBranchWindow("msig-"), count = addressWindow.range, addressStart = addressWindow.start, branchStart = branchWindow.start, branchRange = branchWindow.range, hardening = hodlReadHardening("msig-"), n = Number(document.getElementById("msig-n")?.value), m = Number(document.getElementById("msig-m")?.value);
  if (hardening.branch) throw new Error("Hardened address branches cannot be derived from the supplied multisig extended public keys. Turn off Harden for Starting address branch index.");
  if (hardening.address) throw new Error("Hardened address indexes cannot be derived from multisig extended public keys. Turn off Harden for Starting address index.");
  if (!(m >= 1 && n >= 1 && m <= n && n <= 15)) throw new Error("Pick how many signatures out of how many keys.");
  let kind = hodlScriptKind(), purpose = hodlReadMsigPurpose(), legacyStandard = hodlSelectedLegacyMultisigStandard(), nodes = [], xpubs = [], keyTokens = [], accountNumbers = [], purposeIndexes = [];
  if (kind === "mixed") throw new Error("Co-signer keys indicate different script types. Export every key for the same multisig script type before deriving.");
  for (let index = 0; index < n; index++) {
    let field = document.getElementById("msig-x-" + index), raw = field?.value.trim() || "";
    if (!raw) throw new Error("Paste an origin and extended public key for co-signer " + (index + 1) + ".");
    let parsed = hodlParseMultisigCosigner(raw);
    if (parsed.isPrivate) throw new Error("Co-signer " + (index + 1) + " is an extended private key. Paste only an extended public key.");
    if (parsed.network !== network) throw new Error(`Co-signer ${index + 1}'s ${parsed.prefix} is for ${parsed.network}, but this multisig is set to ${network}.`);
    if (!hodlMultisigPrefixCompatible(parsed, kind, purpose)) throw new Error(parsed.scope === "singlesig" ? `Co-signer ${index + 1} uses a singlesig ${parsed.prefix}. Use a generic ${cr[network].x.pubName}, or the proper uppercase multisig export for this script type.` : `Co-signer ${index + 1}'s ${parsed.prefix} does not match the selected multisig script type.`);
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
    let node = parsed.node, canonical = hodlCanonicalMultisigKey(parsed);
    if (xpubs.includes(canonical)) throw new Error(`Co-signer ${index + 1} duplicates an earlier co-signer. Every slot must use a distinct extended public key.`);
    nodes.push(node);
    xpubs.push(canonical);
    keyTokens.push(hodlMultisigKeyToken(parsed, network));
  }
  let uniquePurposes = [...new Set(purposeIndexes)];
  if (uniquePurposes.length !== 1 || uniquePurposes[0] !== purpose) throw new Error("Every co-signer purpose index must match the selected Purpose.");
  let accountSummary = hodlSummarizeMultisigAccounts(accountNumbers), accountWarning = hodlMultisigAccountWarning(accountSummary);
  return { network, coinType, count, addressStart, branchStart, branchRange, hardening, n, m, kind, purpose, legacyStandard, nodes, xpubs, keyTokens, accountSummary, accountWarning };
}
async function hodlBuildMsig(progress) {
  let error = document.getElementById("msig-error");
  error.textContent = "";
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
        let publicKeys = nodes.map((node) => {
          let key = node.derive(path + index).publicKey;
          if (!key) throw new Error("Could not derive a public key");
          return key;
        });
        // Final defense behind the co-signer identity check: never emit a
        // script whose public keys repeat, whatever the supplied encodings were.
        if (new Set(publicKeys.map(M.encode)).size !== publicKeys.length) throw new Error("Two co-signers derive the same public key. Every co-signer must use a distinct extended public key.");
        rows.push(Object.assign({ index, branch, role: hodlAddressBranchRole(branch), path: path.slice(1) + index }, hodlMsigAddr(publicKeys, m, network, kind, sorted)));
        let pause = progress.step();
        if (pause) await pause;
      }
      addressBranches.push({ branch, role: hodlAddressBranchRole(branch), label: hodlAddressBranchLabel(branch), publicDescriptor: Le(descriptor), privateDescriptor: null, rows });
    }
    let receiveBranch = addressBranches.find((entry) => entry.branch === 0), changeBranch = addressBranches.find((entry) => entry.branch === 1);
    let notes = ["This is watch-only. Private keys never entered this calculator.", "Each key origin lets a signer match its seed to one co-signer.", "A signer is only needed when you spend."];
    if (bip45) notes.push("Legacy BIP45 addresses use co-signer branch 0 before the selected address branch.");
    if (kind === "p2sh" && legacyStandard === "bip87") notes.push("Legacy P2SH uses the selected BIP87 account paths. Keep the descriptor with every seed backup.");
    if (kind === "p2tr") notes.push("Taproot script-path multisig. The internal key is the BIP341 NUMS point, so spending is only possible through the " + (sorted ? "sortedmulti_a" : "multi_a") + " script path.");
    if (!sorted) notes.push("This wallet uses " + hodlMsigPolicyOp(kind, !1) + ", so the listed co-signer order is part of the script. Reordering keys changes addresses.");
    re = {
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
    hodlSnapshotMsigSummary();
    hodlCommitDerivedMsig();
    hodlFocusWalletResult();
    return true;
  } catch (exception) {
    if (exception instanceof HodlDerivationCancelledError) throw exception;
    re = null;
    hodlClearMsigOut();
    error.textContent = exception.message || String(exception);
    hodlCaptureMsig();
    return false;
  }
}
function hodlClearMsigOut() {
  let out = document.getElementById("msig-out");
  if (out) out.innerHTML = "";
}
function hodlShowMsig() {
  if (!re || re.kind !== "msig") return;
  Ge = false;
  let out = document.getElementById("msig-out");
  if (!out) return;
  let accountLabel = re.accountMixed ? " \xB7 Account Mixed" : re.account == null ? "" : ` \xB7 Account ${re.account}`, purposeLabel = Number.isSafeInteger(re.purpose) ? ` \xB7 Purpose ${hodlOriginPathIndex(re.purpose, re.hardening?.purpose !== false)}` : "", branches = hodlAccountAddressBranches(re), firstBranch = branches[0], firstAddress = firstBranch?.rows[0], firstIndex = firstAddress?.index ?? 0, firstLabel = firstBranch ? hodlAddressBranchLabel(firstBranch.branch) : "Address";
  out.innerHTML = `
    <section class="card account-result-card">
      <div class="kicker">${re.m}-of-${re.n} multisig${purposeLabel}${re.sorted===!1?" \xB7 listed order":""} \xB7 ${re.network}${accountLabel}</div>
      <h2 tabindex="-1">Your multisig wallet</h2>
      <p class="muted">Anyone can pay these addresses. Spending later needs ${re.m} signature${re.m===1?"":"s"} from the configured ${re.n} signing key${re.n===1?"":"s"}. This screen has no private keys.</p>
      ${hodlWalletMessages(re,"multisig")}
      ${re.sorted===!1&&re.scriptOrder?.length?`<section class="account-result-section" aria-labelledby="multisig-order-heading"><div class="wallet-data-section-head"><h3 id="multisig-order-heading">Script key order</h3><p class="muted">${hodlMsigPolicyOp(re.script,!1)} uses the co-signers in this order. Changing the order creates a different wallet.</p></div><ol class="msig-script-order">${re.scriptOrder.map(item=>`<li><span class="msig-script-order-position">Position ${item.position}</span><code>${$t(item.fingerprint?item.fingerprint+"/"+item.path:item.fingerprint||"")}</code></li>`).join("")}</ol></section>`:""}
      <section class="account-result-section account-watch-section" aria-labelledby="multisig-watch-heading">
        <div class="wallet-data-section-head">
          <h3 id="multisig-watch-heading">Watch-only wallet data</h3>
          <p class="muted">These descriptors reveal every address in the selected branches for this multisig, but cannot authorize spending.</p>
        </div>
        ${hodlWatchOnlyDescriptorExport(re.receiveDescriptor, re.changeDescriptor, branches)}
      </section>
      <section class="account-result-section account-address-section" aria-labelledby="multisig-address-heading">
        <div class="wallet-data-section-head">
          <h3 id="multisig-address-heading">Addresses</h3>
          <p class="muted">Verify the first selected address on every signing device before accepting bitcoin.</p>
        </div>
        ${firstAddress ? `<div class="account-address-lead"><h4 class="wallet-data-subtitle">${$t(firstLabel)} address #${firstIndex}</h4><div class="qr" aria-label="Multisig ${$t(firstLabel.toLowerCase())} address ${firstIndex} QR code">${an(firstAddress.address)}</div><p class="mono">${$t(firstAddress.address)}</p><p class="muted mono">${$t(firstAddress.path)}</p></div>` : ""}
        ${hodlAddressBranchTables(branches, false, "msig")}
        ${hodlAddressMatchMarkup()}
      </section>
      <p class="muted">Import the watch-only wallet descriptor into Sparrow or another wallet.</p>
    </section>`;
  hodlBindAddressVirtualization(hodlAddressBranchVirtualConfigs(branches, false, "msig"));
  hodlBindAddressMatch()
}
function hodlDiceCompare() {
}
var hodlPsbtPriv = null, hodlPsbtHd = null, hodlPsbtSource = "", hodlPsbtNote = "No session key. Inspect-only mode.";
function hodlPsbtNeed(bytes, offset, length, message) {
  if (!Number.isSafeInteger(offset) || !Number.isSafeInteger(length) || offset < 0 || length < 0 || offset + length > bytes.length) throw new Error(message || "PSBT ended early.");
}
function hodlU32(number) {
  let bytes = new Uint8Array(4);
  new DataView(bytes.buffer).setUint32(0, number >>> 0, true);
  return bytes;
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
  return M.encode(copy);
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
  if (/^[0-9a-fA-F]+$/.test(compact) && compact.length % 2 === 0 && compact.length >= 10) bytes = M.decode(compact.toLowerCase());
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
    let key = bytes.slice(keyStart, keyStart + keyLength), keyHex = M.encode(key);
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
  return "script " + M.encode(script);
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
  let problems = [];
  if (declared !== null && declared !== 1) problems.push("The PSBT requests " + hodlSighashLabel(declared) + ", which does not commit to all shown outputs.");
  if (suffix !== null && suffix !== 1) problems.push("This signature uses " + hodlSighashLabel(suffix) + ", which does not commit to all shown outputs.");
  if (declared !== null && suffix !== null && declared !== suffix) problems.push("The PSBT-declared policy and the signature's appended sighash byte disagree.");
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
        if (xe.verify(signature.der, sighash, candidate, { prehash: false, format: "der", lowS: false })) {
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
    if (outputScript.length === 22 && outputScript[0] === 0 && outputScript[1] === 20) return Os(Uint8Array.of(118, 169, 20), outputScript.slice(2), Uint8Array.of(136, 172));
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
    let compact = xe.Signature.fromBytes(der, "der").toBytes("compact");
    return { r: compact.slice(0, 32), s: compact.slice(32) };
  } catch {
    return null;
  }
}

function hodlPubId(pubkey) {
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

function hodlPrivForPub(pubkey) {
  if (hodlPsbtPriv) {
    let compressed = xe.getPublicKey(hodlPsbtPriv, true), uncompressed = xe.getPublicKey(hodlPsbtPriv, false);
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
  let rootFingerprint = Us(hodlPsbtHd.fingerprint);
  for (let derivation of hodlBip32(entries, pubkey)) {
    if (M.encode(derivation.fingerprint) !== rootFingerprint) continue;
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
  hodlPsbtNote = "No session key. Inspect-only mode.";
}
function hodlLoadPsbtKey(text, passphrase) {
  hodlPsbtWipeMem();
  let value = text.trim(), hex = value.replace(/\s/g, "").replace(/^0x/i, "");
  if (!value) return;
  if (/^[5KL9c][1-9A-HJ-NP-Za-km-z]{50,51}$/.test(value)) {
    let decoded = Ls(value);
    hodlPsbtPriv = decoded.priv;
    hf(hodlPsbtPriv);
    hodlPsbtNote = `Session key: ${decoded.network} WIF. Kept in page memory only.`;
  } else if (/^[0-9a-fA-F]{64}$/.test(hex)) {
    hodlPsbtPriv = M.decode(hex.toLowerCase());
    hf(hodlPsbtPriv);
    hodlPsbtNote = "Session key: 32-byte private key. Kept in page memory only.";
  } else {
    try {
      let parsed = uf(value);
      if (parsed && parsed.isPrivate && parsed.node) {
        hodlPsbtHd = parsed.node;
        hodlPsbtNote = "Session key: " + (parsed.prefix || "xprv") + ". Kept in page memory only.";
        hodlPsbtSource = "manual";
        return;
      }
    } catch {
    }
    let mnemonic = Mt(value);
    if (!mnemonic.ok) throw new Error(mnemonic.error || "Enter a BIP39 seed phrase, root xprv/tprv, WIF, or 64-character hex key.");
    let seed = wi(mnemonic.words.join(" "), passphrase || "");
    try {
      hodlPsbtHd = Gt.fromMasterSeed(seed);
    } finally {
      seed.fill(0);
    }
    hodlPsbtNote = "Session key: BIP39 seed" + (passphrase ? " + passphrase" : "") + ". Kept in page memory only.";
  }
  hodlPsbtSource = "manual";
}
function hodlUseActiveKeyForPsbt() {
  let state = hodlKeys[hodlActiveKey];
  if (!state || !state.result) throw new Error("Generate an active key first, then return to PSBT / Nonce.");
  let result = state.result;
  hodlPsbtWipeMem();
  if (result.kind === "hd" && result.mnemonic) {
    let seed = wi(result.mnemonic, state.fields.pass || "");
    try {
      hodlPsbtHd = Gt.fromMasterSeed(seed);
    } finally {
      seed.fill(0);
    }
  } else if (result.kind === "hd" && result.rootXprv) hodlPsbtHd = Gt.fromExtendedKey(uf(result.rootXprv).xkey);
  else if (result.kind === "hd" && result.importedPrivateKey) throw new Error("The active key is an account-level extended private key. PSBT session signing needs origin-aware relative paths, which this version does not infer. Use the original seed or root xprv/tprv instead.");
  else if (result.kind === "single" && result.privHex) {
    hodlPsbtPriv = M.decode(result.privHex);
    hf(hodlPsbtPriv);
  } else throw new Error("The active key has no private material available for a session check.");
  hodlPsbtSource = "active";
  hodlPsbtNote = "Session key from " + (state.name || "the active key") + ". Kept in page memory only.";
}
function hodlInitPsbt() {
  let go = document.getElementById("psbt-go");
  if (!go) return;
  go.onclick = hodlRunPsbt;
  document.getElementById("psbt-use-calc").onclick = () => {
    let error = document.getElementById("psbt-error");
    error.textContent = "";
    try {
      hodlUseActiveKeyForPsbt();
      document.getElementById("psbt-key").value = "";
      document.getElementById("psbt-pass").value = "";
      document.getElementById("psbt-session").textContent = hodlPsbtNote;
    } catch (exception) {
      error.textContent = exception.message || String(exception);
    }
  };
  document.getElementById("psbt-wipe").onclick = () => {
    hodlPsbtWipeMem();
    document.getElementById("psbt-key").value = "";
    document.getElementById("psbt-pass").value = "";
    document.getElementById("psbt-text").value = "";
    let ax = document.getElementById("psbt-ax-transcript");
    if (ax) ax.value = "";
    document.getElementById("psbt-out").innerHTML = "";
    document.getElementById("psbt-error").textContent = "";
    document.getElementById("psbt-session").textContent = "Session ended and accessible fields were cleared (best effort).";
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
var hodlBip85Root = null, hodlBip85Note = "No parent loaded. Derive a key first, or paste a root xprv.", hodlBip85Source = "", hodlBip85Result = null, hodlBip85Reveal = false, hodlBip85Testnet = false;
function hodlBip85WipeMem() {
  wipeBip85Result(hodlBip85Result);
  hodlBip85Result = null;
  hodlBip85Reveal = false;
  if (hodlBip85Root) try {
    hodlBip85Root.wipePrivateData();
  } catch {
  }
  hodlBip85Root = null;
  hodlBip85Source = "";
  hodlBip85Testnet = false;
  hodlBip85Note = "No parent loaded. Derive a key first, or paste a root xprv.";
}
function hodlBip85PrivateValue(value) {
  let mask = "************", text = String(value ?? "\u2014");
  if (hodlBip85Reveal) return `<span class="secret private-field-value">${$t(text)}</span>`;
  let bullets = "\u2022".repeat(Math.max(Array.from(text).length, mask.length));
  return `<span class="secret private-field-value secret-placeholder"><span class="secret-placeholder-mask" aria-hidden="true">${bullets}</span><span class="secret-placeholder-message" aria-hidden="true">${mask}</span><span class="secret-placeholder-label">Private value hidden</span></span>`;
}
function hodlBip85SecretField(label, value) {
  return `<p class="private-field"><span class="muted">${$t(label)}</span>${hodlBip85PrivateValue(value)}</p>`;
}
function hodlBip85Spec() {
  let app = document.getElementById("bip85-app")?.value || "bip39";
  let index = document.getElementById("bip85-index")?.value || "0";
  return { app, index, words: Number(document.getElementById("bip85-words")?.value || 24), numBytes: Number(document.getElementById("bip85-bytes")?.value || 32), length: Number(document.getElementById("bip85-pwdlen")?.value || (app === "pwd-base85" ? 12 : 21)), testnet: hodlBip85Testnet };
}
function hodlBip85CurrentPath() {
  try {
    let spec = hodlBip85Spec(), index = parseHardenedIndex(spec.index);
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
  let value = String(text || "").trim(), { xkey, isPrivate } = uf(value);
  if (!isPrivate) throw new Error("BIP-85 needs a private root (xprv/tprv), not an extended public key.");
  let node = Gt.fromExtendedKey(xkey);
  if (node.depth !== 0) throw new Error("BIP-85 starts at the BIP32 root. This extended key is not depth 0.");
  hodlBip85WipeMem();
  hodlBip85Root = node;
  hodlBip85Testnet = /^[tuvn]prv/i.test(value);
  hodlBip85Source = "manual";
  hodlBip85Note = "Parent: pasted root " + (hodlBip85Testnet ? "tprv" : "xprv") + ". Kept in page memory only.";
}
function hodlUseActiveKeyForBip85() {
  let state = hodlKeys[hodlActiveKey];
  if (!state || !state.result) throw new Error("Derive an active key first, then return to BIP-85.");
  let result = state.result;
  hodlBip85WipeMem();
  if (result.kind === "hd" && result.mnemonic) {
    let seed = wi(result.mnemonic, state.fields.pass || "");
    try {
      hodlBip85Root = Gt.fromMasterSeed(seed);
    } finally {
      hodlWipeBytes(seed);
    }
    hodlBip85Testnet = false;
    hodlBip85Note = "Parent: " + (state.name || "the active key") + (result.passphraseUsed || (state.fields.pass || "").length ? " with BIP-39 passphrase (COLDCARD does the same \u2014 children differ without it)." : ".") + " Kept in page memory only.";
  } else if (result.kind === "hd" && result.rootXprv) {
    hodlBip85Root = Gt.fromExtendedKey(uf(result.rootXprv).xkey);
    hodlBip85Testnet = result.network === "testnet";
    hodlBip85Note = "Parent: root xprv from " + (state.name || "the active key") + ". Kept in page memory only.";
  } else if (result.kind === "hd") throw new Error("The active key is not a BIP32 root. Import the original seed or root xprv.");
  else throw new Error("BIP-85 needs an HD root. The active key is a single private key.");
  hodlBip85Source = "active";
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
  if (!hodlBip85Result) {
    box.innerHTML = "";
    return;
  }
  let derived = hodlBip85Result, notes = [...derived.notes || [], ...derived.warnings || []].map((message) => `<li>${$t(message)}</li>`).join("");
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
        ${ye("Path", derived.path)}
        ${hodlBip85SecretField(derived.secretLabel, derived.secret)}
        ${hodlBip85SecretField("Derived entropy", derived.entropyHex)}
      </div>
      ${notes ? `<ul class="bip85-notes">${notes}</ul>` : ""}
    </section>`;
  document.getElementById("bip85-reveal")?.addEventListener("change", (event) => {
    hodlBip85Reveal = event.target.checked;
    hodlRenderBip85Out();
    requestAnimationFrame(() => document.getElementById("bip85-reveal")?.focus({ preventScroll: true }));
  });
  let copy = document.getElementById("bip85-copy");
  if (copy) {
    copy.dataset.phrase = derived.secret;
    copy.onclick = () => hodlCopyBip85Child(copy);
  }
}
function hodlRunBip85() {
  let error = document.getElementById("bip85-error"), session = document.getElementById("bip85-session"), manual = document.getElementById("bip85-key")?.value || "";
  if (error) error.textContent = "";
  try {
    if (manual.trim()) {
      hodlBip85LoadXprv(manual);
      document.getElementById("bip85-key").value = "";
    } else if (!hodlBip85Root) hodlUseActiveKeyForBip85();
    wipeBip85Result(hodlBip85Result);
    hodlBip85Result = deriveApplication(hodlBip85Root, hodlBip85Spec());
    hodlBip85Reveal = false;
    if (session) session.textContent = hodlBip85Note;
    hodlRenderBip85Out();
  } catch (exception) {
    if (error) error.textContent = exception.message || String(exception);
  }
}
function hodlInitBip85() {
  let go = document.getElementById("bip85-go");
  if (!go) return;
  go.onclick = hodlRunBip85;
  // Entry point beside Derive Wallet (idea adopted from PR #150): jump to the
  // BIP-85 tab with the active key loaded as parent. Errors land in the tab's
  // own error line; secrets stay behind the existing reveal/wipe flow.
  let open = document.getElementById("bip85-open");
  if (open) open.onclick = () => {
    hodlShowWorkspace("bip85");
    let error = document.getElementById("bip85-error");
    if (error) error.textContent = "";
    try {
      hodlUseActiveKeyForBip85();
      let session = document.getElementById("bip85-session");
      if (session) session.textContent = hodlBip85Note;
    } catch (exception) {
      if (error) error.textContent = exception.message || String(exception);
    }
  };
  document.getElementById("bip85-use-calc").onclick = () => {
    let error = document.getElementById("bip85-error");
    if (error) error.textContent = "";
    try {
      hodlUseActiveKeyForBip85();
      document.getElementById("bip85-key").value = "";
      document.getElementById("bip85-session").textContent = hodlBip85Note;
    } catch (exception) {
      if (error) error.textContent = exception.message || String(exception);
    }
  };
  document.getElementById("bip85-wipe").onclick = () => {
    hodlBip85WipeMem();
    document.getElementById("bip85-key").value = "";
    document.getElementById("bip85-out").innerHTML = "";
    document.getElementById("bip85-error").textContent = "";
    document.getElementById("bip85-session").textContent = "Derived child and parent session were cleared (best effort).";
  };
  for (let id of ["bip85-app", "bip85-index", "bip85-words", "bip85-bytes", "bip85-pwdlen"]) {
    document.getElementById(id)?.addEventListener("input", hodlBip85SyncOptions);
    document.getElementById(id)?.addEventListener("change", hodlBip85SyncOptions);
  }
  hodlBip85SyncOptions();
}
function hodlRunPsbt() {
  let error = document.getElementById("psbt-error"), output = document.getElementById("psbt-out"), manual = document.getElementById("psbt-key").value;
  error.textContent = "";
  output.innerHTML = "";
  try {
    if (manual.trim()) {
      hodlLoadPsbtKey(manual, document.getElementById("psbt-pass").value);
      document.getElementById("psbt-key").value = "";
      document.getElementById("psbt-pass").value = "";
    }
    document.getElementById("psbt-session").textContent = hodlPsbtNote;
    let bytes = hodlPsbtBytes(document.getElementById("psbt-text").value);
    if (isPsbtMagic(bytes)) output.innerHTML = hodlRenderPsbt(hodlParsePsbt(bytes));
    else output.innerHTML = hodlRenderRawTx(parseRawTx(bytes));
  } catch (exception) {
    error.textContent = exception instanceof Error ? exception.message : String(exception);
  }
}

var hodlSpHd = null, hodlSpKeys = null, hodlSpNote = "No session key. Receive and verify need a seed or root xprv.", hodlSpMode = "receive", hodlSpReveal = false;
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
    let parsed = uf(value.replace(/\s/g, ""));
    if (!parsed.isPrivate) throw new Error("Watch-only extended keys cannot derive BIP-352 scan/spend paths.");
    if (parsed.node.depth !== 0) throw new Error("Silent Payments needs a BIP32 root private key (depth 0), not an account xprv.");
    hodlSpHd = parsed.node;
    hodlSpNote = `Session key: root ${parsed.prefix}. Kept in page memory only.`;
    return;
  }
  let mnemonic = Mt(value);
  if (!mnemonic.ok) throw new Error(mnemonic.error || "Enter a BIP39 seed phrase or a BIP32 root xprv/tprv.");
  let seed = wi(mnemonic.words.join(" "), passphrase || "");
  try {
    hodlSpHd = Gt.fromMasterSeed(seed);
  } finally {
    seed.fill(0);
  }
  hodlSpNote = "Session key: BIP39 seed" + (passphrase ? " + passphrase" : "") + ". Kept in page memory only.";
}
function hodlSpUseActiveKey() {
  let state = hodlKeys[hodlActiveKey];
  if (!state || !state.result) throw new Error("Generate an active key first, then return to Silent Payments.");
  let result = state.result;
  hodlSpWipeKeys();
  if (result.kind === "hd" && result.mnemonic) {
    let seed = wi(result.mnemonic, state.fields.pass || "");
    try { hodlSpHd = Gt.fromMasterSeed(seed); } finally { seed.fill(0); }
    hodlSpNote = "Session key from " + (state.name || "the active key") + " (BIP39 seed). Kept in page memory only.";
  } else if (result.kind === "hd" && result.rootXprv) {
    hodlSpHd = Gt.fromExtendedKey(uf(result.rootXprv).xkey);
    hodlSpNote = "Session key from " + (state.name || "the active key") + " (root xprv). Kept in page memory only.";
  } else throw new Error("Silent Payments needs the active key's seed or root xprv. Account-level and single keys cannot derive m/352'.");
}
function hodlSpEnsureHd() {
  let manual = document.getElementById("sp-key")?.value;
  if (manual && manual.trim()) {
    hodlSpLoadKey(manual, document.getElementById("sp-pass")?.value);
    document.getElementById("sp-key").value = "";
    document.getElementById("sp-pass").value = "";
  }
  if (!hodlSpHd || !hodlSpHd.privateKey) throw new Error("Load a BIP39 seed or root xprv first (or use the active key).");
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
    scanPub: xe.getPublicKey(scanNode.privateKey, true),
    spendPub: xe.getPublicKey(spendNode.privateKey, true),
    fingerprint: Us(root.fingerprint),
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
  let lines = String(text || "").split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
  if (!lines.length) throw new Error("Paste at least one silent payment address.");
  return lines.map((line) => {
    let match = line.match(/^(sp1[0-9a-z]+|tsp1[0-9a-z]+)(?:\s+(\d+))?$/i);
    if (!match) throw new Error(`Not a silent payment address: ${line.slice(0, 24)}`);
    return { address: match[1].toLowerCase(), count: match[2] ? Number(match[2]) : 1 };
  });
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
  let scanPoint = xe.Point.fromBytes(hodlSpKeys.scanPub);
  let spendPoint = xe.Point.fromBytes(hodlSpKeys.spendPub);
  let address = labeled ? createLabeledSilentPaymentAddress(hodlSpKeys.scanPriv, spendPoint, m, hrp) : encodeSilentPaymentAddress(scanPoint, spendPoint, hrp);
  let spscan = encodeSpscan(hodlSpKeys.scanPriv, hodlSpKeys.spendPub, hodlSpNetwork());
  let spspend = encodeSpspend(hodlSpKeys.scanPriv, hodlSpKeys.spendPriv, hodlSpNetwork());
  let origin = `${hodlSpKeys.fingerprint}/352h/${hodlSpCoinType()}h/${hodlSpAccount()}h`;
  let qr = an(address);
  let secrets = hodlSpReveal;
  document.getElementById("sp-out").innerHTML = `
    <div class="sp-result">
      <p class="label">Reusable silent payment address${labeled ? ` · label m = ${m}${m === 0 ? " (change)" : ""}` : ""}</p>
      <div class="sp-qr">${qr}</div>
      <p class="psbt-kv" id="sp-address-value">${hodlSpEscape(address)}</p>
      ${hodlSpCopyButton("sp-address-value", "Copy address")}
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
  let recipients = hodlSpParseRecipients(document.getElementById("sp-recipients")?.value);
  let hrp = hodlSpHrp(hodlSpNetwork());
  for (const recipient of recipients) decodeSilentPaymentAddress(recipient.address, hrp);
  let result = createSilentPaymentOutputs(hodlSpParseVins(document.getElementById("sp-send-vins")?.value), recipients, { hrp });
  if (!result.outputs.length) {
    document.getElementById("sp-out").innerHTML = `<p class="psbt-warn">No silent payment outputs. Eligible inputs may be missing, the private-key sum may be zero, or a scan-key group exceeded K<sub>max</sub> = 2323.</p>`;
    return;
  }
  let network = hodlSpNetwork();
  document.getElementById("sp-out").innerHTML = `<p class="psbt-ok">${result.outputs.length} unique taproot output${result.outputs.length === 1 ? "" : "s"}.</p>` + result.outputs.map((xonly, index) => {
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
  } catch (exception) {
    error.textContent = exception instanceof Error ? exception.message : String(exception);
  }
}
function hodlInitSp() {
  if (!document.getElementById("sp-card")) return;
  document.querySelectorAll("#sp-modes [data-sp-mode]").forEach((button) => {
    button.onclick = () => { hodlSpSetMode(button.dataset.spMode); document.getElementById("sp-out").innerHTML = ""; document.getElementById("sp-error").textContent = ""; };
  });
  document.getElementById("sp-derive").onclick = () => { hodlSpMode = "receive"; hodlRunSp(); };
  document.getElementById("sp-send-go").onclick = () => { hodlSpMode = "send"; hodlRunSp(); };
  document.getElementById("sp-verify-go").onclick = () => { hodlSpMode = "verify"; hodlRunSp(); };
  document.getElementById("sp-use-calc").onclick = () => {
    document.getElementById("sp-error").textContent = "";
    try {
      hodlSpUseActiveKey();
      document.getElementById("sp-key").value = "";
      document.getElementById("sp-pass").value = "";
      document.getElementById("sp-session").textContent = hodlSpNote;
    } catch (exception) {
      document.getElementById("sp-error").textContent = exception.message || String(exception);
    }
  };
  document.getElementById("sp-wipe").onclick = () => {
    hodlSpWipeMem();
    ["sp-key", "sp-pass", "sp-recipients", "sp-send-vins", "sp-verify-vins", "sp-verify-outputs", "sp-label"].forEach((id) => {
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
  let tagHash = Z(new TextEncoder().encode(tag)), total = 64;
  for (let chunk of chunks) total += chunk.length;
  let bytes = new Uint8Array(total);
  bytes.set(tagHash, 0);
  bytes.set(tagHash, 32);
  let offset = 64;
  for (let chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.length;
  }
  return Z(bytes);
}
function hodlBytesToBig(bytes) {
  return BigInt("0x" + M.encode(bytes));
}
function hodlPointFrom(bytes) {
  let Point = xe.Point;
  if (typeof Point.fromBytes === "function") return Point.fromBytes(bytes);
  if (typeof Point.fromHex === "function") return Point.fromHex(M.encode(bytes));
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
      host = M.decode(token.toLowerCase());
    } else if (token.length === 66) {
      let opening = M.decode(token.toLowerCase());
      if (opening[0] !== 2 && opening[0] !== 3) throw new Error("Jade opening R must be a compressed secp256k1 point.");
      openings.push(opening);
    } else if (token.length === 130) {
      if (host || openings.length) throw new Error("Paste the host nonce and opening once, or as separate hex values.");
      host = M.decode(token.slice(0, 64).toLowerCase());
      let opening = M.decode(token.slice(64).toLowerCase());
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
  let committed = hodlPointFrom(opening).add(xe.Point.BASE.multiply(tweakInt)), xBytes = hodlPointBytes(committed, true).slice(1);
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
  let plain = xe.sign(sighash, privateKey, { prehash: false, extraEntropy: false });
  if (hodlEq(plain.slice(0, 32), r)) {
    return hodlIsLowR(r) ? { ok: true, className: "psbt-ok", message: "Matches RFC 6979 (plain deterministic nonce)." } : { ok: true, className: "psbt-ok", message: "Matches RFC 6979 (plain deterministic nonce). r is high; Bitcoin Core would grind this one." };
  }
  for (let n = 1; n <= 64; n++) {
    let expected = xe.sign(sighash, privateKey, { prehash: false, extraEntropy: hodlLe32Counter(n) });
    if (hodlEq(expected.slice(0, 32), r)) {
      return { ok: true, className: "psbt-ok", message: "Matches RFC 6979 with Bitcoin Core-style low-r grind (retry " + n + "). Saves one byte. Not a leak." };
    }
  }
  let zeros = xe.sign(sighash, privateKey, { prehash: false, extraEntropy: new Uint8Array(32) });
  if (hodlEq(zeros.slice(0, 32), r)) {
    return { ok: true, className: "psbt-ok", message: "Matches RFC 6979 with 32 zero extra-entropy bytes (some libraries mix this in)." };
  }
  return { ok: false, className: "psbt-warn", message: "Does not match plain RFC 6979 or Bitcoin Core-style low-r grind. Honest signers may add other auxiliary randomness. A mismatch alone is not evidence of compromise. Reused r on two different messages is the real alarm." };
}
function hodlSessionOwnership(network) {
  if (hodlPsbtHd) return indexHdKey(hodlPsbtHd, network);
  if (hodlPsbtPriv) return indexSingleKey(hodlPsbtPriv, network, (key, compressed) => xe.getPublicKey(key, compressed));
  return new Map();
}
function hodlDeclaredOutput(entries, script, network) {
  if (!hodlPsbtHd || !entries || !script) return null;
  let fingerprint = Us(hodlPsbtHd.fingerprint), declared = null;
  for (let entry of hodlFind(entries, 2)) {
    if (entry.val.length < 4 || (entry.val.length - 4) % 4) continue;
    let fp = M.encode(entry.val.slice(0, 4));
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
          if (hodlAddressesEqual(address, pf(scriptType, node.publicKey, network))) encoded = true;
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
    return "<p class='" + (opReturn.ok ? "psbt-warn" : "psbt-bad") + "'><strong>Output " + index + "</strong> \xB7 " + hodlSats(output.amount) + " BTC<br>" + lines.map($t).join("<br>") + "</p>";
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
    extra = "<br><strong>PSBT lies:</strong> claims " + $t(declared.path) + " but this session key does not produce this output. Do not sign.";
    className = "psbt-bad";
  } else if (scan.state === "ours") {
    let label = scan.role === "change" ? "change" : scan.role === "receive" ? "receive (this wallet)" : "this session key";
    extra = "<br>" + $t(label + " \xB7 " + scan.path);
    className = scan.role === "change" || scan.role === "key" ? "psbt-ok" : "psbt-kv";
  } else if (declared && declared.state === "ours") {
    extra = "<br>" + $t((declared.role === "change" ? "change" : "this wallet") + " \xB7 " + declared.path + " (verified)");
    className = "psbt-ok";
  } else if (scan.state === "external") {
    extra = "<br>not in this wallet (accounts 0\u20132, 50 receive + 50 change, four script types)";
  } else if (scan.state === "no-session") {
    extra = "<br><span class='muted'>Load a session key to see if this output is yours.</span>";
  }
  return "<p class='" + className + "'><strong>Output " + index + "</strong> \xB7 " + hodlSats(output.amount) + " BTC<br>" + $t(address) + extra + "</p>";
}
function hodlOwnershipWarning(outputs, network, map) {
  if (!map || !map.size) return "";
  let ours = outputs.some((output) => matchOwnership(map, output.script).state === "ours" || matchOwnership(map, hodlAddr(output.script, network)).state === "ours");
  if (ours) return "<p class='muted'>Session key: outputs compared against " + map.size + " derived scripts (accounts 0\u20132, 50 receive + 50 change, four types).</p>";
  if (outputs.length < 2) return "<p class='muted'>This output is not in the session wallet (accounts 0\u20132, 50 receive + 50 change, four script types).</p>";
  return "<p class='psbt-bad'><strong>No output belongs to this session wallet.</strong> If you expected change, do not sign. A destination-swap can replace both the payment and the change.</p>";
}
function hodlRenderPsbt(psbt) {
  // psbt-network is a mainnet/testnet select, not a numeric coin-type input,
  // so hodlSelectedNetwork (which reads coin types) cannot parse it.
  let network = document.getElementById("psbt-network")?.value === "testnet" ? "testnet" : "mainnet",
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
    uninspected = 0;
  let inscriptionReport = { inputs: [], envelopes: [] };
  try {
    inscriptionReport = inspectPsbtInscriptions(psbt);
  } catch {
    inscriptionReport = { inputs: [], envelopes: [] };
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
    html.push("<p class='psbt-kv'><strong>Input " + index + "</strong> \xB7 " + hodlHexRev(previous.txid) + " : " + previous.vout + (witnessUtxo ? " \xB7 " + hodlSats(witnessUtxo.amount) + " BTC claimed" : "") + "<br>" + $t(destination) + "<br>" + (signatures.length + tapSignatures.length ? signatures.length + tapSignatures.length + " signature(s) present" : finalized ? "Finalized input data present" : "Not signed yet") + (declaredSighashError ? "<br>Declared sighash policy unreadable: " + $t(declaredSighashError) : "<br>Signature policy: " + $t(declaredLabel)) + "</p>");
    let inputEnvelopes = (inscriptionReport.inputs[index] && inscriptionReport.inputs[index].envelopes) || [];
    inputEnvelopes.forEach((envelope) => {
      let className = envelope.unrecognizedEven || envelope.bodyBytes > 100000 ? "psbt-bad" : "psbt-warn";
      html.push("<p class='" + className + "'><strong>Inscription envelope</strong> \xB7 input " + index + " \xB7 #" + envelope.envelopeIndex + " \xB7 " + $t(envelope.source) + "<br>" + describeEnvelope(envelope).map($t).join("<br>") + "</p>");
    });
    if (declaredSighashError) html.push("<p class='psbt-bad'><strong>Policy problem:</strong> input " + index + " declares a malformed sighash policy. Do not sign until its policy is known.</p>");
    else if (declaredSighash !== null && declaredSighash !== 1) html.push("<p class='psbt-bad'><strong>Policy problem:</strong> input " + index + " requests " + $t(declaredLabel) + "; that policy does not commit to all shown outputs. Do not accept the displayed outputs as what a signature will authorize.</p>");
    signatures.forEach(signature => {
      let parts = hodlSigParts(signature.der),
        looseR = parts ? parts.r : hodlDerRLoose(signature.der),
        scriptCode = hodlInputScriptCode(entries, witnessUtxo),
        sighash = witnessUtxo && scriptCode ? hodlBip143(tx, index, scriptCode, witnessUtxo.amount, signature.sighash) : null,
        signatureValid = parts && sighash ? xe.verify(signature.der, sighash, signature.pubkey, {
          prehash: !1,
          format: "der",
          lowS: !1
        }) : null,
        privateKey = hodlPrivForPub(signature.pubkey) || hodlPrivFromPath(entries, signature.pubkey),
        message = "Need the matching key in this session to check RFC 6979 and low-r grind.",
        className = "muted";
      let suffixForPolicy = signature.raw.length >= 2 ? signature.sighash : null,
        sighashProblems = hodlSighashProblems(declaredSighash, suffixForPolicy);
      if (!parts && !looseR) {
        uninspected += 1;
        message = "Signature is not DER and its nonce cannot be inspected.";
        className = "psbt-warn";
        if (sighashProblems.length) {
          message = "Signature policy problem: " + sighashProblems.join(" ");
          className = "psbt-bad";
        }
      } else {
        rValues.push({
          input: index,
          r: looseR,
          hex: M.encode(looseR),
          pubkey: hodlPubId(signature.pubkey),
          sighash,
          valid: parts ? signatureValid : null
        });
        if (sighashProblems.length) {
          // An unsafe or conflicting sighash policy blocks every other check.
          message = "Signature policy problem: " + sighashProblems.join(" ");
          className = "psbt-bad";
        } else if (!parts) {
          message = "Signature is not strict DER. Its r value is still compared for nonce reuse.";
          className = "psbt-warn"
        } else if (signatureValid === !1) {
          message = "This signature does not verify against the reconstructed input digest.";
          className = "psbt-warn";
        } else if (transcript) {
          let opening = transcript.openings.length === 1 ? transcript.openings[0] : transcript.openings[ecdsaIndex];
          if (!opening) {
            message = "No Jade opening R was provided for this signature.";
            className = "psbt-warn";
          } else try {
            if (hodlAntiExfilCommitOk(parts.r, opening, transcript.host)) {
              message = "Matches Jade anti-exfil (sign-to-contract). Host entropy mixed into the nonce. Not a leak.";
              className = "psbt-ok";
            } else {
              message = "Does not match this Jade anti-exfil transcript. Signature r is not R + H(R||\u03C1)G.";
              className = "psbt-warn";
              if (privateKey && sighash) try {
                let cmp = hodlRfc6979Compare(sighash, privateKey, parts.r);
                if (cmp.ok) {
                  message += " " + cmp.message;
                  className = cmp.className;
                } else message += " Also does not match RFC 6979 or low-r grind.";
              } catch (exception) {
                message += " " + (exception.message || String(exception));
              }
            }
          } catch (exception) {
            message = "Could not verify Jade anti-exfil: " + (exception.message || String(exception));
            className = "psbt-warn";
          }
        } else if (privateKey && sighash) try {
          let cmp = hodlRfc6979Compare(sighash, privateKey, parts.r);
          message = cmp.message;
          className = cmp.className;
        } catch (exception) {
          message = "Could not recompute this signature: " + (exception.message || String(exception));
          className = "psbt-warn";
        }
        else if (privateKey && !scriptCode) {
          message = "Matching key found, but this input script is not yet supported for RFC 6979 comparison.";
          className = "psbt-warn";
        }
      }
      ecdsaIndex += 1;
      rows.push({ input: index, message, className, pubkey: M.encode(signature.pubkey) });
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
  if (transcriptError) html.push("<p class='psbt-warn'><strong>Jade anti-exfil transcript not used:</strong> " + $t(transcriptError) + "</p>");
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
  if (rValues.length) html.push("<p class='psbt-kv'>r values:<br>" + rValues.map(value => $t(value.hex) + " (input " + value.input + ")").join("<br>") + "</p>");
  rows.forEach(row => html.push("<p class='" + row.className + "'><strong>Input " + row.input + "</strong> pubkey " + $t(row.pubkey.slice(0, 18)) + "\u2026 \u2014 " + $t(row.message) + "</p>"));
  if (tapSignatureCount) html.push("<p class='muted'>This PSBT also contains " + tapSignatureCount + " Taproot / Schnorr signature(s). They are counted but their BIP340 nonces are not analyzed in this version.</p>");
  html.push("<p class='muted'>RFC 6979 comparison currently covers SegWit v0 P2WPKH and P2WSH signatures using SIGHASH_ALL, including Bitcoin Core-style low-r grinding. Jade anti-exfil is secp256k1-zkp sign-to-contract and needs the USB host nonce plus signer opening; QR / sign_psbt Jade does not run it yet. BitBox anti-klepto is a different construction. Nonce reuse detection compares r values for the same secp256k1 point, including signatures carried by finalized scriptSig/witness fields, compressed and uncompressed encodings, and recoverable non-strict DER. A clean verdict is not issued when a signature cannot be inspected. Inscription detection reads OP_FALSE OP_IF \"ord\" envelopes in tap-leaf scripts and finalized witnesses; it does not number sats. Output ownership is derived from the session key: accounts 0\u20132, 50 receive + 50 change, all four script types. It does not talk to the chain.</p>");
  return html.join("")
}
function hodlRenderRawTx(tx) {
  // psbt-network is a mainnet/testnet select, not a numeric coin-type input,
  // so hodlSelectedNetwork (which reads coin types) cannot parse it.
  let network = document.getElementById("psbt-network")?.value === "testnet" ? "testnet" : "mainnet",
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
    html.push("<p class='psbt-kv'><strong>Input " + index + "</strong> \xB7 " + hodlHexRev(input.txid) + " : " + input.vout + "<br>sequence " + $t("0x" + input.sequence.toString(16)) + (input.sequence < 0xfffffffe ? " \xB7 RBF-capable" : "") + "</p>");
  });
  inscriptionHints(tx).forEach((hint) => {
    html.push("<p class='psbt-warn'><strong>Inscription envelope</strong> in input " + hint.input + " (" + hint.bytes + " bytes of script/witness). This transaction reveals OP_FALSE OP_IF \"ord\" data.</p>");
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
      hex: M.encode(looseR),
      pubkey: hodlPubId(signature.pubkey),
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
  if (rValues.length) html.push("<p class='psbt-kv'>r values:<br>" + rValues.map((value) => $t(value.hex) + " (input " + value.input + ")").join("<br>") + "</p>");
  html.push("<p class='muted'>Raw-transaction inspect does not reconstruct sighashes. Paste the PSBT when you still can; use this path for a fully signed hex dump from a hardware wallet or Bitcoin Core.</p>");
  return html.join("");
}
var hodlAccountId = "bip84",
  hodlNextKeyId = 1,
  hodlNextKeyNumber = 1,
  hodlKeys = [],
  hodlActiveKey = -1;

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
  return { id, number, color: hodlKeyColor(id), name: name || hodlDefaultKeyName(number), mode: "dice", diceMethod: "coldcard", cardMethod: "hashed", seedMethod: "words", seedZeroIndexed: false, cardColemanSymbols: false, entropyFormat: "bin", globalSync: false, globalSyncSource: "", globalSyncBitCount: 0, seedAutocomplete: true, passphraseBip39Words: false, brainWalletOutput: "scalar", passphraseAutocomplete: true, brainWalletTrim: false, showCards: false, showDiceFairness: false, targetWords: 24, diceCoinPositions: [], lastWord: "", dplusLastWord: "", result: null, reveal: false, accountId: "bip84", error: "", fields: { pass: "", script: "bip84", derivationPath: "m/84'/0'/0'/0/0", derivationAccountPath: "m/84'/0'/0'", purpose: "84'", purposeHarden: true, coinType: "0'", coinTypeHarden: true, network: "mainnet", account: "0'", accountHarden: true, branchStart: "0", branchHarden: false, branchRange: "1", addressStart: "0", addressHarden: false, addressRange: "1", dice: "", bitboxDice: "", dplusDice: "", hex: "", bin: "", base4: "", base8: "", base32: "", base64: "", cards: "", directCards: "", seed: "", seedNumbers: "", brainLab: "", key: "", keyKind: "wif", privateKeys: { wif: "", "hex-key": "", minikey: "", brain: "" } } };
}
function hodlNewLabState() {
  let state = hodlNewKeyState("Key Lab", 0, 0);
  state.isLab = true;
  return state;
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
  if (!image || !fingerprint || typeof hodlLifeHash?.fromFingerprint !== "function") return;
  hodlLifeHash.fromFingerprint(fingerprint).then((url) => {
    if (!image.isConnected) return;
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
  if (edit) edit.onclick = hodlSelectLab;
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
      el.value = id === "dice" ? ge === "dplus" ? state.fields.dplusDice || "" : ge === "bitbox" ? state.fields.bitboxDice || "" : state.fields.dice || "" : id === "key" ? privateKeys[restoredKeyKind] || "" : id === "direct-cards" ? state.fields.directCards || "" : id === "seed-numbers" ? state.fields.seedNumbers || "" : state.fields[id] || "";
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
  Ne = mode;
  hodlSeedMethod = hodlNormalizeSeedMethod(state?.seedMethod);
  hodlSeedZeroIndexed = Boolean(state?.seedZeroIndexed);
  hodlEntropyFormat = hodlNormalizeEntropyFormat(state?.entropyFormat);
  [...Zs.children].forEach((button, index) => {
    let active = hodlKeyModes[index] === Ne;
    button.classList.toggle("active", active);
    button.setAttribute("aria-pressed", String(active));
  });
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
}
function hodlCaptureKey() {
  if (hodlActiveKey < 0 || !hodlKeys[hodlActiveKey]) return;
  let state = hodlKeys[hodlActiveKey];
  state.mode = Ne;
  state.diceMethod = ge;
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
  state.targetWords = Pt;
  state.diceCoinPositions = hodlDiceCoinPositions.slice();
  if (ge === "dplus") state.dplusLastWord = ft;
  else if (ge === "bitbox") state.lastWord = ft;
  state.result = re;
  state.reveal = Ge;
  state.accountId = hodlSelectedScriptType();
  state.fields.script = state.accountId;
  state.error = document.getElementById("error")?.textContent || "";
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
  if (dice) state.fields[ge === "dplus" ? "dplusDice" : ge === "bitbox" ? "bitboxDice" : "dice"] = dice.value;
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
    Ne = "dice";
    ge = "coldcard";
    hodlCardMethod = "hashed";
    hodlSeedMethod = "words";
    hodlSeedZeroIndexed = false;
    hodlCardColemanSymbols = false;
    hodlEntropyFormat = "bin";
    Pt = 24;
    hodlDiceCoinPositions = [];
    ft = "";
    re = null;
    Ge = false;
    hodlAccountId = "bip84";
    [...Zs.children].forEach((button, index) => {
      let active = index === 0;
      button.classList.toggle("active", active);
      button.setAttribute("aria-pressed", String(active));
    });
    hodlRenderKeyForm();
    let pass2 = document.getElementById("pass");
    if (pass2) {
      pass2.value = "";
      hodlRenderPassphraseInputState(pass2, false);
    }
    hodlSyncSelect(document.getElementById("script-type"), "bip84");
    hodlSetPurpose(84);
    let network2 = document.getElementById("network");
    if (network2) network2.value = "0";
    hodlUpdateCoinTypeHelp(network2);
    let account2 = document.getElementById("account");
    if (account2) account2.value = "0";
    let derivationPath2 = document.getElementById("derivation-path");
    if (derivationPath2) {
      derivationPath2.value = "m/84'/0'/0'/0/0";
      derivationPath2.dataset.accountPath = "m/84'/0'/0'";
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
    W("#error").textContent = "";
    dr.innerHTML = "";
    document.getElementById("calc-card").hidden = true;
    hodlSyncKeyResultView();
    hodlQueueMasterFingerprintPreview(0);
    hodlUpdateDerivationPathPreview();
    hodlSyncKeyClearButton();
    hodlSyncDeriveButton();
    return;
  }
  Ne = state.mode;
  ge = state.diceMethod;
  hodlCardMethod = state.cardMethod === "direct" ? "direct" : "hashed";
  hodlSeedMethod = hodlNormalizeSeedMethod(state.seedMethod);
  hodlSeedZeroIndexed = Boolean(state.seedZeroIndexed);
  hodlCardColemanSymbols = Boolean(state.cardColemanSymbols);
  hodlEntropyFormat = hodlNormalizeEntropyFormat(state.entropyFormat);
  Pt = hodlSeedLengths[Number(state.targetWords)] ? Number(state.targetWords) : 24;
  hodlDiceCoinPositions = hodlNormalizeDiceCoinPositions(state.diceCoinPositions);
  ft = ge === "dplus" ? state.dplusLastWord || "" : ge === "bitbox" ? state.lastWord || "" : "";
  [...Zs.children].forEach((button, index) => {
    let active = hodlKeyModes[index] === Ne;
    button.classList.toggle("active", active);
    button.setAttribute("aria-pressed", String(active));
  });
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
  re = state.result;
  Ge = state.reveal;
  document.getElementById("calc-card").hidden = false;
  W("#error").textContent = state.error || "";
  tc();
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
  W("#key-tabs").children[next]?.focus();
}
var hodlKeySilhouette = "M512 176c0 97.2-78.8 176-176 176-11.2 0-22.2-1.1-32.8-3.1l-24 27c-4.4 4.9-10.8 8.1-17.9 8.1H224v40c0 13.3-10.7 24-24 24h-40v40c0 13.3-10.7 24-24 24H24c-13.3 0-24-10.7-24-24v-78.1c0-6.4 2.5-12.5 7-17l161.8-161.8c-5.7-17.4-8.8-35.9-8.8-55.2C160 78.8 238.8 0 336 0s176 78.8 176 176zM374 112a54 54 0 1 0 0 108 54 54 0 1 0 0-108z";
function hodlCreateKeyIcon(color) {
  let ns = "http://www.w3.org/2000/svg", span = document.createElement("span"), svg = document.createElementNS(ns, "svg"), path = document.createElementNS(ns, "path");
  span.className = "key-tab-icon";
  span.style.color = color;
  span.setAttribute("aria-hidden", "true");
  svg.setAttribute("viewBox", "0 0 512 512");
  svg.setAttribute("fill", "currentColor");
  svg.setAttribute("focusable", "false");
  svg.setAttribute("aria-hidden", "true");
  path.setAttribute("data-part", "key-silhouette");
  path.setAttribute("fill-rule", "evenodd");
  path.setAttribute("clip-rule", "evenodd");
  path.setAttribute("d", hodlKeySilhouette);
  svg.appendChild(path);
  span.appendChild(svg);
  return span;
}
function hodlCreateMsigIcon() {
  let ns = "http://www.w3.org/2000/svg", darkest = "#4b4f55", middle = "#888d94", span = document.createElement("span"), svg = document.createElementNS(ns, "svg");
  span.className = "multisig-tab-icon";
  span.setAttribute("aria-hidden", "true");
  svg.setAttribute("viewBox", "0 -4 49 40");
  svg.setAttribute("focusable", "false");
  svg.setAttribute("aria-hidden", "true");
  svg.setAttribute("data-keyhole-cx", "34");
  svg.setAttribute("data-keyhole-cy", "10.5");
  svg.setAttribute("data-keyhole-r", "2.808");
  let ring = document.createElementNS(ns, "path");
  ring.setAttribute("data-part", "keychain-ring");
  ring.setAttribute("d", "M32.14 7.53 A7.78 7.78 0 1 1 36.97 12.36");
  ring.setAttribute("fill", "none");
  ring.setAttribute("stroke", middle);
  ring.setAttribute("stroke-width", "1.7");
  ring.setAttribute("stroke-linecap", "round");
  ring.setAttribute("stroke-linejoin", "round");
  svg.appendChild(ring);
  [["key-back", darkest, -28], ["key-middle", middle, 0], ["key-front", "#d1d4d8", 28]].forEach(([part, fill, angle]) => {
    let path = document.createElementNS(ns, "path");
    path.setAttribute("data-part", part);
    path.setAttribute("d", hodlKeySilhouette);
    path.setAttribute("fill", fill);
    path.setAttribute("fill-rule", "evenodd");
    path.setAttribute("clip-rule", "evenodd");
    path.setAttribute("transform", "translate(34 10.5) rotate(" + angle + ") scale(.052) translate(-374 -166)");
    svg.appendChild(path);
  });
  let thread = document.createElementNS(ns, "path");
  thread.setAttribute("data-part", "keychain-thread");
  thread.setAttribute("d", "M36.97 12.36 A7.78 7.78 0 0 0 45 10.5");
  thread.setAttribute("fill", "none");
  thread.setAttribute("stroke", middle);
  thread.setAttribute("stroke-width", "1.7");
  thread.setAttribute("stroke-linecap", "round");
  thread.setAttribute("stroke-linejoin", "round");
  svg.appendChild(thread);
  span.appendChild(svg);
  return span;
}
function hodlCreateLabIcon() {
  let span = document.createElement("span"), source = document.querySelector(".site-logo");
  span.className = "key-tab-icon key-tab-lab-icon";
  span.setAttribute("aria-hidden", "true");
  if (source) source.querySelectorAll("svg").forEach((svg) => span.appendChild(svg.cloneNode(true)));
  return span;
}
function hodlCreateKeyTab(index) {
  let state = hodlKeys[index], active = index === hodlActiveKey, button = document.createElement("button"), fingerprint = state.result?.masterFingerprint || "", name = state.isLab ? "Key Lab" : fingerprint || state.name || "Key " + state.number, label = document.createElement("span");
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
  } else button.append(hodlCreateKeyIcon(state.color), label);
  button.dataset.keyNumber = String(state.number);
  button.setAttribute("role", "tab");
  button.setAttribute("aria-controls", "calc-card");
  button.setAttribute("aria-selected", String(active));
  if (state.isLab) {
    button.setAttribute("aria-label", "Key Lab" + (active ? ", selected" : ". Activate to derive a key."));
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
  let base = "Key " + number, name = base, suffix = 2;
  while (hodlKeyNameTaken(name, -1)) {
    name = base + " (" + suffix + ")";
    suffix++;
  }
  return name;
}
function hodlBeginKeyRename(index) {
  if (index !== hodlActiveKey || !hodlKeys[index] || hodlKeys[index].isLab) return;
  let box = W("#key-tabs"), tab = box.children[index];
  if (!tab || tab.classList.contains("key-tab-editing")) return;
  let state = hodlKeys[index], editor = document.createElement("div"), input = document.createElement("input"), previous = state.name || "Key " + state.number;
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
    if (commit && name && !hodlKeyNameTaken(name, index)) state.name = name;
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
  editor.append(hodlCreateKeyIcon(state.color), input);
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
  let button = W("#delete-key"), state = hodlKeys[hodlActiveKey];
  if (!button) return;
  button.disabled = !state || state.isLab;
  button.setAttribute("aria-disabled", String(button.disabled));
}
function hodlRenderKeyTabs() {
  let box = W("#key-tabs"), panel = W("#calc-card");
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
}
function hodlSelectKey(index) {
  if (index === hodlActiveKey || !hodlKeys[index]) return;
  hodlCaptureKey();
  hodlActiveKey = index;
  hodlRenderKeyTabs();
  hodlRestoreKey();
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
  let deletedIndex = hodlActiveKey, deletedState = state;
  hodlKeys.splice(deletedIndex, 1);
  hodlNextKeyNumber = hodlKeys.length ? hodlKeys.reduce((latest, state) => Math.max(latest, state.number), 0) + 1 : deletedState.number;
  if (!hodlKeys.length) {
    hodlKeys.push(hodlNewLabState());
    hodlActiveKey = 0;
  } else hodlActiveKey = Math.min(deletedIndex, hodlKeys.length - 1);
  hodlRenderKeyTabs();
  hodlRestoreKey();
  (hodlActiveKey >= 0 ? W("#key-tabs").children[hodlActiveKey] : W("#add-key"))?.focus();
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
      xpubs: ["", "", ""],
      coinType: "0",
      coinTypeHarden: true,
      network: "mainnet",
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
  let state = hodlNewMsigState("Multisig Lab", 0, 0);
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
  if (edit) edit.onclick = hodlSelectMsigLab;
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
function hodlMsigStateNeedsClear(state) {
  if (!state) return !1;
  let fields = state.fields || {},
    xpubs = Array.isArray(fields.xpubs) ? fields.xpubs : [];
  return Boolean(state.result) || String(state.error ?? "").length > 0 || xpubs.some(value => String(value ?? "").length > 0) ||
    String(fields.m ?? "2") !== "2" || String(fields.n ?? "3") !== "3" || String(fields.script ?? "p2wsh") !== "p2wsh" || String(fields.purpose ?? "48") !== "48" || fields.purposeHarden === false || Boolean(fields.legacyBip87) || String(fields.keyOrder ?? "sorted") !== "sorted" || String(fields.coinType ?? (fields.network === "testnet" ? "1" : "0")) !== "0" || fields.coinTypeHarden === false || fields.accountHarden === false || String(fields.branchStart ?? "0") !== "0" || Boolean(fields.branchHarden) || String(fields.branchRange ?? "2") !== "2" || String(fields.addressStart ?? "0") !== "0" || Boolean(fields.addressHarden) || String(fields.addressRange ?? fields.count ?? "5") !== "5"
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
  state.result = re && re.kind === "msig" ? re : null;
  state.error = document.getElementById("msig-error").textContent || "";
}
function hodlRestoreMsig() {
  let state = hodlMsigs[hodlActiveMsig], panel = document.getElementById("msig-card");
  if (!state) {
    re = null;
    Ge = false;
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
  document.getElementById("msig-error").textContent = state.error || "";
  re = state.result;
  Ge = false;
  panel.hidden = false;
  if (re && re.kind === "msig") hodlShowMsig();
  else hodlClearMsigOut();
  hodlSyncMsigResultView();
  hodlSyncMsigClearButton();
}
function hodlWipeActiveMsig() {
  if (hodlActiveMsig < 0 || !hodlMsigs[hodlActiveMsig]) return;
  let state = hodlMsigs[hodlActiveMsig];
  hodlMsigs[hodlActiveMsig] = state.isLab ? hodlNewMsigLabState() : hodlNewMsigState(state.name, state.id, state.number);
  hodlRestoreMsig();
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
  W("#msig-tabs").children[next]?.focus();
}
function hodlCreateMsigTab(index) {
  let state = hodlMsigs[index], active = index === hodlActiveMsig, button = document.createElement("button"), name = state.isLab ? "Multisig Lab" : state.createdPolicy || state.name || "Multisig " + state.number, label = document.createElement("span");
  button.type = "button";
  button.id = state.isLab ? "msig-tab-lab" : "msig-tab-" + (index + 1);
  button.className = "tab key-tab msig-tab" + (state.isLab ? " is-lab" : "") + (active ? " active" : "");
  button.dataset.msigNumber = String(state.number);
  label.className = "key-tab-label";
  label.textContent = name;
  button.append(state.isLab ? hodlCreateLabIcon() : hodlCreateMsigIcon(), label);
  button.setAttribute("role", "tab");
  button.setAttribute("aria-controls", "msig-card");
  button.setAttribute("aria-selected", String(active));
  if (state.isLab) {
    button.setAttribute("aria-label", "Multisig Lab" + (active ? ", selected" : ". Activate to derive a multisig."));
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
  let base = "Multisig " + number, name = base, suffix = 2;
  while (hodlMsigNameTaken(name, -1)) {
    name = base + " (" + suffix + ")";
    suffix++;
  }
  return name;
}
function hodlBeginMsigRename(index) {
  if (index !== hodlActiveMsig || !hodlMsigs[index] || hodlMsigs[index].isLab) return;
  let box = W("#msig-tabs"), tab = box.children[index];
  if (!tab || tab.classList.contains("key-tab-editing")) return;
  let state = hodlMsigs[index], editor = document.createElement("div"), input = document.createElement("input"), previous = state.name || "Multisig " + state.number;
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
    if (commit && name && !hodlMsigNameTaken(name, index)) state.name = name;
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
  let button = W("#delete-msig"), state = hodlMsigs[hodlActiveMsig];
  if (!button) return;
  button.disabled = !state || state.isLab;
  button.setAttribute("aria-disabled", String(button.disabled));
}
function hodlRenderMsigTabs() {
  let box = W("#msig-tabs"), panel = W("#msig-card");
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
  (hodlActiveMsig >= 0 ? W("#msig-tabs").children[hodlActiveMsig] : W("#add-msig"))?.focus();
}
function hodlShowWorkspace(id) {
  if (id === hodlWorkspace) return;
  let preservedTop = window.scrollY, preservedLeft = window.scrollX;
  if (hodlWorkspace === "calc") hodlCaptureKey();
  else if (hodlWorkspace === "msig") hodlCaptureMsig();
  hodlWorkspace = id;
  [...W("#workspace-tabs").querySelectorAll("[data-workspace]")].forEach((button) => {
    let active = button.dataset.workspace === id;
    button.classList.toggle("active", active);
    button.setAttribute("aria-selected", String(active));
    if (active) hodlRevealTab(W("#workspace-tabs"), [...W("#workspace-tabs").children].indexOf(button));
  });
  document.getElementById("key-manager").hidden = id !== "calc";
  document.getElementById("msig-manager").hidden = id !== "msig";
  document.getElementById("calc-card").hidden = true;
  document.getElementById("msig-card").hidden = true;
  document.getElementById("psbt-card").hidden = id !== "psbt";
  document.getElementById("psbted-card").hidden = id !== "psbted";
  document.getElementById("bip85-card").hidden = id !== "bip85";
  document.getElementById("sp-card").hidden = id !== "sp";
  // The context block sits outside its tool's card, so it is shown and hidden
  // with the card rather than by it.
  ["psbt", "psbted", "bip85", "sp", "msig", "calc"].forEach((tool) => {
    document.getElementById(`${tool}-tool-intro`).hidden = id !== tool;
  });
  re = null;
  Ge = false;
  dr.innerHTML = "";
  if (id === "calc") {
    hodlRenderKeyTabs();
    hodlRestoreKey();
  } else if (id === "msig") {
    hodlRenderMsigTabs();
    hodlRestoreMsig();
  } else if (id === "bip85") hodlBip85SyncOptions();
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
  W("#add-key").onclick = hodlAddKey;
  W("#delete-key").onclick = hodlDeleteActiveKey;
  hodlRenderKeyTabs();
  hodlInitTabDrag(W("#key-tabs"));
  if (hodlWorkspace === "calc") hodlRestoreKey();
  else document.getElementById("calc-card").hidden = true;
}
function hodlInitMsigManager() {
  W("#add-msig").onclick = hodlAddMsig;
  W("#delete-msig").onclick = hodlDeleteActiveMsig;
  hodlRenderMsigTabs();
  hodlInitTabDrag(W("#msig-tabs"));
  if (hodlWorkspace === "msig") hodlRestoreMsig();
  else document.getElementById("msig-card").hidden = true;
}
function hodlSeedInitialManagers() {
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
var hodlWorkspaceTabs = [["calc", "Keys", "Keys"], ["bip85", "BIP-85", "BIP85"], ["msig", "Multi Signature", "MultiSig"], ["sp", "Silent Payments", "SP"], ["psbt", "PSBT / Nonce", "PSBT"], ["psbted", "PSBT Editor", "Editor"]];
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
  W("#workspace-tabs").querySelectorAll("[data-workspace]")[next]?.focus();
}
function hodlSyncWorkspaceOverflow() {
  let strip = document.getElementById("workspace-tabs"), hint = document.getElementById("workspace-more");
  if (!strip || !hint) return;
  hint.hidden = strip.scrollWidth - strip.clientWidth - strip.scrollLeft <= 1;
}
function hodlInitWorkspace() {
  let box = W("#workspace");
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
    button.innerHTML = `<span class="workspace-tab-full"></span><span class="workspace-tab-short"></span>`;
    button.firstChild.textContent = label;
    button.lastChild.textContent = short;
    // The short form is display:none at wide widths and the full one is hidden
    // at narrow ones, and hidden text is not in the accessibility tree — so the
    // name is stated outright rather than left to whichever span is showing.
    button.setAttribute("aria-label", label);
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
  hodlInitMsig();
  hodlInitPsbt();
  initPsbtEditor();
  hodlInitBip85();
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
    toggle.setAttribute("aria-label", `Theme: ${mode}. Switch to ${light ? "dark" : "light"}`);
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
      return state.isLab ? hodlNewLabState() : hodlNewKeyState(state.name, state.id, state.number);
    });
    re = null;
    Ge = false;
    ft = "";
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
    let spKey = document.getElementById("sp-key"), spPass = document.getElementById("sp-pass");
    if (spKey) spKey.value = "";
    if (spPass) spPass.value = "";
    let spVins = document.getElementById("sp-send-vins");
    if (spVins) spVins.value = "";
    let spOut = document.getElementById("sp-out"), spError = document.getElementById("sp-error"), spSession = document.getElementById("sp-session");
    if (spOut) spOut.innerHTML = "";
    if (spError) spError.textContent = "";
    if (spSession) spSession.textContent = hodlSpNote;
    let spRecipients = document.getElementById("sp-recipients"), spVerifyVins = document.getElementById("sp-verify-vins"), spVerifyOutputs = document.getElementById("sp-verify-outputs"), spLabel = document.getElementById("sp-label");
    if (spRecipients) spRecipients.value = "";
    if (spVerifyVins) spVerifyVins.value = "";
    if (spVerifyOutputs) spVerifyOutputs.value = "";
    if (spLabel) spLabel.value = "";
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
    let error = document.getElementById("error");
    if (error) error.textContent = "";
    // The PSBT editor holds the loaded document in module state; its own wipe
    // button drops it. Last, so a failure there cannot skip the clears above.
    let psbtEditorWipe = document.getElementById("psbted-wipe");
    if (psbtEditorWipe) try { psbtEditorWipe.click(); } catch {}
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
function hodlBoot() {
  hodlInitWorkspace();
  hodlSeedInitialManagers();
  hodlInitKeyManager();
  hodlInitMsigManager();
  hodlInitClearActionState();
  hodlInitSecretFieldAutoClear();
  hodlInitTheme();
  hodlInitBetaWarningDismiss();
  hodlInitMasterFingerprintPreview();
  hodlInitDerivationControls();
  hodlInitAddressBenchmark();
  hodlInitSegmentedControls();
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
