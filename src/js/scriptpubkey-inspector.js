import { addressFromScript, descriptorDerive } from "./addresses.js";
import { bech32mDecode, fromWords } from "./bech32.js";

const MAX_SCRIPT_BYTES = 10000;
const TYPE_LABELS = Object.freeze({
  p2pkh: "P2PKH",
  p2sh: "P2SH",
  p2wpkh: "P2WPKH",
  p2wsh: "P2WSH",
  p2tr: "P2TR",
  p2a: "Pay to Anchor (P2A)",
  p2pk: "Pay to public key (P2PK)",
  multisig: "Bare multisig",
  op_return: "OP_RETURN",
  witness: "Witness program",
  witness_invalid: "Malformed witness program",
  unknown: "Unrecognized or unsupported script",
});

const bytesToHex = (bytes) => [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");

const hexToBytes = (text) => {
  const hex = String(text ?? "").replace(/\s/g, "");
  if (!hex) throw new Error("Script hex is empty.");
  if (hex.length % 2 || /[^0-9a-f]/i.test(hex)) throw new Error("Script must be an even number of hexadecimal digits.");
  if (hex.length > MAX_SCRIPT_BYTES * 2) throw new Error(`Script exceeds the ${MAX_SCRIPT_BYTES}-byte inspection limit.`);
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
};

const isWitnessVersion = (opcode) => opcode === 0x00 || (opcode >= 0x51 && opcode <= 0x60);
const witnessVersion = (opcode) => opcode === 0 ? 0 : opcode - 0x50;

const classifyWitnessProgram = (script) => {
  if (script.length < 2 || !isWitnessVersion(script[0])) return null;
  const programLength = script[1];
  if (programLength < 2 || programLength > 40 || script.length !== programLength + 2) {
    return { type: "witness_invalid", label: TYPE_LABELS.witness_invalid, addressable: false };
  }
  const version = witnessVersion(script[0]);
  if (version === 0 && programLength !== 20 && programLength !== 32) {
    return { type: "witness_invalid", label: TYPE_LABELS.witness_invalid, addressable: false };
  }
  return { type: "witness", label: `Witness v${version} program (${programLength} bytes)`, addressable: true };
};

const classifyBareMultisig = (script) => {
  if (script.length < 3 || script[0] < 0x51 || script[0] > 0x60 || script.at(-1) !== 0xae) return false;
  const m = script[0] - 0x50;
  let offset = 1;
  while (offset < script.length - 2 && script[offset] === 0x21) offset += 34;
  if (offset >= script.length - 1 || script[offset] < 0x51 || script[offset] > 0x60) return false;
  const n = script[offset] - 0x50;
  const keyCount = (offset - 1) / 34;
  return Number.isInteger(keyCount) && keyCount === n && m <= n && n > 0 && n <= 16 && offset + 2 === script.length;
};

export const classifyScript = (script) => {
  if (!(script instanceof Uint8Array)) throw new Error("Script must be a Uint8Array.");
  if (!script.length) return { type: "invalid", label: "Empty script", addressable: false };

  if (script.length === 25 && script[0] === 0x76 && script[1] === 0xa9 && script[2] === 0x14 && script[23] === 0x88 && script[24] === 0xac)
    return { type: "p2pkh", label: TYPE_LABELS.p2pkh, addressable: true };
  if (script.length === 23 && script[0] === 0xa9 && script[1] === 0x14 && script[22] === 0x87)
    return { type: "p2sh", label: TYPE_LABELS.p2sh, addressable: true };
  if (script.length === 22 && script[0] === 0x00 && script[1] === 0x14)
    return { type: "p2wpkh", label: TYPE_LABELS.p2wpkh, addressable: true };
  if (script.length === 34 && script[0] === 0x00 && script[1] === 0x20)
    return { type: "p2wsh", label: TYPE_LABELS.p2wsh, addressable: true };
  if (script.length === 34 && script[0] === 0x51 && script[1] === 0x20)
    return { type: "p2tr", label: TYPE_LABELS.p2tr, addressable: true };
  if (script.length === 4 && bytesToHex(script) === "51024e73")
    return { type: "p2a", label: TYPE_LABELS.p2a, addressable: true };
  if (script[0] === 0x6a)
    return { type: "op_return", label: TYPE_LABELS.op_return, addressable: false };

  const witness = classifyWitnessProgram(script);
  if (witness) return witness;
  if (classifyBareMultisig(script)) return { type: "multisig", label: TYPE_LABELS.multisig, addressable: false };
  if ((script[0] === 0x21 || script[0] === 0x41) && script.at(-1) === 0xac && script.length === script[0] + 2)
    return { type: "p2pk", label: TYPE_LABELS.p2pk, addressable: false };
  return { type: "unknown", label: TYPE_LABELS.unknown, addressable: false };
};

export const inspectScriptPubKey = (input, network = "mainnet") => {
  let script;
  try {
    script = input instanceof Uint8Array ? input : hexToBytes(input);
  } catch (error) {
    return { type: "invalid", label: error instanceof Error ? error.message : String(error), addressable: false, address: null };
  }
  const classification = classifyScript(script);
  const address = classification.addressable ? addressFromScript(script, network) : null;
  return { scriptHex: bytesToHex(script), ...classification, address };
};

const decodeSilentPayment = (text) => {
  const raw = String(text ?? "").trim();
  if (!/^t?sp1/i.test(raw)) return null;
  const decoded = bech32mDecode(raw.toLowerCase());
  if (!decoded || !["sp", "tsp"].includes(decoded.prefix) || decoded.words[0] !== 0) return { valid: false };
  try {
    return { valid: fromWords(decoded.words.slice(1)).length === 66 };
  } catch {
    return { valid: false };
  }
};

export const inspectAddress = (input, network = "mainnet") => {
  const text = String(input ?? "").trim();
  if (!text) return { state: "empty" };
  const silent = decodeSilentPayment(text);
  if (silent) return silent.valid ? { state: "silent-payment", address: text.toLowerCase() } : { state: "invalid-silent-payment", address: text };
  try {
    const derived = descriptorDerive(`addr(${text})`, 0, network);
    const classification = classifyScript(hexToBytes(derived.scriptHex));
    return { state: "recognized", address: text, scriptHex: derived.scriptHex, type: classification.type, label: classification.label };
  } catch {
    return { state: "invalid", address: text };
  }
};

const bytesEqual = (a, b) => {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
};

export const compareAddressAndScript = (addressInput, scriptInput, network = "mainnet") => {
  const address = inspectAddress(addressInput, network);
  const hasScriptInput = String(scriptInput ?? "").trim().length > 0;
  const script = hasScriptInput ? inspectScriptPubKey(scriptInput, network) : null;
  const comparableAddress = address.state === "recognized";
  const comparableScript = script && script.type !== "invalid";
  return {
    address,
    script,
    state: address.state === "silent-payment" || address.state === "invalid-silent-payment"
      ? address.state
      : !comparableAddress || !comparableScript
        ? "incomplete"
        : bytesEqual(hexToBytes(address.scriptHex), hexToBytes(script.scriptHex)) ? "match" : "mismatch",
  };
};

const escapeHtml = (value) => String(value ?? "").replace(/[&<>\"']/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;", "'": "&#39;" })[char]);

const STYLE = `
.scriptpubkey-inspector-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 1rem; }
.scriptpubkey-inspector label { display: block; font-weight: 600; margin-bottom: .35rem; }
.scriptpubkey-inspector textarea, .scriptpubkey-inspector select { width: 100%; box-sizing: border-box; }
.scriptpubkey-inspector textarea { min-height: 7rem; resize: vertical; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
.scriptpubkey-inspector-output { margin-top: 1rem; }
.scriptpubkey-inspector-row { display: grid; grid-template-columns: minmax(9rem, auto) 1fr; gap: .75rem; padding: .4rem 0; border-bottom: 1px solid var(--border, #444); }
.scriptpubkey-inspector-value { overflow-wrap: anywhere; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
.scriptpubkey-inspector-status { margin-top: 1rem; padding: .7rem; border-radius: 6px; font-weight: 700; }
.scriptpubkey-inspector-status[data-state="match"] { border: 1px solid currentColor; }
@media (max-width: 700px) { .scriptpubkey-inspector-grid { grid-template-columns: 1fr; } }
`;

const makeInspector = () => {
  if (document.getElementById("scriptpubkey-card")) return;
  const anchor = document.getElementById("psbt-manager") || document.getElementById("workspace-panel") || document.body;

  const intro = document.createElement("div");
  intro.className = "tool-intro";
  intro.id = "scriptpubkey-tool-intro";
  intro.hidden = true;
  intro.innerHTML = `
    <div class="kicker">Offline · address ↔ scriptPubKey</div>
    <h2>ScriptPubKey</h2>
    <p class="muted tool-intro-note">Inspect an output script offline and compare it with an ordinary Bitcoin address. A match means only that both inputs resolve to the same scriptPubKey bytes. No ownership, spendability, or network checks.</p>
  `;

  const panel = document.createElement("section");
  panel.id = "scriptpubkey-card";
  panel.className = "card no-print scriptpubkey-inspector";
  panel.hidden = true;
  panel.setAttribute("aria-labelledby", "scriptpubkey-inspector-title");
  panel.innerHTML = `
    <h2 id="scriptpubkey-inspector-title" class="sr-only">ScriptPubKey inspector</h2>
    <div class="scriptpubkey-inspector-grid">
      <div>
        <label for="scriptpubkey-inspector-address">Address</label>
        <textarea id="scriptpubkey-inspector-address" autocomplete="off" spellcheck="false" placeholder="bc1q…"></textarea>
      </div>
      <div>
        <label for="scriptpubkey-inspector-script">scriptPubKey hex</label>
        <textarea id="scriptpubkey-inspector-script" autocomplete="off" spellcheck="false" placeholder="0014…"></textarea>
      </div>
    </div>
    <div style="margin-top:.75rem">
      <label for="scriptpubkey-inspector-network">Network</label>
      <select id="scriptpubkey-inspector-network">
        <option value="mainnet">Bitcoin Mainnet</option>
        <option value="testnet">Testnet / Signet</option>
      </select>
    </div>
    <div class="scriptpubkey-inspector-output" id="scriptpubkey-inspector-output" aria-live="polite"></div>
  `;

  // Place after the PSBT manager block so it sits with other workspace panels.
  if (anchor.id === "psbt-manager") {
    const journalIntro = document.getElementById("journal-tool-intro") || document.getElementById("journal-manager");
    if (journalIntro) {
      journalIntro.insertAdjacentElement("beforebegin", intro);
      journalIntro.insertAdjacentElement("beforebegin", panel);
    } else {
      anchor.insertAdjacentElement("afterend", intro);
      intro.insertAdjacentElement("afterend", panel);
    }
  } else {
    anchor.append(intro, panel);
  }

  if (!document.getElementById("scriptpubkey-inspector-style")) {
    const style = document.createElement("style");
    style.id = "scriptpubkey-inspector-style";
    style.textContent = STYLE;
    document.head.append(style);
  }

  const addressInput = panel.querySelector("#scriptpubkey-inspector-address");
  const scriptInput = panel.querySelector("#scriptpubkey-inspector-script");
  const networkInput = panel.querySelector("#scriptpubkey-inspector-network");
  const output = panel.querySelector("#scriptpubkey-inspector-output");

  const render = () => {
    const result = compareAddressAndScript(addressInput.value, scriptInput.value, networkInput.value);
    const rows = [];
    if (result.address.state === "recognized") {
      rows.push(`<div class="scriptpubkey-inspector-row"><strong>Address type</strong><span>${escapeHtml(result.address.label)}</span></div>`);
      rows.push(`<div class="scriptpubkey-inspector-row"><strong>Address → scriptPubKey</strong><span class="scriptpubkey-inspector-value">${escapeHtml(result.address.scriptHex)}</span></div>`);
    } else if (result.address.state === "silent-payment") {
      rows.push(`<div class="scriptpubkey-inspector-row"><strong>Address</strong><span>Valid Silent Payment address; it does not directly represent one fixed scriptPubKey.</span></div>`);
    } else if (result.address.state === "invalid-silent-payment") {
      rows.push(`<div class="scriptpubkey-inspector-row"><strong>Address</strong><span>Invalid Silent Payment address.</span></div>`);
    } else if (result.address.state !== "empty") {
      rows.push(`<div class="scriptpubkey-inspector-row"><strong>Address</strong><span>Invalid or not valid on the selected network.</span></div>`);
    }
    if (result.script) {
      rows.push(`<div class="scriptpubkey-inspector-row"><strong>Script type</strong><span>${escapeHtml(result.script.label)}</span></div>`);
      if (result.script.type === "invalid") rows.push(`<div class="scriptpubkey-inspector-row"><strong>Script input</strong><span>${escapeHtml(result.script.label)}</span></div>`);
      else if (result.script.address) rows.push(`<div class="scriptpubkey-inspector-row"><strong>scriptPubKey → address</strong><span class="scriptpubkey-inspector-value">${escapeHtml(result.script.address)}</span></div>`);
    }
    let status = "";
    if (result.state === "match") status = `<div class="scriptpubkey-inspector-status" data-state="match">✓ Address and supplied scriptPubKey match.</div>`;
    else if (result.state === "mismatch") status = `<div class="scriptpubkey-inspector-status">Address and supplied scriptPubKey do not match.</div>`;
    else if (result.state === "silent-payment") status = `<div class="scriptpubkey-inspector-status">Silent Payment address: output derivation is outside this inspector.</div>`;
    else if (result.state === "invalid-silent-payment") status = `<div class="scriptpubkey-inspector-status">Invalid Silent Payment address.</div>`;
    else if (result.script?.type === "invalid") status = `<div class="scriptpubkey-inspector-status">Invalid scriptPubKey input.</div>`;
    else if (result.script && !result.script.address) status = `<div class="scriptpubkey-inspector-status">The supplied script is valid as hex but has no standard address representation in this inspector.</div>`;
    output.innerHTML = rows.join("") + status;
  };

  [addressInput, scriptInput, networkInput].forEach((input) => input.addEventListener("input", render));
  networkInput.addEventListener("change", render);
};

if (typeof document !== "undefined") {
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", makeInspector, { once: true });
  else makeInspector();
}
