// Lightning node identity tool for EntropyLab: derives the node pubkey a
// Lightning implementation would announce from a user-supplied seed phrase.
// The derivations themselves (aezeed for LND, BIP-39 for LDK) live in
// lightning-derive.js.
//
// The derivation runs in a key worker (ln-worker.js), not in the page. The
// seed's secrets (the decoded entropy, the salt, the root xprv) stay in the
// worker; the page holds the public result, and the secret text only while
// the user reveals it. Clear, a format or network change, and page hide
// terminate the worker, which takes its whole heap and WebAssembly memory
// with it: one release for every copy the derivation made, where the page
// could only drop its own references.
//
// Deterministic transformations of user input only: nothing here generates
// entropy.
import { wasmModuleBytes } from "./entropylab-wasm.js";
import { t } from "./i18n.js";
import { sessionNoticePrivateMaterialAccepted, sessionNoticeSecretCopied, sessionNoticeSessionEnded } from "./session-notices.js";

export { isKnownInternalVersion, deriveLndNode, deriveLdkNode } from "./lightning-derive.js";

// ── Tool wiring (markup in src/shell.html, #ln-card) ────────────────────────
const hodlLnNote = "No node key derived. Enter a seed phrase and derive.";

const escapeHtml = (value) => String(value).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

let hodlLnLast = null; // the last derivation's public result
let hodlLnRevealed = null; // the secret text, only while it is revealed
let hodlLnReveal = false;
let hodlLnJournalLog = () => {};
let hodlLnWorker = null; // { worker, url } of the running key worker
let hodlLnRun = 0; // answers from a stopped or superseded worker are ignored

// The key worker's source (scripts/ln-worker-source.mjs), injected by the
// build; absent when this module runs outside a build (the Node tests).
const hodlLnWorkerSource = typeof __LN_WORKER_SOURCE__ === "string" ? __LN_WORKER_SOURCE__ : null;
let hodlLnSpawnWorker = () => {
  if (!hodlLnWorkerSource) throw new Error("The Lightning key worker is not available in this build.");
  const url = URL.createObjectURL(new Blob([hodlLnWorkerSource], { type: "text/javascript" }));
  return { worker: new Worker(url), url };
};
// Tests run the same worker source under node:worker_threads.
export function hodlLnSetWorkerFactory(factory) {
  hodlLnSpawnWorker = factory;
}

const hodlLnStopWorker = () => {
  if (hodlLnWorker) {
    hodlLnWorker.worker.terminate();
    if (hodlLnWorker.url) URL.revokeObjectURL(hodlLnWorker.url);
  }
  hodlLnWorker = null;
};

export function hodlLnWipeMem() {
  hodlLnRun += 1;
  hodlLnStopWorker();
  hodlLnLast = null;
  hodlLnRevealed = null;
  hodlLnReveal = false;
}

const hodlLnFormat = () => (document.getElementById("ln-format")?.value === "bip39" ? "bip39" : "aezeed");
const hodlLnCoinType = () => (document.getElementById("ln-network")?.value === "testnet" ? 1 : 0);

const hodlLnNormalize = (text) => String(text || "").trim().toLowerCase().replace(/[^a-z\s]/g, " ").split(/\s+/).filter(Boolean);

const hodlLnBirthdayIso = (timestamp) => new Date(timestamp * 1000).toISOString().slice(0, 10);

const hodlLnCopyButton = (target, label) => `<button type="button" class="btn secondary psbt-copy" data-ln-copy="${target}">${escapeHtml(label)}</button>`;

function hodlLnRender() {
  const output = document.getElementById("ln-out");
  if (!output) return;
  if (!hodlLnLast) {
    output.innerHTML = "";
    return;
  }
  const r = hodlLnLast;
  const secrets = hodlLnReveal;
  const shown = secrets ? hodlLnRevealed : null;
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
      ${shown ? `
        ${aezeed ? `<p class="label">Decoded entropy (the BIP32 master seed)</p>
        <p class="psbt-kv" id="ln-entropy">${escapeHtml(shown.entropyHex)}</p>
        ${hodlLnCopyButton("ln-entropy", "Copy entropy")}
        <p class="label">Salt</p>
        <p class="psbt-kv">${escapeHtml(shown.saltHex)}</p>` : ""}
        <p class="label">BIP32 root private key (xprv)</p>
        <p class="psbt-kv" id="ln-root-xprv">${escapeHtml(shown.rootXprv)}</p>
        ${hodlLnCopyButton("ln-root-xprv", "Copy root xprv")}
        <p class="muted">The root xprv can spend the node's on-chain wallet. Reveal it only while this file runs offline on an air-gapped computer.</p>` : secrets ? "" : `<p class="muted">Private material stays hidden until you reveal it.</p>`}
    </div>`;
  document.getElementById("ln-reveal")?.addEventListener("change", (event) => {
    hodlLnReveal = event.target.checked;
    // The secret text is asked of the worker only now, and dropped on hide.
    hodlLnRevealed = null;
    if (hodlLnReveal) hodlLnWorker?.worker.postMessage({ type: "reveal", run: hodlLnRun });
    hodlLnRender();
  });
}

// A failure wipes the run and names the problem. Keyed errors (aezeed.js
// taxonomy, lightning-derive.js validations) format and translate through
// t(); anything else shows its raw message.
function hodlLnFail(error, format) {
  hodlLnWipeMem();
  hodlLnRender();
  document.getElementById("ln-error").textContent = error && typeof error.key === "string"
    ? t(error.key, error.vars)
    : error && typeof error.message === "string" ? error.message : String(error);
  hodlLnJournalLog("derive-error", format, "ln");
}

function hodlLnMessage(run, format, data) {
  if (run !== hodlLnRun || !data) return;
  if (data.type === "derived") {
    hodlLnLast = data.result;
    hodlLnRender();
    document.getElementById("ln-session").textContent = "Node key derived. Decoded key material stays in page memory until you clear it.";
    sessionNoticePrivateMaterialAccepted();
    hodlLnJournalLog("derive", `${format} ${hodlLnLast.nodePubKey.slice(0, 8)}`, "ln");
  } else if (data.type === "error") {
    hodlLnFail(data.error, format);
  } else if (data.type === "revealed") {
    // Hidden again before the answer came: keep nothing.
    if (!hodlLnReveal || !data.secrets) return;
    hodlLnRevealed = data.secrets;
    hodlLnRender();
  }
}

function hodlRunLn() {
  document.getElementById("ln-error").textContent = "";
  hodlLnWipeMem();
  const run = hodlLnRun;
  const format = hodlLnFormat();
  const words = hodlLnNormalize(document.getElementById("ln-seed").value);
  const passphrase = document.getElementById("ln-pass").value;
  try {
    hodlLnWorker = hodlLnSpawnWorker();
  } catch (exception) {
    hodlLnFail(exception, format);
    return;
  }
  const { worker } = hodlLnWorker;
  worker.onmessage = (event) => hodlLnMessage(run, format, event.data);
  worker.onerror = (event) => {
    if (run === hodlLnRun) hodlLnFail(new Error(event?.message || "The Lightning key worker stopped."), format);
  };
  // The module bytes are public; the worker instantiates its own copy, with
  // its own linear memory.
  const wasm = wasmModuleBytes();
  worker.postMessage({ type: "init", wasm: wasm.buffer }, [wasm.buffer]);
  worker.postMessage({ type: "derive", run, format, words, passphrase, coinType: format === "aezeed" ? hodlLnCoinType() : 0 });
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

// Wires the Lightning card. `journalLog` is the app's hodlJournalLog; the
// module takes it as an option instead of importing app.js (same shape as
// initPsbtEditor's options object).
export function hodlInitLn({ journalLog } = {}) {
  const go = document.getElementById("ln-go");
  if (!go) return;
  if (typeof journalLog === "function") hodlLnJournalLog = journalLog;
  go.onclick = hodlRunLn;
  document.getElementById("ln-wipe").onclick = () => {
    sessionNoticeSessionEnded();
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
    // The entropy (16 bytes, the BIP32 master seed) is too short for the
    // shape classifier, so the controls say which copies are secret.
    if (button.dataset.lnCopy !== "ln-node-pubkey") sessionNoticeSecretCopied();
    navigator.clipboard?.writeText(node.textContent || "").catch(() => {});
  });
  document.getElementById("ln-session").textContent = hodlLnNote;
  hodlLnSyncFormat();
}
