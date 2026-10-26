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
// The derivations themselves (aezeed for LND, BIP-39 for LDK, hsm_secret
// for Core Lightning) live in lightning-derive.js and run in a terminable
// key worker (ln-worker.js): the worker holds the decoded entropy, salt,
// seeds, xprvs and a loaded hsm_secret's words; this page holds the public
// result, and the secret text only while the user reveals it. Clear, a
// format or network change, End Session and page hide ask the worker to
// scrub its secrets and overwrite its WebAssembly memory, then terminate
// it, so its whole heap goes with it.
//
// Deterministic transformations of user input only: nothing here generates
// entropy.
import { wasmModuleBytes, wasmRetired } from "./entropylab-wasm.js";
import { createLnKeyHandler } from "./lightning-derive.js";
import { t, tHtml as hodlT } from "./i18n.js";
import { privateCopyButtonHtml } from "./private-data.js";
import { publicFieldHtml, publicValueHtml } from "./public-data.js";
import { bolt11Decode } from "./bolt11.js";
import { bolt12Decode, bolt12RecipientVisibility } from "./bolt12.js";

export { isKnownInternalVersion, deriveLndNode, deriveLdkNode } from "./lightning-derive.js";

// ── Tool wiring (markup in src/shell.html, #ln-card) ────────────────────────

const escapeHtml = (value) => String(value).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

let hodlLnLast = null; // the last derivation's public result
let hodlLnRevealed = null; // the secret text, only while it is revealed
let hodlLnReveal = false;
let hodlLnHsmLoaded = false; // a type-2 hsm_secret file's words are loaded in the worker
let hodlLnHsmReading = false; // the chosen file's bytes are still being read (no load posted yet)
let hodlLnHsmDeriveQueued = false; // a Derive clicked during the read, to run once the file is loaded
let hodlLnJournalLog = () => {};
let hodlLnCopyIcon = () => "";
let hodlLnWorker = null; // { worker, url } of the running key worker
let hodlLnRun = 0; // derive generation: answers from a stopped or superseded run are ignored
let hodlLnHsmRun = 0; // hsm_secret load generation, separate from the derive run
let hodlLnHsmPending = false; // a load is in the worker, its reply still owed
let hodlLnPendingFormat = "aezeed"; // the in-flight derive's format, for the journal

// A 24-word seed phrase is a few hundred characters; past this bound the
// text is a mispaste (a whole file, not a phrase), refused before any
// normalizing or deriving.
const LN_SEED_MAX_LENGTH = 4096;

// The key worker's source (scripts/ln-worker-source.mjs), injected by the
// build; absent when this module runs outside a build (the Node tests).
const hodlLnWorkerSource = typeof __LN_WORKER_SOURCE__ === "string" ? __LN_WORKER_SOURCE__ : null;
let hodlLnSpawnWorker = () => {
  if (hodlLnWorkerSource) {
    const url = URL.createObjectURL(new Blob([hodlLnWorkerSource], { type: "text/javascript" }));
    return { worker: new Worker(url), url };
  }
  if (typeof Worker === "undefined" && typeof process !== "undefined" && process.versions?.node) {
    // No Web Workers, and only under Node (the test suite): the same
    // protocol handler runs in process and answers synchronously. A
    // production build always carries the worker source, so any other
    // workerless environment falls through to the refusal below instead of
    // deriving keys outside the terminable worker.
    const standIn = { onmessage: null, onerror: null, terminated: false };
    const handle = createLnKeyHandler((message) => standIn.onmessage?.({ data: message }));
    standIn.postMessage = (data) => {
      if (!standIn.terminated) handle(data);
    };
    standIn.terminate = () => {
      standIn.terminated = true;
    };
    return { worker: standIn, url: null };
  }
  throw new Error("The Lightning key worker is not available in this build.");
};
// Tests run the same worker source under node:worker_threads.
export function hodlLnSetWorkerFactory(factory) {
  hodlLnSpawnWorker = factory;
}

const hodlLnStopping = new Set(); // workers asked to scrub, termination still owed

const hodlLnTerminate = (spawned) => {
  clearTimeout(spawned.scrubTimer);
  hodlLnStopping.delete(spawned);
  spawned.worker.terminate();
  if (spawned.url) URL.revokeObjectURL(spawned.url);
};

// Terminating a worker hands its memory back to the browser unscrubbed, so
// every stop first asks the worker to scrub itself: it drops every held
// secret, zeroes its typed arrays and overwrites its own WebAssembly memory
// (the same retireWasm End Session uses on the page), then answers
// "scrubbed". The worker is terminated as soon as that answer arrives, or
// after a short bound if it is too busy or already gone to answer —
// whichever comes first.
const hodlLnStopWorker = () => {
  const spawned = hodlLnWorker;
  if (!spawned) return;
  hodlLnWorker = null;
  hodlLnStopping.add(spawned);
  try {
    spawned.worker.postMessage({ type: "scrub" });
  } catch {
    // A worker that cannot take the scrub is terminated all the same.
  }
  if (hodlLnStopping.has(spawned)) {
    // No synchronous "scrubbed" answer: terminate on the answer or the bound.
    spawned.scrubTimer = setTimeout(() => hodlLnTerminate(spawned), 250);
  }
};

// pagehide cannot wait for the "scrubbed" answer — the page may be frozen
// with the worker's heap intact — so post the scrub and terminate in the
// same turn. Best effort: the worker may be killed before it runs the
// scrub, but its heap does not outlive the page.
const hodlLnStopWorkerNow = () => {
  hodlLnStopWorker();
  for (const spawned of [...hodlLnStopping]) hodlLnTerminate(spawned);
};

// The page's copies: the public result and any revealed secret text. The
// worker keeps the derivation's secrets (and a loaded hsm_secret's words)
// until the next derive or the key-side wipe.
const hodlLnClearResult = () => {
  hodlLnLast = null;
  hodlLnRevealed = null;
  hodlLnReveal = false;
};

// The key side: terminate the worker, so its whole heap and WebAssembly
// memory — every copy the derivation made — is released at once, and clear
// the result. A format, network or coin-type change calls this; the pasted
// invoice survives it.
export function hodlLnKeyWipeMem() {
  hodlLnRun += 1;
  hodlLnHsmRun += 1;
  hodlLnStopWorker();
  hodlLnClearResult();
  hodlLnHsmLoaded = false;
  hodlLnHsmPending = false;
  hodlLnHsmReading = false;
  hodlLnHsmDeriveQueued = false;
  const session = document.getElementById("ln-session");
  if (session) session.textContent = "";
}

// The full wipe: key material and the pasted invoice. Clear, End Session
// and pagehide call this.
export function hodlLnWipeMem() {
  hodlLnKeyWipeMem();
  hodlLnInvWipeMem();
}

const hodlLnFormat = () => {
  const value = document.getElementById("ln-format")?.value;
  if (value === "bip39") return "bip39";
  if (value === "cln-hsm") return "cln-hsm";
  return "aezeed";
};
const hodlLnCoinType = () => (document.getElementById("ln-network")?.value === "testnet" ? 1 : 0);
const hodlLnNetworkName = () => (document.getElementById("ln-network")?.value === "testnet" ? "testnet" : "bitcoin");

const hodlLnNormalize = (text) => String(text || "").trim().toLowerCase().replace(/[^a-z\s]/g, " ").split(/\s+/).filter(Boolean);

const hodlLnBirthdayIso = (timestamp) => new Date(timestamp * 1000).toISOString().slice(0, 10);

const hodlLnPrivateField = (id, label, value) => `<div class="private-field is-revealed" data-private-field><p class="label copy-field-label">${escapeHtml(label)}${privateCopyButtonHtml(hodlLnCopyIcon)}</p><p class="psbt-kv" id="${id}" data-private-value data-i18n-skip translate="no">${escapeHtml(value)}</p></div>`;

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
  const cln = r.format === "cln-hsm";
  const implementation = cln ? "Core Lightning" : aezeed ? "LND" : "LDK (ldk-node)";
  // Every translated string is computed ahead of the template with the
  // helper for its sink (AGENTS.md): hodlT for HTML element content, t for
  // the labels hodlLnPrivateField escapes itself.
  const nodeKeyLabel = hodlT("{implementation} node identity public key", { implementation });
  const pathLabel = cln ? hodlT("On-chain account path") : hodlT("Identity key path");
  const networkName = cln
    ? (r.network === "testnet" ? t("testnet") : t("mainnet"))
    : aezeed ? (r.coinType === 1 ? t("testnet") : t("mainnet")) : "";
  const pathNote = cln
    ? ` · ${escapeHtml(networkName)}`
    : aezeed
      ? ` · ${hodlT("coin type {coinType} ({network})", { coinType: r.coinType, network: networkName })}`
      : ` · ${hodlT("the LDK node identity does not depend on the network")}`;
  const detailNote = cln
    ? ""
    : aezeed
      ? `<p class="muted">${hodlT("Internal (key-derivation) version {v} · wallet birthday day {days} ({date} UTC, day 0 = Bitcoin genesis). Rescans from the birthday recover on-chain funds; channel funds need the node's channel backup.", { v: r.internalVersion, days: r.birthdayDays, date: hodlLnBirthdayIso(r.birthdayTimestamp) })}</p>`
      : `<p class="muted">${hodlT("Derived the ldk-node way: BIP39 seed → master key → its private key re-seeds a second BIP32 tree → node secret at")} <code>m/0'</code>.</p>`;
  const revealLabel = cln
    ? hodlT("Reveal the account private key (xprv)")
    : aezeed ? hodlT("Reveal the root private key and decoded entropy") : hodlT("Reveal the root private key");
  const entropyLabel = t("Decoded entropy (the BIP32 master seed)");
  const saltLabel = t("Salt");
  const rootXprvLabel = cln ? t("BIP86 account private key (xprv)") : t("BIP32 root private key (xprv)");
  const privateNote = cln
    ? hodlT("The account xprv can spend the node's on-chain wallet. Reveal it only while this file runs offline on an air-gapped computer.")
    : hodlT("The root xprv can spend the node's on-chain wallet. Reveal it only while this file runs offline on an air-gapped computer.");
  const hiddenNote = hodlT("Private material stays hidden until you reveal it.");
  const clnDetails = cln ? `
      <p class="label">${hodlT("Watch-only descriptors")}</p>
      <ul class="ln-descriptors">${r.descriptors.map((descriptor) => `<li>${publicValueHtml(descriptor, { clipboard: true })}</li>`).join("")}</ul>
      <p class="label">${hodlT("First 10 receive addresses")}</p>
      <ul class="ln-addresses">${r.addresses.map((address, index) => `<li><span class="muted">${index}</span> ${publicValueHtml(address, { clipboard: true })}</li>`).join("")}</ul>` : "";
  output.innerHTML = `
    <div class="ln-result">
      ${cln ? `<p class="muted" data-ln-note="single-key">${hodlT("Single key. This is not a channel backup.")}</p>` : ""}
      ${publicFieldHtml(nodeKeyLabel, r.nodePubKey, { id: "ln-node-pubkey", copyIcon: hodlLnCopyIcon })}
      <p class="muted">${pathLabel} ${publicValueHtml(r.path, { clipboard: false })}${pathNote}</p>
      ${detailNote}
      ${clnDetails}
      <label class="choice"><input type="checkbox" id="ln-reveal" data-private-reveal ${secrets ? "checked" : ""}> <span>${revealLabel}</span></label>
      ${shown ? `
        ${aezeed ? `${hodlLnPrivateField("ln-entropy", entropyLabel, shown.entropyHex)}
        ${hodlLnPrivateField("ln-salt", saltLabel, shown.saltHex)}` : ""}
        ${hodlLnPrivateField("ln-root-xprv", rootXprvLabel, shown.rootXprv)}
        <p class="muted">${privateNote}</p>` : secrets ? "" : `<p class="muted">${hiddenNote}</p>`}
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
      // The secret text is asked of the key worker only now, and dropped on hide.
      hodlLnRevealed = null;
      // A retired session (End Session) keeps no worker to ask: scrub and
      // terminate a leftover one instead of posting to it.
      if (hodlLnReveal) {
        if (wasmRetired()) hodlLnStopWorker();
        else hodlLnWorker?.worker.postMessage({ type: "reveal", run: hodlLnRun });
      }
      hodlLnRender();
    });
  }
}

// Keyed errors (the aezeed.js and hsm-secret.js taxonomies, the
// lightning-derive.js validations) format and translate through t();
// anything else shows its raw message. The worker's error answers carry the
// same { message, key, vars, code } shape as the page's own thrown errors.
const hodlLnShowError = (error, exception) => {
  error.textContent = exception && typeof exception.key === "string"
    ? t(exception.key, exception.vars)
    : exception && typeof exception.message === "string" ? exception.message : String(exception);
  error.dataset.code = exception && typeof exception.code === "string" ? exception.code : "";
};

// The key worker answers a derive, a reveal or an hsm_secret load. Each
// request kind has its own generation — the derive run and the hsm_secret
// load run — and an answer whose id is stale for its kind came from a
// stopped or superseded request and is ignored.
function hodlLnMessage(data) {
  if (!data || typeof data.type !== "string") return;
  if (data.request === "load-hsm" || data.type === "hsm-loaded" ? data.run !== hodlLnHsmRun : data.run !== hodlLnRun) return;
  if (data.type === "derived") {
    hodlLnLast = data.result;
    hodlLnRender();
    const session = document.getElementById("ln-session");
    if (session) session.textContent = t("Node key derived. Decoded key material stays in an isolated worker until you clear it.");
    hodlLnJournalLog("derive", `${data.result.format} ${hodlLnLast.nodePubKey.slice(0, 8)}`, "ln");
    return;
  }
  if (data.type === "revealed") {
    // Hidden again before the answer came: keep nothing.
    if (!hodlLnReveal || !data.secrets) return;
    hodlLnRevealed = data.secrets;
    hodlLnRender();
    return;
  }
  if (data.type === "hsm-loaded") {
    // The worker holds the file's words; the page keeps only the flag.
    hodlLnHsmPending = false;
    hodlLnHsmLoaded = true;
    hodlLnClearResult();
    // The file is the most recent entry: drop any typed words so Derive
    // cannot silently use them instead of the file the status line names.
    const seed = document.getElementById("ln-seed");
    if (seed) seed.value = "";
    const error = document.getElementById("ln-error");
    if (error) {
      error.textContent = "";
      error.dataset.code = "";
    }
    const session = document.getElementById("ln-session");
    if (session) session.textContent = t("hsm_secret read. Press Derive.");
    hodlLnRender();
    // A Derive clicked while the file was still being read is remembered:
    // the worker now holds the words, so run it.
    if (hodlLnHsmDeriveQueued) {
      hodlLnHsmDeriveQueued = false;
      hodlRunLn();
    }
    return;
  }
  if (data.type === "error") {
    hodlLnClearResult();
    if (data.request === "load-hsm") {
      hodlLnHsmLoaded = false;
      hodlLnHsmPending = false;
      hodlLnHsmDeriveQueued = false;
      // A derive that raced this load (posted after it, before its refusal
      // arrived) must not overwrite the load's keyed refusal with a generic
      // "hsm-secret-missing": supersede it.
      hodlLnRun += 1;
    }
    hodlLnRender();
    // The result is gone, and a refused load drops the held file: the status
    // says what is left, never "Node key derived…" or a dropped file's
    // "hsm_secret read…".
    const session = document.getElementById("ln-session");
    if (session) session.textContent = hodlLnHsmLoaded ? t("hsm_secret read. Press Derive.") : t("No node key derived. Enter a seed phrase and derive.");
    const error = document.getElementById("ln-error");
    if (error) hodlLnShowError(error, data.error);
    if (data.request === "load-hsm") {
      hodlLnJournalLog("hsm-file-error", data.error && typeof data.error.code === "string" ? data.error.code : "unknown", "ln");
    } else {
      hodlLnJournalLog("derive-error", hodlLnPendingFormat, "ln");
    }
  }
}

// Spawn the key worker on first use and hand it the WebAssembly module
// bytes (public), from which it instantiates its own copy with its own
// linear memory. The worker is reused across derives so a loaded
// hsm_secret's words survive to the next Derive; the wipes terminate it.
function hodlLnEnsureWorker() {
  // End Session retires the module while a worker may still be running, so
  // the retired state is checked on every use, not only at spawn: a retired
  // session scrubs and terminates any worker it still holds, and refuses.
  if (wasmRetired()) {
    hodlLnStopWorker();
    throw Object.assign(new Error("This session has ended; reload the page to start a new one."), { code: "session-ended" });
  }
  if (hodlLnWorker) return hodlLnWorker.worker;
  // The module bytes come first: a retired session refuses here, before any
  // worker is spawned.
  const wasm = wasmModuleBytes();
  const spawned = hodlLnSpawnWorker();
  hodlLnWorker = spawned;
  spawned.worker.onmessage = (event) => {
    if (event.data && event.data.type === "scrubbed") {
      // The worker scrubbed its secrets and its WebAssembly memory:
      // terminate it now, ahead of the bound.
      hodlLnTerminate(spawned);
      return;
    }
    hodlLnMessage(event.data);
  };
  spawned.worker.onerror = (event) => {
    // A crashed worker can never answer again — and cannot scrub itself:
    // terminate it and revoke its URL at once, or its heap survives. Both
    // runs are over, and any answer it already queued is stale.
    hodlLnTerminate(spawned);
    if (hodlLnWorker !== spawned) return;
    hodlLnWorker = null;
    hodlLnRun += 1;
    hodlLnHsmRun += 1;
    hodlLnHsmLoaded = false;
    hodlLnHsmPending = false;
    // A read still in flight is superseded by the run bump and returns early,
    // so its flags are cleared here or every later Derive would wait forever.
    hodlLnHsmReading = false;
    hodlLnHsmDeriveQueued = false;
    hodlLnClearResult();
    const session = document.getElementById("ln-session");
    if (session) session.textContent = t("No node key derived. Enter a seed phrase and derive.");
    hodlLnRender();
    const error = document.getElementById("ln-error");
    if (error) {
      error.textContent = event && typeof event.message === "string" && event.message !== "" ? event.message : t("The Lightning key worker stopped.");
      error.dataset.code = "";
    }
  };
  spawned.worker.postMessage({ type: "init", wasm: wasm.buffer }, [wasm.buffer]);
  return spawned.worker;
}

function hodlRunLn() {
  const error = document.getElementById("ln-error");
  error.textContent = "";
  error.dataset.code = "";
  hodlLnClearResult();
  // Re-render with the click, before anything is posted: the previous
  // result — and any revealed secret text — leaves the screen now, not when
  // the worker answers.
  hodlLnRender();
  const format = hodlLnFormat();
  // Every Derive click supersedes the previous run — even one refused below,
  // before anything is posted: the earlier run's in-flight answer is stale
  // and must not render beside the refusal.
  hodlLnRun += 1;
  hodlLnPendingFormat = format;
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
    if (format === "cln-hsm" && passphrase !== "") {
      throw Object.assign(new Error("No passphrase is needed for a type 2 hsm_secret."), {
        key: "No passphrase is needed for a type 2 hsm_secret.",
        code: "hsm-secret-passphrase-not-needed",
      });
    }
    if (format === "cln-hsm" && hodlLnHsmReading) {
      // The file is still being read: remember the click and derive once
      // the worker holds the words (the hsm-loaded answer runs it).
      hodlLnHsmDeriveQueued = true;
      return;
    }
    // A file that is loaded or still loading is the latest entry: derive
    // from the words the worker holds, not the box. The worker processes
    // messages in order, so a pending load arrives before this derive.
    const fromFile = format === "cln-hsm" && (hodlLnHsmPending || hodlLnHsmLoaded);
    hodlLnEnsureWorker().postMessage({
      type: "derive",
      run: hodlLnRun,
      format,
      words: fromFile ? [] : words,
      text: fromFile ? "" : text,
      passphrase,
      coinType: format === "aezeed" ? hodlLnCoinType() : 0,
      network: hodlLnNetworkName(),
    });
  } catch (exception) {
    // A refused derive wipes the last result's secrets, as it did in page.
    hodlLnWorker?.worker.postMessage({ type: "drop" });
    hodlLnClearResult();
    hodlLnRender();
    // As for a worker refusal: the status says what is left.
    const session = document.getElementById("ln-session");
    if (session) session.textContent = hodlLnHsmLoaded ? t("hsm_secret read. Press Derive.") : t("No node key derived. Enter a seed phrase and derive.");
    hodlLnShowError(error, exception);
    hodlLnJournalLog("derive-error", format, "ln");
  }
}

function hodlLnSyncFormat() {
  const format = hodlLnFormat();
  const network = document.getElementById("ln-network-field");
  if (network) network.hidden = format === "bip39";
  const upload = document.getElementById("ln-hsm-upload");
  if (upload) upload.hidden = format !== "cln-hsm";
  const note = document.getElementById("ln-seed-help");
  if (note) {
    if (format === "aezeed") note.textContent = t("The 24-word cipher seed LND printed at wallet creation.");
    else if (format === "bip39") note.textContent = t("A 12 to 24 word BIP-39 seed phrase, as used by ldk-node.");
    else note.textContent = t("The 12 words lightning-hsmtool getsecret prints, or choose the hsm_secret file.");
  }
}


// Reads the chosen hsm_secret and hands its bytes to the key worker, which
// refuses every non-type-2 shape with the same keyed errors and, for a
// type-2 file, holds the words. The page keeps only a "file loaded" flag.
// The page's copy of the bytes is zeroed and the input reset in a finally
// block; the worker zeroes its own copy after reading.
async function hodlLnReadHsmFile() {
  const input = document.getElementById("ln-hsm-file");
  if (!input) return;
  const file = input.files && input.files[0];
  if (!file) return;
  // The file is the latest entry from the moment it is picked: bump the
  // load generation and mark the load pending BEFORE the read, and clear
  // any typed words, so words typed earlier cannot win over the file and a
  // Derive during the read cannot use the box. The load has its own
  // generation, separate from the derive run: a Derive clicked while the
  // file loads must not drop the load's reply, and typing supersedes the
  // load.
  hodlLnHsmRun += 1;
  hodlLnHsmPending = true;
  hodlLnHsmReading = true;
  // A Derive queued for an earlier file is not a request for this one: it
  // goes, as it does when words are typed.
  hodlLnHsmDeriveQueued = false;
  const run = hodlLnHsmRun;
  const seed = document.getElementById("ln-seed");
  if (seed) seed.value = "";
  let bytes = null;
  try {
    bytes = new Uint8Array(await file.arrayBuffer());
    if (run !== hodlLnHsmRun) {
      // Typing (or a wipe) during the read superseded the file: the load is
      // never posted. The bytes were never transferred; wipe them here and
      // keep the typed words.
      bytes.fill(0);
      bytes = null;
      return;
    }
    hodlLnHsmReading = false;
    hodlLnEnsureWorker().postMessage({ type: "load-hsm", run, bytes }, [bytes.buffer]);
  } catch (exception) {
    // A superseded read's failure is not this file's: it must not drop the
    // newer file's words or clear its flags.
    if (run !== hodlLnHsmRun) return;
    // A file that could not be read drops the last result's secrets and the
    // held file's words, as the in-page refusal did.
    hodlLnHsmReading = false;
    hodlLnHsmDeriveQueued = false;
    hodlLnHsmPending = false;
    hodlLnWorker?.worker.postMessage({ type: "drop" });
    hodlLnWorker?.worker.postMessage({ type: "drop-hsm" });
    hodlLnClearResult();
    hodlLnHsmLoaded = false;
    hodlLnRender();
    // The held file is gone too: its "hsm_secret read…" status goes with it.
    const session = document.getElementById("ln-session");
    if (session) session.textContent = t("No node key derived. Enter a seed phrase and derive.");
    const error = document.getElementById("ln-error");
    if (error) hodlLnShowError(error, exception);
    hodlLnJournalLog("hsm-file-error", exception && typeof exception.code === "string" ? exception.code : "unknown", "ln");
  } finally {
    // The transfer detached the buffer: the page holds nothing left to wipe.
    // The input reset must run either way.
    if (bytes && bytes.byteLength > 0) bytes.fill(0);
    input.value = "";
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
    parts.push(lnInvRow(hodlT("Amount"), r.amountMsat === null || r.amountMsat === undefined
      ? hodlT("No amount set — payer chooses.")
      : `${escapeHtml(lnInvFormatMsat(r.amountMsat))} (${escapeHtml(r.amountMsat)} msat)`));
    if (r.description !== null) parts.push(lnInvRow(hodlT("Description"), escapeHtml(r.description)));
    if (r.descriptionHash) parts.push(lnInvRow(hodlT("Description hash"), `<code>${escapeHtml(r.descriptionHash)}</code>`));
    parts.push(lnInvRow(hodlT("Payment hash"), publicValueHtml(r.paymentHash, { id: "ln-inv-payment-hash", copyIcon: hodlLnCopyIcon })));
    parts.push(lnInvRow(hodlT("Node id (recovered)"), publicValueHtml(r.nodeId, { id: "ln-inv-node-id", copyIcon: hodlLnCopyIcon })));
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
        parts.push(hodlLnPrivateField("ln-inv-payment-secret", t("Payment secret"), r.paymentSecret));
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
    if (r.fields.issuerId !== undefined) parts.push(lnInvRow(hodlT("Issuer signing key"), publicValueHtml(r.fields.issuerId, { id: "ln-inv-issuer-id", copyIcon: hodlLnCopyIcon })));
    if (r.fields.nodeId !== undefined) parts.push(lnInvRow(hodlT("Invoice node id"), publicValueHtml(r.fields.nodeId, { id: "ln-inv-invoice-node-id", copyIcon: hodlLnCopyIcon })));
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

// Test hook: render a decoded result directly, so the amountless rendering
// can be checked for both null and undefined without a decoder that emits
// the other.
export function hodlLnInvRenderResult(result) {
  hodlLnInvLast = result;
  hodlLnInvRender();
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
  // The page's network setting is not the LND coin-type select: re-render
  // the invoice card when the page announces a change, so its warning
  // matches the new page network.
  if (typeof document !== "undefined" && typeof document.addEventListener === "function") {
    document.addEventListener("hodl:network-default", () => hodlLnInvRender());
  }
  const go = document.getElementById("ln-go");
  if (!go) return;
  // The shell owns the CLN controls (#ln-hsm-upload / #ln-hsm-file); the
  // tool only wires them. A page without them (the LND/LDK fixtures, and any
  // shell that predates C2) must behave exactly as before: no CLN-only code
  // runs, and no format option is invented.
  const upload = document.getElementById("ln-hsm-upload");
  const hsmFile = document.getElementById("ln-hsm-file");
  if (upload && hsmFile) {
    upload.onclick = () => hsmFile.click();
    hsmFile.onchange = hodlLnReadHsmFile;
  }
  // Typing is the most recent entry too — even while a file is still
  // loading. Every input supersedes the load's generation, so a late reply
  // is ignored; and while a load is pending or a file is loaded, the worker
  // (which processes messages in order) drops the held file mnemonic and the
  // page its status line, so Derive cannot silently use the file instead of
  // the words. Otherwise the LND/LDK formats are untouched.
  const seedField = document.getElementById("ln-seed");
  if (seedField) {
    seedField.addEventListener("input", () => {
      hodlLnHsmRun += 1;
      hodlLnHsmReading = false;
      hodlLnHsmDeriveQueued = false;
      if (!hodlLnHsmLoaded && !hodlLnHsmPending) return;
      hodlLnHsmLoaded = false;
      hodlLnHsmPending = false;
      hodlLnWorker?.worker.postMessage({ type: "drop-hsm" });
      const file = document.getElementById("ln-hsm-file");
      if (file) file.value = "";
      const session = document.getElementById("ln-session");
      if (session) session.textContent = "";
    });
  }
  go.onclick = hodlRunLn;
  // pagehide cannot wait for the worker's scrub answer: scrub and terminate
  // in the same turn (best effort — see hodlLnStopWorkerNow).
  if (typeof window !== "undefined" && typeof window.addEventListener === "function") {
    window.addEventListener("pagehide", hodlLnStopWorkerNow);
  }
  document.getElementById("ln-wipe").onclick = () => {
    hodlLnWipeMem();
    for (const id of ["ln-seed", "ln-pass", "ln-hsm-file"]) {
      const field = document.getElementById(id);
      if (field) field.value = "";
    }
    document.getElementById("ln-out").innerHTML = "";
    document.getElementById("ln-error").textContent = "";
    document.getElementById("ln-error").dataset.code = "";
    const session = document.getElementById("ln-session");
    if (session) session.textContent = t("Accessible fields were cleared (best effort).");
  };
  for (const id of ["ln-format", "ln-network"]) {
    document.getElementById(id)?.addEventListener("change", () => {
      // A stale result next to a flipped select is how a correct seed looks
      // wrong (a mainnet pubkey beside "Testnet"): wipe and re-render on any
      // format or network change. The invoice card is not key material: it
      // survives, and is re-rendered so its network warning matches the page.
      // The key side includes a held hsm_secret file's words, so the file
      // input goes too.
      hodlLnKeyWipeMem();
      const file = document.getElementById("ln-hsm-file");
      if (file) file.value = "";
      hodlLnRender();
      hodlLnSyncFormat();
      hodlLnInvRender();
    });
  }
  const session = document.getElementById("ln-session");
  if (session) session.textContent = t("No node key derived. Enter a seed phrase and derive.");
  hodlLnSyncFormat();
}
