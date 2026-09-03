// Vanity address grinding over a Key Station key.
//
// The grinder never invents entropy: it turns one dial of a wallet the user
// already holds and reports which setting of that dial yields an address with
// the chosen prefix. Two dials:
//
// - Passphrase grind: counter i maps to a fixed-width base-62 "odometer"
//   string over a-zA-Z0-9 ("aaa…", "aab…", …) appended to the key's starting
//   passphrase; the candidate BIP39 passphrase is stretched the standard way
//   (PBKDF2 → BIP32 master → the key's derivation path) and the address at
//   that path is checked against the prefix.
// - Derivation grind: the passphrase stays fixed and counter i is the BIP32
//   account index; the parent node above the account is derived once here and
//   the WASM side walks account → branch → address (or the BIP-352 scan and
//   spend paths for Silent Payments).
//
// Same key, same counter, same address — so a found counter replays by hand
// and "Update key" on the Keys tab simply writes that passphrase or account
// index back to the key it came from.
//
// Buckets: the counter space splits into contiguous ranges (a bucket of
// passphrases sharing leading characters, or a run of account indexes). One
// Web Worker grinds one range at a time; workers are spawned from an inline
// Blob source so the shipped file stays self-contained (CSP worker-src blob:).
import { hash160 } from "./hashes.js";
import { addressFromScript } from "./addresses.js";
import { bech32mEncode, toWords } from "./bech32.js";
import { VANITY_WASM_B64 } from "./vanity-wasm-b64.js";
import { VANITY_WORKER_SOURCE } from "./vanity-worker.js";

export const VANITY_ALPHABET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
export const VANITY_MAX_PASS_LEN = 32;
// Buffer limits shared with vanity-wasm/src/lib.rs (MAX_SALT_LEN, MAX_KEY_LEN,
// MAX_PATH_LEN) and vanity-worker.js (MAX_SALT, MAX_KEY, MAX_PATH).
export const VANITY_MAX_SALT_LEN = 256;
export const VANITY_MAX_MNEMONIC_LEN = 1024;
export const VANITY_MAX_PATH_LEN = 16;
export const VANITY_HARDENED = 0x80000000;
export const VANITY_MAX_INDEX = 0x7fffffff;
const VANITY_BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const VANITY_BECH32_ALPHABET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
// A Silent Payment code is "sp1q" + the scan key's compressed prefix byte
// (0x02 or 0x03) in 5-bit groups: the first group is always 0 ("q"), the
// second is 010xx or 011xx — one of only eight characters — so the fixed
// prefix is "sp1qq" and the first free character is drawn from `firstFree`.
export const VANITY_SCRIPTS = Object.freeze({
  "p2pkh": Object.freeze({ code: 0, label: "Legacy P2PKH", prefix: "1", max: 34, bech32: false }),
  "p2sh-p2wpkh": Object.freeze({ code: 1, label: "Nested SegWit P2SH-P2WPKH", prefix: "3", max: 34, bech32: false }),
  "p2wpkh": Object.freeze({ code: 2, label: "Native SegWit P2WPKH", prefix: "bc1q", max: 42, bech32: true }),
  "p2tr": Object.freeze({ code: 3, label: "Taproot P2TR", prefix: "bc1p", max: 62, bech32: true }),
  "sp": Object.freeze({ code: 4, label: "Silent Payments BIP-352", prefix: "sp1qq", max: 116, bech32: true, firstFree: "gf2tvdw0" }),
});
export const VANITY_METHODS = Object.freeze({
  passphrase: Object.freeze({ mode: 0, label: "Passphrase grind" }),
  derivation: Object.freeze({ mode: 1, label: "Derivation grind" }),
});
// The Rust counter is a u64, so the addressable space saturates at u64::MAX.
const COUNTER_LIMIT = (1n << 64n) - 1n;
const encoder = new TextEncoder();

// Decoded once on the main thread; each worker receives its own copy and
// instantiates privately (no shared memory — works without cross-origin
// isolation, including from file://).
const wasmBytes = (() => {
  const binary = atob(VANITY_WASM_B64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
})();

const vanityScript = (script) => VANITY_SCRIPTS[script] ?? VANITY_SCRIPTS.p2wpkh;
const vanityMethod = (method) => VANITY_METHODS[method] ?? VANITY_METHODS.passphrase;

// A vanity prefix must start with the selected address type's fixed leading
// characters. That fixed prefix alone would match every address of the type,
// so at least one more character is required to keep results meaningful (and
// the result buffer bounded).
export function validateVanityPrefix(prefix, script = "p2wpkh") {
  const meta = vanityScript(script);
  let value = String(prefix ?? "").trim();
  if (meta.bech32) value = value.toLowerCase();
  if (!value.startsWith(meta.prefix)) throw new Error(`${meta.label} addresses start with “${meta.prefix}”; the prefix must too.`);
  if (value.length <= meta.prefix.length) throw new Error(`Add at least one character after “${meta.prefix}” — “${meta.prefix}” alone matches every ${meta.label} address.`);
  if (value.length > meta.max) throw new Error(`The prefix is longer than a whole ${meta.label} address (${meta.max} characters).`);
  const alphabet = meta.bech32 ? VANITY_BECH32_ALPHABET : VANITY_BASE58_ALPHABET;
  if (![...value.slice(meta.prefix.length)].every((character) => alphabet.includes(character))) {
    throw new Error(meta.bech32 ? "Bech32 addresses use qpzry9x8gf2tvdw0s3jn54khce6mua7l after the separator (no b, i, o, or 1)." : "Base58 addresses use no 0 (zero), O, I, or l characters.");
  }
  if (meta.firstFree && !meta.firstFree.includes(value[meta.prefix.length])) {
    throw new Error(`The character after “${meta.prefix}” encodes the scan key's parity: every ${meta.label} code continues with one of ${[...meta.firstFree].join(", ")}.`);
  }
  return value;
}

// The starting passphrase (the key's own BIP39 passphrase) prefixes every
// candidate; the WASM buffer that holds it caps at 256 bytes.
export function validateVanityPassphrase(passphrase) {
  const text = String(passphrase ?? "").normalize("NFKD");
  const length = encoder.encode(text).length;
  if (length > VANITY_MAX_SALT_LEN) {
    throw new Error(`The starting passphrase is ${length} UTF-8 bytes, over the ${VANITY_MAX_SALT_LEN}-byte vanity limit — shorten it on the Keys tab.`);
  }
  return text;
}

// The mnemonic is the PBKDF2 password, NFKD-normalized as BIP39 requires.
export function validateVanityMnemonic(mnemonic) {
  const text = String(mnemonic ?? "").trim().normalize("NFKD");
  if (!text.length) throw new Error("The passphrase grind needs the key's seed words — this key has no mnemonic.");
  const length = encoder.encode(text).length;
  if (length > VANITY_MAX_MNEMONIC_LEN) throw new Error(`The mnemonic is ${length} UTF-8 bytes, over the ${VANITY_MAX_MNEMONIC_LEN}-byte vanity limit.`);
  return text;
}

// Expected candidates per matching address: each free base58 character is one
// of 58 possibilities; each free bech32 character is one of 32 (or, for the
// Silent Payment parity character, one of 8).
export function estimateVanityWork(prefix, script = "p2wpkh") {
  const meta = vanityScript(script);
  const free = Math.max(0, String(prefix ?? "").length - meta.prefix.length);
  if (!free) return 1n;
  const per = BigInt(meta.bech32 ? 32 : 58);
  return meta.firstFree ? BigInt(meta.firstFree.length) * per ** BigInt(free - 1) : per ** BigInt(free);
}

// Passphrase grind: the counter space is 62^passLen odometer strings.
export function validateVanityRange(passLen, start, count) {
  if (!Number.isInteger(passLen) || passLen < 1 || passLen > VANITY_MAX_PASS_LEN) {
    throw new Error(`Passphrase length is 1 to ${VANITY_MAX_PASS_LEN} characters.`);
  }
  if (start < 0n || count < 1n) throw new Error("The start counter is zero or more; the range is at least one candidate.");
  const space = 62n ** BigInt(passLen);
  const limit = space < COUNTER_LIMIT ? space : COUNTER_LIMIT;
  if (start >= limit) throw new Error(`The start counter is beyond the ${passLen}-character counter space.`);
  if (start + count > limit) {
    throw new Error(passLen <= 10
      ? `The range runs past the ${passLen}-character space (${limit.toString()} counters).`
      : "The range runs past the 64-bit counter.");
  }
  return { passLen, start, count };
}

// Derivation grind: the counter is a BIP32 child index, 0 to 2^31 - 1.
export function validateVanityIndexRange(start, count) {
  if (start < 0n || count < 1n) throw new Error("The start account is zero or more; the range is at least one account.");
  const limit = BigInt(VANITY_MAX_INDEX) + 1n;
  if (start > BigInt(VANITY_MAX_INDEX)) throw new Error("The start account is beyond the BIP32 index range (0 to 2,147,483,647).");
  if (start + count > limit) throw new Error("The range runs past the last BIP32 account index (2,147,483,647).");
  return { start, count };
}

// "m/84'/0'/0'" → [0x80000054, 0x80000000, 0x80000000]; h, H, and ' mark
// hardened components, as on the Keys tab.
export function vanityPathIndexes(path) {
  const raw = String(path ?? "").trim();
  if (!/^m(?:\/[^/]+)*$/.test(raw)) throw new Error("Derivation path must start with m and contain slash-separated BIP32 indexes.");
  const components = raw === "m" ? [] : raw.slice(2).split("/").map((part) => {
    const match = /^(\d+)([hH']?)$/.exec(part), index = Number(match?.[1]);
    if (!match || !Number.isSafeInteger(index) || index > VANITY_MAX_INDEX) throw new Error("Each derivation path index is a whole number from 0 to 2,147,483,647, optionally followed by h or '.");
    return match[2] ? index + VANITY_HARDENED : index;
  });
  if (components.length > VANITY_MAX_PATH_LEN) throw new Error(`Derivation paths are at most ${VANITY_MAX_PATH_LEN} components deep for the vanity grind.`);
  return components;
}

export function vanityPathString(indexes) {
  return "m" + [...indexes].map((index) => `/${index >= VANITY_HARDENED ? `${index - VANITY_HARDENED}'` : String(index)}`).join("");
}

// Splits [start, start + count) into `workers` contiguous, disjoint ranges
// covering the whole span. The first `count % workers` buckets carry one
// extra candidate.
export function vanityBuckets(start, count, workers) {
  const n = Math.max(1, Math.min(64, Math.floor(workers) || 1));
  const base = count / BigInt(n);
  const extra = count % BigInt(n);
  const buckets = [];
  let cursor = start;
  for (let i = 0; i < n; i++) {
    const size = base + (BigInt(i) < extra ? 1n : 0n);
    if (size > 0n) buckets.push({ start: cursor, count: size });
    cursor += size;
  }
  return buckets;
}

// The worker record carries HASH160 for hash-based scripts, the x-only
// output key for P2TR, or the scan and spend public keys for Silent
// Payments; the displayed address is recomputed here through the same
// encoders the rest of the app uses.
export function vanityAddressFromRecord(record, script = "p2wpkh") {
  const meta = vanityScript(script);
  const payload = record.payload;
  if (meta.code === 4) return bech32mEncode("sp", [0, ...toWords(payload.slice(0, 66))]);
  if (meta.code === 3) return addressFromScript(new Uint8Array([0x51, 0x20, ...payload.slice(0, 32)]), "mainnet");
  const hash = payload.slice(0, 20);
  if (meta.code === 1) {
    const redeem = new Uint8Array([0, 20, ...hash]);
    return addressFromScript(new Uint8Array([0xa9, 0x14, ...hash160(redeem), 0x87]), "mainnet");
  }
  if (meta.code === 2) return addressFromScript(new Uint8Array([0x00, 0x14, ...hash]), "mainnet");
  return addressFromScript(new Uint8Array([0x76, 0xa9, 0x14, ...hash, 0x88, 0xac]), "mainnet");
}

// Default spawn: a classic worker from an inline Blob URL, keeping the
// shipped file self-contained (allowed by the CSP's worker-src blob:). The
// URL is revoked when the pool terminates.
const spawnBlobWorker = () => {
  const url = URL.createObjectURL(new Blob([VANITY_WORKER_SOURCE], { type: "text/javascript" }));
  try {
    return { worker: new Worker(url), url };
  } catch (error) {
    URL.revokeObjectURL(url);
    throw error;
  }
};

// One grinding run. Spawns one worker per bucket, streams matches/progress,
// and terminates the pool when the run completes, is stopped, or fails.
// Callbacks: onProgress({ done, total, rate }), onMatch(match),
// onDone({ done, stopped, found }), onError(message).
// start() options:
//   method     "passphrase" | "derivation"
//   script     VANITY_SCRIPTS key; prefix, start, count (BigInt), workers
//   passphrase the key's starting passphrase (NFKD); prefixes candidates in the
//              passphrase grind, reported unchanged in the derivation grind
//   mnemonic   passphrase grind: the NFKD seed words
//   passLen    passphrase grind: odometer characters appended
//   path       passphrase grind: the full derivation path (u32 indexes);
//              derivation grind: the components below `node`
//   node       derivation grind: Uint8Array(64) private key ‖ chain code of
//              the parent above the counter slot
//   counterSlot, pathPrefix  derivation grind: which path component the
//              counter replaces, and the parent's own path (display only)
// Match: { counter, index, passphrase, path, payload, address } — index is the
// found account index (derivation grind) or null; passphrase is the full
// candidate BIP39 passphrase; path is the concrete derivation path.
// `spawn` is the worker factory; it is injectable so the test suite can run
// this pool under node:worker_threads (which has no Blob URLs).
export class VanityGrinder {
  constructor(callbacks = {}, spawn = spawnBlobWorker) {
    this.callbacks = callbacks;
    this.spawn = spawn;
    this.workers = [];
    this.urls = [];
    this.running = false;
    this.runId = 0;
  }

  start({ method = "passphrase", script = "p2wpkh", prefix, start, count, workers, passLen = 0, passphrase = "", mnemonic = "", path = [], node = null, counterSlot = 0, pathPrefix = [] }) {
    // Any previous run is hard-terminated; its late messages are dropped via
    // the run id so they cannot corrupt the new run's totals.
    this.#terminate();
    const runId = ++this.runId;
    const total = count;
    const mode = vanityMethod(method).mode;
    const scriptCode = vanityScript(script).code;
    const passphraseText = String(passphrase ?? "");
    const pathIndexes = [...path].map((index) => Number(index) >>> 0);
    const key = mode === 1 ? Uint8Array.from(node ?? []) : encoder.encode(String(mnemonic ?? ""));
    const salt = mode === 1 ? new Uint8Array(0) : encoder.encode(passphraseText);
    const buckets = vanityBuckets(start, count, workers);
    const progress = new Array(buckets.length).fill(0n);
    let found = 0;
    let finished = 0;
    let handed = 0;
    let failed = false;
    this.running = true;
    this.startedAt = performance.now();
    // The main-thread copies of the key material are dead once every worker
    // holds its own (or the run is torn down first).
    const wipe = () => {
      key.fill(0);
      salt.fill(0);
    };
    this.wipe = wipe;

    const describe = (match) => {
      if (mode === 1) {
        const concrete = pathIndexes.slice();
        concrete[counterSlot] = (Number(match.counter) | (concrete[counterSlot] & VANITY_HARDENED)) >>> 0;
        return { index: Number(match.counter), passphrase: passphraseText, path: vanityPathString([...pathPrefix, ...concrete]) };
      }
      return { index: null, passphrase: passphraseText + match.passphrase, path: vanityPathString(pathIndexes) };
    };
    const finish = (stopped) => {
      if (runId !== this.runId || !this.running) return;
      this.running = false;
      const done = progress.reduce((sum, value) => sum + value, 0n);
      this.callbacks.onDone?.({ done, total, stopped, found });
      this.#terminate();
    };
    const fail = (message) => {
      if (failed) return;
      failed = true;
      this.callbacks.onError?.(message);
      finish(true);
    };

    buckets.forEach((bucket, index) => {
      let spawned;
      try {
        spawned = this.spawn();
      } catch (error) {
        fail(error?.message || "Vanity workers are blocked in this context.");
        return;
      }
      const { worker, url } = spawned;
      if (url) this.urls.push(url);
      this.workers.push(worker);
      worker.onmessage = (event) => {
        if (runId !== this.runId) return;
        const msg = event.data;
        if (!msg || typeof msg !== "object") return;
        if (msg.type === "ready") {
          // Every worker gets its own copy of the key material (structured
          // clone); it lives in that worker's WASM memory until termination.
          worker.postMessage({ type: "grind", mode, key: key.slice(), salt: salt.slice(), path: pathIndexes, counterSlot, prefix, passLen, start: bucket.start, count: bucket.count, script: scriptCode });
          handed += 1;
          if (handed === buckets.length) wipe();
        } else if (msg.type === "progress") {
          progress[index] = msg.done;
          for (const match of msg.matches) {
            found += 1;
            this.callbacks.onMatch?.({ counter: match.counter, ...describe(match), payload: match.payload, address: vanityAddressFromRecord(match, script) });
          }
          const done = progress.reduce((sum, value) => sum + value, 0n);
          const elapsed = (performance.now() - this.startedAt) / 1000;
          this.callbacks.onProgress?.({ done, total, rate: elapsed > 0 ? Number(done) / elapsed : 0 });
        } else if (msg.type === "done") {
          progress[index] = msg.done;
          finished += 1;
          if (finished === buckets.length) finish(msg.stopped);
        } else if (msg.type === "error") {
          fail(msg.message || "Vanity worker failed.");
        }
      };
      worker.onerror = (event) => {
        event.preventDefault?.();
        fail(event.message || "Vanity worker failed to start.");
      };
      // Every worker gets a private copy of the module (transferred).
      const copy = wasmBytes.slice().buffer;
      worker.postMessage({ type: "init", wasm: copy }, [copy]);
    });
  }

  stop() {
    for (const worker of this.workers) worker.postMessage({ type: "stop" });
  }

  cancel() {
    this.runId += 1;
    this.#terminate();
  }

  #terminate() {
    this.wipe?.();
    for (const worker of this.workers) worker.terminate();
    for (const url of this.urls) URL.revokeObjectURL(url);
    this.workers = [];
    this.urls = [];
    this.running = false;
  }
}

// A short timing sample of each grind on this device, so the tab can turn
// "1 in N candidates" into a time. The inputs are fixed published constants
// (the BIP39 test-vector mnemonic, an all-ones private key with an all-twos
// chain code) — never the session's keys — and the sample's matches are
// discarded. One worker, three small grinds in sequence; resolves with
// candidates per second per worker for each method.
export const VANITY_BENCHMARK_SAMPLES = Object.freeze({
  passphrase: { mode: 0, count: 24n, script: 2, path: [84 + VANITY_HARDENED, VANITY_HARDENED, VANITY_HARDENED, 0, 0], counterSlot: 0xffffffff, passLen: 8 },
  derivation: { mode: 1, count: 1200n, script: 2, path: [VANITY_HARDENED, 0, 0], counterSlot: 0, passLen: 0 },
  sp: { mode: 1, count: 600n, script: 4, path: [VANITY_HARDENED], counterSlot: 0, passLen: 0 },
});
const BENCHMARK_MNEMONIC = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const BENCHMARK_NODE = Uint8Array.from({ length: 64 }, (_, i) => (i < 32 ? 1 : 2));

export function vanityBenchmark(spawn = spawnBlobWorker) {
  return new Promise((resolve, reject) => {
    let spawned;
    try {
      spawned = spawn();
    } catch (error) {
      reject(error);
      return;
    }
    const { worker, url } = spawned;
    const names = Object.keys(VANITY_BENCHMARK_SAMPLES);
    const rates = {};
    let index = 0;
    let startedAt = 0;
    const finish = (error) => {
      worker.terminate();
      if (url) URL.revokeObjectURL(url);
      if (error) reject(error);
      else resolve(rates);
    };
    const next = () => {
      const name = names[index];
      if (!name) {
        finish();
        return;
      }
      const sample = VANITY_BENCHMARK_SAMPLES[name];
      startedAt = performance.now();
      worker.postMessage({ type: "grind", mode: sample.mode, key: sample.mode === 1 ? BENCHMARK_NODE.slice() : encoder.encode(BENCHMARK_MNEMONIC), salt: new Uint8Array(0), path: sample.path, counterSlot: sample.counterSlot, prefix: "bc1qqqqqqqqqqqq", passLen: sample.passLen, start: 0n, count: sample.count, script: sample.script });
    };
    worker.onmessage = (event) => {
      const msg = event.data;
      if (!msg || typeof msg !== "object") return;
      if (msg.type === "ready") next();
      else if (msg.type === "done") {
        const elapsed = Math.max(1, performance.now() - startedAt) / 1000;
        rates[names[index]] = Number(msg.done) / elapsed;
        index += 1;
        next();
      } else if (msg.type === "error") finish(new Error(msg.message || "Vanity benchmark failed."));
    };
    worker.onerror = (event) => {
      event.preventDefault?.();
      finish(new Error(event.message || "Vanity benchmark worker failed to start."));
    };
    const copy = wasmBytes.slice().buffer;
    worker.postMessage({ type: "init", wasm: copy }, [copy]);
  });
}
