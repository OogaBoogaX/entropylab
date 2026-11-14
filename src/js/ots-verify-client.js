// Page side of the OpenTimestamps verification worker (preview builds only).
// The worker source and the WASM bytes are injected by the build; this module
// never touches the DOM.
//
// Security contract: a proof is parsed, verified and hashed only inside a
// terminable worker; a run that takes too long ends as incomplete, never as a
// verdict; a reply that arrives after stop() or a timeout is ignored.
import { verifyOts } from "./ots-verifier.js";
import { wasmModuleBytes } from "./entropylab-wasm.js";

const failure = (code, message) => Object.assign(new Error(message || code), { code });

const timeLimit = () =>
  Object.assign(new Error("Verification incomplete: the time limit was reached. Nothing was verified."), {
    name: "OtsBudgetError",
    code: "TIME_LIMIT",
  });

const isNode = () => typeof process !== "undefined" && process.versions?.node;

// Copy a view that does not cover its whole buffer, so the transfer detaches
// only bytes this run owns.
const transferable = (bytes) => {
  if (!(bytes instanceof Uint8Array)) return null;
  if (bytes.byteOffset === 0 && bytes.byteLength === bytes.buffer.byteLength) return bytes.buffer;
  return bytes.slice().buffer;
};

const rebuild = (error) => {
  const name = error && typeof error.name === "string" ? error.name : "Error";
  const message = error && typeof error.message === "string" ? error.message : "Verification failed.";
  let rebuilt;
  if (name === "RangeError") rebuilt = new RangeError(message);
  else if (name === "TypeError") rebuilt = new TypeError(message);
  else {
    rebuilt = new Error(message);
    rebuilt.name = name;
  }
  if (error && error.code != null) rebuilt.code = error.code;
  return rebuilt;
};

export function createOtsVerifier({
  source = typeof __OTS_WORKER_SOURCE__ === "string" ? __OTS_WORKER_SOURCE__ : null,
  wasmBytes = wasmModuleBytes,
  Worker = globalThis.Worker,
  timeoutMs = 15000,
} = {}) {
  let current = null;
  let nextRun = 1;

  const terminate = (entry) => {
    clearTimeout(entry.timer);
    try {
      entry.worker.terminate();
    } catch {
      // A worker that cannot be terminated holds nothing this run needs.
    }
    if (entry.url) URL.revokeObjectURL(entry.url);
  };

  const settle = (entry, data) => {
    if (entry !== current) return;
    if (!data || typeof data !== "object" || data.run !== entry.run) return;
    current = null;
    clearTimeout(entry.timer);
    terminate(entry);
    if (data.type === "verified") {
      entry.resolve(data.result);
      return;
    }
    if (data.type === "error") {
      entry.reject(rebuild(data.error));
      return;
    }
    entry.reject(failure("BAD_MESSAGE", "Bad message."));
  };

  const stop = () => {
    const entry = current;
    if (!entry) return;
    current = null;
    terminate(entry);
    entry.reject(failure("CANCELLED", "Verification cancelled."));
  };

  const verify = (input = {}) => {
    stop();
    if (!source) {
      if (typeof Worker === "undefined" && isNode()) return verifyOts(input);
      return Promise.reject(failure("NO_WORKER", "The OpenTimestamps verifier worker is not available in this build."));
    }
    if (typeof Worker !== "function") {
      return Promise.reject(failure("NO_WORKER", "Web Workers are not available."));
    }
    const run = nextRun++;
    return new Promise((resolve, reject) => {
      let url;
      let worker;
      try {
        url = URL.createObjectURL(new Blob([source], { type: "text/javascript" }));
        worker = new Worker(url);
      } catch (error) {
        if (url) URL.revokeObjectURL(url);
        reject(error);
        return;
      }
      const entry = { worker, url, run, resolve, reject, timer: null };
      worker.onmessage = (event) => settle(entry, event.data);
      worker.onerror = () => {
        if (entry !== current) return;
        current = null;
        terminate(entry);
        entry.reject(failure("WORKER_FAILED", "The OpenTimestamps verifier worker stopped."));
      };
      current = entry;
      entry.timer = setTimeout(() => {
        if (entry !== current) return;
        current = null;
        terminate(entry);
        entry.reject(timeLimit());
      }, timeoutMs);
      try {
        const wasm = wasmBytes();
        worker.postMessage({ type: "init", wasm: wasm.buffer }, [wasm.buffer]);
        const proof = transferable(input.proofBytes);
        const header = transferable(input.header);
        const expected = transferable(input.expectedDigest);
        const original = transferable(input.originalFileBytes);
        worker.postMessage(
          { type: "verify", run, proof, header, expected, original },
          [proof, header, expected, original].filter(Boolean),
        );
      } catch (error) {
        if (entry === current) {
          current = null;
          terminate(entry);
          entry.reject(error);
        }
      }
    });
  };

  return { verify, stop };
}
