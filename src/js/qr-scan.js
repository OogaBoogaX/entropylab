// Page wrapper for the QR decoder worker (preview builds only). The worker
// source and the WASM bytes are injected by the build; this module never
// touches the DOM. P3 wires retireQrDecoders() into End Session and pagehide.
//
// Security contract: a frame is decoded only inside the terminable worker;
// the frame and the worker's WASM buffers are zeroed after every decode, and
// a frame refused here or in the worker is zeroed too; a
// stale or malformed reply never resolves a decode; stop() scrubs the
// worker's WASM memory before terminating it.
const MIN_DIM = 21;
const MAX_DIM = 4096;
const MAX_PIXELS = 4_194_304;

const decoders = new Set();

const failure = (code) => Object.assign(new Error(code), { code });

// A frame this wrapper refuses is zeroed here, as the worker zeroes the frames
// it refuses: it can hold a photographed seed QR.
const zeroFrame = (gray) => {
  try {
    if (ArrayBuffer.isView(gray)) new Uint8Array(gray.buffer, gray.byteOffset, gray.byteLength).fill(0);
  } catch {
    // A detached frame holds nothing to zero.
  }
};

export function createQrDecoder({
  // The build defines __QR_WORKER_SOURCE__ (preview only); the typeof guard
  // keeps the bare identifier safe where the define is absent.
  source = typeof __QR_WORKER_SOURCE__ === "string" ? __QR_WORKER_SOURCE__ : globalThis.__QR_WORKER_SOURCE__,
  wasmBytes,
  Worker = globalThis.Worker,
  timeoutMs = 4000,
  scrubMs = 250,
} = {}) {
  if (typeof source !== "string" || !source) throw new Error("The QR decoder worker is not available in this build.");
  if (!(wasmBytes instanceof Uint8Array) || wasmBytes.length === 0) throw new Error("The QR decoder WASM bytes are missing.");
  if (typeof Worker !== "function") throw new Error("Web Workers are not available.");

  let spawned = null;
  let pending = null;
  let nextRun = 1;
  let stoppedFlag = false;
  const stopping = new Set();

  const terminate = (entry) => {
    clearTimeout(entry.scrubTimer);
    stopping.delete(entry);
    entry.worker.terminate();
    if (entry.url) URL.revokeObjectURL(entry.url);
  };

  const retire = () => {
    const entry = spawned;
    if (!entry) return;
    spawned = null;
    stopping.add(entry);
    try {
      entry.worker.postMessage({ type: "scrub" });
    } catch {
      // A worker that cannot take the scrub is terminated all the same.
    }
    if (stopping.has(entry)) {
      entry.scrubTimer = setTimeout(() => terminate(entry), scrubMs);
    }
  };

  const zeroPayload = (data) => {
    if (data?.payload instanceof ArrayBuffer) new Uint8Array(data.payload).fill(0);
  };

  const settle = (entry, data) => {
    if (entry !== spawned || !pending || data?.run !== pending.run) {
      zeroPayload(data);
      return;
    }
    if (data.type === "decoded") {
      const { resolve, reject, timer } = pending;
      pending = null;
      clearTimeout(timer);
      if (!Number.isInteger(data.code)) return reject(failure("WORKER_ERROR"));
      if (data.code > 0) {
        if (!(data.payload instanceof ArrayBuffer)) return reject(failure("WORKER_ERROR"));
        return resolve({ code: data.code, payload: new Uint8Array(data.payload) });
      }
      zeroPayload(data);
      return resolve({ code: data.code, payload: null });
    }
    if (data.type === "error") {
      const { reject, timer } = pending;
      pending = null;
      clearTimeout(timer);
      const code = typeof data.error?.code === "string" ? data.error.code : "BAD_MESSAGE";
      // The wrapper only sends checked frames, so an error reply means the
      // worker's state is off (after DECODE_FAILED it has dropped its WASM
      // instance): retire it, and the next decode starts a fresh one.
      retire();
      return reject(failure(code));
    }
    zeroPayload(data);
  };

  const onError = (entry) => {
    if (entry !== spawned) return;
    const current = pending;
    pending = null;
    if (current) {
      clearTimeout(current.timer);
      current.reject(failure("WORKER_ERROR"));
    }
    retire();
  };

  const spawn = () => {
    const url = URL.createObjectURL(new Blob([source], { type: "text/javascript" }));
    let worker;
    try {
      worker = new Worker(url);
    } catch (error) {
      URL.revokeObjectURL(url);
      throw error;
    }
    const entry = { worker, url, scrubTimer: null };
    worker.onmessage = (event) => {
      const data = event.data;
      if (data?.type === "scrubbed") {
        if (stopping.has(entry)) terminate(entry);
        return;
      }
      settle(entry, data);
    };
    worker.onerror = () => onError(entry);
    const bytes = wasmBytes.slice();
    try {
      worker.postMessage({ type: "init", wasm: bytes.buffer }, [bytes.buffer]);
    } catch (error) {
      worker.terminate();
      URL.revokeObjectURL(url);
      throw error;
    }
    spawned = entry;
    return entry;
  };

  const decode = (gray, width, height) => {
    const refuse = (code) => {
      zeroFrame(gray);
      return Promise.reject(failure(code));
    };
    if (stoppedFlag) return refuse("STOPPED");
    if (!(gray instanceof Uint8Array)) return refuse("BAD_ARGS");
    if (!Number.isInteger(width) || !Number.isInteger(height) || width < MIN_DIM || height < MIN_DIM) return refuse("BAD_ARGS");
    if (width > MAX_DIM || height > MAX_DIM || width * height > MAX_PIXELS) return refuse("TOO_LARGE");
    if (gray.byteLength !== width * height) return refuse("BAD_ARGS");
    if (gray.byteOffset !== 0 || gray.byteLength !== gray.buffer.byteLength) return refuse("BAD_ARGS");
    if (pending) return refuse("BUSY");
    let entry;
    try {
      entry = spawned ?? spawn();
    } catch (error) {
      zeroFrame(gray);
      return Promise.reject(error);
    }
    const run = nextRun++;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        if (pending?.run !== run) return;
        pending = null;
        retire();
        reject(failure("TIMEOUT"));
      }, timeoutMs);
      pending = { run, resolve, reject, timer };
      try {
        entry.worker.postMessage({ type: "decode", run, width, height, gray: gray.buffer }, [gray.buffer]);
      } catch (error) {
        // The transfer failed (a SharedArrayBuffer frame, say), so the frame
        // is still here: zero it.
        clearTimeout(timer);
        pending = null;
        zeroFrame(gray);
        reject(error);
      }
    });
  };

  const stop = () => {
    if (stoppedFlag) return;
    stoppedFlag = true;
    decoders.delete(decoder);
    if (pending) {
      const { reject, timer } = pending;
      pending = null;
      clearTimeout(timer);
      reject(failure("STOPPED"));
    }
    retire();
  };

  const decoder = { decode, stop };
  decoders.add(decoder);
  return decoder;
}

export function retireQrDecoders() {
  for (const decoder of [...decoders]) decoder.stop();
}
