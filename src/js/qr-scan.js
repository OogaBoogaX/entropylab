// Page wrapper for the QR decoder worker (preview builds only). The worker
// source and the WASM bytes are injected by the build; this module never
// touches the DOM. Ceremony capture retires its decoder through CameraCapture
// and the frame adapter; retireQrDecoders() remains available for global cleanup.
//
// Security contract: a frame is decoded only inside the terminable worker;
// the frame and the worker's WASM buffers are zeroed after every decode, and
// a frame refused here or in the worker is zeroed too; a
// stale or malformed reply never resolves a decode; stop() asks the worker to
// overwrite its WASM memory and waits for the acknowledgement, up to the
// decode timeout while a decode is running. A worker that does not answer by
// then (a hung decode) is terminated without the overwrite, and stop()
// reports scrubbed: false. Termination frees the memory but does not
// overwrite it. A failed scrub is not forgotten: a decoder's stop() reports
// false if any of its workers was cut off unscrubbed, including one retired
// earlier by the watchdog or an error, and retireQrDecoders() reports false
// if any worker was, since it last reported.
const MIN_DIM = 21;
const MAX_DIM = 4096;
const MAX_PIXELS = 4_194_304;

const decoders = new Set();
// Stops whose workers are still scrubbing: a stopped decoder leaves the
// registry at once, so retireQrDecoders() waits for these too.
const retiringStops = new Set();
// A worker terminated without acknowledging its scrub since the last
// retireQrDecoders() report.
let unscrubbedSinceReport = false;

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
  let stopPromise = null;
  let failedScrub = false;
  const stopping = new Set();

  const terminate = (entry, scrubbed) => {
    if (!stopping.has(entry)) return;
    stopping.delete(entry);
    clearTimeout(entry.scrubTimer);
    entry.worker.terminate();
    if (entry.url) URL.revokeObjectURL(entry.url);
    if (!scrubbed) {
      failedScrub = true;
      unscrubbedSinceReport = true;
    }
    entry.resolve(scrubbed);
  };

  const retire = () => {
    const entry = spawned;
    if (!entry) return null;
    spawned = null;
    stopping.add(entry);
    const deadline = entry.busy ? Math.max(scrubMs, timeoutMs) : scrubMs;
    entry.busy = false;
    entry.retired = new Promise((resolve) => {
      entry.resolve = resolve;
    });
    try {
      entry.worker.postMessage({ type: "scrub" });
    } catch {
      // A worker that cannot take the scrub is terminated all the same.
    }
    if (stopping.has(entry)) {
      entry.scrubTimer = setTimeout(() => terminate(entry, false), deadline);
    }
    return entry.retired;
  };

  const zeroPayload = (data) => {
    if (data?.payload instanceof ArrayBuffer) new Uint8Array(data.payload).fill(0);
  };

  const settle = (entry, data) => {
    // Only the reply to the decode in flight ends it: a stale reply must not
    // make a busy worker look idle and shorten its scrub deadline.
    if ((data?.type === "decoded" || data?.type === "error") && data.run === entry.busyRun) entry.busy = false;
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
    const entry = { worker, url, scrubTimer: null, busy: false, retired: null, resolve: null };
    worker.onmessage = (event) => {
      const data = event.data;
      if (data?.type === "scrubbed") {
        if (stopping.has(entry)) terminate(entry, true);
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
        entry.busy = true;
        entry.busyRun = run;
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
    if (stopPromise) return stopPromise;
    stoppedFlag = true;
    decoders.delete(decoder);
    if (pending) {
      const { reject, timer } = pending;
      pending = null;
      clearTimeout(timer);
      reject(failure("STOPPED"));
    }
    const retiring = [...stopping];
    const fresh = retire();
    const promises = retiring.map((entry) => entry.retired);
    if (fresh) promises.push(fresh);
    stopPromise = Promise.all(promises).then((results) => ({ scrubbed: results.every(Boolean) && !failedScrub }));
    const settled = stopPromise;
    retiringStops.add(settled);
    settled.then(() => retiringStops.delete(settled));
    return stopPromise;
  };

  const decoder = { decode, stop };
  decoders.add(decoder);
  return decoder;
}

export function retireQrDecoders() {
  const earlier = [...retiringStops];
  const stops = [...decoders].map((decoder) => decoder.stop());
  return Promise.all([...earlier, ...stops]).then((results) => {
    const scrubbed = results.every((result) => result.scrubbed) && !unscrubbedSinceReport;
    unscrubbedSinceReport = false;
    return { scrubbed };
  });
}
