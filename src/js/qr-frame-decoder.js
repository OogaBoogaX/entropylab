import { createQrDecoder } from "./qr-scan.js";
import { QR_WASM_B64 } from "./qr-wasm-b64.js";

// Camera pixel conversion only; worker ownership, deadlines and scrubbing are
// provided by the shared decoder. No separate worker or decoder implementation.
// stop() retires the current worker; a subsequent decode intentionally starts a
// fresh one for the next message. Returned bytes are wiped, but decoded strings
// are immutable and transferred frames rely on best-effort worker cleanup.
export function createQrFrameDecoder({ createDecoder = createQrDecoder } = {}) {
  let decoder = null, generation = 0;
  return {
    stop() {
      generation++;
      const previous = decoder;
      decoder = null;
      previous?.stop();
    },
    async decode(rgba, width, height) {
      const epoch = generation;
      let gray, payload;
      try {
        if (!(rgba instanceof Uint8ClampedArray) || !Number.isInteger(width) ||
            !Number.isInteger(height) || width < 21 || height < 21 ||
            width > 1280 || height > 960 || rgba.length !== width * height * 4)
          throw new Error("INVALID_CAMERA_FRAME");
        gray = new Uint8Array(width * height);
        for (let i = 0; i < gray.length; i++) {
          const p = i * 4;
          gray[i] = (77 * rgba[p] + 150 * rgba[p + 1] + 29 * rgba[p + 2]) >>> 8;
        }
        rgba.fill(0);
        if (!decoder) {
          const wasmBytes = Uint8Array.from(atob(QR_WASM_B64), c => c.charCodeAt(0));
          decoder = createDecoder({ wasmBytes });
        }
        const result = await decoder.decode(gray, width, height);
        payload = result.payload;
        if (epoch !== generation) return null;
        if (result.code === -1 || result.code === -2 || result.code === -3 || result.code === -4) return null;
        if (!Number.isInteger(result.code) || result.code <= 0 || result.code > 4096 ||
            !(payload instanceof Uint8Array) || payload.length !== result.code)
          throw new Error("INVALID_QR_RESULT");
        return new TextDecoder("utf-8", { fatal: true }).decode(payload);
      } finally {
        if (rgba instanceof Uint8ClampedArray) rgba.fill(0);
        // The shared worker transfers this buffer; detached views cannot fill.
        if (gray?.byteLength) gray.fill(0);
        if (payload instanceof Uint8Array) payload.fill(0);
      }
    },
  };
}
