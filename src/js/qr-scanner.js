// The camera scanner controller (preview builds only). It owns the camera
// stream, the frame loop and the canvas; the decoder's lifetime is the
// caller's. Nothing here logs, stores or returns a frame: every grayscale
// buffer is handed to the decoder, which zeroes it, and every ImageData is
// zeroed as soon as it has been read.
//
// Security contract: a frame is read only while a live session's generation
// still matches, a stream that resolves after stop() or a later start() has
// its tracks stopped and is dropped, and a decode reply that arrives after
// its session ended is discarded (its payload zeroed) instead of reaching
// onResult.

const MAX_IMAGE_BYTES = 10 * 1024 * 1024;
const MAX_IMAGE_PIXELS = 4_194_304;
const MAX_IMAGE_SIDE = 4096;
const RASTER_TYPES = new Set(["image/png", "image/jpeg", "image/webp", "image/bmp"]);

const failure = (code) => Object.assign(new Error(code), { code });

const wipe = (buffer) => {
  try {
    if (ArrayBuffer.isView(buffer)) new Uint8Array(buffer.buffer, buffer.byteOffset, buffer.byteLength).fill(0);
    else if (buffer instanceof ArrayBuffer) new Uint8Array(buffer).fill(0);
  } catch {
    // A detached buffer holds nothing to wipe.
  }
};

const stopTracks = (stream) => {
  let tracks = [];
  try {
    tracks = stream?.getTracks?.() ?? [];
  } catch {
    tracks = [];
  }
  for (const track of tracks) {
    try {
      track.stop();
    } catch {
      // A track that already ended has nothing to stop.
    }
  }
};

const cameraStatus = (error) => {
  const name = String(error?.name ?? "");
  if (name === "NotAllowedError" || name === "PermissionDeniedError" || name === "SecurityError") return "denied";
  if (name === "NotFoundError" || name === "DevicesNotFoundError" || name === "OverconstrainedError") return "no-camera";
  return "error";
};

export function createQrScanner({
  decoder,
  mediaDevices = globalThis.navigator?.mediaDevices,
  isSecureContext = globalThis.isSecureContext,
  video,
  canvas,
  timeoutMs = 60000,
  maxFrame = { width: 1280, height: 720 },
  requestFrame = globalThis.requestAnimationFrame,
  onResult,
  onStatus,
} = {}) {
  let generation = 0;
  let active = null;

  const status = (code, detail) => {
    try {
      onStatus?.(code, detail);
    } catch {
      // A listener must not leave the camera running.
    }
  };

  const teardown = () => {
    generation += 1;
    const current = active;
    active = null;
    if (current) {
      current.live = false;
      if (current.timer !== null) {
        clearTimeout(current.timer);
        current.timer = null;
      }
      if (current.stream) {
        stopTracks(current.stream);
        current.stream = null;
      }
    }
    try {
      video.pause?.();
      video.srcObject = null;
    } catch {
      // A detached video has nothing to release.
    }
    try {
      canvas.width = 0;
      canvas.height = 0;
    } catch {
      // A detached canvas has nothing to clear.
    }
    return current !== null;
  };

  const readGray = (ctx, width, height) => {
    const image = ctx.getImageData(0, 0, width, height);
    const data = image?.data;
    if (!data || data.length !== width * height * 4) {
      wipe(data);
      throw failure("UNREADABLE");
    }
    const gray = new Uint8Array(width * height);
    try {
      for (let i = 0, j = 0; i < gray.length; i += 1, j += 4) {
        gray[i] = (77 * data[j] + 150 * data[j + 1] + 29 * data[j + 2]) >> 8;
      }
    } finally {
      data.fill(0);
    }
    return gray;
  };

  const schedule = (current) => {
    if (!current.live || current.gen !== generation || current.frameRequested) return;
    current.frameRequested = true;
    try {
      requestFrame(() => {
        current.frameRequested = false;
        if (!current.live || current.gen !== generation) return;
        frame(current);
      });
    } catch {
      current.frameRequested = false;
    }
  };

  const settle = (current, reply) => {
    const code = reply?.code;
    if (Number.isInteger(code) && code > 0) {
      const payload = reply?.payload;
      // A positive code is the payload's byte length; anything else is a
      // malformed reply, never a scan.
      if (!(payload instanceof Uint8Array) || payload.length !== code) {
        wipe(payload);
        teardown();
        status("error", "DECODE_FAILED");
        return;
      }
      teardown();
      try {
        onResult?.(payload);
      } catch {
        // The caller owns the payload now.
      }
      return;
    }
    // No other reply carries a scan: any payload that came with one is wiped.
    wipe(reply?.payload);
    if (code === -3) {
      status("two-codes");
      schedule(current);
      return;
    }
    if (code === -1 || code === -2 || code === -4) {
      schedule(current);
      return;
    }
    teardown();
    status("error", Number.isInteger(code) ? code : "DECODE_FAILED");
  };

  const fail = (current, error) => {
    const code = typeof error?.code === "string" ? error.code : "DECODE_FAILED";
    if (code === "BUSY") {
      schedule(current);
      return;
    }
    // fail() runs only for a live session (stop() ends it first and stays
    // silent), so STOPPED here means the decoder was retired underneath a
    // running scan: report it rather than leave the caller on "scanning".
    teardown();
    status("error", code);
  };

  const decodeFrame = (current, gray, width, height) => {
    current.decoding = true;
    let pending;
    try {
      pending = decoder.decode(gray, width, height);
    } catch (error) {
      current.decoding = false;
      wipe(gray);
      fail(current, error);
      return;
    }
    Promise.resolve(pending).then(
      (reply) => {
        current.decoding = false;
        if (!current.live || current.gen !== generation) {
          wipe(reply?.payload);
          return;
        }
        settle(current, reply);
      },
      (error) => {
        current.decoding = false;
        if (!current.live || current.gen !== generation) return;
        fail(current, error);
      },
    );
  };

  const frame = (current) => {
    if (!current.live || current.gen !== generation) return;
    if (current.decoding) {
      schedule(current);
      return;
    }
    const sourceWidth = Number(video?.videoWidth) || 0;
    const sourceHeight = Number(video?.videoHeight) || 0;
    if (sourceWidth <= 0 || sourceHeight <= 0) {
      schedule(current);
      return;
    }
    const scale = Math.min(1, maxFrame.width / sourceWidth, maxFrame.height / sourceHeight);
    const width = Math.max(1, Math.floor(sourceWidth * scale));
    const height = Math.max(1, Math.floor(sourceHeight * scale));
    let ctx = null;
    try {
      ctx = canvas.getContext("2d", { willReadFrequently: true });
    } catch {
      ctx = null;
    }
    if (!ctx) {
      teardown();
      status("error", "UNREADABLE");
      return;
    }
    try {
      canvas.width = width;
      canvas.height = height;
      ctx.drawImage(video, 0, 0, width, height);
    } catch {
      teardown();
      status("error", "UNREADABLE");
      return;
    }
    let gray;
    try {
      gray = readGray(ctx, width, height);
    } catch (error) {
      teardown();
      status("error", typeof error?.code === "string" ? error.code : "UNREADABLE");
      return;
    }
    decodeFrame(current, gray, width, height);
    schedule(current);
  };

  const start = () => {
    if (!isSecureContext || typeof mediaDevices?.getUserMedia !== "function") {
      status("unsupported");
      return;
    }
    teardown();
    const current = { gen: generation, stream: null, timer: null, decoding: false, frameRequested: false, live: true };
    active = current;
    let request;
    try {
      request = mediaDevices.getUserMedia({
        video: { facingMode: "environment", width: { ideal: 640 }, height: { ideal: 480 } },
        audio: false,
      });
    } catch (error) {
      active = null;
      current.live = false;
      status(cameraStatus(error), error?.name);
      return;
    }
    Promise.resolve(request).then(
      (stream) => {
        if (!current.live || current.gen !== generation) {
          stopTracks(stream);
          return;
        }
        current.stream = stream;
        try {
          video.srcObject = stream;
          // A stream does not play by itself: a paused video keeps handing
          // the canvas its first frame. start() runs from a click, so the
          // browser allows play(); a refusal leaves the timeout to report.
          video.muted = true;
          const playing = video.play?.();
          if (playing && typeof playing.catch === "function") playing.catch(() => {});
        } catch {
          // A detached video cannot show the stream; the tracks still stop.
        }
        status("scanning");
        current.timer = setTimeout(() => {
          current.timer = null;
          if (!current.live || current.gen !== generation) return;
          teardown();
          status("timeout");
        }, timeoutMs);
        schedule(current);
      },
      (error) => {
        if (!current.live || current.gen !== generation) return;
        active = null;
        current.live = false;
        status(cameraStatus(error), error?.name);
      },
    );
  };

  const stop = () => {
    if (teardown()) status("stopped");
  };

  // Rejects with TOO_LARGE, UNSUPPORTED_TYPE or UNREADABLE for the file
  // itself; a decoder refusal passes through with its own code (BUSY while a
  // camera frame is still decoding, STOPPED after retireQrDecoders()), so the
  // caller stops the camera before scanning a photo.
  const scanImage = async (file) => {
    if (!file || typeof file.size !== "number" || typeof file.type !== "string") throw failure("UNREADABLE");
    if (file.size > MAX_IMAGE_BYTES) throw failure("TOO_LARGE");
    if (!RASTER_TYPES.has(file.type.toLowerCase())) throw failure("UNSUPPORTED_TYPE");
    if (typeof createImageBitmap !== "function") throw failure("UNREADABLE");
    let bitmap = null;
    try {
      bitmap = await createImageBitmap(file);
    } catch {
      throw failure("UNREADABLE");
    }
    try {
      const sourceWidth = Number(bitmap?.width) || 0;
      const sourceHeight = Number(bitmap?.height) || 0;
      if (sourceWidth <= 0 || sourceHeight <= 0) throw failure("UNREADABLE");
      const scale = Math.min(
        1,
        MAX_IMAGE_SIDE / sourceWidth,
        MAX_IMAGE_SIDE / sourceHeight,
        Math.sqrt(MAX_IMAGE_PIXELS / (sourceWidth * sourceHeight)),
      );
      // Round down: rounding up can land a few pixels over the decoder's cap.
      const width = Math.max(1, Math.floor(sourceWidth * scale));
      const height = Math.max(1, Math.floor(sourceHeight * scale));
      let ctx = null;
      try {
        ctx = canvas.getContext("2d", { willReadFrequently: true });
      } catch {
        ctx = null;
      }
      if (!ctx) throw failure("UNREADABLE");
      canvas.width = width;
      canvas.height = height;
      ctx.drawImage(bitmap, 0, 0, width, height);
      const gray = readGray(ctx, width, height);
      let reply;
      try {
        reply = await decoder.decode(gray, width, height);
      } finally {
        // The decoder zeroes (or detaches) the frame; wiping here as well
        // costs nothing and does not depend on that.
        wipe(gray);
      }
      const code = reply?.code;
      // The same rules as the camera path: a positive code is the payload's
      // byte length; -1 to -4 are "no single code" results and carry nothing;
      // any other reply is malformed. Only a scan ever returns bytes.
      if (Number.isInteger(code) && code > 0) {
        if (!(reply.payload instanceof Uint8Array && reply.payload.length === code)) {
          wipe(reply?.payload);
          throw failure("DECODE_FAILED");
        }
        return { code, payload: reply.payload };
      }
      wipe(reply?.payload);
      if (code === -1 || code === -2 || code === -3 || code === -4) return { code, payload: null };
      throw failure("DECODE_FAILED");
    } finally {
      try {
        bitmap?.close?.();
      } catch {
        // A bitmap that already closed has nothing to release.
      }
      try {
        canvas.width = 0;
        canvas.height = 0;
      } catch {
        // A detached canvas has nothing to clear.
      }
    }
  };

  return { start, stop, scanImage };
}
