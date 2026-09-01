// LifeHash (https://lifehash.info), version2, rendered as a crisp PNG data URL.
//
// A visual hash: SHA-256 seeds a 16x16 Conway's Game of Life; the run's
// history is collapsed into a grayscale "frac" grid, then coloured by a
// gradient and mirrored by a symmetry pattern chosen from hash bits. The
// result is a deterministic, recognisable icon for a fingerprint.
//
// Faithful port of the reference algorithm (Blockchain Commons / the
// `lifehash` JS package), using WebCrypto SHA-256 so no dependency is added.
// Rendered via Canvas into a same-origin data URL, so it works fully offline
// and inside the document's CSP (img-src 'self' data:).

const hodlLifeHash = (() => {
  const SIZE = 16;
  const MAX_GENERATIONS = 150;

  const sha256 = async (bytes) => new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));

  // MSB-first bit reader over a byte array.
  const makeBitEnumerator = (data) => {
    let index = 0, mask = 128;
    const hasNext = () => mask !== 0 || index !== data.length - 1;
    const next = () => {
      if (!hasNext()) throw new Error("BitEnumerator underflow.");
      if (mask === 0) { mask = 128; index += 1; }
      const bit = (data[index] & mask) !== 0;
      mask >>= 1;
      return bit;
    };
    const nextBits = (bitMask, bits) => {
      let val = 0, m = bitMask;
      for (let i = 0; i < bits; i += 1) { if (next()) val |= m; m >>= 1; }
      return val;
    };
    return {
      next,
      nextUint2: () => nextBits(2, 2),
      nextFrac: () => nextBits(32768, 16) / 65535.0,
    };
  };

  // --- Game of Life on a toroidal 16x16 grid -------------------------------
  const gridIndex = (x, y) => y * SIZE + x;
  const wrap = (i) => (i + SIZE) % SIZE;

  const countNeighbors = (cells, x, y) => {
    let total = 0;
    for (let oy = -1; oy <= 1; oy += 1) {
      for (let ox = -1; ox <= 1; ox += 1) {
        if (ox === 0 && oy === 0) continue;
        if (cells[gridIndex(wrap(x + ox), wrap(y + oy))]) total += 1;
      }
    }
    return total;
  };

  const cellsToBytes = (cells) => {
    const out = new Uint8Array((SIZE * SIZE) / 8);
    for (let i = 0; i < SIZE * SIZE; i += 1) {
      if (cells[i]) out[i >> 3] |= 128 >> (i & 7);
    }
    return out;
  };

  const runGameOfLife = async (digest) => {
    // version2 seeds from a second hash of the digest.
    const seed = await sha256(digest);
    let cells = new Array(SIZE * SIZE).fill(false);
    for (let i = 0; i < SIZE * SIZE; i += 1) cells[i] = (seed[i >> 3] & (128 >> (i & 7))) !== 0;

    const historySet = new Set();
    const history = [];
    while (history.length < MAX_GENERATIONS) {
      const data = cellsToBytes(cells);
      const key = (await sha256(data)).toString();
      if (historySet.has(key)) break;
      historySet.add(key);
      history.push(data);
      const next = new Array(SIZE * SIZE).fill(false);
      for (let y = 0; y < SIZE; y += 1) {
        for (let x = 0; x < SIZE; x += 1) {
          const alive = cells[gridIndex(x, y)];
          const n = countNeighbors(cells, x, y);
          next[gridIndex(x, y)] = alive ? n === 2 || n === 3 : n === 3;
        }
      }
      cells = next;
    }
    return history;
  };

  // --- Colour ---------------------------------------------------------------
  const clamp01 = (n) => Math.max(Math.min(n, 1), 0);
  // interpolate is a plain lerp; lerpFraction is its inverse (value -> 0..1 fraction).
  const interpolate = (a, b, t) => t * (b - a) + a;
  const lerpFraction = (fromA, fromB, t) => (fromA - t) / (fromA - fromB);
  const lerp = (fromA, fromB, toC, toD, t) => interpolate(toC, toD, lerpFraction(fromA, fromB, t));
  const modulo = (a, b) => ((a % b) + b) % b;

  const rgb = (r, g, b) => ({ r, g, b });
  const lerpColor = (c1, c2, t) => {
    const f = clamp01(t);
    return rgb(clamp01(c1.r * (1 - f) + c2.r * f), clamp01(c1.g * (1 - f) + c2.g * f), clamp01(c1.b * (1 - f) + c2.b * f));
  };
  const lighten = (c, t) => lerpColor(c, rgb(1, 1, 1), t);
  const darken = (c, t) => lerpColor(c, rgb(0, 0, 0), t);
  const luminance = (c) => Math.sqrt((0.299 * c.r) ** 2 + (0.587 * c.g) ** 2 + (0.114 * c.b) ** 2);

  const fromUint8 = (r, g, b) => rgb(r / 255, g / 255, b / 255);
  const spectrumCmykSafe = blendMany([
    [0, 168, 222], [41, 60, 130], [210, 59, 130], [217, 63, 53], [244, 228, 81], [0, 158, 84], [0, 168, 222],
  ].map(([r, g, b]) => fromUint8(r, g, b)));

  function blend(color1, color2) {
    return (t) => lerpColor(color1, color2, t);
  }
  function blendMany(colors) {
    const count = colors.length;
    if (count === 0) return blend(rgb(0, 0, 0), rgb(0, 0, 0));
    if (count === 1) return blend(colors[0], colors[0]);
    if (count === 2) return blend(colors[0], colors[1]);
    return (t) => {
      if (t >= 1) return colors[count - 1];
      if (t <= 0) return colors[0];
      const segments = count - 1, s = t * segments, segment = Math.trunc(s), frac = modulo(s, 1);
      return lerpColor(colors[segment], colors[segment + 1], frac);
    };
  }
  const reverse = (fn) => (t) => fn(1 - t);

  const monochromatic = (entropy) => {
    const hue = entropy.nextFrac();
    const isTint = entropy.next();
    const isReversed = entropy.next();
    const keyAdvance = entropy.nextFrac() * 0.3 + 0.05;
    const neutralAdvance = entropy.nextFrac() * 0.3 + 0.05;
    let keyColor = spectrumCmykSafe(hue);
    let contrastBrightness;
    if (isTint) { contrastBrightness = 1; keyColor = darken(keyColor, 0.5); } else { contrastBrightness = 0; }
    const neutralColor = rgb(contrastBrightness, contrastBrightness, contrastBrightness);
    const gradient = blend(lerpColor(keyColor, neutralColor, keyAdvance), lerpColor(neutralColor, keyColor, neutralAdvance));
    return isReversed ? reverse(gradient) : gradient;
  };
  const complementary = (entropy) => {
    const s1 = entropy.nextFrac();
    const s2 = modulo(s1 + 0.5, 1);
    const lighterAdvance = entropy.nextFrac() * 0.3;
    const darkerAdvance = entropy.nextFrac() * 0.3;
    const isReversed = entropy.next();
    const c1 = spectrumCmykSafe(s1), c2 = spectrumCmykSafe(s2);
    const [darker, lighter] = luminance(c1) > luminance(c2) ? [c2, c1] : [c1, c2];
    const gradient = blend(darken(darker, darkerAdvance), lighten(lighter, lighterAdvance));
    return isReversed ? reverse(gradient) : gradient;
  };
  const triadic = (entropy) => {
    const s1 = entropy.nextFrac();
    const s2 = modulo(s1 + 1 / 3, 1);
    const s3 = modulo(s1 + 2 / 3, 1);
    const lighterAdvance = entropy.nextFrac() * 0.3;
    const darkerAdvance = entropy.nextFrac() * 0.3;
    const isReversed = entropy.next();
    const sorted = [spectrumCmykSafe(s1), spectrumCmykSafe(s2), spectrumCmykSafe(s3)].sort((a, b) => luminance(a) - luminance(b));
    const gradient = blendMany([lighten(sorted[2], lighterAdvance), sorted[1], darken(sorted[0], darkerAdvance)]);
    return isReversed ? reverse(gradient) : gradient;
  };
  const analogous = (entropy) => {
    const s1 = entropy.nextFrac();
    const s2 = modulo(s1 + 1 / 12, 1);
    const s3 = modulo(s1 + 2 / 12, 1);
    const s4 = modulo(s1 + 3 / 12, 1);
    const advance = entropy.nextFrac() * 0.5 + 0.2;
    const isReversed = entropy.next();
    const c1 = spectrumCmykSafe(s1), c2 = spectrumCmykSafe(s2), c3 = spectrumCmykSafe(s3), c4 = spectrumCmykSafe(s4);
    const [darkest, dark, light, lightest] = luminance(c1) < luminance(c4) ? [c1, c2, c3, c4] : [c4, c3, c2, c1];
    const gradient = blendMany([darken(darkest, advance), darken(dark, advance / 2), lighten(light, advance / 2), lighten(lightest, advance)]);
    return isReversed ? reverse(gradient) : gradient;
  };
  const selectGradient = (entropy) => {
    const val = entropy.nextUint2();
    if (val === 0) return monochromatic(entropy);
    if (val === 1) return complementary(entropy);
    if (val === 2) return triadic(entropy);
    if (val === 3) return analogous(entropy);
    return blend(rgb(0, 0, 0), rgb(1, 1, 1));
  };

  // --- Frac grid (history collapsed to grayscale) ---------------------------
  const buildFracGrid = (history) => {
    const frac = new Array(SIZE * SIZE).fill(0);
    for (let i = 0; i < history.length; i += 1) {
      const f = clamp01(lerpFraction(0, history.length, i + 1));
      const data = history[i];
      for (let p = 0; p < SIZE * SIZE; p += 1) {
        if ((data[p >> 3] & (128 >> (p & 7))) !== 0) frac[p] = f;
      }
    }
    // version2 normalises the frac range to [0, 1].
    const min = Math.min(...frac), max = Math.max(...frac);
    if (max > min) for (let p = 0; p < SIZE * SIZE; p += 1) frac[p] = lerpFraction(min, max, frac[p]);
    return frac;
  };

  // --- Symmetry: snowflake (bit 1) or pinwheel (bit 0), output is 32x32 -----
  const renderColors = (frac, gradient, snowflake) => {
    const OUT = SIZE * 2;
    const out = new Uint8Array(OUT * OUT * 3);
    const maxX = OUT - 1, maxY = OUT - 1;
    const set = (x, y, color) => {
      const o = (y * OUT + x) * 3;
      out[o] = Math.floor(clamp01(color.r) * 255);
      out[o + 1] = Math.floor(clamp01(color.g) * 255);
      out[o + 2] = Math.floor(clamp01(color.b) * 255);
    };
    for (let y = 0; y < SIZE; y += 1) {
      for (let x = 0; x < SIZE; x += 1) {
        const color = gradient(frac[gridIndex(x, y)]);
        if (snowflake) {
          set(x, y, color); set(maxX - x, y, color); set(x, maxY - y, color); set(maxX - x, maxY - y, color);
        } else {
          set(x, y, color); set(y, maxX - x, color); set(maxY - y, x, color); set(maxX - x, maxY - y, color);
        }
      }
    }
    return { width: OUT, height: OUT, data: out };
  };

  // --- Minimal PNG encoder (truecolour, no filtering) ------------------------
  const crcTable = (() => {
    const table = new Uint32Array(256);
    for (let n = 0; n < 256; n += 1) {
      let c = n;
      for (let k = 0; k < 8; k += 1) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
      table[n] = c >>> 0;
    }
    return table;
  })();
  const crc32 = (bytes) => {
    let c = 0xffffffff;
    for (let i = 0; i < bytes.length; i += 1) c = crcTable[(c ^ bytes[i]) & 0xff] ^ (c >>> 8);
    return (c ^ 0xffffffff) >>> 0;
  };
  const chunk = (type, data) => {
    const out = new Uint8Array(8 + data.length + 4);
    const view = new DataView(out.buffer);
    view.setUint32(0, data.length);
    out.set(type, 4);
    out.set(data, 8);
    view.setUint32(8 + data.length, crc32(out.subarray(4, 8 + data.length)));
    return out;
  };
  const u32 = (n) => Uint8Array.from([(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255]);
  const adler32 = (bytes) => {
    let a = 1, b = 0;
    for (let i = 0; i < bytes.length; i += 1) { a = (a + bytes[i]) % 65521; b = (b + a) % 65521; }
    return ((b << 16) | a) >>> 0;
  };
  const ascii = (s) => Uint8Array.from([...s].map((c) => c.charCodeAt(0)));

  const encodePng = (width, height, rgbData) => {
    // One scanline per row, filter type 0, wrapped in a single stored deflate block.
    const stride = width * 3;
    const raw = new Uint8Array((stride + 1) * height);
    for (let y = 0; y < height; y += 1) {
      raw[y * (stride + 1)] = 0;
      raw.set(rgbData.subarray(y * stride, (y + 1) * stride), y * (stride + 1) + 1);
    }
    const blocks = [];
    const MAX = 65535;
    for (let offset = 0; offset < raw.length; offset += MAX) {
      const slice = raw.subarray(offset, Math.min(offset + MAX, raw.length));
      const last = offset + MAX >= raw.length;
      const block = new Uint8Array(5 + slice.length);
      block[0] = last ? 1 : 0;
      const view = new DataView(block.buffer);
      view.setUint16(1, slice.length, true);
      view.setUint16(3, ~slice.length & 0xffff, true);
      block.set(slice, 5);
      blocks.push(block);
    }
    const zlib = new Uint8Array(2 + blocks.reduce((n, b) => n + b.length, 0) + 4);
    zlib[0] = 0x78; zlib[1] = 0x01;
    let at = 2;
    for (const block of blocks) { zlib.set(block, at); at += block.length; }
    new DataView(zlib.buffer).setUint32(at, adler32(raw));

    const ihdr = new Uint8Array(13);
    ihdr.set(u32(width), 0); ihdr.set(u32(height), 4);
    ihdr[8] = 8; ihdr[9] = 2; // 8-bit truecolour
    const png = [
      Uint8Array.from([137, 80, 78, 71, 13, 10, 26, 10]),
      chunk(ascii("IHDR"), ihdr),
      chunk(ascii("IDAT"), zlib),
      chunk(ascii("IEND"), new Uint8Array(0)),
    ];
    const total = png.reduce((n, part) => n + part.length, 0);
    const out = new Uint8Array(total);
    let offset = 0;
    for (const part of png) { out.set(part, offset); offset += part.length; }
    return out;
  };

  const base64 = (bytes) => {
    let binary = "";
    const CHUNK = 8192;
    for (let i = 0; i < bytes.length; i += CHUNK) binary += String.fromCharCode(...bytes.subarray(i, i + CHUNK));
    return btoa(binary);
  };

  // --- Public: data URL for a 32-byte digest ---------------------------------
  const fromDigest = async (digest, moduleSize = 3) => {
    if (!(digest instanceof Uint8Array) || digest.length !== 32) throw new Error("LifeHash digest must be 32 bytes.");
    const history = await runGameOfLife(digest);
    const entropy = makeBitEnumerator(digest);
    entropy.next(); entropy.next(); // version2 burns two bits before the gradient
    const gradient = selectGradient(entropy);
    const snowflake = entropy.next();
    const frac = buildFracGrid(history);
    const { width, height, data } = renderColors(frac, gradient, snowflake);
    const scaled = scaleUp(width, height, data, moduleSize);
    return "data:image/png;base64," + base64(encodePng(scaled.width, scaled.height, scaled.data));
  };

  const scaleUp = (width, height, data, moduleSize) => {
    const w = width * moduleSize, h = height * moduleSize;
    const out = new Uint8Array(w * h * 3);
    for (let y = 0; y < h; y += 1) {
      for (let x = 0; x < w; x += 1) {
        const so = (Math.floor(y / moduleSize) * width + Math.floor(x / moduleSize)) * 3;
        const to = (y * w + x) * 3;
        out[to] = data[so]; out[to + 1] = data[so + 1]; out[to + 2] = data[so + 2];
      }
    }
    return { width: w, height: h, data: out };
  };

  // The app identifies keys by their 8-hex-digit master fingerprint. The raw
  // fingerprint bytes are hashed — not their hex string form — matching
  // Sparrow (toucan's LifeHashIcon.setHex hashes hexToBytes(fingerprint)), so
  // the same fingerprint shows the same icon across wallets. Note this
  // deliberately differs from lifehash.info, which hashes the string.
  const fromFingerprint = async (fingerprintHex, moduleSize) =>
    fromDigest(await sha256(hexToBytes(String(fingerprintHex))), moduleSize);

  // Case-insensitive (mixed-case hex decodes to the same bytes).
  const hexToBytes = (hex) => {
    if (hex.length % 2 !== 0 || /[^0-9a-f]/i.test(hex)) throw new Error("LifeHash fingerprint must be even-length hex.");
    const out = new Uint8Array(hex.length / 2);
    for (let i = 0; i < out.length; i += 1) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    return out;
  };

  return { fromDigest, fromFingerprint, _internals: { runGameOfLife, buildFracGrid, selectGradient, renderColors, encodePng, makeBitEnumerator } };
})();
