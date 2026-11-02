// RFC1951 raw DEFLATE for BBQr's 10-bit window. No wrapper, dictionary,
// checksum, or streaming state: the caller supplies a complete bounded input.
const LENGTH_BASE = [3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258];
const LENGTH_BITS = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0];
const DISTANCE_BASE = [1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577];
const DISTANCE_BITS = [0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13];
const CODE_ORDER = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15];

function fail(code = "bad-part") {
  const error = new Error(code === "too-large" ? "DEFLATE output exceeds limit" : "Invalid BBQr DEFLATE stream");
  error.code = code;
  throw error;
}

function wipeTree(tree) {
  if (!tree) return;
  tree.counts.fill(0);
  tree.symbols.fill(0);
}

// Canonical codes are represented by counts per bit-length and symbols in
// length/symbol order, not a large lookup table. Reject incomplete trees except
// the RFC's one-bit singleton and the literal-only empty distance alphabet.
function makeTree(lengths, kind) {
  const counts = new Uint16Array(16);
  let symbols;
  let offsets;
  try {
    let max = 0;
    let total = 0;
    for (let i = 0; i < lengths.length; i += 1) {
      const length = lengths[i];
      if (!length) continue;
      if (length > 15) fail();
      counts[length] += 1;
      total += 1;
      if (length > max) max = length;
    }
    let left = 1;
    for (let length = 1; length <= 15; length += 1) {
      left = left * 2 - counts[length];
      if (left < 0) fail();
    }
    if (!max) {
      if (kind !== "distance") fail();
    } else if (left && (kind === "codes" || max !== 1)) {
      fail();
    }
    symbols = new Uint16Array(total);
    offsets = new Uint16Array(16);
    for (let length = 1; length < 15; length += 1) {
      offsets[length + 1] = offsets[length] + counts[length];
    }
    for (let symbol = 0; symbol < lengths.length; symbol += 1) {
      const length = lengths[symbol];
      if (length) symbols[offsets[length]++] = symbol;
    }
    return { counts, symbols, max };
  } catch (error) {
    counts.fill(0);
    symbols?.fill(0);
    throw error;
  } finally {
    offsets?.fill(0);
  }
}

// Fixed trees contain public RFC constants and are shared read-only. Build
// lazily so importing a preview reader adds no release-time initialization.
let fixedLiteral = null;
let fixedDistance = null;

// Returns a fresh owned Uint8Array. Never modifies input. Output exhaustion has
// code 'too-large'; malformed/truncated/trailing data or a distance over 1024
// has code 'bad-part'. The caller bounds compressed input separately. Owned
// scratch/output is wiped best-effort on both success and failure, not input.
export function inflateRawBounded(input, maxBytes) {
  if (!(input instanceof Uint8Array) || !Number.isSafeInteger(maxBytes) || maxBytes < 0) fail();
  let output;
  let position = 0;
  let bitBuffer = 0;
  let bitCount = 0;
  let written = 0;

  function readBits(count) {
    while (bitCount < count) {
      if (position >= input.length) fail();
      bitBuffer |= input[position++] << bitCount;
      bitCount += 8;
    }
    const value = bitBuffer & ((1 << count) - 1);
    bitBuffer >>>= count;
    bitCount -= count;
    return value;
  }

  function decode(tree) {
    let code = 0;
    let first = 0;
    let index = 0;
    for (let length = 1; length <= tree.max; length += 1) {
      code = code * 2 + readBits(1);
      const count = tree.counts[length];
      if (code >= first && code - first < count) return tree.symbols[index + code - first];
      index += count;
      first = (first + count) * 2;
    }
    fail();
  }

  function dynamicTrees() {
    let codeLengths;
    let lengths;
    let codeTree;
    let literal;
    let distance;
    try {
      const literalCount = readBits(5) + 257;
      const distanceCount = readBits(5) + 1;
      const codeCount = readBits(4) + 4;
      if (literalCount > 286) fail();
      codeLengths = new Uint8Array(19);
      for (let i = 0; i < codeCount; i += 1) codeLengths[CODE_ORDER[i]] = readBits(3);
      codeTree = makeTree(codeLengths, "codes");
      lengths = new Uint8Array(literalCount + distanceCount);
      let index = 0;
      while (index < lengths.length) {
        const symbol = decode(codeTree);
        if (symbol <= 15) {
          lengths[index++] = symbol;
          continue;
        }
        let repeat;
        let value = 0;
        if (symbol === 16) {
          if (!index) fail();
          value = lengths[index - 1];
          repeat = readBits(2) + 3;
        } else if (symbol === 17) {
          repeat = readBits(3) + 3;
        } else if (symbol === 18) {
          repeat = readBits(7) + 11;
        } else {
          fail();
        }
        if (repeat > lengths.length - index) fail();
        lengths.fill(value, index, index + repeat);
        index += repeat;
      }
      if (!lengths[256]) fail();
      literal = makeTree(lengths.subarray(0, literalCount), "literal");
      distance = makeTree(lengths.subarray(literalCount), "distance");
      return { literal, distance };
    } catch (error) {
      wipeTree(literal);
      wipeTree(distance);
      throw error;
    } finally {
      codeLengths?.fill(0);
      lengths?.fill(0);
      wipeTree(codeTree);
    }
  }

  try {
    output = new Uint8Array(maxBytes);
    let final;
    do {
      final = readBits(1);
      const type = readBits(2);
      if (type === 0) {
        // Stored blocks discard the current byte's padding and begin aligned.
        bitBuffer = 0;
        bitCount = 0;
        const length = readBits(16);
        if ((length ^ readBits(16)) !== 65535 || length > input.length - position) fail();
        if (length > maxBytes - written) fail("too-large");
        output.set(input.subarray(position, position + length), written);
        position += length;
        written += length;
      } else if (type === 1 || type === 2) {
        if (type === 1 && !fixedLiteral) {
          fixedLiteral = makeTree(Array.from({ length: 288 }, (_, i) => i < 144 ? 8 : i < 256 ? 9 : i < 280 ? 7 : 8), "literal");
          fixedDistance = makeTree(Array(32).fill(5), "distance");
        }
        const trees = type === 2 ? dynamicTrees() : null;
        const literal = trees ? trees.literal : fixedLiteral;
        const distance = trees ? trees.distance : fixedDistance;
        try {
          for (;;) {
            const symbol = decode(literal);
            if (symbol < 256) {
              if (written >= maxBytes) fail("too-large");
              output[written++] = symbol;
            } else if (symbol === 256) {
              break;
            } else {
              if (symbol > 285) fail();
              const lengthIndex = symbol - 257;
              const length = LENGTH_BASE[lengthIndex] + readBits(LENGTH_BITS[lengthIndex]);
              const distanceSymbol = decode(distance);
              if (distanceSymbol > 29) fail();
              const back = DISTANCE_BASE[distanceSymbol] + readBits(DISTANCE_BITS[distanceSymbol]);
              if (back > 1024 || back > written) fail();
              if (length > maxBytes - written) fail("too-large");
              // Forward bytewise copy deliberately permits overlapping matches.
              const end = written + length;
              while (written < end) {
                output[written] = output[written - back];
                written += 1;
              }
            }
          }
        } finally {
          if (trees) {
            wipeTree(trees.literal);
            wipeTree(trees.distance);
          }
        }
      } else {
        fail();
      }
    } while (!final);
    // readBits never prefetches whole unused bytes. Only the final byte's
    // unused high bits may remain; accepting an extra byte hides bad framing.
    if (position !== input.length) fail();
    return output.slice(0, written);
  } finally {
    output?.fill(0);
    bitBuffer = 0;
    bitCount = 0;
  }
}
