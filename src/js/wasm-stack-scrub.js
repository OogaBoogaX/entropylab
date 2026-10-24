// Shadow-stack hygiene shared by the WASM loaders (entropylab-wasm.js,
// psbt-wasm.js).
//
// A Rust frame spills its arguments and temporaries into the WASM shadow
// stack, which lives in linear memory and is not erased when the frame pops.
// The boundary helpers (el_free / psbt_free) zero the heap buffers they
// release, but dead stack cells are outside any buffer, so each loader wraps
// its exports to zero the whole stack region once per task after any export
// ran (see makeStackScrub below).

// Returns the initial stack pointer of a stack-first module: the top of the
// region [0, top) that holds nothing but the downward-growing shadow stack.
// Read from the binary rather than assumed, and fails closed: if the linker
// layout ever changes (static data or a passive segment that could land below
// the stack top, no unique stack pointer, any imports), zeroing [0, top)
// would corrupt the module, so loading throws and the test suite fails.
export const stackRegion = (bytes) => {
  let p = 8;
  const uleb = () => {
    let value = 0, shift = 0, byte;
    do { byte = bytes[p++]; value += (byte & 0x7f) * 2 ** shift; shift += 7; } while (byte & 0x80);
    return value;
  };
  const sleb = () => {
    let value = 0, shift = 0, byte;
    do { byte = bytes[p++]; value += (byte & 0x7f) * 2 ** shift; shift += 7; } while (byte & 0x80);
    return byte & 0x40 ? value - 2 ** shift : value;
  };
  // A constant expression; returns its value when it is a plain i32.const.
  const constExpr = () => {
    const op = bytes[p++];
    let value = null;
    if (op === 0x41) value = sleb();
    else if (op === 0x42 || op === 0x23) sleb();
    else if (op === 0x43) p += 4;
    else if (op === 0x44) p += 8;
    else throw new Error(`stackRegion: unsupported constant expression opcode 0x${op.toString(16)}`);
    if (bytes[p++] !== 0x0b) throw new Error("stackRegion: unsupported constant expression");
    return value;
  };
  const stackPointers = [];
  const dataOffsets = [];
  while (p < bytes.length) {
    const id = bytes[p++];
    const size = uleb();
    const end = p + size;
    if (id === 2) throw new Error("stackRegion: the module has imports; the stack layout is not verified");
    if (id === 6) {
      for (let n = uleb(); n > 0; n--) {
        const type = bytes[p++];
        const mutable = bytes[p++] === 1;
        const init = constExpr();
        if (type === 0x7f && mutable && init !== null) stackPointers.push(init);
      }
    } else if (id === 11) {
      for (let n = uleb(); n > 0; n--) {
        const flags = uleb();
        if (flags === 1) throw new Error("stackRegion: passive data segment; not stack-first-verifiable");
        if (flags === 2) uleb();
        const offset = constExpr();
        if (offset === null) throw new Error("stackRegion: data segment offset is not a constant");
        dataOffsets.push(offset);
        const length = uleb(); // not `p += uleb()`: that reads p before uleb advances it
        p += length;
      }
    }
    p = end;
  }
  if (stackPointers.length !== 1) throw new Error(`stackRegion: expected one stack pointer, found ${stackPointers.length}`);
  const top = stackPointers[0];
  if (!(top > 0)) throw new Error("stackRegion: invalid stack pointer");
  if (dataOffsets.some((offset) => offset < top)) throw new Error("stackRegion: data below the stack top; the module is not stack-first");
  return top;
};

// Builds the per-module scrub plumbing for one loader: verifies the binary's
// stack-first layout at load, then returns the pieces the loader wires in:
//   bind(instance)  — records the memory (and refuses a heap below the stack)
//   scrubStack()    — zeroes the whole shadow-stack region; only valid while
//                     no export is running, which always holds when JS runs
//                     because these modules import nothing and so can never
//                     call back into JS mid-export
//   guard(exports)  — every export schedules one scrub per task on the way
//                     out, so no facade (and no future export) has to
//                     remember to; the fill costs about 20 µs for a 1 MiB
//                     stack, which is why it is batched
export const makeStackScrub = (bytes) => {
  const stackTop = stackRegion(bytes);
  let memory = null;
  let scrubQueued = false;
  const bind = (instance) => {
    memory = instance.exports.memory;
    if (instance.exports.__heap_base && instance.exports.__heap_base.value < stackTop) {
      throw new Error("WebAssembly module: the heap starts below the stack top");
    }
  };
  const scrubStack = () => {
    if (memory) new Uint8Array(memory.buffer).fill(0, 0, stackTop);
  };
  const scheduleScrub = () => {
    if (scrubQueued) return;
    scrubQueued = true;
    queueMicrotask(() => {
      scrubQueued = false;
      scrubStack();
    });
  };
  const guard = (exports) => {
    const wrapped = {};
    for (const [name, value] of Object.entries(exports)) {
      wrapped[name] = typeof value === "function"
        ? (...args) => {
            try {
              return value(...args);
            } finally {
              scheduleScrub();
            }
          }
        : value;
    }
    return Object.freeze(wrapped);
  };
  return { stackTop, bind, scrubStack, guard };
};

// End session's memory wipe, shared by both loaders' retirement: overwrites
// every byte with 0x55, 0xAA and 0xFF, alternating and complementary bit
// patterns, and finishes with 0x00, so the memory is left zeroed. Each pass
// covers the whole region; `onPass(pattern, bytes)` lets the suite observe it.
export const OVERWRITE_PATTERNS = Object.freeze([0x55, 0xaa, 0xff, 0x00]);
export const overwriteWithPatterns = (bytes, onPass) => {
  for (const pattern of OVERWRITE_PATTERNS) {
    bytes.fill(pattern);
    onPass?.(pattern, bytes);
  }
};
