// In-memory transport observer. Never signs, generates entropy, or persists data.
import { hodlBytewordsDecode } from "./psbt-ur.js";
import { createUrCollector } from "./ur-fountain.js";
import { aexbDecode, aexbVerify } from "./aexb.js";
import { verifyAexbTransaction } from "./aexb-transaction.js";
const MAX_BYTES = 2065600,
  MAX_PARTS = 512,
  MAX_FRAME = 20000;
const equal = (a, b) => a.length === b.length && a.every((v, i) => v === b[i]);
function fail(code) {
  throw new Error(code);
}
// Canonical CBOR fields with bounded lengths; only a part checksum may also use
// the fixed-width uint32 form emitted by BCR-2024-001 reference encoders.
function reader(bytes) {
  let at = 0;
  const head = (major, fixedUint32 = false) => {
    if (at >= bytes.length) fail("CBOR_TRUNCATED");
    const h = bytes[at++];
    if (h >> 5 !== major) fail("CBOR_TYPE");
    const n = h & 31;
    if (n < 24) return n;
    const width = { 24: 1, 25: 2, 26: 4 }[n];
    if (!width || at + width > bytes.length) fail("CBOR_LENGTH");
    let v = 0;
    for (let i = 0; i < width; i++) v = v * 256 + bytes[at++];
    if (!(fixedUint32 && width === 4) && v < { 1: 24, 2: 256, 4: 65536 }[width]) fail("CBOR_NONCANONICAL");
    return v;
  };
  return {
    uint: () => head(0),
    // Preserve minimal-width checksums already accepted, plus fixed uint32.
    checksum: () => head(0, true),
    array: () => head(4),
    bstr: () => {
      const n = head(2);
      if (n > MAX_BYTES || at + n > bytes.length) fail("CBOR_LENGTH");
      const b = bytes.slice(at, at + n);
      at += n;
      return b;
    },
    end: () => {
      if (at !== bytes.length) fail("CBOR_TRAILING");
    },
  };
}
// Transport assembly belongs to the shared collector. The adapter keeps the
// ceremony's narrower wire grammar, limits and canonical CBOR byte envelope.
export class UrCapture {
  constructor({ track } = {}) {
    this.collector = createUrCollector({
      types: ["x-btc-anti-exfil"], maxMessageLen: MAX_BYTES,
      maxSeqLen: MAX_PARTS, track,
    });
  }
  clear() {
    this.collector.reset();
  }
  progress() {
    const state = this.collector.state();
    return {
      received: state.known,
      total: state.seqLen || 0,
      complete: state.status === "complete",
    };
  }
  receive(raw) {
    if (typeof raw !== "string" || raw.length > MAX_FRAME) fail("FRAME_LIMIT");
    const m = raw.trim().toLowerCase().match(/^ur:([a-z0-9-]+)\/(?:(\d+)-(\d+)\/)?([a-z]+)$/);
    if (!m) fail("INVALID_UR");
    if (m[1] !== "x-btc-anti-exfil") fail("UR_TYPE");
    // Preflight the ceremony-specific fragment cap and canonical wire encoding
    // before the shared collector retains any assembly state.
    if (m[2]) {
      const seq = Number(m[2]), count = Number(m[3]);
      if (!Number.isInteger(seq) || seq < 1 || seq > 0xffffffff || count < 1 || count > MAX_PARTS)
        fail("PART_LIMIT");
      const payload = hodlBytewordsDecode(m[4]);
      let data;
      try {
        const r = reader(payload);
        if (r.array() !== 5) fail("PART_FORMAT");
        if (r.uint() !== seq || r.uint() !== count) fail("PART_SEQUENCE");
        const length = r.uint();
        r.checksum(); // The shared collector checks the whole-message CRC.
        data = r.bstr();
        r.end();
        if (!length || length > MAX_BYTES || !data.length || data.length > 8192 || Math.ceil(length / data.length) !== count)
          fail("PART_LIMIT");
      } finally {
        payload.fill(0);
        data?.fill(0);
      }
    }
    const result = this.collector.receive(raw);
    if (result.status === "progress" || result.status === "duplicate") return this.progress();
    if (result.status !== "complete") {
      const errors = { mismatch: "MIXED_MESSAGE", conflict: "CONFLICTING_FRAME",
        invalid: "MESSAGE_CHECKSUM", "too-large": "PART_LIMIT", "wrong-type": "UR_TYPE" };
      fail(errors[result.status] || "INVALID_UR");
    }
    let bytes;
    try {
      const r = reader(result.message);
      bytes = r.bstr();
      r.end();
      return { complete: true, bytes };
    } catch (error) {
      bytes?.fill(0);
      throw error;
    } finally {
      // Completed output belongs to the caller; the collector retains no copy.
      result.message.fill(0);
    }
  }
}
function wipeMessage(bytes, decoded) {
  bytes?.fill(0);
  if (!decoded) return;
  for (const value of Object.values(decoded))
    if (value instanceof Uint8Array) value.fill(0);
  for (const value of Object.values(decoded.package || {}))
    if (value instanceof Uint8Array) value.fill(0);
  for (const slot of decoded.slots || [])
    for (const value of Object.values(slot))
      if (value instanceof Uint8Array) value.fill(0);
}
export class AexbCapture {
  constructor() {
    this.clear();
  }
  clear() {
    for (const entry of this.messages?.values() || [])
      wipeMessage(entry.bytes, entry.decoded);
    this.messages = new Map();
    this.transactionResult = null;
  }
  accept(input) {
    if (!(input instanceof Uint8Array) || input.length > MAX_BYTES)
      fail("MESSAGE_LIMIT");
    if (
      input[0] !== 65 ||
      input[1] !== 69 ||
      input[2] !== 88 ||
      input[3] !== 84
    )
      fail("AEXT_ENVELOPE_REQUIRED");
    const bytes = input.slice();
    let decoded, retained = false;
    try {
    decoded = aexbDecode(bytes);
    if (![2, 3, 4].includes(decoded.stage)) fail("CAPTURE_STAGE");
    const previous = this.messages.get(decoded.stage);
    if (previous) {
      if (!equal(bytes, previous.bytes)) fail("STAGE_CONFLICT");
      return this.snapshot();
    }
    const first = this.messages.values().next().value?.decoded;
    if (
      first &&
      (first.network !== decoded.network ||
        !equal(first.sessionId, decoded.sessionId) ||
        !equal(first.psbtDigest, decoded.psbtDigest))
    )
      fail("SESSION_MISMATCH");
    this.messages.set(decoded.stage, { bytes, decoded });
    retained = true;
    return this.snapshot();
    } finally {
      // Duplicate/rejected messages must not leave unnecessary owned copies.
      if (!retained) wipeMessage(bytes, decoded);
    }
  }
  snapshot() {
    const stages = [...this.messages.keys()].sort(),
      get = (s) => this.messages.get(s)?.decoded;
    let verdict = null;
    if (stages.length === 3) {
      try {
        verdict = aexbVerify(get(4), get(3), get(2));
      } catch {
        // accept() and UI reads also verify. Let finish() clear the transcript
        // and the UI show STOP even when verification cannot complete.
        verdict = { ok: false, reason: "VERIFICATION_UNAVAILABLE" };
      }
    }
    return { stages, verdict };
  }
  finish() {
    if (this.messages.size !== 3) return null;
    let totalSlots = 0;
    try {
      totalSlots = this.messages.get(4).decoded.slots.length;
      const proof = this.snapshot().verdict;
      if (!proof.ok) return { ok: false, reason: proof.reason || proof.slots?.find(slot => !slot.ok)?.reason || "VERIFICATION_FAILED", checkedSlots: 0, totalSlots };
      return { ...this.checkTransaction(), totalSlots };
    } catch {
      return { ok: false, reason: "VERIFICATION_UNAVAILABLE", checkedSlots: 0, totalSlots };
    } finally {
      // Completion never keeps the transcript waiting for a human acknowledgement.
      this.clear();
    }
  }
  checkTransaction() {
    const proof = this.snapshot();
    if (!proof.verdict?.ok) return null;
    if (!this.transactionResult) this.transactionResult = verifyAexbTransaction(this.messages.get(3).decoded, this.messages.get(4).decoded);
    return { ...this.transactionResult };
  }
}
