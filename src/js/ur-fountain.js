// Bounded fountain decoder and strict UR collector for BCR-2024-001 parts.
// Pure module: no DOM, no camera, no user-facing strings (status codes only).
// PR 3/4 wire retireUrCollectors() into End Session and pagehide.
import { sha256 } from "./hashes.js";
import { hodlUrParsePart, hodlUrPartParse, hodlCrc32 } from "./psbt-ur.js";

const MASK64 = (1n << 64n) - 1n;

const rotl64 = (value, shift) => ((value << BigInt(shift)) | (value >> BigInt(64 - shift))) & MASK64;

export function xoshiro256(seedBytes) {
  const digest = sha256(seedBytes);
  const word = (index) => {
    let value = 0n;
    for (let i = 0; i < 8; i++) value = (value << 8n) | BigInt(digest[index * 8 + i]);
    return value;
  };
  let s0 = word(0);
  let s1 = word(1);
  let s2 = word(2);
  let s3 = word(3);
  const next = () => {
    const result = (rotl64((s1 * 5n) & MASK64, 7) * 9n) & MASK64;
    const t = (s1 << 17n) & MASK64;
    s2 ^= s0;
    s3 ^= s1;
    s1 ^= s2;
    s0 ^= s3;
    s2 ^= t;
    s3 = rotl64(s3, 45);
    s0 &= MASK64;
    s1 &= MASK64;
    s2 &= MASK64;
    s3 &= MASK64;
    return result;
  };
  const nextDouble = () => Number(next()) / 2 ** 64;
  // Converting a 64-bit draw to a double can round up to exactly 1.0 (the
  // reference has the same edge, about once in 2^53 draws): clamp, so the
  // result stays in range. No reference vector reaches it.
  const nextInt = (low, high) => Math.min(high, Math.floor(nextDouble() * (high - low + 1)) + low);
  const nextByte = () => nextInt(0, 255);
  const nextData = (count) => {
    const out = new Uint8Array(count);
    for (let i = 0; i < count; i++) out[i] = nextByte();
    return out;
  };
  return { next, nextDouble, nextInt, nextByte, nextData };
}

export const seedFromString = (text) => new TextEncoder().encode(text);

export const seedFromUint32 = (value) =>
  Uint8Array.of((value >>> 24) & 255, (value >>> 16) & 255, (value >>> 8) & 255, value & 255);

export function randomSampler(probs) {
  const n = probs.length;
  const sum = probs.reduce((total, weight) => total + weight, 0);
  const P = probs.map((weight) => (weight * n) / sum);
  const prob = new Array(n).fill(0);
  const alias = new Array(n).fill(0);
  const S = [];
  const L = [];
  for (let i = n - 1; i >= 0; i--) {
    if (P[i] < 1) S.push(i);
    else L.push(i);
  }
  while (S.length && L.length) {
    const a = S.pop();
    const g = L.pop();
    prob[a] = P[a];
    alias[a] = g;
    P[g] += P[a] - 1;
    if (P[g] < 1) S.push(g);
    else L.push(g);
  }
  while (L.length) prob[L.pop()] = 1;
  while (S.length) prob[S.pop()] = 1;
  return {
    next(f) {
      const r1 = f();
      const r2 = f();
      const i = Math.min(n - 1, Math.floor(n * r1));
      return r2 < prob[i] ? i : alias[i];
    },
  };
}

export function shuffled(items, rng) {
  const remaining = items.slice();
  const result = [];
  while (remaining.length) {
    const index = rng.nextInt(0, remaining.length - 1);
    result.push(remaining[index]);
    remaining.splice(index, 1);
  }
  return result;
}

export function chooseDegree(seqLen, rng) {
  const weights = [];
  for (let i = 1; i <= seqLen; i++) weights.push(1 / i);
  const sampler = randomSampler(weights);
  return sampler.next(() => rng.nextDouble()) + 1;
}

export function chooseFragments(seqNum, seqLen, checksum) {
  if (seqNum <= seqLen) return [seqNum - 1];
  const seed = new Uint8Array(8);
  seed.set(seedFromUint32(seqNum), 0);
  seed.set(seedFromUint32(checksum), 4);
  const rng = xoshiro256(seed);
  const degree = chooseDegree(seqLen, rng);
  const indexes = shuffled(Array.from({ length: seqLen }, (_, i) => i), rng);
  return indexes.slice(0, degree).sort((a, b) => a - b);
}

export function findNominalFragmentLength(messageLen, minLen, maxLen) {
  const maxFragmentCount = Math.floor(messageLen / minLen);
  for (let count = 1; count <= maxFragmentCount; count++) {
    const fragmentLen = Math.ceil(messageLen / count);
    if (fragmentLen <= maxLen) return fragmentLen;
  }
  return null;
}

export function partitionMessage(message, fragmentLen) {
  const fragments = [];
  for (let offset = 0; offset < message.length; offset += fragmentLen) {
    const fragment = new Uint8Array(fragmentLen);
    fragment.set(message.subarray(offset, offset + fragmentLen));
    fragments.push(fragment);
  }
  return fragments;
}

const collectors = new Set();

const zeroBytes = (bytes) => {
  if (bytes) bytes.fill(0);
};

const equalBytes = (a, b) => {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
};

const isZero = (bytes) => {
  let acc = 0;
  for (let i = 0; i < bytes.length; i++) acc |= bytes[i];
  return acc === 0;
};

const xorInto = (target, source) => {
  for (let i = 0; i < target.length; i++) target[i] ^= source[i];
};

const isStrictSubset = (a, b) => {
  if (a.length >= b.length) return false;
  const set = new Set(b);
  for (const value of a) if (!set.has(value)) return false;
  return true;
};

const sameSet = (a, b) => {
  if (a.length !== b.length) return false;
  const set = new Set(b);
  for (const value of a) if (!set.has(value)) return false;
  return true;
};

const crc32Number = (bytes) => {
  const crc = hodlCrc32(bytes);
  return ((crc[0] << 24) | (crc[1] << 16) | (crc[2] << 8) | crc[3]) >>> 0;
};

// A UR with a seq-count component is multi-part; a bare ur:type/bytewords is
// a single-part UR whose payload is the whole message.
const MULTIPART = /^ur:[a-z0-9-]+\/\d+-\d+\//;

export function retireUrCollectors() {
  for (const collector of [...collectors]) collector.reset();
}

export function createUrCollector(options = {}) {
  // Each part costs about seqLen^2 steps (choosing its fragments shuffles
  // seqLen indexes), and a hostile stream picks seqLen. 1000 parts is far
  // more than any PSBT a camera scan carries, and keeps that cost small.
  // workBudget bounds the work one received part may do (index and byte
  // steps), cascades included.
  const { types, maxMessageLen = 1048576, maxSeqLen = 1000, workBudget = 10_000_000, track } = options;
  if (!Array.isArray(types) || types.length === 0) {
    throw new Error("createUrCollector needs a non-empty types array.");
  }
  const allowed = new Set(types);
  const tracked = Array.isArray(track) ? track : null;

  let bound = null;
  let simple = new Map();
  let mixed = [];
  let seen = new Map();
  let received = 0;
  let status = "idle";
  let dead = false;
  let deadStatus = null;
  let mixedCap = 0;
  let seenCap = 0;

  const alloc = (length) => {
    const buffer = new Uint8Array(length);
    if (tracked) tracked.push(buffer);
    return buffer;
  };

  const allocCopy = (source) => {
    const buffer = alloc(source.length);
    buffer.set(source);
    return buffer;
  };

  const wipeAll = () => {
    for (const buffer of simple.values()) zeroBytes(buffer);
    simple.clear();
    for (const entry of mixed) zeroBytes(entry.data);
    mixed = [];
    for (const buffer of seen.values()) zeroBytes(buffer);
    seen.clear();
  };

  const collector = { receive: null, reset: null, state: null };

  const kill = (nextStatus) => {
    wipeAll();
    dead = true;
    deadStatus = nextStatus;
    status = nextStatus;
    collectors.delete(collector);
    return { status: nextStatus };
  };

  const integrate = (startIndexes, startData) => {
    const queue = [{ indexes: startIndexes, data: startData }];
    let work = 0;
    while (queue.length) {
      // A hostile stream can line parts up so that one new fragment cascades
      // through the whole store. Past the budget, the rest of this part's
      // equations are dropped (zeroed): that costs only efficiency, since the
      // final CRC still decides and later parts carry the same information.
      if (work > workBudget) {
        for (const pending of queue) zeroBytes(pending.data);
        return "ok";
      }
      const item = queue.shift();
      const data = item.data;

      // Reduce by known simple fragments.
      const remaining = [];
      work += item.indexes.length;
      for (const index of item.indexes) {
        const known = simple.get(index);
        if (known) { xorInto(data, known); work += data.length; }
        else remaining.push(index);
      }
      let indexes = remaining;

      if (indexes.length === 0) {
        if (!isZero(data)) {
          zeroBytes(data);
          for (const pending of queue) zeroBytes(pending.data);
          return "conflict";
        }
        zeroBytes(data);
        continue;
      }

      if (indexes.length === 1) {
        const index = indexes[0];
        simple.set(index, data);
        for (let i = mixed.length - 1; i >= 0; i--) {
          const entry = mixed[i];
          work += entry.indexes.length;
          if (entry.indexes.includes(index)) {
            mixed.splice(i, 1);
            xorInto(entry.data, data);
            work += data.length;
            entry.indexes = entry.indexes.filter((value) => value !== index);
            queue.push(entry);
          }
        }
        continue;
      }

      // Reduce by stored mixed parts that are strict subsets. The subset
      // stays stored: it is still a valid equation for later parts.
      for (let i = 0; i < mixed.length; i++) {
        const entry = mixed[i];
        work += entry.indexes.length + indexes.length;
        if (isStrictSubset(entry.indexes, indexes)) {
          xorInto(data, entry.data);
          work += data.length;
          indexes = indexes.filter((value) => !entry.indexes.includes(value));
        }
      }

      if (indexes.length === 0) {
        if (!isZero(data)) {
          zeroBytes(data);
          for (const pending of queue) zeroBytes(pending.data);
          return "conflict";
        }
        zeroBytes(data);
        continue;
      }

      if (indexes.length === 1) {
        queue.unshift({ indexes, data });
        continue;
      }

      // Reduce stored mixed parts that are strict supersets.
      for (let i = mixed.length - 1; i >= 0; i--) {
        const entry = mixed[i];
        work += entry.indexes.length + indexes.length;
        if (isStrictSubset(indexes, entry.indexes)) {
          mixed.splice(i, 1);
          xorInto(entry.data, data);
          work += data.length;
          entry.indexes = entry.indexes.filter((value) => !indexes.includes(value));
          queue.push(entry);
        }
      }

      // Same index set: duplicate or conflict.
      let duplicate = false;
      for (const entry of mixed) {
        work += entry.indexes.length + indexes.length;
        if (sameSet(entry.indexes, indexes)) {
          if (!equalBytes(entry.data, data)) {
            zeroBytes(data);
            for (const pending of queue) zeroBytes(pending.data);
            return "conflict";
          }
          duplicate = true;
          break;
        }
      }
      if (duplicate) {
        zeroBytes(data);
        continue;
      }

      mixed.push({ indexes, data });
      if (mixed.length > mixedCap) {
        const dropped = mixed.shift();
        zeroBytes(dropped.data);
      }
    }
    return "ok";
  };

  // Parsing a frame makes fresh copies of its bytes (the bytewords payload
  // and the part's data). They are zeroed once the collector has copied what
  // it keeps, whatever the outcome.
  const receive = (text) => {
    if (dead) return { status: deadStatus };
    let parsed;
    try {
      parsed = hodlUrParsePart(text);
    } catch {
      return { status: "bad-part" };
    }
    const scratch = [parsed.payload, parsed.part && parsed.part.data];
    try {
      return accept(text, parsed, scratch);
    } finally {
      for (const bytes of scratch) zeroBytes(bytes);
    }
  };

  const accept = (text, parsed, scratch) => {
    const normalized = String(text).trim().toLowerCase().replace(/^ur:\/\//, "ur:");

    if (!MULTIPART.test(normalized)) {
      if (!allowed.has(parsed.type)) return { status: "wrong-type" };
      if (bound) return { status: "mismatch" };
      if (parsed.payload.length > maxMessageLen) return { status: "too-large" };
      const message = new Uint8Array(parsed.payload.length);
      message.set(parsed.payload);
      status = "complete";
      dead = true;
      deadStatus = "done";
      return { status: "complete", type: parsed.type, message };
    }

    let part;
    if (parsed.fountain) {
      part = hodlUrPartParse(parsed.payload);
      if (part) scratch.push(part.data);
      if (!part || part.seqNum !== parsed.seq || part.seqLen !== parsed.count) {
        return { status: "bad-part" };
      }
    } else {
      part = parsed.part;
      if (!part) return { status: "legacy" };
    }

    if (!(part.messageLen >= 1 && part.messageLen <= maxMessageLen)) return { status: "too-large" };
    if (!(part.seqLen >= 1 && part.seqLen <= maxSeqLen)) return { status: "too-large" };
    if (!(part.data.length >= 1) || part.seqLen !== Math.ceil(part.messageLen / part.data.length)) {
      return { status: "bad-part" };
    }
    if (!Number.isInteger(part.checksum) || part.checksum < 0 || part.checksum > 0xffffffff) {
      return { status: "bad-part" };
    }
    if (!(part.seqNum >= 1)) return { status: "bad-part" };

    if (!allowed.has(parsed.type)) return { status: "wrong-type" };

    if (!bound) {
      bound = {
        type: parsed.type,
        seqLen: part.seqLen,
        messageLen: part.messageLen,
        checksum: part.checksum,
        fragmentLen: part.data.length,
      };
      mixedCap = 2 * bound.seqLen + 16;
      // The duplicate/conflict map is capped too: seqNum is attacker-chosen,
      // so an unbounded map would let a hostile stream allocate forever.
      seenCap = 4 * bound.seqLen + 64;
      collectors.add(collector);
    } else if (
      bound.type !== parsed.type ||
      bound.seqLen !== part.seqLen ||
      bound.messageLen !== part.messageLen ||
      bound.checksum !== part.checksum ||
      bound.fragmentLen !== part.data.length
    ) {
      return { status: "mismatch" };
    }

    const prior = seen.get(part.seqNum);
    if (prior) {
      if (equalBytes(prior, part.data)) return { status: "duplicate" };
      return kill("conflict");
    }
    seen.set(part.seqNum, allocCopy(part.data));
    if (seen.size > seenCap) {
      const oldest = seen.keys().next().value;
      zeroBytes(seen.get(oldest));
      seen.delete(oldest);
    }
    received += 1;

    const indexes = chooseFragments(part.seqNum, bound.seqLen, bound.checksum);
    const data = allocCopy(part.data);
    if (integrate(indexes, data) === "conflict") return kill("conflict");

    if (simple.size === bound.seqLen) {
      const joined = alloc(bound.seqLen * bound.fragmentLen);
      for (let i = 0; i < bound.seqLen; i++) joined.set(simple.get(i), i * bound.fragmentLen);
      let paddingOk = true;
      for (let i = bound.messageLen; i < joined.length; i++) {
        if (joined[i] !== 0) {
          paddingOk = false;
          break;
        }
      }
      const checksumOk = crc32Number(joined.subarray(0, bound.messageLen)) === bound.checksum;
      if (!paddingOk || !checksumOk) {
        zeroBytes(joined);
        return kill("invalid");
      }
      const message = new Uint8Array(bound.messageLen);
      message.set(joined.subarray(0, bound.messageLen));
      zeroBytes(joined);
      const type = bound.type;
      wipeAll();
      status = "complete";
      dead = true;
      deadStatus = "done";
      collectors.delete(collector);
      return { status: "complete", type, message };
    }

    status = "progress";
    return { status: "progress", type: bound.type, seqLen: bound.seqLen, known: simple.size };
  };

  const reset = () => {
    wipeAll();
    bound = null;
    received = 0;
    status = "idle";
    dead = false;
    deadStatus = null;
    mixedCap = 0;
    seenCap = 0;
    collectors.delete(collector);
  };

  const state = () => ({
    status,
    type: bound ? bound.type : null,
    seqLen: bound ? bound.seqLen : null,
    known: simple.size,
    received,
  });

  collector.receive = receive;
  collector.reset = reset;
  collector.state = state;
  return collector;
}
