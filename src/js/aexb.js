// Offline AEXB-v1 verifier for FractalEncrypt's airgap anti-exfil protocol.
// Pure module: no DOM, no network, no randomness generation.

import { secp256k1 } from "./secp256k1.js";
import { sha256 } from "./hashes.js";
import { s2cHostCommitment, s2cSignatureMatches } from "./s2c.js";

const MAGIC_AEXB = ascii("AEXB");
const MAGIC_AEXT = ascii("AEXT");
const FORMAT_VERSION = 1;
const FLAGS = 0;
const SIGHASH_ALL = 0x00000001;
const MAX_SLOTS = 128;
const MAX_SLOTS_PER_INPUT = 16;
const MAX_MESSAGE_BYTES = 65536;
const MAX_PSBT_BYTES = 2000000;
const GROUP_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n;

export class AexbError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "AexbError";
    this.code = code;
  }
}

export function aexbDecode(input) {
  const bytes = toBytes(input);
  if (startsWith(bytes, MAGIC_AEXT)) return decodePackage(bytes);
  if (startsWith(bytes, MAGIC_AEXB)) return decodeMessage(bytes);
  throw new AexbError("INVALID_MESSAGE", "not an AEXB or AEXT message");
}

export function aexbVerify(decoded, reveal = null, commitment = null) {
  // Wrapper forms only fill arguments the caller left out: an explicit
  // reveal or commitment is never replaced by a field of the same object
  // that carries the signatures.
  if (decoded && decoded.signatures && decoded.reveal) {
    reveal = reveal ?? decoded.reveal;
    decoded = decoded.signatures;
  }
  if (decoded && decoded.message4 && decoded.message3) {
    reveal = reveal ?? decoded.message3;
    commitment = commitment ?? decoded.message2 ?? decoded.message1 ?? null;
    decoded = decoded.message4;
  }
  if (!decoded || typeof decoded !== "object") return fail("INVALID_MESSAGE");
  if (decoded.stage === 3) return verifyReveal(decoded, commitment);
  if (decoded.stage === 4) {
    if (!reveal) return fail("MISSING_REVEAL");
    return verifySignatures(decoded, reveal, commitment);
  }
  return fail("UNSUPPORTED_STAGE");
}

export function aexbEncode(decoded) {
  validateMessage(decoded);
  const stage = decoded.stage;
  const recordLength = 105 + (stage >= 2 ? 33 : 0) + (stage === 3 ? 32 : 0) + (stage === 4 ? 64 : 0);
  const payloadLength = decoded.slots.length * recordLength;
  const out = new Uint8Array(78 + payloadLength);
  out.set(MAGIC_AEXB, 0);
  out[4] = FORMAT_VERSION;
  out[5] = decoded.network;
  out[6] = stage;
  out[7] = FLAGS;
  writeU32(out, 8, payloadLength);
  out.set(decoded.sessionId, 12);
  out.set(decoded.psbtDigest, 44);
  writeU16(out, 76, decoded.slots.length);
  let offset = 78;
  for (const slot of decoded.slots) {
    writeU32(out, offset, slot.inputIndex);
    writeU32(out, offset + 4, slot.sighashType);
    out.set(slot.signerPubkey, offset + 8);
    out.set(slot.messageHash, offset + 41);
    out.set(slot.commitment, offset + 73);
    offset += 105;
    if (stage >= 2) {
      out.set(slot.opening, offset);
      offset += 33;
    }
    if (stage === 3) {
      out.set(slot.rho, offset);
      offset += 32;
    }
    if (stage === 4) {
      out.set(slot.signature, offset);
      offset += 64;
    }
  }
  return out;
}

export function aexbEncodePackage(decoded) {
  validateMessage(decoded);
  const message = aexbEncode(decoded);
  const psbt = decoded.psbt || new Uint8Array(0);
  return aextEncodePackage({
    version: 1,
    network: decoded.network,
    stage: decoded.stage,
    message,
    psbt
  });
}

function fail(reason) {
  return { ok: false, verdict: "fail", reason, slots: [] };
}

function verifyReveal(reveal, commitment) {
  if (!reveal || reveal.stage !== 3 || !Array.isArray(reveal.slots)) return fail("INVALID_MESSAGE");
  if (reveal.slots.length === 0) return fail("EMPTY_SLOT_SET");
  const binding = checkCommitmentBinding(reveal, commitment);
  if (binding.fail) return binding.fail;
  const originalSlots = binding.slots;
  const slots = reveal.slots.map((slot, index) => {
    if (!equalBytes(slot.commitment, originalSlots[index].commitment)) {
      return { slot: index, ok: false, reason: "COMMITMENT_MISMATCH" };
    }
    if (!slot.rho || slot.rho.length !== 32) {
      return { slot: index, ok: false, reason: "COMMITMENT_MISMATCH" };
    }
    const expected = s2cHostCommitment(slot.rho);
    if (!equalBytes(expected, originalSlots[index].commitment)) {
      return { slot: index, ok: false, reason: "COMMITMENT_MISMATCH" };
    }
    return { slot: index, ok: true, reason: null };
  });
  const ok = slots.every((slot) => slot.ok);
  return { ok, verdict: ok ? "ok" : "fail", slots };
}

function verifySignatures(signatures, reveal, commitment) {
  if (!signatures || signatures.stage !== 4 || !Array.isArray(signatures.slots)) {
    return fail("INVALID_MESSAGE");
  }
  if (!reveal || reveal.stage !== 3 || !Array.isArray(reveal.slots)) {
    return fail("TRANSCRIPT_MISMATCH");
  }
  if (signatures.slots.length === 0 || reveal.slots.length === 0) {
    return fail("EMPTY_SLOT_SET");
  }
  if (
    signatures.network !== reveal.network ||
    !equalBytes(signatures.sessionId, reveal.sessionId) ||
    !equalBytes(signatures.psbtDigest, reveal.psbtDigest) ||
    signatures.slots.length !== reveal.slots.length
  ) {
    return fail("TRANSCRIPT_MISMATCH");
  }
  const binding = checkCommitmentBinding(reveal, commitment);
  if (binding.fail) return binding.fail;
  const originalSlots = binding.slots;

  const slots = [];
  for (let index = 0; index < signatures.slots.length; index++) {
    const sigSlot = signatures.slots[index];
    const revealSlot = reveal.slots[index];
    if (!equalBytes(revealSlot.commitment, originalSlots[index].commitment)) {
      slots.push({ slot: index, ok: false, reason: "COMMITMENT_MISMATCH" });
      continue;
    }
    if (
      sigSlot.inputIndex !== revealSlot.inputIndex ||
      !equalBytes(sigSlot.signerPubkey, revealSlot.signerPubkey) ||
      !equalBytes(sigSlot.messageHash, revealSlot.messageHash) ||
      sigSlot.sighashType !== revealSlot.sighashType ||
      !equalBytes(sigSlot.commitment, revealSlot.commitment)
    ) {
      slots.push({ slot: index, ok: false, reason: "TRANSCRIPT_MISMATCH" });
      continue;
    }
    if (!equalBytes(sigSlot.opening, revealSlot.opening)) {
      slots.push({ slot: index, ok: false, reason: "OPENING_MISMATCH" });
      continue;
    }
    if (!revealSlot.rho || revealSlot.rho.length !== 32) {
      slots.push({ slot: index, ok: false, reason: "COMMITMENT_MISMATCH" });
      continue;
    }
    const expectedCommitment = s2cHostCommitment(revealSlot.rho);
    if (!equalBytes(expectedCommitment, originalSlots[index].commitment)) {
      slots.push({ slot: index, ok: false, reason: "COMMITMENT_MISMATCH" });
      continue;
    }

    if (!(sigSlot.signature instanceof Uint8Array) || sigSlot.signature.length !== 64) {
      slots.push({ slot: index, ok: false, reason: "SIGNATURE_INVALID" });
      continue;
    }
    const rBytes = sigSlot.signature.slice(0, 32);
    const r = bytesToBigInt(rBytes);
    if (!s2cSignatureMatches(rBytes, sigSlot.opening, revealSlot.rho)) {
      slots.push({ slot: index, ok: false, reason: "OPENING_MISMATCH" });
      continue;
    }
    const s = bytesToBigInt(sigSlot.signature.slice(32));
    if (!(r >= 1n && r < GROUP_N && s >= 1n && s <= GROUP_N / 2n)) {
      slots.push({ slot: index, ok: false, reason: "NON_LOW_S" });
      continue;
    }
    if (!ecdsaVerify(sigSlot.signerPubkey, sigSlot.messageHash, sigSlot.signature)) {
      slots.push({ slot: index, ok: false, reason: "SIGNATURE_INVALID" });
      continue;
    }
    slots.push({ slot: index, ok: true, reason: null });
  }

  const ok = slots.every((slot) => slot.ok);
  return { ok, verdict: ok ? "ok" : "fail", slots };
}

// The Python reference binds the reveal to the earlier commitment through
// validate_transition(): each adjacent stage must repeat the same commitment,
// and the stage-3 reveal is checked against that repeated commitment. This
// module has no transition validator, so the caller supplies the stage-2
// message (the signer's pre-reveal opening commitment) and we perform the
// equivalent binding explicitly. A stage-1-only commitment cannot bind the
// openings, so it is refused rather than reported as "ok".
function checkCommitmentBinding(message, commitment) {
  if (!commitment || typeof commitment !== "object") {
    return { fail: fail("MISSING_COMMITMENT") };
  }
  if (commitment.stage === 1) {
    return { fail: fail("MISSING_STAGE2_OPENING") };
  }
  if (commitment.stage !== 2) {
    return { fail: fail("INVALID_COMMITMENT") };
  }
  if (!Array.isArray(commitment.slots)) {
    return { fail: fail("INVALID_COMMITMENT") };
  }
  if (
    message.network !== commitment.network ||
    !equalBytes(message.sessionId, commitment.sessionId) ||
    !equalBytes(message.psbtDigest, commitment.psbtDigest) ||
    message.slots.length !== commitment.slots.length
  ) {
    return { fail: fail("TRANSCRIPT_MISMATCH") };
  }
  for (let index = 0; index < message.slots.length; index++) {
    const slot = message.slots[index];
    const original = commitment.slots[index];
    if (
      slot.inputIndex !== original.inputIndex ||
      !equalBytes(slot.signerPubkey, original.signerPubkey) ||
      !equalBytes(slot.messageHash, original.messageHash) ||
      slot.sighashType !== original.sighashType
    ) {
      return { fail: fail("TRANSCRIPT_MISMATCH") };
    }
    if (!equalBytes(slot.opening, original.opening)) {
      return { fail: fail("OPENING_MISMATCH") };
    }
  }
  return { slots: commitment.slots };
}

function ecdsaVerify(pub, msg, sig) {
  try {
    return secp256k1.verify(sig, msg, pub, { prehash: false, lowS: true }) === true;
  } catch {
    return false;
  }
}

function decodeMessage(encoded) {
  if (!(encoded instanceof Uint8Array) || encoded.length < 78) {
    throw new AexbError("INVALID_MESSAGE", "message is shorter than the AEXB header");
  }
  if (encoded.length > MAX_MESSAGE_BYTES) {
    throw new AexbError("INVALID_MESSAGE", "AEXB message is oversized");
  }
  if (!startsWith(encoded, MAGIC_AEXB)) {
    throw new AexbError("INVALID_MESSAGE", "message has the wrong AEXB magic");
  }
  const version = encoded[4];
  if (version !== FORMAT_VERSION) {
    throw new AexbError("INVALID_MESSAGE", `unsupported AEXB format version ${version}`);
  }
  const network = encoded[5];
  if (network > 4) throw new AexbError("INVALID_MESSAGE", `unknown AEXB network ${network}`);
  const stage = encoded[6];
  if (stage < 1 || stage > 4) throw new AexbError("WRONG_STAGE", `unknown AEXB stage ${stage}`);
  const flags = encoded[7];
  if (flags !== FLAGS) throw new AexbError("INVALID_MESSAGE", "unknown AEXB flags are set");
  const payloadLength = readU32(encoded, 8);
  const sessionId = encoded.slice(12, 44);
  const psbtDigest = encoded.slice(44, 76);
  const slotCount = readU16(encoded, 76);
  if (slotCount < 1 || slotCount > MAX_SLOTS) {
    throw new AexbError("INVALID_MESSAGE", "AEXB slot count is outside v1 limits");
  }
  const recordLength = 105 + (stage >= 2 ? 33 : 0) + (stage === 3 ? 32 : 0) + (stage === 4 ? 64 : 0);
  const expectedPayloadLength = slotCount * recordLength;
  if (payloadLength !== expectedPayloadLength) {
    throw new AexbError("INVALID_MESSAGE", "AEXB payload length is not canonical for its stage");
  }
  if (encoded.length !== 78 + payloadLength) {
    throw new AexbError("INVALID_MESSAGE", "AEXB length does not match payload");
  }

  const slots = [];
  let offset = 78;
  for (let i = 0; i < slotCount; i++) {
    slots.push(decodeSlot(stage, encoded, offset));
    offset += recordLength;
  }
  const message = { format: "AEXB", version, network, stage, flags, sessionId, psbtDigest, slots };
  validateMessage(message);
  return message;
}

function decodeSlot(stage, encoded, offset) {
  const inputIndex = readU32(encoded, offset);
  const sighashType = readU32(encoded, offset + 4);
  const signerPubkey = encoded.slice(offset + 8, offset + 41);
  const messageHash = encoded.slice(offset + 41, offset + 73);
  const commitment = encoded.slice(offset + 73, offset + 105);
  let cursor = offset + 105;
  let opening = null;
  let rho = null;
  let signature = null;
  if (stage >= 2) {
    opening = encoded.slice(cursor, cursor + 33);
    cursor += 33;
  }
  if (stage === 3) {
    rho = encoded.slice(cursor, cursor + 32);
    cursor += 32;
  }
  if (stage === 4) {
    signature = encoded.slice(cursor, cursor + 64);
    cursor += 64;
  }
  return { inputIndex, sighashType, signerPubkey, messageHash, commitment, opening, rho, signature };
}

function validateMessage(message) {
  if (!message || typeof message !== "object") throw new AexbError("INVALID_MESSAGE", "invalid message");
  if (message.network < 0 || message.network > 4) throw new AexbError("INVALID_MESSAGE", "invalid network");
  if (message.stage < 1 || message.stage > 4) throw new AexbError("INVALID_MESSAGE", "invalid stage");
  requireBytes("session ID", message.sessionId, 32);
  requireBytes("PSBT digest", message.psbtDigest, 32);
  if (!Array.isArray(message.slots) || message.slots.length < 1 || message.slots.length > MAX_SLOTS) {
    throw new AexbError("INVALID_MESSAGE", "slot collection is outside v1 limits");
  }

  let previousIdentifier = null;
  const perInput = new Map();
  const commitments = new Set();
  const reveals = new Set();
  const openings = new Set();

  for (const slot of message.slots) {
    validateSlot(message.stage, slot);
    const identifier = [slot.inputIndex, slot.signerPubkey];
    if (previousIdentifier !== null && compareIdentifier(identifier, previousIdentifier) <= 0) {
      throw new AexbError(
        "SIGNATURE_SLOT_MISMATCH",
        "slots must be unique and ordered by input index then compressed public key"
      );
    }
    previousIdentifier = identifier;

    const commitmentHex = bytesToHex(slot.commitment);
    if (commitments.has(commitmentHex)) {
      throw new AexbError("COMMITMENT_MISMATCH", "host commitments must be unique across the slot set");
    }
    commitments.add(commitmentHex);

    if (slot.rho !== null) {
      const rhoHex = bytesToHex(slot.rho);
      if (reveals.has(rhoHex)) {
        throw new AexbError("COMMITMENT_MISMATCH", "host reveals must be unique across the slot set");
      }
      reveals.add(rhoHex);
    }

    if (slot.opening !== null) {
      const xHex = bytesToHex(slot.opening.slice(1));
      if (openings.has(xHex)) {
        throw new AexbError(
          "OPENING_MISMATCH",
          "signer opening x-coordinates must be unique across the slot set"
        );
      }
      openings.add(xHex);
    }

    const count = (perInput.get(slot.inputIndex) || 0) + 1;
    perInput.set(slot.inputIndex, count);
    if (count > MAX_SLOTS_PER_INPUT) {
      throw new AexbError(
        "SIGNATURE_SLOT_MISMATCH",
        `input ${slot.inputIndex} exceeds the v1 per-input slot limit`
      );
    }
  }
}

function validateSlot(stage, slot) {
  if (!Number.isInteger(slot.inputIndex) || slot.inputIndex < 0 || slot.inputIndex > 0xFFFFFFFF) {
    throw new AexbError("INVALID_MESSAGE", "input index must be a uint32");
  }
  if (slot.sighashType !== SIGHASH_ALL) {
    throw new AexbError("INVALID_MESSAGE", "protocol v1 supports only explicit SIGHASH_ALL");
  }
  requirePoint("signer public key", slot.signerPubkey);
  requireBytes("message hash", slot.messageHash, 32);
  requireBytes("host commitment", slot.commitment, 32);

  const needsOpening = stage >= 2;
  const needsRho = stage === 3;
  const needsSignature = stage === 4;
  if ((slot.opening !== null) !== needsOpening) {
    throw new AexbError("INVALID_MESSAGE", "opening presence conflicts with stage");
  }
  if ((slot.rho !== null) !== needsRho) {
    throw new AexbError("INVALID_MESSAGE", "host reveal presence conflicts with stage");
  }
  if ((slot.signature !== null) !== needsSignature) {
    throw new AexbError("INVALID_MESSAGE", "signature presence conflicts with stage");
  }
  if (slot.opening !== null) requirePoint("signer opening", slot.opening);
  if (slot.rho !== null) requireBytes("host reveal", slot.rho, 32);
  if (slot.signature !== null) {
    requireBytes("compact signature", slot.signature, 64);
    const r = bytesToBigInt(slot.signature.slice(0, 32));
    const s = bytesToBigInt(slot.signature.slice(32));
    if (!(r >= 1n && r < GROUP_N && s >= 1n && s <= GROUP_N / 2n)) {
      throw new AexbError("INVALID_MESSAGE", "signature scalars are invalid or non-low-S");
    }
  }
}

export function aextDecodePackage(input) {
  const encoded = toBytes(input);
  if (encoded.length < 48) throw new AexbError("INVALID_MESSAGE", "package is shorter than the AEXT header");
  if (!startsWith(encoded, MAGIC_AEXT)) throw new AexbError("INVALID_MESSAGE", "package has the wrong AEXT magic");
  const version = encoded[4];
  if (version !== 1) throw new AexbError("INVALID_MESSAGE", `unsupported AEXT version ${version}`);
  const network = encoded[5];
  if (network > 4) throw new AexbError("INVALID_MESSAGE", `unknown AEXT network ${network}`);
  const stage = encoded[6];
  if (stage < 1 || stage > 4) throw new AexbError("WRONG_STAGE", `unknown AEXT stage ${stage}`);
  const flags = encoded[7];
  if ((flags & ~1) !== 0) throw new AexbError("INVALID_MESSAGE", "unknown AEXT flags are set");
  const messageLength = readU32(encoded, 8);
  const psbtLength = readU32(encoded, 12);
  if (messageLength > MAX_MESSAGE_BYTES) throw new AexbError("INVALID_MESSAGE", "AEXT message is oversized");
  if (psbtLength > MAX_PSBT_BYTES) throw new AexbError("INVALID_MESSAGE", "AEXT PSBT is oversized");
  if (encoded.length !== 48 + messageLength + psbtLength) {
    throw new AexbError("INVALID_MESSAGE", "AEXT length does not match payload");
  }

  const psbtDigest = encoded.slice(16, 48);
  const message = encoded.slice(48, 48 + messageLength);
  const psbt = encoded.slice(48 + messageLength);
  const hasPsbt = (flags & 1) === 1;
  if (stage === 1 || stage === 3) {
    if (!hasPsbt) throw new AexbError("INVALID_MESSAGE", "AEXT PSBT is required for this stage");
    if (psbtLength === 0) throw new AexbError("INVALID_MESSAGE", "AEXT PSBT is required for this stage");
    if (!startsWith(psbt, Uint8Array.from([0x70, 0x73, 0x62, 0x74, 0xff]))) {
      throw new AexbError("INVALID_MESSAGE", "AEXT PSBT has the wrong magic");
    }
    const digest = sha256(psbt);
    if (!equalBytes(digest, psbtDigest)) throw new AexbError("INVALID_MESSAGE", "AEXT PSBT digest mismatch");
  } else {
    if (hasPsbt) throw new AexbError("INVALID_MESSAGE", "AEXT PSBT is forbidden for this stage");
    if (psbtLength !== 0) throw new AexbError("INVALID_MESSAGE", "AEXT PSBT is forbidden for this stage");
    if (!allZero(psbtDigest)) throw new AexbError("INVALID_MESSAGE", "AEXT PSBT digest must be zero when absent");
  }

  return { version, network, stage, flags, messageLength, psbtLength, psbtDigest, message, psbt };
}

export function aextEncodePackage(pkg) {
  if (!pkg || typeof pkg !== "object") throw new AexbError("INVALID_MESSAGE", "invalid package");
  const version = pkg.version === undefined ? 1 : pkg.version;
  if (version !== 1) throw new AexbError("INVALID_MESSAGE", `unsupported AEXT version ${version}`);
  const network = pkg.network;
  if (!Number.isInteger(network) || network < 0 || network > 4) {
    throw new AexbError("INVALID_MESSAGE", "invalid network");
  }
  const stage = pkg.stage;
  if (!Number.isInteger(stage) || stage < 1 || stage > 4) {
    throw new AexbError("INVALID_MESSAGE", "invalid stage");
  }
  const message = normalizeBytes(pkg.message);
  const psbt = pkg.psbt ? normalizeBytes(pkg.psbt) : new Uint8Array(0);
  if (message.length > MAX_MESSAGE_BYTES) throw new AexbError("INVALID_MESSAGE", "AEXT message is oversized");
  if (psbt.length > MAX_PSBT_BYTES) throw new AexbError("INVALID_MESSAGE", "AEXT PSBT is oversized");
  const hasPsbt = stage === 1 || stage === 3;
  if (hasPsbt) {
    if (psbt.length === 0) throw new AexbError("INVALID_MESSAGE", "AEXT PSBT is required for this stage");
    if (!startsWith(psbt, Uint8Array.from([0x70, 0x73, 0x62, 0x74, 0xff]))) {
      throw new AexbError("INVALID_MESSAGE", "AEXT PSBT has the wrong magic");
    }
  } else {
    if (psbt.length !== 0) throw new AexbError("INVALID_MESSAGE", "AEXT PSBT is forbidden for this stage");
  }
  const flags = hasPsbt ? 1 : 0;
  const psbtDigest = hasPsbt ? sha256(psbt) : new Uint8Array(32);
  const out = new Uint8Array(48 + message.length + psbt.length);
  out.set(MAGIC_AEXT, 0);
  out[4] = version;
  out[5] = network;
  out[6] = stage;
  out[7] = flags;
  writeU32(out, 8, message.length);
  writeU32(out, 12, psbt.length);
  out.set(psbtDigest, 16);
  out.set(message, 48);
  out.set(psbt, 48 + message.length);
  return out;
}

function decodePackage(encoded) {
  // Decode the embedded AEXB message before the AEXT PSBT checks so that a
  // message-level failure keeps its specific error code instead of being
  // masked by an AEXT framing error.
  const message = decodeMessage(packageMessageBytes(encoded));
  const pkg = aextDecodePackage(encoded);
  if (message.network !== pkg.network) throw new AexbError("INVALID_MESSAGE", "AEXT network does not match AEXB");
  if (message.stage !== pkg.stage) throw new AexbError("WRONG_STAGE", "AEXT stage does not match AEXB");
  if (pkg.stage === 1 || pkg.stage === 3) {
    if (!equalBytes(message.psbtDigest, pkg.psbtDigest)) {
      throw new AexbError("INVALID_MESSAGE", "AEXB PSBT digest mismatch");
    }
  }
  return {
    ...message,
    psbt: pkg.psbt,
    package: {
      version: pkg.version,
      network: pkg.network,
      stage: pkg.stage,
      flags: pkg.flags,
      messageLength: pkg.messageLength,
      psbtLength: pkg.psbtLength,
      psbtDigest: pkg.psbtDigest
    }
  };
}

function packageMessageBytes(encoded) {
  if (!(encoded instanceof Uint8Array) || encoded.length < 48) {
    throw new AexbError("INVALID_MESSAGE", "package is shorter than the AEXT header");
  }
  if (!startsWith(encoded, MAGIC_AEXT)) {
    throw new AexbError("INVALID_MESSAGE", "package has the wrong AEXT magic");
  }
  const messageLength = readU32(encoded, 8);
  const psbtLength = readU32(encoded, 12);
  if (encoded.length !== 48 + messageLength + psbtLength) {
    throw new AexbError("INVALID_MESSAGE", "AEXT length does not match payload");
  }
  return encoded.slice(48, 48 + messageLength);
}

function requireBytes(name, value, length) {
  if (!(value instanceof Uint8Array) || value.length !== length) {
    throw new AexbError("INVALID_MESSAGE", `${name} must be exactly ${length} bytes`);
  }
}

function requirePoint(name, value) {
  requireBytes(name, value, 33);
  if (value[0] !== 2 && value[0] !== 3) throw new AexbError("INVALID_MESSAGE", `invalid ${name}`);
  try {
    pointFromBytes(value);
  } catch {
    throw new AexbError("INVALID_MESSAGE", `invalid ${name}`);
  }
}

function compareIdentifier(a, b) {
  if (a[0] !== b[0]) return a[0] - b[0];
  return compareBytes(a[1], b[1]);
}

function compareBytes(a, b) {
  const length = Math.min(a.length, b.length);
  for (let i = 0; i < length; i++) {
    if (a[i] !== b[i]) return a[i] - b[i];
  }
  return a.length - b.length;
}

function pointFromBytes(bytes) {
  return secp256k1.Point.fromBytes(bytes);
}

function bytesToBigInt(bytes) {
  let value = 0n;
  for (const byte of bytes) value = (value << 8n) | BigInt(byte);
  return value;
}

function bytesToHex(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

function hexToBytes(hex) {
  const clean = hex.startsWith("0x") || hex.startsWith("0X") ? hex.slice(2) : hex;
  if (clean.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(clean)) {
    throw new AexbError("INVALID_MESSAGE", "invalid hex");
  }
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function normalizeBytes(value) {
  if (value instanceof Uint8Array) return value;
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  if (ArrayBuffer.isView(value)) return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  if (typeof value === "string") return hexToBytes(value);
  throw new AexbError("INVALID_MESSAGE", "expected bytes");
}

function toBytes(input) {
  if (input instanceof Uint8Array) return input;
  if (input instanceof ArrayBuffer) return new Uint8Array(input);
  if (ArrayBuffer.isView(input)) return new Uint8Array(input.buffer, input.byteOffset, input.byteLength);
  if (typeof input === "string") {
    const text = input.trim();
    if (!text) throw new AexbError("INVALID_MESSAGE", "empty input");
    const hex = text.startsWith("0x") || text.startsWith("0X") ? text.slice(2) : text;
    if (hex.length > 0 && hex.length % 2 === 0 && /^[0-9a-fA-F]+$/.test(hex)) return hexToBytes(hex);
    return new TextEncoder().encode(text);
  }
  throw new AexbError("INVALID_MESSAGE", "unsupported input type");
}

function startsWith(bytes, prefix) {
  if (bytes.length < prefix.length) return false;
  for (let i = 0; i < prefix.length; i++) if (bytes[i] !== prefix[i]) return false;
  return true;
}

function equalBytes(a, b) {
  if (!(a instanceof Uint8Array) || !(b instanceof Uint8Array) || a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

function allZero(bytes) {
  for (const byte of bytes) if (byte !== 0) return false;
  return true;
}

function readU16(bytes, offset) {
  return (bytes[offset] << 8) | bytes[offset + 1];
}

function writeU16(out, offset, value) {
  out[offset] = (value >>> 8) & 0xff;
  out[offset + 1] = value & 0xff;
}

function readU32(bytes, offset) {
  return (
    ((bytes[offset] << 24) |
      (bytes[offset + 1] << 16) |
      (bytes[offset + 2] << 8) |
      bytes[offset + 3]) >>>
    0
  );
}

function writeU32(out, offset, value) {
  out[offset] = (value >>> 24) & 0xff;
  out[offset + 1] = (value >>> 16) & 0xff;
  out[offset + 2] = (value >>> 8) & 0xff;
  out[offset + 3] = value & 0xff;
}

function ascii(text) {
  return new TextEncoder().encode(text);
}
