// Shared ECDSA sign-to-contract (anti-exfil) relation.
// Pure module: no DOM, no network, no randomness generation.

import { secp256k1 } from "./secp256k1.js";
import { sha256 } from "./hashes.js";

const GROUP_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n;
const DATA_TAG = "s2c/ecdsa/data";
const POINT_TAG = "s2c/ecdsa/point";

// Host commitment: TaggedHash("s2c/ecdsa/data", rho), 32 bytes.
export function s2cHostCommitment(rho32) {
  return taggedHash(DATA_TAG, rho32);
}

// Committed nonce R0 + tweak*G as 33 compressed bytes, or null when the tweak
// is zero or outside [1, n) or the opening is not a valid curve point.
export function s2cCommittedNonce(opening33, rho32) {
  let tweak;
  try {
    tweak = bytesToBigInt(taggedHash(POINT_TAG, opening33, rho32));
  } catch {
    return null;
  }
  if (tweak === 0n || tweak >= GROUP_N) return null;
  try {
    const opening = secp256k1.Point.fromBytes(opening33);
    return opening.add(secp256k1.Point.BASE.multiply(tweak)).toBytes(true);
  } catch {
    return null;
  }
}

// True when the signature's r commits to x(R0 + tweak*G) mod n.
export function s2cSignatureMatches(r32, opening33, rho32) {
  const committed = s2cCommittedNonce(opening33, rho32);
  if (!committed) return false;
  try {
    const r = bytesToBigInt(r32);
    const x = bytesToBigInt(committed.slice(1));
    return r % GROUP_N === x % GROUP_N;
  } catch {
    return false;
  }
}

function taggedHash(tag, ...parts) {
  const tagHash = sha256(new TextEncoder().encode(tag));
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const data = new Uint8Array(64 + total);
  data.set(tagHash, 0);
  data.set(tagHash, 32);
  let offset = 64;
  for (const part of parts) {
    data.set(part, offset);
    offset += part.length;
  }
  return sha256(data);
}

function bytesToBigInt(bytes) {
  let value = 0n;
  for (const byte of bytes) value = (value << 8n) | BigInt(byte);
  return value;
}
