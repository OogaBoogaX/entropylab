// BIP-352 Silent Payments calculator.
// Deterministic only: same inputs → same outputs. No entropy is invented.
// Curve ops go through the libsecp256k1 WASM facade (./secp256k1.js),
// hashes through the bitcoin_hashes WASM facade (./hashes.js).
import { hash160, sha256 } from "./hashes.js";
import { bech32mDecode, bech32mEncode, fromWords, toWords } from "./bech32.js";
import { HDKey } from "./hdkey.js";
import { secp256k1 } from "./secp256k1.js";

export const BIP352_PURPOSE = 352;
export const BIP352_K_MAX = 2323;
export const BIP352_BECH32_LIMIT = 1023;
export const NUMS_H = Uint8Array.from(
  "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0".match(/../g).map((b) => parseInt(b, 16)),
);
const ORDER = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const Point = secp256k1.Point;

const textEncoder = new TextEncoder();
const hexToBytes = (hex) => {
  if (typeof hex !== "string" || hex.length % 2 || /[^0-9a-f]/i.test(hex)) throw new Error("Invalid hexadecimal input.");
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
};
const bytesToHex = (bytes) => [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
// Avoid immutable hex intermediates for sender scalars. BigInts themselves
// cannot be wiped; callers must still erase the byte buffers they own.
const bytesToBig = (bytes) => {
  let value = 0n;
  for (const byte of bytes) value = (value << 8n) | BigInt(byte);
  return value;
};
const bigToBytes32 = (value) => {
  if (value < 0n || value >= (1n << 256n)) throw new Error("Scalar does not fit in 32 bytes.");
  const bytes = new Uint8Array(32);
  for (let i = 31; i >= 0; i--) {
    bytes[i] = Number(value & 255n);
    value >>= 8n;
  }
  return bytes;
};
const publicKeyForScalar = (scalar) => {
  const bytes = bigToBytes32(scalar);
  try { return secp256k1.getPublicKey(bytes, true); }
  finally { bytes.fill(0); }
};
const equalBytes = (a, b) => {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
};

export function taggedHash(tag, ...chunks) {
  const tagHash = sha256(textEncoder.encode(tag));
  let total = 64;
  for (const chunk of chunks) total += chunk.length;
  const bytes = new Uint8Array(total);
  bytes.set(tagHash, 0);
  bytes.set(tagHash, 32);
  let offset = 64;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.length;
  }
  try {
    return sha256(bytes);
  } finally {
    // The chunks can include a Silent Payments scan private key or a shared
    // secret; sha256 has copied what it needs before this returns.
    bytes.fill(0);
  }
}

export function serUint32(value) {
  if (!Number.isInteger(value) || value < 0 || value > 0xffffffff) throw new Error("ser32 value out of range.");
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, value, false);
  return out;
}

const scalarFromBytes = (bytes) => {
  if (!(bytes instanceof Uint8Array) || bytes.length !== 32) throw new Error("Scalar must be 32 bytes.");
  const value = bytesToBig(bytes);
  if (value === 0n || value >= ORDER) throw new Error("Scalar is out of the secp256k1 range.");
  return value;
};

const reduceScalar = (value) => {
  const n = ((value % ORDER) + ORDER) % ORDER;
  if (n === 0n) throw new Error("Scalar is out of the secp256k1 range.");
  return n;
};

const pointFromBytes = (bytes) => Point.fromBytes(bytes);
const pointFromXOnly = (xonly) => {
  if (!(xonly instanceof Uint8Array) || xonly.length !== 32) throw new Error("X-only public key must be 32 bytes.");
  const compressed = new Uint8Array(33);
  compressed[0] = 0x02;
  compressed.set(xonly, 1);
  return Point.fromBytes(compressed);
};
const pointToCompressed = (point) => point.toBytes(true);
const pointToXOnly = (point) => point.toBytes(true).slice(1);
const pointHasEvenY = (point) => point.toBytes(true)[0] === 0x02;
const negatePoint = (point) => {
  const bytes = point.toBytes(true);
  bytes[0] = bytes[0] === 2 ? 3 : 2;
  return Point.fromBytes(bytes);
};
const pointMultiply = (point, scalar) => point.multiply(reduceScalar(scalar));
const pointAdd = (a, b) => {
  try {
    return a.add(b);
  } catch {
    return null;
  }
};
const sumPoints = (points) => {
  let acc = null;
  for (const point of points) {
    if (!point) continue;
    acc = acc ? pointAdd(acc, point) : point;
  }
  return acc;
};

const readCompactSize = (bytes, offset) => {
  if (offset >= bytes.length) throw new Error("Witness ended early.");
  const first = bytes[offset];
  if (first < 0xfd) return [first, offset + 1];
  if (first === 0xfd) {
    if (offset + 3 > bytes.length) throw new Error("Witness ended inside a compact size.");
    const value = bytes[offset + 1] | (bytes[offset + 2] << 8);
    if (value < 0xfd) throw new Error("Non-minimal compact size.");
    return [value, offset + 3];
  }
  if (first === 0xfe) {
    if (offset + 5 > bytes.length) throw new Error("Witness ended inside a compact size.");
    const value = (bytes[offset + 1] | (bytes[offset + 2] << 8) | (bytes[offset + 3] << 16) | (bytes[offset + 4] << 24)) >>> 0;
    if (value < 0x10000) throw new Error("Non-minimal compact size.");
    return [value, offset + 5];
  }
  throw new Error("Witness compact size is too large.");
};

export function parseWitnessHex(hex) {
  if (!hex) return [];
  const bytes = hexToBytes(hex);
  let offset = 0;
  const [count, afterCount] = readCompactSize(bytes, offset);
  offset = afterCount;
  const stack = [];
  for (let i = 0; i < count; i++) {
    const [length, afterLength] = readCompactSize(bytes, offset);
    offset = afterLength;
    if (offset + length > bytes.length) throw new Error("Witness item overruns the buffer.");
    stack.push(bytes.slice(offset, offset + length));
    offset += length;
  }
  if (offset !== bytes.length) throw new Error("Witness has trailing bytes.");
  return stack;
}

export function serializeOutpoint(txid, vout) {
  const hash = hexToBytes(txid);
  if (hash.length !== 32) throw new Error("Outpoint txid must be 32 bytes.");
  if (!Number.isInteger(vout) || vout < 0 || vout > 0xffffffff) throw new Error("Outpoint vout out of range.");
  const out = new Uint8Array(36);
  for (let i = 0; i < 32; i++) out[i] = hash[31 - i];
  out[32] = vout & 0xff;
  out[33] = (vout >>> 8) & 0xff;
  out[34] = (vout >>> 16) & 0xff;
  out[35] = (vout >>> 24) & 0xff;
  return out;
}

export const isP2pkh = (spk) => spk.length === 25 && spk[0] === 0x76 && spk[1] === 0xa9 && spk[2] === 0x14 && spk[23] === 0x88 && spk[24] === 0xac;
export const isP2sh = (spk) => spk.length === 23 && spk[0] === 0xa9 && spk[1] === 0x14 && spk[22] === 0x87;
export const isP2wpkh = (spk) => spk.length === 22 && spk[0] === 0x00 && spk[1] === 0x14;
export const isP2tr = (spk) => spk.length === 34 && spk[0] === 0x51 && spk[1] === 0x20;
const isFutureSegwit = (spk) => spk.length >= 4 && spk.length <= 42 && spk[0] >= 0x52 && spk[0] <= 0x60 && spk[1] === spk.length - 2;

const compressedPointOrNull = (bytes) => {
  if (!(bytes instanceof Uint8Array) || bytes.length !== 33 || (bytes[0] !== 2 && bytes[0] !== 3)) return null;
  try {
    return Point.fromBytes(bytes);
  } catch {
    return null;
  }
};

// The key a P2WPKH spend (native or P2SH-wrapped) reveals: the last witness
// item, which consensus requires to hash to the 20-byte key hash. Pasted data
// that breaks that is refused rather than skipped, since the send flow would
// drop a skipped input from its key sum while the chain counts it. A
// consistent uncompressed key is ineligible under BIP-352 (null), as before.
const p2wpkhWitnessKey = (keyhash, witness) => {
  const key = witness[witness.length - 1];
  if (!witness.length || !(key instanceof Uint8Array) || !equalBytes(hash160(key), keyhash)) {
    throw new Error("A P2WPKH input's witness key does not hash to the key hash it spends. Check the pasted witness.");
  }
  return compressedPointOrNull(key);
};

// The pushes a scriptSig makes, in order, or null when the script is not
// push-only or a push overruns it. OP_0 pushes empty, OP_1NEGATE pushes
// [0x81] and OP_n pushes [n]; a P2SH scriptSig must be push-only (BIP 16).
const scriptSigPushes = (scriptSig) => {
  const pushes = [];
  let offset = 0;
  while (offset < scriptSig.length) {
    const opcode = scriptSig[offset];
    offset += 1;
    if (opcode === 0x4f) {
      pushes.push(Uint8Array.of(0x81));
      continue;
    }
    if (opcode >= 0x51 && opcode <= 0x60) {
      pushes.push(Uint8Array.of(opcode - 0x50));
      continue;
    }
    let length;
    if (opcode === 0x00) length = 0;
    else if (opcode <= 0x4b) length = opcode;
    else if (opcode === 0x4c || opcode === 0x4d || opcode === 0x4e) {
      const width = opcode === 0x4c ? 1 : opcode === 0x4d ? 2 : 4;
      if (offset + width > scriptSig.length) return null;
      // Push lengths are little-endian in Bitcoin Script.
      length = 0;
      for (let i = width - 1; i >= 0; i--) length = length * 256 + scriptSig[offset + i];
      offset += width;
    } else {
      return null;
    }
    if (offset + length > scriptSig.length) return null;
    pushes.push(scriptSig.slice(offset, offset + length));
    offset += length;
  }
  return pushes;
};

// BIP 141: a witness program is a version byte (OP_0 or OP_1..OP_16)
// followed by one direct push of 2..40 bytes that ends the script.
const isWitnessProgram = (script) => script.length >= 4 && script.length <= 42
  && (script[0] === 0x00 || (script[0] >= 0x51 && script[0] <= 0x60))
  && script[1] >= 2 && script[1] <= 40 && script[1] === script.length - 2;

export function extractInputPubKey(vin) {
  const prevout = vinPrevoutScript(vin);
  const scriptSig = vin.scriptSig instanceof Uint8Array ? vin.scriptSig : hexToBytes(vin.scriptSig || "");
  // A non-empty witness array wins; an empty one does not hide txinwitness.
  const witness = Array.isArray(vin.witness) && vin.witness.length ? vin.witness : parseWitnessHex(vin.txinwitness || "");
  if (isP2pkh(prevout)) {
    const spkHash = prevout.slice(3, 23);
    for (let i = scriptSig.length; i >= 33; i--) {
      const candidate = scriptSig.slice(i - 33, i);
      if (!equalBytes(hash160(candidate), spkHash)) continue;
      const point = compressedPointOrNull(candidate);
      if (point) return { point, isTaproot: false };
    }
    // A consistent uncompressed or hybrid key is ineligible under BIP-352,
    // as before. A scriptSig with no 33- or 65-byte window hashing to the
    // key hash is mangled paste: a valid P2PKH spend must reveal the key,
    // and skipping the input would silently drop it from the key sum.
    for (let i = scriptSig.length; i >= 65; i--) {
      if (equalBytes(hash160(scriptSig.slice(i - 65, i)), spkHash)) return null;
    }
    throw new Error("A P2PKH input's scriptSig does not contain the key its prevout pays to. Check the pasted prevout and scriptSig.");
  }
  if (isP2sh(prevout)) {
    // A valid P2SH spend's scriptSig is push-only and its last push is the
    // redeem script the prevout hash commits to (BIP 16), with or without a
    // witness. Pasted data that breaks that is refused, not skipped: the
    // send flow treats a skipped input as ineligible and leaves it out of
    // the key sum, while the chain would count a P2SH-P2WPKH input, so the
    // output would be one the recipient never finds.
    const pushes = scriptSigPushes(scriptSig);
    const redeem = pushes && pushes.length ? pushes[pushes.length - 1] : null;
    const committed = !!redeem && equalBytes(hash160(redeem), prevout.slice(2, 22));
    const program = committed && isWitnessProgram(redeem);
    // A redeem that is a witness program must be the scriptSig's single
    // direct push (consensus WITNESS_MALLEATED_P2SH), and a legacy redeem
    // must carry no witness (consensus WITNESS_UNEXPECTED).
    const shapeOk = program
      ? scriptSig.length === redeem.length + 1 && scriptSig[0] === redeem.length
      : !witness.length;
    if (!committed || !shapeOk) {
      throw new Error("A P2SH input's scriptSig does not push the redeem script its prevout commits to. Check the pasted prevout and scriptSig.");
    }
    if (program && isP2wpkh(redeem)) {
      const point = p2wpkhWitnessKey(redeem.slice(2, 22), witness);
      return point ? { point, isTaproot: false } : null;
    }
    // P2SH-P2WSH, future witness versions and consistent legacy P2SH redeems
    // (e.g. multisig) are ineligible and skipped as before.
    return null;
  }
  if (isP2wpkh(prevout)) {
    const point = p2wpkhWitnessKey(prevout.slice(2, 22), witness);
    if (point) return { point, isTaproot: false };
  }
  if (isP2tr(prevout)) {
    // Every P2TR spend carries a witness (consensus). Without one the pasted
    // vin cannot show whether it is an ineligible NUMS script-path spend, and
    // skipping it would drop a key-path input from the key sum.
    if (!witness.length) throw new Error("A P2TR input has no witness. Check the pasted witness.");
    const stack = witness.slice();
    if (stack.length > 1 && stack[stack.length - 1][0] === 0x50) stack.pop();
    if (stack.length > 1) {
      const control = stack[stack.length - 1];
      if (control.length >= 33 && equalBytes(control.slice(1, 33), NUMS_H)) return null;
    }
    try {
      return { point: pointFromXOnly(prevout.slice(2)), isTaproot: true };
    } catch {
      return null;
    }
  }
  return null;
}

// A vin carries spend data when its scriptSig holds bytes or its witness
// holds items; a sender pastes its inputs before signing, so both are empty.
// The shapes are the ones extractInputPubKey accepts (raw bytes or hex
// string, witness array or serialized hex).
export const vinHasSpendData = (vin) => {
  const scriptSig = vin.scriptSig instanceof Uint8Array ? vin.scriptSig : hexToBytes(vin.scriptSig || "");
  // Either witness field counts: a vin carrying an empty array and hex
  // witness data is not treated as unsigned.
  return scriptSig.length > 0 || (Array.isArray(vin.witness) && vin.witness.length > 0) || parseWitnessHex(vin.txinwitness || "").length > 0;
};

// The eligible key of an input that has no spend data, resolved from its
// private key: a sender has no signatures at output-building time, so the
// key cannot be read out of a scriptSig or witness the way
// extractInputPubKey does. The scalar must produce the prevout script — the
// same key the later signed spend will reveal — or the input is refused;
// any other prevout type stays ineligible (null), as with spend data.
const unsignedInputKey = (vin, index) => {
  const prevout = vinPrevoutScript(vin);
  const scalar = scalarFromBytes(typeof vin.private_key === "string" ? hexToBytes(vin.private_key) : vin.private_key);
  const pub = publicKeyForScalar(scalar);
  const mismatch = new Error(`Input ${index} private key does not match its eligible input public key.`);
  const point = Point.fromBytes(pub);
  // A key hash that matches the scalar's uncompressed (0x04) or hybrid
  // (0x06/0x07, SEC1) key encoding is consistent but ineligible under
  // BIP-352, exactly as its signed form is skipped.
  const uncompressed = point.toBytes(false);
  const hybrid = Uint8Array.from(uncompressed);
  hybrid[0] = pointHasEvenY(point) ? 0x06 : 0x07;
  const keyHashInput = (keyhash) => {
    if (equalBytes(hash160(pub), keyhash)) return { point, isTaproot: false };
    if (equalBytes(hash160(uncompressed), keyhash)) return null;
    if (equalBytes(hash160(hybrid), keyhash)) return null;
    throw mismatch;
  };
  if (isP2pkh(prevout)) return keyHashInput(prevout.slice(3, 23));
  if (isP2wpkh(prevout)) return keyHashInput(prevout.slice(2, 22));
  if (isP2sh(prevout)) {
    // The scalar's P2SH-P2WPKH script: a914 || hash160(0014 || hash160(key)) || 87.
    // Matching only the uncompressed or hybrid key is consistent but
    // ineligible, like the signed form. Any other P2SH (multisig,
    // P2SH-P2WSH) cannot be told from a wrong key without its redeem
    // script, so it is refused: paste the scriptSig (the redeem push needs
    // no signature) and it is skipped.
    const p2shP2wpkh = (key) => {
      const redeem = new Uint8Array(22);
      redeem[1] = 0x14;
      redeem.set(hash160(key), 2);
      const script = new Uint8Array(23);
      script[0] = 0xa9;
      script[1] = 0x14;
      script.set(hash160(redeem), 2);
      script[22] = 0x87;
      return script;
    };
    if (equalBytes(p2shP2wpkh(pub), prevout)) return { point, isTaproot: false };
    if (equalBytes(p2shP2wpkh(uncompressed), prevout)) return null;
    if (equalBytes(p2shP2wpkh(hybrid), prevout)) return null;
    throw mismatch;
  }
  if (isP2tr(prevout)) {
    // The private key of a taproot input is already the BIP-341-tweaked key
    // of the output key, so the eligible point is the prevout program
    // itself, exactly as extractInputPubKey returns for a key-path spend.
    if (!equalBytes(pointToXOnly(Point.fromBytes(pub)), prevout.slice(2, 34))) throw mismatch;
    return { point: pointFromXOnly(prevout.slice(2, 34)), isTaproot: true };
  }
  return null;
};

export function inputHash(outpoints, sumPoint) {
  if (!outpoints.length) throw new Error("Silent payment input hash needs at least one outpoint.");
  const serialized = outpoints.map((outpoint) => serializeOutpoint(outpoint.txid, outpoint.vout));
  serialized.sort((a, b) => {
    for (let i = 0; i < 36; i++) if (a[i] !== b[i]) return a[i] - b[i];
    return 0;
  });
  return taggedHash("BIP0352/Inputs", serialized[0], pointToCompressed(sumPoint));
}

export function hrpForNetwork(network) {
  return network === "testnet" || network === "signet" || network === "regtest" ? "tsp" : "sp";
}

export function encodeSilentPaymentAddress(scanPoint, spendPoint, hrp = "sp", version = 0) {
  if (version < 0 || version > 30) throw new Error("Silent payment address version must be 0–30.");
  const payload = new Uint8Array(66);
  payload.set(pointToCompressed(scanPoint), 0);
  payload.set(pointToCompressed(spendPoint), 33);
  const words = [version, ...toWords(payload)];
  return bech32mEncode(hrp, words);
}

export function decodeSilentPaymentAddress(address, expectedHrp) {
  if (typeof address !== "string" || !address) throw new Error("Silent payment address is empty.");
  // Bech32/Bech32m permit all-lowercase or all-uppercase encodings and
  // require mixed case to be rejected — lowercasing first would launder a
  // corrupted or crafted address into a valid one (issue #335).
  if (address !== address.toLowerCase() && address !== address.toUpperCase()) {
    throw new Error("A silent payment address must be all lowercase or all uppercase, not mixed case.");
  }
  const lower = address.toLowerCase();
  const decoded = bech32mDecode(lower);
  if (!decoded) throw new Error("Not a Bech32m silent payment address.");
  const { prefix: hrp, words } = decoded;
  if (expectedHrp && hrp !== expectedHrp) throw new Error(`Silent payment address HRP is ${hrp}, expected ${expectedHrp}.`);
  if (hrp !== "sp" && hrp !== "tsp") throw new Error(`Unknown silent payment HRP: ${hrp}.`);
  if (!words.length) throw new Error("Silent payment address has no data.");
  const version = words[0];
  if (version === 31) throw new Error("Silent payment address version 31 is reserved.");
  if (version > 30) throw new Error("Silent payment address version is unsupported.");
  const payload = fromWords(words.slice(1));
  if (version === 0 && payload.length !== 66) throw new Error("Silent payment v0 address payload must be 66 bytes.");
  if (payload.length < 66) throw new Error("Silent payment address payload is too short.");
  return {
    hrp,
    version,
    scan: pointFromBytes(payload.slice(0, 33)),
    spend: pointFromBytes(payload.slice(33, 66)),
  };
}

export function generateLabel(scanPriv, m) {
  const scalar = scanPriv instanceof Uint8Array ? scalarFromBytes(scanPriv) : scanPriv;
  const scalarBytes = bigToBytes32(scalar);
  try {
    return scalarFromBytes(taggedHash("BIP0352/Label", scalarBytes, serUint32(m)));
  } finally {
    scalarBytes.fill(0); // embeds the scan private key
  }
}

export function labeledSpendPoint(scanPriv, spendPoint, m) {
  const label = generateLabel(scanPriv, m);
  const tweak = Point.BASE.multiply(label);
  const labeled = pointAdd(spendPoint, tweak);
  if (!labeled) throw new Error("Label tweak produced the point at infinity.");
  return labeled;
}

export function createLabeledSilentPaymentAddress(scanPriv, spendPoint, m, hrp = "sp") {
  const scanBytes = scanPriv instanceof Uint8Array ? scanPriv : bigToBytes32(scanPriv);
  const scanPoint = Point.fromBytes(secp256k1.getPublicKey(scanBytes, true));
  return encodeSilentPaymentAddress(scanPoint, labeledSpendPoint(scanBytes, spendPoint, m), hrp);
}

export function deriveSilentPaymentKeys(masterSeed, { coinType = 0, account = 0 } = {}) {
  if (!(masterSeed instanceof Uint8Array) || !masterSeed.length) throw new Error("BIP-352 derivation needs a BIP32 master seed.");
  if (!Number.isInteger(coinType) || coinType < 0 || coinType > 0x7fffffff) throw new Error("coin_type is out of range.");
  if (!Number.isInteger(account) || account < 0 || account > 0x7fffffff) throw new Error("account is out of range.");
  const root = HDKey.fromMasterSeed(masterSeed);
  if (!root.hasPrivateKey) throw new Error("Watch-only keys cannot derive BIP-352 scan/spend paths (they are hardened).");
  const scanPath = `m/${BIP352_PURPOSE}'/${coinType}'/${account}'/1'/0`;
  const spendPath = `m/${BIP352_PURPOSE}'/${coinType}'/${account}'/0'/0`;
  const scanNode = root.derive(scanPath);
  const spendNode = root.derive(spendPath);
  if (!scanNode.hasPrivateKey || !spendNode.hasPrivateKey) throw new Error("BIP-352 child keys are missing private material.");
  // The getter copies, so one read per key is the whole private material;
  // the session owns these copies and no slice() duplicates are made.
  const scanPriv = scanNode.privateKey;
  const spendPriv = spendNode.privateKey;
  const scanPub = secp256k1.getPublicKey(scanPriv, true);
  const spendPub = secp256k1.getPublicKey(spendPriv, true);
  const keys = {
    coinType,
    account,
    scanPath,
    spendPath,
    scanPriv,
    spendPriv,
    scanPub,
    spendPub,
    scanPoint: Point.fromBytes(scanPub),
    spendPoint: Point.fromBytes(spendPub),
    fingerprint: root.fingerprint,
  };
  // The result owns the getter copies; the derivation nodes are dead.
  scanNode.wipePrivateData();
  spendNode.wipePrivateData();
  root.wipePrivateData();
  return keys;
}

const encodeKeyExpression = (hrp, payload) => {
  // Prepend the version in place. A spread would abandon the array toWords
  // returned, which carries the scan (and, for spspend, spend) private-key
  // bits (RT-JSBOUNDARY-1).
  const words = toWords(payload);
  words.unshift(0);
  try {
    return bech32mEncode(hrp, words);
  } finally {
    // The words carry the scan (and, for spspend, spend) private key bits.
    words.fill(0);
  }
};

export function encodeSpscan(scanPriv, spendPub, network = "mainnet") {
  const payload = new Uint8Array(65);
  payload.set(scanPriv instanceof Uint8Array ? scanPriv : bigToBytes32(scanPriv), 0);
  payload.set(spendPub, 32);
  try {
    return encodeKeyExpression(network === "mainnet" ? "spscan" : "tspscan", payload);
  } finally {
    payload.fill(0); // embeds the scan private key
  }
}

export function encodeSpspend(scanPriv, spendPriv, network = "mainnet") {
  const payload = new Uint8Array(64);
  payload.set(scanPriv instanceof Uint8Array ? scanPriv : bigToBytes32(scanPriv), 0);
  payload.set(spendPriv instanceof Uint8Array ? spendPriv : bigToBytes32(spendPriv), 32);
  try {
    return encodeKeyExpression(network === "mainnet" ? "spspend" : "tspspend", payload);
  } finally {
    payload.fill(0); // embeds both private keys
  }
}

export function formatSpDescriptor(keyExpression, origin) {
  if (origin) return `sp([${origin}]${keyExpression})`;
  return `sp(${keyExpression})`;
}

export function p2trAddressFromXonly(xonly, network = "mainnet") {
  const key = typeof xonly === "string" ? hexToBytes(xonly) : xonly;
  if (key.length !== 32) throw new Error("Taproot output key must be 32 bytes.");
  const hrp = network === "mainnet" ? "bc" : "tb";
  return bech32mEncode(hrp, [1, ...toWords(key)]);
}

// The prevout's scriptPubKey bytes (BIP352 input-key eligibility tests the
// script type), not the txid/vout pair "prevout" means elsewhere.
// The prevout script of a vin, in any of the accepted shapes (raw bytes, hex
// string, or the published-vector { scriptPubKey: { hex } } form).
export const vinPrevoutScript = (vin) => (vin.prevout instanceof Uint8Array ? vin.prevout : hexToBytes(typeof vin.prevout === "string" ? vin.prevout : vin.prevout.scriptPubKey.hex));

// A vin whose witness array is read as bytes: hex-string items (JSON) become
// bytes, byte arrays are kept, and any other item throws in hexToBytes, so a
// witness that cannot be read is never ignored. The app's send flow applies
// this to each pasted vin before anything reads its witness.
export const normalizeVinWitness = (vin) => (
  vin && typeof vin === "object" && Array.isArray(vin.witness) && vin.witness.length
    ? { ...vin, witness: vin.witness.map((item) => (item instanceof Uint8Array ? item : hexToBytes(item))) }
    : vin
);

const normalizeVin = (raw) => {
  const vin = normalizeVinWitness(raw);
  return {
    txid: vin.txid,
    vout: vin.vout,
    scriptSig: vin.scriptSig || "",
    txinwitness: vin.txinwitness || "",
    // The witness-array form extractInputPubKey accepts; anything else is
    // left out, as before, and txinwitness is used.
    witness: Array.isArray(vin.witness) && vin.witness.length ? vin.witness : undefined,
    prevout: vinPrevoutScript(vin),
    private_key: vin.private_key,
  };
};

// BIP-352 spends a taproot input with "the private key corresponding to the
// taproot output key (i.e. the tweaked private key)": the BIP-341 key-path
// tweak of the even-Y internal key. Supplying the raw internal key instead
// produces outputs the recipient can never detect.
export function taprootOutputPrivateKey(secret) {
  const internal = scalarFromBytes(secret instanceof Uint8Array ? secret : hexToBytes(secret));
  const even = pointHasEvenY(Point.fromBytes(publicKeyForScalar(internal))) ? internal : ORDER - internal;
  const xonly = pointToXOnly(Point.fromBytes(publicKeyForScalar(even)));
  // BIP-341 permits a zero tweak, but not a hash >= the group order.
  const tweakBytes = taggedHash("TapTweak", xonly);
  let tweak;
  try { tweak = bytesToBig(tweakBytes); }
  finally { tweakBytes.fill(0); }
  if (tweak >= ORDER) throw new Error("Taproot key-path tweak is out of range.");
  const output = (even + tweak) % ORDER;
  if (output === 0n) throw new Error("Taproot key-path tweak produced an invalid key.");
  return bigToBytes32(output);
}

export function eligibleInputKeys(vins) {
  const pubkeys = [];
  const privkeys = [];
  for (const [index, raw] of vins.entries()) {
    const vin = normalizeVin(raw);
    // A sender has no signatures yet: an input that carries its private key
    // but has no spend data is resolved from that key and its prevout script
    // type instead of the scriptSig or witness it does not have.
    const extracted = vin.private_key && !vinHasSpendData(vin)
      ? unsignedInputKey(vin, index)
      : extractInputPubKey(vin);
    if (!extracted) continue;
    pubkeys.push(extracted);
    if (vin.private_key) {
      const scalar = scalarFromBytes(typeof vin.private_key === "string" ? hexToBytes(vin.private_key) : vin.private_key);
      const suppliedPoint = Point.fromBytes(publicKeyForScalar(scalar));
      const matches = extracted.isTaproot
        ? equalBytes(pointToXOnly(suppliedPoint), pointToXOnly(extracted.point))
        : equalBytes(pointToCompressed(suppliedPoint), pointToCompressed(extracted.point));
      if (!matches) throw new Error(`Input ${index} private key does not match its eligible input public key.`);
      privkeys.push({
        scalar,
        isTaproot: extracted.isTaproot,
      });
    }
  }
  return { pubkeys, privkeys };
}

// The UI opts out of the vector API's secret scalar-sum diagnostic.
export function createSilentPaymentOutputs(vins, recipients, { hrp = "sp", includePrivateKeySum = true } = {}) {
  if (vins.some((vin) => isFutureSegwit(vinPrevoutScript(vin)))) {
    throw new Error("BIP-352 v0 cannot send with an input that spends a future SegWit version.");
  }
  const { pubkeys, privkeys } = eligibleInputKeys(vins);
  if (!pubkeys.length) return { outputs: [], inputPubKeys: [], inputPrivateKeySum: null, sharedSecrets: [] };
  if (privkeys.length !== pubkeys.length) throw new Error("Sending needs a private key for every eligible input.");
  const negated = privkeys.map(({ scalar, isTaproot }) => {
    let k = scalar;
    if (isTaproot) {
      const pub = Point.fromBytes(publicKeyForScalar(k));
      if (!pointHasEvenY(pub)) k = ORDER - k;
    }
    return k;
  });
  let aSum = 0n;
  for (const k of negated) aSum = (aSum + k) % ORDER;
  if (aSum === 0n) {
    return {
      outputs: [],
      inputPubKeys: pubkeys.map((entry) => bytesToHex(pointToCompressed(entry.point))),
      inputPrivateKeySum: includePrivateKeySum ? "0".repeat(64) : null,
      sharedSecrets: [],
    };
  }
  const A = Point.BASE.multiply(aSum);
  const outpoints = vins.map((vin) => ({ txid: vin.txid, vout: vin.vout }));
  const hash = scalarFromBytes(inputHash(outpoints, A));
  const groups = [];
  const groupIndex = new Map();
  for (const recipient of recipients) {
    const count = recipient.count ?? 1;
    if (!Number.isInteger(count) || count < 1) throw new Error("Recipient count must be a positive integer.");
    const decoded = decodeSilentPaymentAddress(recipient.address, hrp);
    const scanHex = bytesToHex(pointToCompressed(decoded.scan));
    let group = groupIndex.get(scanHex);
    if (!group) {
      group = { scan: decoded.scan, scanHex, spends: [], size: 0 };
      groupIndex.set(scanHex, group);
      groups.push(group);
    }
    group.spends.push({ spend: decoded.spend, count });
    group.size += count;
  }
  // The K_max check runs on the summed counts, before any expansion, so a
  // huge pasted count fails instead of allocating an attacker-sized array.
  if (groups.some((group) => group.size > BIP352_K_MAX)) {
    return {
      outputs: [],
      inputPubKeys: pubkeys.map((entry) => bytesToHex(pointToCompressed(entry.point))),
      inputPrivateKeySum: includePrivateKeySum ? bytesToHex(bigToBytes32(aSum)) : null,
      sharedSecrets: null,
    };
  }
  const ecdhScalar = reduceScalar(hash * aSum);
  const outputs = [];
  const sharedSecrets = [];
  const seenScan = new Set();
  for (const group of groups) {
    const secretPoint = pointMultiply(group.scan, ecdhScalar);
    const secretHex = bytesToHex(pointToCompressed(secretPoint));
    if (!seenScan.has(group.scanHex)) {
      sharedSecrets.push(secretHex);
      seenScan.add(group.scanHex);
    }
    // Per-group expansion is bounded by K_max after the check above.
    let k = 0;
    for (const { spend, count } of group.spends) {
      for (let copy = 0; copy < count; copy++, k++) {
        const tK = scalarFromBytes(taggedHash("BIP0352/SharedSecret", pointToCompressed(secretPoint), serUint32(k)));
        const tweaked = pointAdd(spend, Point.BASE.multiply(tK));
        if (!tweaked) throw new Error("Silent payment output is the point at infinity.");
        outputs.push(bytesToHex(pointToXOnly(tweaked)));
      }
    }
  }
  return {
    // BIP352: every generated P_i stays in the transaction — multiplicity is
    // part of the payment request and the scan progression, so the ordered
    // list is returned as-is and never deduplicated (issue #332).
    outputs,
    inputPubKeys: pubkeys.map((entry) => bytesToHex(pointToCompressed(entry.point))),
    inputPrivateKeySum: includePrivateKeySum ? bytesToHex(bigToBytes32(aSum)) : null,
    sharedSecrets,
  };
}

export function scanSilentPaymentOutputs({ scanPriv, spendPub, vins, outputs, labels = [] }) {
  if (vins.some((vin) => isFutureSegwit(vinPrevoutScript(vin)))) {
    return { outputs: [], inputPubKeySum: null, tweak: null, sharedSecret: null };
  }
  const scanScalar = scanPriv instanceof Uint8Array ? scalarFromBytes(scanPriv) : scanPriv;
  const spendPoint = spendPub instanceof Uint8Array ? Point.fromBytes(spendPub) : spendPub;
  const { pubkeys } = eligibleInputKeys(vins);
  if (!pubkeys.length) return { outputs: [], inputPubKeySum: null, tweak: null, sharedSecret: null };
  const A = sumPoints(pubkeys.map((entry) => entry.point));
  if (!A) return { outputs: [], inputPubKeySum: null, tweak: null, sharedSecret: null };
  const hashBytes = inputHash(vins.map((vin) => ({ txid: vin.txid, vout: vin.vout })), A);
  const hash = scalarFromBytes(hashBytes);
  const tweakPoint = pointMultiply(A, hash);
  const shared = pointMultiply(A, reduceScalar(hash * scanScalar));
  const labelMap = new Map();
  for (const m of labels) {
    const scalar = generateLabel(scanScalar, m);
    const point = Point.BASE.multiply(scalar);
    labelMap.set(bytesToHex(pointToCompressed(point)), { scalar, m });
  }
  const remaining = outputs.map((item) => (typeof item === "string" ? hexToBytes(item) : item)).map((bytes) => bytes.slice());
  const found = [];
  let k = 0;
  scan: while (k < BIP352_K_MAX) {
    const tK = scalarFromBytes(taggedHash("BIP0352/SharedSecret", pointToCompressed(shared), serUint32(k)));
    const P_k = pointAdd(spendPoint, Point.BASE.multiply(tK));
    if (!P_k) throw new Error("Silent payment scan tweak is the point at infinity.");
    const pkX = pointToXOnly(P_k);
    for (let i = 0; i < remaining.length; i++) {
      const output = remaining[i];
      if (equalBytes(pkX, output)) {
        found.push({ pub_key: bytesToHex(pkX), priv_key_tweak: bytesToHex(bigToBytes32(tK)), label: null });
        remaining.splice(i, 1);
        k += 1;
        continue scan;
      }
      if (labelMap.size) {
        const outputPoint = pointFromXOnly(output);
        let labelPoint = pointAdd(outputPoint, negatePoint(P_k));
        let labelHex = labelPoint ? bytesToHex(pointToCompressed(labelPoint)) : "";
        if (!labelMap.has(labelHex)) {
          labelPoint = pointAdd(negatePoint(outputPoint), negatePoint(P_k));
          labelHex = labelPoint ? bytesToHex(pointToCompressed(labelPoint)) : "";
        }
        if (labelMap.has(labelHex)) {
          const { scalar: labelScalar, m } = labelMap.get(labelHex);
          const P_km = pointAdd(P_k, Point.BASE.multiply(labelScalar));
          found.push({
            pub_key: bytesToHex(pointToXOnly(P_km)),
            priv_key_tweak: bytesToHex(bigToBytes32((tK + labelScalar) % ORDER)),
            label: m,
          });
          remaining.splice(i, 1);
          k += 1;
          continue scan;
        }
      }
    }
    break;
  }
  return {
    outputs: found,
    inputPubKeySum: bytesToHex(pointToCompressed(A)),
    tweak: bytesToHex(pointToCompressed(tweakPoint)),
    sharedSecret: bytesToHex(pointToCompressed(shared)),
  };
}

export function spendPrivForOutput(spendPriv, tweak) {
  const spend = spendPriv instanceof Uint8Array ? scalarFromBytes(spendPriv) : spendPriv;
  const t = tweak instanceof Uint8Array ? scalarFromBytes(tweak) : typeof tweak === "string" ? scalarFromBytes(hexToBytes(tweak)) : tweak;
  let full = (spend + t) % ORDER;
  if (full === 0n) throw new Error("Spend key + tweak is zero.");
  const pub = Point.fromBytes(publicKeyForScalar(full));
  if (!pointHasEvenY(pub)) full = ORDER - full;
  return bigToBytes32(full);
}

export { hexToBytes, bytesToHex, scalarFromBytes, Point };
