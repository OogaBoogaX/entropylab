// BIP-47 reusable payment codes. Deterministic only: same inputs → same
// outputs. No entropy is invented and nothing here touches the network — the
// notification transaction is pasted in, never fetched, and never broadcast.
// Curve ops go through the libsecp256k1 WASM facade (./secp256k1.js), hashes
// through the bitcoin_hashes WASM facade (./hashes.js), Base58Check through
// rust-bitcoin's base58ck (./base58.js), and addresses through rust-bitcoin's
// Address (./addresses.js). One secp implementation, no second crypto path.
import { hmacSha512, sha256 } from "./hashes.js";
import { HDKey } from "./hdkey.js";
import { secp256k1 } from "./secp256k1.js";
import { base58checkDecode, base58checkEncode } from "./base58.js";
import { addressFor } from "./addresses.js";

export const BIP47_PURPOSE = 47;
// Base58Check version byte; it is what gives every payment code its leading P.
export const BIP47_BASE58_VERSION = 0x47;
export const BIP47_PAYLOAD_BYTES = 80;
export const BIP47_VERSION_V1 = 0x01;
export const BIP47_VERSION_V2 = 0x02;
// The ECDH deposit keys and the identity level are both capped at 2^31 - 1:
// the deposit keys are the unhardened children, the identity level is the
// hardened one.
export const BIP47_INDEX_MAX = 2147483647;
const ORDER = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const Point = secp256k1.Point;

const hexToBytes = (hex) => {
  if (typeof hex !== "string" || hex.length % 2 || /[^0-9a-f]/i.test(hex)) throw new Error("Invalid hexadecimal input.");
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
};
const bytesToHex = (bytes) => [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
const bytesToBig = (bytes) => BigInt("0x" + bytesToHex(bytes));
const bigToBytes32 = (value) => {
  if (value <= 0n || value >= ORDER) throw new Error("Scalar is out of the secp256k1 range.");
  return hexToBytes(value.toString(16).padStart(64, "0"));
};
const toBytes = (value, what) => {
  if (value instanceof Uint8Array) return value;
  if (typeof value === "string") return hexToBytes(value.trim());
  throw new Error(`${what} must be a Uint8Array or a hex string.`);
};

export function wipeBytes(bytes) {
  if (bytes && bytes.fill) bytes.fill(0);
  return bytes;
}

const scalarFromBytes = (bytes) => {
  if (!(bytes instanceof Uint8Array) || bytes.length !== 32) throw new Error("Scalar must be 32 bytes.");
  const value = bytesToBig(bytes);
  if (value === 0n || value >= ORDER) throw new Error("Scalar is out of the secp256k1 range.");
  return value;
};

export function parseIndex(value, label = "index") {
  const n = typeof value === "number" ? value : Number(String(value ?? "").trim());
  if (!Number.isInteger(n) || n < 0 || n > BIP47_INDEX_MAX) throw new Error(`${label} must be an integer from 0 to ${BIP47_INDEX_MAX}.`);
  return n;
}

export function coinTypeForNetwork(network) {
  return network === "mainnet" ? 0 : 1;
}

export function paymentCodePath(coinType = 0, identity = 0) {
  return `m/${BIP47_PURPOSE}'/${parseIndex(coinType, "coin_type")}'/${parseIndex(identity, "identity")}'`;
}

// ── Payment code representation ─────────────────────────────────────────────
// 80 bytes: version | features | sign | x(32) | chain code(32) | reserved(13).
// The sign byte and the x value together are the compressed public key, which
// is why they are stored adjacently and read back out as one 33-byte slice.

export function serializePaymentCode({ publicKey, chainCode, version = BIP47_VERSION_V1, features = 0 } = {}) {
  const pub = toBytes(publicKey, "Payment code public key");
  const chain = toBytes(chainCode, "Payment code chain code");
  if (pub.length !== 33 || (pub[0] !== 0x02 && pub[0] !== 0x03)) throw new Error("Payment code needs a compressed secp256k1 public key.");
  if (chain.length !== 32) throw new Error("Payment code chain code must be 32 bytes.");
  if (version !== BIP47_VERSION_V1 && version !== BIP47_VERSION_V2) throw new Error("Only version 1 and version 2 payment codes are supported.");
  if (!Number.isInteger(features) || features < 0 || features > 0xff) throw new Error("Payment code features byte must be 0 to 255.");
  const payload = new Uint8Array(BIP47_PAYLOAD_BYTES);
  payload[0] = version;
  payload[1] = features;
  payload.set(pub, 2); // sign byte + x value
  payload.set(chain, 35);
  return payload;
}

export function encodePaymentCode(payload) {
  const bytes = toBytes(payload, "Payment code payload");
  if (bytes.length !== BIP47_PAYLOAD_BYTES) throw new Error(`Payment code payload must be ${BIP47_PAYLOAD_BYTES} bytes.`);
  const versioned = new Uint8Array(1 + BIP47_PAYLOAD_BYTES);
  versioned[0] = BIP47_BASE58_VERSION;
  versioned.set(bytes, 1);
  return base58checkEncode(versioned);
}

export function decodePaymentCode(text) {
  if (typeof text !== "string" || !text.trim()) throw new Error("Payment code is empty.");
  const decoded = base58checkDecode(text.trim());
  if (decoded.length !== 1 + BIP47_PAYLOAD_BYTES) throw new Error(`Payment code must decode to ${BIP47_PAYLOAD_BYTES} bytes after the version byte.`);
  if (decoded[0] !== BIP47_BASE58_VERSION) throw new Error(`Payment code version byte is 0x${decoded[0].toString(16)}, expected 0x47.`);
  const payload = decoded.slice(1);
  const version = payload[0];
  if (version !== BIP47_VERSION_V1 && version !== BIP47_VERSION_V2) throw new Error(`Unsupported payment code version ${version}.`);
  if (payload[2] !== 0x02 && payload[2] !== 0x03) throw new Error("Payment code sign byte must be 0x02 or 0x03.");
  const publicKey = payload.slice(2, 35);
  // Rejects an x value that is not on the curve, which is exactly the check
  // BIP-47 asks a recipient to run on an unblinded notification payload.
  Point.fromBytes(publicKey);
  return {
    version,
    features: payload[1],
    bitmessage: (payload[1] & 1) === 1,
    publicKey,
    chainCode: payload.slice(35, 67),
    reserved: payload.slice(67),
    payload,
  };
}

// A payment code is an extended public key plus metadata, so its unhardened
// children are ordinary BIP32 public derivations. Depth 3 is the level the
// spec puts it at (m/47'/coin_type'/identity'); the parent fingerprint is not
// recoverable from the 80-byte form and only affects re-serialization, which
// this module never does.
export function paymentCodeNode(code) {
  const decoded = typeof code === "string" ? decodePaymentCode(code) : code;
  return new HDKey({ depth: 3, index: 0, parentFingerprint: 0, chainCode: decoded.chainCode, publicKey: decoded.publicKey });
}

export function paymentCodeFromNode(node, { version = BIP47_VERSION_V1, features = 0 } = {}) {
  if (!node?.publicKey || !node?.chainCode) throw new Error("A payment code needs a BIP32 node with a public key and chain code.");
  return serializePaymentCode({ publicKey: node.publicKey, chainCode: node.chainCode, version, features });
}

// ── Notification address ────────────────────────────────────────────────────

export function notificationPublicKey(code) {
  return paymentCodeNode(code).deriveChild(0).publicKey;
}

export function notificationAddress(code, network = "mainnet") {
  return addressFor("p2pkh", notificationPublicKey(code), network);
}

// ── Derivation from a root ──────────────────────────────────────────────────

export function derivePaymentCodeKeys(root, { coinType = 0, identity = 0, version = BIP47_VERSION_V1, features = 0, network = "mainnet" } = {}) {
  if (!root || typeof root.derive !== "function") throw new Error("BIP-47 derivation needs a BIP32 node.");
  const path = paymentCodePath(coinType, identity);
  const node = root.derive(path);
  try {
    if (!node.publicKey) throw new Error("BIP-47 needs a node with a public key.");
    const payload = paymentCodeFromNode(node, { version, features });
    const notificationNode = node.deriveChild(0);
    let notificationPriv = null;
    try {
      notificationPriv = notificationNode.privateKey;
      return {
        path,
        coinType: parseIndex(coinType, "coin_type"),
        identity: parseIndex(identity, "identity"),
        version,
        features,
        watchOnly: !node.privateKey,
        fingerprint: root.fingerprint,
        accountFingerprint: node.fingerprint,
        publicKey: node.publicKey,
        chainCode: node.chainCode,
        payload,
        paymentCode: encodePaymentCode(payload),
        notificationPublicKey: notificationNode.publicKey,
        notificationAddress: addressFor("p2pkh", notificationNode.publicKey, network),
        // Only present when the caller brought a private root. Callers own it
        // and are expected to wipe it; the nodes below are dead by then.
        notificationPrivateKey: notificationPriv,
      };
    } finally {
      notificationNode.wipePrivateData();
    }
  } finally {
    node.wipePrivateData();
  }
}

// Refuses to hand back a private root's children when only public material was
// supplied, which is what "watch-only" has to mean here: a payment code and a
// notification address are public, every ECDH step below is not.
export function paymentCodeKeysFromAccountNode(node, { coinType = 0, identity = 0, version = BIP47_VERSION_V1, features = 0, network = "mainnet" } = {}) {
  if (!node?.deriveChild) throw new Error("BIP-47 needs a BIP32 node.");
  if (node.depth !== 3) throw new Error("A payment code account key must be the node at m/47'/coin_type'/identity' (depth 3), or a depth-0 root.");
  const payload = paymentCodeFromNode(node, { version, features });
  const notificationNode = node.deriveChild(0);
  try {
    return {
      // The 80-byte form carries no path, so an account key cannot state one.
      path: "",
      coinType: parseIndex(coinType, "coin_type"),
      identity: parseIndex(identity, "identity"),
      version,
      features,
      watchOnly: !node.privateKey,
      fingerprint: node.parentFingerprint,
      accountFingerprint: node.fingerprint,
      publicKey: node.publicKey,
      chainCode: node.chainCode,
      payload,
      paymentCode: encodePaymentCode(payload),
      notificationPublicKey: notificationNode.publicKey,
      notificationAddress: addressFor("p2pkh", notificationNode.publicKey, network),
      notificationPrivateKey: notificationNode.privateKey,
    };
  } finally {
    notificationNode.wipePrivateData();
  }
}

// The caller owns `node` above; this owns the one it parses, so it wipes it.
export function derivePaymentCodeFromExtendedKey(xkey, { coinType = 0, identity = 0, version = BIP47_VERSION_V1, features = 0, network = "mainnet" } = {}) {
  const node = HDKey.fromExtendedKey(xkey);
  try {
    if (node.depth === 0) return derivePaymentCodeKeys(node, { coinType, identity, version, features, network });
    return paymentCodeKeysFromAccountNode(node, { coinType, identity, version, features, network });
  } finally {
    node.wipePrivateData();
  }
}

// ── ECDH ────────────────────────────────────────────────────────────────────

// S = kP, then s = SHA256(S.x). BIP-47 requires the caller to move to the next
// index when s falls outside the group, so this reports that case rather than
// silently reducing it.
export function sharedSecretScalar(privateKey, point) {
  const key = toBytes(privateKey, "Private key");
  const secret = point.multiply(scalarFromBytes(key));
  const x = secret.toBytes(true).slice(1);
  const digest = sha256(x);
  const value = bytesToBig(digest);
  if (value === 0n || value >= ORDER) {
    wipeBytes(digest);
    return null;
  }
  return { scalar: value, bytes: digest, pointX: x };
}

const nextEcdhIndex = (privateKey, node, index) => {
  let i = index;
  while (i <= BIP47_INDEX_MAX) {
    const child = node.deriveChild(i);
    const shared = sharedSecretScalar(privateKey, Point.fromBytes(child.publicKey));
    if (shared) return { index: i, child, shared };
    // Not reachable with any published vector; the spec still requires it.
    child.wipePrivateData();
    i += 1;
  }
  throw new Error("No BIP-47 index below 2^31 produced a valid shared secret.");
};

// ── Sending: Alice's 0th private key against Bob's ith public key ───────────

export function deriveSendAddresses({ senderPrivateKey, recipientPaymentCode, start = 0, count = 10, network = "mainnet" } = {}) {
  const priv = toBytes(senderPrivateKey, "Sender private key");
  if (priv.length !== 32) throw new Error("The sender key is the 0th private key of the sender's payment code (32 bytes).");
  const node = paymentCodeNode(recipientPaymentCode);
  const first = parseIndex(start, "start index");
  if (!Number.isInteger(count) || count < 1 || count > 1000) throw new Error("Derive between 1 and 1000 addresses at a time.");
  const out = [];
  let cursor = first;
  for (let n = 0; n < count; n++) {
    const { index, child, shared } = nextEcdhIndex(priv, node, cursor);
    const ephemeral = Point.fromBytes(child.publicKey).add(Point.BASE.multiply(shared.scalar));
    const publicKey = ephemeral.toBytes(true);
    out.push({
      index,
      publicKey: bytesToHex(publicKey),
      // The BIP's published vectors tabulate the secret point's x value as
      // "S"; the scalar shared secret is its SHA-256. Both are shown so a
      // reader can follow either against the vector table.
      secretPointX: bytesToHex(shared.pointX),
      sharedSecret: bytesToHex(shared.bytes),
      address: addressFor("p2pkh", publicKey, network),
    });
    wipeBytes(shared.bytes);
    cursor = index + 1;
  }
  return out;
}

// ── Receiving: my ith private key against the sender's 0th public key ───────

export function deriveReceiveAddresses({ recipientNode, senderPaymentCode, start = 0, count = 10, network = "mainnet", includePrivate = false } = {}) {
  if (!recipientNode?.deriveChild) throw new Error("Receiving needs the recipient's payment code node.");
  if (includePrivate && !recipientNode.privateKey) throw new Error("Private receive keys need the payment code's private node; watch-only material cannot produce them.");
  if (!recipientNode.privateKey) throw new Error("Receive addresses need the recipient's private payment code node (the ECDH secret is not public).");
  const senderNode = paymentCodeNode(senderPaymentCode);
  const senderZero = senderNode.deriveChild(0);
  const senderPoint = Point.fromBytes(senderZero.publicKey);
  const first = parseIndex(start, "start index");
  if (!Number.isInteger(count) || count < 1 || count > 1000) throw new Error("Derive between 1 and 1000 addresses at a time.");
  const out = [];
  for (let n = 0; n < count; n++) {
    const index = first + n;
    if (index > BIP47_INDEX_MAX) throw new Error(`index must be an integer from 0 to ${BIP47_INDEX_MAX}.`);
    const child = recipientNode.deriveChild(index);
    const childPriv = child.privateKey;
    try {
      const shared = sharedSecretScalar(childPriv, senderPoint);
      // The sender skips an index whose shared secret leaves the group, so the
      // recipient must skip it in the same place rather than shift the window.
      if (!shared) {
        out.push({ index, skipped: true });
        continue;
      }
      const full = (scalarFromBytes(childPriv) + shared.scalar) % ORDER;
      if (full === 0n) throw new Error("BIP-47 receive key + shared secret is zero.");
      const privateKey = bigToBytes32(full);
      try {
        const publicKey = secp256k1.getPublicKey(privateKey, true);
        out.push({
          index,
          publicKey: bytesToHex(publicKey),
          secretPointX: bytesToHex(shared.pointX),
          sharedSecret: bytesToHex(shared.bytes),
          address: addressFor("p2pkh", publicKey, network),
          privateKey: includePrivate ? bytesToHex(privateKey) : "",
        });
      } finally {
        wipeBytes(privateKey);
      }
      wipeBytes(shared.bytes);
    } finally {
      wipeBytes(childPriv); // the getter copy
      child.wipePrivateData();
    }
  }
  return out;
}

// ── Notification transaction (pasted in, never fetched, never broadcast) ────

export function serializeOutpoint(txid, vout) {
  const hash = toBytes(txid, "Outpoint txid");
  if (hash.length !== 32) throw new Error("Outpoint txid must be 32 bytes.");
  if (!Number.isInteger(vout) || vout < 0 || vout > 0xffffffff) throw new Error("Outpoint vout is out of range.");
  const out = new Uint8Array(36);
  for (let i = 0; i < 32; i++) out[i] = hash[31 - i]; // txids are shown reversed
  new DataView(out.buffer).setUint32(32, vout, true);
  return out;
}

// s = HMAC-SHA512(key = the 36-byte outpoint, data = the secret point's x).
// The BIP prose writes the two arguments in one order for the sender and the
// other for the recipient; its own published vectors settle it as this one,
// and blindPaymentCode's round trip against them is what proves it.
export function blindingFactor(outpoint, secretPointX) {
  const key = toBytes(outpoint, "Outpoint");
  if (key.length !== 36) throw new Error("The blinding outpoint must be the 36-byte serialization.");
  const x = toBytes(secretPointX, "Secret point x value");
  if (x.length !== 32) throw new Error("The secret point x value must be 32 bytes.");
  return hmacSha512(key, x);
}

// XOR is its own inverse, so blinding and unblinding are one function; the
// version, features, sign and reserved bytes are left untouched by design.
export function maskPaymentCodePayload(payload, mask) {
  const bytes = toBytes(payload, "Payment code payload");
  if (bytes.length !== BIP47_PAYLOAD_BYTES) throw new Error(`Payment code payload must be ${BIP47_PAYLOAD_BYTES} bytes.`);
  const factor = toBytes(mask, "Blinding factor");
  if (factor.length !== 64) throw new Error("The blinding factor must be 64 bytes.");
  const out = bytes.slice();
  for (let i = 0; i < 64; i++) out[3 + i] ^= factor[i];
  return out;
}

// Sender side: blind my payment code for the OP_RETURN of a notification
// transaction I will build and sign somewhere else. Nothing is broadcast here.
export function blindPaymentCode({ payload, senderPrivateKey, recipientNotificationPublicKey, txid, vout, outpoint } = {}) {
  const point = Point.fromBytes(toBytes(recipientNotificationPublicKey, "Recipient notification public key"));
  const priv = toBytes(senderPrivateKey, "Designated input private key");
  const shared = sharedSecretScalar(priv, point);
  if (!shared) throw new Error("The notification shared secret is outside the secp256k1 group; use a different designated input.");
  const serialized = outpoint ? toBytes(outpoint, "Outpoint") : serializeOutpoint(txid, vout);
  const mask = blindingFactor(serialized, shared.pointX);
  try {
    return { blinded: maskPaymentCodePayload(payload, mask), mask, outpoint: serialized, secretPointX: shared.pointX };
  } finally {
    wipeBytes(shared.bytes);
  }
}

// Recipient side: recover the sender's payment code from a pasted notification
// payload using my notification private key and the transaction's designated
// pubkey and outpoint. Returns null when the unblinded x value is not on the
// curve, which is the BIP's "ignore this payload" verdict rather than an error.
export function unblindPaymentCode({ blinded, notificationPrivateKey, designatedPublicKey, txid, vout, outpoint } = {}) {
  const point = Point.fromBytes(toBytes(designatedPublicKey, "Designated public key"));
  const priv = toBytes(notificationPrivateKey, "Notification private key");
  const shared = sharedSecretScalar(priv, point);
  if (!shared) throw new Error("The notification shared secret is outside the secp256k1 group.");
  const serialized = outpoint ? toBytes(outpoint, "Outpoint") : serializeOutpoint(txid, vout);
  const mask = blindingFactor(serialized, shared.pointX);
  try {
    const payload = maskPaymentCodePayload(blinded, mask);
    let decoded = null;
    try {
      decoded = decodePaymentCode(encodePaymentCode(payload));
    } catch {
      return { payload, decoded: null, paymentCode: "", mask, outpoint: serialized };
    }
    return { payload, decoded, paymentCode: encodePaymentCode(payload), mask, outpoint: serialized };
  } finally {
    wipeBytes(shared.bytes);
  }
}

// The 80-byte payload as it sits in a notification transaction's OP_RETURN:
// OP_RETURN OP_PUSHDATA1 0x50 <80 bytes>. Reads the payload out of either the
// full output script or a bare 80-byte push.
export function paymentCodePayloadFromScript(script) {
  const bytes = toBytes(script, "OP_RETURN script");
  if (bytes.length === BIP47_PAYLOAD_BYTES) return bytes.slice();
  if (bytes.length === BIP47_PAYLOAD_BYTES + 3 && bytes[0] === 0x6a && bytes[1] === 0x4c && bytes[2] === BIP47_PAYLOAD_BYTES) return bytes.slice(3);
  throw new Error("Not a BIP-47 notification payload: expected an 80-byte OP_RETURN push.");
}

// ── Verification ────────────────────────────────────────────────────────────

// Checks a pasted address against a derived window rather than against the
// chain: no scan, no lookup, just "is this one of the addresses this pair of
// payment codes produces".
export function findDerivedAddress(address, entries) {
  const wanted = String(address ?? "").trim();
  if (!wanted) throw new Error("Paste an address to verify.");
  const hit = entries.find((entry) => entry.address === wanted);
  return hit ? { found: true, index: hit.index, address: hit.address, publicKey: hit.publicKey } : { found: false, index: null, address: wanted, publicKey: "" };
}

export { hexToBytes, bytesToHex, Point };
