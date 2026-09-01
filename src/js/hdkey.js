// BIP32 hierarchical deterministic keys for EntropyLab, backed by
// rust-bitcoin's bitcoin::bip32 compiled to WebAssembly (Rust crate in
// entropylab-wasm/, loaded by entropylab-wasm.js).
//
// Drop-in replacement for the slice of @scure/bip32 the app uses: the HDKey
// class with fromMasterSeed / fromExtendedKey / derive / deriveChild and the
// depth / index / parentFingerprint / chainCode / privateKey / publicKey /
// fingerprint / privateExtendedKey / publicExtendedKey surface. The WASM does
// the cryptography (master key, single-step CKD); path grammar, node
// bookkeeping, and serialization byte layout live here and mirror @scure/bip32
// exactly, including the BIP32 retry-with-next-index verdict (the WASM
// reports it as a distinct code; rust-bitcoin's own ckd_priv would panic on
// that statistically-unreachable branch).
import { hash160 } from "./hashes.js";
import { secp256k1 } from "./secp256k1.js";
import { base58checkEncode, base58checkDecode } from "./base58.js";
import { heap, wasmExports as wasm, withInput, withOutput } from "./entropylab-wasm.js";

export const HARDENED_OFFSET = 0x80000000;
const MAX_DEPTH = 255;
export const BITCOIN_VERSIONS = { private: 0x0488ade4, public: 0x0488b21e };

const ORDER = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const bytesToBig = (bytes) => bytes.reduce((n, b) => (n << 8n) | BigInt(b), 0n);
const isValidSecretKey = (bytes) => {
  if (!(bytes instanceof Uint8Array) || bytes.length !== 32) return false;
  const n = bytesToBig(bytes);
  return n > 0n && n < ORDER;
};

const toU32 = (value, title) => {
  if (!Number.isSafeInteger(value) || value < 0 || value > 0xffffffff) throw new Error(`${title} must be a uint32`);
  return value;
};
const validateVersions = (versions) => {
  toU32(versions.private, "versions.private");
  toU32(versions.public, "versions.public");
  return versions;
};

// Packs the node fields into the 78-byte BIP32 serialization. The wire
// version is always mainnet xprv/xpub (what rust-bitcoin parses); the node's
// own versions only shape the base58 strings, as in @scure/bip32.
const packNode = (isPrivate, node) => {
  const body = new Uint8Array(78);
  const view = new DataView(body.buffer);
  view.setUint32(0, isPrivate ? BITCOIN_VERSIONS.private : BITCOIN_VERSIONS.public, false);
  body[4] = node.depth;
  view.setUint32(5, node.parentFingerprint >>> 0, false);
  view.setUint32(9, node.index >>> 0, false);
  body.set(node._chainCode, 13);
  if (isPrivate) body.set(node._privateKey, 46);
  else body.set(node._publicKey, 45);
  return body;
};

const unpackNode = (body) => ({
  depth: body[4],
  parentFingerprint: new DataView(body.buffer, body.byteOffset).getUint32(5, false),
  index: new DataView(body.buffer, body.byteOffset).getUint32(9, false),
  chainCode: body.slice(13, 45),
  key: body.slice(45),
});

export class HDKey {
  static fromMasterSeed(seed, versions = BITCOIN_VERSIONS) {
    versions = validateVersions(versions);
    if (!(seed instanceof Uint8Array)) throw new Error("seed must be a Uint8Array");
    if (8 * seed.length < 128 || 8 * seed.length > 512) {
      throw new RangeError("HDKey: seed length must be between 128 and 512 bits; 256 bits is advised, got " + 8 * seed.length + " bits");
    }
    const body = withInput(seed, (p) => withOutput(78, (out) => wasm().el_hd_master(p, seed.length, out)));
    if (!body) throw new Error("HDKey: master key derivation failed (invalid key material)");
    try {
      const node = unpackNode(body);
      return new HDKey({ versions, depth: 0, index: 0, parentFingerprint: 0, chainCode: node.chainCode, privateKey: body.slice(46) });
    } finally {
      body.fill(0); // the master serialization (private key + chain code) is secret
    }
  }

  static fromExtendedKey(base58key, versions = BITCOIN_VERSIONS) {
    versions = validateVersions(versions);
    // => version(4) || depth(1) || fingerprint(4) || index(4) || chain(32) || key(33)
    const keyBuffer = base58checkDecode(base58key);
    let key = null;
    try {
      if (keyBuffer.length !== 78) {
        throw new Error(`HDKey: invalid extended key length: expected 78 bytes, got ${keyBuffer.length}`);
      }
      const keyView = new DataView(keyBuffer.buffer, keyBuffer.byteOffset);
      const version = keyView.getUint32(0, false);
      const opt = {
        versions,
        depth: keyBuffer[4],
        parentFingerprint: keyView.getUint32(5, false),
        index: keyView.getUint32(9, false),
        chainCode: keyBuffer.slice(13, 45),
      };
      key = keyBuffer.slice(45);
      const isPriv = key[0] === 0;
      if (version !== versions[isPriv ? "private" : "public"]) {
        throw new Error("Version mismatch");
      }
      if (isPriv) {
        return new HDKey({ ...opt, privateKey: key.slice(1) });
      }
      return new HDKey({ ...opt, publicKey: key });
    } finally {
      // The decoded 78-byte payload (and the sliced key copy) can carry an
      // extended private key; the HDKey constructor copies what it needs.
      keyBuffer.fill(0);
      if (key) key.fill(0);
    }
  }

  constructor(opt) {
    if (!opt || typeof opt !== "object") throw new Error("HDKey: constructor requires an options object");
    const depth = opt.depth ?? 0;
    const index = opt.index ?? 0;
    const parentFingerprint = opt.parentFingerprint ?? 0;
    if (!Number.isSafeInteger(depth) || depth < 0 || depth > MAX_DEPTH) {
      throw new RangeError("HDKey: depth must be an integer in range 0..255");
    }
    toU32(index, "index");
    toU32(parentFingerprint, "parentFingerprint");
    if (depth === 0 && (index !== 0 || parentFingerprint !== 0)) {
      throw new Error("HDKey: zero depth with non-zero index/parent fingerprint");
    }
    this.versions = opt.versions ? validateVersions(opt.versions) : BITCOIN_VERSIONS;
    this.depth = depth;
    if (opt.chainCode && opt.chainCode.length !== 32) throw new Error("chainCode must be 32 bytes");
    this._chainCode = opt.chainCode ? Uint8Array.from(opt.chainCode) : null;
    this.index = index;
    this.parentFingerprint = parentFingerprint;
    if (opt.publicKey && opt.privateKey) throw new Error("HDKey: publicKey and privateKey at same time.");
    if (opt.privateKey) {
      if (!isValidSecretKey(opt.privateKey)) throw new Error("Invalid private key");
      // Don't alias caller-owned secret buffers.
      this._privateKey = Uint8Array.from(opt.privateKey);
      this._publicKey = secp256k1.getPublicKey(this._privateKey, true);
    } else if (opt.publicKey) {
      this._publicKey = secp256k1.Point.fromBytes(opt.publicKey).toBytes(true); // force compressed point
    } else {
      throw new Error("HDKey: no public or private key provided");
    }
    this._pubHash = hash160(this._publicKey);
  }

  get fingerprint() {
    if (!this._pubHash) throw new Error("No publicKey set!");
    return new DataView(this._pubHash.buffer, this._pubHash.byteOffset).getUint32(0, false);
  }
  get identifier() {
    return this._pubHash ? Uint8Array.from(this._pubHash) : undefined;
  }
  get pubKeyHash() {
    return this._pubHash ? Uint8Array.from(this._pubHash) : undefined;
  }
  get privateKey() {
    return this._privateKey ? Uint8Array.from(this._privateKey) : null;
  }
  get publicKey() {
    return this._publicKey ? Uint8Array.from(this._publicKey) : null;
  }
  get chainCode() {
    return this._chainCode ? Uint8Array.from(this._chainCode) : null;
  }
  get privateExtendedKey() {
    const priv = this._privateKey;
    if (!priv) throw new Error("No private key");
    const key = new Uint8Array([0, ...priv]);
    try {
      return this.serialize(this.versions.private, key);
    } finally {
      key.fill(0);
    }
  }
  get publicExtendedKey() {
    if (!this._publicKey) throw new Error("No public key");
    return this.serialize(this.versions.public, this._publicKey);
  }

  serialize(version, key) {
    const body = new Uint8Array(78);
    const view = new DataView(body.buffer);
    view.setUint32(0, version, false);
    body[4] = this.depth;
    view.setUint32(5, this.parentFingerprint >>> 0, false);
    view.setUint32(9, this.index >>> 0, false);
    body.set(this._chainCode, 13);
    body.set(key, 45);
    try {
      return base58checkEncode(body);
    } finally {
      body.fill(0); // the private serialization embeds the key and chain code
    }
  }

  neutered() {
    return new HDKey({
      versions: this.versions,
      depth: this.depth,
      index: this.index,
      parentFingerprint: this.parentFingerprint,
      chainCode: this._chainCode,
      publicKey: this._publicKey,
    });
  }

  wipePrivateData() {
    if (this._privateKey) this._privateKey.fill(0);
    this._privateKey = null;
    return this;
  }

  derive(path) {
    if (!/^[mM]'?/.test(path)) throw new Error('Path must start with "m" or "M"');
    if (/^[mM]'?$/.test(path)) return this;
    const parts = path.replace(/^[mM]'?\//, "").split("/");
    if (parts.length > MAX_DEPTH - this.depth) {
      throw new Error("HDKey: path exceeds the serializable depth 255");
    }
    let child = this;
    for (const part of parts) {
      const m = /^(\d+)('?)$/.exec(part);
      if (!m) throw new Error("invalid child index: " + part);
      let idx = +m[1];
      if (!Number.isSafeInteger(idx) || idx >= HARDENED_OFFSET) throw new Error("Invalid index");
      if (m[2] === "'") idx += HARDENED_OFFSET;
      const next = child.deriveChild(idx);
      // Intermediate path nodes are dead once their child exists; wipe the
      // private half instead of leaving the keys for the GC to keep.
      if (child !== this) child.wipePrivateData();
      child = next;
    }
    return child;
  }

  deriveChild(index) {
    toU32(index, "index");
    if (!this._publicKey || !this._chainCode) throw new Error("No publicKey or chainCode set");
    const hardened = index >= HARDENED_OFFSET;
    if (hardened && !this._privateKey) throw new Error("Could not derive hardened child key");
    if (this.depth + 1 > MAX_DEPTH) throw new Error("HDKey: depth exceeds the serializable value 255");
    const input = packNode(!!this._privateKey, this);
    // The WASM returns 78 (bytes written), 1 (BIP32 retry-with-next-index
    // verdict), or -1 (hard error); keep the three distinct.
    let code, body;
    try {
      ({ code, body } = withInput(input, (p) => {
        const outPtr = wasm().el_alloc(78);
        try {
          const fn = this._privateKey ? "el_hd_ckd_priv" : "el_hd_ckd_pub";
          const produced = wasm()[fn](p, index >>> 0, outPtr);
          return { code: produced, body: produced === 78 ? heap().slice(outPtr, outPtr + 78) : null };
        } finally {
          wasm().el_free(outPtr, 78);
        }
      }));
    } finally {
      input.fill(0); // a private node's serialization embeds its key
    }
    if (code === 1) {
      // BIP32: invalid I_L or child -> proceed with the next index.
      const maxIndex = this._privateKey ? 2 ** 32 - 1 : HARDENED_OFFSET - 1;
      if (index >= maxIndex) throw new Error(`HDKey: cannot retry child derivation at index ${index}`);
      return this.deriveChild(index + 1);
    }
    if (code !== 78 || !body) throw new Error("HDKey: child derivation failed");
    const node = unpackNode(body);
    body.fill(0); // unpackNode slices (copies) what the child keeps
    const opt = {
      versions: this.versions,
      chainCode: node.chainCode,
      depth: node.depth,
      parentFingerprint: node.parentFingerprint,
      index: node.index,
    };
    if (this._privateKey) opt.privateKey = node.key.slice(1);
    else opt.publicKey = node.key;
    return new HDKey(opt);
  }
}
