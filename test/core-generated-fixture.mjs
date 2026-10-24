// Generated wallet.dat fixture for the Key Station import tests.
//
// Builds the records of a wallet the way Bitcoin Core 23+ writes one created
// with createwallet (SetupDescriptorGeneration, v28.3): the stored descriptor
// embeds the MASTER xpub with the full account path as its tail
// (wpkh(tpub…/84h/1h/0h/0/*)), and every walletdescriptorkey record holds the
// same raw 32-byte secret — the key Core generated and fed to
// CExtKey::SetSeed, i.e. the BIP32 master seed. Everything here is computed
// with the harness's independent reference crypto (node:crypto + BigInt
// secp256k1), never the modules under test.
//
// Used by test/core-wallet.test.mjs; the exact row hex is also embedded into
// test/browser-suite.html's Core Wallet section (regenerate the literal with:
//   node -e "import('./test/core-generated-fixture.mjs').then(m => console.log(JSON.stringify(m.GENERATED_ROWS)))"
// ).
import {
  hdMasterFromSeed,
  hdDeriveHardened,
  serializeExtendedKey,
  publicKeyForPrivate,
  deriveBranchBody,
  sha256,
  ripemd160,
  descriptorChecksum,
  bytesToHex,
  hexToBytes,
} from "./wallet-export-harness.mjs";

// The seed Core would have generated (fixed so the rows are stable).
export const GENERATED_SEED = sha256(new TextEncoder().encode("entropylab core-wallet import fixture seed"));

const TPUB = 0x043587cf;
const TPRV = 0x04358394;
export const GENERATED_ROOT_TPRV = serializeExtendedKey(hdMasterFromSeed(GENERATED_SEED), TPRV, true);
export const GENERATED_ROOT_TPUB = serializeExtendedKey(hdMasterFromSeed(GENERATED_SEED), TPUB, false);
// The wallet's master fingerprint: BIP32 fingerprint (hash160 head) of the
// master pubkey — the secret the walletdescriptorkey records carry is the
// master secret (see buildGeneratedUnitRecords).
export const GENERATED_MASTER_FINGERPRINT = bytesToHex(ripemd160(sha256(publicKeyForPrivate(hdMasterFromSeed(GENERATED_SEED).secret))).subarray(0, 4));

// Bitcoin serialisation helpers, matching the record layouts the export
// writes (documented in src/js/wallet-export.js).
const utf8 = (text) => new TextEncoder().encode(text);
const u8 = (value) => Uint8Array.of(value & 0xff);
const u32le = (value) => Uint8Array.of(value & 0xff, (value >>> 8) & 0xff, (value >>> 16) & 0xff, (value >>> 24) & 0xff);
const u64le = (value) => {
  const bytes = new Uint8Array(8);
  new DataView(bytes.buffer).setBigUint64(0, BigInt(value), true);
  return bytes;
};
const compactSize = (n) => (n < 253 ? u8(n) : (() => { throw new Error("test records stay under 253"); })());
const concat = (...parts) => {
  const out = new Uint8Array(parts.reduce((n, part) => n + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
};
const streamString = (text) => concat(compactSize(utf8(text).length), utf8(text));

// Core CPrivKey DER form of a 32-byte secret: the exact 214-byte template,
// cross-checked against the Core ground-truth records in
// test/wallet-export-reference.mjs.
const DER_HEAD = hexToBytes("3081d30201010420");
const DER_PARAMS = hexToBytes(
  "a08185308182020101302c06072a8648ce3d0101022100fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f" +
  "300604010004010704210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798" +
  "022100fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141020101a124032200",
);
export const derForSecret = (secret) => concat(DER_HEAD, secret, DER_PARAMS, publicKeyForPrivate(secret));

// The output types a generated wallet covers: (label, Core's (purpose, type)).
export const GENERATED_TYPES = [
  ["pkh", 44, 0],
  ["wpkh", 84, 2],
  ["tr", 86, 3],
];

// One generated descriptor set covering GENERATED_TYPES: external + internal
// per type, each row set mirroring Core (descriptor, cache parent at the full
// tail path, master-secret key record, active pointer). embeddedTpub lets a
// test store a descriptor whose embedded key is NOT the record holder's —
// the unroutable-key refusal case.
export const buildGeneratedUnitRecords = (seed, { embeddedTpub = null, purposes = GENERATED_TYPES } = {}) => {
  const master = hdMasterFromSeed(seed);
  // AddDescriptorKeyWithDB stores master_key.key (the BIP32 master secret
  // derived by CExtKey::SetSeed), not the random 32 bytes Core generated.
  const pubkey = publicKeyForPrivate(master.secret);
  const der = derForSecret(master.secret);
  const rows = [];
  for (const [wrapper, purpose, type] of purposes) {
    for (const internal of [false, true]) {
      const inner = embeddedTpub ?? serializeExtendedKey(master, TPUB, false);
      const keyed = `${inner}/${purpose}h/1h/0h/${internal ? 1 : 0}/*`;
      const body = wrapper === "pkh" ? `pkh(${keyed})` : wrapper === "wpkh" ? `wpkh(${keyed})` : `tr(${keyed})`;
      const descriptor = `${body}#${descriptorChecksum(body)}`;
      const id = sha256(utf8(descriptor)); // compat form == body: no origin key info
      rows.push([concat(streamString("walletdescriptor"), id), concat(streamString(descriptor), u64le(0), u32le(0), u32le(0), u32le(1000))]);
      let account = master;
      for (const index of [purpose, 1, 0]) account = hdDeriveHardened(account, index);
      const accountXpub = serializeExtendedKey(account, TPUB, false);
      const cacheBody = deriveBranchBody(accountXpub, internal ? 1 : 0);
      rows.push([concat(streamString("walletdescriptorcache"), id, u32le(0)), concat(compactSize(cacheBody.length), cacheBody)]);
      const keyHash = sha256(sha256(concat(pubkey, der)));
      rows.push([concat(streamString("walletdescriptorkey"), id, compactSize(pubkey.length), pubkey), concat(compactSize(der.length), der, keyHash)]);
      rows.push([concat(streamString(internal ? "activeinternalspk" : "activeexternalspk"), u8(type)), id]);
    }
  }
  return rows;
};

const HEADER = (extra = []) => [
  ["0776657273696f6e", "ec460400"],
  ["0a6d696e76657273696f6e", "ac970200"],
  ["05666c616773", "0000000006000000"],
  ["0962657374626c6f636b", "8011010000"],
  ["1262657374626c6f636b5f6e6f6d65726b6c65", "801101000106226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f"],
  ...extra,
];

export const buildGeneratedWalletRecords = (options) =>
  [...HEADER().map(([key, value]) => [hexToBytes(key), hexToBytes(value)]), ...buildGeneratedUnitRecords(GENERATED_SEED, options)];

// A fresh regtest signing wallet covering all three single-sig types, exactly
// as createwallet would leave it.
export const GENERATED_ROWS = buildGeneratedWalletRecords().map(([key, value]) => [bytesToHex(key), bytesToHex(value)]);

export const REGTEST_APP_ID = 0xfabfb5da;
