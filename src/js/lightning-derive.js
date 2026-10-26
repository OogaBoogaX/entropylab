// Lightning node identity derivations, DOM-free: what the Lightning tool's
// key worker (ln-worker.js) runs, and what the tests check against the
// reference libraries. lightning.js re-exports the public pieces.
//
// Two seed schemes and Core Lightning's hsm_secret:
//
// * aezeed (LND). The 24-word cipher seed deciphers (aezeed.js) to 16 bytes
//   of entropy that LND feeds DIRECTLY to BIP32 as the master seed (no BIP39
//   PBKDF2). The node identity key sits at m/1017'/coinType'/6'/0/0
//   (BIP43 purpose 1017, key family 6 = node key; coin type 0 on mainnet,
//   1 on testnet), per lnd/keychain/derivation.go.
//
// * BIP-39 (LDK, ldk-node convention). ldk-node turns the mnemonic into the
//   standard 64-byte BIP39 seed, takes the BIP32 master key's own 32-byte
//   private key, and hands that to LDK's KeysManager, which re-seeds a
//   second BIP32 master from it and derives the node secret at m/0'
//   (hardened), per ldk-node/src/builder.rs and rust-lightning's
//   sign::KeysManager. The result is network-independent.
//
// * hsm_secret (Core Lightning, type 2). The node id and the BIP86 account
//   xpub come from hsm-secret.js; the account xprv and the first receive
//   addresses are derived below from the same seed.
//
// Deterministic transformations of user input only: nothing here generates
// entropy.
import { HDKey, HARDENED_OFFSET } from "./hdkey.js";
import { mnemonicToSeedSync, validateMnemonic } from "./bip39.js";
import { aezeedDecode } from "./aezeed.js";
import { wordlist as bip39English } from "./bip39-english.js";
import { hex } from "./coders.js";
import * as hodlHashes from "./hashes.js";
import { detectHsmSecretType, readClnMnemonic, deriveClnNode, HSM_SECRET_PLAIN, HSM_SECRET_ENCRYPTED, HSM_SECRET_MNEMONIC_WITH_PASS, HSM_SECRET_INVALID } from "./hsm-secret.js";

// The aezeed internal (key-derivation) version this tool understands: LND
// writes version 0 and rejects anything else; guggero's cryptography-toolkit
// also emits version 1. Deriving a node key from an unknown internal version
// would print a key no Lightning implementation would ever use.
export const isKnownInternalVersion = (version) => version === 0 || version === 1;

// LND: the aezeed entropy is the BIP32 seed; node key at
// m/1017'/coinType'/6'/0/0. Returns the compressed pubkey hex, the path, and
// the root xprv (what chantools showrootkey prints; importable into wallets).
export const deriveLndNode = (entropy16, coinType) => {
  if (!(entropy16 instanceof Uint8Array) || entropy16.length !== 16) {
    throw new Error("aezeed entropy must be 16 bytes.");
  }
  if (coinType !== 0 && coinType !== 1) throw new Error("Coin type must be 0 (mainnet) or 1 (testnet).");
  const path = `m/1017'/${coinType}'/6'/0/0`;
  const master = HDKey.fromMasterSeed(entropy16);
  let node = null;
  try {
    node = master.derive(path);
    return { nodePubKey: hex.encode(node.publicKey), path, rootXprv: master.privateExtendedKey };
  } finally {
    if (node) node.wipePrivateData();
    master.wipePrivateData();
  }
};

// A BIP39 passphrase is UTF-8 text: a lone surrogate would silently encode
// as U+FFFD and derive a wallet that is not the one the user typed (the
// calculator's BIP39 path refuses the same, #1015). JS strings are UTF-16,
// so the check is a scan for unpaired surrogates.
const isWellFormedUtf16 = (text) => {
  for (let i = 0; i < text.length; i++) {
    const code = text.charCodeAt(i);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = text.charCodeAt(i + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return false;
      i++;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      return false;
    }
  }
  return true;
};

// LDK (ldk-node): BIP39 seed -> master xprv -> its raw private key re-seeds
// a second master -> node secret at m/0'. The root xprv returned is the
// first-stage master (the on-chain wallet root ldk-node uses).
export const deriveLdkNode = (mnemonic, passphrase = "") => {
  if (!isWellFormedUtf16(passphrase)) {
    // The wrong side was the message: the guard fired, but its fallback text
    // ("not well-formed Unicode") dropped the actionable word the key and
    // the refusal tests carry — "surrogate", an invisible pasted character
    // the user must retype rather than paste.
    throw Object.assign(new Error("The passphrase contains an unpaired surrogate."), {
      key: "The passphrase contains an unpaired surrogate, which cannot be encoded as UTF-8. Retype the passphrase instead of pasting it.",
      code: "passphrase-utf8",
    });
  }
  const seed64 = mnemonicToSeedSync(mnemonic, passphrase);
  let master1 = null, master2 = null, node = null, key32 = null;
  try {
    master1 = HDKey.fromMasterSeed(seed64);
    key32 = master1.privateKey;
    master2 = HDKey.fromMasterSeed(key32);
    node = master2.deriveChild(0 + HARDENED_OFFSET);
    return { nodePubKey: hex.encode(node.publicKey), path: "m/0'", rootXprv: master1.privateExtendedKey };
  } finally {
    seed64.fill(0);
    if (key32) key32.fill(0);
    if (node) node.wipePrivateData();
    if (master2) master2.wipePrivateData();
    if (master1) master1.wipePrivateData();
  }
};

// A BIP-39 phrase for the LDK path, or a keyed error the page translates.
export function validateLnBip39(words) {
  if (words.length === 0) throw Object.assign(new Error("Type or paste your seed phrase."), { key: "Type or paste your seed phrase." });
  if (![12, 15, 18, 21, 24].includes(words.length)) {
    throw Object.assign(new Error("A seed phrase is 12, 15, 18, 21, or 24 words. You entered {n}."), { key: "A seed phrase is 12, 15, 18, 21, or 24 words. You entered {n}.", vars: { n: words.length } });
  }
  const unknown = words.map((word, index) => ({ word, index })).filter(({ word }) => !bip39English.includes(word));
  if (unknown.length > 0) {
    throw Object.assign(new Error("Unknown word"), { key: "Word {n} (“{word}”) is not on the BIP39 English list.", vars: { n: unknown[0].index + 1, word: unknown[0].word } });
  }
  const phrase = words.join(" ");
  if (!validateMnemonic(phrase)) {
    throw Object.assign(new Error("Bad checksum"), { key: "The BIP39 checksum does not match. A word is likely mistyped, missing, or swapped." });
  }
  return phrase;
}

// ── Core Lightning hsm_secret (type 2) ──────────────────────────────────────

// CLN fixes coin type 0' on every network (hsm-secret.js); the network only
// changes the extended-key version bytes and the bech32 address prefix.
const CLN_NETWORKS = {
  bitcoin: { private: 0x0488ade4, public: 0x0488b21e, hrp: "bc" },
  testnet: { private: 0x04358394, public: 0x043587cf, hrp: "tb" },
};

const hodlHash160 = (bytes) => {
  if (typeof hodlHashes.hash160 === "function") return hodlHashes.hash160(bytes);
  if (typeof hodlHashes.ripemd160 === "function") return hodlHashes.ripemd160(hodlHashes.sha256(bytes));
  throw new Error("hash160 is unavailable.");
};

const BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const BECH32_GENERATOR = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];

const hodlLnBech32Polymod = (values) => {
  let checksum = 1;
  for (const value of values) {
    const top = checksum >>> 25;
    checksum = ((checksum & 0x1ffffff) << 5) ^ value;
    for (let i = 0; i < 5; i++) if ((top >>> i) & 1) checksum ^= BECH32_GENERATOR[i];
  }
  return checksum;
};

const hodlLnConvertBits = (bytes, from, to, pad) => {
  let accumulator = 0;
  let bits = 0;
  const out = [];
  const maxValue = (1 << to) - 1;
  for (const byte of bytes) {
    accumulator = (accumulator << from) | byte;
    bits += from;
    while (bits >= to) {
      bits -= to;
      out.push((accumulator >> bits) & maxValue);
    }
  }
  if (pad && bits > 0) out.push((accumulator << (to - bits)) & maxValue);
  return out;
};

const hodlLnBech32Encode = (hrp, data) => {
  const expanded = [];
  for (const char of hrp) expanded.push(char.charCodeAt(0) >> 5);
  expanded.push(0);
  for (const char of hrp) expanded.push(char.charCodeAt(0) & 31);
  const values = [...expanded, ...data, 0, 0, 0, 0, 0, 0];
  const mod = hodlLnBech32Polymod(values) ^ 1;
  const checksum = [];
  for (let i = 0; i < 6; i++) checksum.push((mod >>> (5 * (5 - i))) & 31);
  return `${hrp}1${[...data, ...checksum].map((value) => BECH32_CHARSET[value]).join("")}`;
};

const hodlLnP2wpkhAddress = (publicKey, hrp) => hodlLnBech32Encode(hrp, [0, ...hodlLnConvertBits(hodlHash160(publicKey), 8, 5, true)]);

// The BIP86 account xprv and the first ten native-segwit receive addresses.
// deriveClnNode returns the node id and the descriptors; the xprv and the
// addresses are derived here from the same seed, then every buffer is wiped.
const hodlLnDeriveClnAccount = (phrase, network) => {
  const params = Object.hasOwn(CLN_NETWORKS, network) ? CLN_NETWORKS[network] : null;
  if (!params) throw Object.assign(new Error("Unknown network."), { key: "Unknown network.", code: "hsm-secret-network" });
  const seed = mnemonicToSeedSync(phrase, "");
  let master = null;
  let account = null;
  let chain = null;
  try {
    master = HDKey.fromMasterSeed(seed, { private: params.private, public: params.public });
    account = master.derive("m/86'/0'/0'");
    const xprv = account.privateExtendedKey;
    chain = account.deriveChild(0);
    const addresses = [];
    for (let index = 0; index < 10; index++) {
      const child = chain.deriveChild(index);
      try {
        addresses.push(hodlLnP2wpkhAddress(child.publicKey, params.hrp));
      } finally {
        child.wipePrivateData();
      }
    }
    return { xprv, addresses };
  } finally {
    seed.fill(0);
    if (chain) chain.wipePrivateData();
    if (account) account.wipePrivateData();
    if (master) master.wipePrivateData();
  }
};

// ── One derivation: the public result, and the secrets that stay ────────────

// The CLN derive: the node id, descriptors and addresses are public; the
// BIP86 account xprv stays with the caller (the worker) until revealed.
const deriveClnHsm = (phrase, network) => {
  const derived = deriveClnNode(phrase, network);
  const account = hodlLnDeriveClnAccount(phrase, network);
  return {
    result: { format: "cln-hsm", network, path: "m/86'/0'/0'", nodePubKey: derived.nodeId, descriptors: derived.descriptors, xpub: derived.xpub, addresses: account.addresses },
    secret: { rootXprv: account.xprv },
  };
};

// One aezeed or LDK derivation: the public result the page shows, and the
// secrets that stay with whoever called this (the worker) until revealed.
export function deriveLightning({ format, words, passphrase = "", coinType = 0 }) {
  if (format === "aezeed") {
    const decoded = aezeedDecode(words, passphrase);
    try {
      if (!isKnownInternalVersion(decoded.internalVersion)) {
        throw Object.assign(new Error("Unsupported internal version"), {
          key: "This cipher seed uses internal (key-derivation) version {v}, which no current Lightning implementation understands. Refusing to derive from it.",
          vars: { v: decoded.internalVersion },
          code: "internal-version",
        });
      }
      const derived = deriveLndNode(decoded.entropy, coinType);
      return {
        result: { format, coinType, nodePubKey: derived.nodePubKey, path: derived.path, internalVersion: decoded.internalVersion, birthdayDays: decoded.birthdayDays, birthdayTimestamp: decoded.birthdayTimestamp },
        secret: { entropy: decoded.entropy, salt: decoded.salt, rootXprv: derived.rootXprv },
      };
    } catch (exception) {
      decoded.entropy.fill(0);
      decoded.salt.fill(0);
      throw exception;
    }
  }
  if (format !== "bip39") throw new Error("Unknown Lightning seed format.");
  const derived = deriveLdkNode(validateLnBip39(words), passphrase);
  return { result: { format: "bip39", nodePubKey: derived.nodePubKey, path: derived.path }, secret: { rootXprv: derived.rootXprv } };
}

// ── The key-worker protocol ─────────────────────────────────────────────────
// Shared by ln-worker.js (the shipped worker, where `post` is postMessage)
// and the in-process stand-in the Node tests run synchronously. The handler
// owns the secrets: the last derivation's entropy, salt and xprv, and the
// CLN mnemonic read from a chosen hsm_secret file. Replies carry the public
// result only, except a "revealed" answer, which carries the secret text on
// explicit request. Every refusal keeps the keyed error shape (message, key,
// vars, code) the page translates today.
export function createLnKeyHandler(post, { scrubWasm = () => {} } = {}) {
  let held = null; // the last derivation's secrets
  let hsmMnemonic = null; // the type-2 words read from a chosen hsm_secret file

  const drop = () => {
    if (held) {
      if (held.entropy) held.entropy.fill(0);
      if (held.salt) held.salt.fill(0);
      // The xprv and mnemonic strings are immutable JS values; dropping the
      // references is the best effort available.
    }
    held = null;
  };

  const fail = (run, request, exception) => post({
    type: "error",
    run,
    request,
    error: {
      message: exception instanceof Error ? exception.message : String(exception),
      key: exception && typeof exception.key === "string" ? exception.key : undefined,
      vars: exception && typeof exception.vars === "object" ? exception.vars : undefined,
      code: exception && typeof exception.code === "string" ? exception.code : undefined,
    },
  });

  return (data) => {
    if (!data || typeof data.type !== "string") return;
    if (data.type === "init") {
      // The bundle wrapper consumes the real init (it carries the module
      // bytes); the in-process stand-in gets it instead. Either way the
      // sender learns the handler is up.
      post({ type: "ready" });
      return;
    }
    if (data.type === "derive") {
      drop();
      try {
        let outcome;
        if (data.format === "cln-hsm") {
          const words = Array.isArray(data.words) ? data.words : [];
          // The last entry wins: typed words when there are any, else the
          // hsm_secret file the worker is holding.
          const phrase = words.length > 0 ? readClnMnemonic(String(data.text ?? "")) : hsmMnemonic;
          if (!phrase) {
            throw Object.assign(new Error("Type or paste the 12 words, or choose the hsm_secret file."), {
              key: "Type or paste the 12 words, or choose the hsm_secret file.",
              code: "hsm-secret-missing",
            });
          }
          outcome = deriveClnHsm(phrase, data.network);
        } else {
          outcome = deriveLightning(data);
        }
        held = outcome.secret;
        post({ type: "derived", run: data.run, request: "derive", result: outcome.result });
      } catch (exception) {
        drop();
        fail(data.run, "derive", exception);
      }
      return;
    }
    if (data.type === "reveal") {
      const secrets = held
        ? { entropyHex: held.entropy ? hex.encode(held.entropy) : null, saltHex: held.salt ? hex.encode(held.salt) : null, rootXprv: held.rootXprv ?? null }
        : null;
      post({ type: "revealed", run: data.run, request: "reveal", secrets });
      return;
    }
    if (data.type === "load-hsm") {
      // A new file replaces the old result's secrets and the old file's
      // words, whether it proves usable or not (the page clears either way).
      drop();
      hsmMnemonic = null;
      const bytes = data.bytes instanceof Uint8Array ? data.bytes : new Uint8Array(0);
      try {
        const type = detectHsmSecretType(bytes);
        if (type === HSM_SECRET_MNEMONIC_WITH_PASS) {
          throw Object.assign(new Error("This hsm_secret needs a passphrase; only type 2 (no passphrase) is supported."), {
            key: "This hsm_secret needs a passphrase; only type 2 (no passphrase) is supported.",
            code: "hsm-secret-passphrase",
          });
        }
        if (type === HSM_SECRET_PLAIN) {
          throw Object.assign(new Error("This is a legacy 32-byte hsm_secret, not a mnemonic secret."), {
            key: "This is a legacy 32-byte hsm_secret, not a mnemonic secret.",
            code: "hsm-secret-plain",
          });
        }
        if (type === HSM_SECRET_ENCRYPTED) {
          throw Object.assign(new Error("This encrypted legacy hsm_secret is not supported."), {
            key: "This encrypted legacy hsm_secret is not supported.",
            code: "hsm-secret-encrypted",
          });
        }
        if (type === HSM_SECRET_INVALID) {
          throw Object.assign(new Error("This hsm_secret is truncated."), {
            key: "This hsm_secret is truncated.",
            code: "hsm-secret-truncated",
          });
        }
        hsmMnemonic = readClnMnemonic(bytes);
        post({ type: "hsm-loaded", run: data.run, request: "load-hsm" });
      } catch (exception) {
        hsmMnemonic = null;
        fail(data.run, "load-hsm", exception);
      } finally {
        bytes.fill(0);
      }
      return;
    }
    if (data.type === "drop-hsm") {
      // Typing is the most recent entry: the held file's words go.
      hsmMnemonic = null;
      return;
    }
    if (data.type === "drop") {
      // A refused derive or file load wipes the last result's secrets, as the
      // page's own in-page refusal did. The held file's words survive a
      // derive refusal.
      drop();
      return;
    }
    if (data.type === "scrub") {
      // The page is about to terminate this worker: drop every held secret,
      // then overwrite this worker's own WebAssembly memory (scrubWasm is
      // retireWasm in the shipped worker; the in-process stand-in shares the
      // page's instance, so it passes nothing). Answer so the page can
      // terminate ahead of its bound.
      drop();
      hsmMnemonic = null;
      scrubWasm();
      post({ type: "scrubbed" });
    }
  };
}
