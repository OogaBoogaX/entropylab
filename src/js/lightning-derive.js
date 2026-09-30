// Lightning node identity derivations, DOM-free: what the Lightning tool's
// key worker (ln-worker.js) runs, and what test/lightning.test.mjs checks
// against @scure. lightning.js re-exports the public pieces.
//
// Two seed schemes, two derivations:
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
// Deterministic transformations of user input only: nothing here generates
// entropy.
import { HDKey, HARDENED_OFFSET } from "./hdkey.js";
import { mnemonicToSeedSync, validateMnemonic } from "./bip39.js";
import { aezeedDecode } from "./aezeed.js";
import { wordlist as bip39English } from "./bip39-english.js";
import { hex } from "./coders.js";

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

// LDK (ldk-node): BIP39 seed -> master xprv -> its raw private key re-seeds
// a second master -> node secret at m/0'. The root xprv returned is the
// first-stage master (the on-chain wallet root ldk-node uses).
export const deriveLdkNode = (mnemonic, passphrase = "") => {
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

// One derivation for the key worker: the public result the page shows, and
// the secrets that stay with whoever called this (the worker) until revealed.
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
  const derived = deriveLdkNode(validateLnBip39(words), passphrase);
  return { result: { format: "bip39", nodePubKey: derived.nodePubKey, path: derived.path }, secret: { rootXprv: derived.rootXprv } };
}
