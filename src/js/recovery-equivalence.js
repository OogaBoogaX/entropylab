// Wallet Recovery Equivalence Verification (issue #171).
//
// compareRecoveryArtifacts() answers one narrow question: do the supplied
// recovery artifacts (seed/mnemonic, xpub, SLIP-132 key, descriptor,
// address) describe the same key derivation and output policy?
//
// Security reasoning:
// - Verification only. Never generates entropy, never signs, never touches
//   the network. It composes the repo's existing, already-tested primitives
//   (HDKey, descriptorDerive, base58check, bip39) as black boxes and adds
//   no new cryptography.
// - Fail closed: unsupported descriptor templates, malformed keys, and
//   artifact subsets that share no checkable claim produce explicit
//   "insufficient" outcomes with a named failing step, never a silent pass.
// - A user pasting a seed here extends the same trust they already place
//   in EntropyLab's other workspaces; nothing new is persisted or exposed.
//
// Scope (v1): single-signature templates — pkh, wpkh, sh(wpkh), tr — with
// one extended public key and an optional [fingerprint/path] key origin.
// Multisig (wsh/multi/sortedmulti, Ypub/Zpub), miniscript, combo(), and
// raw-hex-key-only descriptors are reported UNSUPPORTED, not INVALID.

import { HDKey } from "./hdkey.js";
import { mnemonicToSeedSync, validateMnemonic } from "./bip39.js";
import { addressFor, descriptorDerive } from "./addresses.js";
import { base58checkDecode, base58checkEncode } from "./base58.js";

const BITCOIN_TESTNET_VERSIONS = { private: 0x04358394, public: 0x043587cf };

// SLIP-132 mainnet single-signature prefixes → the script type they claim.
// Multisig prefixes (Ypub/Zpub) and testnet slip prefixes are recognized for
// network labeling but carry no single-sig script-type claim in v1.
const SLIP132_SCRIPT_TYPE = { zpub: "p2wpkh", ypub: "p2sh-p2wpkh" };
const EXTENDED_PUB_RE =
  /(?:xpub|tpub|ypub|upub|zpub|vpub|Ypub|Zpub|Upub|Vpub)[1-9A-HJ-NP-Za-km-z]{90,}/;
const ORIGIN_RE = /\[([0-9a-fA-F]{8})((?:\/[0-9]+['hH]?)*)\]/;

// Single-signature descriptor templates v1 understands, mapped to the script
// type addressFor() expects. sh(...) is only supported when it wraps wpkh.
const TEMPLATE_SCRIPT_TYPE = {
  pkh: "p2pkh",
  wpkh: "p2wpkh",
  "sh(wpkh)": "p2sh-p2wpkh",
  tr: "p2tr",
};

function hexSeedBytes(seedHex) {
  if (!/^[0-9a-fA-F]+$/.test(seedHex) || seedHex.length % 2 !== 0) return null;
  const out = new Uint8Array(seedHex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(seedHex.slice(2 * i, 2 * i + 2), 16);
  return out;
}

// Normalize any extended public key to its Core form (xpub/tpub) by swapping
// the 4-byte version word; the remaining 74 bytes are untouched. This is a
// pure re-encoding of the same key material — SLIP-132 changes presentation,
// not the key.
function toCoreExtendedPub(key) {
  const prefix = key.slice(0, 4);
  const versions = /^[xyz]pub/i.test(key) && (prefix === "tpub" || /^[tuv]/i.test(prefix))
    ? BITCOIN_TESTNET_VERSIONS
    : null;
  const body = base58checkDecode(key);
  try {
    if (body.length !== 78) return null;
    const isPriv = body[45] === 0;
    if (isPriv) return null; // never echo private material back out
    const target = versions ? versions.public : 0x0488b21e;
    const view = new DataView(body.buffer, body.byteOffset);
    view.setUint32(0, target, false);
    return base58checkEncode(body);
  } finally {
    body.fill(0);
  }
}

function versionsForNetwork(network) {
  return network === "mainnet" ? undefined : BITCOIN_TESTNET_VERSIONS;
}

// Parse a single-signature descriptor into its claims. Returns null when the
// template or key shape is outside v1 scope (caller reports UNSUPPORTED).
function parseDescriptorClaims(descriptor) {
  const text = String(descriptor ?? "").trim().replace(/#[0-9a-z]{8}$/, "");
  const fnMatch = text.match(/^([a-z]+)\(/);
  if (!fnMatch) return null;
  let fn = fnMatch[1];
  if (fn === "sh") {
    if (/^sh\(wpkh\(/.test(text)) fn = "sh(wpkh)";
    else return null;
  }
  const scriptType = TEMPLATE_SCRIPT_TYPE[fn];
  if (!scriptType) return null;
  const keyMatch = text.match(EXTENDED_PUB_RE);
  const originMatch = text.match(ORIGIN_RE);
  return {
    scriptType,
    coreXpub: keyMatch ? toCoreExtendedPub(keyMatch[0]) : null,
    originFingerprint: originMatch ? originMatch[1].toLowerCase() : null,
    // HDKey.derive wants 'h'/'H' normalized to "'".
    originPath: originMatch ? originMatch[2].replace(/[hH]/g, "'") : null,
  };
}

function stepOk(name) {
  return { name, ok: true };
}
function stepFail(name, detail) {
  return { name, ok: false, detail };
}

// Derive the canonical claims a seed/mnemonic makes about a wallet, using the
// descriptor's origin path when one is available (otherwise BIP-84 account 0).
function claimsFromSeed(master, descriptorClaims) {
  const fingerprintHex = master.fingerprint.toString(16).padStart(8, "0");
  const path = descriptorClaims?.originPath ?? "/84'/0'/0'";
  const account = master.derive("m" + path);
  return { fingerprintHex, account };
}

/**
 * Compare two or more recovery artifacts and report whether they describe
 * the same key derivation and output policy.
 *
 * @param {object} artifacts - subset of { seed, mnemonic, xpub, slip132, descriptor, address }
 * @param {object} [opts] - { network = "mainnet", receiveIndex = 0 }
 * @returns {{ steps: Array<{name: string, ok: boolean, detail?: string}>,
 *             verdict: "consistent" | "inconsistent" | "insufficient",
 *             mismatchAt?: string }}
 */
export function compareRecoveryArtifacts(artifacts, opts) {
  const { network = "mainnet", receiveIndex = 0 } = opts ?? {};
  const steps = [];

  const supplied = {};
  for (const key of ["seed", "mnemonic", "xpub", "slip132", "descriptor", "address"]) {
    const value = artifacts?.[key];
    if (value != null && String(value).trim() !== "") supplied[key] = String(value).trim();
  }
  if (Object.keys(supplied).length < 2) {
    return { steps, verdict: "insufficient" };
  }

  const versions = versionsForNetwork(network);

  // ---- Descriptor claims (parse once; several comparisons reuse them).
  let descriptorClaims = null;
  let descriptorAddress = null;
  if (supplied.descriptor) {
    descriptorClaims = parseDescriptorClaims(supplied.descriptor);
    if (!descriptorClaims) {
      steps.push(stepFail("Support", "descriptor template outside v1 scope (pkh/wpkh/sh(wpkh)/tr, single extended key)"));
    } else {
      try {
        descriptorAddress = descriptorDerive(supplied.descriptor, receiveIndex, network).address;
      } catch (err) {
        steps.push(stepFail("Support", `descriptor does not derive at index ${receiveIndex}: ${err.message}`));
        descriptorClaims = null;
      }
    }
  }

  // ---- User-supplied extended key (xpub or SLIP-132), normalized to Core.
  let userCoreXpub = null;
  let slip132ClaimedType = null;
  const userKeyText = supplied.xpub ?? supplied.slip132;
  if (userKeyText && /^[YZUV]pub/.test(userKeyText)) {
    // Ypub/Zpub/Upub/Vpub are multisig SLIP-132 prefixes. v1 is single-sig
    // only; misinterpreting one as a single-sig key would be worse than
    // refusing it, so fail closed with a named step.
    steps.push(stepFail("Support", "multisig SLIP-132 (Ypub/Zpub/Upub/Vpub) is outside v1 single-sig scope"));
  } else if (userKeyText) {
    if (supplied.slip132) slip132ClaimedType = SLIP132_SCRIPT_TYPE[supplied.slip132.slice(0, 4)] ?? null;
    userCoreXpub = toCoreExtendedPub(userKeyText);
    if (!userCoreXpub) {
      steps.push(stepFail("Support", "extended key is not a recognized public extended key"));
    } else {
      try {
        HDKey.fromExtendedKey(userCoreXpub, versions);
      } catch (err) {
        steps.push(stepFail("Support", `extended key does not parse: ${err.message}`));
        userCoreXpub = null;
      }
    }
  }

  // ---- Seed / mnemonic side: master fingerprint + account key.
  let seedClaims = null;
  const mnemonic = supplied.mnemonic;
  if (mnemonic) {
    if (!validateMnemonic(mnemonic)) {
      steps.push(stepFail("Support", "mnemonic fails BIP-39 checksum"));
    } else {
      const seedBytes = mnemonicToSeedSync(mnemonic);
      try {
        seedClaims = claimsFromSeed(HDKey.fromMasterSeed(seedBytes, versions), descriptorClaims);
      } finally {
        seedBytes.fill(0);
      }
    }
  } else if (supplied.seed) {
    const seedBytes = hexSeedBytes(supplied.seed);
    if (!seedBytes) {
      steps.push(stepFail("Support", "seed must be lowercase/uppercase hex, even length"));
    } else {
      try {
        seedClaims = claimsFromSeed(HDKey.fromMasterSeed(seedBytes, versions), descriptorClaims);
      } finally {
        seedBytes.fill(0);
      }
    }
  }

  // ---- Pairwise comparisons. A step is only emitted when a real check ran.
  if (seedClaims && descriptorClaims?.originFingerprint) {
    if (seedClaims.fingerprintHex === descriptorClaims.originFingerprint) {
      steps.push(stepOk("Master fingerprint"));
    } else {
      steps.push(stepFail("Master fingerprint", `seed derives ${seedClaims.fingerprintHex}, descriptor origin claims ${descriptorClaims.originFingerprint}`));
    }
  }

  const descriptorCoreXpub = descriptorClaims?.coreXpub ?? null;
  if (seedClaims && descriptorCoreXpub) {
    const derived = seedClaims.account.neutered().publicExtendedKey;
    if (derived === descriptorCoreXpub) steps.push(stepOk("Account key"));
    else steps.push(stepFail("Account key", "seed-derived account xpub differs from the descriptor's key"));
  } else if (userCoreXpub && descriptorCoreXpub) {
    if (userCoreXpub === descriptorCoreXpub) steps.push(stepOk("Account key"));
    else steps.push(stepFail("Account key", "supplied extended key differs from the descriptor's key"));
  }

  if (slip132ClaimedType && descriptorClaims) {
    if (slip132ClaimedType === descriptorClaims.scriptType) {
      steps.push(stepOk("Script type"));
    } else {
      steps.push(stepFail("Script type", `SLIP-132 prefix claims ${slip132ClaimedType}, descriptor is ${descriptorClaims.scriptType}`));
    }
  }

  // Address comparisons: descriptor side and (when possible) seed side.
  if (supplied.address && descriptorAddress) {
    if (supplied.address === descriptorAddress) steps.push(stepOk("Receive address"));
    else steps.push(stepFail("Receive address", `descriptor derives ${descriptorAddress}, supplied ${supplied.address}`));
  } else if (seedClaims && descriptorAddress && descriptorClaims) {
    // Cross-check the seed against the descriptor at the receive index.
    // This catches path/script confusion (e.g. same key under pkh vs wpkh)
    // even when the account-key comparison happens to match.
    const child = seedClaims.account.derive(`m/0/${receiveIndex}`);
    const seedAddress = addressFor(descriptorClaims.scriptType, child.publicKey, network);
    if (seedAddress === descriptorAddress) steps.push(stepOk("Receive address"));
    else steps.push(stepFail("Receive address", `seed side derives ${seedAddress}, descriptor derives ${descriptorAddress}`));
  }

  const comparable = steps.filter((s) => s.name !== "Support");
  if (comparable.length === 0) {
    // Two+ artifacts were supplied but none share a checkable claim.
    return { steps, verdict: "insufficient" };
  }
  const firstFailure = comparable.find((s) => !s.ok);
  if (firstFailure) {
    return { steps, verdict: "inconsistent", mismatchAt: firstFailure.name };
  }
  return { steps, verdict: "consistent" };
}

