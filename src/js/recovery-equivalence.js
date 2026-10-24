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
//   in EntropyLab's other workspaces. Byte buffers (seed bytes, decoded
//   base58 payloads) are zeroed after use; JS strings (mnemonic, keys)
//   cannot be wiped and are best effort.
//
// Scope (v1): single-signature templates — pkh, wpkh, sh(wpkh), tr — with
// one extended public key, an optional [fingerprint/path] key origin, and a
// /0/*, /1/* or /<0;1>/* key path. tr() is key-path only: a script tree is
// outside scope. Multisig (wsh/multi/sortedmulti, Ypub/Zpub), miniscript,
// combo(), and raw-hex-key-only descriptors are reported UNSUPPORTED, not
// INVALID.

import { HDKey, HARDENED_OFFSET } from "./hdkey.js";
import { mnemonicToSeedSync, validateMnemonic } from "./bip39.js";
import { addressFor, descriptorDerive } from "./addresses.js";
import { base58checkDecode, base58checkEncode } from "./base58.js";
import { descriptorChecksum } from "./core-importdescriptors.js";

const BITCOIN_TESTNET_VERSIONS = { private: 0x04358394, public: 0x043587cf };

// SLIP-132 single-signature prefixes → the script type they claim. Uppercase
// Ypub/Zpub/Upub/Vpub are multisig and outside v1 scope.
const SLIP132_SCRIPT_TYPE = {
  zpub: "p2wpkh",
  ypub: "p2sh-p2wpkh",
  vpub: "p2wpkh",
  upub: "p2sh-p2wpkh",
};

// Version word for each recognized extended-public-key prefix. The version
// word is also the key's network claim: tpub/upub/vpub are testnet.
const EXTENDED_PUB_VERSIONS = {
  xpub: 0x0488b21e,
  ypub: 0x049d7cb2,
  zpub: 0x04b24746,
  tpub: 0x043587cf,
  upub: 0x044a5262,
  vpub: 0x045f1cf6,
};

const EXTENDED_PUB_RE =
  /(?:xpub|tpub|ypub|upub|zpub|vpub|Ypub|Zpub|Upub|Vpub)[1-9A-HJ-NP-Za-km-z]{90,}/g;
const ORIGIN_RE = /\[([0-9a-fA-F]{8})((?:\/[0-9]+['hH]?)*)\]/;

// Single-signature descriptor templates v1 understands, mapped to the script
// type addressFor() expects. sh(...) is only supported when it wraps wpkh.
const TEMPLATE_SCRIPT_TYPE = {
  pkh: "p2pkh",
  wpkh: "p2wpkh",
  "sh(wpkh)": "p2sh-p2wpkh",
  tr: "p2tr",
};

// A BIP-32 seed is 128 to 512 bits (16 to 64 bytes); anything else is not a
// seed this module can stand behind, however it was produced.
function hexSeedBytes(seedHex) {
  if (!/^[0-9a-fA-F]+$/.test(seedHex) || seedHex.length % 2 !== 0) return null;
  if (seedHex.length < 32 || seedHex.length > 128) return null;
  const out = new Uint8Array(seedHex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(seedHex.slice(2 * i, 2 * i + 2), 16);
  return out;
}

// Byte equality for the mnemonic-vs-seed check. Both buffers are the user's
// own material, so constant time is not required.
function bytesEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

// Normalize any extended public key to the Core form of its own network
// (xpub on mainnet, tpub on testnet) by swapping the 4-byte version word;
// the remaining 74 bytes are untouched. This is a pure re-encoding of the
// same key material — SLIP-132 changes presentation, not the key.
function toCoreExtendedPub(key, version) {
  let body;
  try {
    body = base58checkDecode(key);
  } catch {
    return null;
  }
  try {
    if (body.length !== 78) return null;
    if (body[45] === 0) return null; // never echo private material back out
    const view = new DataView(body.buffer, body.byteOffset);
    view.setUint32(0, version, false);
    return base58checkEncode(body);
  } catch {
    return null;
  } finally {
    body.fill(0);
  }
}

function networkOfPrefix(prefix) {
  return prefix === "tpub" || prefix === "upub" || prefix === "vpub" ? "testnet" : "mainnet";
}

// The Core version word for a key's own network: xpub on mainnet, tpub on
// testnet. SLIP-132 prefixes only change presentation, not the network.
function coreVersionFor(prefix) {
  return networkOfPrefix(prefix) === "testnet" ? BITCOIN_TESTNET_VERSIONS.public : 0x0488b21e;
}

function versionsForNetwork(network) {
  return network === "mainnet" ? undefined : BITCOIN_TESTNET_VERSIONS;
}

// bech32/bech32m addresses are case-insensitive (BIP-173: all-lower or
// all-upper; a mixed-case string is invalid); Base58 is case-sensitive and
// must match exactly.
function addressesEqual(a, b) {
  if (a === b) return true;
  const bech32 = /^(bc|tb|bcrt)1/i;
  const oneCase = (s) => s === s.toLowerCase() || s === s.toUpperCase();
  if (bech32.test(a) && bech32.test(b) && oneCase(a) && oneCase(b)) return a.toLowerCase() === b.toLowerCase();
  return false;
}

// The argument of the descriptor's single key function, e.g. the
// "[fpr/path]xpub/0/*" inside wpkh(...) or sh(wpkh(...)).
function keyArgumentOf(text, fn) {
  const marker = fn === "sh(wpkh)" ? "wpkh(" : fn + "(";
  const open = text.indexOf(marker);
  if (open < 0) return null;
  const start = open + marker.length;
  let depth = 1;
  for (let i = start; i < text.length; i++) {
    const ch = text[i];
    if (ch === "(") depth++;
    else if (ch === ")") {
      depth--;
      if (depth === 0) return text.slice(start, i);
    }
  }
  return null;
}

// v1 only understands an account-level origin: purpose'/coin'/account', all
// three hardened. Anything else is a named Support failure, not a guess.
function isAccountPath(path) {
  const match = /^\/(\d+)'\/(\d+)'\/(\d+)'$/.exec(path);
  if (!match) return false;
  return match.slice(1).every((n) => Number(n) <= 2147483647);
}

// Parse a single-signature descriptor into its claims. Returns { error } when
// the template, key shape, key path or origin is outside v1 scope; the caller
// turns that into a named Support failure. The checksum is verified whenever
// it is present; a descriptor without one is accepted and flagged
// checksumAbsent so the caller can surface it.
function parseDescriptorClaims(descriptor) {
  const text = String(descriptor ?? "").trim();
  const hash = text.lastIndexOf("#");
  let body = text;
  let checksumAbsent = false;
  if (hash >= 0) {
    const checksum = text.slice(hash + 1);
    body = text.slice(0, hash);
    let expected;
    try {
      expected = descriptorChecksum(body);
    } catch {
      return { error: "descriptor checksum could not be computed" };
    }
    if (checksum.length !== 8 || expected !== checksum) {
      return { error: "descriptor checksum does not match its body" };
    }
  } else {
    checksumAbsent = true;
  }
  // A descriptor never contains whitespace; "[origin] key" would otherwise
  // read as "[origin]key" (Muse, review of 57e9d37).
  if (/\s/.test(body)) return { error: "descriptor contains whitespace" };
  // Private extended keys are refused before anything else reads the text:
  // this module compares public material only (red-team on 57e9d37).
  if (/\b[xtyzuvYZUV]prv[1-9A-HJ-NP-Za-km-z]/.test(body)) {
    return { error: "descriptor carries a private key; only public descriptors are compared" };
  }
  const fnMatch = body.match(/^([a-z]+)\(/);
  if (!fnMatch) return { error: "descriptor template outside v1 scope (pkh/wpkh/sh(wpkh)/tr, single extended key)" };
  let fn = fnMatch[1];
  if (fn === "sh") {
    if (/^sh\(wpkh\(/.test(body)) fn = "sh(wpkh)";
    else return { error: "descriptor template outside v1 scope (pkh/wpkh/sh(wpkh)/tr, single extended key)" };
  }
  const scriptType = TEMPLATE_SCRIPT_TYPE[fn];
  if (!scriptType) return { error: "descriptor template outside v1 scope (pkh/wpkh/sh(wpkh)/tr, single extended key)" };

  const arg = keyArgumentOf(body, fn);
  if (arg == null) return { error: "descriptor key argument could not be read" };
  // The body must be exactly the template around its one argument: anything
  // after the closing parenthesis (a stray ",{...}" script tree, a second
  // expression) is refused, never read past.
  if (body !== (fn === "sh(wpkh)" ? `sh(wpkh(${arg}))` : `${fn}(${arg})`)) {
    return { error: "descriptor has text outside its single key expression" };
  }

  // tr() is single-key only in v1: a script tree (or any second argument)
  // is outside scope and must be refused, not silently ignored.
  if (fn === "tr" && /[,{]/.test(arg)) {
    return { error: "tr() with a script tree or extra arguments is outside v1 single-key scope" };
  }

  const keyMatches = arg.match(EXTENDED_PUB_RE) ?? [];
  if (keyMatches.length === 0) return { error: "descriptor key is not a single extended public key" };
  if (keyMatches.length > 1) return { error: "descriptor carries more than one extended key (single-sig v1 scope)" };
  const key = keyMatches[0];
  const prefix = key.slice(0, 4);
  if (/^[YZUV]pub$/.test(prefix)) {
    return { error: "multisig SLIP-132 (Ypub/Zpub/Upub/Vpub) is outside v1 single-sig scope" };
  }
  if (EXTENDED_PUB_VERSIONS[prefix] == null) return { error: "extended key prefix is not recognized" };
  const coreXpub = toCoreExtendedPub(key, coreVersionFor(prefix));
  if (!coreXpub) return { error: "descriptor key is not a recognized public extended key" };

  // The key path after the xpub selects the branch. v1 understands only the
  // receive branch (/0/*), the change branch (/1/*) and the multipath form
  // (/<0;1>/*); anything else is a named Support failure.
  const keyIndex = arg.indexOf(key);
  const afterKey = arg.slice(keyIndex + key.length);
  const branchMatch = /^\/(0|1)\/\*$/.exec(afterKey);
  const multiMatch = /^\/<0;1>\/\*$/.exec(afterKey);
  if (!branchMatch && !multiMatch) {
    return { error: "descriptor key path is not /0/*, /1/* or /<0;1>/*" };
  }
  const branch = branchMatch && branchMatch[1] === "1" ? 1 : 0;

  const originMatch = arg.match(ORIGIN_RE);
  let originFingerprint = null;
  let originPath = null;
  // BIP-380: at most one key origin, and only directly before the key. A
  // second "[...]" would otherwise be ignored (Muse, review of ff6854a).
  if ((arg.match(/\[/g) ?? []).length > 1 || (originMatch && originMatch.index !== 0)) {
    return { error: "descriptor key must have at most one origin, directly before the key" };
  }
  if (originMatch) {
    originFingerprint = originMatch[1].toLowerCase();
    // HDKey.derive wants 'h'/'H' normalized to "'".
    originPath = originMatch[2].replace(/[hH]/g, "'");
    if (!isAccountPath(originPath)) {
      return { error: "descriptor origin is not an account-level path (purpose'/coin'/account')" };
    }
  } else if (arg.includes("[")) {
    return { error: "descriptor origin could not be parsed" };
  }
  return {
    scriptType,
    coreXpub,
    keyPrefix: prefix,
    keyNetwork: networkOfPrefix(prefix),
    originFingerprint,
    originPath,
    branch,
    checksumAbsent,
  };
}

function stepOk(name) {
  return { name, ok: true };
}
function stepFail(name, detail) {
  return { name, ok: false, detail };
}
// Attach the descriptor checksum status to the result when a descriptor was
// supplied: "verified" when present and matching, "absent" when omitted.
function withChecksum(result, checksumStatus) {
  if (checksumStatus) result.checksum = checksumStatus;
  return result;
}

// Candidate account paths for a supplied key. With a descriptor origin the
// path is fixed; otherwise the SLIP-132 prefix names the purpose, and a plain
// xpub/tpub is tried at the four standard purposes on its own network.
function candidatePathsFor(keyClaim, descriptorClaims) {
  if (descriptorClaims?.originPath) return [descriptorClaims.originPath];
  const coin = keyClaim.network === "testnet" ? 1 : 0;
  // The account comes from the key itself (depth 3, hardened index), so an
  // account-1 key is compared at account 1, not assumed to be account 0.
  const account = keyClaim.account;
  const prefix = keyClaim.keyPrefix;
  if (prefix === "ypub" || prefix === "upub") return [`/49'/${coin}'/${account}'`];
  if (prefix === "zpub" || prefix === "vpub") return [`/84'/${coin}'/${account}'`];
  return [`/44'/${coin}'/${account}'`, `/49'/${coin}'/${account}'`, `/84'/${coin}'/${account}'`, `/86'/${coin}'/${account}'`];
}

// Account-level purpose → the script type its addresses use. Used to derive
// candidate addresses when no descriptor pins the template.
const PURPOSE_SCRIPT_TYPE = [
  { purpose: 44, scriptType: "p2pkh" },
  { purpose: 49, scriptType: "p2sh-p2wpkh" },
  { purpose: 84, scriptType: "p2wpkh" },
  { purpose: 86, scriptType: "p2tr" },
];

// Purposes implied by a key prefix: SLIP-132 names one, a plain xpub/tpub
// could be any of the four standard purposes.
function purposesForPrefix(prefix) {
  if (prefix === "ypub" || prefix === "upub") return PURPOSE_SCRIPT_TYPE.filter((p) => p.purpose === 49);
  if (prefix === "zpub" || prefix === "vpub") return PURPOSE_SCRIPT_TYPE.filter((p) => p.purpose === 84);
  return PURPOSE_SCRIPT_TYPE;
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
  // An unknown network or an invalid index is refused up front, before any
  // derivation, rather than failing (or being coerced) deep inside it.
  if (network !== "mainnet" && network !== "testnet") steps.push(stepFail("Support", 'network must be "mainnet" or "testnet"'));
  if (!Number.isSafeInteger(receiveIndex) || receiveIndex < 0 || receiveIndex > 2147483647) {
    steps.push(stepFail("Support", "receiveIndex must be a whole number from 0 to 2,147,483,647"));
  }
  if (steps.length) return { steps, verdict: "inconsistent", mismatchAt: "Support" };

  const supplied = {};
  for (const key of ["seed", "mnemonic", "xpub", "slip132", "descriptor", "address"]) {
    const value = artifacts?.[key];
    if (value == null) continue;
    if (typeof value !== "string") {
      // Never coerce: String() on a hostile object can throw, and a coerced
      // value is not what the user supplied. Fail closed with a named step.
      steps.push(stepFail("Support", `${key} must be a string`));
      continue;
    }
    if (value.trim() !== "") supplied[key] = value.trim();
  }
  // The BIP-39 passphrase is used exactly as given: spaces are part of it,
  // so it is never trimmed. It modifies the mnemonic, it is not an artifact.
  let passphrase = "";
  const rawPassphrase = artifacts?.passphrase;
  if (rawPassphrase != null) {
    if (typeof rawPassphrase !== "string") {
      steps.push(stepFail("Support", "passphrase must be a string"));
    } else {
      passphrase = rawPassphrase;
    }
  }
  // A passphrase only modifies a mnemonic. With no mnemonic it would be
  // silently ignored, so it is refused instead.
  if (passphrase !== "" && !supplied.mnemonic) {
    steps.push(stepFail("Support", "a passphrase applies only to a mnemonic, and none was supplied"));
  }
  // Too little to compare is "insufficient", unless something the user
  // supplied was refused: that is never softened to insufficient.
  if (Object.keys(supplied).length < 2) {
    if (steps.length) return { steps, verdict: "inconsistent", mismatchAt: "Support" };
    return { steps, verdict: "insufficient" };
  }

  // ---- Descriptor claims (parse once; several comparisons reuse them).
  let descriptorClaims = null;
  let descriptorAddress = null;
  let checksumStatus = null;
  if (supplied.descriptor) {
    let parsed;
    try {
      parsed = parseDescriptorClaims(supplied.descriptor);
    } catch {
      parsed = { error: "descriptor could not be parsed" };
    }
    if (parsed.error) {
      steps.push(stepFail("Support", parsed.error));
    } else {
      descriptorClaims = parsed;
      checksumStatus = parsed.checksumAbsent ? "absent" : "verified";
      // descriptorDerive refuses BIP-389 multipath (one call derives one
      // branch), so a /<0;1>/* descriptor is evaluated on its receive branch,
      // /0/*, matching descriptorClaims.branch. Its checksum was verified
      // above against the multipath text, so the single-path form drops it.
      const body = supplied.descriptor.split("#")[0];
      const derivable = body.includes("/<0;1>/*") ? body.replace("/<0;1>/*", "/0/*") : supplied.descriptor;
      try {
        descriptorAddress = descriptorDerive(derivable, receiveIndex, descriptorClaims.keyNetwork).address;
      } catch {
        steps.push(stepFail("Support", `descriptor does not derive at index ${receiveIndex}`));
        descriptorClaims = null;
      }
    }
  }

  // ---- Every supplied key becomes a claim, so none can be shadowed.
  const keyClaims = [];
  const addKeyClaim = (source, keyText) => {
    const prefix = keyText.slice(0, 4);
    if (/^[YZUV]pub$/.test(prefix)) {
      // Ypub/Zpub/Upub/Vpub are multisig SLIP-132 prefixes. v1 is single-sig
      // only; misinterpreting one as a single-sig key would be worse than
      // refusing it, so fail closed with a named step.
      steps.push(stepFail("Support", "multisig SLIP-132 (Ypub/Zpub/Upub/Vpub) is outside v1 single-sig scope"));
      return;
    }
    if (EXTENDED_PUB_VERSIONS[prefix] == null) {
      steps.push(stepFail("Support", `${source} is not a recognized public extended key`));
      return;
    }
    const keyNetwork = networkOfPrefix(prefix);
    const coreXpub = toCoreExtendedPub(keyText, coreVersionFor(prefix));
    if (!coreXpub) {
      steps.push(stepFail("Support", `${source} is not a recognized public extended key`));
      return;
    }
    let node;
    try {
      node = HDKey.fromExtendedKey(coreXpub, versionsForNetwork(keyNetwork));
    } catch {
      steps.push(stepFail("Support", `${source} does not parse`));
      return;
    }
    // An account-level key is depth 3 with a hardened child index; that
    // index is the account, so an account-1 key is compared at account 1.
    if (node.depth !== 3 || node.index < HARDENED_OFFSET) {
      steps.push(stepFail("Support", `${source} is not an account-level key (depth 3, hardened index)`));
      return;
    }
    // The prefix, not the field name, decides the script-type claim: a
    // SLIP-132 key keeps its claim whichever field it arrives in.
    const scriptTypeClaim = SLIP132_SCRIPT_TYPE[prefix] ?? null;
    keyClaims.push({ source, coreXpub, network: keyNetwork, keyPrefix: prefix, scriptTypeClaim, account: node.index - HARDENED_OFFSET });
  };

  if (supplied.xpub) addKeyClaim("xpub", supplied.xpub);
  if (supplied.slip132) addKeyClaim("slip132", supplied.slip132);
  if (descriptorClaims) {
    let node = null;
    try {
      node = HDKey.fromExtendedKey(descriptorClaims.coreXpub, versionsForNetwork(descriptorClaims.keyNetwork));
    } catch {
      node = null;
    }
    const accountLevel = node && node.depth === 3 && node.index >= HARDENED_OFFSET;
    // The origin is a claim about the key itself: its last step is the
    // account, so the key must be depth 3 at that hardened index. This needs
    // no seed, so an account-1 key labelled as account 0 is caught even when
    // only the descriptor and an address are supplied.
    if (descriptorClaims.originPath && node) {
      const originAccount = Number(/'\/(\d+)'$/.exec(descriptorClaims.originPath)?.[1]);
      if (node.depth !== 3 || node.index !== HARDENED_OFFSET + originAccount) {
        const where = node.index >= HARDENED_OFFSET ? `${node.index - HARDENED_OFFSET}'` : `${node.index}`;
        steps.push(stepFail("Origin", `descriptor key is at depth ${node.depth}, index ${where}; its origin claims m${descriptorClaims.originPath}`));
      }
    }
    if (!descriptorClaims.originPath && !accountLevel) {
      steps.push(stepFail("Support", "descriptor key is not an account-level key (depth 3, hardened index)"));
    } else {
      keyClaims.push({
        source: "descriptor",
        coreXpub: descriptorClaims.coreXpub,
        network: descriptorClaims.keyNetwork,
        keyPrefix: descriptorClaims.keyPrefix,
        scriptTypeClaim: SLIP132_SCRIPT_TYPE[descriptorClaims.keyPrefix] ?? null,
        account: accountLevel ? node.index - HARDENED_OFFSET : null,
      });
    }
  }

  // ---- Network enforcement: opts.network is the expected network. A key or
  // descriptor on another network is a mismatch, never a silent pass.
  for (const claim of keyClaims) {
    if (claim.network !== network) {
      steps.push(stepFail("Network", `${claim.source} is ${claim.network}, expected ${network}`));
    }
  }

  // ---- Seed / mnemonic side: master fingerprint + account key. The
  // descriptor's key network decides the version words, so a testnet
  // descriptor is compared against testnet-derived keys; with no descriptor
  // the first supplied key's network is used.
  const seedNetwork = descriptorClaims?.keyNetwork ?? keyClaims[0]?.network ?? network;
  const versions = versionsForNetwork(seedNetwork);
  const seedClaimsList = [];
  // Every node built from seed material holds a private key; wipe them all
  // before returning, on every path.
  const privateNodes = [];
  const trackPrivate = (node) => {
    if (node?.hasPrivateKey) privateNodes.push(node);
    return node;
  };
  const addSeedClaim = (source, master) => {
    const fingerprintHex = master.fingerprint.toString(16).padStart(8, "0");
    seedClaimsList.push({ source, master, fingerprintHex });
  };

  let mnemonicSeedBytes = null;
  if (supplied.mnemonic) {
    let valid = false;
    try {
      valid = validateMnemonic(supplied.mnemonic);
    } catch {
      valid = false;
    }
    if (!valid) {
      steps.push(stepFail("Support", "mnemonic fails BIP-39 checksum"));
    } else {
      let seedBytes = null;
      try {
        seedBytes = mnemonicToSeedSync(supplied.mnemonic, passphrase);
        mnemonicSeedBytes = Uint8Array.from(seedBytes);
        addSeedClaim("mnemonic", trackPrivate(HDKey.fromMasterSeed(seedBytes, versions)));
      } catch {
        steps.push(stepFail("Support", "mnemonic could not be derived"));
      } finally {
        if (seedBytes) seedBytes.fill(0);
      }
    }
  }
  if (supplied.seed) {
    const seedBytes = hexSeedBytes(supplied.seed);
    if (!seedBytes) {
      steps.push(stepFail("Support", "seed must be 16 to 64 bytes of hex (BIP-32)"));
    } else {
      try {
        // A mnemonic and a seed are the same kind of artifact: the seed must
        // be the BIP-39 seed of the mnemonic (with the supplied passphrase),
        // not merely a seed that happens to derive the same address.
        if (mnemonicSeedBytes) {
          if (bytesEqual(seedBytes, mnemonicSeedBytes)) steps.push(stepOk("Seed"));
          else steps.push(stepFail("Seed", "seed bytes do not match the BIP-39 seed of the mnemonic"));
        }
        addSeedClaim("seed", trackPrivate(HDKey.fromMasterSeed(seedBytes, versions)));
      } catch {
        steps.push(stepFail("Support", "seed could not be derived"));
      } finally {
        seedBytes.fill(0);
      }
    }
  }

  // ---- Pairwise key comparisons: every supplied key against every other.
  for (let i = 0; i < keyClaims.length; i++) {
    for (let j = i + 1; j < keyClaims.length; j++) {
      const a = keyClaims[i];
      const b = keyClaims[j];
      if (a.network !== b.network) {
        steps.push(stepFail("Network", `${a.source} is ${a.network}, ${b.source} is ${b.network}`));
      } else if (a.coreXpub !== b.coreXpub) {
        steps.push(stepFail("Account key", `${a.source} and ${b.source} derive different account keys`));
      } else {
        steps.push(stepOk("Account key"));
      }
    }
  }

  // ---- Seed vs key: derive the seed at the candidate paths for each key.
  // With a descriptor origin the path is fixed; otherwise the purpose comes
  // from the SLIP-132 prefix, and a plain xpub/tpub is tried at the four
  // standard purposes on its own network. The matched path is the detail.
  const descriptorKeyClaim = keyClaims.find((c) => c.source === "descriptor") ?? null;
  const seedAccounts = new Map();
  for (const seedClaim of seedClaimsList) {
    const perKey = new Map();
    seedAccounts.set(seedClaim, perKey);
    for (const keyClaim of keyClaims) {
      if (keyClaim.network !== seedNetwork) {
        steps.push(stepFail("Network", `${seedClaim.source} is ${seedNetwork}, ${keyClaim.source} is ${keyClaim.network}`));
        continue;
      }
      const candidates = candidatePathsFor(keyClaim, descriptorClaims);
      let matched = null;
      for (const path of candidates) {
        let account;
        try {
          account = trackPrivate(seedClaim.master.derive("m" + path));
        } catch {
          continue;
        }
        if (account.neutered().publicExtendedKey === keyClaim.coreXpub) {
          matched = { path, account };
          break;
        }
      }
      if (matched) {
        perKey.set(keyClaim, matched);
        steps.push({ name: "Account key", ok: true, detail: `matched m${matched.path}` });
      } else {
        steps.push(stepFail("Account key", `${seedClaim.source} does not derive ${keyClaim.source} at ${candidates.join(" or ")}`));
      }
    }
  }

  // The standard purpose (44/49/84/86) at which any seed derived this key,
  // or null when no seed matched it.
  const matchedPurposeOf = (keyClaim) => {
    for (const perKey of seedAccounts.values()) {
      const match = perKey.get(keyClaim);
      if (match) return Number(/^\/(\d+)'/.exec(match.path)?.[1]);
    }
    return null;
  };

  if (descriptorClaims?.originFingerprint) {
    for (const claim of seedClaimsList) {
      if (claim.fingerprintHex === descriptorClaims.originFingerprint) {
        steps.push(stepOk("Master fingerprint"));
      } else {
        steps.push(stepFail("Master fingerprint", `${claim.source} derives ${claim.fingerprintHex}, descriptor origin claims ${descriptorClaims.originFingerprint}`));
      }
    }
  }

  // ---- Script-type claims: each SLIP-132 prefix claims a script type, as
  // do the descriptor template and its origin purpose. Any disagreement is a
  // mismatch.
  const scriptClaims = [];
  for (const claim of keyClaims) {
    if (claim.scriptTypeClaim) scriptClaims.push({ source: claim.source, scriptType: claim.scriptTypeClaim });
  }
  if (descriptorClaims) scriptClaims.push({ source: "descriptor template", scriptType: descriptorClaims.scriptType });
  // A standard origin purpose claims one too: 49' is p2sh-p2wpkh, so a
  // wpkh() template under a 49' origin (a ypub imported as wpkh) restores
  // different addresses than the wallet used, and is a mismatch.
  if (descriptorClaims?.originPath) {
    const purpose = Number(/^\/(\d+)'/.exec(descriptorClaims.originPath)?.[1]);
    const standard = PURPOSE_SCRIPT_TYPE.find((p) => p.purpose === purpose);
    if (standard) scriptClaims.push({ source: `descriptor origin ${purpose}'`, scriptType: standard.scriptType });
  } else if (descriptorKeyClaim) {
    // With no origin, the purpose at which a seed derived the descriptor's
    // key is the same evidence: the 49' account key under wpkh() is the
    // same mismatch whether or not an origin says 49'.
    const standard = PURPOSE_SCRIPT_TYPE.find((p) => p.purpose === matchedPurposeOf(descriptorKeyClaim));
    if (standard) scriptClaims.push({ source: `seed match at ${standard.purpose}'`, scriptType: standard.scriptType });
  }
  for (let i = 0; i < scriptClaims.length; i++) {
    for (let j = i + 1; j < scriptClaims.length; j++) {
      if (scriptClaims[i].scriptType === scriptClaims[j].scriptType) {
        steps.push(stepOk("Script type"));
      } else {
        steps.push(stepFail("Script type", `${scriptClaims[i].source} claims ${scriptClaims[i].scriptType}, ${scriptClaims[j].source} claims ${scriptClaims[j].scriptType}`));
      }
    }
  }

  // Address comparisons: descriptor side and (when possible) seed side.
  if (supplied.address && descriptorAddress) {
    if (addressesEqual(supplied.address, descriptorAddress)) steps.push(stepOk("Receive address"));
    else steps.push(stepFail("Receive address", `descriptor derives ${descriptorAddress}, supplied ${supplied.address}`));
  } else if (descriptorAddress && descriptorClaims) {
    // Cross-check the seed against the descriptor at the receive index.
    // This catches path/script confusion (e.g. same key under pkh vs wpkh)
    // even when the account-key comparison happens to match. The descriptor's
    // key path selects the branch (receive 0 or change 1).
    for (const claim of seedClaimsList) {
      const perKey = seedAccounts.get(claim);
      const match = descriptorKeyClaim ? perKey.get(descriptorKeyClaim) : null;
      if (!match) continue; // Account key failure already reported
      let seedAddress = null;
      try {
        const child = trackPrivate(match.account.derive(`m/${descriptorClaims.branch}/${receiveIndex}`));
        seedAddress = addressFor(descriptorClaims.scriptType, child.publicKey, seedNetwork);
      } catch {
        steps.push(stepFail("Support", `seed side does not derive at index ${receiveIndex}`));
        continue;
      }
      if (addressesEqual(seedAddress, descriptorAddress)) steps.push(stepOk("Receive address"));
      else steps.push(stepFail("Receive address", `seed side derives ${seedAddress}, descriptor derives ${descriptorAddress}`));
    }
  } else if (supplied.address && !descriptorClaims) {
    // No descriptor: derive candidate addresses from every supplied key and
    // seed (receive and change chains, indexes 0-19) and look for the
    // supplied address. A supplied address is never ignored.
    const SCAN = 20;
    let matched = null;
    const tried = [];
    const scanAccount = (account, scriptType, claimNetwork, label) => {
      for (const branch of [0, 1]) {
        for (let i = 0; i < SCAN; i++) {
          let addr;
          try {
            const child = trackPrivate(account.derive(`m/${branch}/${i}`));
            addr = addressFor(scriptType, child.publicKey, claimNetwork);
          } catch {
            continue;
          }
          if (addressesEqual(addr, supplied.address)) {
            matched = `${label}/${branch}/${i}`;
            return true;
          }
        }
      }
      return false;
    };
    for (const keyClaim of keyClaims) {
      if (matched) break;
      let account;
      try {
        account = HDKey.fromExtendedKey(keyClaim.coreXpub, versionsForNetwork(keyClaim.network));
      } catch {
        continue;
      }
      // A seed that derived this key fixes its purpose, so a plain xpub of
      // the 84' account does not also "match" a p2pkh address of that key.
      const seedPurpose = matchedPurposeOf(keyClaim);
      const purposes = purposesForPrefix(keyClaim.keyPrefix).filter((p) => seedPurpose == null || p.purpose === seedPurpose);
      for (const { scriptType } of purposes) {
        tried.push(`${keyClaim.source} ${scriptType}`);
        if (scanAccount(account, scriptType, keyClaim.network, keyClaim.source)) break;
      }
    }
    // A supplied key decides where the address must be found: the seed-only
    // scan runs only when no key was supplied, so a zpub cannot be "rescued"
    // by an address that lives under a different purpose.
    if (keyClaims.length === 0) {
      for (const seedClaim of seedClaimsList) {
        if (matched) break;
        const coin = seedNetwork === "testnet" ? 1 : 0;
        for (const { purpose, scriptType } of PURPOSE_SCRIPT_TYPE) {
          let account;
          try {
            account = trackPrivate(seedClaim.master.derive(`m/${purpose}'/${coin}'/0'`));
          } catch {
            continue;
          }
          const label = `${seedClaim.source} m/${purpose}'/${coin}'/0'`;
          tried.push(label);
          if (scanAccount(account, scriptType, seedNetwork, label)) break;
        }
      }
    }
    if (matched) {
      steps.push({ name: "Receive address", ok: true, detail: `matched ${matched}` });
    } else if (tried.length > 0) {
      steps.push(stepFail("Receive address", `address not among the first 20 receive/change addresses of ${tried.join(", ")}`));
    }
  }

  // Every private node built from seed material is wiped before returning,
  // on every path.
  const finish = (result) => {
    for (const node of privateNodes) node.wipePrivateData();
    if (mnemonicSeedBytes) mnemonicSeedBytes.fill(0);
    return withChecksum(result, checksumStatus);
  };
  // A supplied artifact that could not be checked is never a pass.
  if (steps.some((s) => s.name === "Support" && !s.ok)) {
    return finish({ steps, verdict: "inconsistent", mismatchAt: "Support" });
  }
  const comparable = steps.filter((s) => s.name !== "Support");
  if (comparable.length === 0) {
    // Two+ artifacts were supplied but none share a checkable claim.
    return finish({ steps, verdict: "insufficient" });
  }
  const firstFailure = comparable.find((s) => !s.ok);
  if (firstFailure) {
    return finish({ steps, verdict: "inconsistent", mismatchAt: firstFailure.name });
  }
  return finish({ steps, verdict: "consistent" });
}

