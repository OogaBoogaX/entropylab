// Mixing a Bitcoin Core wallet.dat's spend secrets with a dice/card
// transcript into fresh seed entropy (issue #552).
//
// Pure byte transformation: no DOM, no network, no randomness, and no curve
// math of its own — the caller injects the hash and the public-key helper.
// The wallet document is the one hodlCoreWallet.parseWalletDat returns.
//
// Contract: a secret is mixed only after it proves itself against its own
// record pubkey; an encrypted, watch-only, tampered or malformed file is
// refused with a stable code; and the file alone never produces a phrase,
// because the transcript must carry entropy of its own.

const utf8 = (text) => new TextEncoder().encode(text);

// Domain separation: the fingerprint and the mixed entropy are different
// hashes, and neither is sha256(transcript) — a dice-only phrase.
const FP_DOMAIN = "entropylab-core-mix-fp-v1";
const MIX_DOMAIN = "entropylab-core-mix-v1";

// 12, 15, 18, 21 and 24 words.
const ENTROPY_BYTES = [16, 20, 24, 28, 32];

// Bitcoin Core CPrivKey DER form: 3081d3 020101 0420 <32-byte secret> …
const DER_LENGTH = 214;

const bytesEqual = (a, b) =>
  a instanceof Uint8Array && b instanceof Uint8Array && a.length === b.length && a.every((byte, index) => byte === b[index]);

const compareBytes = (a, b) => {
  const length = Math.min(a.length, b.length);
  for (let index = 0; index < length; index++) if (a[index] !== b[index]) return a[index] - b[index];
  return a.length - b.length;
};

const concat = (...parts) => {
  const out = new Uint8Array(parts.reduce((total, part) => total + part.length, 0));
  let offset = 0;
  for (const part of parts) { out.set(part, offset); offset += part.length; }
  return out;
};

const toHex = (bytes) => [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");

// The 32-byte secret of a CPrivKey record, or null when the DER shape is not
// the one Core writes (the same check stationImports makes).
const derSecret = (der) => {
  if (!(der instanceof Uint8Array) || der.length !== DER_LENGTH) return null;
  if (der[0] !== 0x30 || der[6] !== 0x04 || der[7] !== 0x20) return null;
  return der.slice(8, 40);
};

// Every spend secret in the file, proven against its own record pubkey,
// de-duplicated and sorted so the result cannot depend on record order.
// deps = { publicKeyForPrivate, sha256 }.
const coreMixSecrets = (doc, deps) => {
  const records = [
    ...(Array.isArray(doc?.records) ? doc.records : []),
    ...(Array.isArray(doc?.others) ? doc.others : []),
  ];
  if (records.some((record) => record?.name === "walletdescriptorcryptedkey")) {
    throw new Error("encrypted: this wallet's private keys are encrypted, so its secrets cannot be read.");
  }

  const descriptors = Array.isArray(doc?.descriptors) ? doc.descriptors : [];
  const found = [];
  // A refusal part-way through must not leave the secrets already collected
  // behind in memory: wipe them before the error leaves.
  try {
    for (const entry of descriptors) {
      for (const keyRecord of Array.isArray(entry?.keys) ? entry.keys : []) {
        const secret = derSecret(keyRecord?.der);
        if (secret === null) {
          throw new Error("malformed-key: a walletdescriptorkey record is not the expected DER private key.");
        }
        let pubkey;
        try {
          pubkey = deps.publicKeyForPrivate(secret);
        } catch {
          secret.fill(0);
          throw new Error("key-mismatch: a key record's secret is not a valid secp256k1 private key.");
        }
        if (!bytesEqual(pubkey, keyRecord.pubkey)) {
          secret.fill(0);
          throw new Error("key-mismatch: a key record's secret does not match its record pubkey.");
        }
        found.push(secret);
      }
    }
  } catch (error) {
    wipeCoreMixSecrets(found);
    throw error;
  }
  if (!found.length) {
    throw new Error("watch-only: this wallet has no walletdescriptorkey record, so there is no secret to mix.");
  }

  found.sort(compareBytes);
  const secrets = [];
  for (const secret of found) {
    if (secrets.length && bytesEqual(secrets[secrets.length - 1], secret)) {
      secret.fill(0); // a duplicate copy, not the one kept
      continue;
    }
    secrets.push(secret);
  }

  const preimage = concat(utf8(FP_DOMAIN), Uint8Array.of(0), ...secrets);
  let digest = null;
  let fingerprint;
  try {
    digest = deps.sha256(preimage);
    fingerprint = toHex(digest.subarray(0, 4));
  } finally {
    preimage.fill(0);
    digest?.fill(0);
  }
  return { secrets, count: secrets.length, fingerprint };
};

// The first `entropyBytes` bytes of sha256(domain || 0x00 || secrets ||
// 0x00 || transcript). `secrets` must be the sorted, de-duplicated array
// coreMixSecrets returned; `transcript` is the exact string the dice or card
// method already hashes.
const coreMixEntropy = (secrets, transcript, entropyBytes, deps) => {
  if (typeof transcript !== "string" || transcript.trim() === "") {
    throw new Error("empty-transcript: the wallet alone must never produce a phrase; add dice or card entropy.");
  }
  if (!Array.isArray(secrets) || secrets.length === 0) {
    throw new Error("coreMixEntropy: at least one wallet secret is required.");
  }
  for (const secret of secrets) {
    if (!(secret instanceof Uint8Array) || secret.length !== 32) {
      throw new Error("coreMixEntropy: every secret must be a 32-byte Uint8Array.");
    }
  }
  if (!ENTROPY_BYTES.includes(entropyBytes)) {
    throw new Error("coreMixEntropy: entropyBytes must be 16, 20, 24, 28 or 32.");
  }

  const secretBytes = concat(...secrets);
  const transcriptBytes = utf8(transcript);
  let preimage = null;
  let digest = null;
  try {
    preimage = concat(utf8(MIX_DOMAIN), Uint8Array.of(0), secretBytes, Uint8Array.of(0), transcriptBytes);
    digest = deps.sha256(preimage);
    if (!(digest instanceof Uint8Array) || digest.length < entropyBytes) {
      throw new Error("coreMixEntropy: the hash returned fewer bytes than requested.");
    }
    // An explicit copy: Buffer.prototype.slice is a view, so a Buffer-returning
    // hash would otherwise hand back memory the finally block zeroes.
    const entropy = new Uint8Array(entropyBytes);
    entropy.set(digest.subarray(0, entropyBytes));
    return entropy;
  } finally {
    secretBytes.fill(0);
    transcriptBytes.fill(0);
    preimage?.fill(0);
    digest?.fill(0);
  }
};

const wipeCoreMixSecrets = (secrets) => {
  if (!Array.isArray(secrets)) return;
  for (const secret of secrets) {
    if (secret instanceof Uint8Array) secret.fill(0);
  }
};

export { coreMixSecrets, coreMixEntropy, wipeCoreMixSecrets };
