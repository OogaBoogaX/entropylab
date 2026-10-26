// BIP39 mnemonic operations for EntropyLab, backed by the rust-bip39 crate
// compiled to WebAssembly (Rust crate in entropylab-wasm/, loaded by
// entropylab-wasm.js). English only.
//
// Drop-in replacement for the slice of @scure/bip39 the app uses:
// entropyToMnemonic, mnemonicToEntropy, validateMnemonic, mnemonicToSeedSync.
// NFKD normalization happens here in JS (String.normalize), exactly as the
// previous implementation did it; the crate parses already-normalized text.
// The English wordlist itself stays JS-side (bip39-english.js) because the UI
// reads it directly; a test proves it identical to the crate's list.
import { wasmExports as wasm, withInput, withOutput } from "./entropylab-wasm.js";
import { pbkdf2Sha512, sha256 } from "./hashes.js";
import { wordlist as bip39English } from "./bip39-english.js";

export { bip39English };

const textEncoder = new TextEncoder();
// ignoreBOM: a leading U+FEFF is passphrase content (NFKD keeps it, BIP39
// hashes it), not an encoding signature to drop — the salt from passphrase
// bytes in saltFor must equal the salt from the same passphrase as text.
// entropyToMnemonic's decode is unaffected: its words are plain ASCII.
const textDecoder = new TextDecoder("utf-8", { ignoreBOM: true });
const strictTextDecoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

const PHRASE_CAP = 1024; // a 24-word phrase is at most ~250 bytes
const ENTROPY_CAP = 64; // BIP39 entropy is 16..32 bytes

const nfkd = (value) => {
  if (typeof value !== "string") throw new TypeError("invalid mnemonic type: " + typeof value);
  return value.normalize("NFKD");
};

const isWellFormed = (value) => {
  for (const char of value) {
    const point = char.codePointAt(0);
    if (point >= 0xd800 && point <= 0xdfff) return false;
  }
  return true;
};

// @scure/bip39 split the NFKD phrase on a single ASCII space and required
// 12/15/18/21/24 words; rust-bip39 splits on any run of whitespace, so it
// would accept double spaces, tabs, newlines, and surrounding blanks. Those
// phrases are not a drop-in equivalent: mnemonicToSeedSync hashes the phrase
// as typed, so accepting one here would report "valid" for a phrase whose
// seed no other wallet derives. Reject them the way the previous
// implementation did, before the crate ever sees the text.
//
// A word-count check alone is not enough: "word\t word" is twelve pieces when
// split on " " but twelve clean words when split on whitespace runs, so the
// crate would accept a phrase the count admits. Equivalent acceptance means
// the two tokenizations agree, which holds exactly when every separator is a
// single ASCII space and no token carries whitespace of its own.
//
// JavaScript's \s is not Unicode's White_Space set: it leaves out U+0085
// (NEL), which rust-bip39 splits on. With \S alone, "word\u0085word" was one
// token here and two words in the crate, so twelve tokens validated as a
// fifteen-word phrase whose seed no other wallet derives (deep sweep of
// cb18b09).
const WORD_COUNTS = [12, 15, 18, 21, 24];
const SINGLE_ASCII_SPACES = /^[^\s\u0085]+( [^\s\u0085]+)*$/;
const isCanonicalPhrase = (phrase) => SINGLE_ASCII_SPACES.test(phrase) && WORD_COUNTS.includes(phrase.split(" ").length);

const entropyToMnemonic = (entropy, wordlist = bip39English) => {
  if (!(entropy instanceof Uint8Array) || ![16, 20, 24, 28, 32].includes(entropy.length)) {
    throw new RangeError("invalid entropy length");
  }
  if (wordlist !== bip39English) throw new Error("Only the BIP39 English wordlist is supported.");
  const out = withInput(entropy, (p) => withOutput(PHRASE_CAP, (o) => wasm().el_bip39_entropy_to_mnemonic(p, entropy.length, o, PHRASE_CAP)));
  if (!out) throw new Error("BIP39 mnemonic encoding failed.");
  // `out` is the seed phrase itself. The string is the result; the bytes are
  // a second copy of the secret and are erased here (RT-JSBOUNDARY-1).
  try {
    return textDecoder.decode(out);
  } finally {
    out.fill(0);
  }
};

const mnemonicToEntropy = (mnemonic, wordlist = bip39English) => {
  if (wordlist !== bip39English) throw new Error("Only the BIP39 English wordlist is supported.");
  const text = nfkd(mnemonic);
  if (!isCanonicalPhrase(text)) throw new Error("Invalid mnemonic");
  const phrase = textEncoder.encode(text);
  try {
    const out = withInput(phrase, (p) => withOutput(ENTROPY_CAP, (o) => wasm().el_bip39_mnemonic_to_entropy(p, phrase.length, o, ENTROPY_CAP)));
    if (!out) throw new Error("Invalid mnemonic");
    return out;
  } finally {
    phrase.fill(0); // the encoded mnemonic is secret
  }
};

const validateMnemonic = (mnemonic, wordlist = bip39English) => {
  if (wordlist !== bip39English) return false;
  try {
    const text = nfkd(mnemonic);
    if (!isCanonicalPhrase(text)) return false;
    const phrase = textEncoder.encode(text);
    try {
      return withInput(phrase, (p) => wasm().el_bip39_validate(p, phrase.length)) === 1;
    } finally {
      phrase.fill(0);
    }
  } catch {
    return false;
  }
};

// The salt, NFKD("mnemonic" + passphrase) as UTF-8. The passphrase may come
// as UTF-8 bytes (the passphrase vault): ASCII is its own NFKD, so it joins
// the salt as bytes and never becomes a string; anything else is decoded
// once for its normalization.
const MNEMONIC_SALT = textEncoder.encode("mnemonic");
const saltFor = (passphrase) => {
  // undefined means the caller omitted the argument: BIP39 says that is the
  // empty passphrase. null is never passed by the app (all call sites pass
  // strings or bytes), so a null can only be a caller bug (e.g. a missing
  // config value). Silently deriving the no-passphrase wallet would remove
  // the user's passphrase protection without a word. Throw instead.
  if (passphrase === undefined) passphrase = "";
  if (passphrase === null) throw new TypeError("Invalid passphrase");
  if (passphrase instanceof Uint8Array) {
    if (passphrase.every((byte) => byte < 0x80)) {
      const salt = new Uint8Array(MNEMONIC_SALT.length + passphrase.length);
      salt.set(MNEMONIC_SALT);
      salt.set(passphrase, MNEMONIC_SALT.length);
      return salt;
    }
    let text;
    try {
      text = strictTextDecoder.decode(passphrase);
    } catch {
      throw new Error("Invalid passphrase");
    }
    return textEncoder.encode(nfkd("mnemonic" + text));
  }
  // Check the same string "mnemonic" + passphrase hashes: "" + passphrase
  // coerces exactly as that concatenation does (a String object becomes its
  // value, a Symbol still throws), where String() would differ.
  passphrase = "" + passphrase;
  if (!isWellFormed(passphrase)) throw new Error("Invalid passphrase");
  return textEncoder.encode(nfkd("mnemonic" + passphrase));
};

// PBKDF2-HMAC-SHA512(NFKD(mnemonic), NFKD("mnemonic" + passphrase), 2048, 64).
const mnemonicToSeedSync = (mnemonic, passphrase = "") => {
  // The reference refuses a phrase that is not 12/15/18/21/24 words or not
  // well-formed Unicode; hashing whatever string arrives would turn a typo
  // into a valid-looking wallet.
  // The module's own isWellFormed, as for the passphrase: the native method is
  // missing on older engines, where a feature test would skip the refusal.
  if (typeof mnemonic !== "string" || !isWellFormed(mnemonic)) throw new Error("Invalid mnemonic");
  const text = nfkd(mnemonic);
  if (!isCanonicalPhrase(text)) throw new Error("Invalid mnemonic");
  const salt = saltFor(passphrase);
  let phrase = new Uint8Array(0);
  try {
    phrase = textEncoder.encode(text);
    return pbkdf2Sha512(phrase, salt, 2048, 64);
  } finally {
    // The encoded phrase and the passphrase-bearing salt are secret; the
    // 64-byte seed is the caller's to keep or wipe. The salt is wiped even if
    // encoding the phrase throws.
    phrase.fill(0);
    salt.fill(0);
  }
};

// Byte-based seed derivation: the BIP39 seed without ever building the
// phrase as a JavaScript string (strings cannot be zeroed). The canonical
// English mnemonic is pure ASCII, so it is its own NFKD form and needs no
// normalization; the passphrase is handled exactly as in mnemonicToSeedSync,
// through saltFor. The wordlist's own entries are the only word strings.
const encodedWords = bip39English.map((word) => textEncoder.encode(word));

// The 11-bit groups over the entropy plus its SHA-256 checksum bits.
const indicesFromEntropy = (entropy) => {
  const checksum = sha256(entropy);
  try {
    const entropyBits = entropy.length * 8;
    const indices = new Uint16Array((entropyBits + entropyBits / 32) / 11);
    for (let i = 0; i < indices.length; i++) {
      let value = 0;
      for (let j = 0; j < 11; j++) {
        const position = i * 11 + j;
        const byte = position < entropyBits ? entropy[position >> 3] : checksum[(position - entropyBits) >> 3];
        value = (value << 1) | ((byte >> (7 - (position & 7))) & 1);
      }
      indices[i] = value;
    }
    return indices;
  } finally {
    checksum.fill(0);
  }
};

// The entropy carried by the leading whole bits of the 11-bit groups.
const entropyFromIndices = (indices) => {
  const entropy = new Uint8Array((indices.length / 3) * 4);
  for (let i = 0; i < entropy.length * 8; i++) {
    if ((indices[(i / 11) | 0] >> (10 - (i % 11))) & 1) entropy[i >> 3] |= 0x80 >> (i & 7);
  }
  return entropy;
};

// The trailing bits of the groups must equal the top bits of SHA-256(entropy),
// exactly as mnemonicToEntropy's round trip through the crate requires.
const validChecksum = (indices, entropy) => {
  const checksum = sha256(entropy);
  try {
    const entropyBits = entropy.length * 8;
    for (let j = 0; j < indices.length / 3; j++) {
      const position = entropyBits + j;
      const actual = (indices[(position / 11) | 0] >> (10 - (position % 11))) & 1;
      if (actual !== ((checksum[j >> 3] >> (7 - (j & 7))) & 1)) return false;
    }
    return true;
  } finally {
    checksum.fill(0);
  }
};

// The mnemonic's UTF-8 bytes: each word's ASCII bytes, one 0x20 between words.
const phraseBytesFromIndices = (indices) => {
  let length = indices.length - 1;
  for (const index of indices) length += encodedWords[index].length;
  const phrase = new Uint8Array(length);
  let offset = 0;
  for (let i = 0; i < indices.length; i++) {
    if (i > 0) phrase[offset++] = 0x20;
    phrase.set(encodedWords[indices[i]], offset);
    offset += encodedWords[indices[i]].length;
  }
  return phrase;
};

// PBKDF2-HMAC-SHA512(phrase bytes, saltFor(passphrase), 2048, 64), with the
// phrase bytes, the indices copy and the salt zeroed in finally, as
// mnemonicToSeedSync does. Every secret copy is made inside the try, so a
// passphrase saltFor refuses still leaves nothing behind.
const seedFromEntropy = (entropy, passphrase = "") => {
  if (!(entropy instanceof Uint8Array) || ![16, 20, 24, 28, 32].includes(entropy.length)) {
    throw new RangeError("invalid entropy length");
  }
  let indices = new Uint16Array(0), salt = new Uint8Array(0), phrase = new Uint8Array(0);
  try {
    indices = indicesFromEntropy(entropy);
    salt = saltFor(passphrase);
    phrase = phraseBytesFromIndices(indices);
    return pbkdf2Sha512(phrase, salt, 2048, 64);
  } finally {
    phrase.fill(0);
    salt.fill(0);
    indices.fill(0);
  }
};

const seedFromIndices = (indices, passphrase = "") => {
  if (!(indices instanceof Uint16Array) || !WORD_COUNTS.includes(indices.length)) throw new Error("Invalid mnemonic");
  let owned = new Uint16Array(0), salt = new Uint8Array(0), phrase = new Uint8Array(0), entropy = new Uint8Array(0);
  try {
    owned = Uint16Array.from(indices);
    salt = saltFor(passphrase);
    for (const index of owned) if (index > 2047) throw new Error("Invalid mnemonic");
    entropy = entropyFromIndices(owned);
    if (!validChecksum(owned, entropy)) throw new Error("Invalid mnemonic");
    phrase = phraseBytesFromIndices(owned);
    return pbkdf2Sha512(phrase, salt, 2048, 64);
  } finally {
    phrase.fill(0);
    salt.fill(0);
    entropy.fill(0);
    owned.fill(0);
  }
};

export { entropyToMnemonic, mnemonicToEntropy, mnemonicToSeedSync, seedFromEntropy, seedFromIndices, validateMnemonic };
