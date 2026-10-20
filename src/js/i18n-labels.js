// Translatable label tables for the enum-indexed families: strings that a
// call site selects by value (`t(hodlKeyModeLabels[mode])`) and therefore
// cannot write as an English literal. The values here ARE the English source
// text; scripts/i18n-sync.mjs flattens this module into the extracted source
// set, so the locale catalogs translate them content-keyed like any prose.
// Plain prose does not belong here — write it inline and call t("…").

// Key Station method picker (hodlKeyModes indexes these).
export const hodlKeyModeLabels = Object.freeze({
  dice: "Dice rolls",
  cards: "Cards",
  hex: "Number bases",
  seed: "Seed phrase",
  key: "Private key",
});

// MS Station co-signer derivation specs (app.js's hodlMsigSpecs indexes these).
export const hodlMsigSpecLabels = Object.freeze({
  bip48: "BIP48 multisig",
  bip87: "BIP87 multisig",
  bip45: "BIP45 multisig",
  bip44: "BIP44 account key",
  bip49: "BIP49 account key",
  bip84: "BIP84 account key",
  bip86: "BIP86 account key",
  custom: "Custom",
});

// Header network picker (Bitcoin Core's four networks).
export const hodlNetworkNames = Object.freeze({
  mainnet: "Bitcoin",
  testnet: "Testnet",
  signet: "Signet",
  regtest: "Regtest",
});

// Number-bases entropy formats. app.js's hodlEntropyFormats spreads these into
// its per-format records next to the non-translatable alphabet machinery.
export const hodlHexFormatLabels = Object.freeze({
  bin: Object.freeze({
    label: "Binary (Base 2)",
    shortLabel: "Binary",
    unit: "binary digits",
    desc: "Use one 0 or 1 for each coin flip.",
    detail: "Each digit contributes one bit; spaces are added every 11 bits.",
  }),
  base4: Object.freeze({
    label: "Quaternary (Base 4)",
    shortLabel: "Quaternary",
    unit: "quaternary digits",
    desc: "Each digit contributes exactly two bits; useful with a fair four-sided source.",
  }),
  base8: Object.freeze({
    label: "Octal (Base 8)",
    shortLabel: "Octal",
    unit: "octal digits",
    desc: "Each octal digit contributes three bits.",
  }),
  hex: Object.freeze({
    label: "Hexadecimal (Base 16)",
    shortLabel: "Hexadecimal",
    unit: "hexadecimal characters",
    desc: "Each hexadecimal character contributes four bits.",
  }),
  base32: Object.freeze({
    label: "Base32 (Bech32)",
    shortLabel: "Bech32",
    unit: "Bech32 characters",
    desc: "Uses the lowercase Bech32 data-character alphabet without an HRP or checksum; a restricted final character carries any remaining bits.",
    detail: "Each character contributes five bits.",
  }),
  base64: Object.freeze({
    label: "Base64 (RFC 4648 alphabet)",
    shortLabel: "Base64",
    unit: "characters",
    desc: "Uses the case-sensitive RFC 4648 alphabet with + and /, then switches to coin flips for any remaining bits.",
    detail: "Each character contributes six bits.",
  }),
});

// Beginner explanations for the four single-key script types; app.js's
// hodlScriptTypes references them next to the derivation constants.
export const hodlScriptBeginnerTexts = Object.freeze({
  bip44: "Addresses that start with 1. Oldest type. Bitcoin Core can import these with importprivkey.",
  bip49: "Addresses that start with 3. A SegWit script wrapped so older wallets can still send to it.",
  bip84: "Addresses that start with bc1q. The default in Bitcoin Core, Sparrow, and Electrum today.",
  bip86: "Addresses that start with bc1p. Newest type. Use this if your wallet speaks Taproot.",
});

// Pearson frequency-test labels, not certifications of randomness or entropy.
// The internal hodlDiceFairnessVerdict ids remain stable.
export const hodlFairnessVerdictLabels = Object.freeze({
  "need-more": "Need more rolls",
  fair: "No frequency warning",
  unsure: "Borderline frequency result",
  biased: "Frequency imbalance warning",
});

// The Key Station summary line's variant, by mode and sub-method (app.js's
// hodlKeySummaryMethodParts indexes these; the mode itself is hodlKeyModeLabels).
export const hodlKeySummarySubmethodLabels = Object.freeze({
  dice: Object.freeze({
    coldcard: "Base 10 [1-6] / Hashed rolls",
    coleman: "Base 6 [0-5] / Hashed rolls",
    bitbox: "BitBox diceware / Direct word selection",
    dplus: "D++ / Direct word selection",
  }),
  cards: Object.freeze({ direct: "Direct word selection", hashed: "Hashed card transcript" }),
  hex: Object.freeze({
    bin: "Binary (Base 2)",
    base4: "Quaternary (Base 4)",
    base8: "Octal (Base 8)",
    hex: "Hexadecimal (Base 16)",
    base32: "Base32 (Bech32)",
    base64: "Base64 (RFC 4648 alphabet)",
  }),
  seed: Object.freeze({ numbers: "BIP39 word numbers", words: "Direct word entry" }),
  key: Object.freeze({ wif: "WIF", "hex-key": "Private key hex", minikey: "Mini key", brain: "Brain wallet" }),
});
