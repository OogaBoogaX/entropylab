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
  }),
  base4: Object.freeze({
    label: "Base 4",
    shortLabel: "Base 4",
    unit: "base-4 digits",
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
    label: "Crockford Base32",
    shortLabel: "Base32",
    unit: "characters",
    desc: "Uses the unambiguous Crockford alphabet, then switches to coin flips for any remaining bits; O becomes 0 and I or L becomes 1.",
  }),
  base64: Object.freeze({
    label: "Base64 (RFC 4648 alphabet)",
    shortLabel: "Base64",
    unit: "characters",
    desc: "Uses the case-sensitive RFC 4648 alphabet with + and /, then switches to coin flips for any remaining bits.",
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

// Pearson chi-squared fairness verdicts (hodlDiceFairnessVerdict ids).
export const hodlFairnessVerdictLabels = Object.freeze({
  "need-more": "Need more rolls",
  fair: "Looks pretty fair",
  unsure: "Not sure; roll some more",
  biased: "Looks biased",
});
