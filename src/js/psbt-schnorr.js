// BIP340 / Taproot nonce compare. R is the first 32 bytes of a 64/65-byte sig.

// The defined Taproot sighash bytes (BIP341): the three base types, each with
// or without ANYONECANPAY. SIGHASH_DEFAULT (0x00) exists only as the 64-byte
// form — an appended 0x00 suffix byte is invalid, and every other undefined
// suffix is invalid too.
export const TAPROOT_SIGHASH_BYTES = new Set([0x01, 0x02, 0x03, 0x81, 0x82, 0x83]);

// A Schnorr signature is exactly 64 bytes, or 65 with a defined sighash
// suffix. The first signature byte is R's x-coordinate and says nothing
// about the encoding, so Schnorr-vs-DER is never decided by it (issue #333).
export function hodlLooksSchnorr(item) {
  return !!item && (item.length === 64 || (item.length === 65 && TAPROOT_SIGHASH_BYTES.has(item[64])));
}

export function hodlParseSchnorr(raw) {
  if (!hodlLooksSchnorr(raw)) return null;
  return {
    r: raw.slice(0, 32),
    s: raw.slice(32, 64),
    sighash: raw.length === 65 ? raw[64] : 0,
    raw,
  };
}

// Taproot policy problems, with the commitment direction named: NONE and
// SINGLE (± ANYONECANPAY) drop outputs; ANYONECANPAY|ALL keeps every output
// but drops the other inputs; an undefined byte is not a policy at all
// (issue #333).
export function hodlTapSighashProblems(declared, suffix, hodlSighashLabel) {
  const problems = [];
  const describe = (value, whose, verb) => {
    if (value === 0 || value === 1) return null; // DEFAULT and ALL commit to everything
    const label = hodlSighashLabel(value);
    if (!TAPROOT_SIGHASH_BYTES.has(value)) return whose + " " + verb + " " + label + ", not a defined Taproot sighash byte.";
    if ((value & 0x7f) !== 1) return whose + " " + verb + " " + label + ", which does not commit to all shown outputs.";
    return whose + " " + verb + " " + label + ", which does not commit to all shown inputs.";
  };
  const declaredProblem = declared === null ? null : describe(declared, "The PSBT", "requests");
  if (declaredProblem) problems.push(declaredProblem);
  const suffixProblem = suffix === null ? null : describe(suffix, "This Schnorr signature", "uses");
  if (suffixProblem) problems.push(suffixProblem);
  if (declared !== null && suffix !== null && declared !== suffix && !((declared === 0 || declared === 1) && (suffix === 0 || suffix === 1))) {
    problems.push("The PSBT-declared policy and the Schnorr signature's sighash byte disagree.");
  }
  return problems;
}

export function hodlTapKeySigs(entries, hodlFind) {
  return hodlFind(entries, 19).filter((entry) => entry.keydata.length === 0).map((entry) => {
    const parsed = hodlParseSchnorr(entry.val);
    return parsed
      ? Object.assign({ pubkey: new Uint8Array(), source: "tap-key" }, parsed)
      : { pubkey: new Uint8Array(), r: null, s: null, sighash: null, raw: entry.val, source: "tap-key" };
  });
}

export function hodlTapScriptSigs(entries, hodlFind) {
  return hodlFind(entries, 20).map((entry) => {
    const parsed = hodlParseSchnorr(entry.val);
    const pubkey = entry.keydata.length >= 32 ? entry.keydata.slice(0, 32) : new Uint8Array();
    return parsed
      ? Object.assign({ pubkey, source: "tap-script" }, parsed)
      : { pubkey, r: null, s: null, sighash: null, raw: entry.val, source: "tap-script" };
  });
}

export function hodlCompareSchnorrNonces(rValues, hodlEq) {
  const possible = [];
  for (let first = 0; first < rValues.length; first++) {
    for (let second = first + 1; second < rValues.length; second++) {
      const a = rValues[first], b = rValues[second];
      if (!a.r || !b.r || !hodlEq(a.r, b.r)) continue;
      if (a.pubkey && b.pubkey && a.pubkey.length && b.pubkey.length && !hodlEq(a.pubkey, b.pubkey)) continue;
      if (a.input !== b.input) possible.push([a, b]);
    }
  }
  // `reused` stays empty: definite nonce reuse needs EC point math, which the
  // ECDSA comparison (hodlCompareNonces) already performs; here we only flag
  // possible cross-input R-value sharing.
  return { reused: [], possible };
}
