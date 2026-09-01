// BIP340 / Taproot nonce compare. R is the first 32 bytes of a 64/65-byte sig.

export function hodlLooksSchnorr(item) {
  return !!item && (item.length === 64 || (item.length === 65 && item[0] !== 48));
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

export function hodlTapSighashProblems(declared, suffix, hodlSighashLabel) {
  const problems = [];
  const declaredUnsafe = declared !== null && declared !== 0 && declared !== 1;
  const suffixUnsafe = suffix !== null && suffix !== 0 && suffix !== 1;
  if (declaredUnsafe) problems.push("The PSBT requests " + hodlSighashLabel(declared) + ", which does not commit to all shown outputs.");
  if (suffixUnsafe) problems.push("This Schnorr signature uses " + hodlSighashLabel(suffix) + ", which does not commit to all shown outputs.");
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
