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
  // Keydata is the 32-byte x-only key plus the 32-byte leaf hash; anything
  // shorter is a lookalike the consensus layer never verifies.
  return hodlFind(entries, 20).filter((entry) => entry.keydata.length === 64).map((entry) => {
    const parsed = hodlParseSchnorr(entry.val);
    const pubkey = entry.keydata.slice(0, 32);
    const leafHash = entry.keydata.slice(32, 64);
    return parsed
      ? Object.assign({ pubkey, leafHash, source: "tap-script" }, parsed)
      : { pubkey, leafHash, r: null, s: null, sighash: null, raw: entry.val, source: "tap-script" };
  });
}

// R values group by their hex encoding, exactly like hodlCompareNonces in
// app.js groups ECDSA r values.
function hodlSchnorrRHex(bytes) {
  let hex = "";
  for (const byte of bytes) hex += byte.toString(16).padStart(2, "0");
  return hex;
}

// BIP340 nonce reuse. Two signatures sharing R share their nonce. Under one
// x-only key that is a key leak: BIP341's signature message commits to the
// input index, the leaf hash and the spend path (ext_flag), so the messages
// differ and s1 - s2 = (e1 - e2)*d reveals the key. Under two keys it leaks
// whenever the keys are related: a Taproot output key Q = P + tG and its
// internal key P (s1 - s2 = (e1 - e2)*d + e1*t, with t public), or one
// wallet's non-hardened keys (DeepSeek's red-team of #1051, F1). So every
// pair sharing R is reported, whatever its keys, and each says whether its
// keys match; the one exception is one signature copied into two fields
// (the same R and the same s: the same e, so the same message), which leaks
// nothing. A pair whose s is missing is reported (fail closed). A record
// without a parsed R cannot be compared and one without a 32-byte x-only key
// cannot be attributed: both count in `incomplete`, never silently skipped,
// and a keyless record with an R still joins the comparison.
export function hodlCompareSchnorrNonces(records, hodlEq) {
  const reused = [];
  let incomplete = 0;
  const comparable = [];
  for (const record of records) {
    const readable = record.r && record.r.length === 32;
    if (!readable || !record.pubkey || record.pubkey.length !== 32) incomplete++;
    if (readable) comparable.push(record);
  }
  // Group by R and compare only within a group, like hodlCompareNonces:
  // identical attacker-supplied R values collapse into one quadratic bucket,
  // so total candidate pairs are bounded before any result pair is allocated.
  const byR = new Map();
  for (const record of comparable) {
    const tag = hodlSchnorrRHex(record.r);
    let group = byR.get(tag);
    if (!group) byR.set(tag, (group = []));
    group.push(record);
  }
  let comparisons = 0;
  for (const group of byR.values()) {
    comparisons += group.length * (group.length - 1) / 2;
    if (comparisons > 32768) throw new Error("Nonce comparison limit exceeded: too many signatures share the same r value.");
  }
  for (const group of byR.values()) {
    if (group.length < 2) continue;
    for (let first = 0; first < group.length; first++)
      for (let second = first + 1; second < group.length; second++) {
        const a = group[first], b = group[second];
        if (a.s && b.s && hodlEq(a.s, b.s)) continue; // the same signature twice
        const pair = [a, b];
        pair.sameKey = Boolean(a.pubkey?.length === 32 && b.pubkey?.length === 32 && hodlEq(a.pubkey, b.pubkey));
        reused.push(pair);
      }
  }
  return { reused, incomplete };
}

// BIP341 witness shapes. With at least two elements, a last element starting
// 0x50 is the annex, which no signature check reads; it is dropped first.
function hodlTapStack(stack) {
  const last = stack[stack.length - 1];
  return stack.length >= 2 && last.length && last[0] === 0x50 ? stack.slice(0, -1) : stack;
}

// A tapscript (leaf version 0xc0) control block: 33 + 32m bytes, m <= 128.
// No P2WSH witness script starts 0xc0/0xc1 (undefined opcodes in v0), so a
// v0 witness is never mistaken for a script-path spend.
function hodlLooksControlBlock(item) {
  return item.length >= 33 && item.length <= 33 + 32 * 128 && (item.length - 33) % 32 === 0 && (item[0] & 0xfe) === 0xc0;
}

// "key" for a key-path spend (one 64/65-byte signature), "script" for a
// tapscript script-path spend, null for anything else.
export function hodlTapWitnessShape(stack) {
  const items = hodlTapStack(stack);
  if (items.length === 1 && (items[0].length === 64 || items[0].length === 65)) return "key";
  if (items.length >= 2 && hodlLooksControlBlock(items[items.length - 1])) return "script";
  return null;
}

// The keys of the two leaf templates whose signatures can be attributed from
// the script alone: pk() is <key> OP_CHECKSIG; multi_a (and sortedmulti_a)
// is <k1> OP_CHECKSIG <k2> OP_CHECKSIGADD … <kn> OP_CHECKSIGADD <m> OP_NUMEQUAL.
function hodlTapLeafKeys(script) {
  if (script.length === 34 && script[0] === 0x20 && script[33] === 0xac) return [script.slice(1, 33)];
  const keys = [];
  let at = 0;
  while (at + 34 <= script.length && script[at] === 0x20 && script[at + 33] === (keys.length ? 0xba : 0xac)) {
    keys.push(script.slice(at + 1, at + 33));
    at += 34;
  }
  if (!keys.length) return null;
  let m = 0;
  if (script[at] >= 0x51 && script[at] <= 0x60) { m = script[at] - 0x50; at += 1; }
  else if (script[at] === 0x01 && at + 2 <= script.length) { m = script[at + 1]; at += 2; }
  else if (script[at] === 0x02 && at + 3 <= script.length) { m = script[at + 1] | (script[at + 2] << 8); at += 3; }
  if (!m || m > keys.length || at + 1 !== script.length || script[at] !== 0x9c) return null;
  return keys;
}

// The BIP340 signatures of a finalized script-path spend whose leaf is pk()
// or multi_a, each keyed by its x-only key from the leaf: the script checks
// the top stack item first, so the witness lists the signatures in reverse
// key order, and an empty item is a key that did not sign. An unparseable
// signature is kept with r null (incomplete, never skipped). Null for any
// other witness or leaf: the caller counts it as unchecked.
export function hodlTapScriptPathSigs(stack) {
  const items = hodlTapStack(stack);
  if (items.length < 2 || !hodlLooksControlBlock(items[items.length - 1])) return null;
  const keys = hodlTapLeafKeys(items[items.length - 2]);
  const inputs = items.slice(0, -2);
  if (!keys || inputs.length !== keys.length) return null;
  const records = [];
  keys.forEach((pubkey, at) => {
    const item = inputs[inputs.length - 1 - at];
    if (!item.length) return;
    const parsed = hodlParseSchnorr(item);
    records.push(parsed
      ? { pubkey, r: parsed.r, s: parsed.s, source: "tap-script" }
      : { pubkey, r: null, s: null, source: "tap-script" });
  });
  return records.length ? records : null;
}
