//! PSBT inspect sanitizer: two families only.
//!
//! 1. `duplicate_keys` — BIP-174 forbids duplicate keys *within one map*.
//!    Scan each map's `Vec<RawPair>` (not a hashed map) so a second identical
//!    `type||keydata` is a finding instead of a silent overwrite.
//! 2. `xpub_derives_child` — when a bip32/tap derivation claims an origin,
//!    check it against *applicable* global xpubs (master fingerprint match +
//!    path prefix + unhardened suffix). The key encoding is fixed by the
//!    record type — legacy BIP32 keydata is a secp256k1 public key, tap
//!    keydata is a 32-byte x-only key — never inferred from its length.
//!
//! These are format / origin-consistency facts, not a safety verdict.
//! A derivation that cannot be checked (no applicable xpub, hardened gap,
//! malformed record, exhausted work budget) is `incomplete`, never a pass.
//! rust-bitcoin's own parse verdict stays in `rustBitcoinError` and is not
//! replaced.

use crate::{hex_encode, pair_type_name, read_varint, RawPair};
use bitcoin::bip32::{ChildNumber, Xpub};
use bitcoin::secp256k1::{PublicKey, Secp256k1, XOnlyPublicKey};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};

const MAX_FINDINGS: usize = 32;

/// Hard caps on origin-check work for a whole inspect, so a small hostile
/// file cannot freeze the inspector. Every visited candidate pays both:
/// the prefix probe costs path elements (MAX_SCAN_ELEMENTS, memcmp-cheap)
/// and a matched prefix costs at least one CKD step (MAX_CKD_STEPS, one
/// HMAC-SHA512 + EC operation each). Both are far above any honest PSBT (a
/// handful of xpubs times a few hundred keys times short paths). Exhaustion
/// degrades the family to `incomplete` — never a silent pass, never a false
/// mismatch.
const MAX_CKD_STEPS: u32 = 4096;
const MAX_SCAN_ELEMENTS: u32 = 4 * 1024 * 1024;

pub(crate) struct Origin {
    pub(crate) fingerprint: [u8; 4],
    path: Vec<ChildNumber>,
}

struct GlobalXpub {
    path: Vec<ChildNumber>,
    xpub: Xpub,
}

fn family(state: &str, findings: Vec<Value>, truncated: bool) -> Value {
    json!({ "state": state, "findings": findings, "truncated": truncated })
}

fn push(findings: &mut Vec<Value>, truncated: &mut bool, finding: Value) {
    if findings.len() >= MAX_FINDINGS {
        *truncated = true;
        return;
    }
    findings.push(finding);
}

pub(crate) fn parse_origin(value: &[u8]) -> Result<Origin, String> {
    if value.len() < 4 {
        return Err("derivation value is shorter than its 4-byte fingerprint".into());
    }
    if (value.len() - 4) % 4 != 0 {
        return Err("derivation path is not a multiple of 4 bytes".into());
    }
    let fingerprint = value[..4].try_into().unwrap();
    let path = value[4..]
        .chunks_exact(4)
        .map(|c| ChildNumber::from(u32::from_le_bytes(c.try_into().unwrap())))
        .collect();
    Ok(Origin { fingerprint, path })
}

pub(crate) fn tap_origin(value: &[u8]) -> Result<Origin, String> {
    let mut off = 0usize;
    let count = read_varint(value, &mut off)?;
    let hashes_end = usize::try_from(count)
        .ok()
        .and_then(|n| n.checked_mul(32))
        .and_then(|l| off.checked_add(l))
        .filter(|end| end.checked_add(4).is_some_and(|e| e <= value.len()))
        .ok_or_else(|| "tap bip32 derivation is truncated".to_string())?;
    parse_origin(&value[hashes_end..])
}

fn fp_hex(fp: &[u8; 4]) -> String {
    hex_encode(fp) // 8 hex chars; the full fingerprint, never the value bytes
}

fn finding_duplicate(kind: &str, index: Option<usize>, pair: &RawPair) -> Value {
    let type_byte = pair.key[0];
    json!({
        "code": "duplicate_key",
        "scope": kind,
        "index": index,
        "key": hex_encode(&pair.key),
        "name": pair_type_name(kind, type_byte),
    })
}

fn finding_origin(
    kind: &str,
    index: Option<usize>,
    pair: &RawPair,
    fingerprint: Option<[u8; 4]>,
    reason: &str,
) -> Value {
    let type_byte = pair.key[0];
    json!({
        "code": "xpub_derives_child",
        "scope": kind,
        "index": index,
        "key": hex_encode(&pair.key),
        "name": pair_type_name(kind, type_byte),
        "fingerprint": fingerprint.map(|fp| fp_hex(&fp)),
        "reason": reason,
    })
}

fn duplicate_keys(kind: &str, index: Option<usize>, pairs: &[RawPair]) -> (Vec<Value>, bool) {
    let mut seen = HashSet::<&[u8]>::new();
    let mut findings = Vec::new();
    let mut truncated = false;
    for pair in pairs {
        if pair.key.is_empty() {
            continue;
        }
        if !seen.insert(pair.key.as_slice()) {
            push(
                &mut findings,
                &mut truncated,
                finding_duplicate(kind, index, pair),
            );
        }
    }
    (findings, truncated)
}

/// The key encoding a derivation record must carry, fixed by its BIP-174 /
/// BIP-371 type — never guessed from the observed length.
#[derive(Clone, Copy)]
enum KeyShape {
    /// `PSBT_IN/OUT_BIP32_DERIVATION`: a secp256k1 public key.
    Legacy,
    /// `PSBT_IN/OUT_TAP_BIP32_DERIVATION`: a 32-byte x-only key.
    XOnly,
}

/// The observed key, parsed once per record. The parse doubles as the shape
/// validation: it accepts exactly what rust-bitcoin accepts for the type.
enum ObservedKey {
    Legacy(PublicKey),
    XOnly(XOnlyPublicKey),
}

fn parse_observed(shape: KeyShape, observed: &[u8]) -> Option<ObservedKey> {
    match shape {
        KeyShape::Legacy => PublicKey::from_slice(observed).ok().map(ObservedKey::Legacy),
        KeyShape::XOnly => XOnlyPublicKey::from_slice(observed)
            .ok()
            .map(ObservedKey::XOnly),
    }
}

/// Like-for-like comparison: full key for legacy, x coordinate for tap.
fn key_matches(observed: &ObservedKey, derived: &PublicKey) -> bool {
    match observed {
        ObservedKey::Legacy(p) => p == derived,
        ObservedKey::XOnly(x) => *x == derived.x_only_public_key().0,
    }
}

fn path_prefix(prefix: &[ChildNumber], full: &[ChildNumber]) -> Option<Vec<ChildNumber>> {
    if full.len() < prefix.len() {
        return None;
    }
    if full[..prefix.len()] != prefix[..] {
        return None;
    }
    Some(full[prefix.len()..].to_vec())
}

/// Global xpubs indexed by master fingerprint. Byte-identical records (the
/// Core #35665 duplicate case) collapse to one candidate — same key, same
/// origin, same derived children — so a padded file cannot multiply the
/// derivation work below.
fn collect_xpubs(globals: &[RawPair]) -> HashMap<[u8; 4], Vec<GlobalXpub>> {
    let mut out: HashMap<[u8; 4], Vec<GlobalXpub>> = HashMap::new();
    let mut seen = HashSet::<(&[u8], &[u8])>::new();
    for pair in globals {
        if pair.key.first() != Some(&0x01) || pair.key.len() < 2 {
            continue;
        }
        if !seen.insert((&pair.key, &pair.value)) {
            continue;
        }
        let Ok(xpub) = Xpub::decode(&pair.key[1..]) else {
            continue;
        };
        let Ok(origin) = parse_origin(&pair.value) else {
            continue;
        };
        out.entry(origin.fingerprint).or_default().push(GlobalXpub {
            path: origin.path,
            xpub,
        });
    }
    out
}

struct OriginScan {
    findings: Vec<Value>,
    truncated: bool,
    saw_incomplete: bool,
    saw_problem: bool,
    ckd_left: u32,
    scan_left: u32,
    budget_notice: bool,
}

impl OriginScan {
    fn new() -> Self {
        Self {
            findings: Vec::new(),
            truncated: false,
            saw_incomplete: false,
            saw_problem: false,
            ckd_left: MAX_CKD_STEPS,
            scan_left: MAX_SCAN_ELEMENTS,
            budget_notice: false,
        }
    }

    fn push(&mut self, finding: Value) {
        push(&mut self.findings, &mut self.truncated, finding);
    }

    /// One notice is enough; every exhaustion still flips the family to
    /// `incomplete` via `saw_incomplete`.
    fn budget_exhausted(
        &mut self,
        kind: &str,
        index: Option<usize>,
        pair: &RawPair,
        fingerprint: [u8; 4],
    ) {
        self.saw_incomplete = true;
        if !self.budget_notice {
            self.budget_notice = true;
            self.push(finding_origin(
                kind,
                index,
                pair,
                Some(fingerprint),
                "budget_exhausted",
            ));
        }
    }
}

fn check_one_derivation(
    secp: &Secp256k1<bitcoin::secp256k1::VerifyOnly>,
    xpubs: &HashMap<[u8; 4], Vec<GlobalXpub>>,
    kind: &str,
    index: Option<usize>,
    pair: &RawPair,
    shape: KeyShape,
    origin: Result<Origin, String>,
    scan: &mut OriginScan,
) {
    let origin = match origin {
        Ok(o) => o,
        Err(_) => {
            scan.saw_incomplete = true;
            scan.push(finding_origin(kind, index, pair, None, "malformed"));
            return;
        }
    };
    let Some(observed) = parse_observed(shape, &pair.key[1..]) else {
        scan.saw_incomplete = true;
        scan.push(finding_origin(
            kind,
            index,
            pair,
            Some(origin.fingerprint),
            "malformed_key",
        ));
        return;
    };
    let bucket = xpubs.get(&origin.fingerprint).map_or(&[][..], Vec::as_slice);
    let mut hardened_gap = false;
    let mut checked_any = false;
    for xpub in bucket {
        // The prefix probe is a memcmp of up to min(path lengths) elements;
        // charge it before running so giant paths cannot stall the scan.
        let probe = u32::try_from(xpub.path.len().min(origin.path.len()).max(1))
            .unwrap_or(u32::MAX);
        if probe > scan.scan_left {
            scan.budget_exhausted(kind, index, pair, origin.fingerprint);
            return;
        }
        scan.scan_left -= probe;
        // Applicable = xpub path is a prefix of the child path. Hardened
        // suffixes are not mismatches; they are not checked.
        let Some(suffix) = path_prefix(&xpub.path, &origin.path) else {
            continue;
        };
        // Charge one CKD step per suffix element (and at least one per
        // candidate: even an empty suffix pays for the key comparison)
        // *before* the hardened scan and derivation run.
        let cost = u32::try_from(suffix.len()).unwrap_or(u32::MAX).max(1);
        if cost > scan.ckd_left {
            scan.budget_exhausted(kind, index, pair, origin.fingerprint);
            return;
        }
        scan.ckd_left -= cost;
        if suffix.iter().any(|c| c.is_hardened()) {
            hardened_gap = true;
            continue;
        }
        checked_any = true;
        let derived = if suffix.is_empty() {
            xpub.xpub.public_key
        } else {
            match xpub.xpub.derive_pub(secp, &suffix) {
                Ok(child) => child.public_key,
                Err(_) => continue,
            }
        };
        if key_matches(&observed, &derived) {
            return;
        }
    }
    if !checked_any {
        scan.saw_incomplete = true;
        let reason = if hardened_gap {
            "hardened_gap"
        } else {
            "no_applicable_xpub"
        };
        scan.push(finding_origin(
            kind,
            index,
            pair,
            Some(origin.fingerprint),
            reason,
        ));
        return;
    }
    scan.saw_problem = true;
    scan.push(finding_origin(
        kind,
        index,
        pair,
        Some(origin.fingerprint),
        "mismatch",
    ));
}

fn scan_derivations(
    secp: &Secp256k1<bitcoin::secp256k1::VerifyOnly>,
    xpubs: &HashMap<[u8; 4], Vec<GlobalXpub>>,
    kind: &str,
    index: Option<usize>,
    pairs: &[RawPair],
    scan: &mut OriginScan,
) {
    for pair in pairs {
        if pair.key.is_empty() {
            continue;
        }
        let type_byte = pair.key[0];
        let (origin, shape) = match (kind, type_byte) {
            ("input", 0x06) | ("output", 0x02) => (parse_origin(&pair.value), KeyShape::Legacy),
            ("input", 0x16) | ("output", 0x07) => (tap_origin(&pair.value), KeyShape::XOnly),
            _ => continue,
        };
        check_one_derivation(secp, xpubs, kind, index, pair, shape, origin, scan);
    }
}

pub(crate) fn analyze(
    globals: &[RawPair],
    inputs: &[Vec<RawPair>],
    outputs: &[Vec<RawPair>],
) -> Value {
    let mut dup_findings = Vec::new();
    let mut dup_trunc = false;
    let (g, t) = duplicate_keys("global", None, globals);
    dup_findings.extend(g);
    dup_trunc |= t;
    for (i, map) in inputs.iter().enumerate() {
        let (f, t) = duplicate_keys("input", Some(i), map);
        for item in f {
            push(&mut dup_findings, &mut dup_trunc, item);
        }
        dup_trunc |= t;
    }
    for (j, map) in outputs.iter().enumerate() {
        let (f, t) = duplicate_keys("output", Some(j), map);
        for item in f {
            push(&mut dup_findings, &mut dup_trunc, item);
        }
        dup_trunc |= t;
    }
    let dup_state = if dup_findings.is_empty() {
        "complete"
    } else {
        "problem"
    };

    let secp = Secp256k1::verification_only();
    let xpubs = collect_xpubs(globals);
    let mut scan = OriginScan::new();
    for (i, map) in inputs.iter().enumerate() {
        scan_derivations(&secp, &xpubs, "input", Some(i), map, &mut scan);
    }
    for (j, map) in outputs.iter().enumerate() {
        scan_derivations(&secp, &xpubs, "output", Some(j), map, &mut scan);
    }
    let origin_state = if scan.saw_problem {
        "problem"
    } else if scan.saw_incomplete {
        "incomplete"
    } else {
        "complete"
    };

    json!({
        "duplicateKeys": family(dup_state, dup_findings, dup_trunc),
        "xpubDerivesChild": family(origin_state, scan.findings, scan.truncated),
    })
}
