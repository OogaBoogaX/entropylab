//! Consensus-level problem analysis for a parsed PSBT: the layer every edit
//! is checked against unless insane editing is on. Structural BIP-174
//! validity is enforced by the parser itself; this module answers the harder
//! question — could the transaction these maps describe ever be valid, and do
//! the signatures and UTXO claims in them hold up?
//!
//! Two severities:
//!   error   — a consensus rule or a BIP-174 signer check is violated: the
//!             build gate refuses the edit (insane editing bypasses it).
//!   warning — suspicious but not provably invalid: partial signatures that
//!             do not verify (a signing round in progress), missing UTXO
//!             declarations BIP-174 only recommends, non-standard sighashes.
//!
//! Verification needs the spent outputs, and the only source a PSBT has is
//! its own UTXO declarations — so every verdict here is "against the claimed
//! previous output". What can be checked without a claim is (a witness
//! script hashing to the claimed program, a Taproot control block proving
//! its script under the claimed output key).

use std::collections::BTreeMap;
use std::rc::Rc;

use bitcoin::blockdata::script::{Instruction, Script};
use bitcoin::consensus::{encode, Decodable};
use bitcoin::hashes::{hash160, sha256, sha256d, Hash};
use bitcoin::secp256k1::{self, Message, PublicKey, Secp256k1, XOnlyPublicKey};
use bitcoin::sighash::{Annex, EcdsaSighashType, Prevouts, SighashCache, TapSighashType};
use bitcoin::taproot::{ControlBlock, LeafVersion, TapLeafHash};
use bitcoin::{Amount, ScriptBuf, TapSighash, Transaction, TxOut, Witness};

use crate::scriptcode;
use crate::{hex_encode, pair_utxo_claim, tx_sanity_error, RawPair};

pub(crate) const ERROR: &str = "error";
pub(crate) const WARNING: &str = "warning";

// Signature verification is the only superlinear work here (a legacy sighash
// re-serializes the transaction), and the inspector accepts up to 100k
// inputs. Past this many verifications in one analysis the remaining
// signatures are reported unchecked instead — the same budgeted shape the
// sanitize pass uses (a 5 MB hostile PSBT must not freeze the editor).
const MAX_SIGNATURE_CHECKS: usize = 256;
// A legacy signature hash re-serializes the whole transaction, so their work
// is bounded by bytes hashed rather than by signature count alone. 32 MiB
// admits every ordinary wallet (a 100-input consolidation at ~4 KiB per
// digest uses ~400 KiB) while keeping a hostile multisig document from hashing
// gigabytes; the two budgets fail independently.
const MAX_LEGACY_DIGEST_BYTES: usize = 32 * 1024 * 1024;
const _: () = assert!(1 << scriptcode::MAX_MULTISIG_COMPANIONS <= MAX_SIGNATURE_CHECKS);
const _: () = assert!(
    scriptcode::MAX_STARTS <= MAX_SIGNATURE_CHECKS,
    "every start the analysis lists must be checkable within the budget"
);

/// The verification budget: `take()` bounds the number of signatures and
/// `take_digest()` the bytes hashed by legacy sighashes. Each returns false
/// once its own budget is exhausted, and the caller notes the exhaustion in
/// the problem list exactly once.
struct Budget {
    left: usize,
    noted: bool,
    digest_left: usize,
    digest_noted: bool,
}

/// One script's separator analysis, memoized for the whole run: every
/// signature of an input is checked against the same script, and the result
/// depends only on the script's bytes. Identity is the content, not the
/// buffer — spend scripts are re-buffered each input, so a stale pointer
/// match carries the old bytes alongside.
struct AnalysisMemo<T> {
    script: Option<Box<[u8]>>,
    result: Option<Rc<T>>,
}

impl<T> AnalysisMemo<T> {
    fn get(&mut self, script: &[u8], compute: impl FnOnce(&[u8]) -> T) -> Rc<T> {
        if self.script.as_deref() != Some(script) {
            self.script = Some(script.into());
            self.result = Some(Rc::new(compute(script)));
        }
        Rc::clone(self.result.as_ref().expect("stored above or by an earlier call"))
    }
}

/// Tapscript separator analyses for the whole run, keyed by leaf hash. The
/// hash commits to the leaf's bytes and version, so it names the analysis
/// exactly; the map holds every leaf, so signatures alternating between
/// leaves no longer evict each other, and no script is copied (#539). A
/// BTreeMap: no hasher seed to draw, no collisions to aim for.
type TapscriptMemo = BTreeMap<TapLeafHash, Rc<scriptcode::Tapscript>>;

/// An input's tapscript leaves (PSBT_IN_TAP_LEAF_SCRIPT, 0x15, leaf version
/// 0xc0) by leaf hash, each hashed once — not once per script-path
/// signature (#539). The first declaration of a hash wins, as the
/// per-signature scan's first match did.
fn tapscript_leaves(map: &[RawPair]) -> BTreeMap<TapLeafHash, &[u8]> {
    let mut leaves = BTreeMap::new();
    for pair in map.iter().filter(|pair| pair.key[0] == 0x15) {
        let Some((&version, script)) = pair.value.split_last() else { continue };
        if !matches!(LeafVersion::from_consensus(version), Ok(LeafVersion::TapScript)) {
            continue;
        }
        leaves.entry(TapLeafHash::from_script(Script::from_bytes(script), LeafVersion::TapScript)).or_insert(script);
    }
    leaves
}

impl Budget {
    fn new() -> Self {
        Self { left: MAX_SIGNATURE_CHECKS, noted: false, digest_left: MAX_LEGACY_DIGEST_BYTES, digest_noted: false }
    }

    fn take(&mut self, problems: &mut Vec<Problem>) -> bool {
        if self.left > 0 {
            self.left -= 1;
            return true;
        }
        if !self.noted {
            self.noted = true;
            // Error severity: past the budget the document is not fully
            // vouched, and a gate that cannot check must fail closed (insane
            // editing is the bypass), never wave the rest through.
            problems.push(Problem::error(
                "transaction".into(),
                "verification_budget",
                format!("verification budget exhausted after {MAX_SIGNATURE_CHECKS} signature checks — later signatures are unchecked"),
            ));
        }
        false
    }

    /// Charges the bytes a legacy signature hash re-serializes. Called at
    /// every digest the multisig/codeseparator enumeration would compute,
    /// not once per signature: each candidate is another full transaction
    /// hash. Takes nothing and fails when fewer bytes remain.
    fn take_digest(&mut self, bytes: usize, problems: &mut Vec<Problem>) -> bool {
        if bytes <= self.digest_left {
            self.digest_left -= bytes;
            return true;
        }
        self.digest_left = 0;
        if !self.digest_noted {
            self.digest_noted = true;
            problems.push(Problem::error(
                "transaction".into(),
                "verification_budget",
                format!("verification budget exhausted after {} MiB of legacy signature hashing — later signatures are unchecked", MAX_LEGACY_DIGEST_BYTES / (1024 * 1024)),
            ));
        }
        false
    }
}

#[derive(Debug)]
pub(crate) struct Problem {
    pub(crate) severity: &'static str,
    pub(crate) scope: String,
    pub(crate) code: &'static str,
    pub(crate) message: String,
}

impl Problem {
    pub(crate) fn error(scope: String, code: &'static str, message: impl Into<String>) -> Self {
        Problem { severity: ERROR, scope, code, message: message.into() }
    }
    pub(crate) fn warning(scope: String, code: &'static str, message: impl Into<String>) -> Self {
        Problem { severity: WARNING, scope, code, message: message.into() }
    }
}

/// How an input's spend will be authorized, from the claimed scriptPubKey
/// plus the input map's redeem/witness scripts. `Unknown` means the claim is
/// missing or P2SH without its redeem script — nothing can be asserted then.
enum Spend {
    P2wpkh,
    P2wsh(Option<ScriptBuf>),
    P2tr(XOnlyPublicKey),
    WrappedP2wpkh(ScriptBuf),
    WrappedP2wsh(ScriptBuf, Option<ScriptBuf>),
    /// P2SH whose redeem script is not a witness program.
    LegacyP2sh(ScriptBuf),
    /// The claimed scriptPubKey itself is the script being signed.
    Legacy,
    /// A witness program of a version this crate does not know (v2+): segwit
    /// for the UTXO-declaration checks, unverifiable for signatures.
    UnknownWitness,
    Unknown,
}

impl Spend {
    fn is_witness(&self) -> bool {
        matches!(
            self,
            Spend::P2wpkh | Spend::P2wsh(_) | Spend::P2tr(_) | Spend::WrappedP2wpkh(_) | Spend::WrappedP2wsh(..) | Spend::UnknownWitness
        )
    }
}

/// The single pair of a keyless-data type in an input map, when exactly one
/// exists. (Duplicate keys are a format error caught before analysis.)
fn input_field<'a>(map: &'a [RawPair], type_byte: u8) -> Option<&'a [u8]> {
    map.iter()
        .find(|pair| pair.key.as_slice() == [type_byte])
        .map(|pair| pair.value.as_slice())
}

/// The input map's witness script (0x05), hash-checked against the program it
/// must match: the claim's own program for native P2WSH, the redeem script's
/// for the wrapped form (BIP-174 signer checks).
fn checked_witness_script(
    map: &[RawPair],
    program: &[u8],
    scope: &str,
    problems: &mut Vec<Problem>,
) -> Option<ScriptBuf> {
    let value = input_field(map, 0x05)?;
    if sha256::Hash::hash(value).to_byte_array()[..] != program[..] {
        problems.push(Problem::error(
            scope.into(),
            "witness_script_mismatch",
            "witnessScript does not hash to the claimed output's witness program",
        ));
        return None;
    }
    Some(ScriptBuf::from_bytes(value.to_vec()))
}

/// Classifies one input's spend from its claim and script pairs, reporting
/// the BIP-174 signer checks that fail along the way (redeem/witness script
/// hash mismatches).
fn classify(index: usize, map: &[RawPair], claim: &TxOut, problems: &mut Vec<Problem>) -> Spend {
    let scope = format!("input {index}");
    let script = claim.script_pubkey.as_script();
    if script.is_p2wpkh() {
        return Spend::P2wpkh;
    }
    if script.is_p2wsh() {
        let ws = checked_witness_script(map, &script.as_bytes()[2..], &scope, problems);
        return Spend::P2wsh(ws);
    }
    if script.is_p2tr() {
        return match XOnlyPublicKey::from_slice(&script.as_bytes()[2..]) {
            Ok(key) => Spend::P2tr(key),
            Err(_) => Spend::Unknown, // 32 bytes that are not a liftable key
        };
    }
    if script.is_witness_program() {
        return Spend::UnknownWitness; // a future witness version
    }
    if script.is_p2sh() {
        // A finalized input normally has no 0x04: BIP-174's Input Finalizer
        // clears it. Its redeem script is then the final scriptSig's last
        // push, which BIP-16 hash-binds to this output, so a finalized
        // wrapped-segwit spend is still checked against it (#866).
        let (redeem, from_script_sig) = match input_field(map, 0x04) {
            Some(redeem) => (redeem.to_vec(), false),
            None => {
                // No final scriptSig: an unfinalized input, nothing to check.
                let Some(script_sig) = input_field(map, 0x07) else { return Spend::Unknown };
                // A present one is read as consensus reads it: push-only, any
                // push encoding (minimal pushes are policy for a legacy
                // spend; check_final_scriptsig still holds a wrapped-segwit
                // scriptSig to the exact single push).
                match script_pushes(Script::from_bytes(script_sig)).and_then(|mut pushes| pushes.pop()) {
                    Some(last) => (last, true),
                    // Not push-only, unparseable, or empty: BIP-16 rejects
                    // the spend, so fail closed rather than skip the input.
                    None => {
                        problems.push(Problem::error(
                            scope,
                            "final_scriptsig_bad",
                            "final scriptSig of a P2SH input must be push-only and end with its redeem script",
                        ));
                        return Spend::Unknown;
                    }
                }
            }
        };
        if hash160::Hash::hash(&redeem).to_byte_array()[..] != script.as_bytes()[2..22] {
            problems.push(Problem::error(
                scope,
                "redeem_script_mismatch",
                if from_script_sig {
                    "final scriptSig's redeem script push does not hash to the claimed output's P2SH scriptPubKey"
                } else {
                    "redeemScript does not hash to the claimed output's P2SH scriptPubKey"
                },
            ));
            return Spend::Unknown;
        }
        let redeem = ScriptBuf::from_bytes(redeem);
        if redeem.is_p2wpkh() {
            return Spend::WrappedP2wpkh(redeem);
        }
        if redeem.is_p2wsh() {
            let ws = checked_witness_script(map, &redeem.as_bytes()[2..], &scope, problems);
            return Spend::WrappedP2wsh(redeem, ws);
        }
        if from_script_sig {
            // A legacy redeem script recovered from the scriptSig stays
            // unclassified, as before: a legacy classification would start
            // the non-witness UTXO checks on finalized legacy inputs, which
            // is a separate question from the wrapped-segwit gap.
            return Spend::Unknown;
        }
        return Spend::LegacyP2sh(redeem);
    }
    Spend::Legacy
}

/// Signature versions that hash an ECDSA scriptCode.
#[derive(Clone, Copy)]
enum SigVersion {
    Legacy,
    WitnessV0,
}

/// The legacy or BIP-143 digest for one scriptCode. `hash_type` is the
/// signature's last byte as Core reads it (an int, committed as all four
/// bytes): rust-bitcoin's typed BIP-143 API only takes the six defined
/// types, whose flags it derives from the same bits Core masks, so the
/// preimage is built with that type and its final nHashType field then
/// overwritten with the byte actually signed. `code` is already the
/// serialized scriptCode (legacy: separators stripped).
fn ecdsa_digest(
    cache: &mut SighashCache<&Transaction>,
    index: usize,
    version: SigVersion,
    code: &[u8],
    value: Amount,
    hash_type: u32,
) -> Option<[u8; 32]> {
    match version {
        SigVersion::Legacy => Some(cache.legacy_signature_hash(index, Script::from_bytes(code), hash_type).ok()?.to_byte_array()),
        SigVersion::WitnessV0 => {
            let mut preimage = Vec::new();
            cache
                .segwit_v0_encode_signing_data_to(&mut preimage, index, Script::from_bytes(code), value, EcdsaSighashType::from_consensus(hash_type))
                .ok()?;
            let tail = preimage.len() - 4;
            preimage[tail..].copy_from_slice(&hash_type.to_le_bytes());
            Some(sha256d::Hash::hash(&preimage).to_byte_array())
        }
    }
}

/// Verifies one ECDSA signature (DER plus hash type byte) the way Core's
/// OP_CHECKSIG does for a partial or final signature whose execution path
/// is still open: accepted when it verifies under some scriptCode an
/// execution of the spend's script could hash (see scriptcode.rs), refused
/// when it verifies under none. Returns the verdict text on failure; None
/// when it cannot be computed (a P2WSH spend without its witness script),
/// the budget ran out between candidates, or a multisig embeds too many
/// signatures to try every deletion (noted as `verification_incomplete`).
///
/// Consensus, not policy: strict DER (BIP66) is required, S may be high
/// (LOW_S is policy; Core normalizes before verifying), any hash type byte
/// is committed as given (STRICTENC is policy), and the public key is
/// parsed as libsecp256k1 does.
fn check_ecdsa(
    cache: &mut SighashCache<&Transaction>,
    index: usize,
    spend: &Spend,
    claim: &TxOut,
    pubkey: &[u8],
    sig: &[u8],
    budget: &mut Budget,
    problems: &mut Vec<Problem>,
    starts_memo: &mut AnalysisMemo<scriptcode::Shape>,
) -> Option<Result<(), String>> {
    let hash_type = *sig.last()? as u32;
    // SIGHASH_SINGLE on an input with no corresponding output: legacy
    // consensus assigns the constant-one digest (the "SIGHASH_SINGLE bug")
    // and segwit v0 a zero hashOutputs. The signature is still verified
    // against that consensus digest — but it commits to no output, so the
    // condition is named alongside the verdict (audit C3-8).
    if hash_type & 0x1f == 0x03 && index >= cache.transaction().output.len() {
        problems.push(Problem::warning(
            format!("input {index}"),
            "sighash_single_no_output",
            "signature uses SIGHASH_SINGLE with no corresponding output: its digest commits to no output (legacy: the constant-one digest; segwit v0: a zero hashOutputs)",
        ));
    }
    let p2wpkh_code;
    let (version, script): (SigVersion, &[u8]) = match spend {
        Spend::P2wpkh => {
            p2wpkh_code = claim.script_pubkey.p2wpkh_script_code()?;
            (SigVersion::WitnessV0, p2wpkh_code.as_bytes())
        }
        Spend::WrappedP2wpkh(redeem) => {
            p2wpkh_code = redeem.p2wpkh_script_code()?;
            (SigVersion::WitnessV0, p2wpkh_code.as_bytes())
        }
        Spend::P2wsh(Some(ws)) | Spend::WrappedP2wsh(_, Some(ws)) => (SigVersion::WitnessV0, ws.as_bytes()),
        Spend::LegacyP2sh(redeem) => (SigVersion::Legacy, redeem.as_bytes()),
        Spend::Legacy => (SigVersion::Legacy, claim.script_pubkey.as_bytes()),
        // No witness script, or taproot (Schnorr; reported by the caller),
        // or a future witness version: nothing to hash.
        Spend::P2wsh(None) | Spend::WrappedP2wsh(_, None) | Spend::P2tr(_) | Spend::Unknown | Spend::UnknownWitness => return None,
    };
    // A legacy sign re-serializes the whole transaction for each candidate
    // scriptCode. Each digest is charged its transaction size inside the loop
    // below; witness v0 hashes one candidate per signature, so the signature
    // budget alone bounds them.
    let shape = starts_memo.get(script, scriptcode::code_starts);
    let starts = match &*shape {
        scriptcode::Shape::Starts(starts) if starts.is_empty() => {
            // No opcode in the script checks a signature: none it carries is
            // ever consumed. Hash the whole script, what a signer would.
            vec![scriptcode::CodeStart { offset: 0, position: scriptcode::NO_CODESEPARATOR, multisig: false }]
        }
        scriptcode::Shape::Starts(starts) => starts.clone(),
        scriptcode::Shape::Truncated => {
            return Some(Err("cannot be valid: its script has a push running past the end, so it never executes".into()))
        }
        scriptcode::Shape::Unbalanced => {
            return Some(Err("cannot be valid: its script's IF/ELSE/ENDIF do not balance, so it never executes".into()))
        }
        scriptcode::Shape::Overlimit => {
            return Some(Err("cannot be valid: its script exceeds consensus limits (10,000 bytes / 201 opcodes), so it never executes".into()))
        }
    };
    if !scriptcode::is_valid_signature_encoding(sig) {
        return Some(Err("signature is not valid DER".into()));
    }
    let pubkey = match PublicKey::from_slice(pubkey) {
        Ok(key) => key,
        Err(_) => return Some(Err("public key is not a valid secp256k1 key".into())),
    };
    let mut signature = match secp256k1::ecdsa::Signature::from_der_lax(&sig[..sig.len() - 1]) {
        Ok(sig) => sig,
        Err(_) => return Some(Err("signature is not valid DER".into())),
    };
    signature.normalize_s();
    let secp = Secp256k1::verification_only();
    // The caller took one unit of budget for this signature; every further
    // distinct scriptCode is another digest and takes its own.
    let mut seen: Vec<[u8; 32]> = Vec::new();
    for start in starts {
        let tail = &script[start.offset..];
        let codes = match version {
            SigVersion::Legacy => match scriptcode::legacy_script_codes(tail, sig, start.multisig) {
                Some(codes) => codes,
                None => {
                    // Too many subsets to try: unchecked, and an error so
                    // the gate fails closed — never reported invalid.
                    problems.push(Problem::error(
                        format!("input {index}"),
                        "verification_incomplete",
                        format!(
                            "a signature is unchecked: its multisig script embeds more than {} signature-shaped pushes, too many combinations to try",
                            scriptcode::MAX_MULTISIG_COMPANIONS
                        ),
                    ));
                    return None;
                }
            },
            SigVersion::WitnessV0 => vec![tail.to_vec()],
        };
        for code in codes {
            let id = sha256::Hash::hash(&code).to_byte_array();
            if seen.contains(&id) {
                continue;
            }
            if !seen.is_empty() && !budget.take(problems) {
                return None;
            }
            seen.push(id);
            if matches!(version, SigVersion::Legacy) && !budget.take_digest(cache.transaction().total_size(), problems) {
                return None;
            }
            let digest = ecdsa_digest(cache, index, version, &code, claim.value, hash_type)?;
            let message = Message::from_digest_slice(&digest).expect("a sighash is 32 bytes");
            if secp.verify_ecdsa(&message, &signature, &pubkey).is_ok() {
                return Some(Ok(()));
            }
        }
    }
    Some(Err("signature does not verify against the claimed previous output".into()))
}

/// BIP-341 sighash for a taproot input. Every input needs a resolved claim —
/// the digest commits to all of them — so a partial claim set makes every
/// taproot signature unverifiable (the caller then stays silent: an
/// unverifiable signature is not an invalid one). `annex` is the final
/// witness's annex when it has one: the message must commit to it
/// (spend_type bit 0, sha_annex) or a valid signature is flagged and an
/// annex-less one passes. Partial signatures carry no annex (PSBTv0 has no
/// field for one).
fn taproot_sighash_key_spend(
    cache: &mut SighashCache<&Transaction>,
    index: usize,
    prevouts: &Option<Vec<TxOut>>,
    annex: Option<&[u8]>,
    sighash_type: TapSighashType,
) -> Option<[u8; 32]> {
    let prevouts = prevouts.as_ref()?;
    // taproot_key_spend_signature_hash has no annex parameter; encode the
    // BIP-341 message directly (the caller checked the 0x50 prefix).
    let annex = annex.map(|bytes| Annex::new(bytes).expect("annex starts with 0x50"));
    let mut engine = TapSighash::engine();
    cache
        .taproot_encode_signing_data_to(&mut engine, index, &Prevouts::All(prevouts), annex, None, sighash_type)
        .ok()?;
    Some(TapSighash::from_engine(engine).to_byte_array())
}

/// BIP-342 sighash for a script-path signature that committed to
/// `codesep_pos`, the opcode position of the last OP_CODESEPARATOR its
/// execution ran (NO_CODESEPARATOR when none did).
fn taproot_sighash_script_spend(
    cache: &mut SighashCache<&Transaction>,
    index: usize,
    prevouts: &Option<Vec<TxOut>>,
    leaf_hash: TapLeafHash,
    codesep_pos: u32,
    sighash_type: TapSighashType,
) -> Option<[u8; 32]> {
    let prevouts = prevouts.as_ref()?;
    let mut engine = TapSighash::engine();
    cache
        .taproot_encode_signing_data_to(&mut engine, index, &Prevouts::All(prevouts), None, Some((leaf_hash, codesep_pos)), sighash_type)
        .ok()?;
    Some(TapSighash::from_engine(engine).to_byte_array())
}

/// BIP-341 has no SIGHASH_SINGLE fallback: when the input has no output at
/// the same index, validation fails outright (unlike legacy and segwit v0,
/// which hash a constant). Both sighash encoders above report that as an
/// error, indistinguishable from a missing prevout set, so callers ask this
/// first to tell "cannot compute" from "can never verify".
fn taproot_single_without_output(cache: &SighashCache<&Transaction>, index: usize, ty: TapSighashType) -> bool {
    matches!(ty, TapSighashType::Single | TapSighashType::SinglePlusAnyoneCanPay) && index >= cache.transaction().output.len()
}

/// The codesep_pos values a script-path signature under `leaf_hash` can have
/// committed to: from the leaf's script when the input declares it (its
/// entry in `tapscript_leaves`), the positions of the separators an
/// execution can run last before a signature check, no-separator first when
/// it is one. Without the script, only the no-separator default — what a
/// signer uses absent a script. `truncated` when the script offers more
/// candidates than the verification budget can reach (the prefix is exactly
/// what the budget could try).
fn tapscript_codesep_positions(
    script: Option<&[u8]>,
    leaf_hash: TapLeafHash,
    memo: &mut TapscriptMemo,
) -> (Vec<u32>, bool) {
    let shape = script.map(|script| Rc::clone(memo.entry(leaf_hash).or_insert_with(|| Rc::new(scriptcode::tapscript_starts(script)))));
    match shape {
        Some(shape) => match &*shape {
            scriptcode::Tapscript::Starts { positions, truncated } if !positions.is_empty() => (positions.clone(), *truncated),
            _ => (vec![scriptcode::NO_CODESEPARATOR], false),
        },
        None => (vec![scriptcode::NO_CODESEPARATOR], false),
    }
}

/// Parses a 64/65-byte BIP-340 signature into (signature, sighash type);
/// the message names what is being read for the verdict text.
fn read_tap_sig(value: &[u8], what: &str) -> Result<(secp256k1::schnorr::Signature, TapSighashType), String> {
    let (raw, sighash_byte) = match value.len() {
        64 => (value, 0u8),
        65 => (&value[..64], value[64]),
        _ => return Err(format!("{what} must be 64 or 65 bytes")),
    };
    // BIP-341 SIGHASH_DEFAULT exists only as the implicit 64-byte form: an
    // appended 0x00 byte is not a valid encoding. from_consensus_u8 maps it
    // to Default, so reject it here before verification agrees with a
    // signature Bitcoin Core will refuse.
    if value.len() == 65 && sighash_byte == 0 {
        return Err(format!("{what} appends SIGHASH_DEFAULT (0x00); use the 64-byte form"));
    }
    let signature =
        secp256k1::schnorr::Signature::from_slice(raw).map_err(|_| format!("{what} is not a valid Schnorr signature"))?;
    let sighash_type = TapSighashType::from_consensus_u8(sighash_byte)
        .map_err(|_| format!("{what} uses invalid taproot sighash type 0x{sighash_byte:02x}"))?;
    Ok((signature, sighash_type))
}

fn check_schnorr(digest: [u8; 32], signature: &secp256k1::schnorr::Signature, key: &XOnlyPublicKey) -> Result<(), String> {
    let message = Message::from_digest_slice(&digest).expect("a sighash is 32 bytes");
    Secp256k1::verification_only()
        .verify_schnorr(signature, &message, key)
        .map_err(|_| "signature does not verify against the claimed previous output".into())
}

/// Partial signatures (0x02): verified when the spend is classifiable and the
/// sighash computable. Invalid partials are warnings, not gate errors — a
/// PSBT mid-signing-round is a normal object, and a wrong partial signature
/// is the signer's problem, not the format's. A Taproot input carrying
/// ECDSA partials is the oddity worth naming.
fn check_partial_sigs(
    cache: &mut SighashCache<&Transaction>,
    index: usize,
    map: &[RawPair],
    spend: &Spend,
    claim: &TxOut,
    sighash_field: Option<u32>,
    budget: &mut Budget,
    problems: &mut Vec<Problem>,
    starts_memo: &mut AnalysisMemo<scriptcode::Shape>,
) {
    let scope = format!("input {index}");
    for pair in map.iter().filter(|pair| pair.key[0] == 0x02) {
        let pubkey = &pair.key[1..];
        let short = &hex_encode(pubkey);
        let short = &short[..short.len().min(16)];
        if matches!(spend, Spend::P2tr(_)) {
            problems.push(Problem::warning(
                scope.clone(),
                "partial_sig_on_taproot",
                format!("ECDSA partial signature (pubkey {short}…) on a taproot input, which signs with Schnorr"),
            ));
            continue;
        }
        if let Some(&byte) = pair.value.last() {
            if EcdsaSighashType::from_standard(byte as u32).is_err() {
                problems.push(Problem::warning(
                    scope.clone(),
                    "sighash_nonstandard",
                    format!("partial signature (pubkey {short}…) uses non-standard sighash type 0x{byte:02x}"),
                ));
            }
            if sighash_field.is_some_and(|declared| declared != byte as u32) {
                problems.push(Problem::warning(
                    scope.clone(),
                    "sighash_mismatch",
                    format!("partial signature (pubkey {short}…) sighash byte disagrees with PSBT_IN_SIGHASH_TYPE"),
                ));
            }
        }
        if !budget.take(problems) {
            continue;
        }
        match check_ecdsa(cache, index, spend, claim, pubkey, &pair.value, budget, problems, starts_memo) {
            Some(Ok(())) => {}
            Some(Err(why)) => problems.push(Problem::warning(
                scope.clone(),
                "partial_sig_invalid",
                format!("partial signature (pubkey {short}…) {why}"),
            )),
            // No sighash: the spend type cannot be hashed without a witness
            // script, or the legacy-digest charge exhausted the budget. Either
            // way the signature is not checked — say so rather than stay silent.
            None => problems.push(Problem::warning(
                scope.clone(),
                "partial_sig_unchecked",
                format!("partial signature (pubkey {short}…) is unchecked: no signature hash is computable for this input"),
            )),
        }
    }
}

/// Taproot signatures: the key-spend signature (0x13) against the claimed
/// output key, and script-path signatures (0x14) against their xonly key and
/// leaf hash. Warnings, like ECDSA partials.
fn check_tap_sigs(
    cache: &mut SighashCache<&Transaction>,
    index: usize,
    map: &[RawPair],
    spend: &Spend,
    prevouts: &Option<Vec<TxOut>>,
    budget: &mut Budget,
    problems: &mut Vec<Problem>,
    tap_memo: &mut TapscriptMemo,
) {
    let Spend::P2tr(output_key) = spend else { return };
    let scope = format!("input {index}");
    if let Some(value) = input_field(map, 0x13) {
        match read_tap_sig(value, "key-path signature") {
            Err(why) => problems.push(Problem::warning(scope.clone(), "tap_sig_invalid", why)),
            Ok((sig, ty)) if !budget.take(problems) => {
                let _ = (sig, ty);
            }
            Ok((_sig, ty)) if taproot_single_without_output(cache, index, ty) => {
                problems.push(Problem::warning(
                    scope.clone(),
                    "tap_sig_invalid",
                    "key-path signature uses SIGHASH_SINGLE with no corresponding output, which BIP-341 rejects",
                ));
            }
            Ok((sig, ty)) => match taproot_sighash_key_spend(cache, index, prevouts, None, ty) {
                None => {} // prevout set incomplete: cannot compute, cannot accuse
                Some(digest) => {
                    if let Err(why) = check_schnorr(digest, &sig, output_key) {
                        problems.push(Problem::warning(scope.clone(), "tap_sig_invalid", format!("key-path {why}")));
                    }
                }
            },
        }
    }
    // Built on the first script-path signature that gets this far, so an
    // input without one hashes nothing.
    let mut leaf_scripts = None;
    for pair in map.iter().filter(|pair| pair.key[0] == 0x14 && pair.key.len() == 65) {
        let xonly = &pair.key[1..33];
        let leaf_hash = &pair.key[33..65];
        let short = &hex_encode(xonly)[..16];
        let Ok(key) = XOnlyPublicKey::from_slice(xonly) else {
            problems.push(Problem::warning(
                scope.clone(),
                "tap_sig_invalid",
                format!("script-path signature (xonly {short}…) has an invalid public key"),
            ));
            continue;
        };
        if !budget.take(problems) {
            continue;
        }
        let (sig, ty) = match read_tap_sig(&pair.value, "script-path signature") {
            Err(why) => {
                problems.push(Problem::warning(scope.clone(), "tap_sig_invalid", why));
                continue;
            }
            Ok(parsed) => parsed,
        };
        if taproot_single_without_output(cache, index, ty) {
            problems.push(Problem::warning(
                scope.clone(),
                "tap_sig_invalid",
                format!("script-path signature (xonly {short}…) uses SIGHASH_SINGLE with no corresponding output, which BIP-341 rejects"),
            ));
            continue;
        }
        let leaf_hash = TapLeafHash::from_slice(leaf_hash).expect("32 bytes");
        // Valid when it verifies at some position; each position past the
        // first is another digest and takes its own budget.
        let script = leaf_scripts.get_or_insert_with(|| tapscript_leaves(map)).get(&leaf_hash).copied();
        let (positions, truncated) = tapscript_codesep_positions(script, leaf_hash, tap_memo);
        let mut verdict = None;
        for (n, &position) in positions.iter().enumerate() {
            if n > 0 && !budget.take(problems) {
                verdict = None;
                break;
            }
            let Some(digest) = taproot_sighash_script_spend(cache, index, prevouts, leaf_hash, position, ty) else { break };
            verdict = Some(check_schnorr(digest, &sig, &key));
            if matches!(verdict, Some(Ok(()))) {
                break;
            }
        }
        if let Some(Err(why)) = verdict {
            if truncated {
                // The unreachable tail may contain a position the signature
                // committed to: unchecked, an error so the gate fails closed,
                // never reported invalid (same shape as the multisig cap).
                problems.push(Problem::error(
                    scope.clone(),
                    "verification_incomplete",
                    format!(
                        "a signature is unchecked: its script allows more separator positions than the {} the verification budget reaches",
                        scriptcode::MAX_STARTS
                    ),
                ));
            } else {
                problems.push(Problem::warning(
                    scope.clone(),
                    "tap_sig_invalid",
                    format!("script-path signature (xonly {short}…) {why}"),
                ));
            }
        }
    }
}

/// The pushes of a final scriptSig; None when the script is not push-only or
/// does not parse. The small-number opcodes are pushes (of the empty vector
/// for OP_0, of the number for OP_1..OP_16, of 0x81 for OP_1NEGATE) — a P2SH
/// multisig scriptSig starts with OP_0, as CHECKMULTISIG's stack dummy.
/// Non-minimal push encodings are accepted: minimal pushes are policy
/// (SCRIPT_VERIFY_MINIMALDATA), and consensus reads any push form.
fn script_pushes(script: &Script) -> Option<Vec<Vec<u8>>> {
    use bitcoin::opcodes::all::{OP_PUSHNUM_1, OP_PUSHNUM_16, OP_PUSHNUM_NEG1};
    use bitcoin::opcodes::OP_0;
    let mut pushes = Vec::new();
    for instruction in script.instructions() {
        match instruction {
            Ok(Instruction::PushBytes(bytes)) => pushes.push(bytes.as_bytes().to_vec()),
            Ok(Instruction::Op(op)) if op == OP_0 => pushes.push(Vec::new()),
            Ok(Instruction::Op(op)) if op == OP_PUSHNUM_NEG1 => pushes.push(vec![0x81]),
            Ok(Instruction::Op(op)) if op.to_u8() >= OP_PUSHNUM_1.to_u8() && op.to_u8() <= OP_PUSHNUM_16.to_u8() => {
                pushes.push(vec![op.to_u8() - OP_PUSHNUM_1.to_u8() + 1]);
            }
            _ => return None,
        }
    }
    Some(pushes)
}

/// Final scriptSig (0x07): for a P2PKH claim it must be exactly [sig,
/// pubkey], the pubkey must hash to the claim, and the signature must verify
/// — a finalized input is the claim "this is the spending transaction", so a
/// failure here is a consensus-invalid spend, an error. For P2SH the last
/// push must be the redeem script (hash-checked); a wrapped-segwit redeem
/// script then requires the final witness, which is checked separately.
fn check_final_scriptsig(
    cache: &mut SighashCache<&Transaction>,
    index: usize,
    value: &[u8],
    spend: &Spend,
    claim: &TxOut,
    has_final_witness: bool,
    budget: &mut Budget,
    problems: &mut Vec<Problem>,
    starts_memo: &mut AnalysisMemo<scriptcode::Shape>,
) {
    let scope = format!("input {index}");
    let script = Script::from_bytes(value);
    let claim_script = claim.script_pubkey.as_script();
    // BIP-141: a native witness program is spent with an empty scriptSig.
    // P2SH-wrapped witness inputs are handled below; their scriptSig must
    // push exactly the redeem script.
    if claim_script.is_witness_program() {
        if !value.is_empty() {
            problems.push(Problem::error(
                scope.clone(),
                "final_scriptsig_bad",
                "final scriptSig of a native SegWit input must be empty",
            ));
        }
        // An *empty* final scriptSig is also the not-yet-finalized state: a
        // native witness program is spent with an empty scriptSig, so its
        // presence says nothing an absent field does not. Only a non-empty one
        // is a consensus error (above). The wrapped case below can tell the
        // two apart, because there the final scriptSig must carry a push.
        return;
    }
    if claim_script.is_p2sh() {
        let Spend::LegacyP2sh(redeem) = spend else {
            // Wrapped segwit: scriptSig must push exactly the redeem script,
            // and the input then needs its final witness.
            let wrapped = matches!(spend, Spend::WrappedP2wpkh(_) | Spend::WrappedP2wsh(..));
            if wrapped {
                // BIP-141 requires the scriptSig to be exactly the canonical
                // single push of the redeemScript. `script_pushes` accepts
                // non-minimal encodings for legacy consensus reads, so it
                // cannot decide this: compare the bytes instead.
                let redeem = match spend {
                    Spend::WrappedP2wpkh(redeem) | Spend::WrappedP2wsh(redeem, _) => redeem,
                    _ => unreachable!(),
                };
                let mut canonical = ScriptBuf::new();
                // `push_slice` takes `AsRef<PushBytes>`, which `&[u8]` does
                // not implement; the redeemScript is at most 34 bytes, so the
                // fallible conversion cannot fail.
                let redeem_push = bitcoin::script::PushBytesBuf::try_from(redeem.as_bytes().to_vec())
                    .expect("a wrapped-segwit redeemScript fits a single push");
                canonical.push_slice(redeem_push);
                let ok = script.as_bytes() == canonical.as_bytes();
                if !ok {
                    problems.push(Problem::error(
                        scope.clone(),
                        "final_scriptsig_bad",
                        "final scriptSig of a wrapped-segwit input must push exactly its redeemScript",
                    ));
                }
                if !has_final_witness {
                    problems.push(Problem::error(
                        scope,
                        "final_witness_bad",
                        "wrapped-segwit input has a final scriptSig but no final witness",
                    ));
                }
            }
            return;
        };
        // Legacy P2SH: the last push is the redeem script (its hash was
        // checked at classification); executing the script is out of scope.
        match script_pushes(script) {
            Some(pushes) if pushes.last().is_some_and(|last| *last == *redeem.as_bytes()) => {}
            _ => problems.push(Problem::error(
                scope,
                "final_scriptsig_bad",
                "final scriptSig's last push is not the input's redeemScript",
            )),
        }
        return;
    }
    if !claim_script.is_p2pkh() {
        return; // bare multisig and friends need an interpreter; structure says nothing
    }
    let Some(pushes) = script_pushes(script) else {
        problems.push(Problem::error(
            scope,
            "final_scriptsig_bad",
            "final scriptSig of a P2PKH input is not push-only",
        ));
        return;
    };
    if pushes.len() != 2 {
        problems.push(Problem::error(
            scope,
            "final_scriptsig_bad",
            "final scriptSig of a P2PKH input must be [signature, public key]",
        ));
        return;
    }
    let [sig, pubkey] = [&pushes[0], &pushes[1]];
    if hash160::Hash::hash(pubkey).to_byte_array()[..] != claim_script.as_bytes()[3..23] {
        problems.push(Problem::error(
            scope.clone(),
            "final_scriptsig_bad",
            "final scriptSig public key does not hash to the claimed output's key hash",
        ));
        return;
    }
    if !budget.take(problems) {
        return;
    }
    match check_ecdsa(cache, index, &Spend::Legacy, claim, pubkey, sig, budget, problems, starts_memo) {
        Some(Ok(())) => {}
        Some(Err(why)) => problems.push(Problem::error(scope, "final_scriptsig_bad", format!("final scriptSig {why}"))),
        None => problems.push(Problem::error(scope, "final_scriptsig_bad", "final scriptSig sighash cannot be computed")),
    }
}

/// Final witness (0x08): structure and signature against the claim. P2WPKH is
/// exactly [sig, pubkey] with the pubkey hashing to the program; P2WSH's last
/// item must hash to the program (and equal the declared witnessScript);
/// P2TR is a single key-path signature or a script-path stack whose control
/// block must prove its script under the claimed output key. A final witness
/// spending a proven non-witness output is only a warning (consensus never
/// reads it; policy does).
fn check_final_witness(
    cache: &mut SighashCache<&Transaction>,
    index: usize,
    witness: &Witness,
    spend: &Spend,
    claim: &TxOut,
    prevouts: &Option<Vec<TxOut>>,
    final_script_sig: Option<&[u8]>,
    budget: &mut Budget,
    problems: &mut Vec<Problem>,
    starts_memo: &mut AnalysisMemo<scriptcode::Shape>,
) {
    let scope = format!("input {index}");
    // BIP-141: a P2SH-wrapped witness spend carries the redeem script as the
    // exact single push in scriptSig; a final witness without it extracts an
    // empty scriptSig and is consensus-invalid.
    if matches!(spend, Spend::WrappedP2wpkh(_) | Spend::WrappedP2wsh(..)) && final_script_sig.is_none() {
        problems.push(Problem::error(
            scope.clone(),
            "final_witness_bad",
            "wrapped-segwit input has a final witness but no final scriptSig",
        ));
    }
    let items: Vec<&[u8]> = witness.iter().collect();
    match spend {
        Spend::P2wpkh | Spend::WrappedP2wpkh(_) => {
            let program = match spend {
                Spend::P2wpkh => &claim.script_pubkey.as_bytes()[2..22],
                // Wrapped: the claim is the P2SH wrapper; the program lives
                // in the redeem script.
                Spend::WrappedP2wpkh(redeem) => &redeem.as_bytes()[2..22],
                _ => unreachable!(),
            };
            if items.len() != 2 {
                problems.push(Problem::error(
                    scope,
                    "final_witness_bad",
                    format!("P2WPKH final witness must be [signature, public key], got {} item(s)", items.len()),
                ));
                return;
            }
            // Consensus reads v0 witnesses under no compressed-key rule;
            // compressed keys are a relay/mining policy requirement. Accept
            // 65-byte keys that hash to the program and verify, and name the
            // policy difference rather than refusing a valid spend.
            if items[1].len() != 33 && items[1].len() != 65 {
                problems.push(Problem::error(
                    scope.clone(),
                    "final_witness_bad",
                    "P2WPKH final witness public key must be 33 or 65 bytes",
                ));
                return;
            }
            if items[1].len() == 65 {
                problems.push(Problem::warning(
                    scope.clone(),
                    "witness_pubkey_uncompressed",
                    "P2WPKH final witness uses an uncompressed public key: consensus-valid when it verifies, but non-standard (relay/mining policy)",
                ));
            }
            if hash160::Hash::hash(items[1]).to_byte_array()[..] != program[..] {
                problems.push(Problem::error(
                    scope,
                    "final_witness_bad",
                    "final witness public key does not hash to the claimed output's witness program",
                ));
                return;
            }
            if !budget.take(problems) {
                return;
            }
            match check_ecdsa(cache, index, spend, claim, items[1], items[0], budget, problems, starts_memo) {
                Some(Ok(())) => {}
                Some(Err(why)) => problems.push(Problem::error(scope, "final_witness_bad", format!("final witness {why}"))),
                None => problems.push(Problem::error(scope, "final_witness_bad", "final witness sighash cannot be computed")),
            }
        }
        Spend::P2wsh(declared) | Spend::WrappedP2wsh(_, declared) => {
            let Some((&script_item, _stack)) = items.split_last() else {
                problems.push(Problem::error(scope, "final_witness_bad", "P2WSH final witness is empty"));
                return;
            };
            let program = match spend {
                Spend::P2wsh(_) => &claim.script_pubkey.as_bytes()[2..34],
                Spend::WrappedP2wsh(redeem, _) => &redeem.as_bytes()[2..34],
                _ => unreachable!(),
            };
            if sha256::Hash::hash(script_item).to_byte_array()[..] != program[..] {
                problems.push(Problem::error(
                    scope,
                    "final_witness_bad",
                    "final witness's last item does not hash to the claimed output's witness program",
                ));
                return;
            }
            if declared.as_ref().is_some_and(|ws| ws.as_bytes() != script_item) {
                problems.push(Problem::error(
                    scope,
                    "final_witness_bad",
                    "final witness's script disagrees with the input's witnessScript",
                ));
            }
            // Executing the witness script needs an interpreter, which this
            // crate deliberately does not carry; the hash binding above is
            // the structural part of the check.
        }
        Spend::P2tr(output_key) => {
            // BIP-341: with at least two stack elements, a last element
            // starting with 0x50 is the annex — it comes off the stack but
            // stays in the signature message.
            let (items, annex) = if items.len() >= 2 && items.last().is_some_and(|last| !last.is_empty() && last[0] == 0x50) {
                (&items[..items.len() - 1], Some(items[items.len() - 1]))
            } else {
                (&items[..], None)
            };
            if items.len() == 1 {
                match read_tap_sig(items[0], "final key-path signature") {
                    Err(why) => problems.push(Problem::error(scope, "final_witness_bad", why)),
                    Ok((sig, ty)) if !budget.take(problems) => {
                        let _ = (sig, ty);
                    }
                    Ok((_sig, ty)) if taproot_single_without_output(cache, index, ty) => {
                        problems.push(Problem::error(
                            scope,
                            "final_witness_bad",
                            "final key-path signature uses SIGHASH_SINGLE with no corresponding output, which BIP-341 rejects",
                        ));
                    }
                    Ok((sig, ty)) => match taproot_sighash_key_spend(cache, index, prevouts, annex, ty) {
                        Some(digest) => {
                            if let Err(why) = check_schnorr(digest, &sig, output_key) {
                                problems.push(Problem::error(scope, "final_witness_bad", format!("final {why}")));
                            }
                        }
                        None => problems.push(Problem::error(
                            scope,
                            "final_witness_bad",
                            "final key-path signature's sighash cannot be computed from the declared UTXOs",
                        )),
                    },
                }
                return;
            }
            if items.len() < 2 {
                problems.push(Problem::error(scope, "final_witness_bad", "taproot final witness is empty"));
                return;
            }
            let (control, rest) = items.split_last().unwrap();
            let script = Script::from_bytes(rest.last().unwrap());
            let control = match ControlBlock::decode(control) {
                Ok(control) => control,
                Err(_) => {
                    problems.push(Problem::error(scope, "final_witness_bad", "taproot control block does not decode"));
                    return;
                }
            };
            // This crate understands 0xc0 tapscript only: a future leaf version
            // executes under rules it cannot check, so its script-path signature
            // would pass unvetted. Refuse rather than vouch for it.
            if control.leaf_version != LeafVersion::TapScript {
                problems.push(Problem::error(
                    scope,
                    "final_witness_bad",
                    "taproot control block commits to a leaf version whose script this tool cannot check",
                ));
                return;
            }
            if !control.verify_taproot_commitment(&Secp256k1::verification_only(), *output_key, script) {
                problems.push(Problem::error(
                    scope,
                    "final_witness_bad",
                    "taproot control block does not prove its script under the claimed output key",
                ));
            }
            // Script-path stack execution needs an interpreter; the
            // commitment above is the checkable part.
        }
        // No claim, an unclassifiable one, or a future witness version:
        // nothing to check against.
        Spend::Unknown | Spend::UnknownWitness => {}
        legacy => {
            if !legacy.is_witness() {
                problems.push(Problem::warning(
                    scope,
                    "final_witness_on_legacy",
                    "final witness on an input spending a non-witness output — never read by consensus, non-standard",
                ));
            }
        }
    }
}

/// One input's UTXO declarations resolved to claims, with the disagreements
/// reported as problems. Returns the claim to classify and verify against
/// (None on conflict — no verdict can rest on a disputed output).
fn input_claims(
    tx: &Transaction,
    index: usize,
    map: &[RawPair],
    problems: &mut Vec<Problem>,
) -> (Option<TxOut>, Option<TxOut>) {
    let scope = format!("input {index}");
    let mut witness_claim = None;
    let mut non_witness_claim = None;
    for pair in map {
        match pair.key.as_slice() {
            [0x01] => witness_claim = pair_utxo_claim(pair, tx, index),
            [0x00] => {
                // A non-witness UTXO whose txid is not the input's prevout is
                // not merely useless: BIP-174 makes it an invalid PSBT (the
                // signer's first check fails).
                if let Ok(prev) = Transaction::consensus_decode(&mut &pair.value[..]) {
                    if encode::serialize(&prev) == pair.value {
                        // Callers guarantee one map per transaction input;
                        // stay defensive anyway — this is a gate.
                        let Some(input) = tx.input.get(index) else { continue };
                        if input.previous_output.txid != prev.compute_txid() {
                            problems.push(Problem::error(
                                scope.clone(),
                                "nonwitness_txid_mismatch",
                                "non-witness UTXO's txid does not match the input's prevout — the PSBT is invalid per BIP-174",
                            ));
                        }
                    }
                }
                non_witness_claim = pair_utxo_claim(pair, tx, index);
            }
            _ => {}
        }
    }
    if let (Some(wit), Some(non)) = (&witness_claim, &non_witness_claim) {
        if wit.value != non.value || wit.script_pubkey != non.script_pubkey {
            problems.push(Problem::error(
                scope,
                "utxo_claim_conflict",
                format!(
                    "witness UTXO ({} sats) and non-witness UTXO ({} sats) claim different previous outputs",
                    wit.value.to_sat(),
                    non.value.to_sat()
                ),
            ));
            return (None, None);
        }
    }
    (witness_claim, non_witness_claim)
}

/// Every consensus-level and BIP-174-level problem with the PSBT, as a flat
/// list ordered transaction-first then by input. `prevouts` for taproot
/// sighashes is assembled once from all inputs' claims.
pub(crate) fn analyze(tx: &Transaction, inputs: &[Vec<RawPair>]) -> Vec<Problem> {
    let mut problems = Vec::new();
    if let Some(reason) = tx_sanity_error(tx) {
        problems.push(Problem::error(
            "transaction".into(),
            "tx_consensus",
            format!("unsigned transaction is consensus-invalid: {reason}"),
        ));
    }

    // First pass: claims and their disagreements.
    let claims: Vec<(Option<TxOut>, Option<TxOut>)> = inputs
        .iter()
        .enumerate()
        .map(|(index, map)| input_claims(tx, index, map, &mut problems))
        .collect();

    // The taproot prevout set: every input's claim, or nothing (BIP-341
    // commits to all of them).
    let all_claims: Option<Vec<TxOut>> = claims
        .iter()
        .map(|(wit, non)| wit.clone().or_else(|| non.clone()))
        .collect();

    let mut cache = SighashCache::new(tx);
    let mut budget = Budget::new();
    let mut starts_memo = AnalysisMemo { script: None, result: None };
    let mut tap_memo = TapscriptMemo::new();
    for (index, map) in inputs.iter().enumerate() {
        let scope = format!("input {index}");
        let (witness_claim, non_witness_claim) = &claims[index];
        let claim = witness_claim.clone().or_else(|| non_witness_claim.clone());
        let Some(claim) = claim else { continue }; // no claim: the fee line already says "unknown"
        if claim.script_pubkey.is_op_return() {
            problems.push(Problem::error(
                scope.clone(),
                "unspendable_prevout",
                "spends an OP_RETURN output, which is provably unspendable",
            ));
            continue;
        }
        let spend = classify(index, map, &claim, &mut problems);
        if spend.is_witness() && witness_claim.is_none() {
            problems.push(Problem::warning(
                scope.clone(),
                "missing_witness_utxo",
                "segwit input carries no witness UTXO — a signer needs it to verify the spent amount (BIP-174)",
            ));
        }
        if !spend.is_witness() && !matches!(spend, Spend::Unknown) {
            if non_witness_claim.is_none() {
                problems.push(Problem::warning(
                    scope.clone(),
                    "missing_nonwitness_utxo",
                    "non-witness input carries only a witness UTXO claim — BIP-174 expects the full previous transaction here (fee-attack exposure)",
                ));
            }
            if witness_claim.is_some() {
                problems.push(Problem::error(
                    scope.clone(),
                    "witness_utxo_on_legacy",
                    "witness UTXO declared for a non-witness input — BIP-174 forbids creating a non-witness signature against it",
                ));
            }
        }
        // The declared sighash policy: non-standard values are legal for a
        // signer to refuse, so they are named, not gated.
        if let Some(value) = input_field(map, 0x03) {
            if value.len() == 4 {
                let n = u32::from_le_bytes(value.try_into().unwrap());
                let standard = if matches!(spend, Spend::P2tr(_)) {
                    u8::try_from(n).is_ok_and(|byte| TapSighashType::from_consensus_u8(byte).is_ok())
                } else {
                    EcdsaSighashType::from_standard(n).is_ok()
                };
                if !standard {
                    problems.push(Problem::warning(
                        scope.clone(),
                        "sighash_nonstandard",
                        format!("PSBT_IN_SIGHASH_TYPE declares non-standard sighash type 0x{n:02x}"),
                    ));
                }
            }
        }
        let sighash_field = input_field(map, 0x03)
            .filter(|value| value.len() == 4)
            .map(|value| u32::from_le_bytes(value.try_into().unwrap()));
        check_partial_sigs(&mut cache, index, map, &spend, &claim, sighash_field, &mut budget, &mut problems, &mut starts_memo);
        check_tap_sigs(&mut cache, index, map, &spend, &all_claims, &mut budget, &mut problems, &mut tap_memo);
        let final_witness = input_field(map, 0x08).and_then(|value| Witness::consensus_decode(&mut &value[..]).ok());
        let final_script_sig = input_field(map, 0x07);
        if let Some(value) = final_script_sig {
            check_final_scriptsig(&mut cache, index, value, &spend, &claim, final_witness.is_some(), &mut budget, &mut problems, &mut starts_memo);
        }
        if let Some(witness) = &final_witness {
            check_final_witness(&mut cache, index, witness, &spend, &claim, &all_claims, final_script_sig, &mut budget, &mut problems, &mut starts_memo);
        }
    }
    problems
}

/// The build gate: the error-severity problems of an about-to-be-built
/// document, as one rejection message. The transaction-sanity wording is the
/// historical gate message (tests and the UI match it); other violations
/// name themselves. Not called at all under insane editing.
pub(crate) fn gate_error(tx: &Transaction, inputs: &[Vec<RawPair>]) -> Option<String> {
    let problems = analyze(tx, inputs);
    let errors: Vec<&Problem> = problems.iter().filter(|p| p.severity == ERROR).collect();
    if errors.is_empty() {
        return None;
    }
    if errors[0].code == "tx_consensus" {
        let mut message = errors[0].message.clone();
        if errors.len() > 1 {
            message.push_str(&format!(" (and {} more problem{})", errors.len() - 1, if errors.len() > 2 { "s" } else { "" }));
        }
        return Some(message);
    }
    let listed = errors
        .iter()
        .take(3)
        .map(|p| format!("{}: {}", p.scope, p.message))
        .collect::<Vec<_>>()
        .join("; ");
    let more = if errors.len() > 3 { format!(" (and {} more)", errors.len() - 3) } else { String::new() };
    Some(format!("the edit fails Bitcoin consensus/PSBT checks — {listed}{more}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::SecretKey;
    use bitcoin::{OutPoint, Sequence, TxIn, Txid};

    fn hex(text: &str) -> Vec<u8> {
        crate::hex_decode(text).unwrap()
    }

    fn pair(key: &str, value: &str) -> RawPair {
        RawPair { key: hex(key), value: hex(value) }
    }

    /// Bitcoin Core's src/test/data/sighash.json (v31.1, copied verbatim to
    /// test/fixtures/core/): 500 legacy digests over random transactions,
    /// scripts (210 with OP_CODESEPARATOR opcodes) and 32-bit hash types.
    /// Core's SignatureHash takes the scriptCode as given and skips its
    /// separators when serializing; the verifier's legacy digest must be that
    /// function, fed the stripped code it hashes with.
    #[test]
    fn legacy_digests_match_bitcoin_core_sighash_json() {
        let vectors: serde_json::Value =
            serde_json::from_str(include_str!("../../test/fixtures/core/sighash.json")).unwrap();
        let vectors = vectors.as_array().unwrap();
        assert_eq!(vectors.len(), 501, "a header row and 500 vectors");
        let mut with_separators = 0;
        for (n, vector) in vectors.iter().skip(1).enumerate() {
            let [tx, script, index, hash_type, expected] = vector.as_array().unwrap().as_slice() else { panic!("vector {n}") };
            let tx: Transaction = encode::deserialize(&hex(tx.as_str().unwrap())).unwrap();
            let script = hex(script.as_str().unwrap());
            let index = index.as_u64().unwrap() as usize;
            let hash_type = hash_type.as_i64().unwrap() as i32 as u32;
            let mut expected = hex(expected.as_str().unwrap());
            expected.reverse(); // Core prints uint256 byte-reversed
            assert!(matches!(scriptcode::code_starts(&script), scriptcode::Shape::Starts(_) | scriptcode::Shape::Unbalanced), "vector {n} parses");
            let code = scriptcode::strip_codeseparators(&script);
            if code.len() < script.len() {
                with_separators += 1;
            }
            let mut cache = SighashCache::new(&tx);
            let digest = ecdsa_digest(&mut cache, index, SigVersion::Legacy, &code, Amount::ZERO, hash_type).unwrap();
            assert_eq!(digest.to_vec(), expected, "sighash.json vector {n}");
        }
        assert_eq!(with_separators, 210);
    }

    /// BIP-143's own examples (native P2WPKH SIGHASH_ALL, P2SH-P2WSH 6-of-6
    /// with all six types), as digests: ecdsa_digest's typed-then-patched
    /// preimage must equal the published sighash for every defined type.
    #[test]
    fn witness_v0_digests_match_bip143_examples() {
        // BIP-143 "Native P2WPKH": input 1, scriptCode for key hash
        // 1d0f172a0ecb48aee1be1f2687d2963ae33f71a1, 6 BTC, SIGHASH_ALL.
        let tx: Transaction = encode::deserialize(&hex("0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f0000000000eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac11000000")).unwrap();
        let code = hex("76a9141d0f172a0ecb48aee1be1f2687d2963ae33f71a188ac");
        let mut cache = SighashCache::new(&tx);
        let digest = ecdsa_digest(&mut cache, 1, SigVersion::WitnessV0, &code, Amount::from_sat(600_000_000), 0x01).unwrap();
        assert_eq!(crate::hex_encode(&digest), "c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670");
        // BIP-143 "P2SH-P2WSH": 6-of-6, 987654321 sats, one digest per type.
        let tx: Transaction = encode::deserialize(&hex("010000000136641869ca081e70f394c6948e8af409e18b619df2ed74aa106c1ca29787b96e0100000000ffffffff0200e9a435000000001976a914389ffce9cd9ae88dcc0631e88a821ffdbe9bfe2688acc0832f05000000001976a9147480a33f950689af511e6e84c138dbbd3c3ee41588ac00000000")).unwrap();
        let code = hex("56210307b8ae49ac90a048e9b53357a2354b3334e9c8bee813ecb98e99a7e07e8c3ba32103b28f0c28bfab54554ae8c658ac5c3e0ce6e79ad336331f78c428dd43eea8449b21034b8113d703413d57761b8b9781957b8c0ac1dfe69f492580ca4195f50376ba4a21033400f6afecb833092a9a21cfdf1ed1376e58c5d1f47de74683123987e967a8f42103a6d48b1131e94ba04d9737d61acdaa1322008af9602b3b14862c07a1789aac162102d8b661b0b3302ee2f162b09e07a55ad5dfbe673a9f01d9f0c19617681024306b56ae");
        for (hash_type, expected) in [
            (0x01, "185c0be5263dce5b4bb50a047973c1b6272bfbd0103a89444597dc40b248ee7c"),
            (0x02, "e9733bc60ea13c95c6527066bb975a2ff29a925e80aa14c213f686cbae5d2f36"),
            (0x03, "1e1f1c303dc025bd664acb72e583e933fae4cff9148bf78c157d1e8f78530aea"),
            (0x81, "2a67f03e63a6a422125878b40b82da593be8d4efaafe88ee528af6e5a9955c6e"),
            (0x82, "781ba15f3779d5542ce8ecb5c18716733a5ee42a6f51488ec96154934e2c890a"),
            (0x83, "511e8e52ed574121fc1b654970395502128263f62662e076dc6baf05c2e6a99b"),
        ] {
            let mut cache = SighashCache::new(&tx);
            let digest = ecdsa_digest(&mut cache, 0, SigVersion::WitnessV0, &code, Amount::from_sat(987_654_321), hash_type).unwrap();
            assert_eq!(crate::hex_encode(&digest), expected, "hash type 0x{hash_type:02x}");
        }
    }

    // A one-input transaction spending a made-up prevout, paying 1000 sats
    // to OP_TRUE. `claim` is the TxOut the prevout is claimed to hold.
    fn fixture() -> (Transaction, TxOut) {
        let key = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let secp = Secp256k1::new();
        let pubkey = bitcoin::PublicKey::new(key.public_key(&secp));
        let claim = TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: ScriptBuf::new_p2pkh(&pubkey.pubkey_hash()),
        };
        let tx = Transaction {
            version: bitcoin::transaction::Version(2),
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint { txid: Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array([0x11; 32])), vout: 0 },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut { value: Amount::from_sat(1000), script_pubkey: ScriptBuf::from_bytes(vec![0x51]) }],
        };
        (tx, claim)
    }

    // The witness-UTXO pair value for a TxOut: 8-byte LE amount + script.
    fn witness_utxo_value(out: &TxOut) -> String {
        let mut bytes = out.value.to_sat().to_le_bytes().to_vec();
        bytes.push(out.script_pubkey.as_bytes().len() as u8);
        bytes.extend_from_slice(out.script_pubkey.as_bytes());
        hex_encode(&bytes)
    }

    // A previous transaction paying `claim`, for non-witness UTXO pairs;
    // returns it and its txid so the spending tx can point at it.
    fn prev_tx_for(claim: &TxOut) -> (Transaction, Txid) {
        let prev = Transaction {
            version: bitcoin::transaction::Version(2),
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint { txid: Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array([0x99; 32])), vout: 0 },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![claim.clone()],
        };
        let txid = prev.compute_txid();
        (prev, txid)
    }

    #[test]
    fn clean_p2pkh_claim_yields_no_problems() {
        let (tx, claim) = fixture();
        let (prev, txid) = prev_tx_for(&claim);
        let mut tx = tx;
        tx.input[0].previous_output.txid = txid;
        let map = vec![pair("00", &hex_encode(&encode::serialize(&prev)))];
        let problems = analyze(&tx, &[map]);
        assert_eq!(problems.len(), 0, "{problems:?}");
    }

    #[test]
    fn witness_utxo_on_a_legacy_spend_is_an_error() {
        let (tx, claim) = fixture();
        // A witness UTXO whose script is P2PKH is BIP-174's "witness UTXO
        // provided for a non-witness input" case: signer checks fail.
        let problems = analyze(&tx, &[vec![pair("01", &witness_utxo_value(&claim))]]);
        assert!(problems.iter().any(|p| p.code == "missing_nonwitness_utxo" && p.severity == WARNING));
        assert!(problems.iter().any(|p| p.code == "witness_utxo_on_legacy" && p.severity == ERROR));
        assert!(gate_error(&tx, &[vec![pair("01", &witness_utxo_value(&claim))]]).is_some());
    }

    #[test]
    fn conflicting_utxo_claims_are_an_error() {
        let (tx, claim) = fixture();
        let mut other = claim.clone();
        other.value = Amount::from_sat(60_000);
        // The non-witness claim embeds a previous transaction paying the
        // *other* amount; the spending tx points at it.
        let (prev, txid) = prev_tx_for(&other);
        let mut tx = tx;
        tx.input[0].previous_output.txid = txid;
        let map = vec![pair("01", &witness_utxo_value(&claim)), pair("00", &hex_encode(&encode::serialize(&prev)))];
        let problems = analyze(&tx, &[map]);
        assert!(problems.iter().any(|p| p.code == "utxo_claim_conflict" && p.severity == ERROR));
    }

    #[test]
    fn nonwitness_utxo_txid_mismatch_is_an_error() {
        let (tx, claim) = fixture();
        let (prev, _txid) = prev_tx_for(&claim);
        // tx still points at [0x11; 32]:0, prev hashes to something else.
        let map = || vec![pair("00", &hex_encode(&encode::serialize(&prev)))];
        let problems = analyze(&tx, &[map()]);
        assert!(problems.iter().any(|p| p.code == "nonwitness_txid_mismatch" && p.severity == ERROR));
        assert!(gate_error(&tx, &[map()]).is_some());
    }

    /// A signature over `code` (already the serialized scriptCode) with key
    /// [1; 32], its hash type byte appended.
    fn sign_code(tx: &Transaction, code: &[u8], hash_type: u32) -> (Vec<u8>, Vec<u8>) {
        let secp = Secp256k1::new();
        let key = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let mut cache = SighashCache::new(tx);
        let digest = ecdsa_digest(&mut cache, 0, SigVersion::Legacy, code, Amount::ZERO, hash_type).unwrap();
        let mut sig = secp.sign_ecdsa(&Message::from_digest_slice(&digest).unwrap(), &key).serialize_der().to_vec();
        sig.push(hash_type as u8);
        (key.public_key(&secp).serialize().to_vec(), sig)
    }

    // IF CODESEPARATOR CODESEPARATOR ENDIF <K> CHECKSIG: three starts, two
    // of which (past either separator) serialize to the same scriptCode.
    fn three_starts_two_codes(pubkey: &[u8]) -> TxOut {
        let script = [&[0x63, 0xab, 0xab, 0x68, 0x21][..], pubkey, &[0xac]].concat();
        TxOut { value: Amount::from_sat(50_000), script_pubkey: ScriptBuf::from_bytes(script) }
    }

    #[test]
    fn each_distinct_candidate_takes_one_budget_unit_and_duplicates_none() {
        let (tx, _) = fixture();
        let (pubkey, _) = sign_code(&tx, &[], 1);
        let claim = three_starts_two_codes(&pubkey);
        // Signed over a code no start produces: every candidate is tried.
        let (_, sig) = sign_code(&tx, &[0xac], 1);
        let mut budget = Budget { left: 10, ..Budget::new() };
        let mut problems = Vec::new();
        let mut cache = SighashCache::new(&tx);
        let mut memo = AnalysisMemo { script: None, result: None };
        let verdict = check_ecdsa(&mut cache, 0, &Spend::Legacy, &claim, &pubkey, &sig, &mut budget, &mut problems, &mut memo);
        assert!(matches!(verdict, Some(Err(_))), "{verdict:?}");
        // The caller paid for the first digest; the second distinct code costs
        // one more; the third start repeats the second and costs nothing.
        assert_eq!(budget.left, 9);
        assert!(problems.is_empty());
    }

    #[test]
    fn running_out_between_candidates_accuses_nothing_and_fails_closed() {
        let (tx, _) = fixture();
        let (pubkey, _) = sign_code(&tx, &[], 1);
        let claim = three_starts_two_codes(&pubkey);
        let past_separator = [&[0x68, 0x21][..], &pubkey, &[0xac]].concat();
        let whole = [&[0x63, 0x68, 0x21][..], &pubkey, &[0xac]].concat();
        // Valid only for the second candidate, with no budget left for it.
        let (_, sig) = sign_code(&tx, &past_separator, 1);
        let mut budget = Budget { left: 0, ..Budget::new() };
        let mut problems = Vec::new();
        let mut cache = SighashCache::new(&tx);
        let mut memo = AnalysisMemo { script: None, result: None };
        assert_eq!(check_ecdsa(&mut cache, 0, &Spend::Legacy, &claim, &pubkey, &sig, &mut budget, &mut problems, &mut memo), None);
        assert!(problems.iter().any(|p| p.code == "verification_budget" && p.severity == ERROR), "{problems:?}");
        // Valid for the first candidate: verified without touching the budget.
        let (_, sig) = sign_code(&tx, &whole, 1);
        let mut problems = Vec::new();
        let mut budget = Budget { left: 0, ..Budget::new() };
        let mut memo = AnalysisMemo { script: None, result: None };
        assert_eq!(check_ecdsa(&mut cache, 0, &Spend::Legacy, &claim, &pubkey, &sig, &mut budget, &mut problems, &mut memo), Some(Ok(())));
        assert!(problems.is_empty());
    }

    #[test]
    fn a_script_core_can_never_run_is_refused_before_separator_accounting() {
        // 400 IF CODESEPARATOR ENDIF blocks before one CHECKSIG: 1201 opcodes
        // above OP_16 — past MAX_OPS_PER_SCRIPT, so EvalScript fails the
        // script on any path before any of the separators is reached. The
        // signature is moot and gets the never-executes verdict at once;
        // the budget is untouched.
        let (tx, _) = fixture();
        let (pubkey, sig) = sign_code(&tx, &[0xac], 1);
        let mut script: Vec<u8> = std::iter::repeat([0x63, 0xab, 0x68]).take(400).flatten().collect();
        script.push(0x21);
        script.extend_from_slice(&pubkey);
        script.push(0xac);
        let claim = TxOut { value: Amount::from_sat(1), script_pubkey: ScriptBuf::from_bytes(script) };
        let map = vec![pair(&format!("02{}", hex_encode(&pubkey)), &hex_encode(&sig))];
        let mut problems = Vec::new();
        let mut budget = Budget::new();
        let mut cache = SighashCache::new(&tx);
        let mut memo = AnalysisMemo { script: None, result: None };
        check_partial_sigs(&mut cache, 0, &map, &Spend::Legacy, &claim, None, &mut budget, &mut problems, &mut memo);
        assert_eq!(budget.left, MAX_SIGNATURE_CHECKS - 1, "{problems:?}");
        let [problem] = problems.as_slice() else { panic!("{problems:?}") };
        assert_eq!(problem.code, "partial_sig_invalid");
        assert!(problem.message.contains("never executes"), "{problem:?}");
        // Inside the limits the same shape verifies as before: 60 blocks.
        let mut script: Vec<u8> = std::iter::repeat([0x63, 0xab, 0x68]).take(60).flatten().collect();
        script.push(0x21);
        script.extend_from_slice(&pubkey);
        script.push(0xac);
        let claim = TxOut { value: Amount::from_sat(1), script_pubkey: ScriptBuf::from_bytes(script) };
        let mut problems = Vec::new();
        let mut memo = AnalysisMemo { script: None, result: None };
        check_partial_sigs(&mut cache, 0, &map, &Spend::Legacy, &claim, None, &mut budget, &mut problems, &mut memo);
        let [problem] = problems.as_slice() else { panic!("{problems:?}") };
        assert_eq!(problem.code, "partial_sig_invalid");
        assert!(!problem.message.contains("never executes"), "{problem:?}");
    }

    /// More candidate separator positions than the budget can ever reach: the
    /// prefix still verifies a signature that commits to it, and one that
    /// does not is reported unchecked (fail closed), never invalid.
    #[test]
    fn tapscript_positions_past_budget_reach_are_incomplete_not_invalid() {
        use bitcoin::taproot::{LeafVersion, TapLeafHash};
        let secp = Secp256k1::new();
        let keypair = secp256k1::Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[1u8; 32]).unwrap());
        let (xonly, _parity) = keypair.x_only_public_key();
        // 300 IF CODESEPARATOR ELSE ENDIF blocks: each adds its separator to
        // the candidates (the empty arm keeps the entry set), 301 in all —
        // more than the budget can reach. Block j's separator sits at opcode
        // position 4*j + 1.
        let mut leaf = Vec::new();
        for _ in 0..300 {
            leaf.extend_from_slice(&[0x63, 0xab, 0x67, 0x68]);
        }
        leaf.extend_from_slice(&[0x20]);
        leaf.extend_from_slice(&xonly.serialize());
        leaf.push(0xac);
        let leaf_hash = TapLeafHash::from_script(Script::from_bytes(&leaf), LeafVersion::TapScript);
        let claim = TxOut { value: Amount::from_sat(50_000), script_pubkey: ScriptBuf::new_p2tr(&secp, xonly, None) };
        let (tx, _) = fixture();
        let prevouts = vec![claim.clone()];
        let sign_at = |position: u32| {
            let mut cache = SighashCache::new(&tx);
            let digest = taproot_sighash_script_spend(&mut cache, 0, &Some(prevouts.clone()), leaf_hash, position, TapSighashType::Default).unwrap();
            secp.sign_schnorr_no_aux_rand(&Message::from_digest_slice(&digest).unwrap(), &keypair).serialize().to_vec()
        };
        let map_for = |sig: &[u8]| {
            let mut key = hex_encode(&[0x14]);
            key.push_str(&hex_encode(&xonly.serialize()));
            key.push_str(&hex_encode(&leaf_hash.to_byte_array()));
            let mut leaf_with_version = leaf.clone();
            leaf_with_version.push(0xc0);
            vec![pair("01", &witness_utxo_value(&claim)), pair("15", &hex_encode(&leaf_with_version)), pair(&key, &hex_encode(sig))]
        };
        // A signature at a position inside the prefix (block 5's separator,
        // opcode position 21) still verifies, with no incomplete report.
        let problems = analyze(&tx, &[map_for(&sign_at(4 * 5 + 1))]);
        assert!(problems.is_empty(), "{problems:?}");
        // One at a position past the prefix (block 280's separator): correct
        // under the script but unreachable within budget — unchecked, an
        // error, and never named invalid.
        let problems = analyze(&tx, &[map_for(&sign_at(4 * 280 + 1))]);
        assert!(!problems.iter().any(|p| p.code == "tap_sig_invalid"), "{problems:?}");
        assert!(problems.iter().any(|p| p.code == "verification_incomplete" && p.severity == ERROR), "{problems:?}");
        // A junk signature: budget cost is capped at MAX_SIGNATURE_CHECKS
        // however many candidates the script offers.
        let mut junk = sign_at(0);
        junk[10] ^= 1;
        let problems = analyze(&tx, &[map_for(&junk)]);
        assert!(!problems.iter().any(|p| p.code == "tap_sig_invalid"), "unchecked is not invalid: {problems:?}");
        assert!(problems.iter().any(|p| p.code == "verification_incomplete" && p.severity == ERROR), "{problems:?}");
    }

    #[test]
    fn a_valid_legacy_partial_signature_passes_and_a_flipped_one_is_named() {
        let (tx, claim) = fixture();
        let secp = Secp256k1::new();
        let key = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let pubkey = bitcoin::PublicKey::new(key.public_key(&secp));
        let cache = SighashCache::new(&tx);
        let sighash = cache
            .legacy_signature_hash(0, &claim.script_pubkey, EcdsaSighashType::All.to_u32())
            .unwrap();
        let message = Message::from_digest_slice(&sighash.to_byte_array()).unwrap();
        let sig = secp.sign_ecdsa(&message, &key);
        let mut value = sig.serialize_der().to_vec();
        value.push(0x01);
        let key_hex = hex_encode(&pubkey.to_bytes());
        let good = vec![pair(&format!("02{key_hex}"), &hex_encode(&value))];
        let problems = analyze(&tx, &[good]);
        assert!(!problems.iter().any(|p| p.code == "partial_sig_invalid"), "{problems:?}");
        // Flip one byte of r: DER stays well-formed, verification fails.
        let mut bad = value.clone();
        bad[5] ^= 1;
        let badmap = vec![pair("01", &witness_utxo_value(&claim)), pair(&format!("02{key_hex}"), &hex_encode(&bad))];
        let problems = analyze(&tx, &[badmap]);
        assert!(problems.iter().any(|p| p.code == "partial_sig_invalid" && p.severity == WARNING));
    }

    #[test]
    fn a_valid_p2wpkh_final_witness_passes_and_a_wrong_key_is_an_error() {
        let secp = Secp256k1::new();
        let key = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let pubkey = bitcoin::PublicKey::new(key.public_key(&secp));
        let (tx, _) = fixture();
        let claim = TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: ScriptBuf::new_p2wpkh(&pubkey.wpubkey_hash().unwrap()),
        };
        let mut cache = SighashCache::new(&tx);
        let sighash = cache
            .p2wpkh_signature_hash(0, &claim.script_pubkey, claim.value, EcdsaSighashType::All)
            .unwrap();
        let message = Message::from_digest_slice(&sighash.to_byte_array()).unwrap();
        let sig = secp.sign_ecdsa(&message, &key);
        let mut sig_bytes = sig.serialize_der().to_vec();
        sig_bytes.push(0x01);
        let witness = Witness::from_slice(&[sig_bytes, pubkey.to_bytes()]);
        let map = vec![
            pair("01", &witness_utxo_value(&claim)),
            pair("08", &hex_encode(&encode::serialize(&witness))),
        ];
        let problems = analyze(&tx, &[map]);
        assert!(problems.is_empty(), "{problems:?}");

        // Same witness against a different key's program: must be named.
        let other_key = SecretKey::from_slice(&[2u8; 32]).unwrap();
        let other_claim = TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: ScriptBuf::new_p2wpkh(&bitcoin::PublicKey::new(other_key.public_key(&secp)).wpubkey_hash().unwrap()),
        };
        let badmap = || {
            vec![
                pair("01", &witness_utxo_value(&other_claim)),
                pair("08", &hex_encode(&encode::serialize(&witness))),
            ]
        };
        let problems = analyze(&tx, &[badmap()]);
        assert!(problems.iter().any(|p| p.code == "final_witness_bad" && p.severity == ERROR));
        assert!(gate_error(&tx, &[badmap()]).is_some());
    }

    /// An uncompressed key in a v0 witness is consensus-valid when it hashes
    /// to the program and its signature verifies; compressed-only is relay
    /// policy. It must be a warning, not an error that blocks export.
    #[test]
    fn an_uncompressed_p2wpkh_final_witness_verifies_with_a_policy_warning() {
        let secp = Secp256k1::new();
        let key = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let pubkey = bitcoin::PublicKey::new_uncompressed(key.public_key(&secp));
        let (tx, _) = fixture();
        let claim = TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::hash(&pubkey.to_bytes())),
        };
        let mut cache = SighashCache::new(&tx);
        let sighash = cache
            .p2wpkh_signature_hash(0, &claim.script_pubkey, claim.value, EcdsaSighashType::All)
            .unwrap();
        let message = Message::from_digest_slice(&sighash.to_byte_array()).unwrap();
        let sig = secp.sign_ecdsa(&message, &key);
        let mut sig_bytes = sig.serialize_der().to_vec();
        sig_bytes.push(0x01);
        let witness = Witness::from_slice(&[sig_bytes.clone(), pubkey.to_bytes()]);
        let map = vec![
            pair("01", &witness_utxo_value(&claim)),
            pair("08", &hex_encode(&encode::serialize(&witness))),
        ];
        let problems = analyze(&tx, &[map]);
        assert!(!problems.iter().any(|p| p.severity == ERROR), "{problems:?}");
        assert!(
            problems.iter().any(|p| p.code == "witness_pubkey_uncompressed" && p.severity == WARNING),
            "{problems:?}"
        );
        assert!(gate_error(&tx, &[vec![pair("01", &witness_utxo_value(&claim)), pair("08", &hex_encode(&encode::serialize(&witness)))]]).is_none());

        // A key that is neither compressed nor uncompressed is malformed.
        let bad = Witness::from_slice(&[sig_bytes, vec![2u8; 32]]);
        let badmap = vec![
            pair("01", &witness_utxo_value(&claim)),
            pair("08", &hex_encode(&encode::serialize(&bad))),
        ];
        let problems = analyze(&tx, &[badmap]);
        assert!(problems.iter().any(|p| p.code == "final_witness_bad" && p.severity == ERROR), "{problems:?}");
    }

    /// An *empty* final scriptSig is also the native-segwit not-yet-finalized
    /// state: BIP-141 spends a native witness program with an empty scriptSig,
    /// so the unsigned transaction is byte-identical whether the map omits 0x07
    /// or carries it empty, and the gate must treat those alike. A non-empty
    /// one is still a consensus error.
    #[test]
    fn an_empty_native_witness_final_scriptsig_is_not_a_consensus_error() {
        let secp = Secp256k1::new();
        let key = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let pubkey = bitcoin::PublicKey::new(key.public_key(&secp));
        let (tx, _) = fixture();
        let claim = TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: ScriptBuf::new_p2wpkh(&pubkey.wpubkey_hash().unwrap()),
        };
        let empty = || vec![pair("01", &witness_utxo_value(&claim)), pair("07", "")];
        let problems = analyze(&tx, &[empty()]);
        assert!(problems.is_empty(), "{problems:?}");
        assert!(gate_error(&tx, &[empty()]).is_none());

        let nonempty = vec![pair("01", &witness_utxo_value(&claim)), pair("07", "51")];
        let problems = analyze(&tx, &[nonempty]);
        assert!(problems.iter().any(|p| p.code == "final_scriptsig_bad" && p.severity == ERROR), "{problems:?}");
    }

    /// A partial signature on a P2WSH input without PSBT_IN_WITNESS_SCRIPT has
    /// no scriptCode to hash; it must be named unchecked, not pass silently.
    #[test]
    fn a_partial_sig_without_a_witness_script_is_reported_unchecked() {
        let secp = Secp256k1::new();
        let key = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let pubkey = bitcoin::PublicKey::new(key.public_key(&secp));
        let script = ScriptBuf::from_bytes(vec![0x51]);
        let claim = TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: ScriptBuf::new_p2wsh(&script.wscript_hash()),
        };
        let (tx, _) = fixture();
        let map = vec![
            pair("01", &witness_utxo_value(&claim)),
            pair(&format!("02{}", hex_encode(&pubkey.to_bytes())), &hex_encode(&[0u8; 71])),
        ];
        let problems = analyze(&tx, &[map]);
        assert!(
            problems.iter().any(|p| p.code == "partial_sig_unchecked" && p.severity == WARNING),
            "{problems:?}"
        );
    }

    /// Legacy hashing is charged at every digest, so a multisig
    /// companion explosion cannot spend one signature unit per hash. The
    /// digest budget is separate from the signature-count budget and notes
    /// exhaustion once.
    #[test]
    fn the_digest_budget_charges_every_legacy_digest() {
        let mut problems = Vec::new();
        let mut budget = Budget { digest_left: 3_000, ..Budget::new() };
        assert!(budget.take_digest(1_000, &mut problems));
        assert_eq!(budget.digest_left, 2_000);
        assert!(budget.take_digest(2_000, &mut problems));
        assert_eq!(budget.digest_left, 0);
        assert!(!budget.take_digest(1, &mut problems));
        assert_eq!(problems.len(), 1);
        assert_eq!(problems[0].code, "verification_budget");
        assert!(!budget.take_digest(1, &mut problems));
        assert_eq!(problems.len(), 1, "exhaustion is noted once");
        // The signature-count budget is untouched by digest work.
        assert_eq!(budget.left, MAX_SIGNATURE_CHECKS);
    }

    /// An ordinary consolidation must not hit the digest budget: the largest
    /// realistic transaction (100 inputs, ~4 KiB unsigned) with all 256
    /// signatures checked stays well under it. This is the arithmetic guard;
    /// the signed hundred-input fixture below exercises the same claim through
    /// verification (AR-11).
    #[test]
    fn an_ordinary_consolidation_stays_inside_the_digest_budget() {
        let per_digest = 4 * 1024;
        assert!(
            MAX_SIGNATURE_CHECKS * per_digest < MAX_LEGACY_DIGEST_BYTES,
            "the digest budget must admit a 100-input, 256-signature consolidation"
        );
    }

    /// The maximum legacy multisig companion set produces 2^8 candidate
    /// scriptCodes for one signature. Every distinct candidate is one
    /// full-transaction hash, and each is charged to the digest budget
    /// (AR-11). The signature-count budget is not touched: this is byte work,
    /// not another signature.
    #[test]
    fn a_multisig_companion_explosion_is_charged_per_digest() {
        let (tx, _) = fixture();
        let mut tx = tx;
        // A ~4 KiB transaction makes one legacy digest measurable.
        tx.output.push(TxOut { value: Amount::ZERO, script_pubkey: ScriptBuf::from_bytes(vec![0x6a; 4_000]) });
        let per_digest = tx.total_size();
        assert!(per_digest > 4_000, "the fixture must be large enough to measure: {per_digest}");
        let (pubkey, sig) = sign_code(&tx, &[0xac], 1);
        // OP_2 <eight distinct strict-DER pushes> OP_2 OP_CHECKMULTISIG: any
        // subset of the companions may be deleted by FindAndDelete, so every
        // subset is a candidate scriptCode.
        let companion = |n: u8| scriptcode::push_encoding(&[0x30, 0x06, 0x02, 0x01, 0x02, 0x02, 0x01, n, 0x01]);
        let mut script = vec![0x52];
        for n in 1..=scriptcode::MAX_MULTISIG_COMPANIONS as u8 {
            script.extend_from_slice(&companion(n + 1));
        }
        script.extend_from_slice(&[0x52, 0xae]);
        let claim = TxOut { value: Amount::from_sat(50_000), script_pubkey: ScriptBuf::from_bytes(script) };
        let candidates = 1usize << scriptcode::MAX_MULTISIG_COMPANIONS;

        let mut budget = Budget::new();
        let mut problems = Vec::new();
        let mut cache = SighashCache::new(&tx);
        let mut memo = AnalysisMemo { script: None, result: None };
        let verdict = check_ecdsa(&mut cache, 0, &Spend::Legacy, &claim, &pubkey, &sig, &mut budget, &mut problems, &mut memo);
        assert!(matches!(verdict, Some(Err(_))), "{verdict:?}");
        assert_eq!(budget.digest_left, MAX_LEGACY_DIGEST_BYTES - candidates * per_digest);
        // Each extra candidate is also one verification attempt, so the
        // signature budget pays it too; the digest budget independently pays
        // the hashed bytes.
        assert_eq!(budget.left, MAX_SIGNATURE_CHECKS - (candidates - 1));
        assert!(problems.is_empty(), "{problems:?}");

        // Ten digests of budget buy ten candidates; the eleventh fails closed
        // with a budget error, never as an invalid signature.
        let mut budget = Budget { digest_left: 10 * per_digest, ..Budget::new() };
        let mut problems = Vec::new();
        let mut memo = AnalysisMemo { script: None, result: None };
        assert_eq!(check_ecdsa(&mut cache, 0, &Spend::Legacy, &claim, &pubkey, &sig, &mut budget, &mut problems, &mut memo), None);
        assert_eq!(budget.digest_left, 0);
        assert!(problems.iter().any(|p| p.code == "verification_budget" && p.severity == ERROR), "{problems:?}");
    }

    /// A signed hundred-input P2PKH consolidation: every input has a real
    /// signature and the same claimed prevout shape, and analyse() verifies
    /// all hundred legacy digests inside the byte budget. The old
    /// KiB-denominated charge exhausted after 51 checks (AR-04, AR-11).
    #[test]
    fn a_signed_hundred_input_consolidation_verifies_within_the_digest_budget() {
        let secp = Secp256k1::new();
        let mut tx = Transaction {
            version: bitcoin::transaction::Version(2),
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: Vec::new(),
            output: vec![TxOut { value: Amount::from_sat(5_000), script_pubkey: ScriptBuf::from_bytes(vec![0x51]) }],
        };
        let mut keys = Vec::new();
        let mut claims = Vec::new();
        let mut maps = Vec::new();
        for n in 1..=100u8 {
            let key = SecretKey::from_slice(&[n; 32]).unwrap();
            let pubkey = bitcoin::PublicKey::new(key.public_key(&secp));
            let claim = TxOut { value: Amount::from_sat(1_000), script_pubkey: ScriptBuf::new_p2pkh(&pubkey.pubkey_hash()) };
            let (prev, txid) = prev_tx_for(&claim);
            tx.input.push(TxIn {
                previous_output: OutPoint { txid, vout: 0 },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            });
            keys.push((key, pubkey));
            claims.push(claim);
            maps.push(vec![pair("00", &hex_encode(&encode::serialize(&prev)))]);
        }
        // Sign every input over the finished transaction. Legacy hashing
        // clears every scriptSig, so filling them afterwards keeps the
        // signatures valid.
        let signed: Vec<(Vec<u8>, Vec<u8>)> = {
            let mut cache = SighashCache::new(&tx);
            (0..tx.input.len())
                .map(|index| {
                    let (key, pubkey) = &keys[index];
                    let digest = ecdsa_digest(&mut cache, index, SigVersion::Legacy, claims[index].script_pubkey.as_bytes(), Amount::ZERO, 1).unwrap();
                    let mut sig = secp.sign_ecdsa(&Message::from_digest_slice(&digest).unwrap(), key).serialize_der().to_vec();
                    sig.push(1);
                    (sig, pubkey.to_bytes())
                })
                .collect()
        };
        for (index, (sig, pubkey)) in signed.into_iter().enumerate() {
            let mut script_sig = ScriptBuf::new();
            script_sig.push_slice(bitcoin::script::PushBytesBuf::try_from(sig).unwrap());
            script_sig.push_slice(bitcoin::script::PushBytesBuf::try_from(pubkey).unwrap());
            let script_sig_hex = hex_encode(script_sig.as_bytes());
            tx.input[index].script_sig = script_sig;
            maps[index].push(pair("07", &script_sig_hex));
        }
        assert_eq!(tx.input.len(), 100);
        assert!(100 * tx.total_size() < MAX_LEGACY_DIGEST_BYTES, "the fixture must fit the digest budget");
        let problems = analyze(&tx, &maps);
        assert!(problems.is_empty(), "{problems:?}");
    }

    /// A P2SH-P2WPKH input: the claim is the P2SH wrapper, so the witness
    /// program the final witness's key must hash to lives in the redeem
    /// script, not in the claim's scriptPubKey (audit B1). An honest
    /// finalized wrapped spend passes; the same witness against a claim that
    /// wraps a different key's program is an error.
    #[test]
    fn a_valid_wrapped_p2wpkh_final_witness_passes_and_a_wrong_key_is_an_error() {
        let secp = Secp256k1::new();
        let key = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let pubkey = bitcoin::PublicKey::new(key.public_key(&secp));
        let (tx, _) = fixture();
        let redeem = ScriptBuf::new_p2wpkh(&pubkey.wpubkey_hash().unwrap());
        let claim = TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: ScriptBuf::new_p2sh(&redeem.script_hash()),
        };
        let mut cache = SighashCache::new(&tx);
        let sighash = cache
            .p2wpkh_signature_hash(0, &redeem, claim.value, EcdsaSighashType::All)
            .unwrap();
        let message = Message::from_digest_slice(&sighash.to_byte_array()).unwrap();
        let sig = secp.sign_ecdsa(&message, &key);
        let mut sig_bytes = sig.serialize_der().to_vec();
        sig_bytes.push(0x01);
        let witness = Witness::from_slice(&[sig_bytes, pubkey.to_bytes()]);
        // A wrapped spend's final scriptSig pushes exactly the redeem script.
        let script_sig = ScriptBuf::from_bytes([[redeem.as_bytes().len() as u8].as_slice(), redeem.as_bytes()].concat());
        let map = vec![
            pair("01", &witness_utxo_value(&claim)),
            pair("04", &hex_encode(redeem.as_bytes())),
            pair("07", &hex_encode(script_sig.as_bytes())),
            pair("08", &hex_encode(&encode::serialize(&witness))),
        ];
        let problems = analyze(&tx, &[map]);
        assert!(problems.is_empty(), "{problems:?}");

        // BIP-141 requires the scriptSig to be exactly the canonical push.
        // A non-minimal PUSHDATA1 of the same redeemScript is not that spend,
        // even though consensus reads non-minimal pushes in legacy scripts.
        let non_minimal = ScriptBuf::from_bytes([[0x4c, redeem.as_bytes().len() as u8].as_slice(), redeem.as_bytes()].concat());
        let slowmap = || {
            vec![
                pair("01", &witness_utxo_value(&claim)),
                pair("04", &hex_encode(redeem.as_bytes())),
                pair("07", &hex_encode(non_minimal.as_bytes())),
                pair("08", &hex_encode(&encode::serialize(&witness))),
            ]
        };
        let problems = analyze(&tx, &[slowmap()]);
        assert!(problems.iter().any(|p| p.code == "final_scriptsig_bad" && p.severity == ERROR), "{problems:?}");
        assert!(gate_error(&tx, &[slowmap()]).is_some());

        // The claim wraps a different key's program: the same witness must be named.
        let other_key = SecretKey::from_slice(&[2u8; 32]).unwrap();
        let other_redeem = ScriptBuf::new_p2wpkh(&bitcoin::PublicKey::new(other_key.public_key(&secp)).wpubkey_hash().unwrap());
        let other_claim = TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: ScriptBuf::new_p2sh(&other_redeem.script_hash()),
        };
        let other_script_sig = ScriptBuf::from_bytes([[other_redeem.as_bytes().len() as u8].as_slice(), other_redeem.as_bytes()].concat());
        let badmap = || {
            vec![
                pair("01", &witness_utxo_value(&other_claim)),
                pair("04", &hex_encode(other_redeem.as_bytes())),
                pair("07", &hex_encode(other_script_sig.as_bytes())),
                pair("08", &hex_encode(&encode::serialize(&witness))),
            ]
        };
        let problems = analyze(&tx, &[badmap()]);
        assert!(problems.iter().any(|p| p.code == "final_witness_bad" && p.severity == ERROR));
        assert!(gate_error(&tx, &[badmap()]).is_some());
    }

    /// BIP-141's exact-push rule holds for P2SH-P2WSH too: the canonical
    /// 34-byte push passes, a PUSHDATA1 encoding of the same redeemScript is
    /// a consensus-invalid scriptSig.
    #[test]
    fn a_wrapped_p2wsh_requires_the_canonical_redeem_push() {
        let (tx, _) = fixture();
        let witness_script = ScriptBuf::from_bytes(vec![0x51]);
        let redeem = ScriptBuf::new_p2wsh(&witness_script.wscript_hash());
        let claim = TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: ScriptBuf::new_p2sh(&redeem.script_hash()),
        };
        let witness = Witness::from_slice(&[witness_script.as_bytes()]);
        let canonical = ScriptBuf::from_bytes([[redeem.as_bytes().len() as u8].as_slice(), redeem.as_bytes()].concat());
        let non_minimal = ScriptBuf::from_bytes([[0x4c, redeem.as_bytes().len() as u8].as_slice(), redeem.as_bytes()].concat());
        let map = |script_sig: &ScriptBuf| {
            vec![
                pair("01", &witness_utxo_value(&claim)),
                pair("04", &hex_encode(redeem.as_bytes())),
                pair("07", &hex_encode(script_sig.as_bytes())),
                pair("08", &hex_encode(&encode::serialize(&witness))),
            ]
        };
        let problems = analyze(&tx, &[map(&canonical)]);
        assert!(problems.is_empty(), "{problems:?}");
        let problems = analyze(&tx, &[map(&non_minimal)]);
        assert!(problems.iter().any(|p| p.code == "final_scriptsig_bad" && p.severity == ERROR), "{problems:?}");
        assert!(gate_error(&tx, &[map(&non_minimal)]).is_some());
    }

    #[test]
    fn p2sh_multisig_final_scriptsig_with_op_0_dummy_is_accepted() {
        // A finalized 1-of-1 P2SH multisig: scriptSig = OP_0 <sig> <redeem>.
        // OP_0 is the CHECKMULTISIG dummy push; mistaking it for a non-push
        // would falsely gate a valid finalized input.
        let secp = Secp256k1::new();
        let key = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let pubkey = bitcoin::PublicKey::new(key.public_key(&secp));
        let redeem = ScriptBuf::from_bytes(
            [[0x51].as_slice(), &[0x21], &pubkey.to_bytes(), &[0x51, 0xae]].concat(),
        );
        let (tx, _) = fixture();
        let claim = TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: ScriptBuf::new_p2sh(&redeem.script_hash()),
        };
        // A legacy P2SH spend claims through the full previous transaction,
        // not a witness UTXO.
        let (prev, txid) = prev_tx_for(&claim);
        let mut tx = tx;
        tx.input[0].previous_output.txid = txid;
        let script_sig = ScriptBuf::from_bytes(
            [[0x00].as_slice(), &[0x02, 0xaa, 0xbb], &redeem.as_bytes().len().to_le_bytes()[..1], redeem.as_bytes()].concat(),
        );
        let map = vec![
            pair("00", &hex_encode(&encode::serialize(&prev))),
            pair("04", &hex_encode(redeem.as_bytes())),
            pair("07", &hex_encode(script_sig.as_bytes())),
        ];
        let problems = analyze(&tx, &[map]);
        assert!(problems.is_empty(), "{problems:?}");
    }

    /// BIP-341: when a final key-path witness carries an annex, the signature
    /// message commits to it (spend_type bit 0 set, sha_annex appended). A
    /// signature made over the annex-bearing message must pass; one made over
    /// the annex-less message — valid only if the annex were dropped — must be
    /// named. The reference digests are built byte by byte from the BIP-341
    /// message layout here, not by the sighash code under test.
    /// SIGHASH_SINGLE on an input with no corresponding output: legacy
    /// consensus assigns the constant-one digest (the "SIGHASH_SINGLE bug")
    /// and segwit v0 a zero hashOutputs — either way the signature commits
    /// to no output and must be named, never quietly verified (audit C3-8).
    #[test]
    fn sighash_single_without_a_matching_output_is_named() {
        let secp = Secp256k1::new();
        let key = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let pubkey = bitcoin::PublicKey::new(key.public_key(&secp));
        let claim = TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: ScriptBuf::new_p2pkh(&pubkey.pubkey_hash()),
        };
        let (prev, txid) = prev_tx_for(&claim);
        let build_tx = |outputs: usize| Transaction {
            version: bitcoin::transaction::Version(2),
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![
                TxIn {
                    previous_output: OutPoint { txid: Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array([0x22; 32])), vout: 0 },
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                },
                TxIn {
                    previous_output: OutPoint { txid, vout: 0 },
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                },
            ],
            output: (0..outputs)
                .map(|_| TxOut { value: Amount::from_sat(1000), script_pubkey: ScriptBuf::from_bytes(vec![0x51]) })
                .collect(),
        };
        // The construction really is the bug case: consensus gives input 1's
        // SIGHASH_SINGLE signature the constant-one digest (uint256 1, so the
        // 1 sits in the first byte of the internal byte order), and this
        // signature verifies against exactly that digest.
        let mut one = [0u8; 32];
        one[0] = 1;
        let message = Message::from_digest_slice(&one).unwrap();
        let sig = secp.sign_ecdsa(&message, &key);
        assert!(secp.verify_ecdsa(&message, &sig, &key.public_key(&secp)).is_ok());
        let mut value = sig.serialize_der().to_vec();
        value.push(0x03); // SIGHASH_SINGLE
        let sigmap = || {
            vec![
                pair("00", &hex_encode(&encode::serialize(&prev))),
                pair(&format!("02{}", hex_encode(&pubkey.to_bytes())), &hex_encode(&value)),
            ]
        };
        // One output, so input 1 has no matching output: the condition is
        // named, and the verdict is unchanged — the constant-one signature
        // verifies, so there is no invalid-signature report.
        let problems = analyze(&build_tx(1), &[vec![], sigmap()]);
        assert!(
            problems.iter().any(|p| p.code == "sighash_single_no_output" && p.severity == WARNING),
            "the constant-one digest must not verify quietly: {problems:?}"
        );
        assert!(
            !problems.iter().any(|p| p.code == "partial_sig_invalid"),
            "verification still ran and passed: {problems:?}"
        );
        // With a matching output the same signature shape takes the ordinary
        // path (a digest exists; this one simply does not verify against it).
        let problems = analyze(&build_tx(2), &[vec![], sigmap()]);
        assert!(
            !problems.iter().any(|p| p.code == "sighash_single_no_output"),
            "a digestible SIGHASH_SINGLE must not be misnamed: {problems:?}"
        );
        assert!(
            problems.iter().any(|p| p.code == "partial_sig_invalid"),
            "and it is still checked: {problems:?}"
        );
    }

    #[test]
    fn a_final_key_path_witness_commits_to_its_annex() {
        use bitcoin::hashes::HashEngine as _;
        use bitcoin::key::TapTweak as _;
        let secp = Secp256k1::new();
        let key = secp256k1::Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[1u8; 32]).unwrap());
        let (xonly, _parity) = key.x_only_public_key();
        let (tx, _) = fixture();
        let claim = TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: ScriptBuf::new_p2tr(&secp, xonly, None),
        };
        let tweaked = key.tap_tweak(&secp, None).to_keypair();
        let annex = [0x50, 0xaa, 0xbb, 0xcc];
        // SigMsg for the fixture transaction (version 2, locktime 0, one
        // input spending txid 0x11…:0 with sequence MAX, one 1000-sat OP_TRUE
        // output), SIGHASH_DEFAULT, key path (ext_flag 0).
        let sigmsg = |with_annex: bool| {
            let sha = |bytes: &[u8]| sha256::Hash::hash(bytes).to_byte_array();
            let mut msg = vec![0x00, 0x00]; // epoch, SIGHASH_DEFAULT
            msg.extend_from_slice(&2i32.to_le_bytes()); // nVersion
            msg.extend_from_slice(&0u32.to_le_bytes()); // nLockTime
            msg.extend_from_slice(&sha(&[[0x11; 32].as_slice(), &0u32.to_le_bytes()].concat())); // sha_prevouts
            msg.extend_from_slice(&sha(&50_000u64.to_le_bytes())); // sha_amounts
            msg.extend_from_slice(&sha(&[&[0x22], claim.script_pubkey.as_bytes()].concat())); // sha_scriptpubkeys
            msg.extend_from_slice(&sha(&0xffff_ffffu32.to_le_bytes())); // sha_sequences
            msg.extend_from_slice(&sha(&[1_000u64.to_le_bytes().as_slice(), &[0x01, 0x51]].concat())); // sha_outputs
            msg.push(if with_annex { 0x01 } else { 0x00 }); // spend_type
            msg.extend_from_slice(&0u32.to_le_bytes()); // input index
            if with_annex {
                // sha_annex commits to the annex as serialized in the
                // witness, 0x50 prefix included.
                msg.extend_from_slice(&sha(&[&[annex.len() as u8], annex.as_slice()].concat()));
            }
            let mut engine = TapSighash::engine();
            engine.input(&msg);
            TapSighash::from_engine(engine).to_byte_array()
        };
        let sign = |with_annex: bool| {
            secp.sign_schnorr_no_aux_rand(&Message::from_digest_slice(&sigmsg(with_annex)).unwrap(), &tweaked).serialize().to_vec()
        };
        let map_for = |sig: &[u8]| {
            let witness = Witness::from_slice(&[sig.to_vec(), annex.to_vec()]);
            vec![pair("01", &witness_utxo_value(&claim)), pair("08", &hex_encode(&encode::serialize(&witness)))]
        };
        // Signed over the annex-bearing message: valid, no problems.
        let problems = analyze(&tx, &[map_for(&sign(true))]);
        assert!(problems.is_empty(), "{problems:?}");
        // Signed over the annex-less message but spending with an annex:
        // consensus would reject it, so the verifier must name it.
        let problems = analyze(&tx, &[map_for(&sign(false))]);
        assert!(problems.iter().any(|p| p.code == "final_witness_bad" && p.severity == ERROR), "{problems:?}");
    }

    #[test]
    fn a_valid_taproot_key_sig_passes_and_a_flipped_one_is_named() {
        let secp = Secp256k1::new();
        let key = secp256k1::Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[1u8; 32]).unwrap());
        let (xonly, _parity) = key.x_only_public_key();
        let (tx, _) = fixture();
        let claim = TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: ScriptBuf::new_p2tr(&secp, xonly, None),
        };
        let prevouts = vec![claim.clone()];
        let mut cache = SighashCache::new(&tx);
        let sighash = cache
            .taproot_key_spend_signature_hash(0, &Prevouts::All(&prevouts), TapSighashType::Default)
            .unwrap();
        let message = Message::from_digest_slice(&sighash.to_byte_array()).unwrap();
        // A key-path spend signs with the tweaked key: the output key in the
        // scriptPubKey commits to the BIP-341 tweak of the internal key.
        use bitcoin::key::TapTweak as _;
        let tweaked = key.tap_tweak(&secp, None).to_keypair();
        let sig = secp.sign_schnorr_no_aux_rand(&message, &tweaked);
        let map = vec![pair("01", &witness_utxo_value(&claim)), pair("13", &hex_encode(&sig.serialize()))];
        let problems = analyze(&tx, &[map]);
        assert!(problems.is_empty(), "{problems:?}");

        let mut bad = sig.serialize();
        bad[10] ^= 1;
        let map = vec![pair("01", &witness_utxo_value(&claim)), pair("13", &hex_encode(&bad))];
        let problems = analyze(&tx, &[map]);
        assert!(problems.iter().any(|p| p.code == "tap_sig_invalid" && p.severity == WARNING));
    }
}

