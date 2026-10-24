//! Offline payjoin detection (issue #446).
//!
//! BIP-78 flow: the receiver hands out a BIP-21 URI with `pj=`; the sender
//! builds a signed, broadcastable Original PSBT; the receiver answers with a
//! Payjoin Proposal that adds its own finalized inputs and may add or replace
//! its own outputs; the sender runs the BIP-78 checklist, re-signs its own
//! inputs and broadcasts. BIP-77 carries the same two PSBTs through an
//! asynchronous, end-to-end encrypted directory and keeps BIP-78's sender
//! checklist unchanged. Only the PSBTs matter here: nothing in this module
//! contacts an endpoint or a directory, and nothing generates randomness.
//!
//! `shape` reads one PSBT and reports signals only. A proposal finalizes
//! exactly the receiver's added inputs and leaves the sender's unfinalized,
//! so a mix of finalized and unfinalized inputs is the proposal's shape and
//! the finalized ones are the candidate receiver inputs. Inputs whose BIP-32
//! origins name disjoint master fingerprints come from more than one wallet.
//! Both patterns also occur outside payjoin (coinjoins, collaborative
//! batches, signing in progress), and a fully re-signed payjoin looks like
//! any other transaction, so this is never a verdict.
//!
//! `compare` reads the Original PSBT and the Payjoin Proposal. With both,
//! receiver inputs are exact (proposal inputs spending an outpoint the
//! original does not) and output substitution is visible (an original output
//! script absent from the proposal). The BIP-78 checklist items decidable
//! from the two files are reported as problems. `pjos=0` /
//! `disableoutputsubstitution` and the fee-contribution parameters live in
//! the URI and the request, not in the PSBTs, so what depends on them is
//! reported as a fact (which output changed, by how much) for the user.

use crate::sanitize::{parse_origin, tap_origin};
use crate::verify::{Problem, ERROR};
use crate::{
    hex_decode, pair_utxo_claim, parse_raw, resolve_input_amount, sats_json, tx_sanity_error,
    AmountClaim, RawPair, RawPsbt, MAX_JSON_BYTES, MAX_PROBLEMS,
};
use bitcoin::{Amount, OutPoint, Transaction};
use serde_json::{json, Value};
use std::collections::{BTreeSet, HashMap, VecDeque};

fn has_type(map: &[RawPair], types: &[u8]) -> bool {
    map.iter().any(|pair| pair.key.first().is_some_and(|t| types.contains(t)))
}

/// BIP-174 finalized: a keyless PSBT_IN_FINAL_SCRIPTSIG or
/// PSBT_IN_FINAL_SCRIPTWITNESS is present.
fn is_finalized(map: &[RawPair]) -> bool {
    map.iter().any(|pair| pair.key == [0x07] || pair.key == [0x08])
}

/// PSBT_IN_BIP32_DERIVATION, PSBT_IN_TAP_BIP32_DERIVATION.
const INPUT_KEYPATHS: &[u8] = &[0x06, 0x16];
/// PSBT_OUT_BIP32_DERIVATION, PSBT_OUT_TAP_BIP32_DERIVATION.
const OUTPUT_KEYPATHS: &[u8] = &[0x02, 0x07];
/// Unfinalized signatures: PSBT_IN_PARTIAL_SIG plus the taproot key- and
/// script-path signatures. BIP-78 predates taproot; a loose taproot
/// signature is the same "partial signature has been filled" case.
const INPUT_SIGNATURES: &[u8] = &[0x02, 0x13, 0x14];

fn input_fingerprints(map: &[RawPair]) -> BTreeSet<[u8; 4]> {
    map.iter()
        .filter_map(|pair| match pair.key.first() {
            Some(0x06) => parse_origin(&pair.value).ok(),
            Some(0x16) => tap_origin(&pair.value).ok(),
            _ => None,
        })
        .map(|origin| origin.fingerprint)
        .collect()
}

/// Number of wallet groups among inputs that declare any BIP-32 origin: two
/// inputs share a group when they share a master fingerprint (directly or
/// through other inputs). Malformed origins are the sanitizer's finding and
/// are ignored here.
fn origin_groups(inputs: &[Vec<RawPair>]) -> usize {
    fn root(parent: &mut [usize], mut i: usize) -> usize {
        while parent[i] != i {
            parent[i] = parent[parent[i]];
            i = parent[i];
        }
        i
    }
    let mut parent: Vec<usize> = (0..inputs.len()).collect();
    let mut owner: HashMap<[u8; 4], usize> = HashMap::new();
    let mut with_origin = Vec::new();
    for (i, map) in inputs.iter().enumerate() {
        let fingerprints = input_fingerprints(map);
        if fingerprints.is_empty() {
            continue;
        }
        with_origin.push(i);
        for fingerprint in fingerprints {
            match owner.get(&fingerprint) {
                Some(&j) => {
                    let (a, b) = (root(&mut parent, i), root(&mut parent, j));
                    parent[a] = b;
                }
                None => {
                    owner.insert(fingerprint, i);
                }
            }
        }
    }
    with_origin.into_iter().map(|i| root(&mut parent, i)).collect::<BTreeSet<_>>().len()
}

/// Single-PSBT payjoin signals for the inspect document.
pub(crate) fn shape(inputs: &[Vec<RawPair>]) -> Value {
    let finalized: Vec<usize> = (0..inputs.len()).filter(|&i| is_finalized(&inputs[i])).collect();
    let proposal_shape = !finalized.is_empty() && finalized.len() < inputs.len();
    let groups = origin_groups(inputs);
    json!({
        "proposalShape": proposal_shape,
        "candidateReceiverInputs": if proposal_shape { finalized } else { Vec::new() },
        "originGroups": groups,
        "multiWallet": groups >= 2,
        "signal": proposal_shape || groups >= 2,
    })
}

fn claimed(map: &[RawPair], tx: &Transaction, index: usize) -> Option<u64> {
    match resolve_input_amount(map, tx, index) {
        AmountClaim::Claimed(amount) => Some(amount),
        AmountClaim::None | AmountClaim::Conflict => None,
    }
}

/// Fee from per-input amounts, or None when any amount is unknown, a sum
/// overflows or passes MAX_MONEY, or the outputs exceed the inputs.
fn fee(amounts: &[Option<u64>], tx: &Transaction) -> Option<u64> {
    let max = Amount::MAX_MONEY.to_sat();
    let total_in = amounts.iter().try_fold(0u64, |sum, amount| sum.checked_add((*amount)?))?;
    let total_out = tx.output.iter().try_fold(0u64, |sum, output| sum.checked_add(output.value.to_sat()))?;
    if total_in > max || total_out > max {
        return None;
    }
    total_in.checked_sub(total_out)
}

/// Original PSBT against Payjoin Proposal. `payment_script` is the
/// scriptPubKey of the BIP-21 address when the user supplies it; without it
/// a single replaced output is reported as an unconfirmed substitution.
pub(crate) fn compare(original: &RawPsbt, proposal: &RawPsbt, payment_script: Option<&[u8]>) -> Value {
    let (otx, ptx) = (&original.unsigned_tx, &proposal.unsigned_tx);
    let mut problems = Vec::new();
    let mut error = |scope: String, code: &'static str, message: String| problems.push(Problem::error(scope, code, message));

    for (name, tx) in [("original", otx), ("proposal", ptx)] {
        if let Some(reason) = tx_sanity_error(tx) {
            error("transaction".into(), "tx_invalid", format!("the {name} transaction is invalid ({reason})"));
        }
    }
    if otx.version != ptx.version {
        error("transaction".into(), "version_changed", "the proposal changed the transaction version".into());
    }
    if otx.lock_time != ptx.lock_time {
        error("transaction".into(), "locktime_changed", "the proposal changed the nLockTime".into());
    }

    // ── Inputs: matched by outpoint ──
    let mut original_index: HashMap<OutPoint, usize> = HashMap::new();
    for (i, input) in otx.input.iter().enumerate() {
        original_index.entry(input.previous_output).or_insert(i);
    }
    let original_amounts: Vec<Option<u64>> =
        (0..otx.input.len()).map(|i| claimed(&original.inputs[i], otx, i)).collect();
    let mut proposal_amounts = Vec::with_capacity(ptx.input.len());
    let mut receiver_inputs = Vec::new();
    let mut sender_order = Vec::new();
    let mut sequences = BTreeSet::new();
    for (j, input) in ptx.input.iter().enumerate() {
        let map = &proposal.inputs[j];
        let scope = format!("proposal input {j}");
        sequences.insert(input.sequence);
        if has_type(map, INPUT_KEYPATHS) {
            error(scope.clone(), "input_keypaths", "carries BIP-32 keypaths, which a proposal must not".into());
        }
        if has_type(map, INPUT_SIGNATURES) {
            error(scope.clone(), "input_signature", "carries an unfinalized signature, which a proposal must not".into());
        }
        match original_index.get(&input.previous_output) {
            Some(&i) => {
                sender_order.push(i);
                // The sender's own UTXO claim, never the proposal's: a
                // receiver-supplied amount for a sender input is not trusted.
                proposal_amounts.push(original_amounts[i]);
                if input.sequence != otx.input[i].sequence {
                    error(scope.clone(), "sender_sequence_changed", format!("changed the sequence of original input {i}"));
                }
                if is_finalized(map) {
                    error(scope, "sender_input_finalized", format!("finalizes original input {i}; only receiver inputs may be finalized"));
                }
            }
            None => {
                receiver_inputs.push(j);
                proposal_amounts.push(claimed(map, ptx, j));
                if !is_finalized(map) {
                    error(scope.clone(), "receiver_input_not_finalized", "is a receiver input but is not finalized".into());
                }
                if !map.iter().any(|pair| pair_utxo_claim(pair, ptx, j).is_some()) {
                    error(scope, "receiver_input_missing_utxo", "is a receiver input without a valid witness or non-witness UTXO".into());
                }
            }
        }
    }
    if sequences.len() > 1 {
        error("transaction".into(), "mixed_sequence", "proposal inputs do not all use the same sequence".into());
    }
    let seen: BTreeSet<usize> = sender_order.iter().copied().collect();
    for i in (0..otx.input.len()).filter(|i| !seen.contains(i)) {
        error(format!("original input {i}"), "sender_input_missing", "is not spent by the proposal".into());
    }
    // `>=` also catches one original input spent twice.
    if sender_order.windows(2).any(|w| w[0] >= w[1]) {
        error("transaction".into(), "inputs_reordered", "the proposal reorders the original inputs".into());
    }

    // ── Fees ──
    let original_fee = fee(&original_amounts, otx);
    let proposal_fee = fee(&proposal_amounts, ptx);
    let fee_increase = match (original_fee, proposal_fee) {
        (Some(before), Some(after)) if after < before => {
            error("transaction".into(), "fee_decreased", format!("the proposal lowers the absolute fee from {before} to {after} sats"));
            None
        }
        (Some(before), Some(after)) => Some(after - before),
        _ => None,
    };
    let receiver_contribution = receiver_inputs
        .iter()
        .try_fold(0u64, |sum, &j| sum.checked_add(proposal_amounts[j]?));

    // ── Outputs: order-preserving match by script ──
    // Each original output takes the first proposal output with the same
    // script after the previous match (BIP-78 forbids reordering). Per-script
    // queues keep this linear on a 100k-output file.
    let mut positions: HashMap<&[u8], VecDeque<usize>> = HashMap::new();
    for (j, output) in ptx.output.iter().enumerate() {
        positions.entry(output.script_pubkey.as_bytes()).or_default().push_back(j);
    }
    let mut matched: Vec<Option<usize>> = vec![None; ptx.output.len()];
    let mut unmatched = Vec::new();
    let mut cursor = 0usize;
    for (i, output) in otx.output.iter().enumerate() {
        let hit = positions.get_mut(output.script_pubkey.as_bytes()).and_then(|queue| {
            while queue.front().is_some_and(|&j| j < cursor) {
                queue.pop_front();
            }
            queue.pop_front()
        });
        match hit {
            Some(j) => {
                matched[j] = Some(i);
                cursor = j + 1;
            }
            None => unmatched.push(i),
        }
    }
    let added: Vec<usize> = (0..ptx.output.len()).filter(|&j| matched[j].is_none()).collect();
    let added_scripts: BTreeSet<&[u8]> = added.iter().map(|&j| ptx.output[j].script_pubkey.as_bytes()).collect();

    let payment_index = payment_script.and_then(|s| otx.output.iter().position(|o| o.script_pubkey.as_bytes() == s));
    if payment_script.is_some() && payment_index.is_none() {
        error("transaction".into(), "payment_output_not_found", "the original PSBT does not pay the given payment script".into());
    }

    // An unmatched original output whose script reappears among the added
    // outputs moved rather than disappeared.
    let (reordered, replaced): (Vec<usize>, Vec<usize>) = unmatched
        .into_iter()
        .partition(|&i| added_scripts.contains(otx.output[i].script_pubkey.as_bytes()));
    for &i in &reordered {
        error(format!("original output {i}"), "outputs_reordered", "appears in the proposal out of its original order".into());
    }
    let moved: BTreeSet<&[u8]> = reordered.iter().map(|&i| otx.output[i].script_pubkey.as_bytes()).collect();
    let added: Vec<usize> =
        added.into_iter().filter(|&j| !moved.contains(ptx.output[j].script_pubkey.as_bytes())).collect();

    // BIP-78 lets exactly one original output be replaced: the payment
    // output. Known, it must be that one; unknown, a lone replacement is
    // reported as unconfirmed and two or more cannot all be the payment.
    let substituted = match payment_index {
        Some(p) => replaced.contains(&p).then_some(p),
        None if replaced.len() == 1 => Some(replaced[0]),
        None => None,
    };
    for &i in replaced.iter().filter(|&&i| Some(i) != substituted) {
        error(format!("original output {i}"), "sender_output_missing",
            "is missing from the proposal; only the payment output may be replaced".into());
    }
    let mut warnings = Vec::new();
    let substitution = match substituted {
        None => Value::Null,
        Some(i) => {
            let confirmed = payment_index.is_some();
            warnings.push(Problem::warning(format!("original output {i}"), "output_substituted", if confirmed {
                "the payment output was replaced; BIP-78 allows this only when output substitution was not disabled (pjos=0)"
            } else {
                "was replaced; this is allowed only for the payment output — supply the payment address to confirm"
            }));
            json!({ "originalOutput": i, "paymentOutputConfirmed": confirmed })
        }
    };

    let mut value_changes = Vec::new();
    let mut sender_decrease = Some(0u64);
    for (j, slot) in matched.iter().enumerate() {
        let Some(i) = *slot else { continue };
        let (before, after) = (otx.output[i].value.to_sat(), ptx.output[j].value.to_sat());
        if before == after {
            continue;
        }
        value_changes.push(json!({ "originalOutput": i, "proposalOutput": j, "before": sats_json(before), "after": sats_json(after) }));
        if after > before {
            continue;
        }
        let scope = format!("original output {i}");
        if Some(i) == payment_index {
            warnings.push(Problem::warning(scope, "payment_output_decreased",
                "the payment output was reduced; BIP-78 allows this only when output substitution was not disabled"));
        } else {
            sender_decrease = sender_decrease.and_then(|sum| sum.checked_add(before - after));
            warnings.push(Problem::warning(scope, "output_decreased",
                format!("was reduced by {} sats; BIP-78 lets the receiver reduce only the sender's designated fee output, within maxadditionalfeecontribution", before - after)));
        }
    }
    // With the payment output known, every other decrease is the sender's
    // money and must go entirely to the added fee.
    if payment_index.is_some() {
        if let (Some(taken), Some(increase)) = (sender_decrease, fee_increase) {
            if taken > increase {
                error("transaction".into(), "contribution_not_to_fee",
                    format!("sender outputs lost {taken} sats but the fee rose by only {increase}"));
            }
        }
    }
    for (j, map) in proposal.outputs.iter().enumerate() {
        if has_type(map, OUTPUT_KEYPATHS) {
            error(format!("proposal output {j}"), "output_keypaths", "carries BIP-32 keypaths, which a proposal must not".into());
        }
    }

    problems.extend(warnings);
    let has_error = problems.iter().any(|p| p.severity == ERROR);
    let checklist = if has_error {
        "problem"
    } else if original_fee.is_none() || proposal_fee.is_none() {
        "incomplete"
    } else {
        "complete"
    };
    let truncated = problems.len() > MAX_PROBLEMS;
    problems.truncate(MAX_PROBLEMS);
    json!({
        // BIP-78: a proposal that adds no receiver input is valid but is not
        // an actual payjoin.
        "payjoin": !receiver_inputs.is_empty(),
        "receiverInputs": receiver_inputs,
        "receiverContribution": receiver_contribution.map_or(Value::Null, sats_json),
        "substitution": substitution,
        "addedOutputs": added,
        "valueChanges": value_changes,
        "fee": {
            "original": original_fee.map_or(Value::Null, sats_json),
            "proposal": proposal_fee.map_or(Value::Null, sats_json),
        },
        "checklist": checklist,
        "problems": problems.iter().map(|p| json!({
            "severity": p.severity,
            "scope": p.scope,
            "code": p.code,
            "message": p.message,
        })).collect::<Vec<_>>(),
        "problemsTruncated": truncated,
    })
}

/// FFI request: `{"original": hex, "proposal": hex, "paymentScript": hex|null}`.
pub(crate) fn compare_request(json_bytes: &[u8]) -> Result<String, String> {
    if json_bytes.len() > MAX_JSON_BYTES {
        return Err("payjoin request is too large".into());
    }
    let doc: Value =
        serde_json::from_slice(json_bytes).map_err(|e| format!("payjoin request is not valid JSON: {e}"))?;
    let psbt = |field: &str| -> Result<RawPsbt, String> {
        let text = doc[field].as_str().ok_or_else(|| format!("`{field}` must be a hex string"))?;
        parse_raw(&hex_decode(text)?).map_err(|e| format!("{field} PSBT: {e}"))
    };
    let original = psbt("original")?;
    let proposal = psbt("proposal")?;
    let payment = match &doc["paymentScript"] {
        Value::Null => None,
        Value::String(text) => Some(hex_decode(text)?),
        _ => return Err("`paymentScript` must be a hex string or null".into()),
    };
    let report = compare(&original, &proposal, payment.as_deref());
    let text = serde_json::to_string(&report).map_err(|e| format!("JSON encode failed: {e}"))?;
    if text.len() > MAX_JSON_BYTES {
        return Err("payjoin report is too large".into());
    }
    Ok(text)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{hex_encode, push_pair};
    use bitcoin::consensus::encode;
    use bitcoin::hashes::Hash as _;
    use bitcoin::locktime::absolute::LockTime;
    use bitcoin::transaction::Version;
    use bitcoin::{ScriptBuf, Sequence, TxIn, TxOut, Txid, Witness};

    type Map = Vec<(Vec<u8>, Vec<u8>)>;

    fn spk(byte: u8) -> ScriptBuf {
        let mut bytes = vec![0x00, 0x14];
        bytes.extend([byte; 20]);
        ScriptBuf::from_bytes(bytes)
    }

    fn outpoint(byte: u8, vout: u32) -> OutPoint {
        OutPoint { txid: Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array([byte; 32])), vout }
    }

    fn txin(point: OutPoint) -> TxIn {
        TxIn { previous_output: point, script_sig: ScriptBuf::new(), sequence: Sequence(0xffff_fffd), witness: Witness::new() }
    }

    fn txout(sats: u64, script: ScriptBuf) -> TxOut {
        TxOut { value: Amount::from_sat(sats), script_pubkey: script }
    }

    fn tx(input: Vec<TxIn>, output: Vec<TxOut>) -> Transaction {
        Transaction { version: Version(2), lock_time: LockTime::ZERO, input, output }
    }

    fn witness_utxo(sats: u64, script: &ScriptBuf) -> (Vec<u8>, Vec<u8>) {
        let mut value = sats.to_le_bytes().to_vec();
        value.push(script.len() as u8);
        value.extend_from_slice(script.as_bytes());
        (vec![0x01], value)
    }

    fn final_witness() -> (Vec<u8>, Vec<u8>) {
        (vec![0x08], vec![0x01, 0x00])
    }

    fn origin(key_type: u8, fingerprint: [u8; 4]) -> (Vec<u8>, Vec<u8>) {
        let mut key = vec![key_type];
        key.extend([0x02; 33]);
        let mut value = fingerprint.to_vec();
        value.extend(0u32.to_le_bytes());
        (key, value)
    }

    fn psbt(tx: &Transaction, inputs: &[Map], outputs: &[Map]) -> Vec<u8> {
        assert_eq!(inputs.len(), tx.input.len());
        let mut out = b"psbt\xff".to_vec();
        push_pair(&mut out, &[0x00], &encode::serialize(tx));
        out.push(0x00);
        for map in inputs {
            for (key, value) in map {
                push_pair(&mut out, key, value);
            }
            out.push(0x00);
        }
        for j in 0..tx.output.len() {
            for (key, value) in outputs.get(j).into_iter().flatten() {
                push_pair(&mut out, key, value);
            }
            out.push(0x00);
        }
        out
    }

    fn raw(tx: &Transaction, inputs: &[Map]) -> RawPsbt {
        parse_raw(&psbt(tx, inputs, &[])).expect("fixture parses")
    }

    const PAYMENT: u8 = 0xaa;
    const SENDER_SPK: u8 = 0xbb;
    const CHANGE: u8 = 0xcc;
    const RECEIVER_SPK: u8 = 0xee;

    // Original: one sender input (100k) paying 50k to PAYMENT and 40k change;
    // fee 10k. Signed and finalized with its witness UTXO, per BIP-78.
    fn original() -> RawPsbt {
        let t = tx(vec![txin(outpoint(0x11, 0))], vec![txout(50_000, spk(PAYMENT)), txout(40_000, spk(CHANGE))]);
        raw(&t, &[vec![witness_utxo(100_000, &spk(SENDER_SPK)), final_witness()]])
    }

    // Clean BIP-78 proposal: the sender input unfinalized and stripped, a
    // finalized receiver input (30k) inserted after it, the payment output
    // grown by the receiver's input and the change reduced by exactly the
    // 1k fee increase.
    fn proposal_tx() -> Transaction {
        tx(
            vec![txin(outpoint(0x11, 0)), txin(outpoint(0x22, 1))],
            vec![txout(80_000, spk(PAYMENT)), txout(39_000, spk(CHANGE))],
        )
    }

    fn receiver_map() -> Map {
        vec![witness_utxo(30_000, &spk(RECEIVER_SPK)), final_witness()]
    }

    fn proposal_with(t: &Transaction, inputs: &[Map], outputs: &[Map]) -> RawPsbt {
        parse_raw(&psbt(t, inputs, outputs)).expect("fixture parses")
    }

    fn clean_proposal() -> RawPsbt {
        proposal_with(&proposal_tx(), &[vec![], receiver_map()], &[])
    }

    fn codes(report: &Value) -> Vec<String> {
        report["problems"].as_array().unwrap().iter().map(|p| p["code"].as_str().unwrap().to_string()).collect()
    }

    fn has_error(report: &Value, code: &str) -> bool {
        report["problems"].as_array().unwrap().iter().any(|p| p["code"] == code && p["severity"] == ERROR)
    }

    #[test]
    fn clean_proposal_flags_the_receiver_input_and_passes_the_checklist() {
        let report = compare(&original(), &clean_proposal(), Some(spk(PAYMENT).as_bytes()));
        assert_eq!(report["payjoin"], true);
        assert_eq!(report["receiverInputs"], json!([1]));
        assert_eq!(report["receiverContribution"], "30000");
        assert_eq!(report["substitution"], Value::Null);
        assert_eq!(report["addedOutputs"], json!([]));
        assert_eq!(report["fee"], json!({ "original": "10000", "proposal": "11000" }));
        assert_eq!(report["checklist"], "complete", "{report}");
        // The change reduction is reported, not failed: with the payment
        // output known it is within the fee increase.
        assert_eq!(codes(&report), vec!["output_decreased"]);
    }

    #[test]
    fn a_proposal_adding_no_receiver_input_is_not_a_payjoin() {
        let t = tx(vec![txin(outpoint(0x11, 0))], vec![txout(50_000, spk(PAYMENT)), txout(40_000, spk(CHANGE))]);
        let report = compare(&original(), &proposal_with(&t, &[vec![]], &[]), None);
        assert_eq!(report["payjoin"], false);
        assert_eq!(report["receiverInputs"], json!([]));
        assert_eq!(report["checklist"], "complete", "{report}");
    }

    #[test]
    fn output_substitution_is_flagged_and_confirmed_by_the_payment_script() {
        let mut t = proposal_tx();
        t.output[0].script_pubkey = spk(0xdd);
        let proposal = proposal_with(&t, &[vec![], receiver_map()], &[]);

        let unconfirmed = compare(&original(), &proposal, None);
        assert_eq!(unconfirmed["substitution"], json!({ "originalOutput": 0, "paymentOutputConfirmed": false }));
        assert_eq!(unconfirmed["addedOutputs"], json!([0]));
        assert!(codes(&unconfirmed).contains(&"output_substituted".to_string()));
        assert_eq!(unconfirmed["checklist"], "complete", "{unconfirmed}");

        let confirmed = compare(&original(), &proposal, Some(spk(PAYMENT).as_bytes()));
        assert_eq!(confirmed["substitution"], json!({ "originalOutput": 0, "paymentOutputConfirmed": true }));
        assert_eq!(confirmed["checklist"], "complete", "{confirmed}");
    }

    #[test]
    fn replacing_a_non_payment_output_is_rejected() {
        // The receiver swaps the sender's change for its own script.
        let mut t = proposal_tx();
        t.output[1].script_pubkey = spk(0xdd);
        let proposal = proposal_with(&t, &[vec![], receiver_map()], &[]);
        let report = compare(&original(), &proposal, Some(spk(PAYMENT).as_bytes()));
        assert!(has_error(&report, "sender_output_missing"), "{report}");
        assert_eq!(report["substitution"], Value::Null);
        assert_eq!(report["checklist"], "problem");
    }

    #[test]
    fn two_replaced_outputs_are_rejected_without_a_payment_script() {
        let mut t = proposal_tx();
        t.output[0].script_pubkey = spk(0xdd);
        t.output[1].script_pubkey = spk(0xde);
        let report = compare(&original(), &proposal_with(&t, &[vec![], receiver_map()], &[]), None);
        assert_eq!(codes(&report).iter().filter(|c| *c == "sender_output_missing").count(), 2);
        assert_eq!(report["substitution"], Value::Null);
    }

    #[test]
    fn a_payment_script_the_original_does_not_pay_is_rejected() {
        let report = compare(&original(), &clean_proposal(), Some(spk(0x01).as_bytes()));
        assert!(has_error(&report, "payment_output_not_found"), "{report}");
    }

    #[test]
    fn reordered_outputs_are_not_mistaken_for_substitution() {
        let mut t = proposal_tx();
        t.output.swap(0, 1);
        let report = compare(&original(), &proposal_with(&t, &[vec![], receiver_map()], &[]), None);
        assert!(has_error(&report, "outputs_reordered"), "{report}");
        assert_eq!(report["substitution"], Value::Null);
        assert_eq!(report["addedOutputs"], json!([]));
    }

    #[test]
    fn a_dropped_or_reordered_sender_input_is_rejected() {
        let t = tx(vec![txin(outpoint(0x22, 1))], proposal_tx().output);
        let dropped = compare(&original(), &proposal_with(&t, &[receiver_map()], &[]), None);
        assert!(has_error(&dropped, "sender_input_missing"), "{dropped}");

        let orig_tx = tx(vec![txin(outpoint(0x11, 0)), txin(outpoint(0x33, 0))], vec![txout(150_000, spk(PAYMENT))]);
        let two = raw(&orig_tx, &[vec![witness_utxo(100_000, &spk(SENDER_SPK))], vec![witness_utxo(60_000, &spk(SENDER_SPK))]]);
        let swapped = tx(vec![txin(outpoint(0x33, 0)), txin(outpoint(0x11, 0))], vec![txout(150_000, spk(PAYMENT))]);
        let report = compare(&two, &proposal_with(&swapped, &[vec![], vec![]], &[]), None);
        assert!(has_error(&report, "inputs_reordered"), "{report}");
    }

    #[test]
    fn finalization_must_match_input_ownership() {
        let sender_finalized = compare(&original(), &proposal_with(&proposal_tx(), &[vec![final_witness()], receiver_map()], &[]), None);
        assert!(has_error(&sender_finalized, "sender_input_finalized"), "{sender_finalized}");

        let unfinalized = vec![witness_utxo(30_000, &spk(RECEIVER_SPK))];
        let receiver_open = compare(&original(), &proposal_with(&proposal_tx(), &[vec![], unfinalized], &[]), None);
        assert!(has_error(&receiver_open, "receiver_input_not_finalized"), "{receiver_open}");
        // The receiver input is still identified: ownership comes from the
        // outpoint, not from the finalization state.
        assert_eq!(receiver_open["receiverInputs"], json!([1]));
    }

    #[test]
    fn a_receiver_input_needs_a_valid_utxo_claim() {
        let bare = compare(&original(), &proposal_with(&proposal_tx(), &[vec![], vec![final_witness()]], &[]), None);
        assert!(has_error(&bare, "receiver_input_missing_utxo"), "{bare}");
        assert_eq!(bare["receiverContribution"], Value::Null);

        // A non-witness UTXO for some other transaction claims nothing.
        let prev = tx(vec![txin(outpoint(0x44, 0))], vec![txout(30_000, spk(RECEIVER_SPK))]);
        let wrong = vec![(vec![0x00], encode::serialize(&prev)), final_witness()];
        let report = compare(&original(), &proposal_with(&proposal_tx(), &[vec![], wrong], &[]), None);
        assert!(has_error(&report, "receiver_input_missing_utxo"), "{report}");

        // The same UTXO under the right outpoint is accepted.
        let mut t = proposal_tx();
        t.input[1].previous_output = OutPoint { txid: prev.compute_txid(), vout: 0 };
        let right = vec![(vec![0x00], encode::serialize(&prev)), final_witness()];
        let report = compare(&original(), &proposal_with(&t, &[vec![], right], &[]), None);
        assert!(!codes(&report).contains(&"receiver_input_missing_utxo".to_string()), "{report}");
        assert_eq!(report["receiverContribution"], "30000");
    }

    #[test]
    fn keypaths_and_loose_signatures_in_a_proposal_are_rejected() {
        let sig = (vec![0x02].into_iter().chain([0x03; 33]).collect(), vec![0x30, 0x00]);
        let inputs = [vec![origin(0x06, [1, 2, 3, 4]), sig], receiver_map()];
        let outputs = [vec![origin(0x02, [1, 2, 3, 4])]];
        let report = compare(&original(), &proposal_with(&proposal_tx(), &inputs, &outputs), None);
        for code in ["input_keypaths", "input_signature", "output_keypaths"] {
            assert!(has_error(&report, code), "{code}: {report}");
        }
        let tap_sig = compare(&original(), &proposal_with(&proposal_tx(), &[vec![(vec![0x13], vec![0; 64])], receiver_map()], &[]), None);
        assert!(has_error(&tap_sig, "input_signature"), "{tap_sig}");
    }

    #[test]
    fn sequence_version_and_locktime_changes_are_rejected() {
        let mut t = proposal_tx();
        t.input[0].sequence = Sequence::MAX;
        t.version = Version(1);
        t.lock_time = LockTime::from_consensus(800_000);
        let report = compare(&original(), &proposal_with(&t, &[vec![], receiver_map()], &[]), None);
        for code in ["sender_sequence_changed", "mixed_sequence", "version_changed", "locktime_changed"] {
            assert!(has_error(&report, code), "{code}: {report}");
        }
    }

    #[test]
    fn a_lower_absolute_fee_is_rejected() {
        let mut t = proposal_tx();
        t.output[0].value = Amount::from_sat(90_000); // fee 1k < original 10k
        t.output[1].value = Amount::from_sat(39_000);
        let report = compare(&original(), &proposal_with(&t, &[vec![], receiver_map()], &[]), None);
        assert!(has_error(&report, "fee_decreased"), "{report}");
    }

    #[test]
    fn a_sender_output_drained_beyond_the_fee_increase_is_rejected() {
        let mut t = proposal_tx();
        t.output[0].value = Amount::from_sat(85_000); // receiver takes 5k of change
        t.output[1].value = Amount::from_sat(34_000); // fee still 11k: +1k
        let proposal = proposal_with(&t, &[vec![], receiver_map()], &[]);
        let known = compare(&original(), &proposal, Some(spk(PAYMENT).as_bytes()));
        assert!(has_error(&known, "contribution_not_to_fee"), "{known}");
        // Without the payment output the decrease is surfaced, not judged.
        let unknown = compare(&original(), &proposal, None);
        assert!(codes(&unknown).contains(&"output_decreased".to_string()));
        assert!(!has_error(&unknown, "contribution_not_to_fee"));
    }

    #[test]
    fn sender_input_amounts_come_from_the_original_not_the_proposal() {
        // A BIP-77 proposal carries UTXO data for sender inputs too; an
        // inflated claim there must not move the fee arithmetic.
        let inflated = vec![witness_utxo(100_000_000, &spk(SENDER_SPK))];
        let report = compare(&original(), &proposal_with(&proposal_tx(), &[inflated, receiver_map()], &[]), Some(spk(PAYMENT).as_bytes()));
        assert_eq!(report["fee"]["proposal"], "11000");
        assert_eq!(report["checklist"], "complete", "{report}");
    }

    #[test]
    fn unknown_original_amounts_leave_the_checklist_incomplete() {
        let t = tx(vec![txin(outpoint(0x11, 0))], vec![txout(50_000, spk(PAYMENT)), txout(40_000, spk(CHANGE))]);
        let no_utxo = raw(&t, &[vec![final_witness()]]);
        let report = compare(&no_utxo, &clean_proposal(), None);
        assert_eq!(report["fee"]["original"], Value::Null);
        assert_eq!(report["checklist"], "incomplete", "{report}");
    }

    #[test]
    fn shape_names_finalized_inputs_only_when_finalization_is_mixed() {
        let t = proposal_tx();
        let mixed = shape(&raw(&t, &[vec![], receiver_map()]).inputs);
        assert_eq!(mixed["proposalShape"], true);
        assert_eq!(mixed["candidateReceiverInputs"], json!([1]));
        assert_eq!(mixed["signal"], true);

        for inputs in [[receiver_map(), receiver_map()], [vec![], vec![]]] {
            let uniform = shape(&raw(&t, &inputs).inputs);
            assert_eq!(uniform["proposalShape"], false);
            assert_eq!(uniform["candidateReceiverInputs"], json!([]));
            assert_eq!(uniform["signal"], false);
        }
    }

    #[test]
    fn shape_counts_wallets_by_master_fingerprint() {
        let t = proposal_tx();
        let disjoint = shape(&raw(&t, &[vec![origin(0x06, [1; 4])], vec![origin(0x06, [2; 4])]]).inputs);
        assert_eq!(disjoint["originGroups"], 2);
        assert_eq!(disjoint["multiWallet"], true);
        assert_eq!(disjoint["signal"], true);

        // A shared cosigner fingerprint ties two multisig inputs together.
        let joined = shape(&raw(&t, &[
            vec![origin(0x06, [1; 4]), origin(0x06, [3; 4])],
            vec![origin(0x06, [2; 4]), origin(0x06, [3; 4])],
        ]).inputs);
        assert_eq!(joined["originGroups"], 1);
        assert_eq!(joined["multiWallet"], false);

        // Taproot origins count; a malformed origin is ignored, not a wallet.
        let mut tap_value = vec![0x00];
        tap_value.extend([2u8; 4]);
        tap_value.extend(0u32.to_le_bytes());
        let tap_key: Vec<u8> = std::iter::once(0x16).chain([0x04; 32]).collect();
        let tap = shape(&raw(&t, &[vec![origin(0x06, [1; 4])], vec![(tap_key, tap_value), (vec![0x06, 0x02], vec![1, 2])]]).inputs);
        assert_eq!(tap["originGroups"], 2);
    }

    #[test]
    fn inspect_carries_the_payjoin_shape() {
        let bytes = psbt(&proposal_tx(), &[vec![], receiver_map()], &[]);
        let doc: Value = serde_json::from_str(&crate::inspect(&bytes).unwrap()).unwrap();
        assert_eq!(doc["payjoin"]["proposalShape"], true);
        assert_eq!(doc["payjoin"]["candidateReceiverInputs"], json!([1]));
    }

    #[test]
    fn compare_request_accepts_hex_psbts_and_rejects_malformed_fields() {
        let t = tx(vec![txin(outpoint(0x11, 0))], vec![txout(50_000, spk(PAYMENT)), txout(40_000, spk(CHANGE))]);
        let original_hex = hex_encode(&psbt(&t, &[vec![witness_utxo(100_000, &spk(SENDER_SPK)), final_witness()]], &[]));
        let proposal_hex = hex_encode(&psbt(&proposal_tx(), &[vec![], receiver_map()], &[]));
        let payment_hex = hex_encode(spk(PAYMENT).as_bytes());

        let ok = |request: Value| -> Value {
            serde_json::from_str(&compare_request(request.to_string().as_bytes()).unwrap()).unwrap()
        };
        assert_eq!(ok(json!({ "original": original_hex, "proposal": proposal_hex }))["payjoin"], true);
        let with_payment = ok(json!({ "original": original_hex, "proposal": proposal_hex, "paymentScript": payment_hex }));
        assert_eq!(with_payment["checklist"], "complete");

        for bad in [
            json!({ "proposal": proposal_hex }),
            json!({ "original": original_hex, "proposal": 7 }),
            json!({ "original": original_hex, "proposal": "zz" }),
            json!({ "original": original_hex, "proposal": "70736274ff" }),
            json!({ "original": original_hex, "proposal": proposal_hex, "paymentScript": 1 }),
            json!({ "original": original_hex, "proposal": proposal_hex, "paymentScript": "abc" }),
        ] {
            assert!(compare_request(bad.to_string().as_bytes()).is_err(), "{bad}");
        }
        assert!(compare_request(b"not json").is_err());
    }
}
