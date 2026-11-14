//! Offline payjoin signals (issue #446).
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
//! The two-file BIP-78 sender checklist (Original PSBT against Payjoin
//! Proposal) is not here: it is decided from the sender's own inputs and
//! outputs in JavaScript, where its spec cases are tested with the app.

use crate::sanitize::{parse_origin, tap_origin};
use crate::RawPair;
use serde_json::{json, Value};
use std::collections::{BTreeSet, HashMap};

/// BIP-174 finalized: a keyless PSBT_IN_FINAL_SCRIPTSIG or
/// PSBT_IN_FINAL_SCRIPTWITNESS is present.
fn is_finalized(map: &[RawPair]) -> bool {
    map.iter().any(|pair| pair.key == [0x07] || pair.key == [0x08])
}

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{parse_raw, push_pair, RawPsbt};
    use bitcoin::consensus::encode;
    use bitcoin::hashes::Hash as _;
    use bitcoin::locktime::absolute::LockTime;
    use bitcoin::transaction::Version;
    use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness};

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
    const CHANGE: u8 = 0xcc;
    const RECEIVER_SPK: u8 = 0xee;

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
}
