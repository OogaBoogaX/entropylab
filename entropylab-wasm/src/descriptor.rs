//! Output-descriptor evaluation on rust-miniscript: it parses descriptors
//! and derives their scripts/addresses (BIP380-386; multipath is refused
//! because one call derives one output). Taproot `sortedmulti_a` — the
//! tapscript sorted multisig — is not implemented by rust-miniscript
//! (multi_a is, sortedmulti only for sh/wsh), so the keys are derived here,
//! sorted as x-only bytes, and the expression rewritten to the multi_a it
//! denotes before rust-miniscript sees it.
//!
//! The boundary is one export, `el_desc_derive`: descriptor text and a child
//! index in, a newline-separated record out — address (empty when the
//! template has none), scriptPubKey hex, then the comma-separated derived
//! keys (compressed hex) so the caller can enforce its own key-distinctness
//! policy. Everything here is watch-only in effect: xprv/WIF key expressions
//! are accepted but are reduced to their public keys immediately; the few
//! secret temporaries live only for the call, like the existing BIP32 path
//! (see the crate doc's residual note).

use crate::{ctx, read, wipe_string};
use bitcoin::bip32::ChildNumber;
use bitcoin::{Network, PublicKey as BtcPublicKey, ScriptBuf};
use miniscript::descriptor::{checksum, DescriptorPublicKey, DescriptorSecretKey, SinglePubKey, Wildcard};
use miniscript::{Descriptor, ForEachKey};
use std::str::FromStr;

/// App-built descriptors are under 2 KB; capping the input bounds parse
/// recursion depth ahead of rust-miniscript's own limits.
const MAX_DESCRIPTOR_BYTES: usize = 16_384;

/// Parses a BIP380 key expression (hex key, xpub/xprv with optional origin
/// and path, or WIF) and reduces secrets to their public half.
fn parse_key_expression(text: &str) -> Result<DescriptorPublicKey, String> {
    match DescriptorSecretKey::from_str(text) {
        Ok(secret) => secret
            .to_public(ctx())
            .map_err(|_| "invalid key expression".to_string()),
        Err(_) => DescriptorPublicKey::from_str(text).map_err(|_| "invalid key expression".to_string()),
    }
}

/// The compressed encoding of one sortedmulti_a participant's key at child
/// `index`: fixed path steps are applied, and a trailing `/*` derives the
/// child at `index`.
fn participant_public_key(key: &DescriptorPublicKey, index: u32) -> Result<[u8; 33], String> {
    match key {
        DescriptorPublicKey::Single(single) => match single.key {
            SinglePubKey::FullKey(pk) => {
                if !pk.compressed {
                    return Err("uncompressed public keys cannot be taproot multisig participants".into());
                }
                Ok(pk.inner.serialize())
            }
            SinglePubKey::XOnly(xpk) => {
                // An x-only key is its even-y lift (BIP340), compressed form.
                let mut bytes = [0u8; 33];
                bytes[0] = 0x02;
                bytes[1..].copy_from_slice(&xpk.serialize());
                Ok(bytes)
            }
        },
        DescriptorPublicKey::XPub(xkey) => {
            let mut node = xkey.xkey;
            for step in xkey.derivation_path.as_ref() {
                node = node
                    .ckd_pub(ctx(), *step)
                    .map_err(|_| "cannot derive a hardened step from an xpub participant".to_string())?;
            }
            match xkey.wildcard {
                Wildcard::None => {}
                Wildcard::Unhardened => {
                    let child =
                        ChildNumber::from_normal_idx(index).map_err(|_| "derivation index out of range".to_string())?;
                    node = node
                        .ckd_pub(ctx(), child)
                        .map_err(|_| "participant key derivation failed".to_string())?;
                }
                Wildcard::Hardened => {
                    return Err("a hardened wildcard cannot be derived from an xpub participant".into());
                }
            }
            Ok(node.public_key.serialize())
        }
        DescriptorPublicKey::MultiXPub(_) => {
            Err("multipath key expressions are not supported in sortedmulti_a".into())
        }
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from_digit((byte >> 4) as u32, 16).unwrap_or('0'));
        out.push(char::from_digit((byte & 15) as u32, 16).unwrap_or('0'));
    }
    out
}

/// Splits an argument list on its top-level commas (origin brackets carry
/// no commas, but the depth counting keeps the rule obvious).
fn split_top_level(args: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut depth = 0usize;
    let mut start = 0;
    for (i, ch) in args.char_indices() {
        match ch {
            '(' | '[' | '<' => depth += 1,
            ')' | ']' | '>' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                out.push(&args[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    out.push(&args[start..]);
    out
}

/// sortedmulti_a(k, keys…) — the tapscript sorted multisig — is not
/// implemented by rust-miniscript (multi_a is, sortedmulti only for
/// sh/wsh), so the keys are derived here, sorted as x-only bytes, and the
/// expression rewritten to the multi_a it denotes.
fn rewrite_sorted_multi_a(args: &str, index: u32) -> Result<String, String> {
  let parts = split_top_level(args);
  if parts.len() < 2 {
      return Err("sortedmulti_a needs a threshold and at least one key".into());
  }
  let threshold = parts[0].trim();
  if threshold.is_empty() || !threshold.bytes().all(|b| b.is_ascii_digit()) {
      return Err("invalid sortedmulti_a threshold".into());
  }
  let mut keys: Vec<[u8; 32]> = Vec::new();
  for arg in &parts[1..] {
      if arg.is_empty() {
          return Err("empty sortedmulti_a key".into());
      }
      let key = parse_key_expression(arg)?;
      let plain = participant_public_key(&key, index)?;
      let mut xonly = [0u8; 32];
      xonly.copy_from_slice(&plain[1..]);
      keys.push(xonly);
  }
  keys.sort();
  let mut out = format!("multi_a({}", threshold);
  for key in keys {
      out.push(',');
      out.push_str(&hex_lower(&key));
  }
  out.push(')');
  Ok(out)
}

/// Replaces every `sortedmulti_a(...)` in `body` with the multi_a it denotes
/// (keys derived at child `index`, then sorted as x-only bytes). The fragment
/// must sit in argument position (after '(', ',', '{', or ':'); the resulting
/// string is validated by rust-miniscript afterwards.
fn substitute_sorted_multi_a(body: &str, index: u32) -> Result<String, String> {
    let mut out = body.to_owned();
    let mut cursor = 0usize;
    while let Some(found) = out[cursor..].find("sortedmulti_a(") {
        let start = cursor + found;
        let prev = if start == 0 { None } else { Some(out.as_bytes()[start - 1]) };
        if !matches!(prev, Some(b'(') | Some(b',') | Some(b'{') | Some(b':')) {
            return Err("sortedmulti_a() can only appear where a miniscript fragment is expected".into());
        }
        let open = start + "sortedmulti_a".len();
        let bytes = out.as_bytes();
        let mut depth = 1usize;
        let mut i = open + 1;
        let mut close = None;
        while i < bytes.len() {
            match bytes[i] {
                b'(' => depth += 1,
                b')' => {
                    depth -= 1;
                    if depth == 0 {
                        close = Some(i);
                        break;
                    }
                }
                _ => {}
            }
            i += 1;
        }
        let close = close.ok_or_else(|| "unbalanced sortedmulti_a() expression".to_string())?;
        let replacement = rewrite_sorted_multi_a(&out[open + 1..close], index)?;
        out.replace_range(start..=close, &replacement);
        cursor = start + replacement.len();
    }
    Ok(out)
}

struct Derived {
    address: Option<String>,
    script_pubkey: ScriptBuf,
    keys: Vec<BtcPublicKey>,
}

fn derive_miniscript(body: &str, index: u32, network: Network) -> Result<Derived, String> {
    let (descriptor, secrets) = Descriptor::parse_descriptor(ctx(), body).map_err(|e| format!("invalid descriptor: {}", e))?;
    drop(secrets); // parsed xprv/WIF keys; only their public halves are used
    if descriptor.is_multipath() {
        return Err("a multipath descriptor denotes several wallets; derive one branch at a time".into());
    }
    let concrete = descriptor
        .derived_descriptor(ctx(), index)
        .map_err(|_| "descriptor cannot be derived at this index".to_string())?;
    let script_pubkey = concrete.script_pubkey();
    let address = concrete.address(network).ok().map(|a| a.to_string());
    let mut keys = Vec::new();
    concrete.for_each_key(|key| {
        keys.push(*key);
        true
    });
    Ok(Derived {
        address,
        script_pubkey,
        keys,
    })
}

fn derive_descriptor(body: &str, index: u32, network: Network) -> Result<Derived, String> {
    if body.is_empty() || body.len() > MAX_DESCRIPTOR_BYTES {
        return Err("descriptor length out of range".into());
    }
    if !body.contains("sortedmulti_a(") {
        return derive_miniscript(body, index, network);
    }
    // sortedmulti_a() is tapscript-only; anything else containing it is
    // rejected outright.
    if !body.starts_with("tr(") {
        return Err("sortedmulti_a() is only allowed inside tr() expressions".into());
    }
    let mut substituted = substitute_sorted_multi_a(body, index)?;
    let result = derive_miniscript(&substituted, index, network);
    wipe_string(&mut substituted);
    result
}

/// Evaluates a descriptor at child `index` and writes the record
/// `address\nscriptPubKeyHex\nkeyHex,keyHex,...` (address empty when the
/// template has none). Returns the record length, -1 on any parse/derivation
/// failure, or -2 when `cap` is too small.
#[no_mangle]
pub unsafe extern "C" fn el_desc_derive(
    desc: *const u8,
    desc_len: usize,
    index: u32,
    net: u8,
    out: *mut u8,
    cap: usize,
) -> i32 {
    let text = match std::str::from_utf8(read(desc, desc_len)) {
        Ok(text) => text,
        Err(_) => return -1,
    };
    let network = match crate::network_from_selector(net) {
        Some(network) => network,
        None => return -1,
    };
    let body = match checksum::verify_checksum(text) {
        Ok(body) => body,
        Err(_) => return -1,
    };
    let derived = match derive_descriptor(body, index, network) {
        Ok(derived) => derived,
        // Error text can embed the failing fragment, and the input may carry
        // xprv/WIF material: wipe before returning the bare -1 sentinel.
        Err(mut error) => {
            wipe_string(&mut error);
            return -1;
        }
    };
    let mut record = String::new();
    if let Some(address) = derived.address {
        record.push_str(&address);
    }
    record.push('\n');
    for byte in derived.script_pubkey.as_bytes() {
        record.push(char::from_digit((byte >> 4) as u32, 16).unwrap_or('0'));
        record.push(char::from_digit((byte & 15) as u32, 16).unwrap_or('0'));
    }
    record.push('\n');
    for (i, key) in derived.keys.iter().enumerate() {
        if i > 0 {
            record.push(',');
        }
        for byte in key.inner.serialize() {
            record.push(char::from_digit((byte >> 4) as u32, 16).unwrap_or('0'));
            record.push(char::from_digit((byte & 15) as u32, 16).unwrap_or('0'));
        }
    }
    if record.len() > cap {
        wipe_string(&mut record);
        return -2;
    }
    std::ptr::copy_nonoverlapping(record.as_ptr(), out, record.len());
    let len = record.len() as i32;
    wipe_string(&mut record);
    len
}

#[cfg(test)]
mod tests {
    use super::*;

    const NET: Network = Network::Bitcoin;

    fn script_hex(body: &str, index: u32) -> String {
        let derived = derive_descriptor(body, index, NET).expect("descriptor derives");
        derived
            .script_pubkey
            .as_bytes()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect()
    }

    // -- rust-miniscript-backed multisig ---------------------------------------

    // Three fixed test keys (the published BIP67-style vector keys, also used
    // by the app's multisig vectors).
    const VK: [&str; 3] = [
        "02F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
        "03DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
        "023590A94E768F8E1815C2F24B4D80A8E3149316C3518CE7B7AD338368D038CA66",
    ];

    #[test]
    fn multisig_descriptors_derive_through_miniscript() {
        // BIP67-sorted 2-of-3 over three fixed test keys, each wrapped form.
        let inner = format!("sortedmulti(2,{},{},{})", VK[0].to_lowercase(), VK[1].to_lowercase(), VK[2].to_lowercase());
        for (wrapper, prefix) in [("sh", "a914"), ("wsh", "0020"), ("sh(wsh", "a914")] {
            let body = if wrapper == "sh(wsh" {
                format!("sh(wsh({}))", inner)
            } else {
                format!("{}({})", wrapper, inner)
            };
            let derived = derive_descriptor(&body, 0, NET).expect("multisig derives");
            assert!(derived.script_pubkey.as_bytes().starts_with(&[0xa9, 0x14]) == prefix.starts_with("a9"));
            assert!(derived.address.is_some());
            assert_eq!(derived.keys.len(), 3);
        }
        // sortedmulti is order-independent; multi preserves the listed order.
        let reversed = format!("sortedmulti(2,{},{},{})", VK[2].to_lowercase(), VK[1].to_lowercase(), VK[0].to_lowercase());
        assert_eq!(script_hex(&format!("wsh({})", inner), 0), script_hex(&format!("wsh({})", reversed), 0));
        let listed = format!("multi(2,{},{},{})", VK[2].to_lowercase(), VK[1].to_lowercase(), VK[0].to_lowercase());
        assert_ne!(script_hex(&format!("wsh({})", inner), 0), script_hex(&format!("wsh({})", listed), 0));
    }

    #[test]
    fn sortedmulti_a_is_derived_sorted_and_matches_the_wallet_vector() {
        // The app's Taproot multisig: NUMS internal key, sortedmulti_a leaf.
        // Expected values are the ones test/msig-address-kinds.test.mjs pins
        // against @scure/btc-signer for secret keys 1, 2, 3.
        let nums = "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0";
        let keys = [
            "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
            "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
            "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
        ];
        let desc = format!("tr({},sortedmulti_a(2,{}))", nums, keys.join(","));
        let derived = derive_descriptor(&desc, 0, NET).expect("sortedmulti_a derives");
        assert_eq!(
            derived.address.as_deref(),
            Some("bc1pm5jn9xnjz3v9xm7jjw2yheajy92pps5fdazdpfnmvzfymu787hhs2vktyy")
        );
        // Key order must not matter for sortedmulti_a...
        let mut shuffled = keys;
        shuffled.reverse();
        let desc_rev = format!("tr({},sortedmulti_a(2,{}))", nums, shuffled.join(","));
        assert_eq!(script_hex(&desc, 0), script_hex(&desc_rev, 0));
        // ...but must be preserved by multi_a.
        let listed = format!("tr({},multi_a(2,{}))", nums, shuffled.join(","));
        assert_ne!(script_hex(&desc, 0), script_hex(&listed, 0));
        // testnet rendering uses the same script.
        let testnet = derive_descriptor(&desc, 0, Network::Testnet).expect("testnet derives");
        assert_eq!(
            testnet.address.as_deref(),
            Some("tb1pm5jn9xnjz3v9xm7jjw2yheajy92pps5fdazdpfnmvzfymu787hhsayqy7t")
        );
        // Signet shares the testnet encodings; regtest keeps the script but
        // switches the bech32 HRP to bcrt (issue #329).
        let signet = derive_descriptor(&desc, 0, Network::Signet).expect("signet derives");
        assert_eq!(signet.address.as_deref(), testnet.address.as_deref());
        let regtest = derive_descriptor(&desc, 0, Network::Regtest).expect("regtest derives");
        assert_eq!(regtest.script_pubkey, testnet.script_pubkey);
        assert!(regtest.address.as_deref().is_some_and(|a| a.starts_with("bcrt1p")));
    }

    #[test]
    fn ranged_xpub_descriptor_matches_bip86_vector() {
        // BIP86's own test key: tr(xpub.../0/*) at index 0 is the published address.
        let body = "tr(xpub6BgBgsespWvERF3LHQu6CnqdvfEvtMcQjYrcRzx53QJjSxarj2afYWcLteoGVky7D3UKDP9QyrLprQ3VCECoY49yfdDEHGCtMMj92pReUsQ/0/*)";
        let derived = derive_descriptor(body, 0, NET).expect("bip86 descriptor");
        assert_eq!(
            derived.address.as_deref(),
            Some("bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr")
        );
    }
}
