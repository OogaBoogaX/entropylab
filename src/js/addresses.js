// Bitcoin script and address construction for EntropyLab, backed by
// rust-bitcoin's Address/ScriptBuf compiled to WebAssembly (Rust crate in
// entropylab-wasm/, loaded by entropylab-wasm.js).
//
// Drop-in replacement for the slice of @scure/btc-signer the app uses:
// p2pkh/p2sh-p2wpkh/p2wpkh/p2tr address rendering, P2SH/P2WSH wrapping,
// bare and taproot multisig leaf scripts, and script -> address rendering
// (which returns null for unknown templates, like the previous fallback that
// showed the script hex). Networks are "mainnet" | "testnet".
//
// descriptorDerive is the rust-miniscript side of the crate: it parses an
// output descriptor (BIP380-386 key expressions, xpubs and xprvs included),
// derives the child at `index`, and returns the address, the scriptPubKey
// hex, and the derived keys (compressed hex) so callers can enforce
// key-distinctness policies of their own.
import { wasmExports as wasm, withInput, withOutput } from "./entropylab-wasm.js";

const textDecoder = new TextDecoder();
const textEncoder = new TextEncoder();
const SCRIPT_CAP = 4096; // every script the app builds is far smaller
const ADDRESS_CAP = 128; // a v1 bech32m address is <= 74 chars for known templates
const DESCRIPTOR_CAP = 4096; // address + scriptPubKey hex + 15 multisig keys is ~1.2 KB

const netOf = (network) => {
  if (network === "mainnet") return 0;
  if (network === "testnet") return 1;
  throw new Error("Unknown Bitcoin network: " + network);
};

const assertBytes = (bytes, what) => {
  if (!(bytes instanceof Uint8Array)) throw new Error(`${what} must be a Uint8Array.`);
};

// Runs `fn(ptr, len, out, cap)` with `input` copied into WASM memory.
const scriptCall = (input, fn) => withInput(input, (p) => withOutput(SCRIPT_CAP, (out) => fn(p, input.length, out, SCRIPT_CAP)));

export const p2pkhScript = (pubkey) => {
  assertBytes(pubkey, "Public key");
  const script = scriptCall(pubkey, (p, len, out, cap) => wasm().el_spk_p2pkh(p, len, out, cap));
  if (!script) throw new Error("Invalid public key for P2PKH.");
  return script;
};

export const p2wpkhScript = (pubkey) => {
  assertBytes(pubkey, "Public key");
  const script = scriptCall(pubkey, (p, len, out, cap) => wasm().el_spk_p2wpkh(p, len, out, cap));
  if (!script) throw new Error("P2WPKH needs a compressed public key.");
  return script;
};

export const p2shP2wpkhScript = (pubkey) => {
  assertBytes(pubkey, "Public key");
  const script = scriptCall(pubkey, (p, len, out, cap) => wasm().el_spk_p2sh_p2wpkh(p, len, out, cap));
  if (!script) throw new Error("P2SH-P2WPKH needs a compressed public key.");
  return script;
};

// BIP86 key-path-only Taproot output (internal key tweaked with no tree).
export const p2trKeyScript = (xonly) => {
  assertBytes(xonly, "x-only key");
  if (xonly.length !== 32) throw new Error("Taproot internal key must be 32 bytes.");
  const script = scriptCall(xonly, (p, len, out, cap) => wasm().el_spk_p2tr_key(p, out, cap));
  if (!script) throw new Error("Invalid Taproot internal key.");
  return script;
};

// P2TR output with a single-leaf tapscript tree (the multisig Taproot case).
export const p2trLeafScript = (xonly, leaf) => {
  assertBytes(xonly, "x-only key");
  assertBytes(leaf, "Taproot leaf script");
  if (xonly.length !== 32) throw new Error("Taproot internal key must be 32 bytes.");
  const script = withInput(xonly, (k) =>
    withInput(leaf, (l) => withOutput(SCRIPT_CAP, (out) => wasm().el_spk_p2tr_leaf(k, l, leaf.length, out, SCRIPT_CAP)))
  );
  if (!script) throw new Error("Invalid Taproot key or leaf script.");
  return script;
};

// P2SH scriptPubKey wrapping an arbitrary redeem script.
export const p2shScript = (script) => {
  assertBytes(script, "Redeem script");
  const out = scriptCall(script, (p, len, o, cap) => wasm().el_spk_p2sh(p, len, o, cap));
  if (!out) throw new Error("Invalid redeem script.");
  return out;
};

// P2WSH scriptPubKey for an arbitrary witness script.
export const p2wshScript = (script) => {
  assertBytes(script, "Witness script");
  const out = scriptCall(script, (p, len, o, cap) => wasm().el_spk_p2wsh(p, len, o, cap));
  if (!out) throw new Error("Invalid witness script.");
  return out;
};

const concatKeys = (keys, size, what) => {
  const out = new Uint8Array(keys.length * size);
  keys.forEach((key, i) => {
    assertBytes(key, what);
    if (key.length !== size) throw new Error(`${what} must be ${size} bytes.`);
    out.set(key, i * size);
  });
  return out;
};

// Bare multisig redeem script: OP_m <keys..> OP_n OP_CHECKMULTISIG.
export const multisigScript = (m, pubkeys) => {
  const packed = concatKeys(pubkeys, 33, "Multisig public key");
  const script = withInput(packed, (p) => withOutput(SCRIPT_CAP, (out) => wasm().el_script_multisig(m, p, packed.length, out, SCRIPT_CAP)));
  if (!script) throw new Error("Invalid multisig parameters (need 0 < m <= n <= 16 with valid keys).");
  return script;
};

// Taproot multisig leaf: <pk1> OP_CHECKSIG <pk2> OP_CHECKSIGADD .. <m> OP_NUMEQUAL.
export const multisigTrScript = (m, xonlyKeys) => {
  const packed = concatKeys(xonlyKeys, 32, "Multisig x-only key");
  const script = withInput(packed, (p) => withOutput(SCRIPT_CAP, (out) => wasm().el_script_multisig_tr(m, p, packed.length, out, SCRIPT_CAP)));
  if (!script) throw new Error("Invalid taproot multisig parameters (need 0 < m <= n <= 999 with valid keys).");
  return script;
};

// Renders a scriptPubKey as an address, or returns null for unknown
// templates (the caller shows the script hex, as before).
export const addressFromScript = (script, network) => {
  assertBytes(script, "Script");
  const net = netOf(network);
  const out = withInput(script, (p) =>
    withOutput(ADDRESS_CAP, (o) => wasm().el_addr_from_script(p, script.length, net, o, ADDRESS_CAP))
  );
  return out ? textDecoder.decode(out) : null;
};

// Evaluates an output descriptor at a child index: the address (null when
// the template has none, e.g. bare scripts), the scriptPubKey hex, and the
// derived participant keys (compressed hex, descriptor order; multisig
// sortedmulti/multi_a keys are pre-sort). Multipath (<0;1>) descriptors are
// refused: one call derives one output — pass a single branch. A present
// #checksum is verified by the crate. Throws on any parse or derivation
// failure, exactly like the script builders above return null/throw.
export const descriptorDerive = (descriptor, index, network) => {
  if (!Number.isSafeInteger(index) || index < 0 || index > 2147483647) throw new Error("Descriptor derivation index must be 0 to 2,147,483,647.");
  const bytes = textEncoder.encode(String(descriptor ?? ""));
  const net = netOf(network);
  const record = withInput(bytes, (p) =>
    withOutput(DESCRIPTOR_CAP, (out) => wasm().el_desc_derive(p, bytes.length, index, net, out, DESCRIPTOR_CAP))
  );
  if (!record) throw new Error("Invalid output descriptor, or it cannot be derived at this index.");
  const [address, scriptHex, keys] = textDecoder.decode(record).split("\n");
  return { address: address || null, scriptHex, pubkeys: keys ? keys.split(",") : [] };
};

// One-call helpers for the four single-signature templates, mirroring how the
// app used scure's p2pkh/p2sh(p2wpkh)/p2wpkh/p2tr .address getters.
export const addressFor = (scriptType, pubkey, network) => {
  switch (scriptType) {
    case "p2pkh":
      return addressFromScript(p2pkhScript(pubkey), network);
    case "p2sh-p2wpkh":
      return addressFromScript(p2shP2wpkhScript(pubkey), network);
    case "p2wpkh":
      return addressFromScript(p2wpkhScript(pubkey), network);
    case "p2tr": {
      const xonly = pubkey.length === 33 ? pubkey.slice(1) : pubkey;
      return addressFromScript(p2trKeyScript(xonly), network);
    }
    default:
      throw new Error("Unknown script type: " + scriptType);
  }
};
