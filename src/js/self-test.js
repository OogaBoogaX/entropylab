// Known-answer self-test: before boot wires a single input, run published
// test vectors through the same WebAssembly engine and JS glue the
// calculator uses, and refuse to start when this host computes any of them
// wrong. browser-check.js confirms the platform features exist (the
// WebAssembly check there only compiles an empty module); this confirms the
// host actually executes libsecp256k1, rust-bitcoin and rust-bip39 correctly.
// A miscompiling engine, a corrupted artifact, or a broken facade produces
// wrong keys silently; a fixed vector turns that into a visible failure.
//
// What this cannot catch: a targeted exploit that recognises these inputs,
// or a bug confined to inputs no vector exercises. It is a floor under the
// host, not a proof about it.
//
// PSBT_SELF_TESTS do the same for the separate rust-bitcoin PSBT module that
// decides what the PSBT tools show: amounts, scripts, fees, which files are
// refused, which signatures count. Boot runs them whenever that module loads
// (see app.js); a module that fails to load is left to the PSBT tools, which
// already report it when used.
//
// Every expected value is a published vector (BIP32 test vector 1, the BIP39
// reference vectors, the BIP44/49/84/86 "abandon ... about" first receive
// addresses, the d = 1 "Satoshi Nakamoto" RFC 6979 signature, the published
// root keys and hardcoded node pubkeys of the Lightning LND/LDK node
// derivations), checked
// against @scure/bip32, @scure/bip39, @scure/btc-signer and @noble/curves in
// test/self-test-wasm.test.mjs. No randomness is generated or consumed.
import { entropyToMnemonic, mnemonicToSeedSync } from "./bip39.js";
import { HDKey } from "./hdkey.js";
import { addressFor } from "./addresses.js";
import { secp256k1 } from "./secp256k1.js";
import { hex } from "./coders.js";
import { psbtInspectDoc, psbtBuildBytes } from "./psbt-wasm.js";
import { psbtEditorBuildDoc } from "./psbt-editor.js";
import { deriveLndNode, deriveLdkNode } from "./lightning.js";

const ABANDON = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const BIP32_V1_SEED = "000102030405060708090a0b0c0d0e0f";
const BIP32_V1_XPUB_M_0H_1_2H = "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5";
// sha256("Satoshi Nakamoto"), signed with secret key 1.
const ECDSA_MSGHASH = "a0dc65ffca799873cbea0ac274015b9526505daaaed385155425f7337704883e";
const ECDSA_SIG =
  "934b1ea10a4b3c1757e2b0c017d0b6143ce3c9a7e6a4a49860d7a6ab210ee3d8" +
  "2442ce9d2b916064108014783e923ec36b49743e2ffa1c4496f01a512aafd9e5";
const secretKeyOne = () => {
  const key = new Uint8Array(32);
  key[31] = 1;
  return key;
};

// The four address tests share one root so PBKDF2 runs once, not four times.
// It is a published test key, so holding it for the page's life is harmless.
let abandonRoot = null;
const firstReceive = (purpose, scriptType) => {
  if (!abandonRoot) abandonRoot = HDKey.fromMasterSeed(mnemonicToSeedSync(ABANDON));
  return addressFor(scriptType, abandonRoot.derive(`m/${purpose}'/0'/0'/0/0`).publicKey, "mainnet");
};

// The Lightning node pubkey is the tool's security-relevant output, so the
// Lightning self-tests gate it too, not just the path and root xprv. The
// expected pubkeys are HARDCODED constants, never values re-derived through
// the engine under test: a systematic engine fault — one shared by the
// tool's derivation and any boot-time re-derivation — could otherwise make
// the two agree on a wrong key and boot with a wrong node identity. Every
// constant is proven equal to the value @scure/bip32 + @scure/bip39 derive
// for the same input in test/self-test-wasm.test.mjs, so the oracle is the
// independent implementation; the tool's own outputs are differentials
// against @scure in test/lightning.test.mjs.
// LND: BIP32 test vector 1's seed at m/1017'/coinType'/6'/0/0.
export const LND_MAINNET_NODE_PUBKEY = "0282faf17eeae0aa1dbdbe49c4fcbdb6738595ead9afdd7f8fb4a22c6c44d2849b";
export const LND_TESTNET_NODE_PUBKEY = "02a14ebdb9129db3dee2220dd26e01da2dba312dd086e61653c4faaebca3fb31c8";
// LDK (ldk-node): the "abandon ... about" seed, re-seeded from the stage-1
// master's private key, at m/0' — and, apart from it, the plain m/0' of the
// seed that a skipped second-stage re-seed would derive instead.
export const LDK_NODE_PUBKEY = "027cf7c81dc777e46572ff964f17650a0f6f783319fcc140fb9a69425e2fbdc93c";
export const LDK_PLAIN_NODE_PUBKEY = "027f1d87730e460e921b382242911565bf93daf2081ed685b2edd1d01176b2c13c";

// Names are trusted literals: the failure screen renders them as markup.
export const SELF_TESTS = [
  {
    name: "BIP39 mnemonic encoding",
    expected: "legal winner thank year wave sausage worth useful legal winner thank yellow",
    run: () => entropyToMnemonic(hex.decode("7f".repeat(16))),
  },
  {
    name: "BIP39 seed (PBKDF2-HMAC-SHA512)",
    expected:
      "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e5349553" +
      "1f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04",
    run: () => hex.encode(mnemonicToSeedSync(ABANDON, "TREZOR")),
  },
  {
    name: "BIP32 private derivation",
    expected: "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76",
    run: () => HDKey.fromMasterSeed(hex.decode(BIP32_V1_SEED)).derive("m/0'/1/2'/2/1000000000").privateExtendedKey,
  },
  {
    // Public-only (neutered) derivation from the published m/0'/1/2' xpub
    // must land on the same child as private derivation does.
    name: "BIP32 public derivation",
    expected: "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy",
    run: () => HDKey.fromExtendedKey(BIP32_V1_XPUB_M_0H_1_2H).derive("m/2/1000000000").publicExtendedKey,
  },
  { name: "P2PKH address (BIP44)", expected: "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA", run: () => firstReceive(44, "p2pkh") },
  { name: "P2SH-P2WPKH address (BIP49)", expected: "37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf", run: () => firstReceive(49, "p2sh-p2wpkh") },
  { name: "P2WPKH address (BIP84)", expected: "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu", run: () => firstReceive(84, "p2wpkh") },
  { name: "P2TR address (BIP86)", expected: "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr", run: () => firstReceive(86, "p2tr") },
  {
    name: "ECDSA signing (RFC 6979)",
    expected: ECDSA_SIG,
    run: () => hex.encode(secp256k1.sign(hex.decode(ECDSA_MSGHASH), secretKeyOne(), { prehash: false, extraEntropy: false })),
  },
  {
    // Fail-open is the dangerous direction: a verifier that accepts anything
    // would report forged signatures as valid. Require both answers.
    name: "ECDSA verification",
    expected: "valid:true tampered:false",
    run: () => {
      const pubkey = secp256k1.getPublicKey(secretKeyOne(), true);
      const msghash = hex.decode(ECDSA_MSGHASH);
      const tampered = hex.decode(ECDSA_SIG);
      tampered[63] ^= 1;
      const valid = secp256k1.verify(hex.decode(ECDSA_SIG), msghash, pubkey, { prehash: false });
      const forged = secp256k1.verify(tampered, msghash, pubkey, { prehash: false });
      return `valid:${valid} tampered:${forged}`;
    },
  },
  {
    // LND (lnd/keychain/derivation.go): the aezeed entropy is the BIP32
    // seed; the node key sits at m/1017'/coinType'/6'/0/0. The published
    // characterization entropy (test/lightning.test.mjs) equals BIP32 test
    // vector 1's seed, so the root xprv is the BIP's published chain-m key.
    // The node pubkey itself is a hardcoded constant proven against
    // @scure/bip32 in test/self-test-wasm.test.mjs.
    name: "LND node key (aezeed, mainnet)",
    expected: "m/1017'/0'/6'/0/0 xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi",
    run: () => {
      const derived = deriveLndNode(hex.decode(BIP32_V1_SEED), 0);
      if (derived.nodePubKey !== LND_MAINNET_NODE_PUBKEY) throw new Error("LND mainnet node pubkey mismatch");
      return `${derived.path} ${derived.rootXprv}`;
    },
  },
  {
    name: "LND node key (aezeed, testnet)",
    expected: "m/1017'/1'/6'/0/0 xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi",
    run: () => {
      const derived = deriveLndNode(hex.decode(BIP32_V1_SEED), 1);
      if (derived.nodePubKey !== LND_TESTNET_NODE_PUBKEY) throw new Error("LND testnet node pubkey mismatch");
      return `${derived.path} ${derived.rootXprv}`;
    },
  },
  {
    // ldk-node: BIP39 seed -> master -> its private key re-seeds a second
    // BIP32 tree -> node secret at m/0'. The first-stage root xprv is the
    // published "abandon ... about" root (the BIP84 vector's key); the node
    // pubkey is a hardcoded constant proven against @scure in
    // test/self-test-wasm.test.mjs.
    name: "LDK node key (ldk-node)",
    expected: "m/0' xprv9s21ZrQH143K3GJpoapnV8SFfukcVBSfeCficPSGfubmSFDxo1kuHnLisriDvSnRRuL2Qrg5ggqHKNVpxR86QEC8w35uxmGoggxtQTPvfUu",
    run: () => {
      const derived = deriveLdkNode(ABANDON);
      if (derived.nodePubKey !== LDK_NODE_PUBKEY) throw new Error("LDK node pubkey mismatch");
      // A skipped second-stage re-seed yields exactly the plain m/0' child,
      // so refuse it even when both derivations agree on the wrong key.
      if (derived.nodePubKey === LDK_PLAIN_NODE_PUBKEY) throw new Error("LDK node pubkey skipped the second-stage re-seed");
      return `${derived.path} ${derived.rootXprv}`;
    },
  },
];

// BIP-174 valid vector 2 and invalid vector 2, and BIP-370 minimal valid v2,
// verbatim from the BIPs (hex; the same bytes test/psbt-wasm.test.mjs uses).
const BIP174_VALID_2 =
  "70736274ff0100a00200000002ab0949a08c5af7c49b8212f417e2f15ab3f5c33dcf153821a8139f877a5b7be4000000" +
  "0000feffffffab0949a08c5af7c49b8212f417e2f15ab3f5c33dcf153821a8139f877a5b7be40100000000feffffff02" +
  "603bea0b000000001976a914768a40bbd740cbe81d988e71de2a4d5c71396b1d88ac8e240000000000001976a9146f46" +
  "20b553fa095e721b9ee0efe9fa039cca459788ac000000000001076a47304402204759661797c01b036b259289486862" +
  "18347d89864b719e1f7fcf57d1e511658702205309eabf56aa4d8891ffd111fdf1336f3a29da866d7f8486d75546ceed" +
  "af93190121035cdc61fc7ba971c0b501a646a2a83b102cb43881217ca682dc86e2d73fa882920001012000e1f5050000" +
  "000017a9143545e6e33b832c47050f24d3eeb93c9c03948bc787010416001485d13537f2e265405a34dbafa9e3dda01f" +
  "b82308000000";
const BIP174_INVALID_2 =
  "70736274ff0100750200000001268171371edff285e937adeea4b37b78000c0566cbb3ad64641713ca42171bf6000000" +
  "0000feffffff02d3dff505000000001976a914d0c59903c5bac2868760e90fd521a4665aa7652088ac00e1f505000000" +
  "0017a9143545e6e33b832c47050f24d3eeb93c9c03948bc787b32e1300000100fda5010100000000010289a3c71eab4d" +
  "20e0371bbba4cc698fa295c9463afa2e397f8533ccb62f9567e50100000017160014be18d152a9b012039daf3da7de4f" +
  "53349eecb985ffffffff86f8aa43a71dff1448893a530a7237ef6b4608bbb2dd2d0171e63aec6a4890b4010000001716" +
  "0014fe3e9ef1a745e974d902c4355943abcb34bd5353ffffffff0200c2eb0b000000001976a91485cff1097fd9e008bb" +
  "34af709c62197b38978a4888ac72fef84e2c00000017a914339725ba21efd62ac753a9bcd067d6c7a6a39d0587024730" +
  "4402202712be22e0270f394f568311dc7ca9a68970b8025fdd3b240229f07f8a5f3a240220018b38d7dcd314e734c927" +
  "6bd6fb40f673325bc4baa144c800d2f2f02db2765c012103d2e15674941bad4a996372cb87e1856d3652606d98562fe3" +
  "9c5e9e7e413f210502483045022100d12b852d85dcd961d2f5f4ab660654df6eedcc794c0c33ce5cc309ffb5fce58d02" +
  "2067338a8e0e1725c197fb1a88af59f51e44e4255b20167c8684031c05d1f2592a01210223b72beef0965d10be0778ef" +
  "ecd61fcac6f79a4ea169393380734464f84f2ab30000000000";
const BIP370_MINIMAL =
  "70736274ff01020402000000010401010105010201fb040200000000010e200b0ad921419c1c8719735d72dc739f9ea9" +
  "e0638d1fe4c1eef0f9944084815fc8010f0400000000000103080008af2f000000000104160014c430f64c4756da310d" +
  "bd1a085572ef299926272c000103088bbdeb0b0000000001041600144dd193ac964a56ac1b9e1cca8454fe2f474f8513" +
  "00";
// The same file with output 1's amount edited from 9358 to 9357 sat: only
// that little-endian 8-byte field differs (8e24... -> 8d24...).
const BIP174_VALID_2_EDITED = BIP174_VALID_2.replace("8e24000000000000", "8d24000000000000");

// BIP-341 defines six Taproot sighash bytes for a 65-byte signature; 0x00
// (SIGHASH_DEFAULT) is valid only as the implicit 64-byte form. A one-input
// v0 PSBT carrying a placeholder PSBT_IN_TAP_KEY_SIG with the given suffix.
const tapKeySigPsbt = (suffix) => {
  const tx = "02000000" + "01" + "00".repeat(32) + "00000000" + "00" + "ffffffff" + "01" + "0000000000000000" + "00" + "00000000";
  return "70736274ff" + "0100" + (tx.length / 2).toString(16).padStart(2, "0") + tx + "00" + "01" + "13" + "41" + "5a".repeat(64) + suffix + "00" + "00";
};
const psbtSummary = (doc) =>
  `v${doc.psbtVersion} in:${doc.tx.inputs.map((input) => `${input.txid}:${input.vout}`).join(",")}` +
  ` out:${doc.tx.outputs.map((output) => `${output.value}:${output.scriptPubKey}`).join(",")} total:${doc.totalOut}`;

// The raw vectors, exported so the test suite can decode them independently.
export const PSBT_SELF_TEST_VECTORS = { BIP174_VALID_2, BIP174_INVALID_2, BIP370_MINIMAL };

// Expected decodes match @scure/btc-signer's (checked in the test suite).
export const PSBT_SELF_TESTS = [
  {
    name: "PSBT decode (BIP-174)",
    expected:
      "v0 in:e47b5b7a879f13a8213815cf3dc3f5b35af1e217f412829bc4f75a8ca04909ab:0," +
      "e47b5b7a879f13a8213815cf3dc3f5b35af1e217f412829bc4f75a8ca04909ab:1" +
      " out:199900000:76a914768a40bbd740cbe81d988e71de2a4d5c71396b1d88ac," +
      "9358:76a9146f4620b553fa095e721b9ee0efe9fa039cca459788ac total:199909358",
    run: () => psbtSummary(psbtInspectDoc(hex.decode(BIP174_VALID_2))),
  },
  {
    // The editor's own path from document back to bytes, which is what a
    // user takes to their signer. Unedited it must reproduce the file
    // exactly; with one amount edited, exactly that field must change. The
    // edit is the control: a rebuild that ignored the document and echoed
    // its input would pass the first half alone.
    name: "PSBT rebuild (BIP-174)",
    expected: `unedited:${BIP174_VALID_2} edited:${BIP174_VALID_2_EDITED}`,
    run: () => {
      const doc = psbtEditorBuildDoc(psbtInspectDoc(hex.decode(BIP174_VALID_2)));
      const unedited = hex.encode(psbtBuildBytes(doc));
      doc.tx.outputs[1].value = "9357";
      return `unedited:${unedited} edited:${hex.encode(psbtBuildBytes(doc))}`;
    },
  },
  {
    // Fail-open is the dangerous direction; the valid file is the control
    // against a parser that rejects everything.
    name: "PSBT rejects an invalid file (BIP-174)",
    expected: "valid:accepted invalid:rejected",
    run: () =>
      [["valid", BIP174_VALID_2], ["invalid", BIP174_INVALID_2]]
        .map(([label, vector]) => {
          try {
            psbtInspectDoc(hex.decode(vector));
            return `${label}:accepted`;
          } catch {
            return `${label}:rejected`;
          }
        })
        .join(" "),
  },
  {
    name: "PSBT v2 decode (BIP-370)",
    expected:
      "v2 in:c85f81844094f9f0eec1e41f8d63e0a99e9f73dc725d7319871c9c4121d90a0b:0" +
      " out:800000000:0014c430f64c4756da310dbd1a085572ef299926272c," +
      "199998859:00144dd193ac964a56ac1b9e1cca8454fe2f474f8513 total:999998859",
    run: () => psbtSummary(psbtInspectDoc(hex.decode(BIP370_MINIMAL))),
  },
  {
    name: "Taproot signature sighash check (BIP-341)",
    expected: "01:decoded 00:rejected ff:rejected",
    run: () =>
      ["01", "00", "ff"]
        .map((suffix) => {
          const pair = psbtInspectDoc(hex.decode(tapKeySigPsbt(suffix))).inputs[0].find((entry) => entry.name === "PSBT_IN_TAP_KEY_SIG");
          return `${suffix}:${pair?.decoded ? "decoded" : "rejected"}`;
        })
        .join(" "),
  },
];

// Returns the names of the tests this host fails. A test passes only when
// it returns exactly its expected string; a throw, a missing or empty
// expectation, or any other value is a failure, so a malformed entry can
// never pass by comparing undefined to undefined.
export const runSelfTests = (tests = SELF_TESTS) => {
  const failed = [];
  for (const { name, expected, run } of tests) {
    let ok = false;
    try {
      ok = typeof expected === "string" && expected !== "" && run() === expected;
    } catch {
      ok = false;
    }
    if (!ok) failed.push(name);
  }
  return failed;
};

// The boot gate: records the outcome on <html> (data-self-tests /
// data-self-tests-failed, alongside browser-check.js's barrage counters) so
// tests and support can confirm it ran, then hands any failures to `onFail`
// and returns false so the caller never boots. Returns true when every test
// passed.
export const selfTestGate = (root, onFail, tests = SELF_TESTS) => {
  const failed = runSelfTests(tests);
  if (root) {
    root.dataset.selfTests = String(tests.length);
    root.dataset.selfTestsFailed = String(failed.length);
  }
  if (failed.length === 0) return true;
  onFail(failed);
  return false;
};
