import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";

import {
  buildVerificationPackage,
  verificationPackageFilename,
} from "../src/js/verification-package.js";
import { hashesReady } from "../src/js/hashes.js";
import { psbtWasmReady } from "../src/js/psbt-wasm.js";

// base58.js runs in the WASM module.
await hashesReady;
await psbtWasmReady;

// BIP-84 test vector: account 0 of "abandon … about" in both serialisations,
// so the SLIP-132 rewrite has an expected value that does not come from the
// code under test.
const BIP84_XPUB = "xpub6CatWdiZiodmUeTDp8LT5or8nmbKNcuyvz7WyksVFkKB4RHwCD3XyuvPEbvqAQY3rAPshWcMLoP2fMFMKHPJ4ZeZXYVUhLv1VMrjPC7PW6V";
const BIP84_ZPUB = "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs";

// Bitcoin Core doc/descriptors.md example, checksum included.
const CORE_DESCRIPTOR_BODY = "wpkh([d34db33f/84h/0h/0h]xpub6DJ2dNUysrn5Vt36jH2KLBT2i1auw1tTSSomg8PhqNiUtx8QX2SvC9nrHu81fT41fvDUnhMjEzQgXnQjKEu3oaqMSzhSrHMxyyoEAmUHQbY/0/*)";
const CORE_DESCRIPTOR_CHECKSUM = "cjjspncu";

// BIP-84 first receive and first change address.
const RECEIVE_ADDRESS = "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu";
const CHANGE_ADDRESS = "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g";

// A real one-input PSBT (key 0x01*32), the fixture of the signer-audit captures.
const PSBT_BASE64 = "cHNidP8BAFICAAAAARERERERERERERERERERERERERERERERERERERERERERAAAAAAD/////AZBfAQAAAAAAFgAUebAAiHYmspSpFFAaTNImtYsjWYMAAAAAAAEBH6CGAQAAAAAAFgAUebAAiHYmspSpFFAaTNImtYsjWYMiBgMbhMVWexJkQJldPtWqugVl1x4YNGBIGf+cF/Xp1d0HjxgSNFZ4VAAAgAAAAIAAAACAAAAAAAAAAAAAAA==";
const WALLET_DAT_BYTES = new Uint8Array([0x53, 0x51, 0x4c, 0x69, 0x74, 0x65, 1, 2, 3]);
const WALLET_DAT_SHA256 = createHash("sha256").update(WALLET_DAT_BYTES).digest("hex");

const FULL_INPUT = {
  network: "mainnet",
  masterFingerprint: "d34db33f",
  descriptors: [`wpkh([d34db33f/84h/0h/0h]${BIP84_XPUB}/0/*)`],
  xpubs: [BIP84_XPUB],
  receiveAddresses: [{ index: 0, address: RECEIVE_ADDRESS }],
  changeAddresses: [{ index: 0, address: CHANGE_ADDRESS }],
  psbtBase64: PSBT_BASE64,
  walletDatBytes: WALLET_DAT_BYTES,
};

test("round-trips a full package with the documented keys in order", () => {
  const json = buildVerificationPackage(FULL_INPUT);
  assert.ok(json.endsWith("\n"), "the package ends with a newline");
  assert.ok(json.includes('\n  "schema": "entropylab-verification/1",\n'), "pretty-printed with two spaces");
  const parsed = JSON.parse(json);
  assert.deepEqual(Object.keys(parsed), [
    "schema",
    "network",
    "masterFingerprint",
    "descriptors",
    "xpubs",
    "receiveAddresses",
    "changeAddresses",
    "psbt",
    "walletDatSha256",
  ]);
  assert.equal(parsed.schema, "entropylab-verification/1");
  assert.equal(parsed.network, "main");
  assert.equal(parsed.masterFingerprint, "d34db33f");
  assert.equal(parsed.descriptors.length, 1);
  assert.ok(parsed.descriptors[0].startsWith(`wpkh([d34db33f/84h/0h/0h]${BIP84_XPUB}/0/*)#`));
  assert.match(parsed.descriptors[0], /#[a-z0-9]{8}$/);
  assert.deepEqual(parsed.xpubs, [BIP84_XPUB]);
  assert.deepEqual(parsed.receiveAddresses, [{ index: 0, address: RECEIVE_ADDRESS }]);
  assert.deepEqual(parsed.changeAddresses, [{ index: 0, address: CHANGE_ADDRESS }]);
  assert.equal(parsed.psbt, PSBT_BASE64);
  assert.equal(parsed.walletDatSha256, WALLET_DAT_SHA256);
});

const NETWORK_CASES = [
  ["mainnet", "main"],
  ["testnet", "test"],
  ["testnet3", "test"],
  ["testnet4", "testnet4"],
  ["signet", "signet"],
  ["regtest", "regtest"],
];

for (const [entropylabName, expected] of NETWORK_CASES) {
  test(`maps the ${entropylabName} network to ${expected}`, () => {
    const parsed = JSON.parse(buildVerificationPackage({
      network: entropylabName,
      descriptors: [`wpkh(${BIP84_XPUB}/0/*)`],
    }));
    assert.equal(parsed.network, expected);
  });
}

test("refuses an unknown network", () => {
  assert.throws(
    () => buildVerificationPackage({
      network: "liquid",
      receiveAddresses: [{ index: 0, address: RECEIVE_ADDRESS }],
    }),
    { message: /^network:/ },
  );
});

test("appends a missing descriptor checksum", () => {
  const parsed = JSON.parse(buildVerificationPackage({
    network: "mainnet",
    descriptors: [CORE_DESCRIPTOR_BODY],
  }));
  assert.deepEqual(parsed.descriptors, [`${CORE_DESCRIPTOR_BODY}#${CORE_DESCRIPTOR_CHECKSUM}`]);
});

test("refuses a descriptor whose checksum does not match", () => {
  assert.throws(
    () => buildVerificationPackage({
      network: "mainnet",
      descriptors: [`${CORE_DESCRIPTOR_BODY}#cjjspncv`],
    }),
    { message: /^checksum:/ },
  );
});

test("rewrites a SLIP-132 zpub descriptor as xpub", () => {
  const parsed = JSON.parse(buildVerificationPackage({
    network: "mainnet",
    descriptors: [`wpkh([d34db33f/84h/0h/0h]${BIP84_ZPUB}/0/*)`],
  }));
  assert.equal(parsed.descriptors.length, 1);
  assert.ok(parsed.descriptors[0].includes(BIP84_XPUB), "the zpub is rewritten as the matching xpub");
  assert.equal(parsed.descriptors[0].includes("zpub"), false);
  assert.match(parsed.descriptors[0], /#[a-z0-9]{8}$/);
});

const PRIVATE_FORMS = {
  "an extended private key": "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi",
  "a capital Zprv": "ZprvAWgYBBk7JR8Gjrh4UJQ2uJdG1r3WNRRfURiABBE3RvMXYSrRJL62XuezvGdPvG6GFBZduosCc1YP5wixPox7zhZLfiUm8aunE96BBa4Kei5",
  "a WIF": "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ",
  "a twelve word mnemonic": "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
};

const PLACEMENTS = {
  descriptor: (material) => ({ descriptors: [material] }),
  xpub: (material) => ({ xpubs: [material] }),
  address: (material) => ({ receiveAddresses: [{ index: 0, address: material }] }),
  psbt: (material) => ({ psbtBase64: material }),
};

for (const [formName, material] of Object.entries(PRIVATE_FORMS)) {
  for (const [placeName, place] of Object.entries(PLACEMENTS)) {
    test(`refuses ${formName} in the ${placeName} field`, () => {
      assert.throws(
        () => buildVerificationPackage({ network: "mainnet", ...place(material) }),
        (error) => {
          // The PSBT field accepts only a real PSBT, so material placed there
          // is refused as not-a-PSBT; every other field refuses it as private.
          assert.match(error.message, placeName === "psbt" ? /^(private|psbt):/ : /^private:/);
          assert.equal(error.message.includes(material), false, "the refusal must not echo the material");
          return true;
        },
      );
    });
  }
}

test("refuses a package with nothing to verify", () => {
  assert.throws(
    () => buildVerificationPackage({ network: "mainnet" }),
    { message: /^empty:/ },
  );
  assert.throws(
    () => buildVerificationPackage({ network: "mainnet", descriptors: [], receiveAddresses: [], changeAddresses: [] }),
    { message: /^empty:/ },
  );
});

test("the same input produces byte-identical output", () => {
  const first = buildVerificationPackage(FULL_INPUT);
  const second = buildVerificationPackage(structuredClone(FULL_INPUT));
  assert.equal(first, second);
});

test("the file name is built from the network and fingerprint only", () => {
  assert.equal(verificationPackageFilename({ network: "mainnet", masterFingerprint: "73c5da0a" }), "entropylab-verification-main-73c5da0a.json");
  assert.equal(verificationPackageFilename({ network: "testnet4" }), "entropylab-verification-testnet4.json");
  assert.throws(() => verificationPackageFilename({ network: "liquid" }), /^Error: network:/);
  assert.throws(() => verificationPackageFilename({ network: "mainnet", masterFingerprint: "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35" }), /^Error: masterFingerprint:/);
});

// Red-team on bea059f (VP-1/VP-3): the scanners recognise known private
// forms; the xpub field and every key position must instead PROVE they hold
// a public extended key, so unknown forms are refused too.
const BIP38 = "6PRVWUbkzzsbcVac2qwfssoUJAN1Xhrg6bNk8J7Nzm5H7kxEbn2Nh2ZoGg"; // BIP-38 test vector

test("xpubs must be verifiable public extended keys", () => {
  const base = { network: "mainnet", descriptors: [`wpkh([d34db33f/84h/0h/0h]${BIP84_XPUB}/0/*)`] };
  for (const bad of [BIP38, "deadbeef".repeat(8), `${BIP84_XPUB.slice(0, -1)}X`, `${BIP84_XPUB} extra`]) {
    assert.throws(() => buildVerificationPackage({ ...base, xpubs: [bad] }), (error) => error.message.startsWith("private:") && !error.message.includes(bad.slice(0, 20)));
  }
  const parsed = JSON.parse(buildVerificationPackage({ ...base, xpubs: [BIP84_ZPUB] }));
  assert.deepEqual(parsed.xpubs, [BIP84_XPUB], "a zpub is emitted in its xpub form");
});

test("every key position in a descriptor must be a public extended key", () => {
  assert.throws(() => buildVerificationPackage({ network: "mainnet", descriptors: [`wpkh(${BIP38}/0/*)`] }), (error) => error.message.startsWith("private:") && !error.message.includes(BIP38));
});

test("the emitted descriptor's checksum pins the emitted body (VP-2)", () => {
  const parsed = JSON.parse(buildVerificationPackage({ network: "mainnet", descriptors: [`wpkh([d34db33f/84h/0h/0h]${BIP84_ZPUB}/0/*)`] }));
  const [body, checksum] = parsed.descriptors[0].split("#");
  assert.ok(body.includes(BIP84_XPUB));
  assert.equal(checksum.length, 8);
  // Re-feeding the emitted descriptor must be accepted unchanged.
  assert.equal(JSON.parse(buildVerificationPackage({ network: "mainnet", descriptors: [parsed.descriptors[0]] })).descriptors[0], parsed.descriptors[0]);
});

// Reviews of bea059f (GLM, MiniMax, Muse): every field is strictly typed, so
// a secret cannot hide in a field's free text or be split across fields.
test("the PSBT field takes a real PSBT and is not scanned as base58 text (GLM)", () => {
  const parsed = JSON.parse(buildVerificationPackage({ network: "mainnet", descriptors: [`wpkh(${BIP84_XPUB}/0/*)`], psbtBase64: PSBT_BASE64 }));
  assert.equal(parsed.psbt, PSBT_BASE64);
  // Base64 that is not PSBT data (here a WIF-shaped run after the prefix) is refused as not a PSBT.
  for (const bad of ["cHNidP8 not base64", `cHNidP8${"B".repeat(44)}+AAAA`]) {
    assert.throws(() => buildVerificationPackage({ network: "mainnet", descriptors: [`wpkh(${BIP84_XPUB}/0/*)`], psbtBase64: bad }), /^Error: psbt:/);
  }
});

test("raw hex keys are refused in descriptors; only the NUMS point is allowed", () => {
  const hexKey = "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35";
  assert.throws(() => buildVerificationPackage({ network: "mainnet", descriptors: [`tr(${hexKey})`] }), (error) => error.message.startsWith("private:") && !error.message.includes(hexKey));
  const nums = "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0";
  const parsed = JSON.parse(buildVerificationPackage({ network: "mainnet", descriptors: [`tr(${nums},sortedmulti_a(1,${BIP84_XPUB}/0/*))`] }));
  assert.ok(parsed.descriptors[0].startsWith(`tr(${nums},`));
});

test("addresses must be valid addresses of the declared network", () => {
  const base = { network: "mainnet", descriptors: [`wpkh(${BIP84_XPUB}/0/*)`] };
  for (const bad of ["e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35", "abandon abandon abandon abandon abandon abandon", "tb1qcr8te4kr609gcawutmrza0j4xv80jy8zn4ydx6", `${RECEIVE_ADDRESS.slice(0, -1)}q`]) {
    assert.throws(() => buildVerificationPackage({ ...base, receiveAddresses: [{ index: 0, address: bad }] }), /^Error: receiveAddresses: not a valid/);
  }
});

// Reviews of 989f478 (GLM, Muse, Nemotron) and the red-team's VP-4.
test("the wallet.dat hash is computed from the bytes; a caller-supplied hex is refused", () => {
  const base = { network: "mainnet", descriptors: [`wpkh(${BIP84_XPUB}/0/*)`] };
  assert.equal(JSON.parse(buildVerificationPackage({ ...base, walletDatBytes: WALLET_DAT_BYTES })).walletDatSha256, WALLET_DAT_SHA256);
  const hexKey = "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35";
  assert.throws(() => buildVerificationPackage({ ...base, walletDatSha256: hexKey }), (error) => error.message.startsWith("walletDat:") && !error.message.includes(hexKey));
});

test("a descriptor must be exactly a supported shape: no trailing text", () => {
  for (const extra of [" abandon ability able", "/extra", " #note"]) {
    assert.throws(() => buildVerificationPackage({ network: "mainnet", descriptors: [`wpkh(${BIP84_XPUB}/0/*)${extra}`] }), /^Error: (descriptor|checksum|private):/);
  }
});

test("a PSBT with a proprietary or unknown field is refused", () => {
  const bytes = Buffer.from(PSBT_BASE64, "base64");
  const txLength = bytes[7]; // psbtÿ, then key 01 00, then the value length
  const separator = 8 + txLength; // the global map's 0x00 separator
  assert.equal(bytes[separator], 0x00, "fixture: one global pair, then the separator");
  const insert = (pair) => Buffer.concat([bytes.subarray(0, separator), Buffer.from(pair), bytes.subarray(separator)]).toString("base64");
  const proprietary = insert([0x05, 0xfc, 0x02, 0x68, 0x69, 0x00, 0x03, 0x61, 0x62, 0x63]);
  const unknown = insert([0x01, 0x77, 0x01, 0x00]);
  for (const psbt of [proprietary, unknown]) {
    assert.throws(() => buildVerificationPackage({ network: "mainnet", descriptors: [`wpkh(${BIP84_XPUB}/0/*)`], psbtBase64: psbt }), /^Error: psbt:/);
  }
});

test("a large wallet.dat is hashed, not scanned byte by byte (Kimi)", () => {
  const big = new Uint8Array(8 * 1024 * 1024).fill(0x41);
  const started = Date.now();
  const parsed = JSON.parse(buildVerificationPackage({ network: "mainnet", descriptors: [`wpkh(${BIP84_XPUB}/0/*)`], walletDatBytes: big }));
  assert.ok(Date.now() - started < 5000, "an 8 MiB wallet.dat must not stall the build");
  assert.equal(parsed.walletDatSha256, createHash("sha256").update(big).digest("hex"));
});
