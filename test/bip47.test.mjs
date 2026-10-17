// BIP-47 v1 payment-code calculator tests (src/js/bip47.js core,
// src/js/bip47-ui.js render/availability, shell and app.js wiring).
//
// Pinned vector provenance (keep with the values below):
// Source: SamouraiDev gist `6aad669604c5930864bd`, the link in BIP-47's
// "Test Vectors" section. These vectors are not in bitcoin/bips. Every value
// was independently recomputed during prompt review.
// Run with `npm test`.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { HDKey } from "../src/js/hdkey.js";
import { mnemonicToSeedSync } from "../src/js/bip39.js";
import { secp256k1 } from "../src/js/secp256k1.js";
import { sha256, hmacSha512 } from "../src/js/hashes.js";
import { base58checkEncode, base58checkDecode } from "../src/js/base58.js";
import { parseRawTx } from "../src/js/tx.js";
import { p2pkhScript, addressFromScript } from "../src/js/addresses.js";
import {
  PAIR_ROW_COUNT,
  bip47AccountNode,
  bip47AccountPath,
  bip47BlindNotification,
  bip47BlindPayload,
  bip47ChildPublic,
  bip47DecodeNotificationTx,
  bip47Mask,
  bip47NotificationAddress,
  bip47OutpointFromDisplay,
  bip47PairRows,
  bip47Payload,
  bip47SharedX,
  bytesToHex,
  decodePaymentCode,
  encodePaymentCode,
  equalBytes,
  extractDesignatedPubKey,
  hexToBytes,
} from "../src/js/bip47.js";
import {
  hodlBip47Availability,
  hodlBip47RenderBlind,
  hodlBip47RenderDecoded,
  hodlBip47RenderPairs,
  hodlBip47RenderSelf,
  hodlBip47RenderTx,
  hodlBip47Wipe,
  hodlInitBip47,
} from "../src/js/bip47-ui.js";

const rootDir = dirname(dirname(fileURLToPath(import.meta.url)));
const shell = readFileSync(join(rootDir, "src/shell.html"), "utf8");
const appSource = readFileSync(join(rootDir, "src/js/app.js"), "utf8");
const uiSource = readFileSync(join(rootDir, "src/js/bip47-ui.js"), "utf8");

const ORDER = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const toBig = (bytes) => bytes.reduce((n, b) => (n << 8n) | BigInt(b), 0n);
const toBytes32 = (value) => Uint8Array.from({ length: 32 }, (_, i) => Number((value >> BigInt(8 * (31 - i))) & 255n));

// SamouraiDev gist 6aad669604c5930864bd (BIP-47 "Test Vectors" link), every
// value independently recomputed during prompt review.
const ALICE = {
  mnemonic: "response seminar brave tip suit recall often sound stick owner lottery motion",
  seed: "64dca76abc9c6f0cf3d212d248c380c4622c8f93b2c425ec6a5567fd5db57e10d3e6f94a2f6af4ac2edb8998072aad92098db73558c323777abf5bd1082d970a",
  code: "PM8TJTLJbPRGxSbc8EJi42Wrr6QbNSaSSVJ5Y3E4pbCYiTHUskHg13935Ubb7q8tx9GVbh2UuRnBc3WSyJHhUrw8KhprKnn9eDznYGieTzFcwQRya4GA",
  a0: "8d6a8ecd8ee5e0042ad0cb56e3a971c760b5145c3917a8e7beaf0ed92d7a520c",
  A0: "0353883a146a23f988e0f381a9507cbdb3e3130cd81b3ce26daf2af088724ce683",
  notificationAddress: "1JDdmqFLhpzcUwPeinhJbUPw4Co3aWLyzW",
};
const BOB = {
  mnemonic: "reward upper indicate eight swift arch injury crystal super wrestle already dentist",
  seed: "87eaaac5a539ab028df44d9110defbef3797ddb805ca309f61a69ff96dbaa7ab5b24038cf029edec5235d933110f0aea8aeecf939ed14fc20730bba71e4b1110",
  code: "PM8TJS2JxQ5ztXUpBBRnpTbcUXbUHy2T1abfrb3KkAAtMEGNbey4oumH7Hc578WgQJhPjBxteQ5GHHToTYHE3A1w6p7tU6KSoFmWBVbFGjKPisZDbP97",
  notificationAddress: "1ChvUUvht2hUQufHBXF8NgLhW8SwE2ecGV",
  b: [
    "04448fd1be0c9c13a5ca0b530e464b619dc091b299b98c5cab9978b32b4a1b8b",
    "6bfa917e4c44349bfdf46346d389bf73a18cec6bc544ce9f337e14721f06107b",
    "46d32fbee043d8ee176fe85a18da92557ee00b189b533fce2340e4745c4b7b8c",
    "4d3037cfd9479a082d3d56605c71cbf8f38dc088ba9f7a353951317c35e6c343",
    "97b94a9d173044b23b32f5ab64d905264622ecd3eafbe74ef986b45ff273bbba",
    "ce67e97abf4772d88385e66d9bf530ee66e07172d40219c62ee721ff1a0dca01",
    "ef049794ed2eef833d5466b3be6fe7676512aa302afcde0f88d6fcfe8c32cc09",
    "d3ea8f780bed7ef2cd0e38c5d943639663236247c0a77c2c16d374e5a202455b",
    "efb86ca2a3bad69558c2f7c2a1e2d7008bf7511acad5c2cbf909b851eb77e8f3",
    "18bcf19b0b4148e59e2bba63414d7a8ead135a7c2f500ae7811125fb6f7ce941",
  ],
  B: [
    "024ce8e3b04ea205ff49f529950616c3db615b1e37753858cc60c1ce64d17e2ad8",
    "03e092e58581cf950ff9c8fc64395471733e13f97dedac0044ebd7d60ccc1eea4d",
    "029b5f290ef2f98a0462ec691f5cc3ae939325f7577fcaf06cfc3b8fc249402156",
    "02094be7e0eef614056dd7c8958ffa7c6628c1dab6706f2f9f45b5cbd14811de44",
    "031054b95b9bc5d2a62a79a58ecfe3af000595963ddc419c26dab75ee62e613842",
    "03dac6d8f74cacc7630106a1cfd68026c095d3d572f3ea088d9a078958f8593572",
    "02396351f38e5e46d9a270ad8ee221f250eb35a575e98805e94d11f45d763c4651",
    "039d46e873827767565141574aecde8fb3b0b4250db9668c73ac742f8b72bca0d0",
    "038921acc0665fd4717eb87f81404b96f8cba66761c847ebea086703a6ae7b05bd",
    "03d51a06c6b48f067ff144d5acdfbe046efa2e83515012cf4990a89341c1440289",
  ],
};
const SHARED_X = [
  "f5bb84706ee366052471e6139e6a9a969d586e5fe6471a9b96c3d8caefe86fef",
  "adfb9b18ee1c4460852806a8780802096d67a8c1766222598dc801076beb0b4d",
  "79e860c3eb885723bb5a1d54e5cecb7df5dc33b1d56802906762622fa3c18ee5",
  "d8339a01189872988ed4bd5954518485edebf52762bf698b75800ac38e32816d",
  "14c687bc1a01eb31e867e529fee73dd7540c51b9ff98f763adf1fc2f43f98e83",
  "725a8e3e4f74a50ee901af6444fb035cb8841e0f022da2201b65bc138c6066a2",
  "521bf140ed6fb5f1493a5164aafbd36d8a9e67696e7feb306611634f53aa9d1f",
  "5f5ecc738095a6fb1ea47acda4996f1206d3b30448f233ef6ed27baf77e81e46",
  "1e794128ac4c9837d7c3696bbc169a8ace40567dc262974206fcf581d56defb4",
  "fe36c27c62c99605d6cd7b63bf8d9fe85d753592b14744efca8be20a4d767c37",
];
const PAIR_ADDRESSES = [
  "141fi7TY3h936vRUKh1qfUZr8rSBuYbVBK",
  "12u3Uued2fuko2nY4SoSFGCoGLCBUGPkk6",
  "1FsBVhT5dQutGwaPePTYMe5qvYqqjxyftc",
  "1CZAmrbKL6fJ7wUxb99aETwXhcGeG3CpeA",
  "1KQvRShk6NqPfpr4Ehd53XUhpemBXtJPTL",
  "1KsLV2F47JAe6f8RtwzfqhjVa8mZEnTM7t",
  "1DdK9TknVwvBrJe7urqFmaxEtGF2TMWxzD",
  "16DpovNuhQJH7JUSZQFLBQgQYS4QB9Wy8e",
  "17qK2RPGZMDcci2BLQ6Ry2PDGJErrNojT5",
  "1GxfdfP286uE24qLZ9YRP3EWk2urqXgC4s",
];
const NOTIFY = {
  wif: "Kx983SRhAZpAhj7Aac1wUXMJ6XZeyJKqCxJJ49dxEbYCT4a1ozRD",
  pubkey: "0272d83d8a1fa323feab1c085157a0791b46eba34afb8bfbfaeb3a3fcc3f2c9ad8",
  outpoint: "86f411ab1c8e70ae8a0795ab7a6757aea6e4d5ae1826fc7b8f00c597d500609c01000000",
  outpointDisplay: "9c6000d597c5008f7bfc2618aed5e4a6ae57677aab95078aae708e1cab11f486:1",
  x: "736a25d9250238ad64ed5da03450c6a3f4f8f4dcdf0b58d1ed69029d76ead48d",
  mask: "be6e7a4256cac6f4d4ed4639b8c39c4cb8bece40010908e70d17ea9d77b4dc57f1da36f2d6641ccb37cf2b9f3146686462e0fa3161ae74f88c0afd4e307adbd5",
  plain: "010002b85034fb08a8bfefd22848238257b252721454bbbfba2c3667f168837ea2cdad671af9f65904632e2dcc0c6ad314e11d53fc82fa4c4ea27a4a14eccecc478fee00000000000000000000000000",
  blinded: "010002063e4eb95e62791b06c50e1a3a942e1ecaaa9afbbeb324d16ae6821e091611fa96c0cf048f607fe51a0327f5e2528979311c78cb2de0d682c61e1180fc3d543b00000000000000000000000000",
  tx: "010000000186f411ab1c8e70ae8a0795ab7a6757aea6e4d5ae1826fc7b8f00c597d500609c010000006b483045022100ac8c6dbc482c79e86c18928a8b364923c774bfdbd852059f6b3778f2319b59a7022029d7cc5724e2f41ab1fcfc0ba5a0d4f57ca76f72f19530ba97c860c70a6bf0a801210272d83d8a1fa323feab1c085157a0791b46eba34afb8bfbfaeb3a3fcc3f2c9ad8ffffffff0210270000000000001976a9148066a8e7ee82e5c5b9b7dc1765038340dc5420a988ac1027000000000000536a4c50010002063e4eb95e62791b06c50e1a3a942e1ecaaa9afbbeb324d16ae6821e091611fa96c0cf048f607fe51a0327f5e2528979311c78cb2de0d682c61e1180fc3d543b0000000000000000000000000000000000",
  txid: "9414f1681fb1255bd168a806254321a837008dd4480c02226063183deb100204",
};

const aliceRootFromMnemonic = () => HDKey.fromMasterSeed(mnemonicToSeedSync(ALICE.mnemonic, ""));
const bobRootFromMnemonic = () => HDKey.fromMasterSeed(mnemonicToSeedSync(BOB.mnemonic, ""));
const aliceRootFromSeed = () => HDKey.fromMasterSeed(hexToBytes(ALICE.seed));
const bobRootFromSeed = () => HDKey.fromMasterSeed(hexToBytes(BOB.seed));
const accountCode = (rootNode, coinType) => {
  const account = bip47AccountNode(rootNode, coinType);
  try { return encodePaymentCode(account.publicKey, account.chainCode); }
  finally { account.wipePrivateData(); }
};
const wifToPriv = (wif) => base58checkDecode(wif).slice(1, 33);

// ── 1. Payment codes and keys ────────────────────────────────────────────────

test("1. payment codes derive from the mnemonics and from the raw BIP32 seeds", () => {
  assert.equal(accountCode(aliceRootFromMnemonic(), 0), ALICE.code);
  assert.equal(accountCode(aliceRootFromSeed(), 0), ALICE.code);
  assert.equal(accountCode(bobRootFromMnemonic(), 0), BOB.code);
  assert.equal(accountCode(bobRootFromSeed(), 0), BOB.code);
  assert.equal(bip47AccountPath(0), "m/47'/0'/0'");
  const aliceAccount = bip47AccountNode(aliceRootFromMnemonic(), 0);
  const a0 = aliceAccount.deriveChild(0);
  assert.equal(bytesToHex(a0.privateKey), ALICE.a0);
  assert.equal(bytesToHex(a0.publicKey), ALICE.A0);
  a0.wipePrivateData();
  aliceAccount.wipePrivateData();
  const bobAccount = bip47AccountNode(bobRootFromMnemonic(), 0);
  for (const [index, key] of [0, 1, 2, 3, 4, 5, 6, 7, 8, 9].map((i) => [i, bobAccount.deriveChild(i)])) {
    assert.equal(bytesToHex(key.privateKey), BOB.b[index], `b${index}`);
    assert.equal(bytesToHex(key.publicKey), BOB.B[index], `B${index}`);
    key.wipePrivateData();
  }
  bobAccount.wipePrivateData();
});

// ── 2. Notification addresses ────────────────────────────────────────────────

test("2. both notification addresses match (P2PKH of the non-hardened child 0)", () => {
  for (const [root, expected] of [[aliceRootFromMnemonic(), ALICE.notificationAddress], [bobRootFromMnemonic(), BOB.notificationAddress]]) {
    const account = bip47AccountNode(root, 0);
    const child0 = bip47ChildPublic(account.publicKey, account.chainCode, 0);
    assert.equal(bip47NotificationAddress(child0, "mainnet"), expected);
    // Public-only child derivation ties child 0 to the account pubkey+chain.
    account.wipePrivateData();
  }
});

// ── 3. Shared secrets, from both sides ───────────────────────────────────────

test("3. S_i = x(a0·B_i) = x(b_i·A0) for i = 0..9", () => {
  const aliceAccount = bip47AccountNode(aliceRootFromMnemonic(), 0);
  const bobAccount = bip47AccountNode(bobRootFromMnemonic(), 0);
  const a0 = aliceAccount.deriveChild(0).privateKey;
  try {
    for (let i = 0; i < 10; i++) {
      const bi = bobAccount.deriveChild(i).privateKey;
      try {
        const bPub = secp256k1.getPublicKey(bi, true);
        const sender = bip47SharedX(a0, bPub); // x(a0·B_i)
        const a0Pub = secp256k1.getPublicKey(a0, true);
        const receiver = bip47SharedX(bi, a0Pub); // x(b_i·A0)
        assert.equal(bytesToHex(sender), SHARED_X[i], `sender ${i}`);
        assert.equal(bytesToHex(receiver), SHARED_X[i], `receiver ${i}`);
      } finally {
        bi.fill(0);
      }
    }
  } finally {
    a0.fill(0);
  }
  aliceAccount.wipePrivateData();
  bobAccount.wipePrivateData();
});

// ── 4. Pair addresses + b'0 cross-check ──────────────────────────────────────

test("4. Alice's send rows and Bob's receive rows both equal the list; b'0 ties receive keys to published values", () => {
  const aliceAccount = bip47AccountNode(aliceRootFromMnemonic(), 0);
  const bobAccount = bip47AccountNode(bobRootFromMnemonic(), 0);
  const a0 = aliceAccount.deriveChild(0).privateKey;
  const bobDecoded = decodePaymentCode(BOB.code);
  const aliceDecoded = decodePaymentCode(ALICE.code);
  const send = bip47PairRows("send", { own: a0, publicKey: bobDecoded.publicKey, chainCode: bobDecoded.chainCode }, 0, PAIR_ROW_COUNT, "mainnet");
  assert.deepEqual(send.rows.map((row) => row.address), PAIR_ADDRESSES);
  assert.deepEqual(send.rows.map((row) => row.index), [...Array(10).keys()]);
  assert.deepEqual(send.skipped, []);
  const receive = bip47PairRows("receive", { own: bobAccount, publicKey: aliceDecoded.publicKey, chainCode: aliceDecoded.chainCode }, 0, PAIR_ROW_COUNT, "mainnet");
  assert.deepEqual(receive.rows.map((row) => row.address), PAIR_ADDRESSES);
  for (const [i, row] of receive.rows.entries()) {
    // The receive private key is real: its pubkey must land on the same address.
    const pub = secp256k1.getPublicKey(row.privateKey, true);
    assert.equal(addressFromScript(p2pkhScript(pub), "mainnet"), PAIR_ADDRESSES[i]);
    assert.equal(bytesToHex(row.publicKey), bytesToHex(pub), `row ${i} public/private agree`);
    row.privateKey.fill(0);
  }
  a0.fill(0);
  aliceAccount.wipePrivateData();
  bobAccount.wipePrivateData();
  // b'0 = (b0 + SHA256(S0)) mod n, and it pays address 0.
  const b0 = hexToBytes(BOB.b[0]);
  const s0 = sha256(hexToBytes(SHARED_X[0]));
  const b0prime = (toBig(b0) + toBig(s0)) % ORDER;
  assert.equal(bytesToHex(toBytes32(b0prime)), "d687f6b820e6e3d47296b01f3b73ccdc930eded39d559921a7dd8ed81b2c8f82");
  assert.equal(addressFromScript(p2pkhScript(secp256k1.getPublicKey(toBytes32(b0prime), true)), "mainnet"), PAIR_ADDRESSES[0]);
  b0.fill(0);
});

// ── 5. Notification vector ───────────────────────────────────────────────────

test("5. WIF -> designated pubkey; x(S); the HMAC argument order is settled; blind/unblind; txid; outpoint display", () => {
  const aPriv = wifToPriv(NOTIFY.wif);
  try {
    assert.equal(bytesToHex(secp256k1.getPublicKey(aPriv, true)), NOTIFY.pubkey, "WIF -> designated pubkey");
    const bobB0 = hexToBytes(BOB.B[0]);
    const x = bip47SharedX(aPriv, bobB0);
    assert.equal(bytesToHex(x), NOTIFY.x, "x(S)");
    const mask = bip47Mask(x, hexToBytes(NOTIFY.outpoint));
    assert.equal(bytesToHex(mask), NOTIFY.mask, "mask with key = outpoint");
    const wrong = hmacSha512(x, hexToBytes(NOTIFY.outpoint));
    assert.notEqual(bytesToHex(wrong), NOTIFY.mask, "mask with key = x must NOT match (locks the argument order)");
    const blinded = bip47BlindNotification(hexToBytes(NOTIFY.plain), aPriv, bobB0, hexToBytes(NOTIFY.outpoint));
    assert.equal(bytesToHex(blinded), NOTIFY.blinded, "blinding Alice's plain payload");
    const unblinded = bip47BlindPayload(hexToBytes(NOTIFY.blinded), hexToBytes(NOTIFY.mask));
    assert.equal(bytesToHex(unblinded), NOTIFY.plain, "unblind round-trip");
    const raw = hexToBytes(NOTIFY.tx);
    const txidHash = sha256(sha256(raw));
    const txid = Buffer.from(txidHash).reverse().toString("hex");
    assert.equal(txid, NOTIFY.txid, "tx hex hashes to the txid");
    const outpoint = bip47OutpointFromDisplay(NOTIFY.outpointDisplay);
    assert.equal(bytesToHex(outpoint), NOTIFY.outpoint, "display txid:vout -> 36 internal bytes");
  } finally {
    aPriv.fill(0);
  }
});

test("5. decoding the tx with Bob's root recovers Alice's code and flags the payment; Alice's root learns nothing", () => {
  const bobRoot = bobRootFromMnemonic();
  const bobNotifPriv = bobRoot.derive("m/47'/0'/0'/0").privateKey;
  try {
    const result = bip47DecodeNotificationTx(NOTIFY.tx, bobNotifPriv);
    assert.equal(result.status, "ok");
    assert.equal(result.code, ALICE.code);
    assert.equal(result.paysOurNotification, true);
    assert.equal(result.inputIndex, 0);
    assert.equal(result.kind, "p2pkh");
    assert.equal(result.publicKeyHex, NOTIFY.pubkey);
    const markup = hodlBip47RenderTx(result, { network: "mainnet" });
    assert.doesNotMatch(markup, /doesn't prove/);
    assert.match(markup, /notification address of yours/);
  } finally {
    bobNotifPriv.fill(0);
  }
  const aliceRoot = aliceRootFromMnemonic();
  const aliceNotifPriv = aliceRoot.derive("m/47'/0'/0'/0").privateKey;
  try {
    const wrong = bip47DecodeNotificationTx(NOTIFY.tx, aliceNotifPriv);
    assert.notEqual(wrong.code, ALICE.code, "Alice's root must NOT recover Alice's code");
    assert.equal(wrong.paysOurNotification, false);
    const markup = hodlBip47RenderTx(wrong, { network: "mainnet" });
    assert.match(markup, /doesn't prove the transaction was meant for you/);
  } finally {
    aliceNotifPriv.fill(0);
  }
});

// ── 6. Payment-code parsing ──────────────────────────────────────────────────

test("6. codes round-trip; bad shapes are rejected", () => {
  for (const code of [ALICE.code, BOB.code]) {
    const decoded = decodePaymentCode(code);
    assert.equal(decoded.supported, true);
    assert.equal(decoded.version, 1);
    assert.equal(decoded.features, 0);
    assert.deepEqual(decoded.warnings, []);
    assert.equal(encodePaymentCode(decoded.publicKey, decoded.chainCode, decoded.features), code);
  }
  // Bad checksum: a different trailing character fails the checksum.
  assert.throws(() => decodePaymentCode(`${ALICE.code.slice(0, -2)}A${ALICE.code.slice(-1)}`), /Not a valid Base58Check payment code\./);
  // A Base58 version byte other than 0x47.
  const aliceDecoded = decodePaymentCode(ALICE.code);
  const payload = bip47Payload(aliceDecoded.publicKey, aliceDecoded.chainCode, aliceDecoded.features);
  const wrongVersion = base58checkEncode(Uint8Array.from([0x00, ...payload]));
  assert.throws(() => decodePaymentCode(wrongVersion), /version byte 0x47/);
  // Payload that is not 80 bytes.
  const shortPayload = base58checkEncode(Uint8Array.from([0x47, ...payload.slice(0, 79)]));
  assert.throws(() => decodePaymentCode(shortPayload), /80-byte payload/);
  // Sign byte 0x04.
  const badSign = payload.slice();
  badSign[2] = 0x04;
  assert.throws(() => decodePaymentCode(base58checkEncode(Uint8Array.from([0x47, ...badSign]))), /sign byte/);
  // Off-curve x: mutate x until the point check fails (found deterministically).
  for (let candidate = 0; candidate < 256; candidate++) {
    const mutated = payload.slice();
    mutated[3] = candidate;
    try {
      decodePaymentCode(base58checkEncode(Uint8Array.from([0x47, ...mutated])));
    } catch (error) {
      assert.match(error.message, /not on the secp256k1 curve/);
      return;
    }
  }
  assert.fail("no off-curve x found");
});

test("6. payload version 0x02 is reported as not derived here; a non-zero reserved byte warns but still decodes", () => {
  const aliceDecoded = decodePaymentCode(ALICE.code);
  const payload = bip47Payload(aliceDecoded.publicKey, aliceDecoded.chainCode, aliceDecoded.features);
  const v2 = payload.slice();
  v2[0] = 0x02;
  const decoded = decodePaymentCode(base58checkEncode(Uint8Array.from([0x47, ...v2])));
  assert.equal(decoded.supported, false);
  assert.equal(decoded.version, 2);
  const markup = hodlBip47RenderDecoded({ code: "PM8T…", decoded, network: "mainnet" });
  assert.match(markup, /not derived in this card/);
  const dirty = payload.slice();
  dirty[70] = 0x01;
  const still = decodePaymentCode(base58checkEncode(Uint8Array.from([0x47, ...dirty])));
  assert.equal(still.supported, true);
  assert.equal(still.warnings.length, 1);
  assert.match(still.warnings[0], /Reserved byte 70/);
});

// ── 7. Network ───────────────────────────────────────────────────────────────

test("7. coin-1 codes still start with PM8T, decode as v1, and carry no network; addresses follow the selected network", () => {
  const coin0 = accountCode(aliceRootFromMnemonic(), 0);
  const coin1 = accountCode(aliceRootFromMnemonic(), 1);
  assert.ok(coin1.startsWith("PM8T"), "coin-1 codes keep the 0x47 prefix");
  assert.notEqual(coin1, coin0);
  const decoded = decodePaymentCode(coin1);
  assert.equal(decoded.supported, true);
  assert.equal(decoded.version, 1);
  // The decode surface has no network field at all.
  for (const key of Object.keys(decoded)) assert.doesNotMatch(key, /network/i);
  // The note is always rendered (self, decode, pairs, tx outputs).
  const notePattern = /Payment codes don't say which network they're for/;
  assert.match(hodlBip47RenderSelf({ code: coin0, version: 1, features: 0, accountPath: "m/47'/0'/0'", coinType: 0, network: "mainnet", notificationAddress: ALICE.notificationAddress, notificationPrivHex: ALICE.a0 }), notePattern);
  assert.match(hodlBip47RenderDecoded({ code: coin0, decoded, network: "mainnet" }), notePattern);
  const txResult = bip47DecodeNotificationTx(NOTIFY.tx, bobRootFromMnemonic().derive("m/47'/0'/0'/0").privateKey);
  assert.match(hodlBip47RenderTx(txResult, { network: "testnet" }), notePattern);
  const send = bip47PairRows("send", { own: hexToBytes(ALICE.a0), publicKey: decoded.publicKey, chainCode: decoded.chainCode }, 0, 1, "testnet");
  assert.match(hodlBip47RenderPairs({ ...send, direction: "send", coinType: 1, network: "testnet" }), notePattern);
  // Testnet addresses use the testnet P2PKH prefix (m…/n…).
  const child0 = bip47ChildPublic(decoded.publicKey, decoded.chainCode, 0);
  const testnetAddress = bip47NotificationAddress(child0, "testnet");
  assert.match(testnetAddress, /^[mn]/, "testnet notification address uses the testnet P2PKH prefix");
  send.rows.forEach((row) => assert.match(row.address, /^[mn]/));
  // No UI path claims a wrong-network detection for a payment code.
  assert.doesNotMatch(uiSource, /wrong[ -]network|network mismatch|wrong network|wrong-payment-network/i);
});

// ── 8. Watch-only (pasted code, no session root) ─────────────────────────────

test("8. watch-only: the code and its notification address show; pair/tx/blind and every private-key control stay disabled; no private-key element exists", () => {
  const map = hodlBip47Availability({ hasSession: false, hasCode: true, hasPairCode: false, hasTx: false, hasBlindKey: false, hasBlindOutpoint: false, hasBlindCode: false });
  assert.equal(map["bip47-decode-go"], false, "decode stays enabled with a pasted code");
  assert.equal(map["bip47-self-go"], true, "own code needs the session root");
  for (const id of ["bip47-send-go", "bip47-receive-go", "bip47-tx-go", "bip47-blind-go", "bip47-blind-key", "bip47-blind-outpoint", "bip47-blind-code", "bip47-tx", "bip47-tx-manual", "bip47-pair-code", "bip47-pair-start"]) {
    assert.equal(map[id], true, `${id} must be disabled`);
  }
  const decoded = decodePaymentCode(ALICE.code);
  const markup = hodlBip47RenderDecoded({ code: ALICE.code, decoded, network: "mainnet" });
  assert.match(markup, new RegExp(ALICE.code.replace(/[^A-Za-z0-9]/g, (c) => `\\${c}`)));
  assert.match(markup, new RegExp(ALICE.notificationAddress));
  assert.doesNotMatch(markup, /private key|Reveal/i, "no private-key element in the watch-only render");
});

// ── 9. Empty state ───────────────────────────────────────────────────────────

test("9. with no session root and no pasted code, every card action is disabled", () => {
  const map = hodlBip47Availability({ hasSession: false, hasCode: false, hasPairCode: false, hasTx: false, hasBlindKey: false, hasBlindOutpoint: false, hasBlindCode: false });
  for (const [id, disabled] of Object.entries(map)) assert.equal(disabled, true, `${id} must be disabled`);
});

// ── 10. Send rows never render a private-key element ─────────────────────────

test("10. send rows carry no private key and render no private-key element", () => {
  const bobDecoded = decodePaymentCode(BOB.code);
  const a0 = hexToBytes(ALICE.a0);
  const send = bip47PairRows("send", { own: a0, publicKey: bobDecoded.publicKey, chainCode: bobDecoded.chainCode }, 0, PAIR_ROW_COUNT, "mainnet");
  a0.fill(0);
  for (const row of send.rows) {
    assert.equal("privateKey" in row, false, "send rows never have a private key");
  }
  const markup = hodlBip47RenderPairs({ ...send, direction: "send", coinType: 0, network: "mainnet" }, { reveal: true });
  assert.doesNotMatch(markup, /private key|Reveal|bip47-pairs-reveal/i, "no private-key element in send markup, even asked to reveal");
});

// ── 11. Designated input classification ──────────────────────────────────────

// Minimal segwit serializer for the constructed cases below (built by
// blinding with the vector's designated key, not published vectors).
const u32le = (v) => [v & 255, (v >>> 8) & 255, (v >>> 16) & 255, (v >>> 24) & 255];
const varint = (n) => (n < 0xfd ? [n] : n < 0x10000 ? [0xfd, n & 255, (n >>> 8) & 255] : [0xfe, ...u32le(n)]);
const serializeTxLocal = ({ version = 2, inputs, outputs, locktime = 0 }) => {
  const hasWitness = inputs.some((input) => (input.witness || []).length);
  const bytes = [...u32le(version >>> 0)];
  if (hasWitness) bytes.push(0x00, 0x01);
  bytes.push(...varint(inputs.length));
  for (const input of inputs) {
    bytes.push(...input.txid, ...u32le(input.vout >>> 0), ...varint(input.scriptSig.length), ...input.scriptSig, ...u32le((input.sequence ?? 0xffffffff) >>> 0));
  }
  bytes.push(...varint(outputs.length));
  for (const output of outputs) {
    let amount = BigInt(output.amount);
    for (let i = 0; i < 8; i++) bytes.push(Number((amount >> BigInt(8 * i)) & 255n));
    bytes.push(...varint(output.script.length), ...output.script);
  }
  if (hasWitness) {
    for (const input of inputs) {
      const witness = input.witness || [];
      bytes.push(...varint(witness.length));
      for (const item of witness) bytes.push(...varint(item.length), ...item);
    }
  }
  bytes.push(...u32le(locktime >>> 0));
  return Uint8Array.from(bytes);
};
const opReturnOutput = (payload80) => ({ amount: 0n, script: Uint8Array.from([0x6a, 0x4c, 0x50, ...payload80]) });
const vectorInputBase = () => ({
  txid: hexToBytes(NOTIFY.outpoint.slice(0, 64)), // designated input of the published vector
  vout: 1,
  sequence: 0xffffffff,
});
const bobNotifPrivFromMnemonic = () => bobRootFromMnemonic().derive("m/47'/0'/0'/0").privateKey;

test("11. the P2PKH vector's designated input is classified from the tx alone", () => {
  const tx = parseRawTx(hexToBytes(NOTIFY.tx));
  const found = extractDesignatedPubKey(tx);
  assert.equal(found.status, "found");
  assert.equal(found.inputIndex, 0);
  assert.equal(found.kind, "p2pkh");
  assert.equal(bytesToHex(found.publicKey), NOTIFY.pubkey);
});

test("11. a constructed P2WPKH designated input works (constructed, not a published vector)", () => {
  const aPriv = wifToPriv(NOTIFY.wif);
  const pub = hexToBytes(NOTIFY.pubkey);
  const sig = parseRawTx(hexToBytes(NOTIFY.tx)).inputs[0].scriptSig.slice(1, 73); // reuse the vector's sig bytes as filler
  const input = { ...vectorInputBase(), scriptSig: new Uint8Array(), witness: [sig, pub] };
  const outpoint = new Uint8Array([...input.txid, ...u32le(input.vout)]);
  const blinded = bip47BlindNotification(hexToBytes(NOTIFY.plain), aPriv, hexToBytes(BOB.B[0]), outpoint);
  aPriv.fill(0);
  const payerOutput = { amount: 10000n, script: p2pkhScript(hexToBytes(BOB.B[0])) };
  const txBytes = serializeTxLocal({ inputs: [input], outputs: [payerOutput, opReturnOutput(blinded)] });
  const priv = bobNotifPrivFromMnemonic();
  try {
    const result = bip47DecodeNotificationTx(bytesToHex(txBytes), priv);
    assert.equal(result.status, "ok");
    assert.equal(result.kind, "p2wpkh");
    assert.equal(result.code, ALICE.code);
    assert.equal(result.paysOurNotification, true);
  } finally {
    priv.fill(0);
  }
});

test("11. a constructed P2SH-P2WPKH designated input works (constructed, not a published vector)", () => {
  const aPriv = wifToPriv(NOTIFY.wif);
  const pub = hexToBytes(NOTIFY.pubkey);
  const redeem = Uint8Array.from([0x16, 0x00, 0x14, ...hexToBytes("00112233445566778899aabbccddeeff00112233")]);
  const sig = parseRawTx(hexToBytes(NOTIFY.tx)).inputs[0].scriptSig.slice(1, 73);
  const input = { ...vectorInputBase(), scriptSig: redeem, witness: [sig, pub] };
  const outpoint = new Uint8Array([...input.txid, ...u32le(input.vout)]);
  const blinded = bip47BlindNotification(hexToBytes(NOTIFY.plain), aPriv, hexToBytes(BOB.B[0]), outpoint);
  aPriv.fill(0);
  const payerOutput = { amount: 10000n, script: p2pkhScript(hexToBytes(BOB.B[0])) };
  const txBytes = serializeTxLocal({ inputs: [input], outputs: [payerOutput, opReturnOutput(blinded)] });
  const priv = bobNotifPrivFromMnemonic();
  try {
    const result = bip47DecodeNotificationTx(bytesToHex(txBytes), priv);
    assert.equal(result.status, "ok");
    assert.equal(result.kind, "p2sh-p2wpkh");
    assert.equal(result.code, ALICE.code);
  } finally {
    priv.fill(0);
  }
});

test("11. an unclassifiable first input requires the manual pubkey and never falls through to a later input", () => {
  const aPriv = wifToPriv(NOTIFY.wif);
  // Input 0: a bare-P2PK-shaped unlock (pubkey push only) — unclassifiable.
  const manualPub = hexToBytes(NOTIFY.pubkey);
  const unclassifiable = {
    txid: hexToBytes("11".repeat(32)),
    vout: 0,
    sequence: 0xffffffff,
    scriptSig: Uint8Array.from([0x21, ...manualPub]),
    witness: [],
  };
  // Input 1: perfectly classifiable P2PKH — must NOT be picked ahead of input 0.
  const p2pkhInput = { ...vectorInputBase(), scriptSig: parseRawTx(hexToBytes(NOTIFY.tx)).inputs[0].scriptSig, witness: [] };
  const outpoint = new Uint8Array([...unclassifiable.txid, ...u32le(unclassifiable.vout)]);
  const blinded = bip47BlindNotification(hexToBytes(NOTIFY.plain), aPriv, hexToBytes(BOB.B[0]), outpoint);
  aPriv.fill(0);
  const txBytes = serializeTxLocal({ inputs: [unclassifiable, p2pkhInput], outputs: [opReturnOutput(blinded)] });
  const parsed = parseRawTx(txBytes);
  const found = extractDesignatedPubKey(parsed);
  assert.equal(found.status, "manual-needed");
  assert.equal(found.inputIndex, 0, "scanning stops at the unrecognized first input");
  const priv = bobNotifPrivFromMnemonic();
  try {
    const manualNeeded = bip47DecodeNotificationTx(bytesToHex(txBytes), priv);
    assert.equal(manualNeeded.status, "manual-needed");
    assert.equal(manualNeeded.inputIndex, 0);
    assert.match(hodlBip47RenderTx(manualNeeded), /manual field/);
    const resolved = bip47DecodeNotificationTx(bytesToHex(txBytes), priv, { designatedPub: manualPub });
    assert.equal(resolved.status, "ok");
    assert.equal(resolved.kind, "manual");
    assert.equal(resolved.code, ALICE.code);
    assert.equal(resolved.inputIndex, 0, "the manual key binds the first input, not the later P2PKH one");
    // A non-point manual key is reported, never silently accepted.
    const invalid = bip47DecodeNotificationTx(bytesToHex(txBytes), priv, { designatedPub: "beef" });
    assert.equal(invalid.status, "manual-invalid");
  } finally {
    priv.fill(0);
  }
});

test("11. a tx with no 80-byte OP_RETURN is reported as such", () => {
  const txBytes = serializeTxLocal({ inputs: [{ ...vectorInputBase(), scriptSig: new Uint8Array(), witness: [] }], outputs: [{ amount: 1n, script: p2pkhScript(hexToBytes(BOB.B[0])) }] });
  const priv = bobNotifPrivFromMnemonic();
  try {
    const result = bip47DecodeNotificationTx(bytesToHex(txBytes), priv);
    assert.equal(result.status, "no-payload");
    assert.match(hodlBip47RenderTx(result), /No OP_RETURN output carries an 80-byte payload/);
  } finally {
    priv.fill(0);
  }
});

// ── 12. Skipped indices ──────────────────────────────────────────────────────

test("12. an invalid tweak is skipped, listed, and never renumbered", () => {
  const bobDecoded = decodePaymentCode(BOB.code);
  const a0 = hexToBytes(ALICE.a0);
  // Stub the scalar check so index 1 (and only index 1) is invalid.
  const invalidTweak = sha256(hexToBytes(SHARED_X[1]));
  const checkTweak = (sBytes) => !equalBytes(sBytes, invalidTweak);
  const send = bip47PairRows("send", { own: a0, publicKey: bobDecoded.publicKey, chainCode: bobDecoded.chainCode, checkTweak }, 0, PAIR_ROW_COUNT, "mainnet");
  a0.fill(0);
  assert.deepEqual(send.rows.map((row) => row.index), [0, 2, 3, 4, 5, 6, 7, 8, 9, 10], "rows show the actual indices used");
  assert.deepEqual(send.skipped, [1], "index 1 is listed as skipped");
  assert.match(hodlBip47RenderPairs({ ...send, direction: "send", coinType: 0, network: "mainnet" }), /Skipped indices[\s\S]*1[\s\S]*Nothing is renumbered/);
});

// ── 13. Wipe ─────────────────────────────────────────────────────────────────

test("13. hodlSpWipeKeys() also wipes BIP-47 state, and hodlBip47Wipe resets reveal flags and clears fields", () => {
  const wipeStart = appSource.indexOf("function hodlSpWipeKeys()");
  const wipeEnd = appSource.indexOf("\n}", wipeStart);
  assert.ok(wipeStart >= 0, "hodlSpWipeKeys exists");
  assert.ok(appSource.slice(wipeStart, wipeEnd).includes("hodlBip47Wipe()"), "SP key changes or wipes must also wipe BIP-47 state");
  assert.match(appSource, /import \{ hodlInitBip47, hodlBip47Wipe \} from "\.\/bip47-ui\.js"/);

  // Behaviour: session state, reveal flags, and the private-key field clear.
  const elements = new Map();
  const fakeElement = (id) => {
    if (!elements.has(id)) {
      elements.set(id, {
        id,
        value: "",
        innerHTML: "",
        textContent: "",
        disabled: false,
        hidden: false,
        onclick: null,
        onchange: null,
        classList: { toggle: () => {} },
        setAttribute: () => {},
        addEventListener: () => {},
      });
    }
    return elements.get(id);
  };
  globalThis.document = {
    getElementById: fakeElement,
    querySelectorAll: () => [],
  };
  try {
    const aliceRoot = aliceRootFromMnemonic();
    hodlInitBip47({
      ensureHd: () => {},
      getHd: () => aliceRoot,
      coinType: () => 0,
      network: () => "mainnet",
      parsePrivateKey: (text) => wifToPriv(text),
    });
    const go = fakeElement("bip47-self-go");
    go.onclick();
    assert.equal(fakeElement("bip47-error").textContent, "");
    assert.match(fakeElement("bip47-out").innerHTML, new RegExp(ALICE.code.replace(/[^A-Za-z0-9]/g, (c) => `\\${c}`)));
    const toggle = fakeElement("bip47-self-reveal");
    toggle.onchange({ target: { checked: true } });
    assert.match(fakeElement("bip47-out").innerHTML, new RegExp(ALICE.a0), "reveal shows the notification private key");
    fakeElement("bip47-blind-key").value = NOTIFY.wif;
    hodlBip47Wipe();
    assert.equal(fakeElement("bip47-blind-key").value, "", "the private-key input is cleared");
    assert.equal(fakeElement("bip47-out").innerHTML, "", "outputs are cleared");
    // Reveal flags reset: the next run hides the key again.
    go.onclick();
    assert.doesNotMatch(fakeElement("bip47-out").innerHTML, new RegExp(ALICE.a0), "reveal flags are false after wipe");
  } finally {
    delete globalThis.document;
  }
});

// ── 14. Print/save ───────────────────────────────────────────────────────────

test("14. no private material in the card's markup without its reveal toggle; the card is no-print", () => {
  assert.match(shell, /<section class="card no-print tool-card" id="bip47-card" role="tabpanel" hidden>/);
  const selfResult = { code: ALICE.code, version: 1, features: 0, accountPath: "m/47'/0'/0'", coinType: 0, network: "mainnet", notificationAddress: ALICE.notificationAddress, notificationPrivHex: ALICE.a0 };
  const hiddenMarkup = hodlBip47RenderSelf(selfResult, { reveal: false });
  assert.doesNotMatch(hiddenMarkup, new RegExp(ALICE.a0));
  const shownMarkup = hodlBip47RenderSelf(selfResult, { reveal: true });
  assert.match(shownMarkup, new RegExp(ALICE.a0));
  const receiveDecoded = decodePaymentCode(ALICE.code);
  const bobAccount = bip47AccountNode(bobRootFromMnemonic(), 0);
  const receive = bip47PairRows("receive", { own: bobAccount, publicKey: receiveDecoded.publicKey, chainCode: receiveDecoded.chainCode }, 0, 1, "mainnet");
  const b0Tweaked = "d687f6b820e6e3d47296b01f3b73ccdc930eded39d559921a7dd8ed81b2c8f82"; // (b0 + SHA256(S0)) mod n, the published cross-check
  const hiddenPairs = hodlBip47RenderPairs({ ...receive, direction: "receive", coinType: 0, network: "mainnet" }, { reveal: false });
  assert.doesNotMatch(hiddenPairs, new RegExp(b0Tweaked));
  const shownPairs = hodlBip47RenderPairs({ ...receive, direction: "receive", coinType: 0, network: "mainnet" }, { reveal: true });
  assert.match(shownPairs, new RegExp(b0Tweaked));
  receive.rows.forEach((row) => row.privateKey.fill(0));
  bobAccount.wipePrivateData();
});

// ── 15. Shell contract ───────────────────────────────────────────────────────

test("15. shell contract: sibling placement, tab labels, and label wording", () => {
  // #bip47-card is the next element sibling of #sp-card (sp-card is a <div> in current markup).
  const spIndex = shell.indexOf('<div class="card no-print tool-card" id="sp-card"');
  assert.ok(spIndex >= 0);
  const closeIndex = shell.indexOf("</div>", shell.indexOf('id="sp-address-view"', spIndex));
  assert.match(shell.slice(closeIndex + "</div>".length).replace(/^\s+/, ""), /^(?:<\/div>\s*)*<section class="card no-print tool-card" id="bip47-card" role="tabpanel" hidden>/);
  // The #workspace-tabs buttons carry exactly these aria-labels, in order.
  const tabsBlock = shell.slice(shell.indexOf('id="workspace-tabs"'), shell.indexOf('id="key-tabs"'));
  const labels = [...tabsBlock.matchAll(/<button[^>]*aria-label="([^"]+)"/g)].map((match) => match[1]);
  assert.deepEqual(labels, ["Keys", "Multi Signature", "PSBT", "BIP-85 Child", "Silent Payments", "Vanity Address"]);
  // No tab label may match /privacy|paynym|bip-?47/i.
  for (const label of labels) assert.doesNotMatch(label, /privacy|paynym|bip-?47/i);
  // The card's wording: "BIP-47 payment code", "PayNym" at most once in muted help text.
  assert.match(shell, /BIP-47 payment code/);
  const cardMarkup = `${shell}${uiSource}`;
  const paynymCount = (cardMarkup.match(/PayNym/g) || []).length;
  assert.ok(paynymCount <= 1, "the PayNym name may appear at most once");
});

test("app.js carries only the three wiring hooks", () => {
  assert.match(appSource, /document\.getElementById\("bip47-card"\)\.hidden = id !== "sp"/);
  assert.match(appSource, /import \{ hodlInitBip47, hodlBip47Wipe \} from "\.\/bip47-ui\.js"/);
  assert.match(appSource, /hodlInitBip47\(\{/);
});
