// BIP-47 v1 payment-code calculator tests (src/js/bip47.js core).
//
// Pinned vector provenance (keep with the values below):
// Source: SamouraiDev gist `6aad669604c5930864bd`, the link in BIP-47's
// "Test Vectors" section. These vectors are not in bitcoin/bips. Every value
// was independently recomputed during prompt review.
// Run with `npm test`.
import { test } from "node:test";
import assert from "node:assert/strict";
import { HDKey } from "../src/js/hdkey.js";
import { mnemonicToSeedSync } from "../src/js/bip39.js";
import { secp256k1 } from "../src/js/secp256k1.js";
import { sha256, hmacSha512, hash160 } from "../src/js/hashes.js";
import { base58checkEncode, base58checkDecode } from "../src/js/base58.js";
import { parseRawTx } from "../src/js/tx.js";
import { p2pkhScript, addressFromScript } from "../src/js/addresses.js";
import * as bip47Module from "../src/js/bip47.js";
import {
  Bip47Error,
  PAIR_ROW_COUNT,
  bip47AccountNode,
  bip47AccountPath,
  bip47ChildPublic,
  bip47DecodeNotificationTx,
  bip47InputOutpoint,
  bip47Mask,
  bip47NotificationAddress,
  bip47OutpointFromDisplay,
  bip47PairRows,
  bip47Payload,
  bip47ReceiveRow,
  bip47SendRow,
  bip47SharedX,
  bytesToHex,
  decodePaymentCode,
  decodePaymentCodePayload,
  encodePaymentCode,
  equalBytes,
  extractDesignatedPubKey,
  hexToBytes,
} from "../src/js/bip47.js";

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
const accountCode = (rootNode, network) => {
  const account = bip47AccountNode(rootNode, network);
  try { return encodePaymentCode(account.publicKey, account.chainCode); }
  finally { account.wipePrivateData(); }
};
const wifToPriv = (wif) => base58checkDecode(wif).slice(1, 33);
const bobNotifPrivFromMnemonic = () => bobRootFromMnemonic().derive("m/47'/0'/0'/0").privateKey;
const xorPayload = (payload, mask) => {
  const out = payload.slice();
  for (let i = 0; i < 32; i++) {
    out[3 + i] ^= mask[i];
    out[35 + i] ^= mask[32 + i];
  }
  return out;
};

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
  txid: hexToBytes(NOTIFY.outpoint.slice(0, 64)),
  vout: 1,
  sequence: 0xffffffff,
});

// ── 1. Payment codes and keys ────────────────────────────────────────────────

test("1. payment codes derive from the mnemonics and from the raw BIP32 seeds", () => {
  assert.equal(accountCode(aliceRootFromMnemonic(), "mainnet"), ALICE.code);
  assert.equal(accountCode(aliceRootFromSeed(), "mainnet"), ALICE.code);
  assert.equal(accountCode(bobRootFromMnemonic(), "mainnet"), BOB.code);
  assert.equal(accountCode(bobRootFromSeed(), "mainnet"), BOB.code);
  assert.equal(bip47AccountPath(0), "m/47'/0'/0'");
  const aliceAccount = bip47AccountNode(aliceRootFromMnemonic(), "mainnet");
  const a0 = aliceAccount.deriveChild(0);
  assert.equal(bytesToHex(a0.privateKey), ALICE.a0);
  assert.equal(bytesToHex(a0.publicKey), ALICE.A0);
  a0.wipePrivateData();
  aliceAccount.wipePrivateData();
  const bobAccount = bip47AccountNode(bobRootFromMnemonic(), "mainnet");
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
    const account = bip47AccountNode(root, "mainnet");
    const child0 = bip47ChildPublic(account.publicKey, account.chainCode, 0);
    assert.equal(bip47NotificationAddress(child0, "mainnet"), expected);
    account.wipePrivateData();
  }
});

// ── 3. Shared secrets, from both sides ───────────────────────────────────────

test("3. S_i = x(a0·B_i) = x(b_i·A0) for i = 0..9", () => {
  const aliceAccount = bip47AccountNode(aliceRootFromMnemonic(), "mainnet");
  const bobAccount = bip47AccountNode(bobRootFromMnemonic(), "mainnet");
  const a0 = aliceAccount.deriveChild(0).privateKey;
  try {
    for (let i = 0; i < 10; i++) {
      const bi = bobAccount.deriveChild(i).privateKey;
      try {
        const bPub = secp256k1.getPublicKey(bi, true);
        const sender = bip47SharedX(a0, bPub);
        const a0Pub = secp256k1.getPublicKey(a0, true);
        const receiver = bip47SharedX(bi, a0Pub);
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
  const aliceAccount = bip47AccountNode(aliceRootFromMnemonic(), "mainnet");
  const bobAccount = bip47AccountNode(bobRootFromMnemonic(), "mainnet");
  const a0 = aliceAccount.deriveChild(0).privateKey;
  const bobDecoded = decodePaymentCode(BOB.code);
  const aliceDecoded = decodePaymentCode(ALICE.code);
  const send = bip47PairRows("send", { own: a0, code: bobDecoded }, 0, PAIR_ROW_COUNT, "mainnet");
  assert.deepEqual(send.rows.map((row) => row.address), PAIR_ADDRESSES);
  assert.deepEqual(send.rows.map((row) => row.index), [...Array(10).keys()]);
  assert.deepEqual(send.skipped, []);
  assert.equal(send.budgetExhausted, false);
  const receive = bip47PairRows("receive", { own: bobAccount, code: aliceDecoded }, 0, PAIR_ROW_COUNT, "mainnet");
  assert.deepEqual(receive.rows.map((row) => row.address), PAIR_ADDRESSES);
  for (const [i, row] of receive.rows.entries()) {
    const pub = secp256k1.getPublicKey(row.privateKey, true);
    assert.equal(addressFromScript(p2pkhScript(pub), "mainnet"), PAIR_ADDRESSES[i]);
    assert.equal(bytesToHex(row.publicKey), bytesToHex(pub), `row ${i} public/private agree`);
    row.privateKey.fill(0);
  }
  a0.fill(0);
  aliceAccount.wipePrivateData();
  bobAccount.wipePrivateData();
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
    const blinded = xorPayload(hexToBytes(NOTIFY.plain), mask);
    assert.equal(bytesToHex(blinded), NOTIFY.blinded, "blinding Alice's plain payload");
    const unblinded = xorPayload(hexToBytes(NOTIFY.blinded), mask);
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

test("5. decoding the tx with Bob's root recovers Alice's code and flags the payment; a different key does not recover Alice's code and its result does not pay that key's notification address", () => {
  const bobRoot = bobRootFromMnemonic();
  const bobNotifPriv = bobRoot.derive("m/47'/0'/0'/0").privateKey;
  try {
    const result = bip47DecodeNotificationTx(NOTIFY.tx, bobNotifPriv);
    assert.equal(result.status, "ok");
    assert.equal(result.code, ALICE.code);
    assert.equal(result.codeRecovered, true);
    assert.equal(result.hasOutputToNotificationAddress, true);
    assert.equal(result.inputIndex, 0);
    assert.equal(result.kind, "p2pkh");
    assert.equal(result.publicKeyHex, NOTIFY.pubkey);
    assert.equal(result.designatedDisplayTxid, "9c6000d597c5008f7bfc2618aed5e4a6ae57677aab95078aae708e1cab11f486");
  } finally {
    bobNotifPriv.fill(0);
  }
  const aliceRoot = aliceRootFromMnemonic();
  const aliceNotifPriv = aliceRoot.derive("m/47'/0'/0'/0").privateKey;
  try {
    const wrong = bip47DecodeNotificationTx(NOTIFY.tx, aliceNotifPriv);
    assert.notEqual(wrong.code, ALICE.code, "Alice's root must NOT recover Alice's code");
    assert.equal(wrong.codeRecovered, false);
    assert.equal(wrong.hasOutputToNotificationAddress, false);
    assert.equal(wrong.recipientCheck, "does-not-pay-this-notification-address");
  } finally {
    aliceNotifPriv.fill(0);
  }
});

test("5b. a wrong notification key can still yield a derivable code, but it is not Alice's and does not pay that key's notification address", () => {
  let found = null;
  for (let i = 1; i <= 64; i++) {
    const priv = new Uint8Array(32);
    priv[31] = i;
    try {
      const result = bip47DecodeNotificationTx(NOTIFY.tx, priv);
      if (result.codeRecovered) {
        found = { i, result };
        break;
      }
    } finally {
      priv.fill(0);
    }
  }
  assert.ok(found, "a small key produced a structurally derivable code within 64 tries");
  assert.notEqual(found.result.code, ALICE.code);
  assert.equal(found.result.hasOutputToNotificationAddress, false);
  assert.equal(found.result.recipientCheck, "does-not-pay-this-notification-address");
});

// ── 6. Payment-code parsing ──────────────────────────────────────────────────

test("6. codes round-trip; bad shapes are rejected", () => {
  for (const code of [ALICE.code, BOB.code]) {
    const decoded = decodePaymentCode(code);
    assert.equal(decoded.supported, true);
    assert.equal(decoded.version, 1);
    assert.equal(decoded.features, 0);
    assert.equal(decoded.derivable, true);
    assert.deepEqual(decoded.warnings, []);
    assert.equal(encodePaymentCode(decoded.publicKey, decoded.chainCode, decoded.features), code);
  }
  assert.throws(() => decodePaymentCode(`${ALICE.code.slice(0, -2)}A${ALICE.code.slice(-1)}`), /Not a valid Base58Check payment code\./);
  const aliceDecoded = decodePaymentCode(ALICE.code);
  const payload = bip47Payload(aliceDecoded.publicKey, aliceDecoded.chainCode, aliceDecoded.features);
  const wrongVersion = base58checkEncode(Uint8Array.from([0x00, ...payload]));
  assert.throws(() => decodePaymentCode(wrongVersion), /version byte 0x47/);
  const shortPayload = base58checkEncode(Uint8Array.from([0x47, ...payload.slice(0, 79)]));
  assert.throws(() => decodePaymentCode(shortPayload), /80-byte payload/);
  const badSign = payload.slice();
  badSign[2] = 0x04;
  assert.throws(() => decodePaymentCode(base58checkEncode(Uint8Array.from([0x47, ...badSign]))), /sign byte/);
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
  assert.equal(decoded.derivable, false);
  const dirty = payload.slice();
  dirty[70] = 0x01;
  const still = decodePaymentCode(base58checkEncode(Uint8Array.from([0x47, ...dirty])));
  assert.equal(still.supported, true);
  assert.equal(still.derivable, false);
  assert.equal(still.warnings.length, 1);
  assert.match(still.warnings[0], /Reserved byte 70/);
  const reencoded = encodePaymentCode(still.publicKey, still.chainCode, still.features, still.reservedBytes);
  const roundTrip = decodePaymentCode(reencoded);
  assert.deepEqual(roundTrip.reservedBytes, still.reservedBytes);
  assert.equal(roundTrip.reservedBytes[3], 0x01);
});

// ── 7. Network ───────────────────────────────────────────────────────────────

test("7. coin-1 codes still start with PM8T, decode as v1, and carry no network; addresses follow the selected network", () => {
  const coin0 = accountCode(aliceRootFromMnemonic(), "mainnet");
  const coin1 = accountCode(aliceRootFromMnemonic(), "testnet");
  assert.ok(coin1.startsWith("PM8T"), "coin-1 codes keep the 0x47 prefix");
  assert.notEqual(coin1, coin0);
  const decoded = decodePaymentCode(coin1);
  assert.equal(decoded.supported, true);
  assert.equal(decoded.version, 1);
  for (const key of Object.keys(decoded)) assert.doesNotMatch(key, /network/i);
  const child0 = bip47ChildPublic(decoded.publicKey, decoded.chainCode, 0);
  const testnetAddress = bip47NotificationAddress(child0, "testnet");
  assert.match(testnetAddress, /^[mn]/, "testnet notification address uses the testnet P2PKH prefix");
  const send = bip47PairRows("send", { own: hexToBytes(ALICE.a0), code: decoded }, 0, 1, "testnet");
  send.rows.forEach((row) => assert.match(row.address, /^[mn]/));
});

// ── 8. Root contract ─────────────────────────────────────────────────────────

test("8. root contract: master root only; mainnet -> coin 0; testnet/signet/regtest -> coin 1", () => {
  const root = aliceRootFromMnemonic();
  const child = root.deriveChild(0);
  assert.throws(() => bip47AccountNode(child, "mainnet"), (e) => e instanceof Bip47Error && e.code === "ROOT_NOT_MASTER");
  child.wipePrivateData();
  const watchOnly = root.neutered();
  assert.throws(() => bip47AccountNode(watchOnly, "mainnet"), (e) => e instanceof Bip47Error && e.code === "ROOT_NOT_MASTER");
  const mainnet = bip47AccountNode(root, "mainnet");
  const expectedMainnet = root.derive("m/47'/0'/0'");
  assert.equal(bytesToHex(mainnet.publicKey), bytesToHex(expectedMainnet.publicKey));
  mainnet.wipePrivateData();
  expectedMainnet.wipePrivateData();
  for (const network of ["testnet", "signet", "regtest"]) {
    const account = bip47AccountNode(root, network);
    const expected = root.derive("m/47'/1'/0'");
    assert.equal(bytesToHex(account.publicKey), bytesToHex(expected.publicKey), network);
    account.wipePrivateData();
    expected.wipePrivateData();
  }
  assert.equal(bip47AccountPath(0), "m/47'/0'/0'");
  assert.equal(bip47AccountPath(1), "m/47'/1'/0'");
});

// ── 9. Derivability ──────────────────────────────────────────────────────────

test("9. derivability: non-zero reserved byte, feature 0x80 or version 2 decode but refuse every derivation", () => {
  const aliceDecoded = decodePaymentCode(ALICE.code);
  const payload = bip47Payload(aliceDecoded.publicKey, aliceDecoded.chainCode, aliceDecoded.features);
  const featurePayload = payload.slice();
  featurePayload[1] = 0x80;
  const featureCode = decodePaymentCode(base58checkEncode(Uint8Array.from([0x47, ...featurePayload])));
  assert.equal(featureCode.derivable, false);
  const reservedPayload = payload.slice();
  reservedPayload[70] = 0x01;
  const reservedCode = decodePaymentCode(base58checkEncode(Uint8Array.from([0x47, ...reservedPayload])));
  assert.equal(reservedCode.derivable, false);
  const v2Payload = payload.slice();
  v2Payload[0] = 0x02;
  const v2Code = decodePaymentCode(base58checkEncode(Uint8Array.from([0x47, ...v2Payload])));
  assert.equal(v2Code.derivable, false);
  const a0 = hexToBytes(ALICE.a0);
  const bobAccount = bip47AccountNode(bobRootFromMnemonic(), "mainnet");
  try {
    for (const code of [featureCode, reservedCode, v2Code]) {
      assert.throws(() => bip47SendRow(a0, code, 0, "mainnet"), (e) => e instanceof Bip47Error && e.code === "CODE_NOT_DERIVABLE");
      assert.throws(() => bip47ReceiveRow(bobAccount, code, 0, "mainnet"), (e) => e instanceof Bip47Error && e.code === "CODE_NOT_DERIVABLE");
      assert.throws(() => bip47PairRows("send", { own: a0, code }, 0, 1, "mainnet"), (e) => e instanceof Bip47Error && e.code === "CODE_NOT_DERIVABLE");
      assert.throws(() => bip47NotificationAddress(code, "mainnet"), (e) => e instanceof Bip47Error && e.code === "CODE_NOT_DERIVABLE");
    }
  } finally {
    a0.fill(0);
    bobAccount.wipePrivateData();
  }
});

// ── 10. Indexes and the attempt budget ───────────────────────────────────────

test("10. indexes: -1, 1.5, 2^31 and \"3\" are BAD_INDEX; forced skips are listed and never renumbered; the budget stops at count + 32", () => {
  const bobDecoded = decodePaymentCode(BOB.code);
  const aliceDecoded = decodePaymentCode(ALICE.code);
  const a0 = hexToBytes(ALICE.a0);
  const bobAccount = bip47AccountNode(bobRootFromMnemonic(), "mainnet");
  try {
    for (const bad of [-1, 1.5, 2 ** 31, "3"]) {
      assert.throws(() => bip47SendRow(a0, bobDecoded, bad, "mainnet"), (e) => e instanceof Bip47Error && e.code === "BAD_INDEX");
      assert.throws(() => bip47ReceiveRow(bobAccount, aliceDecoded, bad, "mainnet"), (e) => e instanceof Bip47Error && e.code === "BAD_INDEX");
      assert.throws(() => bip47PairRows("send", { own: a0, code: bobDecoded }, bad, 1, "mainnet"), (e) => e instanceof Bip47Error && e.code === "BAD_INDEX");
    }
    const invalidTweak = sha256(hexToBytes(SHARED_X[0]));
    const checkTweak = (sBytes) => !equalBytes(sBytes, invalidTweak);
    const send = bip47PairRows("send", { own: a0, code: bobDecoded, checkTweak }, 0, 3, "mainnet");
    assert.deepEqual(send.rows.map((row) => row.index), [1, 2, 3]);
    assert.deepEqual(send.skipped, [0]);
    assert.equal(send.budgetExhausted, false);
    const exhausted = bip47PairRows("send", { own: a0, code: bobDecoded, checkTweak: () => false }, 0, 5, "mainnet");
    assert.equal(exhausted.rows.length, 0);
    assert.equal(exhausted.skipped.length, 5 + 32);
    assert.equal(exhausted.budgetExhausted, true);
    assert.equal(exhausted.skipped[0], 0);
    assert.equal(exhausted.skipped[exhausted.skipped.length - 1], 36);
  } finally {
    a0.fill(0);
    bobAccount.wipePrivateData();
  }
});

// ── 11. Designated input ─────────────────────────────────────────────────────

test("11. designated input: input 0 without a key and input 1 P2WPKH uses input 1; a bad nested P2WPKH is not accepted; a manual key is manual-unverified", () => {
  const aPriv = wifToPriv(NOTIFY.wif);
  const pub = hexToBytes(NOTIFY.pubkey);
  const sig = parseRawTx(hexToBytes(NOTIFY.tx)).inputs[0].scriptSig.slice(1, 73);
  const priv = bobNotifPrivFromMnemonic();
  try {
    const input0 = { txid: hexToBytes("11".repeat(32)), vout: 0, sequence: 0xffffffff, scriptSig: new Uint8Array(), witness: [] };
    const input1 = { ...vectorInputBase(), scriptSig: new Uint8Array(), witness: [sig, pub] };
    const outpoint1 = new Uint8Array([...input1.txid, ...u32le(input1.vout)]);
    const x1 = bip47SharedX(aPriv, hexToBytes(BOB.B[0]));
    const mask1 = bip47Mask(x1, outpoint1);
    const blinded1 = xorPayload(hexToBytes(NOTIFY.plain), mask1);
    const tx1 = serializeTxLocal({ inputs: [input0, input1], outputs: [{ amount: 10000n, script: p2pkhScript(hexToBytes(BOB.B[0])) }, opReturnOutput(blinded1)] });
    const found1 = extractDesignatedPubKey(parseRawTx(tx1));
    assert.equal(found1.inputIndex, 1);
    assert.equal(found1.kind, "p2wpkh");
    assert.equal(bytesToHex(found1.pubkey), NOTIFY.pubkey);
    const result1 = bip47DecodeNotificationTx(bytesToHex(tx1), priv);
    assert.equal(result1.status, "ok");
    assert.equal(result1.inputIndex, 1);
    assert.equal(result1.kind, "p2wpkh");
    assert.equal(result1.code, ALICE.code);

    const wrongProgram = hexToBytes("00112233445566778899aabbccddeeff00112233");
    const wrongRedeem = Uint8Array.from([0x16, 0x00, 0x14, ...wrongProgram]);
    const badNested = { ...vectorInputBase(), scriptSig: wrongRedeem, witness: [sig, pub] };
    const goodWitness = { ...vectorInputBase(), scriptSig: new Uint8Array(), witness: [sig, pub] };
    const tx2 = serializeTxLocal({ inputs: [badNested, goodWitness], outputs: [opReturnOutput(hexToBytes(NOTIFY.blinded))] });
    const found2 = extractDesignatedPubKey(parseRawTx(tx2));
    assert.equal(found2.inputIndex, 1);
    assert.equal(found2.kind, "p2wpkh");

    const manualInput = { txid: hexToBytes("22".repeat(32)), vout: 0, sequence: 0xffffffff, scriptSig: new Uint8Array(), witness: [] };
    const outpoint0 = new Uint8Array([...manualInput.txid, ...u32le(manualInput.vout)]);
    const x0 = bip47SharedX(aPriv, hexToBytes(BOB.B[0]));
    const mask0 = bip47Mask(x0, outpoint0);
    const blinded0 = xorPayload(hexToBytes(NOTIFY.plain), mask0);
    const tx3 = serializeTxLocal({ inputs: [manualInput], outputs: [opReturnOutput(blinded0)] });
    const found3 = extractDesignatedPubKey(parseRawTx(tx3), pub, 0);
    assert.equal(found3.kind, "manual-unverified");
    assert.equal(found3.inputIndex, 0);
    const result3 = bip47DecodeNotificationTx(bytesToHex(tx3), priv, { designatedPub: pub, designatedInput: 0 });
    assert.equal(result3.kind, "manual-unverified");
    assert.equal(result3.code, ALICE.code);
  } finally {
    aPriv.fill(0);
    priv.fill(0);
  }
});

test("11b. a manual designated key must name its input; the mask uses that input's outpoint", () => {
  const aPriv = wifToPriv(NOTIFY.wif);
  const priv = bobNotifPrivFromMnemonic();
  // The designated key is the public key of the input the sender spends (the
  // vector WIF), not the sender's notification key.
  const aPub = secp256k1.getPublicKey(aPriv, true);
  try {
    const sig = parseRawTx(hexToBytes(NOTIFY.tx)).inputs[0].scriptSig.slice(1, 73);
    const input0 = { txid: hexToBytes("11".repeat(32)), vout: 0, sequence: 0xffffffff, scriptSig: new Uint8Array(), witness: [] };
    const input1 = { txid: hexToBytes("22".repeat(32)), vout: 1, sequence: 0xffffffff, scriptSig: new Uint8Array(), witness: [sig, aPub] };
    const outpoint1 = bip47InputOutpoint(input1);
    const x1 = bip47SharedX(aPriv, hexToBytes(BOB.B[0]));
    const mask1 = bip47Mask(x1, outpoint1);
    const blinded1 = xorPayload(hexToBytes(NOTIFY.plain), mask1);
    const tx = serializeTxLocal({
      inputs: [input0, input1],
      outputs: [
        { amount: 10000n, script: p2pkhScript(hexToBytes(BOB.B[0])) },
        opReturnOutput(blinded1),
      ],
    });
    const txBytes = bytesToHex(tx);
    const parsed = parseRawTx(tx);
    const found = extractDesignatedPubKey(parsed, aPub, 1);
    assert.equal(found.status, "found");
    assert.equal(found.inputIndex, 1);
    assert.equal(found.kind, "manual-unverified");
    const result = bip47DecodeNotificationTx(txBytes, priv, { designatedPub: aPub, designatedInput: 1 });
    assert.equal(result.status, "ok");
    assert.equal(result.code, ALICE.code);
    assert.equal(result.inputIndex, 1);
    const wrong = bip47DecodeNotificationTx(txBytes, priv, { designatedPub: aPub, designatedInput: 0 });
    assert.ok(wrong.status === "undecodable" || wrong.code !== ALICE.code);
    assert.throws(() => bip47DecodeNotificationTx(txBytes, priv, { designatedPub: aPub }), (e) => e instanceof Bip47Error && e.code === "BAD_INDEX");
    assert.throws(() => bip47DecodeNotificationTx(txBytes, priv, { designatedPub: aPub, designatedInput: 2 }), (e) => e instanceof Bip47Error && e.code === "BAD_INDEX");
    const auto = extractDesignatedPubKey(parsed);
    assert.equal(auto.inputIndex, 1);
    assert.equal(auto.kind, "p2wpkh");
    const autoResult = bip47DecodeNotificationTx(txBytes, priv);
    assert.equal(autoResult.status, "ok");
    assert.equal(autoResult.code, ALICE.code);
    assert.equal(autoResult.inputIndex, 1);
  } finally {
    aPriv.fill(0);
    priv.fill(0);
  }
});

test("11c. an uncompressed P2PKH key is accepted and normalised for ECDH; a later compressed key is not selected", () => {
  const aPriv = wifToPriv(NOTIFY.wif);
  const priv = bobNotifPrivFromMnemonic();
  try {
    // The designated input's own key (the vector WIF), uncompressed.
    const uncompressed = secp256k1.getPublicKey(aPriv, false);
    assert.equal(uncompressed.length, 65);
    const sig = parseRawTx(hexToBytes(NOTIFY.tx)).inputs[0].scriptSig.slice(1, 73);
    const scriptSig = Uint8Array.from([sig.length, ...sig, uncompressed.length, ...uncompressed]);
    const input0 = { txid: hexToBytes("33".repeat(32)), vout: 0, sequence: 0xffffffff, scriptSig, witness: [] };
    const outpoint0 = bip47InputOutpoint(input0);
    const x0 = bip47SharedX(aPriv, hexToBytes(BOB.B[0]));
    const mask0 = bip47Mask(x0, outpoint0);
    const blinded0 = xorPayload(hexToBytes(NOTIFY.plain), mask0);
    const tx = serializeTxLocal({
      inputs: [input0],
      outputs: [
        { amount: 10000n, script: p2pkhScript(hexToBytes(BOB.B[0])) },
        opReturnOutput(blinded0),
      ],
    });
    const parsed = parseRawTx(tx);
    const found = extractDesignatedPubKey(parsed);
    assert.equal(found.status, "found");
    assert.equal(found.kind, "p2pkh");
    assert.equal(found.pubkey.length, 65);
    assert.equal(bytesToHex(found.compressedPubkey), bytesToHex(secp256k1.getPublicKey(aPriv, true)));
    const result = bip47DecodeNotificationTx(bytesToHex(tx), priv);
    assert.equal(result.status, "ok");
    assert.equal(result.code, ALICE.code);
    assert.equal(result.publicKeyHex, bytesToHex(uncompressed));
    const input1 = { txid: hexToBytes("44".repeat(32)), vout: 1, sequence: 0xffffffff, scriptSig: new Uint8Array(), witness: [sig, hexToBytes(ALICE.A0)] };
    const tx2 = serializeTxLocal({
      inputs: [input0, input1],
      outputs: [
        { amount: 10000n, script: p2pkhScript(hexToBytes(BOB.B[0])) },
        opReturnOutput(blinded0),
      ],
    });
    const found2 = extractDesignatedPubKey(parseRawTx(tx2));
    assert.equal(found2.inputIndex, 0);
    assert.equal(found2.kind, "p2pkh");
    assert.equal(found2.pubkey.length, 65);
    const result2 = bip47DecodeNotificationTx(bytesToHex(tx2), priv);
    assert.equal(result2.status, "ok");
    assert.equal(result2.code, ALICE.code);
    assert.equal(result2.inputIndex, 0);
  } finally {
    aPriv.fill(0);
    priv.fill(0);
  }
});

// ── 12. Payload ──────────────────────────────────────────────────────────────

test("12. payload: two OP_RETURNs, one OP_RETURN with two 80-byte pushes, or zero OP_RETURNs are AMBIGUOUS_PAYLOAD", () => {
  const priv = bobNotifPrivFromMnemonic();
  try {
    const input = { ...vectorInputBase(), scriptSig: new Uint8Array(), witness: [] };
    const twoOpReturns = serializeTxLocal({ inputs: [input], outputs: [opReturnOutput(hexToBytes(NOTIFY.plain)), opReturnOutput(hexToBytes(NOTIFY.plain))] });
    assert.throws(() => bip47DecodeNotificationTx(bytesToHex(twoOpReturns), priv), (e) => e instanceof Bip47Error && e.code === "AMBIGUOUS_PAYLOAD");
    const twoPushes = Uint8Array.from([0x6a, 0x4c, 0x50, ...hexToBytes(NOTIFY.plain), 0x4c, 0x50, ...hexToBytes(NOTIFY.plain)]);
    const oneWithTwo = serializeTxLocal({ inputs: [input], outputs: [{ amount: 0n, script: twoPushes }] });
    assert.throws(() => bip47DecodeNotificationTx(bytesToHex(oneWithTwo), priv), (e) => e instanceof Bip47Error && e.code === "AMBIGUOUS_PAYLOAD");
    const zeroOpReturns = serializeTxLocal({ inputs: [input], outputs: [{ amount: 1n, script: p2pkhScript(hexToBytes(BOB.B[0])) }] });
    assert.throws(() => bip47DecodeNotificationTx(bytesToHex(zeroOpReturns), priv), (e) => e instanceof Bip47Error && e.code === "AMBIGUOUS_PAYLOAD");
  } finally {
    priv.fill(0);
  }
});

test("12b. payload: the OP_RETURN holds exactly one 80-byte push and nothing else", () => {
  const plain = hexToBytes(NOTIFY.plain);
  const input = { ...vectorInputBase(), scriptSig: new Uint8Array(), witness: [] };
  const payloadOf = (script) => bip47Module.bip47NotificationPayload(parseRawTx(serializeTxLocal({ inputs: [input], outputs: [{ amount: 0n, script }] })));
  const ambiguous = (e) => e instanceof Bip47Error && e.code === "AMBIGUOUS_PAYLOAD";
  assert.deepEqual(payloadOf(Uint8Array.from([0x6a, 0x4c, 0x50, ...plain])), plain, "OP_PUSHDATA1 80 bytes");
  assert.deepEqual(payloadOf(Uint8Array.from([0x6a, 0x4d, 0x50, 0x00, ...plain])), plain, "OP_PUSHDATA2 80 bytes");
  assert.throws(() => payloadOf(Uint8Array.from([0x6a, 0x4c, 0x50, ...plain, 0x01, 0xff])), ambiguous, "an extra short push after the payload");
  assert.throws(() => payloadOf(Uint8Array.from([0x6a, 0x51, 0x4c, 0x50, ...plain])), ambiguous, "a stray opcode before the payload");
  assert.throws(() => payloadOf(Uint8Array.from([0x6a, 0x4c, 0x50, ...plain, 0x51])), ambiguous, "a stray opcode after the payload");
  assert.throws(() => payloadOf(Uint8Array.from([0x6a, 0x4c, 0x51, ...plain])), ambiguous, "a push longer than the bytes left");
  assert.throws(() => payloadOf(Uint8Array.from([0x6a, 0x4c, 0x4f, ...plain.slice(0, 79)])), ambiguous, "a 79-byte push");
});

test("12c. a malformed manual designated key is manual-invalid, not a crash", () => {
  const priv = bobNotifPrivFromMnemonic();
  try {
    for (const designatedPub of ["not hex", "02" + "zz".repeat(32), "0".repeat(65), "", "04" + "00".repeat(64)]) {
      const result = bip47DecodeNotificationTx(NOTIFY.tx, priv, { designatedPub, designatedInput: 0 });
      assert.equal(result.status, "manual-invalid", `designatedPub ${JSON.stringify(designatedPub)}`);
      assert.equal(result.inputIndex, null);
    }
  } finally {
    priv.fill(0);
  }
});

// ── 13. Txid display ─────────────────────────────────────────────────────────

test("13. the displayed outpoint txid is the byte-reversed internal hash", () => {
  const priv = bobNotifPrivFromMnemonic();
  try {
    const result = bip47DecodeNotificationTx(NOTIFY.tx, priv);
    const internal = hexToBytes(NOTIFY.outpoint.slice(0, 64));
    const displayed = bytesToHex(internal.slice().reverse());
    assert.equal(result.designatedDisplayTxid, displayed);
    assert.equal(result.designatedDisplayTxid, NOTIFY.outpointDisplay.split(":")[0]);
  } finally {
    priv.fill(0);
  }
});

// ── 14. HMAC and endianness ──────────────────────────────────────────────────

test("14. reversed HMAC argument order and a byte-reversed vout each fail to unblind", () => {
  const x = hexToBytes(NOTIFY.x);
  const outpoint = hexToBytes(NOTIFY.outpoint);
  const mask = bip47Mask(x, outpoint);
  assert.equal(bytesToHex(mask), NOTIFY.mask);
  const wrongMask = hmacSha512(x, outpoint);
  assert.notEqual(bytesToHex(wrongMask), NOTIFY.mask);
  assert.notEqual(bytesToHex(xorPayload(hexToBytes(NOTIFY.blinded), wrongMask)), NOTIFY.plain);
  const reversedVout = outpoint.slice();
  reversedVout.set(outpoint.slice(32, 36).reverse(), 32);
  const wrongVoutMask = bip47Mask(x, reversedVout);
  assert.notEqual(bytesToHex(wrongVoutMask), NOTIFY.mask);
  assert.notEqual(bytesToHex(xorPayload(hexToBytes(NOTIFY.blinded), wrongVoutMask)), NOTIFY.plain);
});

// ── 15. Secret lifecycle ─────────────────────────────────────────────────────

test("15. lifecycle: private and shared buffers are zeroed after a successful row and after a row that throws", () => {
  const captureZeroed = (fn) => {
    const original = Uint8Array.prototype.fill;
    const records = [];
    Uint8Array.prototype.fill = function (value, start, end) {
      if (value === 0) records.push({ buffer: this, before: Uint8Array.from(this) });
      return original.call(this, value, start, end);
    };
    try { fn(); } finally { Uint8Array.prototype.fill = original; }
    return records;
  };
  const a0 = hexToBytes(ALICE.a0);
  const bobDecoded = decodePaymentCode(BOB.code);
  try {
    const successRecords = captureZeroed(() => {
      const row = bip47SendRow(a0, bobDecoded, 0, "mainnet");
      assert.ok(row);
    });
    const xRecord = successRecords.find((r) => bytesToHex(r.before) === SHARED_X[0]);
    assert.ok(xRecord, "shared x was zeroed after a successful row");
    assert.ok(xRecord.buffer.every((b) => b === 0));
    const tweakHex = bytesToHex(sha256(hexToBytes(SHARED_X[0])));
    const tweakRecord = successRecords.find((r) => bytesToHex(r.before) === tweakHex);
    assert.ok(tweakRecord, "tweak was zeroed after a successful row");
    assert.ok(tweakRecord.buffer.every((b) => b === 0));

    const errorRecords = captureZeroed(() => {
      assert.throws(() => bip47SendRow(a0, bobDecoded, 0, "mainnet", { checkTweak: () => { throw new Error("boom"); } }), /boom/);
    });
    const errorXRecord = errorRecords.find((r) => bytesToHex(r.before) === SHARED_X[0]);
    assert.ok(errorXRecord, "shared x was zeroed on the error path");
    assert.ok(errorXRecord.buffer.every((b) => b === 0));

    const bobAccount = bip47AccountNode(bobRootFromMnemonic(), "mainnet");
    const aliceDecoded = decodePaymentCode(ALICE.code);
    let calls = 0;
    const checkTweak = () => { calls += 1; if (calls === 2) throw new Error("boom"); return true; };
    const pairRecords = captureZeroed(() => {
      assert.throws(() => bip47PairRows("receive", { own: bobAccount, code: aliceDecoded, checkTweak }, 0, 3, "mainnet"), /boom/);
    });
    const firstPrivHex = "d687f6b820e6e3d47296b01f3b73ccdc930eded39d559921a7dd8ed81b2c8f82";
    const privRecord = pairRecords.find((r) => bytesToHex(r.before) === firstPrivHex);
    assert.ok(privRecord, "the first row's private key was zeroed when a later row threw");
    assert.ok(privRecord.buffer.every((b) => b === 0));
    bobAccount.wipePrivateData();
  } finally {
    a0.fill(0);
  }
});

// ── 16. Removed exports ──────────────────────────────────────────────────────

test("16. the blinded-payload exports no longer exist", () => {
  assert.equal(bip47Module.bip47BlindNotification, undefined);
  assert.equal(bip47Module.bip47BlindPayload, undefined);
});
