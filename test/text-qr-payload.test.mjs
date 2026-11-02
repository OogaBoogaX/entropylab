import test from "node:test";
import assert from "node:assert/strict";
import {
  TEXT_SCAN_MAX_CHARS,
  classifyLightningText,
  classifySpText,
  classifyPaymentCodeText,
  classifyDescriptorText,
  classifyXpubText,
  classifyText,
  appendRecipient,
  createTextQrReader,
} from "../src/js/text-qr-payload.js";
import { hodlCborBstr, hodlUrEncodeMessage, watchOnlyQrPlan } from "../src/js/psbt-ur.js";

const BOLT11 = "lnbc1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpl2pkx2ctnv5sxxmmwwd5kgetjypeh2ursdae8g6twvus8g6rfwvs8qun0dfjkxaq9qrsgq357wnc5r2ueh7ck6q93dj32dlqnls087fxdwk8qakdyafkq3yap9us6v52vjjsrvywa6rt52cm9r9zqt8r2t7mlcwspyetp5h2tztugp9lfyql";
const OFFER = "lno1pqps7sjqpgtyzm3qv4uxzmtsd3jjqer9wd3hy6tsw35k7msjzfpy7nz5yqcnygrfdej82um5wf5k2uckyypwa3eyt44h6txtxquqh7lz5djge4afgfjn7k4rgrkuag0jsd5xvxg";
const SP = "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv";
const SP2 = "sp1qqgrz6j0lcqnc04vxccydl0kpsj4frfje0ktmgcl2t346hkw30226xqupawdf48k8882j0strrvcmgg2kdawz53a54dd376ngdhak364hzcmynqtn";
const ADDRESS = "175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W";
const ALICE = "PM8TJTLJbPRGxSbc8EJi42Wrr6QbNSaSSVJ5Y3E4pbCYiTHUskHg13935Ubb7q8tx9GVbh2UuRnBc3WSyJHhUrw8KhprKnn9eDznYGieTzFcwQRya4GA";
const BOB = "PM8TJS2JxQ5ztXUpBBRnpTbcUXbUHy2T1abfrb3KkAAtMEGNbey4oumH7Hc578WgQJhPjBxteQ5GHHToTYHE3A1w6p7tU6KSoFmWBVbFGjKPisZDbP97";
const XPUB = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";
const XPRV = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";
const WIF = "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn";
const PHRASE = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const SPANISH = "ábaco ábaco ábaco ábaco ábaco ábaco ábaco ábaco ábaco ábaco ábaco abierto";
const JAPANESE = "あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あおぞら";
const TPUB = "tpubDCHZAX9rt6AMCqXFKo8DTQj3moR5fEozbLupqHq6GrA9s44DdnPSpuNv3fZPR8nAK7mGQFpdGSSF1Ky6Rqjb29JYzaDU998qiv99SWG1pAM";
const PUB = `pkh([420c9ea3/44h/1h/0h]${TPUB}/0/*)#789zdhaw`;
const SH = "sh(wpkh([420c9ea3/49h/1h/0h]tpubDDTTbFgNrTB1UiUHbejR8qpxwxtvwyK4xndVC96RTCfp8jxUT2af1j5QkrTECzV65YRSs5MG3nLu6VvbebxFhaaagieAwTeSmAoMpdjvRUX/0/*))#m7wuf0tf";
const PRIV = "pkh([420c9ea3/44h/1h/0h]tprv8fbX277cjiUgKNVTS9Td414wCmu9Vud623K3YmnnraMm2ZoT1PZreQm3sYtEsmzaz5KifqfkKEm2Q5e7e4wPpWYsbmEKXNzksR8RiJkmM8U/0/*)#jwsdcell";
const NUMS = "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0";
const utf8 = (text) => new TextEncoder().encode(text);

const assertRefused = (result, status) => {
  assert.deepEqual(result, { status });
  assert.equal(Object.hasOwn(result, "text"), false);
};

test("lightning text keeps a BOLT11 invoice and a BOLT12 offer", () => {
  assert.deepEqual(classifyLightningText(BOLT11), { status: "ok", text: BOLT11 });
  assert.deepEqual(classifyLightningText(OFFER), { status: "ok", text: OFFER });
  const upper = BOLT11.toUpperCase();
  assert.deepEqual(classifyLightningText("LIGHTNING:" + upper), { status: "ok", text: upper });
  assert.deepEqual(classifyLightningText(`bitcoin:${ADDRESS}?amount=0.001&lightning=${BOLT11}`), { status: "ok", text: BOLT11 });
  assert.deepEqual(classifyLightningText(`BITCOIN:${ADDRESS}?amount=0.001&LIGHTNING=${BOLT11}`), { status: "ok", text: BOLT11 });
  assert.deepEqual(classifyLightningText(`bitcoin:?lno=${OFFER}`), { status: "ok", text: OFFER });
  assert.deepEqual(classifyLightningText(`bitcoin:?lightning=${BOLT11}`), { status: "ok", text: BOLT11 });
  for (const bad of [SP, `bitcoin:${ADDRESS}`, "lnurl1dp68gurn8ghj7um9wfmx", "you@example.com", BOLT11.slice(0, 20) + " " + BOLT11.slice(20), `bitcoin:?lightning=${BOLT11}&req-somethingnew=1`]) {
    assertRefused(classifyLightningText(bad), "wrong-kind");
  }
  assertRefused(classifyLightningText("lnbc" + "q".repeat(TEXT_SCAN_MAX_CHARS)), "too-large");
});

test("a scanned secret is refused for lightning, recipients and payment codes", () => {
  for (const classify of [classifyLightningText, classifySpText, classifyPaymentCodeText]) {
    for (const secret of [WIF, XPRV, PHRASE, SPANISH, JAPANESE]) assertRefused(classify(secret), "private-key");
  }
});

test("silent-payment text accepts an address or a BIP-321 URI", () => {
  assert.deepEqual(classifySpText(SP), { status: "ok", text: SP });
  const uri = `bitcoin:?sp=${SP}`;
  assert.deepEqual(classifySpText(uri), { status: "ok", text: uri });
  const upper = `BITCOIN:?SP=${SP.toUpperCase()}`;
  assert.deepEqual(classifySpText(upper), { status: "ok", text: upper });
  const mixed = SP.slice(0, 4) + SP.slice(4, 5).toUpperCase() + SP.slice(5);
  for (const bad of [`${SP} 2`, BOLT11, mixed, `bitcoin:?req-pop=x&sp=${SP}`, "you@example.com"]) {
    assertRefused(classifySpText(bad), "wrong-kind");
  }
});

test("appendRecipient adds one line and refuses the same address", () => {
  assert.deepEqual(appendRecipient("", SP), { status: "ok", value: SP });
  assert.deepEqual(appendRecipient(`${SP2}\n\n`, SP), { status: "ok", value: `${SP2}\n${SP}` });
  assert.deepEqual(appendRecipient(`bitcoin:?sp=${SP}`, SP), { status: "already-listed" });
  assert.deepEqual(appendRecipient(SP.toUpperCase(), SP), { status: "already-listed" });
  assert.deepEqual(appendRecipient(`${SP} 2`, SP), { status: "already-listed" });
});

test("payment codes accept Alice and Bob and refuse a bad code", () => {
  assert.deepEqual(classifyPaymentCodeText(ALICE), { status: "ok", text: ALICE });
  assert.deepEqual(classifyPaymentCodeText(BOB), { status: "ok", text: BOB });
  assertRefused(classifyPaymentCodeText(ALICE.slice(0, -1) + "B"), "wrong-kind");
  assertRefused(classifyPaymentCodeText(XPUB), "wrong-kind");
  assertRefused(classifyPaymentCodeText(ALICE.slice(0, 10) + " " + ALICE.slice(10)), "wrong-kind");
});

test("descriptor text accepts public descriptors and refuses a key", () => {
  const multi = `wsh(sortedmulti(2,[d34db33f/48h/0h/0h/2h]${XPUB}/0/*,[d34db33f/48h/0h/1h/2h]${XPUB}/0/*))`;
  const tr = `tr(${NUMS},sortedmulti_a(1,${XPUB}/0/*,${XPUB}/1/*))`;
  for (const text of [PUB, SH, multi, tr]) assert.deepEqual(classifyDescriptorText(text), { status: "ok", text });
  for (const secret of [PRIV, `wpkh(${WIF})`, `tr(${"11".repeat(32)})`]) assertRefused(classifyDescriptorText(secret), "private-key");
  for (const bad of [XPUB, `wsh(sortedmulti(2,${XPUB}/0/*)`, `${PUB}\n${SH}`, "cHNidP8BAA=="]) {
    assertRefused(classifyDescriptorText(bad), "wrong-kind");
  }
});

test("xpub text accepts one public key and refuses a private key or a second key", () => {
  const origin = `[d34db33f/48h/0h/0h/2h]${XPUB}`;
  const hardened = `[d34db33f/48'/0'/0'/2']${XPUB}`;
  for (const text of [XPUB, origin, `${origin}/0/*`, `[420c9ea3/44h/1h/0h]${TPUB}`, hardened, `${origin}/<0;1>/*`]) {
    assert.deepEqual(classifyXpubText(text), { status: "ok", text });
  }
  assertRefused(classifyXpubText(XPRV), "private-key");
  assertRefused(classifyXpubText(WIF), "private-key");
  const broken = `${XPUB.slice(0, -1)}9`;
  for (const bad of [`multi(1,${XPUB},${XPUB})`, `{"xpub":"${XPUB}"}`, ALICE, ADDRESS, `wpkh([d34db33f/84h/0h/0h]${XPUB}/0/*)`, broken]) {
    assertRefused(classifyXpubText(bad), "wrong-kind");
  }
});

test("the reader completes one descriptor and then stays done", () => {
  assert.throws(() => classifyText("nope", PUB));
  assert.throws(() => createTextQrReader({ accept: "nope" }));
  const reader = createTextQrReader({ accept: "descriptor" });
  assert.deepEqual(reader.receive(PUB), { status: "complete", text: PUB });
  assert.deepEqual(reader.receive("more"), { status: "done" });
  assert.equal(reader.progress(), null);
});

test("a ur:bytes payload round-trips the descriptor and refuses everything else", () => {
  const one = hodlUrEncodeMessage("bytes", hodlCborBstr(utf8(PUB)));
  assert.equal(one.length, 1);
  const single = createTextQrReader({ accept: "descriptor" });
  assert.deepEqual(single.receive(one[0]), { status: "complete", text: PUB });

  const keys = Array.from({ length: 9 }, (_, i) => `[d34db33f/48h/0h/${i}h/2h]${XPUB}/<0;1>/*`);
  const longText = `wsh(sortedmulti(2,${keys.join(",")}))`;
  assert.ok(longText.length > 1000);
  const plan = watchOnlyQrPlan(longText);
  assert.equal(plan.mode, "ur");
  const animated = createTextQrReader({ accept: "descriptor" });
  for (let i = 0; i < plan.parts.length - 1; i++) {
    assert.equal(animated.receive(plan.parts[i]).status, "partial");
    assert.deepEqual(animated.progress(), { received: i + 1, total: plan.parts.length });
  }
  assert.deepEqual(animated.receive(plan.parts[plan.parts.length - 1]), { status: "complete", text: longText });

  const secretParts = hodlUrEncodeMessage("bytes", hodlCborBstr(utf8(PRIV)));
  const secret = createTextQrReader({ accept: "descriptor" });
  assertRefused(secret.receive(secretParts[0]), "private-key");

  const tagged = createTextQrReader({ accept: "descriptor" });
  const bad = hodlUrEncodeMessage("bytes", Uint8Array.of(0xd9, 0x01, 0x36));
  assertRefused(tagged.receive(bad[0]), "bad-cbor");

  const foreign = createTextQrReader({ accept: "descriptor" });
  const output = hodlUrEncodeMessage("crypto-output", Uint8Array.of(1, 2, 3));
  assertRefused(foreign.receive(output[0]), "unsupported-format");
  assertRefused(createTextQrReader({ accept: "lightning" }).receive(one[0]), "unsupported-format");
  assertRefused(createTextQrReader({ accept: "descriptor" }).receive("B$2U0100"), "unsupported-format");

  const partsA = hodlUrEncodeMessage("bytes", hodlCborBstr(utf8(PUB)), { maxBytes: 40 });
  const partsB = hodlUrEncodeMessage("bytes", hodlCborBstr(utf8(SH)), { maxBytes: 40 });
  const mixed = createTextQrReader({ accept: "descriptor" });
  assert.equal(mixed.receive(partsA[0]).status, "partial");
  assertRefused(mixed.receive(partsB[0]), "mismatch");
});
