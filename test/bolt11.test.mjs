// Tests for the BOLT11 invoice decoder (src/js/bolt11.js): the BOLT11
// specification's own valid and invalid example invoices, plus malformed
// input rejection. Run with `npm test`.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { bolt11Decode } from "../src/js/bolt11.js";
import { secp256k1 } from "../src/js/secp256k1.js";
import { sha256 } from "../src/js/hashes.js";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const specExamples = JSON.parse(readFileSync(join(root, "test/fixtures/bolt11-spec-examples.json"), "utf8"));

// The BOLT11 spec's example invoices are all signed with priv_key
// e126f68f7eafcc8b74f54d269fe206be715000f94dac067d1c04a8ca3b2db734,
// whose node id is:
const SPEC_NODE_ID = "03e7156ae33b0a208d0744199163177e909e80176e55d97a2f221ede0f934dd9ad";
const SPEC_SECRET = "1111111111111111111111111111111111111111111111111111111111111111";
const SPEC_PAYMENT_HASH = "0001020304050607080900010203040506070809000102030405060708090102";

// "Please send $3 for a cup of coffee to the same peer, within one minute"
const COFFEE =
  "lnbc2500u1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq5xysxxatsyp3k7enxv4jsxqzpu9qrsgquk0rl77nj30yxdy8j9vdx85fkpmdla2087ne0xh8nhedh8w27kyke0lp53ut353s06fv3qfegext0eh0ymjpf39tuven09sam30g4vgpfna3rh";
// "Please make a donation of any amount ... to me"
const DONATION =
  "lnbc1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpl2pkx2ctnv5sxxmmwwd5kgetjypeh2ursdae8g6twvus8g6rfwvs8qun0dfjkxaq9qrsgq357wnc5r2ueh7ck6q93dj32dlqnls087fxdwk8qakdyafkq3yap9us6v52vjjsrvywa6rt52cm9r9zqt8r2t7mlcwspyetp5h2tztugp9lfyql";

// "Please send 0.0025 BTC for a cup of nonsense (ナンセンス 1杯)"
const NONSENSE =
  "lnbc2500u1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpquwpc4curk03c9wlrswe78q4eyqc7d8d0xqzpu9qrsgqhtjpauu9ur7fw2thcl4y9vfvh4m9wlfyz2gem29g5ghe2aak2pm3ps8fdhtceqsaagty2vph7utlgj48u0ged6a337aewvraedendscp573dxr";
// "Please send 0.01 BTC with payment metadata 0x01fafaf0" — the metadata
// lives in tag 'm' (27), unknown, so it is skipped and listed.
const METADATA =
  "lnbc10m1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdp9wpshjmt9de6zqmt9w3skgct5vysxjmnnd9jx2mq8q8a04uqsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygs9q2gqqqqqqsgq7hf8he7ecf7n4ffphs6awl9t6676rrclv9ckg3d3ncn7fct63p6s365duk5wrk202cfy3aj5xnnp5gs3vrdvruverwwq7yzhkf5a3xqpd05wjc";

test("spec vector: coffee invoice decodes with recovered node id and valid signature", () => {
  const d = bolt11Decode(COFFEE);
  assert.equal(d.kind, "bolt11");
  assert.equal(d.network, "mainnet");
  assert.equal(d.amountMsat, "250000000"); // 2500u = 0.0025 BTC
  assert.equal(d.timestamp, 1496314658);
  assert.equal(d.paymentHash, SPEC_PAYMENT_HASH);
  assert.equal(d.description, "1 cup coffee");
  assert.equal(d.expiry, 60);
  assert.equal(d.paymentSecret, SPEC_SECRET);
  assert.equal(d.nodeId, SPEC_NODE_ID);
  assert.equal(d.signatureValid, true);
  assert.deepEqual(d.unknownTags, []);
});

test("spec vector: amountless donation invoice", () => {
  const d = bolt11Decode(DONATION);
  assert.equal(d.amountMsat, null);
  assert.equal(d.description, "Please consider supporting this project");
  assert.equal(d.nodeId, SPEC_NODE_ID);
  assert.equal(d.signatureValid, true);
});


test("spec vector: UTF-8 description", () => {
  const d = bolt11Decode(NONSENSE);
  assert.equal(d.description, "ナンセンス 1杯");
  assert.equal(d.nodeId, SPEC_NODE_ID);
});

test("spec vector: unknown tag (payment metadata) is skipped and listed", () => {
  const d = bolt11Decode(METADATA);
  assert.equal(d.amountMsat, "1000000000"); // 10m = 0.01 BTC
  assert.deepEqual(d.unknownTags, [27]);
  assert.equal(d.signatureValid, true);
});

// ── the spec's invalid examples, and other malformed input ─────────────────

const INVALID = {
  "bad checksum":
    "lnbc2500u1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpquwpc4curk03c9wlrswe78q4eyqc7d8d0xqzpuyk0sg5g70me25alkluzd2x62aysf2pyy8edtjeevuv4p2d5p76r4zkmneet7uvyakky2zr4cusd45tftc9c5fh0nnqpnl2jfll544esqchsrnt",
  "no separator":
    "pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpquwpc4curk03c9wlrswe78q4eyqc7d8d0xqzpuyk0sg5g70me25alkluzd2x62aysf2pyy8edtjeevuv4p2d5p76r4zkmneet7uvyakky2zr4cusd45tftc9c5fh0nnqpnl2jfll544esqchsrny",
  "mixed case":
    "LNBC2500u1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpquwpc4curk03c9wlrswe78q4eyqc7d8d0xqzpuyk0sg5g70me25alkluzd2x62aysf2pyy8edtjeevuv4p2d5p76r4zkmneet7uvyakky2zr4cusd45tftc9c5fh0nnqpnl2jfll544esqchsrny",
  "unrecoverable signature":
    "lnbc2500u1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq5xysxxatsyp3k7enxv4jsxqzpusp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygs9qrsgqwgt7mcn5yqw3yx0w94pswkpq6j9uh6xfqqqtsk4tnarugeektd4hg5975x9am52rz4qskukxdmjemg92vvqz8nvmsye63r5ykel43pgz7zq0g2",
  "too short":
    "lnbc1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpl2pkx2ctnv5sxxmmwwd5kgetjypeh2ursdae8g6na6hlh",
  "invalid multiplier":
    "lnbc2500x1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq5xysxxatsyp3k7enxv4jsxqzpusp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygs9qrsgqrrzc4cvfue4zp3hggxp47ag7xnrlr8vgcmkjxk3j5jqethnumgkpqp23z9jclu3v0a7e0aruz366e9wqdykw6dxhdzcjjhldxq0w6wgqcnu43j",
  "sub-millisatoshi precision":
    "lnbc2500000001p1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq5xysxxatsyp3k7enxv4jsxqzpusp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygs9qrsgq0lzc236j96a95uv0m3umg28gclm5lqxtqqwk32uuk4k6673k6n5kfvx3d2h8s295fad45fdhmusm8sjudfhlf6dcsxmfvkeywmjdkxcp99202x",
  "missing payment secret":
    "lnbc20m1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqhp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqs9qrsgq7ea976txfraylvgzuxs8kgcw23ezlrszfnh8r6qtfpr6cxga50aj6txm9rxrydzd06dfeawfk6swupvz4erwnyutnjq7x39ymw6j38gp49qdkj",
};

for (const [name, invoice] of Object.entries(INVALID)) {
  test(`rejects: ${name}`, () => {
    assert.throws(() => bolt11Decode(invoice), (e) => typeof e.key === "string" && e.key.length > 0);
  });
}

test("rejects: non-invoice input", () => {
  for (const junk of [
    "",
    "   ",
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", // BIP39 mnemonic
    "70736274ff0100a5", // PSBT hex
    "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", // segwit address (valid bech32, wrong prefix)
    "lno1zcss9sy7p0gtkzjs9c5w0j8jjzupqwe", // bolt12-shaped garbage
  ]) {
    assert.throws(() => bolt11Decode(junk), (e) => typeof e.key === "string", JSON.stringify(junk));
  }
});

// Minimal bech32 (constant 1) re-checksum helper so a valid invoice can be
// surgically altered: parseTags runs before signature verification, so a
// tag-level edit only needs a fresh checksum, not a fresh signature.
const CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const polymod = (values) => {
  const GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
  let chk = 1;
  for (const v of values) {
    const top = chk >> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ v;
    for (let i = 0; i < 5; i++) if ((top >> i) & 1) chk ^= GEN[i];
  }
  return chk;
};
const hrpExpand = (hrp) => [
  ...[...hrp].map((c) => c.charCodeAt(0) >> 5),
  0,
  ...[...hrp].map((c) => c.charCodeAt(0) & 31),
];
const alterTagType = (invoice, fromType, toType) => {
  const sep = invoice.lastIndexOf("1");
  const hrp = invoice.slice(0, sep);
  const words = [...invoice.slice(sep + 1, -6)].map((c) => CHARSET.indexOf(c));
  let i = 7; // skip timestamp
  while (i < words.length) {
    const length = words[i + 1] * 32 + words[i + 2];
    if (words[i] === fromType) {
      words[i] = toType;
      break;
    }
    i += 3 + length;
  }
  const chk = polymod([...hrpExpand(hrp), ...words, 0, 0, 0, 0, 0, 0]) ^ 1;
  const checksum = [25, 20, 15, 10, 5, 0].map((shift) => (chk >> shift) & 31);
  return hrp + "1" + [...words, ...checksum].map((w) => CHARSET[w]).join("");
};

test("unknown tags are skipped whatever their type number", () => {
  // The spec's "Same, but including fields which must be ignored." example
  // carries an unknown field of type 10 ('2'), which is even: BOLT11 has no
  // even/odd rule (that belongs to BOLT 1 TLVs and BOLT 12), so a reader
  // must skip it and report it, not refuse the invoice.
  const example = specExamples.examples.find((e) => /must be ignored/.test(e.description));
  assert.ok(example, "the spec's 'fields which must be ignored' example must be in the fixture");
  const d = bolt11Decode(example.invoice);
  assert.equal(d.signatureValid, true);
  assert.equal(d.amountMsat, "2500000000"); // 25m = 0.025 BTC
  assert.equal(d.description, "coffee beans");
  assert.deepEqual(d.unknownTags, [10]);
  assert.equal(d.fallbacks.length, 0); // fallback version 19 is unknown: skipped

  // The metadata invoice's unknown tag 27 flipped to 26 (even) must be
  // skipped too. The edit breaks the signature, but with no declared `n`
  // field the reader recovers the node id, so the decode still succeeds and
  // reports the even tag instead of refusing it.
  assert.deepEqual(bolt11Decode(alterTagType(METADATA, 27, 26)).unknownTags, [26]);
});

// A description is untrusted text: invalid UTF-8 must surface as a keyed,
// translatable failure, not a raw TypeError from TextDecoder. The tag is
// replaced with a single 0xC0 byte, whose lone continuation-byte form is
// invalid under `fatal: true`; the signature is then invalidated, but
// parseTags runs first, so the UTF-8 rejection is what the reader reports.
const TAG_DESCRIPTION = 13;

// 8-bit bytes -> 5-bit words, padding to the word boundary exactly as the
// invoice encoding does.
const b2w = (bytes) => {
  const out = [];
  let acc = 0;
  let bits = 0;
  for (const byte of bytes) {
    acc = (acc << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out.push((acc >>> bits) & 31);
    }
  }
  if (bits > 0) out.push((acc << (5 - bits)) & 31);
  return out;
};

const splitWordCount = (n) => [Math.floor(n / 32), n % 32];

const replaceTagPayload = (invoice, tagType, payloadBytes) => {
  const sep = invoice.lastIndexOf("1");
  const hrp = invoice.slice(0, sep);
  const words = [...invoice.slice(sep + 1, -6)].map((c) => CHARSET.indexOf(c));
  const payloadWords = b2w(payloadBytes);
  const out = words.slice(0, 7); // timestamp
  let i = 7;
  while (i < words.length) {
    const length = words[i + 1] * 32 + words[i + 2];
    if (words[i] === tagType) {
      out.push(tagType, ...splitWordCount(payloadWords.length), ...payloadWords);
    } else {
      out.push(...words.slice(i, i + 3 + length));
    }
    i += 3 + length;
  }
  const chk = polymod([...hrpExpand(hrp), ...out, 0, 0, 0, 0, 0, 0]) ^ 1;
  const checksum = [25, 20, 15, 10, 5, 0].map((shift) => (chk >> shift) & 31);
  return hrp + "1" + [...out, ...checksum].map((w) => CHARSET[w]).join("");
};

test("rejects: a description that is not valid UTF-8 (keyed, not a raw TypeError)", () => {
  const invoice = replaceTagPayload(COFFEE, TAG_DESCRIPTION, [0xc0]);
  assert.throws(
    () => bolt11Decode(invoice),
    (e) => {
      assert.equal(e.key, "The {what} field is not valid UTF-8.");
      assert.deepEqual(e.vars, { what: "description" });
      return true;
    }
  );
});

// ── round 2: hrp without a coin, pico amounts, required p, route hints,
//    fallback addresses, integer fields, and the chosen spec examples ──────

// A checksum-valid bech32 (constant 1) string built from an arbitrary hrp
// and data words, so prefix-level failures can be exercised.
const encodeBech32 = (hrp, words) => {
  const chk = polymod([...hrpExpand(hrp), ...words, 0, 0, 0, 0, 0, 0]) ^ 1;
  const checksum = [25, 20, 15, 10, 5, 0].map((shift) => (chk >> shift) & 31);
  return hrp + "1" + [...words, ...checksum].map((w) => CHARSET[w]).join("");
};

test("rejects: an hrp with no coin letters (keyed, not a raw TypeError)", () => {
  for (const hrp of ["ln", "ln2500u"]) {
    let thrown;
    try {
      bolt11Decode(encodeBech32(hrp, [0, 0, 0, 0, 0, 0, 0]));
    } catch (e) {
      thrown = e;
    }
    assert.ok(thrown, `${hrp} must be refused`);
    assert.equal(thrown instanceof TypeError, false, `${hrp} must not throw a raw TypeError`);
    assert.equal(typeof thrown.key, "string", `${hrp} must fail with a key`);
    assert.ok(thrown.key.length > 0, `${hrp} must fail with a non-empty key`);
  }
});

test("rejects: an hrp whose coin is an inherited Object property", () => {
  // "lnconstructor" has a well-formed coin part, but "constructor" is not a
  // network: a plain NETWORKS[coin] lookup finds Object.prototype's
  // constructor and would decode as if it named a network.
  let thrown;
  try {
    bolt11Decode(encodeBech32("lnconstructor", [0, 0, 0, 0, 0, 0, 0]));
  } catch (e) {
    thrown = e;
  }
  assert.ok(thrown, "lnconstructor must be refused");
  assert.equal(typeof thrown.key, "string", "lnconstructor must fail with a key");
  assert.match(thrown.key, /unknown network/);
  assert.deepEqual(thrown.vars, { coin: "constructor" });
});

// "Please send 0.00967878534 BTC for a list of items within one week, amount
// in pico-BTC" — 9678785340 pico-bitcoin is 967878534 msat, not 96787853400.
const PICO =
  "lnbc9678785340p1pwmna7lpp5gc3xfm08u9qy06djf8dfflhugl6p7lgza6dsjxq454gxhj9t7a0sd8dgfkx7cmtwd68yetpd5s9xar0wfjn5gpc8qhrsdfq24f5ggrxdaezqsnvda3kkum5wfjkzmfqf3jkgem9wgsyuctwdus9xgrcyqcjcgpzgfskx6eqf9hzqnteypzxz7fzypfhg6trddjhygrcyqezcgpzfysywmm5ypxxjemgw3hxjmn8yptk7untd9hxwg3q2d6xjcmtv4ezq7pqxgsxzmnyyqcjqmt0wfjjq6t5v4khxsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygsxqyjw5qcqp2rzjq0gxwkzc8w6323m55m4jyxcjwmy7stt9hwkwe2qxmy8zpsgg7jcuwz87fcqqeuqqqyqqqqlgqqqqn3qq9q9qrsgqrvgkpnmps664wgkp43l22qsgdw4ve24aca4nymnxddlnp8vh9v2sdxlu5ywdxefsfvm0fq3sesf08uf6q9a2ke0hc9j6z6wlxg5z5kqpu2v9wz";

test("spec vector: pico-BTC amount is scaled to millisatoshi", () => {
  const d = bolt11Decode(PICO);
  assert.equal(d.amountMsat, "967878534");
  assert.equal(d.signatureValid, true);
  assert.equal(d.nodeId, SPEC_NODE_ID);
  assert.equal(d.expiry, 604800);
  assert.equal(d.minFinalCltvExpiry, 10);
  assert.equal(d.routeHintHops, 1);
});

// "On mainnet, with fallback address 1RustyRX2oai4EYYDpQGWvEL62BBGqN9T with
// extra routing info to go via nodes 029e03a9… then 039e03a9…"
const FALLBACK_P2PKH =
  "lnbc20m1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqhp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqsfpp3qjmp7lwpagxun9pygexvgpjdc4jdj85fr9yq20q82gphp2nflc7jtzrcazrra7wwgzxqc8u7754cdlpfrmccae92qgzqvzq2ps8pqqqqqqpqqqqq9qqqvpeuqafqxu92d8lr6fvg0r5gv0heeeqgcrqlnm6jhphu9y00rrhy4grqszsvpcgpy9qqqqqqgqqqqq7qqzq9qrsgqdfjcdk6w3ak5pca9hwfwfh63zrrz06wwfya0ydlzpgzxkn5xagsqz7x9j4jwe7yj7vaf2k9lqsdk45kts2fd0fkr28am0u4w95tt2nsq76cqw0";

test("spec vector: P2PKH fallback address and two route hops", () => {
  const d = bolt11Decode(FALLBACK_P2PKH);
  assert.equal(d.signatureValid, true);
  assert.equal(d.amountMsat, "2000000000"); // 20m = 0.02 BTC
  assert.equal(d.nodeId, SPEC_NODE_ID);
  assert.equal(d.fallbacks.length, 1);
  assert.equal(d.fallbacks[0].version, 17);
  assert.equal(d.fallbacks[0].kind, "p2pkh");
  assert.equal(d.fallbacks[0].program.length, 40); // 20-byte hash160
  assert.equal(d.routeHintHops, 2);
});

// "On mainnet, with fallback (P2TR) address
// bc1pptdvg0d2nj99568qn6ssdy4cygnwuxgw2ukmnwgwz7jpqjz2kszse2s3lm"
const FALLBACK_P2TR =
  "lnbc20m1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqhp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqsfp4pptdvg0d2nj99568qn6ssdy4cygnwuxgw2ukmnwgwz7jpqjz2kszs9qrsgqy606dznq28exnydt2r4c29y56xjtn3sk4mhgjtl4pg2y4ar3249rq4ajlmj9jy8zvlzw7cr8mggqzm842xfr0v72rswzq9xvr4hknfsqwmn6xd";

test("spec vector: P2TR fallback address is reported, not dropped", () => {
  const d = bolt11Decode(FALLBACK_P2TR);
  assert.equal(d.signatureValid, true);
  assert.equal(d.amountMsat, "2000000000");
  assert.equal(d.nodeId, SPEC_NODE_ID);
  assert.equal(d.fallbacks.length, 1);
  assert.equal(d.fallbacks[0].version, 1);
  assert.equal(d.fallbacks[0].kind, "witness");
  assert.equal(d.fallbacks[0].program.length, 64); // 32-byte witness program
});

// The spec's "Missing required `p` field" example. The key is pinned by a
// short stable substring so the test cannot pass on a later signature
// failure instead of the missing payment hash.
const MISSING_P =
  "lnbc25m1pvjluezdq5vdhkven9v5sxyetpdeessp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygs9q5sqqqqqqqqqqqqqqqqsgqjy08jd52dtj25pefkh0enc54lxtjtr8wnum2msrq2d8uztp9vhhpccq93ljpff0kkjgzkzcp2czlyenjphf6upazjlc8uxw7za0ynusqrfhg8u";

test("rejects: missing required p field", () => {
  assert.throws(
    () => bolt11Decode(MISSING_P),
    (e) => typeof e.key === "string" && /payment hash/.test(e.key)
  );
});

// Same rule, built the way the rest of this file builds edited invoices: the
// p tag is dropped from a valid invoice. parseTags runs before signature
// verification, so the missing-payment-hash failure is what must surface.
const dropTag = (invoice, tagType) => {
  const sep = invoice.lastIndexOf("1");
  const hrp = invoice.slice(0, sep);
  const words = [...invoice.slice(sep + 1, -6)].map((c) => CHARSET.indexOf(c));
  const out = words.slice(0, 7); // timestamp
  let i = 7;
  while (i < words.length) {
    const length = words[i + 1] * 32 + words[i + 2];
    if (words[i] !== tagType) out.push(...words.slice(i, i + 3 + length));
    i += 3 + length;
  }
  const chk = polymod([...hrpExpand(hrp), ...out, 0, 0, 0, 0, 0, 0]) ^ 1;
  const checksum = [25, 20, 15, 10, 5, 0].map((shift) => (chk >> shift) & 31);
  return hrp + "1" + [...out, ...checksum].map((w) => CHARSET[w]).join("");
};

test("rejects: an invoice with its p field removed", () => {
  assert.throws(
    () => bolt11Decode(dropTag(COFFEE, 1)),
    (e) => typeof e.key === "string" && /payment hash/.test(e.key)
  );
});

// The bundled "high-S signature with a declared node id" vector does not
// pass the bech32 checksum (it fails before parseTags), so it can never
// reach the declared-node-id branch. Build that case instead: add an `n`
// field to the coffee invoice. The signature no longer covers the data, so
// the declared-id verification is what must fail, with its own key.
const hexToBytes = (h) => Uint8Array.from(h.match(/../g).map((b) => parseInt(b, 16)));
const addTag = (invoice, tagType, payloadBytes) => {
  const sep = invoice.lastIndexOf("1");
  const hrp = invoice.slice(0, sep);
  const words = [...invoice.slice(sep + 1, -6)].map((c) => CHARSET.indexOf(c));
  const payloadWords = b2w(payloadBytes);
  const out = [
    ...words.slice(0, 7), // timestamp
    tagType,
    ...splitWordCount(payloadWords.length),
    ...payloadWords,
    ...words.slice(7),
  ];
  const chk = polymod([...hrpExpand(hrp), ...out, 0, 0, 0, 0, 0, 0]) ^ 1;
  const checksum = [25, 20, 15, 10, 5, 0].map((shift) => (chk >> shift) & 31);
  return hrp + "1" + [...out, ...checksum].map((w) => CHARSET[w]).join("");
};

test("rejects: a declared node id the signature does not verify against", () => {
  const invoice = addTag(COFFEE, 19, hexToBytes(SPEC_NODE_ID));
  assert.throws(
    () => bolt11Decode(invoice),
    (e) => typeof e.key === "string" && /declared node id/.test(e.key)
  );
});

test("rejects: an integer field longer than 10 words (no float rounding)", () => {
  // 11 bytes of expiry payload is 18 words, past the 50-bit ceiling.
  const invoice = replaceTagPayload(COFFEE, 6, new Array(11).fill(0xff));
  assert.throws(
    () => bolt11Decode(invoice),
    (e) => typeof e.key === "string" && /too large/.test(e.key)
  );
});

// ── round 2d: an empty description is still a description, a non-point
//    declared node id, and the high-S rule with a declared node id ────────

// A fixed test key (0x01 repeated 32 times) and its compressed node id.
const TEST_KEY = hexToBytes("01".repeat(32));
const TEST_NODE_ID_BYTES = secp256k1.getPublicKey(TEST_KEY, true);
const TEST_NODE_ID = [...TEST_NODE_ID_BYTES].map((b) => b.toString(16).padStart(2, "0")).join("");

// 5-bit words -> bytes with the final byte zero-padded, the form the BOLT11
// signature hashes (hrp || timestamp+tags).
const wordsToBytesPadded = (words) => {
  const out = [];
  let acc = 0;
  let bits = 0;
  for (const w of words) {
    acc = (acc << 5) | w;
    bits += 5;
    while (bits >= 8) {
      bits -= 8;
      out.push((acc >> bits) & 0xff);
    }
  }
  if (bits > 0) out.push((acc << (8 - bits)) & 0xff);
  return Uint8Array.from(out);
};

const hrpOf = (invoice) => invoice.slice(0, invoice.lastIndexOf("1"));

const dataWordsOf = (invoice) => {
  const sep = invoice.lastIndexOf("1");
  const words = [...invoice.slice(sep + 1, -6)].map((c) => CHARSET.indexOf(c));
  return words.slice(0, -104); // drop the 65-byte signature
};

const addTagWords = (dataWords, tagType, payloadBytes) => {
  const payloadWords = b2w(payloadBytes);
  return [
    ...dataWords.slice(0, 7), // timestamp
    tagType,
    ...splitWordCount(payloadWords.length),
    ...payloadWords,
    ...dataWords.slice(7),
  ];
};

const replaceTagPayloadWords = (dataWords, tagType, payloadBytes) => {
  const payloadWords = b2w(payloadBytes);
  const out = dataWords.slice(0, 7);
  let i = 7;
  while (i < dataWords.length) {
    const length = dataWords[i + 1] * 32 + dataWords[i + 2];
    if (dataWords[i] === tagType) {
      out.push(tagType, ...splitWordCount(payloadWords.length), ...payloadWords);
    } else {
      out.push(...dataWords.slice(i, i + 3 + length));
    }
    i += 3 + length;
  }
  return out;
};

const recoveryIdFor = (hash, sig, pub) => {
  for (let r = 0; r < 4; r++) {
    const recovered = secp256k1.recover(hash, sig, r);
    if (recovered && recovered.length === pub.length && recovered.every((b, i) => b === pub[i])) return r;
  }
  throw new Error("could not find a recovery id for the test signature");
};

// Sign the BOLT11 message hash (SHA256(hrp || data words as bytes)) with the
// test key and append the 65-byte signature (64-byte compact + recovery id).
const signInvoice = (hrp, dataWords, key, { highS = false } = {}) => {
  const hrpBytes = new TextEncoder().encode(hrp);
  const dataBytes = wordsToBytesPadded(dataWords);
  const message = new Uint8Array(hrpBytes.length + dataBytes.length);
  message.set(hrpBytes, 0);
  message.set(dataBytes, hrpBytes.length);
  const hash = sha256(message);
  const sig = secp256k1.sign(hash, key, { prehash: false });
  let recid = 0;
  if (highS) {
    const ORDER = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
    const s = BigInt("0x" + [...sig.slice(32)].map((b) => b.toString(16).padStart(2, "0")).join(""));
    const high = (ORDER - s).toString(16).padStart(64, "0");
    for (let i = 0; i < 32; i++) sig[32 + i] = parseInt(high.slice(i * 2, i * 2 + 2), 16);
  } else {
    recid = recoveryIdFor(hash, sig, secp256k1.getPublicKey(key, true));
  }
  return encodeBech32(hrp, [...dataWords, ...b2w([...sig, recid])]);
};

test("an empty description is a description: it decodes alone", () => {
  const hrp = hrpOf(COFFEE);
  const dataWords = replaceTagPayloadWords(dataWordsOf(COFFEE), TAG_DESCRIPTION, []);
  const d = bolt11Decode(signInvoice(hrp, dataWords, TEST_KEY));
  assert.equal(d.description, "");
  assert.equal(d.descriptionHash, null);
  assert.equal(d.signatureValid, true);
});

test("rejects: a non-ASCII character that case-folds to bech32 (U+212A KELVIN SIGN)", () => {
  // U+212A survives the all-uppercase test and lowercases to ASCII "k", so
  // the range check must run on the string as pasted (Kimi K3 review).
  const upper = COFFEE.toUpperCase();
  assert.equal(bolt11Decode(upper).signatureValid, true, "the plain uppercase invoice decodes");
  const at = upper.indexOf("K", upper.lastIndexOf("1"));
  assert.ok(at > 0, "the data part has a K to replace");
  const kelvin = upper.slice(0, at) + "K" + upper.slice(at + 1);
  assert.throws(() => bolt11Decode(kelvin), (e) => typeof e.key === "string" && /outside the bech32 range/.test(e.key));
});

test("rejects: an empty description plus a description hash", () => {
  const hrp = hrpOf(COFFEE);
  const withEmptyD = replaceTagPayloadWords(dataWordsOf(COFFEE), TAG_DESCRIPTION, []);
  const dataWords = addTagWords(withEmptyD, 23, new Uint8Array(32));
  assert.throws(
    () => bolt11Decode(signInvoice(hrp, dataWords, TEST_KEY)),
    (e) => typeof e.key === "string" && /both a description and a description hash/.test(e.key)
  );
});

test("rejects: a declared node id that is not a curve point (keyed, not a raw Error)", () => {
  const hrp = hrpOf(COFFEE);
  const nonPoint = new Uint8Array(33);
  nonPoint[0] = 0x02;
  nonPoint.fill(0xff, 1);
  const dataWords = addTagWords(dataWordsOf(COFFEE), 19, nonPoint);
  let thrown;
  try {
    bolt11Decode(signInvoice(hrp, dataWords, TEST_KEY));
  } catch (e) {
    thrown = e;
  }
  assert.ok(thrown, "a non-point node id must be refused");
  assert.equal(thrown instanceof Error, false, "must not throw a raw Error");
  assert.equal(typeof thrown.key, "string");
  assert.match(thrown.key, /declared node id/);
});

test("a declared node id accepts a low-S signature and rejects its high-S twin", () => {
  const hrp = hrpOf(COFFEE);
  const dataWords = addTagWords(dataWordsOf(COFFEE), 19, TEST_NODE_ID_BYTES);

  const good = bolt11Decode(signInvoice(hrp, dataWords, TEST_KEY));
  assert.equal(good.signatureValid, true);
  assert.equal(good.nodeId, TEST_NODE_ID);

  assert.throws(
    () => bolt11Decode(signInvoice(hrp, dataWords, TEST_KEY, { highS: true })),
    (e) => typeof e.key === "string" && /declared node id/.test(e.key)
  );
});

// ── the BOLT 11 specification's own example sweep ─────────────────────────
// Every example from the spec's test vectors, valid and invalid, driven by
// the fixture so a new spec example is a data change, not a code change.

for (const example of specExamples.examples) {
  test(`BOLT 11 example: ${example.description}`, () => {
    if (example.valid) {
      assert.equal(bolt11Decode(example.invoice).signatureValid, true);
    } else {
      assert.throws(() => bolt11Decode(example.invoice), (e) => typeof e.key === "string");
    }
  });
}
