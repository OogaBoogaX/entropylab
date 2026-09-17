// Tests for the BOLT11 invoice decoder (src/js/bolt11.js): the BOLT11
// specification's own valid and invalid example invoices, plus malformed
// input rejection. Run with `npm test`.
import { test } from "node:test";
import assert from "node:assert/strict";
import { bolt11Decode } from "../src/js/bolt11.js";

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
// Same donation invoice with a high-S (malleated) signature: a reader MUST
// still accept it and recover with the encoded recovery id.
const HIGH_S =
  "lnbc1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpl2pkx2ctnv5sxxmmwwd5kgetjypeh2ursdae8g6twvus8g6rfwvs8qun0dfjkxaq9qrsgq357wnc5r2ueh7ck6q93dj32dlqnls087fxdwk8qakdyafkq3yap2r09nt4ndd0unm3z9u5t48y6ucv4r5sg7lk98c77ctvjczkspk5qprc90gx";
// "Please send 0.0025 BTC for a cup of nonsense (ナンセンス 1杯)"
const NONSENSE =
  "lnbc2500u1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpquwpc4curk03c9wlrswe78q4eyqc7d8d0xqzpu9qrsgqhtjpauu9ur7fw2thcl4y9vfvh4m9wlfyz2gem29g5ghe2aak2pm3ps8fdhtceqsaagty2vph7utlgj48u0ged6a337aewvraedendscp573dxr";
// "Please send 0.01 BTC with payment metadata 0x01fafaf0" — the metadata
// lives in tag 'm' (27), unknown and odd, so it is skipped and listed.
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
  assert.deepEqual(d.unknownOddTags, []);
});

test("spec vector: amountless donation invoice", () => {
  const d = bolt11Decode(DONATION);
  assert.equal(d.amountMsat, null);
  assert.equal(d.description, "Please consider supporting this project");
  assert.equal(d.nodeId, SPEC_NODE_ID);
  assert.equal(d.signatureValid, true);
});

test("spec vector: high-S signature is accepted (no low-S rule without an n field)", () => {
  const d = bolt11Decode(HIGH_S);
  assert.equal(d.signatureValid, true);
  assert.equal(d.description, "Please consider supporting this project");
});

test("spec vector: UTF-8 description", () => {
  const d = bolt11Decode(NONSENSE);
  assert.equal(d.description, "ナンセンス 1杯");
  assert.equal(d.nodeId, SPEC_NODE_ID);
});

test("spec vector: unknown odd tag (payment metadata) is skipped and listed", () => {
  const d = bolt11Decode(METADATA);
  assert.equal(d.amountMsat, "1000000000"); // 10m = 0.01 BTC
  assert.deepEqual(d.unknownOddTags, [27]);
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
  "high-S signature with a declared node id":
    "lnbc25m1p70xwfzpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpl2pkx2ctnv5sxxmmwwd5kgetjypeh2ursdae8g6twvus8g6rfwvs8qun0dfjkxaqnp4q0n326hr8v9zprg8gsvezcch06gfaqqhde2aj730yg0durunfhv66sp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygsp5cfzp9ugllvk03rltd6hvndxj26ux6gcxc5azyxk060rj9tzghct5zvjlps76gx8wpq5yuu79688k8gnm2c0al6v608s96l0xzrrlqqwnzxmu",
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

test("rejects: unknown even tag (unknown odd tags are skipped instead)", () => {
  // The metadata invoice carries unknown odd tag 27; flipping it to 26
  // (even) turns a skippable field into a hard failure.
  assert.throws(
    () => bolt11Decode(alterTagType(METADATA, 27, 26)),
    (e) => /unknown required field/.test(e.key)
  );
  // Sanity: the untouched invoice still decodes.
  assert.equal(bolt11Decode(METADATA).signatureValid, true);
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
