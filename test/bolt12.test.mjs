// Tests for the BOLT12 (offers) decoder (src/js/bolt12.js): the checksum-free
// bech32 envelope (case, `+` continuations, HRP allowlist), TLV stream rules
// (truncation, duplicates, ordering, unknown even/odd types), and field
// decoding for offers, invoice requests, and invoices. Run with `npm test`.
//
// The lno strings are quoted verbatim from the BOLT12 spec's own vectors
// (lightning/bolts, bolt12/format-string-test.json and offers-test.json) —
// raw bech32 with no checksum, exactly as real implementations emit them.
// The spec publishes no lnr/lni strings, so those are built with a local
// checksum-free encoder (toWords + the bech32 charset).
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { toWords } from "../src/js/bech32.js";
import { hex } from "../src/js/coders.js";
import { secp256k1Ready } from "../src/js/secp256k1.js";
import { bolt12Decode, bolt12PathCount, bolt12RecipientVisibility } from "../src/js/bolt12.js";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
await secp256k1Ready;

// Official BOLT 12 test vectors: lightning/bolts bolt12/, commit 191462825ae3, CC-BY 4.0.
const offerVectors = JSON.parse(readFileSync(join(root, "test/fixtures/bolt12-offers-test.json"), "utf8"));
const formatVectors = JSON.parse(readFileSync(join(root, "test/fixtures/bolt12-format-string-test.json"), "utf8"));

// The format-string fixture names the string differently from the offers
// fixture; take the first value that looks like a BOLT12 string.
const bolt12Of = (vector) => {
  const values = Object.values(vector);
  const string = values.find((value) => typeof value === "string" && /^ln[ori]1/i.test(value.replace(/[+\s]/g, "")));
  if (string !== undefined) return string;
  const parts = values.find((value) => Array.isArray(value) && value.every((part) => typeof part === "string"));
  return parts && parts.join("");
};

for (const vector of [...offerVectors, ...formatVectors]) {
  test(`BOLT 12 vector: ${vector.description ?? vector.name ?? "(unnamed)"}`, () => {
    const text = bolt12Of(vector);
    if (vector.valid) {
      assert.doesNotThrow(() => bolt12Decode(text));
    } else {
      assert.throws(() => bolt12Decode(text), (error) => typeof error.key === "string");
    }
  });
}

// ── spec strings (verbatim) ─────────────────────────────────────────────────

// bolt12/format-string-test.json: the canonical example offer.
const SPEC_OFFER = "lno1pqps7sjqpgtyzm3qv4uxzmtsd3jjqer9wd3hy6tsw35k7msjzfpy7nz5yqcnygrfdej82um5wf5k2uckyypwa3eyt44h6txtxquqh7lz5djge4afgfjn7k4rgrkuag0jsd5xvxg";
const SPEC_OFFER_UPPER = "LNO1PQPS7SJQPGTYZM3QV4UXZMTSD3JJQER9WD3HY6TSW35K7MSJZFPY7NZ5YQCNYGRFDEJ82UM5WF5K2UCKYYPWA3EYT44H6TXTXQUQH7LZ5DJGE4AFGFJN7K4RGRKUAG0JSD5XVXG";
const SPEC_OFFER_MIXED = "LnO1PqPs7sJqPgTyZm3qV4UxZmTsD3JjQeR9Wd3hY6TsW35k7mSjZfPy7nZ5YqCnYgRfDeJ82uM5Wf5k2uCkYyPwA3EyT44h6tXtXqUqH7Lz5dJgE4AfGfJn7k4rGrKuAg0jSd5xVxG";

// bolt12/offers-test.json.
const OFFER_MINIMAL = "lno1zcss9mk8y3wkklfvevcrszlmu23kfrxh49px20665dqwmn4p72pksese";
const OFFER_DESCRIPTION = "lno1pgx9getnwss8vetrw3hhyuckyypwa3eyt44h6txtxquqh7lz5djge4afgfjn7k4rgrkuag0jsd5xvxg";
const OFFER_AMOUNT = "lno1pqpzwyq2p32x2um5ypmx2cm5dae8x93pqthvwfzadd7jejes8q9lhc4rvjxd022zv5l44g6qah82ru5rdpnpj";
const OFFER_CURRENCY = "lno1qcp4256ypqpzwyq2p32x2um5ypmx2cm5dae8x93pqthvwfzadd7jejes8q9lhc4rvjxd022zv5l44g6qah82ru5rdpnpj";
const OFFER_TESTNET = "lno1qgsyxjtl6luzd9t3pr62xr7eemp6awnejusgf6gw45q75vcfqqqqqqq2p32x2um5ypmx2cm5dae8x93pqthvwfzadd7jejes8q9lhc4rvjxd022zv5l44g6qah82ru5rdpnpj";
const OFFER_EXPIRY = "lno1pgx9getnwss8vetrw3hhyucwq3ay997czcss9mk8y3wkklfvevcrszlmu23kfrxh49px20665dqwmn4p72pksese";
const OFFER_ISSUER = "lno1pgx9getnwss8vetrw3hhyucjy358garswvaz7tmzdak8gvfj9ehhyeeqgf85c4p3xgsxjmnyw4ehgunfv4e3vggzamrjghtt05kvkvpcp0a79gmy3nt6jsn98ad2xs8de6sl9qmgvcvs";
const OFFER_QUANTITY = "lno1pgx9getnwss8vetrw3hhyuc5qyz3vggzamrjghtt05kvkvpcp0a79gmy3nt6jsn98ad2xs8de6sl9qmgvcvs";
const OFFER_FEATURES = "lno1pgx9getnwss8vetrw3hhyucvp5yqqqqqqqqqqqqqqqqqqqqkyypwa3eyt44h6txtxquqh7lz5djge4afgfjn7k4rgrkuag0jsd5xvxg";
const OFFER_ONE_PATH = "lno1pgx9getnwss8vetrw3hhyucs5ypjgef743p5fzqq9nqxh0ah7y87rzv3ud0eleps9kl2d5348hq2k8qzqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgqpqqqqqqqqqqqqqqqqqqqqqqqqqqqzqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqqzq3zyg3zyg3zyg3vggzamrjghtt05kvkvpcp0a79gmy3nt6jsn98ad2xs8de6sl9qmgvcvs";
const OFFER_TWO_PATHS = "lno1pgx9getnwss8vetrw3hhyucsl5qj5qeyv5l2cs6y3qqzesrth7mlzrlp3xg7xhulusczm04x6g6nms9trspqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqqsqqqqqqqqqqqqqqqqqqqqqqqqqqpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqsqpqg3zyg3zyg3zygpqqqqzqqqqgqqxqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqqgqqqqqqqqqqqqqqqqqqqqqqqqqqqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgqqsg3zyg3zyg3zygtzzqhwcuj966ma9n9nqwqtl032xeyv6755yeflt235pmww58egx6rxry";
const OFFER_UNKNOWN_ODD = "lno1pgx9getnwss8vetrw3hhyuckyypwa3eyt44h6txtxquqh7lz5djge4afgfjn7k4rgrkuag0jsd5xvxfppf5x2mrvdamk7unvvs";
const OFFER_UNKNOWN_ODD_EXPERIMENTAL = "lno1pgx9getnwss8vetrw3hhyuckyypwa3eyt44h6txtxquqh7lz5djge4afgfjn7k4rgrkuag0jsd5xvx078wdv5gg2dpjkcmr0wahhymry";
const OFFER_UNKNOWN_EVEN = "lno1pgz5znzfgdz3vggzqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpysgr0u2xq4dh3kdevrf4zg6hx8a60jv0gxe0ptgyfc6xkryqqqqqqqq";
const OFFER_OUT_OF_ORDER = "lno1zcssyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszpgz5znzfgdzs";
const OFFER_BAD_UTF8 = "lno1pgpgqsgkyypqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqs";
const OFFER_BAD_PADDING = "lno1zcss9mk8y3wkklfvevcrszlmu23kfrxh49px20665dqwmn4p72pkseseq";

const PUBKEY = "02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619";
const TESTNET_CHAIN = "43497fd7f826957108f4a30fd9cec3aeba79972084e90ead01ea330900000000";
const FEATURES_BIT_99 = "08000000000000000000000000";

// ── checksum-free encoder for synthetic lnr/lni/error vectors ───────────────

const BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

const bigsize = (n) => {
  if (typeof n === "bigint") {
    if (n < 0xfdn) return [Number(n)];
    if (n <= 0xffffn) return [0xfd, Number(n >> 8n), Number(n & 0xffn)];
    if (n <= 0xffffffffn) return [0xfe, Number(n >> 24n), Number((n >> 16n) & 0xffn), Number((n >> 8n) & 0xffn), Number(n & 0xffn)];
    const out = [0xff];
    for (let shift = 56n; shift >= 0n; shift -= 8n) out.push(Number((n >> shift) & 0xffn));
    return out;
  }
  if (n < 0xfd) return [n];
  if (n <= 0xffff) return [0xfd, (n >> 8) & 0xff, n & 0xff];
  return [0xfe, (n >>> 24) & 0xff, (n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff];
};

const tlvBytes = (fields) => {
  const out = [];
  for (const [type, valueHex] of fields) {
    const value = hex.decode(valueHex);
    out.push(...bigsize(type), ...bigsize(value.length), ...value);
  }
  return new Uint8Array(out);
};

const encode = (hrp, fields) => hrp + "1" + toWords(tlvBytes(fields)).map((w) => BECH32_CHARSET[w]).join("");

const assertKey = (fn, key) =>
  assert.throws(fn, (error) => {
    assert.equal(error.key, key, `expected key ${JSON.stringify(key)}, got ${JSON.stringify(error.key ?? error.message)}`);
    return true;
  });

// New failures are keyed, but their wording is not pinned.
const assertKeyed = (fn) =>
  assert.throws(fn, (error) => {
    assert.equal(typeof error.key, "string");
    return true;
  });

// ── offers (lno): the spec's own strings decode directly ────────────────────

test("decodes the spec's canonical example offer", () => {
  const result = bolt12Decode(SPEC_OFFER);
  assert.equal(result.kind, "bolt12");
  assert.equal(result.hrp, "lno");
  assert.equal(result.fields.amount, "1000000");
  assert.equal(result.fields.description, "An example description");
  assert.equal(result.fields.issuer, "BOLT 12 industries");
  assert.equal(result.fields.issuerId, PUBKEY);
  assert.deepEqual(result.unknownOddTypes, []);
  assert.equal(result.signaturePresent, false);
});

test("decodes the spec's minimal offer (issuer id only)", () => {
  const result = bolt12Decode(OFFER_MINIMAL);
  assert.deepEqual(result.fields, { issuerId: PUBKEY });
});

test("decodes the spec's offer with amount, description, and node id", () => {
  const result = bolt12Decode(OFFER_AMOUNT);
  assert.equal(result.fields.amount, "10000");
  assert.equal(result.fields.description, "Test vectors");
  assert.equal(result.fields.issuerId, PUBKEY);
});

test("decodes currency, chains, expiry, issuer, quantity, and features", () => {
  assert.equal(bolt12Decode(OFFER_CURRENCY).fields.currency, "USD");
  assert.deepEqual(bolt12Decode(OFFER_TESTNET).fields.chains, [TESTNET_CHAIN]);
  assert.equal(bolt12Decode(OFFER_EXPIRY).fields.absoluteExpiry, (0x7a4297d8).toString(), "2035-01-01 per the spec vector");
  assert.equal(bolt12Decode(OFFER_ISSUER).fields.issuer, "https://bolt12.org BOLT12 industries");
  assert.equal(bolt12Decode(OFFER_QUANTITY).fields.quantityMax, "5");
  assert.equal(bolt12Decode(OFFER_FEATURES).fields.features, FEATURES_BIT_99);
});

test("counts blinded paths and measures them without following them", () => {
  assert.deepEqual(bolt12Decode(OFFER_ONE_PATH).fields.paths, { count: 1, totalBytes: 161 });
  assert.deepEqual(bolt12Decode(OFFER_TWO_PATHS).fields.paths, { count: 2, totalBytes: 298 });
});

test("recipient visibility: issuer id is a signing key, not a destination", () => {
  const published = bolt12Decode(OFFER_MINIMAL);
  assert.equal(bolt12PathCount(published.fields), 0);
  assert.deepEqual(bolt12RecipientVisibility(published.fields), { kind: "published", pathCount: 0 });
  const blinded = bolt12Decode(OFFER_ONE_PATH);
  assert.equal(bolt12PathCount(blinded.fields), 1);
  assert.deepEqual(bolt12RecipientVisibility(blinded.fields), { kind: "blinded", pathCount: 1 });
  assert.deepEqual(bolt12RecipientVisibility({}), { kind: "none", pathCount: 0 });
});

test("collects unknown odd types and decodes around them", () => {
  const odd = bolt12Decode(OFFER_UNKNOWN_ODD);
  assert.deepEqual(odd.unknownOddTypes, ["33"]);
  assert.equal(odd.fields.description, "Test vectors");
  assert.deepEqual(bolt12Decode(OFFER_UNKNOWN_ODD_EXPERIMENTAL).unknownOddTypes, ["1000000033"]);
});

test("accepts an all-uppercase string", () => {
  assert.deepEqual(bolt12Decode(SPEC_OFFER_UPPER), bolt12Decode(SPEC_OFFER));
});

test("accepts `+` continuations, with or without whitespace, anywhere", () => {
  const expected = bolt12Decode(SPEC_OFFER);
  // bolt12/format-string-test.json's valid splitting vectors.
  const inHrp = "l+no1pqps7sjqpgtyzm3qv4uxzmtsd3jjqer9wd3hy6tsw35k7msjzfpy7nz5yqcnygrfdej82um5wf5k2uckyypwa3eyt44h6txtxquqh7lz5djge4afgfjn7k4rgrkuag0jsd5xvxg";
  const multi = "lno1pqps7sjqpgt+yzm3qv4uxzmtsd3jjqer9wd3hy6tsw3+5k7msjzfpy7nz5yqcn+ygrfdej82um5wf5k2uckyypwa3eyt44h6txtxquqh7lz5djge4afgfjn7k4rgrkuag0jsd+5xvxg";
  const whitespace = "lno1pqps7sjqpgt+ yzm3qv4uxzmtsd3jjqer9wd3hy6tsw3+  5k7msjzfpy7nz5yqcn+\nygrfdej82um5wf5k2uckyypwa3eyt44h6txtxquqh7lz5djge4afgfjn7k4rgrkuag0jsd+\r\n 5xvxg";
  for (const split of [inHrp, multi, whitespace]) assert.deepEqual(bolt12Decode(split), expected);
});

// ── invoice requests (lnr) and invoices (lni) ───────────────────────────────

const SIGNATURE = "ab".repeat(64); // bip340sig slot: presence only, never verified
const PAYMENT_HASH = "11".repeat(32);
const PAYINFO = "000003e8" + "0000000a" + "0022" + "0000000000000001" + "00000000000f4240" + "0000";
const PATH_ONE = "0324653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1c0202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020200100000000000000000000000000000000002020202020202020202020202020202020202020202020202020202020202020200081111111111111111";

test("decodes an invoice request with the mirrored offer fields", () => {
  const result = bolt12Decode(encode("lnr", [
    [0, "0102030405"],
    [8, "2710"],
    [10, "5465737420766563746f7273"],
    [22, PUBKEY],
    [82, "030d40"],
    [86, "02"],
    [88, PUBKEY],
    [89, "77686f6f7073"],
    [240, SIGNATURE],
  ]));
  assert.equal(result.hrp, "lnr");
  assert.equal(result.fields.invreqMetadata, "0102030405");
  assert.equal(result.fields.amount, "10000", "mirrored offer_amount");
  assert.equal(result.fields.description, "Test vectors");
  assert.equal(result.fields.issuerId, PUBKEY);
  assert.equal(result.fields.amountMsat, "200000");
  assert.equal(result.fields.quantity, "2");
  assert.equal(result.fields.payerId, PUBKEY);
  assert.equal(result.fields.payerNote, "whoops");
  assert.equal(result.signaturePresent, true);
});

test("decodes an invoice: amount, payment hash, node id, paths, payinfo, expiry", () => {
  const result = bolt12Decode(encode("lni", [
    [0, "0102030405"],
    [10, "5465737420766563746f7273"],
    [160, PATH_ONE],
    [162, PAYINFO],
    [164, "6553f100"],
    [166, "1c20"],
    [168, PAYMENT_HASH],
    [170, "030d40"],
    [176, PUBKEY],
    [240, SIGNATURE],
  ]));
  assert.equal(result.hrp, "lni");
  assert.equal(result.fields.description, "Test vectors");
  assert.deepEqual(result.fields.invoicePaths, { count: 1, totalBytes: 161 });
  assert.equal(result.fields.payinfoCount, 1);
  assert.equal(result.fields.createdAt, "1700000000");
  assert.equal(result.fields.relativeExpiry, "7200");
  assert.equal(result.fields.paymentHash, PAYMENT_HASH);
  assert.equal(result.fields.invoiceAmount, "200000");
  assert.equal(result.fields.nodeId, PUBKEY);
  assert.equal(result.signaturePresent, true);
});

test("an invoice without a signature record reports signaturePresent false", () => {
  const result = bolt12Decode(encode("lni", [[160, PATH_ONE], [162, PAYINFO], [164, "6553f100"], [168, PAYMENT_HASH], [170, "030d40"], [176, PUBKEY]]));
  assert.equal(result.signaturePresent, false);
});

test("refuses an invoice missing a required field, with no paths, or with mismatched payinfo", () => {
  const base = [[160, PATH_ONE], [162, PAYINFO], [164, "6553f100"], [168, PAYMENT_HASH], [170, "030d40"], [176, PUBKEY]];
  // The complete invoice decodes.
  assert.equal(bolt12Decode(encode("lni", base)).hrp, "lni");
  // Each required field, when removed, is refused.
  for (const type of [160, 162, 164, 168, 170, 176]) {
    assertKeyed(() => bolt12Decode(encode("lni", base.filter(([t]) => t !== type))));
  }
  // An empty invoice_paths is refused.
  assertKeyed(() => bolt12Decode(encode("lni", base.map(([t, v]) => [t, t === 160 ? "" : v]))));
  // A payinfo count that differs from the path count is refused.
  assertKeyed(() => bolt12Decode(encode("lni", base.map(([t, v]) => [t, t === 162 ? PAYINFO + PAYINFO : v]))));
});

test("keeps amounts above 2^53 exact as decimal strings", () => {
  const result = bolt12Decode(encode("lno", [[8, "8000000000000005"], [10, "5465737420766563746f7273"], [22, PUBKEY]]));
  assert.equal(result.fields.amount, "9223372036854775813");
});

test("decodes strings longer than bech32m's 1023-character cap", () => {
  // Real invoices with several blinded paths outgrow the bech32 crate's
  // CODE_LENGTH limit; the checksum-free envelope has no such cap.
  const long = encode("lno", [[10, "5465737420766563746f7273"], [22, PUBKEY], [1000000033, "00".repeat(1500)]]);
  assert.ok(long.length > 1023, `${long.length} chars`);
  const result = bolt12Decode(long);
  assert.deepEqual(result.unknownOddTypes, ["1000000033"]);
  assert.equal(result.fields.description, "Test vectors");
});

// ── rejections ──────────────────────────────────────────────────────────────

test("rejects a BOLT11 invoice on its prefix", () => {
  // The BOLT11 spec's own example. With no checksum anywhere, the HRP
  // allowlist is what keeps lnbc/lntb out.
  const bolt11 = "lnbc1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpl2pkx2ctnv5sxxmmwwd5kgetjypeh2ursdae8g6twvus8g6rfwvs8qun0dfjkxaq8rkx3yf5tcsyz3d73gafnh3cax9rn449d9p5uxz9ezhhypd0elx87sjle52x86fux2ypatgddc6k63n7erqz25le42c4u4ecky03ylcqca784w";
  assert.throws(
    () => bolt12Decode(bolt11),
    (error) => {
      assert.equal(error.key, "Not a BOLT12 string: the prefix “{hrp}” is not lno, lnr, or lni.");
      assert.deepEqual(error.vars, { hrp: "lnbc" });
      return true;
    }
  );
});

test("rejects mixed case", () => {
  assertKey(() => bolt12Decode(SPEC_OFFER_MIXED), "BOLT12 strings must be all lowercase or all uppercase, not mixed case.");
});

test("rejects misplaced `+` continuations", () => {
  // bolt12/format-string-test.json's invalid splitting vectors.
  const trailing = SPEC_OFFER + "+";
  const trailingSpace = SPEC_OFFER + "+ ";
  const leading = "+" + SPEC_OFFER;
  const leadingSpace = "+ " + SPEC_OFFER;
  const doubled = "ln++o1pqps7sjqpgtyzm3qv4uxzmtsd3jjqer9wd3hy6tsw35k7msjzfpy7nz5yqcnygrfdej82um5wf5k2uckyypwa3eyt44h6txtxquqh7lz5djge4afgfjn7k4rgrkuag0jsd5xvxg";
  for (const bad of [trailing, trailingSpace, leading, leadingSpace, doubled]) {
    assertKey(() => bolt12Decode(bad), "Not a valid BOLT12 string: “+” must join two bech32 characters.");
  }
});

test("rejects empty input", () => {
  for (const empty of ["", "   "]) {
    assertKey(() => bolt12Decode(empty), "Paste a BOLT12 string (lno1…, lnr1…, or lni1…).");
  }
});

test("rejects a missing separator and non-bech32 characters", () => {
  assertKey(() => bolt12Decode("lnopqps7sjqpgtyzm3qv4uxz"), "Not a valid BOLT12 string: the “1” separator is missing.");
  assert.throws(
    () => bolt12Decode("lno1!!!"),
    (error) => {
      assert.equal(error.key, "Not a valid BOLT12 string: “{c}” is not a bech32 character.");
      assert.deepEqual(error.vars, { c: "!" });
      return true;
    }
  );
});

test("rejects truncated TLV records (spec vectors)", () => {
  // offers-test.json: truncated at type, in length, after length, in value.
  for (const truncated of ["lno1pg", "lno1pt7s", "lno1pgpq", "lno1pgpyz"]) {
    assertKey(() => bolt12Decode(truncated), "Truncated BOLT12 TLV record.");
  }
});

test("rejects an unknown even TLV type (spec vector)", () => {
  // offers-test.json labels this string "unknown even TLV type 78", but the
  // bytes actually encode type 72 (0x48) — either way it is unknown and even.
  assert.throws(
    () => bolt12Decode(OFFER_UNKNOWN_EVEN),
    (error) => {
      assert.equal(error.key, "Unknown required TLV field type {t}.");
      assert.deepEqual(error.vars, { t: "72" });
      return true;
    }
  );
});

test("rejects out-of-order and duplicate TLV types", () => {
  assertKey(() => bolt12Decode(OFFER_OUT_OF_ORDER), "TLV field type {t} is out of order.");
  assertKey(() => bolt12Decode(encode("lno", [[10, "5465737420766563746f7273"], [10, "5465737420766563746f7273"]])), "Duplicate TLV field type {t}.");
});

test("rejects non-BOLT12 garbage", () => {
  const mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
  const psbtHex = "70736274ff0100750200000001268171371edff285e937adeea4c37da1c4e2d6d5f5631c3d7e1c8e4802e1e1a2e30000000000ffffffff";
  for (const garbage of [mnemonic, psbtHex, "hello world"]) {
    assert.throws(() => bolt12Decode(garbage), (error) => typeof error.key === "string");
  }
});

test("rejects bad bech32 data padding and an empty payload (spec vectors)", () => {
  assertKey(() => bolt12Decode(OFFER_BAD_PADDING), "Invalid padding in the BOLT12 data.");
  assertKey(() => bolt12Decode("lno1"), "The BOLT12 payload is empty.");
});

test("rejects malformed fixed-length fields and invalid UTF-8", () => {
  assertKey(() => bolt12Decode(encode("lno", [[10, "5465737420766563746f7273"], [22, "02ee"]])), "The {name} field has an invalid length.");
  assertKey(() => bolt12Decode(OFFER_BAD_UTF8), "The {name} field is not valid UTF-8.");
});

test("rejects prototype keys as an unknown prefix", () => {
  // A bare KINDS[hrp] lookup would resolve these to Object.prototype members.
  for (const hrp of ["constructor", "__proto__"]) {
    assertKey(() => bolt12Decode(`${hrp}1qqqq`), "Not a BOLT12 string: the prefix “{hrp}” is not lno, lnr, or lni.");
  }
});

test("refuses a blinded path with zero hops", () => {
  // first_node_id (valid pubkey) + path_key (valid pubkey) + num_hops 0.
  const zeroHops = PUBKEY + PUBKEY + "00";
  assertKeyed(() => bolt12Decode(encode("lno", [[10, "5465737420766563746f7273"], [16, zeroHops], [22, PUBKEY]])));
});

test("enforces the offer TLV ranges and the 64-byte signature", () => {
  // BOLT12 offer reader: only types 1-79 and 1000000000-1999999999 are
  // allowed in an offer; the 240 signature record is not one of them.
  assertKeyed(() => bolt12Decode(encode("lno", [[10, "5465737420766563746f7273"], [22, PUBKEY], [240, SIGNATURE]])));
  assertKeyed(() => bolt12Decode(encode("lno", [[10, "5465737420766563746f7273"], [22, PUBKEY], [81, "00"]])));
  // lnr/lni: the signature TLV 240 is exactly 64 bytes.
  assertKeyed(() => bolt12Decode(encode("lnr", [[10, "5465737420766563746f7273"], [22, PUBKEY], [240, "ab"]])));
  assertKeyed(() => bolt12Decode(encode("lni", [[168, PAYMENT_HASH], [240, "ab".repeat(65)]])));
});

test("refuses over-long or non-minimal truncated integers", () => {
  // BOLT1: tu64 is at most 8 bytes, tu32 at most 4, and leading zeros MUST
  // be omitted.
  assertKeyed(() => bolt12Decode(encode("lno", [[8, "01".repeat(9)], [10, "5465737420766563746f7273"], [22, PUBKEY]])));
  assertKeyed(() => bolt12Decode(encode("lno", [[8, "0001"], [10, "5465737420766563746f7273"], [22, PUBKEY]])));
  assertKeyed(() => bolt12Decode(encode("lni", [[166, "01".repeat(5)], [168, PAYMENT_HASH], [170, "030d40"], [176, PUBKEY]])));
  assertKeyed(() => bolt12Decode(encode("lni", [[166, "0001"], [168, PAYMENT_HASH], [170, "030d40"], [176, PUBKEY]])));
});

test("reports unknown odd types as exact decimal strings", () => {
  // 2^64-1 is odd and beyond Number.MAX_SAFE_INTEGER; Number() would round
  // it to 18446744073709552000.
  const type = 18446744073709551615n;
  const result = bolt12Decode(encode("lnr", [[10, "5465737420766563746f7273"], [22, PUBKEY], [type, "00"]]));
  assert.deepEqual(result.unknownOddTypes, ["18446744073709551615"]);
});
