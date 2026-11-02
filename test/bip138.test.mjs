// BIP-138 encrypted backups: the pure module against every official vector,
// then the app-level contract (export, open, refusals).
// Run with: npm test
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import * as bip138 from "../src/js/bip138.js";

const fixture = (name) => JSON.parse(readFileSync(new URL(`./fixtures/bip138/${name}.json`, import.meta.url), "utf8"));
const hex = (bytes) => Buffer.from(bytes).toString("hex");
const bytes = (text) => Uint8Array.from(Buffer.from(text, "hex"));
const utf8 = (text) => new TextEncoder().encode(text);
const code = (fn) => { try { fn(); } catch (error) { return error.code; } return null; };

const XPUB_A = "xpub6FC1fXFP1GXLX5TKtcjHGT4q89SDRehkQLtbKJ2PzWcvbBHtyDsJPLtpLtkGqYNYZdVVAjRQ5kug9CsapegmmeRutpP7PW4u4wVF9JfkDhw";
const XPUB_B = "xpub6EWhjpPa6FqrcaPBuGBZRJVjzGJ1ZsMygRF26RwN932Vfkn1gyCiTbECVitBjRCkexEvetLdiqzTcYimmzYxyR1BZ79KNevgt61PDcukmC7";
const XPUB_C = "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL";
const MASTER_XPUB = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";
const XPRV = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";
const WIF = "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn";
const NUMS = "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0";
const DESC = "wsh(sortedmulti(2,[6738736c/48'/0'/0'/2']" + XPUB_A + "/<0;1>/*,[b2b1f0cf/48'/0'/0'/2']" + XPUB_B + "/<0;1>/*))";

// An independent path reader, straight from the specification, so the
// expected sorted/deduplicated set never comes from the module under test.
const readPath = (text) => text.replace(/^m\/?/, "").split("/").filter(Boolean).map((part) => {
  const hardened = /['hH]$/.test(part);
  const value = Number(part.replace(/['hH]$/, ""));
  return hardened ? (value + 0x80000000) >>> 0 : value;
});
const comparePaths = (a, b) => {
  for (let i = 0; i < Math.min(a.length, b.length); i++) if (a[i] !== b[i]) return a[i] - b[i];
  return a.length - b.length;
};
const H = (n) => (n | 0x80000000) >>> 0;
const isCommonPath = (path) => {
  for (const coin of [0, 1]) for (let account = 0; account <= 9; account++) {
    for (const script of [1, 2]) if (path.length === 4 && path[0] === H(48) && path[1] === H(coin) && path[2] === H(account) && path[3] === H(script)) return true;
    for (const purpose of [44, 49, 84, 86, 87]) if (path.length === 3 && path[0] === H(purpose) && path[1] === H(coin) && path[2] === H(account)) return true;
  }
  return false;
};

test("payload vectors", () => {
  for (const entry of fixture("payload")) {
    const input = bytes(entry.payload);
    if (entry.valid) {
      const items = bip138.bip138DecodePayload(input).map((item) => ({ type: item.type, content: hex(item.content) }));
      assert.deepEqual(items, entry.items, entry.description);
    } else {
      assert.throws(() => bip138.bip138DecodePayload(input), bip138.Bip138Error, entry.description);
    }
  }
});

test("content type vectors", () => {
  for (const entry of fixture("content_type")) {
    const input = bytes(entry.content);
    if (entry.valid) {
      const decoded = bip138.bip138DecodeContentType(input, 0);
      assert.equal(decoded.next, input.length, entry.description);
      assert.equal(hex(bip138.bip138EncodeContentType(decoded)), entry.content, entry.description);
    } else {
      assert.throws(() => bip138.bip138DecodeContentType(input, 0), bip138.Bip138Error, entry.description);
    }
  }
});

test("chacha20poly1305 vectors", () => {
  for (const entry of fixture("chacha20poly1305_encryption")) {
    const secret = bytes(entry.secret), nonce = bytes(entry.nonce), plaintext = bytes(entry.plaintext);
    if (entry.ciphertext !== null) {
      const ciphertext = bip138.bip138Encrypt(secret, nonce, plaintext);
      assert.equal(hex(ciphertext), entry.ciphertext, entry.description);
      assert.equal(hex(bip138.bip138Decrypt(secret, nonce, ciphertext)), entry.plaintext, entry.description);
      const flipped = ciphertext.slice();
      flipped[0] ^= 1;
      assert.equal(bip138.bip138Decrypt(secret, nonce, flipped), null, entry.description);
    } else {
      assert.throws(() => bip138.bip138Encrypt(secret, nonce, plaintext), bip138.Bip138Error, entry.description);
    }
  }
});

test("encryption secret vectors", () => {
  for (const entry of fixture("encryption_secret")) {
    const keys = entry.keys.map((key) => bytes(key.slice(2)));
    const secret = bip138.bip138DecryptionSecret(keys);
    assert.equal(hex(secret), entry.decryption_secret, entry.description);
    const individual = bip138.bip138IndividualSecrets(secret, keys);
    assert.deepEqual(individual.map(hex), entry.individual_secrets, entry.description);
    const xonly = [...new Set(entry.keys.map((key) => key.slice(2)))].sort();
    for (let i = 0; i < individual.length; i++) {
      const si = bip138.bip138TaggedHash("BIP138_INDIVIDUAL_SECRET", bytes(xonly[i]));
      const back = new Uint8Array(32);
      for (let j = 0; j < 32; j++) back[j] = individual[i][j] ^ si[j];
      assert.equal(hex(back), entry.decryption_secret, entry.description);
    }
  }
});

test("derivation path vectors", () => {
  for (const entry of fixture("derivation_path")) {
    const paths = entry.paths.map((path) => bip138.bip138ParsePath(path));
    if (entry.expected === null) {
      assert.throws(() => bip138.bip138EncodeDerivationPaths(paths), bip138.Bip138Error, entry.description);
      continue;
    }
    const encoded = bip138.bip138EncodeDerivationPaths(paths);
    assert.equal(hex(encoded), entry.expected, entry.description);
    const decoded = bip138.bip138DecodeDerivationPaths(encoded, 0);
    assert.equal(decoded.next, encoded.length, entry.description);
    const expected = [...new Map(entry.paths.map((text) => {
      const path = readPath(text);
      return [path.join(","), path];
    })).values()].sort(comparePaths);
    assert.deepEqual(decoded.paths, expected, entry.description);
  }
});

test("individual secret vectors", () => {
  for (const entry of fixture("individual_secrets")) {
    const secrets = entry.secrets.map(bytes);
    if (entry.expected === null) {
      assert.throws(() => bip138.bip138EncodeIndividualSecrets(secrets), bip138.Bip138Error, entry.description);
      continue;
    }
    assert.equal(hex(bip138.bip138EncodeIndividualSecrets(secrets)), entry.expected, entry.description);
    const decoded = bip138.bip138DecodeIndividualSecrets(bytes(entry.expected), 0);
    assert.equal(decoded.next, bytes(entry.expected).length, entry.description);
    assert.deepEqual(decoded.secrets.map(hex), [...new Set(entry.secrets)].sort(), entry.description);
  }
});

test("encrypted backup vectors", () => {
  for (const entry of fixture("encrypted_backup")) {
    if (entry.valid === false) {
      assert.equal(code(() => bip138.bip138ParseBackup(bytes(entry.expected))), "zero-nonce", entry.description);
      continue;
    }
    const keys = entry.keys.map((key) => bytes(key.slice(2)));
    const items = [{ contentType: bytes(entry.content), content: utf8(entry.plaintext) }];
    for (const extra of entry.extra || []) items.push({ contentType: bytes(extra.content), content: utf8(extra.plaintext) });
    const encoded = bip138.bip138EncodeBackup({
      keys,
      payload: bip138.bip138EncodePayload(items),
      nonce: bytes(entry.nonce),
      decoys: entry.decoy_individual_secrets.map(bytes),
      derivationPaths: entry.derivation_paths.map((path) => bip138.bip138ParsePath(path)),
    });
    assert.equal(hex(encoded), entry.expected, entry.description);
    assert.equal(bip138.bip138ToBase64(encoded), entry.expected_base64, entry.description);
    assert.equal(hex(bip138.bip138BytesFromText(entry.expected_base64)), entry.expected, entry.description);
    const parsed = bip138.bip138ParseBackup(bytes(entry.expected + (entry.trailing || "")));
    assert.equal(parsed.version, 1, entry.description);
    assert.equal(parsed.encryption, 1, entry.description);
    assert.equal(hex(parsed.nonce), entry.nonce, entry.description);
    const expectedPaths = [...new Map(entry.derivation_paths.map((text) => {
      const path = readPath(text);
      return [path.join(","), path];
    })).values()].filter((path) => !isCommonPath(path)).sort(comparePaths);
    assert.deepEqual(parsed.derivationPaths, expectedPaths, entry.description);
    for (const key of keys) {
      const plaintext = bip138.bip138DecryptBackup(parsed, key);
      const decoded = bip138.bip138DecodePayload(plaintext);
      assert.equal(decoded.length, items.length, entry.description);
      for (let i = 0; i < items.length; i++) {
        const contentType = bip138.bip138DecodeContentType(items[i].contentType, 0);
        assert.equal(decoded[i].type, contentType.type, entry.description);
        assert.equal(decoded[i].bip, contentType.bip, entry.description);
        assert.equal(hex(decoded[i].params), hex(contentType.params), entry.description);
        assert.equal(hex(decoded[i].content), hex(items[i].content), entry.description);
      }
    }
  }
});

test("recipient key vectors", () => {
  for (const entry of fixture("recipient_keys")) {
    const { keys } = bip138.bip138RecipientKeys(entry.descriptors);
    assert.deepEqual(keys.map(hex), entry.expected_keys === null ? [] : entry.expected_keys, entry.description);
  }
});

test("descriptor and policy document vectors", () => {
  for (const entry of fixture("bip380_descriptor_backup")) {
    assert.equal(bip138.bip138ValidDescriptorDocument(entry.document), entry.valid, entry.description);
  }
  for (const entry of fixture("bip388")) {
    assert.equal(bip138.bip138ValidPolicyDocument(entry.document), entry.valid, entry.description);
  }
});

test("createDescriptorBackup makes a backup every recipient key opens", () => {
  const built = bip138.bip138CreateDescriptorBackup(DESC);
  assert.equal(built.status, "ok");
  assert.deepEqual(built.exclusions, []);
  const parsed = bip138.bip138ParseBackup(built.bytes);
  assert.equal(parsed.derivationPaths.length, 0);
  assert.equal(parsed.secrets.length, 5);
  const secrets = parsed.secrets.map(hex);
  assert.ok(secrets.includes("63f5769bbb36d77fc5d3251700590c087013ca44284850e88f379f2519190f97"));
  assert.ok(secrets.includes("e5b4cabf8bdb9a04a92fc3e104dd2d8a2cb8e5ea886e143236dd4b04619e796d"));
  assert.ok(!parsed.nonce.every((byte) => byte === 0));
  assert.equal(hex(bip138.bip138CreateDescriptorBackup(DESC).bytes), hex(built.bytes), "the same descriptor always yields the same file");
  const keyA = bip138.bip138KeyFromXpubText(XPUB_A).key;
  const keyB = bip138.bip138KeyFromXpubText(XPUB_B).key;
  const keyC = bip138.bip138KeyFromXpubText(XPUB_C).key;
  assert.equal(bip138.bip138OpenDescriptorBackup(built.bytes, keyA).descriptor, DESC);
  assert.equal(bip138.bip138OpenDescriptorBackup(built.bytes, keyB).descriptor, DESC);
  assert.equal(code(() => bip138.bip138OpenDescriptorBackup(built.bytes, keyC)), "wrong-key");
});

test("recipient selection excludes literals, bare xpubs and the NUMS key", () => {
  const taproot = `tr(${NUMS},sortedmulti_a(1,${XPUB_A}/<0;1>/*,${XPUB_B}/<0;1>/*))`;
  const built = bip138.bip138CreateDescriptorBackup(taproot);
  assert.equal(built.status, "ok");
  assert.equal(bip138.bip138RecipientKeys([taproot]).keys.length, 2);
  assert.deepEqual(built.exclusions, [{ descriptor: 0, index: null, internal: true, reason: "nums" }]);
  const bare = bip138.bip138CreateDescriptorBackup(`wsh(multi(1,${XPUB_A},${XPUB_B}))`);
  assert.equal(bare.status, "no-keys");
  assert.deepEqual(bare.exclusions.map((entry) => [entry.index, entry.reason]), [[0, "exposed"], [1, "exposed"]]);
  const literal = bip138.bip138CreateDescriptorBackup(`wsh(multi(1,0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2,${XPUB_A}/<0;1>/*))`);
  assert.equal(literal.status, "ok");
  assert.deepEqual(literal.exclusions, [{ descriptor: 0, index: 0, internal: false, reason: "literal" }]);
});

test("descriptors carrying private keys are refused without repeating them", () => {
  for (const descriptor of [`wsh(multi(1,${XPRV}/0/*,${XPUB_A}/0/*))`, `wpkh(${WIF})`]) {
    assert.throws(() => bip138.bip138CreateDescriptorBackup(descriptor), (error) => {
      assert.equal(error.code, "private-key");
      assert.equal(error.message, "private-key");
      assert.ok(!error.message.includes("xprv") && !error.message.includes("KwDi"));
      return true;
    });
  }
});

test("open refuses damaged, unsupported and wrong-key backups", () => {
  const built = bip138.bip138CreateDescriptorBackup(DESC);
  const keyA = bip138.bip138KeyFromXpubText(XPUB_A).key;
  assert.equal(code(() => bip138.bip138OpenDescriptorBackup(utf8("hello"), keyA)), "magic");
  assert.equal(code(() => bip138.bip138OpenDescriptorBackup(built.bytes.slice(0, 40), keyA)), "truncated");
  const version2 = built.bytes.slice(); version2[6] = 2;
  assert.equal(code(() => bip138.bip138OpenDescriptorBackup(version2, keyA)), "unsupported-version");
  const version0 = built.bytes.slice(); version0[6] = 0;
  assert.equal(code(() => bip138.bip138OpenDescriptorBackup(version0, keyA)), "bad-version");
  const encryption2 = built.bytes.slice(); encryption2[169] = 2;
  assert.equal(code(() => bip138.bip138OpenDescriptorBackup(encryption2, keyA)), "unsupported-encryption");
  const zeroNonce = built.bytes.slice(); zeroNonce.fill(0, 170, 182);
  assert.equal(code(() => bip138.bip138OpenDescriptorBackup(zeroNonce, keyA)), "zero-nonce");
  const flipped = built.bytes.slice(); flipped[flipped.length - 1] ^= 1;
  assert.equal(code(() => bip138.bip138OpenDescriptorBackup(flipped, keyA)), "wrong-key");
});

test("open refuses content it cannot use", () => {
  const keyA = bip138.bip138KeyFromXpubText(XPUB_A).key;
  const keyB = bip138.bip138KeyFromXpubText(XPUB_B).key;
  const nonce = new Uint8Array(12).fill(1);
  const build = (items) => bip138.bip138EncodeBackup({ keys: [keyA, keyB], payload: bip138.bip138EncodePayload(items), nonce });
  const stringOnly = build([{ contentType: bip138.bip138EncodeContentType({ type: 3, params: new Uint8Array() }), content: utf8("note") }]);
  assert.equal(code(() => bip138.bip138OpenDescriptorBackup(stringOnly, keyA)), "unsupported-content");
  const privateContent = build([{ contentType: Uint8Array.of(1, 1, 0x7c), content: utf8(`wpkh(${XPRV}/0/*)`) }]);
  assert.equal(code(() => bip138.bip138OpenDescriptorBackup(privateContent, keyA)), "private-key");
  const documents = fixture("bip380_descriptor_backup");
  const multipath = documents.find((entry) => entry.description === "BIP389 multipath descriptor");
  // The document's descriptor names its own keys, so its backup is made for
  // one of them; the same document opened with a key it does not name is a
  // forgery and is refused (the names-the-key check).
  const multipathItems = [{ contentType: Uint8Array.of(1, 1, 0x7c), content: utf8(JSON.stringify(multipath.document)) }];
  const multipathXpub = multipath.document.descriptor_sets[0].descriptor.match(/[xt]pub[1-9A-HJ-NP-Za-km-z]{100,108}/)[0];
  const multipathKey = bip138.bip138KeyFromXpubText(multipathXpub).key;
  const multipathBytes = bip138.bip138EncodeBackup({ keys: [multipathKey], payload: bip138.bip138EncodePayload(multipathItems), nonce });
  assert.equal(bip138.bip138OpenDescriptorBackup(multipathBytes, multipathKey).descriptor, multipath.document.descriptor_sets[0].descriptor);
  assert.equal(code(() => bip138.bip138OpenDescriptorBackup(build(multipathItems), keyA)), "wrong-key");
  const withChange = documents.find((entry) => entry.description === "Descriptor with change descriptor");
  const changeBytes = build([{ contentType: Uint8Array.of(1, 1, 0x7c), content: utf8(JSON.stringify(withChange.document)) }]);
  assert.equal(code(() => bip138.bip138OpenDescriptorBackup(changeBytes, keyA)), "unsupported-content");
  const badUtf8 = build([{ contentType: Uint8Array.of(1, 1, 0x7c), content: Uint8Array.of(0xff, 0xfe) }]);
  assert.equal(code(() => bip138.bip138OpenDescriptorBackup(badUtf8, keyA)), "damaged");
});

test("keyFromXpubText reads an xpub root and refuses private material", () => {
  const master = bip138.bip138KeyFromXpubText(MASTER_XPUB);
  assert.equal(master.status, "ok");
  assert.equal(hex(master.key), "39a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2");
  const withOrigin = bip138.bip138KeyFromXpubText(`[6738736c/48'/0'/0'/2']${XPUB_A}/<0;1>/*`);
  assert.equal(withOrigin.status, "ok");
  assert.equal(hex(withOrigin.key), "6f155ae2153b09bb4e1383756723c0879e80d0f32767c7e4875d5de2fb9a400d");
  for (const text of [XPRV, WIF, "abandon ".repeat(11) + "about", "0".repeat(63) + "1"]) {
    assert.equal(bip138.bip138KeyFromXpubText(text).status, "private-key");
  }
  assert.equal(bip138.bip138KeyFromXpubText("").status, "invalid");
  assert.equal(bip138.bip138KeyFromXpubText("xpub123").status, "invalid");
});

test("hasPrivateKey spots xprvs and WIFs but not a watch-only descriptor", () => {
  assert.equal(bip138.bip138HasPrivateKey(`wsh(multi(1,${XPRV}/0/*))`), true);
  assert.equal(bip138.bip138HasPrivateKey(`wpkh(${WIF})`), true);
  assert.equal(bip138.bip138HasPrivateKey(DESC), false);
});

test("text and file inputs", () => {
  const built = bip138.bip138CreateDescriptorBackup(DESC);
  const base64 = bip138.bip138ToBase64(built.bytes);
  const wrapped = base64.slice(0, 20) + "\n  " + base64.slice(20);
  assert.equal(bip138.bip138LooksLikeText(wrapped), true);
  assert.equal(hex(bip138.bip138BytesFromText(wrapped)), hex(built.bytes));
  assert.equal(code(() => bip138.bip138BytesFromText("QklQMTM4!!!!")), "base64");
  assert.equal(code(() => bip138.bip138BytesFromText("aGVsbG8=")), "magic");
  const copy = bip138.bip138BytesFromFile(built.bytes);
  assert.notEqual(copy, built.bytes);
  assert.equal(hex(copy), hex(built.bytes));
  assert.equal(hex(bip138.bip138BytesFromFile(utf8(base64 + "\n"))), hex(built.bytes));
  assert.equal(code(() => bip138.bip138BytesFromFile(utf8("hello"))), "magic");
  assert.equal(code(() => bip138.bip138BytesFromFile(utf8("QklQMTM4AQ"))), "base64");
  assert.equal(code(() => bip138.bip138BytesFromFile(new Uint8Array(1048577))), "too-large");
});

test("secret buckets follow the doubling sequence", () => {
  assert.equal(bip138.bip138SecretBucket(1), 5);
  assert.equal(bip138.bip138SecretBucket(5), 5);
  assert.equal(bip138.bip138SecretBucket(6), 10);
  assert.equal(bip138.bip138SecretBucket(11), 20);
  assert.equal(bip138.bip138SecretBucket(200), 255);
  assert.equal(bip138.bip138SecretBucket(255), 255);
  assert.throws(() => bip138.bip138SecretBucket(0), bip138.Bip138Error);
  assert.throws(() => bip138.bip138SecretBucket(256), bip138.Bip138Error);
});

test("the module never draws randomness and touches no DOM", () => {
  const source = readFileSync(new URL("../src/js/bip138.js", import.meta.url), "utf8");
  for (const needle of ["getRandomValues", "Math.random", "document", "window", "fetch(", "./i18n.js"]) {
    assert.ok(!source.includes(needle), `bip138.js must not contain ${needle}`);
  }
});

// A backup opens for anyone who wrote it with one of the wallet's xpubs; one
// whose descriptor does not even name the key that opened it is refused
// (Claude, from the Kaitiaki review: a backup proves only that its writer
// knew the key).
test("open refuses a backup whose descriptor does not name the key that opened it", () => {
  const keyA = bip138.bip138KeyFromXpubText(XPUB_A).key;
  const keyC = bip138.bip138KeyFromXpubText(XPUB_C).key;
  const forged = "wpkh([0badc0de/84'/0'/0']" + XPUB_C + "/0/*)";
  const payload = bip138.bip138EncodePayload([{ contentType: Uint8Array.of(1, 1, 0x7c), content: utf8(forged) }]);
  const nonce = Uint8Array.from({ length: 12 }, (_, i) => i + 1);
  const bytesForA = bip138.bip138EncodeBackup({ keys: [keyA], payload, nonce });
  assert.equal(code(() => bip138.bip138OpenDescriptorBackup(bytesForA, keyA)), "wrong-key", "it decrypts with A, but names only C");
  const bytesForC = bip138.bip138EncodeBackup({ keys: [keyC], payload, nonce });
  assert.equal(bip138.bip138OpenDescriptorBackup(bytesForC, keyC).descriptor, forged, "the same descriptor opens with the key it names");
  assert.equal(bip138.bip138DescriptorNamesKey(DESC, keyA), true);
  assert.equal(bip138.bip138DescriptorNamesKey(DESC, keyC), false);
  assert.equal(bip138.bip138DescriptorNamesKey("not a descriptor", keyA), false);
});
