// Secure entry P3a: parse a private key from bytes, never a string.
//
// Expected values: the published Bitcoin wiki WIF vector, the published
// Casascius mini key example, SHA-256 from @noble/hashes, and WIF encoding
// from @scure/base's Base58Check. The differential half runs app.js's own
// string decoders through the slice harness.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { sha256 } from "@noble/hashes/sha2.js";
import { createBase58check, hex } from "@scure/base";
import { loadAppFunctions } from "./app-slice-harness.mjs";
import { base58checkDecode, base58checkDecodeBytes } from "../src/js/base58.js";
import { sha256 as wasmSha256 } from "../src/js/hashes.js";
import { KeyBytesError, parsePrivateKeyBytes } from "../src/js/key-bytes.js";

const b58 = createBase58check(sha256);
const wifOf = (key, network, compressed) => b58.encode(Uint8Array.from([network === "mainnet" ? 0x80 : 0xef, ...key, ...(compressed ? [1] : [])]));
const WIKI_KEY = hex.decode("0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d");
const WIKI_WIF = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ";
const MINI = "S6c56bnXQiBjk9mqSYE7ykVQ7NzrRy";
const MINI_KEY = hex.decode("4c7a9640c72dc2099f23715d0c8a0d8a35f8906e3cab61dd3f78b67bf887c9ab");
const utf8 = (text) => new TextEncoder().encode(text);

const parse = (input, options) => {
  const before = input.slice();
  const result = parsePrivateKeyBytes(input, options);
  assert.deepEqual(input, before, "input must be untouched");
  return result;
};

const expectCode = (input, options, code) => {
  const before = input.slice();
  assert.throws(() => parsePrivateKeyBytes(input, options), (error) => error instanceof KeyBytesError && error.code === code);
  assert.deepEqual(input, before, "input must be untouched");
};

test("parses the published vectors", () => {
  const wif = parse(utf8(WIKI_WIF));
  assert.equal(wif.source, "wif");
  assert.deepEqual(wif.priv, WIKI_KEY);
  assert.equal(wif.compressed, false);
  assert.equal(wif.network, "mainnet");
  assert.equal(wif.minikey, null);

  const compressedMainnet = parse(utf8(wifOf(WIKI_KEY, "mainnet", true)));
  assert.deepEqual(compressedMainnet.priv, WIKI_KEY);
  assert.equal(compressedMainnet.compressed, true);
  assert.equal(compressedMainnet.network, "mainnet");

  const compressedTestnet = parse(utf8(wifOf(WIKI_KEY, "testnet", true)));
  assert.deepEqual(compressedTestnet.priv, WIKI_KEY);
  assert.equal(compressedTestnet.compressed, true);
  assert.equal(compressedTestnet.network, "testnet");

  const mini = parse(utf8(MINI));
  assert.equal(mini.source, "minikey");
  assert.deepEqual(mini.priv, MINI_KEY);
  assert.equal(mini.compressed, null);
  assert.equal(mini.network, null);
  assert.deepEqual(mini.minikey, utf8(MINI));

  const lower = hex.encode(WIKI_KEY);
  const upper = lower.toUpperCase();
  for (const text of [lower, upper, "0x" + lower, "0X" + upper, "  " + lower.slice(0, 32) + "\n" + lower.slice(32) + "  "]) {
    const result = parse(utf8(text));
    assert.equal(result.source, "hex");
    assert.deepEqual(result.priv, WIKI_KEY);
    assert.equal(result.compressed, null);
    assert.equal(result.network, null);
    assert.equal(result.minikey, null);
  }
});

test("matches the string decoders", async () => {
  const { hodlDecodeWif, hodlIsMiniKey, hodlDecodeMiniKey } = await loadAppFunctions(
    ["hodlDecodeWif", "hodlIsMiniKey", "hodlDecodeMiniKey"],
    { stubs: { hodlBase58Check: { decode: base58checkDecode }, hodlSha256: wasmSha256, hodlError: (key) => new Error(key) } }
  );
  const stringParse = (text, kind) => {
    const a = text.trim();
    const mini = hodlIsMiniKey(a);
    if (kind === "minikey" || mini) {
      if (!mini) throw new Error("BAD_MINIKEY");
      return { source: "minikey", priv: hodlDecodeMiniKey(a), compressed: null, network: null };
    }
    if (/^[5KL9c][1-9A-HJ-NP-Za-km-z]{50,51}$/.test(a)) {
      const wif = hodlDecodeWif(a);
      return { source: "wif", priv: wif.priv, compressed: wif.compressed, network: wif.network };
    }
    const hexText = a.replace(/\s/g, "").replace(/^0x/i, "");
    if (!/^[0-9a-fA-F]{64}$/.test(hexText)) throw new Error("BAD_FORMAT");
    return { source: "hex", priv: hex.decode(hexText.toLowerCase()), compressed: null, network: null };
  };
  const changedWif = WIKI_WIF.slice(0, 10) + (WIKI_WIF[10] === "1" ? "2" : "1") + WIKI_WIF.slice(11);
  const changedMini = MINI.slice(0, 10) + (MINI[10] === "1" ? "2" : "1") + MINI.slice(11);
  const corpus = [
    WIKI_WIF,
    wifOf(WIKI_KEY, "mainnet", true),
    wifOf(WIKI_KEY, "testnet", true),
    MINI,
    hex.encode(WIKI_KEY),
    hex.encode(WIKI_KEY).toUpperCase(),
    "0x" + hex.encode(WIKI_KEY),
    "  " + hex.encode(WIKI_KEY).slice(0, 32) + "\n" + hex.encode(WIKI_KEY).slice(32) + "  ",
    changedWif,
    WIKI_WIF.slice(0, -1),
    b58.encode(Uint8Array.from([0x81, ...WIKI_KEY])),
    b58.encode(Uint8Array.from([0x80, ...WIKI_KEY, 0x02])),
    changedMini,
    MINI.slice(0, 21),
  ];
  for (const text of corpus) {
    for (const kind of ["wif", "hex-key", "minikey"]) {
      const input = utf8(text);
      const before = input.slice();
      let byteResult, byteError;
      try {
        byteResult = parsePrivateKeyBytes(input, { kind });
      } catch (error) {
        byteError = error;
      }
      assert.deepEqual(input, before, "input must be untouched");
      let stringResult, stringError;
      try {
        stringResult = stringParse(text, kind);
      } catch (error) {
        stringError = error;
      }
      if (byteError || stringError) {
        assert.ok(byteError && stringError, `both must refuse: ${text} (${kind})`);
        continue;
      }
      assert.equal(byteResult.source, stringResult.source, text);
      assert.deepEqual(byteResult.priv, stringResult.priv, text);
      assert.equal(byteResult.compressed, stringResult.compressed, text);
      assert.equal(byteResult.network, stringResult.network, text);
    }
  }
});

test("refuses with the right code", () => {
  expectCode(utf8(WIKI_WIF + "\u00a0"), undefined, "NOT_ASCII");
  expectCode(utf8("   "), undefined, "EMPTY");
  expectCode(utf8(WIKI_WIF), { kind: "minikey" }, "BAD_MINIKEY");
  const changedWif = WIKI_WIF.slice(0, 10) + (WIKI_WIF[10] === "1" ? "2" : "1") + WIKI_WIF.slice(11);
  expectCode(utf8(changedWif), undefined, "BAD_CHECKSUM");
  expectCode(utf8(hex.encode(WIKI_KEY).slice(0, 63)), undefined, "BAD_FORMAT");
  expectCode(utf8(WIKI_WIF), { kind: "brain" }, "BAD_KIND");
  expectCode("not bytes", undefined, "BAD_INPUT");
  // A null options object takes the default kind (GLM's review).
  assert.deepEqual(parsePrivateKeyBytes(utf8(WIKI_WIF), null).priv, WIKI_KEY);
  expectCode("not bytes", null, "BAD_INPUT");
});

test("the module never builds a string", () => {
  const source = readFileSync(new URL("../src/js/key-bytes.js", import.meta.url), "utf8");
  for (const forbidden of ["TextDecoder", "fromCharCode", "String(", ".toString("]) {
    assert.equal(source.includes(forbidden), false, `key-bytes.js must not contain ${forbidden}`);
  }
});

test("base58checkDecode is unchanged", () => {
  const text = base58checkDecode(WIKI_WIF);
  const bytes = base58checkDecodeBytes(utf8(WIKI_WIF));
  assert.deepEqual(text, bytes);
  const changedWif = WIKI_WIF.slice(0, 10) + (WIKI_WIF[10] === "1" ? "2" : "1") + WIKI_WIF.slice(11);
  assert.throws(() => base58checkDecode(changedWif));
  assert.throws(() => base58checkDecodeBytes(utf8(changedWif)));
});
