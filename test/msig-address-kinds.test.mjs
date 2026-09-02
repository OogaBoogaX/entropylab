// Every multisig script kind the UI offers must render an address.
//
// Regression guard for #183: hodlMsigAddr called p2trLeafScript, but the
// import from ./addresses.js did not list it, so the Taproot branch threw
// "ReferenceError: p2trLeafScript is not defined" for every Taproot multisig
// address. The facade suites tested p2trLeafScript directly and passed; only
// running the app's own function through the app's own import line catches
// it. So the slice below keeps app.js's real import statements and never
// injects the helpers. hodlMsigAddr now builds a descriptor from the keys
// and evaluates it through rust-miniscript in the WASM crate
// (descriptorDerive), which is what this suite exercises end to end.
// Run with `npm test`.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, unlinkSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { NETWORK, TEST_NETWORK, p2sh, p2tr, p2wsh } from "@scure/btc-signer";
import { sha256 } from "@noble/hashes/sha2.js";
import { secp256k1 } from "../src/js/secp256k1.js";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const app = readFileSync(join(root, "src/js/app.js"), "utf8");

function slice(name) {
  const start = app.indexOf(`function ${name}(`);
  assert.ok(start >= 0, name);
  let depth = 0;
  for (let index = app.indexOf("{", start); index < app.length; index++) {
    if (app[index] === "{") depth++;
    else if (app[index] === "}" && --depth === 0) return app.slice(start, index + 1);
  }
  throw new Error(`Could not extract ${name}`);
}

// app.js's own import statements, with the module specifiers pointed at src/.
function importLine(module) {
  const match = app.match(new RegExp(`^import \\{[^}]*\\} from "\\./${module}\\.js";$`, "m"));
  assert.ok(match, `import from ./${module}.js`);
  return match[0].replace(`"./${module}.js"`, `"../src/js/${module}.js"`);
}

const source = [
  importLine("addresses"),
  importLine("coders"),
  ...["hodlTaprootNumsKey", "hodlXOnlyPubkey", "hodlMsigAddr"].map(slice),
  "export { hodlMsigAddr, hodlTaprootNumsKey };",
].join("\n");

const modulePath = join(root, "test", `.msig-address-kinds-${process.pid}.mjs`);
writeFileSync(modulePath, source);
let hodlMsigAddr, hodlTaprootNumsKey;
try {
  ({ hodlMsigAddr, hodlTaprootNumsKey } = await import(pathToFileURL(modulePath).href));
} finally {
  unlinkSync(modulePath);
}

// Fixed, public keys: secret keys 1..3. Nothing here is secret.
const pubkeys = [1, 2, 3].map((n) => {
  const key = new Uint8Array(32);
  key[31] = n;
  return secp256k1.getPublicKey(key, true);
});

const KINDS = ["p2sh", "p2wsh", "p2sh-p2wsh", "p2tr"];

test("every multisig kind renders an address on both networks", () => {
  for (const network of ["mainnet", "testnet"]) {
    for (const kind of KINDS) {
      const result = hodlMsigAddr(pubkeys, 2, network, kind);
      assert.equal(result.kind, kind);
      assert.equal(typeof result.address, "string");
      assert.ok(result.address.length > 0, `${kind} on ${network} produced no address`);
      assert.match(result.scriptHex, /^[0-9a-f]+$/);
    }
  }
});

test("multisig addresses match their published prefixes", () => {
  const address = (kind, network = "mainnet") => hodlMsigAddr(pubkeys, 2, network, kind).address;
  assert.match(address("p2sh"), /^3/);
  assert.match(address("p2sh-p2wsh"), /^3/);
  assert.match(address("p2wsh"), /^bc1q/);
  assert.match(address("p2tr"), /^bc1p/);
  assert.match(address("p2sh", "testnet"), /^2/);
  assert.match(address("p2wsh", "testnet"), /^tb1q/);
  assert.match(address("p2tr", "testnet"), /^tb1p/);
});

test("sorted and unsorted key orders both derive, and sorting is what BIP67 says", () => {
  const reversed = [...pubkeys].reverse();
  for (const kind of KINDS) {
    assert.equal(
      hodlMsigAddr(pubkeys, 2, "mainnet", kind).address,
      hodlMsigAddr(reversed, 2, "mainnet", kind).address,
      `${kind} sorted derivation depends on input order`,
    );
    assert.notEqual(
      hodlMsigAddr(reversed, 2, "mainnet", kind, false).scriptHex,
      hodlMsigAddr(pubkeys, 2, "mainnet", kind, false).scriptHex,
      `${kind} unsorted derivation ignored input order`,
    );
  }
});

// Actual validation against an independent implementation. Prefixes only
// prove the shape; @scure/btc-signer (a pinned dev dependency, not the code
// under test) derives every address from the raw scripts, so the wiring, the
// script templates, and the tweak are all checked byte for byte.

const NETS = { mainnet: NETWORK, testnet: TEST_NETWORK };

// The BIP341 NUMS internal key the app hardcodes, as a cross-check anchor.
const NUMS = new Uint8Array(
  Buffer.from("50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0", "hex")
);

test("the app NUMS key is the BIP341 nothing-up-my-sleeve point", () => {
  assert.deepEqual(hodlTaprootNumsKey(), NUMS);
});

// Reference builders: raw script templates written out by hand here, then
// handed to btc-signer for the address. Nothing goes through ./addresses.js.
function bareMultisig(m, keys) {
  return new Uint8Array([0x50 + m, ...keys.flatMap((key) => [0x21, ...key]), 0x50 + keys.length, 0xae]);
}
function trLeafMultisig(m, xonlyKeys) {
  // The reference only needs the small-m encoding (OP_1..OP_16); the tests
  // never exceed 15-of-15. rust-bitcoin's push_int switches to script-number
  // pushes above 16, which this helper deliberately does not reimplement.
  assert.ok(m >= 1 && m <= 16 && xonlyKeys.length <= 16, "reference builder covers 1..16 keys only");
  const out = [];
  xonlyKeys.forEach((key, index) => {
    out.push(0x20, ...key, index === 0 ? 0xac : 0xba); // OP_CHECKSIG, then OP_CHECKSIGADD
  });
  out.push(0x50 + m, 0x9c); // OP_m OP_NUMEQUAL
  return new Uint8Array(out);
}
function referenceAddress(m, keys, network, kind) {
  const net = NETS[network];
  const bytewise = (a, b) => {
    for (let index = 0; index < Math.min(a.length, b.length); index++) if (a[index] !== b[index]) return a[index] - b[index];
    return a.length - b.length;
  };
  if (kind === "p2tr") {
    // hodlMsigAddr sorts the 32-byte x-only keys (no prefix byte).
    const xonly = keys.map((key) => key.slice(1)).sort(bytewise);
    const leaf = trLeafMultisig(m, xonly);
    return p2tr(NUMS, { script: leaf, leafVersion: 0xc0 }, net).address;
  }
  // Legacy kinds sort the 33-byte compressed keys, as BIP67 does.
  const sorted = [...keys].sort(bytewise);
  const ms = bareMultisig(m, sorted);
  if (kind === "p2sh") return p2sh({ script: ms }, net).address;
  if (kind === "p2wsh") return p2wsh({ script: ms }, net).address;
  const wsh = new Uint8Array([0x00, 0x20, ...sha256(ms)]);
  return p2sh({ script: wsh }, net).address; // p2sh-p2wsh
}

test("multisig addresses match @scure/btc-signer exactly, every kind and network", () => {
  for (const [network, expectations] of Object.entries({
    mainnet: {
      p2sh: "33hG2q39jRi2NqicRJB4ggY1J8EJm97Szz",
      p2wsh: "bc1qztp0l0rwc8846ardl02fkyrrx43p96j47scz8l7qz3vnfteqc4eqtfqwcm",
      "p2sh-p2wsh": "3L3mWb3pAZfMACpEjSEcmDWnsyHqt4yJym",
      p2tr: "bc1pm5jn9xnjz3v9xm7jjw2yheajy92pps5fdazdpfnmvzfymu787hhs2vktyy",
    },
    testnet: {
      p2sh: "2MuFU6ZyBLtDNadMA6RnwJdXGWUSUaoKLeS",
      p2wsh: "tb1qztp0l0rwc8846ardl02fkyrrx43p96j47scz8l7qz3vnfteqc4equpkpz5",
      "p2sh-p2wsh": "2NBbyaKyqn2AhMzSnQZrVPAW46KW1it9v7r",
      p2tr: "tb1pm5jn9xnjz3v9xm7jjw2yheajy92pps5fdazdpfnmvzfymu787hhsayqy7t",
    },
  })) {
    for (const kind of KINDS) {
      const reference = referenceAddress(2, pubkeys, network, kind);
      assert.equal(reference, expectations[kind], `${kind} on ${network}: reference builder drifted`);
      assert.equal(hodlMsigAddr(pubkeys, 2, network, kind).address, reference, `${kind} on ${network}: app disagrees with btc-signer`);
    }
  }
});

test("every threshold m-of-n derives the btc-signer address (n up to 7)", () => {
  const keys = Array.from({ length: 7 }, (_, index) => {
    const secret = new Uint8Array(32);
    secret[31] = index + 1;
    return secp256k1.getPublicKey(secret, true);
  });
  for (const network of ["mainnet", "testnet"]) {
    for (const kind of KINDS) {
      for (let n = 1; n <= keys.length; n++) {
        for (let m = 1; m <= n; m++) {
          const ours = hodlMsigAddr(keys.slice(0, n), m, network, kind).address;
          assert.equal(ours, referenceAddress(m, keys.slice(0, n), network, kind), `${m}-of-${n} ${kind} on ${network}`);
        }
      }
    }
  }
});

test("the UI maximum (15-of-15) derives on every kind", () => {
  const keys = Array.from({ length: 15 }, (_, index) => {
    const secret = new Uint8Array(32);
    secret[30] = index + 1; // keep keys distinct and low (16-bit)
    return secp256k1.getPublicKey(secret, true);
  });
  for (const kind of KINDS) {
    const ours = hodlMsigAddr(keys, 15, "mainnet", kind).address;
    assert.equal(ours, referenceAddress(15, keys, "mainnet", kind), `15-of-15 ${kind}`);
  }
});

test("unsorted derivation matches btc-signer given the same key order", () => {
  const reversed = [...pubkeys].reverse();
  const ms = bareMultisig(2, reversed);
  const wsh = new Uint8Array([0x00, 0x20, ...sha256(ms)]);
  const leaf = trLeafMultisig(2, reversed.map((key) => key.slice(1)));
  const expectations = {
    p2sh: p2sh({ script: ms }, NETWORK).address,
    p2wsh: p2wsh({ script: ms }, NETWORK).address,
    "p2sh-p2wsh": p2sh({ script: wsh }, NETWORK).address,
    p2tr: p2tr(NUMS, { script: leaf, leafVersion: 0xc0 }, NETWORK).address,
  };
  for (const kind of KINDS) {
    assert.equal(hodlMsigAddr(reversed, 2, "mainnet", kind, false).address, expectations[kind], `unsorted ${kind}`);
  }
});
