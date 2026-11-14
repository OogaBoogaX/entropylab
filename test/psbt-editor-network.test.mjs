// The PSBT editor reads the header picker's network through the getter app.js
// hands it at boot. hodlNetworkDefault maps every non-mainnet choice to
// testnet, so an editor wired to it renders tb1 under a regtest header and
// refuses a valid bcrt1 output. These tests pin the getter and the builder's
// regtest decoding.
// Run with `npm test`.
import { test } from "node:test";
import assert from "node:assert/strict";
import { bech32 } from "@scure/base";
import { buildOutputScript } from "../src/js/script-builder.js";
import { loadAppFunctions } from "./app-slice-harness.mjs";

const HASH160 = new Uint8Array(20).fill(0x11);
// A regtest P2WPKH address from an independently encoded reference (scure's
// bech32), not from the app's own address builder.
const BCRT = bech32.encode("bcrt", [0, ...bech32.toWords(HASH160)]);

test("hodlInspectorNetwork reports regtest as regtest and keeps the other choices", async () => {
  const app = await loadAppFunctions(["hodlInspectorNetwork"], { settable: ["hodlNetworkChoice", "hodlNetworkDefault"] });
  app.__set.hodlNetworkDefault("mainnet");
  app.__set.hodlNetworkChoice("mainnet");
  assert.equal(app.hodlInspectorNetwork(), "mainnet");
  app.__set.hodlNetworkChoice("regtest");
  assert.equal(app.hodlInspectorNetwork(), "regtest");
  app.__set.hodlNetworkDefault("testnet");
  app.__set.hodlNetworkChoice("signet");
  assert.equal(app.hodlInspectorNetwork(), "testnet");
});

test("the script builder decodes a regtest address only on regtest", () => {
  assert.equal(buildOutputScript(BCRT, { network: "regtest" }).scriptHex, "0014" + "11".repeat(20));
  assert.throws(() => buildOutputScript(BCRT, { network: "testnet" }), /does not decode on testnet/);
  assert.throws(() => buildOutputScript(BCRT, { network: "mainnet" }), /does not decode on mainnet/);
});
