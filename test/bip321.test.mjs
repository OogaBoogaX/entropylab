// BIP-321 URI / BIP-353 TXT helper for Silent Payments.
// Run with `npm test` (part of the default suite).
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  bip353Lookup,
  encodeBip353Txt,
  encodeBitcoinUri,
  parseBitcoinUri,
  parseRecipientLine,
  parseRecipientLines,
} from "../src/js/bip321.js";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const read = (path) => readFileSync(join(root, path), "utf8");
const SP = "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv";
const URI = `bitcoin:?sp=${SP}`;

test("a silent payment address prints as bitcoin:?sp=…", () => {
  assert.equal(encodeBitcoinUri(SP), URI);
  assert.equal(encodeBip353Txt(SP), URI);
  assert.equal(encodeBitcoinUri(SP.toUpperCase()), URI);
});

test("a truncated or on-chain address is refused as an SP URI", () => {
  assert.throws(() => encodeBitcoinUri("sp1q"), /Not a silent payment address/);
  assert.throws(() => encodeBitcoinUri("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"), /Not a silent payment address/);
});

test("parseBitcoinUri reads sp=, ignores Lightning, fails closed on req-", () => {
  const parsed = parseBitcoinUri(`${URI}&lno=lno1ignored&amount=0.01`);
  assert.deepEqual(parsed.silentPayments, [SP]);
  assert.equal(parsed.lightning, true);
  assert.equal(parsed.amount, "0.01");
  assert.equal(parseBitcoinUri("bitcoin://?sp=" + SP).silentPayments[0], SP);
  assert.equal(parseBitcoinUri("BITCOIN:?SP=" + SP).silentPayments[0], SP);
  assert.throws(() => parseBitcoinUri("bitcoin:?req-pop=https://example.com"), /Unsupported required URI parameter: req-pop/);
  assert.equal(parseBitcoinUri("https://example.com/?sp=" + SP), null);
});

test("parseBitcoinUri keeps every sp= value", () => {
  const other = SP.replace("sp1qqgste", "sp1qqgsta");
  const parsed = parseBitcoinUri(`bitcoin:?sp=${SP}&sp=${other}`);
  assert.deepEqual(parsed.silentPayments, [SP, other]);
});

test("a bitcoin: URI without sp= is not a silent-payment instruction", () => {
  assert.deepEqual(parseBitcoinUri("bitcoin:bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4?amount=1").silentPayments, []);
  assert.throws(() => parseRecipientLine("bitcoin:bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"), /No silent payment \(sp=\)/);
});

test("recipient lines accept a raw code, a URI, and a trailing count", () => {
  assert.deepEqual(parseRecipientLine(SP), [{ address: SP, count: 1, lightning: false }]);
  assert.deepEqual(parseRecipientLine(`${SP} 2`), [{ address: SP, count: 2, lightning: false }]);
  assert.deepEqual(parseRecipientLine(URI), [{ address: SP, count: 1, lightning: false }]);
  assert.deepEqual(parseRecipientLine(`${URI} 3`), [{ address: SP, count: 3, lightning: false }]);
  const mixed = parseRecipientLines(`${URI}\n${SP} 2`);
  assert.deepEqual(mixed.recipients, [
    { address: SP, count: 1 },
    { address: SP, count: 2 },
  ]);
  assert.equal(mixed.lightning, false);
});

test("a Lightning parameter is noted and then ignored", () => {
  const row = parseRecipientLine(`bitcoin:?sp=${SP}&lightning=lnbc1ignored`);
  assert.equal(row[0].address, SP);
  assert.equal(row[0].lightning, true);
  assert.equal(parseRecipientLines(`bitcoin:?sp=${SP}&lno=lno1x`).lightning, true);
});

test("a payment name is not resolved", () => {
  assert.throws(
    () => parseRecipientLine("steve@silentpayments.net"),
    /does not resolve DNS/,
  );
  assert.throws(
    () => parseRecipientLine("you@example.com"),
    /does not resolve DNS/,
  );
});

test("BIP-353 lookup names stay on the user's domain", () => {
  // matt@mattcorallo.com → matt.user._bitcoin-payment.mattcorallo.com (BIP-353).
  assert.deepEqual(bip353Lookup("you@example.com"), {
    name: "you@example.com",
    lookup: "you.user._bitcoin-payment.example.com",
  });
  assert.deepEqual(bip353Lookup("₿You@Example.COM"), {
    name: "You@Example.COM",
    lookup: "you.user._bitcoin-payment.example.com",
  });
  assert.equal(bip353Lookup(""), null);
  assert.throws(() => bip353Lookup("Example.COM"), /needs a user part/);
  assert.throws(() => bip353Lookup("not a name"), /cannot contain spaces/);
  assert.throws(() => bip353Lookup(URI), /URI, not a payment name/);
});

test("the module never talks to the network, browser storage, or a CSPRNG", () => {
  const src = read("src/js/bip321.js");
  assert.doesNotMatch(src, /\bfetch\s*\(/);
  assert.doesNotMatch(src, /\bWebSocket\b/);
  assert.doesNotMatch(src, /\blocalStorage\b/);
  assert.doesNotMatch(src, /\bsessionStorage\b/);
  assert.doesNotMatch(src, /\bindexedDB\b/);
  assert.doesNotMatch(src, /\bgetRandomValues\b/);
  assert.doesNotMatch(src, /\bMath\.random\b/);
});

test("the Silent Payments tab prints the URI and accepts it on send", () => {
  const app = read("src/js/app.js");
  const shell = read("src/shell.html");
  assert.match(app, /from "\.\/bip321\.js"/);
  assert.match(app, /encodeBitcoinUri/);
  assert.match(app, /parseRecipientLines/);
  assert.match(app, /id="sp-bip321-uri"/);
  assert.match(app, /id="sp-bip353-txt"/);
  assert.match(app, /does not resolve DNS/);
  assert.match(shell, /id="sp-payname"/);
  assert.match(shell, /bitcoin:\?sp=/);
});
