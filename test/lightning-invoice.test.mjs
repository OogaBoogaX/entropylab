// Tests for the Lightning invoice/offer card (#ln-inv-card): the shell
// markup, BOLT11 and BOLT12 rendering, the payment-secret reveal, the
// wrong-chain banner, escaping, refusals, clearing, and the QR wiring.
// Run with `npm test`.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { toWords } from "../src/js/bech32.js";
import { hex } from "../src/js/coders.js";
import { secp256k1Ready } from "../src/js/secp256k1.js";
import { hodlInitLn, hodlLnWipeMem, lnInvNetworkName, hodlLnInvRenderResult } from "../src/js/lightning.js";
import { bolt11Decode } from "../src/js/bolt11.js";
import { MiniDocument } from "./mini-dom.mjs";

await secp256k1Ready;

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const read = (path) => readFileSync(join(root, path), "utf8");
const shell = read("src/shell.html");
const appSource = read("src/js/app.js");

// BOLT11 spec example: "Please send $3 for a cup of coffee to the same peer,
// within one minute". Node id, payment hash and secret are the spec's
// published values (test/bolt11.test.mjs).
const COFFEE = "lnbc2500u1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq5xysxxatsyp3k7enxv4jsxqzpu9qrsgquk0rl77nj30yxdy8j9vdx85fkpmdla2087ne0xh8nhedh8w27kyke0lp53ut353s06fv3qfegext0eh0ymjpf39tuven09sam30g4vgpfna3rh";
const COFFEE_NODE_ID = "03e7156ae33b0a208d0744199163177e909e80176e55d97a2f221ede0f934dd9ad";
const COFFEE_PAYMENT_HASH = "0001020304050607080900010203040506070809000102030405060708090102";
const COFFEE_SECRET = "1111111111111111111111111111111111111111111111111111111111111111";

// BOLT11 spec example: the corrupted-checksum invoice (test/bolt11.test.mjs).
const BAD_CHECKSUM = "lnbc2500u1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpquwpc4curk03c9wlrswe78q4eyqc7d8d0xqzpuyk0sg5g70me25alkluzd2x62aysf2pyy8edtjeevuv4p2d5p76r4zkmneet7uvyakky2zr4cusd45tftc9c5fh0nnqpnl2jfll544esqchsrnt";

// BOLT12 spec offer (test/bolt12.test.mjs): amount, description, issuer id.
const OFFER = "lno1pqps7sjqpgtyzm3qv4uxzmtsd3jjqer9wd3hy6tsw35k7msjzfpy7nz5yqcnygrfdej82um5wf5k2uckyypwa3eyt44h6txtxquqh7lz5djge4afgfjn7k4rgrkuag0jsd5xvxg";

// BOLT12 spec offer with one blinded path (test/bolt12.test.mjs).
const OFFER_ONE_PATH = "lno1pgx9getnwss8vetrw3hhyucs5ypjgef743p5fzqq9nqxh0ah7y87rzv3ud0eleps9kl2d5348hq2k8qzqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgqpqqqqqqqqqqqqqqqqqqqqqqqqqqqzqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqqzq3zyg3zyg3zyg3vggzamrjghtt05kvkvpcp0a79gmy3nt6jsn98ad2xs8de6sl9qmgvcvs";

// BOLT12 spec testnet offer (test/bolt12.test.mjs): chains = [testnet].
const OFFER_TESTNET = "lno1qgsyxjtl6luzd9t3pr62xr7eemp6awnejusgf6gw45q75vcfqqqqqqq2p32x2um5ypmx2cm5dae8x93pqthvwfzadd7jejes8q9lhc4rvjxd022zv5l44g6qah82ru5rdpnpj";

const PUBKEY = "02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619";

// The BIP39 test vector (test/lightning.test.mjs): a valid mnemonic for the
// derive-survives test.
const BIP39_VECTOR_WORDS = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

// A checksum-free BOLT12 encoder (the envelope has no checksum), so a
// description can carry attacker-controlled markup.
const BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const bech32Polymod = (values) => {
  const generator = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
  let checksum = 1;
  for (const value of values) {
    const top = checksum >>> 25;
    checksum = ((checksum & 0x1ffffff) << 5) ^ value;
    for (let i = 0; i < 5; i++) if ((top >>> i) & 1) checksum ^= generator[i];
  }
  return checksum;
};
const bech32Encode = (hrp, data) => {
  const expanded = [];
  for (const char of hrp) expanded.push(char.charCodeAt(0) >> 5);
  expanded.push(0);
  for (const char of hrp) expanded.push(char.charCodeAt(0) & 31);
  const mod = bech32Polymod([...expanded, ...data, 0, 0, 0, 0, 0, 0]) ^ 1;
  const checksum = [];
  for (let i = 0; i < 6; i++) checksum.push((mod >>> (5 * (5 - i))) & 31);
  return `${hrp}1${[...data, ...checksum].map((value) => BECH32_CHARSET[value]).join("")}`;
};
const bigsize = (n) => {
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
const ESCAPE_OFFER = encode("lno", [
  [10, hex.encode(new TextEncoder().encode("<img src=x>"))],
  [22, PUBKEY],
]);

// The BOLT11 spec's amountless form: the same data part as COFFEE with the
// amount removed from the HRP. The test's own bech32 encoder (validated
// against BIP173 in test/lightning.test.mjs) recomputes the checksum, so the
// expected invoice does not come from the code under test.
const AMOUNTLESS_COFFEE = (() => {
  const sep = COFFEE.indexOf("1");
  const data = [...COFFEE.slice(sep + 1, -6)].map((c) => BECH32_CHARSET.indexOf(c));
  return bech32Encode("lnbc", data);
})();

// BOLT12 offer_chains are the genesis block hash in internal byte order
// (reversed from the displayed hash), per BOLT12 12-offer-encoding.md.
// Signet: 00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6
// Regtest: 0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206
const SIGNET_CHAIN = "f61eee3b63a380a477a063af32b2bbc97c9ff9f01f2c4225e973988108000000";
const REGTEST_CHAIN = "06226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f";
const OFFER_SIGNET = encode("lno", [[2, SIGNET_CHAIN], [10, hex.encode(new TextEncoder().encode("signet offer"))], [22, PUBKEY]]);
const OFFER_REGTEST = encode("lno", [[2, REGTEST_CHAIN], [10, hex.encode(new TextEncoder().encode("regtest offer"))], [22, PUBKEY]]);

// The invoice card wired over a mini DOM. `#ln-go` is absent, so the node
// identity card is not initialized; the invoice card must still wire.
function invPage(network = "mainnet", qrSvg = () => "") {
  const page = new MiniDocument();
  globalThis.document = page;
  // The full Lightning card: the node identity controls are needed so
  // hodlInitLn wires the format/network change handlers and the derive path
  // that the invoice-survival tests exercise.
  page.body.innerHTML = '<select id="ln-format"><option value="aezeed" selected>aezeed · LND cipher seed</option><option value="bip39">BIP-39 · LDK (ldk-node)</option></select>'
    + '<div id="ln-network-field"><select id="ln-network"><option value="mainnet" selected>Mainnet</option><option value="testnet">Testnet</option></select></div>'
    + '<textarea id="ln-seed"></textarea><input id="ln-pass" type="password">'
    + '<button id="ln-go" type="button"></button><button id="ln-wipe" type="button"></button>'
    + '<p id="ln-session"></p><p id="ln-error"></p><div id="ln-out"></div>'
    + '<span id="ln-seed-help"></span>'
    + '<textarea id="ln-inv-input"></textarea>'
    + '<button id="ln-inv-decode" type="button"></button>'
    + '<button id="ln-inv-clear" type="button"></button>'
    + '<p id="ln-inv-error" class="err" role="alert"></p>'
    + '<div id="ln-inv-out" aria-live="polite"></div>';
  // The page network is the app's (hodlInspectorNetwork), not the LND
  // coin-type select: inject it the way app.js does.
  hodlInitLn({ journalLog() {}, copyIcon: () => "", qrSvg, pageNetwork: typeof network === "function" ? network : () => network });
  hodlLnWipeMem();
  return page;
}

const decode = (page, text) => {
  page.getElementById("ln-inv-input").value = text;
  page.getElementById("ln-inv-decode").click();
};

test("the invoice card ships in the shell after #ln-card, with its controls", () => {
  const order = ["ln-card", "ln-inv-card", "ln-inv-input", "ln-inv-decode", "ln-inv-clear", "ln-inv-error", "ln-inv-out"];
  let last = -1;
  for (const id of order) {
    const at = shell.indexOf(`id="${id}"`);
    assert.ok(at >= 0, `${id} is missing from the shell`);
    assert.ok(at > last, `${id} is out of order`);
    last = at;
  }
  const cardTag = shell.match(/<section[^>]*id="ln-inv-card"[^>]*>/)?.[0] || "";
  assert.ok(!/role="tabpanel"/.test(cardTag), "the card must not be a nested tabpanel");
  assert.ok(!/\shidden[\s>]/.test(cardTag), "the card must not carry hidden");
  assert.match(shell, /id="ln-inv-error"[^>]*role="alert"/);
  assert.match(shell, /id="ln-inv-out"[^>]*aria-live="polite"/);
});

test("a BOLT11 invoice renders amount, payment hash, node id, and the signature state", () => {
  const page = invPage();
  try {
    decode(page, COFFEE);
    const out = page.getElementById("ln-inv-out");
    assert.equal(page.getElementById("ln-inv-error").textContent, "");
    const html = out.innerHTML;
    assert.ok(html.includes("0.0025"), "amount in BTC");
    assert.ok(html.includes("250000000"), "amount in msat");
    assert.ok(html.includes(COFFEE_PAYMENT_HASH), "payment hash");
    assert.ok(html.includes(COFFEE_NODE_ID), "recovered node id");
    assert.ok(out.querySelector('[data-ln-inv-state="signature"]'), "signature state line");
    assert.ok(html.includes('id="ln-inv-payment-hash"'), "payment hash copy button");
    assert.ok(html.includes('id="ln-inv-node-id"'), "node id copy button");
  } finally {
    delete globalThis.document;
  }
});

test("the payment secret stays hidden until #ln-inv-reveal is checked", () => {
  const page = invPage();
  try {
    decode(page, COFFEE);
    const out = page.getElementById("ln-inv-out");
    assert.ok(!out.textContent.includes(COFFEE_SECRET), "the secret is not rendered before reveal");
    const reveal = page.getElementById("ln-inv-reveal");
    assert.ok(reveal, "the reveal checkbox is rendered");
    reveal.checked = true;
    reveal.dispatchEvent({ type: "change" });
    assert.ok(out.textContent.includes(COFFEE_SECRET), "the secret is rendered after reveal");
    assert.ok(out.innerHTML.includes('id="ln-inv-payment-secret"'), "secret copy button");
  } finally {
    delete globalThis.document;
  }
});

test("a BOLT12 offer renders the offer kind, the published-key warning, and the signature state", () => {
  const page = invPage();
  try {
    decode(page, OFFER);
    const out = page.getElementById("ln-inv-out");
    assert.equal(page.getElementById("ln-inv-error").textContent, "");
    assert.ok(out.querySelector('[data-ln-inv-kind="offer"]'), "kind is offer");
    assert.ok(out.querySelector('[data-ln-inv-state="signature"]'), "signature state line");
    assert.ok(out.querySelector('[data-ln-inv-warning="published-key"]'), "published-key warning");
    assert.ok(out.innerHTML.includes('id="ln-inv-issuer-id"'), "issuer id copy button");
  } finally {
    delete globalThis.document;
  }
});

test("a blinded BOLT12 offer is marked blinded", () => {
  const page = invPage();
  try {
    decode(page, OFFER_ONE_PATH);
    const out = page.getElementById("ln-inv-out");
    assert.equal(page.getElementById("ln-inv-error").textContent, "");
    assert.ok(out.querySelector('[data-ln-inv-visibility="blinded"]'), "blinded visibility");
  } finally {
    delete globalThis.document;
  }
});

test("a testnet offer on a mainnet page shows the chain warning and still decodes", () => {
  const page = invPage("mainnet");
  try {
    decode(page, OFFER_TESTNET);
    const out = page.getElementById("ln-inv-out");
    assert.equal(page.getElementById("ln-inv-error").textContent, "");
    const warning = out.querySelector('[data-ln-inv-warning="chain"]');
    assert.ok(warning, "chain warning");
    assert.ok(warning.textContent.includes("testnet"), "names the invoice's chain");
    assert.ok(warning.textContent.includes("mainnet"), "names the page network");
    assert.ok(out.querySelector('[data-ln-inv-kind="offer"]'), "still decoded");
  } finally {
    delete globalThis.document;
  }
});

test("a mainnet BOLT11 invoice on a testnet page shows the network warning and still decodes", () => {
  const page = invPage("testnet");
  try {
    decode(page, COFFEE);
    const out = page.getElementById("ln-inv-out");
    assert.equal(page.getElementById("ln-inv-error").textContent, "");
    const warning = out.querySelector('[data-ln-inv-warning="network"]');
    assert.ok(warning, "network warning");
    assert.ok(warning.textContent.includes("mainnet"), "names the invoice's network");
    assert.ok(out.innerHTML.includes(COFFEE_PAYMENT_HASH), "still decoded");
  } finally {
    delete globalThis.document;
  }
});

test("a matching-chain BOLT11 invoice shows no network warning", () => {
  const page = invPage("mainnet");
  try {
    decode(page, COFFEE);
    const out = page.getElementById("ln-inv-out");
    assert.equal(page.getElementById("ln-inv-error").textContent, "");
    assert.equal(out.querySelector('[data-ln-inv-warning="network"]'), null, "a mainnet invoice on a mainnet page must not warn");
    assert.ok(out.innerHTML.includes(COFFEE_PAYMENT_HASH), "still decoded");
  } finally {
    delete globalThis.document;
  }
});

test("a matching-chain BOLT12 offer shows no chain warning", () => {
  const page = invPage("testnet");
  try {
    decode(page, OFFER_TESTNET);
    const out = page.getElementById("ln-inv-out");
    assert.equal(page.getElementById("ln-inv-error").textContent, "");
    assert.equal(out.querySelector('[data-ln-inv-warning="chain"]'), null, "a testnet offer on a testnet page must not warn");
    assert.ok(out.querySelector('[data-ln-inv-kind="offer"]'), "still decoded");
  } finally {
    delete globalThis.document;
  }
});

test("signet and regtest are not treated as mainnet", () => {
  const signet = invPage("signet");
  try {
    decode(signet, OFFER_SIGNET);
    assert.equal(signet.getElementById("ln-inv-error").textContent, "");
    assert.equal(signet.getElementById("ln-inv-out").querySelector('[data-ln-inv-warning="chain"]'), null, "a signet offer on a signet page must not warn");
  } finally {
    delete globalThis.document;
  }
  const mainnet = invPage("mainnet");
  try {
    decode(mainnet, OFFER_SIGNET);
    const out = mainnet.getElementById("ln-inv-out");
    const warning = out.querySelector('[data-ln-inv-warning="chain"]');
    assert.ok(warning, "a signet offer on a mainnet page must warn");
    assert.ok(warning.textContent.includes("signet"), "names the offer's chain");
    assert.ok(warning.textContent.includes("mainnet"), "names the page network");
  } finally {
    delete globalThis.document;
  }
  const regtest = invPage("regtest");
  try {
    decode(regtest, OFFER_REGTEST);
    assert.equal(regtest.getElementById("ln-inv-error").textContent, "");
    assert.equal(regtest.getElementById("ln-inv-out").querySelector('[data-ln-inv-warning="chain"]'), null, "a regtest offer on a regtest page must not warn");
  } finally {
    delete globalThis.document;
  }
});

test("without an injected page network the card compares against mainnet", () => {
  const page = new MiniDocument();
  globalThis.document = page;
  page.body.innerHTML = '<textarea id="ln-inv-input"></textarea>'
    + '<button id="ln-inv-decode" type="button"></button>'
    + '<button id="ln-inv-clear" type="button"></button>'
    + '<p id="ln-inv-error" class="err" role="alert"></p>'
    + '<div id="ln-inv-out" aria-live="polite"></div>';
  hodlInitLn({ journalLog() {}, copyIcon: () => "" });
  try {
    decode(page, COFFEE);
    assert.equal(page.getElementById("ln-inv-out").querySelector('[data-ln-inv-warning="network"]'), null, "a mainnet invoice must not warn on the default network");
  } finally {
    delete globalThis.document;
  }
});

test("an attacker-controlled description is escaped as text, not markup", () => {
  const page = invPage();
  try {
    decode(page, ESCAPE_OFFER);
    const out = page.getElementById("ln-inv-out");
    assert.equal(page.getElementById("ln-inv-error").textContent, "");
    assert.equal(out.querySelector("img"), null, "no element was created from the description");
    assert.ok(out.textContent.includes("<img src=x>"), "the description is shown as text");
  } finally {
    delete globalThis.document;
  }
});

test("a corrupted checksum shows a keyed error, no rows, and no echo of the input", () => {
  const page = invPage();
  try {
    decode(page, BAD_CHECKSUM);
    const error = page.getElementById("ln-inv-error").textContent;
    assert.ok(error.length > 0, "an error is shown");
    assert.ok(!error.includes(BAD_CHECKSUM), "the input is never echoed");
    assert.equal(page.getElementById("ln-inv-out").innerHTML, "", "no rows are rendered");
  } finally {
    delete globalThis.document;
  }
});

test("Clear empties the input, the output, the error, and the reveal state", () => {
  const page = invPage();
  try {
    decode(page, COFFEE);
    const reveal = page.getElementById("ln-inv-reveal");
    reveal.checked = true;
    reveal.dispatchEvent({ type: "change" });
    assert.ok(page.getElementById("ln-inv-out").innerHTML.length > 0);
    page.getElementById("ln-inv-clear").click();
    assert.equal(page.getElementById("ln-inv-input").value, "");
    assert.equal(page.getElementById("ln-inv-out").innerHTML, "");
    assert.equal(page.getElementById("ln-inv-error").textContent, "");
    // The reveal state is reset: decoding again hides the secret.
    decode(page, COFFEE);
    assert.ok(!page.getElementById("ln-inv-out").textContent.includes(COFFEE_SECRET));
  } finally {
    delete globalThis.document;
  }
});

test("decoding keeps the pasted invoice in the field", () => {
  const page = invPage();
  try {
    decode(page, COFFEE);
    assert.equal(page.getElementById("ln-inv-input").value, COFFEE, "the decode must not empty the field");
  } finally {
    delete globalThis.document;
  }
});

test("hodlLnWipeMem clears the pasted invoice, the output, and the error", () => {
  const page = invPage();
  try {
    decode(page, COFFEE);
    assert.equal(page.getElementById("ln-inv-input").value, COFFEE, "the pasted invoice is in the field");
    assert.ok(page.getElementById("ln-inv-out").innerHTML.length > 0);
    hodlLnWipeMem();
    assert.equal(page.getElementById("ln-inv-input").value, "", "the pasted invoice is gone");
    assert.equal(page.getElementById("ln-inv-out").innerHTML, "");
    assert.equal(page.getElementById("ln-inv-error").textContent, "");
  } finally {
    delete globalThis.document;
  }
});

test("a decoded invoice survives a format change", () => {
  const page = invPage();
  try {
    decode(page, COFFEE);
    assert.ok(page.getElementById("ln-inv-out").innerHTML.includes(COFFEE_PAYMENT_HASH));
    const format = page.getElementById("ln-format");
    format.value = "bip39";
    format.dispatchEvent({ type: "change" });
    assert.ok(page.getElementById("ln-inv-out").innerHTML.includes(COFFEE_PAYMENT_HASH), "the invoice survives a format change");
    assert.equal(page.getElementById("ln-inv-input").value, COFFEE, "the pasted invoice survives a format change");
  } finally {
    delete globalThis.document;
  }
});

test("a decoded invoice survives a network change and is re-rendered", () => {
  let qrCalls = 0;
  const page = invPage("mainnet", () => {
    qrCalls++;
    return '<svg id="qr-test"></svg>';
  });
  try {
    decode(page, COFFEE);
    assert.equal(qrCalls, 1, "the QR is rendered once on decode");
    const network = page.getElementById("ln-network");
    network.value = "testnet";
    network.dispatchEvent({ type: "change" });
    assert.ok(page.getElementById("ln-inv-out").innerHTML.includes(COFFEE_PAYMENT_HASH), "the invoice survives a network change");
    assert.equal(qrCalls, 2, "the invoice card is re-rendered after the network change");
  } finally {
    delete globalThis.document;
  }
});

test("a page network change re-renders the invoice card's warning", () => {
  let network = "mainnet";
  const page = invPage(() => network);
  try {
    decode(page, COFFEE);
    assert.equal(page.getElementById("ln-inv-out").querySelector('[data-ln-inv-warning="network"]'), null, "no warning on mainnet");
    network = "testnet";
    page.dispatchEvent(new Event("hodl:network-default"));
    const warning = page.getElementById("ln-inv-out").querySelector('[data-ln-inv-warning="network"]');
    assert.ok(warning, "the warning follows the page network");
  } finally {
    delete globalThis.document;
  }
});

test("the invoice card's copy controls use the shared clipboard pattern", () => {
  const page = invPage();
  try {
    decode(page, COFFEE);
    const out = page.getElementById("ln-inv-out");
    assert.equal(out.querySelector('[data-copy]'), null, "a hand-made data-copy button is still rendered");
    assert.ok(out.querySelector('[data-public-value]'), "the public values do not use the shared copy pattern");
    assert.ok(out.querySelector('[data-copy-field]'), "the public values do not use the shared copy field");
    const reveal = page.getElementById("ln-inv-reveal");
    reveal.checked = true;
    reveal.dispatchEvent(new Event("change"));
    assert.ok(out.querySelector('[data-private-value]'), "the payment secret is not on the private-value pattern");
    assert.equal(out.querySelector('[data-copy]'), null, "the payment secret still uses a hand-made data-copy button");
  } finally {
    delete globalThis.document;
  }
});

test("an amountless invoice renders the payer-chooses amount for null and undefined", () => {
  const page = invPage();
  try {
    const decoded = bolt11Decode(AMOUNTLESS_COFFEE);
    assert.ok(decoded.amountMsat === null || decoded.amountMsat === undefined, "the decoder reports no amount");
    // Both shapes take the same no-amount branch: identical output, and no
    // "null", "undefined" or "NaN" formatted as an amount.
    const rendered = [null, undefined].map((amountMsat) => {
      hodlLnInvRenderResult({ ...decoded, amountMsat, text: AMOUNTLESS_COFFEE });
      return page.getElementById("ln-inv-out").innerHTML;
    });
    assert.equal(rendered[0], rendered[1], "null and undefined amounts render differently");
    assert.doesNotMatch(page.getElementById("ln-inv-out").textContent, /\b(?:null|undefined|NaN)\b/, "a missing amount was formatted as a value");
  } finally {
    delete globalThis.document;
  }
});

test("a decoded invoice survives a derive", () => {
  const page = invPage();
  try {
    decode(page, COFFEE);
    page.getElementById("ln-format").value = "bip39";
    page.getElementById("ln-seed").value = BIP39_VECTOR_WORDS;
    page.getElementById("ln-go").onclick();
    assert.equal(page.getElementById("ln-error").textContent, "", "the derive reported an error");
    assert.ok(page.getElementById("ln-inv-out").innerHTML.includes(COFFEE_PAYMENT_HASH), "the invoice survives a derive");
  } finally {
    delete globalThis.document;
  }
});

test("a chainless BOLT12 offer is mainnet: it warns on a testnet page", () => {
  const page = invPage("testnet");
  try {
    decode(page, OFFER);
    const out = page.getElementById("ln-inv-out");
    assert.equal(page.getElementById("ln-inv-error").textContent, "");
    assert.ok(out.querySelector('[data-ln-inv-warning="chain"]'), "a chainless offer on a testnet page must warn");
  } finally {
    delete globalThis.document;
  }
});

test("a chainless BOLT12 offer is mainnet: it does not warn on a mainnet page", () => {
  const page = invPage("mainnet");
  try {
    decode(page, OFFER);
    const out = page.getElementById("ln-inv-out");
    assert.equal(page.getElementById("ln-inv-error").textContent, "");
    assert.equal(out.querySelector('[data-ln-inv-warning="chain"]'), null, "a chainless offer on a mainnet page must not warn");
  } finally {
    delete globalThis.document;
  }
});

test("a BOLT12 offer that lists testnet does not warn on a testnet page", () => {
  const page = invPage("testnet");
  try {
    decode(page, OFFER_TESTNET);
    const out = page.getElementById("ln-inv-out");
    assert.equal(page.getElementById("ln-inv-error").textContent, "");
    assert.equal(out.querySelector('[data-ln-inv-warning="chain"]'), null, "a testnet offer on a testnet page must not warn");
  } finally {
    delete globalThis.document;
  }
});

test("a signet offer on a testnet page warns (signet is not testnet)", () => {
  const page = invPage("testnet");
  try {
    decode(page, OFFER_SIGNET);
    const out = page.getElementById("ln-inv-out");
    assert.ok(out.querySelector('[data-ln-inv-warning="chain"]'), "a signet offer on a testnet page must warn");
  } finally {
    delete globalThis.document;
  }
});

test("a regtest offer on a testnet page warns (regtest is not testnet)", () => {
  const page = invPage("testnet");
  try {
    decode(page, OFFER_REGTEST);
    const out = page.getElementById("ln-inv-out");
    assert.ok(out.querySelector('[data-ln-inv-warning="chain"]'), "a regtest offer on a testnet page must warn");
  } finally {
    delete globalThis.document;
  }
});

test("the BOLT11 network comparison uses the page's vocabulary", () => {
  // The decoder and the page must agree on the network names. The page
  // vocabulary is mainnet/testnet/signet/regtest; the decoder may return an
  // alias (bitcoin, bc, tb, tbs, bcrt), which must normalize to the same.
  for (const [alias, expected] of [
    ["mainnet", "mainnet"],
    ["bitcoin", "mainnet"],
    ["bc", "mainnet"],
    ["testnet", "testnet"],
    ["tb", "testnet"],
    ["signet", "signet"],
    ["tbs", "signet"],
    ["regtest", "regtest"],
    ["bcrt", "regtest"],
  ]) {
    assert.equal(lnInvNetworkName(alias), expected, `${alias} normalizes to ${expected}`);
  }
  // Signet and regtest are not testnet: a signet or regtest invoice must
  // warn on a testnet page.
  assert.notEqual(lnInvNetworkName("signet"), "testnet");
  assert.notEqual(lnInvNetworkName("regtest"), "testnet");
});

test("the QR block renders the user's own pasted string", () => {
  let seen = null;
  const page = invPage("mainnet", (text) => {
    seen = text;
    return '<svg id="qr-test"></svg>';
  });
  try {
    decode(page, COFFEE);
    assert.equal(seen, COFFEE, "the QR input is the pasted string");
    assert.ok(page.getElementById("ln-inv-out").innerHTML.includes('id="qr-test"'), "the QR is on screen");
  } finally {
    delete globalThis.document;
  }
});

test("app.js injects the QR renderer and the page network into hodlInitLn", () => {
  assert.match(appSource, /hodlInitLn\(\{[^}]*qrSvg: hodlQrSvg/);
  assert.match(appSource, /hodlInitLn\(\{[^}]*pageNetwork: \(\) => hodlInspectorNetwork\(\)/);
});
