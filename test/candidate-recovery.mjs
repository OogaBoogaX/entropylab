// Opt-in audit of an UNMODIFIED candidate HTML, through its real recovery UI.
// Usage: node test/candidate-recovery.mjs /absolute/path/entropylab.html
// Contract: supported recovery inputs reproduce independent seed/key/address
// results; malformed recovery inputs cannot enable derivation. Coverage only.
// No app crypto imports or test hooks. Public deterministic fixtures ONLY.
import assert from "node:assert/strict";
import { createHash, pbkdf2Sync } from "node:crypto";
import { readFileSync, mkdtempSync, rmSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { HDKey } from "@scure/bip32";
import { entropyToMnemonic, mnemonicToSeedSync } from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english.js";
import { NETWORK, TEST_NETWORK, p2pkh, p2sh, p2wpkh, p2tr } from "@scure/btc-signer";
import { base58check } from "@scure/base";
import * as driver from "../scripts/residue-audit.mjs";

assert.ok(process.argv[2], "Supply the exact candidate HTML path; this audit never builds it.");
const artifact = readFileSync(resolve(process.argv[2]));
const digest = createHash("sha256").update(artifact).digest("hex");
const hex = (bytes) => Buffer.from(bytes).toString("hex");
const b58 = base58check((bytes) => new Uint8Array(createHash("sha256").update(bytes).digest()));
const work = mkdtempSync(join(tmpdir(), "entropylab-candidate-recovery-"));
const server = createServer((req, res) => res.writeHead(200, { "Content-Type": "text/html" }).end(artifact));
await new Promise((done) => server.listen(0, "127.0.0.1", done));
const origin = `http://127.0.0.1:${server.address().port}`;
const engine = driver.resolveBrowser({ browser: "chrome", browserExplicit: true });
const child = driver.spawnBrowser(engine, { profile: join(work, "profile"), logPath: join(work, "browser.log") });
const client = driver.createPipeClient(child.stdio[3], child.stdio[4]);
const externalRequests = [], exceptions = [];
let events = "", session, cases = 0, addresses = 0, rejected = 0;
// Observe CDP events externally: do not replace any page API or alter its bundle.
child.stdio[4].on("data", (chunk) => {
  events += chunk;
  let end;
  while ((end = events.indexOf("\0")) !== -1) {
    const event = JSON.parse(events.slice(0, end));
    events = events.slice(end + 1);
    if (event.method === "Network.requestWillBeSent") {
      const url = event.params.request.url;
      if (/^https?:/.test(url) && new URL(url).origin !== origin) externalRequests.push(url);
    }
    if (event.method === "Runtime.exceptionThrown") exceptions.push(event.params.exceptionDetails.text);
  }
});
const tracked = { async send(method, ...args) {
  const reply = await client.send(method, ...args);
  if (method === "Target.attachToTarget") {
    session = reply.sessionId;
    await client.send("Network.enable", {}, session);
    await client.send("Runtime.enable", {}, session);
  }
  return reply;
} };
const send = (method, params) => client.send(method, params, session);
const versions = (network) => network === "mainnet"
  ? { private: 0x0488ade4, public: 0x0488b21e }
  : { private: 0x04358394, public: 0x043587cf };
const net = (network) => network === "mainnet" ? NETWORK
  : { ...TEST_NETWORK, bech32: network === "regtest" ? "bcrt" : "tb" };
const payment = (purpose, key, network) => {
  const n = net(network);
  return purpose === 44 ? p2pkh(key, n) : purpose === 49 ? p2sh(p2wpkh(key, n), n)
    : purpose === 84 ? p2wpkh(key, n) : p2tr(key.slice(1), undefined, n);
};
const passphrases = ["", "TREZOR", "caf\u00e9", "cafe\u0301", " leading and trailing \u3000"];
const phrase12 = "abandon ".repeat(11) + "about";
// Published BIP84/BIP86 anchors check the reference and the candidate UI.
// https://github.com/bitcoin/bips/blob/master/bip-0084.mediawiki
// https://github.com/bitcoin/bips/blob/master/bip-0086.mediawiki
const published = new Map([
  [84, "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"],
  [86, "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr"],
]);
console.log(JSON.stringify({ artifactSha256: digest, browser: engine.id, reference: "Node PBKDF2; pinned @scure bip39/bip32/btc-signer/base; BIP84/BIP86 vectors" }));
try {
  const page = await driver.createPage(tracked, `${origin}/case-0`);
  const select = async (id, value) => page.evaluate(`(() => {
    const el = document.getElementById(${JSON.stringify(id)});
    el.value = ${JSON.stringify(String(value))};
    el.dispatchEvent(new Event('change', { bubbles: true }));
  })()`);
  const boot = async () => {
    await page.waitFor('document.documentElement?.dataset.selfTestsFailed === "0"');
    assert.equal(await page.evaluate('Boolean(window.__entropyLabCrypto || window.__entropyLabTest)'), false, "candidate contains test hooks");
    if (await page.evaluate('Boolean(document.getElementById("beta-disclaimer-accept"))')) {
      await page.click("#beta-disclaimer-accept");
      await page.evaluate(`(() => {
        const proof = [...document.querySelectorAll('[id^="beta-disclaimer-proof-text-"]')].find(el => !el.hidden);
        const input = document.getElementById('beta-disclaimer-proof');
        input.value = proof.id.split('-').at(-1);
        input.dispatchEvent(new Event('input', { bubbles: true }));
      })()`);
      await page.click("#beta-disclaimer-confirm");
    }
    await page.waitFor('document.getElementById("key-mode-select") && !document.getElementById("beta-disclaimer")');
    await send("Network.emulateNetworkConditions", { offline: true, latency: 0, downloadThroughput: -1, uploadThroughput: -1 });
  };
  const reset = async () => {
    await send("Network.emulateNetworkConditions", { offline: false, latency: 0, downloadThroughput: -1, uploadThroughput: -1 });
    const path = `/case-${++cases}`;
    await send("Page.navigate", { url: origin + path });
    await page.waitFor(`location.pathname === ${JSON.stringify(path)}`);
    await boot();
  };
  const recover = async ({ length = 16, network = "mainnet", purpose = 84, mode = "seed", passphrase = "", imported = "", pattern = "zero" }) => {
    await reset();
    const entropy = Uint8Array.from({ length }, (_, i) => pattern === "ff" ? 255
      : pattern === "alternating" ? (i % 2 ? 0x55 : 0xaa) : pattern === "incrementing" ? i : 0);
    const mnemonic = entropyToMnemonic(entropy, wordlist);
    const seed = pbkdf2Sync(mnemonic.normalize("NFKD"), ("mnemonic" + passphrase).normalize("NFKD"), 2048, 64, "sha512");
    assert.equal(hex(seed), hex(mnemonicToSeedSync(mnemonic, passphrase)), "independent PBKDF2 reference disagreement");
    const root = HDKey.fromMasterSeed(seed, versions(network));
    const coin = network === "mainnet" ? 0 : 1;
    const accountPath = `m/${purpose}'/${coin}'/0'`;
    const account = root.derive(accountPath);
    const label = `${mode}/${length * 8}/${network}/${purpose}/${JSON.stringify(passphrase)}/${imported}/${pattern}`;
    await page.click(`#network-picker-menu [data-network="${network}"]`);
    await select("seed-length-select", length * 3 / 4);
    await select("key-mode-select", mode);
    if (mode === "hex") await page.click('input[name="entropy-format"][value="hex"]');
    const input = imported === "root-private" ? root.privateExtendedKey
      : imported === "account-public" ? account.publicExtendedKey
      : mode === "hex" ? hex(entropy) : mnemonic;
    await page.type(mode === "hex" ? "#hex" : "#seed", input);
    if (!imported && passphrase) await page.type("#pass", passphrase);
    await select("script-type", `bip${purpose}`);
    await page.type("#derivation-path", `${accountPath}/{0-1}/{0-2}`);
    await page.waitFor('!document.getElementById("go").disabled');
    await page.click("#go");
    await page.waitFor('document.querySelectorAll("#acct [data-address-table] tbody tr[aria-rowindex]").length === 6');
    assert.equal(await page.evaluate('document.querySelectorAll("#out [data-private-value]").length'), 0, `${label}: secrets exposed before reveal`);
    if (imported !== "account-public") await page.click("#reveal");
    const actual = await page.evaluate(`({
      recovery: [...document.querySelectorAll('#out [data-key-group="recovery"] [data-private-value]')].map(el => el.textContent),
      public: [...document.querySelectorAll('#out [data-public-value]')].map(el => el.textContent),
      rows: [...document.querySelectorAll('#acct [data-address-table] tbody tr[aria-rowindex]')].map(row => ({
        path: row.querySelector('td').textContent,
        address: row.querySelector('[data-address-qr]').parentElement.querySelector('[data-public-value]').textContent,
        wif: row.querySelector('[data-private-value]')?.textContent ?? null
      }))
    })`);
    if (!imported) {
      for (const expected of [mnemonic, hex(entropy), hex(seed), root.privateExtendedKey]) {
        assert.ok(actual.recovery.includes(expected), `${label}: recovery mismatch for ${expected}`);
      }
    }
    if (imported === "account-public") assert.equal(actual.recovery.length, 0, `${label}: public import gained secrets`);
    if (imported === "root-private") assert.ok(actual.recovery.includes(root.privateExtendedKey), `${label}: root-private recovery mismatch`);
    assert.ok(actual.public.includes(account.publicExtendedKey), `${label}: account xpub mismatch`);
    for (const [offset, row] of actual.rows.entries()) {
      const branch = Math.floor(offset / 3), index = offset % 3;
      const path = `${accountPath}/${branch}/${index}`, childNode = root.derive(path);
      const address = payment(purpose, childNode.publicKey, network).address;
      if (imported === "account-public") {
        // A bare account xpub cannot authenticate its full origin. The UI
        // correctly shows a relative path instead of inventing that origin.
        assert.ok(row.path.endsWith(`/${branch}/${index}`), `${label}: relative path`);
        assert.ok(!row.path.startsWith("m/"), `${label}: unverified origin presented as known`);
      } else assert.equal(row.path, path, `${label}: displayed path`);
      assert.equal(row.address, address, `${label}: address at ${path}`);
      if (network === "mainnet" && length === 16 && pattern === "zero" && !passphrase && branch === 0 && index === 0 && published.has(purpose)) {
        assert.equal(row.address, published.get(purpose), `${label}: published address`);
      }
      const wif = b58.encode(Uint8Array.from([network === "mainnet" ? 0x80 : 0xef, ...childNode.privateKey, 1]));
      assert.equal(row.wif, imported === "account-public" ? null : wif, `${label}: WIF at ${path}`);
      addresses++;
    }
    await page.click("#wipe");
    assert.equal(await page.evaluate('document.querySelectorAll("#out [data-private-value], #acct [data-address-table] tbody tr[aria-rowindex]").length'), 0, `${label}: wiped key still has rendered output`);
    if (cases % 10 === 0) console.log(`Passed ${cases} recoveries, ${addresses} addresses`);
  };
  for (const [i, length] of [16, 20, 24, 28, 32].entries()) {
    for (const network of ["mainnet", "testnet", "signet", "regtest"]) {
      for (const purpose of [44, 49, 84, 86]) await recover({ length, network, purpose, passphrase: passphrases[i] });
    }
    for (const pattern of ["zero", "ff", "alternating", "incrementing"]) {
      await recover({ length, mode: "hex", passphrase: passphrases[i], pattern });
    }
  }
  for (const network of ["mainnet", "testnet", "signet", "regtest"]) {
    for (const purpose of [44, 49, 84, 86]) {
      for (const imported of ["root-private", "account-public"]) await recover({ network, purpose, imported });
    }
  }
  const root = HDKey.fromMasterSeed(mnemonicToSeedSync(phrase12));
  const corruptChecksum = (key) => key.slice(0, -1) + (key.endsWith("1") ? "2" : "1");
  for (const invalid of ["abandon ".repeat(12).trim(), phrase12 + " abandon", "notaword " + phrase12.split(" ").slice(1).join(" "), corruptChecksum(root.privateExtendedKey), corruptChecksum(root.publicExtendedKey)]) {
    await reset();
    await select("seed-length-select", 12);
    await select("key-mode-select", "seed");
    await page.type("#seed", invalid);
    await page.waitFor('document.getElementById("go").disabled');
    assert.equal(await page.evaluate('document.querySelectorAll("#acct [data-address-table] tbody tr[aria-rowindex]").length'), 0);
    rejected++;
  }
  assert.deepEqual(externalRequests, [], "candidate attempted external network requests");
  assert.deepEqual(exceptions, [], "candidate raised an uncaught browser exception");
  console.log(JSON.stringify({ artifactSha256: digest, recoveries: cases - rejected, addresses, rejected, externalRequests: externalRequests.length, exceptions: exceptions.length, result: "PASS" }));
} finally {
  await driver.stopBrowser(child, client);
  client.dispose();
  await new Promise((done) => server.close(done));
  rmSync(work, { recursive: true, force: true });
}
