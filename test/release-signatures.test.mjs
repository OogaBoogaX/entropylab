// pages-release.yml's signature step (#1406) imports signer public keys only
// from the committed keys/ directory, never from the release's KEYS asset:
// v4 OpenPGP fingerprints are SHA-1, so key material that whoever uploads
// release assets supplies must not be trusted even when its fingerprint is
// listed. This runs the real step against throwaway keys.
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const read = (path) => readFileSync(join(root, path), "utf8");

const stepScript = (workflowPath, stepName) => {
  const text = read(workflowPath);
  const start = text.indexOf(`      - name: ${stepName}\n`);
  assert.ok(start >= 0, `${workflowPath} has the step "${stepName}"`);
  const rest = text.slice(start + 1);
  const end = rest.search(/^      - /m);
  const script = (end >= 0 ? rest.slice(0, end) : rest).split(/\n +run: \|\n/)[1];
  assert.ok(script, `"${stepName}" runs a script`);
  return script.replace(/^ {10}/gm, "");
};

const tools = process.platform !== "win32" && ["bash", "gpg"].every((tool) => spawnSync(tool, ["--version"], { stdio: "ignore" }).status === 0);

test("the signature step never imports the release's KEYS asset", () => {
  const script = stepScript(".github/workflows/pages-release.yml", "Check the release signatures");
  assert.doesNotMatch(script, /--import\s+"?KEYS/, "KEYS is never imported");
  assert.match(script, /KEYFILES=\("\$GITHUB_WORKSPACE"\/keys\/\*\.asc\)/, "keys come from the default branch's committed keys/ directory");
  assert.match(script, /SIGNERS="\$GITHUB_WORKSPACE\/\.github\/release-signers\.txt"/, "the signer list is the default branch's");
  assert.doesNotMatch(script, /TAGTREE|REVIEWED/, "no tag's copy of the trust policy is read");
});

test("the release check verifies the signatures against the shipped manifest", () => {
  const script = stepScript(".github/workflows/pages-release.yml", "Check the release signatures");
  assert.match(script, /--verify SHA256SUMS\.asc SHA256SUMS\.txt/, "the manifest the assets ship is the one verified");
});
test("every active signer in release-signers.txt has a committed key", { skip: !tools && "needs bash and gpg" }, () => {
  const home = mkdtempSync(join(tmpdir(), "signer-keys-"));
  try {
    const gpg = (...args) => execFileSync("gpg", ["--batch", "--homedir", home, ...args], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] });
    for (const name of readdirSync(join(root, "keys")).filter((file) => file.endsWith(".asc"))) gpg("--import", join(root, "keys", name));
    const committed = new Set(gpg("--with-colons", "--fingerprint", "--list-keys").split("\n").reduce((out, line, i, all) => {
      if (line.startsWith("pub:")) { const fpr = all.slice(i + 1).find((next) => next.startsWith("fpr:")); if (fpr) out.push(fpr.split(":")[9]); }
      return out;
    }, []));
    for (const line of read(".github/release-signers.txt").split("\n")) {
      const match = line.match(/^([0-9A-F]{40}) (\S+) active$/);
      if (match) assert.ok(committed.has(match[1]), `${match[2]} (${match[1]}) has a key file under keys/`);
    }
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test("a KEYS asset with an extra key cannot add a signer", { skip: !tools && "needs bash and gpg" }, () => {
  const temp = mkdtempSync(join(tmpdir(), "release-sigs-"));
  try {
    // Two throwaway signing keys in their own home, standing in for signers.
    const keyHome = join(temp, "keyhome");
    mkdirSync(keyHome, { mode: 0o700 });
    const gpg = (...args) => execFileSync("gpg", ["--batch", "--homedir", keyHome, "--pinentry-mode", "loopback", "--passphrase", "", ...args], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
    gpg("--quick-gen-key", "A <a@example.invalid>", "ed25519", "sign", "never");
    gpg("--quick-gen-key", "B <b@example.invalid>", "ed25519", "sign", "never");
    // C signs with a subkey, as Portland.HODL and w-s-bitcoin do: gpg's
    // VALIDSIG names the subkey first and the primary last, and the primary is
    // what release-signers.txt lists.
    gpg("--quick-gen-key", "C <c@example.invalid>", "ed25519", "cert", "never");
    const fprs = gpg("--with-colons", "--fingerprint", "--list-keys").split("\n").filter((line) => line.startsWith("fpr:")).map((line) => line.split(":")[9]);
    const primaries = [];
    for (const line of gpg("--with-colons", "--list-keys").split("\n")) if (line.startsWith("pub:")) primaries.push(line.split(":")[4]);
    const [fprA, fprB, fprC] = primaries.map((keyid) => fprs.find((fpr) => fpr.endsWith(keyid)));
    assert.ok(fprA && fprB && fprC && new Set([fprA, fprB, fprC]).size === 3, "three distinct keys");
    gpg("--quick-add-key", fprC, "ed25519", "sign", "never");
    const exportKey = (fpr) => execFileSync("gpg", ["--batch", "--homedir", keyHome, "--armor", "--export", fpr], { encoding: "utf8" });

    const sums = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9  entropylab.html\n";
    const sumsPath = join(temp, "SHA256SUMS.txt");
    writeFileSync(sumsPath, sums);
    const sigA = execFileSync("gpg", ["--batch", "--homedir", keyHome, "--pinentry-mode", "loopback", "--passphrase", "", "--local-user", fprA, "--detach-sign", "--output", "-", sumsPath]);
    const sigB = execFileSync("gpg", ["--batch", "--homedir", keyHome, "--pinentry-mode", "loopback", "--passphrase", "", "--local-user", fprB, "--detach-sign", "--output", "-", sumsPath]);
    const sigC = execFileSync("gpg", ["--batch", "--homedir", keyHome, "--pinentry-mode", "loopback", "--passphrase", "", "--local-user", fprC, "--detach-sign", "--output", "-", sumsPath]);

    const script = stepScript(".github/workflows/pages-release.yml", "Check the release signatures");
    const run = (name, { listed, committed, keysAsset, min, sigs = [sigA, sigB], extraLines = [] }) => {
      const dir = join(temp, name);
      const workspace = join(dir, "workspace");
      const runnerTemp = join(dir, "runner");
      mkdirSync(join(workspace, "keys"), { recursive: true });
      mkdirSync(join(workspace, ".github"), { recursive: true });
      mkdirSync(join(runnerTemp, "release"), { recursive: true });
      // A listed entry is [fingerprint, name] (written as an active line) or a
      // raw line, so a test can add a malformed or duplicate record.
      const signerLine = (entry) => (typeof entry === "string" ? entry : `${entry[0]} ${entry[1]} active`);
      writeFileSync(join(workspace, ".github/release-signers.txt"), `min-signers ${min}\n${[...listed, ...extraLines].map(signerLine).join("\n")}\n`);
      for (const [index, [fpr, who]] of committed.entries()) writeFileSync(join(workspace, "keys", `${who}-${index}.asc`), exportKey(fpr));
      writeFileSync(join(runnerTemp, "release/SHA256SUMS.txt"), sums);
      writeFileSync(join(runnerTemp, "release/SHA256SUMS.asc"), Buffer.concat(sigs));
      writeFileSync(join(runnerTemp, "release/KEYS"), keysAsset.map(exportKey).join("\n"));
      const result = spawnSync("bash", ["-c", script], { cwd: runnerTemp, env: { ...process.env, RUNNER_TEMP: runnerTemp, GITHUB_WORKSPACE: workspace }, encoding: "utf8" });
      return { status: result.status, log: `${result.stdout}${result.stderr}` };
    };
    const A = [fprA, "A"], B = [fprB, "B"], C = [fprC, "C"];

    // Control: both keys committed and listed, two good signatures.
    const good = run("good", { listed: [A, B], committed: [A, B], keysAsset: [A, B], min: 2 });
    assert.equal(good.status, 0, good.log);
    assert.match(good.log, /Good signature from A/);
    assert.match(good.log, /Good signature from B/);

    // B is listed, but its key is only in the KEYS asset: it must not count,
    // and the deploy fails closed naming B.
    const fromAsset = run("from-asset", { listed: [A, B], committed: [A], keysAsset: [A, B], min: 2 });
    assert.notEqual(fromAsset.status, 0, "a key supplied only by the KEYS asset must not count");
    assert.match(fromAsset.log, /title=Signer keys::active signer B .* has no committed key file/);

    // B is not listed and its key is only in the KEYS asset: its signature is
    // not verifiable from committed keys, and the deploy fails closed.
    const unlisted = run("unlisted", { listed: [A], committed: [A], keysAsset: [A, B], min: 1 });
    assert.notEqual(unlisted.status, 0, "an extra key in the KEYS asset must not add a signer");
    assert.doesNotMatch(unlisted.log, /Good signature from B/);

    // A signer who signs with a subkey is identified by the primary key the
    // list names, so the signature counts.
    const subkey = run("subkey", { listed: [A, C], committed: [A, C], keysAsset: [], min: 2, sigs: [sigA, sigC] });
    assert.equal(subkey.status, 0, subkey.log);
    assert.match(subkey.log, /Good signature from C/);

    // Two keys, one person: the release rule counts distinct people, so two
    // signatures from keys listed under the same name are one signer.
    const sameName = run("same-name", { listed: [[fprA, "A"], [fprB, "A"]], committed: [[fprA, "A"], [fprB, "A"]], keysAsset: [], min: 2, sigs: [sigA, sigB] });
    assert.notEqual(sameName.status, 0, "two keys under one name are one signer");
    assert.match(sameName.log, /title=Too few signers::.*distinct active signer/);

    // The same two keys under one name plus a third person: two distinct
    // people, so min 2 is met and C's good signature is still listed.
    const twoPeople = run("two-people", { listed: [[fprA, "A"], [fprB, "A"], [fprC, "C"]], committed: [[fprA, "A"], [fprB, "A"], [fprC, "C"]], keysAsset: [], min: 2, sigs: [sigA, sigB, sigC] });
    assert.equal(twoPeople.status, 0, twoPeople.log);
    assert.match(twoPeople.log, /Good signature from C/);

    // A stray two-field line must not lend its name to a key: the name comes
    // from the key's active line, so fprB and fprC are one person (B) and the
    // release is under-signed. This is the case that distinguishes the
    // active-line lookup from a first-match lookup.
    const stray = run("stray-line", { listed: [`${fprB} A`, [fprB, "B"], [fprC, "B"]], committed: [[fprB, "B"], [fprC, "B"]], keysAsset: [], min: 2, sigs: [sigB, sigC] });
    assert.notEqual(stray.status, 0, "a stray two-field line must not lend fprB the name A");
    assert.match(stray.log, /title=Too few signers::/);

    // A listed line with no name is refused, not guessed at.
    const noName = run("no-name", { listed: [A], committed: [A, B], keysAsset: [], min: 2, sigs: [sigA, sigB], extraLines: [`${fprB} active`] });
    assert.notEqual(noName.status, 0, "a listed line with no name must be refused");
    assert.match(noName.log, /title=Unknown signer/);

    // The same key listed active and revoked: the revoked record wins, so A
    // does not count and only C's signature remains.
    const activeAndRevoked = run("active-and-revoked", { listed: [A, C], committed: [A, C], keysAsset: [], min: 2, sigs: [sigA, sigC], extraLines: [`${fprA} A revoked`] });
    assert.notEqual(activeAndRevoked.status, 0, "a key listed active and revoked must not count");
    assert.match(activeAndRevoked.log, /title=Too few signers::/);
    const revokedAlone = run("active-and-revoked-min1", { listed: [A, C], committed: [A, C], keysAsset: [], min: 1, sigs: [sigA, sigC], extraLines: [`${fprA} A revoked`] });
    assert.equal(revokedAlone.status, 0, revokedAlone.log);
    assert.match(revokedAlone.log, /Good signature from C/);
    assert.doesNotMatch(revokedAlone.log, /Good signature from A/);
  } finally {
    rmSync(temp, { recursive: true, force: true });
  }
});
