// Bitcoin Core fixtures for tests that check the app against a real node.
// Every test using these skips where bitcoind and bitcoin-cli are not
// installed — except under REQUIRE_BITCOIND=1, which the "Bitcoin Core
// interop" CI job sets after installing its pinned Bitcoin Core v31.1
// release: there a missing binary throws at import, because a job that
// silently skips its whole point must fail. Everywhere else (local runs
// without a node, the dev image) the tests still skip.
import { execFileSync, spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";

// The probe retries: in CI one test file's probe failed within 120 ms while
// the other file, in the same step and on the same PATH, ran its bitcoind
// tests (PR #818's interop run), so a single failed --version is not proof
// the binaries are missing. A failure that persists reports why.
export const BITCOIND = (() => {
  const probe = (bin) => spawnSync(bin, ["--version"], { stdio: "pipe", timeout: 30000 });
  const why = (bin, r) => `${bin}: status ${r.status}, signal ${r.signal}, error ${r.error?.code || r.error?.message || "none"}, stderr ${String(r.stderr || "").trim().slice(0, 200) || "empty"}`;
  let daemon, cli;
  for (let attempt = 0; attempt < 3; attempt++) {
    if (attempt) Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 500 * attempt);
    daemon = probe("bitcoind");
    cli = probe("bitcoin-cli");
    if (daemon.status === 0 && cli.status === 0) return true;
  }
  if (process.env.REQUIRE_BITCOIND === "1") {
    throw new Error(`REQUIRE_BITCOIND=1 but bitcoind and bitcoin-cli are not both on PATH — the Bitcoin Core interop job must install the pinned release before running these tests (${why("bitcoind", daemon)}; ${why("bitcoin-cli", cli)})`);
  }
  return false;
})();

export const CHAIN_FIXTURES = {
  mainnet: { flag: "", subdir: ".", bech32Prefix: "bc1q" },
  testnet: { flag: "-testnet", subdir: "testnet3", bech32Prefix: "tb1q" },
  signet: { flag: "-signet", subdir: "signet", bech32Prefix: "tb1q" },
  regtest: { flag: "-regtest", subdir: "regtest", bech32Prefix: "bcrt1q" },
};

// An OS-assigned localhost port keeps parallel or repeated runs from
// colliding with a real node.
export const freePort = () =>
  new Promise((resolve, reject) => {
    const server = createServer();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address();
      server.close(() => resolve(port));
    });
  });

export const sleepSync = (ms) => Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);

// Boots a fresh node for the chain, runs `body(cli)` where
// cli(...rpcArgs) returns the parsed JSON result (asserting success), and
// always shuts the node down again.
export const waitForChainNodeExit = (pidFile, exists = existsSync, sleep = sleepSync, attempts = 300) => {
  for (let waited = 0; waited < attempts; waited++) {
    if (!exists(pidFile)) return true;
    sleep(100);
  }
  return !exists(pidFile);
};

export const withChainNode = async (network, body) => {
  const fixture = CHAIN_FIXTURES[network];
  const port = await freePort();
  const datadir = mkdtempSync(join(tmpdir(), `entropylab-bitcoind-${network}-`));
  const pidFile = join(datadir, "bitcoind.pid");
  const flagArgs = fixture.flag ? [fixture.flag] : [];
  const cliArgs = [...flagArgs, `-datadir=${datadir}`, "-rpcuser=el", "-rpcpassword=el", `-rpcport=${port}`];
  const cli = (args, { check = true } = {}) => {
    const run = spawnSync("bitcoin-cli", [...cliArgs, ...args], { encoding: "utf8", maxBuffer: 1 << 22 });
    if (check && run.status !== 0) throw new Error(`bitcoin-cli ${args[0]} failed on ${network}: ${run.stderr.trim()}`);
    return run;
  };
  try {
    execFileSync("bitcoind", [...flagArgs, `-datadir=${datadir}`, `-pid=${pidFile}`, "-listen=0", "-connect=0", "-server", "-rpcuser=el", "-rpcpassword=el", `-rpcport=${port}`, "-daemon"], { stdio: "pipe" });
    cli(["-rpcwait", "getblockchaininfo"]);
    await body((args, options) => cli(args, options), join(datadir, fixture.subdir, "wallets"));
  } finally {
    spawnSync("bitcoin-cli", [...cliArgs, "stop"], { stdio: "pipe" });
    // RPC can go quiet before the final chain-state flush. Core removes its
    // PID file at the real shutdown boundary, so never delete the temporary
    // datadir while that PID marker says the process may still be alive.
    if (!waitForChainNodeExit(pidFile)) throw new Error(`bitcoind did not exit within 30 seconds; left its temporary datadir intact at ${datadir}`);
    rmSync(datadir, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  }
};
