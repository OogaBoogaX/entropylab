// Runs the assembled application in headless Firefox, Chrome/Chromium, and
// Microsoft Edge against a local Node.js HTTP server and validates the
// BIP39/BIP32 vectors, input sanitization, same-origin network behavior,
// hosted presentation, and recovery-sheet exports. The in-page
// instrumentation and suite live alongside this harness.
// Each engine that is installed runs the full battery; engines that are not
// are skipped with a reason (at least one must be present). Binary
// resolution: FIREFOX_BINARY / CHROME_BINARY (or CHROMIUM_BINARY) /
// EDGE_BINARY, then the usual platform locations.
// Run with `npm run test:browser` or `npm test`.
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawn, spawnSync } from "node:child_process";
import { createServer } from "node:http";
import {
  closeSync,
  cpSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  openSync,
  readFileSync,
  realpathSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { homedir, tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const read = (path) => readFileSync(join(root, path), "utf8");
const platform = process.platform;

const resolveBinary = ({ envVars, pathNames, extraPaths }) => {
  for (const name of envVars) {
    if (process.env[name]) return process.env[name];
  }
  const tryRun = (bin) => {
    try {
      const result = spawnSync(bin, ["--version"], { stdio: "pipe" });
      if (result.status === 0) return bin;
    } catch {}
    return null;
  };
  for (const bin of pathNames) {
    const found = tryRun(bin);
    if (found) return found;
  }
  for (const p of extraPaths[platform] ?? []) {
    if (existsSync(p)) return p;
  }
  return null;
};

const engines = [
  {
    id: "firefox",
    label: "Firefox",
    kind: "firefox",
    envVars: ["FIREFOX_BINARY"],
    pathNames: ["firefox", "firefox-developer-edition"],
    extraPaths: {
      darwin: [
        "/Applications/Firefox Developer Edition.app/Contents/MacOS/firefox",
        "/Applications/Firefox.app/Contents/MacOS/firefox",
      ],
      win32: [
        "C:\\Program Files\\Firefox Developer Edition\\firefox.exe",
        "C:\\Program Files\\Mozilla Firefox\\firefox.exe",
        "C:\\Program Files (x86)\\Firefox Developer Edition\\firefox.exe",
        "C:\\Program Files (x86)\\Mozilla Firefox\\firefox.exe",
      ],
      linux: [
        "/usr/local/bin/firefox",
        "/usr/bin/firefox",
        "/usr/bin/firefox-developer-edition",
        "/snap/bin/firefox",
        "/snap/bin/firefox-developer-edition",
        "/opt/firefox/firefox",
        "/opt/firefox-developer-edition/firefox",
      ],
    },
  },
  {
    id: "chrome",
    label: "Chrome/Chromium",
    kind: "chromium",
    envVars: ["CHROME_BINARY", "CHROMIUM_BINARY"],
    pathNames: ["google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "chrome", "headless_shell"],
    extraPaths: {
      darwin: [
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        "/Applications/Chromium.app/Contents/MacOS/Chromium",
      ],
      win32: [
        "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
        "C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe",
      ],
      linux: [
        "/usr/bin/google-chrome",
        "/usr/bin/google-chrome-stable",
        "/usr/bin/chromium",
        "/usr/local/bin/chromium",
        "/snap/bin/chromium",
      ],
    },
  },
  {
    id: "edge",
    label: "Microsoft Edge",
    kind: "chromium",
    envVars: ["EDGE_BINARY"],
    pathNames: ["microsoft-edge", "microsoft-edge-stable", "msedge"],
    extraPaths: {
      darwin: ["/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge"],
      win32: [
        "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
        "C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe",
      ],
      linux: [
        "/usr/bin/microsoft-edge",
        "/usr/bin/microsoft-edge-stable",
        "/opt/microsoft/msedge/msedge",
        "/snap/bin/microsoft-edge",
      ],
    },
  },
];
for (const engine of engines) engine.binary = resolveBinary(engine);

// A snap-confined Firefox (the Ubuntu default: /usr/bin/firefox is a wrapper
// around /snap/bin/firefox) runs with a private /tmp mount namespace, so a
// staging area under os.tmpdir() is invisible to the browser: the profile,
// the file:// test page, and the download directory all silently miss and
// the suite times out. Unconfined builds (CI runners, docker dev images,
// mozilla.org tarballs, macOS, Windows) share the host's view of the
// filesystem.
const isSnapConfined = (bin) => {
  if (platform !== "linux" || !bin) return false;
  try {
    const onPath = bin.includes("/")
      ? bin
      : (process.env.PATH ?? "").split(":").filter(Boolean)
          .map((dir) => join(dir, bin)).find((candidate) => existsSync(candidate));
    if (!onPath) return false;
    const resolved = realpathSync(onPath);
    if (resolved.split("/").includes("snap")) return true;
    // The Ubuntu transition wrapper is a tiny shell script, not an ELF binary.
    if (statSync(resolved).size < 1024 * 1024) {
      const content = readFileSync(resolved, "utf8");
      if (content.includes("/snap/bin") || content.includes("snap install firefox")) return true;
    }
  } catch {}
  return false;
};

// For a snap-confined browser, stage under the snap's common directory: the
// one path the sandbox and this harness both see at the identical absolute
// location. Everywhere else, keep using the system temp dir.
const stagingBase = () => {
  if (!engines.some((engine) => engine.kind === "firefox" && isSnapConfined(engine.binary))) return tmpdir();
  const base = join(homedir(), "snap", "firefox", "common");
  mkdirSync(base, { recursive: true });
  return base;
};

// Chromium-based browsers: the setuid sandbox needs privileges a container
// or a root user does not have. Off it for root or when the environment
// opts out (the dev container sets BROWSER_TEST_NO_SANDBOX=1); a normal
// user on a normal machine keeps the sandbox on.
const chromiumSandboxArgs = () => {
  if (process.env.BROWSER_TEST_NO_SANDBOX || (typeof process.getuid === "function" && process.getuid() === 0)) {
    return ["--no-sandbox"];
  }
  return [];
};

const appVersion = JSON.parse(read("package.json")).version;
const appFile = "entropylab.html";
const appSource = join(root, appFile);

// Stage the site exactly the way scripts/build.mjs publishes it (the compiled
// entropylab.html), and add the instrumented test document. Shared by every
// engine so all browsers test the identical bytes.
const stageWorkDir = () => {
  const workDir = mkdtempSync(join(stagingBase(), "entropylab-browser-"));
  const siteDir = join(workDir, "site");
  mkdirSync(join(siteDir, "assets"), { recursive: true });
  // The served download target stays the exact release artifact, so the
  // export check below keeps proving the download link serves the release.
  cpSync(appSource, join(siteDir, appFile));
  cpSync(join(root, "assets"), join(siteDir, "assets"), { recursive: true });

  // The suite drives app internals through __entropyLabCrypto, a test-only
  // bridge the release build strips (scripts/build.mjs). Assemble the test
  // document from a hooks-enabled variant built into the work dir; the build
  // is identical to the release except for that one compiled-in statement.
  execFileSync(process.execPath, [join(root, "scripts/build.mjs"), "--test-hooks", "--out", workDir], { stdio: "inherit" });
  const appHtml = readFileSync(join(workDir, appFile), "utf8");
  const instrumentation = read("test/browser-instrumentation.html");
  const suite = read("test/browser-suite.html");

  // Inject the test instrumentation before the application stylesheet.
  const marker = '<style id="btc-calc-style">';
  const markerIndex = appHtml.indexOf(marker);
  if (markerIndex === -1) throw new Error("could not find the application stylesheet marker");
  const stageOne = `${appHtml.slice(0, markerIndex)}${instrumentation}${appHtml.slice(markerIndex)}`;

  // Append the browser suite before the document end.
  const testHtml = `${stageOne.replace(/<\/body>\s*<\/html>\s*$/, "")}${suite}</body></html>\n`;
  const testHtmlPath = join(siteDir, "browser-tests.html");
  writeFileSync(testHtmlPath, testHtml, "utf8");

  writeFileSync(join(workDir, "not-found.txt"), "Not found\n", "utf8");

  return { workDir, siteDir, testHtmlPath };
};

// Per-engine profile and download staging. Firefox gets a user.js; the
// Chromium family reads download defaults from Default/Preferences in a
// fresh --user-data-dir, and the process cwd is pointed at the same
// directory as a fallback for headless download placement.
const stageEngine = (engine, workDir) => {
  const downloadDir = join(workDir, `downloads-${engine.id}`);
  const onlineProfile = join(workDir, `${engine.id}-profile-online`);
  const offlineProfile = join(workDir, `${engine.id}-profile-offline`);
  mkdirSync(downloadDir, { recursive: true });
  mkdirSync(onlineProfile, { recursive: true });
  mkdirSync(offlineProfile, { recursive: true });
  if (engine.kind === "firefox") {
    const userJs = [
      'user_pref("browser.download.folderList", 2);',
      `user_pref("browser.download.dir", ${JSON.stringify(downloadDir)});`,
      'user_pref("browser.download.useDownloadDir", true);',
      'user_pref("browser.download.alwaysOpenPanel", false);',
      'user_pref("browser.helperApps.neverAsk.saveToDisk", "text/plain,application/octet-stream");',
      'user_pref("browser.shell.checkDefaultBrowser", false);',
      'user_pref("browser.startup.homepage_override.mstone", "ignore");',
      'user_pref("datareporting.policy.dataSubmissionEnabled", false);',
      'user_pref("toolkit.telemetry.enabled", false);',
      "",
    ].join("\n");
    writeFileSync(join(onlineProfile, "user.js"), userJs, "utf8");
    writeFileSync(join(offlineProfile, "user.js"), userJs, "utf8");
  } else {
    const preferences = JSON.stringify(
      {
        download: {
          default_directory: downloadDir,
          directory_upgrade: false,
          prompt_for_download: false,
        },
      },
      null,
      2,
    );
    for (const profile of [onlineProfile, offlineProfile]) {
      mkdirSync(join(profile, "Default"), { recursive: true });
      writeFileSync(join(profile, "Default", "Preferences"), preferences, "utf8");
    }
  }
  return { downloadDir, onlineProfile, offlineProfile };
};

// A real HTTP server: concurrent connections, correct framing, 404s.
const createTestServer = ({ siteDir, testHtmlPath }) => {
  const notFound = { file: join(dirname(testHtmlPath), "..", "not-found.txt"), type: "text/plain; charset=utf-8" };
  const routes = {
    "/": { file: testHtmlPath, type: "text/html; charset=utf-8" },
    "/browser-tests.html": { file: testHtmlPath, type: "text/html; charset=utf-8" },
    [`/${appFile}`]: { file: join(siteDir, appFile), type: "text/html; charset=utf-8" },
  };
  const server = createServer((request, response) => {
    const path = new URL(request.url, "http://localhost").pathname;
    const route = routes[path] ?? { ...notFound, status: 404, reason: "Not Found" };
    response.writeHead(route.status ?? 200, {
      "Content-Type": route.type,
      "Content-Length": statSync(route.file).size,
      "Cache-Control": "no-store",
    });
    response.end(readFileSync(route.file));
  });
  const listen = () => new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => resolve(server.address().port));
  });
  return { server, listen };
};

const spawnBrowser = (engine, { profile, url, logPath, cwd }) => {
  const logFd = openSync(logPath, "w");
  const args = engine.kind === "firefox"
    ? ["--headless", "--new-instance", "--profile", profile, url]
    : [
        "--headless",
        ...chromiumSandboxArgs(),
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-gpu",
        "--disable-dev-shm-usage",
        "--window-size=1280,800",
        `--user-data-dir=${profile}`,
        url,
      ];
  const options = { stdio: ["ignore", logFd, logFd] };
  if (engine.kind === "chromium") options.cwd = cwd;
  const process = spawn(engine.binary, args, options);
  closeSync(logFd);
  process.on("error", () => {});
  return process;
};

const waitForFile = async (file, timeoutMs) => {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (existsSync(file) && statSync(file).size > 0) return true;
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  return false;
};

const parseReport = (file) => {
  const lines = readFileSync(file, "utf8").trim().split("\n");
  const results = lines.map((line) => {
    const [status, name, error] = line.split("\t");
    return { ok: status === "ok", name: name ?? "", error: error ?? "" };
  });
  return {
    checks: results.length,
    results,
    failures: results.filter((result) => !result.ok),
  };
};

const tail = (file, maxLines = 120) => {
  if (!existsSync(file)) return "";
  return readFileSync(file, "utf8").split("\n").slice(-maxLines).join("\n");
};

// One engine: run the hosted (online) and file:// (offline) suites
// concurrently and fail on any failed check in either report.
const runEngine = (engine, staging, port) => async () => {
  const { downloadDir, onlineProfile, offlineProfile } = stageEngine(engine, staging.workDir);
  const onlineUrl = `http://127.0.0.1:${port}/browser-tests.html?online-preview=1`;
  const offlineUrl = `${pathToFileURL(staging.testHtmlPath).href}?offline-test=1`;
  const onlineLog = join(staging.workDir, `${engine.id}-online.log`);
  const offlineLog = join(staging.workDir, `${engine.id}-offline.log`);
  const browsers = [
    spawnBrowser(engine, { profile: onlineProfile, url: onlineUrl, logPath: onlineLog, cwd: downloadDir }),
    spawnBrowser(engine, { profile: offlineProfile, url: offlineUrl, logPath: offlineLog, cwd: downloadDir }),
  ];
  try {
    const onlineReport = join(downloadDir, "online-results.txt");
    const offlineReport = join(downloadDir, "offline-results.txt");
    // Watchdog, not a performance budget: this only detects a hung browser.
    // CI runners render in software and the online and offline instances share
    // a CPU, so Firefox there needs close to a minute for the full suite.
    const [onlineDone, offlineDone] = await Promise.all([
      waitForFile(onlineReport, 150000),
      waitForFile(offlineReport, 150000),
    ]);
    assert.ok(
      onlineDone && offlineDone,
      `Timed out waiting for ${engine.label} test reports.\n--- ${engine.id}-online.log ---\n${tail(onlineLog)}\n--- ${engine.id}-offline.log ---\n${tail(offlineLog)}`,
    );

    const online = parseReport(onlineReport);
    const offline = parseReport(offlineReport);
    // Guard against a report that exists because the suite bailed out early:
    // the hosted suite must genuinely run its full battery of checks.
    assert.ok(online.checks >= 20, `online suite report is incomplete in ${engine.label}: only ${online.checks} checks`);
    assert.ok(offline.checks >= 2, `offline suite report is incomplete in ${engine.label}: only ${offline.checks} checks`);

    const all = [...offline.results, ...online.results];
    let counter = 0;
    for (const result of all) {
      counter += 1;
      if (result.ok) {
        console.log(`ok ${counter} - ${engine.id}: ${result.name}`);
      } else {
        console.error(`not ok ${counter} - ${engine.id}: ${result.name}`);
        console.error(`  ${result.error}`);
      }
    }
    console.log(`1..${counter}`);
    const failures = [...offline.failures, ...online.failures];
    assert.equal(
      failures.length,
      0,
      `${failures.length} ${engine.label} integration test(s) failed: ${failures.map((f) => `${f.name}: ${f.error}`).join("; ")}`,
    );
    console.log(`All ${counter} cryptographic and browser integration checks passed in ${engine.label}.`);
  } finally {
    for (const browser of browsers) {
      browser.kill("SIGKILL");
    }
    // Windows keeps browser profile files locked briefly after SIGKILL; give
    // the handles time to release before the workdir is removed.
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
};

test("headless browsers run the hosted and offline suites", async (t) => {
  assert.match(appVersion, /^\d+(\.\d+)*$/, `invalid application version in package.json: ${appVersion}`);
  assert.ok(existsSync(appSource), `compiled ${appFile} is missing (run 'npm run build')`);
  const present = engines.filter((engine) => engine.binary);
  assert.ok(
    present.length > 0,
    "No supported browser found (Firefox, Chrome/Chromium, or Microsoft Edge). Install one or set FIREFOX_BINARY, CHROME_BINARY, or EDGE_BINARY. The docker dev image (docker compose up --build) ships all three.",
  );
  for (const engine of engines) {
    console.log(`${engine.label}: ${engine.binary ?? "not found (engine skipped)"}`);
  }

  const staging = stageWorkDir();
  const { server, listen } = createTestServer({ siteDir: staging.siteDir, testHtmlPath: staging.testHtmlPath });
  let port = 0;
  try {
    port = await listen();
    // The HTML export target is fetched here, outside the page: the app's CSP
    // (connect-src 'none') deliberately blocks the in-page fetch the suite
    // used to rely on, so the harness proves the download link serves the
    // current self-contained release.
    const exportResponse = await fetch(`http://127.0.0.1:${port}/${appFile}`);
    assert.ok(exportResponse.ok, `HTML export returned HTTP ${exportResponse.status}`);
    const exportBytes = Buffer.from(await exportResponse.arrayBuffer());
    assert.ok(exportBytes.equals(readFileSync(appSource)), "HTML export is not the current self-contained release");

    for (const engine of engines) {
      await t.test(
        engine.label,
        { skip: engine.binary ? false : `no ${engine.label} binary found (set ${engine.envVars.join(" or ")})` },
        runEngine(engine, staging, port),
      );
    }
  } finally {
    await new Promise((resolve) => server.close(resolve));
    rmSync(staging.workDir, { recursive: true, force: true, maxRetries: 10, retryDelay: 300 });
  }
});
