// EntropyLab build script.
//
// Inlines the sources from src/ into a single self-contained entropylab.html
// at the repository root. The file is a generated artifact (gitignored); CI
// rebuilds it for every test run, deploys it with Pages, and commits it back
// to rock after each merge so the file stays downloadable. The Pages workflow
// copies it to a deployment-only index.html so both / and /entropylab.html
// serve the same application. The output is byte-for-byte reproducible from
// the sources, the version declared in package.json, and the commit the
// build is cut from (stamped into the footer).
import { execFileSync } from "node:child_process";
import { readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { buildSync } from "esbuild";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const SRC = join(root, "src");

const read = (path) => readFileSync(join(SRC, path), "utf8");
const version = JSON.parse(readFileSync(join(root, "package.json"), "utf8")).version;

if (!/^\d+(?:\.\d+)*$/.test(version)) {
  throw new Error(`Invalid version in package.json: ${version}`);
}

// The footer identifies the exact source revision the build was cut from; a
// build from a snapshot without git metadata stamps "unknown".
const commit = (() => {
  try {
    return execFileSync("git", ["rev-parse", "HEAD"], { cwd: root, encoding: "utf8" }).trim();
  } catch {
    return "unknown";
  }
})();
if (!/^(?:[0-9a-f]{40}|unknown)$/.test(commit)) {
  throw new Error(`Unexpected git commit id: ${commit}`);
}

const appFile = "entropylab.html";
const workerFile = "service-worker.js";
const generated = () =>
  [appFile, workerFile, ...readdirSync(root).filter((name) =>
    /^entropylab-\d+(?:\.\d+)*\.html$/.test(name)
  )];

if (process.argv.includes("--clean")) {
  for (const name of generated()) rmSync(join(root, name), { force: true });
  console.log("Removed generated files (entropylab.html, service-worker.js, entropylab-*.html)");
  process.exit(0);
}

const template = read("index.html");
const workerTemplate = read("service-worker.js");
const css = read("css/styles.css");
// The header logo is inlined as SVG markup so the downloaded file shows it
// without reaching for assets/ (which only exists on the hosted site). The
// empty span is replaced in the template and in the runtime header template.
const logoSvg = (name) =>
  read(`assets/${name}.svg`).trim()
    .replace("<svg ", `<svg class="site-${name}" aria-hidden="true" focusable="false" `);
const siteLogoSpan = '<span class="site-logo" aria-hidden="true"></span>';
const siteLogo = `<span class="site-logo" aria-hidden="true">${logoSvg("logo-dark")}${logoSvg("logo-light")}</span>`;
// Inlined from the same files the site publishes, so the downloaded document
// and the hosted tab icon can never drift apart. The SVG icon is listed last
// so capable browsers prefer it; the PNG stays for those that ignore SVG icons.
const favicon = readFileSync(join(root, "assets/favicon.png")).toString("base64");
const faviconSvg = read("assets/favicon.svg").trim()
  .replace(/\s+/g, " ")
  .replace(/[#<>"%]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`);
const jsMain = buildSync({
  entryPoints: [join(SRC, "js/app.js")],
  bundle: true,
  minify: true,
  write: false,
  format: "iife",
  platform: "browser",
  target: "es2022",
  legalComments: "none",
  charset: "utf8",
}).outputFiles[0].text.split(siteLogoSpan).join(siteLogo);
const jsSqliteWriter = read("js/sqlite-writer.js");
const jsWalletExport = read("js/wallet-export.js");
const jsOnline = read("js/online.js");
const jsNetwork = read("js/network-check.js");
const jsBrowserCheck = read("js/browser-check.js");
const jsLifeHash = read("js/lifehash.js");
const jsEnhanced = read("js/enhanced-inputs.js");
const jsRepeat = read("js/repeat-inputs.js");

let html = template
  .split(siteLogoSpan).join(siteLogo)
  .replace("/*@@FAVICON@@*/", () => favicon)
  .replace("/*@@FAVICON_SVG@@*/", () => faviconSvg)
  .replace("/*@@CSS@@*/", () => css)
  .replace("/*@@JS_MAIN@@*/", () => jsMain)
  .replace("/*@@JS_SQLITE_WRITER@@*/", () => jsSqliteWriter)
  .replace("/*@@JS_WALLET_EXPORT@@*/", () => jsWalletExport)
  .replace("/*@@JS_ONLINE@@*/", () => jsOnline)
  .replace("/*@@JS_NETWORK@@*/", () => jsNetwork)
  .replace("/*@@JS_BROWSER_CHECK@@*/", () => jsBrowserCheck)
  .replace("/*@@JS_LIFEHASH@@*/", () => jsLifeHash)
  .replace("/*@@JS_ENHANCED@@*/", () => jsEnhanced)
  .replace("/*@@JS_REPEAT@@*/", () => jsRepeat)
  .split("{{VERSION}}").join(version);

html = html
  .split("{{COMMIT}}").join(commit)
  .split("{{COMMIT_SHORT}}").join(commit === "unknown" ? "unknown" : commit.slice(0, 7));

// The hosted service-worker URL must change whenever the self-contained app
// or its offline shell changes, even while several commits share one package
// version. Hashing the pre-token artifact avoids a self-referential digest.
const pwaVersion = createHash("sha256")
  .update(html)
  .update(readFileSync(join(root, "manifest.webmanifest")))
  .update(workerTemplate)
  .digest("hex")
  .slice(0, 16);
html = html.split("{{PWA_VERSION}}").join(pwaVersion);
const worker = workerTemplate.split("{{PWA_VERSION}}").join(pwaVersion);

for (const leftover of `${html}\n${worker}`.match(/\/\*@@|{{(?:VERSION|PWA_VERSION|COMMIT|COMMIT_SHORT)}}/g) || []) {
  throw new Error(`Unreplaced build token in output: ${leftover}`);
}

// Remove stale generated files (e.g. versioned copies from older releases)
for (const name of generated()) rmSync(join(root, name), { force: true });

writeFileSync(join(root, appFile), html);
writeFileSync(join(root, workerFile), worker);

console.log(`Built EntropyLab v${version}`);
console.log(`  ${appFile} (${Buffer.byteLength(html, "utf8")} bytes)`);
console.log(`  ${workerFile} (${Buffer.byteLength(worker, "utf8")} bytes)`);
