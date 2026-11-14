// Local-only launcher for UI work with deterministic Key Station fixtures.
// It builds the same test-hooks variant used by the browser suite into a
// temporary directory and serves only repository assets over loopback.
import { execFileSync } from "node:child_process";
import { createServer } from "node:http";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, extname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const valueFor = (name, fallback) => {
  const exact = process.argv.indexOf(`--${name}`);
  const inline = process.argv.find((value) => value.startsWith(`--${name}=`));
  if (inline) return inline.slice(name.length + 3);
  if (exact >= 0) return process.argv[exact + 1];
  return fallback;
};
const integerFlag = (name, fallback, minimum, maximum) => {
  const raw = valueFor(name, String(fallback));
  if (!/^\d+$/.test(raw || "")) throw new Error(`--${name} must be a whole number`);
  const value = Number(raw);
  if (value < minimum || value > maximum) throw new Error(`--${name} must be between ${minimum} and ${maximum}`);
  return value;
};

if (process.argv.includes("--help")) {
  console.log("Usage: npm run testmode -- --keys=12 [--port=4173]");
  process.exit(0);
}

const keys = integerFlag("keys", 12, 1, 100);
const port = integerFlag("port", 4173, 1, 65535);
const outDir = mkdtempSync(join(tmpdir(), "entropylab-testmode-"));
const cleanup = () => rmSync(outDir, { recursive: true, force: true });
process.on("exit", cleanup);
execFileSync(process.execPath, [join(root, "scripts/build.mjs"), "--test-hooks", "--out", outDir], {
  cwd: root,
  stdio: "inherit",
});

const types = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".png": "image/png",
  ".svg": "image/svg+xml",
  ".webmanifest": "application/manifest+json; charset=utf-8",
};
const resolveRequest = (pathname) => {
  if (pathname === "/" || pathname === "/entropylab.html") return join(outDir, "entropylab.html");
  if (pathname === "/service-worker.js") return join(outDir, "service-worker.js");
  if (pathname === "/manifest.webmanifest") return join(root, "manifest.webmanifest");
  const asset = pathname.match(/^\/assets\/([a-zA-Z0-9._-]+)$/)?.[1];
  return asset ? join(root, "assets", asset) : "";
};

const server = createServer((request, response) => {
  try {
    const pathname = new URL(request.url || "/", "http://127.0.0.1").pathname;
    const file = resolveRequest(pathname);
    if (!file) {
      response.writeHead(404).end("Not found");
      return;
    }
    response.writeHead(200, { "Content-Type": types[extname(file)] || "application/octet-stream", "Cache-Control": "no-store" });
    response.end(readFileSync(file));
  } catch {
    response.writeHead(404).end("Not found");
  }
});

for (const signal of ["SIGINT", "SIGTERM"]) process.on(signal, () => {
  server.close(() => process.exit(0));
});
server.listen(port, "127.0.0.1", () => {
  console.log(`Test mode: http://127.0.0.1:${port}/?test-keys=${keys}`);
  console.log("Press Ctrl+C to stop.");
});
