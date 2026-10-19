// Hosted iPhone/PWA offline shell. The downloadable HTML remains self-contained.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { runInNewContext } from "node:vm";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const read = (path) => readFileSync(join(root, path), "utf8");
const template = read("src/index.html");
const shell = read("src/shell.html");
const worker = read("src/service-worker.js");
const manifest = JSON.parse(read("manifest.webmanifest"));
const workflow = read(".github/workflows/ci-cd.yml");

test("the hosted app publishes complete install metadata", () => {
  assert.equal(manifest.id, "./");
  assert.equal(manifest.start_url, "./");
  assert.equal(manifest.scope, "./");
  assert.equal(manifest.display, "standalone");
  assert.equal(manifest.name, "EntropyLab");
  assert.ok(manifest.icons.some((icon) => icon.sizes === "192x192"));
  assert.ok(manifest.icons.some((icon) => icon.sizes === "512x512"));
  assert.match(template, /rel="manifest" href="manifest\.webmanifest"/);
  assert.match(template, /rel="apple-touch-icon" href="assets\/pwa-icon-180\.png"/);
  assert.match(template, /name="apple-mobile-web-app-capable" content="yes"/);
  assert.match(template, /viewport-fit=cover/);
  assert.match(shell, /Share → Add to Home Screen → Open as Web App/);
  assert.match(shell, /Cached availability is not proof of an air gap/);
});

test("PWA icons have the declared square dimensions and alpha channel", () => {
  for (const size of [180, 192, 512]) {
    const png = readFileSync(join(root, `assets/pwa-icon-${size}.png`));
    assert.equal(png.readUInt32BE(16), size);
    assert.equal(png.readUInt32BE(20), size);
    assert.equal(png[25], 6, `${size}px icon is not RGBA`);
  }
});

test("service-worker registration is production-only and versioned", () => {
  assert.match(template, /\^\(www\\\.\)\?entropylab\\\.online\$/i);
  assert.match(template, /location\.protocol === "https:"/);
  assert.match(template, /serviceWorker\.register\("\.\/service-worker\.js\?v={{PWA_VERSION}}"/);
  assert.match(template, /updateViaCache: "none"/);
  assert.match(template, /registration\.update\(\)/);
  assert.match(read("scripts/build.mjs"), /createHash\("sha256"\)[\s\S]*manifest\.webmanifest[\s\S]*workerTemplate[\s\S]*{{PWA_VERSION}}/);
});

test("the worker caches only the self-contained app and serves navigations offline", () => {
  assert.match(worker, /const VERSION = "{{PWA_VERSION}}"/);
  assert.match(worker, /new Request\("\.\/", \{ cache: "reload" \}\)/);
  assert.match(worker, /new Request\("\.\/entropylab\.html", \{ cache: "reload" \}\)/);
  assert.match(worker, /event\.request\.mode !== "navigate"/);
  assert.match(worker, /url\.origin !== self\.location\.origin/);
  assert.match(worker, /cache\.match\(event\.request, \{ ignoreSearch: true \}\)/);
  assert.doesNotMatch(worker, /caches\.match\(/);
  assert.doesNotMatch(worker, /addEventListener\("(?:push|sync|notificationclick)"/i);
  // The network is touched only to precache the two documents at install
  // time, and only with cache: "reload". The navigation handler itself must
  // serve from the installed cache, never from the network.
  const handler = worker.slice(worker.indexOf("respondWith"));
  assert.doesNotMatch(handler, /fetch\(/);
  assert.doesNotMatch(handler, /caches\.match\(/);
});

test("the worker's installed cache answers a same-origin offline launch without network access", async () => {
  const listeners = new Map(), stored = new Map(), put = [];
  const cache = {
    async put(request, response) {
      put.push(request);
      const url = typeof request === "string" ? request : request.url;
      stored.set(url, await response.text());
    },
    async match(request) {
      const url = typeof request === "string" ? request : new URL(request.url).pathname === "/" ? "./" : `.${new URL(request.url).pathname}`;
      return stored.get(url);
    },
  };
  const caches = {
    async open() { return cache; },
    async keys() { return []; },
    async delete() { return true; },
    async match() { throw new Error("global cache lookup must not be used"); },
  };
  const self = {
    location: { href: "https://entropylab.online/service-worker.js?v=0.1.3", origin: "https://entropylab.online" },
    clients: { async claim() {} },
    async skipWaiting() {},
    addEventListener(type, listener) { listeners.set(type, listener); },
  };
  class Request {
    constructor(url, options) { this.url = url; this.cache = options.cache; }
  }
  // Both precache responses carry this build's own worker-URL marker, as the
  // generated documents do (audit L7).
  const revision = (name) => `<!doctype html><script>navigator.serviceWorker.register("./service-worker.js?v={{PWA_VERSION}}")</script>${name}`;
  const fetch = (request) => Promise.resolve({
    ok: true,
    status: 200,
    clone() { return this; },
    text: async () => revision(request.url === "./" ? "landing" : "app"),
  });
  runInNewContext(worker, { self, caches, URL, Promise, Request, fetch });
  let install;
  listeners.get("install")({ waitUntil(promise) { install = promise; } });
  await install;
  assert.deepEqual(put.map((request) => [request.url, request.cache]), [["./", "reload"], ["./entropylab.html", "reload"]]);
  let response;
  listeners.get("fetch")({
    request: { mode: "navigate", method: "GET", url: "https://entropylab.online/" },
    respondWith(promise) { response = promise; },
  });
  assert.equal(await response, revision("landing"));
});

test("a rolling deploy never caches two different revisions under one cache name (audit L7)", async () => {
  const listeners = new Map(), stored = new Map(), put = [], deleted = [];
  let skipped = false;
  const cache = {
    async put(request, response) {
      put.push(request);
      stored.set(request.url, await response.text());
    },
    async match(request) { return stored.get(request.url); },
  };
  const caches = {
    async open() { return cache; },
    async keys() { return ["entropylab-offline-previous"]; },
    async delete(name) { deleted.push(name); return true; },
  };
  const self = {
    location: { href: "https://entropylab.online/service-worker.js", origin: "https://entropylab.online" },
    clients: { async claim() {} },
    async skipWaiting() { skipped = true; },
    addEventListener(type, listener) { listeners.set(type, listener); },
  };
  class Request {
    constructor(url, options) { this.url = url; this.cache = options.cache; }
  }
  // The landing page answers from this worker's revision while the app
  // document already answers from the next one — the mixed pair the old
  // addAll accepted.
  const fetch = (request) => Promise.resolve({
    ok: true,
    status: 200,
    clone() { return this; },
    text: async () => request.url === "./"
      ? `register("./service-worker.js?v={{PWA_VERSION}}")`
      : `register("./service-worker.js?v=next-revision")`,
  });
  runInNewContext(worker, { self, caches, URL, Promise, Request, fetch });
  let install;
  listeners.get("install")({ waitUntil(promise) { install = promise; } });
  await assert.rejects(install, /revision/, "a mixed-revision pair must fail the install");
  assert.deepEqual(put.map((request) => request.url), ["./"], "only the own-revision document was cached before the foreign one failed");
  assert.equal(stored.has("./entropylab.html"), false, "the foreign-revision document was never cached");
  assert.equal(skipped, false, "the worker does not activate on a mixed precache");
  assert.deepEqual(deleted, [], "the previous usable cache is kept");
});

test("a failed precache never activates or deletes the previous usable cache", async () => {
  const listeners = new Map(), deleted = [];
  let skipped = false;
  const caches = {
    async open() { return { async put() {} }; },
    async keys() { return ["entropylab-offline-previous"]; },
    async delete(name) { deleted.push(name); return true; },
  };
  const self = {
    location: { href: "https://entropylab.online/service-worker.js", origin: "https://entropylab.online" },
    clients: { async claim() {} },
    async skipWaiting() { skipped = true; },
    addEventListener(type, listener) { listeners.set(type, listener); },
  };
  class Request {
    constructor(url, options) { this.url = url; this.cache = options.cache; }
  }
  const fetch = () => Promise.reject(new Error("precache failed"));
  runInNewContext(worker, { self, caches, URL, Promise, Request, fetch });
  let install;
  listeners.get("install")({ waitUntil(promise) { install = promise; } });
  await assert.rejects(install, /precache failed/);
  assert.equal(skipped, false);
  assert.deepEqual(deleted, []);
});

test("Pages publishes the manifest, worker, and icons with the tested HTML", () => {
  assert.match(workflow, /cp manifest\.webmanifest service-worker\.js _site\//);
  assert.match(workflow, /cp -r assets _site\/assets/);
  // Downstream jobs verify the exact candidate the build job produced, so the
  // generated worker must travel inside that artifact too.
  assert.match(workflow, /name: entropylab-candidate\s+path: \|\s+entropylab\.html\s+service-worker\.js/);
});

test("artifact verification binds the generated HTML to the generated worker", () => {
  const verify = read("scripts/verify-site.mjs");
  assert.match(verify, /service-worker\\\.js\\\?v=\(\[0-9a-f\]\{16\}\)/i);
  assert.match(verify, /worker\.match\(\/const VERSION/);
  assert.match(verify, /\[0-9a-f\]\{16\}/);
  assert.match(verify, /htmlPwaVersion !== workerPwaVersion/);
  assert.match(verify, /Unresolved PWA version token/);
});
