// EntropyLab's production-only offline shell.
// Generated with a content-derived version so browser worker update checks can
// refresh the cached app even while several commits share one package version.
const VERSION = "{{PWA_VERSION}}";
const CACHE_PREFIX = "entropylab-offline-";
const CACHE_NAME = `${CACHE_PREFIX}${VERSION}`;

self.addEventListener("install", (event) => {
  event.waitUntil((async () => {
    const cache = await caches.open(CACHE_NAME);
    await cache.addAll([
      new Request("./", { cache: "reload" }),
      new Request("./entropylab.html", { cache: "reload" }),
    ]);
    await self.skipWaiting();
  })());
});

self.addEventListener("activate", (event) => {
  event.waitUntil((async () => {
    const names = await caches.keys();
    await Promise.all(names.filter((name) => name.startsWith(CACHE_PREFIX) && name !== CACHE_NAME).map((name) => caches.delete(name)));
    await self.clients.claim();
  })());
});

self.addEventListener("fetch", (event) => {
  if (event.request.mode !== "navigate" || event.request.method !== "GET") return;
  const url = new URL(event.request.url);
  if (url.origin !== self.location.origin) return;
  event.respondWith((async () => {
    const cache = await caches.open(CACHE_NAME);
    const exact = await cache.match(event.request, { ignoreSearch: true });
    if (exact) return exact;
    return cache.match("./");
  })());
});
