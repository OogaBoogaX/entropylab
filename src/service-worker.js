// EntropyLab's production-only offline shell.
// Generated with a content-derived version so browser worker update checks can
// refresh the cached app even while several commits share one package version.
const VERSION = "{{PWA_VERSION}}";
const CACHE_PREFIX = "entropylab-offline-";
const CACHE_NAME = `${CACHE_PREFIX}${VERSION}`;

self.addEventListener("install", (event) => {
  event.waitUntil((async () => {
    const cache = await caches.open(CACHE_NAME);
    // Both documents enter one cache and must come from this worker's own
    // revision: two independent reload fetches can straddle a rolling deploy
    // and cache the landing page of one revision beside the app of another
    // (audit L7). Each generated document carries this build's own
    // service-worker URL marker; a mismatch fails the install — the previous
    // usable cache stays and the next install retries.
    for (const request of [
      new Request("./", { cache: "reload" }),
      new Request("./entropylab.html", { cache: "reload" }),
    ]) {
      const response = await fetch(request);
      if (!response.ok) throw new Error(`Precache failed: ${response.status}`);
      const clone = response.clone();
      const marker = (await response.text()).match(/service-worker\.js\?v=([^"'\s]+)/)?.[1];
      if (marker !== VERSION) throw new Error(`Precached document is revision ${marker ?? "unknown"}, not this worker's ${VERSION}.`);
      await cache.put(request, clone);
    }
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
