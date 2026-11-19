// Anti-Logging Bear by Priest

const CACHE = "__CACHE_NAME__";
const FILES = __PRECACHE__;
const SHELL = FILES.filter((path) => !path.startsWith("pyodide/") && !path.startsWith("py/"));

self.addEventListener("install", (event) => {
  event.waitUntil(caches.open(CACHE).then((cache) => cache.addAll(SHELL.map((path) => new Request(path, { cache: "no-cache" })))).then(() => self.skipWaiting()));
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(keys.filter((key) => key.startsWith("barry-") && key !== CACHE).map((key) => caches.delete(key))))
      .then(() => self.clients.claim()),
  );
});

self.addEventListener("fetch", (event) => {
  const request = event.request;
  if (request.method !== "GET" || new URL(request.url).origin !== self.location.origin) return;
  event.respondWith(fromCache(request));
});

async function fromCache(request) {
  const cache = await caches.open(CACHE);
  const hit = await cache.match(request, { ignoreSearch: true });
  if (hit) return hit;
  const response = await fetch(request, { cache: "no-cache" });
  const path = new URL(request.url).pathname.slice(new URL(self.registration.scope).pathname.length);
  if (response.ok && FILES.includes(path)) cache.put(request, response.clone());
  return response;
}
