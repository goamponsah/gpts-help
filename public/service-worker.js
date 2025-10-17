/* GPTs Help service worker: fast shell + fresh HTML */
const CACHE_STATIC = 'gptshelp-static-v3';   // bump when asset list changes
const CACHE_PAGES  = 'gptshelp-pages-v3';    // bump when HTML strategy changes

// Normalize both with and without trailing slash
const FOLDERS = ['/pricing', '/overview', '/download', '/support', '/search'];
const ASSETS = [
  '/',                  // homepage
  '/chat.html',
  ...FOLDERS.flatMap(p => [p, p + '/']),
  '/static/brand/logo-192.png',
  '/static/brand/logo-512.png',
];

self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_STATIC).then(c => c.addAll(ASSETS))
  );
  self.skipWaiting();
});

self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys().then(keys =>
      Promise.all(
        keys
          .filter(k => ![CACHE_STATIC, CACHE_PAGES].includes(k))
          .map(k => caches.delete(k))
      )
    )
  );
  self.clients.claim();
});

self.addEventListener('fetch', event => {
  const req = event.request;

  // Only handle GET
  if (req.method !== 'GET') return;

  const url = new URL(req.url);

  // Never cache API calls (keeps Paystack flow working)
  if (url.pathname.startsWith('/api/')) return;

  // For top-level navigations / HTML, use NETWORK-FIRST so updates show immediately
  if (req.mode === 'navigate' || (req.headers.get('accept') || '').includes('text/html')) {
    event.respondWith(networkFirstForPages(req));
    return;
  }

  // For other same-origin static assets, use STALE-WHILE-REVALIDATE
  if (url.origin === self.location.origin) {
    event.respondWith(staleWhileRevalidate(req));
    return;
  }
  // Otherwise let the request go to the network (e.g., CDNs, Paystack)
});

async function networkFirstForPages(request) {
  const cache = await caches.open(CACHE_PAGES);
  try {
    const fresh = await fetch(request);
    cache.put(request, fresh.clone()).catch(()=>{});
    return fresh;
  } catch {
    const cached = await cache.match(request) || await caches.match(request);
    return cached || Response.error();
  }
}

async function staleWhileRevalidate(request) {
  const cache = await caches.open(CACHE_STATIC);
  const cached = await cache.match(request);
  const fetchPromise = fetch(request).then(resp => {
    cache.put(request, resp.clone()).catch(()=>{});
    return resp;
  }).catch(()=>cached);
  return cached || fetchPromise;
}