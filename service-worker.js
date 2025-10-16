/* GPTs Help service worker: cache shell for fast a2hs launch */
const CACHE = 'gptshelp-v1';
const ASSETS = [
  '/',               // if your homepage is index.html
  '/chat.html',
  '/pricing',
  '/overview',
  '/download',
  '/support',
  '/search',
  '/static/brand/logo-192.png',
  '/static/brand/logo-512.png'
];

self.addEventListener('install', event => {
  event.waitUntil(caches.open(CACHE).then(c => c.addAll(ASSETS)));
  self.skipWaiting();
});

self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys().then(keys => Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k))))
  );
  self.clients.claim();
});

self.addEventListener('fetch', event => {
  const { request } = event;
  if (request.method !== 'GET') return;
  event.respondWith(
    caches.match(request).then(cached => cached || fetch(request).then(resp => {
      const copy = resp.clone();
      caches.open(CACHE).then(c => c.put(request, copy)).catch(()=>{});
      return resp;
    }).catch(() => cached))
  );
});
