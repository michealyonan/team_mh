// team_mh shell — network-first always; offline page only when there is no connection.
// Never serves stale app code: app HTML/JS always come from the network.
const C = 'tmh-shell-v1';
const ASSETS = ['./offline.html', './logo.png', './apple-touch-icon.png', './icon-192.png', './icon-512.png', './manifest.webmanifest'];
self.addEventListener('install', e => {
  e.waitUntil(caches.open(C).then(c => c.addAll(ASSETS)).then(() => self.skipWaiting()));
});
self.addEventListener('activate', e => {
  e.waitUntil(caches.keys().then(ks => Promise.all(ks.filter(k => k !== C).map(k => caches.delete(k)))).then(() => self.clients.claim()));
});
self.addEventListener('fetch', e => {
  if (e.request.method !== 'GET') return;
  const url = new URL(e.request.url);
  if (url.origin !== location.origin) return;
  if (e.request.mode === 'navigate') {
    e.respondWith(fetch(e.request).catch(() => caches.match('./offline.html')));
  }
  // everything else (including /api/) goes straight to the network untouched
});
