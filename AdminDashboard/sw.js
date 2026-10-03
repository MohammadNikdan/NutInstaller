// sw.js - caches the static app shell ONLY (HTML/CSS/JS/icons), never any
// admin_*.php response. This panel's whole point is live, current data - an
// offline/stale copy of stats or a cached ban list would be actively
// misleading, so every API call always goes to the network, never to this
// cache. The cache exists purely so the shell (icons, layout, JS) loads
// instantly when you open the installed PWA, before the first live fetch
// completes.

const CACHE_NAME = 'nutricula-admin-shell-v2';
const SHELL_FILES = [
  './',
  './index.html',
  './style.css',
  './app.js',
  './manifest.json',
  './icon-192.png',
  './icon-512.png',
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => cache.addAll(SHELL_FILES))
  );
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.filter((k) => k !== CACHE_NAME).map((k) => caches.delete(k)))
    )
  );
  self.clients.claim();
});

self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);

  // Never intercept API calls or anything outside this panel's own origin -
  // those must always hit the network fresh.
  if (url.pathname.includes('admin_') || event.request.method !== 'GET') {
    return;
  }

  event.respondWith(
    caches.match(event.request).then((cached) => cached || fetch(event.request))
  );
});
