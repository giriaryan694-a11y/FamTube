/*
 * FamTube PWA worker.
 * Privacy-first policy: cache only the offline fallback and public app icons.
 * Never cache authenticated HTML, API responses, media, thumbnails, or uploads.
 */
'use strict';

const CACHE_PREFIX = 'famtube-pwa-';
const CACHE_NAME = `${CACHE_PREFIX}shell-v1`;
const CORE_ASSETS = [
  '/static/offline.html',
  '/static/icons/icon-192.png',
  '/static/icons/icon-512.png'
];
const SAFE_CACHE_PATHS = new Set(CORE_ASSETS);

self.addEventListener('install', (event) => {
  event.waitUntil((async () => {
    const cache = await caches.open(CACHE_NAME);
    await cache.addAll(CORE_ASSETS.map((url) => new Request(url, { cache: 'reload' })));
    await self.skipWaiting();
  })());
});

self.addEventListener('activate', (event) => {
  event.waitUntil((async () => {
    const names = await caches.keys();
    await Promise.all(names
      .filter((name) => name.startsWith(CACHE_PREFIX) && name !== CACHE_NAME)
      .map((name) => caches.delete(name)));
    await self.clients.claim();
  })());
});

self.addEventListener('fetch', (event) => {
  const request = event.request;
  if (request.method !== 'GET') return;

  const url = new URL(request.url);
  if (url.origin !== self.location.origin) return;

  // App pages are dynamic and may contain private videos, account data, and CSRF
  // tokens. Use the network; if it fails, show only a generic offline page.
  if (request.mode === 'navigate') {
    event.respondWith((async () => {
      try {
        return await fetch(request);
      } catch (_error) {
        const offline = await caches.match('/static/offline.html');
        return offline || new Response('FamTube is offline. Reconnect and try again.', {
          status: 503,
          headers: { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' }
        });
      }
    })());
    return;
  }

  // Cache only the explicitly enumerated, non-sensitive PWA shell resources.
  // All media, thumbnails, API, Socket.IO, and other routes remain network-only.
  if (SAFE_CACHE_PATHS.has(url.pathname) && url.search === '') {
    event.respondWith((async () => {
      const cached = await caches.match(request, { ignoreSearch: false });
      if (cached) return cached;
      try {
        const response = await fetch(request);
        if (response.ok && response.type === 'basic') {
          const cache = await caches.open(CACHE_NAME);
          await cache.put(request, response.clone());
        }
        return response;
      } catch (_error) {
        return new Response('Resource unavailable offline.', {
          status: 503,
          headers: { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' }
        });
      }
    })());
  }
});
