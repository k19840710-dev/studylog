// StudyLog Service Worker
// アプリ本体はネットワーク優先 (更新をすぐ反映)、CDN の CSS / フォント / スクリプトはキャッシュ優先で
// オフラインでも開けるようにする。
const CACHE_NAME = 'studylog-v27';
const APP_SHELL = [
  './',
  './index.html',
  './manifest.webmanifest',
  './icon-192.png',
  './icon-512.png',
  './apple-touch-icon.png'
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => cache.addAll(APP_SHELL)).then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(keys.filter((k) => k !== CACHE_NAME).map((k) => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (event) => {
  const req = event.request;
  if (req.method !== 'GET') return;

  // キャッシュするのはアプリ本体と CDN のファイルだけ。
  // Firebase との通信 (データベース・ログイン) には一切触れない
  const url = new URL(req.url);
  const cacheableHosts = ['cdn.tailwindcss.com', 'cdnjs.cloudflare.com', 'fonts.googleapis.com', 'fonts.gstatic.com', 'www.gstatic.com'];
  if (url.origin !== self.location.origin && !cacheableHosts.includes(url.hostname)) return;
  if (url.hostname === 'www.gstatic.com' && !url.pathname.startsWith('/firebasejs/')) return;

  // ページ本体: ネットワーク優先、オフライン時はキャッシュ
  if (req.mode === 'navigate') {
    event.respondWith(
      fetch(req)
        .then((res) => {
          const copy = res.clone();
          caches.open(CACHE_NAME).then((cache) => cache.put('./index.html', copy));
          return res;
        })
        .catch(() => caches.match('./index.html'))
    );
    return;
  }

  // それ以外: キャッシュがあればすぐ返し、裏で更新 (stale-while-revalidate)
  event.respondWith(
    caches.match(req).then((cached) => {
      const network = fetch(req)
        .then((res) => {
          if (res && (res.ok || res.type === 'opaque')) {
            const copy = res.clone();
            caches.open(CACHE_NAME).then((cache) => cache.put(req, copy));
          }
          return res;
        })
        .catch(() => cached);
      return cached || network;
    })
  );
});
