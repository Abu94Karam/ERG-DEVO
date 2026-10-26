// ERG Service Worker — ضعه بجانب index.html في نفس المجلد على الاستضافة
// صفحة التطبيق: الشبكة أولاً (فتصلك التحديثات دائماً) ثم النسخة المخزنة عند انقطاع الاتصال
// مكتبات CDN: تُعرض من التخزين فوراً وتُحدَّث في الخلفية
const VERSION = 'v2';
const STATIC_CACHE = 'erg-static-' + VERSION;
const PAGE_CACHE = 'erg-pages-' + VERSION;
const CDN_HOSTS = [
    'cdn.tailwindcss.com', 'unpkg.com', 'cdnjs.cloudflare.com', 'cdn.jsdelivr.net',
    'www.gstatic.com', 'fonts.googleapis.com', 'fonts.gstatic.com'
];

self.addEventListener('install', () => { self.skipWaiting(); });

self.addEventListener('activate', (e) => {
    e.waitUntil(
        caches.keys()
            .then(keys => Promise.all(keys
                .filter(k => k !== STATIC_CACHE && k !== PAGE_CACHE)
                .map(k => caches.delete(k))))
            .then(() => self.clients.claim())
    );
});

self.addEventListener('fetch', (e) => {
    const req = e.request;
    if (req.method !== 'GET') return;
    const url = new URL(req.url);

    // طلبات Firebase وواجهات الخادم: تذهب للشبكة دائماً (Firestore له كاشه الخاص)
    if (/(firestore|identitytoolkit|securetoken|firebaseio)\.googleapis\.com$/.test(url.hostname)) return;
    if (/\.googleapis\.com$/.test(url.hostname) && !/^fonts\./.test(url.hostname)) return;
    if (url.origin === self.location.origin && url.pathname.startsWith('/api/')) return;

    // صفحة التطبيق: الشبكة أولاً
    const isPage = req.mode === 'navigate' ||
        (url.origin === self.location.origin && (req.headers.get('accept') || '').includes('text/html'));
    if (isPage) {
        e.respondWith(
            fetch(req)
                .then(res => {
                    if (res && res.status === 200) {
                        const copy = res.clone();
                        caches.open(PAGE_CACHE).then(c => c.put(req, copy));
                    }
                    return res;
                })
                .catch(() => caches.match(req, { ignoreSearch: true })
                    .then(r => r || caches.match(self.registration.scope)))
        );
        return;
    }

    // مكتبات CDN: من التخزين فوراً ثم تحديث صامت
    if (CDN_HOSTS.includes(url.hostname)) {
        e.respondWith(
            caches.open(STATIC_CACHE).then(async (cache) => {
                const hit = await cache.match(req);
                const net = fetch(req)
                    .then(res => {
                        if (res && (res.status === 200 || res.type === 'opaque')) cache.put(req, res.clone());
                        return res;
                    })
                    .catch(() => hit);
                return hit || net;
            })
        );
    }
});
