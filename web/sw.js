/* Service worker NetWatch : shell + réception des notifications push. */
const CACHE = "netwatch-v3";
const SHELL = [
  "/",
  "/static/app.js",
  "/static/charts.js",
  "/static/theme.js",
  "/static/style.css",
  "/static/icons/icon-192.png",
  "/manifest.webmanifest",
];

self.addEventListener("install", (e) => {
  e.waitUntil(caches.open(CACHE).then((c) => c.addAll(SHELL)).then(() => self.skipWaiting()));
});

self.addEventListener("activate", (e) => {
  e.waitUntil(
    caches.keys().then((keys) => Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

/* Shell : RÉSEAU D'ABORD (pour que les mises à jour s'appliquent dès qu'on est en ligne),
   avec repli sur le cache hors-ligne. L'API n'est jamais mise en cache
   (données authentifiées et temps réel). */
self.addEventListener("fetch", (e) => {
  const req = e.request;
  if (req.method !== "GET") return;
  const url = new URL(req.url);
  if (url.origin !== location.origin || url.pathname.startsWith("/api/")) return;
  const isShell = url.pathname === "/" || url.pathname.startsWith("/static/") || url.pathname === "/manifest.webmanifest";
  if (!isShell) return;
  e.respondWith(
    fetch(req).then((res) => {
      const copy = res.clone();
      caches.open(CACHE).then((c) => c.put(req, copy)).catch(() => {});
      return res;
    }).catch(() => caches.match(req).then((hit) => hit || caches.match("/")))
  );
});

/* Notification push : le serveur envoie un JSON {title, body, tag, url, severity}. */
self.addEventListener("push", (e) => {
  let d = {};
  try { d = e.data ? e.data.json() : {}; } catch { d = { body: e.data && e.data.text() }; }
  const title = d.title || "NetWatch";
  const options = {
    body: d.body || "",
    tag: d.tag || undefined,
    renotify: !!d.tag,
    icon: "/static/icons/icon-192.png",
    badge: "/static/icons/icon-192.png",
    data: { url: d.url || "/" },
    timestamp: Date.now(),
  };
  e.waitUntil(self.registration.showNotification(title, options));
});

self.addEventListener("notificationclick", (e) => {
  e.notification.close();
  // on n'ouvre jamais autre chose qu'une page de NetWatch
  const wanted = String((e.notification.data && e.notification.data.url) || "/");
  const target = wanted.startsWith("/") && !wanted.startsWith("//") ? wanted : "/";
  e.waitUntil(
    self.clients.matchAll({ type: "window", includeUncontrolled: true }).then((cl) => {
      for (const c of cl) {
        if ("focus" in c) { c.navigate(target).catch(() => {}); return c.focus(); }
      }
      return self.clients.openWindow(target);
    })
  );
});
