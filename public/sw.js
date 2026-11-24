/* AFM — service worker : permet l'installation et l'ouverture de l'application même avec une connexion faible.
   Les données du club (/api/...) ne sont jamais mises en cache : elles viennent toujours du serveur. */
const CACHE = "afm-v6";
const SHELL = ["/", "/index.html", "/logo.png", "/icon-192.png", "/icon-512.png", "/apple-touch-icon.png", "/badge-96.png", "/manifest.webmanifest"];

self.addEventListener("install", e => {
  e.waitUntil(caches.open(CACHE).then(c => c.addAll(SHELL)).then(() => self.skipWaiting()));
});
self.addEventListener("activate", e => {
  e.waitUntil(caches.keys().then(keys => Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k)))).then(() => self.clients.claim()));
});
self.addEventListener("fetch", e => {
  const req = e.request;
  const url = new URL(req.url);
  if (req.method !== "GET" || url.origin !== location.origin || url.pathname.startsWith("/api/")) return;
  // Page : réseau d'abord (pour avoir la dernière version), cache si hors ligne
  if (req.mode === "navigate") {
    e.respondWith(fetch(req).then(r => { const copy = r.clone(); caches.open(CACHE).then(c => c.put("/index.html", copy)); return r; })
      .catch(() => caches.match("/index.html")));
    return;
  }
  // Images et fichiers : cache d'abord, mis à jour en arrière-plan
  e.respondWith(caches.match(req).then(hit => {
    const net = fetch(req).then(r => { if (r.ok) { const copy = r.clone(); caches.open(CACHE).then(c => c.put(req, copy)); } return r; }).catch(() => hit);
    return hit || net;
  }));
});

/* Notifications push : le serveur envoie un signal, on récupère le contenu puis on l'affiche */
self.addEventListener("push", e => {
  e.waitUntil((async () => {
    let items = [];
    try { const r = await fetch("/api/push/inbox", { credentials: "include", cache: "no-store" }); if (r.ok) items = (await r.json()).items || []; } catch (err) {}
    if (!items.length) items = [{ title: "AFM", body: "Du nouveau dans l'application du club", url: "/" }];
    for (const n of items.slice(-3)) {
      await self.registration.showNotification(n.title, { body: n.body, icon: "/icon-192.png", badge: "/badge-96.png", tag: n.tag || n.id, renotify: !!n.tag, data: { url: n.url || "/" }, vibrate: [120, 60, 120] });
    }
    try { const open = await self.registration.getNotifications(); if (self.navigator.setAppBadge) await self.navigator.setAppBadge(open.length); } catch (err) {}
  })());
});
self.addEventListener("notificationclick", e => {
  e.notification.close();
  const url = new URL((e.notification.data && e.notification.data.url) || "/", self.location.origin).href;
  e.waitUntil((async () => {
    const wins = await self.clients.matchAll({ type: "window", includeUncontrolled: true });
    for (const w of wins) { if (new URL(w.url).origin === self.location.origin) { try { await w.navigate(url); } catch (err) {} return w.focus(); } }
    return self.clients.openWindow(url);
  })());
});
