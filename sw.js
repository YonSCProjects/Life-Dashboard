const CACHE_NAME = 'life-dash-v37';
const ASSETS = [
  '/Life-Dashboard/',
  '/Life-Dashboard/index.html',
  '/Life-Dashboard/manifest.json',
];

// Install — cache shell assets
self.addEventListener('install', e => {
  e.waitUntil(caches.open(CACHE_NAME).then(c => c.addAll(ASSETS)));
  self.skipWaiting();
});

// Activate — clean old caches
self.addEventListener('activate', e => {
  e.waitUntil(
    caches.keys().then(keys =>
      Promise.all(keys.filter(k => k !== CACHE_NAME).map(k => caches.delete(k)))
    )
  );
  self.clients.claim();
});

// Fetch — network-first for API calls, cache-first for assets
self.addEventListener('fetch', e => {
  const url = new URL(e.request.url);

  // Always go to network for Google API calls
  if (url.hostname.includes('googleapis.com') || url.hostname.includes('accounts.google.com')) {
    return;
  }

  e.respondWith(
    fetch(e.request)
      .then(response => {
        // Cache successful responses for our own assets
        if (response.ok && url.origin === self.location.origin) {
          const clone = response.clone();
          caches.open(CACHE_NAME).then(c => c.put(e.request, clone));
        }
        return response;
      })
      .catch(() => caches.match(e.request))
  );
});

// Offline queue — store pending actions when offline
self.addEventListener('message', e => {
  if (e.data && e.data.type === 'QUEUE_ACTION') {
    // Store in IndexedDB for later sync
    storeAction(e.data.action);
  }
  if (e.data && e.data.type === 'FLUSH_QUEUE') {
    flushQueue().then(results => {
      e.source.postMessage({ type: 'QUEUE_FLUSHED', results });
    });
  }
});

// ══════════════════════════════════════════════════
// URGENT TASK REMINDERS (background)
// ══════════════════════════════════════════════════

// Server push (Web Push from the Cloudflare Worker) — fires even when the app
// is fully closed. Payload is { title, body }.
self.addEventListener('push', e => {
  let data = { title: '🚨 Urgent tasks need attention', body: 'You have urgent tasks open.' };
  try { if (e.data) data = e.data.json(); } catch {}
  e.waitUntil(self.registration.showNotification(data.title, {
    body: data.body,
    tag: 'urgent-tasks',
    renotify: true,
    requireInteraction: true,
    vibrate: [500, 200, 500, 200, 500],
    icon: '/Life-Dashboard/icons/icon-192.svg',
    badge: '/Life-Dashboard/icons/icon-192.svg',
    data: { url: '/Life-Dashboard/' },
  }));
});

// Periodic Background Sync wakes the worker; we check whether a reminder slot
// is due and fire an attention-catching notification for open urgent tasks.
// (Used only as a fallback when server push isn't enabled.)
self.addEventListener('periodicsync', e => {
  if (e.tag === 'urgent-reminders') e.waitUntil(runUrgentReminderCheck());
});

// Tapping a reminder focuses the app (or opens it if it isn't running).
self.addEventListener('notificationclick', e => {
  e.notification.close();
  const url = (e.notification.data && e.notification.data.url) || '/Life-Dashboard/';
  e.waitUntil(
    self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then(list => {
      for (const c of list) {
        if (c.url.includes('/Life-Dashboard') && 'focus' in c) return c.focus();
      }
      if (self.clients.openWindow) return self.clients.openWindow(url);
    })
  );
});

function notifDB() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open('life-dash-notif', 1);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains('state')) db.createObjectStore('state');
      if (!db.objectStoreNames.contains('fired')) db.createObjectStore('fired');
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}
async function notifGet(store, key) {
  try {
    const db = await notifDB();
    return await new Promise(r => {
      const req = db.transaction(store).objectStore(store).get(key);
      req.onsuccess = () => r(req.result);
      req.onerror = () => r(undefined);
    });
  } catch { return undefined; }
}
async function notifPut(store, key, val) {
  try {
    const db = await notifDB();
    db.transaction(store, 'readwrite').objectStore(store).put(val, key);
  } catch {}
}

async function runUrgentReminderCheck() {
  const cfg = await notifGet('state', 'config');
  if (!cfg || !cfg.enabled || !cfg.tasks || !cfg.tasks.length) return;

  const now = new Date();
  const ymd = now.getFullYear() + '-' + String(now.getMonth() + 1).padStart(2, '0') + '-' + String(now.getDate()).padStart(2, '0');
  const times = cfg.times && cfg.times.length ? cfg.times : ['09:00', '13:00', '17:00', '21:00'];

  // Periodic sync is coarse, so fire the most recent slot passed in the last 3h
  // that hasn't already been delivered today.
  let due = null;
  for (const time of times) {
    const [h, m] = time.split(':').map(Number);
    const slot = new Date(now); slot.setHours(h, m, 0, 0);
    const mins = (now - slot) / 60000;
    if (mins >= 0 && mins < 180) {
      const key = ymd + '#' + time;
      if (!(await notifGet('fired', key))) due = { time, key };
    }
  }
  if (!due) return;
  await notifPut('fired', due.key, Date.now());

  const titles = cfg.tasks.slice(0, 4).map(t => '• ' + t.title);
  const extra = cfg.tasks.length > 4 ? `\n…and ${cfg.tasks.length - 4} more` : '';
  await self.registration.showNotification(
    `🚨 ${cfg.tasks.length} urgent task${cfg.tasks.length > 1 ? 's' : ''} need attention`,
    {
      body: titles.join('\n') + extra,
      tag: 'urgent-tasks',
      renotify: true,
      requireInteraction: true,
      vibrate: [500, 200, 500, 200, 500],
      icon: '/Life-Dashboard/icons/icon-192.svg',
      badge: '/Life-Dashboard/icons/icon-192.svg',
      data: { url: '/Life-Dashboard/' },
    }
  );
}

// Simple IndexedDB helpers for offline queue
function openDB() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open('life-dash-queue', 1);
    req.onupgradeneeded = () => req.result.createObjectStore('actions', { autoIncrement: true });
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

async function storeAction(action) {
  const db = await openDB();
  const tx = db.transaction('actions', 'readwrite');
  tx.objectStore('actions').add(action);
}

async function flushQueue() {
  const db = await openDB();
  const tx = db.transaction('actions', 'readwrite');
  const store = tx.objectStore('actions');
  const all = await new Promise(r => { const req = store.getAll(); req.onsuccess = () => r(req.result); });
  store.clear();
  return all;
}
