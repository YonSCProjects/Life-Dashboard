const CACHE_NAME = 'life-dash-v2';
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
