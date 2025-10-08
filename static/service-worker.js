// iZwi Service Worker
const CACHE_NAME = 'izwi-v1';
const STATIC_CACHE = 'izwi-static-v1';
const DYNAMIC_CACHE = 'izwi-dynamic-v1';

// Assets to cache immediately
const STATIC_ASSETS = [
  '/',
  '/static/styles/app.css',
  '/static/js/dashboard.js',
  '/static/js/push-notifications.js',
  '/static/manifest.json',
  '/static/icons/icon-192.png',
  '/static/icons/icon-512.png',
  '/static/icons/apple-touch-icon.png',
  'https://cdn.tailwindcss.com?plugins=forms,container-queries',
  'https://fonts.googleapis.com/css2?family=Inter:wght@400;500;700&display=swap',
  'https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined'
];

// Install event - cache static assets
self.addEventListener('install', (event) => {
  console.log('[Service Worker] Installing');
  event.waitUntil(
    caches.open(STATIC_CACHE)
      .then((cache) => {
        console.log('[Service Worker] Caching static assets');
        return cache.addAll(STATIC_ASSETS);
      })
      .then(() => {
        console.log('[Service Worker] Static assets cached');
        return self.skipWaiting();
      })
      .catch((error) => {
        console.error('[Service Worker] Error caching static assets:', error);
      })
  );
});

// Activate event - clean up old caches
self.addEventListener('activate', (event) => {
  console.log('[Service Worker] Activating');
  event.waitUntil(
    caches.keys()
      .then((cacheNames) => {
        return Promise.all(
          cacheNames.map((cacheName) => {
            if (cacheName !== STATIC_CACHE && cacheName !== DYNAMIC_CACHE) {
              console.log('[Service Worker] Deleting old cache:', cacheName);
              return caches.delete(cacheName);
            }
          })
        );
      })
      .then(() => {
        console.log('[Service Worker] Activated');
        return self.clients.claim();
      })
  );
});

// Fetch event - implement caching strategies
self.addEventListener('fetch', (event) => {
  const { request } = event;
  const url = new URL(request.url);

  // Skip non-GET requests
  if (request.method !== 'GET') {
    return;
  }

  // Skip external requests that shouldn't be cached
  if (url.origin !== location.origin && !url.hostname.includes('cdn.tailwindcss.com') &&
      !url.hostname.includes('fonts.googleapis.com') && !url.hostname.includes('fonts.gstatic.com')) {
    return;
  }

  event.respondWith(
    caches.match(request)
      .then((cachedResponse) => {
        // If we have a cached response, return it for static assets
        if (cachedResponse && isStaticAsset(request.url)) {
          return cachedResponse;
        }

        // For HTML pages and API calls, try network first
        return fetch(request)
          .then((networkResponse) => {
            // If network request fails, return cached version or offline page
            if (!networkResponse || networkResponse.status !== 200) {
              if (cachedResponse) {
                return cachedResponse;
              }
              // Return offline page for navigation requests
              if (request.mode === 'navigate') {
                return caches.match('/offline');
              }
              return networkResponse;
            }

            // Cache successful responses
            const responseClone = networkResponse.clone();
            caches.open(DYNAMIC_CACHE)
              .then((cache) => {
                cache.put(request, responseClone);
              });

            return networkResponse;
          })
          .catch(() => {
            // Network failed, return cached version or offline page
            if (cachedResponse) {
              return cachedResponse;
            }
            // Return offline page for navigation requests
            if (request.mode === 'navigate') {
              return caches.match('/offline');
            }
            // For other requests, just fail
            throw new Error('Network request failed');
          });
      })
  );
});

// Push notification event
self.addEventListener('push', (event) => {
  console.log('[Service Worker] Push received');

  let notificationData = {
    title: 'iZwi Alert',
    body: 'New emergency alert posted',
    icon: '/static/icons/icon-192.png',
    badge: '/static/icons/icon-192.png',
    tag: 'izwi-alert',
    requireInteraction: true,
    actions: [
      {
        action: 'view',
        title: 'View Alert'
      },
      {
        action: 'dismiss',
        title: 'Dismiss'
      }
    ]
  };

  if (event.data) {
    try {
      const data = event.data.json();
      notificationData = { ...notificationData, ...data };
    } catch (e) {
      console.error('[Service Worker] Error parsing push data:', e);
    }
  }

  event.waitUntil(
    self.registration.showNotification(notificationData.title, notificationData)
  );
});

// Notification click event
self.addEventListener('notificationclick', (event) => {
  console.log('[Service Worker] Notification clicked');

  const { action } = event;

  event.notification.close();

  if (action === 'dismiss') {
    return;
  }

  // Default action is to open the app
  event.waitUntil(
    clients.openWindow('/')
  );
});

// Background sync for offline actions (if supported)
self.addEventListener('sync', (event) => {
  console.log('[Service Worker] Background sync:', event.tag);

  if (event.tag === 'background-sync') {
    event.waitUntil(
      // Handle background sync tasks
      handleBackgroundSync()
    );
  }
});

// Handle background sync tasks
async function handleBackgroundSync() {
  try {
    // Check for any pending actions that need to be synced
    const pendingActions = await getPendingActions();

    for (const action of pendingActions) {
      await syncAction(action);
    }

    console.log('[Service Worker] Background sync completed');
  } catch (error) {
    console.error('[Service Worker] Background sync failed:', error);
  }
}

// Helper function to determine if request is for static asset
function isStaticAsset(url) {
  return url.includes('.css') ||
         url.includes('.js') ||
         url.includes('.png') ||
         url.includes('.jpg') ||
         url.includes('.jpeg') ||
         url.includes('.svg') ||
         url.includes('.ico') ||
         url.includes('.woff') ||
         url.includes('.woff2') ||
         url.includes('.ttf');
}

// Helper function to get pending actions (placeholder for future implementation)
async function getPendingActions() {
  // This would typically check IndexedDB for pending actions
  return [];
}

// Helper function to sync action (placeholder for future implementation)
async function syncAction(action) {
  // This would typically send pending actions to the server
  console.log('[Service Worker] Syncing action:', action);
}
