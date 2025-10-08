/**
 * iZwi Push Notifications
 * Handles web push notification subscription and management
 */

// Push notification utilities
class PushNotifications {
    constructor() {
        this.vapidPublicKey = null;
        this.isSubscribed = false;
        this.subscription = null;
        this.userId = null;

        // Initialize when DOM is ready
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', () => this.init());
        } else {
            this.init();
        }
    }

    async init() {
        console.log('[PushNotifications] Initializing...');

        try {
            // Get user ID first (DOM should be ready now)
            this.userId = this.getCurrentUserId();
            console.log('[PushNotifications] User ID for initialization:', this.userId);

            // Check if push notifications are supported
            if (!('serviceWorker' in navigator) || !('PushManager' in window)) {
                console.log('[PushNotifications] Push notifications not supported');
                this.showUnsupportedMessage();
                return;
            }

            // Get VAPID public key from server
            await this.getVapidPublicKey();

            // Check if already subscribed
            await this.checkSubscriptionStatus();

            // Setup event listeners
            this.setupEventListeners();

            console.log('[PushNotifications] Initialized successfully');

        } catch (error) {
            console.error('[PushNotifications] Initialization failed:', error);
        }
    }

    async getVapidPublicKey() {
        try {
            const response = await fetch('/api/push/vapid-public-key');
            if (!response.ok) {
                throw new Error('Failed to get VAPID public key');
            }
            const data = await response.json();
            this.vapidPublicKey = data.vapid_public_key;

            if (!this.vapidPublicKey) {
                throw new Error('No VAPID public key received');
            }

            console.log('[PushNotifications] VAPID public key obtained');
        } catch (error) {
            console.error('[PushNotifications] Error getting VAPID public key:', error);
            throw error;
        }
    }

    async checkSubscriptionStatus() {
        try {
            const registration = await navigator.serviceWorker.ready;
            const subscription = await registration.pushManager.getSubscription();

            if (subscription) {
                this.subscription = subscription;
                this.isSubscribed = true;
                this.updateSubscriptionUI();
                console.log('[PushNotifications] Already subscribed');
            } else {
                this.isSubscribed = false;
                this.updateSubscriptionUI();
                console.log('[PushNotifications] Not subscribed');
            }
        } catch (error) {
            console.error('[PushNotifications] Error checking subscription status:', error);
        }
    }

    setupEventListeners() {
        // Listen for subscription button clicks
        document.addEventListener('click', (event) => {
            if (event.target.matches('[data-push-action="subscribe"]')) {
                event.preventDefault();
                this.subscribe();
            } else if (event.target.matches('[data-push-action="unsubscribe"]')) {
                event.preventDefault();
                this.unsubscribe();
            }
        });

        // Listen for push notification permission changes
        if ('permissions' in navigator) {
            navigator.permissions.query({ name: 'notifications' })
                .then((permissionStatus) => {
                    permissionStatus.addEventListener('change', () => {
                        this.handlePermissionChange(permissionStatus.state);
                    });
                })
                .catch((error) => {
                    console.log('[PushNotifications] Could not query notification permissions:', error);
                });
        }
    }

    async subscribe() {
        console.log('[PushNotifications] Subscribing to push notifications...');

        try {
            // Get current user ID (DOM should be fully loaded now)
            this.userId = this.getCurrentUserId();
            console.log('[PushNotifications] User ID for subscription:', this.userId);

            if (!this.userId) {
                this.showToast('You must be logged in to enable push notifications.', 'error');
                return;
            }

            // Check if notifications are permitted
            if (Notification.permission === 'denied') {
                console.log('[PushNotifications] Notifications denied');
                this.showPermissionDeniedMessage();
                return;
            }

            // Request notification permission if not granted
            if (Notification.permission === 'default') {
                console.log('[PushNotifications] Requesting notification permission...');
                const permission = await Notification.requestPermission();
                console.log('[PushNotifications] Permission result:', permission);
                if (permission !== 'granted') {
                    this.showPermissionDeniedMessage();
                    return;
                }
            }

            // Get service worker registration
            console.log('[PushNotifications] Getting service worker registration...');
            const registration = await navigator.serviceWorker.ready;
            console.log('[PushNotifications] Service worker ready:', registration);

            // Convert VAPID key to Uint8Array
            console.log('[PushNotifications] VAPID public key length:', this.vapidPublicKey ? this.vapidPublicKey.length : 'No key');
            const vapidKeyUint8Array = this.urlBase64ToUint8Array(this.vapidPublicKey);

            // Subscribe to push notifications
            console.log('[PushNotifications] Creating push subscription...');
            const subscription = await registration.pushManager.subscribe({
                userVisibleOnly: true,
                applicationServerKey: vapidKeyUint8Array
            });
            console.log('[PushNotifications] Push subscription created:', subscription ? 'Success' : 'Failed');

            // Send subscription to server
            console.log('[PushNotifications] Sending subscription to server...');
            await this.sendSubscriptionToServer(subscription);

            this.subscription = subscription;
            this.isSubscribed = true;
            this.updateSubscriptionUI();

            this.showToast('Push notifications enabled!', 'success');
            console.log('[PushNotifications] Successfully subscribed');

        } catch (error) {
            console.error('[PushNotifications] Subscription failed:', error);
            this.showToast('Failed to enable push notifications. Please try again.', 'error');
        }
    }

    async unsubscribe() {
        console.log('[PushNotifications] Unsubscribing from push notifications...');

        try {
            if (this.subscription) {
                await this.subscription.unsubscribe();

                // Remove subscription from server
                await this.removeSubscriptionFromServer();

                this.subscription = null;
                this.isSubscribed = false;
                this.updateSubscriptionUI();

                this.showToast('Push notifications disabled', 'info');
                console.log('[PushNotifications] Successfully unsubscribed');
            }
        } catch (error) {
            console.error('[PushNotifications] Unsubscription failed:', error);
            this.showToast('Failed to disable push notifications. Please try again.', 'error');
        }
    }

    async sendSubscriptionToServer(subscription) {
        try {
            console.log('[PushNotifications] Preparing subscription data...');
            const subscriptionData = {
                user_id: this.userId,
                endpoint: subscription.endpoint,
                keys: {
                    p256dh: arrayBufferToBase64(subscription.getKey('p256dh')),
                    auth: arrayBufferToBase64(subscription.getKey('auth'))
                }
            };

            console.log('[PushNotifications] Subscription data prepared:', subscriptionData);
            console.log('[PushNotifications] CSRF token:', this.getCsrfToken());

            const response = await fetch('/api/push/subscribe', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': this.getCsrfToken()
                },
                body: JSON.stringify(subscriptionData)
            });

            console.log('[PushNotifications] Server response status:', response.status);

            if (!response.ok) {
                const errorData = await response.json();
                console.error('[PushNotifications] Server error response:', errorData);
                throw new Error(errorData.error || 'Failed to save subscription');
            }

            console.log('[PushNotifications] Subscription saved to server');
        } catch (error) {
            console.error('[PushNotifications] Error saving subscription to server:', error);
            throw error;
        }
    }

    async removeSubscriptionFromServer() {
        try {
            const subscriptionData = {
                user_id: this.userId,
                endpoint: this.subscription.endpoint
            };

            const response = await fetch('/api/push/unsubscribe', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': this.getCsrfToken()
                },
                body: JSON.stringify(subscriptionData)
            });

            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.error || 'Failed to remove subscription');
            }

            console.log('[PushNotifications] Subscription removed from server');
        } catch (error) {
            console.error('[PushNotifications] Error removing subscription from server:', error);
            throw error;
        }
    }

    updateSubscriptionUI() {
        const subscribeButtons = document.querySelectorAll('[data-push-action="subscribe"]');
        const unsubscribeButtons = document.querySelectorAll('[data-push-action="unsubscribe"]');

        if (this.isSubscribed) {
            subscribeButtons.forEach(btn => {
                btn.style.display = 'none';
            });
            unsubscribeButtons.forEach(btn => {
                btn.style.display = 'inline-flex';
            });
        } else {
            subscribeButtons.forEach(btn => {
                btn.style.display = 'inline-flex';
            });
            unsubscribeButtons.forEach(btn => {
                btn.style.display = 'none';
            });
        }
    }

    handlePermissionChange(permission) {
        if (permission === 'denied') {
            this.isSubscribed = false;
            this.updateSubscriptionUI();
            this.showPermissionDeniedMessage();
        } else if (permission === 'granted') {
            this.checkSubscriptionStatus();
        }
    }

    showToast(message, type = 'info') {
        // Use existing toast system if available
        if (window.showToast) {
            window.showToast(message, type);
        } else {
            // Fallback toast implementation
            const toast = document.createElement('div');
            toast.className = `fixed top-4 right-4 z-50 p-4 rounded-lg shadow-lg ${
                type === 'success' ? 'bg-green-500' :
                type === 'error' ? 'bg-red-500' : 'bg-blue-500'
            } text-white`;
            toast.textContent = message;

            document.body.appendChild(toast);

            setTimeout(() => {
                toast.remove();
            }, 5000);
        }
    }

    showPermissionDeniedMessage() {
        this.showToast(
            'Push notifications are blocked. Please enable them in your browser settings to receive alerts.',
            'error'
        );
    }

    showUnsupportedMessage() {
        this.showToast(
            'Push notifications are not supported in this browser.',
            'info'
        );
    }

    getCurrentUserId() {
        console.log('[PushNotifications] Getting current user ID...');

        // First try to get user ID from body data attribute
        const body = document.body;
        if (body && body.dataset.userId) {
            const userId = parseInt(body.dataset.userId);
            console.log('[PushNotifications] Found user ID in body data:', userId);
            if (userId && userId > 0) {
                return userId;
            }
        }

        // Fallback: try to get user ID from data-user-id attribute on elements
        const userIdElement = document.querySelector('[data-user-id]');
        if (userIdElement && userIdElement.dataset.userId) {
            const userId = parseInt(userIdElement.dataset.userId);
            console.log('[PushNotifications] Found user ID in element data:', userId);
            if (userId && userId > 0) {
                return userId;
            }
        }

        // Fallback: try to extract from URL or other sources
        const pathParts = window.location.pathname.split('/');
        const dashboardIndex = pathParts.indexOf('dashboard');
        if (dashboardIndex >= 0 && pathParts.length > dashboardIndex) {
            const userId = parseInt(pathParts[dashboardIndex + 1]);
            console.log('[PushNotifications] Found user ID in URL path:', userId);
            if (userId && userId > 0) {
                return userId;
            }
        }

        console.warn('[PushNotifications] Could not determine user ID');
        console.log('[PushNotifications] Body dataset:', body ? body.dataset : 'No body element');
        console.log('[PushNotifications] Current URL:', window.location.href);
        return null;
    }

    getCsrfToken() {
        console.log('[PushNotifications] Getting CSRF token...');

        // Get CSRF token from meta tag or cookie
        const tokenElement = document.querySelector('meta[name="csrf-token"]');
        if (tokenElement && tokenElement.getAttribute('content')) {
            const token = tokenElement.getAttribute('content');
            console.log('[PushNotifications] Found CSRF token in meta tag:', token ? 'Token found' : 'No token');
            return token;
        }

        // Fallback: try to get from cookie
        const cookies = document.cookie.split(';');
        for (let cookie of cookies) {
            const [name, value] = cookie.trim().split('=');
            if (name === 'csrf_token') {
                console.log('[PushNotifications] Found CSRF token in cookie');
                return value;
            }
        }

        console.warn('[PushNotifications] CSRF token not found');
        console.log('[PushNotifications] Available cookies:', document.cookie);
        console.log('[PushNotifications] Meta elements:', document.querySelectorAll('meta[name="csrf-token"]'));
        return '';
    }

    // Utility function to convert VAPID key
    urlBase64ToUint8Array(base64String) {
        const padding = '='.repeat((4 - base64String.length % 4) % 4);
        const base64 = (base64String + padding)
            .replace(/-/g, '+')
            .replace(/_/g, '/');

        const rawData = window.atob(base64);
        const outputArray = new Uint8Array(rawData.length);

        for (let i = 0; i < rawData.length; ++i) {
            outputArray[i] = rawData.charCodeAt(i);
        }
        return outputArray;
    }
}

// Utility function to convert ArrayBuffer to base64
function arrayBufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return window.btoa(binary);
}

// PWA Installation functionality
class PWAManager {
    constructor() {
        this.deferredPrompt = null;
        this.isInstallable = false;

        // Initialize when DOM is ready
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', () => this.init());
        } else {
            this.init();
        }
    }

    async init() {
        console.log('[PWA Manager] Initializing...');

        // Check if PWA installation is supported
        if (!('serviceWorker' in navigator)) {
            console.log('[PWA Manager] Service Worker not supported');
            this.updateInstallUI(false, 'Service Worker not supported');
            return;
        }

        // Listen for beforeinstallprompt event
        window.addEventListener('beforeinstallprompt', (event) => {
            console.log('[PWA Manager] beforeinstallprompt event fired');
            event.preventDefault();
            this.deferredPrompt = event;
            this.isInstallable = true;
            this.updateInstallUI(true, 'Ready to install');
        });

        // Listen for app installed event
        window.addEventListener('appinstalled', () => {
            console.log('[PWA Manager] App installed successfully');
            this.isInstallable = false;
            this.deferredPrompt = null;
            this.updateInstallUI(false, 'App installed successfully!');
        });

        // Check if already installed
        if (window.matchMedia && window.matchMedia('(display-mode: standalone)').matches) {
            console.log('[PWA Manager] App is already installed');
            this.updateInstallUI(false, 'App is already installed');
        }

        console.log('[PWA Manager] Initialized');
    }

    async installPWA() {
        if (!this.deferredPrompt) {
            console.log('[PWA Manager] Install prompt not available');
            this.updateInstallUI(false, 'Install prompt not available');
            return;
        }

        try {
            // Show the install prompt
            this.deferredPrompt.prompt();

            // Wait for user response
            const { outcome } = await this.deferredPrompt.userChoice;

            if (outcome === 'accepted') {
                console.log('[PWA Manager] User accepted the install prompt');
                this.updateInstallUI(false, 'Installing...');
            } else {
                console.log('[PWA Manager] User dismissed the install prompt');
                this.updateInstallUI(true, 'Installation cancelled');
            }

            // Clear the deferred prompt
            this.deferredPrompt = null;

        } catch (error) {
            console.error('[PWA Manager] Error during installation:', error);
            this.updateInstallUI(false, 'Installation failed');
        }
    }

    updateInstallUI(showButton, statusMessage) {
        const installBtn = document.getElementById('install-pwa-btn');
        const statusEl = document.getElementById('install-pwa-status');

        if (installBtn) {
            if (showButton && this.isInstallable) {
                installBtn.classList.remove('hidden');
            } else {
                installBtn.classList.add('hidden');
            }
        }

        if (statusEl) {
            statusEl.textContent = statusMessage || 'Install button will appear when your browser supports PWA installation.';
        }
    }
}

// Initialize PWA manager
const pwaManager = new PWAManager();

// Global function for install button
window.installPWA = function() {
    pwaManager.installPWA();
};

// Initialize push notifications when script loads
const pushNotifications = new PushNotifications();

// Expose to global scope for debugging
window.pushNotifications = pushNotifications;
window.pwaManager = pwaManager;
