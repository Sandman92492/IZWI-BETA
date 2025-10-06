// Dashboard Map and Alert Management
console.log('Dashboard JavaScript loading...');

// Wait for DOM to be ready
document.addEventListener('DOMContentLoaded', function() {
    console.log('DOM ready, preparing map init...');

    var mapContainer = document.getElementById('map');
    if (!mapContainer) {
        console.error('Map container not found!');
        return;
    }

    // Parse alerts data once
    var alertsData = document.getElementById('alerts-data');
    var alerts = alertsData ? (function(){ try { return JSON.parse(alertsData.textContent); } catch(_) { return []; } })() : [];
    console.log('Raw alerts data from template:', alertsData ? alertsData.textContent : 'No alerts-data element found');
    console.log('Parsed alerts:', alerts);

    // Get boundary data and normalize to valid GeoJSON
    var boundaryDataElement = document.getElementById('boundary-data');
    var boundaryData = null;
    function normalizeGeoJson(input) {
        var data = input;
        try {
            if (typeof data === 'string') {
                data = JSON.parse(data);
            }
        } catch (_) { /* ignore */ }
        // If still a string, try one more time (double-encoded cases)
        if (typeof data === 'string') {
            try { data = JSON.parse(data); } catch (_) { /* ignore */ }
        }
        // Wrap bare geometry into a Feature
        if (data && typeof data === 'object' && data.type) {
            var t = data.type;
            if (t === 'Polygon' || t === 'MultiPolygon' || t === 'LineString' || t === 'MultiLineString') {
                return { type: 'Feature', geometry: data, properties: {} };
            }
        }
        return data;
    }

    if (boundaryDataElement) {
        try {
            var rawText = boundaryDataElement.textContent;
            boundaryData = normalizeGeoJson(rawText);
        } catch (e) {
            console.warn('Failed to parse boundary JSON:', e);
            boundaryData = null;
        }
    }
    
    console.log('Boundary data (normalized):', boundaryData);

    // Location detection and map centering
    var mapCenter = [-26.2041, 28.0473]; // Default to Johannesburg
    var mapZoom = 13;
    var locationDetected = false;
    var validAlerts = [];

    // Check if we have meaningful alerts with real coordinates
    if (alerts.length > 0) {
        // Filter alerts with valid coordinates (not default Johannesburg)
        validAlerts = alerts.filter(function(alert) {
            var lat = alert.lat || alert.latitude;
            var lng = alert.lng || alert.longitude;
            return lat && lng && !isNaN(lat) && !isNaN(lng) && (lat !== -26.2041 || lng !== 28.0473);
        });
        
        if (validAlerts.length > 0) {
            // Calculate average coordinates from real alerts
            var sumLat = validAlerts.reduce(function(sum, alert) { 
                return sum + (alert.lat || alert.latitude); 
            }, 0);
            var sumLng = validAlerts.reduce(function(sum, alert) { 
                return sum + (alert.lng || alert.longitude); 
            }, 0);
            
            mapCenter = [sumLat / validAlerts.length, sumLng / validAlerts.length];
            mapZoom = validAlerts.length === 1 ? 15 : 13; // Zoom closer for single alert
            locationDetected = true;
        }
    }

    console.log('Map center:', mapCenter, 'zoom:', mapZoom, 'Location detected:', locationDetected);
    console.log('Valid alerts for centering:', validAlerts.length);

    var map;
    function doInitMap(){
        if (map) return map;
        try {
            // Ensure map container is visible and has dimensions
            const mapElement = document.getElementById('map');
            if (!mapElement) {
                console.error('Map element not found');
                return null;
            }

            if (mapElement.offsetWidth === 0 || mapElement.offsetHeight === 0) {
                console.warn('Map container has no dimensions, retrying...');
                setTimeout(doInitMap, 100);
                return null;
            }

            map = L.map('map', {
                gestureHandling: true,
                fadeAnimation: true,
                zoomAnimation: true,
                markerZoomAnimation: true
            }).setView(mapCenter, mapZoom);

            console.log('Map initialized successfully with dimensions:', mapElement.offsetWidth, 'x', mapElement.offsetHeight);
        } catch (e) {
            console.error('Error initializing map:', e);
            return null;
        }
        return map;
    }

    function containerHasSize(){
        try { return (mapContainer.offsetWidth > 0 && mapContainer.offsetHeight > 0); } catch(_) { return false; }
    }

    function initWhenReady(){
        console.log('initWhenReady called. Container size:', containerHasSize() ? 'has size' : 'no size');

        if (!containerHasSize()) {
            console.log('Container has no size, setting up observers...');
            // Delay and observe for size changes
            try {
                if (!window.__mapSizeObserver) {
                    window.__mapSizeObserver = new ResizeObserver(function(){
                        console.log('ResizeObserver triggered, container size:', containerHasSize());
                        if (containerHasSize()) {
                            try { window.__mapSizeObserver.disconnect(); } catch(_) {}
                            setTimeout(function(){ if (!map) { doInitMap(); afterInit(); } }, 0);
                        }
                    });
                }
                window.__mapSizeObserver.observe(mapContainer);
            } catch(_) {
                console.warn('ResizeObserver not supported');
            }
            // Fallback timer
            setTimeout(function(){
                console.log('Fallback timer, container size:', containerHasSize());
                if (!map && containerHasSize()) { doInitMap(); afterInit(); }
            }, 300);
            return;
        }
        console.log('Container has size, initializing map...');
        if (!map) { doInitMap(); afterInit(); }
    }

    function afterInit(){
        if (!map) return;
        console.log('AfterInit: Map ready, processing alerts:', alerts.length);
        
        // Add standard OSM tiles and adjust visuals in dark mode to keep color but reduce glare
        L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
            attribution: '© OpenStreetMap contributors',
            maxZoom: 18,
            errorTileUrl: 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=='
        }).addTo(map);

        function isDarkMode(){ return document.documentElement.classList.contains('dark'); }
        function applyMapVisuals(){
            try {
                var el = map.getContainer();
                if (!el) return;
                if (isDarkMode()) {
                    // Slightly dim and increase contrast/saturation for subtle dark appearance
                    el.style.filter = 'brightness(0.92) contrast(1.03) saturate(1.05)';
                } else {
                    el.style.filter = '';
                }
            } catch(_) {}
        }
        applyMapVisuals();
        // React to theme changes
        try {
            var observer = new MutationObserver(function(){ applyMapVisuals(); });
            observer.observe(document.documentElement, { attributes:true, attributeFilter:['class'] });
            if (window.matchMedia) {
                var mq = window.matchMedia('(prefers-color-scheme: dark)');
                if (mq && mq.addEventListener) mq.addEventListener('change', function(){ applyMapVisuals(); });
            }
            window.addEventListener('storage', function(e){ if (e.key === 'theme') applyMapVisuals(); });
        } catch(_) {}

        // Community boundary variable
        var communityBoundary = null;

    // Load and display community boundary if available
    if (boundaryData) {
        try {
            var geoJsonData = normalizeGeoJson(boundaryData);
            // If we still don't have a recognizable geojson, bail
            var isFeature = geoJsonData && geoJsonData.type === 'Feature';
            var isFC = geoJsonData && geoJsonData.type === 'FeatureCollection';
            var isGeometry = geoJsonData && geoJsonData.type && ['Polygon','MultiPolygon','LineString','MultiLineString','Point','MultiPoint'].indexOf(geoJsonData.type) >= 0;
            if (isGeometry) {
                geoJsonData = { type: 'Feature', geometry: geoJsonData, properties: {} };
            }
            if (!isFeature && !isFC) {
                throw new Error('Unrecognized GeoJSON structure');
            }
            
            // Add boundary to map with styling
            communityBoundary = L.geoJSON(geoJsonData, {
                style: {
                    color: '#264653',
                    weight: 3,
                    opacity: 0.8,
                    fillColor: '#264653',
                    fillOpacity: 0.1,
                    dashArray: '5, 5'
                }
            }).addTo(map);
            
            // Fit map to boundary if no alerts
            if (alerts.length === 0) {
                map.fitBounds(communityBoundary.getBounds(), {
                    padding: [20, 20]
                });
            }
        } catch (e) {
            console.log('Error loading community boundary:', e);
        }
    }

        // Add markers for each alert
        var alertMarkers = [];
        console.log('Adding markers for', alerts.length, 'alerts');
        alerts.forEach(function(alert) {
            console.log('Processing alert:', alert);
            var categoryColor = getCategoryColor(alert.category);
            var categoryIcon = getCategoryIcon(alert.category);
            var markerVerifiedBadge = alert.is_verified ? '<span class="absolute -top-2 -right-2 bg-green-600 text-white rounded-full text-[10px] px-1.5 py-0.5 shadow">✔</span>' : '';

            // Handle both lat/lng and latitude/longitude field names
            var lat = alert.lat || alert.latitude || -26.2041;
            var lng = alert.lng || alert.longitude || 28.0473;

            var icon = L.divIcon({
                className: 'custom-alert-marker',
                html: '<div class="relative">' +
                      '<div class="w-12 h-12 rounded-full flex items-center justify-center text-white text-xl font-bold shadow-lg border-4 border-white" style="background-color: ' + categoryColor + ';">' +
                      categoryIcon +
                      '</div>' + markerVerifiedBadge +
                      '<div class="absolute -bottom-2 left-1/2 transform -translate-x-1/2 w-0 h-0 border-l-4 border-r-4 border-t-8 border-transparent" style="border-top-color: ' + categoryColor + ';"></div>' +
                      '</div>',
                iconSize: [48, 56],
                iconAnchor: [24, 48]
            });
            var marker = L.marker([lat, lng], {icon: icon}).addTo(map);
            // Enhanced popup with better styling and more information
            const popupVerifiedBadge = alert.is_verified ? '<span style="display: inline-flex; align-items: center; gap: 2px; font-size: 10px; padding: 2px 6px; border-radius: 12px; background-color: #DCFCE7; color: #166534;"><span style="font-size: 10px;">✓</span>Verified</span>' : '';
            const timeAgo = formatTimeAgo(alert.timestamp);

            marker.bindPopup(`
              <div style="min-width: 280px; max-width: 320px; font-family: inherit;">
                <div style="display: flex; align-items: flex-start; gap: 12px; padding: 12px;">
                  <div style="width: 48px; height: 48px; border-radius: 50%; display: flex; align-items: center; justify-content: center; color: white; font-size: 18px; flex-shrink: 0; background-color: ${getCategoryColor(alert.category)};">
                    ${categoryIcon}
                  </div>
                  <div style="flex: 1; min-width: 0;">
                    <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 4px;">
                      <h3 style="font-weight: 600; color: #111827; font-size: 14px; margin: 0;">${alert.category}</h3>
                      ${popupVerifiedBadge}
                    </div>
                    <p style="color: #374151; font-size: 14px; line-height: 1.5; margin: 0 0 8px 0;">${alert.description}</p>
                    <div style="display: flex; align-items: center; justify-content: space-between; font-size: 12px; color: #6B7280;">
                      <span>By: ${alert.author_name || 'Anonymous'}</span>
                      <span>${timeAgo}</span>
                    </div>
                  </div>
                </div>
                <div style="border-top: 1px solid #E5E7EB; padding: 12px; background-color: #F9FAFB;">
                  <button onclick="reportAlert(${alert.id})" style="width: 100%; background-color: #DC2626; color: white; border: none; padding: 8px 12px; border-radius: 8px; font-size: 14px; font-weight: 500; cursor: pointer;" onmouseover="this.style.backgroundColor='#B91C1C'" onmouseout="this.style.backgroundColor='#DC2626'">
                    Report Alert
                  </button>
                </div>
              </div>
            `);
            alertMarkers.push(marker);
        });

        // Final viewport fit: prioritize showing both boundary and alerts
        try {
            var bounds = null;
            if (communityBoundary) {
                bounds = communityBoundary.getBounds();
            }
            if (alertMarkers.length > 0) {
                var group = L.featureGroup(alertMarkers);
                bounds = bounds ? bounds.extend(group.getBounds()) : group.getBounds();
            }
            if (bounds) {
                map.fitBounds(bounds, { padding: [20, 20], maxZoom: 16 });
            }
        } catch (e) {
            console.debug('Viewport fit skipped:', e);
        }

        // Request user location if no meaningful location data exists
        if (!locationDetected && !communityBoundary && alertMarkers.length === 0) {
            requestUserLocation(map);
        }

        // Make map available globally
        window.dashboardMap = map;
        console.log('Map setup complete with', alertMarkers.length, 'markers');

        // Ensure map is properly sized and visible
        function ensureMapSize() {
            try {
                if (map && mapContainer) {
                    const rect = mapContainer.getBoundingClientRect();
                    console.log('Map container dimensions:', rect.width, 'x', rect.height);
                    if (rect.width > 0 && rect.height > 0) {
                        map.invalidateSize();
                        console.log('Map invalidated and resized');
                    }
                }
            } catch(_) {
                console.warn('Error ensuring map size');
            }
        }

        // Ensure map fits properly in its container
        function fitMapToContainer() {
            try {
                if (map && mapContainer) {
                    const rect = mapContainer.getBoundingClientRect();
                    if (rect.width > 0 && rect.height > 0) {
                        map.invalidateSize();
                        console.log('Map fitted to container:', rect.width, 'x', rect.height);
                    }
                }
            } catch(_) {
                console.warn('Error fitting map to container');
            }
        }

        // Invalidate on layout changes with multiple attempts
        setTimeout(fitMapToContainer, 100);
        setTimeout(fitMapToContainer, 300);
        setTimeout(fitMapToContainer, 500);

        window.addEventListener('resize', fitMapToContainer);
        window.addEventListener('load', fitMapToContainer);
        document.addEventListener('visibilitychange', function(){
            if(document.visibilityState==='visible'){
                setTimeout(fitMapToContainer, 100);
            }
        });
    }

    // Kick off init once ready
    initWhenReady();
});

// Request user location with permission prompt
function requestUserLocation(map) {
    showLocationPrompt(function(agreed) {
        if (agreed) {
            showLocationMessage('Locating...', 'loading');
            
            navigator.geolocation.getCurrentPosition(
                function(position) {
                    hideLocationMessage();
                    map.setView([position.coords.latitude, position.coords.longitude], 15);
                    showLocationMessage('Location updated successfully', 'success');
                },
                function(error) {
                    hideLocationMessage();
                    let message = 'Unable to get location. Please check your browser settings.';
                    if (error.code === error.PERMISSION_DENIED) {
                        message = 'Location access denied.';
                    }
                    showLocationMessage(message, 'warning');
                },
                {
                    enableHighAccuracy: true,
                    timeout: 10000,
                    maximumAge: 0
                }
            );
        }
    });
}

// Show location permission prompt
function showLocationPrompt(callback) {
    // Remove existing prompt if any
    if (window.locationPromptElement) {
        closeLocationPrompt(false);
    }
    
    var isMobile = window.matchMedia && window.matchMedia('(max-width: 767px)').matches;
    var promptDiv = document.createElement('div');
    if (isMobile) {
        // Bottom sheet style for mobile
        promptDiv.className = 'fixed inset-0 z-50';
        promptDiv.innerHTML = `
            <div class="absolute inset-0 bg-black/40" onclick="closeLocationPrompt(false)"></div>
            <div class="absolute left-0 right-0 bottom-0 bg-white dark:bg-gray-800 rounded-t-2xl shadow-xl p-4">
                <div class="mx-auto h-1.5 w-10 rounded-full bg-gray-300 dark:bg-gray-600 mb-3"></div>
                <h3 class="text-lg font-semibold mb-2">Share your location?</h3>
                <p class="text-gray-600 dark:text-gray-300 mb-4">Enable precise location to center the map near you.</p>
                <div class="flex gap-3 justify-end">
                    <button onclick="closeLocationPrompt(false)" class="px-4 py-2 text-gray-700 dark:text-gray-200 hover:bg-gray-100 dark:hover:bg-gray-700 rounded">Not now</button>
                    <button onclick="closeLocationPrompt(true)" class="px-4 py-2 bg-blue-600 text-white hover:bg-blue-700 rounded">Share</button>
                </div>
            </div>
        `;
    } else {
        // Centered modal for desktop
        promptDiv.className = 'fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50';
        promptDiv.innerHTML = `
            <div class="bg-white dark:bg-gray-800 p-6 rounded-lg shadow-xl max-w-sm w-full">
                <h3 class="text-lg font-semibold mb-4">Share Your Location?</h3>
                <p class="text-gray-600 dark:text-gray-300 mb-4">This helps center the map to your area.</p>
                <div class="flex gap-3 justify-end">
                    <button onclick="closeLocationPrompt(false)" class="px-4 py-2 text-gray-600 dark:text-gray-200 hover:bg-gray-100 dark:hover:bg-gray-700 rounded">No, thanks</button>
                    <button onclick="closeLocationPrompt(true)" class="px-4 py-2 bg-blue-600 text-white hover:bg-blue-700 rounded">Share Location</button>
                </div>
            </div>
        `;
    }
    
    // Store callback for access by button handlers
    window.locationPromptCallback = callback;
    document.body.appendChild(promptDiv);
    window.locationPromptElement = promptDiv;
}

// Close location prompt
function closeLocationPrompt(agreed) {
    if (window.locationPromptElement) {
        document.body.removeChild(window.locationPromptElement);
        window.locationPromptElement = null;
    }
    
    if (window.locationPromptCallback) {
        window.locationPromptCallback(agreed);
        window.locationPromptCallback = null;
    }
}

// Show location status messages
function showLocationMessage(message, type) {
    // Remove existing message if any
    hideLocationMessage();
    
    var messageDiv = document.createElement('div');
    var bgColor = type === 'loading' ? 'bg-blue-100 text-blue-800 dark:bg-blue-900/40 dark:text-blue-100' : 
                  type === 'warning' ? 'bg-amber-100 text-amber-800 dark:bg-amber-900/40 dark:text-amber-100' : 
                  'bg-gray-100 text-gray-800 dark:bg-gray-800 dark:text-gray-100';
    
    messageDiv.className = 'fixed top-4 right-4 p-3 rounded-lg shadow-lg z-40 max-w-sm ' + bgColor;
    messageDiv.innerHTML = `
        <div class="flex items-center gap-2">
            ${type === 'loading' ? '<div class="animate-spin w-4 h-4 border-2 border-blue-600 border-t-transparent rounded-full"></div>' : ''}
            <span>${message}</span>
            ${type !== 'loading' ? '<button onclick="hideLocationMessage()" class="ml-2 text-xl leading-none">&times;</button>' : ''}
        </div>
    `;
    
    document.body.appendChild(messageDiv);
    window.locationMessageElement = messageDiv;
    
    // Auto-hide after 8 seconds if not loading
    if (type !== 'loading') {
        setTimeout(hideLocationMessage, 8000);
    }
}

// Hide location message
function hideLocationMessage() {
    if (window.locationMessageElement) {
        document.body.removeChild(window.locationMessageElement);
        window.locationMessageElement = null;
    }
}

// Utility functions for alert categories
function getCategoryIcon(category) {
    switch(category.toLowerCase()) {
        case 'emergency': return '🚨';
        case 'fire': return '🔥';
        case 'traffic': return '🚗';
        case 'weather': return '⛈️';
        case 'community': return '🏘️';
        default: return '❗';
    }
}

function getCategoryColor(category) {
    switch(category.toLowerCase()) {
        case 'emergency': return '#DC2626'; // Red
        case 'fire': return '#EA580C'; // Orange-red
        case 'traffic': return '#2563EB'; // Blue
        case 'weather': return '#7C3AED'; // Purple
        case 'community': return '#059669'; // Green
        default: return '#6B7280'; // Gray
    }
}

function formatTimeAgo(timestamp) {
    if (!timestamp) return 'Unknown time';

    try {
        const date = new Date(timestamp);
        const now = new Date();
        const diffInSeconds = Math.floor((now - date) / 1000);

        if (diffInSeconds < 60) return 'Just now';
        if (diffInSeconds < 3600) return `${Math.floor(diffInSeconds / 60)}m ago`;
        if (diffInSeconds < 86400) return `${Math.floor(diffInSeconds / 3600)}h ago`;
        if (diffInSeconds < 2592000) return `${Math.floor(diffInSeconds / 86400)}d ago`;

        return date.toLocaleDateString();
    } catch (e) {
        return 'Unknown time';
    }
}

// Navigation functions
function showPostAlert() {
    window.location.href = '/post-alert';
}

function deleteAlert(alertId) {
    if (confirm('Are you sure you want to delete this alert? This action cannot be undone.')) {
        // Get CSRF token
        const csrfToken = document.querySelector('input[name="csrf_token"]') ?
            document.querySelector('input[name="csrf_token"]').value : '';

        console.log('Attempting to delete alert:', alertId, 'with CSRF token:', csrfToken ? 'present' : 'missing');

        fetch(`/alerts/${alertId}`, {
            method: 'DELETE',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': csrfToken
            }
        })
        .then(response => {
            console.log('Delete response status:', response.status);
            if (response.status === 401) {
                alert('You must be logged in to delete alerts. Please refresh the page and try again.');
                return null;
            }
            return response.json();
        })
        .then(data => {
            if (data && data.success) {
                console.log('Alert deleted successfully');
                // Remove the alert from the page
                const alertElement = document.querySelector(`[data-alert-id="${alertId}"]`) ||
                                   document.querySelector(`button[onclick="deleteAlert(${alertId})"]`).closest('.alert-card');
                if (alertElement) {
                    alertElement.remove();
                }
                // Show success message
                showLocationMessage('Alert deleted successfully', 'success');
            } else {
                console.error('Delete failed:', data);
                alert('There was an error deleting the alert. Please try again.');
            }
        })
        .catch(error => {
            console.error('Error deleting alert:', error);
            alert('There was an error deleting the alert. Please try again.');
        });
    }
}

function reportAlert(alertId) {
    if (confirm('Are you sure you want to report this alert for inappropriate content?')) {
        fetch('/report-alert', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': document.querySelector('input[name="csrf_token"]') ?
                    document.querySelector('input[name="csrf_token"]').value : ''
            },
            body: JSON.stringify({
                alert_id: alertId
            })
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                alert('Thank you for your report. We will review this content.');
            } else {
                alert('There was an error submitting your report. Please try again.');
            }
        })
        .catch(error => {
            console.error('Error reporting alert:', error);
            alert('There was an error submitting your report. Please try again.');
        });
    }
}

// Auto-hide flash messages after 5 seconds
document.addEventListener('DOMContentLoaded', function() {
    const alertMessages = document.querySelectorAll('.alert-message');
    const flashContainer = document.getElementById('flash-container');
    alertMessages.forEach(function(message) {
        setTimeout(function() {
            message.style.transition = 'opacity 0.5s ease-out';
            message.style.opacity = '0';
            setTimeout(function() {
                message.remove();
                if (flashContainer && !flashContainer.querySelector('.alert-message')) {
                    flashContainer.remove();
                }
                if (window.dashboardMap) {
                    window.dashboardMap.invalidateSize();
                }
            }, 500);
        }, 5000);
    });
});