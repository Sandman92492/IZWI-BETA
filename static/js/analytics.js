/**
 * Analytics Dashboard JavaScript
 * Handles KPI widgets, interactive charts, heatmap visualization, and PDF export
 */

// Global variables
let analyticsMap = null;
let heatmapLayer = null;
let charts = {};
let filterTimeout = null;
let currentFilters = {
    communities: [],
    categories: [],
    dateFrom: null,
    dateTo: null
};

/**
 * Initialize the analytics dashboard
 */
function initAnalyticsDashboard() {
    initFilterEvents();
    initMap();
    initCharts();
    loadInitialData();
}

/**
 * Initialize filter events with debouncing
 */
function initFilterEvents() {
    // Date range selector
    const dateRangeSelect = document.getElementById('date-range');
    if (dateRangeSelect) {
        dateRangeSelect.addEventListener('change', function() {
            const customRange = document.getElementById('custom-date-range');
            if (this.value === 'custom') {
                customRange.classList.remove('hidden');
            } else {
                customRange.classList.add('hidden');
                debouncedApplyFilters();
            }
        });
    }

    // Custom date inputs
    const dateFromInput = document.getElementById('date-from');
    const dateToInput = document.getElementById('date-to');
    if (dateFromInput) dateFromInput.addEventListener('change', debouncedApplyFilters);
    if (dateToInput) dateToInput.addEventListener('change', debouncedApplyFilters);

    // Community checkboxes
    const communityCheckboxes = document.querySelectorAll('.community-filter');
    communityCheckboxes.forEach(checkbox => {
        checkbox.addEventListener('change', debouncedApplyFilters);
    });

    // Category checkboxes
    const categoryCheckboxes = document.querySelectorAll('.category-filter');
    categoryCheckboxes.forEach(checkbox => {
        checkbox.addEventListener('change', debouncedApplyFilters);
    });

    // Heatmap toggle
    const heatmapToggle = document.getElementById('heatmap-toggle');
    if (heatmapToggle) {
        heatmapToggle.addEventListener('change', function() {
            toggleHeatmap(this.checked);
        });
    }
}

/**
 * Initialize Leaflet map for heatmap visualization
 */
function initMap() {
    const mapElement = document.getElementById('analytics-map');
    if (!mapElement) {
        console.warn('Analytics map element not found');
        return;
    }

    try {
        // Initialize map centered on Johannesburg (default location)
        analyticsMap = L.map('analytics-map', {
            center: [-26.2041, 28.0473],
            zoom: 10,
            zoomControl: true,
            attributionControl: true
        });

        // Add OpenStreetMap tiles
        L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
            attribution: '© OpenStreetMap contributors',
            maxZoom: 18
        }).addTo(analyticsMap);

        // Add heatmap layer (initially visible)
        heatmapLayer = L.heatLayer([], {
            radius: 20,
            blur: 15,
            maxZoom: 17,
            gradient: {
                0.2: '#FEB24C',
                0.4: '#FD8D3C',
                0.6: '#FC4E2A',
                0.8: '#E31A1C',
                1.0: '#B10026'
            }
        }).addTo(analyticsMap);

        // Hide loading overlay
        const loadingElement = document.getElementById('map-loading');
        if (loadingElement) {
            loadingElement.classList.add('hidden');
        }

        console.log('Analytics map initialized successfully');
    } catch (error) {
        console.error('Error initializing analytics map:', error);
        showToast('Failed to initialize map', 'error');
        hideMapLoading();
    }
}

/**
 * Initialize Chart.js charts
 */
function initCharts() {
    // Charts will be initialized when data is loaded
    // Don't destroy canvas elements - they need to exist for Chart.js
}

/**
 * Apply current filters and refresh all data
 */
function applyFilters() {
    const filters = getCurrentFilters();
    currentFilters = filters;

    showLoadingStates();
    loadKPIs(filters);
    loadCharts(filters);
    loadHeatmap(filters);
}

/**
 * Debounced version of applyFilters for better performance
 */
function debouncedApplyFilters() {
    if (filterTimeout) {
        clearTimeout(filterTimeout);
    }
    filterTimeout = setTimeout(applyFilters, 300);
}

/**
 * Get current filter values from the UI
 */
function getCurrentFilters() {
    const dateRange = document.getElementById('date-range')?.value || 'last_30_days';

    let dateFrom = null;
    let dateTo = null;

    if (dateRange === 'custom') {
        dateFrom = document.getElementById('date-from')?.value;
        dateTo = document.getElementById('date-to')?.value;
    } else {
        // Set date range based on selection
        const now = new Date();
        switch (dateRange) {
            case 'last_7_days':
                dateFrom = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000).toISOString().split('T')[0];
                dateTo = now.toISOString().split('T')[0];
                break;
            case 'last_30_days':
                dateFrom = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000).toISOString().split('T')[0];
                dateTo = now.toISOString().split('T')[0];
                break;
            case 'this_month':
                const startOfMonth = new Date(now.getFullYear(), now.getMonth(), 1);
                dateFrom = startOfMonth.toISOString().split('T')[0];
                dateTo = now.toISOString().split('T')[0];
                break;
            case 'last_90_days':
                dateFrom = new Date(now.getTime() - 90 * 24 * 60 * 60 * 1000).toISOString().split('T')[0];
                dateTo = now.toISOString().split('T')[0];
                break;
        }
    }

    // Get selected communities
    const communityCheckboxes = document.querySelectorAll('.community-filter:checked');
    const communities = Array.from(communityCheckboxes).map(cb => cb.value);

    // Get selected categories
    const categoryCheckboxes = document.querySelectorAll('.category-filter:checked');
    const categories = Array.from(categoryCheckboxes).map(cb => cb.value);

    return {
        date_from: dateFrom,
        date_to: dateTo,
        community_ids: communities,
        categories: categories
    };
}

/**
 * Reset filters to default values
 */
function resetFilters() {
    // Reset date range
    const dateRangeSelect = document.getElementById('date-range');
    if (dateRangeSelect) {
        dateRangeSelect.value = 'last_30_days';
    }

    // Hide custom date range
    const customDateRange = document.getElementById('custom-date-range');
    if (customDateRange) {
        customDateRange.classList.add('hidden');
    }

    // Check all community checkboxes
    const communityCheckboxes = document.querySelectorAll('.community-filter');
    communityCheckboxes.forEach(checkbox => {
        checkbox.checked = true;
    });

    // Check all category checkboxes
    const categoryCheckboxes = document.querySelectorAll('.category-filter');
    categoryCheckboxes.forEach(checkbox => {
        checkbox.checked = true;
    });

    // Apply the reset filters
    debouncedApplyFilters();
}

/**
 * Load KPI data from the server
 */
function loadKPIs(filters) {
    const params = new URLSearchParams();
    if (filters.community_ids.length > 0) {
        filters.community_ids.forEach(id => params.append('community_ids[]', id));
    }
    if (filters.categories.length > 0) {
        filters.categories.forEach(cat => params.append('categories[]', cat));
    }
    if (filters.date_from) params.append('date_from', filters.date_from);
    if (filters.date_to) params.append('date_to', filters.date_to);

    fetch(`/super-admin/analytics/data?${params}`)
        .then(response => {
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            return response.json();
        })
        .then(data => {
            updateKPIs(data);
        })
        .catch(error => {
            console.error('Error loading KPIs:', error);
            showToast('Failed to load KPI data', 'error');
        });
}

/**
 * Update KPI widgets with new data
 */
function updateKPIs(data) {
    const totalAlertsEl = document.getElementById('total-alerts');
    const newAlertsEl = document.getElementById('new-alerts');
    const resolvedAlertsEl = document.getElementById('resolved-alerts');
    const avgResolutionTimeEl = document.getElementById('avg-resolution-time');
    const busiestDayTimeEl = document.getElementById('busiest-day-time');

    if (totalAlertsEl) totalAlertsEl.textContent = data.total_alerts?.toLocaleString() || '0';
    if (newAlertsEl) newAlertsEl.textContent = data.new_alerts?.toLocaleString() || '0';
    if (resolvedAlertsEl) resolvedAlertsEl.textContent = data.resolved_alerts?.toLocaleString() || '0';
    if (avgResolutionTimeEl) avgResolutionTimeEl.textContent = data.avg_resolution_time ? `${data.avg_resolution_time}h` : '0h';
    if (busiestDayTimeEl) busiestDayTimeEl.textContent = data.busiest_day_time || 'No data';
}

/**
 * Load charts data from the server
 */
function loadCharts(filters) {
    const params = new URLSearchParams();
    if (filters.community_ids.length > 0) {
        filters.community_ids.forEach(id => params.append('community_ids[]', id));
    }
    if (filters.categories.length > 0) {
        filters.categories.forEach(cat => params.append('categories[]', cat));
    }
    if (filters.date_from) params.append('date_from', filters.date_from);
    if (filters.date_to) params.append('date_to', filters.date_to);

    fetch(`/super-admin/analytics/charts?${params}`)
        .then(response => {
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            return response.json();
        })
        .then(data => {
            updateCharts(data);
        })
        .catch(error => {
            console.error('Error loading charts:', error);
            showToast('Failed to load chart data', 'error');
        });
}

/**
 * Update all charts with new data
 */
function updateCharts(data) {
    updateTimeChart(data.alerts_over_time || []);
    updateCategoryChart(data.alerts_by_category || []);
    updateStatusChart(data.alerts_by_status || []);
    hideChartsLoading();
}

/**
 * Update time series chart
 */
function updateTimeChart(data) {
    const ctx = document.getElementById('time-chart')?.getContext('2d');
    if (!ctx || !data || data.length === 0) return;

    if (charts.timeChart) {
        charts.timeChart.destroy();
    }

    charts.timeChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: data.map(item => new Date(item.date).toLocaleDateString()),
            datasets: [{
                label: 'Alerts',
                data: data.map(item => item.count),
                borderColor: '#10b981',
                backgroundColor: 'rgba(16, 185, 129, 0.1)',
                tension: 0.1,
                fill: true
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: {
                    beginAtZero: true,
                    ticks: {
                        precision: 0
                    }
                },
                x: {
                    ticks: {
                        maxTicksLimit: 10
                    }
                }
            },
            plugins: {
                legend: {
                    display: false
                }
            }
        }
    });
}

/**
 * Update category distribution chart
 */
function updateCategoryChart(data) {
    const ctx = document.getElementById('category-chart')?.getContext('2d');
    if (!ctx || !data || data.length === 0) return;

    if (charts.categoryChart) {
        charts.categoryChart.destroy();
    }

    const colors = [
        '#DC2626', '#EA580C', '#2563EB', '#7C3AED',
        '#059669', '#6B7280', '#F59E0B'
    ];

    charts.categoryChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: data.map(item => item.category),
            datasets: [{
                data: data.map(item => item.count),
                backgroundColor: colors.slice(0, data.length),
                borderWidth: 0
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        padding: 20,
                        usePointStyle: true
                    }
                }
            }
        }
    });
}

/**
 * Update status distribution chart
 */
function updateStatusChart(data) {
    const ctx = document.getElementById('status-chart')?.getContext('2d');
    if (!ctx || !data || data.length === 0) return;

    if (charts.statusChart) {
        charts.statusChart.destroy();
    }

    const statusColors = {
        'New': '#3B82F6',
        'Investigating': '#F59E0B',
        'Resolved': '#10B981',
        'False Alarm': '#6B7280'
    };

    charts.statusChart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: data.map(item => item.status),
            datasets: [{
                label: 'Count',
                data: data.map(item => item.count),
                backgroundColor: data.map(item => statusColors[item.status] || '#6B7280')
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: {
                    beginAtZero: true,
                    ticks: {
                        precision: 0
                    }
                }
            },
            plugins: {
                legend: {
                    display: false
                }
            }
        }
    });
}

/**
 * Load heatmap data from the server
 */
function loadHeatmap(filters) {
    const params = new URLSearchParams();
    if (filters.community_ids.length > 0) {
        filters.community_ids.forEach(id => params.append('community_ids[]', id));
    }
    if (filters.categories.length > 0) {
        filters.categories.forEach(cat => params.append('categories[]', cat));
    }
    if (filters.date_from) params.append('date_from', filters.date_from);
    if (filters.date_to) params.append('date_to', filters.date_to);

    fetch(`/super-admin/analytics/heatmap?${params}`)
        .then(response => {
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            return response.json();
        })
        .then(data => {
            updateHeatmap(data);
        })
        .catch(error => {
            console.error('Error loading heatmap:', error);
            showToast('Failed to load heatmap data', 'error');
        });
}

/**
 * Update heatmap layer with new data
 */
function updateHeatmap(data) {
    if (heatmapLayer && analyticsMap) {
        heatmapLayer.setLatLngs(data);

        // Fit bounds to heatmap data if we have points
        if (data.length > 0) {
            try {
                // Calculate bounds from the heatmap data points
                const bounds = L.latLngBounds(data.map(point => [point[0], point[1]]));
                analyticsMap.fitBounds(bounds, { padding: [20, 20] });
            } catch (error) {
                // Fallback: set a default view if bounds calculation fails
                console.warn('Could not calculate heatmap bounds, using default view');
                analyticsMap.setView([-26.2041, 28.0473], 10);
            }
        } else {
            // No data points, set default view
            analyticsMap.setView([-26.2041, 28.0473], 10);
        }
    }
}

/**
 * Toggle heatmap visibility
 */
function toggleHeatmap(show) {
    if (!analyticsMap || !heatmapLayer) return;

    if (show) {
        if (!analyticsMap.hasLayer(heatmapLayer)) {
            analyticsMap.addLayer(heatmapLayer);
        }
    } else {
        if (analyticsMap.hasLayer(heatmapLayer)) {
            analyticsMap.removeLayer(heatmapLayer);
        }
    }
}

/**
 * Export current dashboard as PDF report
 */
function exportPDF() {
    const exportBtn = document.getElementById('export-btn');
    if (!exportBtn) return;

    const originalText = exportBtn.innerHTML;

    // Show loading state
    exportBtn.disabled = true;
    exportBtn.innerHTML = '<span class="animate-spin rounded-full h-4 w-4 border-b-2 border-white mx-auto"></span>';

    const filters = getCurrentFilters();

    // Collect current KPI and chart data
    const kpis = {
        total_alerts: parseInt(document.getElementById('total-alerts')?.textContent?.replace(/,/g, '') || '0'),
        new_alerts: parseInt(document.getElementById('new-alerts')?.textContent?.replace(/,/g, '') || '0'),
        resolved_alerts: parseInt(document.getElementById('resolved-alerts')?.textContent?.replace(/,/g, '') || '0'),
        avg_resolution_time: parseFloat(document.getElementById('avg-resolution-time')?.textContent || '0'),
        busiest_day_time: document.getElementById('busiest-day-time')?.textContent || 'No data'
    };

    // For now, we'll send empty charts data since we can't easily extract chart data from Chart.js
    // In a real implementation, you'd want to store the chart data separately
    const charts_data = {};

    // Get CSRF token
    const csrfToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content') ||
                     document.querySelector('input[name="csrf_token"]')?.value;

    fetch('/super-admin/analytics/export-pdf', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': csrfToken || ''
        },
        body: JSON.stringify({
            filters: filters,
            kpis: kpis,
            charts: charts_data
        })
    })
    .then(response => {
        if (response.ok) {
            return response.blob();
        } else {
            throw new Error('Failed to generate PDF');
        }
    })
    .then(blob => {
        // Create download link
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `analytics_report_${new Date().toISOString().split('T')[0]}.pdf`;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        document.body.removeChild(a);

        showToast('PDF report downloaded successfully', 'success');
    })
    .catch(error => {
        console.error('Error exporting PDF:', error);
        showToast('Failed to generate PDF report', 'error');
    })
    .finally(() => {
        // Reset button
        exportBtn.disabled = false;
        exportBtn.innerHTML = originalText;
    });
}

/**
 * Load initial data when dashboard loads
 */
function loadInitialData() {
    // Load data with default filters
    applyFilters();
}

/**
 * Show loading states for all components
 */
function showLoadingStates() {
    showChartsLoading();
    showMapLoading();
}

/**
 * Hide loading states for all components
 */
function hideLoadingStates() {
    hideChartsLoading();
    hideMapLoading();
}

/**
 * Show loading state for charts
 */
function showChartsLoading() {
    const chartContainers = document.querySelectorAll('.h-64');
    chartContainers.forEach(container => {
        // Only add overlay if it doesn't already exist
        if (!container.querySelector('.chart-loading-overlay')) {
            const overlay = document.createElement('div');
            overlay.className = 'chart-loading-overlay absolute inset-0 flex items-center justify-center bg-white/80 dark:bg-gray-800/80 z-10';
            overlay.innerHTML = `
                <div class="text-center">
                    <div class="animate-spin rounded-full h-8 w-8 border-b-2 border-emerald-600 mx-auto mb-2"></div>
                    <p class="text-sm text-gray-600 dark:text-gray-400">Loading chart...</p>
                </div>
            `;
            container.style.position = 'relative';
            container.appendChild(overlay);
        }
    });
}

/**
 * Hide loading state for charts
 */
function hideChartsLoading() {
    // Remove loading overlays
    const overlays = document.querySelectorAll('.chart-loading-overlay');
    overlays.forEach(overlay => overlay.remove());
}

/**
 * Show loading state for map
 */
function showMapLoading() {
    const loadingElement = document.getElementById('map-loading');
    if (loadingElement) {
        loadingElement.classList.remove('hidden');
    }
}

/**
 * Hide loading state for map
 */
function hideMapLoading() {
    const loadingElement = document.getElementById('map-loading');
    if (loadingElement) {
        loadingElement.classList.add('hidden');
    }
}

/**
 * Show toast notification
 */
function showToast(message, type = 'info') {
    // Create toast element if it doesn't exist
    let toastContainer = document.getElementById('toast-container');
    if (!toastContainer) {
        toastContainer = document.createElement('div');
        toastContainer.id = 'toast-container';
        toastContainer.className = 'fixed top-4 right-4 z-50 space-y-2';
        document.body.appendChild(toastContainer);
    }

    const toast = document.createElement('div');

    const colors = {
        success: 'bg-green-500 text-white',
        error: 'bg-red-500 text-white',
        info: 'bg-blue-500 text-white'
    };

    toast.className = `px-4 py-2 rounded-lg shadow-lg ${colors[type] || colors.info} flex items-center gap-2`;
    toast.innerHTML = `
        <span class="material-symbols-outlined text-sm">
            ${type === 'success' ? 'check_circle' : type === 'error' ? 'error' : 'info'}
        </span>
        <span class="text-sm font-medium">${message}</span>
    `;

    toastContainer.appendChild(toast);

    // Auto remove after 4 seconds
    setTimeout(() => {
        if (toast.parentNode) {
            toast.remove();
        }
    }, 4000);
}

// Initialize when DOM is loaded
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initAnalyticsDashboard);
} else {
    initAnalyticsDashboard();
}

// Export functions for global access
window.initAnalyticsDashboard = initAnalyticsDashboard;
window.applyFilters = applyFilters;
window.resetFilters = resetFilters;
window.exportPDF = exportPDF;
window.showToast = showToast;
