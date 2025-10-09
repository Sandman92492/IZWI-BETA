/**
 * iZwi Dashboard Tour System
 * Provides interactive coach marks and tooltips for first-time users
 */

class DashboardTour {
    constructor(options = {}) {
        this.options = {
            showOnFirstVisit: true,
            tourKey: 'izwi_dashboard_tour_completed',
            steps: [
                {
                    target: '.dashboard-map',
                    title: 'Interactive Map',
                    content: 'This is your community map where you can view alerts and locations in real-time.',
                    placement: 'top',
                    showSkip: false
                },
                {
                    target: '.alerts-panel',
                    title: 'Recent Alerts',
                    content: 'See all community alerts here. You can view details, report issues, and stay informed.',
                    placement: 'left',
                    showSkip: false
                },
                {
                    target: '.post-alert-btn',
                    title: 'Post Alerts',
                    content: 'Click here to share important information with your community. Choose from different alert types.',
                    placement: 'bottom',
                    showSkip: false
                },
                {
                    target: '.community-settings',
                    title: 'Community Settings',
                    content: 'Manage your community members, settings, and preferences from here.',
                    placement: 'bottom',
                    showSkip: false
                }
            ],
            ...options
        };

        this.currentStep = 0;
        this.overlay = null;
        this.tooltip = null;
        this.spotlight = null;
        this.isActive = false;

        this.init();
    }

    init() {
        // Check if user has completed the tour
        if (localStorage.getItem(this.options.tourKey) === 'true') {
            return;
        }

        // Show tour after a delay to let dashboard load
        setTimeout(() => {
            this.start();
        }, 2000);
    }

    start() {
        if (this.isActive) return;

        this.isActive = true;
        this.createOverlay();
        this.showStep(0);
    }

    createOverlay() {
        // Create spotlight overlay
        this.spotlight = document.createElement('div');
        this.spotlight.className = 'tour-spotlight';
        this.spotlight.style.cssText = `
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.7);
            z-index: 9998;
            pointer-events: none;
            transition: all 0.3s ease;
        `;

        // Create tooltip
        this.tooltip = document.createElement('div');
        this.tooltip.className = 'tour-tooltip';
        this.tooltip.style.cssText = `
            position: fixed;
            background: white;
            border-radius: 12px;
            padding: 20px;
            box-shadow: 0 10px 25px rgba(0, 0, 0, 0.15);
            z-index: 9999;
            max-width: 300px;
            transform: translate(-50%, -50%);
            transition: all 0.3s ease;
        `;

        // Add tooltip content structure
        this.tooltip.innerHTML = `
            <div class="tour-tooltip-header" style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
                <h3 class="tour-tooltip-title" style="margin: 0; font-size: 18px; font-weight: 600; color: #1f2937;"></h3>
                <button class="tour-skip-btn" style="background: none; border: none; color: #6b7280; font-size: 14px; cursor: pointer; padding: 4px 8px; border-radius: 4px; hover:bg-gray-100;">Skip</button>
            </div>
            <div class="tour-tooltip-content" style="color: #4b5563; line-height: 1.5; margin-bottom: 16px;"></div>
            <div class="tour-tooltip-footer" style="display: flex; justify-content: space-between; align-items: center;">
                <div class="tour-progress" style="display: flex; gap: 4px;"></div>
                <div class="tour-buttons">
                    <button class="tour-prev-btn" style="background: #e5e7eb; color: #374151; border: none; padding: 8px 16px; border-radius: 6px; font-size: 14px; cursor: pointer; margin-right: 8px; display: none;">Previous</button>
                    <button class="tour-next-btn" style="background: #2A9D8F; color: white; border: none; padding: 8px 16px; border-radius: 6px; font-size: 14px; cursor: pointer;">Next</button>
                </div>
            </div>
        `;

        // Add to DOM
        document.body.appendChild(this.spotlight);
        document.body.appendChild(this.tooltip);

        // Bind events
        this.tooltip.querySelector('.tour-skip-btn').addEventListener('click', () => this.end());
        this.tooltip.querySelector('.tour-prev-btn').addEventListener('click', () => this.previousStep());
        this.tooltip.querySelector('.tour-next-btn').addEventListener('click', () => this.nextStep());

        // Close on overlay click
        this.spotlight.addEventListener('click', (e) => {
            if (e.target === this.spotlight) {
                this.end();
            }
        });

        // Close on Escape key
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape' && this.isActive) {
                this.end();
            }
        });
    }

    showStep(stepIndex) {
        const step = this.options.steps[stepIndex];
        if (!step) {
            this.end();
            return;
        }

        this.currentStep = stepIndex;
        const target = document.querySelector(step.target);

        if (!target) {
            console.warn(`Tour target not found: ${step.target}`);
            this.nextStep();
            return;
        }

        // Update tooltip content
        this.tooltip.querySelector('.tour-tooltip-title').textContent = step.title;
        this.tooltip.querySelector('.tour-tooltip-content').textContent = step.content;

        // Update progress indicators
        const progressContainer = this.tooltip.querySelector('.tour-progress');
        progressContainer.innerHTML = '';
        this.options.steps.forEach((_, index) => {
            const dot = document.createElement('div');
            dot.style.cssText = `
                width: 8px;
                height: 8px;
                border-radius: 50%;
                background: ${index === stepIndex ? '#2A9D8F' : '#d1d5db'};
                transition: background 0.3s ease;
            `;
            progressContainer.appendChild(dot);
        });

        // Position tooltip and spotlight
        this.positionTooltip(target, step.placement);

        // Show/hide navigation buttons
        const prevBtn = this.tooltip.querySelector('.tour-prev-btn');
        const nextBtn = this.tooltip.querySelector('.tour-next-btn');

        prevBtn.style.display = stepIndex > 0 ? 'block' : 'none';
        nextBtn.textContent = stepIndex === this.options.steps.length - 1 ? 'Finish' : 'Next';
    }

    positionTooltip(target, placement = 'top') {
        const rect = target.getBoundingClientRect();
        const tooltipRect = this.tooltip.getBoundingClientRect();

        // Calculate spotlight hole
        const holeRadius = Math.max(rect.width, rect.height) / 2 + 20;
        const holeX = rect.left + rect.width / 2;
        const holeY = rect.top + rect.height / 2;

        // Create spotlight hole using CSS clip-path
        this.spotlight.style.clipPath = `
            circle(${holeRadius}px at ${holeX}px ${holeY}px),
            circle(0px at 0px 0px)
        `;

        // Position tooltip
        let top, left;

        switch (placement) {
            case 'top':
                top = rect.top - tooltipRect.height - 15;
                left = rect.left + rect.width / 2;
                break;
            case 'bottom':
                top = rect.bottom + 15;
                left = rect.left + rect.width / 2;
                break;
            case 'left':
                top = rect.top + rect.height / 2;
                left = rect.left - tooltipRect.width - 15;
                break;
            case 'right':
                top = rect.top + rect.height / 2;
                left = rect.right + 15;
                break;
        }

        // Keep tooltip in viewport
        const viewportWidth = window.innerWidth;
        const viewportHeight = window.innerHeight;

        if (left + tooltipRect.width / 2 > viewportWidth) {
            left = viewportWidth - tooltipRect.width / 2 - 10;
        }
        if (left - tooltipRect.width / 2 < 0) {
            left = tooltipRect.width / 2 + 10;
        }
        if (top + tooltipRect.height > viewportHeight) {
            top = viewportHeight - tooltipRect.height - 10;
        }
        if (top < 0) {
            top = 10;
        }

        this.tooltip.style.top = `${top}px`;
        this.tooltip.style.left = `${left}px`;
        this.tooltip.style.transform = 'translate(-50%, -50%)';
    }

    nextStep() {
        if (this.currentStep < this.options.steps.length - 1) {
            this.showStep(this.currentStep + 1);
        } else {
            this.end();
        }
    }

    previousStep() {
        if (this.currentStep > 0) {
            this.showStep(this.currentStep - 1);
        }
    }

    end() {
        if (!this.isActive) return;

        this.isActive = false;

        // Mark tour as completed
        localStorage.setItem(this.options.tourKey, 'true');

        // Remove elements
        if (this.spotlight && this.spotlight.parentNode) {
            this.spotlight.parentNode.removeChild(this.spotlight);
        }
        if (this.tooltip && this.tooltip.parentNode) {
            this.tooltip.parentNode.removeChild(this.tooltip);
        }

        // Clean up event listeners
        document.removeEventListener('keydown', this.handleKeyDown);
    }

    // Static method to check if tour should be shown
    static shouldShowTour() {
        return localStorage.getItem('izwi_dashboard_tour_completed') !== 'true';
    }
}

// Auto-initialize when DOM is ready
document.addEventListener('DOMContentLoaded', function() {
    // Check if we're on the dashboard page
    if (document.querySelector('.dashboard-main')) {
        window.dashboardTour = new DashboardTour();
    }
});

// Export for potential external use
if (typeof module !== 'undefined' && module.exports) {
    module.exports = DashboardTour;
}
