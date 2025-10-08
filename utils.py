import re
import json
import secrets
import string
from datetime import datetime
import bleach
import hashlib

def sanitize_text_input(text):
    """Sanitize user text input to prevent XSS attacks"""
    if not text:
        return text
    # Allow basic formatting but strip dangerous tags and attributes
    allowed_tags = ['p', 'br', 'strong', 'em', 'u']
    allowed_attributes = {}
    return bleach.clean(text, tags=allowed_tags, attributes=allowed_attributes, strip=True)

def sanitize_plain_text(text):
    """Sanitize plain text input, removing all HTML tags"""
    if not text:
        return text
    return bleach.clean(text, tags=[], attributes={}, strip=True)

def validate_email(email):
    """Validate email format"""
    if not email:
        return False
    # Basic email validation pattern
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def validate_json_data(data):
    """Validate and sanitize JSON data"""
    if not data:
        return ""
    try:
        # Try to parse as JSON to validate format
        parsed = json.loads(data)
        # Re-serialize to ensure clean format
        return json.dumps(parsed)
    except (json.JSONDecodeError, ValueError):
        # If not valid JSON, treat as plain text and sanitize
        return sanitize_plain_text(data)

def generate_invite_slug():
    """Generate a unique invite slug for communities"""
    return ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(10))

def hash_code_plaintext(plaintext: str) -> str:
    if not plaintext:
        return ''
    return hashlib.sha256(plaintext.encode('utf-8')).hexdigest()

def is_invite_valid(invite_record, provided_plaintext: str) -> (bool, str | None):
    """Validate an invite code record against provided plaintext."""
    if not invite_record:
        return False, 'Invalid invite code'
    if invite_record.revoked:
        return False, 'Invite code has been revoked'
    if invite_record.expires_at and isinstance(invite_record.expires_at, datetime):
        if datetime.now(invite_record.expires_at.tzinfo) > invite_record.expires_at:
            return False, 'Invite code has expired'
    if invite_record.used_count >= invite_record.max_uses:
        return False, 'Invite code has reached its usage limit'
    if hash_code_plaintext(provided_plaintext) != invite_record.code_hash:
        return False, 'Invite code is incorrect'
    return True, None

def get_category_color(category):
    """Get color for alert category"""
    colors = {
        'Emergency': '#DC2626',  # Red
        'Fire': '#EA580C',       # Orange-red
        'Traffic': '#2563EB',    # Blue
        'Weather': '#7C3AED',    # Purple
        'Community': '#059669',  # Green
        'Other': '#6B7280'       # Gray
    }
    return colors.get(category, '#6B7280')

def get_category_icon(category):
    """Get emoji icon for alert category"""
    icons = {
        'Emergency': '🚨',
        'Fire': '🔥',
        'Traffic': '🚗',
        'Weather': '⛈️',
        'Community': '🏘️',
        'Other': '❗'
    }
    return icons.get(category, '❗')

def format_time_ago(timestamp_input):
    """Format timestamp to relative time"""
    try:
        # Handle both datetime objects and timestamp strings
        if isinstance(timestamp_input, datetime):
            timestamp = timestamp_input
        else:
            # If it's a string, parse it
            timestamp_str = str(timestamp_input)
            timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
        
        now = datetime.now(timestamp.tzinfo) if timestamp.tzinfo else datetime.now()
        diff = now - timestamp
        
        if diff.days > 7:
            # For older dates, show month and day
            return timestamp.strftime("%b %d")
        elif diff.days > 0:
            return f"{diff.days} {'day' if diff.days == 1 else 'days'} ago"
        elif diff.seconds > 3600:
            hours = diff.seconds // 3600
            return f"{hours} {'hour' if hours == 1 else 'hours'} ago"
        elif diff.seconds > 60:
            minutes = diff.seconds // 60
            return f"{minutes} {'minute' if minutes == 1 else 'minutes'} ago"
        else:
            return "Just now"
    except Exception as e:
        # Fallback: return the original input as string
        return str(timestamp_input)

def format_time_left(expires_at):
    """Format time remaining until expiration"""
    if not expires_at:
        return "No expiration"
    
    try:
        # Handle both datetime objects and timestamp strings
        if isinstance(expires_at, datetime):
            expires = expires_at
        else:
            # If it's a string, parse it
            expires_str = str(expires_at)
            expires = datetime.fromisoformat(expires_str.replace('Z', '+00:00'))
        
        now = datetime.now(expires.tzinfo) if expires.tzinfo else datetime.now()
        diff = expires - now
        
        if diff.total_seconds() <= 0:
            return "Expired"
        elif diff.days > 0:
            return f"{diff.days} {'day' if diff.days == 1 else 'days'} left"
        elif diff.seconds > 3600:
            hours = diff.seconds // 3600
            return f"{hours} {'hour' if hours == 1 else 'hours'} left"
        elif diff.seconds > 60:
            minutes = diff.seconds // 60
            return f"{minutes} {'minute' if minutes == 1 else 'minutes'} left"
        else:
            return "Less than a minute left"
    except Exception as e:
        # Fallback: return the original input as string
        return str(expires_at)


# Subscription and Premium Feature Utilities

# Plan ranking and normalization for cumulative entitlements
_PLAN_LEVELS = {
    'free': 0,
    'basic': 0,
    'starter': 0,
    'plus': 1,
    'premium': 1,
    'izwi plus': 1,
    'pro': 1,
    'security pro': 2,
    'superadmin': 2,
    'super admin': 2,
    'b2b': 2,
    'enterprise': 2,
    'proptech premium': 2,
}

def _normalize_plan_name(name):
    try:
        return str(name or 'free').strip().lower()
    except Exception:
        return 'free'

def _plan_level(name):
    return _PLAN_LEVELS.get(_normalize_plan_name(name), 0)

def _role_implied_level(user) -> int:
    try:
        if hasattr(user, 'is_super_admin') and user.is_super_admin():
            return 2
        if hasattr(user, 'is_founder') and user.is_founder():
            return 2
        # Any user associated with a business gets B2B-level entitlements
        if getattr(user, 'business_id', None):
            return 2
    except Exception:
        pass
    return 0

def get_effective_plan_level(user, community=None, business=None) -> int:
    levels = []
    try:
        levels.append(_plan_level(getattr(user, 'subscription_tier', 'Free')))
    except Exception:
        levels.append(0)
    try:
        if community is not None:
            levels.append(_plan_level(getattr(community, 'subscription_plan', 'Free')))
    except Exception:
        levels.append(0)
    try:
        if business is not None:
            levels.append(_plan_level(getattr(business, 'subscription_tier', 'Free')))
    except Exception:
        levels.append(0)
    levels.append(_role_implied_level(user))
    return max(levels) if levels else 0

def has_plan_at_least(user, minimum, community=None, business=None) -> bool:
    required = minimum if isinstance(minimum, int) else _plan_level(minimum)
    return get_effective_plan_level(user, community=community, business=business) >= required

def check_premium_feature_access(user, feature_name=None, community=None, business=None):
    """Check cumulative entitlement: Plus-or-better gains access."""
    if not user:
        return False, "Please log in to access this feature."
    if has_plan_at_least(user, 'plus', community=community, business=business):
        return True, None
    feature_msg = f" '{feature_name}'" if feature_name else ""
    return False, f"This{feature_msg} is a premium feature. Please upgrade your plan."

def get_effective_plan_label(user, community=None, business=None) -> str:
    """Return a human-friendly label for the user's effective plan."""
    level = get_effective_plan_level(user, community=community, business=business)
    if level >= 2:
        return 'B2B'
    if level >= 1:
        return 'iZwi Plus'
    return 'Free'

def get_subscription_limits(subscription_tier):
    """Get limits based on subscription tier"""
    limits = {
        'Free': {
            'max_alerts_per_month': 100,
            'max_community_members': 50,
            'max_communities': 1,
            'advanced_analytics': False,
            'custom_branding': False,
            'priority_support': False
        },
        'Premium': {
            'max_alerts_per_month': 1000,
            'max_community_members': 500,
            'max_communities': 10,
            'advanced_analytics': True,
            'custom_branding': True,
            'priority_support': True
        }
    }
    return limits.get(subscription_tier, limits['Free'])

def check_community_limits(community, action_type):
    """Check if community has reached limits for certain actions"""
    from app import db
    from models import User, Alert
    from datetime import datetime
    from sqlalchemy import func, extract
    
    if not community:
        return False, "Community not found"
    
    # Get subscription limits - handle Community model object
    try:
        subscription_plan = getattr(community, 'subscription_plan', 'Free')
    except (TypeError, AttributeError):
        subscription_plan = 'Free'
    
    limits = get_subscription_limits(subscription_plan)
    
    if action_type == 'add_member':
        # Check member count using SQLAlchemy
        member_count = db.session.query(User).filter_by(community_id=community.id).count()
        
        if member_count >= limits['max_community_members']:
            return False, f"You've reached the maximum number of members ({limits['max_community_members']}) for your plan. Please upgrade to add more members."
    
    elif action_type == 'post_alert':
        # Check alerts this month using SQLAlchemy
        current_year = datetime.now().year
        current_month = datetime.now().month
        
        alert_count = db.session.query(Alert).filter(
            Alert.community_id == community.id,
            extract('year', Alert.timestamp) == current_year,
            extract('month', Alert.timestamp) == current_month
        ).count()
        
        if alert_count >= limits['max_alerts_per_month']:
            return False, f"You've reached the maximum number of alerts ({limits['max_alerts_per_month']}) for this month. Please upgrade your plan."
    
    return True, None

# Business Branding Utilities

def get_community_branding(community_id):
    """Get branding information for a community"""
    from community import get_community_business_info
    
    business_info = get_community_business_info(community_id)
    
    if business_info:
        return {
            'business_name': business_info.name,
            'logo_url': business_info.logo_url,
            'primary_color': business_info.primary_color,
            'is_white_labeled': True
        }
    
    # Default branding for non-business communities
    return {
        'business_name': 'iZwi',
        'logo_url': None,
        'primary_color': '#1F2937',
        'is_white_labeled': False
    }

def apply_business_branding(template_data, community_id):
    """Apply business branding to template data"""
    branding = get_community_branding(community_id)
    
    # Add branding information to template context
    template_data.update({
        'branding': branding,
        'app_name': branding['business_name'],
        'primary_color': branding['primary_color'],
        'logo_url': branding['logo_url']
    })
    
    return template_data

def get_upgrade_prompt(feature_name=None):
    """Get standardized upgrade prompt message"""
    feature_text = f" '{feature_name}'" if feature_name else ""
    return {
        'title': 'Premium Feature',
        'message': f"This{feature_text} is a premium feature. Please upgrade your plan.",
        'action_text': 'Upgrade Now',
        'action_url': '/upgrade'
    }


# Analytics PDF Report Generation
def generate_analytics_pdf(business_id, business, filters, kpis, charts_data):
    """Generate a PDF analytics report using ReportLab"""
    try:
        from reportlab.lib.pagesizes import A4, letter
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import inch
        from reportlab.lib import colors
        from reportlab.lib.enums import TA_CENTER, TA_LEFT
        from reportlab.pdfbase import pdfmetrics
        from reportlab.pdfbase.ttfonts import TTFont
        import io

        # Get business branding
        business_name = business.name if business else 'iZwi'
        primary_color = business.primary_color if business else '#1F2937'

        # Format filter information
        filter_text = []
        if filters.get('date_from') and filters.get('date_to'):
            filter_text.append(f"Date Range: {filters['date_from']} to {filters['date_to']}")
        if filters.get('communities'):
            filter_text.append(f"Communities: {', '.join(filters['communities'])}")
        if filters.get('categories'):
            filter_text.append(f"Categories: {', '.join(filters['categories'])}")

        filters_text = ' | '.join(filter_text) if filter_text else 'All data'

        # Generate timestamp
        from datetime import datetime
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        # Create PDF document
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=72, leftMargin=72, topMargin=72, bottomMargin=18)
        styles = getSampleStyleSheet()

        # Custom styles
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Title'],
            fontSize=24,
            spaceAfter=30,
            alignment=TA_CENTER,
            textColor=colors.HexColor(primary_color)
        )

        heading_style = ParagraphStyle(
            'CustomHeading',
            parent=styles['Heading1'],
            fontSize=18,
            spaceAfter=12,
            textColor=colors.HexColor(primary_color)
        )

        normal_style = styles['Normal']
        normal_center_style = ParagraphStyle(
            'NormalCenter',
            parent=normal_style,
            alignment=TA_CENTER
        )

        # Build PDF content
        story = []

        # Header
        story.append(Paragraph(business_name, title_style))
        story.append(Paragraph("Security Analytics Report", styles['Heading1']))
        story.append(Paragraph("Comprehensive security insights and performance metrics", normal_center_style))
        story.append(Spacer(1, 20))

        # Filters section
        story.append(Paragraph("Report Filters", heading_style))
        story.append(Paragraph(f"<strong>Report Period:</strong> {filters_text}", normal_style))
        story.append(Paragraph(f"<strong>Generated:</strong> {timestamp}", normal_style))
        story.append(Spacer(1, 20))

        # KPI section
        story.append(Paragraph("Key Performance Indicators", heading_style))

        # KPI data
        kpi_data = [
            ['Total Alerts', f"{kpis.get('total_alerts', 0):,}"],
            ['New Alerts', f"{kpis.get('new_alerts', 0):,}"],
            ['Resolved Alerts', f"{kpis.get('resolved_alerts', 0):,}"],
            ['Avg. Resolution Time (hrs)', f"{kpis.get('avg_resolution_time', 0):.1f}"],
            ['Busiest Day & Time', kpis.get('busiest_day_time', 'No data')]
        ]

        # Create KPI table
        kpi_table = Table(kpi_data, colWidths=[2.5*inch, 2.5*inch])
        kpi_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 12),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
            ('BACKGROUND', (1, 0), (1, -1), colors.whitesmoke),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))

        story.append(kpi_table)
        story.append(Spacer(1, 30))

        # Charts section
        story.append(Paragraph("Data Visualizations", heading_style))

        # Placeholder for charts (in a real implementation, you'd generate actual chart images)
        story.append(Paragraph("Alert Trends Over Time", styles['Heading2']))
        story.append(Paragraph("This chart shows alert trends over the selected time period.", normal_style))
        story.append(Spacer(1, 20))

        story.append(Paragraph("Alerts by Category", styles['Heading2']))
        story.append(Paragraph("This chart breaks down alerts by category type.", normal_style))
        story.append(Spacer(1, 20))

        story.append(Paragraph("Alert Status Distribution", styles['Heading2']))
        story.append(Paragraph("This chart shows the distribution of alert statuses.", normal_style))
        story.append(Spacer(1, 30))

        # Footer
        story.append(Paragraph("This report was generated by " + business_name + " Analytics Dashboard", normal_center_style))
        story.append(Paragraph("For questions or support, please contact your administrator", normal_center_style))

        # Build PDF
        doc.build(story)

        # Get PDF bytes
        pdf_bytes = buffer.getvalue()
        buffer.close()

        return pdf_bytes

    except Exception as e:
        # If PDF generation fails, return a simple error PDF or raise the error
        raise Exception(f"Failed to generate PDF: {str(e)}")


# Multi-community access control decorators
from functools import wraps
from flask import session, flash, redirect, url_for, abort
from flask_login import current_user


def require_community_access(f):
    """Decorator to ensure user is member of current community"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        community_id = session.get('current_community_id')
        if not community_id or not current_user.is_member_of(community_id):
            flash('Access denied: You are not a member of this community', 'error')
            return redirect(url_for('select_community'))
        return f(*args, **kwargs)
    return decorated_function


def require_role_in_community(roles):
    """Decorator to ensure user has specific role in current community"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            community_id = session.get('current_community_id')
            role = current_user.get_role_in_community(community_id)
            if role not in roles:
                abort(403)
            return f(*args, **kwargs)
        return decorated_function
    return decorator