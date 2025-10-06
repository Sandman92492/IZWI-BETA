from datetime import datetime, timedelta
from flask import current_app
from flask_login import current_user
from app import db
from sqlalchemy import or_
from models import Alert, User, AlertReport
from utils import sanitize_plain_text, sanitize_text_input

def get_community_alerts(community_id, include_resolved=False):
    """Get all alerts for a community"""
    query = Alert.query.join(User, Alert.user_id == User.id).filter(Alert.community_id == community_id)

    if not include_resolved:
        query = query.filter(Alert.is_resolved == False)

    # Filter out expired alerts
    now = datetime.now()
    query = query.filter(
        or_(
            Alert.expires_at.is_(None),  # No expiration set
            Alert.expires_at > now       # Not yet expired
        )
    )

    alerts = query.order_by(Alert.timestamp.desc()).all()
    
    # Convert to format similar to old structure for compatibility
    alert_data = []
    for alert in alerts:
        user = User.query.get(alert.user_id)
        alert_dict = {
            'id': alert.id,
            'community_id': alert.community_id,
            'user_id': alert.user_id,
            'category': alert.category,
            'description': alert.description,
            'latitude': alert.latitude,
            'longitude': alert.longitude,
            'timestamp': alert.timestamp,
            'is_resolved': alert.is_resolved,
            'is_verified': getattr(alert, 'is_verified', False),
            'expires_at': alert.expires_at,
            'duration_minutes': alert.duration_minutes,
            'author_name': user.name if user else 'Unknown'
        }
        alert_data.append(alert_dict)
    
    return alert_data

def create_alert(community_id, user_id, category, description, latitude=0.0, longitude=0.0, is_verified=False, duration_minutes=None):
    """Create a new alert"""
    # Validate input
    if not category or not description:
        return None, 'Category and description are required'

    if len(description) > 500:
        return None, 'Description must be less than 500 characters'

    # Sanitize input
    category = sanitize_plain_text(category)
    description = sanitize_text_input(description)

    # Validate and parse coordinates
    try:
        latitude = float(latitude) if latitude else 0.0
        longitude = float(longitude) if longitude else 0.0
    except (ValueError, TypeError):
        latitude = 0.0
        longitude = 0.0

    # Handle expiration
    expires_at = None
    if duration_minutes:
        try:
            duration_minutes = int(duration_minutes)
            if duration_minutes > 0:
                expires_at = datetime.now() + timedelta(minutes=duration_minutes)
        except (ValueError, TypeError):
            pass

    # Create new alert
    alert = Alert(
        community_id=community_id,
        user_id=user_id,
        category=category,
        description=description,
        latitude=latitude,
        longitude=longitude,
        timestamp=datetime.now(),
        is_resolved=False,
        is_verified=bool(is_verified),
        expires_at=expires_at,
        duration_minutes=duration_minutes
    )

    db.session.add(alert)
    db.session.commit()

    return alert.id, None

def create_verified_alert(community_id, user_id, category, description, latitude=0.0, longitude=0.0, duration_minutes=None):
    """Create a verified alert shortcut"""
    return create_alert(community_id, user_id, category, description, latitude, longitude, is_verified=True, duration_minutes=duration_minutes)

def report_alert(alert_id, reporter_user):
    """Report an alert for inappropriate content"""
    if not alert_id:
        return False, 'Alert ID is required'
    
    # Log the report action
    current_app.logger.info(f'Alert {alert_id} reported by user {reporter_user.id} ({reporter_user.email}) at {datetime.utcnow()}')
    
    # Persist report
    try:
        rec = AlertReport(alert_id=alert_id, reported_by_user_id=reporter_user.id)
        db.session.add(rec)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f'Failed to persist alert report: {e}')
        return False, 'Failed to submit report'
    
    return True, 'Report submitted successfully'

def resolve_alert(alert_id, user):
    """Mark an alert as resolved (admin only)"""
    if user.role != 'Admin':
        return False, 'Admin access required'
    
    alert = Alert.query.get(alert_id)
    if alert:
        alert.is_resolved = True
        db.session.commit()
        return True, 'Alert marked as resolved'
    else:
        return False, 'Alert not found'

def update_alert(alert_id, user_id, category, description, latitude=0.0, longitude=0.0, duration_minutes=None):
    """Update an existing alert (only by the alert author)"""
    # Get the alert
    alert = Alert.query.get(alert_id)
    if not alert:
        return False, 'Alert not found'

    # Check if user is the author
    if alert.user_id != user_id:
        return False, 'You can only edit your own alerts'

    # Validate input
    if not category or not description:
        return False, 'Category and description are required'

    if len(description) > 500:
        return False, 'Description must be less than 500 characters'

    # Sanitize input
    category = sanitize_plain_text(category)
    description = sanitize_text_input(description)

    # Validate and parse coordinates
    try:
        latitude = float(latitude) if latitude else 0.0
        longitude = float(longitude) if longitude else 0.0
    except (ValueError, TypeError):
        latitude = 0.0
        longitude = 0.0

    # Handle expiration
    expires_at = None
    if duration_minutes:
        try:
            duration_minutes = int(duration_minutes)
            if duration_minutes > 0:
                expires_at = datetime.now() + timedelta(minutes=duration_minutes)
        except (ValueError, TypeError):
            pass

    # Update alert
    alert.category = category
    alert.description = description
    alert.latitude = latitude
    alert.longitude = longitude
    alert.expires_at = expires_at
    alert.duration_minutes = duration_minutes

    db.session.commit()

    return True, 'Alert updated successfully'

def get_alert_by_id(alert_id):
    """Get a specific alert by ID"""
    alert = Alert.query.get(alert_id)
    if alert:
        user = User.query.get(alert.user_id)
        alert_dict = {
            'id': alert.id,
            'community_id': alert.community_id,
            'user_id': alert.user_id,
            'category': alert.category,
            'description': alert.description,
            'latitude': alert.latitude,
            'longitude': alert.longitude,
            'timestamp': alert.timestamp,
            'is_resolved': alert.is_resolved,
            'is_verified': getattr(alert, 'is_verified', False),
            'expires_at': alert.expires_at,
            'duration_minutes': alert.duration_minutes,
            'author_name': user.name if user else 'Unknown'
        }
        return alert_dict
    return None