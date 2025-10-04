from datetime import datetime, timedelta
from flask import session, request, redirect, url_for, flash, current_app
from flask_login import UserMixin, current_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
from app import db
from models import User
from utils import sanitize_plain_text, validate_email

# User model methods moved to models.py


def load_user(user_id):
    """Load user by ID for Flask-Login"""
    return User.query.get(int(user_id))


def check_session_timeout():
    """Check if the current session has timed out"""
    try:
        if 'last_activity' in session:
            last_activity = datetime.fromisoformat(session['last_activity'])
            if datetime.now() - last_activity > timedelta(hours=24):
                session.clear()
                return True
        session['last_activity'] = datetime.now().isoformat()
        return False
    except (ValueError, TypeError):
        # Handle malformed timestamp data
        session.clear()
        return True


def check_session_activity():
    """Check session timeout before each request to authenticated routes"""
    # Skip session timeout for certain routes that don't need authentication
    if request.endpoint in [
            'index', 'signup_page', 'login', 'join_community', 'static',
            'privacy_policy', 'terms_of_service'
    ]:
        return

    # Check session timeout for authenticated users
    if current_user.is_authenticated:
        if check_session_timeout():
            logout_user()
            flash('Your session has expired. Please log in again.')
            return redirect(url_for('login'))


def authenticate_user(email, password):
    """Authenticate user with email and password"""
    # Validate input
    if not email or not password:
        current_app.logger.warning(
            "Auth attempt with missing email or password")
        return None, 'Email and password are required'

    if not validate_email(email):
        current_app.logger.warning(f"Invalid email format: {email}")
        return None, 'Please enter a valid email address'

    # Sanitize email
    email = sanitize_plain_text(email.strip())

    user = User.query.filter_by(email=email).first()

    if not user:
        current_app.logger.warning(f"User not found for email: {email}")
        return None, 'Invalid email or password'

    hash_matches = check_password_hash(user.password_hash, password)
    if hash_matches:
        current_app.logger.info(
            f"Successful auth for user {user.id} ({email})")
        return user, None
    else:
        current_app.logger.warning(
            f"Password mismatch for user {user.id} ({email})")
        return None, 'Invalid email or password'


def create_user(email,
                password,
                community_id=None,
                business_id=None,
                role=None,
                name: str | None = None):
    """Create a new user account"""
    # Validate input
    if not email or not password:
        current_app.logger.warning(
            "Create user attempt with missing email or password")
        return None, 'Email and password are required'

    if not validate_email(email):
        current_app.logger.warning(
            f"Invalid email format in create_user: {email}")
        return None, 'Please enter a valid email address'

    if len(password) < 8:
        return None, 'Password must be at least 8 characters long'

    # Sanitize email
    email = sanitize_plain_text(email.strip())

    # Check if user already exists
    existing_user = User.query.filter_by(email=email).first()
    if existing_user:
        current_app.logger.warning(
            f"Attempt to create duplicate user: {email}")
        return None, 'Email already registered'

    # Determine user role and subscription tier
    if not role:
        if business_id:
            role = 'Business'
        elif community_id:
            role = 'Member'
        else:
            role = 'Admin'

    subscription_tier = 'Premium' if role == 'Business' else 'Free'

    # Create new user
    password_hash = generate_password_hash(password)
    current_app.logger.info(
        f"Generated password hash for {email}: {password_hash[:20]}..."
    )  # Log partial hash for debug

    user = User(email=email,
                password_hash=password_hash,
                name=sanitize_plain_text(name.strip()) if name else '',
                avatar_url='',
                community_id=community_id,
                role=role,
                business_id=business_id,
                subscription_tier=subscription_tier)

    db.session.add(user)
    try:
        db.session.commit()
        current_app.logger.info(
            f"Successfully created user {user.id} ({email}) with role {role} and community_id {community_id}"
        )
        return user, None
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(
            f"Failed to commit new user {email}: {str(e)}")
        return None, 'An error occurred during account creation. Please try again.'
