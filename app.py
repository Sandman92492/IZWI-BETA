import os
from dotenv import load_dotenv
from datetime import timedelta
import time
from logging.config import dictConfig

from flask import Flask, request, redirect, url_for, flash, send_from_directory, jsonify, render_template
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy import text
from werkzeug.middleware.proxy_fix import ProxyFix
from flask_login import LoginManager, login_required
from flask_wtf.csrf import CSRFProtect, CSRFError, generate_csrf


class Base(DeclarativeBase):
    pass


db = SQLAlchemy(model_class=Base)


# Configure logging for better visibility in Replit/Gunicorn
def setup_logging():
    """Configure Flask logging to show INFO level to console"""
    dictConfig({
        'version': 1,
        'formatters': {
            'default': {
                'format':
                '[%(asctime)s] %(levelname)s in %(module)s: %(message)s',
            }
        },
        'handlers': {
            'console': {
                'class': 'logging.StreamHandler',
                'level': 'INFO',
                'formatter': 'default',
                'stream': 'ext://sys.stdout',
            },
        },
        'root': {
            'level': 'INFO',
            'handlers': ['console'],
        },
    })


# Load environment variables from .env early
load_dotenv()

# Validate required environment variables
SESSION_SECRET = os.environ.get("SESSION_SECRET")
DATABASE_URL = os.environ.get("DATABASE_URL")

if not SESSION_SECRET:
    raise RuntimeError("SESSION_SECRET environment variable is required")
if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL environment variable is required")

# create the app
app = Flask(__name__)
app.secret_key = SESSION_SECRET
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1,
                        x_host=1)  # needed for url_for to generate with https

# Session configuration for production compatibility
# Check if running in production (common deployment indicator)
is_production = os.environ.get('REPLIT_DEPLOYMENT') == '1' or os.environ.get(
    'FLASK_ENV') == 'production'

app.config.update(
    WTF_CSRF_TIME_LIMIT=3600,  # CSRF token expires in 1 hour
    WTF_CSRF_SSL_STRICT=is_production,
    SESSION_COOKIE_SECURE=
    is_production,  # True for HTTPS production environments
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=timedelta(days=7),
    REMEMBER_COOKIE_DURATION=timedelta(days=7) if is_production else timedelta(
        days=3),
    REMEMBER_COOKIE_SECURE=is_production,
    REMEMBER_COOKIE_HTTPONLY=True,
    REMEMBER_COOKIE_SAMESITE='Lax',
    REMEMBER_COOKIE_REFRESH_EACH_REQUEST=False,
    # Asset version for cache-busting static files
    ASSET_VERSION=os.environ.get('ASSET_VERSION', str(int(time.time()))),
    TEMPLATES_AUTO_RELOAD=True
)

# In development, disable static file caching to see changes immediately
if not is_production:
    app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0
    try:
        app.jinja_env.auto_reload = True
    except Exception:
        pass

# configure the database, relative to the app instance folder
app.config["SQLALCHEMY_DATABASE_URI"] = DATABASE_URL
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
}
# initialize the app with the extension, flask-sqlalchemy >= 3.0.x
db.init_app(app)

# Set up logging
setup_logging()


def init_database():
    """Initialize database tables - safe for multiple caliiiiils"""
    with app.app_context():
        # Make sure to import the models here or their tables won't be created
        import models  # noqa: F401

        try:
            # Create all tables if they don't exist
            db.create_all()
            
            # Safe migration: add missing columns if needed
            from sqlalchemy import inspect, text
            inspector = inspect(db.engine)
            columns = [c['name'] for c in inspector.get_columns('alert')]
            if 'is_verified' not in columns:
                try:
                    db.session.execute(text('ALTER TABLE alert ADD COLUMN is_verified BOOLEAN DEFAULT 0'))
                    db.session.commit()
                    app.logger.info("Added missing column 'is_verified' to alert table")
                except Exception as mig_e:
                    db.session.rollback()
                    app.logger.error(f"Failed to add 'is_verified' column: {mig_e}")

            # Check for expires_at column
            if 'expires_at' not in columns:
                try:
                    db.session.execute(text('ALTER TABLE alert ADD COLUMN expires_at TIMESTAMP'))
                    db.session.commit()
                    app.logger.info("Added missing column 'expires_at' to alert table")
                except Exception as mig_e:
                    db.session.rollback()
                    app.logger.error(f"Failed to add 'expires_at' column: {mig_e}")

            # Check for duration_minutes column
            if 'duration_minutes' not in columns:
                try:
                    db.session.execute(text('ALTER TABLE alert ADD COLUMN duration_minutes INTEGER'))
                    db.session.commit()
                    app.logger.info("Added missing column 'duration_minutes' to alert table")
                except Exception as mig_e:
                    db.session.rollback()
                    app.logger.error(f"Failed to add 'duration_minutes' column: {mig_e}")

            # Check for status column
            if 'status' not in columns:
                try:
                    db.session.execute(text("ALTER TABLE alert ADD COLUMN status VARCHAR(20) DEFAULT 'New'"))
                    db.session.commit()
                    app.logger.info("Added missing column 'status' to alert table")
                except Exception as mig_e:
                    db.session.rollback()
                    app.logger.error(f"Failed to add 'status' column: {mig_e}")

            # Check for resolved_at column
            if 'resolved_at' not in columns:
                try:
                    db.session.execute(text('ALTER TABLE alert ADD COLUMN resolved_at TIMESTAMP'))
                    db.session.commit()
                    app.logger.info("Added missing column 'resolved_at' to alert table")
                except Exception as mig_e:
                    db.session.rollback()
                    app.logger.error(f"Failed to add 'resolved_at' column: {mig_e}")

            # Migrate existing data to new status field
            try:
                # Update resolved alerts to have status='Resolved'
                db.session.execute(text("UPDATE alert SET status = 'Resolved' WHERE is_resolved = true"))
                # Update unresolved alerts to have status='New'
                db.session.execute(text("UPDATE alert SET status = 'New' WHERE is_resolved = false"))
                # Set resolved_at for already resolved alerts
                db.session.execute(text("UPDATE alert SET resolved_at = timestamp WHERE is_resolved = true AND resolved_at IS NULL"))
                db.session.commit()
                app.logger.info("Migrated existing alert data to new status and resolved_at fields")
            except Exception as mig_e:
                db.session.rollback()
                app.logger.error(f"Failed to migrate existing alert data: {mig_e}")
            # Check for is_on_duty column in user table
            user_columns = [c['name'] for c in inspector.get_columns('user')]
            if 'is_on_duty' not in user_columns:
                try:
                    db.session.execute(text("ALTER TABLE \"user\" ADD COLUMN is_on_duty BOOLEAN DEFAULT false"))
                    db.session.commit()
                    app.logger.info("Added missing column 'is_on_duty' to user table")
                except Exception as mig_e:
                    db.session.rollback()
                    app.logger.error(f"Failed to add 'is_on_duty' column: {mig_e}")

            # Ensure new tables exist (e.g., AlertReport, GuardInvite, GuardLocation, PushSubscription)
            # Ensure invite_code table exists by creating all again (noop if exists)
            db.create_all()

            # Check for user_community_membership table
            if 'user_community_membership' not in inspector.get_table_names():
                try:
                    db.create_all()  # This will create the new UserCommunityMembership table
                    app.logger.info("Created user_community_membership table")
                except Exception as mig_e:
                    db.session.rollback()
                    app.logger.error(f"Failed to create user_community_membership table: {mig_e}")

            # Additional migration for PushSubscription table if it doesn't exist
            try:
                inspector = inspect(db.engine)
                if 'push_subscription' not in inspector.get_table_names():
                    app.logger.info("Creating PushSubscription table")
                    db.create_all()  # This will create any missing tables
            except Exception as e:
                app.logger.error(f"Error ensuring PushSubscription table exists: {e}")

            # Check for community_id column in guard_invite table
            if 'guard_invite' in inspector.get_table_names():
                try:
                    guard_invite_columns = [c['name'] for c in inspector.get_columns('guard_invite')]
                    if 'community_id' not in guard_invite_columns:
                        try:
                            db.session.execute(text('ALTER TABLE guard_invite ADD COLUMN community_id INTEGER'))
                            db.session.commit()
                            app.logger.info("Added missing column 'community_id' to guard_invite table")
                        except Exception as mig_e:
                            db.session.rollback()
                            app.logger.error(f"Failed to add 'community_id' column to guard_invite table: {mig_e}")
                except Exception as e:
                    app.logger.error(f"Error checking guard_invite table structure: {e}")
            
            app.logger.info("Database tables initialized successfully")
        except Exception as e:
            app.logger.error(f"Database initialization error: {e}")
            raise


# Initialize database during app creation
init_database()

# Initialize extensions
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'  # type: ignore
login_manager.login_message = "Please log in to access this page."
login_manager.login_message_category = "info"

csrf = CSRFProtect(app)

# Import after app context
from auth import load_user, check_session_activity
from utils import get_category_color, get_category_icon, format_time_ago, format_time_left
import push_notifications

# Set up user loader for Flask-Login
login_manager.user_loader(load_user)

# Set up session activity check
app.before_request(check_session_activity)

# Register utils functions as Jinja globals for template access
app.jinja_env.globals.update(get_category_color=get_category_color,
                             get_category_icon=get_category_icon,
                             format_time_ago=format_time_ago,
                             format_time_left=format_time_left,
                             csrf_token=generate_csrf)

# Also register as Jinja filters for pipe syntax
app.jinja_env.filters.update(format_time_left=format_time_left)


@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    app.logger.error(f"CSRF error: {e.description}")
    try:
        flash('Security check failed. Please refresh the page and try again.', 'error')
    except Exception:
        pass
    # Use 303 to ensure the browser performs a GET after POST failure
    return redirect(request.referrer or url_for('index')), 303


# PWA Routes
@app.route('/offline')
def offline():
    """Serve offline fallback page"""
    return render_template('offline.html')


@app.route('/static/service-worker.js')
def service_worker():
    """Serve service worker with proper headers"""
    response = send_from_directory('static', 'service-worker.js',
                                   mimetype='application/javascript')
    response.headers['Service-Worker-Allowed'] = '/'
    response.headers['Cache-Control'] = 'no-cache'
    return response


@app.route('/static/manifest.json')
def manifest():
    """Serve web app manifest"""
    response = send_from_directory('static', 'manifest.json',
                                   mimetype='application/manifest+json')
    response.headers['Cache-Control'] = 'no-cache'
    return response


# Push Notification API Routes
@app.route('/api/push/vapid-public-key', methods=['GET'])
def get_vapid_public_key():
    """Get VAPID public key for push notification subscription"""
    try:
        vapid_public_key = push_notifications.get_vapid_public_key()
        return jsonify({'vapid_public_key': vapid_public_key})
    except Exception as e:
        app.logger.error(f'Error getting VAPID public key: {e}')
        return jsonify({'error': 'Failed to get VAPID public key'}), 500


@app.route('/api/push/subscribe', methods=['POST'])
def subscribe_push():
    """Subscribe user to push notifications"""
    try:
        subscription_data = request.get_json()
        if not subscription_data:
            return jsonify({'error': 'No subscription data provided'}), 400

        # Get user_id from the subscription data (sent by client)
        user_id = subscription_data.get('user_id')
        if not user_id:
            return jsonify({'error': 'User ID is required'}), 400

        # Verify the user exists (but don't require them to be logged in for this request)
        from models import User
        user = User.query.get(user_id)
        if not user:
            return jsonify({'error': 'Invalid user ID'}), 400

        result = push_notifications.subscribe_user(subscription_data)

        if 'error' in result:
            return jsonify(result), 400

        return jsonify(result)
    except Exception as e:
        app.logger.error(f'Error subscribing to push notifications: {e}')
        return jsonify({'error': 'Failed to subscribe to push notifications'}), 500


@app.route('/api/push/unsubscribe', methods=['POST'])
def unsubscribe_push():
    """Unsubscribe user from push notifications"""
    try:
        subscription_data = request.get_json()
        if not subscription_data:
            return jsonify({'error': 'No subscription data provided'}), 400

        # Get user_id from the subscription data (sent by client)
        user_id = subscription_data.get('user_id')
        if not user_id:
            return jsonify({'error': 'User ID is required'}), 400

        # Verify the user exists (but don't require them to be logged in for this request)
        from models import User
        user = User.query.get(user_id)
        if not user:
            return jsonify({'error': 'Invalid user ID'}), 400

        result = push_notifications.unsubscribe_user(subscription_data)

        if 'error' in result:
            return jsonify(result), 400

        return jsonify(result)
    except Exception as e:
        app.logger.error(f'Error unsubscribing from push notifications: {e}')
        return jsonify({'error': 'Failed to unsubscribe from push notifications'}), 500


# Health check endpoint for deployment monitoring
@app.route('/health')
def health_check():
    """Health check endpoint for deployment monitoring"""
    try:
        # Check database connection
        from models import User
        db.session.execute(text('SELECT 1'))
        db_status = 'healthy'

        return jsonify({
            'status': 'healthy',
            'database': db_status,
            'timestamp': time.time()
        }), 200
    except Exception as e:
        app.logger.error(f'Health check failed: {e}')
        return jsonify({
            'status': 'unhealthy',
            'error': str(e),
            'timestamp': time.time()
        }), 500
