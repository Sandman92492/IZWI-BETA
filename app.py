import os
from dotenv import load_dotenv
from datetime import timedelta
import time
from logging.config import dictConfig

from flask import Flask, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase
from werkzeug.middleware.proxy_fix import ProxyFix
from flask_login import LoginManager
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
            # Ensure new tables exist (e.g., AlertReport)
            # Ensure invite_code table exists by creating all again (noop if exists)
            db.create_all()
            
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
