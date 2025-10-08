from app import db
from flask_login import UserMixin


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256))
    name = db.Column(db.String(100))
    avatar_url = db.Column(db.String(255))
    community_id = db.Column(db.Integer, db.ForeignKey('community.id'))
    role = db.Column(db.String(20), default='Member')
    business_id = db.Column(db.Integer, db.ForeignKey('business.id'))
    subscription_tier = db.Column(db.String(20), default='Free')
    is_on_duty = db.Column(db.Boolean, default=False)
    
    def is_business_user(self):
        """Check if user is a business-level user"""
        return self.role == 'Business' or self.business_id is not None
    
    def is_super_admin(self):
        """Check if user is a Super Admin for a business"""
        return (self.role == 'SuperAdmin') and self.business_id is not None
    
    def is_founder(self):
        """Check if user is a platform founder"""
        return self.role == 'Founder'
    
    def is_admin(self):
        """Check if user is an admin"""
        return self.role == 'Admin'
    
    def is_moderator(self):
        """Check if user is a moderator"""
        return self.role == 'Moderator'
    
    def has_premium_access(self):
        """Check if user has premium access"""
        return self.subscription_tier == 'Premium' or self.role == 'Business'

    def is_guard(self):
        """Check if user is a guard"""
        return self.role == 'Guard'


class Community(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    admin_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    invite_link_slug = db.Column(db.String(100), unique=True, nullable=False)
    subscription_plan = db.Column(db.String(20), default='Free')
    boundary_data = db.Column(db.Text)
    business_id = db.Column(db.Integer, db.ForeignKey('business.id'))
    max_alerts = db.Column(db.Integer, default=100)
    max_members = db.Column(db.Integer, default=50)


class Alert(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    community_id = db.Column(db.Integer, db.ForeignKey('community.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    category = db.Column(db.String(50), nullable=False)
    description = db.Column(db.Text, nullable=False)
    latitude = db.Column(db.Float, default=0)
    longitude = db.Column(db.Float, default=0)
    timestamp = db.Column(db.DateTime, nullable=False)
    is_resolved = db.Column(db.Boolean, default=False)
    is_premium_feature = db.Column(db.Boolean, default=False)
    is_verified = db.Column(db.Boolean, default=False)
    expires_at = db.Column(db.DateTime, nullable=True)
    duration_minutes = db.Column(db.Integer, nullable=True)


class Business(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    logo_url = db.Column(db.String(255))
    primary_color = db.Column(db.String(7), default='#1F2937')
    contact_email = db.Column(db.String(120))
    subscription_tier = db.Column(db.String(20), default='Free')
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())
    is_active = db.Column(db.Boolean, default=True)


class AlertReport(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    alert_id = db.Column(db.Integer, db.ForeignKey('alert.id'), nullable=False)
    reported_by_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    note = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())


class InviteCode(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    code_hash = db.Column(db.String(255), nullable=False)
    purpose = db.Column(db.String(50), default='business_creation')
    max_uses = db.Column(db.Integer, default=1)
    used_count = db.Column(db.Integer, default=0)
    expires_at = db.Column(db.DateTime, nullable=True)
    revoked = db.Column(db.Boolean, default=False)
    created_by_user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())


class GuardInvite(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    invite_token = db.Column(db.String(255), unique=True, nullable=False)
    business_id = db.Column(db.Integer, db.ForeignKey('business.id'), nullable=False)
    created_by_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    used = db.Column(db.Boolean, default=False)
    used_by_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    used_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())
    expires_at = db.Column(db.DateTime, nullable=True)

    def is_valid(self):
        """Check if invitation is still valid (not used, not expired)"""
        if self.used:
            return False
        if self.expires_at and self.expires_at < db.func.current_timestamp():
            return False
        return True


class GuardLocation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    guard_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    latitude = db.Column(db.Float, nullable=False)
    longitude = db.Column(db.Float, nullable=False)
    timestamp = db.Column(db.DateTime, default=db.func.current_timestamp(), onupdate=db.func.current_timestamp())

    # Index for performance when querying latest locations for guards
    __table_args__ = (
        db.Index('idx_guard_location_user_timestamp', 'guard_user_id', 'timestamp'),
    )


class PushSubscription(db.Model):
    """Model for storing web push notification subscriptions"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    endpoint = db.Column(db.Text, nullable=False)  # Push service endpoint URL
    p256dh = db.Column(db.Text, nullable=False)    # Public key for encryption
    auth = db.Column(db.Text, nullable=False)      # Authentication secret
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())
    updated_at = db.Column(db.DateTime, default=db.func.current_timestamp(), onupdate=db.func.current_timestamp())

    # Ensure one subscription per user per endpoint
    __table_args__ = (
        db.Index('idx_push_subscription_user_endpoint', 'user_id', 'endpoint'),
        db.UniqueConstraint('user_id', 'endpoint', name='unique_user_endpoint')
    )

    def __repr__(self):
        return f'<PushSubscription {self.id} for user {self.user_id}>'