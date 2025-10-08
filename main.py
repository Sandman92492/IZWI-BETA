import os
from datetime import timedelta
from flask import render_template, request, redirect, url_for, flash, session, jsonify, abort
import json
from flask_login import login_user, logout_user, login_required, current_user

# Import the Flask app from app.py
from app import app
from app import db
from app import csrf
import os
import secrets
import string
from datetime import datetime, timedelta
from models import User, InviteCode, Alert, AlertReport
from sqlalchemy import not_

# Import our modular components
from auth import authenticate_user, create_user
from community import (create_community, get_community_by_invite_slug,
                       get_community_info, get_community_members,
                       get_community_boundary_data, remove_member,
                       update_community_name, update_community_boundary,
                       create_business)
from utils import hash_code_plaintext, is_invite_valid
from alerts import get_community_alerts, create_alert, report_alert, create_verified_alert
from community import get_business_communities, get_community_business_info
from models import Community
from models import Alert, User, GuardInvite, GuardLocation
from app import db


# Routes
@app.route('/')
def index():
    return render_template('home.html')


@app.route('/signup')
def signup_page():
    # Check for invite link
    invite_slug = request.args.get('invite')
    invite = None

    if invite_slug:
        community = get_community_by_invite_slug(invite_slug)
        if community:
            session['invite_community_id'] = community[0]
            invite = {'community_name': community[1], 'slug': invite_slug}

    return render_template('landing.html', invite=invite)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')

        app.logger.info(f"Login attempt for email: {email}")
        user, error = authenticate_user(email, password)

        if user:
            # Handle "Remember me" functionality
            remember = request.form.get('remember') == 'on'
            remember_duration = timedelta(days=7) if os.environ.get(
                'FLASK_ENV') == 'production' else timedelta(days=3)
            login_user(user,
                       remember=remember,
                       duration=remember_duration if remember else None)

            session['ask_location'] = True

            # Make session permanent if remember me is checked
            if remember:
                session.permanent = True

            # Debug logging for session
            app.logger.info(f'User {user.id} logged in successfully')
            app.logger.info(
                f'Session ID: {session.get("_id", "No session ID")}')
            app.logger.info(f'User community_id: {user.community_id}')

            # Add success message for login
            flash('Welcome back! You have been successfully logged in.',
                  'success')

            # Redirect based on role
            if hasattr(user, 'is_super_admin') and user.is_super_admin():
                return redirect(url_for('super_admin_dashboard'))
            elif user.community_id:
                return redirect(url_for('dashboard'))
            else:
                return redirect(url_for('define_community'))
        else:
            if error:
                app.logger.warning(f"Login failed for {email}: {error}")
                flash(error)

    return render_template('login.html')


@app.route('/signup/guard')
def guard_signup():
    """Guard signup page with invitation token"""
    token = request.args.get('token')
    if not token:
        flash('Invalid invitation link.', 'error')
        return redirect(url_for('index'))

    # Validate the invitation token
    invite = GuardInvite.query.filter_by(invite_token=token).first()
    if not invite or not invite.is_valid():
        flash('This invitation link is invalid or has expired.', 'error')
        return redirect(url_for('index'))

    return render_template('guard_signup.html', token=token, business_name='Security Company')


@app.route('/signup/guard', methods=['POST'])
def guard_signup_submit():
    """Process guard signup form"""
    token = request.form.get('token')
    if not token:
        flash('Invalid invitation link.', 'error')
        return redirect(url_for('index'))

    # Validate the invitation token
    invite = GuardInvite.query.filter_by(invite_token=token).first()
    if not invite or not invite.is_valid():
        flash('This invitation link is invalid or has expired.', 'error')
        return redirect(url_for('index'))

    name = request.form.get('name', '').strip()
    email = request.form.get('email', '').strip()
    password = request.form.get('password', '')
    password_confirm = request.form.get('password_confirm', '')

    # Validate form data
    if not name or not email or not password:
        flash('All fields are required.', 'error')
        return redirect(url_for('guard_signup', token=token))

    if password != password_confirm:
        flash('Passwords do not match.', 'error')
        return redirect(url_for('guard_signup', token=token))

    if len(password) < 8:
        flash('Password must be at least 8 characters long.', 'error')
        return redirect(url_for('guard_signup', token=token))

    # Check if email already exists
    existing_user = User.query.filter_by(email=email).first()
    if existing_user:
        flash('Email already registered.', 'error')
        return redirect(url_for('guard_signup', token=token))

    # Create the guard user
    guard_user = User(
        email=email,
        password_hash=generate_password_hash(password),
        name=name,
        role='Guard',
        business_id=invite.business_id,
        subscription_tier='Premium'  # Guards get premium access
    )

    # Mark invitation as used
    invite.used = True
    invite.used_by_user_id = guard_user.id
    invite.used_at = datetime.now()

    db.session.add(guard_user)
    db.session.commit()

    # Auto-login the new guard
    login_user(guard_user)

    flash('Welcome! You have been successfully registered as a guard.', 'success')
    return redirect(url_for('guard_dashboard'))


@app.route('/signup', methods=['POST'])
def signup_submit():
    name = request.form.get('name', '').strip()
    email = request.form.get('email', '').strip()
    password = request.form.get('password', '')
    consent = request.form.get('consent')

    app.logger.info(f"Signup attempt for email: {email}")

    # Check consent
    if not consent:
        app.logger.warning("Signup failed: consent not given")
        flash(
            'You must agree to the Terms of Service and Privacy Policy to sign up'
        )
        return redirect(url_for('signup_page'))

    # Get community ID from invite session
    community_id = session.get('invite_community_id')

    user, error = create_user(email, password, community_id, name=name)

    if user:
        app.logger.info(f"Signup successful for {email}, user ID: {user.id}")
        # Log in the new user
        login_user(user)

        # Clear invite session
        session.pop('invite_community', None)  # Fixed typo from previous 'invite_community_id'

        session['ask_location'] = True

        # Redirect based on whether they joined via invite
        if community_id:
            # Store user info for welcome screen
            session['new_user_welcome'] = True
            session['user_name'] = (name or email.split('@')[0]).title()
            return redirect(url_for('welcome'))
        else:
            flash(
                'Welcome! Your account has been created. Let\'s set up your community.',
                'success')
            return redirect(url_for('define_community'))
    else:
        if error:
            app.logger.warning(f"Signup failed for {email}: {error}")
            flash(error)
        return redirect(url_for('signup_page'))


@app.route('/logout')
@login_required
def logout():
    app.logger.info(f"User {current_user.id} logged out")
    logout_user()
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('index'))


@app.route('/dashboard')
@login_required
def dashboard():
    # Redirect guards to their dedicated dashboard
    if current_user.is_guard():
        return redirect(url_for('guard_dashboard'))

    if not current_user.community_id:
        return redirect(url_for('define_community'))

    # Get community alerts
    alerts = get_community_alerts(current_user.community_id)
    app.logger.info(f"Dashboard: Found {len(alerts)} alerts for community {current_user.community_id}")
    community = get_community_info(current_user.community_id)
    # Normalize boundary JSON so the frontend always receives a clean JSON object/feature
    raw_boundary = get_community_boundary_data(current_user.community_id)
    boundary_data = None
    try:
        if raw_boundary:
            obj = json.loads(raw_boundary)
            if isinstance(obj, str):
                try:
                    obj = json.loads(obj)
                except Exception:
                    pass
            # Only embed valid dict-like geojson
            if isinstance(obj, (dict, list)):
                boundary_data = json.dumps(obj)
    except Exception:
        boundary_data = None
    members = get_community_members(current_user.community_id)
    member_count = len(members) if members else 0

    # Determine Plus access for UI controls via cumulative entitlement
    try:
        from utils import has_plan_at_least
        has_plus = has_plan_at_least(current_user, 'plus', community=community)
    except Exception:
        has_plus = False

    return render_template('dashboard.html',
                           alerts=alerts,
                           community=community,
                           boundary_data=boundary_data,
                           member_count=member_count,
                           has_plus=has_plus)


@app.route('/super-admin')
@login_required
def super_admin_dashboard():
    # Security: must be super admin and have a business
    if not (hasattr(current_user, 'is_super_admin') and current_user.is_super_admin()):
        abort(403)
    
    # Fetch all communities for this business
    communities = get_business_communities(current_user.business_id)
    
    # Choose selected community (first by default or via query param)
    selected_id = request.args.get('community_id', type=int)
    if not selected_id and communities:
        selected_id = communities[0].id
    
    selected = Community.query.get(selected_id) if selected_id else None
    if selected and selected.business_id != current_user.business_id:
        abort(403)
    
    alerts = get_community_alerts(selected.id) if selected else []
    raw_boundary = get_community_boundary_data(selected.id) if selected else None
    boundary_data = None
    try:
        if raw_boundary:
            obj = json.loads(raw_boundary)
            if isinstance(obj, str):
                try:
                    obj = json.loads(obj)
                except Exception:
                    pass
            if isinstance(obj, (dict, list)):
                boundary_data = json.dumps(obj)
    except Exception:
        boundary_data = None
    
    return render_template('super_admin.html',
                           communities=communities,
                           selected=selected,
                           alerts=alerts,
                           boundary_data=boundary_data)


@app.route('/super-admin/communities')
@login_required
def super_admin_communities():
    if not (hasattr(current_user, 'is_super_admin') and current_user.is_super_admin()):
        return jsonify({'error': 'Forbidden'}), 403
    communities = get_business_communities(current_user.business_id)
    return jsonify([
        {'id': c.id, 'name': c.name} for c in communities
    ])


@app.route('/super-admin/alerts')
@login_required
def super_admin_alerts():
    if not (hasattr(current_user, 'is_super_admin') and current_user.is_super_admin()):
        return jsonify({'error': 'Forbidden'}), 403
    community_id = request.args.get('community_id', type=int)
    if not community_id:
        return jsonify({'error': 'community_id required'}), 400
    community = Community.query.get(community_id)
    if not community or community.business_id != current_user.business_id:
        return jsonify({'error': 'Forbidden'}), 403
    alerts = get_community_alerts(community_id)
    raw_boundary = get_community_boundary_data(community_id)
    boundary_data = None
    try:
        if raw_boundary:
            obj = json.loads(raw_boundary)
            if isinstance(obj, str):
                try:
                    obj = json.loads(obj)
                except Exception:
                    pass
            if isinstance(obj, (dict, list)):
                boundary_data = obj
    except Exception:
        boundary_data = None
    return jsonify({'alerts': alerts, 'boundary': boundary_data})


@app.route('/super-admin/alerts/<int:alert_id>')
@login_required
def super_admin_alert_detail(alert_id: int):
    if not (hasattr(current_user, 'is_super_admin') and current_user.is_super_admin()):
        return jsonify({'error': 'Forbidden'}), 403
    alert = db.session.get(Alert, alert_id)
    if not alert:
        return jsonify({'error': 'Not found'}), 404
    community = db.session.get(Community, alert.community_id)
    if not community or community.business_id != current_user.business_id:
        return jsonify({'error': 'Forbidden'}), 403
    author = db.session.get(User, alert.user_id)
    report_count = db.session.query(AlertReport).filter_by(alert_id=alert_id).count()
    return jsonify({
        'id': alert.id,
        'community_id': alert.community_id,
        'community_name': community.name if community else None,
        'category': alert.category,
        'description': alert.description,
        'latitude': alert.latitude,
        'longitude': alert.longitude,
        'timestamp': alert.timestamp,
        'is_resolved': alert.is_resolved,
        'is_verified': getattr(alert, 'is_verified', False),
        'author_name': author.name if author else 'Unknown',
        'author_email': author.email if author else None,
        'report_count': report_count
    })


@app.route('/super-admin/reported-alerts')
@login_required
def super_admin_reported_alerts():
    if not (hasattr(current_user, 'is_super_admin') and current_user.is_super_admin()):
        return jsonify({'error': 'Forbidden'}), 403
    community_id = request.args.get('community_id', type=int)
    if not community_id:
        return jsonify({'error': 'community_id required'}), 400
    community = Community.query.get(community_id)
    if not community or community.business_id != current_user.business_id:
        return jsonify({'error': 'Forbidden'}), 403
    subq = db.session.query(AlertReport.alert_id, db.func.count(AlertReport.id).label('reports')).group_by(AlertReport.alert_id).subquery()
    rows = db.session.query(Alert, subq.c.reports).join(subq, Alert.id == subq.c.alert_id).filter(Alert.community_id == community_id).order_by(Alert.timestamp.desc()).all()
    data = []
    for alert, reports in rows:
        author = db.session.get(User, alert.user_id)
        data.append({
            'id': alert.id,
            'category': alert.category,
            'description': alert.description,
            'latitude': alert.latitude,
            'longitude': alert.longitude,
            'timestamp': alert.timestamp,
            'is_resolved': alert.is_resolved,
            'is_verified': getattr(alert, 'is_verified', False),
            'author_name': author.name if author else 'Unknown',
            'reports': int(reports)
        })
    return jsonify({'alerts': data})


@app.route('/super-admin/alerts/<int:alert_id>/resolve', methods=['POST'])
@login_required
def super_admin_resolve_alert(alert_id: int):
    if not (hasattr(current_user, 'is_super_admin') and current_user.is_super_admin()):
        return jsonify({'error': 'Forbidden'}), 403
    alert = db.session.get(Alert, alert_id)
    if not alert:
        return jsonify({'error': 'Not found'}), 404
    community = db.session.get(Community, alert.community_id)
    if not community or community.business_id != current_user.business_id:
        return jsonify({'error': 'Forbidden'}), 403
    alert.is_resolved = True
    db.session.commit()
    app.logger.info(f"Alert {alert_id} resolved by SA {current_user.id}")
    return jsonify({'success': True})


@app.route('/super-admin/alerts/<int:alert_id>', methods=['DELETE'])
@login_required
def super_admin_delete_alert(alert_id: int):
    if not (hasattr(current_user, 'is_super_admin') and current_user.is_super_admin()):
        return jsonify({'error': 'Forbidden'}), 403
    alert = db.session.get(Alert, alert_id)
    if not alert:
        return jsonify({'error': 'Not found'}), 404
    community = db.session.get(Community, alert.community_id)
    if not community or community.business_id != current_user.business_id:
        return jsonify({'error': 'Forbidden'}), 403
    try:
        AlertReport.query.filter_by(alert_id=alert_id).delete()
        db.session.delete(alert)
        db.session.commit()
        app.logger.info(f"Alert {alert_id} deleted by SA {current_user.id}")
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Failed to delete alert {alert_id}: {e}')
        return jsonify({'success': False, 'error': 'Delete failed'}), 500


# Guard invitation and management routes
@app.route('/super-admin/invite-guard', methods=['POST'])
@login_required
def super_admin_invite_guard():
    """Generate a unique guard invitation link"""
    if not (hasattr(current_user, 'is_super_admin') and current_user.is_super_admin()):
        return jsonify({'error': 'Forbidden'}), 403

    invite_token = secrets.token_urlsafe(32)
    expires_at = datetime.now() + timedelta(days=7)  # Invites expire in 7 days

    invite = GuardInvite(
        invite_token=invite_token,
        business_id=current_user.business_id,
        created_by_user_id=current_user.id,
        expires_at=expires_at
    )

    db.session.add(invite)
    db.session.commit()

    invitation_url = url_for('guard_signup', token=invite_token, _external=True)
    return jsonify({
        'success': True,
        'invitation_url': invitation_url,
        'expires_at': expires_at.isoformat()
    })


@app.route('/super-admin/guards')
@login_required
def super_admin_guards():
    """Get all guards for the current business"""
    if not (hasattr(current_user, 'is_super_admin') and current_user.is_super_admin()):
        return jsonify({'error': 'Forbidden'}), 403

    guards = User.query.filter_by(
        role='Guard',
        business_id=current_user.business_id
    ).all()

    guard_data = []
    for guard in guards:
        # Get latest location if available
        latest_location = GuardLocation.query.filter_by(
            guard_user_id=guard.id
        ).order_by(GuardLocation.timestamp.desc()).first()

        guard_data.append({
            'id': guard.id,
            'name': guard.name,
            'email': guard.email,
            'is_on_duty': guard.is_on_duty,
            'last_location_timestamp': latest_location.timestamp.isoformat() if latest_location else None,
            'latitude': latest_location.latitude if latest_location else None,
            'longitude': latest_location.longitude if latest_location else None
        })

    return jsonify({'guards': guard_data})


@app.route('/super-admin/guards/<int:guard_id>/revoke', methods=['POST'])
@login_required
def super_admin_revoke_guard(guard_id: int):
    """Revoke guard access"""
    if not (hasattr(current_user, 'is_super_admin') and current_user.is_super_admin()):
        return jsonify({'error': 'Forbidden'}), 403

    guard = User.query.get(guard_id)
    if not guard or guard.business_id != current_user.business_id:
        return jsonify({'error': 'Guard not found'}), 404

    if guard.role != 'Guard':
        return jsonify({'error': 'User is not a guard'}), 400

    # Change role back to Member and turn off duty status
    guard.role = 'Member'
    guard.is_on_duty = False

    # Clear any existing locations
    GuardLocation.query.filter_by(guard_user_id=guard.id).delete()

    db.session.commit()
    app.logger.info(f"Guard {guard_id} access revoked by SA {current_user.id}")

    return jsonify({'success': True})


@app.route('/super-admin/guard-locations')
@login_required
def super_admin_guard_locations():
    """Get all on-duty guard locations for the business"""
    if not (hasattr(current_user, 'is_super_admin') and current_user.is_super_admin()):
        return jsonify({'error': 'Forbidden'}), 403

    # Get guards who are currently on duty
    on_duty_guards = User.query.filter_by(
        role='Guard',
        business_id=current_user.business_id,
        is_on_duty=True
    ).all()

    locations_data = []
    for guard in on_duty_guards:
        # Get latest location for each guard
        latest_location = GuardLocation.query.filter_by(
            guard_user_id=guard.id
        ).order_by(GuardLocation.timestamp.desc()).first()

        if latest_location:
            locations_data.append({
                'guard_id': guard.id,
                'name': guard.name,
                'latitude': latest_location.latitude,
                'longitude': latest_location.longitude,
                'last_update': latest_location.timestamp.isoformat()
            })

    return jsonify({'guards': locations_data})


# Guard location tracking routes
@app.route('/guard/toggle-duty', methods=['POST'])
@login_required
def guard_toggle_duty():
    """Toggle guard on-duty status"""
    if not current_user.is_guard():
        return jsonify({'error': 'Only guards can toggle duty status'}), 403

    current_status = current_user.is_on_duty
    new_status = not current_status

    # Update user status
    current_user.is_on_duty = new_status
    db.session.commit()

    # If going off-duty, clear location data
    if not new_status:
        GuardLocation.query.filter_by(guard_user_id=current_user.id).delete()
        db.session.commit()

    app.logger.info(f"Guard {current_user.id} toggled duty status to {new_status}")

    return jsonify({
        'success': True,
        'is_on_duty': new_status,
        'message': 'You are now ON DUTY' if new_status else 'You are now OFF DUTY'
    })


@app.route('/guard/update-location', methods=['POST'])
@login_required
def guard_update_location():
    """Receive location updates from guard"""
    if not current_user.is_guard():
        return jsonify({'error': 'Only guards can update location'}), 403

    if not current_user.is_on_duty:
        return jsonify({'error': 'You must be on duty to share location'}), 403

    data = request.get_json()
    if not data:
        return jsonify({'error': 'No location data provided'}), 400

    latitude = data.get('latitude')
    longitude = data.get('longitude')

    if latitude is None or longitude is None:
        return jsonify({'error': 'Latitude and longitude are required'}), 400

    # Validate coordinates are reasonable
    if not (-90 <= latitude <= 90) or not (-180 <= longitude <= 180):
        return jsonify({'error': 'Invalid coordinates'}), 400

    # Upsert location record (update if exists, insert if not)
    location = GuardLocation.query.filter_by(guard_user_id=current_user.id).first()
    if location:
        location.latitude = latitude
        location.longitude = longitude
        location.timestamp = datetime.now()
    else:
        location = GuardLocation(
            guard_user_id=current_user.id,
            latitude=latitude,
            longitude=longitude
        )
        db.session.add(location)

    db.session.commit()

    app.logger.info(f"Location updated for guard {current_user.id}: ({latitude}, {longitude})")

    return jsonify({'success': True})


@app.route('/guard/dashboard')
@login_required
def guard_dashboard():
    """Guard dashboard showing duty status and location sharing"""
    if not current_user.is_guard():
        return redirect(url_for('dashboard'))

    return render_template('guard_dashboard.html', is_on_duty=current_user.is_on_duty)


@app.route('/super-admin/post-alert')
@login_required
def super_admin_post_alert():
    if not (hasattr(current_user, 'is_super_admin') and current_user.is_super_admin()):
        abort(403)

    # Get community_id from query parameters
    community_id = request.args.get('community_id', type=int)
    selected = None

    if community_id:
        community = Community.query.get(community_id)
        if community and community.business_id == current_user.business_id:
            selected = community
        else:
            community_id = None

    # If no valid community selected, get the first available community
    if not selected:
        communities = get_business_communities(current_user.business_id)
        if communities:
            selected = communities[0]
            community_id = selected.id

    return render_template('super_admin_post_alert.html', selected=selected, community_id=community_id)


@app.route('/super-admin/post-verified', methods=['POST'])
@login_required
def super_admin_post_verified():
    if not (hasattr(current_user, 'is_super_admin') and current_user.is_super_admin()):
        return jsonify({'error': 'Forbidden'}), 403
    data = request.get_json() if request.is_json else request.form
    community_id = int(data.get('community_id', 0))
    category = data.get('category')
    description = data.get('description')
    latitude = data.get('latitude', 0.0)
    longitude = data.get('longitude', 0.0)
    duration_minutes = data.get('duration_minutes')

    community = Community.query.get(community_id)
    if not community or community.business_id != current_user.business_id:
        return jsonify({'error': 'Forbidden'}), 403

    alert_id, error = create_verified_alert(community_id, current_user.id, category, description, latitude, longitude, duration_minutes=duration_minutes)
    if alert_id:
        return jsonify({'success': True, 'alert_id': alert_id})
    else:
        return jsonify({'success': False, 'message': error or 'Failed to create alert'}), 400


@app.route('/define-community', methods=['GET', 'POST'])
@login_required
def define_community():
    if request.method == 'POST':
        community_name = request.form.get('community_name', '').strip()
        boundary_data = request.form.get('boundary_data', '')

        community_id, error = create_community(community_name, boundary_data)

        if community_id:
            # Update user with community_id
            user = db.session.get(User, current_user.id)
            user.community_id = community_id
            user.role = 'Admin'
            db.session.commit()

            # Update current_user
            current_user.community_id = community_id
            current_user.role = 'Admin'

            # Store user info for welcome screen
            session['new_community_welcome'] = True
            session['user_name'] = user.name or user.email.split('@')[0]
            session['community_name'] = community_name

            flash('Community created successfully! Welcome to your new community.', 'success')
            return redirect(url_for('welcome'))
        else:
            if error:
                flash(error)

    return render_template('define_community.html')


@app.route('/post-alert', methods=['GET', 'POST'])
@login_required
def post_alert():
    if request.method == 'POST':
        category = request.form.get('category')
        description = request.form.get('description')
        latitude = request.form.get('latitude', 0.0)
        longitude = request.form.get('longitude', 0.0)
        duration_minutes = request.form.get('duration_minutes')

        alert_id, error = create_alert(current_user.community_id, current_user.id, category, description, latitude, longitude, duration_minutes=duration_minutes)

        if alert_id:
            flash('Alert posted successfully!')
            return redirect(url_for('dashboard'))
        else:
            if error:
                flash(error)

    return render_template('post_alert.html')


@app.route('/settings')
@login_required
def settings():
    if not current_user.community_id:
        return redirect(url_for('define_community'))

    # Get community info and members
    community = get_community_info(current_user.community_id)
    members = get_community_members(current_user.community_id)
    boundary_data = get_community_boundary_data(current_user.community_id)
    founder_emails = {e.strip().lower() for e in (os.environ.get('FOUNDER_EMAILS','').split(',') if os.environ.get('FOUNDER_EMAILS') else [])}
    has_founder_access = (hasattr(current_user, 'is_founder') and current_user.is_founder()) or (current_user.email and current_user.email.lower() in founder_emails)

    # Effective plan label for display (cumulative)
    try:
        from utils import get_effective_plan_label
        effective_plan = get_effective_plan_label(current_user, community=community)
    except Exception:
        effective_plan = getattr(community, 'subscription_plan', 'Free')

    return render_template('settings.html',
                           community=community,
                           members=members,
                           boundary_data=boundary_data,
                           founder_access=has_founder_access,
                           effective_plan=effective_plan)


def _has_founder_access(user: User) -> bool:
    try:
        founder_emails = {e.strip().lower() for e in (os.environ.get('FOUNDER_EMAILS','').split(',') if os.environ.get('FOUNDER_EMAILS') else [])}
        return (hasattr(user, 'is_founder') and user.is_founder()) or (user.email and user.email.lower() in founder_emails)
    except Exception:
        return False


@app.route('/founder')
@login_required
def founder_console():
    if not _has_founder_access(current_user):
        abort(403)
    codes = InviteCode.query.order_by(InviteCode.created_at.desc()).all()
    created_code = request.args.get('code')
    return render_template('founder.html', codes=codes, created_code=created_code)


@app.route('/founder/invite-codes', methods=['POST'])
@login_required
def founder_create_invite():
    if not _has_founder_access(current_user):
        abort(403)
    try:
        max_uses = int(request.form.get('max_uses', '1'))
        days_valid = int(request.form.get('days_valid', '30'))
    except ValueError:
        flash('Invalid input values', 'error')
        return redirect(url_for('founder_console'))
    expires_at = datetime.now() + timedelta(days=max_uses * 0)  # default no relation; set below
    if days_valid > 0:
        expires_at = datetime.now() + timedelta(days=days_valid)
    # generate plaintext code
    alphabet = string.ascii_uppercase + string.digits
    plaintext = ''.join(secrets.choice(alphabet) for _ in range(16))
    code_hash = hash_code_plaintext(plaintext)
    rec = InviteCode(code_hash=code_hash,
                     purpose='business_creation',
                     max_uses=max_uses,
                     used_count=0,
                     expires_at=expires_at,
                     revoked=False,
                     created_by_user_id=current_user.id)
    db.session.add(rec)
    db.session.commit()
    flash('Invite code created. Copy it now; it will not be shown again.', 'success')
    return redirect(url_for('founder_console', code=plaintext))


@app.route('/founder/invite-codes/<int:code_id>/revoke', methods=['POST'])
@login_required
def founder_revoke_invite(code_id: int):
    if not _has_founder_access(current_user):
        abort(403)
    rec = db.session.get(InviteCode, code_id)
    if not rec:
        flash('Invite code not found', 'error')
        return redirect(url_for('founder_console'))
    rec.revoked = True
    db.session.commit()
    flash('Invite code revoked', 'success')
    return redirect(url_for('founder_console'))


@app.route('/settings/create-business', methods=['POST'])
@login_required
def settings_create_business():
    name = request.form.get('business_name', '').strip()
    provided_invite = (request.form.get('invite_code') or '').strip()
    if not name:
        flash('Business name is required', 'error')
        return redirect(url_for('settings'))
    if getattr(current_user, 'business_id', None):
        flash('You already belong to a business', 'info')
        return redirect(url_for('settings'))
    # Gate: self-serve flag or invite code env or DB invite
    allow_self_serve = os.environ.get('ALLOW_SELF_SERVE_BUSINESS_REG', 'false').lower() in ('1','true','yes')
    env_secret = os.environ.get('BUSINESS_SIGNUP_SECRET', '')
    invite_ok = False
    error_msg = None
    if allow_self_serve:
        invite_ok = True
    elif env_secret and provided_invite and provided_invite == env_secret:
        invite_ok = True
    else:
        # Try DB invite codes
        invite = InviteCode.query.filter_by(purpose='business_creation').order_by(InviteCode.id.desc()).first() if provided_invite else None
        valid, msg = is_invite_valid(invite, provided_invite)
        invite_ok = valid
        error_msg = msg
    if not invite_ok:
        flash(error_msg or 'A valid invite code is required to create a business', 'error')
        return redirect(url_for('settings'))
    try:
        business_id = create_business(name=name)
        # attach user as super admin
        user = db.session.get(User, current_user.id)
        user.business_id = business_id
        user.role = 'SuperAdmin'
        # If DB invite was used, consume it
        if not allow_self_serve and provided_invite and (not env_secret or provided_invite != env_secret):
            invite = InviteCode.query.filter_by(purpose='business_creation').order_by(InviteCode.id.desc()).first()
            if invite:
                invite.used_count = (invite.used_count or 0) + 1
        db.session.commit()
        flash('Business created and Super Admin access granted', 'success')
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Create business failed: {e}')
        flash('Failed to create business. Please try again.', 'error')
    return redirect(url_for('settings'))


@app.route('/settings/attach-community-to-business', methods=['POST'])
@login_required
def settings_attach_community_to_business():
    # Only allow users who belong to a business and are admin of their community
    if not current_user.business_id:
        flash('You must belong to a business to attach communities', 'error')
        return redirect(url_for('settings'))

    if not (hasattr(current_user, 'is_super_admin') and current_user.is_super_admin()):
        flash('Only Super Admins can attach communities to businesses', 'error')
        return redirect(url_for('settings'))

    # Only allow attaching the user's own community and must be admin of it
    community_id = current_user.community_id
    if not community_id:
        flash('No community to attach', 'error')
        return redirect(url_for('settings'))
    community = Community.query.get(community_id)
    if not community:
        flash('Community not found', 'error')
        return redirect(url_for('settings'))
    if community.admin_user_id != current_user.id:
        abort(403)
    # Attach
    try:
        community.business_id = current_user.business_id
        db.session.commit()
        flash('Community attached to your business', 'success')
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Attach community failed: {e}')
        flash('Failed to attach community', 'error')
    return redirect(url_for('settings'))


@app.route('/remove-member/<int:member_id>')
@login_required
def remove_member_route(member_id):
    success, message = remove_member(member_id, current_user)
    flash(message)
    return redirect(url_for('settings'))


@app.route('/join/<slug>')
def join_community(slug):
    community = get_community_by_invite_slug(slug)

    if community:
        session['invite_community_id'] = community[0]
        return render_template('landing.html', invite=True)
    else:
        flash('Invalid invite link')
        return redirect(url_for('index'))


@app.route('/report-alert', methods=['POST'])
@login_required
def report_alert_route():
    """Handle alert reporting"""
    try:
        data = request.get_json()
        alert_id = data.get('alert_id')

        success, message = report_alert(alert_id, current_user)

        if success:
            return jsonify({'success': True, 'message': message})
        else:
            return jsonify({'success': False, 'message': message}), 400

    except Exception as e:
        app.logger.error(f'Error processing alert report: {e}')
        return jsonify({
            'success':
            False,
            'message':
            'An error occurred while submitting the report'
        }), 500


@app.route('/edit-alert/<int:alert_id>', methods=['GET', 'POST'])
@login_required
def edit_alert(alert_id):
    """Edit an alert (only by the alert author)"""
    from alerts import get_alert_by_id, update_alert

    alert = get_alert_by_id(alert_id)
    if not alert:
        flash('Alert not found')
        return redirect(url_for('dashboard'))

    # Check if user is the author
    if alert['user_id'] != current_user.id:
        flash('You can only edit your own alerts')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        category = request.form.get('category')
        description = request.form.get('description')
        latitude = request.form.get('latitude', 0.0)
        longitude = request.form.get('longitude', 0.0)
        duration_minutes = request.form.get('duration_minutes')

        success, message = update_alert(alert_id, current_user.id, category, description, latitude, longitude, duration_minutes)

        if success:
            flash('Alert updated successfully!')
            return redirect(url_for('dashboard'))
        else:
            flash(message)

    return render_template('edit_alert.html', alert=alert)


@app.route('/update-community-name', methods=['POST'])
@login_required
def update_community_name_route():
    """Update community name (admin only)"""
    try:
        data = request.get_json()
        new_name = data.get('name', '')

        success, message = update_community_name(new_name,
                                                 current_user.community_id,
                                                 current_user)

        if success:
            app.logger.info(
                f'Community {current_user.community_id} name updated to "{new_name}" by admin {current_user.id}'
            )
            return jsonify({'success': True, 'message': message})
        else:
            return jsonify({
                'success': False,
                'message': message
            }), 400 if 'Admin access required' in message else 400

    except Exception as e:
        app.logger.error(f'Error updating community name: {e}')
        return jsonify({
            'success':
            False,
            'message':
            'An error occurred while updating the community name'
        }), 500


@app.route('/update-community-boundary', methods=['POST'])
@login_required
def update_community_boundary_route():
    """Update community boundary (admin only)"""
    try:
        data = request.get_json()
        boundary_data = data.get('boundary_data', '')

        success, message = update_community_boundary(boundary_data,
                                                     current_user.community_id,
                                                     current_user)

        if success:
            app.logger.info(
                f'Community {current_user.community_id} boundary updated by admin {current_user.id}'
            )
            return jsonify({'success': True, 'message': message})
        else:
            return jsonify({
                'success': False,
                'message': message
            }), 400 if 'Admin access required' in message else 400

    except Exception as e:
        app.logger.error(f'Error updating community boundary: {e}')
        return jsonify({
            'success':
            False,
            'message':
            'An error occurred while updating the community boundary'
        }), 500


@app.route('/privacy-policy')
def privacy_policy():
    return render_template('privacy_policy.html')


@app.route('/terms-of-service')
def terms_of_service():
    return render_template('terms_of_service.html')


@app.route('/welcome')
@login_required
def welcome():
    user_name = session.pop('user_name', '')
    return render_template('welcome.html', user_name=user_name)


@app.route('/hide_location_prompt', methods=['POST'])
@login_required
def hide_location_prompt():
    session.pop('ask_location', None)
    return jsonify({'success': True})


@app.route('/pricing')
@login_required
def pricing():
    if not current_user.community_id:
        return redirect(url_for('define_community'))
    return render_template('pricing.html')


# --- Plus: Alert History ---
@app.route('/alerts/history')
@login_required
def alert_history():
    # Premium-gated
    from utils import check_premium_feature_access, format_time_ago
    community = get_community_info(current_user.community_id) if current_user.community_id else None
    access, msg = check_premium_feature_access(current_user, 'Alert History', community=community)
    if not access:
        flash(msg or 'Please upgrade to access alert history')
        return redirect(url_for('pricing'))

    # Query params
    from flask import request
    page = request.args.get('page', default=1, type=int)
    per_page = request.args.get('per_page', default=20, type=int)
    q = (request.args.get('q') or '').strip()
    category = (request.args.get('category') or '').strip()
    include_resolved = request.args.get('resolved', default='1') == '1'

    query = Alert.query.filter(Alert.community_id == current_user.community_id)
    if q:
        like = f"%{q}%"
        query = query.filter(Alert.description.ilike(like))
    if category:
        query = query.filter(Alert.category == category)
    if not include_resolved:
        query = query.filter(Alert.is_resolved == False)

    query = query.order_by(Alert.timestamp.desc())
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    alerts = []
    for a in pagination.items:
        user = db.session.get(User, a.user_id)
        alerts.append({
            'id': a.id,
            'category': a.category,
            'description': a.description,
            'timestamp': a.timestamp,
            'time_ago': format_time_ago(a.timestamp),
            'is_resolved': a.is_resolved,
            'is_verified': getattr(a, 'is_verified', False),
            'author_name': (user.name if user and user.name else (user.email.split('@')[0] if user else 'Unknown'))
        })

    categories = ['Emergency','Fire','Traffic','Weather','Community','Other']
    return render_template('alert_history.html',
                           alerts=alerts,
                           page=page,
                           per_page=per_page,
                           pages=pagination.pages,
                           total=pagination.total,
                           q=q,
                           selected_category=category,
                           include_resolved=include_resolved,
                           categories=categories)


@app.route('/upgrade/plus', methods=['POST'])
@login_required
def upgrade_plus():
    if not current_user.community_id:
        abort(403)
    community = db.session.get(Community, current_user.community_id)
    if not community:
        abort(404)
    try:
        community.subscription_plan = 'Premium'
        # Also grant user premium so they keep features across communities
        cu = db.session.get(User, current_user.id)
        if cu:
            cu.subscription_tier = 'Premium'
        db.session.commit()
        flash('Your community has been upgraded to iZwi Plus!', 'success')
    except Exception:
        db.session.rollback()
        flash('Upgrade failed. Please try again.', 'error')
    return redirect(url_for('settings'))


# --- Member role management (Admin -> Moderator) ---
@app.route('/members/<int:user_id>/promote', methods=['POST'])
@login_required
def promote_member(user_id: int):
    # Only Admin of the community can promote
    if not current_user.community_id:
        abort(403)
    if not getattr(current_user, 'is_admin', lambda: False)():
        abort(403)
    target = db.session.get(User, user_id)
    if not target or target.community_id != current_user.community_id:
        abort(404)
    if target.role == 'Admin':
        abort(400)
    target.role = 'Moderator'
    db.session.commit()
    flash('Member promoted to Moderator', 'success')
    return redirect(url_for('settings'))


@app.route('/members/<int:user_id>/demote', methods=['POST'])
@login_required
def demote_member(user_id: int):
    if not current_user.community_id:
        abort(403)
    if not getattr(current_user, 'is_admin', lambda: False)():
        abort(403)
    target = db.session.get(User, user_id)
    if not target or target.community_id != current_user.community_id:
        abort(404)
    if target.role not in ['Moderator']:
        abort(400)
    target.role = 'Member'
    db.session.commit()
    flash('Moderator demoted to Member', 'success')
    return redirect(url_for('settings'))


# --- Alert deletion by Admin and Moderator ---
@app.route('/admin/cleanup-expired-alerts', methods=['POST'])
def cleanup_expired_alerts():
    """Clean up expired alerts (can be called by cron job)"""
    try:
        from datetime import datetime
        from models import Alert, AlertReport

        now = datetime.now()
        expired_alerts = Alert.query.filter(
            not_(Alert.expires_at == None),
            Alert.expires_at < now
        ).all()

        deleted_count = 0
        for alert in expired_alerts:
            # Delete associated reports first
            AlertReport.query.filter_by(alert_id=alert.id).delete()
            # Delete the alert
            db.session.delete(alert)
            deleted_count += 1

        db.session.commit()

        app.logger.info(f'Expired alerts cleanup: {deleted_count} alerts removed')
        return jsonify({
            'success': True,
            'deleted_count': deleted_count,
            'message': f'Successfully removed {deleted_count} expired alerts'
        })

    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Error during expired alerts cleanup: {e}')
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/alerts/<int:alert_id>', methods=['DELETE'])
@login_required
def delete_alert(alert_id: int):
    alert = db.session.get(Alert, alert_id)
    if not alert:
        return jsonify({'error': 'Not found'}), 404
    # Must belong to same community; Admins can delete any; Moderators can delete if author is Member
    if alert.community_id != current_user.community_id:
        return jsonify({'error': 'Forbidden'}), 403
    author = db.session.get(User, alert.user_id)
    can_delete = False
    if getattr(current_user, 'is_admin', lambda: False)():
        can_delete = True
    elif getattr(current_user, 'is_moderator', lambda: False)():
        can_delete = (author and author.role not in ['Admin', 'Moderator'])
    elif alert.user_id == current_user.id:
        # Users can delete their own alerts
        can_delete = True
    if not can_delete:
        return jsonify({'error': 'Forbidden'}), 403
    try:
        # Also delete associated reports
        AlertReport.query.filter_by(alert_id=alert_id).delete()
        db.session.delete(alert)
        db.session.commit()
        return jsonify({'success': True})
    except Exception:
        db.session.rollback()
        return jsonify({'success': False}), 500


# Error handlers
@app.errorhandler(400)
def bad_request(error):
    return render_template('errors/400.html'), 400


@app.errorhandler(403)
def forbidden(error):
    return render_template('errors/403.html'), 403


@app.errorhandler(404)
def not_found(error):
    return render_template('errors/404.html'), 404


@app.errorhandler(429)
def rate_limit_exceeded(error):
    return render_template('errors/429.html'), 429


@app.errorhandler(500)
def internal_error(error):
    app.logger.error(f'Unhandled Exception: {error}', exc_info=True)
    return render_template('errors/500.html'), 500


if __name__ == '__main__':
    debug_mode = os.environ.get('FLASK_DEBUG',
                                'False').lower() in ('true', '1', 'yes')
    port = int(os.environ.get('PORT', 5001))
    app.logger.info(f" * Running on http://127.0.0.1:{port} (Press CTRL+C to quit)")
    app.run(host='0.0.0.0', port=port, debug=debug_mode)