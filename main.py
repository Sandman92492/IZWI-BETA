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
from werkzeug.security import generate_password_hash
from models import User, InviteCode, Alert, AlertReport
from sqlalchemy import not_

# Import our modular components
from auth import authenticate_user, create_user
from community import (create_community, create_community_for_business,
                       get_community_by_invite_slug, get_community_info,
                       get_community_members, get_community_boundary_data,
                       remove_member, update_community_name,
                       update_community_boundary, create_business,
                       attach_community_to_business, get_unattached_communities,
                       get_community_member_count, get_community_admin_info)
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

            # Redirect based on role and community membership
            if hasattr(user, 'is_super_admin') and user.is_super_admin():
                return redirect(url_for('super_admin_dashboard'))
            elif user.get_communities():
                return redirect(url_for('select_community'))
            else:
                return redirect(url_for('define_community'))
        else:
            if error:
                app.logger.warning(f"Login failed for {email}: {error}")
                flash(error)

    return render_template('login.html')


@app.route('/select-community')
@login_required
def select_community():
    # SuperAdmins bypass this
    if current_user.is_super_admin():
        return redirect(url_for('super_admin_dashboard'))

    # Get user's communities
    memberships = current_user.get_active_memberships()
    communities_with_roles = [(m.community, m.role) for m in memberships]

    return render_template('select_community.html', communities=communities_with_roles)


@app.route('/switch-community/<int:community_id>')
@login_required
def switch_community(community_id):
    if not current_user.is_member_of(community_id):
        flash('Access denied', 'error')
        return redirect(url_for('select_community'))

    session['current_community_id'] = community_id
    return redirect(url_for('dashboard'))


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
        community_id=invite.community_id,
        subscription_tier='Premium'  # Guards get premium access
    )

    # Add and commit the guard user first to get a valid ID
    db.session.add(guard_user)
    db.session.commit()

    # Create community membership record for the guard
    try:
        from models import UserCommunityMembership
        membership = UserCommunityMembership(
            user_id=guard_user.id,
            community_id=invite.community_id,
            role='Guard'
        )
        db.session.add(membership)
        db.session.commit()
        app.logger.info(f"Created guard membership for user {guard_user.id} in community {invite.community_id}")

        # Set current community in session
        session['current_community_id'] = invite.community_id
    except Exception as e:
        app.logger.error(f"Failed to create guard membership record: {e}")

    # Now mark invitation as used with valid user ID
    invite.used = True
    invite.used_by_user_id = guard_user.id
    invite.used_at = datetime.now()
    db.session.commit()

    # Auto-login the new guard
    login_user(guard_user)

    flash('Welcome! You have been successfully registered as a guard.', 'success')
    return redirect(url_for('dashboard'))


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

        # Create community membership record if user joined via invite
        if community_id:
            from models import UserCommunityMembership, Community
            try:
                community = Community.query.get(community_id)
                if community:
                    membership = UserCommunityMembership(
                        user_id=user.id,
                        community_id=community_id,
                        role=user.role  # Use the role that was set in create_user
                    )
                    db.session.add(membership)
                    db.session.commit()
                    app.logger.info(f"Created membership for user {user.id} in community {community_id}")

                    # Set current community in session
                    session['current_community_id'] = community_id
            except Exception as e:
                app.logger.error(f"Failed to create membership record: {e}")

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
            return redirect(url_for('dashboard'))  # Go to dashboard since they have a community
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
    # SuperAdmins bypass this
    if current_user.is_super_admin():
        return redirect(url_for('super_admin_dashboard'))

    # Get current community from session
    current_community_id = session.get('current_community_id')

    # Validate user is member of the community
    if not current_community_id or not current_user.is_member_of(current_community_id):
        return redirect(url_for('select_community'))

    # Get community alerts
    alerts = get_community_alerts(current_community_id)
    app.logger.info(f"Dashboard: Found {len(alerts)} alerts for community {current_community_id}")
    community = get_community_info(current_community_id)
    # Normalize boundary JSON so the frontend always receives a clean JSON object/feature
    raw_boundary = get_community_boundary_data(current_community_id)
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
    members = get_community_members(current_community_id)
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


@app.route('/super-admin/community-info')
@login_required
def super_admin_community_info():
    """Get community information for UI updates"""
    if not (hasattr(current_user, 'is_super_admin') and current_user.is_super_admin()):
        return jsonify({'error': 'Forbidden'}), 403

    community_id = request.args.get('community_id', type=int)
    if not community_id:
        return jsonify({'error': 'community_id required'}), 400

    community = Community.query.get(community_id)
    if not community or community.business_id != current_user.business_id:
        return jsonify({'error': 'Forbidden'}), 403

    return jsonify({
        'success': True,
        'community': {
            'id': community.id,
            'name': community.name
        }
    })


@app.route('/super-admin/validate-community-alerts')
@login_required
def super_admin_validate_community_alerts():
    """Validate that all alerts belong to the correct community (debugging endpoint)"""
    if not (hasattr(current_user, 'is_super_admin') and current_user.is_super_admin()):
        return jsonify({'error': 'Forbidden'}), 403

    # Get all communities for this business
    communities = get_business_communities(current_user.business_id)
    validation_results = {}

    for community in communities:
        # Check if alerts exist for this community that belong to other communities
        alerts_in_wrong_community = Alert.query.filter(
            Alert.community_id == community.id,
            ~Alert.community_id.in_([c.id for c in communities])
        ).count()

        # Check if there are alerts in other communities that should be in this one
        # (This is harder to detect automatically, but we can flag it)
        total_alerts = Alert.query.filter_by(community_id=community.id).count()

        validation_results[community.name] = {
            'community_id': community.id,
            'total_alerts': total_alerts,
            'alerts_in_wrong_community': alerts_in_wrong_community,
            'business_id': community.business_id
        }

    return jsonify({
        'success': True,
        'validation_results': validation_results,
        'business_id': current_user.business_id
    })


# Guard invitation and management routes
@app.route('/super-admin/invite-guard', methods=['POST'])
@login_required
def super_admin_invite_guard():
    """Generate a unique guard invitation link"""
    if not (hasattr(current_user, 'is_super_admin') and current_user.is_super_admin()):
        return jsonify({'error': 'Forbidden'}), 403

    # Get community_id from request
    data = request.get_json() if request.is_json else request.form
    community_id = data.get('community_id')

    if not community_id:
        return jsonify({'error': 'community_id is required'}), 400

    # Validate that the community belongs to the current user's business
    from models import Community
    community = Community.query.get(community_id)
    if not community or community.business_id != current_user.business_id:
        return jsonify({'error': 'Invalid community or access denied'}), 403

    invite_token = secrets.token_urlsafe(32)
    expires_at = datetime.now() + timedelta(days=7)  # Invites expire in 7 days

    invite = GuardInvite(
        invite_token=invite_token,
        business_id=current_user.business_id,
        community_id=community_id,
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
    """Get all guards for a specific community"""
    if not (hasattr(current_user, 'is_super_admin') and current_user.is_super_admin()):
        return jsonify({'error': 'Forbidden'}), 403

    community_id = request.args.get('community_id', type=int)
    if not community_id:
        return jsonify({'error': 'community_id required'}), 400

    # Validate that the community belongs to the current user's business
    from models import Community
    community = Community.query.get(community_id)
    if not community or community.business_id != current_user.business_id:
        return jsonify({'error': 'Forbidden'}), 403

    guards = User.query.filter_by(
        role='Guard',
        business_id=current_user.business_id,
        community_id=community_id
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
    """Get all on-duty guard locations for a specific community"""
    if not (hasattr(current_user, 'is_super_admin') and current_user.is_super_admin()):
        return jsonify({'error': 'Forbidden'}), 403

    community_id = request.args.get('community_id', type=int)
    if not community_id:
        return jsonify({'error': 'community_id required'}), 400

    # Validate that the community belongs to the current user's business
    from models import Community
    community = Community.query.get(community_id)
    if not community or community.business_id != current_user.business_id:
        return jsonify({'error': 'Forbidden'}), 403

    # Get guards who are currently on duty for this community
    on_duty_guards = User.query.filter_by(
        role='Guard',
        business_id=current_user.business_id,
        community_id=community_id,
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


# SuperAdmin Member Management Routes
@app.route('/super-admin/members')
@login_required
def super_admin_members():
    """Get all members for a specific community"""
    if not (hasattr(current_user, 'is_super_admin') and current_user.is_super_admin()):
        return jsonify({'error': 'Forbidden'}), 403

    community_id = request.args.get('community_id', type=int)
    if not community_id:
        return jsonify({'error': 'community_id required'}), 400

    # Validate that the community belongs to the current user's business
    from models import Community
    community = Community.query.get(community_id)
    if not community or community.business_id != current_user.business_id:
        return jsonify({'error': 'Forbidden'}), 403

    members = User.query.filter_by(community_id=community_id).all()
    member_data = []
    for member in members:
        member_data.append({
            'id': member.id,
            'name': member.name,
            'email': member.email,
            'role': member.role,
            'avatar_url': member.avatar_url
        })

    return jsonify({'members': member_data})


@app.route('/super-admin/members/<int:user_id>/promote', methods=['POST'])
@login_required
def super_admin_promote_member(user_id: int):
    """Promote a member (Member → Moderator → Admin)"""
    if not (hasattr(current_user, 'is_super_admin') and current_user.is_super_admin()):
        return jsonify({'error': 'Forbidden'}), 403

    target = db.session.get(User, user_id)
    if not target:
        return jsonify({'error': 'User not found'}), 404

    # Validate that the target belongs to a community in the SuperAdmin's business
    if not target.community_id:
        return jsonify({'error': 'User is not in any community'}), 400

    community = Community.query.get(target.community_id)
    if not community or community.business_id != current_user.business_id:
        return jsonify({'error': 'Forbidden'}), 403

    # Promote: Member → Moderator → Admin
    if target.role == 'Member':
        target.role = 'Moderator'
        message = 'Member promoted to Moderator'
    elif target.role == 'Moderator':
        target.role = 'Admin'
        # Update community admin_user_id if this becomes the new admin
        community.admin_user_id = target.id
        message = 'Moderator promoted to Admin'
    else:
        return jsonify({'error': 'Cannot promote this user further'}), 400

    db.session.commit()
    app.logger.info(f"SuperAdmin {current_user.id} promoted user {user_id} to {target.role}")

    return jsonify({'success': True, 'new_role': target.role, 'message': message})


@app.route('/super-admin/members/<int:user_id>/demote', methods=['POST'])
@login_required
def super_admin_demote_member(user_id: int):
    """Demote a member (Admin → Moderator → Member)"""
    if not (hasattr(current_user, 'is_super_admin') and current_user.is_super_admin()):
        return jsonify({'error': 'Forbidden'}), 403

    target = db.session.get(User, user_id)
    if not target:
        return jsonify({'error': 'User not found'}), 404

    # Validate that the target belongs to a community in the SuperAdmin's business
    if not target.community_id:
        return jsonify({'error': 'User is not in any community'}), 400

    community = Community.query.get(target.community_id)
    if not community or community.business_id != current_user.business_id:
        return jsonify({'error': 'Forbidden'}), 403

    # Prevent demoting the only admin (would leave community without admin)
    admin_count = User.query.filter_by(community_id=target.community_id, role='Admin').count()
    if target.role == 'Admin' and admin_count <= 1:
        return jsonify({'error': 'Cannot demote the only admin of this community'}), 400

    # Demote: Admin → Moderator → Member
    if target.role == 'Admin':
        target.role = 'Moderator'
        # If this was the admin, update community admin_user_id to another admin if available
        if community.admin_user_id == target.id:
            other_admin = User.query.filter_by(community_id=target.community_id, role='Admin').first()
            if other_admin:
                community.admin_user_id = other_admin.id
        message = 'Admin demoted to Moderator'
    elif target.role == 'Moderator':
        target.role = 'Member'
        message = 'Moderator demoted to Member'
    else:
        return jsonify({'error': 'Cannot demote this user further'}), 400

    db.session.commit()
    app.logger.info(f"SuperAdmin {current_user.id} demoted user {user_id} to {target.role}")

    return jsonify({'success': True, 'new_role': target.role, 'message': message})


@app.route('/super-admin/members/<int:user_id>/remove', methods=['POST'])
@login_required
def super_admin_remove_member(user_id: int):
    """Remove a member from their community"""
    if not (hasattr(current_user, 'is_super_admin') and current_user.is_super_admin()):
        return jsonify({'error': 'Forbidden'}), 403

    target = db.session.get(User, user_id)
    if not target:
        return jsonify({'error': 'User not found'}), 404

    # Validate that the target belongs to a community in the SuperAdmin's business
    if not target.community_id:
        return jsonify({'error': 'User is not in any community'}), 400

    community = Community.query.get(target.community_id)
    if not community or community.business_id != current_user.business_id:
        return jsonify({'error': 'Forbidden'}), 403

    # Prevent removing the only admin (would leave community without admin)
    if target.role == 'Admin':
        admin_count = User.query.filter_by(community_id=target.community_id, role='Admin').count()
        if admin_count <= 1:
            return jsonify({'error': 'Cannot remove the only admin of this community'}), 400

    # Remove member from community
    target.community_id = None

    # If this was the admin, update community admin_user_id
    if community.admin_user_id == target.id:
        other_admin = User.query.filter_by(community_id=target.community_id, role='Admin').first()
        if other_admin:
            community.admin_user_id = other_admin.id

    db.session.commit()
    app.logger.info(f"SuperAdmin {current_user.id} removed user {user_id} from community {target.community_id}")

    return jsonify({'success': True, 'message': 'Member removed from community'})


@app.route('/super-admin/members/<int:user_id>/set-role', methods=['POST'])
@login_required
def super_admin_set_member_role(user_id: int):
    """Directly set a member's role"""
    if not (hasattr(current_user, 'is_super_admin') and current_user.is_super_admin()):
        return jsonify({'error': 'Forbidden'}), 403

    target = db.session.get(User, user_id)
    if not target:
        return jsonify({'error': 'User not found'}), 404

    # Validate that the target belongs to a community in the SuperAdmin's business
    if not target.community_id:
        return jsonify({'error': 'User is not in any community'}), 400

    community = Community.query.get(target.community_id)
    if not community or community.business_id != current_user.business_id:
        return jsonify({'error': 'Forbidden'}), 403

    new_role = request.json.get('role')
    if not new_role or new_role not in ['Member', 'Moderator', 'Admin']:
        return jsonify({'error': 'Invalid role specified'}), 400

    # Prevent setting the only admin role to something else
    if target.role == 'Admin' and new_role != 'Admin':
        admin_count = User.query.filter_by(community_id=target.community_id, role='Admin').count()
        if admin_count <= 1:
            return jsonify({'error': 'Cannot change the only admin of this community'}), 400

    old_role = target.role
    target.role = new_role

    # Update community admin_user_id if this becomes/removes admin
    if new_role == 'Admin' and old_role != 'Admin':
        community.admin_user_id = target.id
    elif old_role == 'Admin' and new_role != 'Admin':
        other_admin = User.query.filter_by(community_id=target.community_id, role='Admin').first()
        if other_admin:
            community.admin_user_id = other_admin.id

    db.session.commit()
    app.logger.info(f"SuperAdmin {current_user.id} changed user {user_id} role from {old_role} to {new_role}")

    return jsonify({'success': True, 'new_role': new_role, 'message': f'Role changed to {new_role}'})


@app.route('/admin/set-member-role/<int:member_id>', methods=['POST'])
@login_required
def admin_set_member_role(member_id: int):
    """Set a member's role (regular admin only)"""
    # Only current Admin can change roles
    if not current_user.community_id:
        abort(403)
    if not getattr(current_user, 'is_admin', lambda: False)():
        abort(403)

    target = db.session.get(User, member_id)
    if not target or target.community_id != current_user.community_id:
        abort(404)

    new_role = request.form.get('role')
    if not new_role or new_role not in ['Member', 'Moderator', 'Admin']:
        abort(400)

    # Prevent setting the only admin role to something else
    if target.role == 'Admin' and new_role != 'Admin':
        admin_count = User.query.filter_by(community_id=target.community_id, role='Admin').count()
        if admin_count <= 1:
            abort(400)  # Cannot change the only admin

    old_role = target.role
    target.role = new_role

    # Update community admin_user_id if this becomes/removes admin
    if new_role == 'Admin' and old_role != 'Admin':
        community = db.session.get(Community, current_user.community_id)
        if community:
            community.admin_user_id = target.id
    elif old_role == 'Admin' and new_role != 'Admin':
        community = db.session.get(Community, current_user.community_id)
        if community and community.admin_user_id == target.id:
            other_admin = User.query.filter_by(community_id=target.community_id, role='Admin').first()
            if other_admin:
                community.admin_user_id = other_admin.id

    db.session.commit()
    app.logger.info(f"Admin {current_user.id} changed user {member_id} role from {old_role} to {new_role}")

    flash(f'Role changed to {new_role} successfully', 'success')
    return redirect(url_for('settings'))


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

    app.logger.info(f'Super admin {current_user.id} posting alert to community {community_id}')

    community = Community.query.get(community_id)
    if not community or community.business_id != current_user.business_id:
        return jsonify({'error': 'Forbidden'}), 403

    alert_id, error = create_verified_alert(community_id, current_user.id, category, description, latitude, longitude, duration_minutes=duration_minutes)
    if alert_id:
        app.logger.info(f'Alert {alert_id} successfully created in community {community_id}')
        return jsonify({'success': True, 'alert_id': alert_id})
    else:
        app.logger.error(f'Failed to create alert in community {community_id}: {error}')
        return jsonify({'success': False, 'message': error or 'Failed to create alert'}), 400


@app.route('/super-admin/create-community', methods=['GET', 'POST'])
@login_required
def super_admin_create_community():
    # Security: must be super admin and have a business
    if not (hasattr(current_user, 'is_super_admin') and current_user.is_super_admin()):
        abort(403)

    if not current_user.business_id:
        flash('You must belong to a business to create communities', 'error')
        return redirect(url_for('super_admin_dashboard'))

    if request.method == 'POST':
        community_name = request.form.get('community_name', '').strip()
        boundary_data = request.form.get('boundary_data', '')
        admin_user_id = request.form.get('admin_user_id', '').strip()

        # Convert empty string to None for admin_user_id
        if not admin_user_id:
            admin_user_id = None

        # Create community with business_id
        community_id, error = create_community_for_business(
            community_name,
            boundary_data,
            current_user.business_id,
            admin_user_id
        )

        if community_id:
            flash('Community created successfully!', 'success')
            return redirect(url_for('super_admin_dashboard'))
        else:
            flash(error or 'Failed to create community', 'error')

    return render_template('super_admin_create_community.html')


@app.route('/super-admin/attach-community', methods=['GET', 'POST'])
@login_required
def super_admin_attach_community():
    # Security: must be super admin and have a business
    if not (hasattr(current_user, 'is_super_admin') and current_user.is_super_admin()):
        abort(403)

    if not current_user.business_id:
        flash('You must belong to a business to attach communities', 'error')
        return redirect(url_for('super_admin_dashboard'))

    if request.method == 'POST':
        community_id = request.form.get('community_id', type=int)

        if not community_id:
            flash('Community ID is required', 'error')
            return redirect(url_for('super_admin_attach_community'))

        success, message = attach_community_to_business(community_id, current_user.business_id)

        if success:
            flash(message, 'success')
        else:
            flash(message, 'error')

        return redirect(url_for('super_admin_dashboard'))

    # GET request - show unattached communities
    unattached_communities = get_unattached_communities()
    return render_template('super_admin_attach_community.html', communities=unattached_communities)


@app.route('/super-admin/unattached-communities')
@login_required
def super_admin_unattached_communities():
    # Security: must be super admin
    if not (hasattr(current_user, 'is_super_admin') and current_user.is_super_admin()):
        return jsonify({'error': 'Forbidden'}), 403

    communities = get_unattached_communities()
    return jsonify([
        {
            'id': c.id,
            'name': c.name,
            'admin_name': get_community_admin_info(c.id).name if get_community_admin_info(c.id) else 'No admin',
            'member_count': get_community_member_count(c.id),
            'created_at': c.created_at.strftime('%Y-%m-%d') if c.created_at else 'Unknown'
        } for c in communities
    ])


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


@app.route('/members/<int:user_id>/make-admin', methods=['POST'])
@login_required
def transfer_admin(user_id: int):
    # Only current Admin can transfer
    if not current_user.community_id:
        abort(403)
    if not getattr(current_user, 'is_admin', lambda: False)():
        abort(403)

    target = db.session.get(User, user_id)
    if not target or target.community_id != current_user.community_id:
        abort(404)
    if target.id == current_user.id:
        abort(400)  # Can't transfer to self

    # Transfer: new user becomes Admin, old admin becomes Moderator
    target.role = 'Admin'
    current_user.role = 'Moderator'

    # Update community admin_user_id
    community = db.session.get(Community, current_user.community_id)
    if community:
        community.admin_user_id = target.id

    db.session.commit()
    flash('Admin role transferred successfully', 'success')
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

@app.route('/api/alerts/filter')
@login_required
def filter_alerts():
    """Filter alerts based on provided criteria"""
    try:
        # Get filter parameters
        category = request.args.get('category', '').strip()
        status = request.args.get('status', '').strip()
        verification = request.args.get('verification', '').strip()
        date_range = request.args.get('date_range', '').strip()
        search = request.args.get('search', '').strip()

        if not current_user.community_id:
            return jsonify({'error': 'No community found'}), 400

        # Build query
        query = Alert.query.join(User, Alert.user_id == User.id).filter(Alert.community_id == current_user.community_id)

        # Apply filters
        if category:
            query = query.filter(Alert.category == category)

        if status == 'active':
            query = query.filter(Alert.is_resolved == False)
        elif status == 'resolved':
            query = query.filter(Alert.is_resolved == True)

        if verification == 'verified':
            query = query.filter(Alert.is_verified == True)
        elif verification == 'unverified':
            query = query.filter(Alert.is_verified == False)

        if date_range == 'today':
            from datetime import datetime, date
            today = date.today()
            query = query.filter(db.func.date(Alert.timestamp) == today)
        elif date_range == 'week':
            from datetime import datetime, timedelta
            week_ago = datetime.now() - timedelta(days=7)
            query = query.filter(Alert.timestamp >= week_ago)
        elif date_range == 'month':
            from datetime import datetime, timedelta
            month_ago = datetime.now() - timedelta(days=30)
            query = query.filter(Alert.timestamp >= month_ago)

        if search:
            like_pattern = f"%{search}%"
            query = query.filter(Alert.description.ilike(like_pattern))

        # Filter out expired alerts
        from datetime import datetime
        from sqlalchemy import or_
        now = datetime.now()
        query = query.filter(
            or_(
                Alert.expires_at.is_(None),  # No expiration set
                Alert.expires_at > now       # Not yet expired
            )
        )

        # Order by timestamp descending
        alerts = query.order_by(Alert.timestamp.desc()).all()

        # Convert to expected format
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

        return jsonify({
            'success': True,
            'alerts': alert_data,
            'count': len(alert_data)
        })

    except Exception as e:
        app.logger.error(f'Error filtering alerts: {e}')
        return jsonify({'error': 'Failed to filter alerts'}), 500


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

    # Check in this order:
    if alert.user_id == current_user.id:
        # Users can delete their own alerts (includes moderators)
        can_delete = True
    elif getattr(current_user, 'is_admin', lambda: False)():
        can_delete = True
    elif getattr(current_user, 'is_moderator', lambda: False)():
        can_delete = (author and author.role not in ['Admin', 'Moderator'])
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


# Analytics Dashboard Routes - B2B Premium Feature
@app.route('/super-admin/analytics')
@login_required
def super_admin_analytics():
    """Render the analytics dashboard for super admins"""
    if not (hasattr(current_user, 'is_super_admin') and current_user.is_super_admin()):
        return jsonify({'error': 'Forbidden'}), 403

    if not current_user.business_id:
        return jsonify({'error': 'No business associated with this account'}), 403

    # Get business communities for the logged-in super admin
    communities = get_business_communities(current_user.business_id)

    # Get business branding information
    from utils import get_community_branding
    # For super admin, we can get branding from the business directly
    # Since this is a business-level view, we'll use a default branding
    branding = {
        'business_name': 'iZwi Analytics',
        'logo_url': None,
        'primary_color': '#1F2937',
        'is_white_labeled': False
    }

    # Try to get business-specific branding if available
    try:
        business = get_community_business_info(current_user.business_id)
        if business:
            branding = {
                'business_name': business.name,
                'logo_url': business.logo_url,
                'primary_color': business.primary_color,
                'is_white_labeled': True
            }
    except:
        pass  # Use default branding if business lookup fails

    return render_template('super_admin_analytics.html', communities=communities, branding=branding)


@app.route('/super-admin/analytics/data')
@login_required
def analytics_data():
    """Get aggregated analytics data for KPI widgets"""
    if not (hasattr(current_user, 'is_super_admin') and current_user.is_super_admin()):
        return jsonify({'error': 'Forbidden'}), 403

    if not current_user.business_id:
        return jsonify({'error': 'No business associated with this account'}), 403

    # Parse query parameters
    community_ids = request.args.getlist('community_ids[]')
    date_from = request.args.get('date_from')
    date_to = request.args.get('date_to')
    categories = request.args.getlist('categories[]')

    # Validate business access
    if community_ids:
        for community_id in community_ids:
            community = Community.query.get(community_id)
            if not community or community.business_id != current_user.business_id:
                return jsonify({'error': 'Forbidden'}), 403

    # Build base query
    from models import Alert
    query = Alert.query.join(Community, Alert.community_id == Community.id).filter(
        Community.business_id == current_user.business_id
    )

    # Apply filters
    if community_ids:
        query = query.filter(Alert.community_id.in_(community_ids))

    if date_from:
        try:
            from datetime import datetime
            date_from_dt = datetime.fromisoformat(date_from.replace('Z', '+00:00'))
            query = query.filter(Alert.timestamp >= date_from_dt)
        except ValueError:
            pass

    if date_to:
        try:
            from datetime import datetime
            date_to_dt = datetime.fromisoformat(date_to.replace('Z', '+00:00'))
            query = query.filter(Alert.timestamp <= date_to_dt)
        except ValueError:
            pass

    if categories:
        query = query.filter(Alert.category.in_(categories))

    # Filter out expired alerts
    from datetime import datetime
    from sqlalchemy import or_
    now = datetime.now()
    query = query.filter(
        or_(
            Alert.expires_at.is_(None),
            Alert.expires_at > now
        )
    )

    alerts = query.all()

    # Calculate KPIs
    total_alerts = len(alerts)
    new_alerts = len([a for a in alerts if a.status == 'New'])
    resolved_alerts = len([a for a in alerts if a.status == 'Resolved'])

    # Calculate average time to resolution
    resolved_alerts_with_time = [a for a in alerts if a.status in ['Resolved', 'False Alarm'] and a.resolved_at]
    avg_resolution_time = 0
    if resolved_alerts_with_time:
        total_resolution_time = sum(
            (a.resolved_at - a.timestamp).total_seconds() / 3600  # hours
            for a in resolved_alerts_with_time
        )
        avg_resolution_time = total_resolution_time / len(resolved_alerts_with_time)

    # Find busiest day/time
    from collections import defaultdict
    day_hour_counts = defaultdict(int)
    for alert in alerts:
        day_of_week = alert.timestamp.strftime('%A')
        hour = alert.timestamp.hour
        day_hour_counts[f"{day_of_week} {hour}"] += 1

    busiest_day_time = max(day_hour_counts.items(), key=lambda x: x[1])[0] if day_hour_counts else 'No data'

    return jsonify({
        'total_alerts': total_alerts,
        'new_alerts': new_alerts,
        'resolved_alerts': resolved_alerts,
        'avg_resolution_time': round(avg_resolution_time, 1),
        'busiest_day_time': busiest_day_time
    })


@app.route('/super-admin/analytics/charts')
@login_required
def analytics_charts():
    """Get data for analytics charts"""
    if not (hasattr(current_user, 'is_super_admin') and current_user.is_super_admin()):
        return jsonify({'error': 'Forbidden'}), 403

    if not current_user.business_id:
        return jsonify({'error': 'No business associated with this account'}), 403

    # Parse query parameters (same as analytics_data)
    community_ids = request.args.getlist('community_ids[]')
    date_from = request.args.get('date_from')
    date_to = request.args.get('date_to')
    categories = request.args.getlist('categories[]')

    # Build base query
    from models import Alert
    query = Alert.query.join(Community, Alert.community_id == Community.id).filter(
        Community.business_id == current_user.business_id
    )

    # Apply same filters as analytics_data
    if community_ids:
        query = query.filter(Alert.community_id.in_(community_ids))

    if date_from:
        try:
            from datetime import datetime
            date_from_dt = datetime.fromisoformat(date_from.replace('Z', '+00:00'))
            query = query.filter(Alert.timestamp >= date_from_dt)
        except ValueError:
            pass

    if date_to:
        try:
            from datetime import datetime
            date_to_dt = datetime.fromisoformat(date_to.replace('Z', '+00:00'))
            query = query.filter(Alert.timestamp <= date_to_dt)
        except ValueError:
            pass

    if categories:
        query = query.filter(Alert.category.in_(categories))

    # Filter out expired alerts
    from datetime import datetime
    from sqlalchemy import or_
    now = datetime.now()
    query = query.filter(
        or_(
            Alert.expires_at.is_(None),
            Alert.expires_at > now
        )
    )

    alerts = query.all()

    # Prepare data for charts
    from collections import defaultdict, Counter

    # Alerts over time (grouped by day)
    time_series = defaultdict(int)
    for alert in alerts:
        day = alert.timestamp.strftime('%Y-%m-%d')
        time_series[day] += 1

    alerts_over_time = [{'date': date, 'count': count} for date, count in sorted(time_series.items())]

    # Alerts by category
    category_counts = Counter(alert.category for alert in alerts)
    alerts_by_category = [{'category': cat, 'count': count} for cat, count in category_counts.most_common()]

    # Alerts by status
    status_counts = Counter(alert.status for alert in alerts)
    alerts_by_status = [
        {'status': status, 'count': count}
        for status, count in status_counts.items()
    ]

    return jsonify({
        'alerts_over_time': alerts_over_time,
        'alerts_by_category': alerts_by_category,
        'alerts_by_status': alerts_by_status
    })


@app.route('/super-admin/analytics/heatmap')
@login_required
def analytics_heatmap():
    """Get heatmap data for alert density visualization"""
    if not (hasattr(current_user, 'is_super_admin') and current_user.is_super_admin()):
        return jsonify({'error': 'Forbidden'}), 403

    if not current_user.business_id:
        return jsonify({'error': 'No business associated with this account'}), 403

    # Parse query parameters (same as analytics_data)
    community_ids = request.args.getlist('community_ids[]')
    date_from = request.args.get('date_from')
    date_to = request.args.get('date_to')
    categories = request.args.getlist('categories[]')

    # Build base query
    from models import Alert
    query = Alert.query.join(Community, Alert.community_id == Community.id).filter(
        Community.business_id == current_user.business_id
    )

    # Apply same filters as analytics_data
    if community_ids:
        query = query.filter(Alert.community_id.in_(community_ids))

    if date_from:
        try:
            from datetime import datetime
            date_from_dt = datetime.fromisoformat(date_from.replace('Z', '+00:00'))
            query = query.filter(Alert.timestamp >= date_from_dt)
        except ValueError:
            pass

    if date_to:
        try:
            from datetime import datetime
            date_to_dt = datetime.fromisoformat(date_to.replace('Z', '+00:00'))
            query = query.filter(Alert.timestamp <= date_to_dt)
        except ValueError:
            pass

    if categories:
        query = query.filter(Alert.category.in_(categories))

    # Filter out expired alerts
    from datetime import datetime
    from sqlalchemy import or_
    now = datetime.now()
    query = query.filter(
        or_(
            Alert.expires_at.is_(None),
            Alert.expires_at > now
        )
    )

    # Only include alerts with valid coordinates
    query = query.filter(
        Alert.latitude != 0,
        Alert.longitude != 0
    )

    alerts = query.all()

    # Convert to heatmap data format [lat, lng, intensity]
    heatmap_data = []
    for alert in alerts:
        # Use intensity based on alert category/severity (you can customize this)
        intensity = 1.0  # Default intensity
        if alert.category.lower() in ['emergency', 'fire']:
            intensity = 2.0
        elif alert.category.lower() in ['crime & security']:
            intensity = 1.5

        heatmap_data.append([
            float(alert.latitude),
            float(alert.longitude),
            intensity
        ])

    return jsonify(heatmap_data)


@app.route('/super-admin/analytics/export-pdf', methods=['POST'])
@login_required
def export_analytics_pdf():
    """Export analytics dashboard as PDF report"""
    if not (hasattr(current_user, 'is_super_admin') and current_user.is_super_admin()):
        return jsonify({'error': 'Forbidden'}), 403

    if not current_user.business_id:
        return jsonify({'error': 'No business associated with this account'}), 403

    try:
        # Parse request data
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400

        filters = data.get('filters', {})
        kpis = data.get('kpis', {})
        charts_data = data.get('charts', {})

        # Get business info for branding
        business = get_community_business_info(current_user.business_id)
        if not business:
            # Create a default business object for branding
            from models import Business
            business = Business(
                name='iZwi Analytics',
                logo_url=None,
                primary_color='#1F2937',
                contact_email=None,
                subscription_tier='Free',
                is_active=True
            )

        # Generate PDF using ReportLab (implemented in utils.py)
        from utils import generate_analytics_pdf
        pdf_bytes = generate_analytics_pdf(
            business_id=current_user.business_id,
            business=business,
            filters=filters,
            kpis=kpis,
            charts_data=charts_data
        )

        # Return PDF as download
        from flask import Response
        return Response(
            pdf_bytes,
            mimetype='application/pdf',
            headers={'Content-Disposition': 'attachment; filename=analytics_report.pdf'}
        )

    except Exception as e:
        app.logger.error(f'PDF export error: {e}')
        return jsonify({'error': 'Failed to generate PDF report'}), 500


@app.route('/super-admin/alerts/<int:alert_id>/update-status', methods=['POST'])
@login_required
def update_alert_status(alert_id):
    """Update alert status (for B2B super admins)"""
    if not (hasattr(current_user, 'is_super_admin') and current_user.is_super_admin()):
        return jsonify({'error': 'Forbidden'}), 403

    try:
        data = request.get_json()
        if not data or 'status' not in data:
            return jsonify({'error': 'Status is required'}), 400

        new_status = data['status']

        # Validate status
        valid_statuses = ['New', 'Investigating', 'Resolved', 'False Alarm']
        if new_status not in valid_statuses:
            return jsonify({'error': f'Invalid status. Must be one of: {", ".join(valid_statuses)}'}), 400

        # Get alert and validate business access
        from models import Alert, Community
        alert = Alert.query.get(alert_id)
        if not alert:
            return jsonify({'error': 'Alert not found'}), 404

        community = Community.query.get(alert.community_id)
        if not community or community.business_id != current_user.business_id:
            return jsonify({'error': 'Forbidden'}), 403

        # Update alert status
        alert.status = new_status

        # Set resolved_at if status is terminal
        if new_status in ['Resolved', 'False Alarm']:
            from datetime import datetime
            alert.resolved_at = datetime.now()
        elif new_status in ['New', 'Investigating']:
            # Clear resolved_at for non-terminal statuses
            alert.resolved_at = None

        from app import db
        db.session.commit()

        return jsonify({'success': True, 'message': f'Alert status updated to {new_status}'})

    except Exception as e:
        app.logger.error(f'Error updating alert status: {e}')
        return jsonify({'error': 'Failed to update alert status'}), 500


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