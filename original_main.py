import os
from datetime import timedelta
from flask import render_template, request, redirect, url_for, flash, session, jsonify
from flask_login import login_user, logout_user, login_required, current_user

# Import our modular components
from config import create_app, init_login_manager, init_csrf
from database import init_db
from auth import load_user, check_session_activity, authenticate_user, create_user
from community import (
    create_community, get_community_by_invite_slug, get_community_info, 
    get_community_members, get_community_boundary_data, remove_member,
    update_community_name, update_community_boundary
)
from alerts import get_community_alerts, create_alert, report_alert
from utils import get_category_color, get_category_icon, format_time_ago

# Create Flask application
app = create_app()

# Initialize extensions
login_manager = init_login_manager(app)
csrf = init_csrf(app)

# Set up user loader for Flask-Login
login_manager.user_loader(load_user)

# Set up session activity check
app.before_request(check_session_activity)

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
            invite = {
                'community_name': community[1],
                'slug': invite_slug
            }
    
    return render_template('landing.html', invite=invite)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        
        user, error = authenticate_user(email, password)
        
        if user:
            # Handle "Remember me" functionality
            remember = request.form.get('remember') == 'on'
            remember_duration = timedelta(days=7) if os.environ.get('FLASK_ENV') == 'production' else timedelta(days=3)
            login_user(user, remember=remember, duration=remember_duration if remember else None)
            
            # Make session permanent if remember me is checked
            if remember:
                session.permanent = True
            
            # Add success message for login
            flash('Welcome back! You have been successfully logged in.', 'success')
            
            # Redirect based on whether user has a community
            if user.community_id:
                return redirect(url_for('dashboard'))
            else:
                return redirect(url_for('define_community'))
        else:
            if error:
                flash(error)
    
    return render_template('login.html')

@app.route('/signup', methods=['POST'])
def signup_submit():
    email = request.form.get('email', '').strip()
    password = request.form.get('password', '')
    consent = request.form.get('consent')
    
    # Check consent
    if not consent:
        flash('You must agree to the Terms of Service and Privacy Policy to sign up')
        return redirect(url_for('signup_page'))
    
    # Get community ID from invite session
    community_id = session.get('invite_community_id')
    
    user, error = create_user(email, password, community_id)
    
    if user:
        # Log in the new user
        login_user(user)
        
        # Clear invite session
        session.pop('invite_community_id', None)
        
        # Redirect based on whether they joined via invite
        if community_id:
            # Store user info for welcome screen
            session['new_user_welcome'] = True
            session['user_name'] = email.split('@')[0].title()
            return redirect(url_for('welcome'))
        else:
            flash('Welcome! Your account has been created. Let\'s set up your community.', 'success')
            return redirect(url_for('define_community'))
    else:
        if error:
            flash(error)
        return redirect(url_for('signup_page'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/privacy')
def privacy_policy():
    return render_template('privacy_policy.html')

@app.route('/terms')
def terms_of_service():
    return render_template('terms_of_service.html')

@app.route('/define-community', methods=['GET', 'POST'])
@login_required
def define_community():
    if request.method == 'POST':
        community_name = request.form.get('community_name', '').strip()
        boundary_data = request.form.get('boundary_data', '')
        
        community_id, error = create_community(community_name, boundary_data)
        
        if community_id:
            # Update current user object and refresh the session
            current_user.community_id = community_id
            current_user.role = 'Admin'
            
            # Refresh the user session to ensure updated data persists
            session['_user_id'] = str(current_user.id)
            session.permanent = True
            
            flash(f'Congratulations! Your community "{community_name}" has been created successfully.', 'success')
            return redirect(url_for('dashboard'))
        else:
            if error:
                flash(error)
    
    return render_template('define_community.html')

@app.route('/welcome')
@login_required
def welcome():
    # Check if this is a new user welcome
    if not session.get('new_user_welcome'):
        return redirect(url_for('dashboard'))
    
    user_name = session.get('user_name', 'there')
    
    # Clear the welcome session flag
    session.pop('new_user_welcome', None)
    session.pop('user_name', None)
    
    return render_template('welcome.html', user_name=user_name)

@app.route('/dashboard')
@login_required
def dashboard():
    # Refresh user data from database to ensure we have the latest community_id
    from database import get_db
    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT community_id, role FROM users WHERE id = ?', (current_user.id,))
    user_data = cursor.fetchone()
    
    if user_data and user_data[0]:
        # Update current user object with fresh data from database
        current_user.community_id = user_data[0]
        current_user.role = user_data[1]
    
    if not current_user.community_id:
        return redirect(url_for('define_community'))
    
    # Get community alerts
    alerts = get_community_alerts(current_user.community_id)
    
    # Get community boundary data
    boundary_data = get_community_boundary_data(current_user.community_id)
    
    return render_template('dashboard.html', 
                         alerts=alerts, 
                         boundary_data=boundary_data,
                         get_category_color=get_category_color, 
                         get_category_icon=get_category_icon,
                         format_time_ago=format_time_ago)

@app.route('/post-alert', methods=['GET', 'POST'])
@login_required
def post_alert():
    if not current_user.community_id:
        return redirect(url_for('define_community'))
    
    if request.method == 'POST':
        category = request.form.get('category', '')
        description = request.form.get('description', '')
        latitude = request.form.get('latitude', '0')
        longitude = request.form.get('longitude', '0')
        
        # Convert coordinates to float
        try:
            lat_float = float(latitude) if latitude else 0
            lng_float = float(longitude) if longitude else 0
        except (ValueError, TypeError):
            lat_float = 0
            lng_float = 0
        
        alert_id, error = create_alert(
            current_user.community_id, 
            current_user.id, 
            category, 
            description, 
            lat_float, 
            lng_float
        )
        
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
    
    return render_template('settings.html', community=community, members=members)

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
        return jsonify({'success': False, 'message': 'An error occurred while submitting the report'}), 500

@app.route('/update-community-name', methods=['POST'])
@login_required
def update_community_name_route():
    """Update community name (admin only)"""
    try:
        data = request.get_json()
        new_name = data.get('name', '')
        
        success, message = update_community_name(new_name, current_user.community_id, current_user)
        
        if success:
            app.logger.info(f'Community {current_user.community_id} name updated to "{new_name}" by admin {current_user.id}')
            return jsonify({'success': True, 'message': message})
        else:
            return jsonify({'success': False, 'message': message}), 400 if 'Admin access required' in message else 400
    
    except Exception as e:
        app.logger.error(f'Error updating community name: {e}')
        return jsonify({'success': False, 'message': 'An error occurred while updating the community name'}), 500

@app.route('/update-community-boundary', methods=['POST'])
@login_required
def update_community_boundary_route():
    """Update community boundary (admin only)"""
    try:
        data = request.get_json()
        boundary_data = data.get('boundary_data', '')
        
        success, message = update_community_boundary(boundary_data, current_user.community_id, current_user)
        
        if success:
            app.logger.info(f'Community {current_user.community_id} boundary updated by admin {current_user.id}')
            return jsonify({'success': True, 'message': message})
        else:
            return jsonify({'success': False, 'message': message}), 400 if 'Admin access required' in message else 400
    
    except Exception as e:
        app.logger.error(f'Error updating community boundary: {e}')
        return jsonify({'success': False, 'message': 'An error occurred while updating the community boundary'}), 500

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
    init_db()
    debug_mode = os.environ.get('FLASK_DEBUG', 'False').lower() in ('true', '1', 'yes')
    app.run(host='0.0.0.0', port=5000, debug=debug_mode)