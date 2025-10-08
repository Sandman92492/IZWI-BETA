import json
from flask import session
from flask_login import current_user
from app import db
from models import Community, User, Business
from utils import sanitize_plain_text, validate_json_data, generate_invite_slug

def create_community(community_name, boundary_data='', business_id=None, admin_user_id=None):
    """Create a new community"""
    # Validate input
    if not community_name:
        return None, 'Community name is required'

    if len(community_name) > 100:
        return None, 'Community name must be less than 100 characters'

    # Sanitize input
    community_name = sanitize_plain_text(community_name.strip())
    boundary_data = validate_json_data(boundary_data)

    # Check if community name already exists within the business scope
    query = Community.query.filter_by(name=community_name)
    if business_id:
        query = query.filter_by(business_id=business_id)

    existing_community = query.first()
    if existing_community:
        return None, 'A community with this name already exists. Please choose a different name.'

    # Generate unique invite slug
    invite_slug = generate_invite_slug()

    # Determine subscription plan based on business association
    subscription_plan = 'Premium' if business_id else 'Free'

    # Validate admin_user_id if provided
    if admin_user_id:
        admin_user = User.query.get(admin_user_id)
        if not admin_user:
            return None, 'Invalid admin user specified'

    # Create community
    community = Community(
        name=community_name,
        admin_user_id=admin_user_id if admin_user_id else current_user.id,
        invite_link_slug=invite_slug,
        subscription_plan=subscription_plan,
        boundary_data=boundary_data,
        business_id=business_id
    )
    
    db.session.add(community)
    db.session.flush()  # Get the ID
    
    from flask import current_app
    current_app.logger.info(f"Community created with ID: {community.id}")
    
    # Update user with community_id and admin role
    user = db.session.get(User, current_user.id)
    if user:
        user.community_id = community.id
        user.role = 'Admin'
        current_app.logger.info(f"Updated user {user.id} with community_id: {community.id}")
        
        # Also update the current_user object immediately
        current_user.community_id = community.id
        current_user.role = 'Admin'
        current_app.logger.info(f"Updated current_user object community_id: {current_user.community_id}")
    
    db.session.commit()
    current_app.logger.info(f"Database committed, returning community ID: {community.id}")
    
    return community.id, None

def get_community_by_invite_slug(invite_slug):
    """Get community by invite slug"""
    community = Community.query.filter_by(invite_link_slug=invite_slug).first()
    if community:
        return (community.id, community.name)
    return None

def get_community_info(community_id):
    """Get community information"""
    community = Community.query.get(community_id)
    return community

def get_community_members(community_id):
    """Get all members of a community"""
    members = User.query.filter_by(community_id=community_id).all()
    return members

def get_community_boundary_data(community_id):
    """Get community boundary data"""
    community = Community.query.get(community_id)
    return community.boundary_data if community else None

def remove_member(member_id, admin_user):
    """Remove a member from the community (admin only)"""
    if not (admin_user.role in ['Admin', 'Business', 'SuperAdmin'] or admin_user.is_business_user()):
        return False, 'You do not have permission to remove members'

    user = User.query.get(member_id)
    if not user:
        return False, 'Member not found'

    # NEW: Validate same community (unless SuperAdmin managing their business communities)
    if admin_user.role == 'SuperAdmin':
        # SuperAdmin can only remove from communities in their business
        member_community = Community.query.get(user.community_id)
        if not member_community or member_community.business_id != admin_user.business_id:
            return False, 'You do not have permission to remove this member'
    elif admin_user.community_id != user.community_id:
        return False, 'You can only remove members from your own community'

    user.community_id = None
    db.session.commit()
    return True, 'Member removed successfully'

def update_community_name(new_name, community_id, admin_user):
    """Update community name (admin or business user only)"""
    if not (admin_user.role in ['Admin', 'Business'] or admin_user.is_business_user()):
        return False, 'Admin access required'
    
    # Sanitize and validate input
    new_name = sanitize_plain_text(new_name.strip())
    
    if not new_name:
        return False, 'Community name is required'
    
    if len(new_name) > 100:
        return False, 'Community name must be less than 100 characters'
    
    # Check if name already exists (excluding current community)
    existing_community = Community.query.filter(
        Community.name == new_name,
        Community.id != community_id
    ).first()
    
    if existing_community:
        return False, 'A community with this name already exists'
    
    # Update community name
    community = Community.query.get(community_id)
    if community:
        community.name = new_name
        db.session.commit()
        return True, 'Community name updated successfully!'
    else:
        return False, 'Community not found'

def update_community_boundary(boundary_data, community_id, admin_user):
    """Update community boundary (admin or business user only)"""
    if not (admin_user.role in ['Admin', 'Business'] or admin_user.is_business_user()):
        return False, 'Admin access required'
    
    # Validate JSON if provided
    if boundary_data:
        try:
            json.loads(boundary_data)  # Validate JSON format
        except json.JSONDecodeError:
            return False, 'Invalid boundary data format'
    
    # Update community boundary
    community = Community.query.get(community_id)
    if community:
        community.boundary_data = boundary_data
        db.session.commit()
        return True, 'Community boundary updated successfully!'
    else:
        return False, 'Community not found'

def get_business_info(business_id):
    """Get business information for white-labeling"""
    if not business_id:
        return None
    
    from models import Business
    business = Business.query.filter_by(id=business_id, is_active=True).first()
    return business

def get_community_business_info(community_id):
    """Get business information associated with a community"""
    business = db.session.query(Business).join(
        Community, Business.id == Community.business_id
    ).filter(
        Community.id == community_id,
        Business.is_active == True
    ).first()
    return business

def get_business_communities(business_id):
    """Get all communities associated with a business"""
    communities = Community.query.filter_by(business_id=business_id).all()
    return communities

def create_business(name, logo_url=None, primary_color='#1F2937', contact_email=None, subscription_tier='Free'):
    """Create a new business for white-labeling"""
    # Sanitize inputs
    name = sanitize_plain_text(name.strip())
    if logo_url:
        logo_url = sanitize_plain_text(logo_url.strip())
    if contact_email:
        contact_email = sanitize_plain_text(contact_email.strip())
    if primary_color:
        primary_color = sanitize_plain_text(primary_color.strip())
    
    business = Business(
        name=name,
        logo_url=logo_url,
        primary_color=primary_color,
        contact_email=contact_email,
        subscription_tier=subscription_tier
    )
    
    db.session.add(business)
    db.session.commit()

    return business.id


def create_community_for_business(community_name, boundary_data='', business_id=None, admin_user_id=None):
    """Create a new community for a business (super admin function)"""
    # Validate input
    if not community_name:
        return None, 'Community name is required'

    if len(community_name) > 100:
        return None, 'Community name must be less than 100 characters'

    # Sanitize input
    community_name = sanitize_plain_text(community_name.strip())
    boundary_data = validate_json_data(boundary_data)

    # Check if community name already exists within the business scope
    query = Community.query.filter_by(name=community_name)
    if business_id:
        query = query.filter_by(business_id=business_id)

    existing_community = query.first()
    if existing_community:
        return None, 'A community with this name already exists in this business. Please choose a different name.'

    # Generate unique invite slug
    invite_slug = generate_invite_slug()

    # Determine subscription plan based on business association
    subscription_plan = 'Premium' if business_id else 'Free'

    # Validate admin_user_id if provided
    if admin_user_id:
        admin_user = User.query.get(admin_user_id)
        if not admin_user:
            return None, 'Invalid admin user specified'

    # Create community
    community = Community(
        name=community_name,
        admin_user_id=admin_user_id if admin_user_id else current_user.id,
        invite_link_slug=invite_slug,
        subscription_plan=subscription_plan,
        boundary_data=boundary_data,
        business_id=business_id
    )

    db.session.add(community)
    db.session.flush()  # Get the ID

    from flask import current_app
    current_app.logger.info(f"Community created for business with ID: {community.id}")

    # Update admin user with community_id and admin role if they don't already have a community
    if admin_user_id:
        admin_user = db.session.get(User, admin_user_id)
        if admin_user and not admin_user.community_id:
            admin_user.community_id = community.id
            admin_user.role = 'Admin'
            current_app.logger.info(f"Updated admin user {admin_user.id} with community_id: {community.id}")

    db.session.commit()
    current_app.logger.info(f"Database committed, returning community ID: {community.id}")

    return community.id, None


def attach_community_to_business(community_id, business_id):
    """Attach an unattached community to a business"""
    community = Community.query.get(community_id)
    if not community:
        return False, 'Community not found'

    if community.business_id is not None:
        return False, 'Community is already attached to a business'

    # Validate that the business exists and is active
    business = Business.query.filter_by(id=business_id, is_active=True).first()
    if not business:
        return False, 'Business not found or inactive'

    # Attach community to business
    community.business_id = business_id
    db.session.commit()

    from flask import current_app
    current_app.logger.info(f"Community {community_id} attached to business {business_id}")

    return True, 'Community attached successfully'


def get_unattached_communities():
    """Get all communities that are not attached to any business"""
    communities = Community.query.filter_by(business_id=None).all()
    return communities


def get_community_member_count(community_id):
    """Get the number of members in a community"""
    count = User.query.filter_by(community_id=community_id).count()
    return count


def get_community_admin_info(community_id):
    """Get the admin user information for a community"""
    community = Community.query.get(community_id)
    if not community or not community.admin_user_id:
        return None

    admin = User.query.get(community.admin_user_id)
    return admin