"""
Push notification module for iZwi PWA
Handles web push subscriptions and notifications
"""
import os
import json
from cryptography.hazmat.primitives import serialization
from py_vapid import Vapid
from pywebpush import webpush, WebPushException
from flask import current_app, request, jsonify
from models import db, PushSubscription

# VAPID keys for push notifications
VAPID_PRIVATE_KEY = os.environ.get('VAPID_PRIVATE_KEY')
VAPID_PUBLIC_KEY = os.environ.get('VAPID_PUBLIC_KEY')
VAPID_CLAIM_EMAIL = os.environ.get('VAPID_CLAIM_EMAIL', 'admin@izwi.app')

def generate_vapid_keys():
    """Generate new VAPID keys if they don't exist"""
    if not VAPID_PRIVATE_KEY or not VAPID_PUBLIC_KEY:
        # Generate new VAPID keys
        vapid = Vapid()
        vapid.generate_keys()

        private_key = vapid.private_key
        public_key = vapid.public_key

        # Convert to the format expected by pywebpush
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        return private_pem.decode('utf-8'), public_key.decode('utf-8')

    return VAPID_PRIVATE_KEY, VAPID_PUBLIC_KEY

def get_vapid_public_key():
    """Get the public VAPID key for client-side use"""
    if not VAPID_PUBLIC_KEY:
        _, public_key = generate_vapid_keys()
        return public_key
    return VAPID_PUBLIC_KEY

def subscribe_user(subscription_data):
    """Subscribe a user to push notifications"""
    try:
        user_id = subscription_data.get('user_id')
        endpoint = subscription_data.get('endpoint')
        p256dh = subscription_data.get('keys', {}).get('p256dh')
        auth = subscription_data.get('keys', {}).get('auth')

        if not all([user_id, endpoint, p256dh, auth]):
            return {'error': 'Missing required subscription data'}, 400

        # Check if subscription already exists
        existing = PushSubscription.query.filter_by(
            user_id=user_id,
            endpoint=endpoint
        ).first()

        if existing:
            # Update existing subscription
            existing.p256dh = p256dh
            existing.auth = auth
        else:
            # Create new subscription
            subscription = PushSubscription(
                user_id=user_id,
                endpoint=endpoint,
                p256dh=p256dh,
                auth=auth
            )
            db.session.add(subscription)

        db.session.commit()
        return {'success': True}

    except Exception as e:
        current_app.logger.error(f'Error subscribing user to push notifications: {e}')
        db.session.rollback()
        return {'error': 'Failed to subscribe user'}, 500

def unsubscribe_user(subscription_data):
    """Unsubscribe a user from push notifications"""
    try:
        user_id = subscription_data.get('user_id')
        endpoint = subscription_data.get('endpoint')

        if not all([user_id, endpoint]):
            return {'error': 'Missing required subscription data'}, 400

        subscription = PushSubscription.query.filter_by(
            user_id=user_id,
            endpoint=endpoint
        ).first()

        if subscription:
            db.session.delete(subscription)
            db.session.commit()
            return {'success': True}
        else:
            return {'error': 'Subscription not found'}, 404

    except Exception as e:
        current_app.logger.error(f'Error unsubscribing user from push notifications: {e}')
        db.session.rollback()
        return {'error': 'Failed to unsubscribe user'}, 500

def send_notification_to_user(user_id, title, body, icon=None, badge=None, data=None):
    """Send a push notification to a specific user"""
    try:
        subscriptions = PushSubscription.query.filter_by(user_id=user_id).all()

        if not subscriptions:
            return {'error': 'No subscriptions found for user'}, 404

        # Setup VAPID keys
        private_key, public_key = generate_vapid_keys()
        if not private_key or not public_key:
            return {'error': 'VAPID keys not configured'}, 500

        vapid = Vapid()
        vapid.private_key = serialization.load_pem_private_key(
            private_key.encode('utf-8'),
            password=None
        )
        vapid.public_key = public_key.encode('utf-8')

        notification_data = {
            'title': title,
            'body': body,
            'icon': icon or '/static/icons/icon-192.png',
            'badge': badge or '/static/icons/icon-192.png',
            'tag': 'izwi-notification',
            'requireInteraction': True
        }

        if data:
            notification_data['data'] = data

        success_count = 0
        failed_count = 0

        for subscription in subscriptions:
            try:
                # Prepare subscription info for webpush
                subscription_info = {
                    'endpoint': subscription.endpoint,
                    'keys': {
                        'p256dh': subscription.p256dh,
                        'auth': subscription.auth
                    }
                }

                # Send the notification
                webpush(
                    subscription_info,
                    json.dumps(notification_data),
                    vapid_private_key=private_key,
                    vapid_claims={
                        'sub': f'mailto:{VAPID_CLAIM_EMAIL}'
                    }
                )
                success_count += 1

            except WebPushException as e:
                current_app.logger.error(f'WebPush error for user {user_id}: {e}')
                failed_count += 1
                # If subscription is invalid, remove it
                if e.response.status_code in [400, 401, 403, 404, 410, 413]:
                    try:
                        db.session.delete(subscription)
                    except:
                        pass

            except Exception as e:
                current_app.logger.error(f'Error sending notification to user {user_id}: {e}')
                failed_count += 1

        db.session.commit()

        return {
            'success': True,
            'sent': success_count,
            'failed': failed_count
        }

    except Exception as e:
        current_app.logger.error(f'Error in send_notification_to_user: {e}')
        return {'error': 'Failed to send notification'}, 500

def send_notification_to_community_users(community_id, title, body, icon=None, badge=None, data=None):
    """Send a push notification to users in a specific community"""
    try:
        from models import User

        # Get all users in the community
        community_users = User.query.filter_by(community_id=community_id).all()

        if not community_users:
            current_app.logger.info(f'No users found in community {community_id}')
            return {'success': True, 'sent': 0, 'failed': 0, 'total': 0}

        # Get all subscriptions for users in this community
        user_ids = [user.id for user in community_users]
        subscriptions = PushSubscription.query.filter(
            PushSubscription.user_id.in_(user_ids)
        ).all()

        if not subscriptions:
            current_app.logger.info(f'No push subscriptions found for users in community {community_id}')
            return {'success': True, 'sent': 0, 'failed': 0, 'total': 0}

        # Setup VAPID keys
        private_key, public_key = generate_vapid_keys()
        if not private_key or not public_key:
            return {'error': 'VAPID keys not configured'}, 500

        vapid = Vapid()
        vapid.private_key = serialization.load_pem_private_key(
            private_key.encode('utf-8'),
            password=None
        )
        vapid.public_key = public_key.encode('utf-8')

        notification_data = {
            'title': title,
            'body': body,
            'icon': icon or '/static/icons/icon-192.png',
            'badge': badge or '/static/icons/icon-192.png',
            'tag': 'izwi-alert',
            'requireInteraction': True
        }

        if data:
            notification_data['data'] = data

        success_count = 0
        failed_count = 0
        invalid_subscriptions = []

        for subscription in subscriptions:
            try:
                # Prepare subscription info for webpush
                subscription_info = {
                    'endpoint': subscription.endpoint,
                    'keys': {
                        'p256dh': subscription.p256dh,
                        'auth': subscription.auth
                    }
                }

                # Send the notification
                webpush(
                    subscription_info,
                    json.dumps(notification_data),
                    vapid_private_key=private_key,
                    vapid_claims={
                        'sub': f'mailto:{VAPID_CLAIM_EMAIL}'
                    }
                )
                success_count += 1

            except WebPushException as e:
                current_app.logger.error(f'WebPush error for subscription {subscription.id}: {e}')
                failed_count += 1
                # If subscription is invalid, mark for deletion
                if e.response.status_code in [400, 401, 403, 404, 410, 413]:
                    invalid_subscriptions.append(subscription)

            except Exception as e:
                current_app.logger.error(f'Error sending notification to subscription {subscription.id}: {e}')
                failed_count += 1

        # Clean up invalid subscriptions
        for subscription in invalid_subscriptions:
            try:
                db.session.delete(subscription)
            except:
                pass

        db.session.commit()

        current_app.logger.info(f'Sent notification to {success_count}/{len(subscriptions)} subscriptions for community {community_id}')
        return {
            'success': True,
            'sent': success_count,
            'failed': failed_count,
            'total': len(subscriptions)
        }

    except Exception as e:
        current_app.logger.error(f'Error in send_notification_to_community_users: {e}')
        return {'error': 'Failed to send notification'}, 500


def send_notification_to_all_users(title, body, icon=None, badge=None, data=None):
    """Send a push notification to all subscribed users"""
    try:
        subscriptions = PushSubscription.query.all()

        if not subscriptions:
            return {'error': 'No subscriptions found'}, 404

        # Setup VAPID keys
        private_key, public_key = generate_vapid_keys()
        if not private_key or not public_key:
            return {'error': 'VAPID keys not configured'}, 500

        vapid = Vapid()
        vapid.private_key = serialization.load_pem_private_key(
            private_key.encode('utf-8'),
            password=None
        )
        vapid.public_key = public_key.encode('utf-8')

        notification_data = {
            'title': title,
            'body': body,
            'icon': icon or '/static/icons/icon-192.png',
            'badge': badge or '/static/icons/icon-192.png',
            'tag': 'izwi-alert',
            'requireInteraction': True
        }

        if data:
            notification_data['data'] = data

        success_count = 0
        failed_count = 0
        invalid_subscriptions = []

        for subscription in subscriptions:
            try:
                # Prepare subscription info for webpush
                subscription_info = {
                    'endpoint': subscription.endpoint,
                    'keys': {
                        'p256dh': subscription.p256dh,
                        'auth': subscription.auth
                    }
                }

                # Send the notification
                webpush(
                    subscription_info,
                    json.dumps(notification_data),
                    vapid_private_key=private_key,
                    vapid_claims={
                        'sub': f'mailto:{VAPID_CLAIM_EMAIL}'
                    }
                )
                success_count += 1

            except WebPushException as e:
                current_app.logger.error(f'WebPush error for subscription {subscription.id}: {e}')
                failed_count += 1
                # If subscription is invalid, mark for deletion
                if e.response.status_code in [400, 401, 403, 404, 410, 413]:
                    invalid_subscriptions.append(subscription)

            except Exception as e:
                current_app.logger.error(f'Error sending notification to subscription {subscription.id}: {e}')
                failed_count += 1

        # Clean up invalid subscriptions
        for subscription in invalid_subscriptions:
            try:
                db.session.delete(subscription)
            except:
                pass

        db.session.commit()

        return {
            'success': True,
            'sent': success_count,
            'failed': failed_count,
            'total': len(subscriptions)
        }

    except Exception as e:
        current_app.logger.error(f'Error in send_notification_to_all_users: {e}')
        return {'error': 'Failed to send notification'}, 500
