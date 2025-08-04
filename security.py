"""
Security utilities cho TikTok Shop OAuth Application
"""

import hashlib
import hmac
import secrets
import time
from functools import wraps
from flask import request, jsonify, session
import logging

logger = logging.getLogger(__name__)

class SecurityManager:
    """Quản lý bảo mật cho OAuth application"""
    
    def __init__(self, app=None):
        self.app = app
        self.rate_limit_store = {}
        self.blocked_ips = set()
        
    def init_app(self, app):
        """Initialize với Flask app"""
        self.app = app
        
    def generate_state(self):
        """Tạo state parameter để chống CSRF"""
        state = secrets.token_urlsafe(32)
        session['oauth_state'] = state
        session['oauth_state_created'] = time.time()
        return state
    
    def validate_state(self, received_state):
        """Validate state parameter"""
        stored_state = session.get('oauth_state')
        state_created = session.get('oauth_state_created', 0)
        
        # Check if state exists
        if not stored_state:
            logger.warning("No stored state found in session")
            return False
        
        # Check if state matches
        if not hmac.compare_digest(stored_state, received_state):
            logger.warning(f"State mismatch: stored={stored_state[:10]}..., received={received_state[:10]}...")
            return False
        
        # Check state age (expire after 10 minutes)
        if time.time() - state_created > 600:
            logger.warning("State parameter has expired")
            return False
        
        # Clean up used state
        session.pop('oauth_state', None)
        session.pop('oauth_state_created', None)
        
        return True
    
    def validate_callback_signature(self, params, secret):
        """Validate callback signature nếu TikTok có gửi"""
        # TikTok Shop có thể gửi signature để validate callback
        # Implementation tùy theo documentation chính thức
        signature = params.get('signature')
        if not signature:
            return True  # No signature to validate
        
        # Tạo expected signature
        sorted_params = sorted([(k, v) for k, v in params.items() if k != 'signature'])
        query_string = '&'.join([f"{k}={v}" for k, v in sorted_params])
        expected_signature = hmac.new(
            secret.encode('utf-8'),
            query_string.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        
        return hmac.compare_digest(signature, expected_signature)
    
    def is_rate_limited(self, ip_address, max_requests=10, time_window=300):
        """Check rate limiting cho IP address"""
        current_time = time.time()
        
        if ip_address not in self.rate_limit_store:
            self.rate_limit_store[ip_address] = []
        
        # Clean old requests
        self.rate_limit_store[ip_address] = [
            req_time for req_time in self.rate_limit_store[ip_address]
            if current_time - req_time < time_window
        ]
        
        # Check if rate limited
        if len(self.rate_limit_store[ip_address]) >= max_requests:
            logger.warning(f"Rate limit exceeded for IP: {ip_address}")
            return True
        
        # Add current request
        self.rate_limit_store[ip_address].append(current_time)
        return False
    
    def block_ip(self, ip_address, reason="Security violation"):
        """Block IP address"""
        self.blocked_ips.add(ip_address)
        logger.warning(f"Blocked IP {ip_address}: {reason}")
    
    def is_ip_blocked(self, ip_address):
        """Check if IP is blocked"""
        return ip_address in self.blocked_ips
    
    def sanitize_input(self, data):
        """Sanitize input data"""
        if isinstance(data, str):
            # Remove potentially dangerous characters
            dangerous_chars = ['<', '>', '"', "'", '&', 'javascript:', 'data:']
            for char in dangerous_chars:
                data = data.replace(char, '')
        return data
    
    def log_security_event(self, event_type, details, ip_address=None):
        """Log security events"""
        if not ip_address:
            ip_address = request.remote_addr if request else 'unknown'
        
        logger.warning(f"SECURITY EVENT - {event_type}: {details} from IP: {ip_address}")

# Global security manager instance
security_manager = SecurityManager()

def rate_limit(max_requests=10, time_window=300):
    """Decorator for rate limiting"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            ip_address = request.remote_addr
            
            # Check if IP is blocked
            if security_manager.is_ip_blocked(ip_address):
                security_manager.log_security_event("BLOCKED_IP_ACCESS", f"Blocked IP attempted access", ip_address)
                return jsonify({
                    'success': False,
                    'error': 'Access denied'
                }), 403
            
            # Check rate limiting
            if security_manager.is_rate_limited(ip_address, max_requests, time_window):
                security_manager.log_security_event("RATE_LIMIT_EXCEEDED", f"Max {max_requests} requests in {time_window}s", ip_address)
                return jsonify({
                    'success': False,
                    'error': 'Rate limit exceeded. Please try again later.'
                }), 429
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def require_https():
    """Decorator to require HTTPS"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not request.is_secure and not request.headers.get('X-Forwarded-Proto') == 'https':
                logger.warning(f"HTTP request to secure endpoint from {request.remote_addr}")
                return jsonify({
                    'success': False,
                    'error': 'HTTPS required'
                }), 400
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def validate_content_type(content_type='application/json'):
    """Decorator to validate content type"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if request.content_type != content_type:
                return jsonify({
                    'success': False,
                    'error': f'Content-Type must be {content_type}'
                }), 400
            return f(*args, **kwargs)
        return decorated_function
    return decorator