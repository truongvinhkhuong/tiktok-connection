"""
Configuration management cho TikTok Shop OAuth App
"""

import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

class Config:
    """Base configuration"""
    
    # Flask
    SECRET_KEY = os.getenv('FLASK_SECRET_KEY', 'dev-secret-key-change-in-production')
    DEBUG = os.getenv('FLASK_DEBUG', 'false').lower() == 'true'
    HOST = os.getenv('FLASK_HOST', '0.0.0.0')
    PORT = int(os.getenv('FLASK_PORT', 5002))
    USE_SSL = os.getenv('USE_SSL', 'true').lower() == 'true'
    
    # TikTok Shop OAuth
    TIKTOK_CLIENT_KEY = os.getenv('TIKTOK_CLIENT_KEY', '6h2cosrqj39gj')
    TIKTOK_CLIENT_SECRET = os.getenv('TIKTOK_CLIENT_SECRET')
    TIKTOK_REDIRECT_URI = os.getenv('TIKTOK_REDIRECT_URI', 'https://tiktok.truongvinhkhuong.io.vn/callback')
    
    # TikTok API URLs
    TIKTOK_AUTH_URL = 'https://partner.tiktokshop.com/authorization/oauth/auth'
    TIKTOK_TOKEN_URL = 'https://partner.tiktokshop.com/authorization/v1/token'  # Use working domain
    TIKTOK_API_BASE_URL = 'https://partner.tiktokshop.com'  # Use working domain
    
    # OAuth Settings
    OAUTH_SCOPES = [
        'user.info.basic',
        'user.info.profile',
        'product.info',
        'order.info'
    ]
    
    # Database (optional)
    DATABASE_URL = os.getenv('DATABASE_URL')
    
    @classmethod
    def validate(cls):
        """Validate required configuration"""
        required_vars = [
            'TIKTOK_CLIENT_KEY',
            'TIKTOK_CLIENT_SECRET', 
            'TIKTOK_REDIRECT_URI'
        ]
        
        missing_vars = []
        for var in required_vars:
            if not getattr(cls, var):
                missing_vars.append(var)
        
        if missing_vars:
            raise ValueError(f"Missing required environment variables: {', '.join(missing_vars)}")
        
        return True
    
    @classmethod
    def get_tiktok_auth_url(cls, state=None):
        """Generate TikTok authorization URL"""
        params = {
            'client_key': cls.TIKTOK_CLIENT_KEY,
            'response_type': 'code',
            'redirect_uri': cls.TIKTOK_REDIRECT_URI,
            'scope': ','.join(cls.OAUTH_SCOPES)
        }
        
        if state:
            params['state'] = state
        
        query_string = '&'.join([f"{k}={v}" for k, v in params.items()])
        return f"{cls.TIKTOK_AUTH_URL}?{query_string}"

class DevelopmentConfig(Config):
    """Development configuration"""
    DEBUG = True
    USE_SSL = False  # Disable SSL in development for easier local testing

class ProductionConfig(Config):
    """Production configuration"""
    DEBUG = False
    USE_SSL = True

class TestingConfig(Config):
    """Testing configuration"""
    TESTING = True
    DEBUG = True
    USE_SSL = False

# Configuration mapping
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}