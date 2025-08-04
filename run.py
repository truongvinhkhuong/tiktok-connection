#!/usr/bin/env python3
"""
Script khởi chạy TikTok Shop OAuth Callback Application
"""

import os
import sys
from app import create_app
from config import Config

def main():
    """Main function"""
    print("Starting TikTok Shop OAuth Callback Application...")
    
    # Validate environment
    try:
        Config.validate()
        print("Configuration validated successfully")
    except ValueError as e:
        print(f"Configuration error: {e}")
        print("\nRequired environment variables:")
        print("  - TIKTOK_CLIENT_KEY")
        print("  - TIKTOK_CLIENT_SECRET") 
        print("  - TIKTOK_REDIRECT_URI")
        print("\nCopy env_config.py to .env and fill in your values")
        sys.exit(1)
    
    # Create app
    app = create_app()
    
    # Display startup info
    print(f"Server will start at: http{'s' if Config.USE_SSL else ''}://{Config.HOST}:{Config.PORT}")
    print(f"Environment: {os.getenv('FLASK_ENV', 'development')}")
    print(f"SSL Enabled: {Config.USE_SSL}")
    print(f"Debug Mode: {Config.DEBUG}")
    print(f"Local URL: http://localhost:{Config.PORT}")
    print("\nAvailable endpoints:")
    print("  GET  /                - Home page")
    print("  GET  /callback        - OAuth callback")
    print("  GET  /api/start-oauth - Start OAuth flow")
    print("  GET  /token/info      - Token information")
    print("  GET  /token/clear     - Clear tokens")
    print("  GET  /health          - Health check")
    
    print("\nStarting server...")
    
    # Configure SSL
    ssl_context = None
    if Config.USE_SSL:
        try:
            ssl_context = 'adhoc'
            print("Using adhoc SSL context for development")
        except Exception as e:
            print(f"SSL setup failed: {e}. Running with HTTP")
            ssl_context = None
    
    # Start server
    try:
        app.run(
            host=Config.HOST,
            port=Config.PORT,
            debug=Config.DEBUG,
            ssl_context=ssl_context
        )
    except KeyboardInterrupt:
        print("\nServer stopped by user")
    except Exception as e:
        print(f"Server failed to start: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()