"""
TikTok Shop OAuth Callback Application
Xử lý OAuth callback từ TikTok Shop Partner API với đầy đủ tính năng bảo mật
"""

import os
import logging
import requests
import json
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, session, redirect, url_for
from werkzeug.exceptions import BadRequest
import secrets

# Import custom modules
from config import Config
from security import security_manager, rate_limit, require_https, SecurityManager

# Cấu hình logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s',
    handlers=[
        logging.FileHandler('tiktok_oauth.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)

# Load configuration
try:
    Config.validate()
    app.secret_key = Config.SECRET_KEY
    logger.info("Configuration validated successfully")
except ValueError as e:
    logger.error(f"Configuration error: {e}")
    raise

# Initialize security manager
security_manager.init_app(app)

def validate_callback_params(code, state, error):
    """Validate callback parameters từ TikTok với enhanced security"""
    errors = []
    
    # Check for OAuth errors first
    if error:
        logger.warning(f"OAuth error received: {error}")
        errors.append(f"OAuth Error: {error}")
        error_description = request.args.get('error_description', 'Không có mô tả chi tiết')
        errors.append(f"Mô tả lỗi: {error_description}")
        return errors
    
    # Validate authorization code
    if not code:
        errors.append("Thiếu authorization code")
    elif len(code) < 10 or len(code) > 2048:  # Increased limit for TikTok's long codes
        errors.append("Authorization code có độ dài không hợp lệ")
    elif not code.replace('-', '').replace('_', '').replace('.', '').replace('+', '').replace('/', '').replace('=', '').isalnum():
        errors.append("Authorization code chứa ký tự không hợp lệ")
    
    # Enhanced state validation cho CSRF protection
    if state:
        if not security_manager.validate_state(state):
            errors.append("State parameter không hợp lệ hoặc đã hết hạn - có thể bị CSRF attack")
    else:
        logger.warning("No state parameter received - CSRF protection không có hiệu lực")
    
    # Validate request source (có thể thêm whitelist domains)
    referer = request.headers.get('Referer', '')
    if referer and 'tiktok' not in referer.lower():
        logger.warning(f"Suspicious referer: {referer}")
        # Không block ngay mà chỉ log để monitor
    
    return errors

def exchange_code_for_token(authorization_code):
    """Exchange authorization code để lấy access token"""
    
    # Sanitize input
    authorization_code = security_manager.sanitize_input(authorization_code)
    
    # Chuẩn bị data cho request
    token_data = {
        'grant_type': 'authorization_code',
        'client_key': Config.TIKTOK_CLIENT_KEY,
        'client_secret': Config.TIKTOK_CLIENT_SECRET,
        'code': authorization_code,
        'redirect_uri': Config.TIKTOK_REDIRECT_URI
    }
    
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'User-Agent': 'TikTokShopApp/1.0',
        'Accept': 'application/json'
    }
    
    try:
        logger.info(f"Gửi request lấy access token tới {Config.TIKTOK_TOKEN_URL}")
        
        response = requests.post(
            Config.TIKTOK_TOKEN_URL,
            data=token_data,
            headers=headers,
            timeout=30
        )
        
        logger.info(f"Response status code: {response.status_code}")
        logger.info(f"Response headers: {dict(response.headers)}")
        
        if response.status_code == 200:
            token_response = response.json()
            logger.info("Nhận access token thành công")
            
            # Validate response structure
            if 'access_token' in token_response:
                return {
                    'success': True,
                    'data': token_response,
                    'message': 'Lấy access token thành công'
                }
            else:
                logger.error(f"Response không chứa access_token: {token_response}")
                return {
                    'success': False,
                    'error': 'Response không hợp lệ từ TikTok',
                    'details': token_response
                }
        else:
            error_data = response.text
            try:
                error_json = response.json()
                error_data = error_json
            except:
                pass
            
            logger.error(f"Lỗi từ TikTok API: {response.status_code} - {error_data}")
            return {
                'success': False,
                'error': f'HTTP {response.status_code}',
                'details': error_data
            }
            
    except requests.RequestException as e:
        logger.error(f"Network error khi gọi TikTok API: {str(e)}")
        return {
            'success': False,
            'error': 'Lỗi kết nối mạng',
            'details': str(e)
        }
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        return {
            'success': False,
            'error': 'Lỗi không xác định',
            'details': str(e)
        }

def store_token(token_data):
    """Lưu trữ token (có thể mở rộng để lưu vào database)"""
    try:
        # Hiện tại lưu vào session, có thể mở rộng để lưu vào database
        session['access_token'] = token_data.get('access_token')
        session['refresh_token'] = token_data.get('refresh_token')
        session['expires_in'] = token_data.get('expires_in', 3600)
        session['token_type'] = token_data.get('token_type', 'Bearer')
        session['scope'] = token_data.get('scope', '')
        session['token_received_at'] = datetime.now().isoformat()
        
        logger.info("Token đã được lưu trữ thành công")
        return True
    except Exception as e:
        logger.error(f"Lỗi khi lưu trữ token: {str(e)}")
        return False

@app.route('/')
@rate_limit(max_requests=20, time_window=60)
def index():
    """Trang chủ với thông tin về OAuth flow"""
    
    # Generate OAuth URL with state
    state = security_manager.generate_state()
    oauth_url = Config.get_tiktok_auth_url(state)
    
    return f"""
    <!DOCTYPE html>
    <html lang="vi">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>TikTok Shop OAuth Callback</title>
        <style>
            * {{
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }}
            
            body {{
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                background: linear-gradient(135deg, #2A95BF 0%, #1a7a9e 100%);
                min-height: 100vh;
                color: #333;
            }}
            
            .container {{
                max-width: 1200px;
                margin: 0 auto;
                padding: 20px;
            }}
            
            .header {{
                text-align: center;
                margin-bottom: 40px;
                color: white;
            }}
            
            .header h1 {{
                font-size: 2.5rem;
                margin-bottom: 10px;
                font-weight: 300;
                text-shadow: 0 2px 4px rgba(0,0,0,0.3);
            }}
            
            .header p {{
                font-size: 1.1rem;
                opacity: 0.9;
            }}
            
            .card {{
                background: white;
                border-radius: 15px;
                padding: 30px;
                margin-bottom: 30px;
                box-shadow: 0 10px 30px rgba(0,0,0,0.1);
                border: 1px solid rgba(42, 149, 191, 0.1);
            }}
            
            .card h2 {{
                color: #2A95BF;
                font-size: 1.5rem;
                margin-bottom: 20px;
                font-weight: 600;
                border-bottom: 2px solid #2A95BF;
                padding-bottom: 10px;
            }}
            
            .info-grid {{
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
                gap: 20px;
                margin-bottom: 20px;
            }}
            
            .info-item {{
                background: #f8f9fa;
                padding: 15px;
                border-radius: 8px;
                border-left: 4px solid #2A95BF;
            }}
            
            .info-item strong {{
                color: #2A95BF;
                display: block;
                margin-bottom: 5px;
            }}
            
            .oauth-button {{
                display: inline-block;
                background: linear-gradient(45deg, #2A95BF, #1a7a9e);
                color: white;
                padding: 15px 30px;
                text-decoration: none;
                border-radius: 25px;
                font-weight: 600;
                font-size: 1.1rem;
                transition: all 0.3s ease;
                box-shadow: 0 4px 15px rgba(42, 149, 191, 0.3);
                border: none;
                cursor: pointer;
            }}
            
            .oauth-button:hover {{
                transform: translateY(-2px);
                box-shadow: 0 6px 20px rgba(42, 149, 191, 0.4);
                background: linear-gradient(45deg, #1a7a9e, #2A95BF);
            }}
            
            .endpoints {{
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
                gap: 15px;
            }}
            
            .endpoint-item {{
                background: #f8f9fa;
                padding: 15px;
                border-radius: 8px;
                border: 1px solid #e9ecef;
            }}
            
            .endpoint-item code {{
                background: #2A95BF;
                color: white;
                padding: 4px 8px;
                border-radius: 4px;
                font-size: 0.9rem;
            }}
            
            .endpoint-item p {{
                margin-top: 8px;
                color: #666;
                font-size: 0.9rem;
            }}
            
            .security-note {{
                background: linear-gradient(45deg, #2A95BF, #1a7a9e);
                color: white;
                padding: 20px;
                border-radius: 10px;
                text-align: center;
                margin-top: 30px;
            }}
            
            .security-note small {{
                font-size: 0.9rem;
                opacity: 0.9;
            }}
            
            @media (max-width: 768px) {{
                .container {{
                    padding: 15px;
                }}
                
                .header h1 {{
                    font-size: 2rem;
                }}
                
                .card {{
                    padding: 20px;
                }}
                
                .info-grid {{
                    grid-template-columns: 1fr;
                }}
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>TikTok Shop OAuth Callback</h1>
                <p>Ứng dụng xử lý OAuth callback từ TikTok Shop Partner API</p>
            </div>
            
            <div class="card">
                <h2>Thông tin ứng dụng</h2>
                <div class="info-grid">
                    <div class="info-item">
                        <strong>Client Key</strong>
                        {Config.TIKTOK_CLIENT_KEY}
                    </div>
                    <div class="info-item">
                        <strong>Redirect URI</strong>
                        {Config.TIKTOK_REDIRECT_URI}
                    </div>
                    <div class="info-item">
                        <strong>Token URL</strong>
                        {Config.TIKTOK_TOKEN_URL}
                    </div>
                    <div class="info-item">
                        <strong>Scope</strong>
                        {', '.join(Config.OAUTH_SCOPES)}
                    </div>
                </div>
            </div>
            
            <div class="card">
                <h2>Bắt đầu OAuth Flow</h2>
                <p style="margin-bottom: 20px; color: #666;">
                    Nhấn nút bên dưới để bắt đầu quá trình xác thực với TikTok Shop
                </p>
                <a href="{oauth_url}" target="_blank" class="oauth-button">
                    Authorize with TikTok Shop
                </a>
            </div>
            
            <div class="card">
                <h2>API Endpoints</h2>
                <div class="endpoints">
                    <div class="endpoint-item">
                        <code>GET /callback</code>
                        <p>OAuth callback endpoint</p>
                    </div>
                    <div class="endpoint-item">
                        <code>GET /token/info</code>
                        <p>Thông tin token hiện tại</p>
                    </div>
                    <div class="endpoint-item">
                        <code>GET /token/clear</code>
                        <p>Xóa token khỏi session</p>
                    </div>
                    <div class="endpoint-item">
                        <code>GET /health</code>
                        <p>Health check endpoint</p>
                    </div>
                </div>
            </div>
            
           
        </div>
    </body>
    </html>
    """

@app.route('/callback')
@rate_limit(max_requests=5, time_window=60)
def callback():
    """Xử lý OAuth callback từ TikTok Shop"""
    
    # Log request details
    ip_address = request.remote_addr
    user_agent = request.headers.get('User-Agent', 'Unknown')
    logger.info(f"OAuth callback từ IP: {ip_address}, User-Agent: {user_agent}")
    logger.info(f"Callback parameters: {dict(request.args)}")
    
    # Log code length for debugging
    code = request.args.get('code', '').strip()
    if code:
        logger.info(f"Authorization code length: {len(code)}")
        logger.info(f"Authorization code preview: {code[:50]}...")
    
    # Lấy parameters từ callback
    code = request.args.get('code', '').strip()
    error = request.args.get('error', '').strip()
    state = request.args.get('state', '').strip()
    error_description = request.args.get('error_description', '').strip()
    
    # Sanitize inputs
    code = security_manager.sanitize_input(code)
    error = security_manager.sanitize_input(error)
    state = security_manager.sanitize_input(state)
    
    # Validate parameters
    validation_errors = validate_callback_params(code, state, error)
    if validation_errors:
        security_manager.log_security_event("INVALID_CALLBACK", f"Validation failed: {validation_errors}", ip_address)
        return jsonify({
            'success': False,
            'errors': validation_errors,
            'error_description': error_description,
            'timestamp': datetime.now().isoformat()
        }), 400
    
    # Exchange code for access token
    token_result = exchange_code_for_token(code)
    
    if token_result['success']:
        # Lưu trữ token
        if store_token(token_result['data']):
            response_data = {
                'success': True,
                'message': 'OAuth flow hoàn thành thành công',
                'token_info': {
                    'access_token': token_result['data']['access_token'][:10] + '...',  # Chỉ hiển thị một phần
                    'token_type': token_result['data'].get('token_type', 'Bearer'),
                    'expires_in': token_result['data'].get('expires_in', 3600),
                    'scope': token_result['data'].get('scope', ''),
                    'received_at': datetime.now().isoformat()
                },
                'next_steps': [
                    'Token đã được lưu trữ an toàn',
                    'Có thể bắt đầu gọi TikTok Shop API',
                    'Nhớ refresh token trước khi hết hạn'
                ]
            }
            
            return jsonify(response_data), 200
        else:
            return jsonify({
                'success': False,
                'error': 'Không thể lưu trữ token',
                'timestamp': datetime.now().isoformat()
            }), 500
    else:
        return jsonify({
            'success': False,
            'error': token_result['error'],
            'details': token_result.get('details'),
            'timestamp': datetime.now().isoformat()
        }), 400

@app.route('/token/info')
@rate_limit(max_requests=10, time_window=60)
def token_info():
    """Hiển thị thông tin token hiện tại (debug endpoint)"""
    if 'access_token' not in session:
        return jsonify({
            'success': False,
            'message': 'Không có token nào được lưu trữ',
            'timestamp': datetime.now().isoformat()
        }), 404
    
    # Calculate token expiration
    received_at = session.get('token_received_at')
    expires_in = session.get('expires_in', 3600)
    expires_at = None
    is_expired = False
    
    if received_at:
        try:
            received_time = datetime.fromisoformat(received_at)
            expires_at = received_time + timedelta(seconds=expires_in)
            is_expired = datetime.now() > expires_at
        except:
            pass
    
    return jsonify({
        'success': True,
        'token_info': {
            'has_access_token': bool(session.get('access_token')),
            'has_refresh_token': bool(session.get('refresh_token')),
            'token_type': session.get('token_type'),
            'expires_in': expires_in,
            'expires_at': expires_at.isoformat() if expires_at else None,
            'is_expired': is_expired,
            'scope': session.get('scope'),
            'received_at': received_at
        },
        'timestamp': datetime.now().isoformat()
    })

@app.route('/token/clear')
@rate_limit(max_requests=5, time_window=60)
def clear_token():
    """Xóa token khỏi session (debug endpoint)"""
    had_token = 'access_token' in session
    session.clear()
    
    logger.info(f"Token cleared từ session bởi IP: {request.remote_addr}")
    
    return jsonify({
        'success': True,
        'message': 'Token đã được xóa khỏi session' if had_token else 'Không có token để xóa',
        'had_token': had_token,
        'timestamp': datetime.now().isoformat()
    })

@app.route('/health')
@rate_limit(max_requests=30, time_window=60)
def health_check():
    """Health check endpoint để monitoring"""
    return jsonify({
        'success': True,
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'version': '1.0.0',
        'environment': os.getenv('FLASK_ENV', 'development')
    })

@app.route('/api/start-oauth')
@rate_limit(max_requests=10, time_window=60)
def start_oauth():
    """API endpoint để bắt đầu OAuth flow"""
    try:
        # Generate secure state
        state = security_manager.generate_state()
        oauth_url = Config.get_tiktok_auth_url(state)
        
        logger.info(f"OAuth flow started từ IP: {request.remote_addr}")
        
        return jsonify({
            'success': True,
            'oauth_url': oauth_url,
            'state': state,
            'instructions': [
                'Redirect user tới oauth_url',
                'User sẽ authorize với TikTok Shop',
                'TikTok sẽ redirect về callback URL với authorization code',
                'Application sẽ exchange code cho access token'
            ],
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"Error starting OAuth flow: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Không thể tạo OAuth URL',
            'timestamp': datetime.now().isoformat()
        }), 500

# Error Handlers với enhanced logging và security
@app.errorhandler(400)
def bad_request(error):
    logger.warning(f"Bad request từ IP {request.remote_addr}: {str(error)}")
    return jsonify({
        'success': False,
        'error': 'Yêu cầu không hợp lệ',
        'message': 'Kiểm tra lại parameters và format của request',
        'timestamp': datetime.now().isoformat()
    }), 400

@app.errorhandler(401)
def unauthorized(error):
    security_manager.log_security_event("UNAUTHORIZED_ACCESS", str(error), request.remote_addr)
    return jsonify({
        'success': False,
        'error': 'Không có quyền truy cập',
        'message': 'Cần authentication hợp lệ',
        'timestamp': datetime.now().isoformat()
    }), 401

@app.errorhandler(403)
def forbidden(error):
    security_manager.log_security_event("FORBIDDEN_ACCESS", str(error), request.remote_addr)
    return jsonify({
        'success': False,
        'error': 'Truy cập bị từ chối',
        'message': 'Không có permission để thực hiện action này',
        'timestamp': datetime.now().isoformat()
    }), 403

@app.errorhandler(404)
def not_found(error):
    logger.info(f"404 request từ IP {request.remote_addr}: {request.url}")
    return jsonify({
        'success': False,
        'error': 'Endpoint không tìm thấy',
        'available_endpoints': {
            'GET /': 'Trang chủ với thông tin ứng dụng',
            'GET /callback': 'OAuth callback endpoint',
            'GET /api/start-oauth': 'Bắt đầu OAuth flow',
            'GET /token/info': 'Thông tin token hiện tại',
            'GET /token/clear': 'Xóa token khỏi session',
            'GET /health': 'Health check endpoint'
        },
        'timestamp': datetime.now().isoformat()
    }), 404

@app.errorhandler(429)
def rate_limit_exceeded(error):
    security_manager.log_security_event("RATE_LIMIT_HIT", f"Rate limit exceeded", request.remote_addr)
    return jsonify({
        'success': False,
        'error': 'Rate limit exceeded',
        'message': 'Quá nhiều requests. Vui lòng thử lại sau.',
        'retry_after': '60 seconds',
        'timestamp': datetime.now().isoformat()
    }), 429

@app.errorhandler(500)
def internal_error(error):
    logger.error(f"Internal server error từ IP {request.remote_addr}: {str(error)}")
    security_manager.log_security_event("INTERNAL_ERROR", str(error), request.remote_addr)
    return jsonify({
        'success': False,
        'error': 'Lỗi server nội bộ',
        'message': 'Đã xảy ra lỗi không mong muốn. Vui lòng thử lại sau.',
        'timestamp': datetime.now().isoformat()
    }), 500

@app.errorhandler(Exception)
def handle_unexpected_error(error):
    logger.error(f"Unexpected error từ IP {request.remote_addr}: {str(error)}", exc_info=True)
    security_manager.log_security_event("UNEXPECTED_ERROR", str(error), request.remote_addr)
    return jsonify({
        'success': False,
        'error': 'Lỗi không xác định',
        'message': 'Đã xảy ra lỗi không mong muốn',
        'timestamp': datetime.now().isoformat()
    }), 500

def create_app():
    """Factory function để tạo Flask app"""
    return app

if __name__ == "__main__":
    # Kiểm tra SSL context
    ssl_context = None
    if Config.USE_SSL:
        try:
            # Kiểm tra xem có cryptography library không
            import cryptography
            ssl_context = 'adhoc'  # Tự động tạo SSL certificate cho development
            logger.info("Sử dụng HTTPS với adhoc SSL context")
        except ImportError:
            logger.warning("Thiếu thư viện cryptography. Chạy với HTTP. Cài đặt: pip install cryptography")
            ssl_context = None
        except Exception as e:
            logger.warning(f"Không thể tạo SSL context: {e}. Chạy với HTTP")
            ssl_context = None
    
    # Log startup information
    logger.info("="*50)
    logger.info("TikTok Shop OAuth Callback Application Starting")
    logger.info(f"Environment: {os.getenv('FLASK_ENV', 'development')}")
    logger.info(f"Host: {Config.HOST}")
    logger.info(f"Port: {Config.PORT}")
    logger.info(f"Debug Mode: {Config.DEBUG}")
    logger.info(f"SSL Enabled: {ssl_context is not None}")
    logger.info(f"Client Key: {Config.TIKTOK_CLIENT_KEY}")
    logger.info(f"Redirect URI: {Config.TIKTOK_REDIRECT_URI}")
    logger.info("="*50)
    
    try:
        app.run(
            host=Config.HOST,
            port=Config.PORT,
            debug=Config.DEBUG,
            ssl_context=ssl_context
        )
    except Exception as e:
        logger.error(f"Failed to start server: {e}")
        raise