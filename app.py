"""
TikTok Shop OAuth Callback Application
Xử lý OAuth callback từ TikTok Shop Partner API với đầy đủ tính năng bảo mật
"""

import os
import logging
import requests
import json
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, session, redirect, url_for, render_template
from werkzeug.exceptions import BadRequest
import secrets
import hmac
import hashlib
from urllib.parse import urlparse
from functools import wraps
import time
from collections import defaultdict

# Import custom modules
from config import Config
from security import security_manager, rate_limit, require_https, SecurityManager

def generate_sign(request_option, app_secret):
    """
    Generate HMAC-SHA256 signature for TikTok Shop API requests
    :param request_option: Request options dictionary containing qs (query params), uri (path), headers, body etc.
    :param app_secret: Secret key for signing
    :return: Hexadecimal signature string
    """
    # Step 1: Extract and filter query parameters, exclude "access_token" and "sign", sort alphabetically
    params = request_option.get('qs', {})
    exclude_keys = ["access_token", "sign"]
    sorted_params = [
        {"key": key, "value": params[key]}
        for key in sorted(params.keys())
        if key not in exclude_keys
    ]

    # Step 2: Concatenate parameters in {key}{value} format
    param_string = ''.join([f"{item['key']}{item['value']}" for item in sorted_params])
    sign_string = param_string

    # Step 3: Append API request path to the signature string
    uri = request_option.get('uri', '')
    pathname = urlparse(uri).path if uri else ''
    sign_string = f"{pathname}{param_string}"

    # Step 4: If not multipart/form-data and request body exists, append JSON-serialized body
    content_type = request_option.get('headers', {}).get('content-type', '')
    body = request_option.get('body', {})
    if content_type != 'multipart/form-data' and body:
        body_str = json.dumps(body)  # JSON serialization ensures consistency
        sign_string += body_str

    # Step 5: Wrap signature string with app_secret
    wrapped_string = f"{app_secret}{sign_string}{app_secret}"

    # Step 6: Encode using HMAC-SHA256 and generate hexadecimal signature
    hmac_obj = hmac.new(
        app_secret.encode('utf-8'),
        wrapped_string.encode('utf-8'),
        hashlib.sha256
    )
    sign = hmac_obj.hexdigest()
    return sign

def create_signed_request(access_token, app_key, app_secret, endpoint_path, params=None, body=None):
    """
    Create a signed request for TikTok Shop API
    :param access_token: OAuth access token
    :param app_key: App key
    :param app_secret: App secret
    :param endpoint_path: API endpoint path (e.g., '/api/shop/get_authorized_shop')
    :param params: Query parameters (optional)
    :param body: Request body (optional)
    :return: Dictionary with signed request details
    """
    if params is None:
        params = {}
    
    # Add required parameters
    params['app_key'] = app_key
    params['timestamp'] = str(int(time.time()))
    params['version'] = '2'
    params['shop_id'] = '0'  # Default shop_id, can be overridden
    
    # Create request option for signature generation
    request_option = {
        'qs': params,
        'uri': f"{Config.TIKTOK_API_BASE_URL}{endpoint_path}",
        'headers': {
            'content-type': 'application/json' if body else 'application/x-www-form-urlencoded'
        },
        'body': body or {}
    }
    
    # Generate signature
    signature = generate_sign(request_option, app_secret)
    
    # Add signature to params
    params['sign'] = signature
    
    # Build final URL
    query_string = '&'.join([f"{k}={v}" for k, v in params.items()])
    final_url = f"{Config.TIKTOK_API_BASE_URL}{endpoint_path}?{query_string}"
    
    return {
        'url': final_url,
        'params': params,
        'signature': signature,
        'headers': {
            'Content-Type': 'application/json' if body else 'application/x-www-form-urlencoded',
            'User-Agent': 'TikTokShopApp/1.0',
            'Accept': 'application/json'
        }
    }

def generate_sample_signature(access_token):
    """
    Generate a sample signature for display purposes
    :param access_token: OAuth access token
    :return: Sample signature string
    """
    try:
        # Tạo sample request cho API get_authorized_shop
        sample_request = create_signed_request(
            access_token=access_token,
            app_key=Config.TIKTOK_CLIENT_KEY,
            app_secret=Config.TIKTOK_CLIENT_SECRET,
            endpoint_path='/api/shop/get_authorized_shop',
            params={
                'access_token': access_token
            }
        )
        return sample_request['signature']
    except Exception as e:
        logger.error(f"Lỗi khi tạo sample signature: {str(e)}")
        return "Error generating signature"

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
    
    # Chuẩn bị data cho request theo TikTok Shop Partner documentation
    token_data = {
        'app_key': Config.TIKTOK_CLIENT_KEY,
        'app_secret': Config.TIKTOK_CLIENT_SECRET,
        'auth_code': authorization_code,
        'grant_type': 'authorized_code'  # Note: 'authorized_code' not 'authorization_code'
    }
    
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'User-Agent': 'TikTokShopApp/1.0',
        'Accept': 'application/json',
        'X-TT-ENV': 'production'  # Add required header for TikTok Shop API
    }
    
    try:
        logger.info(f"Gửi request lấy access token tới {Config.TIKTOK_TOKEN_URL}")
        
        # Test DNS resolution
        import socket
        try:
            host = 'auth.tiktok-shops.com'
            ip = socket.gethostbyname(host)
            logger.info(f"DNS resolution successful: {host} -> {ip}")
        except socket.gaierror as e:
            logger.error(f"DNS resolution failed for {host}: {e}")
            return {
                'success': False,
                'error': 'Không thể resolve domain TikTok',
                'details': f"DNS resolution failed: {str(e)}"
            }
        
        # Use session with retry logic
        from requests.adapters import HTTPAdapter
        from urllib3.util.retry import Retry
        
        session = requests.Session()
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        # Build URL with query parameters for GET request
        import urllib.parse
        query_string = urllib.parse.urlencode(token_data)
        url = f"{Config.TIKTOK_TOKEN_URL}?{query_string}"
        
        response = session.get(
            url,
            headers=headers,
            timeout=(10, 30)  # (connect_timeout, read_timeout)
        )
        
        logger.info(f"Response status code: {response.status_code}")
        logger.info(f"Response headers: {dict(response.headers)}")
        
        if response.status_code == 200:
            token_response = response.json()
            logger.info("Nhận access token thành công")
            
            # Validate response structure - TikTok returns data in data.access_token
            if 'data' in token_response and 'access_token' in token_response['data']:
                # Extract token data from the nested structure
                token_data = token_response['data']
                return {
                    'success': True,
                    'data': token_data,
                    'message': 'Lấy access token thành công'
                }
            elif 'access_token' in token_response:
                # Fallback for direct access_token
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
                        <code>GET /api/signature-demo</code>
                        <p>Demo signature generation</p>
                    </div>
                    <div class="endpoint-item">
                        <code>GET /api/test-signed</code>
                        <p>Test signed API request</p>
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
        return render_oauth_result_page(False, validation_errors, error_description)
    
    # Exchange code for access token
    token_result = exchange_code_for_token(code)
    
    if token_result['success']:
        # Lưu trữ token
        if store_token(token_result['data']):
            return render_oauth_result_page(True, token_result['data'], "OAuth flow hoàn thành thành công")
        else:
            return render_oauth_result_page(False, ["Không thể lưu trữ token"], "")
    else:
        return render_oauth_result_page(False, [token_result['error']], token_result.get('details', ''))

def render_oauth_result_page(success, data, message=""):
    """Render HTML page với kết quả OAuth"""
    
    if success:
        # Success page
        html = f"""
        <!DOCTYPE html>
        <html lang="vi">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>TikTok Shop OAuth - Thành công</title>
            <style>
                * {{
                    margin: 0;
                    padding: 0;
                    box-sizing: border-box;
                }}
                
                body {{
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    min-height: 100vh;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    padding: 20px;
                }}
                
                .container {{
                    background: white;
                    border-radius: 20px;
                    box-shadow: 0 20px 40px rgba(0,0,0,0.1);
                    padding: 40px;
                    max-width: 600px;
                    width: 100%;
                    text-align: center;
                }}
                
                .success-icon {{
                    width: 80px;
                    height: 80px;
                    background: #2A95BF;
                    border-radius: 50%;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    margin: 0 auto 30px;
                }}
                
                .success-icon::before {{
                    content: "✓";
                    color: white;
                    font-size: 40px;
                    font-weight: bold;
                }}
                
                h1 {{
                    color: #333;
                    margin-bottom: 20px;
                    font-size: 28px;
                }}
                
                .message {{
                    color: #666;
                    margin-bottom: 30px;
                    font-size: 16px;
                    line-height: 1.6;
                }}
                
                .token-info {{
                    background: #f8f9fa;
                    border: 1px solid #2A95BF;
                    border-radius: 10px;
                    padding: 20px;
                    margin: 20px 0;
                    text-align: left;
                }}
                
                .token-info h3 {{
                    color: #2A95BF;
                    margin-bottom: 15px;
                    font-size: 18px;
                }}
                
                .info-row {{
                    display: flex;
                    justify-content: space-between;
                    margin-bottom: 10px;
                    padding: 8px 0;
                    border-bottom: 1px solid #eee;
                }}
                
                .info-row:last-child {{
                    border-bottom: none;
                }}
                
                .info-label {{
                    font-weight: 600;
                    color: #555;
                }}
                
                .info-value {{
                    color: #333;
                    word-break: break-all;
                }}
                
                .token-preview {{
                    background: #e3f2fd;
                    border: 1px solid #2A95BF;
                    border-radius: 5px;
                    padding: 10px;
                    font-family: monospace;
                    font-size: 12px;
                    color: #2A95BF;
                    word-break: break-all;
                }}
                
                .signature-info {{
                    background: #f8f9fa;
                    border: 1px solid #2A95BF;
                    border-radius: 10px;
                    padding: 20px;
                    margin: 20px 0;
                    text-align: left;
                }}
                
                .signature-info h3 {{
                    color: #2A95BF;
                    margin-bottom: 15px;
                    font-size: 18px;
                }}
                
                .signature-process {{
                    background: #f8f9fa;
                    border: 1px solid #2A95BF;
                    border-radius: 10px;
                    padding: 20px;
                    margin: 20px 0;
                }}
                
                .signature-process h3 {{
                    color: #2A95BF;
                    margin-bottom: 20px;
                    font-size: 18px;
                }}
                
                .process-steps {{
                    display: flex;
                    flex-direction: column;
                    gap: 15px;
                }}
                
                .step {{
                    display: flex;
                    align-items: flex-start;
                    gap: 15px;
                    background: white;
                    padding: 15px;
                    border-radius: 8px;
                    border-left: 4px solid #2A95BF;
                }}
                
                .step-number {{
                    background: #2A95BF;
                    color: white;
                    width: 30px;
                    height: 30px;
                    border-radius: 50%;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    font-weight: bold;
                    font-size: 14px;
                    flex-shrink: 0;
                }}
                
                .step-content strong {{
                    color: #2A95BF;
                    display: block;
                    margin-bottom: 5px;
                    font-size: 14px;
                }}
                
                .step-content p {{
                    color: #666;
                    font-size: 12px;
                    margin: 0;
                    line-height: 1.4;
                }}
                
                .api-endpoints {{
                    background: #f8f9fa;
                    border: 1px solid #2A95BF;
                    border-radius: 10px;
                    padding: 20px;
                    margin: 20px 0;
                }}
                
                .api-endpoints h3 {{
                    color: #2A95BF;
                    margin-bottom: 20px;
                    font-size: 18px;
                }}
                
                .endpoint-grid {{
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
                    gap: 15px;
                }}
                
                .endpoint-card {{
                    background: white;
                    border-radius: 8px;
                    padding: 15px;
                    display: flex;
                    align-items: center;
                    gap: 15px;
                    border-left: 4px solid #2A95BF;
                }}
                
                .endpoint-method {{
                    background: #2A95BF;
                    color: white;
                    padding: 6px 12px;
                    border-radius: 4px;
                    font-weight: bold;
                    font-size: 12px;
                    min-width: 50px;
                    text-align: center;
                }}
                
                .endpoint-details strong {{
                    color: #2A95BF;
                    display: block;
                    margin-bottom: 5px;
                    font-size: 14px;
                }}
                
                .endpoint-details p {{
                    color: #666;
                    font-size: 12px;
                    margin: 0;
                }}
                
                .next-steps {{
                    background: #f8f9fa;
                    border: 1px solid #2A95BF;
                    border-radius: 10px;
                    padding: 20px;
                    margin: 20px 0;
                }}
                
                .next-steps h3 {{
                    color: #2A95BF;
                    margin-bottom: 15px;
                }}
                
                .next-steps ul {{
                    list-style: none;
                    padding: 0;
                }}
                
                .next-steps li {{
                    padding: 8px 0;
                    color: #2A95BF;
                    position: relative;
                    padding-left: 25px;
                }}
                
                .next-steps li::before {{
                    content: "→";
                    position: absolute;
                    left: 0;
                    color: #2A95BF;
                    font-weight: bold;
                }}
                
                .actions {{
                    margin-top: 30px;
                }}
                
                .btn {{
                    display: inline-block;
                    padding: 12px 24px;
                    margin: 0 10px;
                    border-radius: 25px;
                    text-decoration: none;
                    font-weight: 600;
                    transition: all 0.3s ease;
                    border: none;
                    cursor: pointer;
                    font-size: 14px;
                }}
                
                .btn-primary {{
                    background: #2A95BF;
                    color: white;
                }}
                
                .btn-primary:hover {{
                    background: #1a7a9e;
                    transform: translateY(-2px);
                }}
                
                .btn-secondary {{
                    background: #f8f9fa;
                    color: #666;
                    border: 1px solid #ddd;
                }}
                
                .btn-secondary:hover {{
                    background: #e9ecef;
                    transform: translateY(-2px);
                }}
                
                .timestamp {{
                    color: #999;
                    font-size: 12px;
                    margin-top: 20px;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="success-icon"></div>
                <h1>OAuth Thành Công</h1>
                <p class="message">{message}</p>
                
                <div class="token-info">
                    <h3>Thông Tin Token</h3>
                    <div class="info-row">
                        <span class="info-label">Trạng thái:</span>
                        <span class="info-value">✅ Đã lưu trữ an toàn</span>
                    </div>
                    <div class="info-row">
                        <span class="info-label">Access Token:</span>
                        <span class="info-value">
                            <div class="token-preview">{data.get('access_token', '')}</div>
                        </span>
                    </div>
                    <div class="info-row">
                        <span class="info-label">Token Type:</span>
                        <span class="info-value">{data.get('token_type', 'Bearer')}</span>
                    </div>
                    <div class="info-row">
                        <span class="info-label">Hết hạn:</span>
                        <span class="info-value">{data.get('access_token_expire_in', 'N/A')}</span>
                    </div>
                    <div class="info-row">
                        <span class="info-label">Shop Name:</span>
                        <span class="info-value">{data.get('seller_name', 'N/A')}</span>
                    </div>
                    <div class="info-row">
                        <span class="info-label">Region:</span>
                        <span class="info-value">{data.get('seller_base_region', 'N/A')}</span>
                    </div>
                    <div class="info-row">
                        <span class="info-label">Open ID:</span>
                        <span class="info-value">{data.get('open_id', 'N/A')}</span>
                    </div>
                </div>
                
                <div class="signature-info">
                    <h3>API Signature</h3>
                    <div class="info-row">
                        <span class="info-label">App Key:</span>
                        <span class="info-value">{Config.TIKTOK_CLIENT_KEY}</span>
                    </div>
                    <div class="info-row">
                        <span class="info-label">App Secret:</span>
                        <span class="info-value">
                            <div class="token-preview">{Config.TIKTOK_CLIENT_SECRET}</div>
                        </span>
                    </div>
                    <div class="info-row">
                        <span class="info-label">API Base URL:</span>
                        <span class="info-value">{Config.TIKTOK_API_BASE_URL}</span>
                    </div>
                    <div class="info-row">
                        <span class="info-label">Signature Method:</span>
                        <span class="info-value">HMAC-SHA256</span>
                    </div>
                    <div class="info-row">
                        <span class="info-label">Sample Signature:</span>
                        <span class="info-value">
                            <div class="token-preview">{generate_sample_signature(data.get('access_token', ''))}</div>
                        </span>
                    </div>
                </div>
                
                <div class="next-steps">
                    <h3>Bước Tiếp Theo</h3>
                    <ul>
                        <li>Token đã được lưu trữ an toàn trong session</li>
                        <li>Có thể bắt đầu gọi TikTok Shop API với signature</li>
                        <li>Nhớ refresh token trước khi hết hạn</li>
                        <li>Kiểm tra scopes được cấp quyền</li>
                        <li>Sử dụng HMAC-SHA256 signature cho mọi API call</li>
                    </ul>
                </div>
                
                <div class="signature-process">
                    <h3>Signature Process</h3>
                    <div class="process-steps">
                        <div class="step">
                            <div class="step-number">1</div>
                            <div class="step-content">
                                <strong>Extract Parameters</strong>
                                <p>Lấy tất cả query parameters, loại trừ access_token và sign</p>
                            </div>
                        </div>
                        <div class="step">
                            <div class="step-number">2</div>
                            <div class="step-content">
                                <strong>Sort & Concatenate</strong>
                                <p>Sắp xếp theo alphabet và nối theo format {key}{value}</p>
                            </div>
                        </div>
                        <div class="step">
                            <div class="step-number">3</div>
                            <div class="step-content">
                                <strong>Add Path & Body</strong>
                                <p>Thêm API path và JSON body (nếu có)</p>
                            </div>
                        </div>
                        <div class="step">
                            <div class="step-number">4</div>
                            <div class="step-content">
                                <strong>Wrap with Secret</strong>
                                <p>Bọc string với app_secret ở đầu và cuối</p>
                            </div>
                        </div>
                        <div class="step">
                            <div class="step-number">5</div>
                            <div class="step-content">
                                <strong>HMAC-SHA256</strong>
                                <p>Encode bằng HMAC-SHA256 để tạo signature</p>
                            </div>
                        </div>
                    </div>
                </div>
                
                <div class="api-endpoints">
                    <h3>Available API Endpoints</h3>
                    <div class="endpoint-grid">
                        <div class="endpoint-card">
                            <div class="endpoint-method">GET</div>
                            <div class="endpoint-details">
                                <strong>/api/shop/get_authorized_shop</strong>
                                <p>Lấy thông tin shop đã authorize</p>
                            </div>
                        </div>
                        <div class="endpoint-card">
                            <div class="endpoint-method">GET</div>
                            <div class="endpoint-details">
                                <strong>/api/shop/get_shop_list</strong>
                                <p>Lấy danh sách tất cả shops</p>
                            </div>
                        </div>
                        <div class="endpoint-card">
                            <div class="endpoint-method">GET</div>
                            <div class="endpoint-details">
                                <strong>/api/order/get_order_list</strong>
                                <p>Lấy danh sách orders</p>
                            </div>
                        </div>
                        <div class="endpoint-card">
                            <div class="endpoint-method">GET</div>
                            <div class="endpoint-details">
                                <strong>/api/product/get_product_list</strong>
                                <p>Lấy danh sách products</p>
                            </div>
                        </div>
                    </div>
                </div>
                
                <div class="actions">
                    <a href="/token/info" class="btn btn-primary">Xem Token Info</a>
                    <a href="/api/signature-demo" class="btn btn-primary">Signature Demo</a>
                    <a href="/api/test-signed" class="btn btn-primary">Test API</a>
                    <a href="/" class="btn btn-secondary">Về Trang Chủ</a>
                    <a href="/token/clear" class="btn btn-secondary">Xóa Token</a>
                </div>
                
                <div class="timestamp">
                    Thời gian: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
                </div>
            </div>
        </body>
        </html>
        """
    else:
        # Error page
        error_details = data if isinstance(data, list) else [str(data)]
        html = f"""
        <!DOCTYPE html>
        <html lang="vi">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>TikTok Shop OAuth - Lỗi</title>
            <style>
                * {{
                    margin: 0;
                    padding: 0;
                    box-sizing: border-box;
                }}
                
                body {{
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    background: linear-gradient(135deg, #ff6b6b 0%, #ee5a24 100%);
                    min-height: 100vh;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    padding: 20px;
                }}
                
                .container {{
                    background: white;
                    border-radius: 20px;
                    box-shadow: 0 20px 40px rgba(0,0,0,0.1);
                    padding: 40px;
                    max-width: 600px;
                    width: 100%;
                    text-align: center;
                }}
                
                .error-icon {{
                    width: 80px;
                    height: 80px;
                    background: #ff6b6b;
                    border-radius: 50%;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    margin: 0 auto 30px;
                }}
                
                .error-icon::before {{
                    content: "✗";
                    color: white;
                    font-size: 40px;
                    font-weight: bold;
                }}
                
                h1 {{
                    color: #333;
                    margin-bottom: 20px;
                    font-size: 28px;
                }}
                
                .message {{
                    color: #666;
                    margin-bottom: 30px;
                    font-size: 16px;
                    line-height: 1.6;
                }}
                
                .error-details {{
                    background: #f8f9fa;
                    border: 1px solid #2A95BF;
                    border-radius: 10px;
                    padding: 20px;
                    margin: 20px 0;
                    text-align: left;
                }}
                
                .error-details h3 {{
                    color: #2A95BF;
                    margin-bottom: 15px;
                    font-size: 18px;
                }}
                
                .error-list {{
                    list-style: none;
                    padding: 0;
                }}
                
                .error-list li {{
                    padding: 8px 0;
                    color: #2A95BF;
                    position: relative;
                    padding-left: 25px;
                }}
                
                .error-list li::before {{
                    content: "→";
                    position: absolute;
                    left: 0;
                    color: #2A95BF;
                }}
                
                .actions {{
                    margin-top: 30px;
                }}
                
                .btn {{
                    display: inline-block;
                    padding: 12px 24px;
                    margin: 0 10px;
                    border-radius: 25px;
                    text-decoration: none;
                    font-weight: 600;
                    transition: all 0.3s ease;
                    border: none;
                    cursor: pointer;
                    font-size: 14px;
                }}
                
                .btn-primary {{
                    background: #2A95BF;
                    color: white;
                }}
                
                .btn-primary:hover {{
                    background: #1a7a9e;
                    transform: translateY(-2px);
                }}
                
                .btn-secondary {{
                    background: #f8f9fa;
                    color: #666;
                    border: 1px solid #ddd;
                }}
                
                .btn-secondary:hover {{
                    background: #e9ecef;
                    transform: translateY(-2px);
                }}
                
                .timestamp {{
                    color: #999;
                    font-size: 12px;
                    margin-top: 20px;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="error-icon"></div>
                <h1>OAuth Thất Bại</h1>
                <p class="message">Đã xảy ra lỗi trong quá trình xác thực OAuth</p>
                
                <div class="error-details">
                    <h3>🔍 Chi Tiết Lỗi</h3>
                    <ul class="error-list">
                        {''.join([f'<li>{error}</li>' for error in error_details])}
                    </ul>
                </div>
                
                <div class="actions">
                    <a href="/api/start-oauth" class="btn btn-primary">Thử Lại</a>
                    <a href="/" class="btn btn-secondary">Về Trang Chủ</a>
                </div>
                
                <div class="timestamp">
                    Thời gian: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
                </div>
            </div>
        </body>
        </html>
        """
    
    return html

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
    """Bắt đầu OAuth flow"""
    try:
        # Generate state parameter for CSRF protection
        state = security_manager.generate_state()
        
        # Build OAuth URL
        oauth_url = Config.get_tiktok_auth_url(state)
        
        logger.info(f"Redirecting to OAuth URL: {oauth_url}")
        return redirect(oauth_url)
        
    except Exception as e:
        logger.error(f"Lỗi khi tạo OAuth URL: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Không thể tạo OAuth URL',
            'details': str(e)
        }), 500

@app.route('/api/test-signed')
@rate_limit(max_requests=5, time_window=60)
def test_signed_api():
    """Test signed API request với TikTok Shop API"""
    
    # Kiểm tra xem có access token không
    if 'access_token' not in session:
        return jsonify({
            'success': False,
            'error': 'Chưa có access token. Vui lòng hoàn thành OAuth flow trước.'
        }), 401
    
    try:
        access_token = session['access_token']
        
        # Tạo signed request cho API get_authorized_shop
        signed_request = create_signed_request(
            access_token=access_token,
            app_key=Config.TIKTOK_CLIENT_KEY,
            app_secret=Config.TIKTOK_CLIENT_SECRET,
            endpoint_path='/api/shop/get_authorized_shop',
            params={
                'access_token': access_token
            }
        )
        
        # Thực hiện request
        response = requests.get(
            signed_request['url'],
            headers=signed_request['headers'],
            timeout=(10, 30)
        )
        
        # Parse response
        if response.status_code == 200:
            try:
                api_response = response.json()
                return jsonify({
                    'success': True,
                    'message': 'Signed API request thành công',
                    'signed_request': {
                        'url': signed_request['url'],
                        'signature': signed_request['signature'],
                        'params': signed_request['params'],
                        'headers': signed_request['headers']
                    },
                    'api_response': api_response
                })
            except json.JSONDecodeError:
                return jsonify({
                    'success': False,
                    'error': 'API response không phải JSON',
                    'response_text': response.text[:500]
                }), 400
        else:
            return jsonify({
                'success': False,
                'error': f'API request failed với status {response.status_code}',
                'response_text': response.text[:500],
                'signed_request': {
                    'url': signed_request['url'],
                    'signature': signed_request['signature'],
                    'params': signed_request['params']
                }
            }), response.status_code
            
    except Exception as e:
        logger.error(f"Lỗi khi test signed API: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Lỗi khi thực hiện signed API request',
            'details': str(e)
        }), 500

@app.route('/api/signature-demo')
@rate_limit(max_requests=10, time_window=60)
def signature_demo():
    """Demo signature generation với giao diện đẹp"""
    
    # Kiểm tra xem có access token không
    if 'access_token' not in session:
        return """
        <!DOCTYPE html>
        <html lang="vi">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Signature Demo - Cần OAuth</title>
            <style>
                body {
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    background: linear-gradient(135deg, #ff6b6b 0%, #ee5a24 100%);
                    min-height: 100vh;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    padding: 20px;
                }
                .container {
                    background: white;
                    border-radius: 20px;
                    padding: 40px;
                    text-align: center;
                    box-shadow: 0 20px 40px rgba(0,0,0,0.1);
                }
                .btn {
                    display: inline-block;
                    padding: 12px 24px;
                    background: #2A95BF;
                    color: white;
                    text-decoration: none;
                    border-radius: 25px;
                    font-weight: 600;
                    margin: 10px;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>🔐 Signature Demo</h1>
                <p>Bạn cần hoàn thành OAuth flow trước để xem signature demo.</p>
                <a href="/api/start-oauth" class="btn">🚀 Bắt Đầu OAuth</a>
                <a href="/" class="btn">🏠 Về Trang Chủ</a>
            </div>
        </body>
        </html>
        """
    
    try:
        access_token = session['access_token']
        
        # Tạo signed request cho demo
        signed_request = create_signed_request(
            access_token=access_token,
            app_key=Config.TIKTOK_CLIENT_KEY,
            app_secret=Config.TIKTOK_CLIENT_SECRET,
            endpoint_path='/api/shop/get_authorized_shop',
            params={
                'access_token': access_token
            }
        )
        
        return f"""
        <!DOCTYPE html>
        <html lang="vi">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Signature Demo - TikTok Shop API</title>
            <style>
                * {{
                    margin: 0;
                    padding: 0;
                    box-sizing: border-box;
                }}
                
                body {{
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    min-height: 100vh;
                    padding: 20px;
                }}
                
                .container {{
                    max-width: 1200px;
                    margin: 0 auto;
                    background: white;
                    border-radius: 20px;
                    box-shadow: 0 20px 40px rgba(0,0,0,0.1);
                    overflow: hidden;
                }}
                
                .header {{
                    background: #2A95BF;
                    color: white;
                    padding: 30px;
                    text-align: center;
                }}
                
                .header h1 {{
                    font-size: 2rem;
                    margin-bottom: 10px;
                }}
                
                .content {{
                    padding: 30px;
                }}
                
                .section {{
                    margin-bottom: 30px;
                    background: #f8f9fa;
                    border-radius: 10px;
                    padding: 20px;
                }}
                
                .section h2 {{
                    color: #333;
                    margin-bottom: 15px;
                    font-size: 1.3rem;
                }}
                
                .code-block {{
                    background: #2d3748;
                    color: #e2e8f0;
                    padding: 15px;
                    border-radius: 8px;
                    font-family: 'Courier New', monospace;
                    font-size: 14px;
                    overflow-x: auto;
                    margin: 10px 0;
                }}
                
                .param-grid {{
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
                    gap: 15px;
                    margin: 15px 0;
                }}
                
                .param-item {{
                    background: white;
                    padding: 15px;
                    border-radius: 8px;
                    border-left: 4px solid #2A95BF;
                }}
                
                .param-label {{
                    font-weight: bold;
                    color: #333;
                    margin-bottom: 5px;
                }}
                
                .param-value {{
                    color: #666;
                    word-break: break-all;
                    font-family: monospace;
                    font-size: 12px;
                }}
                
                .signature-highlight {{
                    background: #fff3e0;
                    border: 2px solid #ff9800;
                    border-radius: 8px;
                    padding: 15px;
                    margin: 15px 0;
                }}
                
                .signature-highlight .param-value {{
                    color: #e65100;
                    font-weight: bold;
                    font-size: 14px;
                }}
                
                .actions {{
                    text-align: center;
                    margin-top: 30px;
                }}
                
                .btn {{
                    display: inline-block;
                    padding: 12px 24px;
                    margin: 0 10px;
                    border-radius: 25px;
                    text-decoration: none;
                    font-weight: 600;
                    transition: all 0.3s ease;
                }}
                
                .btn-primary {{
                    background: #2A95BF;
                    color: white;
                }}
                
                .btn-primary:hover {{
                    background: #1a7a9e;
                    transform: translateY(-2px);
                }}
                
                .btn-secondary {{
                    background: #f8f9fa;
                    color: #666;
                    border: 1px solid #ddd;
                }}
                
                .btn-secondary:hover {{
                    background: #e9ecef;
                    transform: translateY(-2px);
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🔐 TikTok Shop API Signature Demo</h1>
                    <p>HMAC-SHA256 Signature Generation theo tài liệu chính thức</p>
                </div>
                
                <div class="content">
                    <div class="section">
                        <h2>📋 Request Parameters</h2>
                        <div class="param-grid">
                            <div class="param-item">
                                <div class="param-label">App Key</div>
                                <div class="param-value">{Config.TIKTOK_CLIENT_KEY}</div>
                            </div>
                            <div class="param-item">
                                <div class="param-label">Timestamp</div>
                                <div class="param-value">{signed_request['params']['timestamp']}</div>
                            </div>
                            <div class="param-item">
                                <div class="param-label">Version</div>
                                <div class="param-value">{signed_request['params']['version']}</div>
                            </div>
                            <div class="param-item">
                                <div class="param-label">Shop ID</div>
                                <div class="param-value">{signed_request['params']['shop_id']}</div>
                            </div>
                            <div class="param-item">
                                <div class="param-label">Access Token</div>
                                <div class="param-value">{access_token[:20]}...</div>
                            </div>
                        </div>
                    </div>
                    
                    <div class="section">
                        <h2>🔐 Generated Signature</h2>
                        <div class="signature-highlight">
                            <div class="param-label">HMAC-SHA256 Signature:</div>
                            <div class="param-value">{signed_request['signature']}</div>
                        </div>
                    </div>
                    
                    <div class="section">
                        <h2>🌐 Final Request URL</h2>
                        <div class="code-block">{signed_request['url']}</div>
                    </div>
                    
                    <div class="section">
                        <h2>📝 Request Headers</h2>
                        <div class="code-block">
{chr(10).join([f'{k}: {v}' for k, v in signed_request['headers'].items()])}
                        </div>
                    </div>
                    
                    <div class="section">
                        <h2>🔗 API Documentation</h2>
                        <p>Signature generation tuân theo tài liệu chính thức của TikTok Shop Partner API:</p>
                        <div class="code-block">
                            <a href="https://partner.tiktokshop.com/docv2/page/sign-your-api-request" 
                               target="_blank" style="color: #2A95BF;">
                                https://partner.tiktokshop.com/docv2/page/sign-your-api-request
                            </a>
                        </div>
                    </div>
                    
                    <div class="actions">
                        <a href="/api/test-signed" class="btn btn-primary">🚀 Test API Request</a>
                        <a href="/token/info" class="btn btn-secondary">📊 Token Info</a>
                        <a href="/" class="btn btn-secondary">🏠 Về Trang Chủ</a>
                    </div>
                </div>
            </div>
        </body>
        </html>
        """
        
    except Exception as e:
        logger.error(f"Lỗi khi tạo signature demo: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Lỗi khi tạo signature demo',
            'details': str(e)
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