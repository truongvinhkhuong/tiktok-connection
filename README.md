# TikTok Shop OAuth Callback Application

Ứng dụng Flask xử lý OAuth callback từ TikTok Shop Partner API một cách chính xác và bảo mật.

## ✨ Tính năng

- OAuth flow hoàn chỉnh với TikTok Shop Partner API
- Bảo mật: Rate limiting, CSRF protection, input validation
- Logging chi tiết cho debugging và monitoring
- Cấu hình linh hoạt với environment variables
- Error handling toàn diện
- Token management và storage
- Hỗ trợ HTTPS và HTTP

## Cài đặt nhanh

### 1. Clone và cài đặt dependencies

```bash
git clone <repository-url>
cd tiktok-connection
pip install -r requirements.txt
```

### 2. Cấu hình environment variables

```bash
# Copy file cấu hình mẫu
cp env_config.py .env

# Chỉnh sửa .env với thông tin thực tế
nano .env
```

### 3. Cấu hình TikTok Shop App

Trong file `.env`, cập nhật:

```env
TIKTOK_CLIENT_KEY=your_actual_client_key
TIKTOK_CLIENT_SECRET=your_actual_client_secret
TIKTOK_REDIRECT_URI=https://yourdomain.com/callback
```

### 4. Chạy ứng dụng

```bash
# Development mode
python app.py

# Production mode với Gunicorn
gunicorn -w 4 -b 0.0.0.0:5001 app:app --certfile=cert.pem --keyfile=key.pem
```

## 📋 Cấu hình chi tiết

### Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `TIKTOK_CLIENT_KEY` | ✅ | - | Client key từ TikTok Shop Partner |
| `TIKTOK_CLIENT_SECRET` | ✅ | - | Client secret từ TikTok Shop Partner |
| `TIKTOK_REDIRECT_URI` | ✅ | - | Callback URL đã đăng ký |
| `FLASK_SECRET_KEY` | ⚠️ | random | Secret key cho Flask sessions |
| `FLASK_HOST` | ❌ | 0.0.0.0 | Host để bind server |
| `FLASK_PORT` | ❌ | 5001 | Port để chạy server |
| `FLASK_DEBUG` | ❌ | false | Enable debug mode |
| `USE_SSL` | ❌ | true | Sử dụng HTTPS |

### TikTok Shop API Endpoints

Application sử dụng các endpoints sau:

- **Authorization URL**: `https://partner.tiktokshop.com/authorization/oauth/auth`
- **Token URL**: `https://partner-api.tiktokshop.com/authorization/v1/token`
- **API Base**: `https://partner-api.tiktokshop.com`

## 🔗 API Endpoints

### `GET /`
Trang chủ với thông tin cấu hình

### `GET /callback`
OAuth callback endpoint - xử lý response từ TikTok Shop

**Parameters:**
- `code` (string): Authorization code từ TikTok
- `state` (string): State parameter để chống CSRF
- `error` (string): Error code nếu có lỗi

**Response:**
```json
{
  \"success\": true,
  \"message\": \"OAuth flow hoàn thành thành công\",
  \"token_info\": {
    \"access_token\": \"tat_xxx...\",
    \"token_type\": \"Bearer\",
    \"expires_in\": 3600,
    \"scope\": \"user.info.basic\",
    \"received_at\": \"2024-01-15T10:30:00\"
  }
}
```

### `GET /token/info`
Hiển thị thông tin token hiện tại (debug endpoint)

### `GET /token/clear`
Xóa token khỏi session (debug endpoint)

## 🔒 Bảo mật

### CSRF Protection
- Sử dụng `state` parameter để chống CSRF attacks
- State được generate random và lưu trong session
- Validate state khi nhận callback

### Rate Limiting
- Giới hạn 10 requests/5 phút cho mỗi IP
- Tự động block IP nếu vi phạm
- Log các security events

### Input Validation
- Sanitize tất cả input parameters
- Validate format của authorization code
- Check content-type cho POST requests

### HTTPS Enforcement
- Require HTTPS cho production
- Redirect HTTP requests nếu cần
- Validate SSL certificates

## 📊 Logging

Application ghi log chi tiết:

- OAuth flow events
- Security violations
- API calls và responses
- Error conditions
- Performance metrics

Log files: `tiktok_oauth.log`

## 🛠️ Development

### Cấu trúc dự án

```
tiktok-connection/
├── app.py              # Main Flask application
├── config.py           # Configuration management
├── security.py         # Security utilities
├── requirements.txt    # Python dependencies
├── env_config.py       # Environment config template
├── README.md          # Documentation
└── tiktok_oauth.log   # Log file
```

### Testing

```bash
# Test OAuth flow
curl -X GET \"http://localhost:5001/callback?code=test_code&state=test_state\"

# Test rate limiting
for i in {1..15}; do curl -X GET \"http://localhost:5001/\"; done
```

## 🚀 Production Deployment

### Với Gunicorn

```bash
# Cài đặt Gunicorn
pip install gunicorn

# Chạy với SSL
gunicorn -w 4 -b 0.0.0.0:5001 app:app \\
  --certfile=/path/to/cert.pem \\
  --keyfile=/path/to/key.pem \\
  --access-logfile=/var/log/tiktok-oauth-access.log \\
  --error-logfile=/var/log/tiktok-oauth-error.log
```

### Với Docker

```dockerfile
FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

EXPOSE 5001
CMD [\"gunicorn\", \"-w\", \"4\", \"-b\", \"0.0.0.0:5001\", \"app:app\"]
```

### Với Nginx Reverse Proxy

```nginx
server {
    listen 443 ssl;
    server_name yourdomain.com;
    
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;
    
    location / {
        proxy_pass http://127.0.0.1:5001;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

## ❗ Troubleshooting

### Lỗi thường gặp

1. **\"Missing required environment variables\"**
   - Kiểm tra file `.env` có đầy đủ thông tin
   - Đảm bảo `TIKTOK_CLIENT_SECRET` được set

2. **\"Invalid authorization code\"**
   - Code chỉ sử dụng được 1 lần
   - Check redirect URI có đúng không
   - Kiểm tra client credentials

3. **\"SSL required\"**
   - Set `USE_SSL=false` cho development
   - Cấu hình SSL certificate cho production

4. **\"Rate limit exceeded\"**
   - Đợi 5 phút hoặc restart app
   - Kiểm tra IP có bị block không

## 📞 Hỗ trợ

- TikTok Shop Partner Center: https://partner.tiktokshop.com
- API Documentation: https://partner.tiktokshop.com/docv2/
- GitHub Issues: [Create an issue](../../issues)

## 📄 License

MIT License - xem file LICENSE để biết thêm chi tiết.