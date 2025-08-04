# TikTok Shop OAuth Configuration Template
# Copy this file to .env and fill in your actual values

# TikTok Shop API Credentials (required)
TIKTOK_CLIENT_KEY=6h2cosrqj39gj
TIKTOK_CLIENT_SECRET=your_tiktok_client_secret_here
TIKTOK_REDIRECT_URI=https://tiktok.truongvinhkhuong.io.vn/callback

# Flask Application Settings
FLASK_SECRET_KEY=your_flask_secret_key_here_use_strong_random_string
FLASK_HOST=0.0.0.0
FLASK_PORT=5000
FLASK_DEBUG=false
USE_SSL=true

# Optional: Database for token storage
# Uncomment and configure if you want to store tokens in database
# DATABASE_URL=postgresql://username:password@localhost:5432/tiktok_oauth
# DATABASE_URL=mysql://username:password@localhost:3306/tiktok_oauth
# DATABASE_URL=sqlite:///tiktok_oauth.db