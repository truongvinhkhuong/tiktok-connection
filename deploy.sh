#!/bin/bash

# TikTok Shop OAuth Callback - Production Deployment Script
# Domain: tiktok.truongvinhkhuong.io.vn
# Server IP: 14.225.207.95

set -e

echo "🚀 Deploying TikTok Shop OAuth Callback to Production..."
echo "📍 Domain: tiktok.truongvinhkhuong.io.vn"
echo "🌐 Server IP: 14.225.207.95"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
DOMAIN="tiktok.truongvinhkhuong.io.vn"
SERVER_IP="14.225.207.95"
APP_DIR="/opt/tiktok-oauth"
SERVICE_NAME="tiktok-oauth"
FLASK_PORT="5001"

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    print_error "Please run as root (use sudo)"
    exit 1
fi

# Update system
print_status "Updating system packages..."
apt update && apt upgrade -y

# Install dependencies
print_status "Installing required packages..."
apt install -y python3 python3-pip python3-venv nginx certbot python3-certbot-nginx ufw git supervisor

# Create application directory
print_status "Setting up application directory..."
mkdir -p $APP_DIR
cd $APP_DIR

# Clone or update application
if [ -d ".git" ]; then
    print_status "Updating existing repository..."
    git pull origin master
else
    print_status "Cloning repository..."
    git clone https://github.com/truongvinhkhuong/tiktok-connection.git .
fi

# Create virtual environment
print_status "Setting up Python virtual environment..."
python3 -m venv venv
source venv/bin/activate

# Install Python dependencies
print_status "Installing Python dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

# Create .env file if not exists
if [ ! -f ".env" ]; then
    print_warning ".env file not found. Creating from template..."
    cp env_config.py .env
    print_warning "Please edit .env file with your actual TikTok Shop credentials:"
    print_warning "nano $APP_DIR/.env"
fi

# Create application user
print_status "Creating application user..."
if ! id "tiktok" &>/dev/null; then
    useradd -r -s /bin/false -d $APP_DIR tiktok
fi

# Set Flask port in environment
export FLASK_PORT=$FLASK_PORT

# Set permissions
print_status "Setting file permissions..."
chown -R tiktok:tiktok $APP_DIR
chmod +x $APP_DIR/run.py

# Configure Supervisor for process management
print_status "Setting up Supervisor configuration..."
cat > /etc/supervisor/conf.d/tiktok-oauth.conf << EOF
[program:tiktok-oauth]
command=$APP_DIR/venv/bin/python $APP_DIR/run.py
directory=$APP_DIR
user=tiktok
autostart=true
autorestart=true
redirect_stderr=true
stdout_logfile=/var/log/tiktok-oauth.log
environment=FLASK_ENV=production,USE_SSL=false
EOF

# Configure Nginx
print_status "Setting up Nginx configuration..."
cp nginx.conf /etc/nginx/nginx.conf

# Test Nginx configuration
print_status "Testing Nginx configuration..."
nginx -t

# Configure firewall
print_status "Configuring firewall..."
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh
ufw allow 80/tcp
ufw allow 443/tcp
ufw --force enable

# Create SSL certificate directory
print_status "Creating SSL certificate directory..."
mkdir -p /etc/nginx/ssl

# Get SSL certificate with Certbot
print_status "Setting up SSL certificate..."
if [ ! -f "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" ]; then
    print_status "Obtaining SSL certificate from Let's Encrypt..."
    certbot certonly --nginx -d $DOMAIN --non-interactive --agree-tos --email admin@truongvinhkhuong.io.vn
    
    # Link certificates
    ln -sf /etc/letsencrypt/live/$DOMAIN/fullchain.pem /etc/nginx/ssl/$DOMAIN.crt
    ln -sf /etc/letsencrypt/live/$DOMAIN/privkey.pem /etc/nginx/ssl/$DOMAIN.key
else
    print_status "SSL certificate already exists"
fi

# Create log directory
print_status "Creating log directories..."
mkdir -p /var/log/nginx
mkdir -p $APP_DIR/logs
chown tiktok:tiktok $APP_DIR/logs

# Start services
print_status "Starting services..."
systemctl enable supervisor
systemctl restart supervisor
supervisorctl reread
supervisorctl update
supervisorctl start tiktok-oauth

systemctl enable nginx
systemctl restart nginx

# Setup automatic SSL renewal
print_status "Setting up automatic SSL certificate renewal..."
(crontab -l 2>/dev/null; echo "0 12 * * * /usr/bin/certbot renew --quiet") | crontab -

# Create backup script
print_status "Creating backup script..."
cat > /opt/backup-tiktok-oauth.sh << 'EOF'
#!/bin/bash
BACKUP_DIR="/opt/backups"
DATE=$(date +%Y%m%d_%H%M%S)
mkdir -p $BACKUP_DIR

# Backup application
tar -czf $BACKUP_DIR/tiktok-oauth-$DATE.tar.gz -C /opt/tiktok-oauth .

# Keep only last 7 backups
find $BACKUP_DIR -name "tiktok-oauth-*.tar.gz" -mtime +7 -delete

echo "Backup completed: $BACKUP_DIR/tiktok-oauth-$DATE.tar.gz"
EOF

chmod +x /opt/backup-tiktok-oauth.sh

# Setup daily backup
(crontab -l 2>/dev/null; echo "0 2 * * * /opt/backup-tiktok-oauth.sh") | crontab -

# Display status
print_status "Checking service status..."
supervisorctl status tiktok-oauth
systemctl status nginx --no-pager -l

print_status "Deployment completed successfully! 🎉"
echo ""
echo "📋 Deployment Summary:"
echo "  🌐 Domain: https://$DOMAIN"
echo "  📁 App Directory: $APP_DIR"
echo "  📄 Logs: /var/log/tiktok-oauth.log"
echo "  🔧 Config: /etc/supervisor/conf.d/tiktok-oauth.conf"
echo "  📊 Nginx Config: /etc/nginx/nginx.conf"
echo ""
echo "🔧 Management Commands:"
echo "  📊 Check app status: supervisorctl status tiktok-oauth"
echo "  🔄 Restart app: supervisorctl restart tiktok-oauth"
echo "  📝 View logs: tail -f /var/log/tiktok-oauth.log"
echo "  🌐 Test Nginx: nginx -t"
echo "  🔄 Reload Nginx: systemctl reload nginx"
echo ""
echo "🚨 Important Next Steps:"
echo "  1. Edit $APP_DIR/.env with your TikTok Shop credentials"
echo "  2. Test the OAuth flow: https://$DOMAIN"
echo "  3. Monitor logs for any issues"
echo ""
echo "✅ Your TikTok Shop OAuth callback is now live at:"
echo "   🔗 https://$DOMAIN/callback"