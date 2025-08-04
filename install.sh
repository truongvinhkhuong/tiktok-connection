#!/bin/bash

# TikTok Shop OAuth Callback - Installation Script
echo "🚀 Installing TikTok Shop OAuth Callback Application..."

# Check Python version
python_version=$(python3 --version 2>&1 | grep -o '[0-9]\+\.[0-9]\+' | head -1)
if [[ $(echo "$python_version >= 3.8" | bc -l) -ne 1 ]]; then
    echo "❌ Python 3.8+ required. Current version: $python_version"
    exit 1
fi

echo "✅ Python version: $python_version"

# Create virtual environment
echo "📦 Creating virtual environment..."
python3 -m venv venv
source venv/bin/activate

# Upgrade pip
echo "⬆️  Upgrading pip..."
pip install --upgrade pip

# Install dependencies
echo "📥 Installing dependencies..."
pip install -r requirements.txt

# Copy environment config
if [ ! -f .env ]; then
    echo "⚙️  Setting up environment configuration..."
    cp env_config.py .env
    echo "✅ Created .env file from template"
    echo "⚠️  Please edit .env file with your TikTok Shop credentials before running"
else
    echo "✅ .env file already exists"
fi

# Create logs directory
mkdir -p logs
echo "✅ Created logs directory"

# Set permissions
chmod +x run.py
chmod +x install.sh

echo ""
echo "🎉 Installation completed successfully!"
echo ""
echo "📋 Next steps:"
echo "1. Edit .env file with your TikTok Shop credentials:"
echo "   - TIKTOK_CLIENT_SECRET"
echo "   - TIKTOK_REDIRECT_URI (if different from default)"
echo ""
echo "2. Activate virtual environment:"
echo "   source venv/bin/activate"
echo ""
echo "3. Run the application:"
echo "   python run.py"
echo "   # or"
echo "   python app.py"
echo ""
echo "4. Visit: http://localhost:5000"
echo ""
echo "📚 For more information, see README.md"