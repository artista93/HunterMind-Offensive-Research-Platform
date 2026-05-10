#!/bin/bash
# ============================================
# Install Script - تثبيت المنصة
# ============================================

set -e

echo "🦅 HunterMind Platform - Installation"
echo "====================================="
echo ""

# الألوان
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# التحقق من Python
echo "📌 Checking Python version..."
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 --version)
    echo -e "${GREEN}✓${NC} $PYTHON_VERSION"
else
    echo "❌ Python3 not found. Please install Python 3.9+"
    exit 1
fi

# التحقق من Docker (اختياري)
echo ""
echo "📌 Checking Docker..."
if command -v docker &> /dev/null; then
    DOCKER_VERSION=$(docker --version)
    echo -e "${GREEN}✓${NC} $DOCKER_VERSION"
else
    echo -e "${YELLOW}⚠ Docker not found (optional for sandbox)${NC}"
fi

# إنشاء البيئة الافتراضية
echo ""
echo "📌 Creating virtual environment..."
python3 -m venv venv
source venv/bin/activate

# تثبيت في وضع التطوير
echo ""
echo "📌 Installing HunterMind..."
pip install --upgrade pip
pip install -e .

# تثبيت Playwright
echo ""
echo "📌 Installing Playwright browsers..."
playwright install chromium

# إنشاء المجلدات
echo ""
echo "📌 Creating directories..."
mkdir -p logs
mkdir -p storage/sqlite
mkdir -p storage/vector_db
mkdir -p storage/graph_db
mkdir -p storage/object_storage
mkdir -p storage/checkpoints

echo ""
echo -e "${GREEN}✅ Installation completed successfully!${NC}"
echo ""
echo "To activate the environment:"
echo "  source venv/bin/activate"
echo ""
echo "To run the CLI:"
echo "  python cli.py"
echo ""
echo "To run the API server:"
echo "  python interfaces/api/fastapi_server.py"
echo ""
