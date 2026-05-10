#!/bin/bash
# ============================================
# Bootstrap Script - التثبيت الأولي للمنصة
# ============================================

set -e

echo "🦅 HunterMind Platform - Bootstrap Script"
echo "============================================"
echo ""

# الألوان
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# التحقق من Python
echo "📌 Checking Python version..."
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 --version)
    echo -e "${GREEN}✓${NC} $PYTHON_VERSION"
else
    echo -e "${RED}✗ Python3 not found. Please install Python 3.9+${NC}"
    exit 1
fi

# إنشاء البيئة الافتراضية
echo ""
echo "📌 Creating virtual environment..."
if [ ! -d "venv" ]; then
    python3 -m venv venv
    echo -e "${GREEN}✓ Virtual environment created${NC}"
else
    echo -e "${YELLOW}⚠ Virtual environment already exists${NC}"
fi

# تفعيل البيئة الافتراضية
source venv/bin/activate

# تثبيت المتطلبات
echo ""
echo "📌 Installing dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

# تثبيت Playwright
echo ""
echo "📌 Installing Playwright browsers..."
playwright install chromium
playwright install firefox

# إنشاء المجلدات اللازمة
echo ""
echo "📌 Creating required directories..."
mkdir -p logs
mkdir -p storage/sqlite
mkdir -p storage/vector_db
mkdir -p storage/graph_db
mkdir -p storage/object_storage
mkdir -p storage/checkpoints
mkdir -p offensive/payloads/data
mkdir -p telemetry/logs

# نسخ ملف الإعدادات إذا لم يكن موجوداً
if [ ! -f "config.yaml" ]; then
    cp config.example.yaml config.yaml 2>/dev/null || echo "config.yaml not found, creating default..."
fi

echo ""
echo -e "${GREEN}============================================${NC}"
echo -e "${GREEN}✅ Bootstrap completed successfully!${NC}"
echo -e "${GREEN}============================================${NC}"
echo ""
echo "Next steps:"
echo "  1. Activate environment: source venv/bin/activate"
echo "  2. Run CLI: python cli.py"
echo "  3. Start API: python interfaces/api/fastapi_server.py"
echo "  4. Start Dashboard: python interfaces/dashboard/dashboard_server.py"
echo ""
