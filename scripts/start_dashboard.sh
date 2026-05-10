#!/bin/bash
# ============================================
# Start Dashboard Script - تشغيل لوحة التحكم
# ============================================

set -e

echo "📊 HunterMind - Starting Dashboard"
echo "=================================="

# تفعيل البيئة الافتراضية
source venv/bin/activate

echo ""
echo "Starting Dashboard on http://localhost:5000"
echo "Starting Realtime Monitor on http://localhost:5001"
echo "Starting Attack Visualizer on http://localhost:5002"
echo "Starting Cognitive Visualizer on http://localhost:5003"
echo ""
echo "Press Ctrl+C to stop all..."

# تشغيل جميع مكونات لوحة التحكم
python interfaces/dashboard/dashboard_server.py &
python interfaces/dashboard/realtime_monitor.py &
python interfaces/dashboard/attack_visualizer.py &
python interfaces/dashboard/cognitive_visualizer.py &

# انتظار إشارة الإيقاف
trap 'kill $(jobs -p); echo ""; echo "✅ Dashboard stopped"; exit 0' INT

wait
