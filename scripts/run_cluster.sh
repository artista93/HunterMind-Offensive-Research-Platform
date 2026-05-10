#!/bin/bash
# ============================================
# Run Cluster Script - تشغيل النظام الموزع
# ============================================

set -e

echo "🚀 HunterMind - Starting Distributed Cluster"
echo "============================================"

# تفعيل البيئة الافتراضية
source venv/bin/activate

# بدء المكونات المختلفة
echo ""
echo "📡 Starting components..."

# بدء API Server
echo "  - Starting API Server on port 8000..."
python interfaces/api/fastapi_server.py &
API_PID=$!

# بدء WebSocket Server
echo "  - Starting WebSocket Server on port 8001..."
python interfaces/api/websocket_api.py &
WS_PID=$!

# بدء Dashboard
echo "  - Starting Dashboard on port 5000..."
python interfaces/dashboard/dashboard_server.py &
DASHBOARD_PID=$!

# بدء Realtime Monitor
echo "  - Starting Realtime Monitor on port 5001..."
python interfaces/dashboard/realtime_monitor.py &
MONITOR_PID=$!

# بدء Attack Visualizer
echo "  - Starting Attack Visualizer on port 5002..."
python interfaces/dashboard/attack_visualizer.py &
VISUALIZER_PID=$!

# بدء Cognitive Visualizer
echo "  - Starting Cognitive Visualizer on port 5003..."
python interfaces/dashboard/cognitive_visualizer.py &
COGNITIVE_PID=$!

echo ""
echo "✅ All components started!"
echo ""
echo "📊 Access Points:"
echo "   - API: http://localhost:8000"
echo "   - WebSocket: ws://localhost:8001"
echo "   - Dashboard: http://localhost:5000"
echo "   - Monitor: http://localhost:5001"
echo "   - Attack Visualizer: http://localhost:5002"
echo "   - Cognitive Visualizer: http://localhost:5003"
echo ""
echo "Press Ctrl+C to stop all components..."

# انتظار إشارة الإيقاف
trap 'kill $API_PID $WS_PID $DASHBOARD_PID $MONITOR_PID $VISUALIZER_PID $COGNITIVE_PID; echo ""; echo "✅ All components stopped"; exit 0' INT

# انتظار
wait
