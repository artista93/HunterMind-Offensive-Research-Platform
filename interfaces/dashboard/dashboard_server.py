"""
Dashboard Server - لوحة تحكم متكاملة مع Orchestrator و Event Bus
"""

from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from typing import Dict, List, Optional, Any
from datetime import datetime
import uvicorn
import os
import asyncio
import psutil

import logging

logger = logging.getLogger(__name__)

# إنشاء تطبيق FastAPI
app = FastAPI(title="HunterMind Dashboard", version="1.0.0")

# إعداد القوالب
templates = Jinja2Templates(directory="interfaces/dashboard/templates")

# إنشاء مجلد القوالب إذا لم يكن موجوداً
os.makedirs("interfaces/dashboard/templates", exist_ok=True)

# وقت بدء التشغيل
startup_time = datetime.now()

# اتصالات WebSocket النشطة
active_websockets = set()


class DashboardDataManager:
    """
    مدير بيانات Dashboard المتزامن مع Orchestrator و Event Bus
    """
    
    def __init__(self):
        self.stats = {
            "total_scans": 0,
            "total_vulnerabilities": 0,
            "active_scans": 0,
            "successful_attacks": 0,
            "system_load": 0.0,
            "uptime": 0
        }
        self.recent_scans = []
        self.recent_vulnerabilities = []
        self.system_status = {
            "cpu": 0,
            "memory": 0,
            "disk": 0
        }
        self._orchestrator = None
        self._event_bus = None
        self._initialized = False
    
    async def initialize(self):
        """تهيئة المدير والاتصال بـ Orchestrator و Event Bus"""
        if self._initialized:
            return
        
        try:
            # الاتصال بـ Orchestrator
            from orchestration.orchestrator import get_orchestrator
            self._orchestrator = await get_orchestrator()
            
            # الاتصال بـ Event Bus
            from orchestration.messaging.event_bus import get_event_bus, EventType
            self._event_bus = await get_event_bus()
            
            # الاشتراك في الأحداث
            await self._event_bus.subscribe(EventType.TASK_COMPLETE, self._on_task_complete)
            await self._event_bus.subscribe(EventType.DATA_VULNERABILITY, self._on_vulnerability)
            await self._event_bus.subscribe(EventType.SYSTEM_START, self._on_system_start)
            
            # تحميل البيانات التاريخية
            await self._load_historical_data()
            
            self._initialized = True
            logger.info("Dashboard connected to Orchestrator and Event Bus")
            
        except Exception as e:
            logger.warning(f"Could not connect to Orchestrator: {e}")
            logger.info("Dashboard running in standalone mode")
    
    async def _load_historical_data(self):
        """تحميل البيانات التاريخية من Orchestrator"""
        if not self._orchestrator:
            return
        
        try:
            # تحميل الفحوصات
            scans = await self._orchestrator.list_scans()
            self.stats["total_scans"] = len(scans)
            self.recent_scans = [
                {
                    "status": "completed",
                    "target_url": s.get("target", ""),
                    "scan_type": "full",
                    "findings_count": s.get("findings_count", 0),
                    "timestamp": s.get("date", datetime.now().isoformat())
                }
                for s in scans[-10:]
            ]
            
            # تحميل الثغرات
            vulns = await self._orchestrator.list_vulnerabilities()
            self.stats["total_vulnerabilities"] = len(vulns)
            self.recent_vulnerabilities = [
                {
                    "severity": v.get("severity", "info"),
                    "type": v.get("type", "Unknown"),
                    "url": v.get("url", ""),
                    "parameter": v.get("parameter"),
                    "timestamp": v.get("discovered_at", datetime.now().isoformat())
                }
                for v in vulns[-20:]
            ]
            
        except Exception as e:
            logger.error(f"Failed to load historical data: {e}")
    
    async def _on_task_complete(self, event):
        """معالجة حدث اكتمال المهمة"""
        data = event.data
        self.stats["total_scans"] += 1
        self.stats["active_scans"] = max(0, self.stats["active_scans"] - 1)
        
        scan_entry = {
            "status": "completed",
            "target_url": data.get("target", ""),
            "scan_type": data.get("type", "full"),
            "findings_count": data.get("findings_count", 0),
            "timestamp": datetime.now().isoformat()
        }
        self.recent_scans.insert(0, scan_entry)
        self.recent_scans = self.recent_scans[:10]
        
        # بث التحديث لجميع عملاء WebSocket
        await self._broadcast({
            "type": "scan_complete",
            "data": scan_entry
        })
    
    async def _on_vulnerability(self, event):
        """معالجة حدث اكتشاف ثغرة"""
        data = event.data
        self.stats["total_vulnerabilities"] += 1
        
        vuln_entry = {
            "severity": data.get("severity", "info"),
            "type": data.get("type", "Unknown"),
            "url": data.get("url", ""),
            "parameter": data.get("parameter"),
            "timestamp": datetime.now().isoformat()
        }
        self.recent_vulnerabilities.insert(0, vuln_entry)
        self.recent_vulnerabilities = self.recent_vulnerabilities[:20]
        
        # بث التحديث
        await self._broadcast({
            "type": "vulnerability_found",
            "data": vuln_entry
        })
    
    async def _on_system_start(self, event):
        """معالجة حدث بدء النظام"""
        logger.info("System start event received")
        await self._load_historical_data()
    
    async def _broadcast(self, message: dict):
        """بث رسالة لجميع عملاء WebSocket"""
        for websocket in active_websockets:
            try:
                await websocket.send_json(message)
            except Exception:
                pass
    
    async def update_system_metrics(self):
        """تحديث مقاييس النظام"""
        try:
            self.system_status["cpu"] = psutil.cpu_percent(interval=0.5)
            self.system_status["memory"] = psutil.virtual_memory().percent
            self.system_status["disk"] = psutil.disk_usage('/').percent
        except Exception:
            pass
        
        # تحديث وقت التشغيل
        uptime = (datetime.now() - startup_time).total_seconds()
        self.stats["uptime"] = uptime
    
    def get_template_data(self):
        """الحصول على البيانات للقالب"""
        return {
            "stats": self.stats,
            "recent_scans": self.recent_scans[:10],
            "recent_vulnerabilities": self.recent_vulnerabilities[:10],
            "system_status": self.system_status,
            "startup_time": startup_time.strftime("%Y-%m-%d %H:%M:%S")
        }
    
    def get_stats_api(self):
        """API للحصول على الإحصائيات"""
        return {
            "total_scans": self.stats["total_scans"],
            "total_vulnerabilities": self.stats["total_vulnerabilities"],
            "active_scans": self.stats["active_scans"],
            "successful_attacks": self.stats["successful_attacks"],
            "uptime_seconds": self.stats["uptime"]
        }


# إنشاء مدير البيانات
data_manager = DashboardDataManager()


@app.on_event("startup")
async def startup_event():
    """بدء تشغيل الخادم"""
    await data_manager.initialize()


@app.websocket("/ws/dashboard")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint للتحديثات المباشرة"""
    await websocket.accept()
    active_websockets.add(websocket)
    
    try:
        # إرسال البيانات الحالية عند الاتصال
        await websocket.send_json({
            "type": "initial",
            "stats": data_manager.get_stats_api(),
            "scans": data_manager.recent_scans[:10],
            "vulnerabilities": data_manager.recent_vulnerabilities[:10]
        })
        
        while True:
            # استقبال رسائل من العميل (keepalive)
            await websocket.receive_text()
            
    except WebSocketDisconnect:
        active_websockets.discard(websocket)
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        active_websockets.discard(websocket)


@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    """الصفحة الرئيسية للوحة التحكم"""
    await data_manager.update_system_metrics()
    return templates.TemplateResponse(
        "dashboard.html",
        {"request": request, **data_manager.get_template_data()}
    )


@app.get("/api/stats")
async def get_stats():
    """الحصول على إحصائيات النظام"""
    return data_manager.get_stats_api()


@app.get("/api/scans")
async def get_scans(limit: int = 50, offset: int = 0):
    """الحصول على قائمة الفحوصات"""
    scans = data_manager.recent_scans[offset:offset + limit]
    return {
        "items": scans,
        "total": len(data_manager.recent_scans),
        "offset": offset,
        "limit": limit
    }


@app.get("/api/vulnerabilities")
async def get_vulnerabilities(limit: int = 50, offset: int = 0):
    """الحصول على قائمة الثغرات"""
    vulns = data_manager.recent_vulnerabilities[offset:offset + limit]
    return {
        "items": vulns,
        "total": len(data_manager.recent_vulnerabilities),
        "offset": offset,
        "limit": limit
    }


@app.get("/api/system")
async def get_system_status():
    """الحصول على حالة النظام"""
    await data_manager.update_system_metrics()
    return data_manager.system_status


@app.post("/api/refresh")
async def refresh_data():
    """تحديث البيانات يدوياً"""
    await data_manager._load_historical_data()
    return {"status": "refreshed"}


# قالب HTML محسن مع WebSocket
html_template = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HunterMind Dashboard</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: linear-gradient(135deg, #0f0c29, #302b63, #24243e);
            color: #fff;
            min-height: 100vh;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }
        
        header {
            text-align: center;
            padding: 20px 0;
            border-bottom: 1px solid rgba(255,255,255,0.1);
            margin-bottom: 30px;
        }
        
        h1 {
            font-size: 2.5rem;
            font-weight: 700;
            background: linear-gradient(135deg, #667eea, #764ba2);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }
        
        .subtitle {
            color: rgba(255,255,255,0.6);
            margin-top: 10px;
        }
        
        .connection-status {
            display: inline-block;
            width: 12px;
            height: 12px;
            border-radius: 50%;
            margin-left: 10px;
            animation: pulse 1.5s infinite;
        }
        
        .connection-status.connected {
            background: #27ae60;
            box-shadow: 0 0 10px #27ae60;
        }
        
        .connection-status.disconnected {
            background: #e74c3c;
        }
        
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .stat-card {
            background: rgba(255,255,255,0.1);
            backdrop-filter: blur(10px);
            border-radius: 15px;
            padding: 20px;
            text-align: center;
            transition: transform 0.3s;
            cursor: pointer;
        }
        
        .stat-card:hover {
            transform: translateY(-5px);
        }
        
        .stat-value {
            font-size: 2.5rem;
            font-weight: bold;
            color: #667eea;
        }
        
        .stat-label {
            color: rgba(255,255,255,0.7);
            margin-top: 10px;
        }
        
        .section {
            background: rgba(255,255,255,0.05);
            border-radius: 15px;
            padding: 20px;
            margin-bottom: 30px;
        }
        
        .section-title {
            font-size: 1.3rem;
            margin-bottom: 20px;
            color: #667eea;
        }
        
        .refresh-btn {
            float: right;
            background: rgba(102,126,234,0.3);
            border: 1px solid #667eea;
            color: #667eea;
            padding: 5px 15px;
            border-radius: 20px;
            cursor: pointer;
            font-size: 0.8rem;
            transition: all 0.3s;
        }
        
        .refresh-btn:hover {
            background: #667eea;
            color: white;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
        }
        
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid rgba(255,255,255,0.1);
        }
        
        th {
            color: #667eea;
            font-weight: 600;
        }
        
        .severity {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.8rem;
            font-weight: 600;
        }
        
        .severity-critical { background: #e74c3c; }
        .severity-high { background: #e67e22; }
        .severity-medium { background: #f1c40f; color: #333; }
        .severity-low { background: #27ae60; }
        
        .status {
            display: inline-block;
            width: 10px;
            height: 10px;
            border-radius: 50%;
            margin-right: 8px;
        }
        
        .status-running { background: #27ae60; box-shadow: 0 0 10px #27ae60; }
        .status-pending { background: #f1c40f; }
        .status-completed { background: #3498db; }
        .status-failed { background: #e74c3c; }
        
        .notification {
            position: fixed;
            top: 20px;
            right: 20px;
            background: #2c2c2c;
            border-left: 4px solid #667eea;
            padding: 12px 20px;
            border-radius: 8px;
            animation: slideIn 0.3s ease;
            z-index: 1000;
        }
        
        @keyframes slideIn {
            from {
                transform: translateX(100%);
                opacity: 0;
            }
            to {
                transform: translateX(0);
                opacity: 1;
            }
        }
        
        .notification.critical { border-left-color: #e74c3c; }
        .notification.high { border-left-color: #e67e22; }
        
        @media (max-width: 768px) {
            .stats-grid {
                grid-template-columns: 1fr;
            }
            
            table {
                font-size: 0.8rem;
            }
            
            th, td {
                padding: 8px;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🦅 HunterMind Dashboard <span class="connection-status" id="wsStatus"></span></h1>
            <div class="subtitle">Autonomous Offensive Security Intelligence Platform</div>
        </header>
        
        <div class="stats-grid">
            <div class="stat-card" onclick="refreshData()">
                <div class="stat-value" id="totalScans">{{ stats.total_scans }}</div>
                <div class="stat-label">Total Scans</div>
            </div>
            <div class="stat-card" onclick="refreshData()">
                <div class="stat-value" id="totalVulns">{{ stats.total_vulnerabilities }}</div>
                <div class="stat-label">Vulnerabilities Found</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" id="activeScans">{{ stats.active_scans }}</div>
                <div class="stat-label">Active Scans</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" id="successfulAttacks">{{ stats.successful_attacks }}</div>
                <div class="stat-label">Successful Attacks</div>
            </div>
        </div>
        
        <div class="section">
            <div class="section-title">
                📊 System Status
                <button class="refresh-btn" onclick="refreshSystemStatus()">Refresh</button>
            </div>
            <div class="stats-grid" style="grid-template-columns: repeat(3, 1fr);">
                <div class="stat-card">
                    <div class="stat-value" id="cpuUsage">{{ "%.1f"|format(system_status.cpu) }}%</div>
                    <div class="stat-label">CPU Usage</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value" id="memUsage">{{ "%.1f"|format(system_status.memory) }}%</div>
                    <div class="stat-label">Memory Usage</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value" id="diskUsage">{{ "%.1f"|format(system_status.disk) }}%</div>
                    <div class="stat-label">Disk Usage</div>
                </div>
            </div>
        </div>
        
        <div class="section">
            <div class="section-title">
                📋 Recent Scans
                <button class="refresh-btn" onclick="loadScans()">Refresh</button>
            </div>
            <table id="scansTable">
                <thead>
                    <tr>
                        <th>Status</th>
                        <th>Target URL</th>
                        <th>Scan Type</th>
                        <th>Findings</th>
                        <th>Time</th>
                    </tr>
                </thead>
                <tbody>
                    {% for scan in recent_scans %}
                    <tr>
                        <td><span class="status status-{{ scan.status }}"></span>{{ scan.status }}</td>
                        <td>{{ scan.target_url[:50] }}</td>
                        <td>{{ scan.scan_type }}</td>
                        <td>{{ scan.findings_count }}</td>
                        <td>{{ scan.timestamp[:16] }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
        
        <div class="section">
            <div class="section-title">
                🔍 Recent Vulnerabilities
                <button class="refresh-btn" onclick="loadVulnerabilities()">Refresh</button>
            </div>
            <table id="vulnsTable">
                <thead>
                    <tr>
                        <th>Severity</th>
                        <th>Type</th>
                        <th>URL</th>
                        <th>Parameter</th>
                        <th>Time</th>
                    </tr>
                </thead>
                <tbody>
                    {% for vuln in recent_vulnerabilities %}
                    <tr>
                        <td><span class="severity severity-{{ vuln.severity }}">{{ vuln.severity }}</span></td>
                        <td>{{ vuln.type }}</td>
                        <td>{{ vuln.url[:40] }}</td>
                        <td>{{ vuln.parameter or '-' }}</td>
                        <td>{{ vuln.timestamp[:16] }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
        
        <div style="text-align: center; color: rgba(255,255,255,0.5); font-size: 0.8rem; margin-top: 30px;">
            <p>Started: {{ startup_time }} | Version 1.0.0</p>
        </div>
    </div>
    
    <div id="notificationContainer"></div>
    
    <script>
        let ws = null;
        let reconnectAttempts = 0;
        
        function connectWebSocket() {
            const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
            const wsUrl = `${protocol}//${window.location.host}/ws/dashboard`;
            
            ws = new WebSocket(wsUrl);
            
            ws.onopen = function() {
                document.getElementById('wsStatus').className = 'connection-status connected';
                reconnectAttempts = 0;
                console.log('WebSocket connected');
            };
            
            ws.onmessage = function(event) {
                const data = JSON.parse(event.data);
                handleWebSocketMessage(data);
            };
            
            ws.onclose = function() {
                document.getElementById('wsStatus').className = 'connection-status disconnected';
                console.log('WebSocket disconnected');
                
                reconnectAttempts++;
                const delay = Math.min(3000 * reconnectAttempts, 30000);
                setTimeout(connectWebSocket, delay);
            };
        }
        
        function handleWebSocketMessage(data) {
            if (data.type === 'initial') {
                updateStats(data.stats);
                updateScansTable(data.scans);
                updateVulnsTable(data.vulnerabilities);
            } else if (data.type === 'scan_complete') {
                addNotification('Scan Completed', `Scan of ${data.data.target_url} completed with ${data.data.findings_count} findings`, 'info');
                loadScans();
                loadStats();
            } else if (data.type === 'vulnerability_found') {
                const severity = data.data.severity;
                addNotification('New Vulnerability', `${severity.toUpperCase()}: ${data.data.type} at ${data.data.url}`, severity);
                loadVulnerabilities();
                loadStats();
            }
        }
        
        function addNotification(title, message, severity) {
            const container = document.getElementById('notificationContainer');
            const notification = document.createElement('div');
            notification.className = `notification ${severity}`;
            notification.innerHTML = `
                <strong>${title}</strong><br>
                <small>${message}</small>
            `;
            container.appendChild(notification);
            
            setTimeout(() => {
                notification.remove();
            }, 5000);
        }
        
        async function loadStats() {
            try {
                const response = await fetch('/api/stats');
                const stats = await response.json();
                updateStats(stats);
            } catch (error) {
                console.error('Failed to load stats:', error);
            }
        }
        
        function updateStats(stats) {
            document.getElementById('totalScans').textContent = stats.total_scans;
            document.getElementById('totalVulns').textContent = stats.total_vulnerabilities;
            document.getElementById('activeScans').textContent = stats.active_scans;
            document.getElementById('successfulAttacks').textContent = stats.successful_attacks;
        }
        
        async function loadScans() {
            try {
                const response = await fetch('/api/scans?limit=10');
                const data = await response.json();
                updateScansTable(data.items);
            } catch (error) {
                console.error('Failed to load scans:', error);
            }
        }
        
        function updateScansTable(scans) {
            const tbody = document.querySelector('#scansTable tbody');
            if (!tbody) return;
            
            tbody.innerHTML = scans.map(scan => `
                <tr>
                    <td><span class="status status-${scan.status}"></span>${scan.status}</td>
                    <td>${(scan.target_url || '').substring(0, 50)}</td>
                    <td>${scan.scan_type || 'full'}</td>
                    <td>${scan.findings_count || 0}</td>
                    <td>${(scan.timestamp || '').substring(0, 16)}</td>
                </tr>
            `).join('');
        }
        
        async function loadVulnerabilities() {
            try {
                const response = await fetch('/api/vulnerabilities?limit=20');
                const data = await response.json();
                updateVulnsTable(data.items);
            } catch (error) {
                console.error('Failed to load vulnerabilities:', error);
            }
        }
        
        function updateVulnsTable(vulns) {
            const tbody = document.querySelector('#vulnsTable tbody');
            if (!tbody) return;
            
            tbody.innerHTML = vulns.map(vuln => `
                <tr>
                    <td><span class="severity severity-${vuln.severity}">${vuln.severity}</span></td>
                    <td>${vuln.type}</td>
                    <td>${(vuln.url || '').substring(0, 40)}</td>
                    <td>${vuln.parameter || '-'}</td>
                    <td>${(vuln.timestamp || '').substring(0, 16)}</td>
                </tr>
            `).join('');
        }
        
        async function refreshSystemStatus() {
            try {
                const response = await fetch('/api/system');
                const status = await response.json();
                document.getElementById('cpuUsage').textContent = status.cpu.toFixed(1) + '%';
                document.getElementById('memUsage').textContent = status.memory.toFixed(1) + '%';
                document.getElementById('diskUsage').textContent = status.disk.toFixed(1) + '%';
            } catch (error) {
                console.error('Failed to refresh system status:', error);
            }
        }
        
        async function refreshData() {
            await loadStats();
            await loadScans();
            await loadVulnerabilities();
            await refreshSystemStatus();
            
            addNotification('Data Refreshed', 'Dashboard data has been updated', 'info');
        }
        
        // تحديث دوري كل 30 ثانية
        setInterval(() => {
            loadStats();
            refreshSystemStatus();
        }, 30000);
        
        // بدء الاتصال WebSocket
        connectWebSocket();
        
        // طلب إذن الإشعارات
        if ('Notification' in window && Notification.permission !== 'denied') {
            Notification.requestPermission();
        }
    </script>
</body>
</html>'''

# كتابة قالب HTML
with open("interfaces/dashboard/templates/dashboard.html", "w") as f:
    f.write(html_template)

logger.info("Dashboard HTML template created with WebSocket support")


# تشغيل الخادم
if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5000)

# بيانات لوحة التحكم
dashboard_data = {
    "stats": {
        "total_scans": 0,
        "total_vulnerabilities": 0,
        "active_scans": 0,
        "successful_attacks": 0,
        "system_load": 0.0,
        "uptime": 0
    },
    "recent_scans": [],
    "recent_vulnerabilities": [],
    "system_status": {
        "cpu": 0,
        "memory": 0,
        "disk": 0
    }
}

