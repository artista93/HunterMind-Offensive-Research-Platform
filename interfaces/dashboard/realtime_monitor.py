
import asyncio
from typing import Dict, List, Any, Optional
from datetime import datetime
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
import uvicorn

import logging

logger = logging.getLogger(__name__)

# إنشاء تطبيق FastAPI
app = FastAPI(title="HunterMind Real-time Monitor", version="1.0.0")


class MonitorManager:
    """مدير المراقبة في الوقت الفعلي"""
    
    def __init__(self):
        self.active_connections: List[WebSocket] = []
        self.event_history: List[Dict] = []
        self._lock = asyncio.Lock()
        
        logger.info("MonitorManager initialized")
    
    async def connect(self, websocket: WebSocket):
        """قبول اتصال جديد"""
        await websocket.accept()
        async with self._lock:
            self.active_connections.append(websocket)
        logger.info(f"Client connected. Total: {len(self.active_connections)}")
    
    async def disconnect(self, websocket: WebSocket):
        """قطع اتصال عميل"""
        async with self._lock:
            if websocket in self.active_connections:
                self.active_connections.remove(websocket)
        logger.info(f"Client disconnected. Total: {len(self.active_connections)}")
    
    async def broadcast(self, event: Dict):
        """بث حدث لجميع المتصلين"""
        event["timestamp"] = datetime.now().isoformat()
        
        async with self._lock:
            # تخزين الحدث في التاريخ
            self.event_history.append(event)
            if len(self.event_history) > 1000:
                self.event_history.pop(0)
            
            # بث للعملاء
            for connection in self.active_connections:
                try:
                    await connection.send_json(event)
                except Exception as e:
                    logger.error(f"Broadcast error: {e}")
    
    async def send_to_client(self, websocket: WebSocket, event: Dict):
        """إرسال حدث لعميل محدد"""
        try:
            await websocket.send_json(event)
        except Exception as e:
            logger.error(f"Send to client error: {e}")
    
    async def get_history(self, limit: int = 100) -> List[Dict]:
        """الحصول على تاريخ الأحداث"""
        async with self._lock:
            return self.event_history[-limit:]


# إنشاء مدير المراقبة
monitor_manager = MonitorManager()


@app.websocket("/ws/monitor")
async def monitor_websocket(websocket: WebSocket):
    """نقطة نهاية WebSocket للمراقبة في الوقت الفعلي"""
    await monitor_manager.connect(websocket)
    
    try:
        # إرسال تاريخ الأحداث الحديثة
        history = await monitor_manager.get_history(50)
        if history:
            await monitor_manager.send_to_client(websocket, {
                "type": "history",
                "data": history
            })
        
        # الاستماع للرسائل
        while True:
            data = await websocket.receive_text()
            await handle_monitor_message(data, websocket)
            
    except WebSocketDisconnect:
        await monitor_manager.disconnect(websocket)


async def handle_monitor_message(message: str, websocket: WebSocket):
    """معالجة رسائل المراقبة"""
    import json
    
    try:
        data = json.loads(message)
        msg_type = data.get("type", "unknown")
        
        if msg_type == "ping":
            await monitor_manager.send_to_client(websocket, {
                "type": "pong",
                "timestamp": datetime.now().isoformat()
            })
        
        elif msg_type == "get_history":
            limit = data.get("limit", 100)
            history = await monitor_manager.get_history(limit)
            await monitor_manager.send_to_client(websocket, {
                "type": "history",
                "data": history
            })
        
    except json.JSONDecodeError:
        logger.error(f"Invalid JSON: {message}")


# دوال مساعدة لإرسال الأحداث
async def emit_scan_started(scan_id: str, target_url: str):
    """إرسال حدث بدء الفحص"""
    await monitor_manager.broadcast({
        "type": "scan_started",
        "scan_id": scan_id,
        "target_url": target_url
    })


async def emit_scan_completed(scan_id: str, findings_count: int):
    """إرسال حدث اكتمال الفحص"""
    await monitor_manager.broadcast({
        "type": "scan_completed",
        "scan_id": scan_id,
        "findings_count": findings_count
    })


async def emit_vulnerability_found(vulnerability: Dict):
    """إرسال حدث اكتشاف ثغرة"""
    await monitor_manager.broadcast({
        "type": "vulnerability_found",
        "vulnerability": vulnerability
    })


async def emit_attack_started(attack_id: str, target_url: str, vuln_type: str):
    """إرسال حدث بدء الهجوم"""
    await monitor_manager.broadcast({
        "type": "attack_started",
        "attack_id": attack_id,
        "target_url": target_url,
        "vulnerability_type": vuln_type
    })


async def emit_attack_result(attack_id: str, success: bool, output: str = ""):
    """إرسال نتيجة الهجوم"""
    await monitor_manager.broadcast({
        "type": "attack_result",
        "attack_id": attack_id,
        "success": success,
        "output": output[:200] if output else ""
    })


async def emit_system_alert(severity: str, message: str):
    """إرسال تنبيه النظام"""
    await monitor_manager.broadcast({
        "type": "system_alert",
        "severity": severity,
        "message": message
    })


@app.get("/monitor")
async def get_monitor_page():
    """صفحة المراقبة في الوقت الفعلي"""
    return HTMLResponse(html_template)


# قالب HTML للمراقبة
html_template = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HunterMind Real-time Monitor</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Courier New', monospace;
            background: #0a0a0a;
            color: #0f0;
            min-height: 100vh;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        
        header {
            text-align: center;
            padding: 20px;
            border-bottom: 1px solid #0f0;
            margin-bottom: 20px;
        }
        
        h1 {
            font-size: 2rem;
        }
        
        .status {
            display: inline-block;
            width: 12px;
            height: 12px;
            border-radius: 50%;
            background: #0f0;
            animation: pulse 1s infinite;
            margin-left: 10px;
        }
        
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.3; }
        }
        
        .log-container {
            background: #0a0a0a;
            border: 1px solid #0f0;
            border-radius: 5px;
            height: 500px;
            overflow-y: auto;
            padding: 15px;
        }
        
        .log-entry {
            font-family: 'Courier New', monospace;
            font-size: 0.85rem;
            padding: 5px;
            border-bottom: 1px solid rgba(0,255,0,0.1);
        }
        
        .log-time {
            color: #888;
            margin-right: 15px;
        }
        
        .log-type {
            display: inline-block;
            padding: 2px 8px;
            border-radius: 3px;
            font-size: 0.7rem;
            margin-right: 10px;
        }
        
        .type-scan { background: #3498db; color: white; }
        .type-attack { background: #e67e22; color: white; }
        .type-vulnerability { background: #e74c3c; color: white; }
        .type-alert { background: #f1c40f; color: #333; }
        
        .controls {
            margin-top: 20px;
            display: flex;
            gap: 10px;
            justify-content: center;
        }
        
        button {
            background: #0a0a0a;
            border: 1px solid #0f0;
            color: #0f0;
            padding: 10px 20px;
            cursor: pointer;
            font-family: 'Courier New', monospace;
            transition: all 0.3s;
        }
        
        button:hover {
            background: #0f0;
            color: #0a0a0a;
        }
        
        .stats {
            display: flex;
            gap: 20px;
            justify-content: space-between;
            margin-bottom: 20px;
            padding: 10px;
            background: rgba(0,255,0,0.05);
            border-radius: 5px;
        }
        
        .stat {
            text-align: center;
        }
        
        .stat-value {
            font-size: 1.5rem;
            font-weight: bold;
        }
        
        .stat-label {
            font-size: 0.7rem;
            color: #888;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>📡 Real-time Monitor</h1>
            <div>Live Activity Stream <span class="status"></span></div>
        </header>
        
        <div class="stats">
            <div class="stat">
                <div class="stat-value" id="scanCount">0</div>
                <div class="stat-label">Scans</div>
            </div>
            <div class="stat">
                <div class="stat-value" id="vulnCount">0</div>
                <div class="stat-label">Vulnerabilities</div>
            </div>
            <div class="stat">
                <div class="stat-value" id="attackCount">0</div>
                <div class="stat-label">Attacks</div>
            </div>
            <div class="stat">
                <div class="stat-value" id="connectionStatus">Connecting</div>
                <div class="stat-label">WebSocket</div>
            </div>
        </div>
        
        <div class="log-container" id="logContainer">
            <div class="log-entry">
                <span class="log-time">{{ now }}</span>
                <span class="log-type type-alert">system</span>
                <span>Monitoring started. Waiting for events...</span>
            </div>
        </div>
        
        <div class="controls">
            <button onclick="clearLogs()">Clear Logs</button>
            <button onclick="reconnect()">Reconnect</button>
        </div>
    </div>
    
    <script>
        let ws = null;
        let scanCount = 0;
        let vulnCount = 0;
        let attackCount = 0;
        
        function connect() {
            const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
            const wsUrl = `${protocol}//${window.location.host}/ws/monitor`;
            
            ws = new WebSocket(wsUrl);
            
            ws.onopen = function() {
                document.getElementById('connectionStatus').textContent = 'Connected';
                document.getElementById('connectionStatus').style.color = '#0f0';
                addLog('system', 'WebSocket connected', 'alert');
            };
            
            ws.onmessage = function(event) {
                const data = JSON.parse(event.data);
                handleEvent(data);
            };
            
            ws.onclose = function() {
                document.getElementById('connectionStatus').textContent = 'Disconnected';
                document.getElementById('connectionStatus').style.color = '#e74c3c';
                addLog('system', 'WebSocket disconnected. Reconnecting...', 'alert');
                setTimeout(connect, 3000);
            };
            
            ws.onerror = function(error) {
                addLog('system', 'WebSocket error', 'alert');
            };
        }
        
        function handleEvent(data) {
            const type = data.type;
            
            switch(type) {
                case 'scan_started':
                    scanCount++;
                    updateStats();
                    addLog('scan', `Scan started: ${data.target_url}`, 'scan');
                    break;
                    
                case 'scan_completed':
                    addLog('scan', `Scan completed: ${data.findings_count} findings found`, 'scan');
                    break;
                    
                case 'vulnerability_found':
                    vulnCount++;
                    updateStats();
                    const vuln = data.vulnerability;
                    addLog('vulnerability', `[${vuln.severity.toUpperCase()}] ${vuln.type} at ${vuln.url}`, 'vulnerability');
                    break;
                    
                case 'attack_started':
                    attackCount++;
                    updateStats();
                    addLog('attack', `Attack started: ${data.vulnerability_type} on ${data.target_url}`, 'attack');
                    break;
                    
                case 'attack_result':
                    const status = data.success ? 'SUCCESS' : 'FAILED';
                    addLog('attack', `Attack result: ${status}`, 'attack');
                    break;
                    
                case 'system_alert':
                    addLog('alert', `[${data.severity}] ${data.message}`, 'alert');
                    break;
                    
                case 'history':
                    data.data.forEach(event => {
                        handleEvent(event);
                    });
                    break;
            }
        }
        
        function addLog(category, message, type) {
            const logContainer = document.getElementById('logContainer');
            const logEntry = document.createElement('div');
            logEntry.className = 'log-entry';
            
            const now = new Date();
            const timeStr = now.toLocaleTimeString();
            
            let typeClass = '';
            if (type === 'scan') typeClass = 'type-scan';
            else if (type === 'attack') typeClass = 'type-attack';
            else if (type === 'vulnerability') typeClass = 'type-vulnerability';
            else typeClass = 'type-alert';
            
            logEntry.innerHTML = `
                <span class="log-time">${timeStr}</span>
                <span class="log-type ${typeClass}">${category}</span>
                <span>${escapeHtml(message)}</span>
            `;
            
            logContainer.appendChild(logEntry);
            logEntry.scrollIntoView({ behavior: 'smooth' });
        }
        
        function updateStats() {
            document.getElementById('scanCount').textContent = scanCount;
            document.getElementById('vulnCount').textContent = vulnCount;
            document.getElementById('attackCount').textContent = attackCount;
        }
        
        function clearLogs() {
            const logContainer = document.getElementById('logContainer');
            logContainer.innerHTML = '';
            addLog('system', 'Logs cleared', 'alert');
        }
        
        function reconnect() {
            if (ws) {
                ws.close();
            }
            connect();
        }
        
        function escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }
        
        // بدء الاتصال
        connect();
    </script>
</body>
</html>'''


# تشغيل الخادم
if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5001)

