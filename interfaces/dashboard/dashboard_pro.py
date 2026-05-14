"""
Dashboard Pro - النسخة الاحترافية المتكاملة
"""

from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect, Depends, status
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.templating import Jinja2Templates
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
from contextlib import asynccontextmanager
import uvicorn
import os
import asyncio
import psutil
import json
import hashlib
from jose import JWTError, jwt
from passlib.context import CryptContext
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib.colors import HexColor
import aiosqlite
from apscheduler.schedulers.asyncio import AsyncIOScheduler

import logging

logger = logging.getLogger(__name__)

# ============================================================
# الإعدادات الأساسية
# ============================================================

SECRET_KEY = "huntermind-secret-key-change-in-production"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 480  # 8 ساعات

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer(auto_error=False)
scheduler = AsyncIOScheduler()

# ============================================================
# قاعدة البيانات
# ============================================================

class Database:
    def __init__(self, db_path: str = "./dashboard_pro.db"):
        self.db_path = db_path
    
    async def init_db(self):
        async with aiosqlite.connect(self.db_path) as db:
            # جدول المستخدمين
            await db.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    email TEXT,
                    role TEXT DEFAULT 'viewer',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_login TIMESTAMP
                )
            ''')
            
            # جدول الفحوصات
            await db.execute('''
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target_url TEXT NOT NULL,
                    scan_type TEXT NOT NULL,
                    findings_count INTEGER DEFAULT 0,
                    status TEXT DEFAULT 'pending',
                    duration REAL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    user_id INTEGER
                )
            ''')
            
            # جدول الثغرات
            await db.execute('''
                CREATE TABLE IF NOT EXISTS vulnerabilities (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER,
                    type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    url TEXT NOT NULL,
                    parameter TEXT,
                    payload TEXT,
                    discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # مستخدم افتراضي
            await db.execute('''
                INSERT OR IGNORE INTO users (username, password_hash, email, role)
                VALUES (?, ?, ?, ?)
            ''', ('admin', pwd_context.hash('Admin@123'), 'admin@huntermind.com', 'administrator'))
            
            await db.commit()
    
    async def get_user(self, username: str):
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute("SELECT * FROM users WHERE username = ?", (username,))
            return await cursor.fetchone()
    
    async def get_scans(self, limit: int = 100, offset: int = 0):
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute('''
                SELECT * FROM scans ORDER BY created_at DESC LIMIT ? OFFSET ?
            ''', (limit, offset))
            return await cursor.fetchall()
    
    async def get_vulnerabilities(self, limit: int = 100, offset: int = 0):
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute('''
                SELECT * FROM vulnerabilities ORDER BY discovered_at DESC LIMIT ? OFFSET ?
            ''', (limit, offset))
            return await cursor.fetchall()

db = Database()

# ============================================================
# دوال المصادقة
# ============================================================

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.now() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    if not credentials:
        return None
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            return None
        user = await db.get_user(username)
        return user
    except JWTError:
        return None

# ============================================================
# إنشاء التطبيق
# ============================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    await db.init_db()
    scheduler.start()
    logger.info("Dashboard Pro started")
    yield
    scheduler.shutdown()
    logger.info("Dashboard Pro stopped")

app = FastAPI(title="HunterMind Dashboard Pro", version="2.0.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

templates = Jinja2Templates(directory="interfaces/dashboard/templates")
os.makedirs("interfaces/dashboard/templates", exist_ok=True)

# بيانات اللوحة
dashboard_data = {
    "stats": {"total_scans": 0, "total_vulnerabilities": 0, "active_scans": 0, "successful_attacks": 0},
    "recent_scans": [],
    "recent_vulnerabilities": [],
    "system_status": {"cpu": 0, "memory": 0, "disk": 0}
}

startup_time = datetime.now()
active_websockets = set()

vuln_trend_data = {
    "XSS": [5, 8, 12, 9, 15, 20],
    "SQL Injection": [3, 5, 7, 6, 10, 14],
    "IDOR": [2, 4, 6, 5, 8, 11],
    "RCE": [1, 2, 3, 2, 4, 6]
}

# ============================================================
# WebSocket
# ============================================================

@app.websocket("/ws/dashboard")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    active_websockets.add(websocket)
    try:
        await websocket.send_json({
            "type": "initial",
            "stats": dashboard_data["stats"],
            "scans": dashboard_data["recent_scans"][:10],
            "vulnerabilities": dashboard_data["recent_vulnerabilities"][:20],
            "trend_data": vuln_trend_data
        })
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        active_websockets.discard(websocket)

# ============================================================
# API Routes
# ============================================================

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    return templates.TemplateResponse("dashboard_pro.html", {
        "request": request,
        "stats": dashboard_data["stats"],
        "recent_scans": dashboard_data["recent_scans"][:10],
        "recent_vulnerabilities": dashboard_data["recent_vulnerabilities"][:10],
        "system_status": dashboard_data["system_status"],
        "startup_time": startup_time.strftime("%Y-%m-%d %H:%M:%S"),
        "trend_data": json.dumps(vuln_trend_data)
    })

@app.post("/api/login")
async def login(username: str, password: str):
    user = await db.get_user(username)
    if not user or not pwd_context.verify(password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_access_token({"sub": username})
    return {"access_token": token, "token_type": "bearer", "role": user["role"]}

@app.get("/api/stats")
async def get_stats():
    return dashboard_data["stats"]

@app.get("/api/scans")
async def get_scans(limit: int = 50, offset: int = 0):
    scans = await db.get_scans(limit, offset)
    return {"items": [dict(s) for s in scans], "total": len(scans), "offset": offset, "limit": limit}

@app.get("/api/vulnerabilities")
async def get_vulnerabilities(limit: int = 50, offset: int = 0):
    vulns = await db.get_vulnerabilities(limit, offset)
    return {"items": [dict(v) for v in vulns], "total": len(vulns), "offset": offset, "limit": limit}

@app.get("/api/system")
async def get_system_status():
    return {
        "cpu": psutil.cpu_percent(interval=0.5),
        "memory": psutil.virtual_memory().percent,
        "disk": psutil.disk_usage('/').percent
    }

@app.get("/api/trends")
async def get_trends():
    return vuln_trend_data

@app.post("/api/refresh")
async def refresh_data():
    return {"status": "refreshed"}

# ============================================================
# تحديث البيانات
# ============================================================

async def update_dashboard_data():
    scans = await db.get_scans(limit=100)
    dashboard_data["stats"]["total_scans"] = len(scans)
    vulns = await db.get_vulnerabilities(limit=1000)
    dashboard_data["stats"]["total_vulnerabilities"] = len(vulns)

scheduler.add_job(update_dashboard_data, 'interval', seconds=30)

# ============================================================
# قالب HTML
# ============================================================

html_template = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HunterMind Dashboard Pro</title>
    <script src="https://cdn.jsdelivr.net/npm/echarts@5.4.3/dist/echarts.min.js"></script>
    <style>
        :root {
            --primary: #6366f1;
            --bg-dark: #0f172a;
            --bg-card: rgba(30, 41, 59, 0.95);
        }
        
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: var(--bg-dark);
            color: #fff;
            min-height: 100vh;
        }
        
        .sidebar {
            position: fixed;
            left: 0;
            top: 0;
            width: 260px;
            height: 100vh;
            background: linear-gradient(180deg, #1e293b 0%, #0f172a 100%);
            border-right: 1px solid rgba(255,255,255,0.1);
        }
        
        .logo {
            padding: 24px;
            text-align: center;
            border-bottom: 1px solid rgba(255,255,255,0.1);
        }
        
        .logo span {
            font-size: 1.5rem;
            font-weight: bold;
            background: linear-gradient(135deg, #667eea, #764ba2);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        
        .nav-menu {
            padding: 16px;
        }
        
        .nav-item {
            display: flex;
            align-items: center;
            padding: 12px 16px;
            margin-bottom: 8px;
            border-radius: 12px;
            color: rgba(255,255,255,0.7);
            text-decoration: none;
            cursor: pointer;
            transition: all 0.3s;
        }
        
        .nav-item:hover, .nav-item.active {
            background: rgba(99,102,241,0.2);
            color: #fff;
        }
        
        .nav-item i { margin-right: 12px; }
        
        .main-content {
            margin-left: 260px;
            padding: 24px;
        }
        
        .top-bar {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 24px;
            padding: 16px 24px;
            background: var(--bg-card);
            border-radius: 16px;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
            gap: 20px;
            margin-bottom: 24px;
        }
        
        .stat-card {
            background: var(--bg-card);
            border-radius: 20px;
            padding: 20px;
            text-align: center;
            border: 1px solid rgba(255,255,255,0.1);
            transition: all 0.3s;
            cursor: pointer;
        }
        
        .stat-card:hover {
            transform: translateY(-5px);
            border-color: var(--primary);
        }
        
        .stat-value {
            font-size: 2.5rem;
            font-weight: bold;
            color: var(--primary);
        }
        
        .stat-label {
            color: rgba(255,255,255,0.7);
            margin-top: 8px;
        }
        
        .section {
            background: var(--bg-card);
            border-radius: 20px;
            padding: 24px;
            margin-bottom: 24px;
            border: 1px solid rgba(255,255,255,0.1);
        }
        
        .section-title {
            font-size: 1.2rem;
            margin-bottom: 20px;
            color: var(--primary);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .chart-container { height: 400px; margin-bottom: 20px; }
        
        table {
            width: 100%;
            border-collapse: collapse;
        }
        
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid rgba(255,255,255,0.1);
        }
        
        th { color: var(--primary); }
        
        .severity {
            display: inline-block;
            padding: 4px 10px;
            border-radius: 20px;
            font-size: 0.7rem;
            font-weight: 600;
        }
        
        .severity-critical { background: #ef4444; }
        .severity-high { background: #f59e0b; }
        .severity-medium { background: #eab308; color: #333; }
        .severity-low { background: #10b981; }
        
        .btn-primary {
            background: linear-gradient(135deg, #667eea, #764ba2);
            border: none;
            padding: 8px 16px;
            border-radius: 12px;
            color: white;
            cursor: pointer;
        }
        
        .connection-status {
            display: inline-block;
            width: 10px;
            height: 10px;
            border-radius: 50%;
            margin-left: 10px;
            animation: pulse 1.5s infinite;
        }
        
        .connection-status.connected { background: #10b981; box-shadow: 0 0 10px #10b981; }
        .connection-status.disconnected { background: #ef4444; }
        
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }
        
        .notification {
            position: fixed;
            top: 20px;
            right: 20px;
            background: var(--bg-card);
            border-left: 4px solid var(--primary);
            padding: 12px 20px;
            border-radius: 12px;
            animation: slideIn 0.3s ease;
            z-index: 1000;
        }
        
        @keyframes slideIn {
            from { transform: translateX(100%); opacity: 0; }
            to { transform: translateX(0); opacity: 1; }
        }
        
        @media (max-width: 768px) {
            .sidebar { transform: translateX(-100%); transition: transform 0.3s; }
            .sidebar.open { transform: translateX(0); }
            .main-content { margin-left: 0; }
            .stats-grid { grid-template-columns: 1fr; }
            table { display: block; overflow-x: auto; }
        }
    </style>
</head>
<body>
    <div class="sidebar" id="sidebar">
        <div class="logo"><span>🦅 HunterMind Pro</span></div>
        <nav class="nav-menu">
            <div class="nav-item active"><i>📊</i> Dashboard</div>
            <div class="nav-item"><i>🔍</i> Scans</div>
            <div class="nav-item"><i>⚠️</i> Vulnerabilities</div>
            <div class="nav-item"><i>📄</i> Reports</div>
        </nav>
    </div>
    
    <div class="main-content">
        <div class="top-bar">
            <div class="page-title">Security Dashboard</div>
            <div style="display: flex; align-items: center; gap: 16px;">
                <div class="connection-status" id="wsStatus"></div>
                <div class="avatar" onclick="toggleSidebar()">☰</div>
            </div>
        </div>
        
        <div class="stats-grid">
            <div class="stat-card" onclick="refreshData()">
                <div class="stat-value" id="totalScans">{{ stats.total_scans }}</div>
                <div class="stat-label">Total Scans</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" id="totalVulns">{{ stats.total_vulnerabilities }}</div>
                <div class="stat-label">Vulnerabilities</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" id="cpuUsage">{{ "%.1f"|format(system_status.cpu) }}%</div>
                <div class="stat-label">CPU Usage</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" id="memUsage">{{ "%.1f"|format(system_status.memory) }}%</div>
                <div class="stat-label">Memory Usage</div>
            </div>
        </div>
        
        <div class="section">
            <div class="section-title">📈 Vulnerability Trends <button class="btn-primary" onclick="refreshChart()">Refresh</button></div>
            <div id="trendChart" class="chart-container"></div>
        </div>
        
        <div class="section">
            <div class="section-title">📋 Recent Scans</div>
            <table id="scansTable">
                <thead><tr><th>Target URL</th><th>Findings</th><th>Time</th></tr></thead>
                <tbody>
                    {% for scan in recent_scans %}
                    <tr><td>{{ scan.target_url[:50] }}</td><td>{{ scan.findings_count }}</td><td>{{ scan.timestamp[:16] }}</td></tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
        
        <div class="section">
            <div class="section-title">🔍 Recent Vulnerabilities</div>
            <table id="vulnsTable">
                <thead><tr><th>Severity</th><th>Type</th><th>URL</th></tr></thead>
                <tbody>
                    {% for vuln in recent_vulnerabilities %}
                    <tr>
                        <td><span class="severity severity-{{ vuln.severity }}">{{ vuln.severity }}</span></td>
                        <td>{{ vuln.type }}</td>
                        <td>{{ vuln.url[:40] }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
        
        <div style="text-align: center; color: rgba(255,255,255,0.5); font-size: 0.8rem;">
            <p>Started: {{ startup_time }} | HunterMind Pro v2.0</p>
        </div>
    </div>
    
    <div id="notificationContainer"></div>
    
    <script>
        let ws = null, trendChart = null;
        
        function initChart() {
            trendChart = echarts.init(document.getElementById('trendChart'));
            trendChart.setOption({
                tooltip: { trigger: 'axis' },
                legend: { data: ['XSS', 'SQL Injection', 'IDOR', 'RCE'], textStyle: { color: '#fff' } },
                xAxis: { type: 'category', data: ['Week 1', 'Week 2', 'Week 3', 'Week 4', 'Week 5', 'Week 6'], axisLabel: { color: '#fff' } },
                yAxis: { type: 'value', name: 'Vulnerabilities', nameTextStyle: { color: '#fff' }, axisLabel: { color: '#fff' } },
                series: [
                    { name: 'XSS', type: 'line', data: {{ trend_data.XSS }}, smooth: true, lineStyle: { color: '#f59e0b' } },
                    { name: 'SQL Injection', type: 'line', data: {{ trend_data['SQL Injection'] }}, smooth: true, lineStyle: { color: '#ef4444' } },
                    { name: 'IDOR', type: 'line', data: {{ trend_data.IDOR }}, smooth: true, lineStyle: { color: '#10b981' } },
                    { name: 'RCE', type: 'line', data: {{ trend_data.RCE }}, smooth: true, lineStyle: { color: '#6366f1' } }
                ]
            });
        }
        
        function refreshChart() { if (trendChart) trendChart.resize(); }
        
        function connectWebSocket() {
            const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
            ws = new WebSocket(`${protocol}//${location.host}/ws/dashboard`);
            ws.onopen = () => document.getElementById('wsStatus').className = 'connection-status connected';
            ws.onclose = () => document.getElementById('wsStatus').className = 'connection-status disconnected';
            ws.onmessage = (e) => {
                const data = JSON.parse(e.data);
                if (data.type === 'initial') {
                    document.getElementById('totalScans').textContent = data.stats.total_scans;
                    document.getElementById('totalVulns').textContent = data.stats.total_vulnerabilities;
                }
            };
        }
        
        function addNotification(title, message) {
            const container = document.getElementById('notificationContainer');
            const notif = document.createElement('div');
            notif.className = 'notification';
            notif.innerHTML = `<strong>${title}</strong><br><small>${message}</small>`;
            container.appendChild(notif);
            setTimeout(() => notif.remove(), 5000);
        }
        
        async function refreshData() {
            addNotification('Refreshing', 'Updating dashboard data...');
            const response = await fetch('/api/refresh', { method: 'POST' });
            if (response.ok) addNotification('Success', 'Data refreshed!', 'success');
        }
        
        function toggleSidebar() {
            document.getElementById('sidebar').classList.toggle('open');
        }
        
        initChart();
        connectWebSocket();
        window.addEventListener('resize', () => refreshChart());
        
        setInterval(async () => {
            const resp = await fetch('/api/system');
            const status = await resp.json();
            document.getElementById('cpuUsage').textContent = status.cpu.toFixed(1) + '%';
            document.getElementById('memUsage').textContent = status.memory.toFixed(1) + '%';
        }, 10000);
    </script>
</body>
</html>'''

with open("interfaces/dashboard/templates/dashboard_pro.html", "w") as f:
    f.write(html_template)

logger.info("Dashboard Pro template created")


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5001, reload=True)
