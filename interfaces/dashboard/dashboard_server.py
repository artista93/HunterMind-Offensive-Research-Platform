
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from typing import Dict, List, Optional, Any
from datetime import datetime
import uvicorn
import os

import logging

logger = logging.getLogger(__name__)

# إنشاء تطبيق FastAPI
app = FastAPI(title="HunterMind Dashboard", version="1.0.0")

# إعداد القوالب
templates = Jinja2Templates(directory="interfaces/dashboard/templates")

# إنشاء مجلد القوالب إذا لم يكن موجوداً
os.makedirs("interfaces/dashboard/templates", exist_ok=True)

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

# وقت بدء التشغيل
startup_time = datetime.now()


@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    """الصفحة الرئيسية للوحة التحكم"""
    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "stats": dashboard_data["stats"],
            "recent_scans": dashboard_data["recent_scans"][:10],
            "recent_vulnerabilities": dashboard_data["recent_vulnerabilities"][:10],
            "system_status": dashboard_data["system_status"],
            "startup_time": startup_time.strftime("%Y-%m-%d %H:%M:%S")
        }
    )


@app.get("/api/stats")
async def get_stats():
    """الحصول على إحصائيات النظام"""
    return dashboard_data["stats"]


@app.get("/api/scans")
async def get_scans(limit: int = 50, offset: int = 0):
    """الحصول على قائمة الفحوصات"""
    scans = dashboard_data["recent_scans"][offset:offset + limit]
    return {
        "items": scans,
        "total": len(dashboard_data["recent_scans"]),
        "offset": offset,
        "limit": limit
    }


@app.get("/api/vulnerabilities")
async def get_vulnerabilities(limit: int = 50, offset: int = 0):
    """الحصول على قائمة الثغرات"""
    vulns = dashboard_data["recent_vulnerabilities"][offset:offset + limit]
    return {
        "items": vulns,
        "total": len(dashboard_data["recent_vulnerabilities"]),
        "offset": offset,
        "limit": limit
    }


@app.get("/api/system")
async def get_system_status():
    """الحصول على حالة النظام"""
    return dashboard_data["system_status"]


@app.post("/api/update_stats")
async def update_stats(data: Dict[str, Any]):
    """تحديث إحصائيات لوحة التحكم"""
    dashboard_data["stats"].update(data)
    return {"status": "updated"}


@app.post("/api/add_scan")
async def add_scan(scan: Dict[str, Any]):
    """إضافة فحص جديد إلى القائمة"""
    scan["timestamp"] = datetime.now().isoformat()
    dashboard_data["recent_scans"].insert(0, scan)
    
    # الحفاظ على آخر 100 فحص فقط
    if len(dashboard_data["recent_scans"]) > 100:
        dashboard_data["recent_scans"] = dashboard_data["recent_scans"][:100]
    
    dashboard_data["stats"]["total_scans"] += 1
    
    return {"status": "added"}


@app.post("/api/add_vulnerability")
async def add_vulnerability(vuln: Dict[str, Any]):
    """إضافة ثغرة جديدة إلى القائمة"""
    vuln["timestamp"] = datetime.now().isoformat()
    dashboard_data["recent_vulnerabilities"].insert(0, vuln)
    
    if len(dashboard_data["recent_vulnerabilities"]) > 100:
        dashboard_data["recent_vulnerabilities"] = dashboard_data["recent_vulnerabilities"][:100]
    
    dashboard_data["stats"]["total_vulnerabilities"] += 1
    
    return {"status": "added"}


# إنشاء قالب HTML
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
            <h1>🦅 HunterMind Dashboard</h1>
            <div class="subtitle">Autonomous Offensive Security Intelligence Platform</div>
        </header>
        
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-value">{{ stats.total_scans }}</div>
                <div class="stat-label">Total Scans</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{{ stats.total_vulnerabilities }}</div>
                <div class="stat-label">Vulnerabilities Found</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{{ stats.active_scans }}</div>
                <div class="stat-label">Active Scans</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{{ stats.successful_attacks }}</div>
                <div class="stat-label">Successful Attacks</div>
            </div>
        </div>
        
        <div class="section">
            <div class="section-title">📊 System Status</div>
            <div class="stats-grid" style="grid-template-columns: repeat(3, 1fr);">
                <div class="stat-card">
                    <div class="stat-value">{{ "%.1f"|format(system_status.cpu) }}%</div>
                    <div class="stat-label">CPU Usage</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{{ "%.1f"|format(system_status.memory) }}%</div>
                    <div class="stat-label">Memory Usage</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{{ "%.1f"|format(system_status.disk) }}%</div>
                    <div class="stat-label">Disk Usage</div>
                </div>
            </div>
        </div>
        
        <div class="section">
            <div class="section-title">📋 Recent Scans</div>
            <table>
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
            <div class="section-title">🔍 Recent Vulnerabilities</div>
            <table>
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
</body>
</html>'''

# كتابة قالب HTML
with open("interfaces/dashboard/templates/dashboard.html", "w") as f:
    f.write(html_template)

logger.info("Dashboard HTML template created")


# تشغيل الخادم
if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5000)

