
from fastapi import FastAPI, HTTPException, BackgroundTasks
from pydantic import BaseModel
from typing import Dict, List, Optional, Any
from datetime import datetime
import uvicorn

import logging

logger = logging.getLogger(__name__)

# نماذج البيانات
class ScanRequest(BaseModel):
    """طلب فحص"""
    target_url: str
    scan_type: str = "full"
    max_depth: int = 3
    max_pages: int = 100
    options: Dict[str, Any] = {}

class AttackRequest(BaseModel):
    """طلب هجوم"""
    target_url: str
    vulnerability_type: str
    parameter: Optional[str] = None
    payload: Optional[str] = None

class ExploitRequest(BaseModel):
    """طلب استغلال"""
    target_url: str
    vulnerability_type: str
    parameter: Optional[str] = None

# إنشاء تطبيق FastAPI
app = FastAPI(
    title="HunterMind API",
    description="Autonomous Offensive Security Intelligence Platform API",
    version="1.0.0"
)

# حالة الخادم
server_status = {
    "status": "running",
    "started_at": datetime.now().isoformat(),
    "version": "1.0.0"
}

# مخزن مؤقت للنتائج
scan_results = {}
attack_results = {}


@app.get("/")
async def root():
    """الصفحة الرئيسية"""
    return {
        "message": "HunterMind API",
        "version": "1.0.0",
        "status": "running",
        "endpoints": [
            "/health",
            "/status",
            "/scan",
            "/attack",
            "/exploit",
            "/results/{scan_id}"
        ]
    }


@app.get("/health")
async def health_check():
    """التحقق من صحة الخادم"""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat()
    }


@app.get("/status")
async def get_status():
    """الحصول على حالة المنصة"""
    return server_status


@app.post("/scan")
async def start_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    """
    بدء فحص أمني
    
    Args:
        request: طلب الفحص
        background_tasks: مهام الخلفية
    """
    import uuid
    scan_id = str(uuid.uuid4())[:8]
    
    # تسجيل بدء الفحص
    scan_results[scan_id] = {
        "id": scan_id,
        "target_url": request.target_url,
        "status": "pending",
        "started_at": datetime.now().isoformat(),
        "scan_type": request.scan_type
    }
    
    # إضافة مهمة الخلفية
    background_tasks.add_task(run_scan, scan_id, request)
    
    return {
        "scan_id": scan_id,
        "status": "started",
        "message": f"Scan started for {request.target_url}"
    }


@app.get("/results/{scan_id}")
async def get_results(scan_id: str):
    """الحصول على نتائج الفحص"""
    if scan_id not in scan_results:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    return scan_results[scan_id]


@app.post("/attack")
async def start_attack(request: AttackRequest, background_tasks: BackgroundTasks):
    """
    بدء هجوم على ثغرة محددة
    
    Args:
        request: طلب الهجوم
        background_tasks: مهام الخلفية
    """
    import uuid
    attack_id = str(uuid.uuid4())[:8]
    
    attack_results[attack_id] = {
        "id": attack_id,
        "target_url": request.target_url,
        "vulnerability_type": request.vulnerability_type,
        "status": "pending",
        "started_at": datetime.now().isoformat()
    }
    
    background_tasks.add_task(run_attack, attack_id, request)
    
    return {
        "attack_id": attack_id,
        "status": "started",
        "message": f"Attack started on {request.target_url}"
    }


@app.post("/exploit")
async def start_exploit(request: ExploitRequest, background_tasks: BackgroundTasks):
    """
    بدء استغلال ثغرة
    
    Args:
        request: طلب الاستغلال
        background_tasks: مهام الخلفية
    """
    import uuid
    exploit_id = str(uuid.uuid4())[:8]
    
    attack_results[exploit_id] = {
        "id": exploit_id,
        "target_url": request.target_url,
        "vulnerability_type": request.vulnerability_type,
        "status": "pending",
        "started_at": datetime.now().isoformat()
    }
    
    background_tasks.add_task(run_exploit, exploit_id, request)
    
    return {
        "exploit_id": exploit_id,
        "status": "started",
        "message": f"Exploit started on {request.target_url}"
    }


@app.get("/attacks")
async def list_attacks():
    """قائمة الهجمات"""
    return list(attack_results.values())


@app.get("/scans")
async def list_scans():
    """قائمة الفحوصات"""
    return list(scan_results.values())


# دوال مساعدة
async def run_scan(scan_id: str, request: ScanRequest):
    """تنفيذ الفحص في الخلفية"""
    scan_results[scan_id]["status"] = "running"
    
    try:
        # محاكاة الفحص
        await asyncio.sleep(2)
        
        scan_results[scan_id]["status"] = "completed"
        scan_results[scan_id]["completed_at"] = datetime.now().isoformat()
        scan_results[scan_id]["findings"] = [
            {
                "type": "XSS",
                "severity": "high",
                "url": request.target_url,
                "parameter": "q"
            }
        ]
        
    except Exception as e:
        scan_results[scan_id]["status"] = "failed"
        scan_results[scan_id]["error"] = str(e)


async def run_attack(attack_id: str, request: AttackRequest):
    """تنفيذ الهجوم في الخلفية"""
    attack_results[attack_id]["status"] = "running"
    
    try:
        await asyncio.sleep(1)
        
        attack_results[attack_id]["status"] = "completed"
        attack_results[attack_id]["completed_at"] = datetime.now().isoformat()
        attack_results[attack_id]["result"] = {
            "success": True,
            "output": "Attack completed successfully"
        }
        
    except Exception as e:
        attack_results[attack_id]["status"] = "failed"
        attack_results[attack_id]["error"] = str(e)


async def run_exploit(exploit_id: str, request: ExploitRequest):
    """تنفيذ الاستغلال في الخلفية"""
    attack_results[exploit_id]["status"] = "running"
    
    try:
        await asyncio.sleep(1.5)
        
        attack_results[exploit_id]["status"] = "completed"
        attack_results[exploit_id]["completed_at"] = datetime.now().isoformat()
        attack_results[exploit_id]["result"] = {
            "success": True,
            "extracted_data": "Sensitive information extracted"
        }
        
    except Exception as e:
        attack_results[exploit_id]["status"] = "failed"
        attack_results[exploit_id]["error"] = str(e)


# تشغيل الخادم
if __name__ == "__main__":
    import asyncio
    uvicorn.run(app, host="0.0.0.0", port=8000)

