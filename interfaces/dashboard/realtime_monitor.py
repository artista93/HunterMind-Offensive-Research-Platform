"""
Real-time Monitor - مراقب مباشر متصل بـ EventBus
"""

import asyncio
from typing import Dict, List, Any
from datetime import datetime
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
import uvicorn

import logging

logger = logging.getLogger(__name__)

app = FastAPI(title="HunterMind Real-time Monitor", version="2.0.0")


class MonitorManager:
    """مدير المراقبة في الوقت الفعلي - متصل بـ EventBus"""
    
    def __init__(self):
        self.active_connections: List[WebSocket] = []
        self.event_history: List[Dict] = []
        self._lock = asyncio.Lock()
        self._event_bus = None
        self._initialized = False
        
        logger.info("MonitorManager initialized")
    
    async def initialize(self):
        """تهيئة المدير والاتصال بـ EventBus"""
        if self._initialized:
            return
        
        try:
            from orchestration.messaging.event_bus import get_event_bus, EventType
            
            self._event_bus = await get_event_bus()
            
            # الاشتراك في جميع الأحداث المهمة
            await self._event_bus.subscribe(EventType.SCAN_STARTED, self._on_scan_started)
            await self._event_bus.subscribe(EventType.SCAN_COMPLETED, self._on_scan_completed)
            await self._event_bus.subscribe(EventType.VULNERABILITY_FOUND, self._on_vulnerability_found)
            await self._event_bus.subscribe(EventType.TASK_START, self._on_task_start)
            await self._event_bus.subscribe(EventType.TASK_COMPLETE, self._on_task_complete)
            await self._event_bus.subscribe(EventType.TASK_FAIL, self._on_task_fail)
            
            self._initialized = True
            logger.info("MonitorManager connected to EventBus")
            
        except Exception as e:
            logger.warning(f"Could not connect to EventBus: {e}")
    
    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        async with self._lock:
            self.active_connections.append(websocket)
        logger.info(f"Client connected. Total: {len(self.active_connections)}")
    
    async def disconnect(self, websocket: WebSocket):
        async with self._lock:
            if websocket in self.active_connections:
                self.active_connections.remove(websocket)
        logger.info(f"Client disconnected. Total: {len(self.active_connections)}")
    
    async def broadcast(self, event: Dict):
        """بث حدث لجميع المتصلين"""
        event["timestamp"] = datetime.now().isoformat()
        
        async with self._lock:
            self.event_history.append(event)
            if len(self.event_history) > 1000:
                self.event_history.pop(0)
            
            disconnected = []
            for connection in self.active_connections:
                try:
                    await connection.send_json(event)
                except Exception:
                    disconnected.append(connection)
            
            for conn in disconnected:
                self.active_connections.remove(conn)
    
    # === Event Handlers ===
    
    async def _on_scan_started(self, event):
        await self.broadcast({
            "type": "scan_started",
            "scan_id": event.data.get("scan_id", "unknown"),
            "target_url": event.data.get("target", "")
        })
    
    async def _on_scan_completed(self, event):
        await self.broadcast({
            "type": "scan_completed",
            "scan_id": event.data.get("scan_id", "unknown"),
            "findings_count": event.data.get("vulnerabilities_count", 0)
        })
    
    async def _on_vulnerability_found(self, event):
        await self.broadcast({
            "type": "vulnerability_found",
            "vulnerability": event.data
        })
    
    async def _on_task_start(self, event):
        await self.broadcast({
            "type": "task_start",
            "data": event.data
        })
    
    async def _on_task_complete(self, event):
        await self.broadcast({
            "type": "task_complete",
            "data": event.data
        })
    
    async def _on_task_fail(self, event):
        await self.broadcast({
            "type": "task_fail",
            "error": event.data.get("error", "Unknown error")
        })


monitor_manager = MonitorManager()


@app.on_event("startup")
async def startup():
    await monitor_manager.initialize()


@app.websocket("/ws/monitor")
async def monitor_websocket(websocket: WebSocket):
    await monitor_manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        await monitor_manager.disconnect(websocket)


# دوال مساعدة للاستخدام المباشر
async def emit_scan_started(scan_id: str, target_url: str):
    await monitor_manager.broadcast({"type": "scan_started", "scan_id": scan_id, "target_url": target_url})

async def emit_scan_completed(scan_id: str, findings_count: int):
    await monitor_manager.broadcast({"type": "scan_completed", "scan_id": scan_id, "findings_count": findings_count})

async def emit_vulnerability_found(vulnerability: Dict):
    await monitor_manager.broadcast({"type": "vulnerability_found", "vulnerability": vulnerability})

async def emit_attack_started(attack_id: str, target_url: str, vuln_type: str):
    await monitor_manager.broadcast({"type": "attack_started", "attack_id": attack_id, "target_url": target_url, "vulnerability_type": vuln_type})

async def emit_attack_result(attack_id: str, success: bool, output: str = ""):
    await monitor_manager.broadcast({"type": "attack_result", "attack_id": attack_id, "success": success, "output": output[:200]})

async def emit_system_alert(severity: str, message: str):
    await monitor_manager.broadcast({"type": "system_alert", "severity": severity, "message": message})


@app.get("/monitor")
async def get_monitor_page():
    return HTMLResponse("<h1>Real-time Monitor</h1><p>Connect via WebSocket at /ws/monitor</p>")


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5001)
