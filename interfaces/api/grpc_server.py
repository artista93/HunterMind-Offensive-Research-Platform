
import asyncio
from typing import Dict, List, Optional, Any
from datetime import datetime
import grpc
from concurrent import futures

import logging

logger = logging.getLogger(__name__)


# تعريف الخدمات (في الإصدار الكامل، سيتم استخدام ملفات .proto)
# هنا نستخدم محاكاة بسيطة للخدمات


class HunterMindServicer:
    """
    خدمة HunterMind gRPC
    ينفذ دوال RPC للتفاعل مع المنصة
    """
    
    def __init__(self):
        self.scans: Dict[str, Dict] = {}
        self.attacks: Dict[str, Dict] = {}
        
        logger.info("HunterMind gRPC servicer initialized")
    
    async def HealthCheck(self, request, context):
        """
        التحقق من صحة الخدمة
        
        Args:
            request: طلب فارغ
            context: سياق gRPC
        
        Returns:
            استجابة الصحة
        """
        return {
            "status": "healthy",
            "timestamp": datetime.now().isoformat(),
            "version": "1.0.0"
        }
    
    async def StartScan(self, request, context):
        """
        بدء فحص أمني
        
        Args:
            request: طلب الفحص (target_url, scan_type, max_depth, max_pages)
            context: سياق gRPC
        
        Returns:
            معرف الفحص
        """
        import uuid
        scan_id = str(uuid.uuid4())[:8]
        
        self.scans[scan_id] = {
            "id": scan_id,
            "target_url": request.get("target_url"),
            "status": "pending",
            "started_at": datetime.now().isoformat()
        }
        
        # تشغيل الفحص في الخلفية
        asyncio.create_task(self._run_scan(scan_id, request))
        
        return {"scan_id": scan_id, "status": "started"}
    
    async def GetScanResults(self, request, context):
        """
        الحصول على نتائج الفحص
        
        Args:
            request: طلب النتائج (scan_id)
            context: سياق gRPC
        
        Returns:
            نتائج الفحص
        """
        scan_id = request.get("scan_id")
        
        if scan_id not in self.scans:
            context.set_code(grpc.StatusCode.NOT_FOUND)
            return {"error": "Scan not found"}
        
        return self.scans[scan_id]
    
    async def StartAttack(self, request, context):
        """
        بدء هجوم
        
        Args:
            request: طلب الهجوم (target_url, vulnerability_type, parameter, payload)
            context: سياق gRPC
        
        Returns:
            معرف الهجوم
        """
        import uuid
        attack_id = str(uuid.uuid4())[:8]
        
        self.attacks[attack_id] = {
            "id": attack_id,
            "target_url": request.get("target_url"),
            "vulnerability_type": request.get("vulnerability_type"),
            "status": "pending",
            "started_at": datetime.now().isoformat()
        }
        
        asyncio.create_task(self._run_attack(attack_id, request))
        
        return {"attack_id": attack_id, "status": "started"}
    
    async def GetAttackResults(self, request, context):
        """
        الحصول على نتائج الهجوم
        
        Args:
            request: طلب النتائج (attack_id)
            context: سياق gRPC
        
        Returns:
            نتائج الهجوم
        """
        attack_id = request.get("attack_id")
        
        if attack_id not in self.attacks:
            context.set_code(grpc.StatusCode.NOT_FOUND)
            return {"error": "Attack not found"}
        
        return self.attacks[attack_id]
    
    async def ListScans(self, request, context):
        """
        قائمة الفحوصات
        
        Args:
            request: طلب فارغ
            context: سياق gRPC
        
        Returns:
            قائمة الفحوصات
        """
        return {"scans": list(self.scans.values())}
    
    async def ListAttacks(self, request, context):
        """
        قائمة الهجمات
        
        Args:
            request: طلب فارغ
            context: سياق gRPC
        
        Returns:
            قائمة الهجمات
        """
        return {"attacks": list(self.attacks.values())}
    
    async def _run_scan(self, scan_id: str, request: Dict):
        """تنفيذ الفحص في الخلفية"""
        self.scans[scan_id]["status"] = "running"
        
        try:
            # محاكاة الفحص
            await asyncio.sleep(2)
            
            self.scans[scan_id]["status"] = "completed"
            self.scans[scan_id]["completed_at"] = datetime.now().isoformat()
            self.scans[scan_id]["findings"] = [
                {
                    "type": "XSS",
                    "severity": "high",
                    "url": request.get("target_url"),
                    "parameter": "q"
                }
            ]
            
        except Exception as e:
            self.scans[scan_id]["status"] = "failed"
            self.scans[scan_id]["error"] = str(e)
    
    async def _run_attack(self, attack_id: str, request: Dict):
        """تنفيذ الهجوم في الخلفية"""
        self.attacks[attack_id]["status"] = "running"
        
        try:
            await asyncio.sleep(1.5)
            
            self.attacks[attack_id]["status"] = "completed"
            self.attacks[attack_id]["completed_at"] = datetime.now().isoformat()
            self.attacks[attack_id]["result"] = {
                "success": True,
                "output": "Attack completed successfully"
            }
            
        except Exception as e:
            self.attacks[attack_id]["status"] = "failed"
            self.attacks[attack_id]["error"] = str(e)


class GRPCServer:
    """
    خادم gRPC المتقدم
    يدير تشغيل وإيقاف خادم gRPC
    """
    
    def __init__(self, port: int = 50051):
        self.port = port
        self.server = None
        self.servicer = None
        self._running = False
        
        logger.info(f"gRPC server initialized (port={port})")
    
    async def start(self):
        """بدء تشغيل الخادم"""
        if self._running:
            return
        
        self.server = grpc.aio.server(futures.ThreadPoolExecutor(max_workers=10))
        self.servicer = HunterMindServicer()
        
        # تسجيل الخدمة (في الإصدار الكامل، سيتم استخدام add_HunterMindServicer_to_server)
        # هنا نستخدم محاكاة بسيطة
        
        self.server.add_insecure_port(f'[::]:{self.port}')
        
        await self.server.start()
        self._running = True
        
        logger.info(f"gRPC server started on port {self.port}")
    
    async def stop(self, grace: int = 5):
        """إيقاف تشغيل الخادم"""
        if not self._running:
            return
        
        await self.server.stop(grace)
        self._running = False
        
        logger.info("gRPC server stopped")
    
    async def wait_for_termination(self):
        """انتظار إنهاء الخادم"""
        if self.server:
            await self.server.wait_for_termination()
    
    def is_running(self) -> bool:
        """هل الخادم قيد التشغيل؟"""
        return self._running


# إنشاء الخادم العالمي
_default_server = None


async def get_grpc_server() -> GRPCServer:
    """الحصول على نسخة من خادم gRPC"""
    global _default_server
    if _default_server is None:
        _default_server = GRPCServer()
        await _default_server.start()
    return _default_server


# تشغيل الخادم (للاستخدام المباشر)
if __name__ == "__main__":
    import asyncio
    
    async def main():
        server = await get_grpc_server()
        print(f"gRPC server running on port 50051")
        await server.wait_for_termination()
    
    asyncio.run(main())

