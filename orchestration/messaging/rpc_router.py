
import asyncio
from typing import Dict, List, Optional, Any, Callable, Awaitable
from dataclasses import dataclass, field
from datetime import datetime
import uuid

import logging

logger = logging.getLogger(__name__)


@dataclass
class RPCRequest:
    """طلب RPC"""
    id: str
    method: str
    params: Any
    source: str
    timestamp: datetime = field(default_factory=datetime.now)
    timeout: float = 30.0


@dataclass
class RPCResponse:
    """استجابة RPC"""
    request_id: str
    result: Any
    error: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.now)


class RPCRouter:
    """
    موجه RPC المتقدم
    
    الميزات:
    - استدعاء الإجراءات عن بُعد
    - مهلات زمنية
    - تسجيل الخدمات
    - تتبع الطلبات
    """
    
    def __init__(self):
        self.services: Dict[str, Dict[str, Callable]] = {}
        self.pending_requests: Dict[str, asyncio.Future] = {}
        self.request_history: List[Dict] = []
        self._lock = asyncio.Lock()
        
        logger.info("RPCRouter initialized")
    
    def register_service(self, service_name: str, methods: Dict[str, Callable]):
        """
        تسجيل خدمة جديدة
        
        Args:
            service_name: اسم الخدمة
            methods: قاموس الأساليب (اسم الأسلوب -> دالة المعالجة)
        """
        self.services[service_name] = methods
        logger.info(f"Service registered: {service_name} with {len(methods)} methods")
    
    def unregister_service(self, service_name: str) -> bool:
        """
        إلغاء تسجيل خدمة
        
        Args:
            service_name: اسم الخدمة
        
        Returns:
            نجاح الإلغاء
        """
        if service_name in self.services:
            del self.services[service_name]
            logger.info(f"Service unregistered: {service_name}")
            return True
        return False
    
    async def call(
        self,
        service_name: str,
        method: str,
        params: Any = None,
        source: str = "unknown",
        timeout: float = 30.0
    ) -> Any:
        """
        استدعاء طريقة عن بُعد
        
        Args:
            service_name: اسم الخدمة
            method: اسم الأسلوب
            params: المعاملات
            source: مصدر الطلب
            timeout: مهلة الاستدعاء
        
        Returns:
            نتيجة الاستدعاء
        """
        request_id = str(uuid.uuid4())[:8]
        
        # إنشاء مستقبل للانتظار
        future = asyncio.Future()
        
        async with self._lock:
            self.pending_requests[request_id] = future
        
        # محاكاة إرسال الطلب (في الإصدار الكامل، سيتم إرساله عبر الشبكة)
        asyncio.create_task(self._process_request(request_id, service_name, method, params, source))
        
        try:
            result = await asyncio.wait_for(future, timeout=timeout)
            return result
        except asyncio.TimeoutError:
            async with self._lock:
                self.pending_requests.pop(request_id, None)
            raise TimeoutError(f"RPC call to {service_name}.{method} timed out after {timeout}s")
    
    async def _process_request(
        self,
        request_id: str,
        service_name: str,
        method: str,
        params: Any,
        source: str
    ):
        """معالجة طلب RPC"""
        # تسجيل الطلب
        self.request_history.append({
            "request_id": request_id,
            "service": service_name,
            "method": method,
            "source": source,
            "timestamp": datetime.now().isoformat()
        })
        
        # الحفاظ على آخر 1000 طلب
        if len(self.request_history) > 1000:
            self.request_history.pop(0)
        
        # البحث عن الخدمة والأسلوب
        if service_name not in self.services:
            error = f"Service not found: {service_name}"
            await self._send_response(request_id, None, error)
            return
        
        if method not in self.services[service_name]:
            error = f"Method not found: {service_name}.{method}"
            await self._send_response(request_id, None, error)
            return
        
        handler = self.services[service_name][method]
        
        try:
            if asyncio.iscoroutinefunction(handler):
                result = await handler(params)
            else:
                result = handler(params)
            
            await self._send_response(request_id, result, None)
            
        except Exception as e:
            await self._send_response(request_id, None, str(e))
    
    async def _send_response(self, request_id: str, result: Any, error: Optional[str]):
        """إرسال استجابة RPC"""
        async with self._lock:
            future = self.pending_requests.pop(request_id, None)
            if future and not future.done():
                if error:
                    future.set_exception(Exception(error))
                else:
                    future.set_result(result)
    
    async def handle_request(self, request: RPCRequest) -> RPCResponse:
        """
        معالجة طلب RPC مباشر (للاستخدام الداخلي)
        
        Args:
            request: طلب RPC
        
        Returns:
            استجابة RPC
        """
        if request.service not in self.services:
            return RPCResponse(
                request_id=request.id,
                result=None,
                error=f"Service not found: {request.service}"
            )
        
        if request.method not in self.services[request.service]:
            return RPCResponse(
                request_id=request.id,
                result=None,
                error=f"Method not found: {request.service}.{request.method}"
            )
        
        handler = self.services[request.service][request.method]
        
        try:
            if asyncio.iscoroutinefunction(handler):
                result = await handler(request.params)
            else:
                result = handler(request.params)
            
            return RPCResponse(
                request_id=request.id,
                result=result
            )
            
        except Exception as e:
            return RPCResponse(
                request_id=request.id,
                result=None,
                error=str(e)
            )
    
    async def get_statistics(self) -> Dict:
        """إحصائيات موجه RPC"""
        total_requests = len(self.request_history)
        
        # إحصائيات حسب الخدمة
        service_stats = {}
        for req in self.request_history:
            service = req["service"]
            if service not in service_stats:
                service_stats[service] = 0
            service_stats[service] += 1
        
        return {
            "total_requests": total_requests,
            "pending_requests": len(self.pending_requests),
            "registered_services": len(self.services),
            "total_methods": sum(len(methods) for methods in self.services.values()),
            "service_stats": service_stats
        }

