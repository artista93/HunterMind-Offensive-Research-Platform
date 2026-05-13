
import asyncio
from typing import Dict, List, Optional, Any, Set
from datetime import datetime

from ..base.base_agent import BaseAgent, AgentPriority, AgentMessage
from ..base.agent_state import AgentStateEnum
from offensive.recon.attack_surface_mapper import AttackSurfaceMapper, AttackSurface
from offensive.recon.js_processor import JSProcessor
from offensive.recon.form_extractor import FormExtractor
from offensive.recon.api_collector import APICollector
from offensive.recon.enhanced_crawler import CrawlResult

import logging

logger = logging.getLogger(__name__)


class ReconAgent(BaseAgent):
    """
    وكيل الاستطلاع المتقدم
    
    الميزات:
    - تحليل شامل لسطح الهجوم
    - كشف التقنيات المستخدمة
    - استخراج المعلومات الحساسة
    - تحليل ملفات JavaScript
    - جمع واجهات API
    - تقارير مفصلة
    """
    
    def __init__(
        self,
        name: str = "ReconAgent",
        priority: AgentPriority = AgentPriority.HIGH,
        max_depth: int = 3,
        max_pages: int = 100
    ):
        super().__init__(name, priority)
        
        self._max_depth = max_depth
        self._max_pages = max_pages
        
        # مكونات الاستطلاع
        self._surface_mapper = AttackSurfaceMapper()
        self._js_processor = JSProcessor()
        self._form_extractor = FormExtractor()
        self._api_collector = APICollector()
        
        # نتائج الاستطلاع
        self._attack_surfaces: Dict[str, AttackSurface] = {}
        self._active_recons: Set[str] = set()
        
        logger.info(f"ReconAgent initialized: {name}")
    
    async def _on_initialize(self):
        """تهيئة الوكيل"""
        logger.info("Initializing ReconAgent components...")
    
    async def _on_start(self):
        """بدء تشغيل الوكيل"""
        logger.info("ReconAgent started")
    
    async def _on_stop(self):
        """إيقاف تشغيل الوكيل"""
        # إلغاء الاستطلاع النشط
        for recon_id in list(self._active_recons):
            await self.stop_recon(recon_id)
        
        # إغلاق المكونات
        await self._surface_mapper.close()
        await self._js_processor.close()
        await self._api_collector.close()
        
        logger.info("ReconAgent stopped")
    
    async def _handle_message(self, message: AgentMessage) -> Optional[AgentMessage]:
        """
        معالجة الرسائل الواردة
        
        أنواع الرسائل المدعومة:
        - start_recon: بدء استطلاع جديد
        - stop_recon: إيقاف استطلاع
        - get_status: الحصول على حالة استطلاع
        - get_report: الحصول على تقرير الاستطلاع
        - get_technologies: الحصول على التقنيات المكتشفة
        """
        if message.type == "start_recon":
            result = await self.start_recon(message.content)
            return AgentMessage(
                id="",
                sender=self.name,
                receiver=message.sender,
                type="recon_started",
                content={"recon_id": result.get("recon_id")}
            )
        
        elif message.type == "stop_recon":
            success = await self.stop_recon(message.content.get("recon_id"))
            return AgentMessage(
                id="",
                sender=self.name,
                receiver=message.sender,
                type="recon_stopped",
                content={"success": success}
            )
        
        elif message.type == "get_status":
            status = await self.get_recon_status(message.content.get("recon_id"))
            return AgentMessage(
                id="",
                sender=self.name,
                receiver=message.sender,
                type="recon_status",
                content=status
            )
        
        elif message.type == "get_report":
            report = await self.get_report(message.content.get("recon_id"), message.content.get("format", "json"))
            return AgentMessage(
                id="",
                sender=self.name,
                receiver=message.sender,
                type="recon_report",
                content={"report": report}
            )
        
        elif message.type == "get_technologies":
            technologies = await self.get_detected_technologies(message.content.get("recon_id"))
            return AgentMessage(
                id="",
                sender=self.name,
                receiver=message.sender,
                type="technologies",
                content={"technologies": technologies}
            )
        
        return await super()._handle_message(message)
    
    async def start_recon(
        self,
        target_url: str,
        options: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """
        بدء استطلاع جديد
        
        Args:
            target_url: الرابط المستهدف
            options: خيارات إضافية (max_depth, max_pages, إلخ)
        
        Returns:
            معلومات الاستطلاع
        """
        # تحديث الحالة
        self._state_manager.transition_to(
            AgentStateEnum.BUSY,
            reason=f"Starting recon of {target_url}"
        )
        
        # إنشاء معرف الاستطلاع
        import uuid
        recon_id = str(uuid.uuid4())[:8]
        
        # تحديث الخيارات
        max_depth = options.get("max_depth", self._max_depth) if options else self._max_depth
        max_pages = options.get("max_pages", self._max_pages) if options else self._max_pages
        
        # إعادة تهيئة المكونات
        self._surface_mapper = AttackSurfaceMapper()
        
        self._active_recons.add(recon_id)
        
        try:
            # تنفيذ الاستطلاع
            surface = await self._surface_mapper.map_attack_surface(
                target_url=target_url,
                max_depth=max_depth,
                max_pages=max_pages
            )
            
            # تخزين النتيجة
            self._attack_surfaces[recon_id] = surface
            
            # تحديث الإحصائيات
            self._context.tasks_completed += 1
            
            logger.info(f"Recon completed: {target_url} - {surface.total_pages} pages, {len(surface.technologies)} technologies")
            
            return {
                "recon_id": recon_id,
                "status": "completed",
                "pages_analyzed": surface.total_pages,
                "technologies_found": len(surface.technologies),
                "entry_points": surface.total_entry_points,
                "apis_found": len(surface.api_endpoints),
                "duration": (surface.analyzed_at - surface.analyzed_at).total_seconds() if hasattr(surface, 'analyzed_at') else 0
            }
            
        except Exception as e:
            logger.error(f"Recon failed: {e}")
            self._context.tasks_failed += 1
            raise
            
        finally:
            self._active_recons.discard(recon_id)
            self._state_manager.transition_to(AgentStateEnum.IDLE, reason="Recon completed")
    
    async def stop_recon(self, recon_id: str) -> bool:
        """
        إيقاف استطلاع قيد التنفيذ
        
        Args:
            recon_id: معرف الاستطلاع
        
        Returns:
            نجاح الإيقاف
        """
        if recon_id not in self._active_recons:
            logger.warning(f"Recon {recon_id} not active")
            return False
        
        await self._surface_mapper.close()
        self._active_recons.discard(recon_id)
        
        logger.info(f"Recon {recon_id} stopped")
        return True
    
    async def get_recon_status(self, recon_id: str = None) -> Dict:
        """
        الحصول على حالة الاستطلاع
        
        Args:
            recon_id: معرف الاستطلاع (آخر استطلاع إذا None)
        
        Returns:
            حالة الاستطلاع
        """
        if recon_id and recon_id in self._attack_surfaces:
            surface = self._attack_surfaces[recon_id]
            return {
                "recon_id": recon_id,
                "status": "completed",
                "target_url": surface.target_url,
                "pages_analyzed": surface.total_pages,
                "technologies_found": len(surface.technologies),
                "entry_points": surface.total_entry_points,
                "high_risk": surface.summary.get("risk_levels", {}).get("high", 0),
                "medium_risk": surface.summary.get("risk_levels", {}).get("medium", 0),
                "low_risk": surface.summary.get("risk_levels", {}).get("low", 0),
                "analyzed_at": surface.analyzed_at.isoformat()
            }
        
        # آخر استطلاع
        if self._attack_surfaces:
            last_id = list(self._attack_surfaces.keys())[-1]
            return await self.get_recon_status(last_id)
        
        return {"status": "no_recon"}
    
    async def get_report(
        self,
        recon_id: str = None,
        format: str = "json"
    ) -> str:
        """
        الحصول على تقرير الاستطلاع
        
        Args:
            recon_id: معرف الاستطلاع (آخر استطلاع إذا None)
            format: صيغة التقرير (json, markdown)
        
        Returns:
            التقرير كنص
        """
        if recon_id:
            surface = self._attack_surfaces.get(recon_id)
        else:
            if self._attack_surfaces:
                last_id = list(self._attack_surfaces.keys())[-1]
                surface = self._attack_surfaces.get(last_id)
            else:
                surface = None
        
        if not surface:
            return "No reconnaissance data available"
        
        return await self._surface_mapper.generate_report(surface, format)
    
    async def get_attack_surface(self, recon_id: str = None) -> Optional[AttackSurface]:
        """
        الحصول على كائن سطح الهجوم
        
        Args:
            recon_id: معرف الاستطلاع (آخر استطلاع إذا None)
        
        Returns:
            كائن AttackSurface
        """
        if recon_id:
            return self._attack_surfaces.get(recon_id)
        
        if self._attack_surfaces:
            last_id = list(self._attack_surfaces.keys())[-1]
            return self._attack_surfaces.get(last_id)
        
        return None
    
    async def get_detected_technologies(self, recon_id: str = None) -> List[Dict]:
        """
        الحصول على التقنيات المكتشفة
        
        Args:
            recon_id: معرف الاستطلاع
        
        Returns:
            قائمة بالتقنيات
        """
        surface = await self.get_attack_surface(recon_id)
        if not surface:
            return []
        
        return [
            {
                "name": tech.name,
                "confidence": tech.confidence,
                "category": tech.name.split(':')[0] if ':' in tech.name else "General"
            }
            for tech in surface.technologies
        ]
    
    async def get_entry_points(self, recon_id: str = None) -> List[Dict]:
        """
        الحصول على نقاط الدخول المكتشفة
        
        Args:
            recon_id: معرف الاستطلاع
        
        Returns:
            قائمة بنقاط الدخول
        """
        surface = await self.get_attack_surface(recon_id)
        if not surface:
            return []
        
        return [
            {
                "url": ep.url,
                "type": ep.type,
                "method": ep.method,
                "parameters": ep.parameters
            }
            for ep in surface.entry_points
        ]
    
    async def get_recommendations(self, recon_id: str = None) -> List[str]:
        """
        الحصول على توصيات أمنية
        
        Args:
            recon_id: معرف الاستطلاع
        
        Returns:
            قائمة بالتوصيات
        """
        surface = await self.get_attack_surface(recon_id)
        if not surface:
            return []
        
        return surface.summary.get("recommendations", [])
    
    async def get_summary(self) -> Dict:
        """ملخص الاستطلاعات"""
        return {
            "total_recons": len(self._attack_surfaces),
            "active_recons": len(self._active_recons),
            "completed_recons": len([s for s in self._attack_surfaces.values() if s.status == "completed"]) if self._attack_surfaces else 0,
            "failed_recons": len([s for s in self._attack_surfaces.values() if s.status == "failed"]) if self._attack_surfaces else 0,
            "total_pages_analyzed": sum(s.total_pages for s in self._attack_surfaces.values()),
            "total_technologies": sum(len(s.technologies) for s in self._attack_surfaces.values()),
            "total_entry_points": sum(s.total_entry_points for s in self._attack_surfaces.values())
        }
    
    async def get_statistics(self) -> Dict:
        """إحصائيات الوكيل"""
        base_stats = await super().get_statistics()
        
        return {
            **base_stats,
            "recon_specific": await self.get_summary()
        }
    
    async def clear_results(self):
        """مسح جميع نتائج الاستطلاع"""
        self._attack_surfaces.clear()
        logger.info("All recon results cleared")


# نسخة عالمية
_default_recon_agent = None


async def get_recon_agent() -> ReconAgent:
    """الحصول على نسخة من وكيل الاستطلاع"""
    global _default_recon_agent
    if _default_recon_agent is None:
        _default_recon_agent = ReconAgent()
        await _default_recon_agent.initialize()
        await _default_recon_agent.start()
    return _default_recon_agent

