
import asyncio
from typing import Dict, List, Optional, Any, Set
from datetime import datetime

from ..base.base_agent import BaseAgent, AgentPriority, AgentMessage
from ..base.agent_state import AgentStateEnum
from ...offensive.recon.enhanced_crawler import EnhancedCrawler, CrawlResult, CrawledPage
from ...offensive.recon.js_processor import JSProcessor
from ...offensive.recon.form_extractor import FormExtractor
from ...offensive.recon.api_collector import APICollector

import logging

logger = logging.getLogger(__name__)


class CrawlerAgent(BaseAgent):
    """
    وكيل الزحف المتقدم
    
    الميزات:
    - زحف تلقائي للمواقع
    - اكتشاف SPA وتنفيذ JavaScript
    - استخراج الروابط والنماذج وواجهات API
    - تخزين النتائج في الذاكرة
    - معالجة الأخطاء وإعادة المحاولة
    - تقييد المعدل التلقائي
    """
    
    def __init__(
        self,
        name: str = "CrawlerAgent",
        priority: AgentPriority = AgentPriority.NORMAL,
        max_depth: int = 3,
        max_pages: int = 100,
        max_concurrent: int = 5
    ):
        super().__init__(name, priority)
        
        self._max_depth = max_depth
        self._max_pages = max_pages
        self._max_concurrent = max_concurrent
        
        # مكونات الزحف
        self._crawler = EnhancedCrawler(
            max_depth=max_depth,
            max_pages=max_pages,
            max_concurrent=max_concurrent
        )
        self._js_processor = JSProcessor()
        self._form_extractor = FormExtractor()
        self._api_collector = APICollector()
        
        # نتائج الزحف
        self._crawl_results: Dict[str, CrawlResult] = {}
        self._active_crawls: Set[str] = set()
        
        logger.info(f"CrawlerAgent initialized: {name}")
    
    async def _on_initialize(self):
        """تهيئة الوكيل"""
        logger.info("Initializing CrawlerAgent components...")
        # يمكن إضافة تهيئة إضافية هنا
    
    async def _on_start(self):
        """بدء تشغيل الوكيل"""
        logger.info("CrawlerAgent started")
    
    async def _on_stop(self):
        """إيقاف تشغيل الوكيل"""
        # إلغاء الزحف النشط
        for crawl_id in list(self._active_crawls):
            await self.stop_crawl(crawl_id)
        
        # إغلاق المكونات
        await self._crawler.close()
        await self._js_processor.close()
        await self._api_collector.close()
        
        logger.info("CrawlerAgent stopped")
    
    async def _handle_message(self, message: AgentMessage) -> Optional[AgentMessage]:
        """
        معالجة الرسائل الواردة
        
        أنواع الرسائل المدعومة:
        - start_crawl: بدء زحف جديد
        - stop_crawl: إيقاف زحف
        - get_status: الحصول على حالة زحف
        - get_results: الحصول على نتائج الزحف
        """
        if message.type == "start_crawl":
            result = await self.start_crawl(message.content)
            return AgentMessage(
                id="",
                sender=self.name,
                receiver=message.sender,
                type="crawl_started",
                content={"crawl_id": result.crawl_id if hasattr(result, 'crawl_id') else None}
            )
        
        elif message.type == "stop_crawl":
            success = await self.stop_crawl(message.content.get("crawl_id"))
            return AgentMessage(
                id="",
                sender=self.name,
                receiver=message.sender,
                type="crawl_stopped",
                content={"success": success}
            )
        
        elif message.type == "get_status":
            status = await self.get_crawl_status(message.content.get("crawl_id"))
            return AgentMessage(
                id="",
                sender=self.name,
                receiver=message.sender,
                type="crawl_status",
                content=status
            )
        
        elif message.type == "get_results":
            results = await self.get_crawl_results(message.content.get("crawl_id"))
            return AgentMessage(
                id="",
                sender=self.name,
                receiver=message.sender,
                type="crawl_results",
                content={"results": results}
            )
        
        return await super()._handle_message(message)
    
    async def start_crawl(
        self,
        target_url: str,
        options: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """
        بدء زحف جديد
        
        Args:
            target_url: الرابط المستهدف
            options: خيارات إضافية (max_depth, max_pages, إلخ)
        
        Returns:
            معلومات الزحف
        """
        # تحديث الحالة
        self._state_manager.transition_to(
            AgentStateEnum.BUSY,
            reason=f"Starting crawl of {target_url}"
        )
        
        # إنشاء معرف الزحف
        import uuid
        crawl_id = str(uuid.uuid4())[:8]
        
        # تحديث الخيارات
        max_depth = options.get("max_depth", self._max_depth) if options else self._max_depth
        max_pages = options.get("max_pages", self._max_pages) if options else self._max_pages
        
        # إعادة تهيئة الزاحف بالإعدادات الجديدة
        self._crawler = EnhancedCrawler(
            max_depth=max_depth,
            max_pages=max_pages,
            max_concurrent=self._max_concurrent
        )
        
        # بدء الزحف
        self._active_crawls.add(crawl_id)
        
        try:
            # تنفيذ الزحف
            result = await self._crawler.crawl(target_url, max_depth, max_pages)
            
            # تخزين النتيجة
            self._crawl_results[crawl_id] = result
            result.crawl_id = crawl_id
            
            # تحديث الإحصائيات
            self._context.tasks_completed += 1
            
            logger.info(f"Crawl completed: {target_url} - {len(result.pages_crawled)} pages")
            
            return {
                "crawl_id": crawl_id,
                "status": "completed",
                "pages_crawled": len(result.pages_crawled),
                "total_forms": result.total_forms,
                "total_apis": result.total_api_endpoints,
                "duration": (result.end_time - result.start_time).total_seconds() if result.end_time else 0
            }
            
        except Exception as e:
            logger.error(f"Crawl failed: {e}")
            self._context.tasks_failed += 1
            raise
            
        finally:
            self._active_crawls.discard(crawl_id)
            self._state_manager.transition_to(AgentStateEnum.IDLE, reason="Crawl completed")
    
    async def stop_crawl(self, crawl_id: str) -> bool:
        """
        إيقاف زحف قيد التنفيذ
        
        Args:
            crawl_id: معرف الزحف
        
        Returns:
            نجاح الإيقاف
        """
        if crawl_id not in self._active_crawls:
            logger.warning(f"Crawl {crawl_id} not active")
            return False
        
        await self._crawler.close()
        self._active_crawls.discard(crawl_id)
        
        logger.info(f"Crawl {crawl_id} stopped")
        return True
    
    async def get_crawl_status(self, crawl_id: str = None) -> Dict:
        """
        الحصول على حالة الزحف
        
        Args:
            crawl_id: معرف الزحف (آخر زحف إذا None)
        
        Returns:
            حالة الزحف
        """
        if crawl_id and crawl_id in self._crawl_results:
            result = self._crawl_results[crawl_id]
            return {
                "crawl_id": crawl_id,
                "status": result.status,
                "pages_crawled": len(result.pages_crawled),
                "total_forms": result.total_forms,
                "total_apis": result.total_api_endpoints,
                "errors": len(result.errors),
                "start_time": result.start_time.isoformat(),
                "end_time": result.end_time.isoformat() if result.end_time else None
            }
        
        # آخر زحف
        if self._crawl_results:
            last_id = list(self._crawl_results.keys())[-1]
            return await self.get_crawl_status(last_id)
        
        return {"status": "no_crawls"}
    
    async def get_crawl_results(self, crawl_id: str = None) -> Optional[CrawlResult]:
        """
        الحصول على نتائج الزحف
        
        Args:
            crawl_id: معرف الزحف (آخر زحف إذا None)
        
        Returns:
            نتائج الزحف
        """
        if crawl_id:
            return self._crawl_results.get(crawl_id)
        
        if self._crawl_results:
            last_id = list(self._crawl_results.keys())[-1]
            return self._crawl_results.get(last_id)
        
        return None
    
    async def get_all_results(self) -> List[Dict]:
        """
        الحصول على جميع نتائج الزحف
        
        Returns:
            قائمة بنتائج الزحف
        """
        results = []
        for crawl_id, result in self._crawl_results.items():
            results.append({
                "crawl_id": crawl_id,
                "target_url": result.start_url,
                "pages_crawled": len(result.pages_crawled),
                "total_forms": result.total_forms,
                "total_apis": result.total_api_endpoints,
                "start_time": result.start_time.isoformat(),
                "end_time": result.end_time.isoformat() if result.end_time else None
            })
        return results
    
    async def search_pages(self, query: str) -> List[CrawledPage]:
        """
        البحث في الصفحات التي تم زحفها
        
        Args:
            query: نص البحث
        
        Returns:
            قائمة بالصفحات المطابقة
        """
        results = []
        
        for crawl_result in self._crawl_results.values():
            for page in crawl_result.pages_crawled:
                if query.lower() in page.title.lower() or query.lower() in page.url.lower():
                    results.append(page)
        
        return results
    
    async def get_all_urls(self) -> List[str]:
        """الحصول على جميع الروابط التي تم اكتشافها"""
        urls = set()
        
        for crawl_result in self._crawl_results.values():
            for page in crawl_result.pages_crawled:
                urls.add(page.url)
                urls.update(page.links)
        
        return list(urls)
    
    async def get_all_forms(self) -> List[Dict]:
        """الحصول على جميع النماذج التي تم اكتشافها"""
        forms = []
        
        for crawl_result in self._crawl_results.values():
            for page in crawl_result.pages_crawled:
                for form in page.forms:
                    forms.append({
                        "url": page.url,
                        "action": form.get("action"),
                        "method": form.get("method"),
                        "inputs": form.get("inputs", [])
                    })
        
        return forms
    
    async def get_all_apis(self) -> List[str]:
        """الحصول على جميع واجهات API التي تم اكتشافها"""
        apis = set()
        
        for crawl_result in self._crawl_results.values():
            for page in crawl_result.pages_crawled:
                apis.update(page.api_endpoints)
        
        return list(apis)
    
    async def get_statistics(self) -> Dict:
        """إحصائيات الوكيل"""
        base_stats = await super().get_statistics()
        
        return {
            **base_stats,
            "crawler_specific": {
                "total_crawls": len(self._crawl_results),
                "active_crawls": len(self._active_crawls),
                "max_depth": self._max_depth,
                "max_pages": self._max_pages,
                "max_concurrent": self._max_concurrent,
                "total_pages_crawled": sum(len(r.pages_crawled) for r in self._crawl_results.values()),
                "total_forms_found": sum(r.total_forms for r in self._crawl_results.values()),
                "total_apis_found": sum(r.total_api_endpoints for r in self._crawl_results.values())
            }
        }
    
    async def clear_results(self):
        """مسح جميع نتائج الزحف"""
        self._crawl_results.clear()
        logger.info("All crawl results cleared")


# نسخة عالمية
_default_crawler_agent = None


async def get_crawler_agent() -> CrawlerAgent:
    """الحصول على نسخة من وكيل الزحف"""
    global _default_crawler_agent
    if _default_crawler_agent is None:
        _default_crawler_agent = CrawlerAgent()
        await _default_crawler_agent.initialize()
        await _default_crawler_agent.start()
    return _default_crawler_agent

