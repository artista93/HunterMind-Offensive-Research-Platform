
import asyncio
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass, field
from datetime import datetime

from ..recon.enhanced_crawler import EnhancedCrawler, CrawlResult
from ..recon.js_processor import JSProcessor, JSAnalysisResult
from ..recon.form_extractor import FormExtractor, ExtractedForm
from ..recon.api_collector import APICollector, APIEndpoint
from ..recon.attack_surface_mapper import AttackSurfaceMapper, AttackSurface

import logging

logger = logging.getLogger(__name__)


@dataclass
class ReconPipelineResult:
    """نتائج خط أنابيب الاستطلاع"""
    target_url: str
    start_time: datetime
    end_time: Optional[datetime] = None
    crawl_result: Optional[CrawlResult] = None
    js_analysis: List[JSAnalysisResult] = field(default_factory=list)
    forms: List[ExtractedForm] = field(default_factory=list)
    api_endpoints: List[APIEndpoint] = field(default_factory=list)
    attack_surface: Optional[AttackSurface] = None
    total_pages: int = 0
    total_forms: int = 0
    total_api_endpoints: int = 0
    total_js_files: int = 0
    sensitive_info_found: int = 0
    status: str = "pending"
    error: Optional[str] = None


class ReconPipeline:
    """
    خط أنابيب الاستطلاع المتكامل
    
    الميزات:
    - زحف متقدم للموقع (SPA + JavaScript)
    - تحليل ملفات JavaScript
    - استخراج النماذج وتحليلها
    - جمع واجهات API
    - تحليل سطح الهجوم
    - كشف المعلومات الحساسة
    """
    
    def __init__(self):
        self._crawler = EnhancedCrawler()
        self._js_processor = JSProcessor()
        self._form_extractor = FormExtractor()
        self._api_collector = APICollector()
        self._surface_mapper = AttackSurfaceMapper()
        
        self._active_pipelines: Dict[str, ReconPipelineResult] = {}
        
        logger.info("ReconPipeline initialized")
    
    async def run(
        self,
        target_url: str,
        max_depth: int = 3,
        max_pages: int = 100,
        analyze_js: bool = True,
        extract_forms: bool = True,
        collect_apis: bool = True,
        map_surface: bool = True
    ) -> ReconPipelineResult:
        """
        تنفيذ خط أنابيب الاستطلاع كامل
        
        Args:
            target_url: الرابط المستهدف
            max_depth: أقصى عمق للزحف
            max_pages: الحد الأقصى للصفحات
            analyze_js: تحليل ملفات JavaScript
            extract_forms: استخراج النماذج
            collect_apis: جمع واجهات API
            map_surface: تحليل سطح الهجوم
        
        Returns:
            نتائج خط الأنابيب
        """
        pipeline_id = f"recon_{target_url}_{int(datetime.now().timestamp())}"
        
        result = ReconPipelineResult(
            target_url=target_url,
            start_time=datetime.now()
        )
        
        self._active_pipelines[pipeline_id] = result
        
        logger.info(f"Starting Recon pipeline for {target_url}")
        
        try:
            # 1. زحف الموقع
            logger.info("Phase 1: Crawling...")
            crawl_result = await self._crawler.crawl(target_url, max_depth, max_pages)
            result.crawl_result = crawl_result
            result.total_pages = len(crawl_result.pages_crawled)
            
            # 2. تحليل JavaScript
            if analyze_js:
                logger.info("Phase 2: Analyzing JavaScript...")
                js_files = await self._js_processor.find_all_js_files("", target_url)
                result.total_js_files = len(js_files)
                
                for js_url in js_files[:20]:  # حد أقصى 20 ملف
                    analysis = await self._js_processor.process_url(js_url, target_url)
                    if analysis:
                        result.js_analysis.append(analysis)
                        result.sensitive_info_found += len(analysis.sensitive_info)
            
            # 3. استخراج النماذج
            if extract_forms and crawl_result.pages_crawled:
                logger.info("Phase 3: Extracting forms...")
                for page in crawl_result.pages_crawled[:50]:  # حد أقصى 50 صفحة
                    # استخراج النماذج من محتوى الصفحة (محاكاة)
                    # في الإصدار الكامل، سيتم استخدام المحتوى الفعلي
                    pass
            
            # 4. جمع واجهات API
            if collect_apis:
                logger.info("Phase 4: Collecting API endpoints...")
                for page in crawl_result.pages_crawled[:30]:
                    endpoints = await self._api_collector.collect_from_html("", page.url)
                    result.api_endpoints.extend(endpoints)
                
                # إزالة التكرارات
                seen = set()
                unique_endpoints = []
                for ep in result.api_endpoints:
                    if ep.full_url not in seen:
                        seen.add(ep.full_url)
                        unique_endpoints.append(ep)
                result.api_endpoints = unique_endpoints
                result.total_api_endpoints = len(result.api_endpoints)
            
            # 5. تحليل سطح الهجوم
            if map_surface:
                logger.info("Phase 5: Mapping attack surface...")
                surface = await self._surface_mapper.map_attack_surface(target_url, max_depth, max_pages)
                result.attack_surface = surface
            
            result.status = "completed"
            
        except Exception as e:
            logger.error(f"Recon pipeline failed: {e}")
            result.status = "failed"
            result.error = str(e)
        
        finally:
            result.end_time = datetime.now()
            await self._close()
        
        logger.info(f"Recon pipeline completed: {result.total_pages} pages, {result.total_api_endpoints} APIs, {result.sensitive_info_found} sensitive items")
        
        return result
    
    async def recon_quick(
        self,
        target_url: str,
        max_pages: int = 20
    ) -> ReconPipelineResult:
        """
        استطلاع سريع (للاختبار السريع)
        
        Args:
            target_url: الرابط المستهدف
            max_pages: الحد الأقصى للصفحات
        
        Returns:
            نتائج الاستطلاع
        """
        return await self.run(
            target_url=target_url,
            max_depth=2,
            max_pages=max_pages,
            analyze_js=True,
            extract_forms=True,
            collect_apis=True,
            map_surface=False
        )
    
    async def recon_deep(
        self,
        target_url: str,
        max_depth: int = 5,
        max_pages: int = 500
    ) -> ReconPipelineResult:
        """
        استطلاع عميق (تحليل شامل)
        
        Args:
            target_url: الرابط المستهدف
            max_depth: أقصى عمق للزحف
            max_pages: الحد الأقصى للصفحات
        
        Returns:
            نتائج الاستطلاع
        """
        return await self.run(
            target_url=target_url,
            max_depth=max_depth,
            max_pages=max_pages,
            analyze_js=True,
            extract_forms=True,
            collect_apis=True,
            map_surface=True
        )
    
    async def generate_report(self, result: ReconPipelineResult, format: str = "json") -> str:
        """
        توليد تقرير الاستطلاع
        
        Args:
            result: نتائج خط الأنابيب
            format: صيغة التقرير (json, markdown)
        
        Returns:
            التقرير كنص
        """
        if format == "json":
            import json
            return json.dumps({
                "target_url": result.target_url,
                "start_time": result.start_time.isoformat(),
                "end_time": result.end_time.isoformat() if result.end_time else None,
                "duration": (result.end_time - result.start_time).total_seconds() if result.end_time else 0,
                "statistics": {
                    "pages_crawled": result.total_pages,
                    "forms_found": result.total_forms,
                    "api_endpoints": result.total_api_endpoints,
                    "js_files": result.total_js_files,
                    "sensitive_info": result.sensitive_info_found
                },
                "api_endpoints": [
                    {
                        "path": ep.path,
                        "method": ep.method,
                        "full_url": ep.full_url
                    }
                    for ep in result.api_endpoints[:20]
                ],
                "js_analysis": [
                    {
                        "source": analysis.source_url,
                        "endpoints": len(analysis.endpoints),
                        "sensitive": len(analysis.sensitive_info)
                    }
                    for analysis in result.js_analysis[:10]
                ]
            }, indent=2)
        
        elif format == "markdown":
            report = f"""# Reconnaissance Report

**Target:** {result.target_url}
**Start:** {result.start_time.strftime('%Y-%m-%d %H:%M:%S')}
**End:** {result.end_time.strftime('%Y-%m-%d %H:%M:%S') if result.end_time else 'In progress'}
**Duration:** {(result.end_time - result.start_time).total_seconds():.2f}s

## Statistics

| Metric | Value |
|--------|-------|
| Pages Crawled | {result.total_pages} |
| Forms Found | {result.total_forms} |
| API Endpoints | {result.total_api_endpoints} |
| JS Files Analyzed | {result.total_js_files} |
| Sensitive Info Found | {result.sensitive_info_found} |

## API Endpoints ({len(result.api_endpoints)})

"""
            for ep in result.api_endpoints[:20]:
                report += f"- `{ep.method}` {ep.full_url}\n"
            
            if len(result.api_endpoints) > 20:
                report += f"\n*... and {len(result.api_endpoints) - 20} more endpoints*\n"
            
            report += "\n## JavaScript Analysis\n"
            for analysis in result.js_analysis[:10]:
                report += f"\n### {analysis.source_url}\n"
                report += f"- Endpoints found: {len(analysis.endpoints)}\n"
                report += f"- Sensitive info: {len(analysis.sensitive_info)}\n"
                if analysis.sensitive_info:
                    report += "- Sensitive items:\n"
                    for info in analysis.sensitive_info[:5]:
                        report += f"  - `{info.type}`: {info.value[:50]}...\n"
            
            return report
        
        else:
            raise ValueError(f"Unsupported format: {format}")
    
    async def get_result(self, pipeline_id: str) -> Optional[ReconPipelineResult]:
        """الحصول على نتيجة خط الأنابيب"""
        return self._active_pipelines.get(pipeline_id)
    
    async def get_summary(self) -> Dict:
        """ملخص خطوط الأنابيب النشطة"""
        return {
            "active_pipelines": len(self._active_pipelines),
            "completed": sum(1 for r in self._active_pipelines.values() if r.status == "completed"),
            "failed": sum(1 for r in self._active_pipelines.values() if r.status == "failed"),
            "total_pages": sum(r.total_pages for r in self._active_pipelines.values()),
            "total_apis": sum(r.total_api_endpoints for r in self._active_pipelines.values()),
            "total_sensitive": sum(r.sensitive_info_found for r in self._active_pipelines.values())
        }
    
    async def _close(self):
        """إغلاق جميع المكونات"""
        await self._crawler.close()
        await self._js_processor.close()
        await self._api_collector.close()
        await self._surface_mapper.close()
    
    async def close(self):
        """إغلاق الخط الأنابيب"""
        await self._close()
        logger.info("ReconPipeline closed")


# نسخة عالمية
async def get_recon_pipeline() -> ReconPipeline:
    """الحصول على نسخة من خط أنابيب الاستطلاع"""
    return ReconPipeline()

