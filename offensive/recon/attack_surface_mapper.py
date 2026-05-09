
import asyncio
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from collections import defaultdict
import json

from .enhanced_crawler import EnhancedCrawler, CrawlResult, CrawledPage
from .js_processor import JSProcessor, JSAnalysisResult
from .form_extractor import FormExtractor, ExtractedForm
from .api_collector import APICollector, APIEndpoint, APICollection

import logging

logger = logging.getLogger(__name__)


@dataclass
class Technology:
    """تقنية مكتشفة"""
    name: str
    version: Optional[str] = None
    confidence: float = 0.8
    evidence: str = ""


@dataclass
class EntryPoint:
    """نقطة دخول للهجوم"""
    url: str
    type: str  # form, api, parameter, file_upload, etc.
    method: str  # GET, POST, etc.
    parameters: List[str] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AttackSurface:
    """سطح الهجوم الكامل"""
    target_url: str
    analyzed_at: datetime
    pages: List[CrawledPage] = field(default_factory=list)
    technologies: List[Technology] = field(default_factory=list)
    entry_points: List[EntryPoint] = field(default_factory=list)
    api_endpoints: List[APIEndpoint] = field(default_factory=list)
    forms: List[ExtractedForm] = field(default_factory=list)
    js_files: List[str] = field(default_factory=list)
    sensitive_info: List[Dict] = field(default_factory=list)
    
    # إحصائيات
    total_pages: int = 0
    total_forms: int = 0
    total_api_endpoints: int = 0
    total_entry_points: int = 0
    authentication_points: int = 0
    file_upload_points: int = 0
    
    # ملخص
    summary: Dict[str, Any] = field(default_factory=dict)


class AttackSurfaceMapper:
    """
    مخطط سطح الهجوم المتقدم
    
    الميزات:
    - تحليل شامل لسطح الهجوم
    - كشف التقنيات المستخدمة (WAF, frameworks, libraries)
    - تحديد نقاط الدخول للهجوم
    - تقييم مخاطر كل نقطة دخول
    - توليد تقارير مفصلة
    - دمج بيانات من مصادر متعددة (crawler, JS, forms, APIs)
    """
    
    # أنماط كشف التقنيات
    TECH_PATTERNS = {
        "WAF": {
            "Cloudflare": [r'cloudflare', r'__cfduid'],
            "AWS WAF": [r'awswaf', r'x-amzn-RequestId'],
            "ModSecurity": [r'ModSecurity', r'OWASP'],
            "Imperva": [r'incapsula', r'X-Cdn'],
            "Sucuri": [r'sucuri', r'X-Sucuri-'],
        },
        "Framework": {
            "React": [r'react', r'ReactDOM'],
            "Angular": [r'ng-', r'angular'],
            "Vue.js": [r'vue', r'data-v-'],
            "jQuery": [r'jquery'],
            "Bootstrap": [r'bootstrap'],
            "Tailwind": [r'tailwind'],
        },
        "Server": {
            "Nginx": [r'nginx'],
            "Apache": [r'apache', r'Apache'],
            "IIS": [r'iis', r'Microsoft-IIS'],
            "Cloudflare": [r'cloudflare'],
            "AWS": [r'aws|s3|ec2'],
        },
        "Language": {
            "PHP": [r'\.php', r'PHPSESSID'],
            "Python": [r'\.py', r'python'],
            "Java": [r'\.jsp', r'\.do', r'JSESSIONID'],
            "Ruby": [r'\.rb', r'rails'],
            "Node.js": [r'node', r'express'],
            "ASP.NET": [r'\.aspx', r'ASP\.NET', r'ViewState'],
        },
        "Database": {
            "MySQL": [r'mysql', r'MySQL'],
            "PostgreSQL": [r'postgresql', r'pgsql'],
            "MongoDB": [r'mongodb', r'mongo'],
            "SQLite": [r'sqlite'],
        },
    }
    
    def __init__(self):
        self._crawler = EnhancedCrawler()
        self._js_processor = JSProcessor()
        self._form_extractor = FormExtractor()
        self._api_collector = APICollector()
        
        logger.info("AttackSurfaceMapper initialized")
    
    async def map_attack_surface(
        self,
        target_url: str,
        max_depth: int = 3,
        max_pages: int = 100
    ) -> AttackSurface:
        """
        تحليل وتخطيط سطح الهجوم الكامل
        
        Args:
            target_url: الرابط المستهدف
            max_depth: أقصى عمق للزحف
            max_pages: الحد الأقصى للصفحات
        
        Returns:
            كائن AttackSurface
        """
        logger.info(f"Starting attack surface mapping for {target_url}")
        
        surface = AttackSurface(
            target_url=target_url,
            analyzed_at=datetime.now()
        )
        
        # 1. الزحف إلى الموقع
        logger.info("Phase 1: Crawling...")
        crawl_result = await self._crawler.crawl(target_url, max_depth, max_pages)
        surface.pages = crawl_result.pages_crawled
        surface.total_pages = len(surface.pages)
        
        # 2. تحليل التقنيات من الصفحات
        logger.info("Phase 2: Detecting technologies...")
        for page in surface.pages:
            techs = await self._detect_technologies(page)
            for tech in techs:
                if tech not in surface.technologies:
                    surface.technologies.append(tech)
        
        # 3. استخراج النماذج وتحليلها
        logger.info("Phase 3: Extracting forms...")
        for page in surface.pages:
            if page.content_type.startswith('text/html'):
                # استخدام محتوى الصفحة (يجب حفظه مسبقاً)
                result = await self._form_extractor.extract_from_html("", page.url)
                surface.forms.extend(result.forms)
        
        surface.total_forms = len(surface.forms)
        
        # 4. جمع واجهات API
        logger.info("Phase 4: Collecting API endpoints...")
        all_api_endpoints = []
        
        for page in surface.pages:
            # من HTML
            api_endpoints = await self._api_collector.collect_from_html("", page.url)
            all_api_endpoints.extend(api_endpoints)
        
        # من ملفات JS
        for js_file in surface.js_files:
            js_result = await self._js_processor.process_url(js_file, surface.target_url)
            if js_result:
                for endpoint in js_result.endpoints:
                    api_endpoint = APIEndpoint(
                        path=endpoint.url,
                        method=endpoint.method,
                        full_url=endpoint.url,
                        parameters=endpoint.parameters,
                        discovered_from=f"js:{js_file}"
                    )
                    all_api_endpoints.append(api_endpoint)
        
        # 5. تحديد نقاط الدخول
        logger.info("Phase 5: Identifying entry points...")
        surface.entry_points = await self._identify_entry_points(surface)
        surface.total_entry_points = len(surface.entry_points)
        
        # 6. إحصائيات نقاط المصادقة ورفع الملفات
        for ep in surface.entry_points:
            if ep.type == "login" or ep.type == "auth":
                surface.authentication_points += 1
            if ep.type == "file_upload":
                surface.file_upload_points += 1
        
        # 7. إنشاء الملخص
        surface.summary = await self._create_summary(surface)
        
        logger.info(f"Attack surface mapping completed: {surface.total_pages} pages, "
                   f"{surface.total_entry_points} entry points, "
                   f"{len(surface.api_endpoints)} APIs")
        
        return surface
    
    async def _detect_technologies(self, page: CrawledPage) -> List[Technology]:
        """كشف التقنيات المستخدمة"""
        technologies = []
        content = page.content_type + " " + page.title
        
        for category, techs in self.TECH_PATTERNS.items():
            for tech_name, patterns in techs.items():
                for pattern in patterns:
                    if re.search(pattern, content, re.I):
                        technologies.append(Technology(
                            name=f"{category}:{tech_name}",
                            confidence=0.7,
                            evidence=f"Pattern matched: {pattern}"
                        ))
                        break
        
        return technologies
    
    async def _identify_entry_points(self, surface: AttackSurface) -> List[EntryPoint]:
        """تحديد نقاط الدخول للهجوم"""
        entry_points = []
        
        # من النماذج
        for form in surface.forms:
            # نماذج تسجيل الدخول
            is_login = any(f.name and 'password' in f.name.lower() for f in form.fields)
            if is_login:
                entry_points.append(EntryPoint(
                    url=form.action_url,
                    type="login",
                    method=form.method,
                    parameters=[f.name for f in form.fields if f.name],
                    details={"form_id": form.id, "has_csrf": form.has_csrf_token}
                ))
            
            # رفع الملفات
            if form.has_file_upload:
                entry_points.append(EntryPoint(
                    url=form.action_url,
                    type="file_upload",
                    method=form.method,
                    parameters=[f.name for f in form.fields if f.name],
                    details={"form_id": form.id}
                ))
            
            # نماذج عادية
            else:
                entry_points.append(EntryPoint(
                    url=form.action_url,
                    type="form",
                    method=form.method,
                    parameters=[f.name for f in form.fields if f.name],
                    details={"form_id": form.id}
                ))
        
        # من واجهات API
        for api in surface.api_endpoints:
            entry_points.append(EntryPoint(
                url=api.full_url,
                type="api",
                method=api.method,
                parameters=api.parameters,
                details={"discovered_from": api.discovered_from}
            ))
        
        # من المعاملات في URLs
        for page in surface.pages:
            for param_name, param_values in page.parameters.items():
                entry_points.append(EntryPoint(
                    url=page.url,
                    type="parameter",
                    method="GET",
                    parameters=[param_name],
                    details={"values": param_values}
                ))
        
        return entry_points
    
    async def _create_summary(self, surface: AttackSurface) -> Dict[str, Any]:
        """إنشاء ملخص لسطح الهجوم"""
        # تصنيف نقاط الدخول حسب المخاطر
        high_risk = []
        medium_risk = []
        low_risk = []
        
        for ep in surface.entry_points:
            if ep.type in ["login", "file_upload", "api"]:
                high_risk.append(ep)
            elif ep.type in ["form", "parameter"]:
                medium_risk.append(ep)
            else:
                low_risk.append(ep)
        
        # التقنيات المكتشفة
        tech_summary = defaultdict(list)
        for tech in surface.technologies:
            category, name = tech.name.split(':', 1) if ':' in tech.name else ('General', tech.name)
            tech_summary[category].append(name)
        
        return {
            "total_entry_points": surface.total_entry_points,
            "risk_levels": {
                "high": len(high_risk),
                "medium": len(medium_risk),
                "low": len(low_risk)
            },
            "technologies": dict(tech_summary),
            "authentication_points": surface.authentication_points,
            "file_upload_points": surface.file_upload_points,
            "coverage": {
                "pages_crawled": surface.total_pages,
                "forms_analyzed": surface.total_forms,
                "apis_discovered": len(surface.api_endpoints)
            },
            "recommendations": await self._generate_recommendations(surface)
        }
    
    async def _generate_recommendations(self, surface: AttackSurface) -> List[str]:
        """توليد توصيات أمنية بناءً على التحليل"""
        recommendations = []
        
        # فحص نماذج بدون CSRF
        forms_without_csrf = [f for f in surface.forms if not f.has_csrf_token and f.method == "POST"]
        if forms_without_csrf:
            recommendations.append(f"Implement CSRF protection for {len(forms_without_csrf)} forms")
        
        # فحص نماذج GET مع بيانات حساسة
        get_forms = [f for f in surface.forms if f.method == "GET" and 
                    any(field.type == 'password' for field in f.fields)]
        if get_forms:
            recommendations.append("Avoid using GET method for forms with sensitive data")
        
        # واجهات API بدون مصادقة
        api_without_auth = [a for a in surface.api_endpoints if not a.auth_required]
        if api_without_auth:
            recommendations.append(f"Implement authentication for {len(api_without_auth)} API endpoints")
        
        # معلومات حساسة مكتشفة
        if surface.sensitive_info:
            recommendations.append("Review exposed sensitive information in JavaScript files")
        
        # نقاط رفع ملفات
        if surface.file_upload_points > 0:
            recommendations.append("Implement strict file type validation for upload endpoints")
        
        return recommendations
    
    async def generate_report(self, surface: AttackSurface, format: str = "json") -> str:
        """
        توليد تقرير بصيغة محددة
        
        Args:
            surface: كائن AttackSurface
            format: صيغة التقرير (json, html, markdown)
        
        Returns:
            التقرير كنص
        """
        if format == "json":
            return json.dumps({
                "target_url": surface.target_url,
                "analyzed_at": surface.analyzed_at.isoformat(),
                "summary": surface.summary,
                "technologies": [t.name for t in surface.technologies],
                "entry_points": [
                    {
                        "url": ep.url,
                        "type": ep.type,
                        "method": ep.method,
                        "parameters": ep.parameters
                    }
                    for ep in surface.entry_points
                ],
                "api_endpoints": [
                    {
                        "path": api.path,
                        "method": api.method,
                        "full_url": api.full_url
                    }
                    for api in surface.api_endpoints
                ]
            }, indent=2)
        
        elif format == "markdown":
            report = f"""# Attack Surface Report

**Target:** {surface.target_url}
**Analyzed:** {surface.analyzed_at.isoformat()}

## Summary

- Total Pages: {surface.total_pages}
- Total Entry Points: {surface.total_entry_points}
- API Endpoints: {len(surface.api_endpoints)}
- Forms: {surface.total_forms}
- Authentication Points: {surface.authentication_points}
- File Upload Points: {surface.file_upload_points}

## Risk Levels

- 🔴 High Risk: {surface.summary['risk_levels']['high']}
- 🟡 Medium Risk: {surface.summary['risk_levels']['medium']}
- 🟢 Low Risk: {surface.summary['risk_levels']['low']}

## Technologies Detected

"""
            for category, techs in surface.summary.get('technologies', {}).items():
                report += f"- **{category}:** {', '.join(techs)}\n"
            
            report += "\n## Recommendations\n\n"
            for rec in surface.summary.get('recommendations', []):
                report += f"- {rec}\n"
            
            return report
        
        else:
            raise ValueError(f"Unsupported format: {format}")
    
    async def get_statistics(self) -> Dict:
        """إحصائيات المخطط"""
        return {
            "crawler_stats": await self._crawler.get_statistics(),
            "js_processor_stats": await self._js_processor.get_statistics(),
            "api_collector_stats": await self._api_collector.get_statistics(),
            "tech_patterns": {
                category: len(patterns) 
                for category, patterns in self.TECH_PATTERNS.items()
            }
        }
    
    async def close(self):
        """إغلاق الموارد"""
        await self._crawler.close()
        await self._js_processor.close()
        await self._api_collector.close()
        logger.info("AttackSurfaceMapper closed")


# نسخة عالمية
async def get_attack_surface_mapper() -> AttackSurfaceMapper:
    """الحصول على نسخة من مخطط سطح الهجوم"""
    return AttackSurfaceMapper()

