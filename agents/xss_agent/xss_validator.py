
import asyncio
import re
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime

from ...offensive.scanners.xss_scanner import Finding, Severity, Confidence

try:
    from playwright.async_api import async_playwright, Page
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False

import logging

logger = logging.getLogger(__name__)


class ValidationResult(Enum):
    """نتائج التحقق"""
    CONFIRMED = "confirmed"      # تم تأكيد الثغرة
    PARTIAL = "partial"           # تأكيد جزئي
    NOT_CONFIRMED = "not_confirmed"  # لم يتم التأكيد
    BLOCKED = "blocked"           # تم حظر الطلب
    ERROR = "error"               # خطأ في التحقق


@dataclass
class ValidationDetails:
    """تفاصيل التحقق"""
    result: ValidationResult
    evidence: str
    execution_time: float
    payload_used: str
    browser_detected: bool = False
    console_messages: List[str] = field(default_factory=list)
    screenshot_path: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


class XSSValidator:
    """
    مدقق ثغرات XSS المتقدم
    
    الميزات:
    - تحقق من تنفيذ XSS فعلياً
    - استخدام متصفح حقيقي (Playwright)
    - كشف تنبيهات JavaScript
    - التقاط رسائل الكونسول
    - التقاط لقطات شاشة
    - تحليل الاستجابات
    """
    
    def __init__(self, use_browser: bool = True, headless: bool = True):
        self._use_browser = use_browser and PLAYWRIGHT_AVAILABLE
        self._headless = headless
        self._validation_cache: Dict[str, ValidationDetails] = {}
        
        logger.info(f"XSSValidator initialized (browser={self._use_browser})")
    
    async def validate(
        self,
        url: str,
        payload: str,
        parameter: str = None,
        method: str = "GET",
        context: Dict = None
    ) -> ValidationDetails:
        """
        التحقق من ثغرة XSS
        
        Args:
            url: الرابط المستهدف
            payload: الحمولة
            parameter: اسم المعامل (اختياري)
            method: طريقة الطلب
            context: سياق إضافي
        
        Returns:
            تفاصيل التحقق
        """
        import time
        start_time = time.time()
        
        # بناء الرابط بالحمولة
        test_url = self._build_url(url, parameter, payload) if parameter else url
        
        console_messages = []
        alert_triggered = False
        
        if self._use_browser:
            # استخدام المتصفح للتحقق
            try:
                async with async_playwright() as p:
                    browser = await p.chromium.launch(headless=self._headless)
                    page = await browser.new_page()
                    
                    # إعداد مستمع للتنبيهات
                    async def handle_dialog(dialog):
                        nonlocal alert_triggered
                        alert_triggered = True
                        console_messages.append(f"ALERT: {dialog.message}")
                        await dialog.dismiss()
                    
                    page.on("dialog", handle_dialog)
                    
                    # مستمع لرسائل الكونسول
                    page.on("console", lambda msg: console_messages.append(f"CONSOLE: {msg.text}"))
                    
                    # التنقل إلى الصفحة
                    try:
                        await page.goto(test_url, wait_until="networkidle", timeout=10000)
                        await asyncio.sleep(1)  # انتظار تنفيذ JavaScript
                    except Exception as e:
                        logger.debug(f"Page navigation error: {e}")
                    
                    # التقاط لقطة شاشة
                    screenshot_path = None
                    if alert_triggered or console_messages:
                        screenshot_path = f"/tmp/xss_validation_{int(time.time())}.png"
                        await page.screenshot(path=screenshot_path)
                    
                    await browser.close()
                    
            except Exception as e:
                logger.error(f"Browser validation failed: {e}")
                # العودة إلى التحقق بالاستجابة
                return await self._validate_by_response(url, test_url, payload, start_time)
        
        else:
            # التحقق بالاستجابة فقط
            return await self._validate_by_response(url, test_url, payload, start_time)
        
        execution_time = time.time() - start_time
        
        # تحديد النتيجة
        if alert_triggered:
            result = ValidationResult.CONFIRMED
            evidence = "Alert dialog was triggered"
        elif console_messages:
            result = ValidationResult.PARTIAL
            evidence = f"Console messages detected: {', '.join(console_messages[:3])}"
        else:
            result = ValidationResult.NOT_CONFIRMED
            evidence = "No alert or console messages detected"
        
        return ValidationDetails(
            result=result,
            evidence=evidence,
            execution_time=execution_time,
            payload_used=payload,
            browser_detected=alert_triggered,
            console_messages=console_messages,
            screenshot_path=screenshot_path if 'screenshot_path' in dir() else None
        )
    
    async def _validate_by_response(
        self,
        original_url: str,
        test_url: str,
        payload: str,
        start_time: float
    ) -> ValidationDetails:
        """
        التحقق من خلال تحليل الاستجابة فقط
        
        Args:
            original_url: الرابط الأصلي
            test_url: الرابط المختبر
            payload: الحمولة
            start_time: وقت البدء
        
        Returns:
            تفاصيل التحقق
        """
        import httpx
        import time
        
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get(test_url)
                response_text = response.text
                
                execution_time = time.time() - start_time
                
                # البحث عن الحمولة في الاستجابة
                if payload in response_text:
                    result = ValidationResult.CONFIRMED
                    evidence = f"Payload reflected in response: {payload[:100]}"
                else:
                    result = ValidationResult.NOT_CONFIRMED
                    evidence = "Payload not found in response"
                
                return ValidationDetails(
                    result=result,
                    evidence=evidence,
                    execution_time=execution_time,
                    payload_used=payload,
                    browser_detected=False
                )
                
        except Exception as e:
            execution_time = time.time() - start_time
            return ValidationDetails(
                result=ValidationResult.ERROR,
                evidence=f"Request failed: {e}",
                execution_time=execution_time,
                payload_used=payload
            )
    
    def _build_url(self, base_url: str, parameter: str, payload: str) -> str:
        """
        بناء الرابط مع الحمولة
        
        Args:
            base_url: الرابط الأساسي
            parameter: اسم المعامل
            payload: الحمولة
        
        Returns:
            الرابط الكامل
        """
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
        
        parsed = urlparse(base_url)
        params = parse_qs(parsed.query)
        params[parameter] = [payload]
        new_query = urlencode(params, doseq=True)
        return urlunparse(parsed._replace(query=new_query))
    
    async def validate_batch(
        self,
        validation_tasks: List[Tuple[str, str, str]]
    ) -> List[ValidationDetails]:
        """
        التحقق من مجموعة من الثغرات دفعة واحدة
        
        Args:
            validation_tasks: قائمة (url, payload, parameter)
        
        Returns:
            قائمة بتفاصيل التحقق
        """
        tasks = []
        for url, payload, parameter in validation_tasks:
            tasks.append(self.validate(url, payload, parameter))
        
        return await asyncio.gather(*tasks)
    
    async def get_confirmed_findings(
        self,
        findings: List[Finding]
    ) -> List[Finding]:
        """
        تصفية النتائج المؤكدة فقط
        
        Args:
            findings: قائمة الثغرات المكتشفة
        
        Returns:
            قائمة بالثغرات المؤكدة
        """
        confirmed = []
        
        for finding in findings:
            # التحقق من الذاكرة المؤقتة
            cache_key = f"{finding.url}_{finding.parameter}_{finding.payload}"
            if cache_key in self._validation_cache:
                validation = self._validation_cache[cache_key]
                if validation.result == ValidationResult.CONFIRMED:
                    confirmed.append(finding)
                continue
            
            # تحقق جديد
            validation = await self.validate(
                finding.url,
                finding.payload,
                finding.parameter
            )
            self._validation_cache[cache_key] = validation
            
            if validation.result == ValidationResult.CONFIRMED:
                confirmed.append(finding)
        
        return confirmed
    
    async def generate_validation_report(
        self,
        validation: ValidationDetails
    ) -> str:
        """
        توليد تقرير التحقق
        
        Args:
            validation: تفاصيل التحقق
        
        Returns:
            تقرير Markdown
        """
        status_icon = {
            ValidationResult.CONFIRMED: "✅",
            ValidationResult.PARTIAL: "⚠️",
            ValidationResult.NOT_CONFIRMED: "❌",
            ValidationResult.BLOCKED: "🚫",
            ValidationResult.ERROR: "💥"
        }.get(validation.result, "❓")
        
        report = f"""## XSS Validation Report

**Status:** {status_icon} {validation.result.value}
**Execution Time:** {validation.execution_time:.2f}s
**Payload:** `{validation.payload_used[:100]}`

### Evidence
{validation.evidence}

"""
        if validation.console_messages:
            report += "### Console Messages\n"
            for msg in validation.console_messages[:5]:
                report += f"- `{msg}`\n"
            report += "\n"
        
        if validation.screenshot_path:
            report += f"### Screenshot\n![Screenshot]({validation.screenshot_path})\n\n"
        
        return report
    
    async def get_statistics(self) -> Dict:
        """إحصائيات المدقق"""
        if not self._validation_cache:
            return {"total_validations": 0}
        
        results = {}
        for validation in self._validation_cache.values():
            results[validation.result.value] = results.get(validation.result.value, 0) + 1
        
        return {
            "total_validations": len(self._validation_cache),
            "results_distribution": results,
            "confirmed": results.get("confirmed", 0),
            "partial": results.get("partial", 0),
            "not_confirmed": results.get("not_confirmed", 0),
            "use_browser": self._use_browser,
            "playwright_available": PLAYWRIGHT_AVAILABLE
        }
    
    async def clear_cache(self):
        """مسح ذاكرة التخزين المؤقت"""
        self._validation_cache.clear()
        logger.info("Validation cache cleared")

