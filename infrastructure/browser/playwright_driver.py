
import asyncio
from typing import Dict, List, Optional, Any, Union
from datetime import datetime
import time

from playwright.async_api import Page, BrowserContext, Response, Route

from .browser_pool import BrowserPool, BrowserInstance, get_browser_pool
from .stealth_browser import StealthBrowser, get_stealth_browser


class PlaywrightDriver:
    """محرك Playwright المتقدم"""
    
    def __init__(
        self,
        pool_size: int = 3,
        headless: bool = True,
        session_id: str = None,
        enable_stealth: bool = True
    ):
        self.pool_size = pool_size
        self.headless = headless
        self.session_id = session_id  # ✅ التصحيح: استخدام self.session_id
        self.enable_stealth = enable_stealth
        
        self._browser_pool: Optional[BrowserPool] = None
        self._stealth: Optional[StealthBrowser] = None
        self._current_browser: Optional[BrowserInstance] = None
        self._current_context: Optional[BrowserContext] = None
        self._current_page: Optional[Page] = None
        self._current_context_obj = None  # لتخزين كائن السياق للإغلاق
        
        self._initialized = False
        self._stats = {
            "pages_created": 0,
            "pages_closed": 0,
            "navigations": 0,
            "failed_navigations": 0,
            "avg_response_time_ms": 0.0
        }
    
    async def initialize(self):
        """تهيئة المحرك"""
        if self._initialized:
            return
        
        # تهيئة تجمع المتصفحات
        self._browser_pool = await get_browser_pool(
            pool_size=self.pool_size,
            headless=self.headless
        )
        
        # تهيئة نظام التخفي
        if self.enable_stealth:
            self._stealth = get_stealth_browser()
        
        # إنشاء بصمة للجلسة
        if self.session_id and self._stealth:
            self._stealth.create_session_fingerprint(self.session_id)
        
        self._initialized = True
        print(f"   🚀 Playwright driver initialized (pool: {self.pool_size}, stealth: {self.enable_stealth})")
    
    async def _ensure_browser(self):
        """ضمان وجود متصفح وسياق وصفحة"""
        if not self._initialized:
            await self.initialize()
        
        # الحصول على متصفح
        if not self._current_browser:
            self._current_browser = await self._browser_pool.acquire()
        
        # إنشاء سياق
        if not self._current_context:
            self._current_context_obj = await self._browser_pool.create_context(self._current_browser)
            self._current_context = self._current_context_obj.context
            
            # تطبيق التخفي على السياق
            if self._stealth and self.enable_stealth:
                await self._stealth.apply_to_context(self._current_context, self.session_id)
        
        # إنشاء صفحة
        if not self._current_page or self._current_page.is_closed():
            self._current_page = await self._browser_pool.create_page(self._current_context_obj)
            
            # تطبيق التخفي على الصفحة
            if self._stealth and self.enable_stealth:
                await self._stealth.apply_to_page(self._current_page, self.session_id)  # ✅ التصحيح: self.session_id
            
            self._stats["pages_created"] += 1
    
    async def navigate(
        self,
        url: str,
        timeout: int = 30000,
        wait_until: str = "domcontentloaded",
        headers: Dict = None
    ) -> Optional[Response]:
        """التنقل إلى URL"""
        await self._ensure_browser()
        
        start_time = time.time()
        self._stats["navigations"] += 1
        
        try:
            # إضافة headers إضافية
            if headers:
                await self._current_page.set_extra_http_headers(headers)
            
            response = await self._current_page.goto(
                url,
                timeout=timeout,
                wait_until=wait_until
            )
            
            response_time = (time.time() - start_time) * 1000
            self._stats["avg_response_time_ms"] = (
                self._stats["avg_response_time_ms"] * 0.9 + response_time * 0.1
            )
            
            return response
            
        except Exception as e:
            self._stats["failed_navigations"] += 1
            raise e
    
    async def get_content(self) -> str:
        """الحصول على محتوى الصفحة"""
        await self._ensure_browser()
        return await self._current_page.content()
    
    async def get_title(self) -> str:
        """الحصول على عنوان الصفحة"""
        await self._ensure_browser()
        return await self._current_page.title()
    
    async def get_url(self) -> str:
        """الحصول على URL الحالي"""
        await self._ensure_browser()
        return self._current_page.url
    
    async def execute_script(self, script: str, *args) -> Any:
        """تنفيذ JavaScript في الصفحة"""
        await self._ensure_browser()
        return await self._current_page.evaluate(script, *args)
    
    async def click(self, selector: str, timeout: int = 5000):
        """النقر على عنصر"""
        await self._ensure_browser()
        await self._current_page.click(selector, timeout=timeout)
    
    async def fill(self, selector: str, value: str, timeout: int = 5000):
        """ملء حقل إدخال"""
        await self._ensure_browser()
        await self._current_page.fill(selector, value, timeout=timeout)
    
    async def screenshot(self, path: str = None, full_page: bool = False) -> bytes:
        """التقاط لقطة شاشة"""
        await self._ensure_browser()
        return await self._current_page.screenshot(path=path, full_page=full_page)
    
    async def pdf(self, path: str = None) -> bytes:
        """إنشاء PDF من الصفحة"""
        await self._ensure_browser()
        return await self._current_page.pdf(path=path)
    
    async def wait_for_selector(self, selector: str, timeout: int = 30000):
        """انتظار عنصر"""
        await self._ensure_browser()
        await self._current_page.wait_for_selector(selector, timeout=timeout)
    
    async def wait_for_timeout(self, milliseconds: int):
        """انتظار بسيط"""
        await self._ensure_browser()
        await self._current_page.wait_for_timeout(milliseconds)
    
    async def scroll_to_bottom(self):
        """التمرير إلى أسفل الصفحة"""
        await self._ensure_browser()
        await self.execute_script("window.scrollTo(0, document.body.scrollHeight)")
    
    async def scroll_to_top(self):
        """التمرير إلى أعلى الصفحة"""
        await self._ensure_browser()
        await self.execute_script("window.scrollTo(0, 0)")
    
    async def get_links(self) -> List[str]:
        """الحصول على جميع الروابط في الصفحة"""
        await self._ensure_browser()
        return await self.execute_script("""
            () => Array.from(document.querySelectorAll('a[href]'))
                .map(a => a.href)
                .filter(h => h && !h.startsWith('#') && !h.startsWith('javascript:'))
        """)
    
    async def get_forms(self) -> List[Dict]:
        """الحصول على جميع النماذج في الصفحة"""
        await self._ensure_browser()
        return await self.execute_script("""
            () => Array.from(document.querySelectorAll('form')).map(form => ({
                action: form.action,
                method: form.method,
                inputs: Array.from(form.querySelectorAll('input, textarea, select')).map(i => ({
                    name: i.name,
                    type: i.type || i.tagName
                }))
            }))
        """)
    
    async def intercept_requests(self, patterns: List[str]):
        """اعتراض الطلبات حسب الأنماط"""
        await self._ensure_browser()
        
        async def handle_route(route: Route):
            url = route.request.url
            for pattern in patterns:
                if pattern in url:
                    await route.abort()
                    return
            await route.continue_()
        
        await self._current_page.route("**/*", handle_route)
    
    async def clear_interceptions(self):
        """إزالة اعتراض الطلبات"""
        await self._ensure_browser()
        await self._current_page.unroute_all()
    
    async def get_cookies(self) -> List[Dict]:
        """الحصول على الكوكيز"""
        await self._ensure_browser()
        return await self._current_context.cookies()
    
    async def set_cookies(self, cookies: List[Dict]):
        """تعيين الكوكيز"""
        await self._ensure_browser()
        await self._current_context.add_cookies(cookies)
    
    async def clear_cookies(self):
        """مسح الكوكيز"""
        await self._ensure_browser()
        await self._current_context.clear_cookies()
    
    async def get_local_storage(self, key: str = None) -> Any:
        """الحصول على localStorage"""
        await self._ensure_browser()
        if key:
            return await self.execute_script(f"localStorage.getItem('{key}')")
        return await self.execute_script("Object.entries(localStorage)")
    
    async def set_local_storage(self, key: str, value: str):
        """تعيين localStorage"""
        await self._ensure_browser()
        await self.execute_script(f"localStorage.setItem('{key}', '{value}')")
    
    async def new_page(self) -> Page:
        """إنشاء صفحة جديدة (بدون إعادة استخدام)"""
        await self._ensure_browser()
        page = await self._current_context.new_page()
        self._stats["pages_created"] += 1
        return page
    
    async def close_page(self, page: Page = None):
        """إغلاق صفحة"""
        target = page or self._current_page
        if target and not target.is_closed():
            await target.close()
            self._stats["pages_closed"] += 1
    
    async def reset(self):
        """إعادة تعيين الجلسة (بدون إغلاق المتصفح)"""
        if self._current_page and not self._current_page.is_closed():
            await self.close_page()
        
        # ✅ إصلاح: إغلاق السياق بشكل صحيح
        if self._current_context_obj:
            await self._browser_pool.close_context(self._current_context_obj)
        
        self._current_page = None
        self._current_context = None
        self._current_context_obj = None
        
        # إنشاء سياق جديد
        self._current_context_obj = await self._browser_pool.create_context(self._current_browser)
        self._current_context = self._current_context_obj.context
        if self._stealth and self.enable_stealth:
            await self._stealth.apply_to_context(self._current_context, self.session_id)
        
        self._current_page = await self._browser_pool.create_page(self._current_context_obj)
        if self._stealth and self.enable_stealth:
            await self._stealth.apply_to_page(self._current_page, self.session_id)
    
    async def close(self):
        """إغلاق المحرك وتحرير الموارد"""
        if self._current_page and not self._current_page.is_closed():
            await self.close_page()
        
        # ✅ إصلاح: إغلاق السياق بشكل صحيح
        if self._current_context_obj:
            await self._browser_pool.close_context(self._current_context_obj)
        
        if self._current_browser:
            await self._browser_pool.release(self._current_browser)
        
        self._current_page = None
        self._current_context = None
        self._current_context_obj = None
        self._current_browser = None
        self._initialized = False
    
    def get_stats(self) -> Dict:
        """إحصائيات المحرك"""
        browser_stats = {}
        if self._browser_pool:
            browser_stats = self._browser_pool.get_stats()
        
        return {
            **self._stats,
            "browser_pool": browser_stats,
            "initialized": self._initialized,
            "session_id": self.session_id,
            "stealth_enabled": self.enable_stealth
        }


async def create_driver(
    session_id: str = None,
    headless: bool = True,
    enable_stealth: bool = True,
    pool_size: int = 3
) -> PlaywrightDriver:
    """إنشاء محرك جديد"""
    driver = PlaywrightDriver(
        pool_size=pool_size,
        headless=headless,
        session_id=session_id,
        enable_stealth=enable_stealth
    )
    await driver.initialize()
    return driver

