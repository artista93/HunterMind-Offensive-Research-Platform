import asyncio
import random
import json
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import time

from playwright.async_api import async_playwright, Browser, BrowserContext, Page


class BrowserStatus(Enum):
    IDLE = "idle"
    BUSY = "busy"
    RECYCLING = "recycling"
    ERROR = "error"
    CLOSED = "closed"


class BrowserType(Enum):
    CHROMIUM = "chromium"
    FIREFOX = "firefox"
    WEBKIT = "webkit"


@dataclass
class BrowserInstance:
    id: str
    browser: Browser
    browser_type: BrowserType
    status: BrowserStatus = BrowserStatus.IDLE
    created_at: datetime = field(default_factory=datetime.now)
    last_used: datetime = field(default_factory=datetime.now)
    usage_count: int = 0
    error_count: int = 0
    priority: int = 5
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def use(self):
        self.status = BrowserStatus.BUSY
        self.last_used = datetime.now()
        self.usage_count += 1
    
    def release(self):
        self.status = BrowserStatus.IDLE
        self.last_used = datetime.now()
    
    def mark_error(self):
        self.error_count += 1
        if self.error_count > 3:
            self.status = BrowserStatus.ERROR
    
    def is_healthy(self) -> bool:
        return self.error_count < 3 and self.status != BrowserStatus.CLOSED
    
    def age_seconds(self) -> float:
        return (datetime.now() - self.created_at).total_seconds()


@dataclass
class BrowserContextInstance:
    """مثيل سياق المتصفح"""
    id: str
    context: BrowserContext
    browser_id: str
    created_at: datetime = field(default_factory=datetime.now)
    pages: list = field(default_factory=list)
    
    def add_page(self, page: Page):
        self.pages.append(page)
    
    def remove_page(self, page: Page):
        if page in self.pages:
            self.pages.remove(page)


class StealthConfig:
    """إعدادات التخفي المتقدمة"""
    
    @staticmethod
    def get_stealth_args() -> List[str]:
        return [
            "--no-sandbox",
            "--disable-setuid-sandbox",
            "--disable-dev-shm-usage",
            "--disable-gpu",
            "--disable-blink-features=AutomationControlled",
            "--disable-features=IsolateOrigins,site-per-process",
            "--disable-web-security",
            "--disable-features=BlockInsecurePrivateNetworkRequests",
            "--disable-features=OutOfBlinkCors",
            "--disable-site-isolation-trials",
            "--disable-features=SharedArrayBuffer",
            "--disable-features=VizDisplayCompositor",
            "--disable-background-timer-throttling",
            "--disable-backgrounding-occluded-windows",
            "--disable-renderer-backgrounding",
            "--disable-ipc-flooding-protection",
            "--disable-default-apps",
            "--disable-sync",
            "--disable-translate",
            "--disable-extensions",
            "--disable-component-extensions-with-background-pages",
            "--disable-client-side-phishing-detection",
            "--disable-component-update",
            "--disable-domain-reliability",
            "--disable-breakpad"
        ]
    
    @staticmethod
    def get_random_user_agent() -> str:
        user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0"
        ]
        return random.choice(user_agents)
    
    @staticmethod
    def get_viewport() -> Dict:
        viewports = [
            {"width": 1280, "height": 720},
            {"width": 1366, "height": 768},
            {"width": 1440, "height": 900},
            {"width": 1536, "height": 864},
            {"width": 1920, "height": 1080}
        ]
        return random.choice(viewports)
    
    @staticmethod
    def get_locale() -> str:
        locales = ["en-US", "en-GB", "fr-FR", "de-DE", "es-ES", "it-IT"]
        return random.choice(locales)
    
    @staticmethod
    def get_timezone() -> str:
        timezones = [
            "America/New_York", "America/Los_Angeles", "Europe/London",
            "Europe/Paris", "Asia/Tokyo", "Asia/Dubai", "Australia/Sydney"
        ]
        return random.choice(timezones)
    
    @staticmethod
    def get_permissions() -> List[str]:
        permissions = ["geolocation", "notifications", "clipboard-read", "clipboard-write"]
        return random.sample(permissions, k=random.randint(0, len(permissions)))


class AdaptiveRetry:
    def __init__(self, base_delay: float = 0.5, max_delay: float = 30.0, max_retries: int = 5):
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.max_retries = max_retries
        self.jitter = True
    
    async def execute(self, coro, *args, **kwargs) -> Any:
        last_error = None
        for attempt in range(self.max_retries):
            try:
                return await coro(*args, **kwargs)
            except Exception as e:
                last_error = e
                if attempt == self.max_retries - 1:
                    raise
                delay = min(self.base_delay * (2 ** attempt), self.max_delay)
                if self.jitter:
                    delay = delay * (0.5 + random.random())
                await asyncio.sleep(delay)
        raise last_error


class PriorityQueue:
    def __init__(self):
        self._queue = []
        self._counter = 0
    
    def put(self, item: Any, priority: int = 5):
        import heapq
        heapq.heappush(self._queue, (priority, self._counter, item))
        self._counter += 1
    
    def get(self) -> Optional[Any]:
        import heapq
        if not self._queue:
            return None
        priority, _, item = heapq.heappop(self._queue)
        return item
    
    def size(self) -> int:
        return len(self._queue)
    
    def is_empty(self) -> bool:
        return len(self._queue) == 0


class BrowserPool:
    def __init__(
        self,
        pool_size: int = 3,
        browser_type: BrowserType = BrowserType.CHROMIUM,
        headless: bool = True,
        max_age_seconds: int = 3600,
        enable_stealth: bool = True
    ):
        self.pool_size = pool_size
        self.browser_type = browser_type
        self.headless = headless
        self.max_age_seconds = max_age_seconds
        self.enable_stealth = enable_stealth
        self.stealth = StealthConfig()
        
        self.browsers: List[BrowserInstance] = []
        self.contexts: Dict[str, BrowserContextInstance] = {}
        self.priority_queue = PriorityQueue()
        self.playwright = None
        self._lock = asyncio.Lock()
        self._initialized = False
        self.retry = AdaptiveRetry()
        
        self._stats = {
            "total_creations": 0,
            "total_reuses": 0,
            "total_closures": 0,
            "total_errors": 0,
            "avg_wait_time": 0.0
        }
    
    async def initialize(self):
        if self._initialized:
            return
        self.playwright = await async_playwright().start()
        tasks = [self._create_browser() for _ in range(self.pool_size)]
        browsers = await asyncio.gather(*tasks)
        self.browsers = browsers
        self._stats["total_creations"] = self.pool_size
        self._initialized = True
        print(f"   🌐 Browser pool initialized: {self.pool_size} × {self.browser_type.value}")
    
    async def _create_browser(self) -> BrowserInstance:
        import uuid
        launch_args = StealthConfig.get_stealth_args() if self.enable_stealth else []
        user_agent = StealthConfig.get_random_user_agent()
        viewport = StealthConfig.get_viewport()
        locale = StealthConfig.get_locale()
        timezone_id = StealthConfig.get_timezone()
        
        if self.browser_type == BrowserType.CHROMIUM:
            browser = await self.retry.execute(
                self.playwright.chromium.launch,
                headless=self.headless,
                args=launch_args
            )
        elif self.browser_type == BrowserType.FIREFOX:
            browser = await self.retry.execute(
                self.playwright.firefox.launch,
                headless=self.headless
            )
        else:
            browser = await self.retry.execute(
                self.playwright.webkit.launch,
                headless=self.headless
            )
        
        return BrowserInstance(
            id=str(uuid.uuid4())[:8],
            browser=browser,
            browser_type=self.browser_type,
            metadata={
                "user_agent": user_agent,
                "viewport": viewport,
                "locale": locale,
                "timezone": timezone_id
            }
        )
    
    async def acquire(self, priority: int = 5, timeout: float = 30.0) -> Optional[BrowserInstance]:
        start_time = time.time()
        async with self._lock:
            if not self._initialized:
                await self.initialize()
        
        while time.time() - start_time < timeout:
            async with self._lock:
                for browser in sorted(self.browsers, key=lambda b: b.priority):
                    if browser.status == BrowserStatus.IDLE and browser.is_healthy():
                        if browser.age_seconds() > self.max_age_seconds:
                            await self._recycle_browser(browser)
                            continue
                        browser.use()
                        self._stats["total_reuses"] += 1
                        self._stats["avg_wait_time"] = (
                            self._stats["avg_wait_time"] * 0.9 + (time.time() - start_time) * 0.1
                        )
                        return browser
            await asyncio.sleep(0.1 * (self._stats["total_reuses"] % 10 + 1))
        
        async with self._lock:
            temp_browser = await self._create_browser()
            temp_browser.use()
            temp_browser.priority = priority
            self.browsers.append(temp_browser)
            self._stats["total_creations"] += 1
            self._stats["avg_wait_time"] = (
                self._stats["avg_wait_time"] * 0.9 + (time.time() - start_time) * 0.1
            )
            return temp_browser
    
    async def release(self, browser_instance: BrowserInstance):
        async with self._lock:
            browser_instance.release()
    
    async def _recycle_browser(self, browser_instance: BrowserInstance):
        try:
            await browser_instance.browser.close()
            self._stats["total_closures"] += 1
            new_browser = await self._create_browser()
            index = self.browsers.index(browser_instance)
            self.browsers[index] = new_browser
            self._stats["total_creations"] += 1
        except Exception as e:
            browser_instance.status = BrowserStatus.ERROR
            self._stats["total_errors"] += 1
    
    async def create_context(self, browser_instance: BrowserInstance) -> BrowserContextInstance:
        import uuid
        metadata = browser_instance.metadata
        
        context = await browser_instance.browser.new_context(
            viewport=metadata.get("viewport", {"width": 1280, "height": 720}),
            user_agent=metadata.get("user_agent", StealthConfig.get_random_user_agent()),
            locale=metadata.get("locale", StealthConfig.get_locale()),
            timezone_id=metadata.get("timezone", StealthConfig.get_timezone()),
            permissions=StealthConfig.get_permissions(),
            extra_http_headers={
                "Accept-Language": "en-US,en;q=0.9",
                "Accept-Encoding": "gzip, deflate, br",
                "DNT": "1",
                "Upgrade-Insecure-Requests": "1"
            }
        )
        
        context_instance = BrowserContextInstance(
            id=str(uuid.uuid4())[:8],
            context=context,
            browser_id=browser_instance.id
        )
        
        self.contexts[context_instance.id] = context_instance
        return context_instance
    
    async def close_context(self, context_instance: BrowserContextInstance):
        try:
            await context_instance.context.close()
        except Exception:
            pass
        finally:
            if context_instance.id in self.contexts:
                del self.contexts[context_instance.id]
    
    async def create_page(self, context_instance: BrowserContextInstance) -> Page:
        page = await context_instance.context.new_page()
        context_instance.add_page(page)
        return page
    
    async def navigate(self, page: Page, url: str, timeout: int = 30000) -> bool:
        try:
            await self.retry.execute(
                page.goto,
                url,
                timeout=timeout,
                wait_until="domcontentloaded"
            )
            return True
        except Exception:
            return False
    
    async def close_all(self):
        for browser in self.browsers:
            try:
                await browser.browser.close()
            except Exception:
                pass
        
        for context in list(self.contexts.values()):
            try:
                await context.context.close()
            except Exception:
                pass
        
        self.contexts.clear()
        self.browsers.clear()
        
        if self.playwright:
            await self.playwright.stop()
        
        self._initialized = False
        print("   🔒 Browser pool closed")
    
    def get_stats(self) -> Dict:
        return {
            "pool_size": len(self.browsers),
            "available": sum(1 for b in self.browsers if b.status == BrowserStatus.IDLE),
            "busy": sum(1 for b in self.browsers if b.status == BrowserStatus.BUSY),
            "total_creations": self._stats["total_creations"],
            "total_reuses": self._stats["total_reuses"],
            "total_closures": self._stats["total_closures"],
            "total_errors": self._stats["total_errors"],
            "avg_wait_time_ms": self._stats["avg_wait_time"] * 1000,
            "avg_browser_age": sum(b.age_seconds() for b in self.browsers) / max(1, len(self.browsers))
        }
    
    async def health_check(self) -> bool:
        try:
            browser = await self.acquire(timeout=5.0)
            if browser:
                await self.release(browser)
                return True
        except Exception:
            pass
        return False


_default_pool = None


async def get_browser_pool(
    pool_size: int = 3,
    browser_type: BrowserType = BrowserType.CHROMIUM,
    headless: bool = True
) -> BrowserPool:
    global _default_pool
    if _default_pool is None:
        _default_pool = BrowserPool(
            pool_size=pool_size,
            browser_type=browser_type,
            headless=headless
        )
        await _default_pool.initialize()
    return _default_pool


async def close_browser_pool():
    global _default_pool
    if _default_pool:
        await _default_pool.close_all()
        _default_pool = None
