
import asyncio
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

from playwright.async_api import Page, BrowserContext, Request, Response, Route


class InstrumentationEvent(Enum):
    """أحداث المراقبة"""
    REQUEST = "request"
    RESPONSE = "response"
    CONSOLE = "console"
    DIALOG = "dialog"
    DOWNLOAD = "download"
    FILE_CHOOSER = "file_chooser"
    WEBSOCKET = "websocket"
    WORKER = "worker"
    CRASH = "crash"
    CLOSE = "close"


@dataclass
class InstrumentationData:
    """بيانات المراقبة"""
    event_type: InstrumentationEvent
    timestamp: datetime = field(default_factory=datetime.now)
    data: Dict[str, Any] = field(default_factory=dict)
    source: str = ""


# حدود الذاكرة
MAX_EVENTS = 2000
MAX_STORAGE = 1000


class BrowserInstrumentation:
    """أدوات مراقبة المتصفح المتقدمة"""
    
    def __init__(self):
        self._events: List[InstrumentationData] = []
        self._network_requests: List[Dict] = []
        self._network_responses: List[Dict] = []
        self._console_messages: List[Dict] = []
        self._dialogs: List[Dict] = []
        self._errors: List[Dict] = []
        self._performance_entries: List[Dict] = []
        self._web_requests_filter: List[str] = []
        
        # إحصائيات
        self._stats = {
            "total_requests": 0,
            "total_responses": 0,
            "total_errors": 0,
            "total_console": 0,
            "api_calls": 0,
            "js_errors": 0
        }
    
    def _limit_storage(self):
        """الحد من حجم التخزين لمنع تسرب الذاكرة"""
        if len(self._network_requests) > MAX_STORAGE:
            self._network_requests = self._network_requests[-MAX_STORAGE//2:]
        if len(self._network_responses) > MAX_STORAGE:
            self._network_responses = self._network_responses[-MAX_STORAGE//2:]
        if len(self._console_messages) > MAX_STORAGE:
            self._console_messages = self._console_messages[-MAX_STORAGE//2:]
        if len(self._errors) > MAX_STORAGE:
            self._errors = self._errors[-MAX_STORAGE//2:]
        if len(self._events) > MAX_EVENTS:
            self._events = self._events[-MAX_EVENTS//2:]
    
    def _safe_wrapper(self, fn):
        """غلاف آمن للتعامل مع الأخطاء في الـ callbacks"""
        async def wrapper(*args, **kwargs):
            try:
                return await fn(*args, **kwargs)
            except Exception as e:
                # تسجيل الخطأ بصمت لمنع انقطاع المراقبة
                self._stats["total_errors"] += 1
                return None
        return wrapper
    
    async def setup(self, page: Page, context: BrowserContext = None):
        """إعداد المراقبة على الصفحة"""
        
        # مراقبة الطلبات
        async def on_request(request: Request):
            self._stats["total_requests"] += 1
            
            request_data = {
                "url": request.url,
                "method": request.method,
                "headers": dict(request.headers),
                "post_data": request.post_data[:500] if request.post_data else None,
                "resource_type": request.resource_type,
                "timestamp": datetime.now().isoformat()
            }
            self._network_requests.append(request_data)
            
            # كشف API calls
            if "/api/" in request.url or "/rest/" in request.url or "/graphql" in request.url:
                self._stats["api_calls"] += 1
                self._events.append(InstrumentationData(
                    event_type=InstrumentationEvent.REQUEST,
                    data=request_data,
                    source="network"
                ))
            
            self._limit_storage()
        
        # مراقبة الاستجابات
        async def on_response(response: Response):
            self._stats["total_responses"] += 1
            
            response_data = {
                "url": response.url,
                "status": response.status,
                "status_text": response.status_text,
                "headers": dict(response.headers),
                "timestamp": datetime.now().isoformat()
            }
            
            # محاولة قراءة الـ body للـ APIs
            if "/api/" in response.url or "/rest/" in response.url:
                try:
                    body = await response.text()
                    response_data["body_preview"] = body[:500]
                except:
                    pass
            
            self._network_responses.append(response_data)
            
            # كشف الأخطاء
            if response.status >= 400:
                self._stats["total_errors"] += 1
                self._errors.append(response_data)
            
            self._events.append(InstrumentationData(
                event_type=InstrumentationEvent.RESPONSE,
                data=response_data,
                source="network"
            ))
            
            self._limit_storage()
        
        # مراقبة وحدة التحكم
        async def on_console(msg):
            self._stats["total_console"] += 1
            
            console_data = {
                "type": msg.type,
                "text": msg.text,
                "location": msg.location,
                "timestamp": datetime.now().isoformat()
            }
            self._console_messages.append(console_data)
            
            # كشف أخطاء JavaScript
            if msg.type == "error":
                self._stats["js_errors"] += 1
                self._errors.append(console_data)
            
            self._events.append(InstrumentationData(
                event_type=InstrumentationEvent.CONSOLE,
                data=console_data,
                source="console"
            ))
            
            self._limit_storage()
        
        # مراقبة التنبيهات
        async def on_dialog(dialog):
            dialog_data = {
                "type": dialog.type,
                "message": dialog.message,
                "default_value": dialog.default_value,
                "timestamp": datetime.now().isoformat()
            }
            self._dialogs.append(dialog_data)
            self._events.append(InstrumentationData(
                event_type=InstrumentationEvent.DIALOG,
                data=dialog_data,
                source="dialog"
            ))
            await dialog.dismiss()
            self._limit_storage()
        
        # مراقبة أخطاء الصفحة
        async def on_page_error(error):
            error_data = {
                "error": str(error),
                "timestamp": datetime.now().isoformat()
            }
            self._errors.append(error_data)
            self._stats["total_errors"] += 1
            self._events.append(InstrumentationData(
                event_type=InstrumentationEvent.ERROR,
                data=error_data,
                source="page"
            ))
            self._limit_storage()
        
        # مراقبة انهيار الصفحة
        async def on_crash():
            crash_data = {
                "message": "Page crashed",
                "timestamp": datetime.now().isoformat()
            }
            self._errors.append(crash_data)
            self._stats["total_errors"] += 1
            self._events.append(InstrumentationData(
                event_type=InstrumentationEvent.CRASH,
                data=crash_data,
                source="page"
            ))
            self._limit_storage()
        
        # تسجيل المستمعين مع الغلاف الآمن
        page.on("request", self._safe_wrapper(on_request))
        page.on("response", self._safe_wrapper(on_response))
        page.on("console", self._safe_wrapper(on_console))
        page.on("dialog", self._safe_wrapper(on_dialog))
        page.on("pageerror", self._safe_wrapper(on_page_error))
        page.on("crash", self._safe_wrapper(on_crash))
        
        # استخدام context إذا تم تمريره (لمراقبة الأحداث على مستوى السياق)
        if context:
            context.on("close", self._safe_wrapper(lambda: self._events.append(
                InstrumentationData(event_type=InstrumentationEvent.CLOSE, source="context")
            )))
        
        # مراقبة الأداء
        await self._setup_performance_monitoring(page)
        
        # حقن سكربت مراقبة إضافي (مع الحماية من إعادة التعريف)
        await self._inject_monitoring_script(page)
    
    async def _setup_performance_monitoring(self, page: Page):
        """إعداد مراقبة الأداء"""
        try:
            # جمع مقاييس الأداء
            performance = await page.evaluate("""
                () => {
                    const perf = performance.getEntriesByType('navigation')[0];
                    if (!perf) return null;
                    return {
                        dom_content_loaded: perf.domContentLoadedEventEnd - perf.domContentLoadedEventStart,
                        load_time: perf.loadEventEnd - perf.fetchStart,
                        dom_interactive: perf.domInteractive - perf.fetchStart,
                        redirect_time: perf.redirectEnd - perf.redirectStart,
                        dns_time: perf.domainLookupEnd - perf.domainLookupStart,
                        tcp_time: perf.connectEnd - perf.connectStart,
                        request_time: perf.responseStart - perf.requestStart,
                        response_time: perf.responseEnd - perf.responseStart
                    };
                }
            """)
            if performance:
                self._performance_entries.append(performance)
                self._limit_storage()
        except:
            pass
    
    async def _inject_monitoring_script(self, page: Page):
        """حقن سكربت مراقبة متقدم في الصفحة (مع الحماية من إعادة التعريف)"""
        await page.add_init_script("""
            // منع إعادة تعريف متعددة
            if (window.__instrumentation_installed) {
                console.log("🔍 Instrumentation already installed");
                return;
            }
            
            window.__instrumentation_installed = true;
            
            // مراقبة console.log
            const originalLog = console.log;
            console.log = function(...args) {
                window.__captured_logs = window.__captured_logs || [];
                window.__captured_logs.push(args.join(' '));
                originalLog.apply(console, args);
            };
            
            // مراقبة الأخطاء
            window.addEventListener('error', (e) => {
                window.__captured_errors = window.__captured_errors || [];
                window.__captured_errors.push({
                    message: e.message,
                    filename: e.filename,
                    lineno: e.lineno,
                    colno: e.colno
                });
            });
            
            // مراقبة الـ fetch
            const originalFetch = window.fetch;
            window.fetch = function(...args) {
                window.__captured_fetch = window.__captured_fetch || [];
                window.__captured_fetch.push({
                    url: args[0],
                    options: args[1]
                });
                return originalFetch.apply(this, args);
            };
            
            // مراقبة الـ XHR (مع ترتيب صحيح)
            const originalXHROpen = XMLHttpRequest.prototype.open;
            const originalXHRSend = XMLHttpRequest.prototype.send;
            
            XMLHttpRequest.prototype.open = function(method, url) {
                this.__monitor_data = {method, url};
                return originalXHROpen.apply(this, arguments);
            };
            
            XMLHttpRequest.prototype.send = function(body) {
                window.__captured_xhr = window.__captured_xhr || [];
                window.__captured_xhr.push({
                    method: this.__monitor_data?.method,
                    url: this.__monitor_data?.url,
                    body: body
                });
                return originalXHRSend.call(this, body);
            };
            
            // مراقبة الـ localStorage
            const originalSetItem = localStorage.setItem;
            localStorage.setItem = function(key, value) {
                window.__localStorage_changes = window.__localStorage_changes || [];
                window.__localStorage_changes.push({key, value});
                originalSetItem.call(this, key, value);
            };
            
            console.log("🔍 Browser instrumentation activated");
        """)
    
    async def get_network_requests(self, filter_by: str = None) -> List[Dict]:
        """الحصول على طلبات الشبكة"""
        if filter_by:
            return [r for r in self._network_requests if filter_by in r.get("url", "")]
        return self._network_requests.copy()
    
    async def get_api_calls(self) -> List[Dict]:
        """الحصول على API calls"""
        return [r for r in self._network_requests if "/api/" in r.get("url", "") or "/rest/" in r.get("url", "")]
    
    async def get_errors(self) -> List[Dict]:
        """الحصول على الأخطاء"""
        return self._errors.copy()
    
    async def get_console_logs(self) -> List[Dict]:
        """الحصول على سجلات وحدة التحكم"""
        return self._console_messages.copy()
    
    async def get_performance_metrics(self) -> Dict:
        """الحصول على مقاييس الأداء"""
        if not self._performance_entries:
            return {}
        return self._performance_entries[-1]
    
    async def get_captured_data(self, page: Page) -> Dict:
        """الحصول على البيانات التي تم جمعها من الصفحة"""
        try:
            data = await page.evaluate("""
                () => ({
                    logs: window.__captured_logs || [],
                    errors: window.__captured_errors || [],
                    fetch: window.__captured_fetch || [],
                    xhr: window.__captured_xhr || [],
                    localStorage: window.__localStorage_changes || []
                })
            """)
            return data
        except:
            return {}
    
    def filter_requests(self, patterns: List[str]):
        """تعيين تصفية للطلبات المراد تتبعها"""
        self._web_requests_filter = patterns
    
    def clear(self):
        """مسح جميع البيانات المجمعة"""
        self._events.clear()
        self._network_requests.clear()
        self._network_responses.clear()
        self._console_messages.clear()
        self._dialogs.clear()
        self._errors.clear()
        self._performance_entries.clear()
        self._stats = {
            "total_requests": 0,
            "total_responses": 0,
            "total_errors": 0,
            "total_console": 0,
            "api_calls": 0,
            "js_errors": 0
        }
    
    def get_stats(self) -> Dict:
        """إحصائيات المراقبة"""
        return {
            **self._stats,
            "events_count": len(self._events),
            "network_requests_count": len(self._network_requests),
            "network_responses_count": len(self._network_responses),
            "console_messages_count": len(self._console_messages),
            "dialogs_count": len(self._dialogs),
            "performance_entries_count": len(self._performance_entries),
            "storage_limit": MAX_STORAGE,
            "events_limit": MAX_EVENTS
        }
    
    def get_summary(self) -> Dict:
        """ملخص المراقبة"""
        return {
            "network": {
                "total": self._stats["total_requests"],
                "api_calls": self._stats["api_calls"],
                "errors": self._stats["total_errors"]
            },
            "console": {
                "total": self._stats["total_console"],
                "js_errors": self._stats["js_errors"]
            },
            "performance": self._performance_entries[-1] if self._performance_entries else None
        }


async def create_instrumentation(page: Page, context: BrowserContext = None) -> BrowserInstrumentation:
    """إنشاء أداة مراقبة للصفحة"""
    instrumentation = BrowserInstrumentation()
    await instrumentation.setup(page, context)
    return instrumentation

