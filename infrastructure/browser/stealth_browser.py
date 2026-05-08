
import random
import hashlib
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from playwright.async_api import Page, BrowserContext


@dataclass
class BrowserFingerprint:
    """بصمة المتصفح المتسقة لكل جلسة"""
    user_agent: str
    platform: str
    language: str
    languages: List[str]
    hardware_concurrency: int
    device_memory: int
    screen_resolution: Dict[str, int]
    color_depth: int
    timezone: str
    webgl_vendor: str
    webgl_renderer: str
    session_id: str = ""


class StealthBrowser:
    """متصفح متخفي بـ 3 طبقات - احترافي"""
    
    # الطبقة 1: إعدادات ثابتة (Consistency)
    CONSISTENT_SETTINGS = {
        "languages": ["en-US", "en"],
        "color_depth": 24,
        "platforms": {
            "windows": "Win32",
            "mac": "MacIntel", 
            "linux": "Linux x86_64"
        }
    }
    
    # الطبقة 2: إعدادات قابلة للتغيير (Rotation)
    ROTATABLE_SETTINGS = {
        "user_agents": [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0"
        ],
        "timezones": [
            "America/New_York", "America/Los_Angeles", "Europe/London",
            "Europe/Paris", "Asia/Tokyo", "Asia/Dubai"
        ],
        "viewports": [
            {"width": 1920, "height": 1080},
            {"width": 1366, "height": 768},
            {"width": 1536, "height": 864},
            {"width": 1440, "height": 900}
        ],
        "webgl_vendors": ["Google Inc.", "NVIDIA Corporation", "Intel Inc."],
        "webgl_renderers": [
            "ANGLE (NVIDIA GeForce RTX 3080 Direct3D11 vs_5_0 ps_5_0)",
            "ANGLE (AMD Radeon RX 6800 XT Direct3D11 vs_5_0 ps_5_0)",
            "ANGLE (Intel Iris Xe Graphics Direct3D11 vs_5_0 ps_5_0)"
        ]
    }
    
    # الطبقة 3: تعديلات طفيفة (Minimal Mutation)
    MINIMAL_MUTATIONS = {
        "hardware_concurrency": [4, 6, 8, 12],
        "device_memory": [4, 8, 16]
    }
    
    def __init__(self):
        self._session_fingerprints: Dict[str, BrowserFingerprint] = {}
    
    def _deterministic_hash(self, session_id: str, option: str) -> int:
        """توليد قيمة حتمية لكل جلسة"""
        hash_val = int(hashlib.md5(f"{session_id}_{option}".encode()).hexdigest()[:8], 16)
        return hash_val
    
    def create_session_fingerprint(self, session_id: str, platform: str = "windows") -> BrowserFingerprint:
        """إنشاء بصمة متسقة لكل جلسة"""
        
        # استخدام session_id كـ seed للحتمية
        random.seed(self._deterministic_hash(session_id, "seed"))
        
        # اختيار الإعدادات بناءً على الـ session_id (حتمي)
        ua_index = self._deterministic_hash(session_id, "ua") % len(self.ROTATABLE_SETTINGS["user_agents"])
        tz_index = self._deterministic_hash(session_id, "tz") % len(self.ROTATABLE_SETTINGS["timezones"])
        vp_index = self._deterministic_hash(session_id, "vp") % len(self.ROTATABLE_SETTINGS["viewports"])
        wgv_index = self._deterministic_hash(session_id, "wgv") % len(self.ROTATABLE_SETTINGS["webgl_vendors"])
        wgr_index = self._deterministic_hash(session_id, "wgr") % len(self.ROTATABLE_SETTINGS["webgl_renderers"])
        hc_index = self._deterministic_hash(session_id, "hc") % len(self.MINIMAL_MUTATIONS["hardware_concurrency"])
        dm_index = self._deterministic_hash(session_id, "dm") % len(self.MINIMAL_MUTATIONS["device_memory"])
        
        fingerprint = BrowserFingerprint(
            user_agent=self.ROTATABLE_SETTINGS["user_agents"][ua_index],
            platform=self.CONSISTENT_SETTINGS["platforms"].get(platform, "Win32"),
            language=self.CONSISTENT_SETTINGS["languages"][0],
            languages=self.CONSISTENT_SETTINGS["languages"],
            hardware_concurrency=self.MINIMAL_MUTATIONS["hardware_concurrency"][hc_index],
            device_memory=self.MINIMAL_MUTATIONS["device_memory"][dm_index],
            screen_resolution=self.ROTATABLE_SETTINGS["viewports"][vp_index],
            color_depth=self.CONSISTENT_SETTINGS["color_depth"],
            timezone=self.ROTATABLE_SETTINGS["timezones"][tz_index],
            webgl_vendor=self.ROTATABLE_SETTINGS["webgl_vendors"][wgv_index],
            webgl_renderer=self.ROTATABLE_SETTINGS["webgl_renderers"][wgr_index],
            session_id=session_id
        )
        
        self._session_fingerprints[session_id] = fingerprint
        
        # إعادة تعيين random
        random.seed()
        
        return fingerprint
    
    def get_session_fingerprint(self, session_id: str) -> Optional[BrowserFingerprint]:
        """الحصول على بصمة جلسة موجودة"""
        return self._session_fingerprints.get(session_id)
    
    async def apply_to_context(self, context: BrowserContext, session_id: str = None):
        """تطبيق التخفي على سياق المتصفح"""
        
        # إذا كان هناك session_id، استخدم بصمة متسقة
        fingerprint = None
        if session_id and session_id in self._session_fingerprints:
            fingerprint = self._session_fingerprints[session_id]
        
        # حقن سكربت التخفي المتقدم (بدون تشويش على Canvas)
        await context.add_init_script("""
            //=== WebDriver Detection Bypass ===
            Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
            
            //=== Chrome Automation Bypass ===
            delete window.cdc_adoQpoasnfa76pfcZLmcfl_Array;
            delete window.cdc_adoQpoasnfa76pfcZLmcfl_Promise;
            delete window.cdc_adoQpoasnfa76pfcZLmcfl_Symbol;
            
            //=== Permissions ===
            const originalQuery = window.navigator.permissions.query;
            window.navigator.permissions.query = (parameters) => (
                parameters.name === 'notifications' ?
                    Promise.resolve({state: Notification.permission}) :
                    originalQuery(parameters)
            );
            
            //=== Languages ===
            Object.defineProperty(navigator, 'languages', {get: () => ['en-US', 'en']});
            Object.defineProperty(navigator, 'language', {get: () => 'en-US'});
            
            //=== Plugins (بدون تعديلات مبالغ فيها) ===
            if (navigator.plugins && navigator.plugins.length === 0) {
                const plugins = [
                    {name: 'Chrome PDF Plugin', filename: 'internal-pdf-viewer'},
                    {name: 'Chrome PDF Viewer', filename: 'mhjfbmdgcfjbbpaeojofohoefgiehjai'},
                    {name: 'Native Client', filename: 'internal-nacl-plugin'}
                ];
                plugins.length = 3;
                plugins.item = (i) => plugins[i];
                Object.defineProperty(navigator, 'plugins', {get: () => plugins});
            }
            
            //=== Screen Resolution (غير intrusive) ===
            if (screen.width === 0 || screen.height === 0) {
                Object.defineProperty(screen, 'width', {get: () => window.innerWidth});
                Object.defineProperty(screen, 'height', {get: () => window.innerHeight});
            }
            
            //=== Connection (إذا كان متاحاً) ===
            if (navigator.connection) {
                if (navigator.connection.rtt === 0) {
                    Object.defineProperty(navigator.connection, 'rtt', {get: () => 50});
                }
                if (navigator.connection.downlink === 0) {
                    Object.defineProperty(navigator.connection, 'downlink', {get: () => 10});
                }
            }
            
            console.log("🛡️ Stealth mode activated (Layer 1 & 2)");
        """)
        
        # إذا كان هناك fingerprint، قم بتطبيقه
        if fingerprint:
            await context.set_extra_http_headers({
                "User-Agent": fingerprint.user_agent,
                "Accept-Language": fingerprint.language,
                "Accept-Encoding": "gzip, deflate, br"
            })
    
    async def apply_to_page(self, page: Page, session_id: str = None):
        """تطبيق التخفي على صفحة محددة"""
        
        # حقن سكربت التخفي (بدون تعديل Canvas لتجنب الكشف)
        await page.add_init_script("""
            //=== Timing and Performance ===
            const originalNow = performance.now;
            let timeOffset = 0;
            performance.now = function() {
                return originalNow.call(this) + timeOffset;
            };
            
            //=== Console noise reduction ===
            const originalLog = console.log;
            console.log = function() {
                if (arguments[0] && typeof arguments[0] === 'string') {
                    if (arguments[0].includes('webdriver') || 
                        arguments[0].includes('automation') ||
                        arguments[0].includes('puppeteer')) {
                        return;
                    }
                }
                originalLog.apply(console, arguments);
            };
            
            console.log("🛡️ Stealth mode activated (Layer 3 - Minimal Mutation)");
        """)
    
    def rotate_fingerprint_between_sessions(self):
        """تغيير البصمة بين الجلسات (ليس أثناء الجلسة)"""
        # تنظيف الجلسات القديمة
        self._session_fingerprints.clear()
    
    def get_fingerprint(self, session_id: str = None) -> Dict:
        """الحصول على بصمة المتصفح الحالية"""
        if session_id and session_id in self._session_fingerprints:
            fp = self._session_fingerprints[session_id]
            return {
                "user_agent": fp.user_agent,
                "platform": fp.platform,
                "language": fp.language,
                "languages": fp.languages,
                "hardware_concurrency": fp.hardware_concurrency,
                "device_memory": fp.device_memory,
                "screen_resolution": fp.screen_resolution,
                "color_depth": fp.color_depth,
                "timezone": fp.timezone,
                "webgl_vendor": fp.webgl_vendor,
                "webgl_renderer": fp.webgl_renderer,
                "session_id": fp.session_id
            }
        return {"message": "No active session fingerprint"}
    
    def get_stats(self) -> Dict:
        """إحصائيات التخفي"""
        return {
            "active_sessions": len(self._session_fingerprints),
            "fingerprint_stable": True,
            "layers_active": 3,
            "layer_1_consistency": "enabled",
            "layer_2_rotation": "between_sessions",
            "layer_3_minimal_mutation": "enabled"
        }


# نسخة عالمية
_default_stealth = StealthBrowser()


def get_stealth_browser() -> StealthBrowser:
    """الحصول على نسخة عالمية من المتصفح المتخفي"""
    global _default_stealth
    return _default_stealth

