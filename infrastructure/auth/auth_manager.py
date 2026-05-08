
import asyncio
import json
import time
import uuid
import base64  # ✅ إضافة import base64
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from playwright.async_api import async_playwright, Page, Browser, BrowserContext


class AuthType(Enum):
    """أنواع المصادقة"""
    NONE = "none"
    BASIC = "basic"
    BEARER = "bearer"
    SESSION = "session"
    OAUTH2 = "oauth2"
    JWT = "jwt"
    API_KEY = "api_key"
    CUSTOM = "custom"


class AuthStatus(Enum):
    """حالة المصادقة"""
    NOT_AUTHENTICATED = "not_authenticated"
    AUTHENTICATING = "authenticating"
    AUTHENTICATED = "authenticated"
    EXPIRED = "expired"
    FAILED = "failed"


@dataclass
class AuthCredentials:
    """بيانات المصادقة"""
    username: Optional[str] = None
    password: Optional[str] = None
    token: Optional[str] = None
    api_key: Optional[str] = None
    client_id: Optional[str] = None
    client_secret: Optional[str] = None
    refresh_token: Optional[str] = None
    csrf_token: Optional[str] = None
    extra: Dict[str, Any] = field(default_factory=dict)


@dataclass
class BrowserFingerprint:
    """بصمة المتصفح للحفاظ على الجلسة"""
    user_agent: str = ""
    viewport: Dict[str, int] = field(default_factory=lambda: {"width": 1280, "height": 720})
    timezone_id: str = ""
    locale: str = "en-US"
    geolocation: Optional[Dict] = None
    permissions: List[str] = field(default_factory=list)
    color_scheme: str = "light"


@dataclass
class AuthSession:
    """جلسة مصادقة"""
    id: str
    name: str
    auth_type: AuthType
    credentials: AuthCredentials
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: List[Dict] = field(default_factory=list)
    storage_state: Optional[Dict] = None
    fingerprint: BrowserFingerprint = field(default_factory=BrowserFingerprint)
    csrf_token: Optional[str] = None
    created_at: float = field(default_factory=time.time)
    last_used: float = field(default_factory=time.time)
    expires_at: Optional[float] = None
    status: AuthStatus = AuthStatus.NOT_AUTHENTICATED
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict:
        return {
            "id": self.id,
            "name": self.name,
            "auth_type": self.auth_type.value,
            "headers": self.headers,
            "cookies": self.cookies,
            "storage_state": self.storage_state,
            "fingerprint": {
                "user_agent": self.fingerprint.user_agent,
                "viewport": self.fingerprint.viewport
            },
            "csrf_token": self.csrf_token,
            "created_at": self.created_at,
            "last_used": self.last_used,
            "expires_at": self.expires_at,
            "status": self.status.value
        }
    
    def is_expired(self) -> bool:
        if self.expires_at:
            return time.time() > self.expires_at
        return False
    
    def update_headers(self):
        """تحديث الـ headers بناءً على نوع المصادقة"""
        if self.auth_type == AuthType.BEARER and self.credentials.token:
            self.headers["Authorization"] = f"Bearer {self.credentials.token}"
        elif self.auth_type == AuthType.BASIC and self.credentials.username and self.credentials.password:
            # ✅ base64 متوفر الآن
            credentials = f"{self.credentials.username}:{self.credentials.password}"
            encoded = base64.b64encode(credentials.encode()).decode()
            self.headers["Authorization"] = f"Basic {encoded}"
        elif self.auth_type == AuthType.API_KEY and self.credentials.api_key:
            self.headers["X-API-Key"] = self.credentials.api_key
        
        # إضافة CSRF token
        if self.csrf_token:
            self.headers["X-CSRF-Token"] = self.csrf_token
            self.headers["CSRF-Token"] = self.csrf_token


class LoginFormDetector:
    """كاشف نموذج تسجيل الدخول المتقدم"""
    
    @staticmethod
    async def detect_fields(page: Page) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        """كشف حقول اسم المستخدم وكلمة المرور وزر الإرسال"""
        
        username_selectors = [
            'input[name="username"]', 'input[name="email"]',
            'input[type="email"]', 'input[name="user"]',
            'input[id="username"]', 'input[id="email"]',
            'input[placeholder*="username" i]', 'input[placeholder*="email" i]',
            'input[placeholder*="user" i]', 'input[aria-label*="username" i]'
        ]
        
        password_selectors = [
            'input[type="password"]',
            'input[name="password"]',
            'input[id="password"]',
            'input[placeholder*="password" i]',
            'input[aria-label*="password" i]'
        ]
        
        submit_selectors = [
            'button[type="submit"]', 'input[type="submit"]',
            'button:has-text("Login")', 'button:has-text("Sign in")',
            'button:has-text("Log in")', 'form button',
            '[aria-label*="login" i]', '[aria-label*="sign in" i]'
        ]
        
        username_field = None
        password_field = None
        submit_button = None
        
        for selector in username_selectors:
            try:
                element = await page.query_selector(selector)
                if element and await element.is_visible():
                    username_field = selector
                    break
            except:
                continue
        
        for selector in password_selectors:
            try:
                element = await page.query_selector(selector)
                if element and await element.is_visible():
                    password_field = selector
                    break
            except:
                continue
        
        for selector in submit_selectors:
            try:
                element = await page.query_selector(selector)
                if element and await element.is_visible():
                    submit_button = selector
                    break
            except:
                continue
        
        if not username_field or not password_field:
            forms = await page.query_selector_all('form')
            for form in forms:
                inputs = await form.query_selector_all('input')
                for inp in inputs:
                    inp_type = await inp.get_attribute('type')
                    if inp_type == 'email' or 'user' in str(await inp.get_attribute('name')).lower():
                        if not username_field:
                            username_field = f'form >> input[name="{await inp.get_attribute("name")}"]'
                    elif inp_type == 'password':
                        password_field = f'form >> input[type="password"]'
                
                if username_field and password_field:
                    submit = await form.query_selector('button[type="submit"], input[type="submit"]')
                    if submit:
                        submit_button = 'form >> button[type="submit"]'
                    break
        
        return username_field, password_field, submit_button
    
    @staticmethod
    async def extract_csrf_token(page: Page) -> Optional[str]:
        """استخراج CSRF token من الصفحة"""
        meta_token = await page.evaluate("""
            () => {
                const meta = document.querySelector('meta[name="csrf-token"], meta[name="csrf_token"]');
                return meta ? meta.getAttribute('content') : null;
            }
        """)
        if meta_token:
            return meta_token
        
        hidden_token = await page.evaluate("""
            () => {
                const input = document.querySelector('input[name="csrf_token"], input[name="csrf-token"], input[name="_token"]');
                return input ? input.value : null;
            }
        """)
        if hidden_token:
            return hidden_token
        
        return None


class AuthManager:
    """مدير المصادقة المتقدم"""
    
    def __init__(self):
        self._sessions: Dict[str, AuthSession] = {}
        self._current_session_id: Optional[str] = None
        self._lock = asyncio.Lock()
        self._form_detector = LoginFormDetector()
        
        self._test_credentials = {
            "juice-shop": AuthCredentials(username="test@test.com", password="test123"),
            "gruyere": AuthCredentials(username="test", password="test"),
            "testphp": AuthCredentials(username="test", password="test")
        }
        
        self._default_headers = {
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "en-US,en;q=0.9",
            "Content-Type": "application/json"
        }
    
    async def create_session(
        self,
        name: str,
        auth_type: AuthType = AuthType.NONE,
        credentials: AuthCredentials = None,
        expires_in: int = None
    ) -> AuthSession:
        async with self._lock:
            session_id = str(uuid.uuid4())[:8]
            
            session = AuthSession(
                id=session_id,
                name=name,
                auth_type=auth_type,
                credentials=credentials or AuthCredentials(),
                headers=self._default_headers.copy()
            )
            
            if expires_in:
                session.expires_at = time.time() + expires_in
            
            session.update_headers()
            
            self._sessions[session_id] = session
            return session
    
    async def set_current_session(self, session_id: str) -> bool:
        async with self._lock:
            if session_id in self._sessions:
                self._current_session_id = session_id
                return True
            return False
    
    async def get_current_session(self) -> Optional[AuthSession]:
        async with self._lock:
            if self._current_session_id:
                session = self._sessions.get(self._current_session_id)
                if session and session.is_expired():
                    await self._refresh_session(session)
                return session
            return None
    
    async def _refresh_session(self, session: AuthSession) -> bool:
        if session.auth_type == AuthType.BEARER and session.credentials.refresh_token:
            pass
        session.status = AuthStatus.AUTHENTICATED
        session.last_used = time.time()
        return True
    
    async def _apply_storage_to_page(self, page: Page, session: AuthSession):
        """تطبيق localStorage و sessionStorage"""
        local_data = session.metadata.get("localStorage", {})
        session_data = session.metadata.get("sessionStorage", {})
        
        if local_data or session_data:
            await page.evaluate("""
                (storage) => {
                    if (storage.local) {
                        for (const [k, v] of Object.entries(storage.local)) {
                            localStorage.setItem(k, v);
                        }
                    }
                    if (storage.session) {
                        for (const [k, v] of Object.entries(storage.session)) {
                            sessionStorage.setItem(k, v);
                        }
                    }
                }
            """, {
                "local": local_data,
                "session": session_data
            })
    
    async def authenticate_with_playwright(
        self,
        login_url: str,
        username: str,
        password: str,
        session_name: str = None,
        wait_after_login: int = 5000
    ) -> Optional[AuthSession]:
        browser = None
        context = None
        
        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(
                    headless=True,
                    args=["--no-sandbox", "--disable-setuid-sandbox"]
                )
                context = await browser.new_context()
                page = await context.new_page()
                
                print(f"   🔐 Logging into {login_url}...")
                
                await page.goto(login_url, wait_until="networkidle", timeout=30000)
                
                username_field, password_field, submit_button = await self._form_detector.detect_fields(page)
                
                if not username_field or not password_field:
                    print(f"   ⚠️ Could not detect login form")
                    return None
                
                csrf_token = await self._form_detector.extract_csrf_token(page)
                
                await page.fill(username_field, username)
                await page.fill(password_field, password)
                
                # إضافة CSRF token إذا وجد
                if csrf_token:
                    csrf_field = await page.query_selector('input[name="csrf_token"], input[name="_token"]')
                    if csrf_field:
                        await csrf_field.fill(csrf_token)
                
                if submit_button:
                    await page.click(submit_button)
                else:
                    await page.keyboard.press("Enter")
                
                await page.wait_for_timeout(wait_after_login)
                
                # ✅ حفظ storage_state كامل (أفضل طريقة)
                storage_state = await context.storage_state()
                cookies = await context.cookies()
                
                localStorage = await page.evaluate("""
                    () => {
                        const items = {};
                        for (let i = 0; i < localStorage.length; i++) {
                            const key = localStorage.key(i);
                            items[key] = localStorage.getItem(key);
                                               return items;
                    }
                """)
                
                sessionStorage = await page.evaluate("""
                    () => {
                        const items = {};
                        for (let i = 0; i < sessionStorage.length; i++) {
                            const key = sessionStorage.key(i);
                            items[key] = sessionStorage.getItem(key);
                        }
                        return items;
                    }
                """)
                
                post_login_csrf = await self._form_detector.extract_csrf_token(page)
                
                # ✅ استخدام create_session (الذي يضيف الجلسة مرة واحدة)
                session = await self.create_session(
                    name=session_name or f"playwright_auth",
                    auth_type=AuthType.SESSION
                )
                
                session.cookies = cookies
                session.storage_state = storage_state
                session.csrf_token = post_login_csrf or csrf_token
                session.status = AuthStatus.AUTHENTICATED
                session.metadata["login_url"] = login_url
                session.metadata["username"] = username
                session.metadata["localStorage"] = localStorage
                session.metadata["sessionStorage"] = sessionStorage
                
                if session.csrf_token:
                    session.update_headers()
                
                cookie_str = "; ".join([f"{c['name']}={c['value']}" for c in cookies])
                session.headers["Cookie"] = cookie_str
                
                self._current_session_id = session.id
                
                print(f"   ✅ Authentication successful! Session: {session.id}")
                return session
                
        except Exception as e:
            print(f"   ❌ Authentication failed: {str(e)[:100]}")
            return None
        finally:
            if context:
                try:
                    await context.close()
                except:
                    pass
            if browser:
                try:
                    await browser.close()
                except:
                    pass
    
    async def authenticate_with_test_credentials(self, site_name: str) -> Optional[AuthSession]:
        if site_name not in self._test_credentials:
            return None
        
        creds = self._test_credentials[site_name]
        
        login_urls = {
            "juice-shop": "https://juice-shop.github.io/juice-shop/#/login",
            "gruyere": "https://google-gruyere.appspot.com/",
            "testphp": "https://testphp.vulnweb.com/login.php"
        }
        
        if site_name in login_urls:
            return await self.authenticate_with_playwright(
                login_url=login_urls[site_name],
                username=creds.username,
                password=creds.password,
                session_name=f"{site_name}_auth"
            )
        
        return None
    
    async def set_bearer_token(self, token: str, session_name: str = None) -> AuthSession:
        session = await self.create_session(
            name=session_name or "bearer_auth",
            auth_type=AuthType.BEARER,
            credentials=AuthCredentials(token=token)
        )
        
        session.update_headers()
        session.status = AuthStatus.AUTHENTICATED
        
        self._current_session_id = session.id
        return session
    
    async def set_basic_auth(self, username: str, password: str, session_name: str = None) -> AuthSession:
        session = await self.create_session(
            name=session_name or "basic_auth",
            auth_type=AuthType.BASIC,
            credentials=AuthCredentials(username=username, password=password)
        )
        
        session.update_headers()
        session.status = AuthStatus.AUTHENTICATED
        
        self._current_session_id = session.id
        return session
    
    async def get_headers(self) -> Dict[str, str]:
        session = await self.get_current_session()
        if session:
            return session.headers.copy()
        return self._default_headers.copy()
    
    async def get_cookies(self) -> List[Dict]:
        session = await self.get_current_session()
        if session:
            return session.cookies.copy()
        return []
    
    async def get_storage_state(self) -> Optional[Dict]:
        session = await self.get_current_session()
        if session:
            return session.storage_state
        return None
    
    async def get_csrf_token(self) -> Optional[str]:
        session = await self.get_current_session()
        if session:
            return session.csrf_token
        return None
    
    async def apply_to_context(self, context: BrowserContext, target_url: str = None, session_id: str = None):
        """
        تطبيق الجلسة على سياق Playwright
        target_url: مطلوب لتطبيق localStorage/sessionStorage
        """
        sid = session_id or self._current_session_id
        if not sid or sid not in self._sessions:
            return False
        
        session = self._sessions[sid]
        
        # ✅ دمج headers بشكل صحيح (لا تكتب فوق بعضها)
        headers = session.headers.copy()
        
        if session.fingerprint.user_agent:
            headers["User-Agent"] = session.fingerprint.user_agent
        
        await context.set_extra_http_headers(headers)
        
        # إضافة الكوكيز
        if session.cookies:
            await context.add_cookies(session.cookies)
        
        # ✅ تطبيق storage_state إذا كان موجوداً (أفضل طريقة)
        if session.storage_state:
            try:
                # إعادة إنشاء context مع storage_state
                # ملاحظة: لا يمكن تعديل storage_state بعد إنشاء context
                # لذلك هذه مجرد معلومات للتتبع
                pass
            except:
                pass
        
        # تطبيق localStorage و sessionStorage (كـ fallback)
        if target_url and (session.metadata.get("localStorage") or session.metadata.get("sessionStorage")):
            page = await context.new_page()
            try:
                await page.goto(target_url, wait_until="domcontentloaded", timeout=10000)
                await self._apply_storage_to_page(page, session)
            finally:
                await page.close()
        
        return True
    
    def get_stats(self) -> Dict:
        return {
            "total_sessions": len(self._sessions),
            "authenticated_sessions": sum(1 for s in self._sessions.values() if s.status == AuthStatus.AUTHENTICATED),
            "current_session": self._current_session_id,
            "sessions": [
                {
                    "id": s.id,
                    "name": s.name,
                    "auth_type": s.auth_type.value,
                    "status": s.status.value,
                    "has_csrf": bool(s.csrf_token),
                    "last_used": s.last_used
                }
                for s in self._sessions.values()
            ]
        }
    
    def clear(self):
        self._sessions.clear()
        self._current_session_id = None


_default_auth_manager = None


def get_auth_manager() -> AuthManager:
    global _default_auth_manager
    if _default_auth_manager is None:
        _default_auth_manager = AuthManager()
    return _default_auth_manager

