"""
Interactive Login - نظام تسجيل دخول تفاعلي ذكي

يدعم:
- استخراج تلقائي لحقول النموذج
- طلب البيانات المفقودة من المستخدم
- التعامل مع 2FA / CAPTCHA
- حفظ الجلسة كاملة (cookies + headers + tokens)
- دعم multi-step login
"""

import asyncio
import re
import json
import os
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup

import httpx
import logging

logger = logging.getLogger(__name__)


@dataclass
class LoginField:
    """حقل في نموذج تسجيل الدخول"""
    name: str
    type: str  # email, password, text, hidden, submit, captcha, 2fa
    label: str
    placeholder: str = ""
    required: bool = False
    value: str = ""
    autocomplete: str = ""
    error_message: str = ""
    
    def ask_user(self) -> str:
        """طلب قيمة الحقل من المستخدم"""
        if self.type == "password":
            import getpass
            return getpass.getpass(f"  🔒 {self.label or self.name}: ")
        elif self.type == "captcha":
            print(f"  🛡️  CAPTCHA detected! Please solve manually in browser")
            print(f"  📋 Then paste the token here:")
            return input(f"  CAPTCHA token: ")
        elif self.type == "2fa":
            print(f"  📱 2FA code required!")
            return input(f"  {self.label or 'Verification code'}: ")
        else:
            return input(f"  📝 {self.label or self.name}: ")


@dataclass
class LoginSession:
    """جلسة تسجيل دخول محفوظة"""
    url: str
    cookies: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    tokens: Dict[str, str] = field(default_factory=dict)
    csrf_token: str = ""
    session_id: str = ""
    created_at: str = ""
    user_agent: str = ""
    
    def save(self, path: str = "sessions"):
        """حفظ الجلسة إلى ملف"""
        os.makedirs(path, exist_ok=True)
        filepath = f"{path}/session_{self.session_id}.json"
        
        with open(filepath, 'w') as f:
            json.dump({
                "url": self.url,
                "cookies": self.cookies,
                "headers": self.headers,
                "tokens": self.tokens,
                "csrf_token": self.csrf_token,
                "session_id": self.session_id,
                "created_at": self.created_at,
                "user_agent": self.user_agent,
            }, f, indent=2)
        
        logger.info(f"Session saved to {filepath}")
        return filepath
    
    @classmethod
    def load(cls, filepath: str) -> Optional['LoginSession']:
        """تحميل جلسة من ملف"""
        if not os.path.exists(filepath):
            return None
        
        with open(filepath, 'r') as f:
            data = json.load(f)
        
        session = cls(
            url=data.get("url", ""),
            cookies=data.get("cookies", {}),
            headers=data.get("headers", {}),
            tokens=data.get("tokens", {}),
            csrf_token=data.get("csrf_token", ""),
            session_id=data.get("session_id", ""),
            created_at=data.get("created_at", ""),
            user_agent=data.get("user_agent", ""),
        )
        
        return session


class InteractiveLogin:
    """
    نظام تسجيل دخول تفاعلي ذكي
    
    يتعامل مع:
    - Single-page login (email + password)
    - Multi-step login (email → password → 2FA)
    - CAPTCHA detection (يعرض للمستخدم)
    - CSRF tokens
    - OAuth/SSO redirects
    """
    
    USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    ]
    
    def __init__(self):
        self.client = None
        self.session = LoginSession(url="")
        self._step_history: List[Dict] = []
        
        logger.info("InteractiveLogin initialized")
    
    async def _create_client(self) -> httpx.AsyncClient:
        """إنشاء عميل HTTP مع cookies"""
        import random
        
        return httpx.AsyncClient(
            timeout=30,
            follow_redirects=True,
            verify=False,
            headers={
                "User-Agent": random.choice(self.USER_AGENTS),
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.9",
                "Accept-Encoding": "gzip, deflate, br",
                "Connection": "keep-alive",
                "Upgrade-Insecure-Requests": "1",
            }
        )
    
    async def login(self, login_url: str, username: str = None, password: str = None) -> Optional[LoginSession]:
        """
        تسجيل دخول تفاعلي ذكي
        
        Args:
            login_url: رابط صفحة تسجيل الدخول
            username: اسم المستخدم (اختياري - سيطلبه إذا لم يقدم)
            password: كلمة المرور (اختياري - سيطلبها إذا لم يقدم)
        
        Returns:
            LoginSession محفوظة أو None
        """
        print(f"\n🔐 Interactive Login Wizard")
        print(f"{'='*50}")
        print(f"   Target: {login_url}")
        
        self.session = LoginSession(url=login_url)
        self.session.created_at = datetime.now().isoformat()
        
        self.client = await self._create_client()
        
        try:
            # الخطوة 1: تحميل صفحة login
            print(f"\n📄 Step 1: Loading login page...")
            login_page = await self._fetch_page(login_url)
            
            if not login_page:
                print(f"❌ Cannot access {login_url}")
                return None
            
            # الخطوة 2: استخراج النموذج
            print(f"🔍 Step 2: Analyzing login form...")
            form_info = self._extract_login_form(login_page, login_url)
            
            if not form_info:
                print(f"❌ No login form found on page")
                return None
            
            # عرض الحقول المكتشفة
            print(f"\n   📋 Form fields detected:")
            for field in form_info['fields']:
                print(f"      - {field.type}: {field.name} ({field.label})")
            
            # الخطوة 3: جمع البيانات المطلوبة
            print(f"\n📝 Step 3: Gathering credentials...")
            
            form_data = {}
            
            for field in form_info['fields']:
                if field.type == "hidden":
                    form_data[field.name] = field.value
                
                elif field.type == "email":
                    if username:
                        form_data[field.name] = username
                    else:
                        form_data[field.name] = field.ask_user()
                
                elif field.type == "password":
                    if password:
                        form_data[field.name] = password
                    else:
                        form_data[field.name] = field.ask_user()
                
                elif field.type == "text":
                    if "user" in field.name.lower() or "login" in field.name.lower():
                        if username:
                            form_data[field.name] = username
                        else:
                            form_data[field.name] = input(f"  📝 {field.label or field.name}: ")
                    else:
                        form_data[field.name] = field.ask_user()
                
                elif field.type == "submit":
                    form_data[field.name] = field.value or "Login"
                
                elif field.type in ["captcha", "2fa"]:
                    form_data[field.name] = field.ask_user()
            
            # إضافة CSRF token إذا وجد
            if form_info.get('csrf_token'):
                form_data[form_info['csrf_name']] = form_info['csrf_token']
                self.session.csrf_token = form_info['csrf_token']
            
            # الخطوة 4: إرسال النموذج
            print(f"\n🚀 Step 4: Submitting login...")
            
            result = await self._submit_login(
                form_info['action'],
                form_info['method'],
                form_data,
                login_url
            )
            
            if result['success']:
                # حفظ الجلسة
                import uuid
                self.session.session_id = str(uuid.uuid4())[:8]
                self.session.cookies = result.get('cookies', {})
                self.session.headers = result.get('headers', {})
                self.session.tokens = result.get('tokens', {})
                self.session.user_agent = self.USER_AGENTS[0]
                
                session_path = self.session.save()
                
                print(f"\n{'='*50}")
                print(f"✅ Login Successful!")
                print(f"   Session saved: {session_path}")
                print(f"   Cookies: {len(self.session.cookies)} items")
                print(f"   Tokens: {list(self.session.tokens.keys())}")
                
                return self.session
            
            else:
                # تحليل رسالة الخطأ
                error_msg = result.get('error', 'Unknown error')
                print(f"\n❌ Login Failed: {error_msg}")
                
                # فحص multi-step login
                if result.get('next_step'):
                    print(f"\n🔄 Multi-step login detected!")
                    return await self._handle_multi_step(result, form_data, login_url)
                
                return None
        
        finally:
            if self.client:
                await self.client.aclose()
    
    async def _fetch_page(self, url: str) -> Optional[str]:
        """جلب صفحة"""
        try:
            response = await self.client.get(url)
            
            if response.status_code == 200:
                return response.text
            
            logger.warning(f"Page returned {response.status_code}")
            return response.text if response.status_code < 500 else None
            
        except Exception as e:
            logger.error(f"Failed to fetch {url}: {e}")
            return None
    
    def _extract_login_form(self, html: str, base_url: str) -> Optional[Dict]:
        """استخراج نموذج تسجيل الدخول"""
        soup = BeautifulSoup(html, 'html.parser')
        
        # البحث عن نموذج login
        login_form = None
        
        for form in soup.find_all('form'):
            form_text = form.get_text().lower()
            if any(word in form_text for word in ['login', 'sign in', 'log in', 'email', 'password']):
                login_form = form
                break
        
        # لو ملناش form، ندور على input fields مباشرة
        if not login_form:
            # جمع كل input fields في الصفحة
            inputs = soup.find_all('input')
            if inputs:
                login_form = soup  # نستخدم الصفحة كلها
            else:
                return None
        
        # استخراج action و method
        action = login_form.get('action', '') if hasattr(login_form, 'get') else ''
        method = login_form.get('method', 'POST').upper() if hasattr(login_form, 'get') else 'POST'
        
        if action:
            action_url = urljoin(base_url, action)
        else:
            action_url = base_url
        
        # استخراج CSRF token
        csrf_token = None
        csrf_name = ""
        
        csrf_patterns = ['csrf', 'token', 'authenticity_token', '_token', 'xsrf']
        
        # استخراج الحقول
        fields = []
        
        all_inputs = login_form.find_all(['input', 'button']) if hasattr(login_form, 'find_all') else soup.find_all(['input', 'button'])
        
        for inp in all_inputs:
            name = inp.get('name', '')
            input_type = inp.get('type', 'text').lower()
            
            if not name and input_type != 'submit':
                continue
            
            # البحث عن label
            label = ""
            label_elem = inp.find_previous('label')
            if label_elem:
                label = label_elem.get_text().strip()
            
            placeholder = inp.get('placeholder', '')
            
            # تحديد نوع الحقل
            field_type = self._detect_field_type(name, input_type, placeholder, label)
            
            field = LoginField(
                name=name or input_type,
                type=field_type,
                label=label or placeholder or name,
                placeholder=placeholder,
                required=inp.get('required') is not None,
                value=inp.get('value', ''),
                autocomplete=inp.get('autocomplete', '')
            )
            
            fields.append(field)
            
            # كشف CSRF
            if not csrf_token:
                for pattern in csrf_patterns:
                    if pattern in name.lower():
                        csrf_token = inp.get('value', '')
                        csrf_name = name
                        break
        
        # لو مفيش password field، ممكن يكون multi-step
        has_password = any(f.type == 'password' for f in fields)
        
        return {
            'action': action_url,
            'method': method,
            'fields': fields,
            'csrf_token': csrf_token,
            'csrf_name': csrf_name,
            'has_password': has_password,
            'is_multi_step': not has_password and len(fields) > 0,
        }
    
    def _detect_field_type(self, name: str, input_type: str, placeholder: str, label: str) -> str:
        """تحديد نوع الحقل من اسمه ونوعه"""
        combined = f"{name} {placeholder} {label} {input_type}".lower()
        
        # CAPTCHA
        if any(w in combined for w in ['captcha', 'recaptcha', 'hcaptcha', 'g-recaptcha']):
            return "captcha"
        
        # 2FA
        if any(w in combined for w in ['2fa', 'otp', 'code', 'token', 'verification', 'authenticator']):
            return "2fa"
        
        # Email
        if input_type == 'email' or 'email' in combined:
            return "email"
        
        # Password
        if input_type == 'password' or 'password' in combined:
            return "password"
        
        # Hidden
        if input_type == 'hidden':
            return "hidden"
        
        # Submit
        if input_type == 'submit':
            return "submit"
        
        # Username
        if any(w in combined for w in ['username', 'user', 'login', 'account']):
            return "text"
        
        # Default
        return input_type if input_type in ['text', 'number', 'tel', 'url'] else "text"
    
    async def _submit_login(
        self, action_url: str, method: str, form_data: Dict, referer: str
    ) -> Dict:
        """إرسال نموذج تسجيل الدخول"""
        try:
            headers = {
                "Referer": referer,
                "Origin": f"{urlparse(referer).scheme}://{urlparse(referer).netloc}",
                "Content-Type": "application/x-www-form-urlencoded",
            }
            
            if method == "POST":
                response = await self.client.post(action_url, data=form_data, headers=headers)
            else:
                response = await self.client.get(action_url, params=form_data, headers=headers)
            
            # تحليل النتيجة
            result = {
                'success': False,
                'cookies': {},
                'headers': {},
                'tokens': {},
                'error': '',
                'next_step': False,
                'response_url': str(response.url),
                'status_code': response.status_code,
            }
            
            # جمع cookies
            for cookie in response.cookies:
                result['cookies'][cookie.name] = cookie.value
            
            # جمع tokens من response
            result['tokens'] = self._extract_tokens(response.text, dict(response.headers))
            result['headers'] = dict(response.headers)
            
            # تحديد النجاح
            if response.status_code in [200, 302, 303]:
                # فحص لو تم تحويلنا لصفحة تانية
                if str(response.url) != action_url:
                    # تم التحويل - غالباً نجاح
                    result['success'] = True
                
                # فحص لو فيه welcome/dashboard في الصفحة
                page_text = response.text.lower()
                success_indicators = ['welcome', 'dashboard', 'logout', 'sign out', 'account', 'profile']
                if any(w in page_text for w in success_indicators):
                    result['success'] = True
                
                # فحص رسائل الخطأ
                error_indicators = ['invalid', 'incorrect', 'wrong', 'error', 'failed', 'not found']
                for indicator in error_indicators:
                    if indicator in page_text:
                        # استخراج رسالة الخطأ
                        result['error'] = self._extract_error_message(response.text)
                        result['success'] = False
                        break
                
                # فحص multi-step (مثلاً: تم إرسال رمز تأكيد)
                multi_step_indicators = ['verify', 'confirm', 'code', 'check your email', '2fa', 'two-factor']
                if any(w in page_text for w in multi_step_indicators):
                    result['next_step'] = True
            
            return result
            
        except Exception as e:
            logger.error(f"Login submit failed: {e}")
            return {'success': False, 'error': str(e)}
    
    def _extract_tokens(self, html: str, headers: Dict) -> Dict[str, str]:
        """استخراج tokens من الاستجابة"""
        tokens = {}
        
        # Bearer token من headers
        auth = headers.get('authorization', '') or headers.get('www-authenticate', '')
        if 'bearer' in auth.lower():
            tokens['bearer'] = auth.replace('Bearer ', '').replace('bearer ', '')
        
        # JWT من html
        jwt_pattern = r'eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+'
        jwt_matches = re.findall(jwt_pattern, html)
        if jwt_matches:
            tokens['jwt'] = jwt_matches[0]
        
        # CSRF token من html
        csrf_patterns = [
            r'<meta[^>]+name=["\']csrf-token["\'][^>]+content=["\']([^"\']+)["\']',
            r'name=["\']csrf[^"\']*["\'][^>]+value=["\']([^"\']+)["\']',
        ]
        for pattern in csrf_patterns:
            match = re.search(pattern, html, re.I)
            if match:
                tokens['csrf'] = match.group(1)
                break
        
        # API key
        api_patterns = [r'api[_-]?key["\']?\s*[:=]\s*["\']([^"\']+)["\']']
        for pattern in api_patterns:
            match = re.search(pattern, html, re.I)
            if match:
                tokens['api_key'] = match.group(1)
                break
        
        return tokens
    
    def _extract_error_message(self, html: str) -> str:
        """استخراج رسالة الخطأ من الصفحة"""
        soup = BeautifulSoup(html, 'html.parser')
        
        # البحث عن عناصر الخطأ
        error_selectors = [
            '.error', '.alert', '.alert-danger', '.alert-error',
            '[role="alert"]', '.message-error', '.form-error',
            '.invalid-feedback', '.text-danger', '.text-error'
        ]
        
        for selector in error_selectors:
            elem = soup.select_one(selector)
            if elem:
                return elem.get_text().strip()[:200]
        
        # البحث بالنص
        error_patterns = [
            r'(?:error|invalid|incorrect|wrong)[:\s]+([^<\n]{10,200})',
            r'<[^>]+class="[^"]*error[^"]*"[^>]*>([^<]{10,200})<',
        ]
        
        for pattern in error_patterns:
            match = re.search(pattern, html, re.I)
            if match:
                return match.group(1).strip()
        
        return "Login failed - check credentials"
    
    async def _handle_multi_step(self, result: Dict, form_data: Dict, login_url: str) -> Optional[LoginSession]:
        """التعامل مع multi-step login"""
        print(f"\n🔄 Multi-step login detected!")
        print(f"   Response URL: {result.get('response_url', 'unknown')}")
        
        # هنا ممكن نضيف منطق للتعامل مع:
        # - Email verification (check your email)
        # - 2FA code
        # - Security questions
        # - CAPTCHA
        
        print(f"\n⚠️  Multi-step login needs manual intervention")
        print(f"   Please complete the login in your browser,")
        print(f"   then provide the session cookie:")
        
        session_cookie = input(f"\n   📋 Paste session cookie (name=value): ")
        
        if session_cookie:
            name, value = session_cookie.split('=', 1) if '=' in session_cookie else ('session', session_cookie)
            self.session.cookies[name] = value
            self.session.session_id = f"manual_{datetime.now().strftime('%Y%m%d%H%M%S')}"
            
            path = self.session.save()
            print(f"✅ Session saved manually: {path}")
            return self.session
        
        return None
    
    def load_session(self, session_id: str) -> Optional[LoginSession]:
        """تحميل جلسة محفوظة"""
        filepath = f"sessions/session_{session_id}.json"
        return LoginSession.load(filepath)
    
    def list_sessions(self) -> List[str]:
        """قائمة الجلسات المحفوظة"""
        if not os.path.exists("sessions"):
            return []
        
        sessions = []
        for f in os.listdir("sessions"):
            if f.endswith('.json'):
                sessions.append(f.replace('session_', '').replace('.json', ''))
        
        return sessions


# نسخة عالمية
_interactive_login = None

def get_interactive_login() -> InteractiveLogin:
    global _interactive_login
    if _interactive_login is None:
        _interactive_login = InteractiveLogin()
    return _interactive_login
