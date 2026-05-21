"""
Interactive Login - نظام تسجيل دخول تفاعلي ذكي

يدعم:
- استخراج تلقائي لحقول النموذج (BeautifulSoup + Playwright fallback)
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

import httpx
import logging

logger = logging.getLogger(__name__)


@dataclass
class LoginField:
    """حقل في نموذج تسجيل الدخول"""
    name: str
    type: str
    label: str
    placeholder: str = ""
    required: bool = False
    value: str = ""
    autocomplete: str = ""
    
    def ask_user(self) -> str:
        if self.type == "password":
            import getpass
            return getpass.getpass(f"  🔒 {self.label or self.name}: ")
        elif self.type == "captcha":
            print(f"  🛡️  CAPTCHA detected! Open the page in browser and paste token:")
            return input(f"  CAPTCHA token: ")
        elif self.type == "2fa":
            return input(f"  📱 {self.label or 'Verification code'}: ")
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
        os.makedirs(path, exist_ok=True)
        filepath = f"{path}/session_{self.session_id}.json"
        with open(filepath, 'w') as f:
            json.dump({
                "url": self.url, "cookies": self.cookies,
                "headers": self.headers, "tokens": self.tokens,
                "csrf_token": self.csrf_token, "session_id": self.session_id,
                "created_at": self.created_at, "user_agent": self.user_agent,
            }, f, indent=2)
        return filepath
    
    @classmethod
    def load(cls, filepath: str) -> Optional['LoginSession']:
        if not os.path.exists(filepath):
            return None
        with open(filepath, 'r') as f:
            data = json.load(f)
        return cls(**{k: data.get(k, "") for k in ['url', 'cookies', 'headers', 'tokens', 'csrf_token', 'session_id', 'created_at', 'user_agent']})


class InteractiveLogin:
    """نظام تسجيل دخول تفاعلي ذكي"""
    
    USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36",
    ]
    
    def __init__(self):
        self.client = None
        self.session = LoginSession(url="")
    
    async def login(self, login_url: str, username: str = None, password: str = None) -> Optional[LoginSession]:
        print(f"\n🔐 Interactive Login Wizard")
        print(f"{'='*50}")
        print(f"   Target: {login_url}")
        
        self.session = LoginSession(url=login_url)
        self.session.created_at = datetime.now().isoformat()
        
        import random
        self.client = httpx.AsyncClient(
            timeout=30, follow_redirects=True, verify=False,
            headers={"User-Agent": random.choice(self.USER_AGENTS),
                     "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
                     "Accept-Language": "en-US,en;q=0.9"}
        )
        
        try:
            # الخطوة 1: تحميل الصفحة
            print(f"\n📄 Step 1: Loading page...")
            html = await self._fetch(login_url)
            if not html:
                return None
            
            # الخطوة 2: استخراج النموذج - نجرب BeautifulSoup أولاً، ثم Playwright
            print(f"🔍 Step 2: Detecting login form...")
            form_info = self._extract_form_bs4(html, login_url)
            
            if not form_info:
                print(f"   ⚠️  Static detection failed, trying browser...")
                form_info = await self._extract_form_playwright(login_url)
            
            if not form_info:
                print(f"   ℹ️  Trying generic detection...")
                form_info = self._extract_form_generic(html, login_url)
            
            if not form_info:
                print(f"❌ No login form found. Try manual login:")
                print(f"   Open the page in browser, login, then paste any cookie:")
                cookie = input(f"   📋 Cookie (name=value): ").strip()
                if cookie and '=' in cookie:
                    name, value = cookie.split('=', 1)
                    self.session.cookies[name] = value
                    self.session.session_id = f"manual_{datetime.now().strftime('%Y%m%d%H%M%S')}"
                    self.session.save()
                    print(f"✅ Session saved manually!")
                    return self.session
                return None
            
            # عرض الحقول
            print(f"\n   📋 Fields found:")
            for f in form_info['fields']:
                print(f"      - {f.type}: {f.name} ({f.label})")
            
            # الخطوة 3: جمع البيانات
            print(f"\n📝 Step 3: Enter credentials...")
            form_data = {}
            for field in form_info['fields']:
                if field.type == "hidden":
                    form_data[field.name] = field.value
                elif field.type == "email":
                    form_data[field.name] = username or field.ask_user()
                elif field.type == "password":
                    form_data[field.name] = password or field.ask_user()
                elif field.type == "submit":
                    form_data[field.name] = field.value or "Login"
                elif field.type in ["captcha", "2fa"]:
                    form_data[field.name] = field.ask_user()
                else:
                    if username and ("user" in field.name.lower() or "login" in field.name.lower()):
                        form_data[field.name] = username
                    else:
                        form_data[field.name] = field.ask_user()
            
            if form_info.get('csrf_token'):
                form_data[form_info['csrf_name']] = form_info['csrf_token']
                self.session.csrf_token = form_info['csrf_token']
            
            # الخطوة 4: إرسال
            print(f"\n🚀 Step 4: Submitting...")
            result = await self._submit(form_info['action'], form_info['method'], form_data, login_url)
            
            if result['success']:
                import uuid
                self.session.session_id = str(uuid.uuid4())[:8]
                self.session.cookies.update(result.get('cookies', {}))
                self.session.headers.update(result.get('headers', {}))
                self.session.tokens.update(result.get('tokens', {}))
                self.session.save()
                print(f"\n✅ Login Successful! Session: {self.session.session_id}")
                return self.session
            else:
                print(f"\n❌ Failed: {result.get('error', 'Unknown')}")
                if result.get('next_step'):
                    print(f"🔄 Multi-step detected! Complete in browser and paste cookie:")
                    cookie = input(f"   📋 Cookie: ").strip()
                    if cookie and '=' in cookie:
                        name, value = cookie.split('=', 1)
                        self.session.cookies[name] = value
                        self.session.session_id = f"multi_{datetime.now().strftime('%Y%m%d%H%M%S')}"
                        self.session.save()
                        return self.session
                return None
        
        finally:
            if self.client:
                await self.client.aclose()
    
    async def _fetch(self, url: str) -> Optional[str]:
        try:
            r = await self.client.get(url)
            return r.text if r.status_code < 500 else None
        except:
            return None
    
    def _extract_form_bs4(self, html: str, base_url: str) -> Optional[Dict]:
        """BeautifulSoup extraction"""
        try:
            from bs4 import BeautifulSoup
        except ImportError:
            return None
        
        soup = BeautifulSoup(html, 'html.parser')
        
        # البحث عن form فيه password
        for form in soup.find_all('form'):
            has_password = form.find('input', {'type': 'password'})
            has_email = form.find('input', {'type': 'email'})
            has_text = form.find('input', {'type': 'text'})
            
            if has_password and (has_email or has_text):
                return self._parse_form(form, base_url)
        
        # لو مفيش form كامل، ندور على أي input password
        pw_input = soup.find('input', {'type': 'password'})
        if pw_input:
            parent_form = pw_input.find_parent('form')
            if parent_form:
                return self._parse_form(parent_form, base_url)
            
            # نبني form افتراضي
            fields = []
            all_inputs = soup.find_all('input')
            for inp in all_inputs:
                name = inp.get('name', '') or inp.get('id', '')
                itype = inp.get('type', 'text').lower()
                if not name:
                    continue
                label = ""
                lbl = inp.find_previous('label')
                if lbl:
                    label = lbl.get_text().strip()
                fields.append(LoginField(
                    name=name, type=self._detect_type(name, itype),
                    label=label or inp.get('placeholder', name),
                    placeholder=inp.get('placeholder', ''),
                    value=inp.get('value', '')
                ))
            
            if fields:
                return {'action': base_url, 'method': 'POST', 'fields': fields,
                        'csrf_token': None, 'csrf_name': ''}
        
        return None
    
    async def _extract_form_playwright(self, login_url: str) -> Optional[Dict]:
        """Playwright browser extraction"""
        try:
            from playwright.async_api import async_playwright
        except ImportError:
            return None
        
        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                page = await browser.new_page()
                await page.goto(login_url, wait_until="networkidle", timeout=20000)
                await page.wait_for_timeout(2000)
                
                fields = []
                
                # البحث عن inputs
                inputs = await page.query_selector_all('input')
                for inp in inputs:
                    name = await inp.get_attribute('name') or await inp.get_attribute('id') or ''
                    itype = await inp.get_attribute('type') or 'text'
                    placeholder = await inp.get_attribute('placeholder') or ''
                    value = await inp.get_attribute('value') or ''
                    
                    if not name:
                        continue
                    
                    fields.append(LoginField(
                        name=name, type=self._detect_type(name, itype.lower()),
                        label=placeholder or name, placeholder=placeholder,
                        value=value
                    ))
                
                # البحث عن CSRF
                csrf = await page.evaluate("""
                    () => {
                        const meta = document.querySelector('meta[name="csrf-token"]');
                        if (meta) return meta.getAttribute('content');
                        const input = document.querySelector('input[name*="csrf" i], input[name="_token"]');
                        return input ? input.value : null;
                    }
                """)
                
                await browser.close()
                
                if fields:
                    return {'action': login_url, 'method': 'POST', 'fields': fields,
                            'csrf_token': csrf, 'csrf_name': 'csrf_token' if csrf else ''}
        except:
            pass
        
        return None
    
    def _extract_form_generic(self, html: str, base_url: str) -> Optional[Dict]:
        """Generic regex-based extraction - last resort"""
        # البحث عن input fields باستخدام regex
        input_pattern = re.compile(r'<input[^>]+(?:name|id)=["\']([^"\']+)["\'][^>]*>', re.I)
        type_pattern = re.compile(r'type=["\']([^"\']+)["\']', re.I)
        placeholder_pattern = re.compile(r'placeholder=["\']([^"\']*)["\']', re.I)
        
        fields = []
        for match in input_pattern.finditer(html):
            name = match.group(1)
            input_html = match.group(0)
            itype_match = type_pattern.search(input_html)
            itype = itype_match.group(1).lower() if itype_match else 'text'
            placeholder_match = placeholder_pattern.search(input_html)
            placeholder = placeholder_match.group(1) if placeholder_match else ''
            
            if name and itype in ['email', 'password', 'text']:
                fields.append(LoginField(
                    name=name, type=self._detect_type(name, itype),
                    label=placeholder or name, placeholder=placeholder
                ))
        
        if fields:
            return {'action': base_url, 'method': 'POST', 'fields': fields,
                    'csrf_token': None, 'csrf_name': ''}
        return None
    
    def _parse_form(self, form, base_url: str) -> Dict:
        """Parse BeautifulSoup form"""
        action = urljoin(base_url, form.get('action', '')) or base_url
        method = form.get('method', 'POST').upper()
        
        csrf_token = None
        csrf_name = ""
        fields = []
        
        for inp in form.find_all(['input', 'button']):
            name = inp.get('name', '') or inp.get('id', '')
            itype = inp.get('type', 'text').lower()
            
            if not name and itype != 'submit':
                continue
            
            label = ""
            lbl = inp.find_previous('label')
            if lbl:
                label = lbl.get_text().strip()
            
            fields.append(LoginField(
                name=name or itype, type=self._detect_type(name, itype),
                label=label or inp.get('placeholder', name),
                placeholder=inp.get('placeholder', ''),
                value=inp.get('value', '')
            ))
            
            if not csrf_token:
                for p in ['csrf', 'token', '_token', 'xsrf']:
                    if p in name.lower():
                        csrf_token = inp.get('value', '')
                        csrf_name = name
                        break
        
        return {'action': action, 'method': method, 'fields': fields,
                'csrf_token': csrf_token, 'csrf_name': csrf_name}
    
    def _detect_type(self, name: str, itype: str) -> str:
        combined = f"{name} {itype}".lower()
        if 'captcha' in combined: return "captcha"
        if any(w in combined for w in ['2fa', 'otp', 'code', 'token']): return "2fa"
        if itype == 'email': return "email"
        if itype == 'password': return "password"
        if itype == 'hidden': return "hidden"
        if itype == 'submit': return "submit"
        return "text"
    
    async def _submit(self, action: str, method: str, data: Dict, referer: str) -> Dict:
        try:
            headers = {"Referer": referer, "Content-Type": "application/x-www-form-urlencoded"}
            
            if method == "POST":
                r = await self.client.post(action, data=data, headers=headers)
            else:
                r = await self.client.get(action, params=data, headers=headers)
            
            result = {'success': False, 'cookies': {}, 'headers': dict(r.headers), 'tokens': {},
                      'error': '', 'next_step': False}
            
            for c in r.cookies:
                result['cookies'][c.name] = c.value
            
            result['tokens'] = self._extract_tokens(r.text, dict(r.headers))
            
            text = r.text.lower()
            if any(w in text for w in ['welcome', 'dashboard', 'logout', 'sign out', 'account']):
                result['success'] = True
            elif str(r.url) != action:
                result['success'] = True
            
            if any(w in text for w in ['verify', 'confirm', 'code', '2fa', 'two-factor']):
                result['next_step'] = True
            
            for w in ['invalid', 'incorrect', 'wrong', 'error']:
                if w in text:
                    result['success'] = False
                    result['error'] = f"Server returned '{w}'"
                    break
            
            return result
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def _extract_tokens(self, html: str, headers: Dict) -> Dict:
        tokens = {}
        jwt_match = re.search(r'eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+', html)
        if jwt_match:
            tokens['jwt'] = jwt_match.group(0)
        csrf_match = re.search(r'<meta[^>]+name=["\']csrf[^"\']*["\'][^>]+content=["\']([^"\']+)', html, re.I)
        if csrf_match:
            tokens['csrf'] = csrf_match.group(1)
        return tokens
    
    def load_session(self, session_id: str) -> Optional[LoginSession]:
        return LoginSession.load(f"sessions/session_{session_id}.json")
    
    def list_sessions(self) -> List[str]:
        if not os.path.exists("sessions"):
            return []
        return [f.replace('session_', '').replace('.json', '') for f in os.listdir("sessions") if f.endswith('.json')]


_interactive_login = None

def get_interactive_login() -> InteractiveLogin:
    global _interactive_login
    if _interactive_login is None:
        _interactive_login = InteractiveLogin()
    return _interactive_login
