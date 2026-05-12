import asyncio
import random
import string
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from datetime import datetime

from ..base.base_agent import BaseAgent, AgentPriority, AgentMessage
from ..base.agent_state import AgentStateEnum

from infrastructure.browser.playwright_driver import create_driver, PlaywrightDriver

import logging

logger = logging.getLogger(__name__)


@dataclass
class RegistrationResult:
    success: bool
    username: str
    password: str
    email: str
    register_url: str
    status_code: int
    message: str
    credentials_saved: bool = False
    timestamp: datetime = field(default_factory=datetime.now)


class RegistrationAgent(BaseAgent):
    """وكيل إنشاء الحسابات التلقائي مع دعم التدخل اليدوي"""
    
    def __init__(
        self,
        name: str = "RegistrationAgent",
        priority: AgentPriority = AgentPriority.HIGH,
        timeout: int = 120,
        headless: bool = True
    ):
        super().__init__(name, priority)
        
        self._timeout = timeout
        self._headless = headless
        self._registered_accounts: List[Dict] = []
        self._driver: Optional[PlaywrightDriver] = None
        
        logger.info(f"RegistrationAgent initialized")
    
    async def _on_initialize(self):
        self._driver = await create_driver(
            session_id=self.id,
            headless=self._headless,
            enable_stealth=True,
            pool_size=1
        )
        logger.info("RegistrationAgent initialized with PlaywrightDriver")
    
    async def _on_start(self):
        logger.info("RegistrationAgent started")
    
    async def _on_stop(self):
        if self._driver:
            await self._driver.close()
        logger.info("RegistrationAgent stopped")
    
    async def _handle_message(self, message: AgentMessage) -> Optional[AgentMessage]:
        if message.type == "register":
            result = await self.register(message.content)
            return AgentMessage(
                id="",
                sender=self.name,
                receiver=message.sender,
                type="registration_result",
                content=result.__dict__
            )
        elif message.type == "register_manual":
            result = await self.register_manual(message.content)
            return AgentMessage(
                id="",
                sender=self.name,
                receiver=message.sender,
                type="registration_result",
                content=result.__dict__
            )
        elif message.type == "register_manual_terminal":
            result = await self.register_manual_terminal(message.content)
            return AgentMessage(
                id="",
                sender=self.name,
                receiver=message.sender,
                type="registration_result",
                content=result.__dict__
            )
        return await super()._handle_message(message)
    
    async def generate_random_credentials(self) -> Tuple[str, str, str]:
        prefixes = ["user", "test", "hunter", "sec", "learner"]
        username = f"{random.choice(prefixes)}_{''.join(random.choices(string.digits, k=8))}"
        password = ''.join(random.choices(string.ascii_letters + string.digits + "!@#$%", k=12))
        email = f"{username}@temp-mail.org"
        return username, password, email
    
    async def register_manual(self, data: Dict[str, Any]) -> RegistrationResult:
        """
        وضع التسجيل اليدوي - يفتح المتصفح وينتظر المستخدم
        """
        url = data.get("url") if isinstance(data, dict) else data
        
        if not url:
            return RegistrationResult(
                success=False, username="", password="", email="",
                register_url="", status_code=0,
                message="URL is required for manual registration"
            )
        
        print(f"\n{'='*60}")
        print(f"🖐️  MANUAL REGISTRATION MODE (Browser)")
        print(f"{'='*60}")
        print(f"📍 URL: {url}")
        print(f"\n💡 Instructions:")
        print(f"   1. Browser will open automatically")
        print(f"   2. Fill in the registration form with your details")
        print(f"   3. Complete any CAPTCHA or email verification if needed")
        print(f"   4. After successful registration, come back here and press Enter")
        print(f"{'='*60}\n")
        
        try:
            await self._driver.navigate(url, timeout=self._timeout * 1000)
            
            input("Press Enter after you have completed registration...")
            
            # محاولة استخراج بيانات الدخول من الصفحة
            username = await self._extract_field_value(['input[name="username"]', 'input[name="user"]', 'input[type="email"]'])
            password = await self._extract_field_value(['input[type="password"]'])
            email = await self._extract_field_value(['input[type="email"]', 'input[name="email"]'])
            
            if not username:
                username = input("Enter username (or leave empty): ").strip()
            if not password:
                password = input("Enter password (or leave empty): ").strip()
            
            result = RegistrationResult(
                success=True,
                username=username or "unknown",
                password=password or "unknown",
                email=email or "",
                register_url=url,
                status_code=200,
                message="Manual registration completed",
                credentials_saved=False
            )
            
            self._registered_accounts.append({
                "username": result.username,
                "password": result.password,
                "email": result.email,
                "url": url,
                "created_at": datetime.now().isoformat(),
                "method": "manual"
            })
            result.credentials_saved = True
            
            print(f"\n✅ Credentials saved: {result.username} / {result.password}")
            return result
            
        except Exception as e:
            logger.error(f"Manual registration failed: {e}")
            return RegistrationResult(
                success=False, username="", password="", email="",
                register_url=url, status_code=0,
                message=f"Manual registration error: {str(e)[:100]}"
            )
        finally:
            if self._driver:
                await self._driver.reset()
    
    async def register_manual_terminal(self, data: Dict[str, Any]) -> RegistrationResult:
        """
        وضع التسجيل اليدوي عبر التيرمينال - يعرض حقول النموذج ويطلب الإدخال
        """
        url = data.get("url") if isinstance(data, dict) else data
        
        if not url:
            return RegistrationResult(
                success=False, username="", password="", email="",
                register_url="", status_code=0,
                message="URL is required for manual registration"
            )
        
        print(f"\n{'='*60}")
        print(f"🖐️  MANUAL REGISTRATION MODE (Terminal)")
        print(f"{'='*60}")
        print(f"📍 URL: {url}")
        print(f"\n💡 Instructions:")
        print(f"   1. Analyzing the registration form...")
        print(f"   2. You will be prompted to enter your details")
        print(f"   3. The system will submit the form automatically")
        print(f"{'='*60}\n")
        
        try:
            await self._driver.navigate(url, timeout=self._timeout * 1000)
            
            form_fields = await self._extract_form_fields()
            
            if not form_fields:
                print(f"❌ No form fields detected on the page.")
                return RegistrationResult(
                    success=False, username="", password="", email="",
                    register_url=url, status_code=0,
                    message="No form fields detected"
                )
            
            print(f"📋 Detected form fields:")
            for i, field in enumerate(form_fields, 1):
                print(f"   {i}. {field['name']} (type: {field['type']})")
            
            print(f"\n✏️  Please enter your registration details:\n")
            
            field_values = {}
            for field in form_fields:
                if field['type'] in ['submit', 'button', 'hidden']:
                    continue
                
                prompt = f"   Enter {field['name']}: "
                value = input(prompt)
                if value.strip():
                    field_values[field['name']] = value
            
            print(f"\n📝 Filling the form...")
            for field_name, value in field_values.items():
                await self._driver.fill(f'[name="{field_name}"]', value)
            
            print(f"🚀 Submitting the form...")
            await self._click_submit_button()
            await self._driver.wait_for_timeout(3000)
            
            username = field_values.get('username', field_values.get('email', 'unknown'))
            password = field_values.get('password', 'unknown')
            email = field_values.get('email', '')
            
            result = RegistrationResult(
                success=True,
                username=username,
                password=password,
                email=email,
                register_url=url,
                status_code=200,
                message="Manual registration completed",
                credentials_saved=False
            )
            
            self._registered_accounts.append({
                "username": result.username,
                "password": result.password,
                "email": result.email,
                "url": url,
                "created_at": datetime.now().isoformat(),
                "method": "manual_terminal"
            })
            result.credentials_saved = True
            
            print(f"\n✅ Registration submitted successfully!")
            print(f"   Username: {result.username}")
            print(f"   Password: {result.password}")
            
            return result
            
        except Exception as e:
            logger.error(f"Manual terminal registration failed: {e}")
            return RegistrationResult(
                success=False, username="", password="", email="",
                register_url=url, status_code=0,
                message=f"Manual terminal registration error: {str(e)[:100]}"
            )
        finally:
            if self._driver:
                await self._driver.reset()
    
    async def _extract_form_fields(self) -> List[Dict]:
        """استخراج حقول النموذج من الصفحة"""
        script = """
            () => {
                const forms = document.querySelectorAll('form');
                const fields = [];
                for (const form of forms) {
                    const inputs = form.querySelectorAll('input, select, textarea');
                    for (const input of inputs) {
                        const field = {
                            name: input.name || input.id || 'unknown',
                            type: input.type || input.tagName,
                            placeholder: input.placeholder || '',
                            required: input.required || false
                        };
                        if (field.name !== 'unknown') {
                            fields.push(field);
                        }
                    }
                }
                return fields;
            }
        """
        return await self._driver.execute_script(script)
    
    async def _extract_field_value(self, selectors: List[str]) -> str:
        """استخراج قيمة حقل من الصفحة"""
        for selector in selectors:
            try:
                value = await self._driver.execute_script(f"""
                    const el = document.querySelector('{selector}');
                    return el ? el.value : '';
                """)
                if value:
                    return value
            except:
                continue
        return ""
    
    async def _click_submit_button(self):
        """النقر على زر الإرسال"""
        submit_selectors = [
            'button[type="submit"]',
            'input[type="submit"]',
            'button:has-text("Register")',
            'button:has-text("Sign up")',
            'button:has-text("Create account")',
            'button:has-text("Join")',
            'form button'
        ]
        
        for selector in submit_selectors:
            try:
                await self._driver.click(selector, timeout=2000)
                return
            except:
                continue
    
    async def register(
        self,
        data: Dict[str, Any],
        save_credentials: bool = True
    ) -> RegistrationResult:
        """التسجيل التلقائي (بدون تدخل بشري)"""
        url = data.get("url") if isinstance(data, dict) else data
        username = data.get("username") if isinstance(data, dict) else None
        password = data.get("password") if isinstance(data, dict) else None
        email = data.get("email") if isinstance(data, dict) else None
        
        if not url:
            return RegistrationResult(
                success=False, username="", password="", email="",
                register_url="", status_code=0,
                message="URL is required"
            )
        
        try:
            await self._driver.navigate(url, timeout=self._timeout * 1000)
            
            if not username or not password:
                gen_username, gen_password, gen_email = await self.generate_random_credentials()
                username = username or gen_username
                password = password or gen_password
                email = email or gen_email
            
            await self._auto_fill_form(username, password, email)
            await self._click_submit_button()
            await self._driver.wait_for_timeout(3000)
            
            result = RegistrationResult(
                success=True,
                username=username,
                password=password,
                email=email,
                register_url=url,
                status_code=200,
                message="Auto registration completed"
            )
            
            if save_credentials:
                self._registered_accounts.append({
                    "username": username,
                    "password": password,
                    "email": email,
                    "url": url,
                    "created_at": datetime.now().isoformat(),
                    "method": "auto"
                })
                result.credentials_saved = True
            
            return result
            
        except Exception as e:
            logger.error(f"Auto registration failed: {e}")
            return RegistrationResult(
                success=False, username=username or "", password=password or "",
                email=email or "", register_url=url, status_code=0,
                message=f"Auto registration error: {str(e)[:100]}"
            )
    
    async def _auto_fill_form(self, username: str, password: str, email: str):
        """ملء النموذج تلقائياً"""
        email_selectors = ['input[type="email"]', 'input[name="email"]']
        username_selectors = ['input[name="username"]', 'input[name="user"]']
        password_selectors = ['input[type="password"]']
        
        for selector in email_selectors:
            try:
                await self._driver.fill(selector, email, timeout=2000)
                break
            except:
                continue
        
        for selector in username_selectors:
            try:
                await self._driver.fill(selector, username, timeout=2000)
                break
            except:
                continue
        
        for selector in password_selectors:
            try:
                await self._driver.fill(selector, password, timeout=2000)
                confirm = self._driver._current_page.locator('input[name="confirm_password"], input[name="password2"]')
                if await confirm.count() > 0:
                    await confirm.fill(password)
                break
            except:
                continue
    
    async def get_registered_accounts(self) -> List[Dict]:
        return self._registered_accounts
    
    async def get_statistics(self) -> Dict:
        base_stats = await super().get_statistics()
        return {
            **base_stats,
            "registration_specific": {
                "total_registered_accounts": len(self._registered_accounts)
            }
        }


_default_registration_agent = None

async def get_registration_agent() -> RegistrationAgent:
    global _default_registration_agent
    if _default_registration_agent is None:
        _default_registration_agent = RegistrationAgent()
        await _default_registration_agent.initialize()
        await _default_registration_agent.start()
    return _default_registration_agent
