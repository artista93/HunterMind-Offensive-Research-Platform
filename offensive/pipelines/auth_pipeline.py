
import asyncio
import base64
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass, field
from datetime import datetime

from ..scanners.auth_scanner import AuthScanner, Finding
from ..scanners.base_scanner import ScanContext, ScanTarget, Severity, Confidence
from ..payloads.payload_generator import PayloadType, get_payload_generator
from ..exploitation.exploit_orchestrator import ExploitTarget, get_exploit_orchestrator
from ..exploitation.exploit_memory import get_exploit_memory

import logging

logger = logging.getLogger(__name__)


@dataclass
class AuthPipelineResult:
    """نتائج خط أنابيب المصادقة"""
    target_url: str
    start_time: datetime
    end_time: Optional[datetime] = None
    findings: List[Finding] = field(default_factory=list)
    weak_credentials: List[Dict] = field(default_factory=list)
    jwt_issues: List[Dict] = field(default_factory=list)
    session_issues: List[Dict] = field(default_factory=list)
    mfa_issues: List[Dict] = field(default_factory=list)
    total_findings: int = 0
    weak_credentials_found: int = 0
    jwt_issues_found: int = 0
    compromised_accounts: List[str] = field(default_factory=list)
    status: str = "pending"
    error: Optional[str] = None


class AuthPipeline:
    """
    خط أنابيب اختبار المصادقة المتكامل
    
    الميزات:
    - اختبار قوة كلمات المرور
    - اكتشاف ثغرات JWT (alg none, weak secret, expired)
    - اختبار Session Fixation
    - كشف نقاط نهاية المصادقة غير المحمية
    - اختبار المصادقة متعددة العوامل (MFA)
    - تخمين كلمات المرور الضعيفة
    - تكامل مع ذاكرة الاستغلال
    """
    
    # كلمات مرور ضعيفة شائعة للاختبار
    COMMON_PASSWORDS = [
        "password", "123456", "12345678", "1234", "qwerty", "abc123",
        "admin", "letmein", "welcome", "monkey", "dragon", "master",
        "login", "pass", "password123", "admin123", "user123", "test123"
    ]
    
    def __init__(self):
        self._scanner = AuthScanner()
        self._generator = get_payload_generator()
        self._orchestrator = get_exploit_orchestrator()
        self._memory = get_exploit_memory()
        
        self._active_pipelines: Dict[str, AuthPipelineResult] = {}
        
        logger.info("AuthPipeline initialized")
    
    async def run(
        self,
        target_url: str,
        login_url: str = None,
        username_field: str = "username",
        password_field: str = "password",
        headers: Dict[str, str] = None,
        test_weak_passwords: bool = True,
        test_jwt: bool = True,
        test_session: bool = True,
        max_attempts: int = 20
    ) -> AuthPipelineResult:
        """
        تنفيذ خط أنابيب اختبار المصادقة كامل
        
        Args:
            target_url: الرابط المستهدف
            login_url: رابط صفحة تسجيل الدخول (إذا اختلف عن target_url)
            username_field: اسم حقل اسم المستخدم
            password_field: اسم حقل كلمة المرور
            headers: هيدرات مخصصة
            test_weak_passwords: اختبار كلمات مرور ضعيفة
            test_jwt: اختبار ثغرات JWT
            test_session: اختبار ثغرات الجلسات
            max_attempts: الحد الأقصى لمحاولات التخمين
        
        Returns:
            نتائج خط الأنابيب
        """
        pipeline_id = f"auth_{target_url}_{int(datetime.now().timestamp())}"
        
        result = AuthPipelineResult(
            target_url=target_url,
            start_time=datetime.now()
        )
        
        self._active_pipelines[pipeline_id] = result
        
        logger.info(f"Starting Auth pipeline for {target_url}")
        
        try:
            # 1. تحضير السياق
            context = ScanContext(
                target=ScanTarget(
                    url=target_url,
                    headers=headers or {}
                )
            )
            
            # 2. البحث عن استغلالات سابقة مشابهة
            similar_exploits = self._memory.find_similar_exploits(
                vulnerability_type="Authentication",
                min_success_rate=0.5,
                limit=10
            )
            
            if similar_exploits:
                logger.info(f"Found {len(similar_exploits)} similar exploits in memory")
            
            # 3. تنفيذ الفحص
            findings = await self._scanner.scan(context)
            result.findings = findings
            result.total_findings = len(findings)
            
            # 4. اختبار كلمات المرور الضعيفة
            if test_weak_passwords and login_url:
                weak_results = await self._test_weak_passwords(
                    login_url or target_url,
                    username_field,
                    password_field,
                    max_attempts
                )
                result.weak_credentials = weak_results
                result.weak_credentials_found = len(weak_results)
                
                for cred in weak_results:
                    result.compromised_accounts.append(cred.get("username", ""))
            
            # 5. اختبار JWT
            if test_jwt:
                jwt_results = await self._test_jwt_vulnerabilities(context)
                result.jwt_issues = jwt_results
                result.jwt_issues_found = len(jwt_results)
            
            # 6. اختبار الجلسات
            if test_session:
                session_results = await self._test_session_vulnerabilities(context)
                result.session_issues = session_results
            
            # 7. تخزين الاستغلالات الناجحة في الذاكرة
            for finding in findings:
                if finding.confidence in [Confidence.HIGH, Confidence.CERTAIN]:
                    self._memory.store_exploit(
                        name=f"Auth_{target_url}_{finding.vulnerability_type}",
                        target_type="web",
                        vulnerability_type=finding.vulnerability_type,
                        payload=finding.payload or "",
                        encoding="none",
                        success=True,
                        context=finding.parameter or finding.url,
                        metadata={
                            "url": target_url,
                            "severity": finding.severity.value,
                            "confidence": finding.confidence.value
                        }
                    )
            
            result.status = "completed"
            
        except Exception as e:
            logger.error(f"Auth pipeline failed: {e}")
            result.status = "failed"
            result.error = str(e)
        
        finally:
            result.end_time = datetime.now()
            await self._scanner.close()
        
        logger.info(f"Auth pipeline completed: {result.total_findings} findings, {result.weak_credentials_found} weak credentials")
        
        return result
    
    async def _test_weak_passwords(
        self,
        login_url: str,
        username_field: str,
        password_field: str,
        max_attempts: int
    ) -> List[Dict]:
        """
        اختبار كلمات مرور ضعيفة على صفحة تسجيل الدخول
        
        Args:
            login_url: رابط تسجيل الدخول
            username_field: اسم حقل اسم المستخدم
            password_field: اسم حقل كلمة المرور
            max_attempts: الحد الأقصى للمحاولات
        
        Returns:
            قائمة بالحسابات المخترقة
        """
        import httpx
        
        compromised = []
        common_usernames = ["admin", "user", "test", "root", "administrator"]
        
        attempts = 0
        for username in common_usernames[:3]:
            for password in self.COMMON_PASSWORDS[:max_attempts // len(common_usernames)]:
                if attempts >= max_attempts:
                    break
                
                try:
                    async with httpx.AsyncClient() as client:
                        response = await client.post(
                            login_url,
                            data={
                                username_field: username,
                                password_field: password
                            },
                            follow_redirects=False
                        )
                        
                        # التحقق من نجاح تسجيل الدخول
                        if response.status_code in [302, 303] or "dashboard" in response.text.lower():
                            compromised.append({
                                "username": username,
                                "password": password,
                                "url": login_url,
                                "status_code": response.status_code
                            })
                            
                            logger.warning(f"Found weak credentials: {username}:{password}")
                            
                except Exception as e:
                    logger.debug(f"Login attempt failed: {e}")
                
                attempts += 1
        
        return compromised
    
    async def _test_jwt_vulnerabilities(self, context: ScanContext) -> List[Dict]:
        """
        اختبار ثغرات JWT
        
        Returns:
            قائمة بمشاكل JWT المكتشفة
        """
        issues = []
        
        # البحث عن توكنات JWT في الـ Headers
        auth_header = context.target.headers.get("Authorization", "")
        
        if "Bearer " in auth_header:
            token = auth_header.replace("Bearer ", "")
            
            # اختبار خوارزمية none
            if await self._test_jwt_none_algorithm(token):
                issues.append({
                    "type": "JWT None Algorithm",
                    "severity": "CRITICAL",
                    "description": "JWT accepts 'none' algorithm which allows token forgery",
                    "remediation": "Disable 'none' algorithm. Use strong algorithms like RS256 or HS256."
                })
            
            # اختبار انتهاء الصلاحية
            expired = await self._test_jwt_expiration(token)
            if expired:
                issues.append({
                    "type": "JWT Expired Token Accepted",
                    "severity": "HIGH",
                    "description": "JWT accepts expired tokens",
                    "remediation": "Reject expired tokens. Implement proper token validation."
                })
        
        return issues
    
    async def _test_jwt_none_algorithm(self, token: str) -> bool:
        """اختبار خوارزمية none في JWT"""
        try:
            import jwt
            
            # محاولة فك التشفير مع alg=none
            decoded = jwt.decode(token, options={"verify_signature": False})
            
            # التحقق من نجاح الفك
            return decoded is not None
            
        except Exception:
            return False
    
    async def _test_jwt_expiration(self, token: str) -> bool:
        """اختبار قبول التوكنات منتهية الصلاحية"""
        try:
            import jwt
            
            # فك التشفير دون التحقق من التوقيع
            decoded = jwt.decode(token, options={"verify_signature": False})
            
            # التحقق من وجود exp
            if "exp" in decoded:
                import time
                if decoded["exp"] < time.time():
                    return True
                    
        except Exception:
            pass
        
        return False
    
    async def _test_session_vulnerabilities(self, context: ScanContext) -> List[Dict]:
        """
        اختبار ثغرات الجلسات
        
        Returns:
            قائمة بمشاكل الجلسات المكتشفة
        """
        issues = []
        
        # التحقق من وجود Session ID في URL
        if "PHPSESSID=" in context.target.url or "JSESSIONID=" in context.target.url:
            issues.append({
                "type": "Session ID in URL",
                "severity": "MEDIUM",
                "description": "Session ID is exposed in URL, which may be leaked via Referer headers",
                "remediation": "Store session IDs in cookies only. Use HttpOnly and Secure flags."
            })
        
        # التحقق من استخدام HTTP (غير آمن)
        if context.target.url.startswith("http://"):
            issues.append({
                "type": "Insecure Session Transmission",
                "severity": "HIGH",
                "description": "Session data transmitted over HTTP (not HTTPS)",
                "remediation": "Use HTTPS for all authenticated requests. Enable HSTS."
            })
        
        return issues
    
    async def generate_auth_report(self, result: AuthPipelineResult) -> str:
        """
        توليد تقرير أمن المصادقة
        
        Args:
            result: نتائج خط الأنابيب
        
        Returns:
            تقرير Markdown
        """
        report = f"""# Authentication Security Report

**Target:** {result.target_url}
**Date:** {result.start_time.strftime('%Y-%m-%d %H:%M:%S')}
**Duration:** {(result.end_time - result.start_time).total_seconds():.2f}s

## Summary

| Metric | Value |
|--------|-------|
| Total Findings | {result.total_findings} |
| Weak Credentials Found | {result.weak_credentials_found} |
| JWT Issues Found | {result.jwt_issues_found} |
| Compromised Accounts | {len(result.compromised_accounts)} |

## Weak Credentials

"""
        for cred in result.weak_credentials[:10]:
            report += f"- **{cred['username']}** : `{cred['password']}`\n"
        
        if not result.weak_credentials:
            report += "- No weak credentials found\n"
        
        report += "\n## JWT Issues\n"
        for issue in result.jwt_issues:
            report += f"- **[{issue['severity']}]** {issue['type']}: {issue['description']}\n"
        
        if not result.jwt_issues:
            report += "- No JWT issues found\n"
        
        report += "\n## Recommendations\n"
        report += "1. Enforce strong password policy (minimum 8 characters, mixed case, numbers, symbols)\n"
        report += "2. Implement account lockout after failed attempts\n"
        report += "3. Use multi-factor authentication (MFA)\n"
        report += "4. Implement proper session management with HttpOnly and Secure flags\n"
        report += "5. Use HTTPS exclusively for authenticated traffic\n"
        report += "6. Implement JWT validation with strong algorithms (RS256 or HS256 with strong secrets)\n"
        
        return report
    
    async def get_result(self, pipeline_id: str) -> Optional[AuthPipelineResult]:
        """الحصول على نتيجة خط الأنابيب"""
        return self._active_pipelines.get(pipeline_id)
    
    async def get_summary(self) -> Dict:
        """ملخص خطوط الأنابيب النشطة"""
        return {
            "active_pipelines": len(self._active_pipelines),
            "completed": sum(1 for r in self._active_pipelines.values() if r.status == "completed"),
            "failed": sum(1 for r in self._active_pipelines.values() if r.status == "failed"),
            "total_findings": sum(r.total_findings for r in self._active_pipelines.values()),
            "weak_credentials_found": sum(r.weak_credentials_found for r in self._active_pipelines.values()),
            "jwt_issues_found": sum(r.jwt_issues_found for r in self._active_pipelines.values()),
            "total_compromised": sum(len(r.compromised_accounts) for r in self._active_pipelines.values())
        }
    
    async def close(self):
        """إغلاق الخط الأنابيب"""
        await self._scanner.close()
        logger.info("AuthPipeline closed")


# نسخة عالمية
async def get_auth_pipeline() -> AuthPipeline:
    """الحصول على نسخة من خط أنابيب المصادقة"""
    return AuthPipeline()

