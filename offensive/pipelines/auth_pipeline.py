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
    """
    
    COMMON_PASSWORDS = [
        "password", "123456", "12345678", "1234", "qwerty", "abc123",
        "admin", "letmein", "welcome", "monkey", "dragon", "master",
        "login", "pass", "password123", "admin123", "user123", "test123"
    ]
    
    def __init__(self, http_client=None):
        self._scanner = AuthScanner()
        self._generator = get_payload_generator()
        self._orchestrator = get_exploit_orchestrator()
        self._memory = get_exploit_memory()  # ✅ تمت الإعادة
        self._http_client = http_client
        
        self._active_pipelines: Dict[str, AuthPipelineResult] = {}
        
        logger.info("AuthPipeline initialized")
    
    def set_http_client(self, client):
        self._http_client = client
        if hasattr(self._scanner, 'set_http_client'):
            self._scanner.set_http_client(client)
    
    async def _send_request(
        self,
        url: str,
        method: str = "POST",
        data: Dict = None,
        headers: Dict = None
    ) -> tuple:
        if self._http_client and hasattr(self._http_client, 'send_request'):
            response = await self._http_client.send_request(
                url, method=method, data=data, headers=headers
            )
            return response, 200 if response else 404
        
        try:
            import httpx
            async with httpx.AsyncClient(timeout=30.0, follow_redirects=False) as client:
                if method.upper() == "POST":
                    response = await client.post(url, data=data, headers=headers)
                else:
                    response = await client.get(url, headers=headers)
                return response.text, response.status_code
        except Exception as e:
            logger.debug(f"Request error: {e}")
            return None, 0
    
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
        pipeline_id = f"auth_{target_url}_{int(datetime.now().timestamp())}"
        
        result = AuthPipelineResult(
            target_url=target_url,
            start_time=datetime.now()
        )
        
        self._active_pipelines[pipeline_id] = result
        
        logger.info(f"Starting Auth pipeline for {target_url}")
        
        try:
            context = ScanContext(
                target=ScanTarget(
                    url=target_url,
                    headers=headers or {}
                )
            )
            
            # ✅ استخدام ExploitMemory
            similar_exploits = self._memory.find_similar_exploits(
                vulnerability_type="Authentication",
                min_success_rate=0.5,
                limit=10
            )
            
            if similar_exploits:
                logger.info(f"Found {len(similar_exploits)} similar exploits in memory")
            
            findings = await self._scanner.scan(context)
            result.findings = findings
            result.total_findings = len(findings)
            
            if test_weak_passwords and login_url:
                weak_results = await self._test_weak_passwords(
                    login_url or target_url,
                    username_field,
                    password_field,
                    max_attempts,
                    headers
                )
                result.weak_credentials = weak_results
                result.weak_credentials_found = len(weak_results)
                
                for cred in weak_results:
                    result.compromised_accounts.append(cred.get("username", ""))
            
            if test_jwt:
                jwt_results = await self._test_jwt_vulnerabilities(context)
                result.jwt_issues = jwt_results
                result.jwt_issues_found = len(jwt_results)
            
            if test_session:
                session_results = await self._test_session_vulnerabilities(context)
                result.session_issues = session_results
            
            # ✅ تخزين الاستغلالات الناجحة في ExploitMemory
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
        
        logger.info(f"Auth pipeline completed: {result.total_findings} findings, {result.weak_credentials_found} weak credentials")
        
        return result
    
    async def _test_weak_passwords(
        self,
        login_url: str,
        username_field: str,
        password_field: str,
        max_attempts: int,
        headers: Dict = None
    ) -> List[Dict]:
        compromised = []
        common_usernames = ["admin", "user", "test", "root", "administrator"]
        
        attempts = 0
        for username in common_usernames[:3]:
            for password in self.COMMON_PASSWORDS[:max_attempts // len(common_usernames)]:
                if attempts >= max_attempts:
                    break
                
                try:
                    response_text, status_code = await self._send_request(
                        login_url,
                        method="POST",
                        data={
                            username_field: username,
                            password_field: password
                        },
                        headers=headers
                    )
                    
                    if status_code in [302, 303]:
                        compromised.append({
                            "username": username,
                            "password": password,
                            "url": login_url,
                            "status_code": status_code
                        })
                        logger.warning(f"Found weak credentials: {username}:{password}")
                    
                    elif response_text and ("dashboard" in response_text.lower() or "welcome" in response_text.lower()):
                        compromised.append({
                            "username": username,
                            "password": password,
                            "url": login_url,
                            "status_code": status_code
                        })
                        logger.warning(f"Found weak credentials: {username}:{password}")
                    
                except Exception as e:
                    logger.debug(f"Login attempt failed: {e}")
                
                attempts += 1
        
        return compromised
    
    async def _test_jwt_vulnerabilities(self, context: ScanContext) -> List[Dict]:
        issues = []
        
        auth_header = context.target.headers.get("Authorization", "")
        
        if "Bearer " in auth_header:
            token = auth_header.replace("Bearer ", "")
            
            if await self._test_jwt_none_algorithm(token):
                issues.append({
                    "type": "JWT None Algorithm",
                    "severity": "CRITICAL",
                    "description": "JWT accepts 'none' algorithm which allows token forgery",
                    "remediation": "Disable 'none' algorithm. Use strong algorithms like RS256 or HS256."
                })
            
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
        try:
            import jwt
            decoded = jwt.decode(token, options={"verify_signature": False})
            return decoded is not None
        except Exception:
            return False
    
    async def _test_jwt_expiration(self, token: str) -> bool:
        try:
            import jwt
            import time
            
            decoded = jwt.decode(token, options={"verify_signature": False})
            
            if "exp" in decoded:
                if decoded["exp"] < time.time():
                    return True
        except Exception:
            pass
        
        return False
    
    async def _test_session_vulnerabilities(self, context: ScanContext) -> List[Dict]:
        issues = []
        
        if "PHPSESSID=" in context.target.url or "JSESSIONID=" in context.target.url:
            issues.append({
                "type": "Session ID in URL",
                "severity": "MEDIUM",
                "description": "Session ID is exposed in URL, which may be leaked via Referer headers",
                "remediation": "Store session IDs in cookies only. Use HttpOnly and Secure flags."
            })
        
        if context.target.url.startswith("http://"):
            issues.append({
                "type": "Insecure Session Transmission",
                "severity": "HIGH",
                "description": "Session data transmitted over HTTP (not HTTPS)",
                "remediation": "Use HTTPS for all authenticated requests. Enable HSTS."
            })
        
        return issues
    
    async def generate_auth_report(self, result: AuthPipelineResult) -> str:
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
        
        report += "\n## Session Issues\n"
        for issue in result.session_issues:
            report += f"- **[{issue['severity']}]** {issue['type']}: {issue['description']}\n"
        
        if not result.session_issues:
            report += "- No session issues found\n"
        
        report += "\n## Recommendations\n"
        report += "1. Enforce strong password policy\n"
        report += "2. Implement account lockout after failed attempts\n"
        report += "3. Use multi-factor authentication (MFA)\n"
        report += "4. Implement proper session management with HttpOnly and Secure flags\n"
        report += "5. Use HTTPS exclusively for authenticated traffic\n"
        report += "6. Implement JWT validation with strong algorithms\n"
        
        return report
    
    async def get_result(self, pipeline_id: str) -> Optional[AuthPipelineResult]:
        return self._active_pipelines.get(pipeline_id)
    
    async def get_summary(self) -> Dict:
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
        logger.info("AuthPipeline closed")


async def get_auth_pipeline() -> AuthPipeline:
    return AuthPipeline()
