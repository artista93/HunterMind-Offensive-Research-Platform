import asyncio
import re
import base64
from typing import Dict, List, Optional, Any, Set, Tuple
from datetime import datetime

from ..base.base_agent import BaseAgent, AgentPriority, AgentMessage
from ..base.agent_state import AgentStateEnum
from offensive.scanners.auth_scanner import AuthScanner, Finding, Severity, Confidence
from offensive.scanners.base_scanner import ScanContext, ScanTarget
from offensive.exploitation.exploit_memory import get_exploit_memory

import logging

logger = logging.getLogger(__name__)


class AuthAgent(BaseAgent):
    """
    وكيل اختبار المصادقة المتقدم
    
    الميزات:
    - اختبار قوة كلمات المرور
    - اكتشاف ثغرات JWT
    - اختبار Session Fixation
    - كشف نقاط نهاية المصادقة غير المحمية
    - تخمين كلمات المرور الضعيفة
    - تكامل مع ذاكرة الاستغلال
    """
    
    COMMON_PASSWORDS = [
        "password", "123456", "12345678", "1234", "qwerty", "abc123",
        "admin", "letmein", "welcome", "monkey", "dragon", "master",
        "login", "pass", "password123", "admin123", "user123", "test123",
        "root", "toor", "secret", "changeme", "default"
    ]
    
    COMMON_USERNAMES = [
        "admin", "administrator", "root", "user", "test", "guest",
        "support", "info", "webmaster", "admin1", "admin123"
    ]
    
    def __init__(
        self,
        name: str = "AuthAgent",
        priority: AgentPriority = AgentPriority.HIGH,
        rate_limit: float = 1.0,
        timeout: int = 30,
        max_attempts: int = 20
    ):
        super().__init__(name, priority)
        
        self._rate_limit = rate_limit
        self._timeout = timeout
        self._max_attempts = max_attempts
        self._http_client = None
        
        self._scanner = AuthScanner(
            rate_limit=rate_limit,
            timeout=timeout,
            test_weak_passwords=True,
            analyze_jwt=True,
            check_session_fixation=True
        )
        self._memory = get_exploit_memory()
        
        self._scan_results: Dict[str, List[Finding]] = {}
        self._active_scans: Set[str] = set()
        self._discovered_credentials: List[Dict] = []
        self._jwt_issues: List[Dict] = []
        
        logger.info(f"AuthAgent initialized: {name}")
    
    def set_http_client(self, client):
        """تعيين عميل HTTP"""
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
        """إرسال طلب HTTP"""
        if self._http_client and hasattr(self._http_client, 'send_request'):
            response = await self._http_client.send_request(
                url, method=method, data=data, headers=headers
            )
            return response, 200 if response else 404
        return None, 0
    
    async def _on_initialize(self):
        logger.info("Initializing AuthAgent components...")
    
    async def _on_start(self):
        logger.info("AuthAgent started")
    
    async def _on_stop(self):
        for scan_id in list(self._active_scans):
            await self.stop_scan(scan_id)
        logger.info("AuthAgent stopped")
    
    async def _handle_message(self, message: AgentMessage) -> Optional[AgentMessage]:
        if message.type == "start_scan":
            result = await self.start_scan(message.content)
            return AgentMessage(
                id="",
                sender=self.name,
                receiver=message.sender,
                type="scan_started",
                content={"scan_id": result.get("scan_id")}
            )
        
        elif message.type == "stop_scan":
            success = await self.stop_scan(message.content.get("scan_id"))
            return AgentMessage(
                id="",
                sender=self.name,
                receiver=message.sender,
                type="scan_stopped",
                content={"success": success}
            )
        
        elif message.type == "get_findings":
            findings = await self.get_findings(message.content.get("scan_id"))
            return AgentMessage(
                id="",
                sender=self.name,
                receiver=message.sender,
                type="findings",
                content={"findings": [self._finding_to_dict(f) for f in findings]}
            )
        
        elif message.type == "test_login":
            result = await self.test_login(message.content)
            return AgentMessage(
                id="",
                sender=self.name,
                receiver=message.sender,
                type="login_result",
                content=result
            )
        
        elif message.type == "analyze_jwt":
            result = await self.analyze_jwt(message.content.get("token"))
            return AgentMessage(
                id="",
                sender=self.name,
                receiver=message.sender,
                type="jwt_analysis",
                content=result
            )
        
        return await super()._handle_message(message)
    
    async def start_scan(
        self,
        target_url: str,
        login_url: str = None,
        headers: Dict[str, str] = None,
        cookies: Dict[str, str] = None,
        options: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        self._state_manager.transition_to(
            AgentStateEnum.BUSY,
            reason=f"Starting auth scan of {target_url}"
        )
        
        import uuid
        scan_id = str(uuid.uuid4())[:8]
        
        context = ScanContext(
            target=ScanTarget(
                url=login_url or target_url,
                headers=headers or {},
                cookies=cookies or {}
            )
        )
        
        self._active_scans.add(scan_id)
        
        try:
            findings = await self._scanner.scan(context)
            self._scan_results[scan_id] = findings
            self._context.tasks_completed += 1
            
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
                        metadata={"url": target_url, "severity": finding.severity.value}
                    )
            
            logger.info(f"Auth scan completed: {target_url} - {len(findings)} findings")
            
            return {
                "scan_id": scan_id,
                "status": "completed",
                "findings_count": len(findings),
                "high_confidence": len([f for f in findings if f.confidence in [Confidence.HIGH, Confidence.CERTAIN]]),
                "url": target_url
            }
            
        except Exception as e:
            logger.error(f"Auth scan failed: {e}")
            self._context.tasks_failed += 1
            raise
        finally:
            self._active_scans.discard(scan_id)
            self._state_manager.transition_to(AgentStateEnum.IDLE, reason="Scan completed")
    
    async def stop_scan(self, scan_id: str) -> bool:
        if scan_id not in self._active_scans:
            return False
        self._active_scans.discard(scan_id)
        return True
    
    async def get_findings(self, scan_id: str = None) -> List[Finding]:
        if scan_id and scan_id in self._scan_results:
            return self._scan_results[scan_id]
        if self._scan_results:
            return list(self._scan_results.values())[-1]
        return []
    
    async def test_login(
        self,
        data: Dict[str, Any]
    ) -> Dict[str, Any]:
        url = data.get("url")
        username_field = data.get("username_field", "username")
        password_field = data.get("password_field", "password")
        credentials = data.get("credentials", [])
        
        results = {
            "successful": [],
            "failed": [],
            "total_tested": 0
        }
        
        if not credentials:
            for username in self.COMMON_USERNAMES[:5]:
                for password in self.COMMON_PASSWORDS[:self._max_attempts // 5]:
                    credentials.append({"username": username, "password": password})
        
        for cred in credentials[:self._max_attempts]:
            try:
                response_text, status_code = await self._send_request(
                    url,
                    method="POST",
                    data={
                        username_field: cred["username"],
                        password_field: cred["password"]
                    }
                )
                
                result = {
                    "username": cred["username"],
                    "password": cred["password"],
                    "status_code": status_code
                }
                
                if status_code in [200, 302, 303]:
                    result["success"] = True
                    results["successful"].append(result)
                    self._discovered_credentials.append(result)
                else:
                    result["success"] = False
                    results["failed"].append(result)
                
                results["total_tested"] += 1
                
            except Exception as e:
                logger.debug(f"Login test error: {e}")
        
        return results
    
    async def analyze_jwt(self, token: str) -> Dict[str, Any]:
        result = {
            "valid": False,
            "algorithm": None,
            "payload": None,
            "expired": False,
            "issues": []
        }
        
        try:
            import jwt
            
            headers = jwt.get_unverified_header(token)
            payload = jwt.decode(token, options={"verify_signature": False})
            
            result["algorithm"] = headers.get("alg", "unknown")
            result["payload"] = payload
            result["valid"] = True
            
            if result["algorithm"] == "none":
                result["issues"].append({
                    "type": "none_algorithm",
                    "severity": "CRITICAL",
                    "description": "JWT uses 'none' algorithm which allows token forgery"
                })
            
            exp = payload.get("exp")
            if exp:
                import time
                if exp < time.time():
                    result["expired"] = True
                    result["issues"].append({
                        "type": "expired",
                        "severity": "MEDIUM",
                        "description": "JWT token has expired"
                    })
            
            sensitive_fields = ["password", "secret", "key", "token"]
            for field in sensitive_fields:
                if field in payload:
                    result["issues"].append({
                        "type": "sensitive_data",
                        "severity": "MEDIUM",
                        "description": f"JWT contains sensitive field: {field}"
                    })
                    break
            
            self._jwt_issues.append(result)
            
        except Exception as e:
            result["error"] = str(e)
        
        return result
    
    async def generate_report(self, scan_id: str = None, format: str = "json") -> str:
        findings = await self.get_findings(scan_id)
        
        if format == "json":
            import json
            return json.dumps({
                "scan_id": scan_id or "latest",
                "timestamp": datetime.now().isoformat(),
                "total_findings": len(findings),
                "findings": [self._finding_to_dict(f) for f in findings],
                "discovered_credentials": self._discovered_credentials,
                "jwt_issues": self._jwt_issues
            }, indent=2)
        
        elif format == "markdown":
            report = f"""# Authentication Security Report

**Scan ID:** {scan_id or 'latest'}
**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**Total Findings:** {len(findings)}

## Findings

"""
            for i, finding in enumerate(findings, 1):
                report += f"### {i}. {finding.vulnerability_type}\n"
                report += f"- **Severity:** {finding.severity.value}\n"
                report += f"- **Confidence:** {finding.confidence.value}\n"
                report += f"- **URL:** {finding.url}\n\n"
            
            if self._discovered_credentials:
                report += "## Compromised Credentials\n\n"
                for cred in self._discovered_credentials[:10]:
                    report += f"- **{cred['username']}** : `{cred['password']}`\n"
            
            return report
        
        return "Unsupported format"
    
    def _finding_to_dict(self, finding: Finding) -> Dict:
        return {
            "type": finding.vulnerability_type,
            "severity": finding.severity.value,
            "confidence": finding.confidence.value,
            "url": finding.url,
            "parameter": finding.parameter,
            "description": finding.description,
            "remediation": finding.remediation
        }
    
    async def get_summary(self) -> Dict:
        return {
            "total_scans": len(self._scan_results),
            "active_scans": len(self._active_scans),
            "total_findings": sum(len(f) for f in self._scan_results.values()),
            "discovered_credentials": len(self._discovered_credentials),
            "jwt_issues": len(self._jwt_issues)
        }
    
    async def clear_results(self):
        self._scan_results.clear()
        self._discovered_credentials.clear()
        self._jwt_issues.clear()
        logger.info("Auth agent results cleared")


_default_auth_agent = None

async def get_auth_agent() -> AuthAgent:
    global _default_auth_agent
    if _default_auth_agent is None:
        _default_auth_agent = AuthAgent()
        await _default_auth_agent.initialize()
        await _default_auth_agent.start()
    return _default_auth_agent
