"""
Smart Orchestrator V3 - فحص حقيقي مع تفاصيل كاملة للثغرات + استخراج البيانات
"""

import asyncio, re, json, os
from typing import Dict, List, Optional, Any, Set
from datetime import datetime
from urllib.parse import urlparse, urljoin, parse_qs

import httpx

from orchestration.orchestrator import Orchestrator
from offensive.scanners.base_scanner import ScanContext, ScanTarget
from offensive.recon.data_extractor import DataExtractor, ExtractedData, get_data_extractor
from offensive.reconnaissance.orchestrator import ReconOrchestrator, get_recon_orchestrator

import logging

logger = logging.getLogger(__name__)


class SmartOrchestrator(Orchestrator):
    """منسق ذكي V3 - اكتشاف ثغرات حقيقي مع تفاصيل كاملة + استخراج البيانات"""
    
    def __init__(self):
        super().__init__()
        self._response_cache: Dict[str, Dict] = {}
        self._all_findings: List[Dict] = []
        self._data_extractor = DataExtractor()
        self._extracted_data: List[ExtractedData] = []
        
    async def smart_scan(self, url: str, depth: int = 2, max_pages: int = 10) -> Dict:
        scan_id = f"scan_{len(self._scans)+1:03d}"
        start = datetime.now()
        self._extracted_data = []
        
        print(f"\n{'='*60}")
        print(f"🔍 HunterMind Smart Scan")
        print(f"   Target: {url}")
        print(f"{'='*60}")
        
        # ===== 0: Advanced Reconnaissance =====
        print(f"\n🔍 Phase 0: Advanced Reconnaissance...")
        try:
            recon = ReconOrchestrator()
            recon_report = await recon.execute(url, passive_only=False)
            if recon_report.subdomains:
                print(f"   ✅ Found {len(recon_report.subdomains)} subdomains")
        except Exception as e:
            logger.debug(f"Recon skipped: {e}")
        # ===== 1: جمع الصفحات =====
        print(f"\n📡 Phase 1: Collecting pages and responses...")
        pages_data = await self._collect_all_responses(url, depth, max_pages)
        
        if not pages_data:
            return {"error": "No pages accessible", "findings": []}
        
        print(f"   ✅ Collected {len(pages_data)} pages with full responses")
        
        # ===== 2: تحليل كل صفحة + استخراج البيانات =====
        print(f"\n🔍 Phase 2: Analyzing responses and extracting data...")
        
        all_findings = []
        
        for page_url, data in pages_data.items():
            findings = await self._analyze_response(page_url, data)
            all_findings.extend(findings)
            
            # استخراج البيانات الحساسة
            extracted = self._data_extractor.extract_from_response(
                page_url, data.get("body", ""), data.get("headers", {})
            )
            self._extracted_data.extend(extracted)
            
            if findings:
                types = set(f.get('type', '?') for f in findings)
                print(f"   📄 {page_url[:60]}: {len(findings)} findings ({', '.join(list(types)[:3])})")
        
        # ===== 3: فحص endpoints =====
        print(f"\n⚡ Phase 3: Testing endpoints with parameters...")
        
        endpoints_with_params = self._extract_endpoints_with_params(pages_data)
        
        for endpoint in endpoints_with_params[:10]:
            findings = await self._test_endpoint(endpoint)
            all_findings.extend(findings)
            
            if findings:
                print(f"   🎯 {endpoint['url'][:60]}: {len(findings)} findings")
        
        # ===== 4: إزالة التكرار =====
        all_findings = self._deduplicate_findings(all_findings)
        
        # ===== 5: ملخص =====
        duration = (datetime.now() - start).total_seconds()
        
        by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in all_findings:
            sev = f.get("severity", "low").lower()
            by_severity[sev] = by_severity.get(sev, 0) + 1
        
        print(f"\n{'='*60}")
        print(f"✅ Scan Complete!")
        print(f"   Critical: {by_severity['critical']} | High: {by_severity['high']}")
        print(f"   Medium: {by_severity['medium']} | Low: {by_severity['low']}")
        print(f"   Total: {len(all_findings)} | Duration: {duration:.1f}s")
        
        # ===== عرض تفاصيل الثغرات =====
        if all_findings:
            self._print_vulnerability_details(all_findings)
        
        # ===== عرض البيانات المستخرجة =====
        if self._extracted_data:
            self._data_extractor.print_extracted_data(self._extracted_data)
            
            # حفظ في ملف
            saved_file = self._save_extracted_data(url)
            print(f"\n💾 Full extracted data saved to: {saved_file}")
        
        return {
            "scan_id": scan_id,
            "target": url,
            "pages_analyzed": len(pages_data),
            "endpoints_tested": len(endpoints_with_params[:10]),
            "findings": all_findings[:30],
            "by_severity": by_severity,
            "total_findings": len(all_findings),
            "extracted_data_file": saved_file if self._extracted_data else None,
            "duration": duration,
        }
    
    def _print_vulnerability_details(self, findings: List[Dict]):
        """عرض تفاصيل الثغرات"""
        print(f"\n📋 Vulnerability Details:")
        print(f"{'='*60}")
        
        by_type = {}
        for f in findings:
            t = f.get("type", "Unknown")
            if t not in by_type:
                by_type[t] = []
            by_type[t].append(f)
        
        for vtype, items in sorted(by_type.items()):
            example = items[0]
            sev = example.get("severity", "low").upper()
            count = len(items)
            emoji = "🔴" if sev == "CRITICAL" else "🟠" if sev == "HIGH" else "🟡" if sev == "MEDIUM" else "🟢"
            
            print(f"\n  {emoji} [{sev}] {vtype} (x{count})")
            print(f"     📍 URLs: {', '.join([i.get('url', '?')[:50] for i in items[:3]])}")
            print(f"     🔍 Evidence: {example.get('evidence', 'N/A')[:120]}")
            print(f"     🛡️  CVSS: {example.get('cvss', 'N/A')}")
            print(f"     💡 Fix: {example.get('remediation', 'N/A')[:120]}")
    
    def _save_extracted_data(self, url: str) -> str:
        """حفظ البيانات المستخرجة في ملف JSON"""
        os.makedirs("scan_reports", exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"scan_reports/extracted_{urlparse(url).netloc}_{timestamp}.json"
        
        report = {
            "target": url,
            "timestamp": datetime.now().isoformat(),
            "total_items": sum(d.count for d in self._extracted_data),
            "data": []
        }
        
        for data in self._extracted_data:
            report["data"].append({
                "type": data.data_type,
                "count": data.count,
                "values": data.values,
                "source": data.source_url,
            })
        
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
        
        return filename
    
    def _deduplicate_findings(self, findings: List[Dict]) -> List[Dict]:
        seen = set()
        unique = []
        for f in findings:
            key = f"{f.get('type', '')}|{f.get('severity', '')}|{f.get('url', '')[:50]}"
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique
    
    async def _collect_all_responses(self, url: str, depth: int, max_pages: int) -> Dict[str, Dict]:
        pages = {}
        visited = set()
        queue = [(url, 0)]
        
        async with httpx.AsyncClient(
            timeout=15, follow_redirects=True, verify=False,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0.0.0 Safari/537.36"}
        ) as client:
            while queue and len(pages) < max_pages:
                current_url, current_depth = queue.pop(0)
                if current_url in visited:
                    continue
                visited.add(current_url)
                
                try:
                    response = await client.get(current_url)
                    if response.status_code < 500:
                        pages[current_url] = {
                            "status_code": response.status_code,
                            "headers": dict(response.headers),
                            "cookies": dict(response.cookies),
                            "body": response.text,
                            "url": str(response.url),
                            "content_type": response.headers.get("content-type", ""),
                        }
                        
                        if current_depth < depth and "text/html" in response.headers.get("content-type", ""):
                            links = re.findall(r'href=["\']([^"\']+)["\']', response.text)
                            for link in links[:20]:
                                full_url = urljoin(current_url, link)
                                parsed = urlparse(full_url)
                                if parsed.netloc == urlparse(url).netloc and full_url not in visited:
                                    queue.append((full_url, current_depth + 1))
                except Exception as e:
                    logger.debug(f"Failed to fetch {current_url}: {e}")
        
        return pages
    
    async def _analyze_response(self, url: str, data: Dict) -> List[Dict]:
        findings = []
        body = data.get("body", "")
        headers = data.get("headers", {})
        cookies = data.get("cookies", {})
        content_type = data.get("content_type", "")
        
        findings.extend(self._check_security_headers(url, headers))
        findings.extend(self._check_information_disclosure(url, body, headers))
        findings.extend(self._check_cookie_security(url, cookies))
        findings.extend(self._check_secrets(url, body))
        findings.extend(self._check_jwt_tokens(url, body, headers))
        
        if "text/html" in content_type:
            findings.extend(self._check_forms(url, body))
        
        return findings
    
    def _check_security_headers(self, url: str, headers: Dict) -> List[Dict]:
        findings = []
        headers_lower = {k.lower(): v for k, v in headers.items()}
        
        security_headers = {
            "strict-transport-security": ("Missing HSTS Header", "high", 4.0),
            "content-security-policy": ("Missing CSP Header", "medium", 3.0),
            "x-frame-options": ("Missing X-Frame-Options Header", "medium", 3.0),
            "x-content-type-options": ("Missing X-Content-Type-Options", "low", 1.0),
            "referrer-policy": ("Missing Referrer-Policy", "low", 1.0),
        }
        
        for header_name, (display_name, severity, cvss) in security_headers.items():
            if header_name not in headers_lower:
                findings.append({
                    "type": display_name, "severity": severity, "url": url,
                    "evidence": f"{header_name} header not present",
                    "description": f"Missing {header_name} security header",
                    "remediation": f"Add {header_name} header to server configuration",
                    "cvss": cvss,
                })
        
        return findings
    
    def _check_information_disclosure(self, url: str, body: str, headers: Dict) -> List[Dict]:
        findings = []
        
        server = headers.get("server", "")
        if server:
            findings.append({"type": "Server Header Disclosure", "severity": "low", "url": url,
                           "evidence": f"Server: {server}", "description": f"Server discloses: {server}",
                           "remediation": "Hide server version", "cvss": 2.0})
        
        powered = headers.get("x-powered-by", "")
        if powered:
            findings.append({"type": "Technology Disclosure", "severity": "low", "url": url,
                           "evidence": f"X-Powered-By: {powered}", "description": f"Tech: {powered}",
                           "remediation": "Remove X-Powered-By header", "cvss": 2.0})
        
        emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', body)
        if len(emails) > 5:
            findings.append({"type": "Email Address Harvesting", "severity": "low", "url": url,
                           "evidence": f"Found {len(emails)} email addresses",
                           "description": f"Page exposes {len(emails)} emails",
                           "remediation": "Obfuscate emails", "cvss": 1.0})
        
        internal_ips = re.findall(r'(?:10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.)\d{1,3}\.\d{1,3}', body)
        if internal_ips:
            findings.append({"type": "Internal IP Disclosure", "severity": "medium", "url": url,
                           "evidence": f"Found: {internal_ips[0]}", "description": "Internal IP exposed",
                           "remediation": "Remove internal IPs", "cvss": 5.0})
        
        return findings
    
    def _check_cookie_security(self, url: str, cookies: Dict) -> List[Dict]:
        findings = []
        for name, value in cookies.items():
            cs = f"{name}={value}".lower()
            if "httponly" not in cs:
                findings.append({"type": "Cookie Missing HttpOnly", "severity": "medium", "url": url,
                               "evidence": f"Cookie: {name}", "description": f"'{name}' missing HttpOnly",
                               "remediation": "Set HttpOnly flag", "cvss": 4.0})
            if "secure" not in cs and url.startswith("https"):
                findings.append({"type": "Cookie Missing Secure", "severity": "medium", "url": url,
                               "evidence": f"Cookie: {name}", "description": f"'{name}' missing Secure",
                               "remediation": "Set Secure flag", "cvss": 4.0})
            if "samesite" not in cs:
                findings.append({"type": "Cookie Missing SameSite", "severity": "low", "url": url,
                               "evidence": f"Cookie: {name}", "description": f"'{name}' missing SameSite",
                               "remediation": "Set SameSite=Lax", "cvss": 3.0})
        return findings
    
    def _check_secrets(self, url: str, body: str) -> List[Dict]:
        findings = []
        patterns = [
            (r'(?:AKIA|ASIA)[A-Z0-9]{16}', "AWS Access Key", "critical", 9.0),
            (r'AIza[0-9A-Za-z\-_]{35}', "Google API Key", "high", 8.0),
            (r'(?:ghp|gho|ghu)_[A-Za-z0-9_]{36,}', "GitHub Token", "critical", 9.5),
        ]
        for pattern, name, severity, cvss in patterns:
            for match in re.findall(pattern, body, re.I):
                if not any(w in match.lower() for w in ['example', 'test', 'xxx']):
                    findings.append({"type": f"{name} Exposed", "severity": severity, "url": url,
                                   "evidence": f"Found: {match[:30]}...", "description": f"{name} in source",
                                   "remediation": f"Remove and rotate {name}", "cvss": cvss})
        return findings
    
    def _check_jwt_tokens(self, url: str, body: str, headers: Dict) -> List[Dict]:
        findings = []
        for match in re.finditer(r'eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+', body):
            try:
                parts = match.group(0).split('.')
                padded = parts[1] + '=' * (4 - len(parts[1]) % 4)
                payload = json.loads(__import__('base64').urlsafe_b64decode(padded))
                if "exp" not in payload:
                    findings.append({"type": "JWT Missing Expiration", "severity": "medium", "url": url,
                                   "evidence": "No exp claim", "description": "JWT valid indefinitely",
                                   "remediation": "Set exp claim", "cvss": 5.0})
            except: pass
        return findings
    
    def _check_forms(self, url: str, html: str) -> List[Dict]:
        findings = []
        for match in re.finditer(r'<form[^>]*?(?:action=["\']([^"\']*)["\'])?[^>]*>(.*?)</form>', html, re.DOTALL | re.I):
            action = match.group(1) or url
            content = match.group(2)
            method = re.search(r'method=["\']([^"\']+)["\']', match.group(0), re.I)
            method = method.group(1).upper() if method else "GET"
            has_csrf = bool(re.search(r'name=["\'](?:csrf|token|_token|xsrf)', content, re.I))
            if method == "POST" and not has_csrf:
                findings.append({"type": "Missing CSRF Protection", "severity": "medium", "url": url,
                               "evidence": f"POST form at {action}", "description": "No CSRF token",
                               "remediation": "Add CSRF tokens", "cvss": 5.0})
        return findings
    
    def _extract_endpoints_with_params(self, pages_data: Dict) -> List[Dict]:
        endpoints = []
        for url in pages_data:
            parsed = urlparse(url)
            if parsed.query:
                params = parse_qs(parsed.query)
                endpoints.append({"url": url, "method": "GET", "params": {k: v[0] for k, v in params.items()}})
        return endpoints
    
    async def _test_endpoint(self, endpoint: Dict) -> List[Dict]:
        findings = []
        async with httpx.AsyncClient(timeout=10, verify=False) as client:
            for param_name in list(endpoint["params"].keys())[:2]:
                for payload in ["'", "\"", "1'", "1 OR 1=1"]:
                    try:
                        tp = endpoint["params"].copy()
                        tp[param_name] = payload
                        r = await client.get(endpoint["url"].split('?')[0], params=tp)
                        if any(e in r.text.lower() for e in ["sql syntax", "mysql", "postgresql"]):
                            findings.append({"type": "SQL Injection", "severity": "critical", "url": endpoint["url"],
                                           "parameter": param_name, "payload": payload, "evidence": "SQL error",
                                           "description": f"SQLi in '{param_name}'", "remediation": "Use parameterized queries",
                                           "cvss": 9.8})
                            break
                    except: pass
        return findings


_smart_orchestrator = None

async def get_smart_orchestrator() -> SmartOrchestrator:
    global _smart_orchestrator
    if _smart_orchestrator is None:
        _smart_orchestrator = SmartOrchestrator()
        await _smart_orchestrator.start()
    return _smart_orchestrator
