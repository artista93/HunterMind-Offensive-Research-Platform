"""
Smart Orchestrator V4 - استطلاع متقدم + فحص موجه + استخراج بيانات
"""

import asyncio, re, json, os
from typing import Dict, List, Optional, Any
from datetime import datetime
from urllib.parse import urlparse, urljoin, parse_qs

import httpx

from orchestration.orchestrator import Orchestrator
from offensive.scanners.base_scanner import ScanContext, ScanTarget
from offensive.recon.data_extractor import DataExtractor, ExtractedData, get_data_extractor
from offensive.reconnaissance.orchestrator import ReconOrchestrator, get_recon_orchestrator
from offensive.reconnaissance.active.subdomain_scanner import SubdomainScanner, get_subdomain_scanner
from offensive.reconnaissance.sensitive.file_exploiter import FileExploiter, get_file_exploiter

import logging
logger = logging.getLogger(__name__)


class SmartOrchestrator(Orchestrator):
    """منسق ذكي V4 - استطلاع + فحص موجه + استخراج بيانات"""
    
    def __init__(self):
        super().__init__()
        self._response_cache: Dict[str, Dict] = {}
        self._all_findings: List[Dict] = []
        self._data_extractor = DataExtractor()
        self._extracted_data: List[ExtractedData] = []
        self._recon_report = None
        
    async def smart_scan(self, url: str, depth: int = 2, max_pages: int = 10) -> Dict:
        scan_id = f"scan_{len(self._scans)+1:03d}"
        start = datetime.now()
        self._extracted_data = []
        all_findings = []
        
        print(f"\n{'='*60}")
        print(f"🔍 HunterMind Smart Scan V4")
        print(f"   Target: {url}")
        print(f"{'='*60}")
        
        # ===== Phase 0: Advanced Reconnaissance =====
        print(f"\n🔍 Phase 0: Advanced Reconnaissance (8 steps)...")
        try:
            recon = ReconOrchestrator()
            self._recon_report = await recon.execute(url, passive_only=False)
            print(f"   ✅ Subdomains: {self._recon_report.total_subdomains} | Technologies: {self._recon_report.total_technologies} | Sensitive Files: {self._recon_report.total_sensitive_files}")
        except Exception as e:
            logger.debug(f"Recon skipped: {e}")
            self._recon_report = None
        
        # ===== Phase 1: Scan Subdomains =====
        if self._recon_report and self._recon_report.subdomains:
            print(f"\n🌐 Phase 1: Scanning discovered subdomains...")
            try:
                sub_scanner = SubdomainScanner()
                sub_results = await sub_scanner.scan(self._recon_report.subdomains)
                if sub_results.interesting_count > 0:
                    print(f"   ⚡ {sub_results.interesting_count} interesting subdomains found!")
            except Exception as e:
                logger.debug(f"Subdomain scan skipped: {e}")
        
        # ===== Phase 2: Exploit Sensitive Files =====
        if self._recon_report and self._recon_report.sensitive_files:
            print(f"\n💥 Phase 2: Exploiting sensitive files...")
            try:
                file_exploiter = FileExploiter()
                for sf in self._recon_report.sensitive_files[:10]:
                    if sf.get("status") == 200:
                        result = await file_exploiter.exploit_file(sf["url"], sf["type"])
                        if result:
                            for cred in result.credentials:
                                all_findings.append({
                                    "type": f"Credential Found in {sf['type']}",
                                    "severity": "CRITICAL", "url": sf["url"],
                                    "evidence": cred.get("value", "")[:100],
                                    "cvss": 9.0,
                                })
                            for key in result.api_keys:
                                all_findings.append({
                                    "type": "API Key Exposed",
                                    "severity": "CRITICAL", "url": sf["url"],
                                    "evidence": key[:50], "cvss": 9.0,
                                })
                
                summary = file_exploiter.get_summary()
                if summary["files_exploited"] > 0:
                    print(f"   ✅ Exploited {summary['files_exploited']} files, found {summary['credentials_found']} credentials, {summary['api_keys_found']} keys")
            except Exception as e:
                logger.debug(f"File exploit skipped: {e}")
        
        # ===== Phase 3: CVE Findings =====
        if self._recon_report:
            for tech in self._recon_report.technologies:
                if isinstance(tech, dict) and tech.get("cves", 0) > 0:
                    all_findings.append({
                        "type": f"Known CVEs in {tech['name']}",
                        "severity": "HIGH", "url": url,
                        "evidence": f"{tech['cves']} CVEs ({tech.get('critical', 0)} critical)",
                        "cvss": 8.0,
                    })
        
        # ===== Phase 4: Collect Pages =====
        print(f"\n📡 Phase 4: Collecting pages and responses...")
        pages_data = await self._collect_all_responses(url, depth, max_pages)
        
        if not pages_data:
            print(f"   ⚠️  No pages accessible")
        else:
            print(f"   ✅ Collected {len(pages_data)} pages")
        
        # ===== Phase 5: Analyze Responses =====
        if pages_data:
            print(f"\n🔍 Phase 5: Analyzing responses...")
            
            for page_url, data in pages_data.items():
                findings = await self._analyze_response(page_url, data)
                all_findings.extend(findings)
                
                extracted = self._data_extractor.extract_from_response(
                    page_url, data.get("body", ""), data.get("headers", {})
                )
                self._extracted_data.extend(extracted)
                
                if findings:
                    types = set(f.get('type', '?') for f in findings)
                    print(f"   📄 {page_url[:60]}: {len(findings)} findings")
        
        # ===== Phase 6: Test Endpoints =====
        if pages_data:
            print(f"\n⚡ Phase 6: Testing endpoints with parameters...")
            endpoints_with_params = self._extract_endpoints_with_params(pages_data)
            
            for endpoint in endpoints_with_params[:10]:
                findings = await self._test_endpoint(endpoint)
                all_findings.extend(findings)
                if findings:
                    print(f"   🎯 {endpoint['url'][:60]}: {len(findings)} findings")
        
        # ===== Deduplicate & Summary =====
        all_findings = self._deduplicate_findings(all_findings)
        duration = (datetime.now() - start).total_seconds()
        
        by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in all_findings:
            sev = f.get("severity", "low").lower()
            by_severity[sev] = by_severity.get(sev, 0) + 1
        
        print(f"\n{'='*60}")
        print(f"✅ Smart Scan Complete!")
        print(f"   🔴 Critical: {by_severity['critical']} | 🟠 High: {by_severity['high']}")
        print(f"   🟡 Medium: {by_severity['medium']} | 🟢 Low: {by_severity['low']}")
        print(f"   📊 Total: {len(all_findings)} | ⏱️  Duration: {duration:.1f}s")
        
        if all_findings:
            self._print_vulnerability_details(all_findings)
        
        if self._extracted_data:
            self._data_extractor.print_extracted_data(self._extracted_data)
            saved_file = self._save_extracted_data(url)
            print(f"\n💾 Full extracted data saved to: {saved_file}")
        
        return {
            "scan_id": scan_id, "target": url,
            "recon": {
                "subdomains": self._recon_report.total_subdomains if self._recon_report else 0,
                "technologies": self._recon_report.total_technologies if self._recon_report else 0,
                "sensitive_files": self._recon_report.total_sensitive_files if self._recon_report else 0,
            },
            "pages_analyzed": len(pages_data) if pages_data else 0,
            "findings": all_findings[:30],
            "by_severity": by_severity,
            "total_findings": len(all_findings),
            "extracted_data_file": saved_file if self._extracted_data else None,
            "duration": duration,
        }
    
    def _print_vulnerability_details(self, findings: List[Dict]):
        print(f"\n📋 Vulnerability Details:")
        print(f"{'='*60}")
        by_type = {}
        for f in findings:
            t = f.get("type", "Unknown")
            if t not in by_type: by_type[t] = []
            by_type[t].append(f)
        for vtype, items in sorted(by_type.items()):
            example = items[0]
            sev = example.get("severity", "low").upper()
            emoji = "🔴" if sev == "CRITICAL" else "🟠" if sev == "HIGH" else "🟡" if sev == "MEDIUM" else "🟢"
            print(f"\n  {emoji} [{sev}] {vtype} (x{len(items)})")
            print(f"     📍 URLs: {', '.join([i.get('url', '?')[:50] for i in items[:3]])}")
            print(f"     🔍 Evidence: {example.get('evidence', 'N/A')[:120]}")
            print(f"     🛡️  CVSS: {example.get('cvss', 'N/A')}")
            if example.get('remediation'):
                print(f"     💡 Fix: {example.get('remediation', '')[:120]}")
    
    def _save_extracted_data(self, url: str) -> str:
        os.makedirs("scan_reports", exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"scan_reports/extracted_{urlparse(url).netloc}_{timestamp}.json"
        report = {"target": url, "timestamp": datetime.now().isoformat(), "total_items": sum(d.count for d in self._extracted_data), "data": []}
        for data in self._extracted_data:
            report["data"].append({"type": data.data_type, "count": data.count, "values": data.values, "source": data.source_url})
        with open(filename, 'w') as f: json.dump(report, f, indent=2)
        return filename
    
    def _deduplicate_findings(self, findings: List[Dict]) -> List[Dict]:
        seen, unique = set(), []
        for f in findings:
            key = f"{f.get('type', '')}|{f.get('severity', '')}|{f.get('url', '')[:50]}"
            if key not in seen: seen.add(key); unique.append(f)
        return unique
    
    async def _collect_all_responses(self, url: str, depth: int, max_pages: int) -> Dict[str, Dict]:
        pages, visited, queue = {}, set(), [(url, 0)]
        async with httpx.AsyncClient(timeout=15, follow_redirects=True, verify=False,
            headers={"User-Agent": "Mozilla/5.0 Chrome/124.0.0.0 Safari/537.36"}) as client:
            while queue and len(pages) < max_pages:
                current_url, current_depth = queue.pop(0)
                if current_url in visited: continue
                visited.add(current_url)
                try:
                    response = await client.get(current_url)
                    if response.status_code < 500:
                        pages[current_url] = {"status_code": response.status_code, "headers": dict(response.headers),
                            "cookies": dict(response.cookies), "body": response.text, "url": str(response.url),
                            "content_type": response.headers.get("content-type", "")}
                        if current_depth < depth and "text/html" in response.headers.get("content-type", ""):
                            for link in re.findall(r'href=["\']([^"\']+)["\']', response.text)[:20]:
                                full_url = urljoin(current_url, link)
                                if urlparse(full_url).netloc == urlparse(url).netloc and full_url not in visited:
                                    queue.append((full_url, current_depth + 1))
                except: pass
        return pages
    
    async def _analyze_response(self, url: str, data: Dict) -> List[Dict]:
        findings = []
        body, headers, cookies, ct = data.get("body",""), data.get("headers",{}), data.get("cookies",{}), data.get("content_type","")
        findings.extend(self._check_security_headers(url, headers))
        findings.extend(self._check_information_disclosure(url, body, headers))
        findings.extend(self._check_cookie_security(url, cookies))
        findings.extend(self._check_secrets(url, body))
        findings.extend(self._check_jwt_tokens(url, body, headers))
        if "text/html" in ct: findings.extend(self._check_forms(url, body))
        return findings
    
    def _check_security_headers(self, url, headers):
        f, hl = [], {k.lower(): v for k, v in headers.items()}
        for h, (n, s, c) in {"strict-transport-security":("Missing HSTS","high",4.0),"content-security-policy":("Missing CSP","medium",3.0),"x-frame-options":("Missing X-Frame-Options","medium",3.0)}.items():
            if h not in hl: f.append({"type":n,"severity":s,"url":url,"evidence":f"{h} not present","cvss":c})
        return f
    
    def _check_information_disclosure(self, url, body, headers):
        f = []
        if headers.get("server"): f.append({"type":"Server Disclosure","severity":"low","url":url,"evidence":f"Server: {headers['server']}","cvss":2.0})
        emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', body)
        if len(emails) > 5: f.append({"type":"Email Harvesting","severity":"low","url":url,"evidence":f"{len(emails)} emails","cvss":1.0})
        return f
    
    def _check_cookie_security(self, url, cookies):
        f = []
        for n, v in cookies.items():
            cs = f"{n}={v}".lower()
            if "httponly" not in cs: f.append({"type":"Cookie Missing HttpOnly","severity":"medium","url":url,"evidence":f"Cookie: {n}","cvss":4.0})
            if "secure" not in cs and url.startswith("https"): f.append({"type":"Cookie Missing Secure","severity":"medium","url":url,"evidence":f"Cookie: {n}","cvss":4.0})
        return f
    
    def _check_secrets(self, url, body):
        f = []
        for p, n, s, c in [(r'(?:AKIA|ASIA)[A-Z0-9]{16}',"AWS Key","critical",9.0),(r'AIza[0-9A-Za-z\-_]{35}',"Google API Key","high",8.0)]:
            for m in re.findall(p, body, re.I):
                if not any(w in m.lower() for w in ['example','test']): f.append({"type":f"{n} Exposed","severity":s,"url":url,"evidence":f"Found: {m[:30]}...","cvss":c})
        return f
    
    def _check_jwt_tokens(self, url, body, headers):
        f = []
        for m in re.finditer(r'eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+', body):
            try:
                parts = m.group(0).split('.')
                payload = json.loads(__import__('base64').urlsafe_b64decode(parts[1]+'='*(4-len(parts[1])%4)))
                if "exp" not in payload: f.append({"type":"JWT No Expiration","severity":"medium","url":url,"evidence":"No exp claim","cvss":5.0})
            except: pass
        return f
    
    def _check_forms(self, url, html):
        f = []
        for m in re.finditer(r'<form[^>]*?(?:action=["\']([^"\']*)["\'])?[^>]*>(.*?)</form>', html, re.DOTALL|re.I):
            ct = m.group(2)
            mt = re.search(r'method=["\']([^"\']+)["\']', m.group(0), re.I)
            method = mt.group(1).upper() if mt else "GET"
            if method == "POST" and not re.search(r'name=["\'](?:csrf|token|_token)', ct, re.I):
                f.append({"type":"Missing CSRF","severity":"medium","url":url,"evidence":"POST form without CSRF","cvss":5.0})
        return f
    
    def _extract_endpoints_with_params(self, pages_data):
        e = []
        for url in pages_data:
            p = urlparse(url)
            if p.query: e.append({"url":url,"method":"GET","params":{k:v[0] for k,v in parse_qs(p.query).items()}})
        return e
    
    async def _test_endpoint(self, endpoint):
        f = []
        async with httpx.AsyncClient(timeout=10, verify=False) as c:
            for pn in list(endpoint["params"].keys())[:2]:
                for pl in ["'",'"',"1'","1 OR 1=1"]:
                    try:
                        tp = endpoint["params"].copy(); tp[pn] = pl
                        r = await c.get(endpoint["url"].split('?')[0], params=tp)
                        if any(e in r.text.lower() for e in ["sql syntax","mysql","postgresql"]):
                            f.append({"type":"SQL Injection","severity":"critical","url":endpoint["url"],"parameter":pn,"payload":pl,"evidence":"SQL error","cvss":9.8})
                            break
                    except: pass
        return f


_smart_orchestrator = None

async def get_smart_orchestrator() -> SmartOrchestrator:
    global _smart_orchestrator
    if _smart_orchestrator is None:
        _smart_orchestrator = SmartOrchestrator()
        await _smart_orchestrator.start()
    return _smart_orchestrator
