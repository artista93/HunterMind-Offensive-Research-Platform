"""
Reconnaissance Orchestrator - منسق مرحلة الاستطلاع

ينسق بين:
- Passive Recon (crt.sh, Wayback, DNS, WHOIS)
- Active Recon (Subdomain, Port, SSL)
- Fingerprinting (Wappalyzer, CVE)
- Sensitive Files (Backup, Config, Git, Admin)
- Metadata (PDF, Office, Images)
"""

import asyncio
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime

from offensive.reconnaissance.passive.dns_enum import DNSEnumerator, DNSResult, get_dns_enumerator
from offensive.reconnaissance.passive.crt_sh import CRTShSearch, get_crt_search
from offensive.reconnaissance.passive.wayback import WaybackSearch, get_wayback_search
from offensive.reconnaissance.passive.whois_lookup import WHOISLookup, get_whois_lookup
from offensive.reconnaissance.fingerprinting.wappalyzer import WappalyzerFingerprinter, get_wappalyzer
from offensive.reconnaissance.fingerprinting.cve_lookup import CVELookup, get_cve_lookup
from offensive.reconnaissance.sensitive.sensitive_files import SensitiveFilesScanner, get_sensitive_scanner
from offensive.reconnaissance.metadata.metadata_analyzer import MetadataAnalyzer, get_metadata_analyzer

import logging

logger = logging.getLogger(__name__)


@dataclass
class ReconReport:
    """تقرير الاستطلاع الكامل"""
    target: str
    timestamp: datetime = field(default_factory=datetime.now)
    
    # DNS
    dns_results: Optional[DNSResult] = None
    subdomains: List[str] = field(default_factory=list)
    
    # سيتم إضافتها لاحقاً
    technologies: List[Dict] = field(default_factory=list)
    sensitive_files: List[Dict] = field(default_factory=list)
    metadata_findings: List[Dict] = field(default_factory=list)
    
    # إحصائيات
    total_subdomains: int = 0
    total_technologies: int = 0
    total_sensitive_files: int = 0
    
    def to_dict(self) -> Dict:
        return {
            "target": self.target,
            "timestamp": self.timestamp.isoformat(),
            "subdomains": self.subdomains[:50],
            "total_subdomains": self.total_subdomains,
            "technologies": self.technologies[:20],
            "sensitive_files": self.sensitive_files[:20],
            "total_findings": self.total_subdomains + self.total_technologies + self.total_sensitive_files,
        }


class ReconOrchestrator:
    """
    منسق الاستطلاع
    
    يدير كل أدوات المرحلة الأولى من الفحص
    """
    
    def __init__(self):
        self._dns = DNSEnumerator()
        self._crt = CRTShSearch()
        self._wayback = WaybackSearch()
        self._whois = WHOISLookup()
        self._fingerprinter = WappalyzerFingerprinter()
        self._cve_lookup = CVELookup()
        self._sensitive_scanner = SensitiveFilesScanner()
        self._metadata_analyzer = MetadataAnalyzer()
        self._report: Optional[ReconReport] = None
        
        logger.info("ReconOrchestrator initialized")
    
    async def execute(self, url: str, passive_only: bool = False) -> ReconReport:
        """
        تنفيذ الاستطلاع الكامل
        
        Args:
            url: رابط الهدف
            passive_only: استطلاع سلبي فقط (بدون لمس الهدف)
        
        Returns:
            تقرير الاستطلاع
        """
        from urllib.parse import urlparse
        
        parsed = urlparse(url)
        domain = parsed.netloc or parsed.hostname or url
        
        print(f"\n🔍 Reconnaissance Phase")
        print(f"{'='*60}")
        print(f"   Target: {domain}")
        
        self._report = ReconReport(target=domain)
        
        # 1. DNS Enumeration (Passive + Active)
        print(f"\n📡 Step 1: DNS Enumeration...")
        dns_results = await self._dns.enumerate(domain)
        self._report.dns_results = dns_results
        self._report.subdomains = dns_results.subdomains
        self._report.total_subdomains = len(dns_results.subdomains)
        
        
        # 2. CRT.sh Search (Passive)
        print(f"\n📜 Step 2: CRT.sh Certificate Search...")
        crt_results = await self._crt.search(domain)
        if crt_results.all_subdomains:
            for sub in crt_results.all_subdomains:
                if sub not in self._report.subdomains:
                    self._report.subdomains.append(sub)
            self._report.total_subdomains = len(self._report.subdomains)
        
        # 3. Wayback Machine Search (Passive)
        print(f"\n📚 Step 3: Wayback Machine Search...")
        wayback_results = await self._wayback.search(domain, limit=500)
        if wayback_results.subdomains:
            for sub in wayback_results.subdomains:
                if sub not in self._report.subdomains:
                    self._report.subdomains.append(sub)
            self._report.total_subdomains = len(self._report.subdomains)
        if wayback_results.sensitive_urls:
            for s in wayback_results.sensitive_urls[:5]:
                print(f"      🔑 {s.url[:80]}")
        if wayback_results.config_files:
            print(f"      ⚙️  Found {len(wayback_results.config_files)} config files")
        if wayback_results.backup_files:
            print(f"      💾 Found {len(wayback_results.backup_files)} backup files")
        
        # 4. WHOIS Lookup (Passive)
        print(f"\n📋 Step 4: WHOIS Lookup...")
        whois_results = await self._whois.lookup(domain)
        if whois_results.registrar:
            print(f"      Registrar: {whois_results.registrar}")
        if whois_results.creation_date:
            print(f"      Created: {whois_results.creation_date}")
        if whois_results.expiration_date:
            print(f"      Expires: {whois_results.expiration_date} ({whois_results.days_until_expiry} days)")
        if whois_results.is_expired:
            print(f"      ⚠️  DOMAIN IS EXPIRED!")
        
        # 5. Fingerprinting (Active)
        print(f"\n🔍 Step 5: Technology Fingerprinting...")
        fp_results = await self._fingerprinter.fingerprint(f"https://{domain}")
        if fp_results.technologies:
            self._report.technologies = [{"name": t.name, "category": t.category, "version": t.version, "confidence": t.confidence} for t in fp_results.technologies]
        
        # 7. Sensitive Files Discovery (Active)
        print(f"\n🔑 Step 7: Sensitive Files Discovery...")
        cms = ""
        if fp_results.technologies:
            for t in fp_results.technologies:
                if t.category == "CMS":
                    cms = t.name.lower()
                    break
        sensitive_results = await self._sensitive_scanner.scan(f"https://{domain}", cms_type=cms)
        if sensitive_results.files_found:
            self._report.sensitive_files = [{"url": f.url, "type": f.type, "severity": f.severity, "status": f.status_code} for f in sensitive_results.files_found]
        
        # 8. Metadata Analysis (Passive)
        print(f"\n📋 Step 8: Metadata Analysis...")
        try:
            async with httpx.AsyncClient(timeout=15, verify=False) as client:
                response = await client.get(f"https://{domain}")
                html = response.text if response.status_code == 200 else ""
            metadata_results = await self._metadata_analyzer.analyze(f"https://{domain}", html)
            if metadata_results.metadata_found:
                self._report.metadata_findings = [{"file": m.file_url, "type": m.file_type, "usernames": m.usernames, "emails": len(m.email_addresses)} for m in metadata_results.metadata_found]
        except Exception as e:
            logger.debug(f"Metadata analysis skipped: {e}")
            self._report.total_sensitive_files = len(sensitive_results.files_found)
            self._report.total_technologies = len(fp_results.technologies)
        
        # 6. CVE Lookup (Passive)
        if fp_results.technologies:
            print(f"\n🐛 Step 6: CVE Lookup...")
            for tech in fp_results.technologies[:5]:
                if tech.version:
                    cve_results = await self._cve_lookup.lookup(tech.name, tech.version)
                    if cve_results.total_cves > 0:
                        self._report.technologies.append({"name": tech.name, "cves": cve_results.total_cves, "critical": cve_results.critical_count})
        # عرض النتائج
        if dns_results.subdomains:
            print(f"\n   📋 Discovered Subdomains:")
            for sub in dns_results.subdomains[:10]:
                print(f"      - {sub}")
            if len(dns_results.subdomains) > 10:
                print(f"      ... and {len(dns_results.subdomains) - 10} more")
        
        if dns_results.nameservers:
            print(f"\n   🖧  Nameservers: {', '.join(dns_results.nameservers[:5])}")
        
        if dns_results.mail_servers:
            print(f"\n   📧 Mail Servers: {', '.join(dns_results.mail_servers[:3])}")
        
        if dns_results.zone_transfer_possible:
            print(f"\n   ⚠️  Zone Transfer possible!")
        
        print(f"\n{'='*60}")
        print(f"✅ Reconnaissance Complete!")
        print(f"   Subdomains: {self._report.total_subdomains}")
        
        return self._report
    
    def get_report(self) -> Optional[ReconReport]:
        return self._report


# نسخة عالمية
_recon_orchestrator = None

def get_recon_orchestrator() -> ReconOrchestrator:
    global _recon_orchestrator
    if _recon_orchestrator is None:
        _recon_orchestrator = ReconOrchestrator()
    return _recon_orchestrator
