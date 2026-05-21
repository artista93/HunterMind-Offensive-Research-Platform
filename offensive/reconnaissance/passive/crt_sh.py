"""
crt.sh Certificate Search - اكتشاف النطاقات الفرعية عبر شهادات SSL

يستخدم crt.sh API للبحث عن:
- كل الشهادات المرتبطة بالنطاق
- النطاقات الفرعية الموجودة في الشهادات
- نطاقات إضافية من SAN (Subject Alternative Names)
- شهادات منتهية أو قديمة
"""

import asyncio
import re
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime

import httpx
import logging

logger = logging.getLogger(__name__)


@dataclass
class CertificateInfo:
    """معلومات شهادة SSL"""
    id: str
    issuer: str
    issued_at: str
    expires_at: str
    domains: List[str] = field(default_factory=list)
    subdomains: List[str] = field(default_factory=list)


@dataclass
class CRTResult:
    """نتائج البحث في crt.sh"""
    domain: str
    total_certificates: int = 0
    certificates: List[CertificateInfo] = field(default_factory=list)
    all_subdomains: List[str] = field(default_factory=list)
    unique_domains: List[str] = field(default_factory=list)
    wildcard_domains: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


class CRTShSearch:
    """
    البحث في crt.sh عن شهادات SSL
    
    crt.sh هو قاعدة بيانات مجانية لشهادات SSL
    يديرها Sectigo (Comodo سابقاً)
    """
    
    API_URL = "https://crt.sh/"
    
    def __init__(self):
        self._results: Dict[str, CRTResult] = {}
    
    async def search(self, domain: str) -> CRTResult:
        """
        البحث عن شهادات النطاق
        
        Args:
            domain: النطاق المراد البحث عنه
        
        Returns:
            CRTResult مع كل الشهادات والنطاقات
        """
        print(f"  🔒 Searching crt.sh: {domain}")
        
        result = CRTResult(domain=domain)
        
        try:
            # استخدام API الـ JSON
            certificates = await self._fetch_certificates_json(domain)
            
            # لو فشل JSON، نجرب HTML
            if not certificates:
                certificates = await self._fetch_certificates_html(domain)
            
            # استخراج النطاقات الفرعية
            all_subdomains = set()
            wildcard_domains = set()
            
            for cert in certificates:
                result.certificates.append(cert)
                
                for sub in cert.subdomains:
                    sub_clean = sub.strip().lower()
                    # تجاهل النطاقات غير المرتبطة
                    if domain in sub_clean and sub_clean != domain:
                        all_subdomains.add(sub_clean)
                        
                        # كشف wildcard
                        if sub_clean.startswith('*.'):
                            wildcard_domains.add(sub_clean)
            
            result.all_subdomains = sorted(list(all_subdomains))
            result.wildcard_domains = sorted(list(wildcard_domains))
            result.total_certificates = len(certificates)
            
            print(f"     ✅ Found {len(result.all_subdomains)} subdomains from {result.total_certificates} certificates")
            
        except Exception as e:
            result.errors.append(str(e))
            logger.debug(f"crt.sh search failed: {e}")
        
        self._results[domain] = result
        return result
    
    async def _fetch_certificates_json(self, domain: str) -> List[CertificateInfo]:
        """جلب الشهادات عبر JSON API"""
        certificates = []
        
        try:
            async with httpx.AsyncClient(timeout=30, verify=False) as client:
                # طلب JSON
                params = {
                    "q": f"%.{domain}",
                    "output": "json",
                    "exclude": "expired",
                }
                
                response = await client.get(self.API_URL, params=params)
                
                if response.status_code == 200:
                    data = response.json()
                    
                    # تجميع حسب الـ ID
                    certs_by_id = {}
                    for entry in data:
                        cert_id = entry.get("id")
                        if cert_id not in certs_by_id:
                            certs_by_id[cert_id] = {
                                "id": cert_id,
                                "issuer": entry.get("issuer_name", ""),
                                "issued_at": entry.get("not_before", ""),
                                "expires_at": entry.get("not_after", ""),
                                "domains": []
                            }
                        
                        name = entry.get("name_value", "")
                        if name:
                            certs_by_id[cert_id]["domains"].append(name)
                    
                    # تحويل إلى CertificateInfo
                    for cert_data in certs_by_id.values():
                        domains = cert_data["domains"]
                        cert = CertificateInfo(
                            id=str(cert_data["id"]),
                            issuer=cert_data["issuer"],
                            issued_at=cert_data["issued_at"],
                            expires_at=cert_data["expires_at"],
                            domains=domains,
                            subdomains=list(set(domains)),
                        )
                        certificates.append(cert)
        
        except Exception as e:
            logger.debug(f"JSON fetch failed: {e}")
        
        return certificates
    
    async def _fetch_certificates_html(self, domain: str) -> List[CertificateInfo]:
        """جلب الشهادات عبر HTML (fallback)"""
        certificates = []
        
        try:
            async with httpx.AsyncClient(timeout=30, verify=False) as client:
                params = {"q": f"%.{domain}"}
                response = await client.get(self.API_URL, params=params)
                
                if response.status_code == 200:
                    # استخراج النطاقات من HTML
                    # النمط: <TD style="text-align:center">domain.com</TD>
                    domain_pattern = re.compile(r'<TD[^>]*>([a-zA-Z0-9\*\.\-]+(?:\.' + re.escape(domain) + r')[^<]*)</TD>', re.I)
                    matches = domain_pattern.findall(response.text)
                    
                    if matches:
                        unique_domains = list(set(m.strip().lower() for m in matches))
                        cert = CertificateInfo(
                            id="html",
                            issuer="",
                            issued_at="",
                            expires_at="",
                            domains=unique_domains,
                            subdomains=unique_domains,
                        )
                        certificates.append(cert)
        
        except Exception as e:
            logger.debug(f"HTML fetch failed: {e}")
        
        return certificates
    
    def get_results(self, domain: str) -> Optional[CRTResult]:
        return self._results.get(domain)
    
    def get_all_subdomains(self, domain: str) -> List[str]:
        result = self._results.get(domain)
        return result.all_subdomains if result else []


# نسخة عالمية
_crt_search = None

def get_crt_search() -> CRTShSearch:
    global _crt_search
    if _crt_search is None:
        _crt_search = CRTShSearch()
    return _crt_search
