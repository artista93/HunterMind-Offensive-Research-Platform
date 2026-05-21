"""
WHOIS Lookup - معلومات تسجيل النطاق

يستخدم WHOIS protocol و APIs للبحث عن:
- مالك النطاق (Registrant)
- تاريخ التسجيل والانتهاء
- Nameservers
- تفاصيل الاتصال (إذا كانت متاحة)
- Registrar المعلومات
"""

import asyncio
import re
import socket
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime

import httpx
import logging

logger = logging.getLogger(__name__)


@dataclass
class WHOISInfo:
    """معلومات WHOIS"""
    domain: str
    registrar: str = ""
    registrant_name: str = ""
    registrant_organization: str = ""
    registrant_email: str = ""
    registrant_country: str = ""
    creation_date: str = ""
    expiration_date: str = ""
    updated_date: str = ""
    nameservers: List[str] = field(default_factory=list)
    status: List[str] = field(default_factory=list)
    dnssec: str = ""
    raw_text: str = ""
    is_expired: bool = False
    days_until_expiry: int = 0
    privacy_enabled: bool = False
    errors: List[str] = field(default_factory=list)


class WHOISLookup:
    """
    البحث في WHOIS عن معلومات النطاق
    
    يدعم:
    - WHOIS protocol (port 43)
    - RDAP (Registration Data Access Protocol)
    - whois.com API
    """
    
    # خوادم WHOIS حسب TLD
    WHOIS_SERVERS = {
        "com": "whois.verisign-grs.com",
        "net": "whois.verisign-grs.com",
        "org": "whois.pir.org",
        "io": "whois.nic.io",
        "co": "whois.nic.co",
        "uk": "whois.nic.uk",
        "de": "whois.denic.de",
        "fr": "whois.nic.fr",
        "ru": "whois.tcinet.ru",
        "br": "whois.registro.br",
        "in": "whois.registry.in",
        "me": "whois.nic.me",
        "tv": "whois.nic.tv",
        "gg": "whois.gg",
        "dev": "whois.nic.google",
        "app": "whois.nic.google",
        "ai": "whois.nic.ai",
        "sh": "whois.nic.sh",
    }
    
    def __init__(self):
        self._results: Dict[str, WHOISInfo] = {}
    
    async def lookup(self, domain: str) -> WHOISInfo:
        """
        البحث في WHOIS
        
        Args:
            domain: النطاق المراد البحث عنه
        
        Returns:
            WHOISInfo مع كل المعلومات
        """
        print(f"  📋 WHOIS Lookup: {domain}")
        
        result = WHOISInfo(domain=domain)
        
        try:
            # 1. RDAP API (الأحدث)
            await self._query_rdap(domain, result)
            
            # 2. WHOIS Protocol (fallback)
            if not result.registrar:
                await self._query_whois(domain, result)
            
            # 3. تحليل النتائج
            self._analyze_result(result)
            
            # عرض النتائج
            if result.registrar:
                print(f"     ✅ Registrar: {result.registrar}")
            if result.creation_date:
                print(f"     📅 Created: {result.creation_date}")
            if result.expiration_date:
                print(f"     ⏰ Expires: {result.expiration_date}")
                print(f"     📆 Days left: {result.days_until_expiry}")
            if result.privacy_enabled:
                print(f"     🔒 Privacy: Enabled")
            if result.nameservers:
                print(f"     🖧  NS: {', '.join(result.nameservers[:3])}")
            if result.is_expired:
                print(f"     ⚠️  Domain is EXPIRED!")
        
        except Exception as e:
            result.errors.append(str(e))
            logger.debug(f"WHOIS lookup failed: {e}")
        
        self._results[domain] = result
        return result
    
    async def _query_rdap(self, domain: str, result: WHOISInfo):
        """استخدام RDAP API"""
        try:
            async with httpx.AsyncClient(timeout=15, verify=False) as client:
                # RDAP لـ Verisign (com, net)
                tld = domain.split('.')[-1].lower()
                
                if tld in ['com', 'net']:
                    url = f"https://rdap.verisign.com/{tld}/v1/domain/{domain}"
                else:
                    url = f"https://rdap-bootstrap.arin.net/registry/domain/{domain}"
                
                response = await client.get(url)
                
                if response.status_code == 200:
                    data = response.json()
                    
                    # Registrar
                    result.registrar = data.get("ldhName", "")
                    
                    # Dates
                    events = data.get("events", [])
                    for event in events:
                        action = event.get("eventAction", "")
                        date_str = event.get("eventDate", "")[:10]
                        
                        if action == "registration":
                            result.creation_date = date_str
                        elif action == "expiration":
                            result.expiration_date = date_str
                        elif action == "last changed":
                            result.updated_date = date_str
                    
                    # Nameservers
                    ns_data = data.get("nameservers", [])
                    for ns in ns_data:
                        name = ns.get("ldhName", "") or ns.get("objectClassName", "")
                        if name:
                            result.nameservers.append(name)
                    
                    # Status
                    status_data = data.get("status", [])
                    result.status = status_data
                    
                    # Registrant
                    entities = data.get("entities", [])
                    for entity in entities:
                        roles = entity.get("roles", [])
                        if "registrant" in roles:
                            vcard = entity.get("vcardArray", [[], []])
                            if len(vcard) > 1:
                                for prop in vcard[1]:
                                    if len(prop) >= 4:
                                        ptype = prop[0]
                                        pvalue = prop[3]
                                        if ptype == "fn":
                                            result.registrant_name = pvalue
                                        elif ptype == "org":
                                            result.registrant_organization = pvalue
                                        elif ptype == "email":
                                            result.registrant_email = pvalue
                
        except Exception as e:
            logger.debug(f"RDAP failed: {e}")
    
    async def _query_whois(self, domain: str, result: WHOISInfo):
        """استخدام WHOIS Protocol (port 43)"""
        tld = domain.split('.')[-1].lower()
        server = self.WHOIS_SERVERS.get(tld, "whois.iana.org")
        
        try:
            # استخدام socket للتواصل مع خادم WHOIS
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((server, 43))
            
            # إرسال الاستعلام
            query = f"{domain}\r\n"
            sock.send(query.encode())
            
            # استقبال الرد
            response = b""
            while True:
                try:
                    data = sock.recv(4096)
                    if not data:
                        break
                    response += data
                except socket.timeout:
                    break
            
            sock.close()
            
            result.raw_text = response.decode('utf-8', errors='ignore')
            
            # استخراج المعلومات من النص
            self._parse_whois_text(result.raw_text, result)
            
        except Exception as e:
            logger.debug(f"WHOIS protocol failed: {e}")
    
    def _parse_whois_text(self, text: str, result: WHOISInfo):
        """استخراج المعلومات من نص WHOIS"""
        patterns = {
            "registrar": [
                r'Registrar:\s*(.+)',
                r'Registrar Name:\s*(.+)',
                r'Sponsoring Registrar:\s*(.+)',
            ],
            "creation_date": [
                r'Creation Date:\s*(.+)',
                r'Created:\s*(.+)',
                r'Registration Date:\s*(.+)',
            ],
            "expiration_date": [
                r'Registry Expiry Date:\s*(.+)',
                r'Expiry Date:\s*(.+)',
                r'Expiration Date:\s*(.+)',
            ],
            "registrant_name": [
                r'Registrant Name:\s*(.+)',
                r'Registrant:\s*(.+)',
            ],
            "registrant_organization": [
                r'Registrant Organization:\s*(.+)',
                r'Registrant Org:\s*(.+)',
            ],
            "registrant_email": [
                r'Registrant Email:\s*(.+)',
                r'Admin Email:\s*(.+)',
            ],
            "registrant_country": [
                r'Registrant Country:\s*(.+)',
                r'Country:\s*(.+)',
            ],
        }
        
        for field, field_patterns in patterns.items():
            for pattern in field_patterns:
                match = re.search(pattern, text, re.IGNORECASE)
                if match:
                    value = match.group(1).strip()
                    if value and value != "REDACTED FOR PRIVACY":
                        setattr(result, field, value)
                    break
        
        # Nameservers
        ns_pattern = r'Name Server:\s*(.+)'
        ns_matches = re.findall(ns_pattern, text, re.IGNORECASE)
        result.nameservers = list(set(ns.strip().lower() for ns in ns_matches if ns.strip()))
        
        # Status
        status_pattern = r'Domain Status:\s*(.+)'
        result.status = re.findall(status_pattern, text, re.IGNORECASE)
    
    def _analyze_result(self, result: WHOISInfo):
        """تحليل النتائج"""
        # فحص الخصوصية
        privacy_indicators = [
            "REDACTED FOR PRIVACY",
            "Privacy Protect",
            "WhoisGuard",
            "Domains By Proxy",
            "Contact Privacy",
        ]
        
        for indicator in privacy_indicators:
            if indicator.lower() in result.raw_text.lower():
                result.privacy_enabled = True
                break
        
        # حساب الأيام المتبقية
        if result.expiration_date:
            try:
                from datetime import datetime as dt
                # محاولة تحليل التاريخ
                for fmt in ["%Y-%m-%d", "%Y-%m-%dT%H:%M:%SZ", "%d-%b-%Y", "%Y.%m.%d"]:
                    try:
                        exp_date = dt.strptime(result.expiration_date[:10], fmt[:10])
                        delta = exp_date - dt.now()
                        result.days_until_expiry = delta.days
                        result.is_expired = delta.days < 0
                        break
                    except:
                        continue
            except:
                pass
    
    def get_results(self, domain: str) -> Optional[WHOISInfo]:
        return self._results.get(domain)


# نسخة عالمية
_whois_lookup = None

def get_whois_lookup() -> WHOISLookup:
    global _whois_lookup
    if _whois_lookup is None:
        _whois_lookup = WHOISLookup()
    return _whois_lookup
