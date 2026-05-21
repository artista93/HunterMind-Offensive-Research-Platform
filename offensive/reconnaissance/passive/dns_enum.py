"""
DNS Enumeration - اكتشاف النطاقات الفرعية عبر DNS
"""

import asyncio
import socket
import random
import string
import concurrent.futures
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field

import logging

logger = logging.getLogger(__name__)

# محاولة استيراد dnspython
try:
    import dns.resolver
    import dns.query
    import dns.zone
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False


@dataclass
class DNSRecord:
    domain: str
    record_type: str
    value: str
    ttl: int = 0


@dataclass
class DNSResult:
    domain: str
    records: List[DNSRecord] = field(default_factory=list)
    subdomains: List[str] = field(default_factory=list)
    nameservers: List[str] = field(default_factory=list)
    mail_servers: List[str] = field(default_factory=list)
    txt_records: List[str] = field(default_factory=list)
    has_wildcard: bool = False
    wildcard_ip: str = ""
    zone_transfer_possible: bool = False
    dnssec_enabled: bool = False
    errors: List[str] = field(default_factory=list)


class DNSEnumerator:
    
    COMMON_SUBDOMAINS = [
        "www", "mail", "ftp", "smtp", "pop", "imap", "ns1", "ns2",
        "admin", "administrator", "panel", "cp", "cpanel", "webmail",
        "dev", "development", "staging", "test", "testing", "uat", "qa",
        "beta", "alpha", "demo", "sandbox", "lab",
        "api", "app", "apps", "m", "mobile", "blog", "shop", "store",
        "cdn", "static", "assets", "media", "images", "img", "files",
        "vpn", "secure", "ssl", "auth", "sso", "login", "oauth",
        "status", "health", "monitor", "metrics", "logs",
        "db", "mysql", "postgres", "redis", "mongo",
        "jenkins", "git", "gitlab", "github", "build", "ci",
        "cloud", "aws", "s3", "storage",
        "remote", "portal", "help", "support", "docs", "wiki",
    ]
    
    def __init__(self):
        self._results: Dict[str, DNSResult] = {}
    
    async def enumerate(self, domain: str) -> DNSResult:
        print(f"  🔍 DNS Enumeration: {domain}")
        
        result = DNSResult(domain=domain)
        
        await self._get_dns_records(domain, result)
        
        if DNS_AVAILABLE:
            await self._try_zone_transfer(domain, result)
        
        await self._detect_wildcard(domain, result)
        await self._brute_force_subdomains(domain, result)
        
        if DNS_AVAILABLE:
            await self._check_dnssec(domain, result)
        
        print(f"     ✅ Found {len(result.subdomains)} subdomains, {len(result.records)} records")
        self._results[domain] = result
        return result
    
    async def _get_dns_records(self, domain: str, result: DNSResult):
        record_types = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SOA']
        
        if DNS_AVAILABLE:
            for rtype in record_types:
                try:
                    answers = dns.resolver.resolve(domain, rtype)
                    for answer in answers:
                        value = str(answer)
                        result.records.append(DNSRecord(domain=domain, record_type=rtype, value=value))
                        
                        if rtype == 'NS':
                            result.nameservers.append(value)
                        elif rtype == 'MX':
                            result.mail_servers.append(value)
                        elif rtype == 'TXT':
                            result.txt_records.append(value)
                except dns.resolver.NoAnswer:
                    pass
                except dns.resolver.NXDOMAIN:
                    result.errors.append(f"Domain {domain} not found")
                    return
                except Exception as e:
                    logger.debug(f"DNS {rtype} lookup failed: {e}")
        else:
            # Fallback: socket only
            try:
                ip = socket.gethostbyname(domain)
                result.records.append(DNSRecord(domain=domain, record_type='A', value=ip))
            except Exception as e:
                result.errors.append(f"DNS lookup failed: {e}")
    
    async def _try_zone_transfer(self, domain: str, result: DNSResult):
        if not result.nameservers:
            return
        
        for ns in result.nameservers[:3]:
            try:
                zone = dns.zone.from_xfr(dns.query.xfr(ns, domain, timeout=5))
                if zone:
                    result.zone_transfer_possible = True
                    for name, node in zone.nodes.items():
                        subdomain = str(name) + '.' + domain
                        if subdomain not in result.subdomains:
                            result.subdomains.append(subdomain)
                    break
            except:
                continue
    
    async def _detect_wildcard(self, domain: str, result: DNSResult):
        random_sub = ''.join(random.choices(string.ascii_lowercase + string.digits, k=20))
        test_domain = f"{random_sub}.{domain}"
        
        try:
            ip = socket.gethostbyname(test_domain)
            result.has_wildcard = True
            result.wildcard_ip = ip
        except:
            result.has_wildcard = False
    
    async def _brute_force_subdomains(self, domain: str, result: DNSResult):
        def check_subdomain(sub):
            try:
                full = f"{sub}.{domain}"
                ip = socket.gethostbyname(full)
                return full
            except:
                return None
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            futures = [executor.submit(check_subdomain, sub) for sub in self.COMMON_SUBDOMAINS]
            for future in concurrent.futures.as_completed(futures):
                subdomain = future.result()
                if subdomain and subdomain not in result.subdomains:
                    result.subdomains.append(subdomain)
    
    async def _check_dnssec(self, domain: str, result: DNSResult):
        try:
            answers = dns.resolver.resolve(domain, 'DNSKEY')
            result.dnssec_enabled = len(list(answers)) > 0
        except:
            result.dnssec_enabled = False


_dns_enumerator = None

def get_dns_enumerator() -> DNSEnumerator:
    global _dns_enumerator
    if _dns_enumerator is None:
        _dns_enumerator = DNSEnumerator()
    return _dns_enumerator
