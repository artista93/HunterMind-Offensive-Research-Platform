"""
CVE Lookup - البحث عن ثغرات معروفة في التقنيات المكتشفة

يستخدم:
- NVD (National Vulnerability Database)
- CVE API
- قاعدة بيانات محلية للثغرات الشائعة
- CVSS scores
- Exploit-DB references
"""

import asyncio
import re
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field

import httpx
import logging

logger = logging.getLogger(__name__)


@dataclass
class CVEInfo:
    """معلومات ثغرة CVE"""
    cve_id: str
    description: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    cvss_score: float = 0.0
    published_date: str = ""
    affected_versions: List[str] = field(default_factory=list)
    exploit_available: bool = False
    exploit_url: str = ""
    references: List[str] = field(default_factory=list)
    cwe_id: str = ""


@dataclass
class CVEResult:
    """نتائج البحث عن CVEs"""
    technology: str
    version: str
    total_cves: int = 0
    cves: List[CVEInfo] = field(default_factory=list)
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    errors: List[str] = field(default_factory=list)


class CVELookup:
    """
    البحث عن ثغرات CVE للتقنيات المكتشفة
    
    يبحث في:
    - NVD API
    - قاعدة بيانات محلية
    - Exploit-DB
    """
    
    NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    # قاعدة بيانات محلية للثغرات الشائعة (مبسطة)
    KNOWN_CVES = {
        "WordPress": {
            "5.0": [
                {"id": "CVE-2019-8942", "severity": "HIGH", "cvss": 8.8, "desc": "Remote Code Execution via crop-image"},
                {"id": "CVE-2019-8943", "severity": "HIGH", "cvss": 8.8, "desc": "Path Traversal in crop-image"},
            ],
            "4.0": [
                {"id": "CVE-2017-8295", "severity": "HIGH", "cvss": 7.5, "desc": "Unauthorized Password Reset"},
            ],
        },
        "Drupal": {
            "8.0": [
                {"id": "CVE-2018-7600", "severity": "CRITICAL", "cvss": 9.8, "desc": "Drupalgeddon2 - Remote Code Execution"},
                {"id": "CVE-2019-6340", "severity": "CRITICAL", "cvss": 9.8, "desc": "REST API Remote Code Execution"},
            ],
            "7.0": [
                {"id": "CVE-2014-3704", "severity": "CRITICAL", "cvss": 10.0, "desc": "Drupalgeddon - SQL Injection"},
            ],
        },
        "Joomla": {
            "3.0": [
                {"id": "CVE-2015-8562", "severity": "CRITICAL", "cvss": 9.8, "desc": "Remote Code Execution via User-Agent"},
            ],
        },
        "Apache": {
            "2.4": [
                {"id": "CVE-2021-41773", "severity": "CRITICAL", "cvss": 9.8, "desc": "Path Traversal and RCE"},
                {"id": "CVE-2021-42013", "severity": "CRITICAL", "cvss": 9.8, "desc": "Path Traversal"},
            ],
        },
        "Nginx": {
            "1": [
                {"id": "CVE-2017-7529", "severity": "HIGH", "cvss": 7.5, "desc": "Integer Overflow Information Disclosure"},
            ],
        },
        "PHP": {
            "7.0": [
                {"id": "CVE-2019-11043", "severity": "CRITICAL", "cvss": 9.8, "desc": "PHP-FPM Remote Code Execution"},
            ],
            "5.0": [
                {"id": "CVE-2012-1823", "severity": "CRITICAL", "cvss": 9.8, "desc": "PHP-CGI Remote Code Execution"},
            ],
        },
        "Laravel": {
            "8.0": [
                {"id": "CVE-2021-3129", "severity": "CRITICAL", "cvss": 9.8, "desc": "Ignition Remote Code Execution"},
            ],
        },
        "Django": {
            "3.0": [
                {"id": "CVE-2022-34265", "severity": "CRITICAL", "cvss": 9.8, "desc": "Trunc(kind) SQL Injection"},
            ],
        },
        "jQuery": {
            "3.0": [
                {"id": "CVE-2020-11023", "severity": "MEDIUM", "cvss": 6.1, "desc": "XSS in jQuery.htmlPrefilter"},
            ],
        },
    }
    
    def __init__(self):
        self._results: Dict[str, CVEResult] = {}
    
    async def lookup(self, technology: str, version: str = "") -> CVEResult:
        """
        البحث عن CVEs لتقنية محددة
        
        Args:
            technology: اسم التقنية
            version: الإصدار
        
        Returns:
            CVEResult مع الثغرات المكتشفة
        """
        print(f"  🐛 CVE Lookup: {technology} {version}")
        
        result = CVEResult(technology=technology, version=version)
        
        try:
            # 1. البحث في قاعدة البيانات المحلية
            local_cves = self._search_local_db(technology, version)
            if local_cves:
                result.cves.extend(local_cves)
            
            # 2. البحث في NVD API
            api_cves = await self._search_nvd_api(technology, version)
            if api_cves:
                for cve in api_cves:
                    if cve.cve_id not in [c.cve_id for c in result.cves]:
                        result.cves.append(cve)
            
            # 3. إحصائيات
            result.total_cves = len(result.cves)
            for cve in result.cves:
                if cve.severity == "CRITICAL":
                    result.critical_count += 1
                elif cve.severity == "HIGH":
                    result.high_count += 1
                elif cve.severity == "MEDIUM":
                    result.medium_count += 1
                elif cve.severity == "LOW":
                    result.low_count += 1
            
            if result.total_cves > 0:
                print(f"     ⚠️  Found {result.total_cves} CVEs ({result.critical_count} CRITICAL)")
                for cve in result.cves[:3]:
                    print(f"     🔴 {cve.cve_id}: {cve.desc[:80]} (CVSS: {cve.cvss})")
        
        except Exception as e:
            result.errors.append(str(e))
            logger.debug(f"CVE lookup failed: {e}")
        
        self._results[f"{technology}@{version}"] = result
        return result
    
    def _search_local_db(self, technology: str, version: str) -> List[CVEInfo]:
        """البحث في قاعدة البيانات المحلية"""
        cves = []
        
        # تطابق تام
        if technology in self.KNOWN_CVES:
            tech_cves = self.KNOWN_CVES[technology]
            
            # تطابق الإصدار
            for ver_pattern, ver_cves in tech_cves.items():
                if self._version_matches(version, ver_pattern):
                    for cve_data in ver_cves:
                        cves.append(CVEInfo(
                            cve_id=cve_data["id"],
                            description=cve_data["desc"],
                            severity=cve_data["severity"],
                            cvss_score=cve_data["cvss"],
                        ))
                    break
        
        # تطابق جزئي (لو الإصدار مش معروف)
        if not cves:
            for tech_name, tech_cves in self.KNOWN_CVES.items():
                if technology.lower() in tech_name.lower() or tech_name.lower() in technology.lower():
                    for ver_cves in tech_cves.values():
                        for cve_data in ver_cves[:5]:
                            cves.append(CVEInfo(
                                cve_id=cve_data["id"],
                                description=cve_data["desc"],
                                severity=cve_data["severity"],
                                cvss_score=cve_data["cvss"],
                            ))
                    break
        
        return cves
    
    def _version_matches(self, actual_version: str, pattern_version: str) -> bool:
        """مقارنة الإصدارات"""
        if not actual_version or not pattern_version:
            return True  # لو مفيش إصدار، نعتبره متطابق
        
        # استخراج major version
        actual_major = re.search(r'^(\d+)', actual_version)
        pattern_major = re.search(r'^(\d+)', pattern_version)
        
        if actual_major and pattern_major:
            return actual_major.group(1) == pattern_major.group(1)
        
        return pattern_version in actual_version
    
    async def _search_nvd_api(self, technology: str, version: str) -> List[CVEInfo]:
        """البحث في NVD API"""
        cves = []
        
        try:
            async with httpx.AsyncClient(timeout=30, verify=False) as client:
                # بناء استعلام البحث
                keyword = f"{technology}"
                if version:
                    keyword += f" {version}"
                
                params = {
                    "keywordSearch": keyword,
                    "resultsPerPage": 10,
                }
                
                response = await client.get(self.NVD_API, params=params)
                
                if response.status_code == 200:
                    data = response.json()
                    
                    vulnerabilities = data.get("vulnerabilities", [])
                    for vuln in vulnerabilities:
                        cve_data = vuln.get("cve", {})
                        cve_id = cve_data.get("id", "")
                        
                        # الوصف
                        descriptions = cve_data.get("descriptions", [])
                        desc = ""
                        for d in descriptions:
                            if d.get("lang") == "en":
                                desc = d.get("value", "")[:200]
                                break
                        
                        # CVSS score
                        metrics = cve_data.get("metrics", {})
                        cvss_score = 0.0
                        severity = "UNKNOWN"
                        
                        # CVSS v3
                        cvss_v3 = metrics.get("cvssMetricV31", []) or metrics.get("cvssMetricV30", [])
                        if cvss_v3:
                            cvss_data = cvss_v3[0].get("cvssData", {})
                            cvss_score = cvss_data.get("baseScore", 0.0)
                            severity = cvss_data.get("baseSeverity", "UNKNOWN").upper()
                        
                        # CVSS v2 (fallback)
                        if cvss_score == 0.0:
                            cvss_v2 = metrics.get("cvssMetricV2", [])
                            if cvss_v2:
                                cvss_data = cvss_v2[0].get("cvssData", {})
                                cvss_score = cvss_data.get("baseScore", 0.0)
                                severity = "HIGH" if cvss_score >= 7 else "MEDIUM" if cvss_score >= 4 else "LOW"
                        
                        cves.append(CVEInfo(
                            cve_id=cve_id,
                            description=desc,
                            severity=severity,
                            cvss_score=cvss_score,
                        ))
        
        except Exception as e:
            logger.debug(f"NVD API failed: {e}")
        
        return cves
    
    def get_results(self, tech: str, version: str) -> Optional[CVEResult]:
        return self._results.get(f"{tech}@{version}")


# نسخة عالمية
_cve_lookup = None

def get_cve_lookup() -> CVELookup:
    global _cve_lookup
    if _cve_lookup is None:
        _cve_lookup = CVELookup()
    return _cve_lookup
