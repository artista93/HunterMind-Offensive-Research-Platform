"""Vulnerability Repository - إدارة الثغرات في قاعدة البيانات"""
import json, logging
from typing import Dict, List, Optional, Any
from datetime import datetime

logger = logging.getLogger(__name__)

class VulnerabilityRepository:
    def __init__(self, db_client=None):
        self.db = db_client
        self._vulns: Dict[str, Dict] = {}
    
    async def save_vulnerability(self, vuln_data: Dict) -> str:
        vuln_id = vuln_data.get('id', vuln_data.get('vuln_id', f'vuln_{len(self._vulns)+1:03d}'))
        self._vulns[vuln_id] = vuln_data
        return vuln_id
    
    async def get_vulnerability(self, vuln_id: str) -> Optional[Dict]:
        return self._vulns.get(vuln_id)
    
    async def list_vulnerabilities(self, limit: int = 100, offset: int = 0,
                                   severity: str = None, vuln_type: str = None) -> List[Dict]:
        vulns = list(self._vulns.values())
        if severity:
            vulns = [v for v in vulns if v.get('severity') == severity]
        if vuln_type:
            vulns = [v for v in vulns if v.get('type') == vuln_type]
        vulns.sort(key=lambda x: str(x.get('discovered_at', '')), reverse=True)
        return vulns[offset:offset + limit]
    
    async def get_stats(self) -> Dict:
        vulns = list(self._vulns.values())
        by_severity = {}
        by_type = {}
        for v in vulns:
            sev = v.get('severity', 'unknown')
            typ = v.get('type', 'unknown')
            by_severity[sev] = by_severity.get(sev, 0) + 1
            by_type[typ] = by_type.get(typ, 0) + 1
        return {"total_vulnerabilities": len(vulns), "by_severity": by_severity, "by_type": by_type}
    
    async def search(self, query: str, limit: int = 20) -> List[Dict]:
        query_lower = query.lower()
        results = []
        for vuln in list(self._vulns.values()):
            if query_lower in json.dumps(vuln).lower():
                results.append(vuln)
                if len(results) >= limit: break
        return results
