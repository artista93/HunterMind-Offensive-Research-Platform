"""Scan Repository - إدارة الفحوصات في قاعدة البيانات"""
import json, logging
from typing import Dict, List, Optional, Any
from datetime import datetime

logger = logging.getLogger(__name__)

class ScanRepository:
    def __init__(self, db_client=None):
        self.db = db_client
        self._scans: Dict[str, Dict] = {}
    
    async def save_scan(self, scan_data: Dict) -> str:
        scan_id = scan_data.get('scan_id', scan_data.get('id', f'scan_{len(self._scans)+1:03d}'))
        self._scans[scan_id] = scan_data
        return scan_id
    
    async def get_scan(self, scan_id: str) -> Optional[Dict]:
        return self._scans.get(scan_id)
    
    async def list_scans(self, limit: int = 50, offset: int = 0) -> List[Dict]:
        scans = list(self._scans.values())
        scans.sort(key=lambda x: str(x.get('date', '')), reverse=True)
        return scans[offset:offset + limit]
    
    async def get_stats(self) -> Dict:
        total = len(self._scans)
        completed = len([s for s in self._scans.values() if s.get('status') == 'completed'])
        return {"total_scans": total, "completed_scans": completed}
