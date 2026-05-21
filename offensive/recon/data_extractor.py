"""
Data Extractor - مستخرج البيانات الحساسة من الصفحات

يستخرج ويعرض:
- الإيميلات المكتشفة
- المفاتيح والأسرار
- الـ tokens
- الـ internal URLs
- أخطاء البرمجة
"""

import re
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field

import logging

logger = logging.getLogger(__name__)


@dataclass
class ExtractedData:
    """بيانات مستخرجة"""
    data_type: str
    values: List[str]
    source_url: str
    count: int = 0
    
    def __post_init__(self):
        self.count = len(self.values)


class DataExtractor:
    """مستخرج البيانات الحساسة"""
    
    # أنماط الاستخراج
    PATTERNS = {
        "emails": {
            "pattern": r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            "type": "Email Addresses",
            "deduplicate": True,
        },
        "api_keys": {
            "pattern": r'(?:api[_-]?key|apikey|API_KEY)["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{16,})["\']',
            "type": "API Keys",
            "deduplicate": True,
        },
        "aws_keys": {
            "pattern": r'(?:AKIA|ASIA)[A-Z0-9]{16}',
            "type": "AWS Access Keys",
            "deduplicate": True,
        },
        "google_keys": {
            "pattern": r'AIza[0-9A-Za-z\-_]{35}',
            "type": "Google API Keys",
            "deduplicate": True,
        },
        "github_tokens": {
            "pattern": r'(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}',
            "type": "GitHub Tokens",
            "deduplicate": True,
        },
        "jwt_tokens": {
            "pattern": r'eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+',
            "type": "JWT Tokens",
            "deduplicate": True,
        },
        "internal_ips": {
            "pattern": r'\b(?:10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.)\d{1,3}\.\d{1,3}\b',
            "type": "Internal IPs",
            "deduplicate": True,
        },
        "internal_urls": {
            "pattern": r'https?://(?:localhost|127\.0\.0\.1|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})[^\s"\']*',
            "type": "Internal URLs",
            "deduplicate": True,
        },
        "database_urls": {
            "pattern": r'(?:mysql|postgres|postgresql|mongodb|redis|sqlite)://[^/\s]+:[^/\s]+@[^/\s]+',
            "type": "Database URLs",
            "deduplicate": True,
        },
        "webhooks": {
            "pattern": r'https://hooks\.(?:slack|discord|teams)\.com/[^\s"\']+',
            "type": "Webhook URLs",
            "deduplicate": True,
        },
        "stack_traces": {
            "pattern": r'(?:Stack trace:|Traceback \(most recent call last\):|Warning:.*on line \d+|Fatal error:.*on line \d+)',
            "type": "Error Messages",
            "deduplicate": False,
        },
        "php_info": {
            "pattern": r'(?:phpinfo\(\)|PHP Version \d+\.\d+\.\d+|mysql_\w+\(|mysqli_\w+\()',
            "type": "PHP Information",
            "deduplicate": True,
        },
    }
    
    def __init__(self):
        self._extracted: List[ExtractedData] = []
    
    def extract_from_response(self, url: str, body: str, headers: Dict = None) -> List[ExtractedData]:
        """استخراج كل البيانات من استجابة"""
        results = []
        
        for pattern_name, config in self.PATTERNS.items():
            matches = re.findall(config["pattern"], body, re.IGNORECASE | re.MULTILINE)
            
            if not matches:
                continue
            
            # تنظيف القيم
            values = []
            for match in matches:
                if isinstance(match, tuple):
                    match = match[0] if match[0] else match[-1]
                
                match = match.strip()
                
                # تجاهل false positives
                if self._is_false_positive(match):
                    continue
                
                if config["deduplicate"]:
                    if match not in values:
                        values.append(match)
                else:
                    values.append(match[:200])
            
            if values:
                extracted = ExtractedData(
                    data_type=config["type"],
                    values=values,
                    source_url=url,
                )
                results.append(extracted)
                self._extracted.append(extracted)
        
        return results
    
    def _is_false_positive(self, value: str) -> bool:
        """تجاهل القيم الوهمية"""
        false_keywords = [
            'example', 'test', 'xxx', 'todo', 'your-', 'replace',
            'YOUR_API_KEY', 'API_KEY_HERE', '<your', 'placeholder',
            'sample', 'demo', 'changeme', 'changethis',
        ]
        value_lower = value.lower()
        return any(kw in value_lower for kw in false_keywords)
    
    def print_extracted_data(self, results: List[ExtractedData]):
        """عرض البيانات المستخرجة"""
        if not results:
            return
        
        print(f"\n📊 Extracted Data:")
        print(f"{'='*60}")
        
        for data in results:
            print(f"\n  📌 {data.data_type} ({data.count} found)")
            print(f"     Source: {data.source_url[:80]}")
            
            # عرض القيم
            max_show = 10 if data.data_type == "Email Addresses" else 5
            for i, value in enumerate(data.values[:max_show]):
                # إخفاء جزء من المفاتيح للأمان
                if any(kw in data.data_type.lower() for kw in ['key', 'token', 'secret', 'jwt', 'password']):
                    if len(value) > 20:
                        display = value[:10] + "..." + value[-5:]
                    else:
                        display = value[:5] + "..."
                else:
                    display = value[:80]
                
                print(f"     {i+1}. {display}")
            
            if len(data.values) > max_show:
                print(f"     ... and {len(data.values) - max_show} more")
    
    def get_summary(self) -> Dict:
        """ملخص البيانات المستخرجة"""
        summary = {}
        for data in self._extracted:
            if data.data_type not in summary:
                summary[data.data_type] = {"count": 0, "sources": []}
            summary[data.data_type]["count"] += data.count
            if data.source_url not in summary[data.data_type]["sources"]:
                summary[data.data_type]["sources"].append(data.source_url)
        
        return {
            "total_types": len(summary),
            "types": summary,
        }
    
    def clear(self):
        self._extracted.clear()


_data_extractor = None

def get_data_extractor() -> DataExtractor:
    global _data_extractor
    if _data_extractor is None:
        _data_extractor = DataExtractor()
    return _data_extractor
