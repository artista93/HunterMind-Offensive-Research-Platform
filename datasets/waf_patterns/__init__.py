# datasets/waf_patterns/__init__.py

"""
WAF Patterns Dataset - مجموعة أنماط جدران الحماية
"""

import json
from pathlib import Path
from typing import Dict, Any, List, Optional

# المسار الأساسي
_WAF_DIR = Path(__file__).parent

# تحميل ملف JSON
def _load_json(file_name: str) -> Dict[str, Any]:
    """تحميل ملف JSON من المجلد الحالي"""
    file_path = _WAF_DIR / file_name
    if file_path.exists():
        with open(file_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    return {}

# تحميل بيانات أنماط WAF
WAF_DATA: Dict[str, Any] = _load_json("patterns.json")

def get_wafs() -> Dict[str, Any]:
    """
    استرجاع جميع أنماط WAF
    
    Returns:
        قاموس جميع WAFs مع أنماطهم
    """
    return WAF_DATA.get("wafs", {})

def get_waf_names() -> List[str]:
    """
    استرجاع أسماء جميع WAFs
    
    Returns:
        قائمة بأسماء WAFs
    """
    return list(get_wafs().keys())

def get_waf_patterns(waf_name: str) -> Optional[Dict[str, Any]]:
    """
    استرجاع أنماط WAF محدد
    
    Args:
        waf_name: اسم WAF (مثل 'Cloudflare', 'AWS WAF')
    
    Returns:
        أنماط WAF أو None
    """
    wafs = get_wafs()
    return wafs.get(waf_name)

def detect_waf_by_header(header_name: str) -> List[str]:
    """
    اكتشاف WAF محتمل بناءً على اسم الهيدر
    
    Args:
        header_name: اسم الهيدر
    
    Returns:
        قائمة بأسماء WAFs التي تطابق هذا الهيدر
    """
    detected = []
    for waf_name, patterns in get_wafs().items():
        headers = patterns.get("headers", [])
        if header_name in headers:
            detected.append(waf_name)
    return detected

def detect_waf_by_cookie(cookie_name: str) -> List[str]:
    """
    اكتشاف WAF محتمل بناءً على اسم الكوكي
    
    Args:
        cookie_name: اسم الكوكي
    
    Returns:
        قائمة بأسماء WAFs التي تطابق هذا الكوكي
    """
    detected = []
    for waf_name, patterns in get_wafs().items():
        cookies = patterns.get("cookies", [])
        if cookie_name in cookies:
            detected.append(waf_name)
    return detected

def detect_waf_by_response(response_text: str) -> List[str]:
    """
    اكتشاف WAF محتمل بناءً على نص الاستجابة
    
    Args:
        response_text: نص الاستجابة
    
    Returns:
        قائمة بأسماء WAFs التي تطابق هذا النص
    """
    detected = []
    response_text_lower = response_text.lower()
    
    for waf_name, patterns in get_wafs().items():
        responses = patterns.get("response", [])
        for resp in responses:
            if resp.lower() in response_text_lower:
                detected.append(waf_name)
                break
    
    return detected

__all__ = [
    'WAF_DATA',
    'get_wafs',
    'get_waf_names',
    'get_waf_patterns',
    'detect_waf_by_header',
    'detect_waf_by_cookie',
    'detect_waf_by_response',
]
