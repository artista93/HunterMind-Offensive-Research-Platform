# datasets/attack_payloads/__init__.py

"""
Attack Payloads Dataset - مجموعة حمولات الهجوم
"""

import json
from pathlib import Path
from typing import Dict, Any, List

# المسار الأساسي
_PAYLOADS_DIR = Path(__file__).parent

# تحميل ملفات JSON
def _load_json(file_name: str) -> Dict[str, Any]:
    """تحميل ملف JSON من المجلد الحالي"""
    file_path = _PAYLOADS_DIR / file_name
    if file_path.exists():
        with open(file_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    return {}

# تحميل جميع الحمولات
RCE_PAYLOADS: Dict[str, Any] = _load_json("rce_payloads.json")
SQLI_PAYLOADS: Dict[str, Any] = _load_json("sqli_payloads.json")
XSS_PAYLOADS: Dict[str, Any] = _load_json("xss_payloads.json")

# الحصول على قائمة الحمولات فقط
def get_payloads(payload_type: str) -> List[Dict[str, Any]]:
    """
    استرجاع قائمة الحمولات حسب النوع
    
    Args:
        payload_type: أحد الأنواع 'rce', 'sqli', 'xss'
    
    Returns:
        قائمة الحمولات
    """
    payloads_map = {
        'rce': RCE_PAYLOADS,
        'sqli': SQLI_PAYLOADS,
        'xss': XSS_PAYLOADS,
    }
    
    data = payloads_map.get(payload_type, {})
    return data.get("payloads", [])

# جميع الحمولات مجتمعة
ALL_PAYLOADS = {
    'rce': RCE_PAYLOADS,
    'sqli': SQLI_PAYLOADS,
    'xss': XSS_PAYLOADS,
}

__all__ = [
    'RCE_PAYLOADS',
    'SQLI_PAYLOADS',
    'XSS_PAYLOADS',
    'get_payloads',
    'ALL_PAYLOADS',
]
