# datasets/vulnerable_apps/__init__.py

"""
Vulnerable Apps Dataset - مجموعة التطبيقات الضعيفة للاختبار
"""

import json
from pathlib import Path
from typing import Dict, Any, List, Optional

# المسار الأساسي
_APPS_DIR = Path(__file__).parent

# تحميل ملف JSON
def _load_json(file_name: str) -> Dict[str, Any]:
    """تحميل ملف JSON من المجلد الحالي"""
    file_path = _APPS_DIR / file_name
    if file_path.exists():
        with open(file_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    return {}

# تحميل بيانات التطبيقات
APPS_DATA: Dict[str, Any] = _load_json("apps.json")

def get_applications() -> List[Dict[str, Any]]:
    """
    استرجاع قائمة التطبيقات الضعيفة
    
    Returns:
        قائمة التطبيقات
    """
    return APPS_DATA.get("applications", [])

def get_app_by_name(name: str) -> Optional[Dict[str, Any]]:
    """
    البحث عن تطبيق بالاسم
    
    Args:
        name: اسم التطبيق
    
    Returns:
        بيانات التطبيق أو None
    """
    for app in get_applications():
        if app.get("name") == name:
            return app
    return None

def get_apps_by_vulnerability(vuln_type: str) -> List[Dict[str, Any]]:
    """
    تصفية التطبيقات حسب نوع الثغرة
    
    Args:
        vuln_type: نوع الثغرة (مثل 'SQLi', 'XSS')
    
    Returns:
        قائمة التطبيقات التي تحتوي على هذه الثغرة
    """
    return [
        app for app in get_applications()
        if vuln_type in app.get("vulnerabilities", [])
    ]

def get_app_url(name: str) -> Optional[str]:
    """
    الحصول على URL التطبيق بالاسم
    
    Args:
        name: اسم التطبيق
    
    Returns:
        URL التطبيق أو None
    """
    app = get_app_by_name(name)
    return app.get("url") if app else None

def get_app_credentials(name: str) -> Optional[Dict[str, str]]:
    """
    الحصول على بيانات اعتماد التطبيق
    
    Args:
        name: اسم التطبيق
    
    Returns:
        قاموس username/password أو None
    """
    app = get_app_by_name(name)
    return app.get("credentials") if app else None

__all__ = [
    'APPS_DATA',
    'get_applications',
    'get_app_by_name',
    'get_apps_by_vulnerability',
    'get_app_url',
    'get_app_credentials',
]
