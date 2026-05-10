
import re
import json
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

import logging

logger = logging.getLogger(__name__)


class PrivilegeLevel(Enum):
    """مستويات الصلاحية"""
    GUEST = 0
    USER = 1
    MODERATOR = 2
    ADMIN = 3
    SUPER_ADMIN = 4


@dataclass
class UserPrivilege:
    """صلاحيات المستخدم"""
    user_id: str
    username: Optional[str] = None
    role: str = "user"
    level: PrivilegeLevel = PrivilegeLevel.USER
    permissions: List[str] = field(default_factory=list)
    detected_at: datetime = field(default_factory=datetime.now)
    source: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PrivilegeEscalationPath:
    """مسار رفع الصلاحية"""
    from_user: str
    to_user: str
    from_level: PrivilegeLevel
    to_level: PrivilegeLevel
    method: str  # idor, parameter_injection, role_switching
    endpoint: str
    vulnerability_id: Optional[str] = None
    detected_at: datetime = field(default_factory=datetime.now)


class PrivilegeAnalyzer:
    """
    محلل الصلاحيات المتقدم
    
    الميزات:
    - كشف صلاحيات المستخدمين
    - تحليل إمكانيات رفع الصلاحية
    - كشف الـ Admin endpoints
    - تحليل نماذج تغيير الصلاحيات
    - تحديد المسارات الحرجة
    """
    
    # أنماط كشف الصلاحيات
    ROLE_PATTERNS = {
        "admin": [r'admin', r'administrator', r'superuser', r'root'],
        "moderator": [r'moderator', r'mod', r'editor'],
        "user": [r'user', r'member', r'customer'],
        "guest": [r'guest', r'anonymous', r'visitor'],
    }
    
    # أنماط كشف endpoints الصلاحيات
    PRIVILEGE_ENDPOINTS = [
        r'/admin',
        r'/administrator',
        r'/manage',
        r'/users?/role',
        r'/users?/permission',
        r'/api/admin',
        r'/api/users?/role',
        r'/set-role',
        r'/change-role',
        r'/make-admin',
        r'/grant-permission',
        r'/privilege',
    ]
    
    def __init__(self):
        self._user_privileges: Dict[str, UserPrivilege] = {}
        self._escalation_paths: List[PrivilegeEscalationPath] = []
        self._privileged_endpoints: Set[str] = set()
        
        logger.info("PrivilegeAnalyzer initialized")
    
    async def analyze_user_privileges(
        self,
        user_id: str,
        response_data: Dict[str, Any],
        source: str = ""
    ) -> UserPrivilege:
        """
        تحليل صلاحيات المستخدم من البيانات
        
        Args:
            user_id: معرف المستخدم
            response_data: بيانات الاستجابة
            source: مصدر البيانات
        
        Returns:
            صلاحيات المستخدم
        """
        # استخراج الدور
        role = "user"
        level = PrivilegeLevel.USER
        
        # البحث عن حقل الدور
        role_fields = ["role", "user_role", "permission", "access_level", "is_admin", "is_moderator"]
        
        for field in role_fields:
            if field in response_data:
                value = str(response_data[field]).lower()
                
                # تحديد مستوى الصلاحية
                if "admin" in value or value == "true":
                    role = "admin"
                    level = PrivilegeLevel.ADMIN
                elif "moderator" in value or "mod" in value:
                    role = "moderator"
                    level = PrivilegeLevel.MODERATOR
                elif "guest" in value:
                    role = "guest"
                    level = PrivilegeLevel.GUEST
        
        # استخراج اسم المستخدم
        username = None
        username_fields = ["username", "user", "name", "email"]
        for field in username_fields:
            if field in response_data:
                username = str(response_data[field])
                break
        
        privilege = UserPrivilege(
            user_id=user_id,
            username=username,
            role=role,
            level=level,
            source=source,
            metadata=response_data
        )
        
        self._user_privileges[user_id] = privilege
        
        logger.info(f"Analyzed privileges for user {user_id}: {role}")
        return privilege
    
    async def detect_privilege_endpoints(
        self,
        url: str,
        html: str = None
    ) -> List[str]:
        """
        كشف نقاط نهاية إدارة الصلاحيات
        
        Args:
            url: الرابط
            html: محتوى HTML (اختياري)
        
        Returns:
            قائمة بنقاط النهاية المكتشفة
        """
        endpoints = []
        
        for pattern in self.PRIVILEGE_ENDPOINTS:
            if re.search(pattern, url, re.I):
                endpoints.append(url)
                self._privileged_endpoints.add(url)
        
        if html:
            # البحث في HTML عن روابط للصلاحيات
            link_pattern = re.compile(r'href=["\']([^"\']+)["\']', re.I)
            for match in link_pattern.finditer(html):
                link = match.group(1)
                for pattern in self.PRIVILEGE_ENDPOINTS:
                    if re.search(pattern, link, re.I):
                        full_url = link if link.startswith('http') else url.rstrip('/') + '/' + link.lstrip('/')
                        endpoints.append(full_url)
                        self._privileged_endpoints.add(full_url)
        
        return list(set(endpoints))
    
    async def find_escalation_paths(
        self,
        user_id: str,
        accessible_resources: List[Dict],
        parameter: str = None
    ) -> List[PrivilegeEscalationPath]:
        """
        البحث عن مسارات رفع الصلاحية
        
        Args:
            user_id: معرف المستخدم الحالي
            accessible_resources: الموارد التي يمكن الوصول إليها
            parameter: المعامل المستخدم
        
        Returns:
            قائمة بمسارات رفع الصلاحية
        """
        paths = []
        
        current_privilege = self._user_privileges.get(user_id)
        if not current_privilege:
            return paths
        
        for resource in accessible_resources:
            # استخراج معرف المستخدم من المورد
            resource_id = resource.get("user_id") or resource.get("id")
            
            if resource_id and resource_id != user_id:
                # محاولة تحديد صلاحيات المستخدم الآخر
                other_privilege = self._infer_privilege_from_resource(resource)
                
                if other_privilege and other_privilege.level > current_privilege.level:
                    path = PrivilegeEscalationPath(
                        from_user=user_id,
                        to_user=resource_id,
                        from_level=current_privilege.level,
                        to_level=other_privilege.level,
                        method="idor",
                        endpoint=resource.get("url", ""),
                        vulnerability_id=resource.get("finding_id")
                    )
                    paths.append(path)
                    
                    logger.warning(f"Privilege escalation path found: {user_id} ({current_privilege.role}) -> {resource_id} ({other_privilege.role})")
        
        self._escalation_paths.extend(paths)
        return paths
    
    def _infer_privilege_from_resource(self, resource: Dict) -> Optional[UserPrivilege]:
        """
        استنتاج صلاحيات المستخدم من المورد
        
        Args:
            resource: بيانات المورد
        
        Returns:
            صلاحيات المستخدم
        """
        # التحقق من وجود حقل role
        if "role" in resource:
            role = resource["role"].lower()
            for pattern, roles in self.ROLE_PATTERNS.items():
                if any(r in role for r in roles):
                    level = {
                        "admin": PrivilegeLevel.ADMIN,
                        "moderator": PrivilegeLevel.MODERATOR,
                        "user": PrivilegeLevel.USER,
                        "guest": PrivilegeLevel.GUEST
                    }.get(pattern, PrivilegeLevel.USER)
                    
                    return UserPrivilege(
                        user_id=resource.get("user_id") or resource.get("id", "unknown"),
                        role=pattern,
                        level=level,
                        source="resource_inference"
                    )
        
        # التحقق من وجود بيانات حساسة تشير إلى صلاحيات عالية
        sensitive_fields = ["admin_panel", "user_management", "system_settings"]
        if any(field in resource for field in sensitive_fields):
            return UserPrivilege(
                user_id=resource.get("user_id") or resource.get("id", "unknown"),
                role="admin",
                level=PrivilegeLevel.ADMIN,
                source="resource_inference"
            )
        
        return None
    
    async def analyze_role_parameter(
        self,
        url: str,
        parameter: str,
        response: str
    ) -> Optional[str]:
        """
        تحليل معامل الدور (role parameter)
        
        Args:
            url: الرابط
            parameter: اسم المعامل
            response: الاستجابة
        
        Returns:
            الدور المكتشف أو None
        """
        # أنماط الأدوار المحتملة
        possible_roles = ["admin", "moderator", "user", "guest", "superuser", "root"]
        
        for role in possible_roles:
            if role in response.lower():
                # التحقق من أن الاستجابة تحتوي على تغيير في الدور
                if "role" in response.lower() or "permission" in response.lower():
                    logger.info(f"Potential role parameter '{parameter}' with value '{role}' at {url}")
                    return role
        
        return None
    
    async def get_user_privilege(self, user_id: str) -> Optional[UserPrivilege]:
        """الحصول على صلاحيات المستخدم"""
        return self._user_privileges.get(user_id)
    
    async def get_all_privileges(self) -> List[UserPrivilege]:
        """الحصول على جميع صلاحيات المستخدمين"""
        return list(self._user_privileges.values())
    
    async def get_escalation_paths(self) -> List[PrivilegeEscalationPath]:
        """الحصول على مسارات رفع الصلاحية"""
        return self._escalation_paths
    
    async def get_high_risk_endpoints(self) -> List[str]:
        """الحصول على نقاط النهاية عالية المخاطر"""
        return list(self._privileged_endpoints)
    
    async def generate_privilege_report(self) -> str:
        """
        توليد تقرير الصلاحيات
        
        Returns:
            تقرير Markdown
        """
        report = f"""# Privilege Analysis Report

**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## User Privileges ({len(self._user_privileges)})

| User ID | Username | Role | Level |
|---------|----------|------|-------|
"""
        for priv in self._user_privileges.values():
            report += f"| {priv.user_id} | {priv.username or '-'} | {priv.role} | {priv.level.name} |\n"
        
        report += f"\n## Privilege Escalation Paths ({len(self._escalation_paths)})\n\n"
        for path in self._escalation_paths:
            report += f"- **{path.from_user}** ({path.from_level.name}) → **{path.to_user}** ({path.to_level.name})\n"
            report += f"  - Method: {path.method}\n"
            report += f"  - Endpoint: {path.endpoint}\n"
        
        report += f"\n## High-Risk Endpoints ({len(self._privileged_endpoints)})\n\n"
        for endpoint in list(self._privileged_endpoints)[:20]:
            report += f"- `{endpoint}`\n"
        
        if len(self._privileged_endpoints) > 20:
            report += f"\n*... and {len(self._privileged_endpoints) - 20} more endpoints*\n"
        
        return report
    
    async def get_statistics(self) -> Dict:
        """إحصائيات المحلل"""
        return {
            "total_users_analyzed": len(self._user_privileges),
            "escalation_paths_found": len(self._escalation_paths),
            "privileged_endpoints": len(self._privileged_endpoints),
            "role_distribution": {
                role: sum(1 for p in self._user_privileges.values() if p.role == role)
                for role in ["admin", "moderator", "user", "guest"]
            },
            "high_risk_endpoints": [
                ep for ep in self._privileged_endpoints
                if any(x in ep.lower() for x in ["admin", "manage", "role", "permission"])
            ][:10]
        }
    
    async def clear_data(self):
        """مسح البيانات"""
        self._user_privileges.clear()
        self._escalation_paths.clear()
        self._privileged_endpoints.clear()
        logger.info("Privilege analyzer data cleared")

