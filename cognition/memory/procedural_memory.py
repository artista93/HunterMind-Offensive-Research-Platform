
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime

import logging

logger = logging.getLogger(__name__)


@dataclass
class Procedure:
    """إجراء/مهارة"""
    name: str
    description: str
    steps: List[str]
    success_count: int = 0
    fail_count: int = 0
    last_used: Optional[datetime] = None
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


class ProceduralMemory:
    """
    الذاكرة الإجرائية المتقدمة
    
    الميزات:
    - تخزين الإجراءات والمهارات
    - تتبع نجاح/فشل الإجراءات
    - اقتراح أفضل إجراء لمهمة معينة
    - تحديث الإجراءات بناءً على الخبرة
    """
    
    def __init__(self):
        self._procedures: Dict[str, Procedure] = {}
        self._tag_index: Dict[str, List[str]] = {}
        
        # تهيئة إجراءات افتراضية
        self._init_default_procedures()
        
        logger.info("ProceduralMemory initialized")
    
    def _init_default_procedures(self):
        """تهيئة الإجراءات الافتراضية"""
        
        # إجراء فحص XSS
        self._procedures["xss_scan"] = Procedure(
            name="XSS Scan",
            description="Scan for Cross-Site Scripting vulnerabilities",
            steps=[
                "Identify input parameters",
                "Inject XSS payloads",
                "Analyze responses",
                "Confirm vulnerabilities"
            ],
            tags=["scan", "xss", "web"]
        )
        
        # إجراء فحص SQLi
        self._procedures["sqli_scan"] = Procedure(
            name="SQL Injection Scan",
            description="Scan for SQL Injection vulnerabilities",
            steps=[
                "Identify database parameters",
                "Inject SQL payloads",
                "Detect database errors",
                "Extract database information"
            ],
            tags=["scan", "sqli", "database"]
        )
        
        # إجراء استغلال RCE
        self._procedures["rce_exploit"] = Procedure(
            name="RCE Exploit",
            description="Exploit Remote Code Execution",
            steps=[
                "Verify command injection point",
                "Test basic commands",
                "Execute system commands",
                "Establish persistence"
            ],
            tags=["exploit", "rce", "critical"]
        )
        
        # إجراء رفع صلاحيات
        self._procedures["privilege_escalation"] = Procedure(
            name="Privilege Escalation",
            description="Escalate user privileges",
            steps=[
                "Enumerate current privileges",
                "Identify escalation vectors",
                "Exploit vulnerability",
                "Verify elevated access"
            ],
            tags=["exploit", "privilege", "escalation"]
        )
        
        # إجراء تجاوز WAF
        self._procedures["waf_bypass"] = Procedure(
            name="WAF Bypass",
            description="Bypass Web Application Firewall",
            steps=[
                "Detect WAF type",
                "Test encoding techniques",
                "Apply obfuscation",
                "Bypass protection"
            ],
            tags=["bypass", "waf", "evasion"]
        )
        
        # بناء فهرس العلامات
        for name, proc in self._procedures.items():
            for tag in proc.tags:
                if tag not in self._tag_index:
                    self._tag_index[tag] = []
                self._tag_index[tag].append(name)
    
    async def add_procedure(
        self,
        name: str,
        description: str,
        steps: List[str],
        tags: List[str] = None,
        metadata: Dict = None
    ):
        """
        إضافة إجراء جديد
        
        Args:
            name: اسم الإجراء
            description: وصف الإجراء
            steps: خطوات التنفيذ
            tags: علامات التصنيف
            metadata: بيانات إضافية
        """
        if name in self._procedures:
            logger.warning(f"Procedure {name} already exists")
            return
        
        procedure = Procedure(
            name=name,
            description=description,
            steps=steps,
            tags=tags or [],
            metadata=metadata or {}
        )
        
        self._procedures[name] = procedure
        
        # تحديث فهرس العلامات
        for tag in procedure.tags:
            if tag not in self._tag_index:
                self._tag_index[tag] = []
            if name not in self._tag_index[tag]:
                self._tag_index[tag].append(name)
        
        logger.info(f"Procedure added: {name}")
    
    async def get_procedure(self, name: str) -> Optional[Procedure]:
        """الحصول على إجراء بالاسم"""
        return self._procedures.get(name)
    
    async def find_by_tags(self, tags: List[str]) -> List[Procedure]:
        """
        البحث عن إجراءات حسب العلامات
        
        Args:
            tags: قائمة العلامات
        
        Returns:
            قائمة بالإجراءات المطابقة
        """
        if not tags:
            return []
        
        # العثور على الإجراءات التي تحوي جميع العلامات
        matching = set(self._tag_index.get(tags[0], []))
        for tag in tags[1:]:
            matching &= set(self._tag_index.get(tag, []))
        
        # ترتيب حسب النجاح
        procedures = [self._procedures[name] for name in matching if name in self._procedures]
        procedures.sort(key=lambda x: x.success_count, reverse=True)
        
        return procedures
    
    async def record_usage(self, name: str, success: bool):
        """
        تسجيل استخدام إجراء
        
        Args:
            name: اسم الإجراء
            success: نجاح/فشل الإجراء
        """
        if name not in self._procedures:
            logger.warning(f"Procedure {name} not found")
            return
        
        proc = self._procedures[name]
        
        if success:
            proc.success_count += 1
        else:
            proc.fail_count += 1
        
        proc.last_used = datetime.now()
        
        logger.debug(f"Procedure usage recorded: {name} (success={success})")
    
    async def suggest_best_procedure(
        self,
        task: str,
        tags: List[str] = None
    ) -> Optional[Procedure]:
        """
        اقتراح أفضل إجراء لمهمة معينة
        
        Args:
            task: وصف المهمة
            tags: علامات التصنيف
        
        Returns:
            أفضل إجراء مقترح
        """
        # البحث عن إجراءات حسب العلامات
        if tags:
            candidates = await self.find_by_tags(tags)
        else:
            # بحث بسيط في أسماء الإجراءات
            task_lower = task.lower()
            candidates = [
                proc for proc in self._procedures.values()
                if task_lower in proc.name.lower() or
                any(tag in task_lower for tag in proc.tags)
            ]
        
        if not candidates:
            return None
        
        # حساب درجة لكل إجراء
        scored = []
        for proc in candidates:
            score = 0.0
            
            # نسبة النجاح
            total = proc.success_count + proc.fail_count
            if total > 0:
                score += (proc.success_count / total) * 0.6
            
            # الحداثة
            if proc.last_used:
                days_since = (datetime.now() - proc.last_used).days
                score += max(0, 1 - days_since / 30) * 0.2
            
            # عدد مرات النجاح
            score += min(0.2, proc.success_count / 100) * 0.2
            
            scored.append((score, proc))
        
        scored.sort(key=lambda x: x[0], reverse=True)
        
        return scored[0][1] if scored else None
    
    async def update_procedure(
        self,
        name: str,
        steps: List[str] = None,
        description: str = None,
        tags: List[str] = None
    ):
        """تحديث إجراء موجود"""
        if name not in self._procedures:
            logger.warning(f"Procedure {name} not found")
            return
        
        proc = self._procedures[name]
        
        if steps:
            proc.steps = steps
        
        if description:
            proc.description = description
        
        if tags:
            # تحديث فهرس العلامات
            for old_tag in proc.tags:
                if old_tag in self._tag_index and name in self._tag_index[old_tag]:
                    self._tag_index[old_tag].remove(name)
            
            proc.tags = tags
            
            for new_tag in tags:
                if new_tag not in self._tag_index:
                    self._tag_index[new_tag] = []
                if name not in self._tag_index[new_tag]:
                    self._tag_index[new_tag].append(name)
        
        logger.info(f"Procedure updated: {name}")
    
    async def get_statistics(self) -> Dict:
        """إحصائيات الذاكرة"""
        total_procedures = len(self._procedures)
        
        # أكثر الإجراءات نجاحاً
        most_successful = max(
            self._procedures.values(),
            key=lambda x: x.success_count,
            default=None
        )
        
        # توزيع العلامات
        tag_distribution = {
            tag: len(procs) for tag, procs in self._tag_index.items()
        }
        
        # متوسط نسبة النجاح
        success_rates = []
        for proc in self._procedures.values():
            total = proc.success_count + proc.fail_count
            if total > 0:
                success_rates.append(proc.success_count / total)
        
        avg_success_rate = sum(success_rates) / len(success_rates) if success_rates else 0
        
        return {
            "total_procedures": total_procedures,
            "total_tags": len(self._tag_index),
            "most_successful": most_successful.name if most_successful else None,
            "average_success_rate": avg_success_rate,
            "tag_distribution": tag_distribution
        }

