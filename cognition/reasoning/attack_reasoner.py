
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime

import logging

logger = logging.getLogger(__name__)


@dataclass
class AttackStep:
    """خطوة هجومية"""
    vulnerability: str
    action: str
    prerequisite: List[str]
    outcome: List[str]
    success_probability: float
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AttackChain:
    """سلسلة هجومية"""
    id: str
    steps: List[AttackStep]
    objective: str
    overall_success: float
    created_at: datetime = field(default_factory=datetime.now)


class AttackReasoner:
    """
    مفكر الهجمات المتقدم
    
    الميزات:
    - تحليل الثغرات وإمكانية استغلالها
    - بناء سلاسل هجومية من خطوات متعددة
    - تقييم احتمالية النجاح
    - كشف التبعيات بين الهجمات
    """
    
    def __init__(self):
        self._attack_chains: List[AttackChain] = []
        self._vulnerability_actions: Dict[str, List[AttackStep]] = {}
        
        # تهيئة الإجراءات الممكنة لكل ثغرة
        self._init_vulnerability_actions()
        
        logger.info("AttackReasoner initialized")
    
    def _init_vulnerability_actions(self):
        """تهيئة الإجراءات الممكنة لكل ثغرة"""
        
        # إجراءات XSS
        self._vulnerability_actions["XSS"] = [
            AttackStep(
                vulnerability="XSS",
                action="steal_cookie",
                prerequisite=["XSS"],
                outcome=["session_hijack"],
                success_probability=0.8
            ),
            AttackStep(
                vulnerability="XSS",
                action="keylogging",
                prerequisite=["XSS"],
                outcome=["credential_theft"],
                success_probability=0.7
            ),
            AttackStep(
                vulnerability="XSS",
                action="csrf_bypass",
                prerequisite=["XSS"],
                outcome=["unauthorized_action"],
                success_probability=0.75
            )
        ]
        
        # إجراءات SQLi
        self._vulnerability_actions["SQLi"] = [
            AttackStep(
                vulnerability="SQLi",
                action="extract_data",
                prerequisite=["SQLi"],
                outcome=["data_breach"],
                success_probability=0.9
            ),
            AttackStep(
                vulnerability="SQLi",
                action="bypass_auth",
                prerequisite=["SQLi"],
                outcome=["unauthorized_access"],
                success_probability=0.85
            ),
            AttackStep(
                vulnerability="SQLi",
                action="write_file",
                prerequisite=["SQLi", "file_privileges"],
                outcome=["rce"],
                success_probability=0.6
            )
        ]
        
        # إجراءات RCE
        self._vulnerability_actions["RCE"] = [
            AttackStep(
                vulnerability="RCE",
                action="reverse_shell",
                prerequisite=["RCE"],
                outcome=["shell_access"],
                success_probability=0.85
            ),
            AttackStep(
                vulnerability="RCE",
                action="download_file",
                prerequisite=["RCE"],
                outcome=["file_access"],
                success_probability=0.9
            ),
            AttackStep(
                vulnerability="RCE",
                action="privilege_escalation",
                prerequisite=["RCE", "sudo_privileges"],
                outcome=["root_access"],
                success_probability=0.7
            )
        ]
        
        # إجراءات IDOR
        self._vulnerability_actions["IDOR"] = [
            AttackStep(
                vulnerability="IDOR",
                action="access_other_user",
                prerequisite=["IDOR"],
                outcome=["user_data_access"],
                success_probability=0.8
            ),
            AttackStep(
                vulnerability="IDOR",
                action="modify_other_data",
                prerequisite=["IDOR"],
                outcome=["data_modification"],
                success_probability=0.75
            )
        ]
    
    async def get_possible_actions(
        self,
        vulnerability: str,
        available_resources: List[str] = None
    ) -> List[AttackStep]:
        """
        الحصول على الإجراءات الممكنة لثغرة معينة
        
        Args:
            vulnerability: نوع الثغرة
            available_resources: الموارد المتاحة
        
        Returns:
            قائمة بالإجراءات الممكنة
        """
        actions = self._vulnerability_actions.get(vulnerability, [])
        
        if available_resources:
            actions = [
                a for a in actions
                if all(p in available_resources for p in a.prerequisite)
            ]
        
        return actions
    
    async def build_attack_chain(
        self,
        start_vulnerability: str,
        objective: str,
        max_depth: int = 5
    ) -> Optional[AttackChain]:
        """
        بناء سلسلة هجومية لتحقيق هدف معين
        
        Args:
            start_vulnerability: ثغرة البداية
            objective: الهدف النهائي
            max_depth: أقصى عمق للبحث
        
        Returns:
            سلسلة هجومية أو None
        """
        import uuid
        chain_id = str(uuid.uuid4())[:8]
        
        # BFS للبحث عن مسار يصل إلى الهدف
        queue = [([], set(), 1.0)]
        best_chain = None
        best_score = 0.0
        
        while queue and len(queue) < 100:
            steps, outcomes, prob = queue.pop(0)
            
            # تحديد الإجراءات الممكنة من الحالة الحالية
            current_vuln = start_vulnerability if not steps else steps[-1].vulnerability
            
            for action in await self.get_possible_actions(current_vuln):
                new_outcomes = set(outcomes) | set(action.outcome)
                
                # التحقق من تحقيق الهدف
                if objective in action.outcome or objective in new_outcomes:
                    chain = AttackChain(
                        id=chain_id,
                        steps=steps + [action],
                        objective=objective,
                        overall_success=prob * action.success_probability
                    )
                    
                    if chain.overall_success > best_score:
                        best_score = chain.overall_success
                        best_chain = chain
                
                # متابعة البحث إذا لم نصل للحد الأقصى
                elif len(steps) < max_depth - 1:
                    queue.append((
                        steps + [action],
                        new_outcomes,
                        prob * action.success_probability
                    ))
        
        if best_chain:
            self._attack_chains.append(best_chain)
            logger.info(f"Attack chain built: {objective} (score={best_score:.2f})")
        
        return best_chain
    
    async def get_attack_chains(self) -> List[AttackChain]:
        """الحصول على جميع سلاسل الهجوم"""
        return self._attack_chains
    
    async def get_recommended_chain(
        self,
        objective: str
    ) -> Optional[AttackChain]:
        """
        الحصول على سلسلة هجومية موصى بها لهدف معين
        
        Args:
            objective: الهدف
        
        Returns:
            أفضل سلسلة هجومية
        """
        relevant_chains = [
            c for c in self._attack_chains
            if c.objective == objective
        ]
        
        if not relevant_chains:
            return None
        
        return max(relevant_chains, key=lambda x: x.overall_success)
    
    async def get_statistics(self) -> Dict:
        """إحصائيات المفكر"""
        total_chains = len(self._attack_chains)
        
        objectives = {}
        for chain in self._attack_chains:
            objectives[chain.objective] = objectives.get(chain.objective, 0) + 1
        
        avg_success = sum(c.overall_success for c in self._attack_chains) / total_chains if total_chains > 0 else 0
        
        return {
            "total_attack_chains": total_chains,
            "objectives_distribution": objectives,
            "average_success_probability": avg_success,
            "vulnerabilities_covered": list(self._vulnerability_actions.keys()),
            "total_actions": sum(len(actions) for actions in self._vulnerability_actions.values())
        }


# نسخة عالمية
_default_reasoner = None


async def get_attack_reasoner() -> AttackReasoner:
    """الحصول على نسخة عالمية من محلل الهجمات"""
    global _default_reasoner
    if _default_reasoner is None:
        _default_reasoner = AttackReasoner()
    return _default_reasoner
