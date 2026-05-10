
import numpy as np
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from collections import defaultdict

import logging

logger = logging.getLogger(__name__)


@dataclass
class AttackStep:
    """خطوة هجومية"""
    action: str
    parameters: Dict[str, Any]
    success: bool
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class AttackSequence:
    """تسلسل هجومي"""
    id: str
    steps: List[AttackStep]
    outcome: str  # success, partial, failed
    target: str
    duration: float
    created_at: datetime = field(default_factory=datetime.now)


class AttackSequenceModel:
    """
    نموذج تسلسل الهجمات المتقدم
    
    الميزات:
    - تعلم تسلسلات الهجمات الناجحة
    - التنبؤ بالخطوة التالية المناسبة
    - اكتشاف الأنماط الهجومية
    - توصية بسلاسل الهجوم
    """
    
    def __init__(self):
        self.sequences: List[AttackSequence] = []
        self.transition_matrix: Dict[Tuple[str, str], int] = defaultdict(int)
        self.action_success_rate: Dict[str, float] = defaultdict(float)
        
        logger.info("AttackSequenceModel initialized")
    
    async def add_sequence(self, sequence: AttackSequence):
        """
        إضافة تسلسل هجومي جديد
        
        Args:
            sequence: التسلسل الهجومي
        """
        self.sequences.append(sequence)
        
        # تحديث مصفوفة الانتقال
        for i in range(len(sequence.steps) - 1):
            current = sequence.steps[i].action
            next_action = sequence.steps[i + 1].action
            self.transition_matrix[(current, next_action)] += 1
        
        # تحديث معدل نجاح الإجراءات
        for step in sequence.steps:
            key = step.action
            current = self.action_success_rate.get(key, [0, 0])
            total = current[0] + 1
            success = current[1] + (1 if step.success else 0)
            self.action_success_rate[key] = success / total
        
        logger.debug(f"Attack sequence added: {len(sequence.steps)} steps")
    
    async def predict_next_action(
        self,
        current_action: str,
        context: Dict[str, Any] = None
    ) -> Optional[str]:
        """
        التنبؤ بالإجراء التالي بناءً على الإجراء الحالي
        
        Args:
            current_action: الإجراء الحالي
            context: سياق إضافي
        
        Returns:
            الإجراء المتوقع أو None
        """
        # البحث عن أكثر إجراء تالٍ شيوعاً
        candidates = []
        for (action, next_action), count in self.transition_matrix.items():
            if action == current_action:
                candidates.append((next_action, count))
        
        if not candidates:
            return None
        
        # ترتيب حسب التكرار
        candidates.sort(key=lambda x: x[1], reverse=True)
        
        best_action = candidates[0][0]
        
        # تعديل بناءً على السياق
        if context and context.get("prefer_successful"):
            # تفضيل الإجراءات ذات معدل النجاح العالي
            if self.action_success_rate.get(best_action, 0) < 0.5:
                for action, _ in candidates[1:3]:
                    if self.action_success_rate.get(action, 0) > 0.6:
                        best_action = action
                        break
        
        return best_action
    
    async def recommend_sequence(
        self,
        target_type: str,
        max_length: int = 5
    ) -> List[str]:
        """
        توصية بسلسلة هجومية لهدف معين
        
        Args:
            target_type: نوع الهدف
            max_length: أقصى طول للسلسلة
        
        Returns:
            قائمة بالإجراءات الموصى بها
        """
        # البحث عن تسلسلات ناجحة لنفس نوع الهدف
        successful = [
            seq for seq in self.sequences
            if seq.outcome == "success" and seq.target == target_type
        ]
        
        if not successful:
            return []
        
        # اختيار أفضل تسلسل
        best_seq = max(successful, key=lambda x: len(x.steps))
        
        # استخراج الإجراءات
        actions = [step.action for step in best_seq.steps[:max_length]]
        
        return actions
    
    async def get_most_common_chain(self) -> List[str]:
        """
        الحصول على السلسلة الهجومية الأكثر شيوعاً
        
        Returns:
            قائمة بالإجراءات
        """
        if not self.sequences:
            return []
        
        # تجميع السلاسل المتكررة
        chain_counts = defaultdict(int)
        for seq in self.sequences:
            chain = tuple(step.action for step in seq.steps)
            chain_counts[chain] += 1
        
        # أكثر سلسلة شيوعاً
        most_common = max(chain_counts, key=chain_counts.get)
        
        return list(most_common)
    
    async def get_successful_patterns(self) -> List[List[str]]:
        """
        الحصول على الأنماط الناجحة المتكررة
        
        Returns:
            قائمة بالأنماط الناجحة
        """
        patterns = []
        
        for seq in self.sequences:
            if seq.outcome == "success" and len(seq.steps) >= 2:
                pattern = [step.action for step in seq.steps]
                patterns.append(pattern)
        
        return patterns
    
    async def get_statistics(self) -> Dict:
        """إحصائيات النموذج"""
        total_sequences = len(self.sequences)
        
        if total_sequences == 0:
            return {"total_sequences": 0}
        
        successful = len([s for s in self.sequences if s.outcome == "success"])
        failed = len([s for s in self.sequences if s.outcome == "failed"])
        
        return {
            "total_sequences": total_sequences,
            "successful_sequences": successful,
            "failed_sequences": failed,
            "success_rate": successful / total_sequences,
            "total_transitions": len(self.transition_matrix),
            "unique_actions": len(self.action_success_rate),
            "average_sequence_length": sum(len(s.steps) for s in self.sequences) / total_sequences
        }

