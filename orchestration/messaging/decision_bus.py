
import asyncio
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from datetime import datetime
from collections import defaultdict

import logging

logger = logging.getLogger(__name__)


@dataclass
class Decision:
    """قرار"""
    id: str
    type: str
    payload: Any
    source: str
    timestamp: datetime = field(default_factory=datetime.now)
    priority: int = 3  # 1-5, 1 أعلى
    status: str = "pending"
    result: Optional[Any] = None
    voters: List[str] = field(default_factory=list)
    votes: Dict[str, bool] = field(default_factory=dict)


class DecisionBus:
    """
    ناقل القرارات المتقدم
    
    الميزات:
    - اتخاذ القرارات بالإجماع أو بالأغلبية
    - تسجيل المصوتين
    - تتبع تاريخ القرارات
    - آليات تصويت متعددة
    """
    
    def __init__(self):
        self.decisions: Dict[str, Decision] = {}
        self.voters: Dict[str, Callable] = {}
        self.decision_history: List[Decision] = []
        self._lock = asyncio.Lock()
        
        logger.info("DecisionBus initialized")
    
    def register_voter(self, voter_name: str, voter_fn: Callable):
        """
        تسجيل مصوت جديد
        
        Args:
            voter_name: اسم المصوت
            voter_fn: دالة التصويت (async)
        """
        self.voters[voter_name] = voter_fn
        logger.debug(f"Voter registered: {voter_name}")
    
    async def propose(
        self,
        decision_type: str,
        payload: Any,
        source: str,
        voters: List[str] = None,
        priority: int = 3,
        require_consensus: bool = False
    ) -> Decision:
        """
        اقتراح قرار جديد
        
        Args:
            decision_type: نوع القرار
            payload: بيانات القرار
            source: مصدر القرار
            voters: قائمة المصوتين (الكل إذا None)
            priority: الأولوية (1-5)
            require_consensus: هل يتطلب إجماع؟
        
        Returns:
            القرار بعد التصويت
        """
        import uuid
        decision_id = str(uuid.uuid4())[:8]
        
        if voters is None:
            voters = list(self.voters.keys())
        
        decision = Decision(
            id=decision_id,
            type=decision_type,
            payload=payload,
            source=source,
            priority=priority,
            voters=voters
        )
        
        async with self._lock:
            self.decisions[decision_id] = decision
        
        # جمع الأصوات
        await self._collect_votes(decision, require_consensus)
        
        # تخزين القرار في التاريخ
        async with self._lock:
            self.decision_history.append(decision)
            if len(self.decision_history) > 1000:
                self.decision_history.pop(0)
        
        logger.info(f"Decision {decision_id} finalized: {decision.status}")
        return decision
    
    async def _collect_votes(self, decision: Decision, require_consensus: bool):
        """جمع الأصوات من المصوتين"""
        votes = {}
        
        for voter_name in decision.voters:
            if voter_name not in self.voters:
                continue
            
            try:
                voter_fn = self.voters[voter_name]
                if asyncio.iscoroutinefunction(voter_fn):
                    vote = await voter_fn(decision.payload)
                else:
                    vote = voter_fn(decision.payload)
                
                votes[voter_name] = bool(vote)
                
            except Exception as e:
                logger.error(f"Voter {voter_name} failed: {e}")
                votes[voter_name] = False
        
        decision.votes = votes
        
        # حساب النتيجة
        total_votes = len(votes)
        approve_votes = sum(1 for v in votes.values() if v)
        
        if require_consensus:
            decision.status = "approved" if approve_votes == total_votes else "rejected"
        else:
            decision.status = "approved" if approve_votes > total_votes / 2 else "rejected"
        
        decision.result = {
            "total_votes": total_votes,
            "approve_votes": approve_votes,
            "reject_votes": total_votes - approve_votes,
            "votes_detail": votes
        }
    
    async def get_decision(self, decision_id: str) -> Optional[Decision]:
        """الحصول على قرار بالمعرف"""
        return self.decisions.get(decision_id)
    
    async def get_history(
        self,
        decision_type: str = None,
        status: str = None,
        limit: int = 100
    ) -> List[Decision]:
        """
        الحصول على تاريخ القرارات
        
        Args:
            decision_type: نوع القرار (اختياري)
            status: حالة القرار (اختياري)
            limit: عدد النتائج
        
        Returns:
            قائمة بالقرارات
        """
        async with self._lock:
            decisions = self.decision_history
            
            if decision_type:
                decisions = [d for d in decisions if d.type == decision_type]
            
            if status:
                decisions = [d for d in decisions if d.status == status]
            
            return decisions[-limit:]
    
    async def get_statistics(self) -> Dict:
        """إحصائيات ناقل القرارات"""
        async with self._lock:
            total = len(self.decision_history)
            approved = len([d for d in self.decision_history if d.status == "approved"])
            rejected = total - approved
            
            decision_types = defaultdict(int)
            for d in self.decision_history:
                decision_types[d.type] += 1
            
            return {
                "total_decisions": total,
                "approved_decisions": approved,
                "rejected_decisions": rejected,
                "approval_rate": approved / total if total > 0 else 0,
                "decision_type_distribution": dict(decision_types),
                "total_voters": len(self.voters),
                "active_voters": len(self.voters)
            }

