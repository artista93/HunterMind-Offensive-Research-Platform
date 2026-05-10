
import asyncio
import random
import numpy as np
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from collections import deque

from ..base.base_agent import BaseAgent, AgentPriority, AgentMessage
from ..base.agent_state import AgentStateEnum
from ...storage.sqlite.learning_db import get_learning_database
from ...offensive.exploitation.exploit_memory import get_exploit_memory

import logging

logger = logging.getLogger(__name__)


@dataclass
class LearningExperience:
    """تجربة تعلم"""
    state: Dict[str, Any]
    action: str
    reward: float
    next_state: Dict[str, Any]
    done: bool
    timestamp: datetime = field(default_factory=datetime.now)


class LearningAgent(BaseAgent):
    """
    وكيل التعلم المتقدم
    
    الميزات:
    - تعلم معزز (Reinforcement Learning)
    - تخزين التجارب في قاعدة البيانات
    - تحليل نجاحات وإخفاقات الاستغلال
    - تحسين استراتيجيات الهجوم تلقائياً
    - تكامل مع ذاكرة الاستغلال
    """
    
    def __init__(
        self,
        name: str = "LearningAgent",
        priority: AgentPriority = AgentPriority.NORMAL,
        learning_rate: float = 0.01,
        discount_factor: float = 0.95,
        exploration_rate: float = 0.1
    ):
        super().__init__(name, priority)
        
        self._learning_rate = learning_rate
        self._discount_factor = discount_factor
        self._exploration_rate = exploration_rate
        
        # مكونات التعلم
        self._db = None
        self._memory = get_exploit_memory()
        
        # Q-table (للتخزين المؤقت)
        self._q_table: Dict[str, Dict[str, float]] = {}
        
        # سجل التجارب
        self._experiences: List[LearningExperience] = []
        self._replay_buffer = deque(maxlen=10000)
        
        logger.info(f"LearningAgent initialized: {name}")
    
    async def _on_initialize(self):
        """تهيئة الوكيل"""
        self._db = await get_learning_database()
        logger.info("LearningAgent components initialized")
    
    async def _on_start(self):
        """بدء تشغيل الوكيل"""
        logger.info("LearningAgent started")
    
    async def _on_stop(self):
        """إيقاف تشغيل الوكيل"""
        logger.info("LearningAgent stopped")
    
    async def _handle_message(self, message: AgentMessage) -> Optional[AgentMessage]:
        """معالجة الرسائل الواردة"""
        if message.type == "record_experience":
            result = await self.record_experience(message.content)
            return AgentMessage(
                id="",
                sender=self.name,
                receiver=message.sender,
                type="experience_recorded",
                content=result
            )
        
        elif message.type == "get_best_action":
            action = await self.get_best_action(message.content)
            return AgentMessage(
                id="",
                sender=self.name,
                receiver=message.sender,
                type="best_action",
                content={"action": action}
            )
        
        elif message.type == "update_q_value":
            await self.update_q_value(message.content)
            return AgentMessage(
                id="",
                sender=self.name,
                receiver=message.sender,
                type="q_value_updated",
                content={"success": True}
            )
        
        return await super()._handle_message(message)
    
    async def record_experience(
        self,
        data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        تسجيل تجربة تعلم جديدة
        
        Args:
            data: بيانات التجربة (state, action, reward, next_state, done)
        
        Returns:
            نتيجة التسجيل
        """
        experience = LearningExperience(
            state=data.get("state", {}),
            action=data.get("action", ""),
            reward=data.get("reward", 0.0),
            next_state=data.get("next_state", {}),
            done=data.get("done", False)
        )
        
        self._experiences.append(experience)
        self._replay_buffer.append(experience)
        
        # تحديث Q-value
        await self._update_q_value_from_experience(experience)
        
        # تخزين في قاعدة البيانات
        await self._db.store_experience(
            agent_name=self.name,
            state=experience.state,
            action=experience.action,
            reward=experience.reward,
            next_state=experience.next_state,
            done=experience.done,
            metadata={}
        )
        
        logger.debug(f"Experience recorded: action={experience.action}, reward={experience.reward}")
        
        return {
            "success": True,
            "experience_id": len(self._experiences),
            "reward": experience.reward
        }
    
    async def _update_q_value_from_experience(self, experience: LearningExperience):
        """تحديث Q-value من تجربة"""
        state_key = self._state_to_key(experience.state)
        action = experience.action
        
        if state_key not in self._q_table:
            self._q_table[state_key] = {}
        
        # Q-learning update
        current_q = self._q_table[state_key].get(action, 0.0)
        
        next_state_key = self._state_to_key(experience.next_state)
        max_next_q = self._get_max_q_value(next_state_key) if not experience.done else 0.0
        
        new_q = current_q + self._learning_rate * (
            experience.reward + self._discount_factor * max_next_q - current_q
        )
        
        self._q_table[state_key][action] = new_q
    
    async def get_best_action(
        self,
        state: Dict[str, Any],
        available_actions: List[str] = None
    ) -> str:
        """
        الحصول على أفضل إجراء للحالة الحالية
        
        Args:
            state: الحالة الحالية
            available_actions: قائمة الإجراءات المتاحة
        
        Returns:
            أفضل إجراء
        """
        state_key = self._state_to_key(state)
        
        # استكشاف (Exploration) vs استغلال (Exploitation)
        if random.random() < self._exploration_rate and available_actions:
            return random.choice(available_actions)
        
        # استغلال (Exploitation)
        if state_key in self._q_table:
            q_values = self._q_table[state_key]
            if q_values:
                if available_actions:
                    # تصفية الإجراءات المتاحة فقط
                    filtered = {k: v for k, v in q_values.items() if k in available_actions}
                    if filtered:
                        return max(filtered, key=filtered.get)
                else:
                    return max(q_values, key=q_values.get)
        
        # إجراء عشوائي إذا لم تكن هناك معرفة سابقة
        if available_actions:
            return random.choice(available_actions)
        
        return "default_action"
    
    def _get_max_q_value(self, state_key: str) -> float:
        """الحصول على أقصى Q-value لحالة معينة"""
        if state_key in self._q_table and self._q_table[state_key]:
            return max(self._q_table[state_key].values())
        return 0.0
    
    def _state_to_key(self, state: Dict[str, Any]) -> str:
        """تحويل الحالة إلى مفتاح"""
        # تبسيط الحالة للمفتاح
        key_parts = []
        
        if "vulnerability_type" in state:
            key_parts.append(state["vulnerability_type"])
        if "target_type" in state:
            key_parts.append(state["target_type"])
        if "has_waf" in state:
            key_parts.append(str(state["has_waf"]))
        
        return "|".join(key_parts) if key_parts else "default"
    
    async def update_q_value(
        self,
        data: Dict[str, Any]
    ):
        """
        تحديث Q-value مباشرة
        
        Args:
            data: بيانات التحديث (state, action, value)
        """
        state_key = self._state_to_key(data.get("state", {}))
        action = data.get("action", "")
        value = data.get("value", 0.0)
        
        if state_key not in self._q_table:
            self._q_table[state_key] = {}
        
        self._q_table[state_key][action] = value
        
        logger.debug(f"Q-value updated: {state_key} -> {action} = {value}")
    
    async def replay_experiences(self, batch_size: int = 32):
        """
        إعادة تشغيل التجارب للتعلم (Experience Replay)
        
        Args:
            batch_size: حجم الدفعة
        """
        if len(self._replay_buffer) < batch_size:
            return
        
        batch = random.sample(list(self._replay_buffer), batch_size)
        
        for experience in batch:
            await self._update_q_value_from_experience(experience)
        
        logger.debug(f"Replayed {batch_size} experiences")
    
    async def get_statistics(self) -> Dict:
        """إحصائيات الوكيل"""
        base_stats = await super().get_statistics()
        
        return {
            **base_stats,
            "learning_specific": {
                "total_experiences": len(self._experiences),
                "replay_buffer_size": len(self._replay_buffer),
                "q_table_size": len(self._q_table),
                "learning_rate": self._learning_rate,
                "discount_factor": self._discount_factor,
                "exploration_rate": self._exploration_rate
            }
        }
    
    async def clear_memory(self):
        """مسح ذاكرة التعلم"""
        self._experiences.clear()
        self._replay_buffer.clear()
        self._q_table.clear()
        logger.info("Learning memory cleared")


_default_learning_agent = None

async def get_learning_agent() -> LearningAgent:
    global _default_learning_agent
    if _default_learning_agent is None:
        _default_learning_agent = LearningAgent()
        await _default_learning_agent.initialize()
        await _default_learning_agent.start()
    return _default_learning_agent

