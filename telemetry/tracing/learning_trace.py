
import asyncio
import uuid
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime

import logging

logger = logging.getLogger(__name__)


@dataclass
class LearningEvent:
    """حدث تعلم"""
    id: str
    name: str
    parent_id: Optional[str]
    episode: int
    step: int
    action: str
    reward: float
    loss: float
    epsilon: float
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class LearningTrace:
    """تتبع تعلم"""
    id: str
    name: str
    agent_name: str
    start_time: datetime
    end_time: Optional[datetime] = None
    events: List[LearningEvent] = field(default_factory=list)
    final_reward: float = 0.0
    total_steps: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)


class LearningTracer:
    """
    تتبع التعلم المتقدم
    
    الميزات:
    - تتبع عملية تعلم الوكلاء
    - تسجيل الأحداث والمكافآت
    - تحليل منحنيات التعلم
    - تقييم تحسن الأداء
    """
    
    def __init__(self, max_traces: int = 1000):
        self.traces: Dict[str, LearningTrace] = {}
        self.active_events: Dict[str, LearningEvent] = {}
        self.max_traces = max_traces
        self._lock = asyncio.Lock()
        
        logger.info(f"LearningTracer initialized (max_traces={max_traces})")
    
    async def start_trace(
        self,
        name: str,
        agent_name: str,
        metadata: Dict = None
    ) -> str:
        """
        بدء تتبع تعلم جديد
        
        Args:
            name: اسم التتبع
            agent_name: اسم الوكيل
            metadata: بيانات وصفية
        
        Returns:
            معرف التتبع
        """
        trace_id = str(uuid.uuid4())[:8]
        
        trace = LearningTrace(
            id=trace_id,
            name=name,
            agent_name=agent_name,
            start_time=datetime.now(),
            metadata=metadata or {}
        )
        
        async with self._lock:
            self.traces[trace_id] = trace
            
            if len(self.traces) > self.max_traces:
                oldest = min(self.traces.keys(), key=lambda k: self.traces[k].start_time)
                del self.traces[oldest]
        
        logger.debug(f"Learning trace started: {name} ({trace_id})")
        return trace_id
    
    async def end_trace(
        self,
        trace_id: str,
        final_reward: float,
        total_steps: int
    ):
        """
        إنهاء تتبع التعلم
        
        Args:
            trace_id: معرف التتبع
            final_reward: المكافأة النهائية
            total_steps: إجمالي الخطوات
        """
        async with self._lock:
            if trace_id not in self.traces:
                logger.warning(f"Learning trace {trace_id} not found")
                return
            
            trace = self.traces[trace_id]
            trace.end_time = datetime.now()
            trace.final_reward = final_reward
            trace.total_steps = total_steps
        
        logger.debug(f"Learning trace ended: {trace_id}")
    
    async def add_event(
        self,
        trace_id: str,
        name: str,
        episode: int,
        step: int,
        action: str,
        reward: float,
        loss: float,
        epsilon: float,
        parent_id: str = None
    ) -> str:
        """
        إضافة حدث تعلم
        
        Args:
            trace_id: معرف التتبع
            name: اسم الحدث
            episode: رقم الحلقة
            step: رقم الخطوة
            action: الإجراء
            reward: المكافأة
            loss: الخسارة
            epsilon: معامل الاستكشاف
            parent_id: معرف الحدث الأب
        
        Returns:
            معرف الحدث
        """
        event_id = str(uuid.uuid4())[:8]
        
        event = LearningEvent(
            id=event_id,
            name=name,
            parent_id=parent_id,
            episode=episode,
            step=step,
            action=action,
            reward=reward,
            loss=loss,
            epsilon=epsilon
        )
        
        async with self._lock:
            if trace_id in self.traces:
                self.traces[trace_id].events.append(event)
            
            self.active_events[event_id] = event
        
        logger.debug(f"Learning event added: {name} (episode={episode}, step={step})")
        return event_id
    
    async def get_trace(self, trace_id: str) -> Optional[LearningTrace]:
        """الحصول على تتبع تعلم بالمعرف"""
        async with self._lock:
            return self.traces.get(trace_id)
    
    async def get_traces(self, limit: int = 50) -> List[LearningTrace]:
        """الحصول على قائمة تتبعات التعلم"""
        async with self._lock:
            traces = list(self.traces.values())
            traces.sort(key=lambda x: x.start_time, reverse=True)
            return traces[:limit]
    
    async def get_learning_curve(self, trace_id: str) -> Dict:
        """الحصول على منحنى التعلم للتتبع"""
        trace = await self.get_trace(trace_id)
        if not trace or not trace.events:
            return {"has_data": False}
        
        # تجميع المكافآت حسب الحلقة
        episode_rewards = {}
        episode_losses = {}
        
        for event in trace.events:
            if event.episode not in episode_rewards:
                episode_rewards[event.episode] = []
                episode_losses[event.episode] = []
            episode_rewards[event.episode].append(event.reward)
            episode_losses[event.episode].append(event.loss)
        
        # حساب المتوسطات لكل حلقة
        avg_rewards = []
        avg_losses = []
        
        for episode in sorted(episode_rewards.keys()):
            avg_rewards.append({
                "episode": episode,
                "reward": sum(episode_rewards[episode]) / len(episode_rewards[episode])
            })
            avg_losses.append({
                "episode": episode,
                "loss": sum(episode_losses[episode]) / len(episode_losses[episode])
            })
        
        return {
            "has_data": True,
            "trace_id": trace_id,
            "name": trace.name,
            "agent_name": trace.agent_name,
            "total_episodes": len(episode_rewards),
            "total_events": len(trace.events),
            "final_reward": trace.final_reward,
            "rewards": avg_rewards,
            "losses": avg_losses
        }
    
    async def analyze_learning_progress(self, trace_id: str) -> Dict:
        """
        تحليل تقدم التعلم
        
        Args:
            trace_id: معرف التتبع
        
        Returns:
            تحليل التقدم
        """
        trace = await self.get_trace(trace_id)
        if not trace or not trace.events:
            return {"has_data": False}
        
        # تقسيم الحلقات إلى ثلاث مراحل
        episodes = sorted(list(set(e.episode for e in trace.events)))
        if len(episodes) < 10:
            return {"has_data": True, "insufficient_data": True}
        
        early_episodes = episodes[:len(episodes)//3]
        mid_episodes = episodes[len(episodes)//3:2*len(episodes)//3]
        late_episodes = episodes[2*len(episodes)//3:]
        
        def get_avg_reward_for_episodes(ep_list):
            rewards = []
            for ep in ep_list:
                ep_events = [e for e in trace.events if e.episode == ep]
                if ep_events:
                    avg_reward = sum(e.reward for e in ep_events) / len(ep_events)
                    rewards.append(avg_reward)
            return sum(rewards) / len(rewards) if rewards else 0
        
        early_avg = get_avg_reward_for_episodes(early_episodes)
        mid_avg = get_avg_reward_for_episodes(mid_episodes)
        late_avg = get_avg_reward_for_episodes(late_episodes)
        
        # حساب التحسن
        improvement = (late_avg - early_avg) / early_avg if early_avg > 0 else 0
        
        # تحديد حالة التعلم
        if improvement > 0.5:
            status = "rapid_improvement"
        elif improvement > 0.2:
            status = "steady_improvement"
        elif improvement > 0:
            status = "slow_improvement"
        elif improvement > -0.2:
            status = "plateau"
        else:
            status = "degrading"
        
        return {
            "has_data": True,
            "insufficient_data": False,
            "total_episodes": len(episodes),
            "early_average_reward": early_avg,
            "mid_average_reward": mid_avg,
            "late_average_reward": late_avg,
            "improvement": improvement,
            "status": status,
            "final_epsilon": trace.events[-1].epsilon if trace.events else 0
        }
    
    async def get_statistics(self) -> Dict:
        """إحصائيات تتبع التعلم"""
        async with self._lock:
            total_traces = len(self.traces)
            total_events = sum(len(t.events) for t in self.traces.values())
            
            return {
                "total_traces": total_traces,
                "total_events": total_events,
                "active_events": len(self.active_events),
                "average_events_per_trace": total_events / total_traces if total_traces > 0 else 0,
                "max_traces": self.max_traces
            }


# نسخة عالمية
_default_tracer = None


async def get_learning_tracer() -> LearningTracer:
    """الحصول على نسخة عالمية من تتبع التعلم"""
    global _default_tracer
    if _default_tracer is None:
        _default_tracer = LearningTracer()
    return _default_tracer

