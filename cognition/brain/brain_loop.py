
import asyncio
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from collections import deque

from .cognitive_core import CognitiveState

import logging

logger = logging.getLogger(__name__)


@dataclass
class LoopCycle:
    """دورة حلقة الدماغ"""
    cycle_id: int
    start_time: datetime
    end_time: datetime
    state: CognitiveState
    observations_count: int
    decisions_count: int
    duration_ms: float
    metadata: Dict[str, Any] = field(default_factory=dict)


class BrainLoop:
    """
    حلقة الدماغ المتقدمة
    
    الميزات:
    - إدارة الحلقة الرئيسية للتفكير
    - تتبع دورات التفكير
    - ضبط تردد الحلقة ديناميكياً
    - تجميع الإحصائيات
    - معالجة الأحداث غير المتزامنة
    """
    
    def __init__(self, tick_interval: float = 1.0):
        self._tick_interval = tick_interval
        self._running = False
        self._loop_task: Optional[asyncio.Task] = None
        self._cycles: deque = deque(maxlen=1000)
        self._cycle_counter = 0
        
        # معالجي الأحداث
        self._event_handlers: Dict[str, List[callable]] = {
            "cycle_start": [],
            "cycle_end": [],
            "state_change": []
        }
        
        logger.info(f"BrainLoop initialized (interval={tick_interval}s)")
    
    async def start(self):
        """بدء حلقة الدماغ"""
        if self._running:
            return
        
        self._running = True
        self._loop_task = asyncio.create_task(self._run_loop())
        
        logger.info("BrainLoop started")
    
    async def stop(self):
        """إيقاف حلقة الدماغ"""
        self._running = False
        
        if self._loop_task:
            self._loop_task.cancel()
            try:
                await self._loop_task
            except asyncio.CancelledError:
                pass
        
        logger.info("BrainLoop stopped")
    
    async def _run_loop(self):
        """تشغيل الحلقة الرئيسية"""
        while self._running:
            cycle_start = datetime.now()
            self._cycle_counter += 1
            
            # إطلاق حدث بدء الدورة
            await self._emit_event("cycle_start", {"cycle_id": self._cycle_counter})
            
            try:
                # تنفيذ مراحل الحلقة
                state = await self._process_cycle()
                
                cycle_end = datetime.now()
                duration_ms = (cycle_end - cycle_start).total_seconds() * 1000
                
                # تسجيل الدورة
                cycle = LoopCycle(
                    cycle_id=self._cycle_counter,
                    start_time=cycle_start,
                    end_time=cycle_end,
                    state=state,
                    observations_count=0,
                    decisions_count=0,
                    duration_ms=duration_ms
                )
                self._cycles.append(cycle)
                
                # إطلاق حدث نهاية الدورة
                await self._emit_event("cycle_end", {
                    "cycle_id": self._cycle_counter,
                    "duration_ms": duration_ms
                })
                
            except Exception as e:
                logger.error(f"Brain loop cycle error: {e}")
            
            # انتظار الفاصل الزمني
            await asyncio.sleep(self._tick_interval)
    
    async def _process_cycle(self) -> CognitiveState:
        """معالجة دورة واحدة من الحلقة"""
        # محاكاة معالجة الدورة
        # في الإصدار الكامل، سيتم استدعاء المكونات الفعلية
        
        await asyncio.sleep(0.1)  # محاكاة وقت المعالجة
        
        return CognitiveState.IDLE
    
    async def set_tick_interval(self, interval: float):
        """
        تغيير تردد الحلقة
        
        Args:
            interval: الفاصل الزمني بالثواني
        """
        self._tick_interval = max(0.1, interval)
        logger.info(f"BrainLoop tick interval changed to {interval}s")
    
    async def get_current_cycle(self) -> Optional[LoopCycle]:
        """الحصول على الدورة الحالية"""
        return self._cycles[-1] if self._cycles else None
    
    async def get_cycle_history(self, limit: int = 100) -> List[LoopCycle]:
        """الحصول على تاريخ الدورات"""
        return list(self._cycles)[-limit:]
    
    async def get_statistics(self) -> Dict:
        """إحصائيات الحلقة"""
        if not self._cycles:
            return {"total_cycles": 0}
        
        durations = [c.duration_ms for c in self._cycles]
        
        return {
            "total_cycles": len(self._cycles),
            "current_cycle": self._cycle_counter,
            "average_duration_ms": sum(durations) / len(durations),
            "min_duration_ms": min(durations),
            "max_duration_ms": max(durations),
            "tick_interval": self._tick_interval,
            "running": self._running
        }
    
    async def on(self, event: str, handler: callable):
        """تسجيل معالج حدث"""
        if event in self._event_handlers:
            self._event_handlers[event].append(handler)
    
    async def _emit_event(self, event: str, data: Dict):
        """إطلاق حدث"""
        if event in self._event_handlers:
            for handler in self._event_handlers[event]:
                try:
                    if asyncio.iscoroutinefunction(handler):
                        await handler(data)
                    else:
                        handler(data)
                except Exception as e:
                    logger.error(f"Event handler error: {e}")

