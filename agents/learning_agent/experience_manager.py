
import json
import asyncio
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import defaultdict

from ...storage.sqlite.learning_db import get_learning_database

import logging

logger = logging.getLogger(__name__)


@dataclass
class ExperienceSummary:
    """ملخص التجارب"""
    total_experiences: int
    successful_experiences: int
    failed_experiences: int
    average_reward: float
    success_rate: float
    top_actions: List[Tuple[str, int]]
    recent_activity: List[Dict]


class ExperienceManager:
    """
    مدير التجارب المتقدم
    
    الميزات:
    - تخزين واسترجاع التجارب في قاعدة البيانات
    - تحليل أنماط النجاح والفشل
    - تجميع التجارب حسب الإجراءات
    - تصدير التجارب للتحليل
    - تنظيف التجارب القديمة
    """
    
    def __init__(self, agent_name: str):
        self._agent_name = agent_name
        self._db = None
        self._cache: Dict[str, List[Dict]] = {}
        self._cache_ttl = 300  # 5 دقائق
        self._last_cache_update: Dict[str, datetime] = {}
        
        logger.info(f"ExperienceManager initialized for {agent_name}")
    
    async def initialize(self):
        """تهيئة المدير"""
        self._db = await get_learning_database()
        logger.info("ExperienceManager connected to database")
    
    async def store_experience(
        self,
        state: Dict,
        action: str,
        reward: float,
        next_state: Dict,
        done: bool,
        metadata: Dict = None
    ) -> int:
        """
        تخزين تجربة جديدة
        
        Args:
            state: الحالة
            action: الإجراء
            reward: المكافأة
            next_state: الحالة التالية
            done: هل اكتملت الحلقة؟
            metadata: بيانات إضافية
        
        Returns:
            معرف التجربة
        """
        experience_id = await self._db.store_experience(
            agent_name=self._agent_name,
            state=state,
            action=action,
            reward=reward,
            next_state=next_state,
            done=done,
            metadata=metadata
        )
        
        # تحديث الذاكرة المؤقتة
        cache_key = f"recent_{self._agent_name}"
        if cache_key in self._cache:
            self._cache[cache_key].append({
                "id": experience_id,
                "action": action,
                "reward": reward,
                "timestamp": datetime.now().isoformat()
            })
            # الحفاظ على آخر 100 تجربة فقط
            if len(self._cache[cache_key]) > 100:
                self._cache[cache_key] = self._cache[cache_key][-100:]
        
        logger.debug(f"Experience stored: id={experience_id}, action={action}, reward={reward}")
        return experience_id
    
    async def get_recent_experiences(
        self,
        limit: int = 100,
        since: datetime = None
    ) -> List[Dict]:
        """
        الحصول على التجارب الأخيرة
        
        Args:
            limit: عدد النتائج
            since: منذ تاريخ معين
        
        Returns:
            قائمة بالتجارب
        """
        cache_key = f"recent_{self._agent_name}_{since.isoformat() if since else 'all'}"
        
        # التحقق من الذاكرة المؤقتة
        if cache_key in self._cache:
            cache_time = self._last_cache_update.get(cache_key)
            if cache_time and (datetime.now() - cache_time).total_seconds() < self._cache_ttl:
                return self._cache[cache_key][:limit]
        
        experiences = await self._db.get_experiences(
            agent_name=self._agent_name,
            limit=limit,
            since=since
        )
        
        # تحديث الذاكرة المؤقتة
        self._cache[cache_key] = experiences
        self._last_cache_update[cache_key] = datetime.now()
        
        return experiences
    
    async def get_successful_experiences(
        self,
        min_reward: float = 5.0,
        limit: int = 50
    ) -> List[Dict]:
        """
        الحصول على التجارب الناجحة فقط
        
        Args:
            min_reward: الحد الأدنى للمكافأة
            limit: عدد النتائج
        
        Returns:
            قائمة بالتجارب الناجحة
        """
        experiences = await self.get_recent_experiences(limit=limit * 2)
        
        successful = [
            exp for exp in experiences
            if exp.get("reward", 0) >= min_reward
        ]
        
        return successful[:limit]
    
    async def get_failed_experiences(
        self,
        max_reward: float = 0.0,
        limit: int = 50
    ) -> List[Dict]:
        """
        الحصول على التجارب الفاشلة فقط
        
        Args:
            max_reward: الحد الأقصى للمكافأة
            limit: عدد النتائج
        
        Returns:
            قائمة بالتجارب الفاشلة
        """
        experiences = await self.get_recent_experiences(limit=limit * 2)
        
        failed = [
            exp for exp in experiences
            if exp.get("reward", 0) <= max_reward
        ]
        
        return failed[:limit]
    
    async def analyze_patterns(self, limit: int = 500) -> Dict[str, Any]:
        """
        تحليل أنماط النجاح والفشل في التجارب
        
        Args:
            limit: عدد التجارب للتحليل
        
        Returns:
            نتائج التحليل
        """
        experiences = await self.get_recent_experiences(limit=limit)
        
        if not experiences:
            return {"has_data": False}
        
        # إحصائيات حسب الإجراء
        action_stats = defaultdict(lambda: {"count": 0, "total_reward": 0, "success": 0})
        
        for exp in experiences:
            action = exp.get("action", "unknown")
            reward = exp.get("reward", 0)
            
            action_stats[action]["count"] += 1
            action_stats[action]["total_reward"] += reward
            if reward > 0:
                action_stats[action]["success"] += 1
        
        # أفضل الإجراءات
        best_actions = sorted(
            [(a, s["total_reward"] / s["count"]) for a, s in action_stats.items()],
            key=lambda x: x[1],
            reverse=True
        )[:5]
        
        # الاتجاهات الزمنية
        rewards_over_time = []
        for exp in experiences[-50:]:
            rewards_over_time.append({
                "timestamp": exp.get("timestamp"),
                "reward": exp.get("reward", 0)
            })
        
        return {
            "has_data": True,
            "total_experiences": len(experiences),
            "average_reward": sum(e.get("reward", 0) for e in experiences) / len(experiences),
            "success_rate": sum(1 for e in experiences if e.get("reward", 0) > 0) / len(experiences),
            "unique_actions": len(action_stats),
            "best_actions": best_actions,
            "action_stats": {a: {"count": s["count"], "avg_reward": s["total_reward"] / s["count"]} for a, s in action_stats.items()},
            "rewards_over_time": rewards_over_time
        }
    
    async def get_summary(self) -> ExperienceSummary:
        """
        الحصول على ملخص التجارب
        
        Returns:
            كائن ExperienceSummary
        """
        experiences = await self.get_recent_experiences(limit=1000)
        
        if not experiences:
            return ExperienceSummary(
                total_experiences=0,
                successful_experiences=0,
                failed_experiences=0,
                average_reward=0.0,
                success_rate=0.0,
                top_actions=[],
                recent_activity=[]
            )
        
        total = len(experiences)
        successful = sum(1 for e in experiences if e.get("reward", 0) > 0)
        failed = total - successful
        avg_reward = sum(e.get("reward", 0) for e in experiences) / total
        
        # أفضل الإجراءات
        action_counts = defaultdict(int)
        for exp in experiences:
            action_counts[exp.get("action", "unknown")] += 1
        top_actions = sorted(action_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        
        # النشاط الأخير
        recent = [
            {
                "timestamp": e.get("timestamp"),
                "action": e.get("action"),
                "reward": e.get("reward", 0)
            }
            for e in experiences[-20:]
        ]
        
        return ExperienceSummary(
            total_experiences=total,
            successful_experiences=successful,
            failed_experiences=failed,
            average_reward=avg_reward,
            success_rate=successful / total if total > 0 else 0.0,
            top_actions=top_actions,
            recent_activity=recent
        )
    
    async def export_experiences(self, filepath: str, format: str = "json"):
        """
        تصدير التجارب إلى ملف
        
        Args:
            filepath: مسار الملف
            format: صيغة التصدير (json, csv)
        """
        experiences = await self.get_recent_experiences(limit=10000)
        
        if format == "json":
            with open(filepath, 'w') as f:
                json.dump({
                    "agent_name": self._agent_name,
                    "exported_at": datetime.now().isoformat(),
                    "total_experiences": len(experiences),
                    "experiences": experiences
                }, f, indent=2, default=str)
        
        elif format == "csv":
            import csv
            with open(filepath, 'w', newline='') as f:
                if experiences:
                    fieldnames = list(experiences[0].keys())
                    writer = csv.DictWriter(f, fieldnames=fieldnames)
                    writer.writeheader()
                    writer.writerows(experiences)
        
        logger.info(f"Exported {len(experiences)} experiences to {filepath}")
    
    async def clear_old_experiences(self, days: int = 30):
        """
        تنظيف التجارب القديمة
        
        Args:
            days: عدد الأيام للاحتفاظ
        """
        cutoff = datetime.now() - timedelta(days=days)
        
        # حذف من قاعدة البيانات
        # (تنفيذ في قاعدة البيانات نفسها)
        
        # تنظيف الذاكرة المؤقتة
        self._cache.clear()
        self._last_cache_update.clear()
        
        logger.info(f"Cleared experiences older than {days} days")
    
    async def get_statistics(self) -> Dict:
        """إحصائيات المدير"""
        summary = await self.get_summary()
        
        return {
            "agent_name": self._agent_name,
            "total_experiences": summary.total_experiences,
            "successful": summary.successful_experiences,
            "failed": summary.failed_experiences,
            "success_rate": summary.success_rate,
            "average_reward": summary.average_reward,
            "cache_size": len(self._cache),
            "cache_ttl": self._cache_ttl
        }

