
import asyncio
import json
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

from ..scanners.base_scanner import Finding, Severity
from ..exploitation.exploit_chains import ExploitChain, ChainStep, ExploitChains, get_exploit_chains
from ..exploitation.exploit_orchestrator import ExploitTarget, get_exploit_orchestrator
from ..exploitation.exploit_memory import get_exploit_memory

import logging

logger = logging.getLogger(__name__)


class ChainExecutionStatus(Enum):
    """حالة تنفيذ سلسلة الهجوم"""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"


@dataclass
class AttackChainResult:
    """نتائج سلسلة الهجوم"""
    chain_id: str
    chain_name: str
    status: ChainExecutionStatus
    start_time: datetime
    end_time: Optional[datetime] = None
    steps_executed: int = 0
    steps_succeeded: int = 0
    steps_failed: int = 0
    findings_used: List[str] = field(default_factory=list)
    output: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None


@dataclass
class AttackChainPipelineResult:
    """نتائج خط أنابيب سلاسل الهجوم"""
    target_url: str
    start_time: datetime
    end_time: Optional[datetime] = None
    chains_executed: List[AttackChainResult] = field(default_factory=list)
    successful_chains: int = 0
    failed_chains: int = 0
    total_steps_executed: int = 0
    total_steps_succeeded: int = 0
    overall_success: bool = False
    status: str = "pending"
    error: Optional[str] = None


class AttackChainPipeline:
    """
    خط أنابيب سلاسل الهجوم المتكامل
    
    الميزات:
    - بناء سلاسل هجوم تلقائياً من الثغرات المكتشفة
    - تنفيذ سلاسل هجوم متعددة بشكل متوازي
    - تقييم احتمالية نجاح كل سلسلة
    - اختيار أفضل سلسلة للتنفيذ
    - تتبع تقدم التنفيذ
    - تقارير مفصلة عن النجاحات والإخفاقات
    """
    
    def __init__(self, max_concurrent_chains: int = 3):
        self._max_concurrent_chains = max_concurrent_chains
        self._chains_manager = get_exploit_chains()
        self._orchestrator = get_exploit_orchestrator()
        self._memory = get_exploit_memory()
        
        self._active_pipelines: Dict[str, AttackChainPipelineResult] = {}
        
        logger.info("AttackChainPipeline initialized")
    
    async def run(
        self,
        target_url: str,
        findings: List[Finding],
        auto_select: bool = True,
        chain_ids: List[str] = None,
        max_chains: int = 5
    ) -> AttackChainPipelineResult:
        """
        تنفيذ خط أنابيب سلاسل الهجوم
        
        Args:
            target_url: الرابط المستهدف
            findings: قائمة الثغرات المكتشفة
            auto_select: اختيار تلقائي للسلاسل المناسبة
            chain_ids: قائمة بمعرفات السلاسل للتنفيذ (إذا كان auto_select=False)
            max_chains: الحد الأقصى لعدد السلاسل
        
        Returns:
            نتائج خط الأنابيب
        """
        pipeline_id = f"attack_chain_{target_url}_{int(datetime.now().timestamp())}"
        
        result = AttackChainPipelineResult(
            target_url=target_url,
            start_time=datetime.now()
        )
        
        self._active_pipelines[pipeline_id] = result
        
        logger.info(f"Starting Attack Chain pipeline for {target_url} with {len(findings)} findings")
        
        try:
            # 1. اختيار السلاسل المناسبة
            chains_to_execute = []
            
            if auto_select:
                # اقتراح سلاسل من الثغرات
                suggestions = await self._chains_manager.suggest_chains(findings)
                chains_to_execute = suggestions[:max_chains]
            elif chain_ids:
                for chain_id in chain_ids[:max_chains]:
                    chain = self._chains_manager.get_chain(chain_id)
                    if chain:
                        chains_to_execute.append(chain)
            
            # 2. تنفيذ السلاسل بشكل متوازي
            semaphore = asyncio.Semaphore(self._max_concurrent_chains)
            
            async def execute_with_limit(chain_data):
                async with semaphore:
                    return await self._execute_single_chain(chain_data, findings, target_url)
            
            tasks = [execute_with_limit(chain) for chain in chains_to_execute]
            chain_results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # 3. جمع النتائج
            for res in chain_results:
                if isinstance(res, Exception):
                    logger.error(f"Chain execution error: {res}")
                    result.failed_chains += 1
                elif isinstance(res, AttackChainResult):
                    result.chains_executed.append(res)
                    if res.status == ChainExecutionStatus.COMPLETED:
                        result.successful_chains += 1
                    else:
                        result.failed_chains += 1
                    
                    result.total_steps_executed += res.steps_executed
                    result.total_steps_succeeded += res.steps_succeeded
            
            result.overall_success = result.successful_chains > 0
            result.status = "completed"
            
        except Exception as e:
            logger.error(f"Attack Chain pipeline failed: {e}")
            result.status = "failed"
            result.error = str(e)
        
        finally:
            result.end_time = datetime.now()
        
        logger.info(f"Attack Chain pipeline completed: {result.successful_chains}/{len(result.chains_executed)} chains successful")
        
        return result
    
    async def _execute_single_chain(
        self,
        chain_data: Any,
        findings: List[Finding],
        target_url: str
    ) -> AttackChainResult:
        """
        تنفيذ سلسلة هجوم واحدة
        
        Args:
            chain_data: بيانات السلسلة (Chain object أو dict)
            findings: قائمة الثغرات
            target_url: الرابط المستهدف
        
        Returns:
            نتيجة السلسلة
        """
        # استخراج معلومات السلسلة
        if isinstance(chain_data, dict):
            chain_id = chain_data.get("chain_id", "")
            chain_name = chain_data.get("name", "Unknown Chain")
            chain = self._chains_manager.get_chain(chain_id)
        else:
            chain = chain_data
            chain_id = chain.id if chain else ""
            chain_name = chain.name if chain else "Unknown Chain"
        
        if not chain:
            return AttackChainResult(
                chain_id=chain_id,
                chain_name=chain_name,
                status=ChainExecutionStatus.FAILED,
                start_time=datetime.now(),
                end_time=datetime.now(),
                error="Chain not found"
            )
        
        result = AttackChainResult(
            chain_id=chain_id,
            chain_name=chain_name,
            status=ChainExecutionStatus.IN_PROGRESS,
            start_time=datetime.now()
        )
        
        logger.info(f"Executing attack chain: {chain_name}")
        
        try:
            # تنفيذ السلسلة
            executed_chain = await self._chains_manager.execute_chain(chain_id, self._orchestrator)
            
            # تحديث النتائج
            result.steps_executed = len(executed_chain.steps)
            result.steps_succeeded = sum(1 for s in executed_chain.steps if s.status.value == "success")
            result.steps_failed = sum(1 for s in executed_chain.steps if s.status.value == "failed")
            
            # جمع المخرجات
            for step in executed_chain.steps:
                if step.result and step.result.output:
                    result.output[step.name] = step.result.output[:500]
            
            # تخزين النتائج في الذاكرة
            if result.steps_succeeded > 0:
                self._memory.store_exploit(
                    name=f"Chain_{chain_name}",
                    target_type="web",
                    vulnerability_type="AttackChain",
                    payload=chain_name,
                    encoding="none",
                    success=True,
                    context=target_url,
                    metadata={
                        "chain_id": chain_id,
                        "steps_succeeded": result.steps_succeeded,
                        "steps_total": result.steps_executed
                    }
                )
            
            result.status = (
                ChainExecutionStatus.COMPLETED if result.steps_succeeded == result.steps_executed
                else ChainExecutionStatus.PARTIAL if result.steps_succeeded > 0
                else ChainExecutionStatus.FAILED
            )
            
        except Exception as e:
            logger.error(f"Chain execution failed: {e}")
            result.status = ChainExecutionStatus.FAILED
            result.error = str(e)
        
        finally:
            result.end_time = datetime.now()
        
        return result
    
    async def build_custom_chain(
        self,
        name: str,
        description: str,
        steps: List[Dict],
        target_url: str
    ) -> Optional[str]:
        """
        بناء سلسلة هجوم مخصصة
        
        Args:
            name: اسم السلسلة
            description: وصف السلسلة
            steps: قائمة خطوات السلسلة
            target_url: الرابط المستهدف
        
        Returns:
            معرف السلسلة أو None
        """
        chain_steps = []
        
        for i, step_data in enumerate(steps):
            step = ChainStep(
                id=f"step_{i}",
                name=step_data.get("name", f"Step {i+1}"),
                type=step_data.get("type", "exploit"),
                description=step_data.get("description", ""),
                target=ExploitTarget(
                    url=step_data.get("url", target_url),
                    vulnerability_type=step_data.get("vulnerability_type", ""),
                    parameter=step_data.get("parameter"),
                    method=step_data.get("method", "GET")
                ),
                prerequisite_step_ids=step_data.get("prerequisite_step_ids", []),
                depends_on=step_data.get("depends_on", []),
                timeout=step_data.get("timeout", 60),
                retry_count=step_data.get("retry_count", 3)
            )
            chain_steps.append(step)
        
        chain = ExploitChain(
            id=f"custom_{name}_{int(datetime.now().timestamp())}",
            name=name,
            description=description,
            steps=chain_steps,
            created_at=datetime.now()
        )
        
        return self._chains_manager.add_chain(chain)
    
    async def get_pipeline_result(self, pipeline_id: str) -> Optional[AttackChainPipelineResult]:
        """الحصول على نتيجة خط الأنابيب"""
        return self._active_pipelines.get(pipeline_id)
    
    async def generate_report(self, result: AttackChainPipelineResult, format: str = "json") -> str:
        """
        توليد تقرير سلاسل الهجوم
        
        Args:
            result: نتائج خط الأنابيب
            format: صيغة التقرير (json, markdown)
        
        Returns:
            التقرير كنص
        """
        if format == "json":
            return json.dumps({
                "target_url": result.target_url,
                "start_time": result.start_time.isoformat(),
                "end_time": result.end_time.isoformat() if result.end_time else None,
                "duration": (result.end_time - result.start_time).total_seconds() if result.end_time else 0,
                "statistics": {
                    "chains_executed": len(result.chains_executed),
                    "successful_chains": result.successful_chains,
                    "failed_chains": result.failed_chains,
                    "total_steps": result.total_steps_executed,
                    "successful_steps": result.total_steps_succeeded,
                    "overall_success": result.overall_success
                },
                "chains": [
                    {
                        "name": r.chain_name,
                        "status": r.status.value,
                        "steps_executed": r.steps_executed,
                        "steps_succeeded": r.steps_succeeded,
                        "duration": (r.end_time - r.start_time).total_seconds() if r.end_time else 0,
                        "error": r.error
                    }
                    for r in result.chains_executed
                ]
            }, indent=2)
        
        elif format == "markdown":
            report = f"""# Attack Chain Report

**Target:** {result.target_url}
**Start:** {result.start_time.strftime('%Y-%m-%d %H:%M:%S')}
**End:** {result.end_time.strftime('%Y-%m-%d %H:%M:%S') if result.end_time else 'In progress'}
**Duration:** {(result.end_time - result.start_time).total_seconds():.2f}s

## Summary

| Metric | Value |
|--------|-------|
| Chains Executed | {len(result.chains_executed)} |
| Successful Chains | {result.successful_chains} |
| Failed Chains | {result.failed_chains} |
| Total Steps | {result.total_steps_executed} |
| Successful Steps | {result.total_steps_succeeded} |
| Overall Success | {'✅ Yes' if result.overall_success else '❌ No'} |

## Chain Details

"""
            for chain in result.chains_executed:
                status_icon = "✅" if chain.status == ChainExecutionStatus.COMPLETED else "⚠️" if chain.status == ChainExecutionStatus.PARTIAL else "❌"
                report += f"\n### {status_icon} {chain.chain_name}\n"
                report += f"- **Status:** {chain.status.value}\n"
                report += f"- **Steps:** {chain.steps_succeeded}/{chain.steps_executed} successful\n"
                report += f"- **Duration:** {(chain.end_time - chain.start_time).total_seconds():.2f}s\n"
                if chain.error:
                    report += f"- **Error:** {chain.error}\n"
            
            return report
        
        else:
            raise ValueError(f"Unsupported format: {format}")
    
    async def get_summary(self) -> Dict:
        """ملخص خطوط الأنابيب النشطة"""
        return {
            "active_pipelines": len(self._active_pipelines),
            "completed": sum(1 for r in self._active_pipelines.values() if r.status == "completed"),
            "failed": sum(1 for r in self._active_pipelines.values() if r.status == "failed"),
            "total_chains": sum(len(r.chains_executed) for r in self._active_pipelines.values()),
            "successful_chains": sum(r.successful_chains for r in self._active_pipelines.values()),
            "overall_success_rate": sum(r.successful_chains for r in self._active_pipelines.values()) / 
                                    max(1, sum(len(r.chains_executed) for r in self._active_pipelines.values()))
        }
    
    async def close(self):
        """إغلاق الخط الأنابيب"""
        logger.info("AttackChainPipeline closed")


# نسخة عالمية
async def get_attack_chain_pipeline() -> AttackChainPipeline:
    """الحصول على نسخة من خط أنابيب سلاسل الهجوم"""
    return AttackChainPipeline()

