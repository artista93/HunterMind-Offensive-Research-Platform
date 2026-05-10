
from typing import Dict, List, Optional, Any
from datetime import datetime
import json

from .report_generator import get_report_generator
from .json_exporter import get_json_exporter
from .pdf_exporter import get_pdf_exporter

import logging

logger = logging.getLogger(__name__)


class AttackChainReporter:
    """
    مقدم تقارير سلاسل الهجوم المتقدم
    
    الميزات:
    - تقارير مفصلة عن سلاسل الهجوم
    - توثيق خطوات الاستغلال
    - تحليل المخاطر
    - توصيات أمنية
    """
    
    def __init__(self):
        self.report_gen = get_report_generator()
        self.json_exporter = get_json_exporter()
        self.pdf_exporter = get_pdf_exporter()
        
        logger.info("AttackChainReporter initialized")
    
    async def generate_chain_report(
        self,
        chain_id: str,
        chain_name: str,
        steps: List[Dict],
        target_url: str,
        start_time: datetime,
        end_time: datetime,
        success: bool
    ) -> Dict:
        """
        توليد تقرير لسلسلة هجومية
        
        Args:
            chain_id: معرف السلسلة
            chain_name: اسم السلسلة
            steps: خطوات السلسلة
            target_url: الرابط المستهدف
            start_time: وقت البدء
            end_time: وقت الانتهاء
            success: نجاح السلسلة
        
        Returns:
            بيانات التقرير
        """
        duration = (end_time - start_time).total_seconds()
        
        # تحليل المخاطر
        risk_analysis = self._analyze_risks(steps)
        
        # حساب الإحصائيات
        stats = self._calculate_stats(steps)
        
        report_data = {
            "title": f"Attack Chain Report - {chain_name}",
            "chain_id": chain_id,
            "chain_name": chain_name,
            "target": target_url,
            "duration": self._format_duration(duration),
            "success": success,
            "start_time": start_time.isoformat(),
            "end_time": end_time.isoformat(),
            "statistics": stats,
            "risk_analysis": risk_analysis,
            "steps": steps,
            "recommendations": self._generate_recommendations(steps, success)
        }
        
        return report_data
    
    def _analyze_risks(self, steps: List[Dict]) -> Dict:
        """تحليل المخاطر في السلسلة"""
        risks = {
            "high": 0,
            "medium": 0,
            "low": 0,
            "critical_steps": []
        }
        
        for i, step in enumerate(steps):
            risk = step.get("risk", "medium")
            risks[risk] = risks.get(risk, 0) + 1
            
            if risk == "high":
                risks["critical_steps"].append({
                    "step": i + 1,
                    "name": step.get("name", f"Step {i+1}"),
                    "description": step.get("description", "")
                })
        
        return risks
    
    def _calculate_stats(self, steps: List[Dict]) -> Dict:
        """حساب إحصائيات السلسلة"""
        total = len(steps)
        successful = len([s for s in steps if s.get("success", False)])
        failed = total - successful
        
        # حساب متوسط وقت الخطوة
        total_time = sum(s.get("execution_time", 0) for s in steps)
        avg_time = total_time / total if total > 0 else 0
        
        return {
            "total_steps": total,
            "successful_steps": successful,
            "failed_steps": failed,
            "success_rate": (successful / total * 100) if total > 0 else 0,
            "average_step_time": avg_time,
            "total_execution_time": total_time
        }
    
    def _generate_recommendations(self, steps: List[Dict], success: bool) -> List[str]:
        """توليد توصيات بناءً على السلسلة"""
        recommendations = []
        
        if success:
            recommendations.append("Attack chain successfully executed")
            recommendations.append("Document the attack path for future reference")
            recommendations.append("Consider automating successful steps")
        else:
            recommendations.append("Review failed steps for issues")
            recommendations.append("Consider alternative exploitation techniques")
            recommendations.append("Verify target configurations")
        
        # تحليل الخطوات الفاشلة
        failed_steps = [s for s in steps if not s.get("success", False)]
        if failed_steps:
            recommendations.append(f"Focus on fixing step(s): {', '.join(s.get('name', 'unknown') for s in failed_steps)}")
        
        return recommendations
    
    def _format_duration(self, seconds: float) -> str:
        """تنسيق المدة"""
        if seconds < 60:
            return f"{seconds:.1f} seconds"
        elif seconds < 3600:
            return f"{seconds/60:.1f} minutes"
        else:
            return f"{seconds/3600:.1f} hours"
    
    async def export_to_json(
        self,
        chain_id: str,
        chain_name: str,
        steps: List[Dict],
        target_url: str,
        start_time: datetime,
        end_time: datetime,
        success: bool,
        output_path: str
    ):
        """
        تصدير تقرير سلسلة هجومية إلى JSON
        
        Args:
            chain_id: معرف السلسلة
            chain_name: اسم السلسلة
            steps: خطوات السلسلة
            target_url: الرابط المستهدف
            start_time: وقت البدء
            end_time: وقت الانتهاء
            success: نجاح السلسلة
            output_path: مسار ملف الإخراج
        """
        report_data = await self.generate_chain_report(
            chain_id, chain_name, steps, target_url,
            start_time, end_time, success
        )
        
        await self.json_exporter.export(
            report_data,
            output_path,
            metadata={"type": "attack_chain_report"}
        )
        
        logger.info(f"Attack chain report exported to {output_path}")
    
    async def export_to_pdf(
        self,
        chain_id: str,
        chain_name: str,
        steps: List[Dict],
        target_url: str,
        start_time: datetime,
        end_time: datetime,
        success: bool,
        output_path: str
    ):
        """
        تصدير تقرير سلسلة هجومية إلى PDF
        
        Args:
            chain_id: معرف السلسلة
            chain_name: اسم السلسلة
            steps: خطوات السلسلة
            target_url: الرابط المستهدف
            start_time: وقت البدء
            end_time: وقت الانتهاء
            success: نجاح السلسلة
            output_path: مسار ملف PDF
        """
        report_data = await self.generate_chain_report(
            chain_id, chain_name, steps, target_url,
            start_time, end_time, success
        )
        
        await self.pdf_exporter.export(report_data, output_path, f"Attack Chain Report - {chain_name}")
        
        logger.info(f"Attack chain PDF exported to {output_path}")
    
    async def generate_markdown_report(
        self,
        chain_id: str,
        chain_name: str,
        steps: List[Dict],
        target_url: str,
        start_time: datetime,
        end_time: datetime,
        success: bool
    ) -> str:
        """توليد تقرير Markdown لسلسلة هجومية"""
        report_data = await self.generate_chain_report(
            chain_id, chain_name, steps, target_url,
            start_time, end_time, success
        )
        
        return self.report_gen.generate_markdown(report_data)
    
    async def print_chain_summary(
        self,
        chain_name: str,
        steps: List[Dict],
        success: bool
    ):
        """طباعة ملخص السلسلة في الطرفية"""
        print("\n" + "=" * 60)
        print(f"🔗 Attack Chain: {chain_name}")
        print("=" * 60)
        
        status = "✅ SUCCESS" if success else "❌ FAILED"
        print(f"Status: {status}\n")
        
        print("Steps:")
        for i, step in enumerate(steps, 1):
            step_status = "✅" if step.get("success") else "❌"
            print(f"  {i}. {step_status} {step.get('name', f'Step {i}')}")
            if step.get("description"):
                print(f"     {step.get('description')}")
        
        print("\n" + "=" * 60)


# نسخة عالمية
_default_reporter = None


def get_attack_chain_reporter() -> AttackChainReporter:
    """الحصول على نسخة عالمية من مقدم تقارير سلاسل الهجوم"""
    global _default_reporter
    if _default_reporter is None:
        _default_reporter = AttackChainReporter()
    return _default_reporter

