
import re
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum

import logging

logger = logging.getLogger(__name__)


class SinkType(Enum):
    """نوع المصرف (Sink)"""
    INNER_HTML = "innerHTML"
    OUTER_HTML = "outerHTML"
    DOCUMENT_WRITE = "document.write"
    DOCUMENT_WRITELN = "document.writeln"
    EVAL = "eval"
    FUNCTION = "Function"
    SET_TIMEOUT = "setTimeout"
    SET_INTERVAL = "setInterval"
    EXEC_SCRIPT = "execScript"
    SRC = "src"
    HREF = "href"
    POST_MESSAGE = "postMessage"
    WEB_SQL = "openDatabase"
    LOCAL_STORAGE = "localStorage"
    SESSION_STORAGE = "sessionStorage"


@dataclass
class DetectedSink:
    """مصرف مكتشف"""
    sink_type: SinkType
    location: str  # URL أو اسم الملف
    line_number: Optional[int] = None
    code_snippet: str = ""
    context: str = ""
    risk_level: str = "medium"  # low, medium, high, critical
    metadata: Dict[str, Any] = field(default_factory=dict)


class SinkDetector:
    """
    كاشف المصارف المتقدم
    
    الميزات:
    - كشف المصارف الخطرة في JavaScript
    - تحليل مستوى الخطورة
    - تحديد موقع المصرف (ملف، سطر)
    - دمج مع كشف السياق
    - إحصائيات المخاطر
    """
    
    # أنماط كشف المصارف
    SINK_PATTERNS = {
        SinkType.INNER_HTML: [
            r'\.innerHTML\s*=\s*[^;]+',
            r'\.innerHTML\s*\+=\s*[^;]+',
        ],
        SinkType.OUTER_HTML: [
            r'\.outerHTML\s*=\s*[^;]+',
        ],
        SinkType.DOCUMENT_WRITE: [
            r'document\.write\s*\([^)]+\)',
            r'document\.writeln\s*\([^)]+\)',
        ],
        SinkType.EVAL: [
            r'eval\s*\([^)]+\)',
            r'\(new\s+Function\([^)]+\)\)',
        ],
        SinkType.FUNCTION: [
            r'new\s+Function\s*\([^)]+\)',
            r'Function\s*\([^)]+\)',
        ],
        SinkType.SET_TIMEOUT: [
            r'setTimeout\s*\(\s*["\'][^"\']+["\'][^,]*,\s*\d+',
            r'setTimeout\s*\(\s*[^,]+,\s*\d+',
        ],
        SinkType.SET_INTERVAL: [
            r'setInterval\s*\(\s*["\'][^"\']+["\'][^,]*,\s*\d+',
            r'setInterval\s*\(\s*[^,]+,\s*\d+',
        ],
        SinkType.SRC: [
            r'\.src\s*=\s*[^;]+',
            r'src\s*:\s*["\'][^"\'][^"\']*["\']',
        ],
        SinkType.HREF: [
            r'\.href\s*=\s*[^;]+',
            r'href\s*:\s*["\'][^"\'][^"\']*["\']',
            r'location\.href\s*=\s*[^;]+',
        ],
        SinkType.POST_MESSAGE: [
            r'\.postMessage\s*\([^,]+,\s*["\'][^"\']+["\']',
        ],
        SinkType.WEB_SQL: [
            r'openDatabase\s*\([^)]+\)',
        ],
        SinkType.LOCAL_STORAGE: [
            r'localStorage\.setItem\s*\([^,]+,\s*[^)]+\)',
            r'localStorage\[\s*["\'][^"\']+["\']\s*\]\s*=\s*[^;]+',
        ],
        SinkType.SESSION_STORAGE: [
            r'sessionStorage\.setItem\s*\([^,]+,\s*[^)]+\)',
            r'sessionStorage\[\s*["\'][^"\']+["\']\s*\]\s*=\s*[^;]+',
        ],
    }
    
    # مستويات الخطورة حسب نوع المصرف
    RISK_LEVELS = {
        SinkType.EVAL: "critical",
        SinkType.FUNCTION: "critical",
        SinkType.DOCUMENT_WRITE: "high",
        SinkType.INNER_HTML: "high",
        SinkType.OUTER_HTML: "high",
        SinkType.EXEC_SCRIPT: "high",
        SinkType.SET_TIMEOUT: "medium",
        SinkType.SET_INTERVAL: "medium",
        SinkType.SRC: "medium",
        SinkType.HREF: "medium",
        SinkType.POST_MESSAGE: "medium",
        SinkType.LOCAL_STORAGE: "low",
        SinkType.SESSION_STORAGE: "low",
        SinkType.WEB_SQL: "low",
    }
    
    def __init__(self):
        self._detected_sinks: Dict[str, List[DetectedSink]] = {}
        
        logger.info("SinkDetector initialized")
    
    async def detect_in_js(
        self,
        js_content: str,
        source_url: str
    ) -> List[DetectedSink]:
        """
        كشف المصارف في ملف JavaScript
        
        Args:
            js_content: محتوى JavaScript
            source_url: رابط الملف المصدر
        
        Returns:
            قائمة بالمصارف المكتشفة
        """
        sinks = []
        lines = js_content.split('\n')
        
        for sink_type, patterns in self.SINK_PATTERNS.items():
            for pattern in patterns:
                for line_num, line in enumerate(lines, 1):
                    matches = re.finditer(pattern, line, re.IGNORECASE)
                    for match in matches:
                        sink = DetectedSink(
                            sink_type=sink_type,
                            location=source_url,
                            line_number=line_num,
                            code_snippet=line.strip()[:200],
                            context=self._get_context(lines, line_num),
                            risk_level=self.RISK_LEVELS.get(sink_type, "medium")
                        )
                        sinks.append(sink)
        
        # إزالة التكرارات (نفس السطر ونفس النوع)
        unique_sinks = []
        seen = set()
        for sink in sinks:
            key = f"{sink.sink_type.value}_{sink.location}_{sink.line_number}"
            if key not in seen:
                seen.add(key)
                unique_sinks.append(sink)
        
        # تخزين النتائج
        if source_url not in self._detected_sinks:
            self._detected_sinks[source_url] = []
        self._detected_sinks[source_url].extend(unique_sinks)
        
        logger.info(f"Detected {len(unique_sinks)} sinks in {source_url}")
        
        return unique_sinks
    
    async def detect_in_html(
        self,
        html: str,
        base_url: str
    ) -> List[DetectedSink]:
        """
        كشف المصارف في HTML (سكربتات مضمنة)
        
        Args:
            html: محتوى HTML
            base_url: الرابط الأساسي
        
        Returns:
            قائمة بالمصارف المكتشفة
        """
        sinks = []
        
        # استخراج السكربتات المضمنة
        inline_script_pattern = re.compile(r'<script[^>]*>(.*?)</script>', re.I | re.DOTALL)
        
        for i, match in enumerate(inline_script_pattern.finditer(html)):
            script_content = match.group(1)
            if script_content.strip():
                script_sinks = await self.detect_in_js(
                    script_content,
                    f"{base_url}:inline_{i}"
                )
                sinks.extend(script_sinks)
        
        # استخراج معالج الأحداث المضمنة
        event_patterns = [
            r'on\w+\s*=\s*["\']([^"\']+)["\']',
            r'on\w+\s*=\s*([^\s>]+)',
        ]
        
        for pattern in event_patterns:
            matches = re.finditer(pattern, html, re.I)
            for match in matches:
                event_code = match.group(1)
                sink = DetectedSink(
                    sink_type=SinkType.EVAL,  # معالج الأحداث يعمل مثل eval
                    location=base_url,
                    code_snippet=event_code[:200],
                    risk_level="high"
                )
                sinks.append(sink)
        
        return sinks
    
    def _get_context(self, lines: List[str], line_num: int, radius: int = 2) -> str:
        """الحصول على النص المحيط للسطر"""
        start = max(0, line_num - radius - 1)
        end = min(len(lines), line_num + radius)
        context_lines = lines[start:end]
        
        result = []
        for i, line in enumerate(context_lines, start + 1):
            prefix = ">" if i == line_num else " "
            result.append(f"{prefix} {i:4d} | {line}")
        
        return "\n".join(result)
    
    async def analyze_risk(
        self,
        sinks: List[DetectedSink]
    ) -> Dict[str, Any]:
        """
        تحليل المخاطر الإجمالية للمصارف المكتشفة
        
        Args:
            sinks: قائمة المصارف
        
        Returns:
            تحليل المخاطر
        """
        if not sinks:
            return {"has_sinks": False}
        
        risk_counts = {}
        for sink in sinks:
            risk_counts[sink.risk_level] = risk_counts.get(sink.risk_level, 0) + 1
        
        # تحديد المخطر الإجمالي
        if risk_counts.get("critical", 0) > 0:
            overall_risk = "critical"
        elif risk_counts.get("high", 0) > 0:
            overall_risk = "high"
        elif risk_counts.get("medium", 0) > 0:
            overall_risk = "medium"
        else:
            overall_risk = "low"
        
        return {
            "has_sinks": True,
            "total_sinks": len(sinks),
            "risk_distribution": risk_counts,
            "overall_risk": overall_risk,
            "critical_sinks": [s for s in sinks if s.risk_level == "critical"],
            "high_sinks": [s for s in sinks if s.risk_level == "high"],
            "recommendations": self._get_risk_recommendations(overall_risk, risk_counts)
        }
    
    def _get_risk_recommendations(self, overall_risk: str, risk_counts: Dict) -> List[str]:
        """الحصول على توصيات بناءً على المخاطر"""
        recommendations = []
        
        if overall_risk in ["critical", "high"]:
            recommendations.append("⚠️ CRITICAL: Multiple dangerous sinks detected")
            recommendations.append("Review all eval(), innerHTML, and document.write usage")
            recommendations.append("Implement strict Content Security Policy (CSP)")
            recommendations.append("Use textContent instead of innerHTML where possible")
        
        if risk_counts.get("critical", 0) > 0:
            recommendations.append("Remove or secure eval() and Function() usage - they are extremely dangerous")
        
        if risk_counts.get("high", 0) > 0:
            recommendations.append("Sanitize all data before assigning to innerHTML/outerHTML")
            recommendations.append("Avoid document.write for dynamic content")
        
        if risk_counts.get("medium", 0) > 0:
            recommendations.append("Validate URLs before assigning to src/href")
            recommendations.append("Use safe alternatives for setTimeout with strings")
        
        return recommendations
    
    async def get_sinks_for_url(self, url: str) -> List[DetectedSink]:
        """الحصول على المصارف المكتشفة لهدف معين"""
        return self._detected_sinks.get(url, [])
    
    async def get_critical_sinks(self) -> List[DetectedSink]:
        """الحصول على المصارف الحرجة فقط"""
        critical = []
        for sinks in self._detected_sinks.values():
            for sink in sinks:
                if sink.risk_level in ["critical", "high"]:
                    critical.append(sink)
        return critical
    
    async def get_statistics(self) -> Dict:
        """إحصائيات الكاشف"""
        total_sinks = sum(len(v) for v in self._detected_sinks.values())
        
        # إحصائيات حسب النوع
        type_stats = {}
        for sinks in self._detected_sinks.values():
            for sink in sinks:
                type_stats[sink.sink_type.value] = type_stats.get(sink.sink_type.value, 0) + 1
        
        # إحصائيات حسب المخاطر
        risk_stats = {}
        for sinks in self._detected_sinks.values():
            for sink in sinks:
                risk_stats[sink.risk_level] = risk_stats.get(sink.risk_level, 0) + 1
        
        return {
            "total_files_analyzed": len(self._detected_sinks),
            "total_sinks": total_sinks,
            "avg_sinks_per_file": total_sinks / len(self._detected_sinks) if self._detected_sinks else 0,
            "by_type": type_stats,
            "by_risk": risk_stats,
            "critical_count": risk_stats.get("critical", 0),
            "high_count": risk_stats.get("high", 0)
        }
    
    async def clear_sinks(self, url: str = None):
        """مسح المصارف المكتشفة"""
        if url:
            self._detected_sinks.pop(url, None)
        else:
            self._detected_sinks.clear()
        
        logger.info(f"Sinks cleared for {url if url else 'all targets'}")

