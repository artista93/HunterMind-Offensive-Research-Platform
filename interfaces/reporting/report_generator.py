
import json
from typing import Dict, List, Optional, Any
from datetime import datetime
from dataclasses import dataclass, field

import logging

logger = logging.getLogger(__name__)


@dataclass
class ReportSection:
    """قسم من التقرير"""
    title: str
    content: str
    level: int = 1


class ReportGenerator:
    """
    مولد التقارير المتقدم
    
    الميزات:
    - توليد تقارير بصيغ متعددة (JSON, HTML, Markdown)
    - تقارير قابلة للتخصيص
    - إحصائيات ورسوم بيانية نصية
    - تصدير إلى ملفات
    """
    
    def __init__(self):
        self.sections: List[ReportSection] = []
        self.metadata: Dict[str, Any] = {
            "generated_at": datetime.now().isoformat(),
            "generator": "HunterMind Report Generator",
            "version": "1.0.0"
        }
        
        logger.info("ReportGenerator initialized")
    
    def add_section(self, title: str, content: str, level: int = 1):
        """إضافة قسم إلى التقرير"""
        self.sections.append(ReportSection(title=title, content=content, level=level))
    
    def generate_json(self, data: Dict) -> str:
        """
        توليد تقرير بصيغة JSON
        
        Args:
            data: بيانات التقرير
        
        Returns:
            نص JSON
        """
        report = {
            "metadata": self.metadata,
            "data": data
        }
        
        return json.dumps(report, indent=2, default=str)
    
    def generate_markdown(self, data: Dict) -> str:
        """
        توليد تقرير بصيغة Markdown
        
        Args:
            data: بيانات التقرير
        
        Returns:
            نص Markdown
        """
        lines = []
        
        # العنوان الرئيسي
        lines.append(f"# {data.get('title', 'HunterMind Security Report')}\n")
        
        # معلومات أساسية
        lines.append("## Report Information\n")
        lines.append(f"- **Generated:** {self.metadata['generated_at']}")
        lines.append(f"- **Target:** {data.get('target', 'N/A')}")
        lines.append(f"- **Scan Type:** {data.get('scan_type', 'N/A')}")
        lines.append(f"- **Duration:** {data.get('duration', 'N/A')}\n")
        
        # الملخص
        if "summary" in data:
            lines.append("## Executive Summary\n")
            lines.append(data["summary"])
            lines.append("")
        
        # الإحصائيات
        if "statistics" in data:
            lines.append("## Statistics\n")
            stats = data["statistics"]
            lines.append("| Metric | Value |")
            lines.append("|--------|-------|")
            for key, value in stats.items():
                lines.append(f"| {key} | {value} |")
            lines.append("")
        
        # الثغرات
        if "vulnerabilities" in data and data["vulnerabilities"]:
            lines.append("## Vulnerabilities Found\n")
            
            for i, vuln in enumerate(data["vulnerabilities"], 1):
                lines.append(f"### {i}. {vuln.get('type', 'Unknown')} ({vuln.get('severity', 'unknown').upper()})\n")
                lines.append(f"- **URL:** {vuln.get('url', 'N/A')}")
                lines.append(f"- **Parameter:** {vuln.get('parameter', 'N/A')}")
                lines.append(f"- **Description:** {vuln.get('description', 'N/A')}")
                lines.append(f"- **Remediation:** {vuln.get('remediation', 'N/A')}")
                if vuln.get('payload'):
                    lines.append(f"- **Payload:** `{vuln['payload']}`")
                lines.append("")
        
        # التوصيات
        if "recommendations" in data and data["recommendations"]:
            lines.append("## Recommendations\n")
            for rec in data["recommendations"]:
                lines.append(f"- {rec}")
            lines.append("")
        
        return "\n".join(lines)
    
    def generate_html(self, data: Dict) -> str:
        """
        توليد تقرير بصيغة HTML
        
        Args:
            data: بيانات التقرير
        
        Returns:
            نص HTML
        """
        html = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{data.get('title', 'HunterMind Security Report')}</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: linear-gradient(135deg, #1a1a2e, #16213e);
            color: #fff;
            padding: 40px;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: rgba(255,255,255,0.05);
            border-radius: 15px;
            padding: 30px;
            backdrop-filter: blur(10px);
        }}
        
        h1 {{
            font-size: 2rem;
            margin-bottom: 20px;
            background: linear-gradient(135deg, #667eea, #764ba2);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }}
        
        h2 {{
            font-size: 1.5rem;
            margin: 25px 0 15px 0;
            color: #667eea;
            border-bottom: 2px solid #667eea;
            padding-bottom: 10px;
        }}
        
        h3 {{
            font-size: 1.2rem;
            margin: 20px 0 10px 0;
            color: #a0a0ff;
        }}
        
        .info {{
            background: rgba(0,0,0,0.3);
            padding: 15px;
            border-radius: 10px;
            margin-bottom: 20px;
        }}
        
        .info-item {{
            display: flex;
            margin-bottom: 8px;
        }}
        
        .info-label {{
            font-weight: bold;
            width: 120px;
            color: #888;
        }}
        
        .info-value {{
            color: #fff;
        }}
        
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
        }}
        
        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid rgba(255,255,255,0.1);
        }}
        
        th {{
            background: rgba(102,126,234,0.3);
            color: #667eea;
        }}
        
        .severity {{
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.8rem;
            font-weight: bold;
        }}
        
        .severity-critical {{ background: #e74c3c; }}
        .severity-high {{ background: #e67e22; }}
        .severity-medium {{ background: #f1c40f; color: #333; }}
        .severity-low {{ background: #27ae60; }}
        
        .vuln-card {{
            background: rgba(255,255,255,0.05);
            border-radius: 10px;
            padding: 15px;
            margin-bottom: 15px;
            border-left: 4px solid;
        }}
        
        .recommendations {{
            background: rgba(39,174,96,0.1);
            border-left: 4px solid #27ae60;
            padding: 15px;
            border-radius: 10px;
            margin: 20px 0;
        }}
        
        .recommendations ul {{
            margin-left: 20px;
        }}
        
        .footer {{
            text-align: center;
            margin-top: 30px;
            padding-top: 20px;
            border-top: 1px solid rgba(255,255,255,0.1);
            color: #888;
            font-size: 0.8rem;
        }}
        
        @media (max-width: 768px) {{
            body {{
                padding: 20px;
            }}
            
            .info-item {{
                flex-direction: column;
            }}
            
            .info-label {{
                width: auto;
                margin-bottom: 5px;
            }}
            
            table {{
                font-size: 0.8rem;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>{data.get('title', 'HunterMind Security Report')}</h1>
        
        <div class="info">
            <div class="info-item">
                <span class="info-label">Generated:</span>
                <span class="info-value">{self.metadata['generated_at']}</span>
            </div>
            <div class="info-item">
                <span class="info-label">Target:</span>
                <span class="info-value">{data.get('target', 'N/A')}</span>
            </div>
            <div class="info-item">
                <span class="info-label">Scan Type:</span>
                <span class="info-value">{data.get('scan_type', 'N/A')}</span>
            </div>
            <div class="info-item">
                <span class="info-label">Duration:</span>
                <span class="info-value">{data.get('duration', 'N/A')}</span>
            </div>
        </div>
        
        <h2>Executive Summary</h2>
        <p>{data.get('summary', 'No summary available.')}</p>
        
        <h2>Statistics</h2>
        <table>
            <thead>
                <tr><th>Metric</th><th>Value</th></tr>
            </thead>
            <tbody>
'''
        
        stats = data.get("statistics", {})
        for key, value in stats.items():
            html += f"<tr><td>{key}</td><td>{value}</td></tr>\n"
        
        html += '''
            </tbody>
        </table>
        
        <h2>Vulnerabilities Found</h2>
'''
        
        vulns = data.get("vulnerabilities", [])
        for vuln in vulns:
            severity = vuln.get("severity", "low")
            border_color = {
                "critical": "#e74c3c",
                "high": "#e67e22",
                "medium": "#f1c40f",
                "low": "#27ae60"
            }.get(severity, "#888")
            
            html += f'''
        <div class="vuln-card" style="border-left-color: {border_color};">
            <h3>{vuln.get('type', 'Unknown')} <span class="severity severity-{severity}">{severity.upper()}</span></h3>
            <p><strong>URL:</strong> {vuln.get('url', 'N/A')}</p>
            <p><strong>Parameter:</strong> {vuln.get('parameter', 'N/A')}</p>
            <p><strong>Description:</strong> {vuln.get('description', 'N/A')}</p>
            <p><strong>Remediation:</strong> {vuln.get('remediation', 'N/A')}</p>
'''
            if vuln.get("payload"):
                html += f'<p><strong>Payload:</strong> <code>{vuln["payload"]}</code></p>\n'
            html += "        </div>\n"
        
        if data.get("recommendations"):
            html += '''
        <div class="recommendations">
            <h2>Recommendations</h2>
            <ul>
'''
            for rec in data["recommendations"]:
                html += f"<li>{rec}</li>\n"
            html += '''
            </ul>
        </div>
'''
        
        html += f'''
        <div class="footer">
            <p>Generated by {self.metadata['generator']} v{self.metadata['version']}</p>
        </div>
    </div>
</body>
</html>'''
        
        return html
    
    def generate_scan_report(
        self,
        scan_id: str,
        target_url: str,
        findings: List[Dict],
        start_time: datetime,
        end_time: datetime,
        statistics: Dict
    ) -> Dict:
        """
        توليد تقرير فحص
        
        Args:
            scan_id: معرف الفحص
            target_url: الرابط المستهدف
            findings: قائمة الثغرات
            start_time: وقت البدء
            end_time: وقت الانتهاء
            statistics: إحصائيات الفحص
        
        Returns:
            بيانات التقرير
        """
        duration = (end_time - start_time).total_seconds()
        
        report_data = {
            "title": f"Scan Report - {scan_id}",
            "target": target_url,
            "scan_type": statistics.get("scan_type", "full"),
            "duration": self._format_duration(duration),
            "summary": self._generate_summary(findings, statistics),
            "statistics": {
                "Pages Crawled": statistics.get("pages_crawled", 0),
                "Forms Found": statistics.get("forms_found", 0),
                "API Endpoints": statistics.get("api_endpoints", 0),
                "Vulnerabilities": len(findings),
                "Critical": len([f for f in findings if f.get("severity") == "critical"]),
                "High": len([f for f in findings if f.get("severity") == "high"]),
                "Medium": len([f for f in findings if f.get("severity") == "medium"]),
                "Low": len([f for f in findings if f.get("severity") == "low"])
            },
            "vulnerabilities": findings,
            "recommendations": self._generate_recommendations(findings)
        }
        
        return report_data
    
    def _generate_summary(self, findings: List[Dict], statistics: Dict) -> str:
        """توليد الملخص التنفيذي"""
        total = len(findings)
        critical = len([f for f in findings if f.get("severity") == "critical"])
        
        if total == 0:
            return "No vulnerabilities were discovered during the scan. The target appears to be secure based on the tests performed."
        
        summary = f"The scan identified {total} potential security issues. "
        if critical > 0:
            summary += f"Of these, {critical} are rated as CRITICAL and require immediate attention. "
        
        summary += f"The scan covered {statistics.get('pages_crawled', 0)} pages and discovered {statistics.get('api_endpoints', 0)} API endpoints."
        
        return summary
    
    def _generate_recommendations(self, findings: List[Dict]) -> List[str]:
        """توليد توصيات بناءً على الثغرات"""
        recommendations = set()
        
        for finding in findings:
            if finding.get("type") == "XSS":
                recommendations.add("Implement proper output encoding (HTML entity encode, JavaScript escape)")
                recommendations.add("Implement Content Security Policy (CSP)")
            
            elif finding.get("type") == "SQL Injection":
                recommendations.add("Use parameterized queries/prepared statements")
                recommendations.add("Implement input validation and sanitization")
            
            elif finding.get("type") == "IDOR":
                recommendations.add("Implement proper access control checks")
                recommendations.add("Use indirect references instead of direct IDs")
            
            elif finding.get("type") == "CSRF":
                recommendations.add("Implement anti-CSRF tokens")
                recommendations.add("Enable SameSite cookie attribute")
            
            elif finding.get("type") == "RCE":
                recommendations.add("Avoid using system calls with user input")
                recommendations.add("Implement strict input validation")
        
        if not recommendations:
            recommendations.add("Regular security updates and patches")
            recommendations.add("Conduct periodic security assessments")
        
        return list(recommendations)
    
    def _format_duration(self, seconds: float) -> str:
        """تنسيق المدة"""
        if seconds < 60:
            return f"{seconds:.1f} seconds"
        elif seconds < 3600:
            return f"{seconds/60:.1f} minutes"
        else:
            return f"{seconds/3600:.1f} hours"
    
    def save_report(self, report_data: Dict, output_path: str, format: str = "json"):
        """
        حفظ التقرير إلى ملف
        
        Args:
            report_data: بيانات التقرير
            output_path: مسار الملف
            format: صيغة التقرير (json, markdown, html)
        """
        if format == "json":
            content = self.generate_json(report_data)
        elif format == "markdown":
            content = self.generate_markdown(report_data)
        elif format == "html":
            content = self.generate_html(report_data)
        else:
            raise ValueError(f"Unsupported format: {format}")
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(content)
        
        logger.info(f"Report saved to {output_path} ({format})")


# نسخة عالمية
_default_generator = None


def get_report_generator() -> ReportGenerator:
    """الحصول على نسخة عالمية من مولد التقارير"""
    global _default_generator
    if _default_generator is None:
        _default_generator = ReportGenerator()
    return _default_generator

