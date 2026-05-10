
import io
from typing import Dict, List, Optional, Any
from datetime import datetime
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.platypus import Image as RLImage
from reportlab.pdfgen import canvas
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont

import logging

logger = logging.getLogger(__name__)


class PDFExporter:
    """
    مصدر PDF المتقدم
    
    الميزات:
    - تصدير التقارير إلى PDF
    - تنسيقات مخصصة للصفحة
    - دعم الجداول والقوائم
    - دعم الخطوط العربية
    """
    
    def __init__(self, pagesize: str = "letter"):
        self.pagesize = A4 if pagesize == "a4" else letter
        self.styles = getSampleStyleSheet()
        self._setup_styles()
        
        logger.info(f"PDFExporter initialized (pagesize={pagesize})")
    
    def _setup_styles(self):
        """إعداد أنماط التنسيق"""
        # نمط العنوان الرئيسي
        self.styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#1a1a2e'),
            spaceAfter=30,
            alignment=1  # مركز
        ))
        
        # نمط العنوان الثانوي
        self.styles.add(ParagraphStyle(
            name='CustomHeading2',
            parent=self.styles['Heading2'],
            fontSize=16,
            textColor=colors.HexColor('#667eea'),
            spaceBefore=20,
            spaceAfter=10
        ))
        
        # نمط النص العادي
        self.styles.add(ParagraphStyle(
            name='CustomNormal',
            parent=self.styles['Normal'],
            fontSize=10,
            textColor=colors.HexColor('#333333'),
            spaceAfter=6
        ))
        
        # نمط التنبيهات
        self.styles.add(ParagraphStyle(
            name='Alert',
            parent=self.styles['Normal'],
            fontSize=10,
            textColor=colors.HexColor('#e74c3c'),
            backColor=colors.HexColor('#ffe6e6'),
            spaceAfter=6,
            leftIndent=20
        ))
        
        # نمط النجاح
        self.styles.add(ParagraphStyle(
            name='Success',
            parent=self.styles['Normal'],
            fontSize=10,
            textColor=colors.HexColor('#27ae60'),
            backColor=colors.HexColor('#e6ffe6'),
            spaceAfter=6,
            leftIndent=20
        ))
    
    async def export(
        self,
        report_data: Dict,
        output_path: str,
        title: str = "HunterMind Security Report"
    ):
        """
        تصدير تقرير إلى PDF
        
        Args:
            report_data: بيانات التقرير
            output_path: مسار ملف PDF
            title: عنوان التقرير
        """
        try:
            doc = SimpleDocTemplate(
                output_path,
                pagesize=self.pagesize,
                rightMargin=72,
                leftMargin=72,
                topMargin=72,
                bottomMargin=72
            )
            
            story = []
            
            # إضافة العنوان
            story.append(Paragraph(title, self.styles['CustomTitle']))
            story.append(Spacer(1, 0.2 * inch))
            
            # إضافة معلومات التقرير
            story.append(Paragraph("Report Information", self.styles['CustomHeading2']))
            
            info_data = [
                ["Generated:", report_data.get('metadata', {}).get('generated_at', datetime.now().isoformat())],
                ["Target:", report_data.get('target', 'N/A')],
                ["Scan Type:", report_data.get('scan_type', 'N/A')],
                ["Duration:", report_data.get('duration', 'N/A')]
            ]
            
            info_table = Table(info_data, colWidths=[1.5 * inch, 4 * inch])
            info_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
                ('TEXTCOLOR', (0, 0), (0, -1), colors.black),
                ('ALIGN', (0, 0), (0, -1), 'RIGHT'),
                ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey)
            ]))
            story.append(info_table)
            story.append(Spacer(1, 0.2 * inch))
            
            # إضافة الملخص
            story.append(Paragraph("Executive Summary", self.styles['CustomHeading2']))
            story.append(Paragraph(report_data.get('summary', 'No summary available.'), self.styles['CustomNormal']))
            story.append(Spacer(1, 0.2 * inch))
            
            # إضافة الإحصائيات
            story.append(Paragraph("Statistics", self.styles['CustomHeading2']))
            
            stats = report_data.get('statistics', {})
            stats_data = [[key, str(value)] for key, value in stats.items()]
            
            if stats_data:
                stats_table = Table(stats_data, colWidths=[3 * inch, 2.5 * inch])
                stats_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#667eea')),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, -1), 10),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.grey)
                ]))
                story.append(stats_table)
                story.append(Spacer(1, 0.2 * inch))
            
            # إضافة الثغرات
            vulnerabilities = report_data.get('vulnerabilities', [])
            if vulnerabilities:
                story.append(Paragraph("Vulnerabilities Found", self.styles['CustomHeading2']))
                
                for i, vuln in enumerate(vulnerabilities, 1):
                    severity = vuln.get('severity', 'low').upper()
                    severity_color = {
                        'CRITICAL': colors.HexColor('#e74c3c'),
                        'HIGH': colors.HexColor('#e67e22'),
                        'MEDIUM': colors.HexColor('#f1c40f'),
                        'LOW': colors.HexColor('#27ae60')
                    }.get(severity, colors.black)
                    
                    story.append(Paragraph(
                        f"<b>{i}. {vuln.get('type', 'Unknown')}</b> - "
                        f"<font color='{severity_color}'>{severity}</font>",
                        self.styles['CustomNormal']
                    ))
                    story.append(Paragraph(f"<b>URL:</b> {vuln.get('url', 'N/A')}", self.styles['CustomNormal']))
                    story.append(Paragraph(f"<b>Parameter:</b> {vuln.get('parameter', 'N/A')}", self.styles['CustomNormal']))
                    story.append(Paragraph(f"<b>Description:</b> {vuln.get('description', 'N/A')}", self.styles['CustomNormal']))
                    story.append(Paragraph(f"<b>Remediation:</b> {vuln.get('remediation', 'N/A')}", self.styles['CustomNormal']))
                    story.append(Spacer(1, 0.1 * inch))
            
            # إضافة التوصيات
            recommendations = report_data.get('recommendations', [])
            if recommendations:
                story.append(PageBreak())
                story.append(Paragraph("Recommendations", self.styles['CustomHeading2']))
                
                for rec in recommendations:
                    story.append(Paragraph(f"• {rec}", self.styles['CustomNormal']))
                story.append(Spacer(1, 0.2 * inch))
            
            # إضافة تذييل
            story.append(Spacer(1, 0.5 * inch))
            story.append(Paragraph(
                f"<i>Generated by HunterMind Security Platform</i>",
                self.styles['Normal']
            ))
            
            # بناء PDF
            doc.build(story)
            logger.info(f"PDF exported to {output_path}")
            
        except Exception as e:
            logger.error(f"Failed to export PDF: {e}")
            raise
    
    async def export_scan_report(
        self,
        scan_id: str,
        target_url: str,
        findings: List[Dict],
        start_time: datetime,
        end_time: datetime,
        statistics: Dict,
        output_path: str
    ):
        """
        تصدير تقرير فحص إلى PDF
        
        Args:
            scan_id: معرف الفحص
            target_url: الرابط المستهدف
            findings: قائمة الثغرات
            start_time: وقت البدء
            end_time: وقت الانتهاء
            statistics: إحصائيات الفحص
            output_path: مسار ملف PDF
        """
        duration = (end_time - start_time).total_seconds()
        
        report_data = {
            "metadata": {
                "generated_at": datetime.now().isoformat(),
                "scan_id": scan_id
            },
            "target": target_url,
            "scan_type": statistics.get("scan_type", "full"),
            "duration": self._format_duration(duration),
            "summary": self._generate_summary(findings, statistics),
            "statistics": {
                "Pages Crawled": statistics.get("pages_crawled", 0),
                "Forms Found": statistics.get("forms_found", 0),
                "API Endpoints": statistics.get("api_endpoints", 0),
                "Total Vulnerabilities": len(findings),
                "Critical": len([f for f in findings if f.get("severity") == "critical"]),
                "High": len([f for f in findings if f.get("severity") == "high"]),
                "Medium": len([f for f in findings if f.get("severity") == "medium"]),
                "Low": len([f for f in findings if f.get("severity") == "low"])
            },
            "vulnerabilities": findings,
            "recommendations": self._generate_recommendations(findings)
        }
        
        await self.export(report_data, output_path, f"Scan Report - {scan_id}")
    
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
            vuln_type = finding.get("type", "").upper()
            
            if "XSS" in vuln_type:
                recommendations.add("Implement proper output encoding (HTML entity encode, JavaScript escape)")
                recommendations.add("Implement Content Security Policy (CSP)")
            
            elif "SQL" in vuln_type:
                recommendations.add("Use parameterized queries/prepared statements")
                recommendations.add("Implement input validation and sanitization")
            
            elif "IDOR" in vuln_type:
                recommendations.add("Implement proper access control checks")
                recommendations.add("Use indirect references instead of direct IDs")
            
            elif "CSRF" in vuln_type:
                recommendations.add("Implement anti-CSRF tokens")
                recommendations.add("Enable SameSite cookie attribute")
            
            elif "RCE" in vuln_type:
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


# نسخة عالمية
_default_exporter = None


def get_pdf_exporter() -> PDFExporter:
    """الحصول على نسخة عالمية من مصدر PDF"""
    global _default_exporter
    if _default_exporter is None:
        _default_exporter = PDFExporter()
    return _default_exporter

