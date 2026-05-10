
import json
from typing import Dict, List, Optional, Any
from datetime import datetime, date
from decimal import Decimal
import gzip
import os

import logging

logger = logging.getLogger(__name__)


class CustomJSONEncoder(json.JSONEncoder):
    """مشفر JSON مخصص للتعامل مع الأنواع غير القابلة للتسلسل"""
    
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        if isinstance(obj, date):
            return obj.isoformat()
        if isinstance(obj, Decimal):
            return float(obj)
        if hasattr(obj, '__dict__'):
            return obj.__dict__
        return super().default(obj)


class JSONExporter:
    """
    مصدر JSON المتقدم
    
    الميزات:
    - تصدير البيانات إلى JSON
    - دعم الضغط (gzip)
    - دعم التصدير المتدفق للبيانات الكبيرة
    - تنسيق قابل للتخصيص
    """
    
    def __init__(self, pretty: bool = True, compress: bool = False):
        self.pretty = pretty
        self.compress = compress
        self.indent = 2 if pretty else None
        
        logger.info(f"JSONExporter initialized (pretty={pretty}, compress={compress})")
    
    async def export(
        self,
        data: Any,
        output_path: str,
        metadata: Dict = None
    ):
        """
        تصدير البيانات إلى JSON
        
        Args:
            data: البيانات المراد تصديرها
            output_path: مسار ملف JSON
            metadata: بيانات وصفية إضافية
        """
        # إضافة بيانات وصفية
        export_data = {
            "metadata": {
                "exported_at": datetime.now().isoformat(),
                "exporter": "HunterMind JSON Exporter",
                "version": "1.0.0",
                **(metadata or {})
            },
            "data": data
        }
        
        # تحويل إلى JSON
        json_str = json.dumps(export_data, cls=CustomJSONEncoder, indent=self.indent)
        
        # كتابة الملف
        if self.compress:
            output_path += ".gz"
            with gzip.open(output_path, 'wt', encoding='utf-8') as f:
                f.write(json_str)
        else:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(json_str)
        
        logger.info(f"JSON exported to {output_path} (size: {len(json_str)} bytes)")
    
    async def export_stream(
        self,
        data_generator,
        output_path: str,
        chunk_size: int = 1000
    ):
        """
        تصدير بيانات كبيرة باستخدام التدفق
        
        Args:
            data_generator: مولد البيانات
            output_path: مسار ملف JSON
            chunk_size: حجم الدفعة
        """
        first_chunk = True
        
        if self.compress:
            output_path += ".gz"
            f = gzip.open(output_path, 'wt', encoding='utf-8')
        else:
            f = open(output_path, 'w', encoding='utf-8')
        
        try:
            f.write('{"metadata": {')
            f.write(f'"exported_at": "{datetime.now().isoformat()}",')
            f.write('"exporter": "HunterMind JSON Exporter",')
            f.write('"version": "1.0.0"')
            f.write('}, "data": [')
            
            count = 0
            async for item in data_generator:
                if not first_chunk:
                    f.write(',')
                else:
                    first_chunk = False
                
                json.dump(item, f, cls=CustomJSONEncoder, indent=self.indent if self.pretty else None)
                count += 1
                
                if count % chunk_size == 0:
                    f.flush()
            
            f.write(']}')
            
        finally:
            f.close()
        
        logger.info(f"Stream JSON exported to {output_path} ({count} items)")
    
    async def export_scan_results(
        self,
        scan_id: str,
        scan_results: Dict,
        output_path: str
    ):
        """
        تصدير نتائج الفحص إلى JSON
        
        Args:
            scan_id: معرف الفحص
            scan_results: نتائج الفحص
            output_path: مسار ملف JSON
        """
        export_data = {
            "scan_id": scan_id,
            "timestamp": datetime.now().isoformat(),
            "results": scan_results
        }
        
        await self.export(export_data, output_path, metadata={"type": "scan_results"})
    
    async def export_vulnerabilities(
        self,
        vulnerabilities: List[Dict],
        output_path: str,
        include_details: bool = True
    ):
        """
        تصدير قائمة الثغرات إلى JSON
        
        Args:
            vulnerabilities: قائمة الثغرات
            output_path: مسار ملف JSON
            include_details: تضمين التفاصيل الكاملة
        """
        export_data = {
            "total": len(vulnerabilities),
            "vulnerabilities": []
        }
        
        for vuln in vulnerabilities:
            vuln_data = {
                "id": vuln.get("id"),
                "type": vuln.get("type"),
                "severity": vuln.get("severity"),
                "url": vuln.get("url"),
                "parameter": vuln.get("parameter"),
                "discovered_at": vuln.get("discovered_at")
            }
            
            if include_details:
                vuln_data["description"] = vuln.get("description")
                vuln_data["remediation"] = vuln.get("remediation")
                vuln_data["payload"] = vuln.get("payload")
                vuln_data["evidence"] = vuln.get("evidence")
                vuln_data["cvss_score"] = vuln.get("cvss_score")
            
            export_data["vulnerabilities"].append(vuln_data)
        
        await self.export(export_data, output_path, metadata={"type": "vulnerabilities"})
    
    async def export_attack_history(
        self,
        attacks: List[Dict],
        output_path: str
    ):
        """
        تصدير تاريخ الهجمات إلى JSON
        
        Args:
            attacks: قائمة الهجمات
            output_path: مسار ملف JSON
        """
        export_data = {
            "total": len(attacks),
            "successful": len([a for a in attacks if a.get("success")]),
            "failed": len([a for a in attacks if a.get("success") is False]),
            "attacks": attacks
        }
        
        await self.export(export_data, output_path, metadata={"type": "attack_history"})
    
    async def export_statistics(
        self,
        statistics: Dict,
        output_path: str
    ):
        """
        تصدير الإحصائيات إلى JSON
        
        Args:
            statistics: بيانات الإحصائيات
            output_path: مسار ملف JSON
        """
        await self.export(statistics, output_path, metadata={"type": "statistics"})
    
    async def merge_export(
        self,
        export_files: List[str],
        output_path: str
    ):
        """
        دمج عدة ملفات JSON في ملف واحد
        
        Args:
            export_files: قائمة ملفات JSON للدمج
            output_path: مسار ملف الإخراج
        """
        merged_data = {
            "metadata": {
                "merged_at": datetime.now().isoformat(),
                "source_files": export_files,
                "exporter": "HunterMind JSON Exporter"
            },
            "data": []
        }
        
        for file_path in export_files:
            try:
                if file_path.endswith('.gz'):
                    with gzip.open(file_path, 'rt', encoding='utf-8') as f:
                        data = json.load(f)
                else:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                
                merged_data["data"].append({
                    "source": file_path,
                    "content": data
                })
                
            except Exception as e:
                logger.error(f"Failed to read {file_path}: {e}")
        
        await self.export(merged_data, output_path)
        
        logger.info(f"Merged {len(export_files)} files into {output_path}")
    
    async def export_schema_demo(self, output_path: str):
        """
        تصدير نموذج لهيكل البيانات للتوثيق
        
        Args:
            output_path: مسار ملف JSON
        """
        schema_demo = {
            "scan": {
                "id": "scan_001",
                "target_url": "https://example.com",
                "status": "completed",
                "start_time": "2024-01-01T10:00:00",
                "end_time": "2024-01-01T10:05:00",
                "statistics": {
                    "pages_crawled": 150,
                    "forms_found": 25,
                    "api_endpoints": 12
                }
            },
            "vulnerability": {
                "id": "vuln_001",
                "type": "XSS",
                "severity": "high",
                "url": "https://example.com/search",
                "parameter": "q",
                "payload": "<script>alert('XSS')</script>",
                "description": "Cross-Site Scripting vulnerability",
                "remediation": "Use output encoding"
            },
            "attack": {
                "id": "attack_001",
                "type": "sqli",
                "target": "https://example.com/product",
                "parameter": "id",
                "success": True,
                "execution_time": 1.5,
                "output": "Extracted database: test_db"
            }
        }
        
        await self.export(schema_demo, output_path, metadata={"type": "schema_demo"})
        
        logger.info(f"Schema demo exported to {output_path}")


# نسخة عالمية
_default_exporter = None


def get_json_exporter(pretty: bool = True, compress: bool = False) -> JSONExporter:
    """الحصول على نسخة من مصدر JSON"""
    return JSONExporter(pretty=pretty, compress=compress)

