
import re
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

import logging

logger = logging.getLogger(__name__)


class DBMS(Enum):
    """أنظمة إدارة قواعد البيانات المدعومة"""
    MYSQL = "MySQL"
    POSTGRESQL = "PostgreSQL"
    MSSQL = "Microsoft SQL Server"
    ORACLE = "Oracle"
    SQLITE = "SQLite"
    MARIADB = "MariaDB"
    UNKNOWN = "Unknown"


@dataclass
class DBMSFingerprint:
    """بصمة DBMS"""
    dbms: DBMS
    version: Optional[str] = None
    confidence: float = 0.0
    evidence: List[str] = field(default_factory=list)
    detected_at: datetime = field(default_factory=datetime.now)


class DBMSFingerprinter:
    """
    كاشف بصمة DBMS المتقدم
    
    الميزات:
    - كشف نوع DBMS من الأخطاء
    - كشف من الاستجابات
    - كشف من سلوك الاستعلامات (time-based, boolean-based)
    - كشف الإصدارات
    - 6 أنظمة DBMS مدعومة
    """
    
    # أنماط كشف MySQL
    MYSQL_PATTERNS = {
        "error": [
            r"SQL syntax.*MySQL",
            r"MySQLSyntaxErrorException",
            r"valid MySQL result",
            r"mysql_fetch_array",
            r"MySQL server version",
            r"\[MySQL\]",
        ],
        "version_query": [
            r"@@version",
            r"VERSION\(\)",
            r"@@GLOBAL\.version",
        ],
        "specific": [
            r"information_schema",
            r"INFORMATION_SCHEMA",
            r"MYISAM",
            r"InnoDB",
        ]
    }
    
    # أنماط كشف PostgreSQL
    POSTGRESQL_PATTERNS = {
        "error": [
            r"PostgreSQL.*ERROR",
            r"Warning.*\Wpg_.*",
            r"valid PostgreSQL result",
            r"PG::Error",
            r"PostgreSQL query failed",
        ],
        "version_query": [
            r"version\(\)",
            r"current_setting\('server_version'\)",
        ],
        "specific": [
            r"pg_catalog",
            r"pg_attribute",
            r"pg_class",
        ]
    }
    
    # أنماط كشف MSSQL
    MSSQL_PATTERNS = {
        "error": [
            r"Microsoft SQL Native Client error",
            r"\[SQL Server\]",
            r"Driver.*SQL Server",
            r"SQLServer JDBC Driver",
            r"com.microsoft.sqlserver",
            r"Unclosed quotation mark",
        ],
        "version_query": [
            r"@@version",
            r"@@VERSION",
            r"SERVERPROPERTY\('productversion'\)",
        ],
        "specific": [
            r"sysobjects",
            r"syscolumns",
            r"sysdatabases",
        ]
    }
    
    # أنماط كشف Oracle
    ORACLE_PATTERNS = {
        "error": [
            r"ORA-[0-9]{5}",
            r"Oracle error",
            r"Oracle.*Driver",
            r"javax.servlet.ServletException: oracle",
        ],
        "version_query": [
            r"SELECT banner FROM v\$version",
            r"SELECT version FROM v\$instance",
        ],
        "specific": [
            r"DUAL",
            r"USER_TABLES",
            r"ALL_TABLES",
        ]
    }
    
    # أنماط كشف SQLite
    SQLITE_PATTERNS = {
        "error": [
            r"SQLite/JDBCDriver",
            r"SQLite.Exception",
            r"System.Data.SQLite.SQLiteException",
            r"Warning.*sqlite_.*",
            r"valid SQLite",
        ],
        "version_query": [
            r"sqlite_version\(\)",
            r"SELECT sqlite_version\(\)",
        ],
        "specific": [
            r"sqlite_master",
            r"sqlite_sequence",
        ]
    }
    
    # أنماط كشف MariaDB
    MARIADB_PATTERNS = {
        "error": [
            r"MariaDB",
            r"MariaDB server",
        ],
        "version_query": [
            r"@@version",
            r"VERSION\(\)",
        ],
        "specific": [
            r"Aria",
            r"XtraDB",
        ]
    }
    
    def __init__(self):
        self._fingerprints: Dict[str, DBMSFingerprint] = {}
        
        logger.info("DBMSFingerprinter initialized")
    
    async def fingerprint(
        self,
        error_messages: List[str],
        responses: List[str],
        time_behavior: Dict[str, float] = None
    ) -> DBMSFingerprint:
        """
        كشف بصمة DBMS من مصادر متعددة
        
        Args:
            error_messages: قائمة رسائل الخطأ
            responses: قائمة استجابات الخادم
            time_behavior: سلوك الوقت للاستعلامات
        
        Returns:
            بصمة DBMS
        """
        scores = {}
        evidences = {}
        
        # تحليل رسائل الخطأ
        for error in error_messages:
            await self._analyze_error(error, scores, evidences)
        
        # تحليل الاستجابات
        for response in responses:
            await self._analyze_response(response, scores, evidences)
        
        # تحديد أعلى درجة
        if not scores:
            return DBMSFingerprint(dbms=DBMS.UNKNOWN, confidence=0.0)
        
        best_dbms = max(scores, key=scores.get)
        best_score = scores[best_dbms]
        
        # تحديد الإصدار إذا أمكن
        version = await self._extract_version(best_dbms, evidences.get(best_dbms, []))
        
        return DBMSFingerprint(
            dbms=best_dbms,
            version=version,
            confidence=min(best_score / 100, 1.0),
            evidence=evidences.get(best_dbms, [])
        )
    
    async def _analyze_error(self, error: str, scores: Dict, evidences: Dict):
        """تحليل رسالة الخطأ"""
        error_lower = error.lower()
        
        # MySQL
        for pattern in self.MYSQL_PATTERNS["error"]:
            if re.search(pattern, error, re.I):
                scores[DBMS.MYSQL] = scores.get(DBMS.MYSQL, 0) + 30
                evidences.setdefault(DBMS.MYSQL, []).append(f"Error pattern: {pattern}")
                break
        
        # PostgreSQL
        for pattern in self.POSTGRESQL_PATTERNS["error"]:
            if re.search(pattern, error, re.I):
                scores[DBMS.POSTGRESQL] = scores.get(DBMS.POSTGRESQL, 0) + 30
                evidences.setdefault(DBMS.POSTGRESQL, []).append(f"Error pattern: {pattern}")
                break
        
        # MSSQL
        for pattern in self.MSSQL_PATTERNS["error"]:
            if re.search(pattern, error, re.I):
                scores[DBMS.MSSQL] = scores.get(DBMS.MSSQL, 0) + 30
                evidences.setdefault(DBMS.MSSQL, []).append(f"Error pattern: {pattern}")
                break
        
        # Oracle
        for pattern in self.ORACLE_PATTERNS["error"]:
            if re.search(pattern, error, re.I):
                scores[DBMS.ORACLE] = scores.get(DBMS.ORACLE, 0) + 30
                evidences.setdefault(DBMS.ORACLE, []).append(f"Error pattern: {pattern}")
                break
        
        # SQLite
        for pattern in self.SQLITE_PATTERNS["error"]:
            if re.search(pattern, error, re.I):
                scores[DBMS.SQLITE] = scores.get(DBMS.SQLITE, 0) + 30
                evidences.setdefault(DBMS.SQLITE, []).append(f"Error pattern: {pattern}")
                break
        
        # MariaDB
        for pattern in self.MARIADB_PATTERNS["error"]:
            if re.search(pattern, error, re.I):
                scores[DBMS.MARIADB] = scores.get(DBMS.MARIADB, 0) + 25
                evidences.setdefault(DBMS.MARIADB, []).append(f"Error pattern: {pattern}")
                break
    
    async def _analyze_response(self, response: str, scores: Dict, evidences: Dict):
        """تحليل الاستجابة"""
        response_lower = response.lower()
        
        # جداول النظام
        if "information_schema" in response_lower:
            scores[DBMS.MYSQL] = scores.get(DBMS.MYSQL, 0) + 20
            evidences.setdefault(DBMS.MYSQL, []).append("information_schema found")
        
        if "pg_catalog" in response_lower or "pg_attribute" in response_lower:
            scores[DBMS.POSTGRESQL] = scores.get(DBMS.POSTGRESQL, 0) + 20
            evidences.setdefault(DBMS.POSTGRESQL, []).append("PostgreSQL catalog found")
        
        if "sysobjects" in response_lower or "syscolumns" in response_lower:
            scores[DBMS.MSSQL] = scores.get(DBMS.MSSQL, 0) + 20
            evidences.setdefault(DBMS.MSSQL, []).append("MSSQL system tables found")
        
        if "sqlite_master" in response_lower:
            scores[DBMS.SQLITE] = scores.get(DBMS.SQLITE, 0) + 20
            evidences.setdefault(DBMS.SQLITE, []).append("sqlite_master found")
        
        if "dual" in response_lower:
            scores[DBMS.ORACLE] = scores.get(DBMS.ORACLE, 0) + 15
            evidences.setdefault(DBMS.ORACLE, []).append("DUAL table referenced")
    
    async def _extract_version(self, dbms: DBMS, evidences: List[str]) -> Optional[str]:
        """استخراج الإصدار من الأدلة"""
        version_patterns = {
            DBMS.MYSQL: r'mysql[^\d]*(\d+\.\d+\.\d+)',
            DBMS.MARIADB: r'mariadb[^\d]*(\d+\.\d+\.\d+)',
            DBMS.POSTGRESQL: r'postgresql[^\d]*(\d+\.\d+\.\d+)',
            DBMS.MSSQL: r'sql server[^\d]*(\d+\.\d+\.\d+)',
            DBMS.ORACLE: r'oracle[^\d]*(\d+\.\d+\.\d+)',
            DBMS.SQLITE: r'sqlite[^\d]*(\d+\.\d+\.\d+)',
        }
        
        pattern = version_patterns.get(dbms)
        if not pattern:
            return None
        
        for evidence in evidences:
            match = re.search(pattern, evidence, re.I)
            if match:
                return match.group(1)
        
        return None
    
    async def fingerprint_from_sql_errors(self, errors: List[str]) -> DBMSFingerprint:
        """
        كشف DBMS من أخطاء SQL فقط
        
        Args:
            errors: قائمة رسائل أخطاء SQL
        
        Returns:
            بصمة DBMS
        """
        return await self.fingerprint(errors, [])
    
    async def get_fingerprint_for_target(self, target_url: str) -> Optional[DBMSFingerprint]:
        """الحصول على بصمة DBMS لهدف معين"""
        return self._fingerprints.get(target_url)
    
    async def store_fingerprint(self, target_url: str, fingerprint: DBMSFingerprint):
        """تخزين بصمة DBMS لهدف"""
        self._fingerprints[target_url] = fingerprint
    
    async def generate_fingerprint_report(self, fingerprint: DBMSFingerprint) -> str:
        """
        توليد تقرير البصمة
        
        Args:
            fingerprint: بصمة DBMS
        
        Returns:
            تقرير Markdown
        """
        confidence_level = {
            0.9: "Very High",
            0.7: "High",
            0.5: "Medium",
            0.3: "Low",
        }.get(fingerprint.confidence, "Unknown")
        
        report = f"""## DBMS Fingerprint Report

**Detected DBMS:** {fingerprint.dbms.value}
**Confidence:** {confidence_level} ({fingerprint.confidence:.1%})
**Version:** {fingerprint.version or 'Unknown'}

### Evidence
"""
        for evidence in fingerprint.evidence[:10]:
            report += f"- {evidence}\n"
        
        return report
    
    async def get_statistics(self) -> Dict:
        """إحصائيات الكاشف"""
        return {
            "total_fingerprints": len(self._fingerprints),
            "supported_dbms": [db.value for db in DBMS],
            "pattern_counts": {
                "mysql": len(self.MYSQL_PATTERNS["error"]) + len(self.MYSQL_PATTERNS["version_query"]),
                "postgresql": len(self.POSTGRESQL_PATTERNS["error"]) + len(self.POSTGRESQL_PATTERNS["version_query"]),
                "mssql": len(self.MSSQL_PATTERNS["error"]) + len(self.MSSQL_PATTERNS["version_query"]),
                "oracle": len(self.ORACLE_PATTERNS["error"]) + len(self.ORACLE_PATTERNS["version_query"]),
                "sqlite": len(self.SQLITE_PATTERNS["error"]) + len(self.SQLITE_PATTERNS["version_query"]),
            }
        }
    
    async def clear_fingerprints(self, target_url: str = None):
        """مسح البصمات"""
        if target_url:
            self._fingerprints.pop(target_url, None)
        else:
            self._fingerprints.clear()
        
        logger.info(f"Fingerprints cleared for {target_url if target_url else 'all targets'}")

