
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime

import logging

logger = logging.getLogger(__name__)


@dataclass
class Fact:
    """حقيقة منطقية"""
    predicate: str
    arguments: List[str]
    confidence: float = 1.0
    source: str = "inferred"
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class Rule:
    """قاعدة منطقية"""
    name: str
    premises: List[Tuple[str, List[str]]]  # (predicate, arguments)
    conclusion: Tuple[str, List[str]]
    confidence: float = 1.0
    description: str = ""


class SymbolicReasoner:
    """
    المفكر الرمزي المتقدم
    
    الميزات:
    - قاعدة معرفة من الحقائق
    - قواعد استدلالية
    - استنتاج حقائق جديدة
    - كشف التناقضات
    """
    
    def __init__(self):
        self._facts: List[Fact] = []
        self._rules: List[Rule] = []
        self._inferred_facts: List[Fact] = []
        
        # تهيئة القواعد الافتراضية
        self._init_default_rules()
        
        logger.info("SymbolicReasoner initialized")
    
    def _init_default_rules(self):
        """تهيئة القواعد الافتراضية"""
        
        # قاعدة: إذا كان هناك ثغرة XSS، يمكن تنفيذ JavaScript
        self._rules.append(Rule(
            name="xss_to_javascript",
            premises=[("vulnerability", ["XSS"])],
            conclusion=("can_execute", ["javascript"]),
            description="XSS vulnerability allows JavaScript execution"
        ))
        
        # قاعدة: إذا كان هناك ثغرة SQLi، يمكن استخراج البيانات
        self._rules.append(Rule(
            name="sqli_to_data_extraction",
            premises=[("vulnerability", ["SQLi"])],
            conclusion=("can_extract", ["data"]),
            description="SQLi allows data extraction"
        ))
        
        # قاعدة: إذا كان هناك RCE، يمكن تنفيذ أوامر النظام
        self._rules.append(Rule(
            name="rce_to_command_execution",
            premises=[("vulnerability", ["RCE"])],
            conclusion=("can_execute", ["system_commands"]),
            description="RCE allows system command execution"
        ))
        
        # قاعدة: إذا كان هناك IDOR، يمكن الوصول إلى موارد أخرى
        self._rules.append(Rule(
            name="idor_to_unauthorized_access",
            premises=[("vulnerability", ["IDOR"])],
            conclusion=("can_access", ["unauthorized_resources"]),
            description="IDOR allows unauthorized resource access"
        ))
    
    async def add_fact(
        self,
        predicate: str,
        arguments: List[str],
        confidence: float = 1.0,
        source: str = "user"
    ):
        """
        إضافة حقيقة جديدة
        
        Args:
            predicate: المسند
            arguments: الوسائط
            confidence: مستوى الثقة
            source: مصدر الحقيقة
        """
        fact = Fact(
            predicate=predicate,
            arguments=arguments,
            confidence=confidence,
            source=source
        )
        
        self._facts.append(fact)
        
        logger.debug(f"Fact added: {predicate}({', '.join(arguments)})")
    
    async def add_rule(self, rule: Rule):
        """إضافة قاعدة استدلالية"""
        self._rules.append(rule)
        logger.info(f"Rule added: {rule.name}")
    
    async def infer(self) -> List[Fact]:
        """
        استنتاج حقائق جديدة باستخدام القواعد
        
        Returns:
            قائمة بالحقائق المستنتجة الجديدة
        """
        new_facts = []
        
        for rule in self._rules:
            # التحقق من توفر المقدمات
            premises_satisfied = True
            substitutions = {}
            
            for premise_pred, premise_args in rule.premises:
                found = False
                for fact in self._facts + self._inferred_facts:
                    if fact.predicate == premise_pred and len(fact.arguments) == len(premise_args):
                        # تطابق الوسائط
                        match = True
                        for i, arg in enumerate(premise_args):
                            if arg.startswith('?'):
                                # متغير
                                substitutions[arg] = fact.arguments[i]
                            elif arg != fact.arguments[i]:
                                match = False
                                break
                        
                        if match:
                            found = True
                            break
                
                if not found:
                    premises_satisfied = False
                    break
            
            if premises_satisfied:
                # استنتاج النتيجة
                conclusion_pred, conclusion_args = rule.conclusion
                
                # استبدال المتغيرات
                resolved_args = []
                for arg in conclusion_args:
                    if arg.startswith('?') and arg in substitutions:
                        resolved_args.append(substitutions[arg])
                    else:
                        resolved_args.append(arg)
                
                # إنشاء حقيقة جديدة
                inferred_fact = Fact(
                    predicate=conclusion_pred,
                    arguments=resolved_args,
                    confidence=rule.confidence,
                    source=f"rule:{rule.name}"
                )
                
                # تجنب التكرار
                exists = False
                for fact in self._inferred_facts:
                    if fact.predicate == inferred_fact.predicate and fact.arguments == inferred_fact.arguments:
                        exists = True
                        break
                
                if not exists:
                    new_facts.append(inferred_fact)
                    self._inferred_facts.append(inferred_fact)
        
        logger.info(f"Inferred {len(new_facts)} new facts")
        return new_facts
    
    async def query(
        self,
        predicate: str,
        arguments: List[str] = None
    ) -> List[Fact]:
        """
        الاستعلام عن الحقائق
        
        Args:
            predicate: المسند
            arguments: الوسائط (اختياري)
        
        Returns:
            قائمة بالحقائق المطابقة
        """
        results = []
        
        for fact in self._facts + self._inferred_facts:
            if fact.predicate == predicate:
                if arguments is None or fact.arguments == arguments:
                    results.append(fact)
        
        return results
    
    async def check_contradictions(self) -> List[Tuple[Fact, Fact]]:
        """
        كشف التناقضات في قاعدة المعرفة
        
        Returns:
            قائمة بأزواج الحقائق المتناقضة
        """
        contradictions = []
        
        for i, fact1 in enumerate(self._facts + self._inferred_facts):
            for fact2 in self._facts + self._inferred_facts:
                if i >= len(self._facts + self._inferred_facts) / 2:
                    break
                
                if fact1.predicate == fact2.predicate and fact1.arguments == fact2.arguments:
                    if fact1.confidence > 0.7 and fact2.confidence > 0.7:
                        if fact1.source != fact2.source:
                            contradictions.append((fact1, fact2))
        
        return contradictions
    
    async def get_knowledge_base(self) -> Dict:
        """الحصول على قاعدة المعرفة الكاملة"""
        return {
            "facts": [
                {"predicate": f.predicate, "arguments": f.arguments, "confidence": f.confidence, "source": f.source}
                for f in self._facts
            ],
            "inferred_facts": [
                {"predicate": f.predicate, "arguments": f.arguments, "confidence": f.confidence, "source": f.source}
                for f in self._inferred_facts
            ],
            "rules": [
                {"name": r.name, "premises": r.premises, "conclusion": r.conclusion, "description": r.description}
                for r in self._rules
            ]
        }
    
    async def get_statistics(self) -> Dict:
        """إحصائيات المفكر"""
        return {
            "total_facts": len(self._facts),
            "total_inferred_facts": len(self._inferred_facts),
            "total_rules": len(self._rules),
            "contradictions_found": len(await self.check_contradictions())
        }

