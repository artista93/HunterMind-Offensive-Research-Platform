
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from collections import defaultdict

import logging

logger = logging.getLogger(__name__)


@dataclass
class CausalLink:
    """رابط سببي"""
    cause: str
    effect: str
    strength: float  # 0-1 قوة العلاقة السببية
    confidence: float
    evidence: List[str]
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class CausalChain:
    """سلسلة سببية"""
    id: str
    links: List[CausalLink]
    start_cause: str
    final_effect: str
    overall_strength: float
    created_at: datetime = field(default_factory=datetime.now)


class CausalReasoner:
    """
    المفكر السببي المتقدم
    
    الميزات:
    - تحليل العلاقات السببية
    - بناء سلاسل سببية
    - استنتاج الأسباب المحتملة
    - توقع التأثيرات المستقبلية
    """
    
    def __init__(self):
        self._causal_links: List[CausalLink] = []
        self._causal_chains: List[CausalChain] = []
        self._cause_index: Dict[str, List[CausalLink]] = defaultdict(list)
        self._effect_index: Dict[str, List[CausalLink]] = defaultdict(list)
        
        # تهيئة العلاقات السببية الافتراضية
        self._init_default_causal_links()
        
        logger.info("CausalReasoner initialized")
    
    def _init_default_causal_links(self):
        """تهيئة العلاقات السببية الافتراضية"""
        
        default_links = [
            CausalLink(
                cause="XSS vulnerability",
                effect="session hijacking",
                strength=0.85,
                confidence=0.9,
                evidence=["XSS allows stealing session cookies"]
            ),
            CausalLink(
                cause="SQL injection",
                effect="data breach",
                strength=0.95,
                confidence=0.95,
                evidence=["SQLi allows extracting database contents"]
            ),
            CausalLink(
                cause="RCE vulnerability",
                effect="system compromise",
                strength=0.9,
                confidence=0.9,
                evidence=["RCE allows executing arbitrary commands"]
            ),
            CausalLink(
                cause="weak password",
                effect="account compromise",
                strength=0.7,
                confidence=0.8,
                evidence=["Weak passwords can be brute-forced"]
            ),
            CausalLink(
                cause="session hijacking",
                effect="account takeover",
                strength=0.9,
                confidence=0.9,
                evidence=["Hijacked session gives full access"]
            ),
            CausalLink(
                cause="data breach",
                effect="sensitive information exposure",
                strength=1.0,
                confidence=0.95,
                evidence=["Breached data is exposed"]
            ),
            CausalLink(
                cause="system compromise",
                effect="full control",
                strength=0.95,
                confidence=0.9,
                evidence=["Compromised system gives full control"]
            )
        ]
        
        for link in default_links:
            self._causal_links.append(link)
            self._cause_index[link.cause].append(link)
            self._effect_index[link.effect].append(link)
    
    async def add_causal_link(
        self,
        cause: str,
        effect: str,
        strength: float,
        confidence: float = 0.8,
        evidence: List[str] = None
    ):
        """
        إضافة رابط سببي جديد
        
        Args:
            cause: السبب
            effect: التأثير
            strength: قوة العلاقة (0-1)
            confidence: مستوى الثقة
            evidence: الأدلة
        """
        link = CausalLink(
            cause=cause,
            effect=effect,
            strength=strength,
            confidence=confidence,
            evidence=evidence or []
        )
        
        self._causal_links.append(link)
        self._cause_index[cause].append(link)
        self._effect_index[effect].append(link)
        
        logger.debug(f"Causal link added: {cause} -> {effect} (strength={strength})")
    
    async def get_causes(self, effect: str) -> List[Tuple[str, float]]:
        """
        الحصول على الأسباب المحتملة لتأثير معين
        
        Args:
            effect: التأثير
        
        Returns:
            قائمة (السبب, قوة العلاقة)
        """
        links = self._effect_index.get(effect, [])
        causes = [(link.cause, link.strength * link.confidence) for link in links]
        causes.sort(key=lambda x: x[1], reverse=True)
        return causes
    
    async def get_effects(self, cause: str) -> List[Tuple[str, float]]:
        """
        الحصول على التأثيرات المحتملة لسبب معين
        
        Args:
            cause: السبب
        
        Returns:
            قائمة (التأثير, قوة العلاقة)
        """
        links = self._cause_index.get(cause, [])
        effects = [(link.effect, link.strength * link.confidence) for link in links]
        effects.sort(key=lambda x: x[1], reverse=True)
        return effects
    
    async def build_causal_chain(
        self,
        start_cause: str,
        max_depth: int = 5,
        min_strength: float = 0.5
    ) -> Optional[CausalChain]:
        """
        بناء سلسلة سببية من سبب بداية
        
        Args:
            start_cause: سبب البداية
            max_depth: أقصى عمق
            min_strength: الحد الأدنى لقوة العلاقة
        
        Returns:
            السلسلة السببية
        """
        import uuid
        chain_id = str(uuid.uuid4())[:8]
        
        links = []
        current = start_cause
        total_strength = 1.0
        
        for _ in range(max_depth):
            effects = await self.get_effects(current)
            
            if not effects:
                break
            
            # اختيار أقوى تأثير
            best_effect, best_strength = effects[0]
            
            if best_strength < min_strength:
                break
            
            # البحث عن الرابط الفعلي
            link = None
            for l in self._cause_index.get(current, []):
                if l.effect == best_effect:
                    link = l
                    break
            
            if link:
                links.append(link)
                total_strength *= best_strength
                current = best_effect
            else:
                break
        
        if not links:
            return None
        
        chain = CausalChain(
            id=chain_id,
            links=links,
            start_cause=start_cause,
            final_effect=links[-1].effect if links else start_cause,
            overall_strength=total_strength
        )
        
        self._causal_chains.append(chain)
        
        logger.info(f"Causal chain built: {start_cause} -> {chain.final_effect} (strength={total_strength:.2f})")
        
        return chain
    
    async def predict_effect(self, cause: str, depth: int = 3) -> List[Tuple[str, float]]:
        """
        التنبؤ بالتأثيرات المحتملة لسبب معين
        
        Args:
            cause: السبب
            depth: عمق التنبؤ
        
        Returns:
            قائمة (التأثير, قوة التنبؤ)
        """
        chain = await self.build_causal_chain(cause, depth)
        
        if not chain:
            return []
        
        # جميع التأثيرات في السلسلة
        effects = [(link.effect, link.strength * link.confidence) for link in chain.links]
        
        return effects
    
    async def find_root_causes(self, effect: str) -> List[Tuple[str, float]]:
        """
        البحث عن الأسباب الجذرية لتأثير معين
        
        Args:
            effect: التأثير
        
        Returns:
            قائمة (السبب الجذري, قوة العلاقة)
        """
        root_causes = []
        visited = set()
        queue = [(effect, 1.0)]
        
        while queue:
            current, strength = queue.pop(0)
            
            causes = await self.get_causes(current)
            
            if not causes:
                root_causes.append((current, strength))
            else:
                for cause, cause_strength in causes:
                    if cause not in visited:
                        visited.add(cause)
                        queue.append((cause, strength * cause_strength))
        
        root_causes.sort(key=lambda x: x[1], reverse=True)
        return root_causes
    
    async def get_statistics(self) -> Dict:
        """إحصائيات المفكر"""
        return {
            "total_causal_links": len(self._causal_links),
            "total_causal_chains": len(self._causal_chains),
            "unique_causes": len(self._cause_index),
            "unique_effects": len(self._effect_index),
            "average_link_strength": sum(l.strength for l in self._causal_links) / len(self._causal_links) if self._causal_links else 0,
            "average_chain_strength": sum(c.overall_strength for c in self._causal_chains) / len(self._causal_chains) if self._causal_chains else 0
        }

