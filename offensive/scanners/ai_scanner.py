"""
AI-Enhanced Scanner - فاحص مدعوم بالذكاء الاصطناعي
"""
import asyncio, random, time, json, os
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime
from collections import defaultdict
from .base_scanner import BaseScanner, ScanContext, Finding, Severity, Confidence
import logging

logger = logging.getLogger(__name__)

@dataclass
class PayloadScore:
    payload: str
    success_count: int = 0
    fail_count: int = 0
    last_used: float = 0.0
    avg_response_time: float = 0.0
    contexts: List[str] = field(default_factory=list)
    @property
    def success_rate(self) -> float:
        total = self.success_count + self.fail_count
        return self.success_count / total if total > 0 else 0.5
    @property
    def score(self) -> float:
        return self.success_rate * 0.6 + min(1.0, (time.time() - self.last_used) / 3600) * 0.2 + max(0, 1.0 - self.avg_response_time / 5000) * 0.2

class AIPayloadSelector:
    def __init__(self, learning_rate: float = 0.1, exploration_rate: float = 0.2):
        self.learning_rate = learning_rate
        self.exploration_rate = exploration_rate
        self.epsilon = 1.0
        self.epsilon_min = 0.05
        self.epsilon_decay = 0.995
        self._payload_scores: Dict[str, PayloadScore] = {}
        self._context_memory: Dict[str, List[str]] = defaultdict(list)
        self._successful_patterns: List[Dict] = []
        self._total_selections = 0
        self._total_explorations = 0
        self._total_exploitations = 0
    
    def select_payload(self, payloads: List[str], context: str = "html") -> str:
        self._total_selections += 1
        for p in payloads:
            if p not in self._payload_scores:
                self._payload_scores[p] = PayloadScore(payload=p)
        if random.random() < self.epsilon:
            self._total_explorations += 1
            selected = random.choice(payloads)
            self._payload_scores[selected].last_used = time.time()
            return selected
        self._total_exploitations += 1
        scored = [(p, self._payload_scores.get(p, PayloadScore(payload=p)).score) for p in payloads]
        scored.sort(key=lambda x: x[1], reverse=True)
        selected = scored[0][0]
        self._payload_scores[selected].last_used = time.time()
        return selected
    
    def record_result(self, payload: str, success: bool, response_time: float = 0.0, context: str = "html"):
        if payload not in self._payload_scores:
            self._payload_scores[payload] = PayloadScore(payload=payload)
        score = self._payload_scores[payload]
        if success: score.success_count += 1
        else: score.fail_count += 1
        if response_time > 0: score.avg_response_time = (score.avg_response_time * 0.7 + response_time * 0.3)
        score.last_used = time.time()
        self.epsilon = max(self.epsilon_min, self.epsilon * self.epsilon_decay)
    
    def get_stats(self) -> Dict:
        return {"total_payloads": len(self._payload_scores), "total_selections": self._total_selections, "exploration_rate": self.epsilon}
    
    def save_model(self, path: str = "models/ai_payload_selector.json"):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'w') as f: json.dump({"epsilon": self.epsilon}, f)
    
    def load_model(self, path: str = "models/ai_payload_selector.json"):
        if os.path.exists(path):
            with open(path, 'r') as f: data = json.load(f); self.epsilon = data.get("epsilon", 1.0)

class AIScanner(BaseScanner):
    def __init__(self, name: str, payloads: List[str] = None, **kwargs):
        super().__init__(name=name, **kwargs)
        self._ai_selector = AIPayloadSelector()
        self._payloads = payloads or []
        self._context = "html"
    async def can_scan(self, context: ScanContext) -> bool:
        return len(self._payloads) > 0
    async def scan(self, context: ScanContext) -> List[Finding]:
        return []

_global_ai_selector = None

def get_ai_payload_selector() -> AIPayloadSelector:
    global _global_ai_selector
    if _global_ai_selector is None:
        _global_ai_selector = AIPayloadSelector()
        _global_ai_selector.load_model("models/global_ai_selector.json")
    return _global_ai_selector
