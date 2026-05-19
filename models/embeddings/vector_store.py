"""Simple Vector Store للبحث عن ثغرات مشابهة"""
import json, os, math
from typing import Dict, List, Tuple
from collections import Counter

class SimpleVectorStore:
    def __init__(self):
        self.vectors: Dict[str, Counter] = {}
    def add(self, id: str, text: str):
        words = text.lower().split()
        self.vectors[id] = Counter(words)
    def search(self, query: str, limit: int = 5) -> List[Tuple[str, float]]:
        q_words = Counter(query.lower().split())
        scores = []
        for id, vec in self.vectors.items():
            common = sum((q_words & vec).values())
            total = math.sqrt(sum(q_words.values()) * sum(vec.values()))
            similarity = common / total if total > 0 else 0
            scores.append((id, similarity))
        scores.sort(key=lambda x: x[1], reverse=True)
        return scores[:limit]
    def save(self, path: str):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'w') as f:
            json.dump({k: dict(v) for k, v in self.vectors.items()}, f)
    def load(self, path: str):
        if os.path.exists(path):
            with open(path, 'r') as f:
                self.vectors = {k: Counter(v) for k, v in json.load(f).items()}
