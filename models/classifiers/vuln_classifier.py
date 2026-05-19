"""
Vulnerability Classifier - تصنيف الثغرات باستخدام Naive Bayes
"""

import json
import os
import re
import math
from typing import Dict, List, Optional, Any, Tuple
from collections import defaultdict

import logging

logger = logging.getLogger(__name__)


class VulnerabilityClassifier:
    """
    مصنف الثغرات - Naive Bayes بسيط
    
    يصنف:
    - XSS (Reflected/Stored/DOM)
    - SQLi (Boolean/Time/Error/Union)
    - IDOR
    - CSRF
    - SSRF
    - RCE
    """
    
    VULN_TYPES = [
        "xss_reflected", "xss_stored", "xss_dom",
        "sqli_boolean", "sqli_time", "sqli_error", "sqli_union",
        "idor", "csrf", "ssrf", "rce", "unknown"
    ]
    
    # كلمات مفتاحية لكل نوع
    FEATURES = {
        "xss_reflected": ["script", "alert", "onerror", "onload", "img", "svg", "reflected", "parameter"],
        "xss_stored": ["stored", "database", "persistent", "comment", "profile", "post"],
        "xss_dom": ["dom", "document", "innerhtml", "eval", "settimeout", "location"],
        "sqli_boolean": ["boolean", "true", "false", "and", "or", "blind"],
        "sqli_time": ["sleep", "delay", "waitfor", "benchmark", "pg_sleep"],
        "sqli_error": ["error", "syntax", "mysql", "postgresql", "odbc", "warning"],
        "sqli_union": ["union", "select", "null", "concat", "group_concat"],
        "idor": ["idor", "reference", "object", "authorization", "access", "user", "id"],
        "csrf": ["csrf", "token", "xsrf", "cross-site", "samesite", "form"],
        "ssrf": ["ssrf", "server-side", "metadata", "169.254", "localhost", "internal"],
        "rce": ["rce", "command", "execution", "system", "shell", "eval", "injection"],
    }
    
    def __init__(self):
        # احتمالات مسبقة
        self.prior = {t: 1.0 / len(self.VULN_TYPES) for t in self.VULN_TYPES}
        
        # احتمالات شرطية: P(word|type)
        self.likelihood: Dict[str, Dict[str, float]] = defaultdict(lambda: defaultdict(float))
        
        # إحصائيات
        self._trained_count = 0
        self._total_predictions = 0
        
        logger.info(f"VulnerabilityClassifier initialized ({len(self.VULN_TYPES)} types)")
    
    def _tokenize(self, text: str) -> List[str]:
        """تحويل النص إلى كلمات"""
        text = text.lower()
        # استخراج الكلمات المهمة
        words = re.findall(r'[a-z0-9_\-]+', text)
        # إزالة الكلمات القصيرة
        return [w for w in words if len(w) > 2]
    
    def train(self, text: str, vuln_type: str):
        """
        تدريب المصنف على مثال جديد
        
        Args:
            text: وصف الثغرة
            vuln_type: نوع الثغرة
        """
        if vuln_type not in self.VULN_TYPES:
            vuln_type = "unknown"
        
        words = self._tokenize(text)
        
        # تحديث الاحتمالات الشرطية
        for word in words:
            self.likelihood[vuln_type][word] += 1
        
        # تحديث الاحتمالات المسبقة
        self.prior[vuln_type] += 1
        self._trained_count += 1
    
    def predict(self, text: str) -> Tuple[str, float]:
        """
        توقع نوع الثغرة
        
        Args:
            text: وصف الثغرة
        
        Returns:
            (النوع المتوقع, درجة الثقة)
        """
        words = self._tokenize(text)
        self._total_predictions += 1
        
        scores = {}
        total_prior = sum(self.prior.values())
        
        for vuln_type in self.VULN_TYPES:
            # log(P(type)) + sum(log(P(word|type)))
            score = math.log(self.prior[vuln_type] / total_prior)
            
            for word in words:
                # Laplace smoothing
                count = self.likelihood[vuln_type].get(word, 0)
                total = sum(self.likelihood[vuln_type].values())
                prob = (count + 1) / (total + len(words) + 1)
                score += math.log(prob)
            
            scores[vuln_type] = score
        
        # أفضل نوع
        best_type = max(scores, key=scores.get)
        
        # تحويل log-prob إلى confidence (softmax)
        max_score = scores[best_type]
        exp_scores = {t: math.exp(s - max_score) for t, s in scores.items()}
        total_exp = sum(exp_scores.values())
        confidence = exp_scores[best_type] / total_exp
        
        return best_type, confidence
    
    def predict_top_k(self, text: str, k: int = 3) -> List[Tuple[str, float]]:
        """أفضل k توقعات"""
        words = self._tokenize(text)
        
        scores = {}
        total_prior = sum(self.prior.values())
        
        for vuln_type in self.VULN_TYPES:
            score = math.log(self.prior[vuln_type] / total_prior)
            for word in words:
                count = self.likelihood[vuln_type].get(word, 0)
                total = sum(self.likelihood[vuln_type].values())
                prob = (count + 1) / (total + len(words) + 1)
                score += math.log(prob)
            scores[vuln_type] = score
        
        # ترتيب
        ranked = sorted(scores.items(), key=lambda x: x[1], reverse=True)
        
        # Softmax
        max_score = ranked[0][1]
        exp_scores = [(t, math.exp(s - max_score)) for t, s in ranked[:k]]
        total_exp = sum(s for _, s in exp_scores)
        
        return [(t, s / total_exp) for t, s in exp_scores]
    
    def auto_train_from_findings(self, findings: List[Dict]):
        """
        تدريب تلقائي من نتائج الفحص
        
        Args:
            findings: قائمة الثغرات (type, description, evidence)
        """
        for finding in findings:
            text = finding.get("description", "") + " " + finding.get("evidence", "")
            vuln_type = finding.get("type", "unknown")
            self.train(text, vuln_type)
        
        logger.info(f"Auto-trained on {len(findings)} findings")
    
    def save(self, path: str = "models/classifiers/vuln_classifier.json"):
        """حفظ النموذج"""
        os.makedirs(os.path.dirname(path), exist_ok=True)
        
        with open(path, 'w') as f:
            json.dump({
                "prior": self.prior,
                "likelihood": dict(self.likelihood),
                "trained_count": self._trained_count,
                "total_predictions": self._total_predictions
            }, f, indent=2)
        
        logger.info(f"Classifier saved to {path}")
    
    def load(self, path: str = "models/classifiers/vuln_classifier.json"):
        """تحميل النموذج"""
        if not os.path.exists(path):
            logger.warning(f"Classifier file not found: {path}")
            return
        
        with open(path, 'r') as f:
            data = json.load(f)
        
        self.prior = data.get("prior", self.prior)
        self.likelihood = defaultdict(lambda: defaultdict(float), data.get("likelihood", {}))
        self._trained_count = data.get("trained_count", 0)
        self._total_predictions = data.get("total_predictions", 0)
        
        logger.info(f"Classifier loaded from {path}")
    
    def get_stats(self) -> Dict:
        """إحصائيات المصنف"""
        return {
            "trained_count": self._trained_count,
            "total_predictions": self._total_predictions,
            "vuln_types": len(self.VULN_TYPES),
            "vocabulary_size": sum(len(v) for v in self.likelihood.values()),
            "top_features": {
                t: sorted(self.likelihood[t].items(), key=lambda x: x[1], reverse=True)[:5]
                for t in self.VULN_TYPES if t in self.likelihood
            }
        }


# نسخة عالمية
_default_classifier = None

def get_vuln_classifier() -> VulnerabilityClassifier:
    global _default_classifier
    if _default_classifier is None:
        _default_classifier = VulnerabilityClassifier()
        _default_classifier.load("models/classifiers/vuln_classifier.json")
    return _default_classifier
