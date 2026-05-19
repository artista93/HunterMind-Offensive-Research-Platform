"""Scan Policy Optimizer - تحسين استراتيجية الفحص"""
import json, os, random
from typing import Dict, List

class ScanPolicyOptimizer:
    def __init__(self):
        self.policies = {
            "aggressive": {"rate_limit": 5.0, "timeout": 15, "max_depth": 3},
            "balanced": {"rate_limit": 2.0, "timeout": 30, "max_depth": 2},
            "stealth": {"rate_limit": 0.5, "timeout": 60, "max_depth": 1},
        }
        self.performance: Dict[str, Dict] = {}
    def select_policy(self, target_type: str = "web") -> str:
        if target_type == "api": return "aggressive"
        if target_type == "waf": return "stealth"
        return "balanced"
    def record_performance(self, policy: str, findings: int, duration: float):
        if policy not in self.performance:
            self.performance[policy] = {"uses": 0, "total_findings": 0, "total_time": 0}
        self.performance[policy]["uses"] += 1
        self.performance[policy]["total_findings"] += findings
        self.performance[policy]["total_time"] += duration
    def save(self, path: str): 
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'w') as f: json.dump(self.performance, f)
    def load(self, path: str):
        if os.path.exists(path):
            with open(path, 'r') as f: self.performance = json.load(f)
