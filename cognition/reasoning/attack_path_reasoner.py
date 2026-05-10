
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from collections import defaultdict

import logging

logger = logging.getLogger(__name__)


@dataclass
class AttackNode:
    """عقدة في مسار الهجوم"""
    id: str
    name: str
    vulnerability_type: str
    severity: str
    prerequisites: List[str]
    consequences: List[str]
    exploit_difficulty: float  # 0-1, higher means harder
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AttackPath:
    """مسار هجومي"""
    id: str
    nodes: List[AttackNode]
    start_node: str
    end_node: str
    total_difficulty: float
    total_risk: float
    created_at: datetime = field(default_factory=datetime.now)


class AttackPathReasoner:
    """
    مفكر مسارات الهجوم المتقدم
    
    الميزات:
    - تحليل مسارات الهجوم المحتملة
    - حساب صعوبة الاستغلال لكل مسار
    - تقييم المخاطر الكلية
    - تحديد أضعف مسار للهجوم
    """
    
    def __init__(self):
        self._attack_nodes: Dict[str, AttackNode] = {}
        self._attack_paths: List[AttackPath] = []
        self._adjacency: Dict[str, List[str]] = defaultdict(list)  # node -> reachable nodes
        
        # تهيئة العقد الافتراضية
        self._init_default_nodes()
        
        logger.info("AttackPathReasoner initialized")
    
    def _init_default_nodes(self):
        """تهيئة العقد الافتراضية"""
        
        nodes = [
            AttackNode(
                id="xss",
                name="XSS Vulnerability",
                vulnerability_type="XSS",
                severity="medium",
                prerequisites=["input_injection"],
                consequences=["session_hijack", "defacement"],
                exploit_difficulty=0.3
            ),
            AttackNode(
                id="session_hijack",
                name="Session Hijacking",
                vulnerability_type="Auth",
                severity="high",
                prerequisites=["xss"],
                consequences=["account_takeover"],
                exploit_difficulty=0.5
            ),
            AttackNode(
                id="sqli",
                name="SQL Injection",
                vulnerability_type="SQLi",
                severity="high",
                prerequisites=["database_interaction"],
                consequences=["data_breach", "bypass_auth"],
                exploit_difficulty=0.4
            ),
            AttackNode(
                id="data_breach",
                name="Data Breach",
                vulnerability_type="Data",
                severity="critical",
                prerequisites=["sqli"],
                consequences=["information_disclosure"],
                exploit_difficulty=0.6
            ),
            AttackNode(
                id="bypass_auth",
                name="Authentication Bypass",
                vulnerability_type="Auth",
                severity="critical",
                prerequisites=["sqli"],
                consequences=["unauthorized_access"],
                exploit_difficulty=0.5
            ),
            AttackNode(
                id="account_takeover",
                name="Account Takeover",
                vulnerability_type="Auth",
                severity="critical",
                prerequisites=["session_hijack", "bypass_auth"],
                consequences=["full_access"],
                exploit_difficulty=0.7
            ),
            AttackNode(
                id="rce",
                name="Remote Code Execution",
                vulnerability_type="RCE",
                severity="critical",
                prerequisites=["input_injection"],
                consequences=["system_compromise"],
                exploit_difficulty=0.6
            ),
            AttackNode(
                id="system_compromise",
                name="System Compromise",
                vulnerability_type="System",
                severity="critical",
                prerequisites=["rce"],
                consequences=["full_control"],
                exploit_difficulty=0.8
            ),
            AttackNode(
                id="idor",
                name="IDOR",
                vulnerability_type="IDOR",
                severity="medium",
                prerequisites=["authenticated"],
                consequences=["unauthorized_access"],
                exploit_difficulty=0.3
            )
        ]
        
        for node in nodes:
            self._attack_nodes[node.id] = node
        
        # بناء علاقات الجوار
        self._adjacency = {
            "xss": ["session_hijack"],
            "session_hijack": ["account_takeover"],
            "sqli": ["data_breach", "bypass_auth"],
            "bypass_auth": ["account_takeover"],
            "rce": ["system_compromise"],
            "idor": ["unauthorized_access"]
        }
    
    async def add_attack_node(self, node: AttackNode):
        """إضافة عقدة هجومية جديدة"""
        self._attack_nodes[node.id] = node
        logger.debug(f"Attack node added: {node.name}")
    
    async def add_edge(self, from_node: str, to_node: str):
        """إضافة علاقة بين عقدتين"""
        if from_node in self._attack_nodes and to_node in self._attack_nodes:
            self._adjacency[from_node].append(to_node)
            logger.debug(f"Edge added: {from_node} -> {to_node}")
    
    async def find_attack_paths(
        self,
        start_node: str,
        end_node: str,
        max_depth: int = 5
    ) -> List[AttackPath]:
        """
        البحث عن مسارات هجومية بين عقدتين
        
        Args:
            start_node: عقدة البداية
            end_node: عقدة النهاية
            max_depth: أقصى عمق للبحث
        
        Returns:
            قائمة بالمسارات الهجومية
        """
        if start_node not in self._attack_nodes or end_node not in self._attack_nodes:
            return []
        
        paths = []
        queue = [(start_node, [start_node])]
        
        while queue:
            current, path = queue.pop(0)
            
            if len(path) > max_depth:
                continue
            
            if current == end_node:
                # تحويل المسار إلى كائن AttackPath
                path_nodes = [self._attack_nodes[node_id] for node_id in path]
                total_difficulty = sum(node.exploit_difficulty for node in path_nodes) / len(path_nodes)
                total_risk = sum(self._get_node_risk(node) for node in path_nodes) / len(path_nodes)
                
                import uuid
                path_id = str(uuid.uuid4())[:8]
                
                attack_path = AttackPath(
                    id=path_id,
                    nodes=path_nodes,
                    start_node=start_node,
                    end_node=end_node,
                    total_difficulty=total_difficulty,
                    total_risk=total_risk
                )
                
                paths.append(attack_path)
                continue
            
            for neighbor in self._adjacency.get(current, []):
                if neighbor not in path:
                    queue.append((neighbor, path + [neighbor]))
        
        # ترتيب المسارات حسب المخاطر (الأعلى أولاً)
        paths.sort(key=lambda x: x.total_risk, reverse=True)
        
        return paths
    
    def _get_node_risk(self, node: AttackNode) -> float:
        """حساب خطر العقدة (0-1)"""
        severity_weights = {
            "critical": 1.0,
            "high": 0.8,
            "medium": 0.5,
            "low": 0.3
        }
        
        severity_risk = severity_weights.get(node.severity, 0.5)
        difficulty_risk = 1 - node.exploit_difficulty  # سهولة الاستغلال
        
        return (severity_risk * 0.6 + difficulty_risk * 0.4)
    
    async def get_easiest_path(
        self,
        start_node: str,
        end_node: str
    ) -> Optional[AttackPath]:
        """
        الحصول على أسهل مسار هجومي (أقل صعوبة)
        
        Args:
            start_node: عقدة البداية
            end_node: عقدة النهاية
        
        Returns:
            أسهل مسار هجومي
        """
        paths = await self.find_attack_paths(start_node, end_node)
        
        if not paths:
            return None
        
        return min(paths, key=lambda x: x.total_difficulty)
    
    async def get_riskiest_path(
        self,
        start_node: str,
        end_node: str
    ) -> Optional[AttackPath]:
        """
        الحصول على أكثر مسار هجومي خطورة
        
        Args:
            start_node: عقدة البداية
            end_node: عقدة النهاية
        
        Returns:
            أكثر مسار خطورة
        """
        paths = await self.find_attack_paths(start_node, end_node)
        
        if not paths:
            return None
        
        return max(paths, key=lambda x: x.total_risk)
    
    async def get_all_paths_summary(self) -> Dict:
        """ملخص جميع المسارات الهجومية"""
        if not self._attack_paths:
            return {"total_paths": 0}
        
        return {
            "total_paths": len(self._attack_paths),
            "average_difficulty": sum(p.total_difficulty for p in self._attack_paths) / len(self._attack_paths),
            "average_risk": sum(p.total_risk for p in self._attack_paths) / len(self._attack_paths),
            "highest_risk_path": max(self._attack_paths, key=lambda x: x.total_risk).id if self._attack_paths else None,
            "lowest_difficulty_path": min(self._attack_paths, key=lambda x: x.total_difficulty).id if self._attack_paths else None,
            "paths_by_end_node": defaultdict(
                int,
                {p.end_node: len([path for path in self._attack_paths if path.end_node == p.end_node]) for p in self._attack_paths}
            )
        }
    
    async def get_statistics(self) -> Dict:
        """إحصائيات المفكر"""
        return {
            "total_attack_nodes": len(self._attack_nodes),
            "total_edges": sum(len(neighbors) for neighbors in self._adjacency.values()),
            "total_attack_paths": len(self._attack_paths),
            "node_types": {
                node.vulnerability_type: len([n for n in self._attack_nodes.values() if n.vulnerability_type == node.vulnerability_type])
                for node in self._attack_nodes.values()
            },
            "average_node_difficulty": sum(n.exploit_difficulty for n in self._attack_nodes.values()) / len(self._attack_nodes) if self._attack_nodes else 0
        }

