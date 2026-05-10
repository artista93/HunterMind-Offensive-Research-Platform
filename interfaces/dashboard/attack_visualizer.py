
import json
from typing import Dict, List, Any, Optional
from datetime import datetime
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
import uvicorn

import logging

logger = logging.getLogger(__name__)

# إنشاء تطبيق FastAPI
app = FastAPI(title="HunterMind Attack Visualizer", version="1.0.0")

# بيانات الهجمات
attack_data = {
    "attack_chains": [],
    "attack_statistics": {
        "total_attacks": 0,
        "successful_attacks": 0,
        "failed_attacks": 0,
        "by_type": {}
    }
}


class AttackVisualizer:
    """مصور الهجمات"""
    
    def __init__(self):
        self.chains = []
        self.nodes = {}
        self.edges = []
        
        logger.info("AttackVisualizer initialized")
    
    def add_attack_chain(self, chain_id: str, name: str, steps: List[Dict]):
        """إضافة سلسلة هجومية"""
        chain = {
            "id": chain_id,
            "name": name,
            "steps": steps,
            "created_at": datetime.now().isoformat()
        }
        self.chains.append(chain)
        
        # تحديث العقد والعلاقات للتصور
        for i, step in enumerate(steps):
            node_id = f"{chain_id}_step_{i}"
            self.nodes[node_id] = {
                "id": node_id,
                "label": step.get("name", f"Step {i}"),
                "type": step.get("type", "action"),
                "vulnerability": step.get("vulnerability", "unknown")
            }
            
            if i > 0:
                prev_id = f"{chain_id}_step_{i-1}"
                self.edges.append({
                    "from": prev_id,
                    "to": node_id,
                    "label": "→"
                })
        
        logger.info(f"Attack chain added: {name}")
    
    def get_graph_data(self) -> Dict:
        """الحصول على بيانات الرسم البياني"""
        return {
            "nodes": list(self.nodes.values()),
            "edges": self.edges
        }
    
    def get_chains(self) -> List[Dict]:
        """الحصول على جميع سلاسل الهجوم"""
        return self.chains
    
    def clear(self):
        """مسح البيانات"""
        self.chains.clear()
        self.nodes.clear()
        self.edges.clear()


# إنشاء المصور
visualizer = AttackVisualizer()


@app.get("/visualizer")
async def get_visualizer_page():
    """صفحة مصور الهجمات"""
    return HTMLResponse(html_template)


@app.get("/api/attack-chains")
async def get_attack_chains():
    """الحصول على سلاسل الهجوم"""
    return {
        "chains": visualizer.get_chains(),
        "statistics": attack_data["attack_statistics"]
    }


@app.get("/api/graph-data")
async def get_graph_data():
    """الحصول على بيانات الرسم البياني للتصور"""
    return visualizer.get_graph_data()


@app.post("/api/add-attack-chain")
async def add_attack_chain(data: Dict):
    """إضافة سلسلة هجومية جديدة"""
    chain_id = data.get("id")
    name = data.get("name")
    steps = data.get("steps", [])
    
    visualizer.add_attack_chain(chain_id, name, steps)
    
    # تحديث الإحصائيات
    attack_data["attack_statistics"]["total_attacks"] += 1
    
    return {"status": "added", "chain_id": chain_id}


@app.post("/api/record-attack-result")
async def record_attack_result(data: Dict):
    """تسجيل نتيجة هجوم"""
    success = data.get("success", False)
    attack_type = data.get("type", "unknown")
    
    if success:
        attack_data["attack_statistics"]["successful_attacks"] += 1
    else:
        attack_data["attack_statistics"]["failed_attacks"] += 1
    
    attack_data["attack_statistics"]["by_type"][attack_type] = \
        attack_data["attack_statistics"]["by_type"].get(attack_type, 0) + 1
    
    return {"status": "recorded"}


@app.delete("/api/clear")
async def clear_data():
    """مسح بيانات المصور"""
    visualizer.clear()
    attack_data["attack_chains"] = []
    attack_data["attack_statistics"] = {
        "total_attacks": 0,
        "successful_attacks": 0,
        "failed_attacks": 0,
        "by_type": {}
    }
    return {"status": "cleared"}


# قالب HTML مع رسم بياني تفاعلي
html_template = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HunterMind Attack Visualizer</title>
    <script src="https://cdn.jsdelivr.net/npm/vis-network@9.1.2/dist/vis-network.min.js"></script>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #1a1a2e, #16213e);
            color: #fff;
            min-height: 100vh;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }
        
        header {
            text-align: center;
            padding: 20px;
            border-bottom: 1px solid rgba(255,255,255,0.1);
            margin-bottom: 20px;
        }
        
        h1 {
            font-size: 2rem;
            background: linear-gradient(135deg, #667eea, #764ba2);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        
        .main-content {
            display: grid;
            grid-template-columns: 1fr 300px;
            gap: 20px;
        }
        
        .graph-container {
            background: rgba(255,255,255,0.05);
            border-radius: 15px;
            padding: 15px;
            height: 600px;
        }
        
        #network {
            width: 100%;
            height: 100%;
            background: rgba(0,0,0,0.5);
            border-radius: 10px;
        }
        
        .sidebar {
            background: rgba(255,255,255,0.05);
            border-radius: 15px;
            padding: 20px;
        }
        
        .sidebar h3 {
            margin-bottom: 15px;
            color: #667eea;
        }
        
        .stats {
            margin-bottom: 20px;
            padding: 15px;
            background: rgba(0,0,0,0.3);
            border-radius: 10px;
        }
        
        .stat-item {
            display: flex;
            justify-content: space-between;
            padding: 8px 0;
            border-bottom: 1px solid rgba(255,255,255,0.1);
        }
        
        .chains-list {
            max-height: 300px;
            overflow-y: auto;
        }
        
        .chain-item {
            padding: 10px;
            background: rgba(255,255,255,0.05);
            margin-bottom: 10px;
            border-radius: 5px;
            cursor: pointer;
            transition: all 0.3s;
        }
        
        .chain-item:hover {
            background: rgba(102,126,234,0.3);
        }
        
        .chain-name {
            font-weight: bold;
            margin-bottom: 5px;
        }
        
        .chain-steps {
            font-size: 0.8rem;
            color: #888;
        }
        
        button {
            width: 100%;
            padding: 10px;
            background: #667eea;
            border: none;
            color: white;
            border-radius: 5px;
            cursor: pointer;
            margin-top: 10px;
            transition: all 0.3s;
        }
        
        button:hover {
            background: #764ba2;
        }
        
        .legend {
            margin-top: 20px;
            padding-top: 20px;
            border-top: 1px solid rgba(255,255,255,0.1);
        }
        
        .legend-item {
            display: flex;
            align-items: center;
            margin-bottom: 8px;
        }
        
        .legend-color {
            width: 20px;
            height: 20px;
            border-radius: 50%;
            margin-right: 10px;
        }
        
        .color-critical { background: #e74c3c; }
        .color-high { background: #e67e22; }
        .color-medium { background: #f1c40f; }
        .color-low { background: #27ae60; }
        
        @media (max-width: 768px) {
            .main-content {
                grid-template-columns: 1fr;
            }
            
            .graph-container {
                height: 400px;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🎯 Attack Visualizer</h1>
            <p>Interactive attack chain visualization</p>
        </header>
        
        <div class="main-content">
            <div class="graph-container">
                <div id="network"></div>
            </div>
            
            <div class="sidebar">
                <h3>📊 Statistics</h3>
                <div class="stats" id="stats">
                    <div class="stat-item">
                        <span>Total Attacks:</span>
                        <span id="totalAttacks">0</span>
                    </div>
                    <div class="stat-item">
                        <span>Successful:</span>
                        <span id="successfulAttacks">0</span>
                    </div>
                    <div class="stat-item">
                        <span>Failed:</span>
                        <span id="failedAttacks">0</span>
                    </div>
                    <div class="stat-item">
                        <span>Success Rate:</span>
                        <span id="successRate">0%</span>
                    </div>
                </div>
                
                <h3>🔗 Attack Chains</h3>
                <div class="chains-list" id="chainsList">
                    <div class="chain-item">
                        <div class="chain-name">No chains yet</div>
                    </div>
                </div>
                
                <button onclick="refreshData()">Refresh</button>
                
                <div class="legend">
                    <h3>📖 Legend</h3>
                    <div class="legend-item">
                        <div class="legend-color color-critical"></div>
                        <span>Critical</span>
                    </div>
                    <div class="legend-item">
                        <div class="legend-color color-high"></div>
                        <span>High</span>
                    </div>
                    <div class="legend-item">
                        <div class="legend-color color-medium"></div>
                        <span>Medium</span>
                    </div>
                    <div class="legend-item">
                        <div class="legend-color color-low"></div>
                        <span>Low</span>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <script>
        let network = null;
        
        async function loadGraph() {
            try {
                const response = await fetch('/api/graph-data');
                const data = await response.json();
                
                const nodes = new vis.DataSet(data.nodes.map(node => ({
                    id: node.id,
                    label: node.label,
                    title: `Type: ${node.type}\\nVulnerability: ${node.vulnerability}`,
                    color: getColorBySeverity(node.vulnerability),
                    shape: 'box',
                    font: { color: 'white' }
                })));
                
                const edges = new vis.DataSet(data.edges.map(edge => ({
                    from: edge.from,
                    to: edge.to,
                    arrows: 'to',
                    color: { color: '#667eea' }
                })));
                
                const container = document.getElementById('network');
                const options = {
                    nodes: {
                        shape: 'box',
                        margin: 10,
                        font: { size: 12, color: 'white' }
                    },
                    edges: {
                        smooth: { type: 'curvedCW' }
                    },
                    physics: {
                        enabled: true,
                        stabilization: { iterations: 100 }
                    },
                    interaction: {
                        hover: true,
                        tooltipDelay: 100
                    }
                };
                
                network = new vis.Network(container, { nodes, edges }, options);
                
            } catch (error) {
                console.error('Error loading graph:', error);
            }
        }
        
        function getColorBySeverity(vulnerability) {
            const vulnLower = vulnerability.toLowerCase();
            if (vulnLower.includes('critical') || vulnLower.includes('rce')) {
                return '#e74c3c';
            } else if (vulnLower.includes('high') || vulnLower.includes('sqli')) {
                return '#e67e22';
            } else if (vulnLower.includes('medium') || vulnLower.includes('xss')) {
                return '#f1c40f';
            } else {
                return '#27ae60';
            }
        }
        
        async function loadChains() {
            try {
                const response = await fetch('/api/attack-chains');
                const data = await response.json();
                
                const chainsList = document.getElementById('chainsList');
                if (data.chains.length === 0) {
                    chainsList.innerHTML = '<div class="chain-item"><div class="chain-name">No chains yet</div></div>';
                } else {
                    chainsList.innerHTML = data.chains.map(chain => `
                        <div class="chain-item" onclick="highlightChain('${chain.id}')">
                            <div class="chain-name">${escapeHtml(chain.name)}</div>
                            <div class="chain-steps">${chain.steps.length} steps</div>
                        </div>
                    `).join('');
                }
                
                // تحديث الإحصائيات
                const stats = data.statistics;
                document.getElementById('totalAttacks').textContent = stats.total_attacks;
                document.getElementById('successfulAttacks').textContent = stats.successful_attacks;
                document.getElementById('failedAttacks').textContent = stats.failed_attacks;
                
                const successRate = stats.total_attacks > 0 
                    ? ((stats.successful_attacks / stats.total_attacks) * 100).toFixed(1)
                    : 0;
                document.getElementById('successRate').textContent = `${successRate}%`;
                
            } catch (error) {
                console.error('Error loading chains:', error);
            }
        }
        
        function highlightChain(chainId) {
            // تسليط الضوء على السلسلة في الرسم البياني
            if (network) {
                // البحث عن العقد في السلسلة
                const allNodes = network.getBody().data.nodes.get();
                const chainNodes = allNodes.filter(node => node.id.startsWith(chainId));
                
                // إعادة تعيين الألوان
                allNodes.forEach(node => {
                    network.getBody().data.nodes.update({
                        id: node.id,
                        color: getColorBySeverity(node.vulnerability)
                    });
                });
                
                // تسليط الضوء على العقد في السلسلة
                chainNodes.forEach(node => {
                    network.getBody().data.nodes.update({
                        id: node.id,
                        color: '#f1c40f',
                        borderWidth: 3,
                        borderColor: '#fff'
                    });
                });
            }
        }
        
        function refreshData() {
            loadGraph();
            loadChains();
        }
        
        function escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }
        
        // تحميل البيانات عند بدء التشغيل
        loadGraph();
        loadChains();
        
        // تحديث كل 30 ثانية
        setInterval(refreshData, 30000);
    </script>
</body>
</html>'''


# تشغيل الخادم
if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5002)

