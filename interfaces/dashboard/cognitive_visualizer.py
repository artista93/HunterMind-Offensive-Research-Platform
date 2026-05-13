import asyncio
import json
from typing import Dict, List, Any, Optional
from datetime import datetime
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
import uvicorn

import logging

logger = logging.getLogger(__name__)

# إنشاء تطبيق FastAPI
app = FastAPI(title="HunterMind Cognitive Visualizer", version="1.0.0")


class CognitiveMonitor:
    """مراقب العمليات المعرفية"""
    
    def __init__(self):
        self.active_connections: List[WebSocket] = []
        self.cognitive_state = {
            "current_state": "idle",
            "thinking_cycle": 0,
            "active_agents": [],
            "memory_usage": {
                "working": 0,
                "episodic": 0,
                "semantic": 0
            },
            "last_decision": None,
            "reasoning_chain": []
        }
        self._lock = asyncio.Lock()
        
        logger.info("CognitiveMonitor initialized")
    
    async def connect(self, websocket: WebSocket):
        """قبول اتصال جديد"""
        await websocket.accept()
        async with self._lock:
            self.active_connections.append(websocket)
        logger.info(f"Cognitive client connected. Total: {len(self.active_connections)}")
    
    async def disconnect(self, websocket: WebSocket):
        """قطع اتصال عميل"""
        async with self._lock:
            if websocket in self.active_connections:
                self.active_connections.remove(websocket)
        logger.info(f"Cognitive client disconnected. Total: {len(self.active_connections)}")
    
    async def broadcast(self, data: Dict):
        """بث بيانات للمتصفحات المتصلة"""
        async with self._lock:
            for connection in self.active_connections:
                try:
                    await connection.send_json(data)
                except Exception as e:
                    logger.error(f"Broadcast error: {e}")
    
    async def update_state(self, new_state: Dict):
        """تحديث حالة النظام المعرفي"""
        self.cognitive_state.update(new_state)
        await self.broadcast({
            "type": "state_update",
            "data": self.cognitive_state
        })
    
    async def add_reasoning_step(self, step: Dict):
        """إضافة خطوة تفكير إلى السلسلة"""
        self.cognitive_state["reasoning_chain"].append({
            **step,
            "timestamp": datetime.now().isoformat()
        })
        
        # الحفاظ على آخر 50 خطوة فقط
        if len(self.cognitive_state["reasoning_chain"]) > 50:
            self.cognitive_state["reasoning_chain"] = self.cognitive_state["reasoning_chain"][-50:]
        
        await self.broadcast({
            "type": "reasoning_step",
            "step": step
        })
    
    async def record_decision(self, decision: Dict):
        """تسجيل قرار تم اتخاذه"""
        self.cognitive_state["last_decision"] = {
            **decision,
            "timestamp": datetime.now().isoformat()
        }
        await self.broadcast({
            "type": "decision_made",
            "decision": self.cognitive_state["last_decision"]
        })


# إنشاء مراقب العمليات المعرفية
cognitive_monitor = CognitiveMonitor()


@app.websocket("/ws/cognitive")
async def cognitive_websocket(websocket: WebSocket):
    """نقطة نهاية WebSocket للمراقبة المعرفية"""
    await cognitive_monitor.connect(websocket)
    
    try:
        # إرسال الحالة الحالية
        await cognitive_monitor.broadcast({
            "type": "initial_state",
            "data": cognitive_monitor.cognitive_state
        })
        
        while True:
            data = await websocket.receive_text()
            await handle_cognitive_message(data, websocket)
            
    except WebSocketDisconnect:
        await cognitive_monitor.disconnect(websocket)


async def handle_cognitive_message(message: str, websocket: WebSocket):
    """معالجة رسائل العميل"""
    import json
    
    try:
        data = json.loads(message)
        msg_type = data.get("type", "unknown")
        
        if msg_type == "ping":
            await websocket.send_json({"type": "pong"})
        
        elif msg_type == "get_state":
            await websocket.send_json({
                "type": "state",
                "data": cognitive_monitor.cognitive_state
            })
        
    except json.JSONDecodeError:
        logger.error(f"Invalid JSON: {message}")


@app.get("/cognitive")
async def get_cognitive_page():
    """صفحة تصور العمليات المعرفية"""
    return HTMLResponse(html_template)


@app.post("/api/cognitive/state")
async def update_cognitive_state(data: Dict):
    """تحديث حالة النظام المعرفي"""
    await cognitive_monitor.update_state(data)
    return {"status": "updated"}


@app.post("/api/cognitive/reasoning")
async def add_reasoning_step(data: Dict):
    """إضافة خطوة تفكير"""
    await cognitive_monitor.add_reasoning_step(data)
    return {"status": "added"}


@app.post("/api/cognitive/decision")
async def record_decision(data: Dict):
    """تسجيل قرار"""
    await cognitive_monitor.record_decision(data)
    return {"status": "recorded"}


@app.get("/api/cognitive/state")
async def get_cognitive_state():
    """الحصول على حالة النظام المعرفي"""
    return cognitive_monitor.cognitive_state


# قالب HTML مع تصور تفاعلي
html_template = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HunterMind Cognitive Visualizer</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #0f0c29, #302b63, #24243e);
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
        
        .brain-container {
            display: flex;
            justify-content: center;
            margin: 30px 0;
        }
        
        .brain {
            width: 200px;
            height: 200px;
            background: radial-gradient(circle, #667eea, #764ba2);
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 3rem;
            animation: pulse 2s infinite;
            box-shadow: 0 0 30px rgba(102,126,234,0.5);
        }
        
        @keyframes pulse {
            0%, 100% { transform: scale(1); opacity: 1; }
            50% { transform: scale(1.05); opacity: 0.8; }
        }
        
        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .card {
            background: rgba(255,255,255,0.05);
            backdrop-filter: blur(10px);
            border-radius: 15px;
            padding: 20px;
        }
        
        .card-title {
            font-size: 1.2rem;
            margin-bottom: 15px;
            color: #667eea;
            border-left: 3px solid #667eea;
            padding-left: 10px;
        }
        
        .state-indicator {
            display: inline-block;
            width: 12px;
            height: 12px;
            border-radius: 50%;
            margin-right: 8px;
        }
        
        .state-idle { background: #27ae60; box-shadow: 0 0 10px #27ae60; }
        .state-thinking { background: #f1c40f; box-shadow: 0 0 10px #f1c40f; animation: pulse 1s infinite; }
        .state-deciding { background: #e67e22; box-shadow: 0 0 10px #e67e22; }
        .state-learning { background: #3498db; box-shadow: 0 0 10px #3498db; }
        
        .memory-bar {
            background: rgba(255,255,255,0.1);
            border-radius: 10px;
            height: 20px;
            margin: 10px 0;
            overflow: hidden;
        }
        
        .memory-fill {
            height: 100%;
            background: linear-gradient(90deg, #667eea, #764ba2);
            border-radius: 10px;
            transition: width 0.5s;
        }
        
        .reasoning-chain {
            max-height: 300px;
            overflow-y: auto;
        }
        
        .reasoning-step {
            padding: 10px;
            background: rgba(255,255,255,0.05);
            margin-bottom: 10px;
            border-radius: 8px;
            border-left: 3px solid #667eea;
        }
        
        .step-time {
            font-size: 0.7rem;
            color: #888;
            margin-bottom: 5px;
        }
        
        .step-content {
            font-size: 0.9rem;
        }
        
        .decision-card {
            background: rgba(102,126,234,0.2);
            border: 1px solid #667eea;
        }
        
        .agent-tag {
            display: inline-block;
            padding: 4px 12px;
            background: rgba(102,126,234,0.3);
            border-radius: 20px;
            margin: 5px;
            font-size: 0.8rem;
        }
        
        @keyframes glow {
            0%, 100% { text-shadow: 0 0 5px #667eea; }
            50% { text-shadow: 0 0 20px #667eea; }
        }
        
        .thinking-cycle {
            font-size: 2rem;
            font-weight: bold;
            text-align: center;
            animation: glow 1s infinite;
        }
        
        @media (max-width: 768px) {
            .grid {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🧠 Cognitive Visualizer</h1>
            <p>Real-time cognitive state monitoring</p>
        </header>
        
        <div class="brain-container">
            <div class="brain" id="brainIcon">
                🧠
            </div>
        </div>
        
        <div class="thinking-cycle" id="thinkingCycle">
            Cycle: 0
        </div>
        
        <div class="grid">
            <div class="card">
                <div class="card-title">📊 System State</div>
                <div id="stateDisplay">
                    <span class="state-indicator state-idle"></span>
                    <span id="currentState">idle</span>
                </div>
                <div style="margin-top: 15px;">
                    <div>Working Memory</div>
                    <div class="memory-bar">
                        <div class="memory-fill" id="workingMemoryFill" style="width: 0%"></div>
                    </div>
                    <div>Episodic Memory</div>
                    <div class="memory-bar">
                        <div class="memory-fill" id="episodicMemoryFill" style="width: 0%"></div>
                    </div>
                    <div>Semantic Memory</div>
                    <div class="memory-bar">
                        <div class="memory-fill" id="semanticMemoryFill" style="width: 0%"></div>
                    </div>
                </div>
            </div>
            
            <div class="card">
                <div class="card-title">🤖 Active Agents</div>
                <div id="agentsList">
                    <span class="agent-tag">No active agents</span>
                </div>
            </div>
            
            <div class="card decision-card">
                <div class="card-title">⚡ Last Decision</div>
                <div id="lastDecision">
                    <p style="color: #888;">No decision yet</p>
                </div>
            </div>
        </div>
        
        <div class="card">
            <div class="card-title">🔗 Reasoning Chain</div>
            <div class="reasoning-chain" id="reasoningChain">
                <p style="color: #888; text-align: center;">No reasoning steps yet</p>
            </div>
        </div>
    </div>
    
    <script>
        let ws = null;
        
        function connect() {
            const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
            const wsUrl = `${protocol}//${window.location.host}/ws/cognitive`;
            
            ws = new WebSocket(wsUrl);
            
            ws.onopen = function() {
                console.log('WebSocket connected');
                document.getElementById('brainIcon').style.animation = 'pulse 1s infinite';
            };
            
            ws.onmessage = function(event) {
                const data = JSON.parse(event.data);
                handleMessage(data);
            };
            
            ws.onclose = function() {
                console.log('WebSocket disconnected, reconnecting...');
                document.getElementById('brainIcon').style.animation = 'none';
                setTimeout(connect, 3000);
            };
        }
        
        function handleMessage(data) {
            const type = data.type;
            
            switch(type) {
                case 'initial_state':
                case 'state_update':
                    updateUI(data.data);
                    break;
                    
                case 'reasoning_step':
                    addReasoningStep(data.step);
                    break;
                    
                case 'decision_made':
                    updateDecision(data.decision);
                    break;
            }
        }
        
        function updateUI(state) {
            const stateSpan = document.getElementById('currentState');
            const stateIndicator = document.querySelector('#stateDisplay .state-indicator');
            
            stateSpan.textContent = state.current_state;
            stateIndicator.className = `state-indicator state-${state.current_state}`;
            
            document.getElementById('thinkingCycle').textContent = `Cycle: ${state.thinking_cycle || 0}`;
            
            if (state.memory_usage) {
                document.getElementById('workingMemoryFill').style.width = `${state.memory_usage.working * 100}%`;
                document.getElementById('episodicMemoryFill').style.width = `${state.memory_usage.episodic * 100}%`;
                document.getElementById('semanticMemoryFill').style.width = `${state.memory_usage.semantic * 100}%`;
            }
            
            const agentsList = document.getElementById('agentsList');
            if (state.active_agents && state.active_agents.length > 0) {
                agentsList.innerHTML = state.active_agents.map(agent => 
                    `<span class="agent-tag">${agent}</span>`
                ).join('');
            } else {
                agentsList.innerHTML = '<span class="agent-tag">No active agents</span>';
            }
        }
        
        function addReasoningStep(step) {
            const reasoningChain = document.getElementById('reasoningChain');
            
            if (reasoningChain.innerHTML.includes('No reasoning steps yet')) {
                reasoningChain.innerHTML = '';
            }
            
            const stepDiv = document.createElement('div');
            stepDiv.className = 'reasoning-step';
            stepDiv.innerHTML = `
                <div class="step-time">${new Date().toLocaleTimeString()}</div>
                <div class="step-content"><strong>${step.type || 'Step'}:</strong> ${step.content || step.description || ''}</div>
            `;
            
            reasoningChain.insertBefore(stepDiv, reasoningChain.firstChild);
            
            while (reasoningChain.children.length > 20) {
                reasoningChain.removeChild(reasoningChain.lastChild);
            }
        }
        
        function updateDecision(decision) {
            const decisionDiv = document.getElementById('lastDecision');
            decisionDiv.innerHTML = `
                <div class="step-time">${new Date(decision.timestamp).toLocaleTimeString()}</div>
                <div><strong>Action:</strong> ${decision.action || 'unknown'}</div>
                <div><strong>Confidence:</strong> ${(decision.confidence * 100).toFixed(1)}%</div>
                <div><strong>Reasoning:</strong> ${decision.reasoning || 'N/A'}</div>
            `;
        }
        
        connect();
        
        setInterval(() => {
            if (ws && ws.readyState === WebSocket.OPEN) {
                ws.send(JSON.stringify({ type: 'ping' }));
            }
        }, 5000);
    </script>
</body>
</html>'''


# تشغيل الخادم
if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5003)
