# 🤖 Agents Overview

## Agent Types

### 1. Crawler Agent
- Discovers pages, forms, and links
- Supports SPA crawling with Playwright
- Extracts API endpoints from JavaScript

### 2. Recon Agent
- Analyzes attack surface
- Detects technologies (WAF, frameworks, servers)
- Identifies entry points

### 3. XSS Agent
- Detects reflected, stored, and DOM XSS
- Uses context-aware payloads
- Validates with actual browser execution

### 4. SQLi Agent
- Boolean, time, error, and union-based detection
- DBMS fingerprinting (MySQL, PostgreSQL, MSSQL, Oracle)
- Data extraction capabilities

### 5. IDOR Agent
- Finds guessable object IDs
- Tests horizontal/vertical access
- Analyzes privilege patterns

### 6. WAF Agent
- Detects WAF type (Cloudflare, AWS, ModSecurity)
- Generates bypass techniques
- Adaptive evasion learning

### 7. Auth Agent
- Tests password strength
- Analyzes JWT vulnerabilities
- Session fixation testing

### 8. Exploitation Agent
- Orchestrates exploit execution
- Manages attack chains
- Privilege escalation

### 9. Learning Agent
- Reinforcement learning
- Experience replay
- Q-learning optimization

## Base Agent Interface

All agents inherit from `BaseAgent`:

```python
class MyAgent(BaseAgent):
    async def _on_initialize(self):
        # Initialization logic
        pass
    
    async def _on_start(self):
        # Start logic
        pass
    
    async def _on_stop(self):
        # Cleanup logic
        pass
    
    async def _handle_message(self, message: AgentMessage):
        # Message handling
        pass
```

Agent Communication

Agents communicate via messages:

```python
# Send message
await agent.send_message(AgentMessage(
    type="scan_request",
    content={"target": "https://example.com"}
))

# Receive and respond
async def _handle_message(self, message):
    if message.type == "scan_request":
        result = await self.scan(message.content)
        return AgentMessage(
            type="scan_response",
            content=result
        )
```

