# 🏗️ Architecture Overview

## System Layers

```

┌─────────────────────────────────────────────────────────────┐
│                    INTERFACES LAYER                         │
│         REST API │ WebSocket │ CLI │ Dashboard              │
├─────────────────────────────────────────────────────────────┤
│                  ORCHESTRATION LAYER                        │
│      Orchestrator │ Event Bus │ Task Manager │ Scheduler    │
├─────────────────────────────────────────────────────────────┤
│                      AGENTS LAYER                           │
│   Recon │ Crawler │ XSS │ SQLi │ IDOR │ WAF │ Exploitation │
├─────────────────────────────────────────────────────────────┤
│                    COGNITION LAYER                          │
│   Brain │ Memory │ Knowledge │ Reasoning │ Planning │ Self-Improvement │
├─────────────────────────────────────────────────────────────┤
│                     LEARNING LAYER                          │
│      Meta-Learning │ Reinforcement │ Sequence Learning     │
├─────────────────────────────────────────────────────────────┤
│                    OFFENSIVE LAYER                          │
│         Scanners │ Payloads │ Recon │ Exploitation         │
├─────────────────────────────────────────────────────────────┤
│                 INFRASTRUCTURE LAYER                        │
│    Browser │ Networking │ Auth │ Sandbox │ Runtime         │
├─────────────────────────────────────────────────────────────┤
│                      STORAGE LAYER                          │
│            SQLite │ Vector DB │ Graph DB │ Object Storage   │
├─────────────────────────────────────────────────────────────┤
│                      SCHEMAS LAYER                          │
│              Data Contracts │ Type Definitions              │
└─────────────────────────────────────────────────────────────┘

```

## Dependency Direction

Dependencies flow **downward** only:

```

interfaces → orchestration → agents → cognition → learning → offensive → infrastructure → storage → schemas

```

No circular dependencies allowed!

## Key Components

### 1. Infrastructure Layer
- **Browser**: Playwright-based browser automation
- **Networking**: Proxy, rate limiting, session management
- **Runtime**: Async runtime, dependency injection, process management

### 2. Storage Layer
- **SQLite**: Learning database, persistence
- **Vector DB**: Semantic search with FAISS
- **Graph DB**: Knowledge graph storage

### 3. Offensive Layer
- **Scanners**: XSS, SQLi, IDOR, SSRF, CSRF, RCE detection
- **Payloads**: Generator, mutator, ranker, encoder
- **Exploitation**: Orchestrator, chains, post-exploitation

### 4. Cognition Layer
- **Brain**: Decision making, policy routing
- **Memory**: Episodic, semantic, working, procedural
- **Reasoning**: Multi-step, symbolic, causal

### 5. Learning Layer
- **Meta-Learning**: Learning to learn
- **Reinforcement Learning**: DQN, PPO, Actor-Critic
- **Online Learning**: Continual learning, adaptation
