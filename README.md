<div align="center">

# 🦅 HunterMind Offensive Research Platform

### Autonomous Offensive Security Intelligence System

[![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)](https://www.python.org/)
[![Playwright](https://img.shields.io/badge/Playwright-1.40+-green.svg)](https://playwright.dev/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Research](https://img.shields.io/badge/Purpose-Offensive%20Security%20Research-red.svg)]()

**Autonomous | Cognitive | Adaptive | Scalable**

</div>

---

## ⚠️ Important Disclaimer

**This platform is for authorized security research and educational purposes ONLY.**

- ✅ **ONLY** use on systems you own or have explicit permission to test
- ✅ **ONLY** use in controlled research environments
- ❌ **NEVER** use on production systems without authorization
- ❌ **NOT** responsible for any illegal or unauthorized use
- 🔒 **Always** follow responsible disclosure practices

---

## 🎯 What is HunterMind?

**HunterMind** is an **Autonomous Offensive Security Research Platform** that combines:

- 🧠 **Cognitive Architecture** - Human-like reasoning and decision making
- 🤖 **Multi-Agent System** - Specialized autonomous agents working in coordination
- ⚔️ **Advanced Offensive Capabilities** - State-of-the-art vulnerability discovery and exploitation
- 📚 **Continuous Learning** - Meta-learning, reinforcement learning, and sequence learning
- 🔬 **Research-Oriented** - Built for security researchers and penetration testers
- 🕵️ **Advanced Reconnaissance** - Passive & active recon like real penetration testers
- 💥 **Auto-Exploitation** - Automatic exploitation of discovered secrets and vulnerabilities

---

## 🚀 Key Features

### 🕵️ Advanced Reconnaissance (8-Step Pre-Scan)

| Step | Component | Type | Description |
|------|-----------|------|-------------|
| 1 | **DNS Enumeration** | Passive | A, AAAA, CNAME, MX, TXT, NS records, Zone Transfer |
| 2 | **CRT.sh Search** | Passive | SSL certificate search for hidden subdomains |
| 3 | **Wayback Machine** | Passive | Historical page analysis, old backup/config files |
| 4 | **WHOIS Lookup** | Passive | Domain registration details, expiry, nameservers |
| 5 | **Fingerprinting** | Active | Wappalyzer-style: 50+ technologies, CMS, frameworks |
| 6 | **CVE Lookup** | Passive | Known vulnerabilities in discovered versions |
| 7 | **Sensitive Files** | Active | .env, .git, backups, admin panels, logs, configs |
| 8 | **Metadata Analysis** | Passive | PDF/DOCX/EXIF metadata, usernames, internal paths |

### ⚔️ Offensive Capabilities

| Capability | Details |
|------------|---------|
| **Vulnerability Scanning** | XSS, SQLi, IDOR, SSRF, CSRF, RCE, Auth, GraphQL, API |
| **Advanced Payloads** | Self-evolving payloads, context-aware generation |
| **Attack Chaining** | Multi-step attack path generation and execution |
| **WAF Evasion** | Adaptive bypass techniques, payload obfuscation |
| **Authentication Attacks** | Session hijacking, token extraction, brute force |
| **API Security** | GraphQL introspection, REST API fuzzing |
| **Browser-Based Scanning** | Real browser (Playwright) for JavaScript-heavy sites |
| **Secrets Detection** | AWS keys, GitHub tokens, JWT, API keys, DB URLs |
| **Auto-Exploitation** | JWT cracking, GitHub token validation, webhook testing |

### 📚 Learning Systems

| System | Description |
|--------|-------------|
| **DQN Agent** | Reinforcement learning for payload selection |
| **Naive Bayes Classifier** | Automatic vulnerability type classification |
| **Vector Store** | Similar vulnerability search |
| **Scan Policy Optimizer** | Adaptive scanning strategy selection |

### 🏗️ Enterprise-Grade Architecture

| Component | Description |
|-----------|-------------|
| **Smart Orchestrator** | 6-phase intelligent scanning with recon integration |
| **Event Bus** | 13 event types for real-time communication |
| **WorldState Manager** | Target state tracking, WAF detection, phase management |
| **Payload Manager** | Self-evolving payloads with 14 mutation strategies |
| **Multiple Interfaces** | CLI, REST API, WebSocket, Web Dashboard, Reporting |
| **Session Management** | Interactive login, cookie import, session persistence |

---

## 🏛️ Architecture

```

┌─────────────────────────────────────────────────────────────┐
│                    INTERFACES LAYER                         │
│         CLI │ REST API │ WebSocket │ Dashboard │ Reports    │
├─────────────────────────────────────────────────────────────┤
│                  ORCHESTRATION LAYER                        │
│   SmartOrchestrator │ Orchestrator │ EventBus │ WorldState  │
├─────────────────────────────────────────────────────────────┤
│                 RECONNAISSANCE LAYER                        │
│   Passive (4) │ Active (3) │ Fingerprinting (2) │ Metadata  │
├─────────────────────────────────────────────────────────────┤
│                    OFFENSIVE LAYER                          │
│   12 Scanners │ Recon Tools │ Exploitation │ Payloads       │
├─────────────────────────────────────────────────────────────┤
│                 INFRASTRUCTURE LAYER                        │
│   Networking (7) │ Auth (2) │ Browser │ AI Models (4)       │
├─────────────────────────────────────────────────────────────┤
│                      DATA LAYER                             │
│   PostgreSQL │ Redis │ Datasets │ Models │ Configs          │
└─────────────────────────────────────────────────────────────┘

```

---

## 📁 Project Structure

```

HunterMind_Offensive_Research_Platform/
│
├── 📄 cli.py                        # Main entry point
├── 📁 schemas/                      # 7 data contracts
├── 📁 interfaces/                   # CLI, API, Dashboard, Reporting
├── 📁 orchestration/                # SmartOrchestrator, EventBus, WorldState
├── 📁 offensive/
│   ├── scanners/                    # 12 scanners (XSS, SQLi, IDOR, JWT, Browser...)
│   ├── recon/                       # 8 recon tools (Crawler, JS, Secrets, Site...)
│   ├── exploitation/                # Auto-exploitation engine
│   └── reconnaissance/              # 8-step pre-scan module
│       ├── passive/                 # DNS, CRT.sh, Wayback, WHOIS
│       ├── active/                  # Subdomain scanner
│       ├── fingerprinting/          # Wappalyzer, CVE lookup
│       ├── sensitive/               # Sensitive files + exploitation
│       └── metadata/                # PDF/DOCX/EXIF analysis
├── 📁 infrastructure/
│   ├── networking/                  # 7 tools (Monitor, Proxy, Rate, Session...)
│   ├── auth/                        # InteractiveLogin, AuthManager
│   └── browser/                     # Playwright drivers
├── 📁 models/                       # 4 AI models (DQN, Classifier, Vector, Policy)
├── 📁 datasets/                     # Training data (payloads, chains, WAF, apps)
├── 📁 database/                     # PostgreSQL + Redis clients
├── 📁 configs/                      # YAML configurations
└── 📁 tests/                        # Test suites

```

---

## 🔧 Installation

### Prerequisites

```bash
Python 3.9+
8GB RAM (minimum), 16GB+ recommended
Docker (optional, for sandbox)
```

Quick Install

```bash
# Clone the repository
git clone https://github.com/akkalighter/HunterMind_Offensive_Research_Platform.git
cd HunterMind_Offensive_Research_Platform

# Install dependencies
pip install -r requirements.txt

# Install Playwright (optional - for browser-based scanning)
pip install playwright
playwright install chromium

# Install DNS tools (optional)
pip install dnspython
```

---

🚀 Usage

Command Line Interface

```bash
# Pre-scan reconnaissance (8 steps)
python cli.py analyze https://target.com

# Smart scan (recon + scanning + exploitation)
python cli.py smart https://target.com --depth 2 --max-pages 10

# Full scan with all 12 scanners
python cli.py scan https://target.com --depth 3 --max-pages 50

# Interactive login wizard
python cli.py login https://target.com/login

# Save cookies from browser
python cli.py cookies https://target.com "session=abc123; csrf=xyz789"

# View saved sessions
python cli.py sessions

# System status
python cli.py status

# List scans/vulnerabilities
python cli.py list scans
python cli.py list vulnerabilities
```

Smart Scan Output

```
🔍 HunterMind Smart Scan V4
   Target: https://target.com
============================================================

🔍 Phase 0: Advanced Reconnaissance (8 steps)...
📡 DNS Enumeration: target.com
   ✅ Found 5 subdomains, 12 records
📜 CRT.sh Search: target.com
   ✅ Found 12 subdomains from 8 certificates
📚 Wayback Machine: target.com
   ✅ Found 500 archived URLs, 3 sensitive
📋 WHOIS Lookup: target.com
   ✅ Registrar: Namecheap, Expires in 180 days
🔍 Fingerprinting: https://target.com
   ✅ Found 8 technologies: Nginx, React, Express, Node.js
🐛 CVE Lookup: Express 4.18.0
   ⚠️ Found 3 CVEs (1 CRITICAL)
🔑 Sensitive Files: https://target.com
   ⚠️ Found 2 sensitive files
📋 Metadata Analysis: https://target.com
   ✅ Analyzed 3 files

🌐 Phase 1: Scanning discovered subdomains...
   ✅ 3 accessible subdomains
   ⚡ 1 interesting: admin.target.com (302) - Admin Panel

💥 Phase 2: Exploiting sensitive files...
   ✅ Found 2 credentials, 1 API key

📡 Phase 3: Collecting pages...
   ✅ Collected 8 pages

🔍 Phase 4: Analyzing responses...
   📄 https://target.com: 5 findings

============================================================
✅ Smart Scan Complete!
   🔴 Critical: 2 | 🟠 High: 3
   🟡 Medium: 5 | 🟢 Low: 7
   📊 Total: 17 | ⏱️ Duration: 45.3s

📋 Vulnerability Details:
  🔴 [CRITICAL] GitHub Token Exposed (x1)
     🔍 Found: ghp_abc123...
  🔴 [CRITICAL] AWS Key Exposed (x1)
     🔍 Found: AKIA1234...
  🟠 [HIGH] Known CVEs in Express (x1)
     🔍 3 CVEs (1 critical)

💾 Full extracted data saved to: scan_reports/extracted_target.com_20260521.json
```

---

🧪 Example: Scanning TryHackMe

```bash
python cli.py smart https://tryhackme.com --depth 1 --max-pages 3
```

Real Output

```
🔍 Phase 0: Advanced Reconnaissance (8 steps)...
📡 DNS Enumeration: tryhackme.com
   ✅ Found 5 subdomains (www, mail, api, blog, dev)
📜 CRT.sh Search: tryhackme.com
   ✅ Found 12 subdomains from 8 certificates
🔍 Fingerprinting: https://tryhackme.com
   ✅ Found 8 technologies: Cloudflare, React, Express, Node.js, Google Analytics, Google Fonts, Font Awesome

🔑 Sensitive Files: https://tryhackme.com
   ⚠️ Found 2 sensitive files
     /admin (403) - Admin panel (restricted)
     /.env (404) - Not exposed

📊 Final: 22 findings (0 Critical, 3 High, 8 Medium, 11 Low)
📧 Extracted: 86 email addresses
💾 Full data saved to: scan_reports/extracted_tryhackme.com_20260521.json
```

---

⚙️ Configuration

configs/offensive/default.yaml

```yaml
scanners:
  xss: { enabled: true, rate_limit: 2.0 }
  sqli: { enabled: true, rate_limit: 1.0 }
  idor: { enabled: true, rate_limit: 2.0 }
  rce: { enabled: true, rate_limit: 0.5 }
  ssrf: { enabled: true, rate_limit: 1.0 }
  csrf: { enabled: true, rate_limit: 2.0 }
  auth: { enabled: true, rate_limit: 1.0 }
  graphql: { enabled: true, rate_limit: 1.0 }
  api: { enabled: true, rate_limit: 2.0 }

request_engine:
  max_concurrent: 10
  stealth_mode: true
  user_agent_rotation: true

proxies:
  enabled: false
  rotation: "random"
```

---

🧠 AI Models

Model Type Purpose
DQN Agent Reinforcement Learning Smart payload selection
Vuln Classifier Naive Bayes Automatic vulnerability classification
Vector Store TF-IDF + Cosine Similar vulnerability search
Policy Optimizer Heuristic RL Adaptive scan strategy

---

📚 Documentation

· Architecture Guide
· Reconnaissance Module Guide
· Scanner Development Guide
· API Reference
· Research Guide

---

🤝 Contributing

Development Setup

```bash
git clone https://github.com/akkalighter/HunterMind_Offensive_Research_Platform.git
cd HunterMind_Offensive_Research_Platform
pip install -e .
pytest tests/
```

Code Standards

· Type hints required for all function signatures
· Docstrings for all public APIs
· Tests for all new features
· Follow dependency direction (no circular imports)



📄 License

MIT License - See LICENSE file for details.

---

📊 Project Statistics

Category Count
Total Files 250+
Scanners 12
Recon Tools 8
Networking Tools 7
AI Models 4
Interfaces 4 (CLI, API, Dashboard, Reports)
Schemas 7
Pre-Scan Steps 8
Event Types 13
Test Coverage 60/60 (100%)

---

🙏 Acknowledgments

· OWASP for testing environments
· Playwright team for browser automation
· The security research community

---

📞 Contact

· Email: artistajaafari@gmail.com
· GitHub: akkalighter

---

<div align="center">

🦅 Made for the security research community

Think autonomously. Attack intelligently. Learn continuously.

</div>
