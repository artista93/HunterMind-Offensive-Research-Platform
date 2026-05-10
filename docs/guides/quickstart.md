
🚀 Quick Start Guide

Prerequisites

· Python 3.9+
· Node.js (for Playwright)
· 8GB RAM (16GB recommended)
· Docker (optional, for sandbox)

Installation

```bash
# Clone repository
git clone https://github.com/your-repo/HunterMind.git
cd HunterMind

# Install dependencies
pip install -r requirements.txt

# Install Playwright browsers
playwright install chromium

# Copy configuration
cp config.example.yaml config.yaml
```

Basic Usage

CLI Mode

```bash
# Full security scan
python cli.py scan https://example.com

# Quick scan
python cli.py scan https://example.com --quick --max-pages 20

# List scans
python cli.py list scans

# Show statistics
python cli.py stats
```

API Mode

```bash
# Start API server
python interfaces/api/fastapi_server.py

# In another terminal
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{"target_url": "https://example.com"}'
```

Dashboard Mode

```bash
# Start dashboard
python interfaces/dashboard/dashboard_server.py

# Open browser to http://localhost:5000
```

Example: Scanning OWASP Juice Shop

```bash
python cli.py scan https://juice-shop.herokuapp.com --max-pages 50
```

Expected output:

```
🦅 HunterMind Platform - Scan Started
============================================================

📡 Phase 1: Reconnaissance
   ✅ Target: juice-shop.herokuapp.com
   ✅ Technologies: Angular, Express, SQLite

🕷️ Phase 2: Crawling
   ✅ Pages crawled: 45

🔍 Phase 3: Vulnerability Scanning
   🐛 XSS found! Parameter: search | Severity: HIGH
   🐛 IDOR found! Parameter: id | Severity: MEDIUM

📊 FINAL REPORT
============================================================
Vulnerabilities Found: 3
Total Time: 124.5 seconds
```

Next Steps

· Read Architecture Overview
· Explore Agent Documentation
· Check API Reference
  EOF

5. دليل المساهمة

cat > docs/guides/contributing.md << 'EOF'

🤝 Contributing Guide

Development Setup

```bash
# Clone and install in development mode
git clone https://github.com/your-repo/HunterMind.git
cd HunterMind
pip install -e .

# Run tests
pytest tests/

# Run linter
ruff check .

# Format code
black .
```

Code Standards

· Type hints: Required for all function signatures
· Docstrings: Required for all public APIs
· Tests: Required for all new features
· Async: Use async/await for I/O operations
· Error handling: Use try/except with specific exceptions

Project Structure

```
HunterMind/
├── agents/          # Autonomous agents
├── cognition/       # Cognitive system
├── offensive/       # Attack modules
├── infrastructure/  # Core infrastructure
├── storage/         # Data storage
├── interfaces/      # API, CLI, Dashboard
└── telemetry/       # Monitoring
```

Adding a New Scanner

1. Create scanner in offensive/scanners/
2. Inherit from BaseScanner
3. Implement scan() method
4. Add tests in tests/offensive/
5. Update documentation

Example:

```python
from offensive.scanners.base_scanner import BaseScanner

class MyScanner(BaseScanner):
    async def scan(self, context):
        # Implementation
        return findings
```

Pull Request Process

1. Create feature branch from main
2. Implement changes with tests
3. Run full test suite
4. Submit PR with detailed description
5. Wait for review and CI checks

Reporting Issues

· Use GitHub Issues
· Include version, OS, and steps to reproduce
· Attach logs if applicable

Code of Conduct

· Be respectful and professional
· Provide constructive feedback
· Help others learn
  EOF

6. ملف README الرئيسي للـ docs

cat > docs/README.md << 'EOF'

📖 Documentation

Welcome to the HunterMind documentation!

Contents

Architecture

· System Architecture
· Component Design
· Data Flow

Agents

· Agent Overview
· Base Agent Interface
· Creating Custom Agents

Cognition

· Cognitive Core
· Memory Systems
· Reasoning Engine

Offensive

· Scanners
· Payloads
· Exploitation

API Reference

· REST API
· WebSocket API
· gRPC API

Research

· Experimentation
· Benchmarking
· Pattern Discovery

Guides

· Quick Start
· Contributing
· Troubleshooting

External Links

· GitHub Repository
· Issue Tracker
· Discord Community

License

MIT License - See LICENSE file for details.
