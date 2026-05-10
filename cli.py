#!/usr/bin/env python3
"""
HunterMind CLI - واجهة سطر الأوامر للمنصة
"""

import sys
import asyncio
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from interfaces.cli.cli_runner import main as cli_main

if __name__ == "__main__":
    try:
        asyncio.run(cli_main())
    except KeyboardInterrupt:
        print("\n👋 Goodbye!")
        sys.exit(0)
