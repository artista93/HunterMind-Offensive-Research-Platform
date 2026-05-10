#!/bin/bash
# ============================================
# Benchmark Script - اختبار أداء النظام
# ============================================

set -e

echo "📊 HunterMind - Performance Benchmark"
echo "====================================="

# تفعيل البيئة الافتراضية
source venv/bin/activate

# تثبيت أدوات القياس
pip install pytest-benchmark

echo ""
echo "🏃 Running benchmarks..."

# اختبار أداء الفاحصات
python -c "
import time
import asyncio
from offensive.scanners.xss_scanner import XSSScanner
from offensive.scanners.sqli_scanner import SQLiScanner
from offensive.scanners.idor_scanner import IDORScanner

async def benchmark_scanner(name, scanner, target):
    start = time.time()
    await scanner.scan(target)
    elapsed = time.time() - start
    print(f'  {name}: {elapsed:.2f}s')
    return elapsed

async def main():
    print('\n📡 Scanner Performance:')
    xss_scanner = XSSScanner()
    sqli_scanner = SQLiScanner()
    idor_scanner = IDORScanner()
    
    target = {'url': 'https://juice-shop.herokuapp.com'}
    
    await benchmark_scanner('XSS Scanner', xss_scanner, target)
    await benchmark_scanner('SQLi Scanner', sqli_scanner, target)
    await benchmark_scanner('IDOR Scanner', idor_scanner, target)
    
    await xss_scanner.close()
    await sqli_scanner.close()
    await idor_scanner.close()

asyncio.run(main())
"

echo ""
echo "✅ Benchmark completed!"
