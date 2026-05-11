#!/usr/bin/env python3
"""
اختبار الفاحصات - Scanner Functionality Test
"""

import sys
import asyncio
sys.path.insert(0, '/workspaces/HunterMind_Offensive_Research_Platform')

async def test_xss_scanner():
    print("\n📡 Testing XSS Scanner...")
    try:
        from offensive.scanners.xss_scanner import XSSScanner
        from offensive.scanners.base_scanner import ScanContext, ScanTarget
        
        scanner = XSSScanner()
        context = ScanContext(
            target=ScanTarget(
                url="https://juice-shop.herokuapp.com/#/search",
                params={"q": "test"}
            )
        )
        
        can = await scanner.can_scan(context)
        print(f"  XSS Scanner can_scan: {can}")
        
        payload_count = len(scanner.BASE_PAYLOADS)
        print(f"  XSS Payloads loaded: {payload_count}")
        
        if payload_count > 0:
            print(f"  Example payload: {scanner.BASE_PAYLOADS[0].payload[:80]}...")
        
        return True
    except Exception as e:
        print(f"  ❌ XSS Scanner error: {e}")
        return False

async def test_sqli_scanner():
    print("\n💉 Testing SQLi Scanner...")
    try:
        from offensive.scanners.sqli_scanner import SQLiScanner
        
        scanner = SQLiScanner()
        payload_count = len(scanner.BASE_PAYLOADS)
        print(f"  SQLi Payloads loaded: {payload_count}")
        
        if payload_count > 0:
            print(f"  Example payload: {scanner.BASE_PAYLOADS[0].payload[:80]}...")
        
        return True
    except Exception as e:
        print(f"  ❌ SQLi Scanner error: {e}")
        return False

async def test_idor_scanner():
    print("\n🔐 Testing IDOR Scanner...")
    try:
        from offensive.scanners.idor_scanner import IDORScanner
        
        scanner = IDORScanner()
        print(f"  IDOR Scanner initialized")
        print(f"  Common endpoints: {len(scanner.COMMON_ENDPOINTS)}")
        
        return True
    except Exception as e:
        print(f"  ❌ IDOR Scanner error: {e}")
        return False

async def main():
    print("=" * 50)
    print("🔬 TEST 1: Scanners Functionality")
    print("=" * 50)
    
    results = []
    results.append(await test_xss_scanner())
    results.append(await test_sqli_scanner())
    results.append(await test_idor_scanner())
    
    print("\n" + "=" * 50)
    print(f"RESULTS: {sum(results)}/{len(results)} passed")
    print("=" * 50)

if __name__ == "__main__":
    asyncio.run(main())
