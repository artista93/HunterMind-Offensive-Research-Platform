#!/usr/bin/env python3
"""
اختبار شامل للنظام - Full Integration Test
"""

import sys
import asyncio
sys.path.insert(0, '/workspaces/HunterMind_Offensive_Research_Platform')

async def test_full_integration():
    print("\n🔗 Running Full Integration Test...")
    
    results = {}
    
    # 1. اختبار التبعيات
    print("\n  📦 Checking dependencies...")
    import importlib
    deps = ["aiohttp", "httpx", "fastapi", "uvicorn", "pydantic", "yaml", "playwright", "bs4", "numpy", "psutil"]
    deps_ok = 0
    for dep in deps:
        try:
            importlib.import_module(dep)
            deps_ok += 1
        except ImportError:
            pass
    results["dependencies"] = deps_ok == len(deps)
    print(f"    Dependencies: {deps_ok}/{len(deps)} installed")
    
    # 2. اختبار الملفات الأساسية
    print("\n  📁 Checking core files...")
    import os
    files = ["config.yaml", "cli.py", "main.py", "requirements.txt"]
    files_ok = 0
    for f in files:
        if os.path.exists(f):
            files_ok += 1
    results["core_files"] = files_ok == len(files)
    print(f"    Core files: {files_ok}/{len(files)} present")
    
    # 3. اختبار المجلدات
    print("\n  📂 Checking directories...")
    dirs = ["offensive/scanners", "agents/base", "cognition/brain", "interfaces/api", "storage/sqlite"]
    dirs_ok = 0
    for d in dirs:
        if os.path.exists(d):
            dirs_ok += 1
    results["directories"] = dirs_ok == len(dirs)
    print(f"    Directories: {dirs_ok}/{len(dirs)} present")
    
    # 4. اختبار الاستيرادات
    print("\n  📚 Testing imports...")
    imports = [
        "offensive.scanners.xss_scanner",
        "offensive.scanners.sqli_scanner",
        "agents.base.base_agent",
        "cognition.brain.cognitive_core",
        "orchestration.orchestrator"
    ]
    imports_ok = 0
    for imp in imports:
        try:
            __import__(imp)
            imports_ok += 1
        except Exception as e:
            print(f"    ❌ Failed to import {imp}: {e}")
    results["imports"] = imports_ok == len(imports)
    print(f"    Imports: {imports_ok}/{len(imports)} successful")
    
    # النتيجة النهائية
    all_passed = all(results.values())
    
    print("\n" + "=" * 50)
    print("INTEGRATION TEST RESULTS")
    print("=" * 50)
    for test, passed in results.items():
        print(f"  {test}: {'✅ PASSED' if passed else '❌ FAILED'}")
    
    return all_passed

async def main():
    print("=" * 50)
    print("🔬 TEST 10: Full Integration")
    print("=" * 50)
    
    result = await test_full_integration()
    
    print("\n" + "=" * 50)
    print(f"FINAL RESULT: {'✅ ALL TESTS PASSED' if result else '❌ SOME TESTS FAILED'}")
    print("=" * 50)

if __name__ == "__main__":
    asyncio.run(main())
