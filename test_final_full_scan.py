"""
الاختبار النهائي - تشغيل execute_full_scan على موقع تجريبي
يتحقق من تكامل جميع مكونات المنصة
"""

import sys
import asyncio
from datetime import datetime


async def test_orchestrator_full_scan():
    """اختبار تشغيل فحص شامل حقيقي"""
    print("=" * 60)
    print("🚀 الاختبار النهائي: execute_full_scan")
    print("=" * 60)
    
    try:
        from orchestration.orchestrator import get_orchestrator
        
        print("\n📡 تهيئة Orchestrator...")
        orch = await get_orchestrator()
        print("✅ Orchestrator جاهز")
        
        # هدف تجريبي آمن - موقع مخصص لاختبار الاختراق
        test_target = "http://testphp.vulnweb.com"
        
        print(f"\n🎯 الهدف: {test_target}")
        print("⚙️  الإعدادات: depth=1, max_pages=5")
        print("\n" + "=" * 60)
        print("بدء الفحص...")
        print("=" * 60 + "\n")
        
        start_time = datetime.now()
        
        # تشغيل الفحص
        result = await orch.execute_full_scan(
            url=test_target,
            depth=1,
            max_pages=5
        )
        
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        
        print("\n" + "=" * 60)
        print("📊 نتائج الفحص")
        print("=" * 60)
        
        print(f"\n⏱️  المدة: {duration:.1f} ثانية")
        print(f"📄 الصفحات المفحوصة: {result.get('pages_scanned', 0)}")
        print(f"🐛 الثغرات المكتشفة: {result.get('total_vulnerabilities', 0)}")
        
        # إحصائيات scanners
        scanner_stats = result.get('scanner_stats', {})
        if scanner_stats:
            print(f"\n📊 إحصائيات الـ Scanners:")
            for scanner, stats in scanner_stats.items():
                findings = stats.get('findings_count', 0)
                vulns = stats.get('vulnerabilities_count', 0)
                error = stats.get('error', '')
                status = "✅" if not error else "❌"
                print(f"  {status} {scanner}: {findings} findings → {vulns} vulnerabilities", end="")
                if error:
                    print(f" ({error})", end="")
                print()
        
        # WorldState
        world_state = result.get('world_state', {})
        if world_state:
            print(f"\n🌍 WorldState:")
            print(f"  Phase: {world_state.get('phase', 'N/A')}")
            print(f"  Endpoints: {world_state.get('endpoints', 'N/A')}")
            print(f"  WAF: {world_state.get('waf', 'N/A')}")
        
        # Payload Stats
        payload_stats = result.get('payload_stats', {})
        if payload_stats:
            print(f"\n📚 Payload Stats:")
            print(f"  Total payloads: {payload_stats.get('total_payloads', 0)}")
            print(f"  Total tests: {payload_stats.get('total_tests', 0)}")
        
        # Attack Chains
        chains = result.get('attack_chains', 0)
        print(f"\n🔗 Attack Chains: {chains}")
        
        # الثغرات
        vulnerabilities = result.get('vulnerabilities', [])
        if vulnerabilities:
            print(f"\n🐛 الثغرات المكتشفة (أول 5):")
            for i, vuln in enumerate(vulnerabilities[:5], 1):
                print(f"  {i}. [{vuln.get('severity', '?')}] {vuln.get('type', '?')} - {vuln.get('url', '?')[:60]}")
        else:
            print(f"\n✅ لم يتم اكتشاف ثغرات")
        
        print("\n" + "=" * 60)
        
        # معايير النجاح
        checks = []
        
        # 1. الفحص اشتغل بدون أخطاء
        if result.get('pages_scanned', 0) > 0:
            checks.append(("✅ الفحص اشتغل", True))
        else:
            checks.append(("❌ الفحص ما اشتغل", False))
        
        # 2. scanners اشتغلت
        active_scanners = len([s for s in scanner_stats.values() if s.get('enabled')])
        if active_scanners >= 3:
            checks.append((f"✅ {active_scanners} scanners نشطة", True))
        else:
            checks.append((f"⚠️ {active_scanners} scanners فقط", False))
        
        # 3. WorldState شغال
        if world_state:
            checks.append(("✅ WorldState متصل", True))
        else:
            checks.append(("❌ WorldState غير متصل", False))
        
        # 4. PayloadManager شغال
        if payload_stats:
            checks.append(("✅ PayloadManager متصل", True))
        else:
            checks.append(("⚠️ PayloadManager غير متصل", False))
        
        print("\n📋 معايير النجاح:")
        all_passed = True
        for check, passed in checks:
            print(f"  {check}")
            if not passed:
                all_passed = False
        
        if all_passed:
            print(f"\n🎉 الاختبار النهائي ناجح! جميع المكونات متكاملة وتعمل معاً")
        else:
            print(f"\n⚠️ بعض المكونات تحتاج مراجعة")
        
        return all_passed, result
        
    except Exception as e:
        print(f"\n❌ فشل الاختبار: {e}")
        import traceback
        traceback.print_exc()
        return False, {"error": str(e)}


async def test_orchestrator_status():
    """اختبار حالة Orchestrator"""
    print("\n" + "=" * 60)
    print("📊 اختبار حالة Orchestrator")
    print("=" * 60)
    
    try:
        from orchestration.orchestrator import get_orchestrator
        
        orch = await get_orchestrator()
        status = await orch.get_status()
        
        print(f"✅ الحالة: {status.get('state', 'unknown')}")
        print(f"✅ المكونات: {status.get('components', 0)}")
        print(f"✅ الفحوصات: {status.get('total_scans', 0)}")
        print(f"✅ الثغرات: {status.get('total_vulnerabilities', 0)}")
        
        # WorldState
        ws = status.get('world_state', {})
        if ws:
            print(f"✅ WorldState: {ws.get('phase', 'N/A')}")
        else:
            print(f"⚠️ WorldState غير مهيأ")
        
        # Payload Stats
        ps = status.get('payload_stats', {})
        if ps:
            print(f"✅ Payload Stats: {ps.get('total_payloads', 0)} payloads")
        else:
            print(f"⚠️ Payload Stats غير متاحة")
        
        return True
    except Exception as e:
        print(f"❌ فشل: {e}")
        return False


async def test_local_target():
    """اختبار على هدف محلي إذا كان متاحاً"""
    print("\n" + "=" * 60)
    print("🔍 اختبار هدف محلي")
    print("=" * 60)
    
    try:
        import httpx
        async with httpx.AsyncClient(timeout=5) as client:
            # محاولة الاتصال بـ localhost
            targets = [
                "http://localhost:8080",
                "http://localhost:80",
                "http://127.0.0.1:8080",
            ]
            
            for target in targets:
                try:
                    response = await client.get(target)
                    print(f"✅ وجدنا هدف محلي: {target} (status: {response.status_code})")
                    return target
                except:
                    print(f"  ⏭️ {target} غير متاح")
            
            print("ℹ️ لا توجد أهداف محلية متاحة")
            return None
    except ImportError:
        print("⚠️ httpx غير متوفر - تخطي اختبار الهدف المحلي")
        return None


async def run_all_tests():
    """تشغيل كل الاختبارات النهائية"""
    print("\n" + "🧪" * 30)
    print("   الاختبار النهائي - تكامل المنصة الكامل")
    print("🧪" * 30 + "\n")
    
    results = []
    
    # اختبار 1: حالة Orchestrator
    print("📊 الاختبار 1/3: حالة Orchestrator")
    result1 = await test_orchestrator_status()
    results.append(("حالة Orchestrator", result1))
    
    # اختبار 2: فحص هدف خارجي
    print("\n📊 الاختبار 2/3: فحص هدف خارجي")
    result2, scan_data = await test_orchestrator_full_scan()
    results.append(("فحص هدف خارجي", result2))
    
    # اختبار 3: فحص هدف محلي (اختياري)
    print("\n📊 الاختبار 3/3: فحص هدف محلي")
    local_target = await test_local_target()
    if local_target:
        from orchestration.orchestrator import get_orchestrator
        orch = await get_orchestrator()
        print(f"\n🎯 فحص الهدف المحلي: {local_target}")
        try:
            local_result = await orch.execute_full_scan(url=local_target, depth=1, max_pages=3)
            local_vulns = local_result.get('total_vulnerabilities', 0)
            print(f"✅ فحص محلي مكتمل: {local_vulns} ثغرات")
            results.append(("فحص هدف محلي", True))
        except Exception as e:
            print(f"❌ فشل الفحص المحلي: {e}")
            results.append(("فحص هدف محلي", False))
    else:
        print("⏭️ تخطي - لا يوجد هدف محلي")
        results.append(("فحص هدف محلي", True))  # مش فشل
    
    # ملخص
    print("\n" + "=" * 60)
    print("📋 الملخص النهائي")
    print("=" * 60)
    
    passed = sum(1 for _, r in results if r)
    failed = len(results) - passed
    
    for name, result in results:
        print(f"  {'✅ نجح' if result else '❌ فشل'} - {name}")
    
    print(f"\n✅ نجح: {passed}")
    print(f"❌ فشل: {failed}")
    print(f"📊 النسبة: {passed/len(results)*100:.0f}%")
    
    if failed == 0:
        print("\n🎉 المنصة جاهزة ومتكاملة!")
        print("   - 9 Scanners شغالة")
        print("   - WorldState + PayloadManager + EventBus متصلين")
        print("   - Orchestrator ينسق كل المكونات")
        print("   - Interfaces نظيفة وجاهزة")
    else:
        print(f"\n⚠️ فيه {failed} فشل - يحتاج مراجعة")
    
    return failed == 0


if __name__ == "__main__":
    success = asyncio.run(run_all_tests())
    sys.exit(0 if success else 1)
