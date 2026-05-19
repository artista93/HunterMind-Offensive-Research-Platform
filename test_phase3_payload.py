"""
اختبار المرحلة 3: PayloadLibrary Integration + Evolution
"""

import sys

def test_payload_manager_import():
    """اختبار استيراد PayloadManager"""
    print("=" * 50)
    print("📚 اختبار 1: PayloadManager استيراد")
    print("=" * 50)
    
    try:
        from offensive.scanners.payload_integration import (
            PayloadManager, PayloadTestResult, 
            PayloadEvolutionStrategy, get_payload_manager
        )
        
        mgr = get_payload_manager()
        assert mgr is not None
        
        print(f"✅ PayloadManager initialized")
        print(f"✅ Libraries: {len(mgr.libraries)} types")
        for pt, lib in mgr.libraries.items():
            print(f"   - {pt.value}: {len(lib.payloads)} payloads")
        
        return True
    except Exception as e:
        print(f"❌ FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_get_payloads_for_scanner():
    """اختبار الحصول على حمولات لكل scanner"""
    print("\n" + "=" * 50)
    print("🔍 اختبار 2: get_payloads_for_scanner")
    print("=" * 50)
    
    try:
        from offensive.scanners.payload_integration import get_payload_manager
        
        mgr = get_payload_manager()
        
        scanners = ["xss", "sqli", "idor", "ssrf", "rce"]
        for s in scanners:
            payloads = mgr.get_payloads_for_scanner(s)
            print(f"  ✅ {s}: {len(payloads)} payloads")
        
        return True
    except Exception as e:
        print(f"❌ FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_record_test_result():
    """اختبار تسجيل نتائج الاختبارات"""
    print("\n" + "=" * 50)
    print("📝 اختبار 3: record_test_result")
    print("=" * 50)
    
    try:
        from offensive.scanners.payload_integration import (
            get_payload_manager, PayloadTestResult
        )
        from schemas.payload import PayloadType, Payload
        
        mgr = get_payload_manager()
        
        # إنشاء حمولة وهمية
        import uuid
        test_payload = Payload(
            id=f"PLS-{uuid.uuid4().hex[:8].upper()}",
            content="<script>alert('XSS')</script>",
            payload_type=PayloadType.XSS,
            context=None
        )
        
        # تسجيل نتيجة ناجحة
        result1 = PayloadTestResult(
            payload=test_payload,
            target_url="http://test.com",
            target_parameter="q",
            success=True,
            response_time_ms=150.0,
            status_code=200,
            evidence="XSS reflected"
        )
        mgr.record_test_result(result1)
        
        # تسجيل نتيجة فاشلة
        result2 = PayloadTestResult(
            payload=test_payload,
            target_url="http://test.com",
            target_parameter="q",
            success=False,
            waf_detected=True,
            waf_type="Cloudflare",
            response_time_ms=250.0,
            status_code=403
        )
        mgr.record_test_result(result2)
        
        stats = mgr.get_statistics()
        print(f"✅ Total tests: {stats['total_tests']}")
        print(f"✅ Scanner stats: {stats['scanner_stats']}")
        
        return True
    except Exception as e:
        print(f"❌ FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_payload_evolution():
    """اختبار تطوير الحمولات"""
    print("\n" + "=" * 50)
    print("🧬 اختبار 4: Payload Evolution")
    print("=" * 50)
    
    try:
        from offensive.scanners.payload_integration import (
            get_payload_manager, PayloadEvolutionStrategy
        )
        
        mgr = get_payload_manager()
        
        # تطوير حمولات XSS
        evolved = mgr.evolve_payloads("xss", PayloadEvolutionStrategy.CASE_SWAPPING)
        print(f"✅ CASE_SWAPPING: {len(evolved)} variations")
        
        evolved = mgr.evolve_payloads("xss", PayloadEvolutionStrategy.URL_ENCODING)
        print(f"✅ URL_ENCODING: {len(evolved)} variations")
        
        evolved = mgr.evolve_payloads("sqli", PayloadEvolutionStrategy.COMMENT_INJECTION)
        print(f"✅ COMMENT_INJECTION: {len(evolved)} variations")
        
        # auto-evolve
        count = mgr.auto_evolve_low_performers()
        print(f"✅ Auto-evolve: {count} payloads evolved")
        
        return True
    except Exception as e:
        print(f"❌ FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_best_payloads():
    """اختبار الحصول على أفضل الحمولات"""
    print("\n" + "=" * 50)
    print("🏆 اختبار 5: get_best_payloads")
    print("=" * 50)
    
    try:
        from offensive.scanners.payload_integration import get_payload_manager
        
        mgr = get_payload_manager()
        
        for scanner in ["xss", "sqli"]:
            best = mgr.get_best_payloads(scanner, limit=3)
            print(f"✅ {scanner}: top {len(best)} payloads")
            for p in best:
                print(f"   - {p.name}: success_rate={p.success_rate:.2f}")
        
        return True
    except Exception as e:
        print(f"❌ FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_orchestrator_payload_methods():
    """اختبار دوال Payload Manager في الـ Orchestrator"""
    print("\n" + "=" * 50)
    print("🎛️  اختبار 6: Orchestrator Payload Methods")
    print("=" * 50)
    
    try:
        from orchestration.orchestrator import Orchestrator
        
        orch = Orchestrator()
        
        assert hasattr(orch, '_ensure_payload_manager'), "Missing _ensure_payload_manager"
        assert hasattr(orch, 'get_payload_statistics'), "Missing get_payload_statistics"
        assert hasattr(orch, 'get_best_payloads'), "Missing get_best_payloads"
        assert hasattr(orch, 'evolve_payloads'), "Missing evolve_payloads"
        assert hasattr(orch, 'get_payloads_needing_evolution'), "Missing get_payloads_needing_evolution"
        
        print("✅ All Payload Manager methods present in Orchestrator")
        
        return True
    except Exception as e:
        print(f"❌ FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False


def run_all_tests():
    print("\n" + "🧪" * 30)
    print("   بدء اختبارات المرحلة 3: PayloadLibrary Integration")
    print("🧪" * 30 + "\n")
    
    tests = [
        ("PayloadManager استيراد", test_payload_manager_import),
        ("get_payloads_for_scanner", test_get_payloads_for_scanner),
        ("record_test_result", test_record_test_result),
        ("Payload Evolution", test_payload_evolution),
        ("get_best_payloads", test_best_payloads),
        ("Orchestrator Payload Methods", test_orchestrator_payload_methods),
    ]
    
    results = []
    for name, test_fn in tests:
        try:
            result = test_fn()
            results.append((name, result))
        except Exception as e:
            print(f"\n❌ TEST CRASHED: {name} - {e}")
            results.append((name, False))
    
    print("\n" + "=" * 60)
    print("📋 ملخص النتائج - المرحلة 3")
    print("=" * 60)
    
    passed = sum(1 for _, r in results if r)
    failed = len(results) - passed
    
    for name, result in results:
        print(f"  {'✅ نجح' if result else '❌ فشل'} - {name}")
    
    print(f"\n✅ نجح: {passed}")
    print(f"❌ فشل: {failed}")
    print(f"📊 النسبة: {passed/len(results)*100:.0f}%")
    
    if failed == 0:
        print("\n🎉 المرحلة 3 مكتملة! PayloadLibrary Integration جاهزة")
    
    return failed == 0


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
