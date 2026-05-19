"""اختبار المرحلة 4: WorldState Integration"""
import sys
import asyncio

def test_world_state_manager_import():
    print("=" * 50)
    print("🌍 اختبار 1: WorldStateManager استيراد")
    print("=" * 50)
    try:
        from orchestration.world_state_manager import WorldStateManager, get_world_state_manager
        mgr = get_world_state_manager()
        assert mgr is not None
        print("✅ WorldStateManager imported")
        print("✅ get_world_state_manager() works")
        return True
    except Exception as e:
        print(f"❌ FAILED: {e}")
        return False

def test_world_state_initialize():
    print("\n" + "=" * 50)
    print("🔧 اختبار 2: تهيئة WorldState")
    print("=" * 50)
    try:
        from orchestration.world_state_manager import get_world_state_manager
        from schemas.world_state import ScanPhase
        
        mgr = get_world_state_manager()
        
        async def test():
            state = await mgr.initialize("http://test.com")
            assert state is not None
            assert state.target_url == "http://test.com"
            print(f"✅ Initialized: {state.target_url}")
            print(f"✅ Phase: {state.phase.value}")
            
            await mgr.transition_phase(ScanPhase.RECONNAISSANCE)
            print(f"✅ Phase after transition: {mgr.state.phase.value}")
            
            history = await mgr.get_phase_history()
            print(f"✅ Phase history: {len(history)} entries")
            for h in history:
                print(f"   - {h['phase']}")
            
            return True
        
        return asyncio.run(test())
    except Exception as e:
        print(f"❌ FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_world_state_endpoints():
    print("\n" + "=" * 50)
    print("📍 اختبار 3: إدارة الـ Endpoints")
    print("=" * 50)
    try:
        from orchestration.world_state_manager import get_world_state_manager
        
        # إنشاء WorldStateManager جديد مش global
        from orchestration.world_state_manager import WorldStateManager
        mgr = WorldStateManager()
        
        async def test():
            await mgr.initialize("http://test.com")
            
            # initialize بتضيف target URL تلقائياً
            initial_count = len(mgr.state.discovered_endpoints)
            print(f"✅ Initial endpoints (after initialize): {initial_count}")
            
            # إضافة endpoints جديدة
            ep1 = await mgr.add_endpoint("http://test.com/page1", "GET", ["id", "q"], 150.0, 200)
            ep2 = await mgr.add_endpoint("http://test.com/api/users", "POST", ["username"], 200.0, 201)
            
            count_after_add = len(mgr.state.discovered_endpoints)
            print(f"✅ Endpoints after adding 2 new: {count_after_add}")
            assert count_after_add == initial_count + 2, f"Expected {initial_count + 2}, got {count_after_add}"
            
            # إضافة endpoint مكرر - المفروض يزيد visit_count فقط
            ep3 = await mgr.add_endpoint("http://test.com/page1", "GET", ["id", "q", "page"], 120.0, 200)
            
            count_after_duplicate = len(mgr.state.discovered_endpoints)
            print(f"✅ Endpoints after duplicate: {count_after_duplicate}")
            assert count_after_duplicate == initial_count + 2, f"Expected {initial_count + 2}, got {count_after_duplicate}"
            
            print(f"✅ page1 visit_count: {ep3.visit_count}")
            print(f"✅ page1 parameters: {ep3.parameters}")
            assert ep3.visit_count >= 2
            
            stats = await mgr.get_statistics()
            print(f"✅ Endpoints discovered: {stats['endpoints_discovered']}")
            
            return True
        
        return asyncio.run(test())
    except Exception as e:
        print(f"❌ FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_world_state_waf():
    print("\n" + "=" * 50)
    print("🛡️  اختبار 4: كشف WAF")
    print("=" * 50)
    try:
        from orchestration.world_state_manager import WorldStateManager
        from schemas.world_state import WAFType
        
        async def test():
            # Cloudflare
            mgr1 = WorldStateManager()
            await mgr1.initialize("http://test1.com")
            headers = {"Server": "cloudflare", "CF-RAY": "xxx"}
            waf = await mgr1.detect_waf(headers)
            print(f"✅ Cloudflare detected: {waf}")
            assert waf == WAFType.CLOUDFLARE
            
            # AWS
            mgr2 = WorldStateManager()
            await mgr2.initialize("http://test2.com")
            headers2 = {"X-Amzn-RequestId": "12345"}
            waf2 = await mgr2.detect_waf(headers2)
            print(f"✅ AWS WAF detected: {waf2}")
            assert waf2 == WAFType.AWS_WAF
            
            # No WAF
            mgr3 = WorldStateManager()
            await mgr3.initialize("http://test3.com")
            headers3 = {"Server": "nginx"}
            waf3 = await mgr3.detect_waf(headers3)
            print(f"✅ No WAF: {waf3}")
            assert waf3 is None
            
            return True
        
        return asyncio.run(test())
    except Exception as e:
        print(f"❌ FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_world_state_vulnerabilities():
    print("\n" + "=" * 50)
    print("🐛 اختبار 5: إضافة ثغرات")
    print("=" * 50)
    try:
        from orchestration.world_state_manager import WorldStateManager
        from schemas.vulnerability import (
            Vulnerability, VulnerabilityType, Severity, generate_vulnerability_id
        )
        
        async def test():
            mgr = WorldStateManager()
            await mgr.initialize("http://test.com")
            
            # إنشاء ثغرة
            vuln = Vulnerability(
                id=generate_vulnerability_id(),
                type=VulnerabilityType.XSS_REFLECTED,
                title="Test XSS",
                description="Test vulnerability",
                url="http://test.com/page?id=1",
                parameter="id",
                payload="<script>alert(1)</script>",
                severity=Severity.HIGH,
                cvss_score=7.5,
                confidence=0.8
            )
            
            await mgr.add_vulnerability(vuln)
            
            stats = await mgr.get_statistics()
            print(f"✅ Vulnerabilities found: {stats['vulnerabilities_found']}")
            assert stats['vulnerabilities_found'] == 1
            
            # إضافة ثغرة تانية
            vuln2 = Vulnerability(
                id=generate_vulnerability_id(),
                type=VulnerabilityType.SQLI_BOOLEAN,
                title="Test SQLi",
                description="SQL injection test",
                url="http://test.com/login",
                parameter="username",
                payload="' OR 1=1--",
                severity=Severity.CRITICAL,
                cvss_score=9.8,
                confidence=1.0
            )
            await mgr.add_vulnerability(vuln2)
            
            stats = await mgr.get_statistics()
            print(f"✅ Vulnerabilities after second add: {stats['vulnerabilities_found']}")
            assert stats['vulnerabilities_found'] == 2
            
            summary = await mgr.get_summary()
            print(f"✅ Summary: {summary['vulnerabilities']} vulnerabilities, phase={summary['phase']}")
            
            return True
        
        return asyncio.run(test())
    except Exception as e:
        print(f"❌ FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_scanner_world_state():
    print("\n" + "=" * 50)
    print("🤖 اختبار 6: Scanner + WorldState")
    print("=" * 50)
    try:
        from offensive.scanners.base_scanner import BaseScanner, ScanContext, ScanTarget, Finding, Severity, Confidence
        
        class TestScanner(BaseScanner):
            async def scan(self, context):
                return []
            async def can_scan(self, context):
                return True
        
        scanner = TestScanner("test_scanner")
        
        # بدون WorldState
        assert not scanner.has_world_state()
        print("✅ Scanner without WorldState: OK")
        print(f"   has_world_state: {scanner.has_world_state()}")
        
        # مع WorldStateManager
        from orchestration.world_state_manager import WorldStateManager
        
        async def test():
            mgr = WorldStateManager()
            await mgr.initialize("http://test.com")
            scanner.set_world_state_manager(mgr)
            
            assert scanner.has_world_state()
            print(f"✅ Scanner with WorldState: OK")
            print(f"   has_world_state: {scanner.has_world_state()}")
            print(f"   world_state phase: {scanner.get_world_state().phase.value}")
            
            stats = scanner.get_statistics()
            print(f"✅ Scanner stats: world_state_connected={stats['world_state_connected']}")
            
            return True
        
        return asyncio.run(test())
    except Exception as e:
        print(f"❌ FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False

def run_all_tests():
    print("\n" + "🧪" * 30)
    print("   بدء اختبارات المرحلة 4: WorldState Integration")
    print("🧪" * 30 + "\n")
    
    tests = [
        ("WorldStateManager استيراد", test_world_state_manager_import),
        ("تهيئة WorldState", test_world_state_initialize),
        ("إدارة الـ Endpoints", test_world_state_endpoints),
        ("كشف WAF", test_world_state_waf),
        ("إضافة ثغرات", test_world_state_vulnerabilities),
        ("Scanner + WorldState", test_scanner_world_state),
    ]
    
    results = []
    for name, test_fn in tests:
        try:
            result = test_fn()
            results.append((name, result))
        except Exception as e:
            print(f"\n❌ CRASHED: {name} - {e}")
            import traceback
            traceback.print_exc()
            results.append((name, False))
    
    print("\n" + "=" * 60)
    print("📋 ملخص النتائج - المرحلة 4")
    print("=" * 60)
    
    passed = sum(1 for _, r in results if r)
    failed = len(results) - passed
    
    for name, result in results:
        print(f"  {'✅ نجح' if result else '❌ فشل'} - {name}")
    
    print(f"\n✅ نجح: {passed}")
    print(f"❌ فشل: {failed}")
    print(f"📊 النسبة: {passed/len(results)*100:.0f}%")
    
    if failed == 0:
        print("\n🎉 المرحلة 4 مكتملة! WorldState Integration جاهزة")
    else:
        print(f"\n⚠️  فيه {failed} اختبار فشل - يحتاج تصحيح")
    
    return failed == 0

if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
