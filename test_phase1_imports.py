"""
اختبار الاستيرادات - المرحلة 1 و 2
يتأكد إن كل الملفات الجديدة والمعدلة تشتغل بدون أخطاء
"""

import sys
import asyncio

def test_event_bus_import():
    """اختبار استيراد EventBus والـ EventType الجديد"""
    print("=" * 50)
    print("📡 اختبار 1: EventBus + EventType")
    print("=" * 50)
    
    try:
        from orchestration.messaging.event_bus import EventBus, Event, EventType
        
        # التحقق من وجود الأنواع الجديدة
        assert hasattr(EventType, 'DATA_VULNERABILITY'), "❌ DATA_VULNERABILITY missing"
        assert hasattr(EventType, 'SCAN_STARTED'), "❌ SCAN_STARTED missing"
        assert hasattr(EventType, 'SCAN_COMPLETED'), "❌ SCAN_COMPLETED missing"
        assert hasattr(EventType, 'SCAN_PAGE_COMPLETE'), "❌ SCAN_PAGE_COMPLETE missing"
        assert hasattr(EventType, 'VULNERABILITY_FOUND'), "❌ VULNERABILITY_FOUND missing"
        
        print("✅ EventType.DATA_VULNERABILITY =", EventType.DATA_VULNERABILITY.value)
        print("✅ EventType.SCAN_STARTED =", EventType.SCAN_STARTED.value)
        print("✅ EventType.SCAN_COMPLETED =", EventType.SCAN_COMPLETED.value)
        print("✅ EventType.SCAN_PAGE_COMPLETE =", EventType.SCAN_PAGE_COMPLETE.value)
        print("✅ EventType.VULNERABILITY_FOUND =", EventType.VULNERABILITY_FOUND.value)
        
        # التحقق من إنشاء Event
        event = Event(type=EventType.VULNERABILITY_FOUND, source="test", data={"msg": "test"})
        assert event.type == EventType.VULNERABILITY_FOUND
        assert event.source == "test"
        print("✅ Event creation works")
        
        return True
    except Exception as e:
        print(f"❌ FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_config_import():
    """اختبار استيراد الإعدادات الجديدة"""
    print("\n" + "=" * 50)
    print("⚙️  اختبار 2: Configs + Scanners الإعدادات")
    print("=" * 50)
    
    try:
        from configs.offensive import (
            SCANNERS_CONFIG, XSS_SCANNER_CONFIG, SQLI_SCANNER_CONFIG,
            IDOR_SCANNER_CONFIG, OFFENSIVE_CONFIG
        )
        
        # التحقق من وجود الـ scanners الجديدة
        required = ["xss", "sqli", "idor", "rce", "ssrf", "csrf", "auth", "graphql", "api"]
        
        for scanner_name in required:
            if scanner_name in SCANNERS_CONFIG:
                config = SCANNERS_CONFIG[scanner_name]
                enabled = config.get("enabled", False)
                print(f"  ✅ {scanner_name}: enabled={enabled}, rate_limit={config.get('rate_limit', 'N/A')}")
            else:
                print(f"  ❌ {scanner_name}: MISSING from SCANNERS_CONFIG")
                return False
        
        print(f"\n✅ All {len(required)} scanners configured")
        return True
        
    except Exception as e:
        print(f"❌ FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_adapter_import():
    """اختبار استيراد الـ Adapters"""
    print("\n" + "=" * 50)
    print("🔌 اختبار 3: ScannerAdapter + PayloadAdapter + ConfigLoader")
    print("=" * 50)
    
    try:
        from offensive.scanners.base_scanner import Severity, Confidence, ScannerSeverity, ScannerConfidence
        from offensive.scanners.adapters import (
            ScannerAdapter, PayloadAdapter, ConfigLoader,
            quick_convert, batch_convert
        )
        
        # التحقق من وجود aliases
        assert ScannerSeverity == Severity, "ScannerSeverity alias mismatch"
        assert ScannerConfidence == Confidence, "ScannerConfidence alias mismatch"
        print("✅ ScannerSeverity alias: OK")
        print("✅ ScannerConfidence alias: OK")
        
        # التحقق من وجود الخرائط
        assert ScannerAdapter.SEVERITY_MAP, "SEVERITY_MAP empty"
        assert ScannerAdapter.CONFIDENCE_MAP, "CONFIDENCE_MAP empty"
        assert ScannerAdapter.VULNERABILITY_TYPE_MAP, "VULNERABILITY_TYPE_MAP empty"
        
        print(f"✅ SEVERITY_MAP: {len(ScannerAdapter.SEVERITY_MAP)} mappings")
        print(f"✅ CONFIDENCE_MAP: {len(ScannerAdapter.CONFIDENCE_MAP)} mappings")
        print(f"✅ VULNERABILITY_TYPE_MAP: {len(ScannerAdapter.VULNERABILITY_TYPE_MAP)} mappings")
        
        # اختبار ConfigLoader
        is_enabled = ConfigLoader.is_scanner_enabled("xss")
        print(f"✅ ConfigLoader.is_scanner_enabled('xss'): {is_enabled}")
        
        enabled_list = ConfigLoader.get_enabled_scanners()
        print(f"✅ ConfigLoader.get_enabled_scanners(): {len(enabled_list)} scanners: {enabled_list}")
        
        return True
        
    except Exception as e:
        print(f"❌ FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_scanner_adapters_integration():
    """اختبار تحويل Finding → Vulnerability"""
    print("\n" + "=" * 50)
    print("🔄 اختبار 4: Finding → Vulnerability تحويل")
    print("=" * 50)
    
    try:
        from offensive.scanners.base_scanner import Finding, Severity, Confidence
        from offensive.scanners.adapters import ScannerAdapter, quick_convert
        from schemas.vulnerability import Vulnerability, VulnerabilityType
        
        # إنشاء Finding وهمي
        finding = Finding(
            vulnerability_type="SQL Injection (Boolean-based Blind)",
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            url="http://test.com/page?id=1",
            parameter="id",
            payload="' AND 1=1--",
            evidence="SQL syntax error detected",
            description="Boolean-based blind SQL injection",
            remediation="Use parameterized queries",
            cvss_score=9.8
        )
        
        # تحويل
        vuln = quick_convert(finding, "sqli_scanner")
        
        # التحقق
        assert isinstance(vuln, Vulnerability), f"Expected Vulnerability, got {type(vuln)}"
        assert vuln.type == VulnerabilityType.SQLI_BOOLEAN, f"Expected SQLI_BOOLEAN, got {vuln.type}"
        assert vuln.url == "http://test.com/page?id=1"
        assert vuln.parameter == "id"
        assert vuln.payload == "' AND 1=1--"
        assert vuln.discovered_by == "sqli_scanner"
        assert vuln.id.startswith("VULN-"), f"Expected VULN- prefix, got {vuln.id}"
        
        print(f"✅ Finding → Vulnerability: OK")
        print(f"   ID: {vuln.id}")
        print(f"   Type: {vuln.type.value}")
        print(f"   URL: {vuln.url}")
        print(f"   Severity: {vuln.severity.name}")
        print(f"   Confidence: {vuln.confidence}")
        
        # اختبار batch_convert
        findings = [finding, finding]
        vulns = ScannerAdapter.batch_convert(findings, "test_scanner")
        assert len(vulns) == 2
        print(f"✅ Batch convert: {len(vulns)} vulnerabilities")
        
        return True
        
    except Exception as e:
        print(f"❌ FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_orchestrator_import():
    """اختبار استيراد الـ Orchestrator الجديد"""
    print("\n" + "=" * 50)
    print("🎛️  اختبار 5: Orchestrator (استيراد فقط)")
    print("=" * 50)
    
    try:
        from orchestration.orchestrator import Orchestrator, OrchestratorState
        
        # التحقق من وجود ALL_SCANNERS
        assert hasattr(Orchestrator, 'ALL_SCANNERS'), "ALL_SCANNERS missing"
        scanners = Orchestrator.ALL_SCANNERS
        assert len(scanners) == 9, f"Expected 9 scanners, got {len(scanners)}"
        
        print(f"✅ ALL_SCANNERS: {len(scanners)} scanners defined")
        for key, cls_name in scanners:
            print(f"   - {key}: {cls_name}")
        
        # التحقق من الدوال الجديدة
        orch = Orchestrator()
        assert hasattr(orch, '_scan_page_full'), "_scan_page_full missing"
        assert hasattr(orch, '_init_world_state'), "_init_world_state missing"
        assert hasattr(orch, '_build_attack_chains'), "_build_attack_chains missing"
        assert hasattr(orch, '_scanner_stats'), "_scanner_stats missing"
        assert hasattr(orch, 'get_scanner_statistics'), "get_scanner_statistics missing"
        
        print("✅ All new methods present")
        print(f"✅ OrchestratorState: {[s.value for s in OrchestratorState]}")
        
        return True
        
    except Exception as e:
        print(f"❌ FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_severity_mapping():
    """اختبار خريطة تحويل Severity"""
    print("\n" + "=" * 50)
    print("📊 اختبار 6: Severity + Confidence تحويل")
    print("=" * 50)
    
    try:
        from offensive.scanners.base_scanner import Severity as ScanSev, Confidence as ScanConf, ScannerSeverity, ScannerConfidence
        from offensive.scanners.adapters import ScannerAdapter
        from schemas.vulnerability import Severity as SchemaSev
        
        # اختبار ScannerSeverity alias
        assert ScannerSeverity == ScanSev
        assert ScannerConfidence == ScanConf
        print("✅ ScannerSeverity == Severity")
        print("✅ ScannerConfidence == Confidence")
        
        # اختبار كل القيم
        tests = [
            (ScanSev.CRITICAL, SchemaSev.CRITICAL),
            (ScanSev.HIGH, SchemaSev.HIGH),
            (ScanSev.MEDIUM, SchemaSev.MEDIUM),
            (ScanSev.LOW, SchemaSev.LOW),
            (ScanSev.INFO, SchemaSev.INFO),
        ]
        
        for scan_sev, expected in tests:
            result = ScannerAdapter._map_severity(scan_sev)
            assert result == expected, f"Expected {expected}, got {result}"
            print(f"  ✅ {scan_sev.value} → {result.name}")
        
        # اختبار confidence
        conf_tests = [
            (ScanConf.CERTAIN, 1.0),
            (ScanConf.HIGH, 0.8),
            (ScanConf.MEDIUM, 0.5),
            (ScanConf.LOW, 0.3),
            (ScanConf.TENTATIVE, 0.1),
        ]
        
        for scan_conf, expected in conf_tests:
            result = ScannerAdapter._map_confidence(scan_conf)
            assert result == expected, f"Expected {expected}, got {result}"
            print(f"  ✅ {scan_conf.value} → {result}")
        
        return True
        
    except Exception as e:
        print(f"❌ FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False


def run_all_tests():
    """تشغيل كل الاختبارات"""
    print("\n" + "🧪" * 30)
    print("   بدء اختبارات المرحلتين 1 و 2")
    print("🧪" * 30 + "\n")
    
    tests = [
        ("EventBus + EventType", test_event_bus_import),
        ("Configs + Scanners", test_config_import),
        ("ScannerAdapter + PayloadAdapter + ConfigLoader", test_adapter_import),
        ("Finding → Vulnerability تحويل", test_scanner_adapters_integration),
        ("Orchestrator (استيراد فقط)", test_orchestrator_import),
        ("Severity + Confidence تحويل", test_severity_mapping),
    ]
    
    results = []
    for name, test_fn in tests:
        try:
            result = test_fn()
            results.append((name, result))
        except Exception as e:
            print(f"\n❌ TEST CRASHED: {name} - {e}")
            import traceback
            traceback.print_exc()
            results.append((name, False))
    
    print("\n" + "=" * 60)
    print("📋 ملخص النتائج")
    print("=" * 60)
    
    passed = sum(1 for _, r in results if r)
    failed = len(results) - passed
    
    for name, result in results:
        status = "✅ نجح" if result else "❌ فشل"
        print(f"  {status} - {name}")
    
    print(f"\n✅ نجح: {passed}")
    print(f"❌ فشل: {failed}")
    print(f"📊 النسبة: {passed/len(results)*100:.0f}%")
    
    if failed == 0:
        print("\n🎉 كل الاختبارات نجحت! المرحلتين 1 و 2 مكتملتين وجاهزين للتطبيق")
    else:
        print(f"\n⚠️  فيه {failed} اختبار فشل - يحتاج تصحيح قبل المتابعة")
    
    return failed == 0


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
