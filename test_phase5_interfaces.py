"""
اختبار المرحلة 5: Interfaces - التحقق من صحة الاستيرادات بعد التنظيف
"""

import sys
import asyncio

def test_interfaces_init_import():
    """اختبار استيراد interfaces/__init__.py"""
    print("=" * 50)
    print("📦 اختبار 1: interfaces/__init__.py")
    print("=" * 50)
    
    try:
        from interfaces import (
            api_app, dashboard_app, data_manager,
            CLIRunner, TerminalUI, Color,
            ReportGenerator, JSONExporter, PDFExporter,
            AttackChainReporter,
        )
        
        print("✅ api_app:", type(api_app).__name__)
        print("✅ dashboard_app:", type(dashboard_app).__name__)
        print("✅ data_manager:", type(data_manager).__name__)
        print("✅ CLIRunner:", CLIRunner.__name__)
        print("✅ TerminalUI:", TerminalUI.__name__)
        print("✅ ReportGenerator:", ReportGenerator.__name__)
        print("✅ JSONExporter:", JSONExporter.__name__)
        print("✅ PDFExporter:", PDFExporter.__name__)
        print("✅ AttackChainReporter:", AttackChainReporter.__name__)
        
        return True
    except Exception as e:
        print(f"❌ FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_dashboard_import():
    """اختبار استيراد dashboard"""
    print("\n" + "=" * 50)
    print("📊 اختبار 2: interfaces/dashboard/")
    print("=" * 50)
    
    try:
        from interfaces.dashboard import (
            app, DashboardDataManager, data_manager,
            MonitorManager, monitor_manager,
            AttackVisualizer, visualizer,
            CognitiveMonitor, cognitive_monitor,
        )
        
        print("✅ app:", type(app).__name__)
        print("✅ DashboardDataManager:", DashboardDataManager.__name__)
        print("✅ MonitorManager:", MonitorManager.__name__)
        print("✅ AttackVisualizer:", AttackVisualizer.__name__)
        print("✅ CognitiveMonitor:", CognitiveMonitor.__name__)
        
        # التحقق من الدوال المساعدة
        from interfaces.dashboard import (
            emit_scan_started, emit_scan_completed,
            emit_vulnerability_found, emit_system_alert,
            get_attack_chains, get_graph_data,
            update_cognitive_state, get_cognitive_state,
        )
        
        print("✅ emit_scan_started:", callable(emit_scan_started))
        print("✅ get_attack_chains:", callable(get_attack_chains))
        print("✅ update_cognitive_state:", callable(update_cognitive_state))
        
        return True
    except Exception as e:
        print(f"❌ FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_cli_import():
    """اختبار استيراد CLI"""
    print("\n" + "=" * 50)
    print("💻 اختبار 3: interfaces/cli/")
    print("=" * 50)
    
    try:
        from interfaces.cli import (
            CLIRunner, TerminalUI, Color, ProgressBar, Spinner, Table,
            CommandParser, Command, CommandType,
        )
        
        print("✅ CLIRunner:", CLIRunner.__name__)
        print("✅ TerminalUI:", TerminalUI.__name__)
        print("✅ CommandParser:", CommandParser.__name__)
        print("✅ CommandType:", [c.value for c in CommandType][:5])
        
        # التحقق من عدم وجود cli_runner_real
        try:
            from interfaces.cli.cli_runner_real import CLIRunner as OldRunner
            print("❌ cli_runner_real.py still exists - should be deleted!")
            return False
        except ImportError:
            print("✅ cli_runner_real.py successfully removed")
        
        return True
    except Exception as e:
        print(f"❌ FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_api_import():
    """اختبار استيراد API"""
    print("\n" + "=" * 50)
    print("🔌 اختبار 4: interfaces/api/")
    print("=" * 50)
    
    try:
        from interfaces.api import (
            app, get_grpc_server,
            Severity, Confidence, ScanType, AttackType,
            ScanRequest, ScanResponse, Finding,
        )
        
        print("✅ app:", type(app).__name__)
        print("✅ ScanRequest:", ScanRequest.__name__)
        print("✅ Finding:", Finding.__name__)
        print("✅ Severity:", [s.value for s in Severity])
        
        return True
    except Exception as e:
        print(f"❌ FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_reporting_import():
    """اختبار استيراد Reporting"""
    print("\n" + "=" * 50)
    print("📄 اختبار 5: interfaces/reporting/")
    print("=" * 50)
    
    try:
        from interfaces.reporting import (
            ReportGenerator, get_report_generator,
            JSONExporter, get_json_exporter,
            PDFExporter, get_pdf_exporter,
            AttackChainReporter, get_attack_chain_reporter,
        )
        
        gen = get_report_generator()
        json_exp = get_json_exporter()
        pdf_exp = get_pdf_exporter()
        chain_rep = get_attack_chain_reporter()
        
        print("✅ ReportGenerator:", type(gen).__name__)
        print("✅ JSONExporter:", type(json_exp).__name__)
        print("✅ PDFExporter:", type(pdf_exp).__name__)
        print("✅ AttackChainReporter:", type(chain_rep).__name__)
        
        # اختبار دالة markdown
        md = gen.generate_markdown({"title": "Test", "target": "test.com"})
        print(f"✅ generate_markdown: {len(md)} chars")
        
        return True
    except Exception as e:
        print(f"❌ FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_dashboard_server_integration():
    """اختبار DashboardDataManager"""
    print("\n" + "=" * 50)
    print("🔗 اختبار 6: DashboardDataManager Integration")
    print("=" * 50)
    
    try:
        from interfaces.dashboard.dashboard_server import DashboardDataManager, data_manager
        
        # التحقق من الدوال
        assert hasattr(data_manager, 'initialize')
        assert hasattr(data_manager, '_on_task_complete')
        assert hasattr(data_manager, '_on_vulnerability')
        assert hasattr(data_manager, '_broadcast')
        assert hasattr(data_manager, 'get_template_data')
        assert hasattr(data_manager, 'get_stats_api')
        
        print("✅ All methods present in DashboardDataManager")
        
        # اختبار get_stats_api
        stats = data_manager.get_stats_api()
        print(f"✅ get_stats_api(): {stats}")
        
        return True
    except Exception as e:
        print(f"❌ FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_deleted_files():
    """التحقق من حذف الملفات الزائدة"""
    print("\n" + "=" * 50)
    print("🗑️  اختبار 7: الملفات المحذوفة")
    print("=" * 50)
    
    import os
    
    deleted_files = [
        "interfaces/cli/cli_runner_real.py",
        "interfaces/dashboard/dashboard_pro.py",
        "interfaces/dashboard/scan_tester_pro.py",
    ]
    
    all_deleted = True
    for f in deleted_files:
        if os.path.exists(f):
            print(f"  ❌ لا يزال موجوداً: {f}")
            all_deleted = False
        else:
            print(f"  ✅ تم حذفه: {f}")
    
    return all_deleted


def run_all_tests():
    """تشغيل كل الاختبارات"""
    print("\n" + "🧪" * 30)
    print("   بدء اختبارات المرحلة 5: Interfaces")
    print("🧪" * 30 + "\n")
    
    tests = [
        ("interfaces/__init__.py", test_interfaces_init_import),
        ("Dashboard imports", test_dashboard_import),
        ("CLI imports", test_cli_import),
        ("API imports", test_api_import),
        ("Reporting imports", test_reporting_import),
        ("DashboardDataManager", test_dashboard_server_integration),
        ("الملفات المحذوفة", test_deleted_files),
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
    print("📋 ملخص النتائج - المرحلة 5: Interfaces")
    print("=" * 60)
    
    passed = sum(1 for _, r in results if r)
    failed = len(results) - passed
    
    for name, result in results:
        print(f"  {'✅ نجح' if result else '❌ فشل'} - {name}")
    
    print(f"\n✅ نجح: {passed}")
    print(f"❌ فشل: {failed}")
    print(f"📊 النسبة: {passed/len(results)*100:.0f}%")
    
    if failed == 0:
        print("\n🎉 المرحلة 5 مكتملة! Interfaces جاهزة ونظيفة")
    
    return failed == 0


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
