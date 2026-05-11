#!/bin/bash
# تشغيل جميع الاختبارات المتقدمة

echo ""
echo "═══════════════════════════════════════════════════════════"
echo "🚀 RUNNING ADVANCED TESTS"
echo "═══════════════════════════════════════════════════════════"

cd /workspaces/HunterMind_Offensive_Research_Platform

# تفعيل البيئة الافتراضية
source venv/bin/activate 2>/dev/null || true

# قائمة الاختبارات
tests=(
    "test_scanners.py"
    "test_payloads.py"
    "test_decision_engine.py"
    "test_memory.py"
    "test_agent_registry.py"
    "test_task_manager.py"
    "test_event_bus.py"
    "test_cache.py"
    "test_api.py"
    "test_integration.py"
)

passed=0
total=${#tests[@]}

for test in "${tests[@]}"; do
    echo ""
    echo "─────────────────────────────────────────────────────────"
    python "tests/advanced/$test"
    if [ $? -eq 0 ]; then
        ((passed++))
    fi
done

echo ""
echo "═══════════════════════════════════════════════════════════"
echo "📊 FINAL SUMMARY: $passed/$total tests passed"
echo "═══════════════════════════════════════════════════════════"
