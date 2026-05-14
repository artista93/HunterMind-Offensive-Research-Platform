#!/usr/bin/env python3
"""
فحص جميع الوكلاء للتأكد من أنهم يرثون من BaseAgent ويطبقون الدوال المجردة
"""

import inspect
import sys
from pathlib import Path

# إضافة المسار الرئيسي
sys.path.insert(0, str(Path(__file__).parent))

# استيراد BaseAgent
from agents.base.base_agent import BaseAgent, AgentState, AgentPriority

# قائمة الوكلاء المطلوب فحصها
AGENTS = [
    ("agents.crawler_agent.crawler_agent", "CrawlerAgent"),
    ("agents.recon_agent.recon_agent", "ReconAgent"),
    ("agents.xss_agent.xss_agent", "XSSAgent"),
    ("agents.sqli_agent.sqli_agent", "SQLiAgent"),
    ("agents.idor_agent.idor_agent", "IDORAgent"),
    ("agents.waf_agent.waf_agent", "WAFAgent"),
    ("agents.auth_agent.auth_agent", "AuthAgent"),
    ("agents.exploitation_agent.exploitation_agent", "ExploitationAgent"),
    ("agents.learning_agent.learning_agent", "LearningAgent"),
    ("agents.reasoning_agent.reasoning_agent", "ReasoningAgent"),
    ("agents.planning_agent.planning_agent", "PlanningAgent"),
]

# الدوال المجردة التي يجب تطبيقها
ABSTRACT_METHODS = ['_on_initialize', '_on_start', '_on_stop']

def check_agent(module_path, class_name):
    """فحص وكيل واحد"""
    try:
        module = __import__(module_path, fromlist=[class_name])
        agent_class = getattr(module, class_name)
        
        # التحقق من الوراثة
        if not issubclass(agent_class, BaseAgent):
            return False, "Does not inherit from BaseAgent"
        
        # التحقق من تطبيق الدوال المجردة
        missing_methods = []
        for method in ABSTRACT_METHODS:
            if not hasattr(agent_class, method):
                missing_methods.append(method)
            else:
                # التحقق من أن الدالة ليست مجردة
                attr = getattr(agent_class, method)
                if inspect.ismethod(attr) and getattr(attr, '__isabstractmethod__', False):
                    missing_methods.append(method)
        
        if missing_methods:
            return False, f"Missing abstract methods: {missing_methods}"
        
        return True, "OK"
        
    except ImportError as e:
        return False, f"Import error: {e}"
    except Exception as e:
        return False, f"Error: {e}"

print("=" * 60)
print("🔍 AGENTS INHERITANCE CHECK")
print("=" * 60)
print()

results = []
for module_path, class_name in AGENTS:
    print(f"Checking {class_name}...")
    success, message = check_agent(module_path, class_name)
    status = "✅" if success else "❌"
    print(f"  {status} {message}")
    results.append((class_name, success, message))
    print()

print("=" * 60)
print("📊 SUMMARY")
print("=" * 60)

passed = sum(1 for _, success, _ in results if success)
failed = len(results) - passed

print(f"Total Agents: {len(results)}")
print(f"Passed: {passed} ✅")
print(f"Failed: {failed} ❌")

if failed > 0:
    print("\n❌ FAILED AGENTS:")
    for name, success, msg in results:
        if not success:
            print(f"  - {name}: {msg}")

print("\n" + "=" * 60)
