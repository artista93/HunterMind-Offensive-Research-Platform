#!/usr/bin/env python3
"""
اختبار Agent Registry - Agent Registration Test
"""

import sys
import os

# إضافة المسار الرئيسي للمشروع
sys.path.insert(0, '/workspaces/HunterMind_Offensive_Research_Platform')

import asyncio

async def test_agent_registry():
    print("\n🤖 Testing Agent Registry...")
    try:
        from agents.base.agent_registry import AgentRegistry, AgentType
        
        # إنشاء وكيل وهمي بسيط
        class MockAgent:
            def __init__(self, name):
                self.id = "mock_agent_001"
                self.name = name
                self.priority = 3  # AgentPriority.NORMAL
            
            def get_state(self):
                return "idle"
            
            async def stop(self):
                pass
            
            async def initialize(self):
                pass
            
            async def start(self):
                pass
            
            def is_running(self):
                return True
        
        registry = AgentRegistry()
        await registry.start()
        
        # إنشاء وكيل وهمي
        mock_agent = MockAgent("TestAgent")
        
        # تسجيل الوكيل
        await registry.register_agent(mock_agent, AgentType.XSS, ["scan", "detect"])
        
        # استرجاع الوكيل
        retrieved = await registry.get_agent(mock_agent.id)
        print(f"  Agent retrieved: {retrieved.name if retrieved else 'None'}")
        
        # الحصول على وكلاء حسب النوع
        xss_agents = await registry.get_agents_by_type(AgentType.XSS)
        print(f"  XSS agents count: {len(xss_agents)}")
        
        # إرسال نبض قلب
        heartbeat = await registry.update_heartbeat(mock_agent.id)
        print(f"  Heartbeat sent: {heartbeat}")
        
        stats = await registry.get_statistics()
        print(f"  Registry stats: {stats['total_agents']} agents, {stats['active_agents']} active")
        
        await registry.stop()
        return True
    except Exception as e:
        print(f"  ❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return False

async def main():
    print("=" * 50)
    print("🔬 TEST 5: Agent Registry")
    print("=" * 50)
    
    result = await test_agent_registry()
    
    print("\n" + "=" * 50)
    print(f"RESULT: {'✅ PASSED' if result else '❌ FAILED'}")
    print("=" * 50)

if __name__ == "__main__":
    asyncio.run(main())
