#!/usr/bin/env python3
"""
اختبار الذاكرة - Memory Systems Test
"""

import sys
import asyncio
sys.path.insert(0, '/workspaces/HunterMind_Offensive_Research_Platform')

async def test_working_memory():
    print("\n💭 Testing Working Memory...")
    try:
        from cognition.memory.working_memory import WorkingMemory
        
        memory = WorkingMemory(capacity=5)
        await memory.start()
        
        await memory.store("key1", "value1", priority=5)
        await memory.store("key2", "value2", priority=3)
        await memory.store("key3", "value3", priority=1)
        
        value = await memory.retrieve("key2")
        print(f"  Retrieved: key2 = {value}")
        
        all_items = await memory.get_all()
        print(f"  All items: {all_items}")
        
        stats = await memory.get_statistics()
        print(f"  Memory stats: {stats['total_items']} items, {stats['usage_percentage']:.1f}% full")
        
        await memory.stop()
        return True
    except Exception as e:
        print(f"  ❌ Error: {e}")
        return False

async def test_episodic_memory():
    print("\n📖 Testing Episodic Memory...")
    try:
        from cognition.memory.episodic_memory import EpisodicMemory
        
        memory = EpisodicMemory()
        
        # تخزين أحداث
        await memory.store_episode(
            event_type="scan",
            description="Completed scan of example.com",
            outcome="found 5 vulnerabilities",
            success=True,
            context={"target": "example.com", "depth": 3}
        )
        
        await memory.store_episode(
            event_type="attack",
            description="XSS attack on search parameter",
            outcome="alert triggered",
            success=True,
            context={"target": "example.com", "payload": "<script>alert(1)</script>"}
        )
        
        successful = await memory.retrieve_successful()
        print(f"  Successful episodes: {len(successful)}")
        
        stats = await memory.get_statistics()
        print(f"  Total episodes: {stats['total_episodes']}")
        print(f"  Success rate: {stats['success_rate']:.2%}")
        
        return True
    except Exception as e:
        print(f"  ❌ Error: {e}")
        return False

async def main():
    print("=" * 50)
    print("🔬 TEST 4: Memory Systems")
    print("=" * 50)
    
    results = []
    results.append(await test_working_memory())
    results.append(await test_episodic_memory())
    
    print("\n" + "=" * 50)
    print(f"RESULTS: {sum(results)}/{len(results)} passed")
    print("=" * 50)

if __name__ == "__main__":
    asyncio.run(main())
