#!/usr/bin/env python3
"""
اختبار Cache Manager - Caching Test
"""

import sys
import asyncio
sys.path.insert(0, '/workspaces/HunterMind_Offensive_Research_Platform')

async def test_cache():
    print("\n💾 Testing Cache Manager...")
    try:
        from orchestration.cache_manager import CacheManager
        
        cache = CacheManager(max_size=10, default_ttl=5)
        await cache.start()
        
        # تخزين
        await cache.set("key1", "value1")
        await cache.set("key2", "value2", ttl=2)
        await cache.set("key3", "value3", ttl=10)
        
        # استرجاع
        value1 = await cache.get("key1")
        value2 = await cache.get("key2")
        value3 = await cache.get("key3")
        
        print(f"  Retrieved: key1={value1}, key2={value2}, key3={value3}")
        
        # انتظار انتهاء صلاحية key2
        await asyncio.sleep(3)
        expired = await cache.get("key2")
        print(f"  After 3s, key2 expired: {expired is None}")
        
        # إحصائيات
        stats = await cache.get_stats()
        print(f"  Cache stats: {stats['size']}/{stats['max_size']} items, hit_rate={stats['hit_rate']:.2f}")
        
        await cache.stop()
        return True
    except Exception as e:
        print(f"  ❌ Error: {e}")
        return False

async def main():
    print("=" * 50)
    print("🔬 TEST 8: Cache Manager")
    print("=" * 50)
    
    result = await test_cache()
    
    print("\n" + "=" * 50)
    print(f"RESULT: {'✅ PASSED' if result else '❌ FAILED'}")
    print("=" * 50)

if __name__ == "__main__":
    asyncio.run(main())
