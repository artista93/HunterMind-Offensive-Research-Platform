#!/usr/bin/env python3
"""
اختبار Event Bus - Event Propagation Test
"""

import sys
import asyncio
sys.path.insert(0, '/workspaces/HunterMind_Offensive_Research_Platform')

async def test_event_bus():
    print("\n📡 Testing Event Bus...")
    try:
        from orchestration.messaging.event_bus import EventBus, Event, EventType
        
        bus = EventBus()
        
        events_received = []
        
        async def handler(event):
            events_received.append(event)
            print(f"  Event received: {event.type.value} from {event.source}")
        
        # الاشتراك
        await bus.subscribe(EventType.TASK_START, handler)
        await bus.subscribe(EventType.TASK_COMPLETE, handler)
        await bus.subscribe(EventType.DATA_RECEIVED, handler)
        
        # نشر الأحداث
        await bus.publish(Event(type=EventType.TASK_START, source="test", data={"task": "1"}))
        await bus.publish(Event(type=EventType.TASK_COMPLETE, source="test", data={"task": "1"}))
        await bus.publish(Event(type=EventType.DATA_RECEIVED, source="test", data={"size": 1024}))
        
        await asyncio.sleep(0.5)
        
        print(f"  Events processed: {len(events_received)}")
        
        # الحصول على التاريخ
        history = await bus.get_history(limit=5)
        print(f"  History size: {len(history)}")
        
        stats = await bus.get_statistics()
        print(f"  Event Bus stats: {stats['total_events']} events, {stats['total_subscribers']} subscribers")
        
        return True
    except Exception as e:
        print(f"  ❌ Error: {e}")
        return False

async def main():
    print("=" * 50)
    print("🔬 TEST 7: Event Bus")
    print("=" * 50)
    
    result = await test_event_bus()
    
    print("\n" + "=" * 50)
    print(f"RESULT: {'✅ PASSED' if result else '❌ FAILED'}")
    print("=" * 50)

if __name__ == "__main__":
    asyncio.run(main())
