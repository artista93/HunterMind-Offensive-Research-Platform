#!/usr/bin/env python3
"""
اختبار Task Manager - Task Management Test
"""

import sys
import asyncio
sys.path.insert(0, '/workspaces/HunterMind_Offensive_Research_Platform')

async def test_task_manager():
    print("\n📋 Testing Task Manager...")
    try:
        from orchestration.task_manager import TaskManager, TaskPriority
        
        tm = TaskManager(max_concurrent=3)
        await tm.start()
        
        # مهمة بسيطة
        async def sample_task(name, delay=0.5):
            await asyncio.sleep(delay)
            return f"Task {name} completed"
        
        # إرسال مهام
        task1 = await tm.submit_task("Task 1", sample_task, "A", priority=TaskPriority.HIGH)
        task2 = await tm.submit_task("Task 2", sample_task, "B", priority=TaskPriority.NORMAL)
        task3 = await tm.submit_task("Task 3", sample_task, "C", priority=TaskPriority.LOW)
        
        print(f"  Tasks submitted: {task1}, {task2}, {task3}")
        
        # انتظار التنفيذ
        await asyncio.sleep(2)
        
        # الحصول على حالة المهام
        status1 = await tm.get_task_status(task1)
        status2 = await tm.get_task_status(task2)
        
        print(f"  Task 1 status: {status1['status'] if status1 else 'unknown'}")
        print(f"  Task 2 status: {status2['status'] if status2 else 'unknown'}")
        
        stats = await tm.get_statistics()
        print(f"  Task Manager stats: {stats['total_tasks']} tasks, {stats['completed_tasks']} completed")
        
        await tm.stop()
        return True
    except Exception as e:
        print(f"  ❌ Error: {e}")
        return False

async def main():
    print("=" * 50)
    print("🔬 TEST 6: Task Manager")
    print("=" * 50)
    
    result = await test_task_manager()
    
    print("\n" + "=" * 50)
    print(f"RESULT: {'✅ PASSED' if result else '❌ FAILED'}")
    print("=" * 50)

if __name__ == "__main__":
    asyncio.run(main())
