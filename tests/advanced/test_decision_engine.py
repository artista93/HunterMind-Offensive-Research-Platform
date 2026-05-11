#!/usr/bin/env python3
"""
اختبار محرك القرارات - Decision Engine Test
"""

import sys
import asyncio
sys.path.insert(0, '/workspaces/HunterMind_Offensive_Research_Platform')

async def test_decision_engine():
    print("\n🧠 Testing Decision Engine...")
    try:
        from cognition.brain.decision_engine import DecisionEngine, DecisionOption, DecisionType
        
        engine = DecisionEngine()
        
        options = [
            DecisionOption(
                type=DecisionType.ATTACK,
                action="xss_attack",
                confidence=0.85,
                expected_impact=0.7,
                risk_level="medium",
                resources_needed=["xss_scanner"]
            ),
            DecisionOption(
                type=DecisionType.RECON,
                action="deep_scan",
                confidence=0.9,
                expected_impact=0.5,
                risk_level="low",
                resources_needed=["crawler"]
            ),
            DecisionOption(
                type=DecisionType.LEARN,
                action="train_model",
                confidence=0.75,
                expected_impact=0.6,
                risk_level="low",
                resources_needed=["training_data"]
            )
        ]
        
        decision = await engine.evaluate_options(options)
        
        print(f"  Decision made: {decision.selected_option.action}")
        print(f"  Confidence: {decision.selected_option.confidence}")
        print(f"  Reasoning: {decision.reasoning[:100]}...")
        print(f"  Alternatives: {len(decision.alternatives)}")
        
        stats = await engine.get_statistics()
        print(f"  Total decisions: {stats['total_decisions']}")
        
        return True
    except Exception as e:
        print(f"  ❌ Error: {e}")
        return False

async def main():
    print("=" * 50)
    print("🔬 TEST 3: Decision Engine")
    print("=" * 50)
    
    result = await test_decision_engine()
    
    print("\n" + "=" * 50)
    print(f"RESULT: {'✅ PASSED' if result else '❌ FAILED'}")
    print("=" * 50)

if __name__ == "__main__":
    asyncio.run(main())
