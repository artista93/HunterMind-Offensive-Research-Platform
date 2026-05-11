#!/usr/bin/env python3
"""
اختبار مولد الحمولات - Payload Generator Test
"""

import sys
sys.path.insert(0, '/workspaces/HunterMind_Offensive_Research_Platform')

def test_xss_generation():
    print("\n💉 Testing XSS Payload Generation...")
    try:
        from offensive.payloads.payload_generator import PayloadGenerator
        
        gen = PayloadGenerator()
        payloads = gen.generate_xss_payloads(max_payloads=5)
        
        print(f"  XSS Payloads generated: {len(payloads)}")
        if payloads:
            print(f"  Example: {payloads[0].payload[:80]}...")
        
        return len(payloads) > 0
    except Exception as e:
        print(f"  ❌ Error: {e}")
        return False

def test_sqli_generation():
    print("\n💉 Testing SQLi Payload Generation...")
    try:
        from offensive.payloads.payload_generator import PayloadGenerator
        
        gen = PayloadGenerator()
        payloads = gen.generate_sqli_payloads(max_payloads=5)
        
        print(f"  SQLi Payloads generated: {len(payloads)}")
        if payloads:
            print(f"  Example: {payloads[0].payload[:80]}...")
        
        return len(payloads) > 0
    except Exception as e:
        print(f"  ❌ Error: {e}")
        return False

def test_rce_generation():
    print("\n💉 Testing RCE Payload Generation...")
    try:
        from offensive.payloads.payload_generator import PayloadGenerator
        
        gen = PayloadGenerator()
        payloads = gen.generate_rce_payloads(max_payloads=5)
        
        print(f"  RCE Payloads generated: {len(payloads)}")
        if payloads:
            print(f"  Example: {payloads[0].payload[:80]}...")
        
        return len(payloads) > 0
    except Exception as e:
        print(f"  ❌ Error: {e}")
        return False

def test_mutation():
    print("\n🔄 Testing Payload Mutation...")
    try:
        from offensive.payloads.payload_mutator import PayloadMutator
        from offensive.payloads.payload_generator import PayloadGenerator
        
        gen = PayloadGenerator()
        mutator = PayloadMutator()
        
        original = gen.generate_xss_payloads(max_payloads=1)[0]
        mutated = mutator.mutate_payload(original)
        
        print(f"  Original: {original.payload[:60]}...")
        print(f"  Mutations: {len(mutated)}")
        
        return len(mutated) > 0
    except Exception as e:
        print(f"  ❌ Error: {e}")
        return False

def main():
    print("=" * 50)
    print("🔬 TEST 2: Payload Generator")
    print("=" * 50)
    
    results = []
    results.append(test_xss_generation())
    results.append(test_sqli_generation())
    results.append(test_rce_generation())
    results.append(test_mutation())
    
    print("\n" + "=" * 50)
    print(f"RESULTS: {sum(results)}/{len(results)} passed")
    print("=" * 50)

if __name__ == "__main__":
    main()
