#!/usr/bin/env python3
"""
اختبار API Endpoints - REST API Test
"""

import sys
sys.path.insert(0, '/workspaces/HunterMind_Offensive_Research_Platform')

def test_api_endpoints():
    print("\n🌐 Testing API Endpoints...")
    try:
        from fastapi.testclient import TestClient
        from interfaces.api.fastapi_server import app
        
        client = TestClient(app)
        
        endpoints = [
            ("GET", "/", 200),
            ("GET", "/health", 200),
            ("GET", "/status", 200),
            ("POST", "/scan", 200),
            ("GET", "/scans", 200),
            ("GET", "/attacks", 200),
        ]
        
        passed = 0
        for method, path, expected in endpoints:
            if method == "GET":
                response = client.get(path)
            else:
                response = client.post(path, json={"target_url": "https://example.com"})
            
            status = "✅" if response.status_code == expected else "❌"
            print(f"  {status} {method} {path}: {response.status_code} (expected {expected})")
            
            if response.status_code == expected:
                passed += 1
        
        print(f"\n  API endpoints: {passed}/{len(endpoints)} working")
        
        return passed == len(endpoints)
    except Exception as e:
        print(f"  ❌ Error: {e}")
        return False

def main():
    print("=" * 50)
    print("🔬 TEST 9: API Endpoints")
    print("=" * 50)
    
    result = test_api_endpoints()
    
    print("\n" + "=" * 50)
    print(f"RESULT: {'✅ PASSED' if result else '❌ FAILED'}")
    print("=" * 50)

if __name__ == "__main__":
    main()
