"""
اختبار BrowserScanner على موقع حقيقي
"""
import asyncio
from offensive.scanners.browser_scanner import BrowserScanner
from offensive.scanners.base_scanner import ScanContext, ScanTarget

async def test():
    print("=" * 60)
    print("🧪 اختبار BrowserScanner على موقع حقيقي")
    print("=" * 60)
    
    # الهدف
    url = "https://tryhackme.com"
    
    print(f"\n🎯 الهدف: {url}")
    print(f"⏳ جاري الفحص بمتصفح حقيقي...\n")
    
    scanner = BrowserScanner(timeout=30)
    context = ScanContext(target=ScanTarget(url=url, force_scan=True))
    
    findings = await scanner.execute_scan(context)
    
    print(f"\n{'=' * 60}")
    print(f"📊 نتائج الفحص")
    print(f"{'=' * 60}")
    print(f"   الثغرات المكتشفة: {len(findings)}")
    
    if findings:
        by_severity = {}
        for f in findings:
            sev = f.severity.value
            by_severity[sev] = by_severity.get(sev, 0) + 1
        
        print(f"\n   حسب الخطورة:")
        for sev, count in sorted(by_severity.items()):
            emoji = "🔴" if sev == "critical" else "🟠" if sev == "high" else "🟡" if sev == "medium" else "🟢"
            print(f"     {emoji} {sev}: {count}")
        
        print(f"\n   التفاصيل:")
        for f in findings[:15]:
            print(f"   [{f.severity.value.upper()}] {f.vulnerability_type}")
            print(f"      URL: {f.url[:80]}")
            if f.evidence:
                print(f"      Evidence: {f.evidence[:100]}")
            print()
    else:
        print(f"   ℹ️  لم يتم اكتشاف ثغرات")
    
    print(f"\n✅ تم الانتهاء من الفحص")

asyncio.run(test())
