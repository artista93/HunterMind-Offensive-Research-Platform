#!/bin/bash
# ============================================
# Generate Dataset Script - توليد مجموعة بيانات
# ============================================

set -e

echo "📊 HunterMind - Generate Dataset"
echo "================================"

# تفعيل البيئة الافتراضية
source venv/bin/activate

# توليد حمولات XSS
echo ""
echo "🔄 Generating XSS payloads..."
python -c "
import json
from offensive.payloads.payload_generator import PayloadGenerator

generator = PayloadGenerator()
payloads = generator.generate_xss_payloads(max_payloads=100)

data = {
    'version': '1.0.0',
    'description': 'Generated XSS payloads',
    'payloads': [
        {'name': p.name, 'payload': p.payload, 'type': p.type.value}
        for p in payloads
    ]
}

with open('datasets/attack_payloads/generated_xss.json', 'w') as f:
    json.dump(data, f, indent=2)

print(f'✅ Generated {len(payloads)} XSS payloads')
"

# توليد حمولات SQLi
echo ""
echo "🔄 Generating SQLi payloads..."
python -c "
import json
from offensive.payloads.payload_generator import PayloadGenerator

generator = PayloadGenerator()
payloads = generator.generate_sqli_payloads(max_payloads=100)

data = {
    'version': '1.0.0',
    'description': 'Generated SQLi payloads',
    'payloads': [
        {'name': p.name, 'payload': p.payload, 'type': p.type.value}
        for p in payloads
    ]
}

with open('datasets/attack_payloads/generated_sqli.json', 'w') as f:
    json.dump(data, f, indent=2)

print(f'✅ Generated {len(payloads)} SQLi payloads')
"

# توليد حمولات RCE
echo ""
echo "🔄 Generating RCE payloads..."
python -c "
import json
from offensive.payloads.payload_generator import PayloadGenerator

generator = PayloadGenerator()
payloads = generator.generate_rce_payloads(max_payloads=50)

data = {
    'version': '1.0.0',
    'description': 'Generated RCE payloads',
    'payloads': [
        {'name': p.name, 'payload': p.payload, 'type': p.type.value}
        for p in payloads
    ]
}

with open('datasets/attack_payloads/generated_rce.json', 'w') as f:
    json.dump(data, f, indent=2)

print(f'✅ Generated {len(payloads)} RCE payloads')
"

echo ""
echo "✅ Dataset generation completed!"
echo ""
echo "📁 Generated files:"
echo "   - datasets/attack_payloads/generated_xss.json"
echo "   - datasets/attack_payloads/generated_sqli.json"
echo "   - datasets/attack_payloads/generated_rce.json"
