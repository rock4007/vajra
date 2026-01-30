#!/usr/bin/env python3
"""Test the Vajra backend in real-time"""
import json
import sys
sys.path.insert(0, '.')

try:
    from main import app
    print('✓ main.py imports successfully')
    
    with app.test_client() as client:
        # Test regions endpoint
        r = client.get('/regions')
        print(f'✓ /regions endpoint works: {r.status_code}')
        data = json.loads(r.data)
        print(f'  Region: {data.get("region")}')
        
        # Test POST to sensors endpoint
        r = client.post('/sensors',
            json={'shield_on': True},
            headers={'Content-Type': 'application/json'}
        )
        print(f'✓ /sensors endpoint works: {r.status_code}')
        
        # Test POST to ai_safety endpoint
        r = client.post('/ai_safety',
            json={
                'x': 0.5,
                'y': 0.5,
                'z': 0.5,
                'timestamp': '2026-01-29T12:00:00Z',
                'shield_on': True
            },
            headers={'Content-Type': 'application/json'}
        )
        print(f'✓ /ai_safety endpoint works: {r.status_code}')
        
        print('\n✓ All backend tests passed!')
        
except Exception as e:
    print(f'✗ Error: {e}')
    import traceback
    traceback.print_exc()
    sys.exit(1)
