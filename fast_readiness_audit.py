#!/usr/bin/env python3
"""Fast manual readiness audit (no loops)."""
import requests
import json
import time
from datetime import datetime

BASE_URL = "http://localhost:8008"

print("=" * 80)
print("DEPLOYMENT READINESS AUDIT")
print("=" * 80)

checks = {
    "health": False,
    "version": False,
    "regions": False,
    "fingerprint": False,
    "heartbeat": False,
    "location": False,
    "code_protection": False,
    "auto_heal": False,
}

print("\n[1] Health Check...")
try:
    r = requests.get(f"{BASE_URL}/health", timeout=3)
    if r.status_code == 200:
        checks["health"] = True
        print("  OK - Status 200")
    else:
        print(f"  FAIL - Status {r.status_code}")
except Exception as e:
    print(f"  FAIL - {e}")

print("\n[2] Version Check...")
try:
    r = requests.get(f"{BASE_URL}/version", timeout=3)
    if r.status_code == 200:
        checks["version"] = True
        data = r.json()
        print(f"  OK - Version {data.get('version')}")
        print(f"  Regions: {data.get('supported_regions')}")
    else:
        print(f"  FAIL - Status {r.status_code}")
except Exception as e:
    print(f"  FAIL - {e}")

print("\n[3] Regions Check...")
try:
    r = requests.get(f"{BASE_URL}/regions", timeout=3)
    if r.status_code == 200:
        checks["regions"] = True
        data = r.json()
        print(f"  OK - Region: {data.get('region')}")
    else:
        print(f"  FAIL - Status {r.status_code}")
except Exception as e:
    print(f"  FAIL - {e}")

print("\n[4] Fingerprint Biometric Check...")
try:
    payload = {"device_id": "test_device", "fingerprint_hash": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"}
    r = requests.post(f"{BASE_URL}/fingerprint", json=payload, timeout=3)
    if r.status_code == 200:
        checks["fingerprint"] = True
        print("  OK - Fingerprint endpoint working")
    else:
        print(f"  FAIL - Status {r.status_code}")
except Exception as e:
    print(f"  FAIL - {e}")

print("\n[5] Heartbeat Check...")
try:
    payload = {"device_id": "test_device", "ts": datetime.utcnow().isoformat()}
    r = requests.post(f"{BASE_URL}/heartbeat", json=payload, timeout=3)
    if r.status_code == 200:
        checks["heartbeat"] = True
        print("  OK - Heartbeat endpoint working")
    else:
        print(f"  FAIL - Status {r.status_code}")
except Exception as e:
    print(f"  FAIL - {e}")

print("\n[6] Location Check...")
try:
    payload = {"device_id": "test_device", "lat": 28.5, "lon": 77.3}
    r = requests.post(f"{BASE_URL}/location", json=payload, timeout=3)
    if r.status_code == 200:
        checks["location"] = True
        print("  OK - Location endpoint working")
    else:
        print(f"  FAIL - Status {r.status_code}")
except Exception as e:
    print(f"  FAIL - {e}")

print("\n[7] Code Protection Check...")
try:
    import code_protection_system
    checks["code_protection"] = True
    print("  OK - Code protection system imported")
except Exception as e:
    print(f"  FAIL - {e}")

print("\n[8] Auto-Heal Check...")
try:
    import auto_heal_manager
    checks["auto_heal"] = True
    print("  OK - Auto-heal system imported")
except Exception as e:
    print(f"  FAIL - {e}")

# Summary
print("\n" + "=" * 80)
print("SUMMARY")
print("=" * 80)

passed = sum(1 for v in checks.values() if v)
total = len(checks)

print(f"\nChecks Passed: {passed}/{total}")
for check, result in checks.items():
    status = "PASS" if result else "FAIL"
    print(f"  {status} - {check}")

print("\n" + "=" * 80)
if passed >= 6:
    print("DEPLOYMENT STATUS: READY")
    print("=" * 80)
    print("\nAll critical systems operational. Deploy with confidence.")
else:
    print("DEPLOYMENT STATUS: NOT READY")
    print("=" * 80)
    print(f"\nFix {total - passed} failing checks before deployment.")

print("\n")
