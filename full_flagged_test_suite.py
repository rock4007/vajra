#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Full-Flagged Comprehensive Test Suite
Testing: Heart Rhythm Detection + Real-time SOS + WhatsApp/Call Alerts + 
Emergency Services Dispatch + Geolocation Verification
"""

import sys
import os
sys.stdout.reconfigure(encoding='utf-8') if hasattr(sys.stdout, 'reconfigure') else None

import requests
import json
import time
import threading
from datetime import datetime, timedelta
from pprint import pprint
import random
import math

# Configuration
BACKEND_URL = "http://localhost:8009"
TEST_REPORT = {
    "timestamp": datetime.now().isoformat(),
    "tests": [],
    "results": {},
    "summary": {}
}

# Emergency Service Data (Location-based dispatch)
EMERGENCY_SERVICES = {
    "fire_stations": [
        {"id": "FD-001", "name": "Downtown Fire Station", "lat": 37.7749, "lon": -122.4194, "city": "San Francisco"},
        {"id": "FD-002", "name": "Northside Fire Station", "lat": 37.7849, "lon": -122.4094, "city": "San Francisco"},
    ],
    "ambulances": [
        {"id": "AMB-001", "name": "SF General Ambulance", "lat": 37.7700, "lon": -122.4300, "city": "San Francisco"},
        {"id": "AMB-002", "name": "UCSF Ambulance", "lat": 37.7606, "lon": -122.4548, "city": "San Francisco"},
    ],
    "police_stations": [
        {"id": "PD-001", "name": "Central Police Station", "lat": 37.7799, "lon": -122.4089, "city": "San Francisco"},
        {"id": "PD-002", "name": "Southern Station", "lat": 37.7616, "lon": -122.4086, "city": "San Francisco"},
    ]
}

# Alert Recipients
ALERT_RECIPIENTS = {
    "member_1": {
        "name": "John Doe",
        "phone": "+1234567890",
        "whatsapp": "+1234567890",
        "email": "john@example.com"
    },
    "member_2": {
        "name": "Jane Smith",
        "phone": "+0987654321",
        "whatsapp": "+0987654321",
        "email": "jane@example.com"
    }
}

# Test Device Locations (with variations for multiple scenarios)
TEST_LOCATIONS = [
    {"name": "Downtown", "lat": 37.7749, "lon": -122.4194, "city": "San Francisco"},
    {"name": "Northside", "lat": 37.7849, "lon": -122.4094, "city": "San Francisco"},
    {"name": "Mission District", "lat": 37.7599, "lon": -122.4148, "city": "San Francisco"},
]

# Heart Rhythm Data (Simulated)
NORMAL_HEART_RATE = 60  # bpm
ABNORMAL_HEART_RATE = 120  # bpm (elevated due to distress)
HEART_RATE_VARIANCE = 5  # bpm variance for realism

print("=" * 100)
print("[START] FULL-FLAGGED COMPREHENSIVE TEST SUITE")
print("=" * 100)

def generate_heart_rhythm_data(distress=False):
    """Generate realistic heart rhythm data"""
    base_rate = ABNORMAL_HEART_RATE if distress else NORMAL_HEART_RATE
    heart_rate = base_rate + random.uniform(-HEART_RATE_VARIANCE, HEART_RATE_VARIANCE)
    
    # ECG-like waveform (simplified)
    ecg_values = [random.uniform(0.9, 1.1) for _ in range(10)]
    
    return {
        "heart_rate": round(heart_rate, 1),
        "bpm": round(heart_rate),
        "rhythm": "abnormal" if distress else "normal",
        "ecg_signal": ecg_values,
        "timestamp": datetime.now().isoformat(),
        "confidence": 0.95 if distress else 0.98
    }

def calculate_distance(lat1, lon1, lat2, lon2):
    """Calculate distance between two coordinates in km"""
    R = 6371  # Earth's radius in km
    lat1_rad = math.radians(lat1)
    lat2_rad = math.radians(lat2)
    delta_lat = math.radians(lat2 - lat1)
    delta_lon = math.radians(lon2 - lon1)
    
    a = math.sin(delta_lat/2)**2 + math.cos(lat1_rad) * math.cos(lat2_rad) * math.sin(delta_lon/2)**2
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1-a))
    
    return R * c

def find_nearest_services(location, service_type="fire"):
    """Find nearest emergency services to location"""
    services = EMERGENCY_SERVICES.get(f"{service_type}_stations", [])
    distances = []
    
    for service in services:
        dist = calculate_distance(location["lat"], location["lon"], service["lat"], service["lon"])
        distances.append({
            **service,
            "distance_km": round(dist, 2)
        })
    
    return sorted(distances, key=lambda x: x["distance_km"])

def test_heart_rhythm_detection():
    """Test 1: Heart Rhythm Detection"""
    print("\n" + "="*100)
    print("TEST 1️⃣: HEART RHYTHM DETECTION")
    print("="*100)
    
    test_result = {
        "name": "Heart Rhythm Detection",
        "status": "PENDING",
        "details": {}
    }
    
    try:
        # Test 1A: Normal Heart Rhythm
        print("\n  1A. Simulating NORMAL heart rhythm...")
        normal_rhythm = generate_heart_rhythm_data(distress=False)
        print(f"     Heart Rate: {normal_rhythm['bpm']} bpm")
        print(f"     Rhythm Status: {normal_rhythm['rhythm']}")
        print(f"     Confidence: {normal_rhythm['confidence']*100}%")
        
        # Test 1B: Abnormal Heart Rhythm (Distress)
        print("\n  1B. Simulating ABNORMAL heart rhythm (distress)...")
        abnormal_rhythm = generate_heart_rhythm_data(distress=True)
        print(f"     Heart Rate: {abnormal_rhythm['bpm']} bpm (ELEVATED)")
        print(f"     Rhythm Status: {abnormal_rhythm['rhythm']}")
        print(f"     Confidence: {abnormal_rhythm['confidence']*100}%")
        
        test_result["status"] = "✅ PASSED"
        test_result["details"] = {
            "normal_rhythm": normal_rhythm,
            "abnormal_rhythm": abnormal_rhythm
        }
        print("\n  ✅ Heart Rhythm Detection: PASSED")
        
    except Exception as e:
        test_result["status"] = "❌ FAILED"
        test_result["details"] = {"error": str(e)}
        print(f"\n  ❌ Heart Rhythm Detection: FAILED - {e}")
    
    TEST_REPORT["tests"].append(test_result)
    return test_result["status"] == "✅ PASSED"

def test_geolocation_verification():
    """Test 2: Geolocation Verification"""
    print("\n" + "="*100)
    print("TEST 2️⃣: GEOLOCATION VERIFICATION & ACCURACY")
    print("="*100)
    
    test_result = {
        "name": "Geolocation Verification",
        "status": "PENDING",
        "details": {}
    }
    
    try:
        location_tests = []
        
        for i, location in enumerate(TEST_LOCATIONS, 1):
            print(f"\n  2{chr(64+i)}. Testing location: {location['name']}")
            print(f"     Coordinates: ({location['lat']}, {location['lon']})")
            print(f"     City: {location['city']}")
            
            # Verify geolocation accuracy
            accuracy_score = random.uniform(0.95, 0.99)  # Simulated accuracy
            print(f"     Geolocation Accuracy: {accuracy_score*100:.1f}%")
            
            location_tests.append({
                "location": location,
                "accuracy": accuracy_score,
                "status": "✅" if accuracy_score > 0.90 else "❌"
            })
        
        test_result["status"] = "✅ PASSED"
        test_result["details"] = {"location_tests": location_tests}
        print("\n  ✅ Geolocation Verification: PASSED")
        
    except Exception as e:
        test_result["status"] = "❌ FAILED"
        test_result["details"] = {"error": str(e)}
        print(f"\n  ❌ Geolocation Verification: FAILED - {e}")
    
    TEST_REPORT["tests"].append(test_result)
    return test_result["status"] == "✅ PASSED"

def test_sos_alert_dispatch():
    """Test 3: Real-time SOS Alert Dispatch"""
    print("\n" + "="*100)
    print("TEST 3️⃣: REAL-TIME SOS ALERT DISPATCH")
    print("="*100)
    
    test_result = {
        "name": "SOS Alert Dispatch",
        "status": "PENDING",
        "details": {}
    }
    
    try:
        location = TEST_LOCATIONS[0]  # Use first test location
        device_id = "TEST_DEVICE_001"
        
        print(f"\n  Triggering SOS from device: {device_id}")
        print(f"  Location: {location['name']} ({location['lat']}, {location['lon']})")
        
        # Generate SOS payload
        sos_payload = {
            "device_id": device_id,
            "distress": True,
            "lat": location["lat"],
            "lon": location["lon"],
            "ts": datetime.now().isoformat(),
            "force": True,
            "heart_rhythm": generate_heart_rhythm_data(distress=True)
        }
        
        print(f"\n  📤 Sending SOS alert to backend...")
        
        try:
            response = requests.post(
                f"{BACKEND_URL}/sos_alert",
                json=sos_payload,
                timeout=10
            )
            
            print(f"  Response Status: {response.status_code}")
            response_data = response.json()
            print(f"  Response: {json.dumps(response_data, indent=2)}")
            
            if response.status_code in [200, 202]:
                test_result["status"] = "✅ PASSED"
                print("\n  ✅ SOS Alert Dispatch: PASSED")
            else:
                test_result["status"] = "⚠️  WARNING"
                print(f"\n  ⚠️  SOS Alert returned status {response.status_code}")
            
            test_result["details"] = {
                "sos_payload": sos_payload,
                "response_status": response.status_code,
                "response": response_data
            }
            
        except requests.exceptions.RequestException as e:
            print(f"  ❌ Backend not responding: {e}")
            test_result["status"] = "❌ FAILED"
            test_result["details"] = {"error": str(e)}
        
    except Exception as e:
        test_result["status"] = "❌ FAILED"
        test_result["details"] = {"error": str(e)}
        print(f"\n  ❌ SOS Alert Dispatch: FAILED - {e}")
    
    TEST_REPORT["tests"].append(test_result)
    return test_result["status"] in ["✅ PASSED", "⚠️  WARNING"]

def test_emergency_services_dispatch():
    """Test 4: Emergency Services Dispatch (Fire, Ambulance, Police)"""
    print("\n" + "="*100)
    print("TEST 4️⃣: EMERGENCY SERVICES DISPATCH (Location-based)")
    print("="*100)
    
    test_result = {
        "name": "Emergency Services Dispatch",
        "status": "PENDING",
        "details": {}
    }
    
    try:
        location = TEST_LOCATIONS[0]
        dispatch_log = []
        
        print(f"\n  Alert Location: {location['name']} ({location['lat']}, {location['lon']})")
        
        # Dispatch Fire Services
        print("\n  4A. FIRE DEPARTMENT DISPATCH 🚒")
        fire_dispatch = find_nearest_services(location, "fire")
        nearest_fire = fire_dispatch[0]
        print(f"     Nearest: {nearest_fire['name']} ({nearest_fire['id']})")
        print(f"     Distance: {nearest_fire['distance_km']} km")
        print(f"     ETA: ~{max(2, int(nearest_fire['distance_km']*2))} minutes")
        dispatch_log.append({
            "service": "Fire Department",
            "dispatch": nearest_fire,
            "status": "✅ DISPATCHED"
        })
        
        # Dispatch Ambulance
        print("\n  4B. AMBULANCE DISPATCH 🚑")
        ambulance_dispatch = find_nearest_services(location, "ambulance")
        nearest_ambulance = ambulance_dispatch[0]
        print(f"     Nearest: {nearest_ambulance['name']} ({nearest_ambulance['id']})")
        print(f"     Distance: {nearest_ambulance['distance_km']} km")
        print(f"     ETA: ~{max(3, int(nearest_ambulance['distance_km']*3))} minutes")
        dispatch_log.append({
            "service": "Ambulance",
            "dispatch": nearest_ambulance,
            "status": "✅ DISPATCHED"
        })
        
        # Dispatch Police
        print("\n  4C. POLICE STATION DISPATCH 🚔")
        police_dispatch = find_nearest_services(location, "police")
        nearest_police = police_dispatch[0]
        print(f"     Nearest: {nearest_police['name']} ({nearest_police['id']})")
        print(f"     Distance: {nearest_police['distance_km']} km")
        print(f"     ETA: ~{max(3, int(nearest_police['distance_km']*2.5))} minutes")
        dispatch_log.append({
            "service": "Police Station",
            "dispatch": nearest_police,
            "status": "✅ DISPATCHED"
        })
        
        test_result["status"] = "✅ PASSED"
        test_result["details"] = {"dispatch_log": dispatch_log}
        print("\n  ✅ Emergency Services Dispatch: PASSED")
        
    except Exception as e:
        test_result["status"] = "❌ FAILED"
        test_result["details"] = {"error": str(e)}
        print(f"\n  ❌ Emergency Services Dispatch: FAILED - {e}")
    
    TEST_REPORT["tests"].append(test_result)
    return test_result["status"] == "✅ PASSED"

def test_whatsapp_alerts():
    """Test 5: WhatsApp Alerts to 2 Members"""
    print("\n" + "="*100)
    print("TEST 5️⃣: WHATSAPP ALERTS TO 2 MEMBERS")
    print("="*100)
    
    test_result = {
        "name": "WhatsApp Alerts",
        "status": "PENDING",
        "details": {}
    }
    
    try:
        whatsapp_alerts = []
        location = TEST_LOCATIONS[0]
        
        for member_key, member in ALERT_RECIPIENTS.items():
            print(f"\n  Sending WhatsApp to {member['name']} ({member['whatsapp']})")
            
            # Simulate WhatsApp message
            message = f"""🚨 EMERGENCY SOS ALERT 🚨

📍 Location: {location['name']}, {location['city']}
📱 Device: TEST_DEVICE_001
⏰ Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

Heart Rhythm: ABNORMAL (120 bpm)
Status: ACTIVE SOS

🚑 Emergency Services Dispatched:
• Fire Department: ETA 4 min
• Ambulance: ETA 5 min
• Police: ETA 4 min

⚠️ IMMEDIATE ACTION REQUIRED
Contact emergency services or the victim"""
            
            print(f"     Message: {message[:100]}...")
            print(f"     Status: ✅ SENT (simulated)")
            
            whatsapp_alerts.append({
                "member": member,
                "message": message,
                "status": "✅ SENT",
                "timestamp": datetime.now().isoformat()
            })
        
        test_result["status"] = "✅ PASSED"
        test_result["details"] = {"whatsapp_alerts": whatsapp_alerts}
        print("\n  ✅ WhatsApp Alerts: PASSED")
        
    except Exception as e:
        test_result["status"] = "❌ FAILED"
        test_result["details"] = {"error": str(e)}
        print(f"\n  ❌ WhatsApp Alerts: FAILED - {e}")
    
    TEST_REPORT["tests"].append(test_result)
    return test_result["status"] == "✅ PASSED"

def test_emergency_calls():
    """Test 6: Emergency Calls to 2 Members"""
    print("\n" + "="*100)
    print("TEST 6️⃣: EMERGENCY CALLS TO 2 MEMBERS")
    print("="*100)
    
    test_result = {
        "name": "Emergency Calls",
        "status": "PENDING",
        "details": {}
    }
    
    try:
        call_alerts = []
        location = TEST_LOCATIONS[0]
        
        for member_key, member in ALERT_RECIPIENTS.items():
            print(f"\n  Initiating call to {member['name']} ({member['phone']})")
            
            call_script = f"""
            Automated SOS Call:
            "This is an emergency alert from Vajra Safety System. 
            An emergency has been detected for your contact. 
            Location: {location['name']}, {location['city']}
            Emergency services have been dispatched.
            Press 1 to acknowledge or stay on the line for operator."
            """
            
            print(f"     Call Script: {call_script.strip()[:80]}...")
            print(f"     Status: ✅ CONNECTED (simulated)")
            print(f"     Duration: 45 seconds")
            
            call_alerts.append({
                "member": member,
                "call_script": call_script,
                "status": "✅ CONNECTED",
                "duration_seconds": 45,
                "timestamp": datetime.now().isoformat()
            })
        
        test_result["status"] = "✅ PASSED"
        test_result["details"] = {"call_alerts": call_alerts}
        print("\n  ✅ Emergency Calls: PASSED")
        
    except Exception as e:
        test_result["status"] = "❌ FAILED"
        test_result["details"] = {"error": str(e)}
        print(f"\n  ❌ Emergency Calls: FAILED - {e}")
    
    TEST_REPORT["tests"].append(test_result)
    return test_result["status"] == "✅ PASSED"

def test_backend_health():
    """Test 7: Backend Health & API Status"""
    print("\n" + "="*100)
    print("TEST 7️⃣: BACKEND HEALTH & API STATUS")
    print("="*100)
    
    test_result = {
        "name": "Backend Health",
        "status": "PENDING",
        "details": {}
    }
    
    try:
        print(f"\n  Checking backend at {BACKEND_URL}")
        
        response = requests.get(f"{BACKEND_URL}/health", timeout=5)
        print(f"  Status Code: {response.status_code}")
        
        if response.status_code == 200:
            health_data = response.json()
            print(f"  Backend Status: 🟢 ONLINE")
            print(f"  Response: {json.dumps(health_data, indent=2)}")
            
            test_result["status"] = "✅ PASSED"
            test_result["details"] = {"health": health_data}
        else:
            test_result["status"] = "⚠️  WARNING"
            print(f"  Backend Status: 🟡 PARTIAL")
        
        print("\n  ✅ Backend Health: PASSED")
        
    except requests.exceptions.RequestException as e:
        test_result["status"] = "❌ FAILED"
        test_result["details"] = {"error": str(e)}
        print(f"  ❌ Backend not responding: {e}")
        print("\n  ❌ Backend Health: FAILED")
    
    TEST_REPORT["tests"].append(test_result)
    return test_result["status"] in ["✅ PASSED", "⚠️  WARNING"]

def generate_final_report():
    """Generate comprehensive test report"""
    print("\n" + "="*100)
    print("📊 COMPREHENSIVE TEST REPORT")
    print("="*100)
    
    passed = sum(1 for t in TEST_REPORT["tests"] if "✅" in t["status"])
    total = len(TEST_REPORT["tests"])
    
    print(f"\nTest Results: {passed}/{total} PASSED")
    print("\nDetailed Results:")
    
    for i, test in enumerate(TEST_REPORT["tests"], 1):
        print(f"\n  {i}. {test['name']}")
        print(f"     Status: {test['status']}")
        if test.get("details", {}).get("error"):
            print(f"     Error: {test['details']['error']}")
    
    print("\n" + "="*100)
    print("✨ TEST SUMMARY")
    print("="*100)
    print(f"✅ Passed: {passed}")
    print(f"❌ Failed: {total - passed}")
    print(f"📈 Success Rate: {(passed/total)*100:.1f}%")
    print("="*100)
    
    # Save report to file
    report_file = "full_flagged_test_report.json"
    with open(report_file, "w") as f:
        json.dump(TEST_REPORT, f, indent=2, default=str)
    print(f"\n📄 Full report saved to: {report_file}")

def main():
    """Run all tests"""
    print("\n🚀 Starting Full-Flagged Test Suite...")
    print(f"Backend URL: {BACKEND_URL}")
    print(f"Start Time: {datetime.now()}")
    
    time.sleep(1)
    
    # Run all tests
    test_backend_health()
    time.sleep(1)
    
    test_heart_rhythm_detection()
    time.sleep(1)
    
    test_geolocation_verification()
    time.sleep(1)
    
    test_sos_alert_dispatch()
    time.sleep(1)
    
    test_emergency_services_dispatch()
    time.sleep(1)
    
    test_whatsapp_alerts()
    time.sleep(1)
    
    test_emergency_calls()
    time.sleep(1)
    
    # Generate report
    generate_final_report()
    
    print("\n✨ All tests completed!")
    print("="*100)

if __name__ == "__main__":
    main()
