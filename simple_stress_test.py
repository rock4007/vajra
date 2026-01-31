#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Vajra Light - Simplified Stress Test (500 cases for quick validation)
Then scale to 5000 with admin dashboard display
"""

import requests
import json
import random
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

BASE_URL = "http://127.0.0.1:8009"

def test_backend_connection():
    """Test if backend is responding"""
    print("Testing backend connection...")
    try:
        response = requests.get(f"{BASE_URL}/regions", timeout=5)
        if response.status_code == 200:
            print(f"Backend is online! Response: {response.text[:50]}")
            return True
        else:
            print(f"Backend returned status: {response.status_code}")
            return False
    except Exception as e:
        print(f"Connection failed: {e}")
        return False

def send_heartbeat():
    """Send a single heartbeat"""
    data = {
        "shield_on": random.choice([True, False]),
        "distress": random.choice([True, False]),
        "breathing_normal": random.choice([True, False]),
        "timestamp": datetime.now().isoformat()
    }
    try:
        response = requests.post(f"{BASE_URL}/heartbeat", json=data, timeout=5)
        return response.status_code in [200, 201, 202]
    except:
        return False

def send_location():
    """Send location data"""
    data = {
        "latitude": random.uniform(51.4769, 51.5233),
        "longitude": random.uniform(-0.1278, 0.0005),
        "accuracy": random.uniform(5, 30),
        "timestamp": datetime.now().isoformat()
    }
    try:
        response = requests.post(f"{BASE_URL}/location", json=data, timeout=5)
        return response.status_code in [200, 201, 202]
    except:
        return False

def send_sos_alert():
    """Send SOS alert"""
    alert_types = ["manual", "breathing", "impact"]
    data = {
        "alert_type": random.choice(alert_types),
        "latitude": random.uniform(51.4769, 51.5233),
        "longitude": random.uniform(-0.1278, 0.0005),
        "description": f"Test emergency - {datetime.now().isoformat()}",
        "timestamp": datetime.now().isoformat()
    }
    try:
        response = requests.post(f"{BASE_URL}/sos_alert", json=data, timeout=5)
        return response.status_code in [200, 201, 202]
    except:
        return False

def run_quick_test(num_cases=500):
    """Run quick test"""
    print(f"\nStarting {num_cases} case test...")
    print(f"Time: {datetime.now().strftime('%H:%M:%S')}\n")
    
    stats = {"sent": 0, "success": 0, "failed": 0}
    start_time = time.time()
    
    functions = [send_heartbeat, send_location, send_sos_alert]
    
    for i in range(num_cases):
        func = random.choice(functions)
        stats["sent"] += 1
        if func():
            stats["success"] += 1
        else:
            stats["failed"] += 1
        
        if (i + 1) % 100 == 0:
            print(f"Completed {i + 1}/{num_cases}...")
    
    duration = time.time() - start_time
    
    print(f"\n{'='*60}")
    print("TEST RESULTS")
    print(f"{'='*60}")
    print(f"Total: {stats['sent']}")
    print(f"Success: {stats['success']} ({stats['success']/stats['sent']*100:.1f}%)")
    print(f"Failed: {stats['failed']}")
    print(f"Duration: {duration:.2f}s")
    print(f"Rate: {stats['sent']/duration:.1f} requests/sec")
    print(f"{'='*60}\n")
    
    return stats["success"] > 0

def main():
    if not test_backend_connection():
        print("\nBackend is not running. Start it with:")
        print("  cd d:\\VajraBackend")
        print("  python main.py")
        return
    
    print("\nRunning quick test (500 cases)...")
    if run_quick_test(500):
        print("\nQuick test successful!")
        print(f"\nView results in admin dashboard:")
        print(f"  {BASE_URL}/admin")
    else:
        print("\nTest failed - backend not responding")

if __name__ == "__main__":
    main()
