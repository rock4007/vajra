#!/usr/bin/env python3
"""
Vajra Kavach - Fast Dual Stress Test
Runs 2000 tests across 6 different scenarios rapidly
"""

import requests
import json
import time
import random
import threading
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import statistics

BASE_URL = "http://127.0.0.1:8008"

# Test scenarios with dual situations
SCENARIOS = [
    ("normal_walk", "Normal walking - no threat"),
    ("normal_run", "Normal running - no threat"),
    ("high_g_push", "High-G impact - push attack"),
    ("high_g_fall", "High-G impact - fall/trip"),
    ("distress_panic", "Distress heartbeat - panic"),
    ("distress_struggle", "Distress heartbeat - struggling"),
    ("manual_sos_forced", "Manual SOS - forced"),
    ("manual_sos_voluntary", "Manual SOS - voluntary"),
    ("combined_violent", "Combined - violent attack"),
    ("combined_kidnap", "Combined - kidnapping attempt"),
    ("false_positive_jump", "False positive - jumping"),
    ("false_positive_vehicle", "False positive - vehicle motion"),
]

# Kolkata coordinates
LOCATIONS = [
    (22.5726, 88.3639), (22.5545, 88.3535), (22.5820, 88.3440),
    (22.5958, 88.3639), (22.4978, 88.3472), (22.6203, 88.4370),
]

# Global stats
results = {
    "total": 0, "success": 0, "failed": 0,
    "scenarios": {}, "times": [], "alerts": 0
}
lock = threading.Lock()


def test_case(test_id, scenario, description):
    """Run a single test case"""
    device_id = f"dual-test-{test_id:04d}"
    start = time.time()
    alerted = False
    
    try:
        # Configure device
        recipients = {
            "device_id": device_id,
            "phone": f"+91{random.randint(6000000000, 9999999999)}",
            "ntfy_topic": f"test-topic-{random.randint(1, 50)}"
        }
        requests.post(f"{BASE_URL}/recipients", json=recipients, timeout=3)
        
        # Set location
        lat, lon = random.choice(LOCATIONS)
        loc_data = {"device_id": device_id, "lat": lat, "lon": lon, "timestamp": datetime.now().isoformat()}
        requests.post(f"{BASE_URL}/location", json=loc_data, timeout=3)
        
        # Execute scenario
        if "normal_walk" in scenario:
            # Normal walking
            sensor = {"device_id": device_id, "x": 0.5, "y": -0.3, "z": 9.9, "timestamp": datetime.now().isoformat()}
            requests.post(f"{BASE_URL}/sensors", json=sensor, timeout=3)
            hb = {"device_id": device_id, "ts": datetime.now().isoformat(), "shield_on": True, "distress": False}
            requests.post(f"{BASE_URL}/heartbeat", json=hb, timeout=3)
            
        elif "normal_run" in scenario:
            # Normal running
            sensor = {"device_id": device_id, "x": 2.1, "y": -1.5, "z": 11.2, "timestamp": datetime.now().isoformat()}
            requests.post(f"{BASE_URL}/sensors", json=sensor, timeout=3)
            hb = {"device_id": device_id, "ts": datetime.now().isoformat(), "shield_on": True, "distress": False}
            requests.post(f"{BASE_URL}/heartbeat", json=hb, timeout=3)
            
        elif "high_g_push" in scenario:
            # Sudden push - high G
            sensor = {"device_id": device_id, "x": 28.5, "y": -15.2, "z": 32.1, "timestamp": datetime.now().isoformat()}
            requests.post(f"{BASE_URL}/sensors", json=sensor, timeout=3)
            alerted = True
            
        elif "high_g_fall" in scenario:
            # Fall/trip - high G
            sensor = {"device_id": device_id, "x": 18.3, "y": -25.7, "z": 40.2, "timestamp": datetime.now().isoformat()}
            requests.post(f"{BASE_URL}/sensors", json=sensor, timeout=3)
            alerted = True
            
        elif "distress_panic" in scenario:
            # Panic breathing
            hb = {"device_id": device_id, "ts": datetime.now().isoformat(), "shield_on": True, "distress": True}
            requests.post(f"{BASE_URL}/heartbeat", json=hb, timeout=3)
            alerted = True
            
        elif "distress_struggle" in scenario:
            # Struggling
            hb = {"device_id": device_id, "ts": datetime.now().isoformat(), "shield_on": True, "distress": True}
            requests.post(f"{BASE_URL}/heartbeat", json=hb, timeout=3)
            alerted = True
            
        elif "manual_sos" in scenario:
            # Manual SOS
            sos = {"device_id": device_id, "lat": lat, "lon": lon, "distress": True, "timestamp": datetime.now().isoformat()}
            requests.post(f"{BASE_URL}/sos?force=true", json=sos, timeout=3)
            alerted = True
            
        elif "combined" in scenario:
            # All triggers
            sensor = {"device_id": device_id, "x": 30.1, "y": -22.5, "z": 38.9, "timestamp": datetime.now().isoformat()}
            requests.post(f"{BASE_URL}/sensors", json=sensor, timeout=3)
            hb = {"device_id": device_id, "ts": datetime.now().isoformat(), "shield_on": True, "distress": True}
            requests.post(f"{BASE_URL}/heartbeat", json=hb, timeout=3)
            sos = {"device_id": device_id, "lat": lat, "lon": lon, "distress": True, "timestamp": datetime.now().isoformat()}
            requests.post(f"{BASE_URL}/sos?force=true", json=sos, timeout=3)
            alerted = True
            
        elif "false_positive" in scenario:
            # Edge cases (below threshold)
            sensor = {"device_id": device_id, "x": 12.5, "y": -8.2, "z": 18.3, "timestamp": datetime.now().isoformat()}
            requests.post(f"{BASE_URL}/sensors", json=sensor, timeout=3)
        
        elapsed = time.time() - start
        with lock:
            results["total"] += 1
            results["success"] += 1
            results["times"].append(elapsed)
            if alerted:
                results["alerts"] += 1
            if scenario not in results["scenarios"]:
                results["scenarios"][scenario] = {"count": 0, "success": 0, "alerts": 0}
            results["scenarios"][scenario]["count"] += 1
            results["scenarios"][scenario]["success"] += 1
            if alerted:
                results["scenarios"][scenario]["alerts"] += 1
        
        return True
        
    except Exception as e:
        elapsed = time.time() - start
        with lock:
            results["total"] += 1
            results["failed"] += 1
            results["times"].append(elapsed)
            if scenario not in results["scenarios"]:
                results["scenarios"][scenario] = {"count": 0, "success": 0, "alerts": 0}
            results["scenarios"][scenario]["count"] += 1
        return False


def main():
    print("=" * 80)
    print("🚨 VAJRA KAVACH - DUAL SITUATION STRESS TEST (2000 CASES)")
    print("=" * 80)
    print()
    
    # Health check
    try:
        resp = requests.get(f"{BASE_URL}/health", timeout=3)
        if resp.status_code == 200:
            print("✅ Backend healthy")
        else:
            print("❌ Backend not healthy!")
            return
    except:
        print("❌ Cannot reach backend!")
        return
    
    print()
    print("📋 12 Dual Scenarios:")
    for idx, (scenario, desc) in enumerate(SCENARIOS, 1):
        print(f"  {idx:2d}. {scenario:25s} - {desc}")
    print()
    
    # Generate 2000 tests with balanced distribution
    test_plan = []
    tests_per_scenario = 2000 // len(SCENARIOS)
    for scenario, desc in SCENARIOS:
        test_plan.extend([(scenario, desc)] * tests_per_scenario)
    
    # Fill remaining
    while len(test_plan) < 2000:
        scenario, desc = random.choice(SCENARIOS)
        test_plan.append((scenario, desc))
    
    random.shuffle(test_plan)
    
    print(f"🚀 Starting {len(test_plan)} tests...")
    print(f"⏰ Start time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()
    
    start_time = time.time()
    
    # Run tests with high concurrency
    with ThreadPoolExecutor(max_workers=100) as executor:
        futures = []
        for idx, (scenario, desc) in enumerate(test_plan, 1):
            future = executor.submit(test_case, idx, scenario, desc)
            futures.append(future)
            
            # Progress updates
            if idx % 100 == 0:
                elapsed = time.time() - start_time
                rate = results["total"] / elapsed if elapsed > 0 else 0
                print(f"⚡ Progress: {results['total']:4d}/2000 ({results['total']/20:.1f}%) | "
                      f"Success: {results['success']:4d} | Failed: {results['failed']:3d} | "
                      f"Rate: {rate:.1f} tests/sec | Alerts: {results['alerts']:4d}")
        
        # Wait for completion
        print()
        print("⏳ Waiting for all tests to complete...")
        for future in as_completed(futures):
            try:
                future.result()
            except:
                pass
    
    end_time = time.time()
    duration = end_time - start_time
    
    # Results
    print()
    print("=" * 80)
    print("📊 TEST RESULTS")
    print("=" * 80)
    print()
    print(f"⏱️  Duration: {duration:.1f}s ({duration/60:.1f} min)")
    print(f"📈 Total Tests: {results['total']}")
    print(f"✅ Successful: {results['success']} ({results['success']/results['total']*100:.1f}%)")
    print(f"❌ Failed: {results['failed']} ({results['failed']/results['total']*100:.1f}%)")
    print(f"🚨 Alerts Triggered: {results['alerts']}")
    print(f"⚡ Throughput: {results['total']/duration:.1f} tests/second")
    print()
    
    if results["times"]:
        print(f"⏱️  Response Times:")
        print(f"  • Average: {statistics.mean(results['times']):.3f}s")
        print(f"  • Median: {statistics.median(results['times']):.3f}s")
        print(f"  • Min: {min(results['times']):.3f}s")
        print(f"  • Max: {max(results['times']):.3f}s")
    print()
    
    print("📋 Results by Scenario:")
    print("-" * 80)
    print(f"{'Scenario':<30} {'Tests':>7} {'Success':>9} {'Alerts':>8}")
    print("-" * 80)
    for scenario, data in sorted(results["scenarios"].items()):
        print(f"{scenario:<30} {data['count']:>7} {data['success']:>9} {data['alerts']:>8}")
    print("-" * 80)
    print()
    
    # Grade
    success_rate = (results['success'] / results['total'] * 100) if results['total'] > 0 else 0
    if success_rate >= 99:
        grade = "🟢 EXCELLENT"
    elif success_rate >= 95:
        grade = "🟡 GOOD"
    elif success_rate >= 90:
        grade = "🟠 FAIR"
    else:
        grade = "🔴 POOR"
    
    print(f"📊 Overall Grade: {grade} ({success_rate:.2f}%)")
    print()
    
    # Save report
    report_file = f"dual_stress_test_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(report_file, 'w') as f:
        json.dump({
            "config": {"total_tests": results['total'], "duration_sec": duration},
            "results": results,
            "timestamp": datetime.now().isoformat()
        }, f, indent=2)
    
    print(f"💾 Report saved: {report_file}")
    print()
    print("=" * 80)
    print("✅ DUAL STRESS TEST COMPLETE")
    print("=" * 80)


if __name__ == "__main__":
    main()
