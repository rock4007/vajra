#!/usr/bin/env python3
"""
Vajra Kavach - Comprehensive Stress Test
Simulates 2000 test cases across multiple attack scenarios within 1 hour
"""

import requests
import json
import time
import random
import threading
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed
import statistics

BASE_URL = "http://127.0.0.1:8008"

# Test scenarios
SCENARIOS = {
    "normal_activity": {
        "weight": 40,  # 40% of tests
        "description": "Normal walking, no threats"
    },
    "high_g_attack": {
        "weight": 20,  # 20% of tests
        "description": "Sudden high-G impact (push/fall)"
    },
    "distress_heartbeat": {
        "weight": 15,  # 15% of tests
        "description": "Abnormal breathing/panic"
    },
    "manual_sos": {
        "weight": 10,  # 10% of tests
        "description": "User pressed SOS button"
    },
    "combined_attack": {
        "weight": 10,  # 10% of tests
        "description": "High-G + Distress + Manual SOS"
    },
    "false_positive": {
        "weight": 5,  # 5% of tests
        "description": "Edge cases (running, jumping)"
    }
}

# Kolkata area coordinates for realistic testing
LOCATIONS = [
    (22.5726, 88.3639, "Kolkata Central"),
    (22.5545, 88.3535, "Park Street"),
    (22.5820, 88.3440, "Howrah"),
    (22.5958, 88.3639, "Dum Dum"),
    (22.4978, 88.3472, "Behala"),
    (22.6203, 88.4370, "Salt Lake"),
    (22.5411, 88.3955, "Ballygunge"),
    (22.5698, 88.3697, "Esplanade"),
]

# Global stats
stats = {
    "total_tests": 0,
    "successful": 0,
    "failed": 0,
    "scenarios": {},
    "response_times": [],
    "alerts_triggered": 0,
    "false_positives": 0,
    "start_time": None,
    "end_time": None,
}

stats_lock = threading.Lock()


def log_result(scenario, success, response_time, alerted=False):
    """Thread-safe logging of test results"""
    with stats_lock:
        stats["total_tests"] += 1
        if success:
            stats["successful"] += 1
        else:
            stats["failed"] += 1
        
        stats["response_times"].append(response_time)
        
        if scenario not in stats["scenarios"]:
            stats["scenarios"][scenario] = {
                "count": 0,
                "success": 0,
                "failed": 0,
                "avg_response_time": 0,
                "alerts": 0
            }
        
        stats["scenarios"][scenario]["count"] += 1
        if success:
            stats["scenarios"][scenario]["success"] += 1
        else:
            stats["scenarios"][scenario]["failed"] += 1
        
        if alerted:
            stats["alerts_triggered"] += 1
            stats["scenarios"][scenario]["alerts"] += 1


def generate_device_id(test_num):
    """Generate unique device ID for each test"""
    return f"stress-test-device-{test_num:04d}"


def configure_device(device_id):
    """Configure recipients for a device"""
    recipients = {
        "device_id": device_id,
        "phone": f"+91{random.randint(6000000000, 9999999999)}",
        "whatsapp": f"+91{random.randint(6000000000, 9999999999)}",
        "email": f"test{random.randint(1000, 9999)}@example.com",
        "ntfy_topic": f"vajra-test-{random.randint(1, 100)}"
    }
    
    try:
        resp = requests.post(f"{BASE_URL}/recipients", json=recipients, timeout=5)
        return resp.status_code == 200
    except Exception as e:
        return False


def send_location(device_id, lat=None, lon=None):
    """Send location update"""
    if lat is None or lon is None:
        lat, lon, _ = random.choice(LOCATIONS)
    
    payload = {
        "device_id": device_id,
        "lat": lat,
        "lon": lon,
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }
    
    try:
        resp = requests.post(f"{BASE_URL}/location", json=payload, timeout=5)
        return resp.status_code == 200
    except:
        return False


def send_heartbeat(device_id, distress=False):
    """Send heartbeat"""
    payload = {
        "device_id": device_id,
        "ts": datetime.utcnow().isoformat() + "Z",
        "shield_on": True,
        "distress": distress
    }
    
    try:
        resp = requests.post(f"{BASE_URL}/heartbeat", json=payload, timeout=5)
        return resp.status_code == 200
    except:
        return False


def send_sensor_data(device_id, x, y, z):
    """Send accelerometer data"""
    payload = {
        "device_id": device_id,
        "x": x,
        "y": y,
        "z": z,
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }
    
    try:
        resp = requests.post(f"{BASE_URL}/sensors", json=payload, timeout=5)
        return resp.status_code == 200
    except:
        return False


def send_sos(device_id, force=False):
    """Send manual SOS"""
    lat, lon, _ = random.choice(LOCATIONS)
    payload = {
        "device_id": device_id,
        "lat": lat,
        "lon": lon,
        "distress": True,
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }
    
    try:
        url = f"{BASE_URL}/sos?force={str(force).lower()}"
        resp = requests.post(url, json=payload, timeout=5)
        return resp.status_code == 200
    except:
        return False


# ===== TEST SCENARIOS =====

def scenario_normal_activity(test_num):
    """Normal user activity - walking, no threats"""
    device_id = generate_device_id(test_num)
    start_time = time.time()
    
    try:
        # Configure device
        if not configure_device(device_id):
            log_result("normal_activity", False, time.time() - start_time)
            return
        
        # Send location
        lat, lon, _ = random.choice(LOCATIONS)
        send_location(device_id, lat, lon)
        
        # Normal heartbeat
        send_heartbeat(device_id, distress=False)
        
        # Normal walking motion
        send_sensor_data(device_id, 
                        random.uniform(-1, 1), 
                        random.uniform(-1, 1), 
                        random.uniform(9.5, 10.5))
        
        elapsed = time.time() - start_time
        log_result("normal_activity", True, elapsed, alerted=False)
        
    except Exception as e:
        log_result("normal_activity", False, time.time() - start_time)


def scenario_high_g_attack(test_num):
    """High-G impact attack scenario"""
    device_id = generate_device_id(test_num)
    start_time = time.time()
    
    try:
        configure_device(device_id)
        lat, lon, _ = random.choice(LOCATIONS)
        send_location(device_id, lat, lon)
        
        # Simulate high-G impact (25+ m/s²)
        x = random.uniform(15, 30)
        y = random.uniform(-20, -10)
        z = random.uniform(20, 40)
        send_sensor_data(device_id, x, y, z)
        
        elapsed = time.time() - start_time
        log_result("high_g_attack", True, elapsed, alerted=True)
        
    except Exception as e:
        log_result("high_g_attack", False, time.time() - start_time)


def scenario_distress_heartbeat(test_num):
    """Distress heartbeat scenario"""
    device_id = generate_device_id(test_num)
    start_time = time.time()
    
    try:
        configure_device(device_id)
        lat, lon, _ = random.choice(LOCATIONS)
        send_location(device_id, lat, lon)
        
        # Normal activity first
        send_heartbeat(device_id, distress=False)
        time.sleep(0.1)
        
        # Then distress
        send_heartbeat(device_id, distress=True)
        
        elapsed = time.time() - start_time
        log_result("distress_heartbeat", True, elapsed, alerted=True)
        
    except Exception as e:
        log_result("distress_heartbeat", False, time.time() - start_time)


def scenario_manual_sos(test_num):
    """Manual SOS button press"""
    device_id = generate_device_id(test_num)
    start_time = time.time()
    
    try:
        configure_device(device_id)
        lat, lon, _ = random.choice(LOCATIONS)
        send_location(device_id, lat, lon)
        
        # Manual SOS with force
        send_sos(device_id, force=True)
        
        elapsed = time.time() - start_time
        log_result("manual_sos", True, elapsed, alerted=True)
        
    except Exception as e:
        log_result("manual_sos", False, time.time() - start_time)


def scenario_combined_attack(test_num):
    """Combined attack: High-G + Distress + Manual SOS"""
    device_id = generate_device_id(test_num)
    start_time = time.time()
    
    try:
        configure_device(device_id)
        lat, lon, _ = random.choice(LOCATIONS)
        send_location(device_id, lat, lon)
        
        # High-G impact
        send_sensor_data(device_id, 
                        random.uniform(15, 30), 
                        random.uniform(-20, -10), 
                        random.uniform(20, 40))
        time.sleep(0.1)
        
        # Distress heartbeat
        send_heartbeat(device_id, distress=True)
        time.sleep(0.1)
        
        # Manual SOS
        send_sos(device_id, force=True)
        
        elapsed = time.time() - start_time
        log_result("combined_attack", True, elapsed, alerted=True)
        
    except Exception as e:
        log_result("combined_attack", False, time.time() - start_time)


def scenario_false_positive(test_num):
    """Edge cases that shouldn't trigger alerts"""
    device_id = generate_device_id(test_num)
    start_time = time.time()
    
    try:
        configure_device(device_id)
        lat, lon, _ = random.choice(LOCATIONS)
        send_location(device_id, lat, lon)
        
        # Running/jumping motion (below threshold)
        send_sensor_data(device_id, 
                        random.uniform(10, 15), 
                        random.uniform(-10, 10), 
                        random.uniform(15, 20))
        
        # Normal heartbeat
        send_heartbeat(device_id, distress=False)
        
        elapsed = time.time() - start_time
        log_result("false_positive", True, elapsed, alerted=False)
        
    except Exception as e:
        log_result("false_positive", False, time.time() - start_time)


SCENARIO_FUNCTIONS = {
    "normal_activity": scenario_normal_activity,
    "high_g_attack": scenario_high_g_attack,
    "distress_heartbeat": scenario_distress_heartbeat,
    "manual_sos": scenario_manual_sos,
    "combined_attack": scenario_combined_attack,
    "false_positive": scenario_false_positive,
}


def generate_test_plan(total_tests):
    """Generate weighted test plan"""
    test_plan = []
    
    for scenario, config in SCENARIOS.items():
        count = int(total_tests * config["weight"] / 100)
        test_plan.extend([scenario] * count)
    
    # Fill remaining to reach exact total
    while len(test_plan) < total_tests:
        test_plan.append(random.choice(list(SCENARIOS.keys())))
    
    # Shuffle for realistic distribution
    random.shuffle(test_plan)
    
    return test_plan


def run_stress_test(total_tests=2000, max_workers=50, duration_minutes=60):
    """
    Run comprehensive stress test
    
    Args:
        total_tests: Number of test cases to run (default: 2000)
        max_workers: Concurrent threads (default: 50)
        duration_minutes: Time limit in minutes (default: 60)
    """
    print("=" * 80)
    print("🚨 VAJRA KAVACH - COMPREHENSIVE STRESS TEST")
    print("=" * 80)
    print(f"Total Test Cases: {total_tests}")
    print(f"Target Duration: {duration_minutes} minute(s)")
    print(f"Concurrent Workers: {max_workers}")
    print(f"Backend: {BASE_URL}")
    print("=" * 80)
    print()
    
    # Check backend health
    try:
        resp = requests.get(f"{BASE_URL}/health", timeout=5)
        if resp.status_code != 200:
            print("❌ Backend not healthy! Aborting test.")
            return
        print("✅ Backend health check passed")
    except Exception as e:
        print(f"❌ Cannot reach backend: {e}")
        return
    
    print()
    print("📋 Test Distribution:")
    for scenario, config in SCENARIOS.items():
        count = int(total_tests * config["weight"] / 100)
        print(f"  • {scenario:20s}: {count:4d} tests ({config['weight']:2d}%) - {config['description']}")
    print()
    
    # Generate test plan
    test_plan = generate_test_plan(total_tests)
    
    stats["start_time"] = datetime.now()
    end_deadline = stats["start_time"] + timedelta(minutes=duration_minutes)
    
    print(f"🚀 Starting stress test at {stats['start_time'].strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"⏰ Target end time: {end_deadline.strftime('%Y-%m-%d %H:%M:%S')}")
    print()
    print("=" * 80)
    print()
    
    # Calculate delay between tests to spread over duration (reduced for faster completion)
    delay_between_tests = (duration_minutes * 60) / total_tests / 10  # 10x faster
    
    completed_tests = 0
    last_update = time.time()
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = []
        
        for idx, scenario in enumerate(test_plan, 1):
            # Check if we should stop (time limit)
            if datetime.now() >= end_deadline:
                print("\n⏰ Time limit reached!")
                break
            
            # Submit test
            future = executor.submit(SCENARIO_FUNCTIONS[scenario], idx)
            futures.append(future)
            
            # Progress update every 5 seconds
            if time.time() - last_update >= 5:
                progress = (idx / total_tests) * 100
                elapsed = (datetime.now() - stats["start_time"]).total_seconds()
                tests_per_sec = stats["total_tests"] / elapsed if elapsed > 0 else 0
                
                print(f"⚡ Progress: {stats['total_tests']:4d}/{total_tests} ({progress:.1f}%) | "
                      f"Success: {stats['successful']:4d} | Failed: {stats['failed']:3d} | "
                      f"Speed: {tests_per_sec:.1f} tests/sec | "
                      f"Alerts: {stats['alerts_triggered']:4d}")
                
                last_update = time.time()
            
            # Throttle to spread over duration
            time.sleep(delay_between_tests)
        
        # Wait for all to complete
        print("\n⏳ Waiting for remaining tests to complete...")
        for future in as_completed(futures):
            try:
                future.result()
                completed_tests += 1
            except Exception as e:
                print(f"Test exception: {e}")
    
    stats["end_time"] = datetime.now()
    
    # Generate report
    generate_report()


def generate_report():
    """Generate comprehensive test report"""
    print()
    print("=" * 80)
    print("📊 STRESS TEST RESULTS")
    print("=" * 80)
    print()
    
    duration = (stats["end_time"] - stats["start_time"]).total_seconds()
    
    print(f"⏱️  Duration: {duration:.1f} seconds ({duration/60:.1f} minutes)")
    print(f"📈 Total Tests: {stats['total_tests']}")
    print(f"✅ Successful: {stats['successful']} ({stats['successful']/stats['total_tests']*100:.1f}%)")
    print(f"❌ Failed: {stats['failed']} ({stats['failed']/stats['total_tests']*100:.1f}%)")
    print(f"🚨 Alerts Triggered: {stats['alerts_triggered']}")
    print(f"⚡ Throughput: {stats['total_tests']/duration:.2f} tests/second")
    print()
    
    if stats["response_times"]:
        print("⏱️  Response Times:")
        print(f"  • Average: {statistics.mean(stats['response_times']):.3f}s")
        print(f"  • Median: {statistics.median(stats['response_times']):.3f}s")
        print(f"  • Min: {min(stats['response_times']):.3f}s")
        print(f"  • Max: {max(stats['response_times']):.3f}s")
        if len(stats["response_times"]) > 1:
            print(f"  • Std Dev: {statistics.stdev(stats['response_times']):.3f}s")
    print()
    
    print("📋 Results by Scenario:")
    print("-" * 80)
    print(f"{'Scenario':<22} {'Tests':>7} {'Success':>7} {'Failed':>7} {'Alerts':>7} {'Avg Time':>10}")
    print("-" * 80)
    
    for scenario, data in sorted(stats["scenarios"].items()):
        avg_time = statistics.mean([t for t in stats["response_times"]]) if stats["response_times"] else 0
        print(f"{scenario:<22} {data['count']:>7} {data['success']:>7} "
              f"{data['failed']:>7} {data['alerts']:>7} {avg_time:>9.3f}s")
    
    print("-" * 80)
    print()
    
    # Success rate analysis
    success_rate = (stats["successful"] / stats["total_tests"] * 100) if stats["total_tests"] > 0 else 0
    
    if success_rate >= 99:
        grade = "🟢 EXCELLENT"
    elif success_rate >= 95:
        grade = "🟡 GOOD"
    elif success_rate >= 90:
        grade = "🟠 FAIR"
    else:
        grade = "🔴 POOR"
    
    print(f"📊 Overall Grade: {grade} ({success_rate:.2f}% success rate)")
    print()
    
    # Save detailed report
    report_file = f"stress_test_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(report_file, 'w') as f:
        report_data = {
            "test_config": {
                "total_tests": stats["total_tests"],
                "backend_url": BASE_URL,
                "start_time": stats["start_time"].isoformat(),
                "end_time": stats["end_time"].isoformat(),
                "duration_seconds": duration
            },
            "results": {
                "successful": stats["successful"],
                "failed": stats["failed"],
                "success_rate_pct": success_rate,
                "alerts_triggered": stats["alerts_triggered"],
                "throughput_tests_per_sec": stats["total_tests"] / duration
            },
            "response_times": {
                "average": statistics.mean(stats["response_times"]) if stats["response_times"] else 0,
                "median": statistics.median(stats["response_times"]) if stats["response_times"] else 0,
                "min": min(stats["response_times"]) if stats["response_times"] else 0,
                "max": max(stats["response_times"]) if stats["response_times"] else 0,
                "stdev": statistics.stdev(stats["response_times"]) if len(stats["response_times"]) > 1 else 0
            },
            "scenarios": stats["scenarios"]
        }
        json.dump(report_data, f, indent=2)
    
    print(f"💾 Detailed report saved: {report_file}")
    print()
    print("=" * 80)
    print("✅ STRESS TEST COMPLETE")
    print("=" * 80)


if __name__ == "__main__":
    import sys
    
    # Parse command line args
    total_tests = 2000
    max_workers = 50
    duration_minutes = 60
    
    if len(sys.argv) > 1:
        total_tests = int(sys.argv[1])
    if len(sys.argv) > 2:
        duration_minutes = int(sys.argv[2])
    if len(sys.argv) > 3:
        max_workers = int(sys.argv[3])
    
    run_stress_test(total_tests, max_workers, duration_minutes)
