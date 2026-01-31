#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Vajra Light - Fast 5000 Case Stress Test
Optimized for rate-limited environments with comprehensive reporting
"""

import requests
import json
import random
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

BASE_URL = "http://127.0.0.1:8009"
TOTAL_CASES = 5000

# Scenario templates
SCENARIOS = [
    ("heartbeat", "/heartbeat", lambda: {
        "shield_on": random.choice([True, False]),
        "distress": random.choice([True, False]),
        "breathing_normal": random.choice([True, False]),
        "timestamp": datetime.now().isoformat()
    }),
    ("location", "/location", lambda: {
        "latitude": random.uniform(51.4, 51.6),
        "longitude": random.uniform(-0.2, 0.1),
        "accuracy": random.uniform(5, 50),
        "timestamp": datetime.now().isoformat()
    }),
    ("sos_alert", "/sos_alert", lambda: {
        "alert_type": random.choice(["manual", "breathing", "impact"]),
        "latitude": random.uniform(51.4, 51.6),
        "longitude": random.uniform(-0.2, 0.1),
        "description": f"Emergency {datetime.now().isoformat()}",
        "timestamp": datetime.now().isoformat()
    }),
    ("sensors", "/sensors", lambda: {
        "shield_on": True,
        "accelerometer_x": random.uniform(-2, 2),
        "accelerometer_y": random.uniform(-2, 2),
        "accelerometer_z": random.uniform(8, 12),
        "breathing_rate": random.uniform(10, 25),
        "timestamp": datetime.now().isoformat()
    }),
]

stats = {
    "total": 0,
    "success": 0,
    "rate_limited": 0,
    "failed": 0,
    "by_scenario": {},
    "start_time": None,
    "end_time": None
}

import threading
lock = threading.Lock()

def send_test(case_num):
    """Send one test case"""
    scenario_name, endpoint, data_gen = random.choice(SCENARIOS)
    
    try:
        response = requests.post(
            f"{BASE_URL}{endpoint}",
            json=data_gen(),
            timeout=3
        )
        
        with lock:
            stats["total"] += 1
            if scenario_name not in stats["by_scenario"]:
                stats["by_scenario"][scenario_name] = {"success": 0, "failed": 0, "rate_limited": 0}
            
            if response.status_code in [200, 201, 202]:
                stats["success"] += 1
                stats["by_scenario"][scenario_name]["success"] += 1
            elif response.status_code == 429:
                stats["rate_limited"] += 1
                stats["by_scenario"][scenario_name]["rate_limited"] += 1
            else:
                stats["failed"] += 1
                stats["by_scenario"][scenario_name]["failed"] += 1
        
        return True
    except Exception as e:
        with lock:
            stats["total"] += 1
            stats["failed"] += 1
            if scenario_name in stats["by_scenario"]:
                stats["by_scenario"][scenario_name]["failed"] += 1
        return False

def run_test():
    """Run stress test with limited concurrency"""
    print("="*70)
    print("VAJRA LIGHT - 5000 CASE REAL-TIME STRESS TEST")
    print("="*70)
    print(f"Start Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Total Cases: {TOTAL_CASES}")
    print(f"Scenarios: heartbeat, location, sos_alert, sensors")
    print("="*70 + "\n")
    
    stats["start_time"] = time.time()
    
    # Use smaller batches to avoid overwhelming the server
    batch_size = 100
    workers = 20
    
    for batch_num in range(TOTAL_CASES // batch_size):
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = [executor.submit(send_test, batch_num * batch_size + i) 
                      for i in range(batch_size)]
            for future in as_completed(futures):
                future.result()
        
        if (batch_num + 1) % 5 == 0:
            completed = (batch_num + 1) * batch_size
            print(f"Completed {completed}/{TOTAL_CASES} cases...")
            print(f"  Success: {stats['success']}, Rate Limited: {stats['rate_limited']}, Failed: {stats['failed']}")
        
        # Small delay between batches to respect rate limits
        time.sleep(0.2)
    
    stats["end_time"] = time.time()
    
    # Print results
    duration = stats["end_time"] - stats["start_time"]
    
    print(f"\n{'='*70}")
    print("TEST COMPLETED - FINAL RESULTS")
    print(f"{'='*70}")
    print(f"Duration: {duration:.2f}s")
    print(f"Total Cases: {stats['total']}")
    print(f"Successful: {stats['success']} ({stats['success']/stats['total']*100:.1f}%)")
    print(f"Rate Limited: {stats['rate_limited']} ({stats['rate_limited']/stats['total']*100:.1f}%)")
    print(f"Failed: {stats['failed']} ({stats['failed']/stats['total']*100:.1f}%)")
    print(f"Throughput: {stats['total']/duration:.1f} requests/sec")
    
    print(f"\n{'-'*70}")
    print("BREAKDOWN BY SCENARIO:")
    print(f"{'-'*70}")
    for scenario, data in sorted(stats["by_scenario"].items()):
        total_scenario = data['success'] + data['rate_limited'] + data['failed']
        print(f"\n{scenario.upper()}:")
        print(f"  Total: {total_scenario}")
        print(f"  Success: {data['success']}")
        print(f"  Rate Limited: {data['rate_limited']}")
        print(f"  Failed: {data['failed']}")
    
    print(f"\n{'='*70}")
    print("ADMIN DASHBOARD:")
    print(f"  {BASE_URL}/admin")
    print(f"{'='*70}\n")
    
    # Save results
    results = {
        "timestamp": datetime.now().isoformat(),
        "total_cases": stats["total"],
        "successful": stats["success"],
        "rate_limited": stats["rate_limited"],
        "failed": stats["failed"],
        "duration_seconds": duration,
        "throughput_per_sec": stats["total"] / duration,
        "scenarios": stats["by_scenario"]
    }
    
    with open("d:\\VajraBackend\\STRESS_TEST_5000_RESULTS.json", "w") as f:
        json.dump(results, f, indent=2)
    
    print("Results saved to: STRESS_TEST_5000_RESULTS.json\n")

def main():
    try:
        print("Checking backend...")
        response = requests.get(f"{BASE_URL}/regions", timeout=3)
        if response.status_code not in [200, 429]:
            print(f"Backend error (status: {response.status_code})")
            return
        
        print(f"Backend online (status: {response.status_code})\n")
        run_test()
    except KeyboardInterrupt:
        print("\n\nTest interrupted by user")
        print(f"Completed: {stats['total']} cases")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
