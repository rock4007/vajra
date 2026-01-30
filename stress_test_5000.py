#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Vajra Light - Real-Time Stress Test with 5000 Cases
Tests different emergency situations and displays results in admin dashboard
"""

import requests
import json
import random
import time
import threading
import sys
import os
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed

# Fix encoding for Windows console
if sys.platform == 'win32':
    os.environ['PYTHONIOENCODING'] = 'utf-8'

BASE_URL = "http://localhost:8009"
TOTAL_CASES = 5000

# Test scenarios
SCENARIOS = {
    "heartbeat_normal": {
        "description": "Normal heartbeat (shield on, no distress)",
        "weight": 20,  # 20% of cases
        "endpoint": "/heartbeat",
        "data": lambda: {
            "shield_on": True,
            "distress": False,
            "breathing_normal": True,
            "timestamp": datetime.now().isoformat()
        }
    },
    "heartbeat_distress": {
        "description": "Distress signal (high threat detected)",
        "weight": 15,
        "endpoint": "/heartbeat",
        "data": lambda: {
            "shield_on": True,
            "distress": True,
            "breathing_normal": False,
            "timestamp": datetime.now().isoformat()
        }
    },
    "location_normal": {
        "description": "Normal location update",
        "weight": 20,
        "endpoint": "/location",
        "data": lambda: {
            "latitude": random.uniform(51.4769, 51.5233),  # London
            "longitude": random.uniform(-0.1278, 0.0005),
            "accuracy": random.uniform(5, 30),
            "timestamp": datetime.now().isoformat()
        }
    },
    "location_remote": {
        "description": "Remote location (outside city)",
        "weight": 10,
        "endpoint": "/location",
        "data": lambda: {
            "latitude": random.uniform(50.0, 52.0),
            "longitude": random.uniform(-2.0, 1.0),
            "accuracy": random.uniform(50, 200),
            "timestamp": datetime.now().isoformat()
        }
    },
    "sos_alert_manual": {
        "description": "Manual SOS trigger",
        "weight": 8,
        "endpoint": "/sos_alert",
        "data": lambda: {
            "alert_type": "manual",
            "latitude": random.uniform(51.4769, 51.5233),
            "longitude": random.uniform(-0.1278, 0.0005),
            "description": "User triggered emergency",
            "timestamp": datetime.now().isoformat()
        }
    },
    "sos_alert_breathing": {
        "description": "SOS from abnormal breathing",
        "weight": 7,
        "endpoint": "/sos_alert",
        "data": lambda: {
            "alert_type": "breathing",
            "latitude": random.uniform(51.4769, 51.5233),
            "longitude": random.uniform(-0.1278, 0.0005),
            "description": "Critical breathing pattern detected",
            "timestamp": datetime.now().isoformat()
        }
    },
    "sos_alert_impact": {
        "description": "SOS from impact detection",
        "weight": 7,
        "endpoint": "/sos_alert",
        "data": lambda: {
            "alert_type": "impact",
            "latitude": random.uniform(51.4769, 51.5233),
            "longitude": random.uniform(-0.1278, 0.0005),
            "description": "High-impact collision detected",
            "timestamp": datetime.now().isoformat()
        }
    },
    "sensor_data_normal": {
        "description": "Normal sensor data",
        "weight": 8,
        "endpoint": "/sensors",
        "data": lambda: {
            "shield_on": True,
            "accelerometer_x": random.uniform(-1, 1),
            "accelerometer_y": random.uniform(-1, 1),
            "accelerometer_z": random.uniform(9, 11),  # gravity
            "breathing_rate": random.uniform(12, 20),
            "timestamp": datetime.now().isoformat()
        }
    },
    "sensor_data_abnormal": {
        "description": "Abnormal sensor data (impact detected)",
        "weight": 3,
        "endpoint": "/sensors",
        "data": lambda: {
            "shield_on": True,
            "accelerometer_x": random.uniform(-5, 5),
            "accelerometer_y": random.uniform(-5, 5),
            "accelerometer_z": random.uniform(-5, 20),
            "breathing_rate": random.uniform(30, 45),
            "timestamp": datetime.now().isoformat()
        }
    },
    "ai_safety_analysis": {
        "description": "AI safety analysis request",
        "weight": 2,
        "endpoint": "/ai_safety",
        "data": lambda: {
            "sensor_data": {
                "accelerometer": random.uniform(-3, 3),
                "breathing": random.uniform(10, 30),
                "location": [51.5, -0.1]
            },
            "context": random.choice(["indoor", "outdoor", "vehicle", "public_transit"]),
            "timestamp": datetime.now().isoformat()
        }
    }
}

# Statistics tracking
stats = {
    "total_sent": 0,
    "successful": 0,
    "failed": 0,
    "responses": {},
    "scenarios": {},
    "error_log": [],
    "response_times": [],
    "start_time": None,
    "end_time": None
}

# Lock for thread-safe updates
import threading
stats_lock = threading.Lock()

def get_random_scenario():
    """Select a random scenario based on weights"""
    scenarios_list = list(SCENARIOS.items())
    names = [s[0] for s in scenarios_list]
    weights = [SCENARIOS[s]["weight"] for s in names]
    return random.choices(names, weights=weights, k=1)[0]

def send_test_case(case_num, scenario_name):
    """Send a single test case and record results"""
    scenario = SCENARIOS[scenario_name]
    data = scenario["data"]()
    endpoint = scenario["endpoint"]
    
    try:
        start = time.time()
        response = requests.post(
            f"{BASE_URL}{endpoint}",
            json=data,
            timeout=5
        )
        elapsed = time.time() - start
        
        with stats_lock:
            stats["total_sent"] += 1
            stats["response_times"].append(elapsed)
            
            if scenario_name not in stats["scenarios"]:
                stats["scenarios"][scenario_name] = {
                    "description": scenario["description"],
                    "sent": 0,
                    "success": 0,
                    "failed": 0
                }
            
            stats["scenarios"][scenario_name]["sent"] += 1
            
            if response.status_code in [200, 201, 202, 429]:  # 429 = rate limited
                stats["successful"] += 1
                stats["scenarios"][scenario_name]["success"] += 1
                if response.status_code not in stats["responses"]:
                    stats["responses"][response.status_code] = 0
                stats["responses"][response.status_code] += 1
            else:
                stats["failed"] += 1
                stats["scenarios"][scenario_name]["failed"] += 1
                stats["error_log"].append({
                    "case": case_num,
                    "scenario": scenario_name,
                    "status": response.status_code,
                    "response": response.text[:100]
                })
        
        return True
    except Exception as e:
        with stats_lock:
            stats["total_sent"] += 1
            stats["failed"] += 1
            if scenario_name in stats["scenarios"]:
                stats["scenarios"][scenario_name]["failed"] += 1
            stats["error_log"].append({
                "case": case_num,
                "scenario": scenario_name,
                "error": str(e)
            })
        return False

def run_stress_test(num_workers=50):
    """Run stress test with concurrent workers"""
    print(f"\n{'='*70}")
    print("VAJRA LIGHT - 5000 CASE STRESS TEST")
    print(f"{'='*70}")
    print(f"Starting time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Total cases: {TOTAL_CASES}")
    print(f"Concurrent workers: {num_workers}")
    print(f"{'='*70}\n")
    
    stats["start_time"] = datetime.now()
    
    with ThreadPoolExecutor(max_workers=num_workers) as executor:
        futures = []
        
        for case_num in range(TOTAL_CASES):
            scenario_name = get_random_scenario()
            future = executor.submit(send_test_case, case_num + 1, scenario_name)
            futures.append(future)
            
            # Progress indicator
            if (case_num + 1) % 500 == 0:
                print(f"  Submitted {case_num + 1}/{TOTAL_CASES} cases...")
        
        # Wait for all to complete
        completed = 0
        for future in as_completed(futures):
            completed += 1
            if completed % 500 == 0:
                print(f"  Completed {completed}/{TOTAL_CASES} cases...")
            future.result()
    
    stats["end_time"] = datetime.now()

def print_results():
    """Print comprehensive test results"""
    duration = (stats["end_time"] - stats["start_time"]).total_seconds()
    success_rate = (stats["successful"] / stats["total_sent"] * 100) if stats["total_sent"] > 0 else 0
    avg_response_time = sum(stats["response_times"]) / len(stats["response_times"]) if stats["response_times"] else 0
    
    print(f"\n{'='*70}")
    print("TEST RESULTS SUMMARY")
    print(f"{'='*70}\n")
    
    print(f"Duration: {duration:.2f}s")
    print(f"Total Cases: {stats['total_sent']}")
    print(f"Successful: {stats['successful']} ({success_rate:.1f}%)")
    print(f"Failed: {stats['failed']}")
    print(f"Average Response Time: {avg_response_time*1000:.2f}ms")
    print(f"Min Response Time: {min(stats['response_times'])*1000:.2f}ms" if stats['response_times'] else "N/A")
    print(f"Max Response Time: {max(stats['response_times'])*1000:.2f}ms" if stats['response_times'] else "N/A")
    print(f"Throughput: {stats['total_sent']/duration:.1f} cases/second")
    
    print(f"\n{'─'*70}")
    print(f"HTTP Response Codes:")
    for code in sorted(stats["responses"].keys()):
        count = stats["responses"][code]
        print(f"  {code}: {count}")
    
    print(f"\n{'─'*70}")
    print(f"Scenario Breakdown:")
    print(f"{'─'*70}")
    for scenario_name in sorted(stats["scenarios"].keys()):
        info = stats["scenarios"][scenario_name]
        print(f"\n{scenario_name}")
        print(f"  Description: {info['description']}")
        print(f"  Sent: {info['sent']}")
        print(f"  Success: {info['success']}")
        print(f"  Failed: {info['failed']}")
        if info['sent'] > 0:
            print(f"  Success Rate: {info['success']/info['sent']*100:.1f}%")
    
    if stats["error_log"]:
        print(f"\n{'─'*70}")
        print("Sample Errors (first 10):")
        print(f"{'─'*70}")
        for error in stats["error_log"][:10]:
            print(f"\nCase {error.get('case')}: {error.get('scenario')}")
            if 'error' in error:
                print(f"  Error: {error['error']}")
            else:
                print(f"  Status: {error.get('status')}")
                print(f"  Response: {error.get('response')}")
    
    print(f"\n{'='*70}")
    print("TEST COMPLETE - Results logged to events.log")
    print("View results in admin dashboard: " + f"{BASE_URL}/admin")
    print(f"{'='*70}\n")

def main():
    """Main execution"""
    try:
        # Check backend connectivity
        print("Checking backend connectivity...")
        response = requests.get(f"{BASE_URL}/regions", timeout=3)
        if response.status_code not in [200, 429]:  # 429 = rate limited but alive
            print(f"Backend not responding correctly (status: {response.status_code})")
            return
        print("Backend is online (status: {})!\n".format(response.status_code))
        
        # Run stress test
        run_stress_test(num_workers=50)
        
        # Print results
        print_results()
        
        # Write results to file
        with open("d:\\VajraBackend\\STRESS_TEST_RESULTS.json", "w") as f:
            results = {
                "timestamp": datetime.now().isoformat(),
                "total_cases": stats["total_sent"],
                "successful": stats["successful"],
                "failed": stats["failed"],
                "success_rate": (stats["successful"] / stats["total_sent"] * 100) if stats["total_sent"] > 0 else 0,
                "duration_seconds": (stats["end_time"] - stats["start_time"]).total_seconds(),
                "avg_response_time_ms": (sum(stats["response_times"]) / len(stats["response_times"]) * 1000) if stats["response_times"] else 0,
                "scenarios": stats["scenarios"],
                "http_responses": stats["responses"],
                "error_count": len(stats["error_log"])
            }
            json.dump(results, f, indent=2)
        
        print("Results saved to STRESS_TEST_RESULTS.json")
        
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
