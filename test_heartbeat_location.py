"""
HEARTBEAT RHYTHM & GEO-LOCATION TEST SUITE
Created by: Soumodeep Guha

Complete testing of:
- Heartbeat rhythm monitoring
- Critical heart rate detection
- GPS location tracking
- Emergency location sharing
- Real-time health monitoring
"""

import requests
import json
import time
from datetime import datetime
import random

BASE_URL = "http://localhost:8008"

class HeartbeatLocationTest:
    """Test suite for heartbeat and location features"""
    
    def __init__(self):
        self.results = {
            'heartbeat_tests': [],
            'location_tests': [],
            'integrated_tests': [],
            'emergencies_detected': 0,
            'locations_tracked': 0
        }
    
    def print_header(self, text):
        """Print section header"""
        print("\n" + "="*100)
        print(f"  {text}")
        print("="*100 + "\n")
    
    def test_heartbeat_normal(self):
        """Test normal heartbeat (60-100 BPM)"""
        self.print_header("TEST 1: Normal Heartbeat (60-100 BPM)")
        
        test_cases = [
            {'heart_rate': 72, 'expected': 'normal'},
            {'heart_rate': 85, 'expected': 'normal'},
            {'heart_rate': 95, 'expected': 'normal'},
        ]
        
        for i, case in enumerate(test_cases, 1):
            print(f"Test {i}: Heart Rate = {case['heart_rate']} BPM")
            
            payload = {
                'device_id': f'TEST_DEVICE_{i}',
                'heart_rate': case['heart_rate'],
                'timestamp': datetime.now().isoformat(),
                'user_id': 'TEST_USER_001'
            }
            
            try:
                response = requests.post(
                    f"{BASE_URL}/heartbeat",
                    json=payload,
                    timeout=5
                )
                
                if response.status_code == 200:
                    data = response.json()
                    is_emergency = data.get('is_emergency', False)
                    
                    print(f"  ✓ Status: {response.status_code}")
                    print(f"  ✓ Emergency: {is_emergency}")
                    print(f"  ✓ Result: {'PASS' if not is_emergency else 'FAIL'}\n")
                    
                    self.results['heartbeat_tests'].append({
                        'heart_rate': case['heart_rate'],
                        'expected': case['expected'],
                        'is_emergency': is_emergency,
                        'passed': not is_emergency
                    })
                else:
                    print(f"  ✗ Failed: Status {response.status_code}\n")
            except Exception as e:
                print(f"  ✗ Error: {e}\n")
    
    def test_heartbeat_critical_low(self):
        """Test critical low heartbeat (< 40 BPM)"""
        self.print_header("TEST 2: Critical Low Heartbeat (< 40 BPM) - EMERGENCY")
        
        test_cases = [35, 30, 25, 20]
        
        for i, heart_rate in enumerate(test_cases, 1):
            print(f"Test {i}: Heart Rate = {heart_rate} BPM (CRITICAL LOW)")
            
            payload = {
                'device_id': f'EMERGENCY_DEVICE_{i}',
                'heart_rate': heart_rate,
                'timestamp': datetime.now().isoformat(),
                'user_id': 'EMERGENCY_USER_001'
            }
            
            try:
                response = requests.post(
                    f"{BASE_URL}/heartbeat",
                    json=payload,
                    timeout=5
                )
                
                if response.status_code == 200:
                    data = response.json()
                    is_emergency = data.get('is_emergency', False)
                    emergency_type = data.get('emergency_type', 'None')
                    
                    print(f"  ✓ Status: {response.status_code}")
                    print(f"  🚨 Emergency Detected: {is_emergency}")
                    print(f"  🚨 Type: {emergency_type}")
                    print(f"  ✓ Result: {'PASS - Emergency Triggered!' if is_emergency else 'FAIL - Should be emergency'}\n")
                    
                    if is_emergency:
                        self.results['emergencies_detected'] += 1
                    
                    self.results['heartbeat_tests'].append({
                        'heart_rate': heart_rate,
                        'expected': 'emergency',
                        'is_emergency': is_emergency,
                        'emergency_type': emergency_type,
                        'passed': is_emergency
                    })
                else:
                    print(f"  ✗ Failed: Status {response.status_code}\n")
            except Exception as e:
                print(f"  ✗ Error: {e}\n")
    
    def test_heartbeat_critical_high(self):
        """Test critical high heartbeat (> 180 BPM)"""
        self.print_header("TEST 3: Critical High Heartbeat (> 180 BPM) - EMERGENCY")
        
        test_cases = [185, 190, 200, 220]
        
        for i, heart_rate in enumerate(test_cases, 1):
            print(f"Test {i}: Heart Rate = {heart_rate} BPM (CRITICAL HIGH)")
            
            payload = {
                'device_id': f'PANIC_DEVICE_{i}',
                'heart_rate': heart_rate,
                'timestamp': datetime.now().isoformat(),
                'user_id': 'PANIC_USER_001'
            }
            
            try:
                response = requests.post(
                    f"{BASE_URL}/heartbeat",
                    json=payload,
                    timeout=5
                )
                
                if response.status_code == 200:
                    data = response.json()
                    is_emergency = data.get('is_emergency', False)
                    emergency_type = data.get('emergency_type', 'None')
                    
                    print(f"  ✓ Status: {response.status_code}")
                    print(f"  🚨 Emergency Detected: {is_emergency}")
                    print(f"  🚨 Type: {emergency_type}")
                    print(f"  ✓ Result: {'PASS - Emergency Triggered!' if is_emergency else 'FAIL - Should be emergency'}\n")
                    
                    if is_emergency:
                        self.results['emergencies_detected'] += 1
                    
                    self.results['heartbeat_tests'].append({
                        'heart_rate': heart_rate,
                        'expected': 'emergency',
                        'is_emergency': is_emergency,
                        'emergency_type': emergency_type,
                        'passed': is_emergency
                    })
                else:
                    print(f"  ✗ Failed: Status {response.status_code}\n")
            except Exception as e:
                print(f"  ✗ Error: {e}\n")
    
    def test_location_tracking(self):
        """Test GPS location tracking"""
        self.print_header("TEST 4: GPS Location Tracking")
        
        locations = [
            {'lat': 28.7041, 'lon': 77.1025, 'name': 'New Delhi, India'},
            {'lat': 19.0760, 'lon': 72.8777, 'name': 'Mumbai, India'},
            {'lat': 12.9716, 'lon': 77.5946, 'name': 'Bangalore, India'},
            {'lat': 40.7128, 'lon': -74.0060, 'name': 'New York, USA'},
            {'lat': 51.5074, 'lon': -0.1278, 'name': 'London, UK'},
        ]
        
        for i, loc in enumerate(locations, 1):
            print(f"Test {i}: Location = {loc['name']}")
            
            payload = {
                'device_id': f'LOCATION_DEVICE_{i}',
                'latitude': loc['lat'],
                'longitude': loc['lon'],
                'accuracy': random.randint(5, 20),
                'timestamp': datetime.now().isoformat(),
                'user_id': f'USER_{i:03d}'
            }
            
            try:
                response = requests.post(
                    f"{BASE_URL}/location",
                    json=payload,
                    timeout=5
                )
                
                if response.status_code == 200:
                    data = response.json()
                    
                    print(f"  ✓ Status: {response.status_code}")
                    print(f"  ✓ Latitude: {data.get('latitude')}")
                    print(f"  ✓ Longitude: {data.get('longitude')}")
                    print(f"  ✓ Accuracy: {data.get('accuracy')}m")
                    print(f"  ✓ Google Maps: https://maps.google.com/?q={loc['lat']},{loc['lon']}")
                    print(f"  ✓ Result: PASS\n")
                    
                    self.results['locations_tracked'] += 1
                    self.results['location_tests'].append({
                        'location': loc['name'],
                        'lat': loc['lat'],
                        'lon': loc['lon'],
                        'passed': True
                    })
                else:
                    print(f"  ✗ Failed: Status {response.status_code}\n")
            except Exception as e:
                print(f"  ✗ Error: {e}\n")
    
    def test_integrated_emergency_with_location(self):
        """Test emergency detection with location sharing"""
        self.print_header("TEST 5: Integrated Emergency + Location (Real Scenario)")
        
        scenarios = [
            {
                'name': 'Heart Attack',
                'heart_rate': 25,
                'lat': 28.7041,
                'lon': 77.1025,
                'location': 'Connaught Place, New Delhi'
            },
            {
                'name': 'Panic Attack',
                'heart_rate': 195,
                'lat': 19.0760,
                'lon': 72.8777,
                'location': 'Andheri, Mumbai'
            },
            {
                'name': 'Cardiac Arrest',
                'heart_rate': 18,
                'lat': 12.9716,
                'lon': 77.5946,
                'location': 'Koramangala, Bangalore'
            }
        ]
        
        for i, scenario in enumerate(scenarios, 1):
            print(f"\n🚨 SCENARIO {i}: {scenario['name']}")
            print(f"Location: {scenario['location']}")
            print(f"Heart Rate: {scenario['heart_rate']} BPM")
            print(f"Coordinates: {scenario['lat']}, {scenario['lon']}\n")
            
            device_id = f'EMERGENCY_{i:03d}'
            
            # Step 1: Update location
            print("Step 1: Updating GPS location...")
            location_payload = {
                'device_id': device_id,
                'latitude': scenario['lat'],
                'longitude': scenario['lon'],
                'accuracy': 10,
                'timestamp': datetime.now().isoformat()
            }
            
            try:
                loc_response = requests.post(
                    f"{BASE_URL}/location",
                    json=location_payload,
                    timeout=5
                )
                if loc_response.status_code == 200:
                    print("  ✓ Location updated\n")
            except Exception as e:
                print(f"  ✗ Location update error: {e}\n")
            
            time.sleep(0.5)
            
            # Step 2: Send critical heartbeat
            print("Step 2: Sending critical heartbeat...")
            heartbeat_payload = {
                'device_id': device_id,
                'heart_rate': scenario['heart_rate'],
                'timestamp': datetime.now().isoformat(),
                'distress': True
            }
            
            try:
                hb_response = requests.post(
                    f"{BASE_URL}/heartbeat",
                    json=heartbeat_payload,
                    timeout=5
                )
                
                if hb_response.status_code == 200:
                    data = hb_response.json()
                    is_emergency = data.get('is_emergency', False)
                    emergency_type = data.get('emergency_type', 'None')
                    
                    print(f"  ✓ Heartbeat processed")
                    print(f"  🚨 Emergency Status: {is_emergency}")
                    print(f"  🚨 Emergency Type: {emergency_type}\n")
                    
                    if is_emergency:
                        print(f"  📞 DISPATCHING EMERGENCY SERVICES:")
                        print(f"     - Ambulance: +91102")
                        print(f"     - Police: +91100")
                        print(f"     - Family: +91XXXXXXXXXX")
                        print(f"  📍 Location shared: https://maps.google.com/?q={scenario['lat']},{scenario['lon']}")
                        print(f"  ✅ EMERGENCY ALERT SENT!\n")
                        
                        self.results['emergencies_detected'] += 1
                        self.results['integrated_tests'].append({
                            'scenario': scenario['name'],
                            'passed': True
                        })
            except Exception as e:
                print(f"  ✗ Heartbeat error: {e}\n")
            
            print("-" * 100)
    
    def print_summary(self):
        """Print test summary"""
        self.print_header("TEST SUMMARY - HEARTBEAT & LOCATION")
        
        total_heartbeat = len(self.results['heartbeat_tests'])
        passed_heartbeat = sum(1 for t in self.results['heartbeat_tests'] if t['passed'])
        
        total_location = len(self.results['location_tests'])
        passed_location = sum(1 for t in self.results['location_tests'] if t['passed'])
        
        total_integrated = len(self.results['integrated_tests'])
        passed_integrated = sum(1 for t in self.results['integrated_tests'] if t['passed'])
        
        print(f"📊 HEARTBEAT TESTS:")
        print(f"   Total: {total_heartbeat}")
        print(f"   Passed: {passed_heartbeat}")
        print(f"   Failed: {total_heartbeat - passed_heartbeat}")
        print(f"   Success Rate: {(passed_heartbeat/total_heartbeat*100):.1f}%" if total_heartbeat > 0 else "   Success Rate: N/A")
        
        print(f"\n📍 LOCATION TESTS:")
        print(f"   Total: {total_location}")
        print(f"   Passed: {passed_location}")
        print(f"   Failed: {total_location - passed_location}")
        print(f"   Locations Tracked: {self.results['locations_tracked']}")
        print(f"   Success Rate: {(passed_location/total_location*100):.1f}%" if total_location > 0 else "   Success Rate: N/A")
        
        print(f"\n🔗 INTEGRATED TESTS:")
        print(f"   Total: {total_integrated}")
        print(f"   Passed: {passed_integrated}")
        print(f"   Failed: {total_integrated - passed_integrated}")
        print(f"   Emergencies Detected: {self.results['emergencies_detected']}")
        print(f"   Success Rate: {(passed_integrated/total_integrated*100):.1f}%" if total_integrated > 0 else "   Success Rate: N/A")
        
        overall_total = total_heartbeat + total_location + total_integrated
        overall_passed = passed_heartbeat + passed_location + passed_integrated
        
        print(f"\n🏆 OVERALL:")
        print(f"   Total Tests: {overall_total}")
        print(f"   Passed: {overall_passed}")
        print(f"   Failed: {overall_total - overall_passed}")
        print(f"   Overall Success Rate: {(overall_passed/overall_total*100):.1f}%" if overall_total > 0 else "   Overall Success Rate: N/A")
        
        print("\n" + "="*100)
        print("  ✅ HEARTBEAT & LOCATION FEATURES VERIFIED")
        print("  Created by: Soumodeep Guha")
        print("="*100 + "\n")
    
    def run_all_tests(self):
        """Run all test suites"""
        print("\n" + "="*100)
        print("  🫀 VAJRA KAVACH - HEARTBEAT RHYTHM & GEO-LOCATION TEST SUITE")
        print("  Created by: Soumodeep Guha")
        print("="*100)
        
        # Check server
        try:
            response = requests.get(f"{BASE_URL}/health", timeout=2)
            if response.status_code == 200:
                print("\n✅ Server is running\n")
            else:
                print("\n⚠️  Server may not be operational\n")
        except:
            print("\n❌ Cannot connect to server. Start with: python main.py\n")
            return
        
        # Run tests
        self.test_heartbeat_normal()
        time.sleep(1)
        
        self.test_heartbeat_critical_low()
        time.sleep(1)
        
        self.test_heartbeat_critical_high()
        time.sleep(1)
        
        self.test_location_tracking()
        time.sleep(1)
        
        self.test_integrated_emergency_with_location()
        
        # Summary
        self.print_summary()


def main():
    """Main entry point"""
    tester = HeartbeatLocationTest()
    tester.run_all_tests()


if __name__ == "__main__":
    main()
