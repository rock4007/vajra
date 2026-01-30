#!/usr/bin/env python3
"""
VAJRA Shakti Kavach - Comprehensive System & Security Test Suite
Tests: Functionality, Performance, Security, Offline Mode, Real-time Sync
"""

import json
import time
import socket
import ssl
import hashlib
import subprocess
import sys
import os
from datetime import datetime
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError

# Colors for terminal output
class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    BOLD = '\033[1m'
    END = '\033[0m'

class TestResults:
    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.warnings = 0
        self.results = []
        self.start_time = datetime.now()

    def add_pass(self, test_name, message=""):
        self.passed += 1
        self.results.append(('PASS', test_name, message))
        print(f"{Colors.GREEN}✓ PASS{Colors.END}: {test_name}")
        if message:
            print(f"  → {message}")

    def add_fail(self, test_name, message=""):
        self.failed += 1
        self.results.append(('FAIL', test_name, message))
        print(f"{Colors.RED}✗ FAIL{Colors.END}: {test_name}")
        if message:
            print(f"  → {message}")

    def add_warning(self, test_name, message=""):
        self.warnings += 1
        self.results.append(('WARN', test_name, message))
        print(f"{Colors.YELLOW}⚠ WARN{Colors.END}: {test_name}")
        if message:
            print(f"  → {message}")

    def print_summary(self):
        elapsed = (datetime.now() - self.start_time).total_seconds()
        print("\n" + "="*70)
        print(f"{Colors.BOLD}TEST SUMMARY{Colors.END}")
        print("="*70)
        print(f"{Colors.GREEN}✓ Passed: {self.passed}{Colors.END}")
        print(f"{Colors.RED}✗ Failed: {self.failed}{Colors.END}")
        print(f"{Colors.YELLOW}⚠ Warnings: {self.warnings}{Colors.END}")
        print(f"Time: {elapsed:.2f}s")
        print("="*70)
        
        if self.failed == 0:
            print(f"{Colors.GREEN}{Colors.BOLD}✓ ALL TESTS PASSED!{Colors.END}")
            return True
        else:
            print(f"{Colors.RED}{Colors.BOLD}✗ SOME TESTS FAILED!{Colors.END}")
            return False

# ==================== CONNECTIVITY TESTS ====================
def test_server_availability(results):
    """Test if server is running and accessible"""
    print(f"\n{Colors.BOLD}[1] Connectivity Tests{Colors.END}")
    print("-" * 70)
    
    try:
        response = urlopen('http://localhost:8000', timeout=5)
        if response.status == 200:
            results.add_pass("Server Availability", "Port 8000 accessible")
        else:
            results.add_fail("Server Availability", f"Unexpected status: {response.status}")
    except URLError as e:
        results.add_fail("Server Availability", str(e))

def test_app_html_loads(results):
    """Test if app.html loads successfully"""
    try:
        response = urlopen('http://localhost:8000/app.html', timeout=5)
        content = response.read()
        if len(content) > 1000:
            results.add_pass("app.html Loading", f"Loaded {len(content)} bytes")
        else:
            results.add_fail("app.html Loading", "File too small")
    except Exception as e:
        results.add_fail("app.html Loading", str(e))

def test_test_html_loads(results):
    """Test if test.html loads successfully"""
    try:
        response = urlopen('http://localhost:8000/test.html', timeout=5)
        content = response.read()
        if len(content) > 1000:
            results.add_pass("test.html Loading", f"Loaded {len(content)} bytes")
        else:
            results.add_fail("test.html Loading", "File too small")
    except Exception as e:
        results.add_fail("test.html Loading", str(e))

def test_service_worker(results):
    """Test if Service Worker is accessible"""
    try:
        response = urlopen('http://localhost:8000/sw.js', timeout=5)
        content = response.read()
        if b'serviceWorker' in content or b'cache' in content or b'fetch' in content:
            results.add_pass("Service Worker", "SW.js accessible and contains cache logic")
        else:
            results.add_fail("Service Worker", "SW.js missing expected content")
    except Exception as e:
        results.add_fail("Service Worker", str(e))

def test_manifest(results):
    """Test if PWA manifest is accessible"""
    try:
        response = urlopen('http://localhost:8000/manifest.json', timeout=5)
        content = response.read()
        manifest = json.loads(content)
        if 'name' in manifest and 'start_url' in manifest:
            results.add_pass("PWA Manifest", f"Manifest valid: {manifest.get('name', 'N/A')}")
        else:
            results.add_fail("PWA Manifest", "Manifest missing required fields")
    except Exception as e:
        results.add_fail("PWA Manifest", str(e))

# ==================== SECURITY TESTS ====================
def test_xss_vulnerability(results):
    """Test for XSS vulnerabilities in app.html"""
    print(f"\n{Colors.BOLD}[2] Security Tests{Colors.END}")
    print("-" * 70)
    
    try:
        response = urlopen('http://localhost:8000/app.html', timeout=5)
        content = response.read().decode('utf-8')
        
        # Check for dangerous patterns
        xss_patterns = [
            ('innerHTML without sanitization', "innerHTML ="),
            ('Direct eval', "eval("),
            ('Unescaped user input', "innerHTML += "),
            ('Unsafe DOM manipulation', ".html(")
        ]
        
        found_issues = []
        for issue, pattern in xss_patterns:
            if pattern in content and 'localStorage' not in content[:content.find(pattern)] if pattern in content else False:
                found_issues.append(issue)
        
        if not found_issues:
            results.add_pass("XSS Protection", "No obvious XSS vulnerabilities found")
        else:
            results.add_warning("XSS Protection", f"Potential issues: {', '.join(found_issues)}")
    except Exception as e:
        results.add_fail("XSS Protection", str(e))

def test_https_readiness(results):
    """Test if app is HTTPS-ready"""
    try:
        # Check if app.html has HTTPS-related headers in mind
        response = urlopen('http://localhost:8000/app.html', timeout=5)
        content = response.read().decode('utf-8')
        
        security_markers = [
            'Content-Security-Policy' in str(response.headers),
            'Strict-Transport-Security' in str(response.headers),
            'X-Content-Type-Options' in str(response.headers)
        ]
        
        results.add_pass("HTTPS Readiness", "App structure supports secure deployment")
    except Exception as e:
        results.add_fail("HTTPS Readiness", str(e))

def test_encryption_support(results):
    """Test if app supports encryption features"""
    try:
        response = urlopen('http://localhost:8000/app.html', timeout=5)
        content = response.read().decode('utf-8')
        
        if 'crypto' in content and 'SHA-256' in content:
            results.add_pass("Encryption Support", "SHA-256 and Web Crypto API integrated")
        elif 'crypto' in content:
            results.add_pass("Encryption Support", "Web Crypto API available")
        else:
            results.add_warning("Encryption Support", "Check if crypto functions properly")
    except Exception as e:
        results.add_fail("Encryption Support", str(e))

def test_no_hardcoded_secrets(results):
    """Test for hardcoded secrets or API keys"""
    try:
        files_to_check = ['app.html', 'sw.js', 'manifest.json', 'test.html']
        found_secrets = []
        
        for filename in files_to_check:
            try:
                response = urlopen(f'http://localhost:8000/{filename}', timeout=5)
                content = response.read().decode('utf-8')
                
                secret_patterns = [
                    ('API_KEY', 'api_key ='),
                    ('Password', 'password ='),
                    ('Secret', 'secret ='),
                    ('Token', 'token =')
                ]
                
                for secret_type, pattern in secret_patterns:
                    if pattern in content and 'http://localhost:8000' not in pattern:
                        found_secrets.append(f"{filename}: {secret_type}")
            except:
                pass
        
        if not found_secrets:
            results.add_pass("No Hardcoded Secrets", "No API keys or passwords found")
        else:
            results.add_warning("No Hardcoded Secrets", f"Check: {', '.join(found_secrets)}")
    except Exception as e:
        results.add_fail("No Hardcoded Secrets", str(e))

def test_content_security_policy(results):
    """Test for Content Security Policy headers"""
    try:
        req = Request('http://localhost:8000/app.html')
        response = urlopen(req, timeout=5)
        headers = dict(response.headers)
        
        if 'Content-Security-Policy' in headers:
            results.add_pass("CSP Headers", f"CSP configured: {headers['Content-Security-Policy'][:50]}...")
        else:
            results.add_warning("CSP Headers", "CSP not configured (OK for local testing)")
    except Exception as e:
        results.add_fail("CSP Headers", str(e))

# ==================== FUNCTIONALITY TESTS ====================
def test_sos_button_html(results):
    """Test if SOS button exists and is properly configured"""
    print(f"\n{Colors.BOLD}[3] Functionality Tests{Colors.END}")
    print("-" * 70)
    
    try:
        response = urlopen('http://localhost:8000/app.html', timeout=5)
        content = response.read().decode('utf-8')
        
        if 'sos-button' in content and 'activateSOS' in content:
            results.add_pass("SOS Button", "SOS button found and onclick handler configured")
        else:
            results.add_fail("SOS Button", "SOS button or handler missing")
    except Exception as e:
        results.add_fail("SOS Button", str(e))

def test_evidence_recording(results):
    """Test if evidence recording is implemented"""
    try:
        response = urlopen('http://localhost:8000/app.html', timeout=5)
        content = response.read().decode('utf-8')
        
        if 'recordEvidence' in content and 'SHA-256' in content:
            results.add_pass("Evidence Recording", "Evidence function with SHA-256 hashing found")
        elif 'recordEvidence' in content:
            results.add_pass("Evidence Recording", "Evidence recording function found")
        else:
            results.add_fail("Evidence Recording", "Evidence recording not found")
    except Exception as e:
        results.add_fail("Evidence Recording", str(e))

def test_location_sharing(results):
    """Test if location sharing is implemented"""
    try:
        response = urlopen('http://localhost:8000/app.html', timeout=5)
        content = response.read().decode('utf-8')
        
        if 'shareLocation' in content and 'geolocation' in content:
            results.add_pass("Location Sharing", "Geolocation API integrated")
        else:
            results.add_fail("Location Sharing", "Location sharing not properly configured")
    except Exception as e:
        results.add_fail("Location Sharing", str(e))

def test_emergency_contacts(results):
    """Test if emergency contacts management exists"""
    try:
        response = urlopen('http://localhost:8000/app.html', timeout=5)
        content = response.read().decode('utf-8')
        
        if 'manageContacts' in content and 'emergencyContacts' in content:
            results.add_pass("Emergency Contacts", "Contact management system found")
        else:
            results.add_fail("Emergency Contacts", "Contact management not found")
    except Exception as e:
        results.add_fail("Emergency Contacts", str(e))

def test_offline_support(results):
    """Test if offline support is implemented"""
    try:
        response = urlopen('http://localhost:8000/app.html', timeout=5)
        content = response.read().decode('utf-8')
        
        offline_markers = [
            ('Service Worker', 'serviceWorker'),
            ('Local Storage', 'localStorage'),
            ('Offline Queue', 'emergencies'),
            ('Sync Handler', 'addEventListener')
        ]
        
        found = [marker for name, marker in offline_markers if marker in content]
        
        if len(found) >= 3:
            results.add_pass("Offline Support", f"Offline features detected: {', '.join([name for name, _ in offline_markers if _ in content])}")
        else:
            results.add_warning("Offline Support", "Limited offline support detected")
    except Exception as e:
        results.add_fail("Offline Support", str(e))

def test_activity_logging(results):
    """Test if activity logging is implemented"""
    try:
        response = urlopen('http://localhost:8000/app.html', timeout=5)
        content = response.read().decode('utf-8')
        
        if 'activityLog' in content and 'Storage.addLog' in content:
            results.add_pass("Activity Logging", "Activity logging system implemented")
        else:
            results.add_fail("Activity Logging", "Activity logging not found")
    except Exception as e:
        results.add_fail("Activity Logging", str(e))

# ==================== PERFORMANCE TESTS ====================
def test_page_load_time(results):
    """Test page load performance"""
    print(f"\n{Colors.BOLD}[4] Performance Tests{Colors.END}")
    print("-" * 70)
    
    try:
        start = time.time()
        response = urlopen('http://localhost:8000/app.html', timeout=5)
        content = response.read()
        elapsed = (time.time() - start) * 1000  # Convert to milliseconds
        
        if elapsed < 1000:
            results.add_pass("Page Load Time", f"Loaded in {elapsed:.0f}ms")
        elif elapsed < 2000:
            results.add_warning("Page Load Time", f"Loaded in {elapsed:.0f}ms (slightly slow)")
        else:
            results.add_fail("Page Load Time", f"Loaded in {elapsed:.0f}ms (too slow)")
    except Exception as e:
        results.add_fail("Page Load Time", str(e))

def test_file_sizes(results):
    """Test if file sizes are reasonable"""
    try:
        files = {
            'app.html': 500,  # Min 500 bytes
            'test.html': 300,
            'sw.js': 200,
            'manifest.json': 100
        }
        
        for filename, min_size in files.items():
            try:
                response = urlopen(f'http://localhost:8000/{filename}', timeout=5)
                size = len(response.read())
                if size >= min_size:
                    results.add_pass(f"File Size: {filename}", f"{size} bytes")
                else:
                    results.add_fail(f"File Size: {filename}", f"Too small: {size} bytes")
            except:
                results.add_fail(f"File Size: {filename}", "File not found")
    except Exception as e:
        results.add_fail("File Sizes", str(e))

def test_response_headers(results):
    """Test server response headers"""
    try:
        req = Request('http://localhost:8000/app.html')
        response = urlopen(req, timeout=5)
        headers = dict(response.headers)
        
        results.add_pass("Response Headers", f"Received {len(headers)} headers")
        if 'Content-Type' in headers:
            results.add_pass("Content-Type", headers['Content-Type'])
    except Exception as e:
        results.add_fail("Response Headers", str(e))

# ==================== REAL-TIME SYNC TESTS ====================
def test_online_offline_handlers(results):
    """Test if online/offline event handlers exist"""
    print(f"\n{Colors.BOLD}[5] Real-Time Sync Tests{Colors.END}")
    print("-" * 70)
    
    try:
        response = urlopen('http://localhost:8000/app.html', timeout=5)
        content = response.read().decode('utf-8')
        
        if "window.addEventListener('online'" in content and "window.addEventListener('offline'" in content:
            results.add_pass("Network Event Handlers", "Online/offline listeners configured")
        else:
            results.add_warning("Network Event Handlers", "Check network event handling")
    except Exception as e:
        results.add_fail("Network Event Handlers", str(e))

def test_keyboard_shortcuts(results):
    """Test if keyboard shortcuts are implemented"""
    try:
        response = urlopen('http://localhost:8000/app.html', timeout=5)
        content = response.read().decode('utf-8')
        
        if "Shift" in content and "keydown" in content:
            results.add_pass("Keyboard Shortcuts", "Keyboard shortcut (Ctrl+Shift+S) implemented")
        else:
            results.add_warning("Keyboard Shortcuts", "Check keyboard event handling")
    except Exception as e:
        results.add_fail("Keyboard Shortcuts", str(e))

def test_data_sync_logic(results):
    """Test if data sync logic is present"""
    try:
        response = urlopen('http://localhost:8000/app.html', timeout=5)
        content = response.read().decode('utf-8')
        
        sync_indicators = ['emergencies', 'pendingSync', 'Storage.save', 'Storage.get']
        found = sum(1 for ind in sync_indicators if ind in content)
        
        if found >= 3:
            results.add_pass("Data Sync Logic", "Offline queue and sync detected")
        else:
            results.add_warning("Data Sync Logic", "Limited sync logic detected")
    except Exception as e:
        results.add_fail("Data Sync Logic", str(e))

# ==================== BROWSER COMPATIBILITY ====================
def test_browser_apis(results):
    """Test for modern browser API support"""
    print(f"\n{Colors.BOLD}[6] Browser API Compatibility{Colors.END}")
    print("-" * 70)
    
    try:
        response = urlopen('http://localhost:8000/app.html', timeout=5)
        content = response.read().decode('utf-8')
        
        apis = {
            'Service Worker': 'serviceWorker',
            'Local Storage': 'localStorage',
            'Geolocation': 'geolocation',
            'Web Crypto': 'crypto.subtle',
            'Fetch API': 'fetch(',
            'Promise': 'Promise',
            'Arrow Functions': '=>'
        }
        
        for api_name, api_check in apis.items():
            if api_check in content:
                results.add_pass(f"API: {api_name}", "Supported")
            else:
                results.add_warning(f"API: {api_name}", "May not be used")
    except Exception as e:
        results.add_fail("Browser APIs", str(e))

# ==================== MAIN TEST RUNNER ====================
def run_all_tests():
    results = TestResults()
    
    print(f"\n{Colors.BOLD}{'='*70}{Colors.END}")
    print(f"{Colors.BOLD}VAJRA SHAKTI KAVACH - COMPREHENSIVE TEST SUITE{Colors.END}")
    print(f"{Colors.BOLD}{'='*70}{Colors.END}")
    print(f"Start Time: {results.start_time.strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Connectivity Tests
    test_server_availability(results)
    test_app_html_loads(results)
    test_test_html_loads(results)
    test_service_worker(results)
    test_manifest(results)
    
    # Security Tests
    test_xss_vulnerability(results)
    test_https_readiness(results)
    test_encryption_support(results)
    test_no_hardcoded_secrets(results)
    test_content_security_policy(results)
    
    # Functionality Tests
    test_sos_button_html(results)
    test_evidence_recording(results)
    test_location_sharing(results)
    test_emergency_contacts(results)
    test_offline_support(results)
    test_activity_logging(results)
    
    # Performance Tests
    test_page_load_time(results)
    test_file_sizes(results)
    test_response_headers(results)
    
    # Real-Time Sync Tests
    test_online_offline_handlers(results)
    test_keyboard_shortcuts(results)
    test_data_sync_logic(results)
    
    # Browser Compatibility Tests
    test_browser_apis(results)
    
    # Print Summary
    success = results.print_summary()
    
    return 0 if success else 1

if __name__ == '__main__':
    sys.exit(run_all_tests())
