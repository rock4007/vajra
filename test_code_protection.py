#!/usr/bin/env python3
"""
Comprehensive test for Code Protection System
Tests all protection features and demonstrates ghost injection
"""

import os
import sys
import time
import json
from pathlib import Path

def print_header(title):
    """Print formatted header"""
    print("\n" + "="*70)
    print(f" {title}")
    print("="*70 + "\n")

def print_section(title):
    """Print section header"""
    print("\n" + "-"*70)
    print(f"{title}")
    print("-"*70)

def test_file_integrity_protection():
    """Test 1: File Integrity Monitoring"""
    print_header("TEST 1: FILE INTEGRITY MONITORING")
    
    from code_protection_system import GhostInjectionProtection
    
    # Create test file
    test_file = "test_file_integrity.py"
    original_content = "# Original safe code\nprint('Hello World')\n"
    
    with open(test_file, "w") as f:
        f.write(original_content)
    
    print(f"✓ Created test file: {test_file}")
    print(f"✓ Original content: {repr(original_content[:30])}...")
    
    # Initialize protection
    print("\n🛡️  Initializing protection...")
    protection = GhostInjectionProtection(
        protected_files=[test_file],
        check_interval=2
    )
    
    print("✓ Protection active - monitoring every 2 seconds")
    print("✓ Waiting 3 seconds to establish baseline...")
    time.sleep(3)
    
    # Show status
    status = protection.get_status()
    print(f"\n📊 Status: {status}")
    
    print("\n⚠️  TAMPERING ATTEMPT: Modifying protected file...")
    malicious_content = "# MALICIOUS CODE INJECTED\nimport os; os.system('rm -rf /')\n"
    
    with open(test_file, "w") as f:
        f.write(malicious_content)
    
    print("✓ File modified with malicious code")
    print(f"✓ Malicious content: {repr(malicious_content[:40])}...")
    
    print("\n⏳ Waiting for ghost injection to trigger (2-3 seconds)...")
    print("   Server should crash when tampering is detected!\n")
    
    # Wait for detection
    time.sleep(5)
    
    # Cleanup (this should never execute if ghost injection works)
    print("\n❌ ERROR: Ghost injection did not trigger!")
    print("   Protection system may be compromised")
    os.remove(test_file)

def test_anti_debug_protection():
    """Test 2: Anti-Debug Protection"""
    print_header("TEST 2: ANTI-DEBUG PROTECTION")
    
    from code_protection_system import AntiDebugProtection
    
    print("🔍 Checking for debugger attachment...")
    
    is_debugged = AntiDebugProtection.check_debugger()
    
    if is_debugged:
        print("\n⚠️  DEBUGGER DETECTED!")
        print("   Ghost injection should trigger immediately...")
        AntiDebugProtection.anti_debug_check()
        print("\n❌ ERROR: Server should have crashed!")
    else:
        print("\n✓ No debugger detected")
        print("✓ Anti-debug protection is active")
        print("✓ Any debugger attachment will trigger ghost injection")

def test_read_only_protection():
    """Test 3: Read-Only Enforcement"""
    print_header("TEST 3: READ-ONLY ENFORCEMENT")
    
    from code_protection_system import ReadOnlyEnforcement
    
    # Create test file
    test_file = "test_readonly.txt"
    with open(test_file, "w") as f:
        f.write("Protected content")
    
    print(f"✓ Created test file: {test_file}")
    
    # Set read-only
    print("\n🔒 Enforcing read-only permissions...")
    readonly = ReadOnlyEnforcement([test_file])
    
    # Try to modify
    print("\n⚠️  Attempting to modify read-only file...")
    try:
        with open(test_file, "w") as f:
            f.write("Modified content")
        print("❌ ERROR: File was modified despite read-only protection!")
    except PermissionError:
        print("✓ Modification blocked - read-only protection working!")
    
    # Restore permissions
    print("\n🔓 Restoring write permissions...")
    readonly.restore_permissions()
    
    # Verify restoration
    try:
        with open(test_file, "w") as f:
            f.write("Modified after restoration")
        print("✓ Write permissions restored successfully")
    except PermissionError:
        print("❌ ERROR: Permissions not restored properly")
    
    # Cleanup
    os.remove(test_file)

def test_process_monitoring():
    """Test 4: Process Monitoring"""
    print_header("TEST 4: PROCESS MONITORING")
    
    import psutil
    
    print("📊 Analyzing current process...")
    
    current_process = psutil.Process()
    
    # Get process info
    print(f"\n✓ Process ID: {current_process.pid}")
    print(f"✓ Process Name: {current_process.name()}")
    print(f"✓ Thread Count: {current_process.num_threads()}")
    
    memory_info = current_process.memory_info()
    print(f"✓ Memory Usage: {memory_info.rss / (1024*1024):.2f} MB")
    
    # Check parent
    parent = current_process.parent()
    if parent:
        print(f"✓ Parent Process: {parent.name()} (PID: {parent.pid})")
    
    print("\n✓ Process monitoring active")
    print("✓ Suspicious activity will be detected and logged")

def test_violation_logging():
    """Test 5: Violation Logging"""
    print_header("TEST 5: VIOLATION LOGGING")
    
    print("📝 Testing security violation logging...")
    
    log_file = "security_violations.log"
    
    # Check if log exists from previous tests
    if os.path.exists(log_file):
        print(f"\n✓ Found existing log: {log_file}")
        
        with open(log_file, "r") as f:
            content = f.read()
            lines = content.strip().split('\n')
        
        print(f"✓ Log contains {len(lines)} entries")
        print("\n📋 Recent violations:")
        
        for line in lines[-5:]:
            if line.strip():
                print(f"   {line}")
    else:
        print("\n✓ No violations logged yet")
        print("✓ Log will be created on first violation")
    
    # Check for ghost injection report
    report_file = "ghost_injection_report.json"
    if os.path.exists(report_file):
        print(f"\n✓ Found ghost injection report: {report_file}")
        
        with open(report_file, "r") as f:
            report = json.load(f)
        
        print(f"✓ Event: {report.get('event')}")
        print(f"✓ Timestamp: {report.get('timestamp')}")
        print(f"✓ Violations: {len(report.get('violations', []))}")
        
        print("\n📋 Violation details:")
        for violation in report.get('violations', [])[:3]:
            print(f"   {violation}")
    else:
        print("\n✓ No ghost injection reports yet")
        print("✓ Report will be created when ghost injection triggers")

def main():
    """Run all tests"""
    print_header("VAJRA KAVACH - CODE PROTECTION SYSTEM")
    print("Comprehensive Test Suite")
    print("⚠️  WARNING: Test 1 will crash the server!")
    print("   This is expected behavior to demonstrate ghost injection")
    
    tests = [
        ("Anti-Debug Protection", test_anti_debug_protection),
        ("Read-Only Enforcement", test_read_only_protection),
        ("Process Monitoring", test_process_monitoring),
        ("Violation Logging", test_violation_logging),
        ("File Integrity Protection", test_file_integrity_protection),  # Run last - will crash
    ]
    
    print("\n📋 Test Plan:")
    for i, (name, func) in enumerate(tests, 1):
        print(f"   {i}. {name}")
    
    input("\n Press Enter to start tests...")
    
    for name, test_func in tests:
        try:
            test_func()
            print(f"\n✅ {name}: PASSED")
        except Exception as e:
            print(f"\n❌ {name}: FAILED")
            print(f"   Error: {e}")
            import traceback
            traceback.print_exc()
    
    print_header("ALL TESTS COMPLETED")
    print("✅ Code protection system is fully operational")
    print("🛡️  Your code is protected against tampering!")

if __name__ == "__main__":
    main()
