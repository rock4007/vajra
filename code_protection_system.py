#!/usr/bin/env python3
"""
VAJRA KAVACH - CODE PROTECTION & ANTI-TAMPERING SYSTEM
Protects against: Code modification, Copy-paste attacks, File locking, Malicious injection
Ghost Injection: Server crashes if tampering detected
"""

import hashlib
import os
import sys
import threading
import time
import psutil
import signal
from datetime import datetime
from pathlib import Path
import json
import atexit
import traceback

class GhostInjectionProtection:
    """
    Anti-tampering protection system that triggers server crash on malicious activity
    Features:
    - File integrity monitoring (checksum validation)
    - Read-only enforcement
    - Anti-debugging protection
    - Memory tampering detection
    - Process injection detection
    """
    
    def __init__(self, protected_files=None, check_interval=5):
        self.protected_files = protected_files or []
        self.check_interval = check_interval
        self.file_checksums = {}
        self.monitoring = False
        self.monitor_thread = None
        self.tampering_detected = False
        self.violations = []
        
        # Create integrity log
        self.log_file = "security_violations.log"
        
        # Initialize checksums
        self._compute_initial_checksums()
        
        # Start monitoring
        self.start_monitoring()
        
        # Register cleanup handlers
        atexit.register(self.cleanup)
    
    def _compute_checksum(self, filepath):
        """Compute SHA256 checksum of a file"""
        try:
            sha256_hash = hashlib.sha256()
            with open(filepath, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception as e:
            self._log_violation(f"Error computing checksum for {filepath}: {e}")
            return None
    
    def _compute_initial_checksums(self):
        """Compute initial checksums for all protected files"""
        print("[GHOST PROTECTION] Computing file integrity checksums...")
        for filepath in self.protected_files:
            if os.path.exists(filepath):
                checksum = self._compute_checksum(filepath)
                self.file_checksums[filepath] = checksum
                print(f"  ✓ {filepath}: {checksum[:16]}...")
        print(f"[GHOST PROTECTION] {len(self.file_checksums)} files protected\n")
    
    def _check_file_integrity(self):
        """Check if any protected files have been modified"""
        violations = []
        
        for filepath, original_checksum in self.file_checksums.items():
            if not os.path.exists(filepath):
                violations.append(f"CRITICAL: Protected file deleted: {filepath}")
                continue
            
            current_checksum = self._compute_checksum(filepath)
            if current_checksum != original_checksum:
                violations.append(f"CRITICAL: File modified: {filepath}")
                violations.append(f"  Original: {original_checksum}")
                violations.append(f"  Current:  {current_checksum}")
        
        return violations
    
    def _check_process_injection(self):
        """Detect debugger attachment and process injection"""
        violations = []
        
        try:
            # Get current process
            current_process = psutil.Process()
            
            # Check for suspicious parent processes
            parent = current_process.parent()
            if parent:
                suspicious_parents = ['gdb', 'lldb', 'windbg', 'x64dbg', 'ollydbg', 'ida', 'ida64']
                if any(name in parent.name().lower() for name in suspicious_parents):
                    violations.append(f"CRITICAL: Debugger detected: {parent.name()}")
            
            # Check for unusual number of threads
            thread_count = current_process.num_threads()
            if thread_count > 50:  # Unusual for a Flask app
                violations.append(f"WARNING: Unusual thread count: {thread_count}")
            
            # Check for memory anomalies
            memory_info = current_process.memory_info()
            if memory_info.rss > 500 * 1024 * 1024:  # More than 500MB
                violations.append(f"WARNING: High memory usage: {memory_info.rss / (1024*1024):.2f} MB")
        
        except Exception as e:
            violations.append(f"Error checking process: {e}")
        
        return violations
    
    def _log_violation(self, message):
        """Log security violation"""
        timestamp = datetime.utcnow().isoformat()
        log_entry = f"[{timestamp}] {message}\n"
        
        try:
            with open(self.log_file, "a") as f:
                f.write(log_entry)
        except:
            pass
        
        print(f"[GHOST PROTECTION] {message}")
        self.violations.append({"timestamp": timestamp, "message": message})
    
    def _trigger_ghost_injection(self, violations):
        """
        GHOST INJECTION: Crash the server immediately on tampering detection
        This prevents malicious code from executing
        """
        self.tampering_detected = True
        
        print("\n" + "="*70)
        print("🚨 GHOST INJECTION TRIGGERED 🚨")
        print("="*70)
        print("SECURITY VIOLATION DETECTED - SERVER TERMINATING")
        print("-"*70)
        
        for violation in violations:
            print(f"  ⚠ {violation}")
            self._log_violation(violation)
        
        print("-"*70)
        print("ALL OPERATIONS HALTED")
        print("CHECK security_violations.log FOR DETAILS")
        print("="*70 + "\n")
        
        # Write final violation report
        self._write_violation_report(violations)
        
        # Force immediate termination (simulating server crash)
        # This prevents any malicious code from executing
        os._exit(1)  # Immediate exit without cleanup
    
    def _write_violation_report(self, violations):
        """Write detailed violation report"""
        report = {
            "timestamp": datetime.utcnow().isoformat(),
            "event": "GHOST_INJECTION_TRIGGERED",
            "violations": violations,
            "all_violations": self.violations,
            "protected_files": list(self.file_checksums.keys()),
            "system_info": {
                "pid": os.getpid(),
                "cwd": os.getcwd(),
                "python_version": sys.version
            }
        }
        
        try:
            with open("ghost_injection_report.json", "w") as f:
                json.dump(report, f, indent=2)
        except:
            pass
    
    def _monitor_loop(self):
        """Main monitoring loop"""
        print(f"[GHOST PROTECTION] Monitoring started (check interval: {self.check_interval}s)")
        
        while self.monitoring:
            try:
                violations = []
                
                # Check file integrity
                file_violations = self._check_file_integrity()
                violations.extend(file_violations)
                
                # Check for process injection
                process_violations = self._check_process_injection()
                violations.extend(process_violations)
                
                # If critical violations detected, trigger ghost injection
                critical_violations = [v for v in violations if "CRITICAL" in v]
                if critical_violations:
                    self._trigger_ghost_injection(violations)
                
                # Log warnings
                warnings = [v for v in violations if "WARNING" in v]
                for warning in warnings:
                    self._log_violation(warning)
                
                time.sleep(self.check_interval)
            
            except Exception as e:
                self._log_violation(f"Monitor error: {e}")
                time.sleep(self.check_interval)
    
    def start_monitoring(self):
        """Start the monitoring thread"""
        if not self.monitoring:
            self.monitoring = True
            self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
            self.monitor_thread.start()
    
    def stop_monitoring(self):
        """Stop the monitoring thread"""
        self.monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=2)
    
    def cleanup(self):
        """Cleanup on exit"""
        self.stop_monitoring()
    
    def get_status(self):
        """Get current protection status"""
        return {
            "monitoring": self.monitoring,
            "protected_files": len(self.file_checksums),
            "violations": len(self.violations),
            "tampering_detected": self.tampering_detected
        }


class ReadOnlyEnforcement:
    """
    Enforce read-only access to protected files
    Prevents file locking and unauthorized modifications
    """
    
    def __init__(self, protected_paths=None):
        self.protected_paths = protected_paths or []
        self._set_read_only()
    
    def _set_read_only(self):
        """Set files to read-only mode"""
        print("[READ-ONLY] Setting file permissions...")
        
        for path in self.protected_paths:
            if os.path.exists(path):
                try:
                    # On Windows: Remove write permissions
                    if sys.platform == 'win32':
                        os.chmod(path, 0o444)  # Read-only for all
                    else:
                        os.chmod(path, 0o444)  # Read-only for all
                    
                    print(f"  ✓ {path} - READ-ONLY")
                except Exception as e:
                    print(f"  ✗ {path} - Error: {e}")
        
        print(f"[READ-ONLY] {len(self.protected_paths)} files protected\n")
    
    def restore_permissions(self):
        """Restore write permissions (for development only)"""
        print("[READ-ONLY] Restoring write permissions...")
        
        for path in self.protected_paths:
            if os.path.exists(path):
                try:
                    if sys.platform == 'win32':
                        os.chmod(path, 0o666)  # Read-write for all
                    else:
                        os.chmod(path, 0o666)  # Read-write for all
                    
                    print(f"  ✓ {path} - WRITABLE")
                except Exception as e:
                    print(f"  ✗ {path} - Error: {e}")


class AntiDebugProtection:
    """
    Anti-debugging protection to prevent code analysis
    """
    
    @staticmethod
    def check_debugger():
        """Check if debugger is attached"""
        try:
            # Windows-specific check
            if sys.platform == 'win32':
                import ctypes
                return ctypes.windll.kernel32.IsDebuggerPresent() != 0
            
            # Linux/Unix check
            else:
                # Check /proc/self/status for TracerPid
                with open('/proc/self/status', 'r') as f:
                    for line in f:
                        if line.startswith('TracerPid:'):
                            pid = int(line.split(':', 1)[1].strip())
                            return pid != 0
        except:
            pass
        
        return False
    
    @staticmethod
    def anti_debug_check():
        """Perform anti-debug check and crash if debugger detected"""
        if AntiDebugProtection.check_debugger():
            print("\n" + "="*70)
            print("🚨 DEBUGGER DETECTED - GHOST INJECTION TRIGGERED 🚨")
            print("="*70)
            print("Unauthorized debugging attempt detected")
            print("Server terminating immediately")
            print("="*70 + "\n")
            
            # Immediate termination
            os._exit(1)


def initialize_protection(app_root=None):
    """
    Initialize all protection systems
    Call this at the start of your application
    """
    
    if app_root is None:
        app_root = os.path.dirname(os.path.abspath(__file__))
    
    print("\n" + "="*70)
    print("VAJRA KAVACH - CODE PROTECTION SYSTEM")
    print("="*70)
    print(f"Initializing security at: {app_root}\n")
    
    # Define files to protect
    protected_files = [
        os.path.join(app_root, 'main.py'),
        os.path.join(app_root, 'config.py'),
        os.path.join(app_root, 'supabase-client.js'),
        os.path.join(app_root, 'background.js'),
        os.path.join(app_root, 'content-script.js'),
        os.path.join(app_root, 'manifest.json'),
    ]
    
    # Filter existing files
    protected_files = [f for f in protected_files if os.path.exists(f)]
    
    # 1. Anti-Debug Protection
    print("[1/3] Anti-Debug Protection")
    AntiDebugProtection.anti_debug_check()
    print("  ✓ No debugger detected\n")
    
    # 2. Read-Only Enforcement (optional - uncomment for production)
    # print("[2/3] Read-Only Enforcement")
    # readonly = ReadOnlyEnforcement(protected_files)
    # print()
    
    # 3. Ghost Injection Protection (File Integrity Monitoring)
    print("[2/3] Ghost Injection Protection")
    ghost_protection = GhostInjectionProtection(
        protected_files=protected_files,
        check_interval=5  # Check every 5 seconds
    )
    
    # 4. Continuous monitoring
    print("[3/3] Continuous Monitoring")
    print("  ✓ Real-time file integrity monitoring active")
    print("  ✓ Process injection detection active")
    print("  ✓ Ghost injection ready to trigger on tampering\n")
    
    print("="*70)
    print("✅ CODE PROTECTION ACTIVE")
    print("="*70)
    print("⚠  WARNING: Any tampering will trigger immediate server crash")
    print("⚠  All violations logged to: security_violations.log")
    print("="*70 + "\n")
    
    return ghost_protection


def test_protection():
    """Test the protection system"""
    print("\n" + "="*70)
    print("TESTING CODE PROTECTION SYSTEM")
    print("="*70 + "\n")
    
    # Create test file
    test_file = "test_protected.txt"
    with open(test_file, "w") as f:
        f.write("Original content")
    
    # Initialize protection
    ghost = GhostInjectionProtection(
        protected_files=[test_file],
        check_interval=2
    )
    
    print("Protection initialized. Waiting 3 seconds...")
    time.sleep(3)
    
    print("\nStatus:", ghost.get_status())
    
    print("\n⚠ Attempting to modify protected file...")
    print("(This should trigger ghost injection in ~2 seconds)\n")
    
    # Modify the file
    with open(test_file, "w") as f:
        f.write("MODIFIED CONTENT - MALICIOUS CODE")
    
    # Wait for detection
    time.sleep(5)
    
    print("\nIf you see this, ghost injection failed!")
    
    # Cleanup
    os.remove(test_file)


if __name__ == "__main__":
    # Test mode
    if len(sys.argv) > 1 and sys.argv[1] == "test":
        test_protection()
    else:
        # Normal mode - initialize protection
        protection = initialize_protection()
        
        # Keep running
        try:
            print("Protection running. Press Ctrl+C to stop.")
            while True:
                time.sleep(10)
                status = protection.get_status()
                print(f"[STATUS] Files: {status['protected_files']}, Violations: {status['violations']}")
        except KeyboardInterrupt:
            print("\n\nShutting down protection system...")
