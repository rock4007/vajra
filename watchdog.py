#!/usr/bin/env python3
"""
VajraBackend Watchdog - Auto-restart and auto-heal mechanism
Monitors backend health and automatically restarts if crashed
"""

import subprocess
import time
import requests
import os
import signal
import sys
from datetime import datetime

class BackendWatchdog:
    def __init__(self, port=8009, check_interval=5):
        self.port = port
        self.check_interval = check_interval
        self.backend_process = None
        self.backend_path = os.path.dirname(__file__)
        self.max_restart_attempts = 5
        self.restart_count = 0
        self.last_crash_time = None

    def log(self, message, level='INFO'):
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        print(f"[{timestamp}] [{level}] {message}")

    def is_backend_alive(self):
        """Check if backend is responding to health check"""
        try:
            response = requests.get(f'http://127.0.0.1:{self.port}/health', timeout=3)
            return response.status_code == 200
        except Exception:
            return False

    def start_backend(self):
        """Start the Flask backend"""
        try:
            self.log("Starting VajraBackend...")
            cmd = [sys.executable, 'main.py']
            self.backend_process = subprocess.Popen(
                cmd,
                cwd=self.backend_path,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                preexec_fn=None if os.name == 'nt' else os.setsid
            )
            self.log(f"Backend started with PID {self.backend_process.pid}")
            
            # Wait for backend to be ready
            for i in range(10):
                time.sleep(0.5)
                if self.is_backend_alive():
                    self.log("✅ Backend is alive and responding", 'SUCCESS')
                    self.restart_count = 0
                    return True
            
            self.log("❌ Backend started but not responding to health check", 'ERROR')
            return False
        except Exception as e:
            self.log(f"Failed to start backend: {e}", 'ERROR')
            return False

    def kill_backend(self):
        """Kill the backend process"""
        if self.backend_process:
            try:
                if os.name == 'nt':
                    os.system(f'taskkill /F /PID {self.backend_process.pid}')
                else:
                    os.killpg(os.getpgid(self.backend_process.pid), signal.SIGTERM)
                self.log(f"Backend process {self.backend_process.pid} terminated")
                self.backend_process = None
            except Exception as e:
                self.log(f"Error killing backend: {e}", 'ERROR')

    def restart_backend(self):
        """Restart the backend"""
        self.restart_count += 1
        self.log(f"🔄 Restart attempt {self.restart_count}/{self.max_restart_attempts}", 'WARNING')
        
        if self.restart_count > self.max_restart_attempts:
            self.log("❌ Max restart attempts reached. Manual intervention required.", 'ERROR')
            return False
        
        self.kill_backend()
        time.sleep(1)
        return self.start_backend()

    def monitor(self):
        """Main monitoring loop"""
        self.log("=" * 60)
        self.log("VajraBackend Watchdog Started", 'SUCCESS')
        self.log("=" * 60)
        
        # Start backend initially
        if not self.start_backend():
            self.log("Failed to start backend initially", 'ERROR')
            return
        
        try:
            while True:
                time.sleep(self.check_interval)
                
                if not self.is_backend_alive():
                    self.log("🚨 Backend is not responding!", 'ERROR')
                    
                    # Check if process is still alive
                    if self.backend_process and self.backend_process.poll() is not None:
                        self.log("Backend process has terminated", 'ERROR')
                        self.last_crash_time = datetime.now()
                    
                    self.log("🔄 Triggering auto-restart...", 'WARNING')
                    if not self.restart_backend():
                        self.log("❌ Auto-restart failed", 'ERROR')
                else:
                    # Backend is healthy
                    if self.restart_count > 0:
                        self.log("✅ Backend recovered successfully", 'SUCCESS')
                    self.restart_count = 0

        except KeyboardInterrupt:
            self.log("\n⏹️ Watchdog stopping...", 'WARNING')
            self.kill_backend()
            self.log("Watchdog stopped", 'SUCCESS')
            sys.exit(0)

def main():
    watchdog = BackendWatchdog(port=8009, check_interval=5)
    watchdog.monitor()

if __name__ == '__main__':
    main()
