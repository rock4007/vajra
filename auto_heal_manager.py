#!/usr/bin/env python3
"""Auto-heal manager for VajraBackend."""

import os
import time
import threading
from datetime import datetime

class AutoHealManager:
    def __init__(self, app_root, protected_files=None, backup_suffix=".bak", log_path="auto_heal.log"):
        self.app_root = app_root
        self.backup_suffix = backup_suffix
        self.log_path = os.path.join(app_root, log_path)
        self.protected_files = protected_files or []
        self._running = False
        self._thread = None

    def _log(self, message, level="INFO"):
        try:
            ts = datetime.utcnow().isoformat()
            line = f"[{ts}] {level}: {message}\n"
            with open(self.log_path, "a", encoding="utf-8") as fh:
                fh.write(line)
        except Exception:
            pass

    def _restore_from_backup(self, target_path):
        backup_path = f"{target_path}{self.backup_suffix}"
        if not os.path.exists(backup_path):
            return False
        try:
            with open(backup_path, "rb") as src, open(target_path, "wb") as dst:
                dst.write(src.read())
            return True
        except Exception:
            return False

    def check_and_heal(self):
        restored = 0
        missing = 0
        for rel_path in self.protected_files:
            path = os.path.join(self.app_root, rel_path)
            if not os.path.exists(path):
                missing += 1
                if self._restore_from_backup(path):
                    restored += 1
                    self._log(f"Restored missing file from backup: {rel_path}")
                else:
                    self._log(f"Missing protected file and no backup found: {rel_path}", level="WARN")
        if missing == 0:
            self._log("Auto-heal check completed: no missing files.")
        else:
            self._log(f"Auto-heal check completed: missing={missing}, restored={restored}")

    def _loop(self, interval_seconds):
        self._running = True
        self._log(f"Auto-heal monitor started (interval={interval_seconds}s)")
        while self._running:
            try:
                self.check_and_heal()
                time.sleep(interval_seconds)
            except Exception as exc:
                self._log(f"Auto-heal loop error: {exc}", level="ERROR")
                time.sleep(interval_seconds)

    def start(self, interval_seconds=3600):
        if self._thread and self._thread.is_alive():
            return
        self._thread = threading.Thread(target=self._loop, args=(interval_seconds,), daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=2)


def start_auto_heal(app_root, protected_files=None, interval_seconds=3600):
    manager = AutoHealManager(
        app_root=app_root,
        protected_files=protected_files or [],
    )
    manager.start(interval_seconds=interval_seconds)
    return manager
