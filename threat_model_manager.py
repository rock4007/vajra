#!/usr/bin/env python3
"""Threat model updater with scheduled 3‑month intelligence refresh."""

import json
import os
import threading
import time
from datetime import datetime, timedelta

DEFAULT_MODEL = {
    "version": "1.0",
    "last_updated": None,
    "next_update": None,
    "intel_sources": [],
    "threats": []
}

class ThreatModelUpdater:
    def __init__(self, app_root, model_path="threat_model.json", intel_feed_path="threat_intel_feed.json", update_interval_days=90):
        self.app_root = app_root
        self.model_path = os.path.join(app_root, model_path)
        self.intel_feed_path = os.path.join(app_root, intel_feed_path)
        self.update_interval_days = update_interval_days
        self._running = False
        self._thread = None
        self.log_path = os.path.join(app_root, "threat_model_updates.log")

    def _log(self, message, level="INFO"):
        try:
            ts = datetime.utcnow().isoformat()
            line = f"[{ts}] {level}: {message}\n"
            with open(self.log_path, "a", encoding="utf-8") as fh:
                fh.write(line)
        except Exception:
            pass

    def _load_json(self, path, default):
        if not os.path.exists(path):
            return default
        try:
            with open(path, "r", encoding="utf-8") as fh:
                return json.load(fh)
        except Exception:
            return default

    def _save_json(self, path, data):
        try:
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(data, fh, indent=2)
        except Exception:
            pass

    def _next_update_date(self):
        return (datetime.utcnow() + timedelta(days=self.update_interval_days)).isoformat()

    def _merge_intelligence(self, model, intel):
        if not isinstance(intel, dict):
            return model
        sources = intel.get("sources", [])
        threats = intel.get("threats", [])
        if sources:
            model.setdefault("intel_sources", [])
            for src in sources:
                if src not in model["intel_sources"]:
                    model["intel_sources"].append(src)
        if threats:
            model.setdefault("threats", [])
            for threat in threats:
                if threat not in model["threats"]:
                    model["threats"].append(threat)
        return model

    def update_if_due(self):
        model = self._load_json(self.model_path, DEFAULT_MODEL.copy())
        last_updated = model.get("last_updated")
        due = True
        if last_updated:
            try:
                last_dt = datetime.fromisoformat(last_updated)
                due = (datetime.utcnow() - last_dt) >= timedelta(days=self.update_interval_days)
            except Exception:
                due = True
        if not due:
            return

        intel = self._load_json(self.intel_feed_path, {})
        if intel:
            model = self._merge_intelligence(model, intel)
            self._log("Threat model updated with new intelligence.")
        else:
            self._log("Threat model update due, but no new intelligence feed found.", level="WARN")

        model["last_updated"] = datetime.utcnow().isoformat()
        model["next_update"] = self._next_update_date()
        self._save_json(self.model_path, model)

    def _loop(self, check_interval_seconds):
        self._running = True
        self._log(f"Threat model updater started (check interval={check_interval_seconds}s)")
        while self._running:
            try:
                self.update_if_due()
                time.sleep(check_interval_seconds)
            except Exception as exc:
                self._log(f"Updater loop error: {exc}", level="ERROR")
                time.sleep(check_interval_seconds)

    def start(self, check_interval_seconds=86400):
        if self._thread and self._thread.is_alive():
            return
        self._thread = threading.Thread(target=self._loop, args=(check_interval_seconds,), daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=2)


def start_threat_model_updates(app_root, check_interval_seconds=86400, update_interval_days=90):
    updater = ThreatModelUpdater(
        app_root=app_root,
        update_interval_days=update_interval_days,
    )
    updater.start(check_interval_seconds=check_interval_seconds)
    return updater
