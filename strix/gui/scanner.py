"""Background scanner runner and process manager for iqAudi360."""

from __future__ import annotations

import logging
import os
import queue
import re
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from strix.core.paths import runs_base_dir
from strix.gui.data import get_scan_detail

logger = logging.getLogger(__name__)


class ScanJob:
    """Represents a running or completed background scan job."""

    def __init__(
        self,
        job_id: str,
        target: str,
        scan_mode: str = "deep",
        scope_mode: str = "auto",
        options: dict[str, Any] | None = None,
        tenant_id: str | None = None,
        created_by: str | None = None,
    ) -> None:
        self.job_id = job_id
        self.target = target
        self.scan_mode = scan_mode
        self.scope_mode = scope_mode
        self.options = options or {}
        self.tenant_id = tenant_id
        self.created_by = created_by
        self.run_name: str | None = None
        self.status: str = "starting"  # starting, running, completed, stopped, failed
        self.start_time: str = datetime.now(timezone.utc).isoformat()
        self.end_time: str | None = None
        self.exit_code: int | None = None
        self.logs: list[str] = []
        self.subscribers: list[queue.Queue[dict[str, Any]]] = []
        self.proc: subprocess.Popen[str] | None = None
        self._lock = threading.Lock()

    def add_log(self, line: str) -> None:
        """Add a log line and notify subscribers."""
        clean_line = line.rstrip("\r\n")
        with self._lock:
            self.logs.append(clean_line)
            # Detect run_name from CLI output if not set yet
            if not self.run_name:
                match = re.search(r"(?:iqaudi360_runs[/\\]|scan\s+|run_name=)([a-zA-Z0-9_\-\.]+)", clean_line)
                if match:
                    candidate = match.group(1).strip()
                    if candidate and not candidate.startswith("iqaudi360_runs"):
                        self.run_name = candidate
                        if self.tenant_id:
                            try:
                                from strix.gui.auth.db import record_scan_ownership
                                record_scan_ownership(candidate, self.tenant_id, self.created_by or "system")
                            except Exception:
                                pass

        self.broadcast({
            "type": "log",
            "line": clean_line,
            "run_name": self.run_name,
            "status": self.status,
            "timestamp": datetime.now(timezone.utc).strftime("%H:%M:%S"),
        })

    def broadcast(self, event_data: dict[str, Any]) -> None:
        """Send event to all active SSE queues."""
        with self._lock:
            subscribers_snapshot = list(self.subscribers)
        for q in subscribers_snapshot:
            try:
                q.put_nowait(event_data)
            except Exception:
                pass

    def add_subscriber(self) -> queue.Queue[dict[str, Any]]:
        """Register a subscriber queue for SSE streaming."""
        q: queue.Queue[dict[str, Any]] = queue.Queue(maxsize=1000)
        with self._lock:
            self.subscribers.append(q)
            # Replay existing logs to new subscriber
            for log_line in self.logs[-200:]:
                q.put_nowait({
                    "type": "log",
                    "line": log_line,
                    "run_name": self.run_name,
                    "status": self.status,
                    "timestamp": "",
                })
        return q

    def remove_subscriber(self, q: queue.Queue[dict[str, Any]]) -> None:
        """Unregister a subscriber queue."""
        with self._lock:
            if q in self.subscribers:
                self.subscribers.remove(q)

    def to_dict(self) -> dict[str, Any]:
        """Convert job info to JSON-friendly dictionary."""
        return {
            "job_id": self.job_id,
            "target": self.target,
            "scan_mode": self.scan_mode,
            "scope_mode": self.scope_mode,
            "status": self.status,
            "run_name": self.run_name or self.job_id,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "exit_code": self.exit_code,
            "log_count": len(self.logs),
            "options": self.options,
        }


class ScanManager:
    """Manages active and historical background scans."""

    _instance: ScanManager | None = None

    def __init__(self) -> None:
        self.jobs: dict[str, ScanJob] = {}
        self._lock = threading.Lock()

    @classmethod
    def get_instance(cls) -> ScanManager:
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def start_scan(
        self,
        target: str,
        scan_mode: str = "deep",
        scope_mode: str = "auto",
        options: dict[str, Any] | None = None,
        tenant_id: str | None = None,
        created_by: str | None = None,
    ) -> ScanJob:
        """Launch a real iqAudi360 scan as a background process."""
        options = options or {}
        timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_target = re.sub(r"[^a-zA-Z0-9_\-]", "_", target)[:24].strip("_")
        job_id = f"scan_{safe_target}_{timestamp_str}"

        job = ScanJob(
            job_id=job_id,
            target=target,
            scan_mode=scan_mode,
            scope_mode=scope_mode,
            options=options,
            tenant_id=tenant_id,
            created_by=created_by,
        )

        if tenant_id:
            try:
                from strix.gui.auth.db import record_scan_ownership
                record_scan_ownership(job_id, tenant_id, created_by or "system")
            except Exception:
                pass

        with self._lock:
            self.jobs[job_id] = job

        # Assemble CLI command
        # python -m strix.interface.main -t <target> -n -m <mode> --scope-mode <scope>
        cmd: list[str] = [
            sys.executable,
            "-u",  # Unbuffered stdio
            "-m",
            "strix.interface.main",
            "--target",
            target,
            "--non-interactive",
            "--scan-mode",
            scan_mode,
            "--scope-mode",
            scope_mode,
        ]

        if options.get("max_budget_usd"):
            cmd.extend(["--max-budget", str(options["max_budget_usd"])])

        if options.get("max_turns"):
            cmd.extend(["--max-turns", str(options["max_turns"])])

        if options.get("instruction"):
            cmd.extend(["--instruction", str(options["instruction"])])

        if options.get("instruction_file"):
            cmd.extend(["--instruction-file", str(options["instruction_file"])])

        if options.get("workspace_file"):
            cmd.extend(["--workspace-file", str(options["workspace_file"])])

        if options.get("diff_base"):
            cmd.extend(["--diff-base", str(options["diff_base"])])

        if options.get("config"):
            cmd.extend(["--config", str(options["config"])])

        if options.get("mcp_config"):
            cmd.extend(["--mcp-config", str(options["mcp_config"])])

        if options.get("mcp_server"):
            for s in options["mcp_server"]:
                cmd.extend(["--mcp-server", str(s)])

        if options.get("mcp_exclude"):
            for s in options["mcp_exclude"]:
                cmd.extend(["--mcp-exclude", str(s)])

        logger.info("Spawning iqAudi360 background scanner: %s", " ".join(cmd))

        # Launch background process
        env = os.environ.copy()
        env["PYTHONUNBUFFERED"] = "1"

        creationflags = 0
        if sys.platform == "win32":
            creationflags = subprocess.CREATE_NEW_PROCESS_GROUP

        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
            text=True,
            bufsize=1,
            encoding="utf-8",
            errors="replace",
            env=env,
            creationflags=creationflags,
        )

        job.proc = proc
        job.status = "running"

        # Worker thread to read stdout/stderr
        def _read_output() -> None:
            job.add_log(f"[*] Starting iqAudi360 scan for target: {target}")
            job.add_log(f"[*] Mode: {scan_mode.upper()} | Scope: {scope_mode.upper()}")
            job.add_log(f"[*] Command: {' '.join(cmd)}")
            job.add_log("=" * 60)

            # Monitor runs_base_dir for newly created directory
            base_dir = runs_base_dir()
            initial_dirs = set(base_dir.iterdir()) if base_dir.is_dir() else set()

            try:
                if proc.stdout:
                    for line in iter(proc.stdout.readline, ""):
                        if not line:
                            break
                        job.add_log(line)

                        # If run_name still not detected, check for new directory in base_dir
                        if not job.run_name and base_dir.is_dir():
                            current_dirs = set(base_dir.iterdir())
                            new_dirs = current_dirs - initial_dirs
                            if new_dirs:
                                # Pick the newest dir
                                newest = max(new_dirs, key=lambda p: p.stat().st_mtime)
                                job.run_name = newest.name

                proc.stdout.close()
            except Exception as exc:
                job.add_log(f"[!] Error reading process stream: {exc}")

            proc.wait()
            job.exit_code = proc.returncode
            job.end_time = datetime.now(timezone.utc).isoformat()

            # Exit code meanings:
            # 0: clean run, no vulns
            # 2: clean run, vulns found
            # 1: fatal error
            if job.exit_code in (0, 2):
                job.status = "completed"
                job.add_log(f"[*] Scan completed successfully (exit code {job.exit_code}).")
            elif job.status == "stopped":
                job.add_log("[!] Scan was stopped by operator.")
            else:
                job.status = "failed"
                job.add_log(f"[!] Scan ended with error code {job.exit_code}.")

            job.broadcast({
                "type": "status",
                "status": job.status,
                "exit_code": job.exit_code,
                "run_name": job.run_name or job.job_id,
            })

        worker = threading.Thread(target=_read_output, daemon=True)
        worker.start()

        return job

    def stop_scan(self, job_or_run_id: str) -> bool:
        """Stop an active scan process."""
        job = self.jobs.get(job_or_run_id)
        if not job:
            # Try finding by run_name
            for j in self.jobs.values():
                if j.run_name == job_or_run_id:
                    job = j
                    break

        if not job or not job.proc or job.status != "running":
            return False

        job.status = "stopped"
        job.add_log("[!] Termination requested by user...")
        try:
            job.proc.terminate()
            time.sleep(1)
            if job.proc.poll() is None:
                job.proc.kill()
            return True
        except Exception as exc:
            logger.error("Error stopping scan %s: %s", job_or_run_id, exc)
            return False

    def get_job(self, job_or_run_id: str) -> ScanJob | None:
        """Get ScanJob by job_id or run_name."""
        if job_or_run_id in self.jobs:
            return self.jobs[job_or_run_id]
        for job in self.jobs.values():
            if job.run_name == job_or_run_id:
                return job
        return None

    def list_jobs(self) -> list[dict[str, Any]]:
        """List all tracked jobs in this session."""
        with self._lock:
            return [job.to_dict() for job in self.jobs.values()]
