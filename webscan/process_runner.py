"""Scanner process lifecycle, cancellation and evidence recording.

No CLI/UI globals: callers supply a notification callback.
"""
from __future__ import annotations
import dataclasses
import http.client
import os
from pathlib import Path
import shlex
import shutil
import signal
import subprocess
import threading
import time
from . import evidence, reliability, web_engine, whatweb_snapshot


@dataclasses.dataclass
class Job:
    name: str
    tool: str
    argv: list[str]
    folder: Path
    timeout: int
    outputs: list[str] = dataclasses.field(default_factory=list)
    skip_reason: str = ""
    snapshot: dict | None = None


class ProcessRunner:
    def __init__(self, dry_run=False, notify=print):
        self.notify = notify
        self.dry_run = dry_run
        self.stop = threading.Event()
        self.lock = threading.Lock()
        self.active = set()
        self.web_skip_reason = ""

    @staticmethod
    def kill(proc):
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        proc.wait()

    def cancel(self):
        self.stop.set()
        with self.lock:
            for proc in list(self.active):
                self.kill(proc)

    def execute(self, job):
        try:
            return self._execute(job)
        except Exception as exc:
            return dict(name=job.name, tool=job.tool, command='', argv=evidence.safe(job.argv),
                folder=str(job.folder), status='failed', elapsed=0, exit_code=None,
                outputs=job.outputs, note='Job could not be started: ' + reliability.record('subprocess_setup', exc))

    def _execute(self, job):
        job.folder.mkdir(parents=True, exist_ok=True)
        record = {"name": job.name, "tool": job.tool, "command": shlex.join(evidence.safe(job.argv)),
                  "argv": job.argv, "folder": str(job.folder), "status": "planned", "elapsed": 0,
                  "exit_code": None, "outputs": job.outputs, "note": ""}
        (job.folder / "command.txt").write_text(record["command"] + "\n", encoding="utf-8")
        if self.dry_run:
            self.notify("[PLAN] " + record["command"])
            return record
        if self.stop.is_set():
            record.update(status="cancelled", note="Run interrupted before starting.")
            return record
        binary = shutil.which(job.argv[0])
        boundary_reason = self.web_skip_reason if job.tool != "nmap" and not job.snapshot else ""
        if job.skip_reason or boundary_reason or not binary:
            record.update(status="skipped", note=job.skip_reason or boundary_reason or f"{job.argv[0]} is not installed/on PATH.")
            self.notify(f"[SKIP] {job.name}: {record['note']}")
            return record
        start = time.monotonic()
        if job.snapshot:
            try:
                whatweb_snapshot.prepare(job.snapshot, job.folder, self.stop, self.request_gate)
            except (OSError, ValueError, http.client.HTTPException, InterruptedError) as exc:
                record.update(status='failed', note='Pinned WhatWeb snapshot failed: ' + reliability.record('whatweb_snapshot', exc))
                self.notify('[WHATWEB] ' + record['note'])
                return record
        self.notify(f"[START] {job.name}")
        proc = None
        try:
            with (job.folder / "console.log").open("wb") as log:
                with self.lock:
                    if self.stop.is_set():
                        record.update(status="cancelled", note="Run interrupted before starting.")
                        return record
                    # Argument arrays only; shell expansion never executes user input.
                    proc = subprocess.Popen([binary, *job.argv[1:]], stdout=log, stderr=subprocess.STDOUT,
                                            stdin=subprocess.DEVNULL, start_new_session=True)
                    self.active.add(proc)
                deadline = start + job.timeout
                while proc.poll() is None:
                    if self.stop.wait(0.2):
                        self.kill(proc)
                        record.update(status="cancelled", note="Run interrupted.")
                        break
                    if time.monotonic() >= deadline:
                        self.kill(proc)
                        record.update(status="timeout", note="Time limit reached; output may be incomplete.")
                        break
                record["exit_code"] = proc.returncode
                if record["status"] == "planned":
                    record["status"] = "completed" if proc.returncode == 0 or (job.tool == "wpscan" and proc.returncode == 5) else "failed"
                    if record["status"] == "failed":
                        record["note"] = "See console.log for scanner errors/version incompatibilities."
        except Exception as exc:
            record.update(status="failed", note='Execution error: ' + reliability.record('subprocess_execution', exc))
            if proc and proc.poll() is None:
                self.kill(proc)
        except KeyboardInterrupt:
            self.cancel()
            record.update(status="cancelled", note="Run interrupted.")
        finally:
            if proc:
                with self.lock:
                    self.active.discard(proc)
            record["elapsed"] = round(time.monotonic() - start, 2)
        if job.snapshot:
            try:
                whatweb_snapshot.remap(job.folder / 'results.json', job.snapshot['url'])
                record['source_url'] = job.snapshot['url']
                record['fingerprint_mode'] = 'pinned_http_snapshot'
            except (OSError, ValueError, TypeError) as exc:
                if record['status'] == 'completed':
                    record.update(status='failed', note='WhatWeb snapshot output invalid: ' + reliability.record('whatweb_output', exc))
        if job.tool == 'dalfox' and record['exit_code'] == 1 and record['status'] == 'failed':
            record.update(status='completed', note='Dalfox exit 1: findings emitted; validation required.')
        if job.tool in web_engine.TOOLS and record['status'] == 'completed':
            note = web_engine.completion(job.tool, job.folder)
            if note:
                record.update(status='incomplete', note=note)
        self.notify(f"[{record['status'].upper()}] {job.name} ({record['elapsed']}s)")
        return record


