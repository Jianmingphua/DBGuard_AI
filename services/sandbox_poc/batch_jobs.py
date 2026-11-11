"""Background batches: one at a time per service process, progress in memory, start and
finish in the durable history. A batch found RUNNING after its process died is INTERRUPTED.

Nothing here executes SQL or talks to Docker: it only runs the reviewed batch function in
a thread and turns its progress events into the fields the UI polls.
"""
from collections import OrderedDict
import copy
import logging
import os
import threading
import time
import uuid
from datetime import datetime, timezone

from . import history
from . import terminal_capture
from .shared import ContractError

logger = logging.getLogger(__name__)

# Identifies this process in the history, so a restart (even with the same PID) is seen.
PROCESS_TOKEN = uuid.uuid4().hex
RUNNING, INTERRUPTED = "RUNNING", "INTERRUPTED"
FINAL = ("VERIFIED", "PARTIAL", "FAILED", "CLEANUP_FAILED", INTERRUPTED)
MAX_STEPS = 500  # progress lines kept per batch
INTERRUPTED_REASON = ("The service stopped while this batch was running, so it has no result. "
                      "Run the batch again.")


class BatchBusy(Exception):
    """Another batch is running in this service."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class BatchJob:
    def __init__(self, batch_id: str, fixes: int, clock=time.monotonic):
        self.id = batch_id
        self.clock = clock
        self.lock = threading.Lock()
        self.started = clock()
        self.finished = None
        self.status = RUNNING
        self.phase, self.step, self.current_fix = "starting", "starting", None
        self.step_text = "Starting…"
        self.steps = []
        self.result = None
        # Work units: one per individual test, one per fix in each combined test,
        # one undo per combined test, one for the package.
        self.fixes = fixes
        self.individual_done = 0
        self.passing = 0
        self.attempts = []  # [{"size", "done", "finished"}]
        self.package_done = 0
        self._individual_started = None
        self._individual_seconds = []
        self._combined_last = None
        self._combined_seconds = []

    def event(self, event: dict) -> None:
        """Progress callback given to batch.run_batch (called from the batch thread)."""
        kind, now = event.get("kind"), self.clock()
        with self.lock:
            if kind == "plan":
                self.fixes = event.get("count", self.fixes)
            elif kind == "individual_start":
                self._individual_started = now
            elif kind == "individual_done":
                self.individual_done += 1
                if self._individual_started is not None:
                    self._individual_seconds.append(now - self._individual_started)
                    self._individual_started = None
                if event.get("status") == "PASSED":
                    self.passing += 1
            elif kind == "combined_start":
                self.attempts.append({"size": event.get("count", 0), "done": 0, "finished": False})
                self._combined_last = now
            elif kind in ("combined_step", "combined_check") and self.attempts:
                current = self.attempts[-1]
                current["done"] = min(current["size"], current["done"] + 1)
                if self._combined_last is not None:
                    self._combined_seconds.append(now - self._combined_last)
                self._combined_last = now
            elif kind == "combined_done" and self.attempts:
                self.attempts[-1]["finished"] = True
            elif kind == "done":
                self.package_done = 1
            self.phase = event.get("phase", self.phase)
            self.step = event.get("step", self.step)
            if "fix_id" in event:
                self.current_fix = event["fix_id"]
            elif kind in ("restart", "rollback", "bundle", "done", "combined_start", "combined_done"):
                self.current_fix = None
            text = event.get("text")
            if isinstance(text, str) and text:
                self.step_text = text
                line = {"at": _now(), "text": text}
                line.update({k: event[k] for k in ("fix_id", "status") if event.get(k) is not None})
                self.steps.append(line)
                del self.steps[:-MAX_STEPS]

    def finish(self, status: str, result: dict | None) -> None:
        with self.lock:
            self.status = status if status in FINAL else "FAILED"
            self.result = result
            self.finished = self.clock()
            self.current_fix = None
            self.phase = self.step = "done"

    def _counts(self) -> tuple[int, int]:
        if not self.attempts:
            # No combined test yet: assume every fix still in the race reaches it.
            combined_total = self.passing + (self.fixes - self.individual_done)
            undo = 1
        else:
            combined_total = sum(a["done"] if a["finished"] else a["size"] for a in self.attempts)
            undo = len(self.attempts)
        total = self.fixes + combined_total + undo + 1
        done = (self.individual_done + sum(a["done"] for a in self.attempts)
                + sum(1 for a in self.attempts if a["finished"]) + self.package_done)
        if self.status != RUNNING:
            return total, total
        return min(done, total), total

    def _estimate(self) -> int | None:
        """Seconds left, from the average time per step measured so far in this batch."""
        if self.status != RUNNING or not self._individual_seconds:
            return 0 if self.status != RUNNING else None
        individual = sum(self._individual_seconds) / len(self._individual_seconds)
        # Before any combined step is timed, assume half an individual test per fix.
        combined = (sum(self._combined_seconds) / len(self._combined_seconds)
                    if self._combined_seconds else individual / 2)
        left_individual = self.fixes - self.individual_done
        if not self.attempts:
            left_combined = self.passing + left_individual
        else:
            current = self.attempts[-1]
            left_combined = 0 if current["finished"] else current["size"] - current["done"]
        # Undoing takes about as long as applying; the package is about one step.
        return round(left_individual * individual + left_combined * combined * 2 + combined)

    def progress(self) -> dict:
        with self.lock:
            done, total = self._counts()
            end = self.finished if self.finished is not None else self.clock()
            return {"status": self.status, "done": done, "total": total, "phase": self.phase,
                    "current_fix": self.current_fix, "step": self.step, "step_text": self.step_text,
                    "elapsed_seconds": round(end - self.started, 1), "estimate_seconds": self._estimate(),
                    "steps": copy.deepcopy(self.steps)}

    def view(self) -> dict:
        view = {"batch_id": self.id, "run_id": self.id, **self.progress()}
        with self.lock:
            view["result"] = self.result if self.status != RUNNING else None
        return view


class BatchJobs:
    """Process-local registry. Only one batch runs at a time; finished ones stay readable."""

    def __init__(self, keep: int = 8):
        self.keep = keep
        self.lock = threading.Lock()
        self.jobs = OrderedDict()

    def get(self, batch_id: str) -> BatchJob | None:
        with self.lock:
            return self.jobs.get(batch_id)

    def busy(self) -> bool:
        with self.lock:
            return any(job.status == RUNNING for job in self.jobs.values())

    def start(self, fixes: int, work, on_start, on_finish, batch_id: str | None = None) -> BatchJob:
        """Start ``work(progress) -> (result, bundle)`` in a background thread.

        ``on_start(job)`` records the RUNNING batch before the thread starts;
        ``on_finish(job, result, bundle)`` stores the outcome. BatchBusy if one is running.
        """
        with self.lock:
            if any(job.status == RUNNING for job in self.jobs.values()):
                raise BatchBusy()
            job = BatchJob(batch_id or str(uuid.uuid4()), fixes)
            self.jobs[job.id] = job
            for old in [key for key, item in self.jobs.items() if item.status != RUNNING][:-self.keep]:
                del self.jobs[old]
        try:
            on_start(job)
            thread = threading.Thread(target=self._run, args=(job, work, on_finish), daemon=True,
                                      name="dbguard-batch-" + job.id[:8])
            thread.start()
        except BaseException:
            job.finish("FAILED", None)
            with self.lock:
                self.jobs.pop(job.id, None)
            raise
        return job

    @staticmethod
    def _run(job: BatchJob, work, on_finish) -> None:
        try:
            # Melvin (10 Nov): no screenshots inside the sandbox for batches.
            with terminal_capture.suppressed():
                result, bundle = work(job.event)
        except Exception as exc:
            # Our own contract messages are safe to show; anything else only by type.
            reason = (str(exc) if isinstance(exc, ContractError)
                      else f"The batch stopped with an internal error ({type(exc).__name__})")
            logger.warning("Sandbox batch %s stopped: %s", job.id, type(exc).__name__)
            result, bundle = {"run_id": job.id, "schema_version": "sandbox-batch-v1", "status": "FAILED",
                              "reason": reason, "fixes": [], "requires_dba_review": True}, None
            job.event({"kind": "done", "status": "FAILED", "phase": "done", "step": "done",
                       "text": f"Finished: FAILED. {reason}"})
        try:
            result = on_finish(job, result, bundle) or result
        except Exception as exc:
            logger.warning("Sandbox batch %s result could not be stored: %s", job.id, type(exc).__name__)
        job.finish(result.get("status", "FAILED"), result)


JOBS = BatchJobs()


def owner() -> dict:
    return {"pid": os.getpid(), "token": PROCESS_TOKEN}


def _process_alive(pid) -> bool:
    if not isinstance(pid, int) or pid <= 0 or pid == os.getpid():
        # Our own PID with another token: the PID was reused by this restarted service.
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except OSError:
        return True  # exists, owned by someone else
    return True


def reconcile(jobs: BatchJobs | None = None) -> list[str]:
    """Mark recorded batches INTERRUPTED when the process that ran them is gone.

    A RUNNING row belongs to a live batch only if this process still tracks it, or another
    live service process (the demo and main API share one history folder) owns it.
    """
    jobs = jobs or JOBS
    marked = []
    for run_id, result in history.running_batches():
        mine = (result.get("owner") or {}).get("token") == PROCESS_TOKEN
        if (mine and jobs.get(run_id) is not None) or (
                not mine and _process_alive((result.get("owner") or {}).get("pid"))):
            continue
        progress = dict(result.get("progress") or {})
        progress.update(status=INTERRUPTED, current_fix=None, step="interrupted", estimate_seconds=0,
                        step_text=INTERRUPTED_REASON)
        result.update(status=INTERRUPTED, reason=INTERRUPTED_REASON, progress=progress)
        history.update_result(run_id, result)
        marked.append(run_id)
    return marked


def stored_view(batch_id: str, result: dict) -> dict:
    """The GET shape for a batch read back from history (after a reload or restart)."""
    progress = {"done": 0, "total": 0, "phase": "done", "current_fix": None, "step": "done",
                "step_text": "", "elapsed_seconds": None, "estimate_seconds": 0, "steps": [],
                **(result.get("progress") or {})}
    status = result.get("status")
    progress["status"] = status
    final = status in FINAL and status != INTERRUPTED
    view = {"batch_id": batch_id, "run_id": batch_id, **progress, "result": result if final else None}
    if status == INTERRUPTED:
        view["reason"] = result.get("reason")
    return view
