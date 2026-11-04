"""Request-scoped monotonic timing; stores no visitor or provider content."""

from contextlib import contextmanager, nullcontext
from contextvars import ContextVar
from threading import Lock
import time


PHASES = (
    "request_admission", "worker_admission", "query_routing",
    "embedding_client_initialization", "embedding", "hybrid_retrieval",
    "generation_client_initialization", "generation", "response_preparation",
)
current_diagnostics = ContextVar("chat_diagnostics", default=None)


class ChatDeadlineExceeded(TimeoutError):
    pass


class ChatDiagnostics:
    def __init__(self, started: float, seconds: float):
        self.started = started
        self.deadline = started + seconds
        self.lock = Lock()
        self.stopped = False
        self.admitted_at = None
        self.worker_at = None
        self.durations = dict.fromkeys(PHASES, 0.0)
        self.frames = []
        self.generation = None

    def record_generation(self, metadata):
        with self.lock:
            # A worker that outlives its HTTP request must not update its log.
            if not self.stopped and time.monotonic() < self.deadline:
                self.generation = metadata.copy()

    def generation_snapshot(self):
        with self.lock:
            return self.generation.copy() if self.generation is not None else None

    def stop(self):
        with self.lock:
            self.stopped = True

    def check(self):
        with self.lock:
            expired = self.stopped or time.monotonic() >= self.deadline
        if expired:
            raise ChatDeadlineExceeded()

    def admitted(self):
        with self.lock:
            self.admitted_at = time.monotonic()

    def worker_started(self):
        with self.lock:
            self.worker_at = time.monotonic()
        self.check()

    @contextmanager
    def phase(self, name):
        self.check()
        frame = [name, time.monotonic(), 0.0]
        with self.lock:
            self.frames.append(frame)
        try:
            yield
        finally:
            with self.lock:
                elapsed = time.monotonic() - frame[1]
                self.durations[name] += max(0.0, elapsed - frame[2])
                self.frames.pop()
                if self.frames:
                    self.frames[-1][2] += elapsed
        # A completed slow call must not proceed to another provider phase.
        self.check()

    def snapshot(self):
        with self.lock:
            now = time.monotonic()
            durations = self.durations.copy()
            durations["request_admission"] = (self.admitted_at or now) - self.started
            if self.admitted_at is not None:
                durations["worker_admission"] = (self.worker_at or now) - self.admitted_at
            for position, (name, began, children) in enumerate(self.frames):
                active_child = now - self.frames[position + 1][1] if position + 1 < len(self.frames) else 0.0
                durations[name] += max(0.0, now - began - children - active_child)
            active = self.frames[-1][0] if self.frames else (
                "request_admission" if self.admitted_at is None else
                "worker_admission" if self.worker_at is None else None
            )
            return {key: round(max(0.0, value) * 1000, 2) for key, value in durations.items()}, active


def phase(name):
    diagnostics = current_diagnostics.get()
    return diagnostics.phase(name) if diagnostics is not None else nullcontext()
