"""Process-local, bounded request admission and pre-JSON body protection."""

import asyncio
import json
import logging
import math
import re
import secrets
from threading import BoundedSemaphore, Lock
import time
from uuid import uuid4

from starlette.responses import JSONResponse

from src.config import Settings
from src.diagnostics import ChatDiagnostics, current_diagnostics
from src.provider import ERROR_DETAIL


logger = logging.getLogger("portfolio.api")
if not logger.handlers:
    logger.addHandler(logging.StreamHandler())
logger.setLevel(logging.INFO)
logger.propagate = False


class RateLimiter:
    """Fixed windows; live entries are never evicted to admit new identities."""

    def __init__(self, requests: int, window_seconds: int, max_clients: int):
        self.requests = requests
        self.window_seconds = window_seconds
        self.max_clients = max_clients
        self.clients = {}
        self.lock = Lock()
        self.clock = time.monotonic

    def check(self, peer: str) -> tuple[int | None, int | None]:
        with self.lock:
            now = self.clock()
            expired = [key for key, (_, reset) in self.clients.items() if reset <= now]
            for key in expired:
                del self.clients[key]
            if peer not in self.clients:
                if len(self.clients) >= self.max_clients:
                    reset = min(reset for _, reset in self.clients.values())
                    return 503, max(1, math.ceil(reset - now))
                self.clients[peer] = (1, now + self.window_seconds)
                return None, None
            count, reset = self.clients[peer]
            if count >= self.requests:
                return 429, max(1, math.ceil(reset - now))
            self.clients[peer] = (count + 1, reset)
            return None, None


class ChatControls:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.capacity = BoundedSemaphore(settings.max_concurrent)
        self.tasks = set()
        self.rate_limiter = RateLimiter(
            settings.rate_requests, settings.rate_window_seconds, settings.rate_max_clients
        )
        # One constant identity gives a bounded aggregate budget, independent of IP.
        self.authenticated_budget = RateLimiter(
            settings.staging_budget_requests, settings.staging_budget_window_seconds, 1
        )


def staging_authorized(scope, expected: str) -> bool:
    headers = [value for key, value in scope.get("headers", [])
               if key.lower() == b"authorization"]
    if len(headers) != 1:
        return False
    match = re.fullmatch(rb"(?i:Bearer) ([A-Za-z0-9_-]{43,256})", headers[0])
    return match is not None and secrets.compare_digest(match[1], expected.encode("ascii"))


class CapacityLease:
    """Retain a slot until an already-started sync provider worker finishes."""

    def __init__(self, capacity, operation_owned=False):
        self.capacity = capacity
        self.lock = Lock()
        self.started = False
        self.released = False
        self.aborted = False
        self.worker_finished = False
        self.operation_finished = not operation_owned

    def start(self):
        with self.lock:
            if self.released or self.aborted:
                return False
            self.started = True
            return True

    def release(self, idle_only=False):
        with self.lock:
            if not idle_only or not self.started:
                self.worker_finished = True
                self._release_if_finished()

    def abort(self):
        with self.lock:
            self.aborted = True

    def finish_operation(self):
        with self.lock:
            self.operation_finished = True
            self._release_if_finished()

    def _release_if_finished(self):
        if (not self.released and self.operation_finished
                and (not self.started or self.worker_finished)):
            self.released = True
            self.capacity.release()


class ChatProtectionMiddleware:
    def __init__(self, app, controls: ChatControls):
        self.app = app
        self.controls = controls

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request_id = uuid4().hex
        started = time.monotonic()
        status = 500
        lease = None
        task = None
        diagnostics = None
        accept_response = True
        state = scope.setdefault("state", {})
        state["request_id"] = request_id

        async def tracked_send(message):
            nonlocal status
            if message["type"] == "http.response.start":
                status = message["status"]
                message = dict(message)
                message["headers"] = list(message.get("headers", [])) + [
                    (b"x-request-id", request_id.encode("ascii"))
                ]
            await send(message)

        async def reject(code, detail, retry_after=None):
            headers = {"Retry-After": str(retry_after)} if retry_after is not None else None
            if code == 401:
                headers = {"WWW-Authenticate": "Bearer"}
            await JSONResponse({"detail": detail}, status_code=code, headers=headers)(
                scope, receive, tracked_send
            )

        try:
            # Default-deny all routes except public health checks. Future paid
            # endpoints inherit this gate without remembering a dependency.
            public_health = (scope["method"] in ("GET", "HEAD")
                             and scope["path"] in ("/health", "/ready"))
            if self.controls.settings.staging_auth_enabled and not public_health:
                if not staging_authorized(scope, self.controls.settings.staging_auth_token):
                    await reject(401, "Unauthorized.")
                    return
                limited_status, retry = self.controls.authenticated_budget.check("authenticated")
                if limited_status:
                    await reject(429, "Request limit exceeded. Please try again later.", retry)
                    return

            # Include the redirect alias so /chat/ cannot bypass protection.
            if scope["method"] == "POST" and scope["path"] in ("/chat", "/chat/"):
                diagnostics = ChatDiagnostics(started, self.controls.settings.chat_deadline_seconds)
                state["chat_diagnostics"] = diagnostics
                peer = scope.get("client")
                # ASGI peer only. Forwarding-header trust belongs at the server.
                peer = peer[0] if peer else "unknown"
                limited_status, retry = self.controls.rate_limiter.check(peer)
                if limited_status:
                    await reject(limited_status, "Request limit exceeded. Please try again later.", retry)
                    return
                if not self.controls.capacity.acquire(blocking=False):
                    await reject(503, "The AI assistant is busy. Please try again later.", 1)
                    return
                lease = CapacityLease(self.controls.capacity, operation_owned=True)
                state["chat_capacity"] = lease

                limit = self.controls.settings.max_body_bytes
                lengths = [value for key, value in scope.get("headers", [])
                           if key.lower() == b"content-length"]
                if lengths:
                    try:
                        if len(lengths) != 1 or not lengths[0].isdigit():
                            raise ValueError()
                        length = int(lengths[0])
                    except ValueError:
                        await reject(400, "Invalid request body length.")
                        return
                    if length > limit:
                        await reject(413, "Request body too large.")
                        return

                response_messages = []

                async def capture_send(message):
                    # Do not commit headers until response preparation finishes.
                    # In particular, never forward a late 200 after a 504.
                    if accept_response:
                        response_messages.append(message)

                async def run_operation():
                    nonlocal status
                    token = current_diagnostics.set(diagnostics)
                    try:
                        body = bytearray()
                        while True:
                            message = await receive()
                            if message["type"] == "http.disconnect":
                                status = 499
                                return
                            chunk = message.get("body", b"")
                            if len(body) + len(chunk) > limit:
                                await JSONResponse({"detail": "Request body too large."}, status_code=413)(
                                    scope, receive, capture_send
                                )
                                return
                            body.extend(chunk)
                            if not message.get("more_body", False):
                                break
                        diagnostics.admitted()
                        delivered = False

                        async def replay_body():
                            nonlocal delivered
                            if not delivered:
                                delivered = True
                                return {"type": "http.request", "body": bytes(body), "more_body": False}
                            return await receive()

                        await self.app(scope, replay_body, capture_send)
                    finally:
                        current_diagnostics.reset(token)

                task = asyncio.create_task(run_operation())
                self.controls.tasks.add(task)

                def operation_done(completed):
                    self.controls.tasks.discard(completed)
                    lease.finish_operation()
                    # Consume abandoned exceptions without logging provider data.
                    if not completed.cancelled():
                        completed.exception()

                task.add_done_callback(operation_done)
                remaining = max(0.0, diagnostics.deadline - time.monotonic())
                done, _ = await asyncio.wait({task}, timeout=remaining)
                if not done or time.monotonic() >= diagnostics.deadline:
                    accept_response = False
                    diagnostics.stop()
                    state["provider_failure"] = "deadline"
                    lease.abort()
                    task.cancel()
                    # Deliberately do not await cancellation: AnyIO/sync worker
                    # completion must not postpone this response.
                    await reject(504, ERROR_DETAIL)
                    return
                try:
                    task.result()
                except Exception:
                    state["provider_failure"] = "unexpected"
                    await reject(500, ERROR_DETAIL)
                    return
                for message in response_messages:
                    await tracked_send(message)
            else:
                await self.app(scope, receive, tracked_send)
        except asyncio.CancelledError:
            status = 499
            accept_response = False
            if diagnostics is not None:
                diagnostics.stop()
            if lease is not None:
                lease.abort()
            if task is not None:
                task.cancel()
            raise
        finally:
            # With a task, its completion callback owns operation cleanup.
            # A cancelled task may finish before its synchronous worker does.
            if lease is not None and task is None:
                lease.finish_operation()
            payload = {
                "event": "http_request",
                "request_id": request_id,
                "status": status,
                "duration_ms": round((time.monotonic() - started) * 1000, 2),
                "provider_failure": state.get("provider_failure"),
            }
            if diagnostics is not None:
                payload["phase_timings_ms"], payload["active_phase"] = diagnostics.snapshot()
                generation = diagnostics.generation_snapshot()
                if generation is not None:
                    payload["generation"] = generation
                if status not in (504, 499):
                    payload["active_phase"] = None
                if status == 504 and diagnostics.stopped:
                    payload["provider_failure"] = "deadline"
            logger.info(json.dumps(payload))
