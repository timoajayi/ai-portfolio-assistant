"""Process-local, bounded request admission and pre-JSON body protection."""

import asyncio
import json
import logging
import math
from threading import BoundedSemaphore, Lock
import time
from uuid import uuid4

from starlette.responses import JSONResponse

from src.config import Settings


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
        self.rate_limiter = RateLimiter(
            settings.rate_requests, settings.rate_window_seconds, settings.rate_max_clients
        )


class CapacityLease:
    """Retain a slot until an already-started sync provider worker finishes."""

    def __init__(self, capacity):
        self.capacity = capacity
        self.lock = Lock()
        self.started = False
        self.released = False

    def start(self):
        with self.lock:
            if self.released:
                return False
            self.started = True
            return True

    def release(self, idle_only=False):
        with self.lock:
            if not self.released and (not idle_only or not self.started):
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
            await JSONResponse({"detail": detail}, status_code=code, headers=headers)(
                scope, receive, tracked_send
            )

        try:
            # Include the redirect alias so /chat/ cannot bypass protection.
            if scope["method"] == "POST" and scope["path"] in ("/chat", "/chat/"):
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
                lease = CapacityLease(self.controls.capacity)
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

                body = bytearray()
                while True:
                    message = await receive()
                    if message["type"] == "http.disconnect":
                        status = 499  # Operational log only; peer has gone away.
                        return
                    chunk = message.get("body", b"")
                    if len(body) + len(chunk) > limit:
                        await reject(413, "Request body too large.")
                        return
                    body.extend(chunk)
                    if not message.get("more_body", False):
                        break

                delivered = False

                async def replay_body():
                    nonlocal delivered
                    if not delivered:
                        delivered = True
                        return {"type": "http.request", "body": bytes(body), "more_body": False}
                    return await receive()

                await self.app(scope, replay_body, tracked_send)
            else:
                await self.app(scope, receive, tracked_send)
        except asyncio.CancelledError:
            status = 499
            raise
        finally:
            # Validation/body errors release here. A started synchronous handler
            # owns its lease even if the surrounding ASGI task is cancelled.
            if lease is not None:
                lease.release(idle_only=True)
            logger.info(json.dumps({
                "event": "http_request",
                "request_id": request_id,
                "status": status,
                "duration_ms": round((time.monotonic() - started) * 1000, 2),
                "provider_failure": state.get("provider_failure"),
            }))
