import asyncio
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import json
import os
from threading import BoundedSemaphore, Event
from types import SimpleNamespace
from unittest.mock import patch

import httpx
from fastapi.testclient import TestClient
from google.genai import errors

from src.config import Settings
from src.provider import ERROR_DETAIL
from src.reliability import CapacityLease, RateLimiter
from tests.offline import OfflineTestCase


class ReliabilityTestCase(OfflineTestCase):
    def setUp(self):
        super().setUp()
        self.api = self.load("src.api")
        self.controls = self.api.app.state.chat_controls
        self.http = self.stack.enter_context(TestClient(self.api.app))
        self.models.embed_content.reset_mock()
        # Logs are asserted explicitly in LoggingTests, not printed routinely.
        self.stack.enter_context(patch("src.reliability.logger.info"))

    def post(self, **kwargs):
        return self.http.post("/chat", json={"message": "Docker?"}, **kwargs)

    def assert_no_provider_work(self):
        self.models.embed_content.assert_not_called()
        self.models.generate_content.assert_not_called()

    async def raw_request(self, chunks, headers=(), client=("192.0.2.1", 1234), path="/chat"):
        """Real ASGI receive frames: TestClient combines chunked request bodies."""
        frames = iter([
            {"type": "http.request", "body": chunk, "more_body": i < len(chunks) - 1}
            for i, chunk in enumerate(chunks)
        ])
        messages = []

        async def receive():
            return next(frames, {"type": "http.disconnect"})

        async def send(message):
            messages.append(message)

        scope = {
            "type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1",
            "method": "POST", "scheme": "http", "path": path,
            "raw_path": path.encode(), "root_path": "", "query_string": b"",
            "headers": [(b"content-type", b"application/json"), *headers],
            "client": client, "server": ("offline.invalid", 80),
        }
        await self.api.app(scope, receive, send)
        start = next(m for m in messages if m["type"] == "http.response.start")
        content = b"".join(m.get("body", b"") for m in messages if m["type"] == "http.response.body")
        return start["status"], dict(start["headers"]), json.loads(content)


class BodyLimitTests(ReliabilityTestCase):
    def test_content_length_over_limit_is_rejected_before_json_parsing(self):
        self.controls.settings = replace(self.controls.settings, max_body_bytes=32)
        response = self.http.post("/chat", content=b"x" * 33)
        self.assertEqual(response.status_code, 413)
        self.assertEqual(response.json(), {"detail": "Request body too large."})
        self.assert_no_provider_work()

    def test_exact_byte_limit_accepts_valid_json(self):
        body = b'{"message":"Docker?"}'
        self.controls.settings = replace(self.controls.settings, max_body_bytes=len(body))
        response = self.http.post("/chat", content=body, headers={"Content-Type": "application/json"})
        self.assertEqual(response.status_code, 200)

    def test_streamed_body_without_content_length_exceeding_limit(self):
        self.controls.settings = replace(self.controls.settings, max_body_bytes=20)
        status, _, _ = asyncio.run(self.raw_request([b'{"message":"', b"x" * 10, b'"}']))
        self.assertEqual(status, 413)
        self.assert_no_provider_work()

    def test_false_small_content_length_cannot_bypass_counted_limit(self):
        self.controls.settings = replace(self.controls.settings, max_body_bytes=20)
        status, _, _ = asyncio.run(self.raw_request(
            [b"x" * 10, b"x" * 11], headers=[(b"content-length", b"1")]
        ))
        self.assertEqual(status, 413)
        self.assert_no_provider_work()

    def test_streamed_valid_json_is_replayed_without_truncation(self):
        status, _, body = asyncio.run(self.raw_request([b'{"message":', b'"Docker?"}']))
        self.assertEqual(status, 200)
        self.assertEqual(body, {"answer": "Offline test answer."})

    def test_limit_counts_utf8_bytes_not_characters(self):
        body = '{"message":"éééé"}'.encode()
        self.controls.settings = replace(self.controls.settings, max_body_bytes=len(body) - 1)
        self.assertEqual(self.http.post("/chat", content=body).status_code, 413)
        self.assert_no_provider_work()

    def test_invalid_and_duplicate_lengths_are_rejected(self):
        for headers in (
            [(b"content-length", b"-1")], [(b"content-length", b"invalid")],
            [(b"content-length", b"1"), (b"content-length", b"2")],
        ):
            with self.subTest(headers=headers):
                status, _, _ = asyncio.run(self.raw_request([b"{}"], headers))
                self.assertEqual(status, 400)
        self.assert_no_provider_work()

    def test_invalid_json_still_returns_validation_error(self):
        self.assertEqual(self.http.post("/chat", content=b"{").status_code, 422)
        self.assert_no_provider_work()

    def test_unknown_fields_still_return_validation_error(self):
        response = self.http.post("/chat", json={"message": "Docker?", "unexpected": True})
        self.assertEqual(response.status_code, 422)
        self.assert_no_provider_work()

    def test_cors_and_request_identifier_are_present_on_rejections(self):
        self.controls.settings = replace(self.controls.settings, max_body_bytes=1)
        response = self.http.post("/chat", content=b"{}", headers={"Origin": "http://localhost:3000"})
        self.assertEqual(response.status_code, 413)
        self.assertEqual(response.headers["access-control-allow-origin"], "http://localhost:3000")
        self.assertEqual(len(response.headers["x-request-id"]), 32)


class RateLimitTests(ReliabilityTestCase):
    def setUp(self):
        super().setUp()
        self.limiter = RateLimiter(2, 60, 2)
        self.now = 100.0
        self.limiter.clock = lambda: self.now
        self.controls.rate_limiter = self.limiter

    def test_threshold_and_retry_after(self):
        self.assertEqual(self.post().status_code, 200)
        self.assertEqual(self.post().status_code, 200)
        response = self.post()
        self.assertEqual(response.status_code, 429)
        self.assertEqual(response.headers["Retry-After"], "60")
        self.assertEqual(self.models.generate_content.call_count, 2)
        self.assertEqual(self.models.embed_content.call_count, 2)

    def test_reset_and_retry_after_round_up(self):
        self.post()
        self.post()
        self.now = 159.8
        self.assertEqual(self.post().headers["Retry-After"], "1")
        self.now = 160
        self.assertEqual(self.post().status_code, 200)

    def test_forwarding_headers_cannot_change_identity(self):
        self.post(headers={"X-Forwarded-For": "192.0.2.1"})
        self.post(headers={"X-Forwarded-For": "192.0.2.2"})
        response = self.post(headers={"X-Forwarded-For": "192.0.2.3", "Forwarded": "for=192.0.2.3"})
        self.assertEqual(response.status_code, 429)

    def test_peer_addresses_have_separate_windows(self):
        for peer in ("192.0.2.1", "192.0.2.2"):
            status, _, _ = asyncio.run(self.raw_request([b'{"message":"Docker?"}'], client=(peer, 123)))
            self.assertEqual(status, 200)
        self.assertEqual(len(self.limiter.clients), 2)

    def test_memory_cap_fails_closed_without_evicting_live_clients(self):
        self.assertEqual(self.limiter.check("one"), (None, None))
        self.assertEqual(self.limiter.check("two"), (None, None))
        self.assertEqual(self.limiter.check("three"), (503, 60))
        self.assertEqual(set(self.limiter.clients), {"one", "two"})
        self.now = 160
        self.assertEqual(self.limiter.check("three"), (None, None))
        self.assertEqual(set(self.limiter.clients), {"three"})

    def test_capacity_of_identity_table_returns_retry_after_at_endpoint(self):
        self.limiter.max_clients = 1
        self.limiter.check("another-peer")
        response = self.post()
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.headers["Retry-After"], "60")
        self.assert_no_provider_work()

    def test_health_is_not_rate_limited(self):
        self.post()
        self.post()
        self.assertEqual(self.http.get("/health").status_code, 200)


class ConcurrencyTests(ReliabilityTestCase):
    def setUp(self):
        super().setUp()
        self.controls.capacity = BoundedSemaphore(1)

    def test_saturation_fails_fast_without_provider_work(self):
        self.assertTrue(self.controls.capacity.acquire(blocking=False))
        try:
            response = self.post()
            self.assertEqual(response.status_code, 503)
            self.assertEqual(response.headers["Retry-After"], "1")
            self.assert_no_provider_work()
        finally:
            self.controls.capacity.release()

    def test_active_generation_rejects_another_request_then_releases(self):
        entered, finish = Event(), Event()

        def slow_generation(**kwargs):
            entered.set()
            if not finish.wait(5):
                raise AssertionError("Test failed to release the fake provider")
            return SimpleNamespace(text="Done", candidates=[SimpleNamespace(finish_reason="STOP")])

        self.models.generate_content.side_effect = slow_generation
        with ThreadPoolExecutor(max_workers=1) as pool:
            first = pool.submit(self.post)
            try:
                self.assertTrue(entered.wait(5))
                self.assertEqual(self.post().status_code, 503)
                self.assertEqual(self.models.generate_content.call_count, 1)
            finally:
                finish.set()
            self.assertEqual(first.result(timeout=5).status_code, 200)
        self.models.generate_content.side_effect = None
        self.assertEqual(self.post().status_code, 200)

    def test_capacity_releases_after_provider_exception_or_timeout(self):
        for failure, status in ((RuntimeError("private"), 500), (TimeoutError("private"), 504)):
            with self.subTest(failure=type(failure).__name__):
                self.models.generate_content.side_effect = failure
                self.assertEqual(self.post().status_code, status)
                self.models.generate_content.side_effect = None
                self.assertEqual(self.post().status_code, 200)

    def test_capacity_releases_after_invalid_json_or_oversized_body(self):
        self.assertEqual(self.http.post("/chat", content=b"{").status_code, 422)
        self.controls.settings = replace(self.controls.settings, max_body_bytes=32)
        self.assertEqual(self.http.post("/chat", content=b"x" * 33).status_code, 413)
        self.assertEqual(self.post().status_code, 200)

    def test_worker_lease_remains_held_after_outer_request_cancellation(self):
        capacity = BoundedSemaphore(1)
        self.assertTrue(capacity.acquire(blocking=False))
        lease = CapacityLease(capacity)
        self.assertTrue(lease.start())
        lease.release(idle_only=True)  # Middleware's cancellation cleanup.
        self.assertFalse(capacity.acquire(blocking=False))
        lease.release()  # Synchronous worker finishes here.
        lease.release()  # Cleanup must not over-release.
        self.assertTrue(capacity.acquire(blocking=False))
        self.assertFalse(capacity.acquire(blocking=False))
        capacity.release()

    def test_cancelled_asgi_request_holds_capacity_until_sync_worker_finishes(self):
        entered, finish = Event(), Event()

        def generation(**kwargs):
            entered.set()
            if not finish.wait(5):
                raise AssertionError("Fake provider was not released")
            return SimpleNamespace(text="Done", candidates=[SimpleNamespace(finish_reason="STOP")])

        self.models.generate_content.side_effect = generation

        async def scenario():
            task = asyncio.create_task(self.raw_request([b'{"message":"Docker?"}']))

            async def wait_for_worker():
                while not entered.is_set():
                    await asyncio.sleep(0.001)

            try:
                await asyncio.wait_for(wait_for_worker(), timeout=2)
                task.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await task
                self.assertFalse(self.controls.capacity.acquire(blocking=False))
            finally:
                finish.set()
                if not task.done():
                    task.cancel()
                    try:
                        await task
                    except asyncio.CancelledError:
                        pass

            async def wait_for_release():
                while not self.controls.capacity.acquire(blocking=False):
                    await asyncio.sleep(0.001)
                self.controls.capacity.release()

            await asyncio.wait_for(wait_for_release(), timeout=2)

        asyncio.run(scenario())

    def test_abandoned_request_cannot_start_provider_work_later(self):
        capacity = BoundedSemaphore(1)
        capacity.acquire()
        lease = CapacityLease(capacity)
        lease.release(idle_only=True)
        self.assertFalse(lease.start())
        self.assertTrue(capacity.acquire(blocking=False))
        capacity.release()

    def test_disconnect_before_handler_releases_capacity(self):
        async def request():
            async def receive():
                return {"type": "http.disconnect"}

            async def send(message):
                self.fail("Disconnected request should not send a response")

            await self.api.app({
                "type": "http", "method": "POST", "path": "/chat", "headers": [],
                "client": ("192.0.2.1", 123),
            }, receive, send)

        asyncio.run(request())
        self.assert_no_provider_work()
        self.assertTrue(self.controls.capacity.acquire(blocking=False))
        self.controls.capacity.release()


class ProviderPolicyTests(ReliabilityTestCase):
    def test_explicit_transport_timeouts_and_no_automatic_retries(self):
        # Client construction is now lazy; inspect policies after actual use.
        self.client_factory.assert_not_called()
        self.assertEqual(self.post().status_code, 200)
        calls = self.client_factory.call_args_list
        self.assertEqual(len(calls), 2)
        self.assertEqual([c.kwargs["http_options"].timeout for c in calls], [10000, 20000])
        self.assertEqual([c.kwargs["http_options"].retry_options.attempts for c in calls], [1, 1])

    def test_default_output_budget_is_sent_without_changing_model(self):
        self.post()
        arguments = self.models.generate_content.call_args.kwargs
        self.assertEqual(arguments["model"], "gemini-3.8-flash")
        self.assertEqual(arguments["config"]["max_output_tokens"], 1024)
        self.assertEqual(arguments["config"]["thinking_config"]["thinking_level"], "LOW")

    def test_generation_and_embedding_transport_timeouts_are_sanitized(self):
        for operation in (self.models.generate_content, self.models.embed_content):
            with self.subTest(operation=operation._mock_name):
                operation.side_effect = httpx.ReadTimeout("private provider diagnostic")
                response = self.post()
                self.assertEqual(response.status_code, 504)
                self.assertEqual(response.json(), {"detail": ERROR_DETAIL})
                operation.side_effect = None

    def test_generation_and_embedding_quota_errors(self):
        for operation in (self.models.generate_content, self.models.embed_content):
            with self.subTest(operation=operation._mock_name):
                operation.side_effect = errors.ClientError(429, {"error": {"message": "private quota detail"}})
                response = self.post()
                self.assertEqual(response.status_code, 503)
                self.assertEqual(response.headers["Retry-After"], "60")
                self.assertEqual(response.json(), {"detail": ERROR_DETAIL})
                operation.side_effect = None

    def test_sdk_gateway_timeout_and_other_provider_failures(self):
        for code, status in ((408, 504), (504, 504), (500, 502), (403, 502)):
            with self.subTest(code=code):
                self.models.generate_content.side_effect = errors.APIError(code, {"error": {"message": "private"}})
                self.assertEqual(self.post().status_code, status)

    def test_provider_connection_failure_returns_safe_gateway_error(self):
        self.models.generate_content.side_effect = httpx.ConnectError("private connection details")
        response = self.post()
        self.assertEqual(response.status_code, 502)
        self.assertEqual(response.json(), {"detail": ERROR_DETAIL})

    def test_candidate_safety_block_is_detected_even_with_text(self):
        self.models.generate_content.return_value = SimpleNamespace(
            text="Partial content", prompt_feedback=None,
            candidates=[SimpleNamespace(finish_reason="SAFETY")],
        )
        response = self.post()
        self.assertEqual(response.status_code, 502)
        self.assertEqual(response.json(), {"detail": ERROR_DETAIL})

    def test_empty_and_whitespace_provider_responses_return_safe_error(self):
        for text in (None, "", " \n\t "):
            with self.subTest(text=repr(text)):
                self.models.generate_content.return_value = SimpleNamespace(
                    text=text, candidates=[SimpleNamespace(finish_reason="STOP")],
                )
                response = self.post()
                self.assertEqual(response.status_code, 502)
                self.assertEqual(response.json(), {"detail": ERROR_DETAIL})


class ConfigurationTests(OfflineTestCase):
    def test_environment_controls_both_clients_and_output_budget(self):
        with patch.dict(os.environ, {
            "GEMINI_EMBEDDING_TIMEOUT_MS": "1234",
            "GEMINI_GENERATION_TIMEOUT_MS": "5678",
            "GEMINI_MAX_OUTPUT_TOKENS": "321",
        }):
            api = self.load("src.api")
        self.client_factory.assert_not_called()
        with TestClient(api.app) as client:
            self.assertEqual(client.post("/chat", json={"message": "Docker?"}).status_code, 200)
        calls = self.client_factory.call_args_list
        self.assertEqual(len(calls), 2)
        self.assertEqual([c.kwargs["http_options"].timeout for c in calls], [1234, 5678])
        self.assertTrue(all(c.kwargs["http_options"].retry_options.attempts == 1 for c in calls))
        self.assertEqual(self.models.generate_content.call_args.kwargs["config"]["max_output_tokens"], 321)

    def test_every_control_has_validated_positive_integer_configuration(self):
        defaults = {
            "GEMINI_EMBEDDING_TIMEOUT_MS": ("embedding_timeout_ms", 10000),
            "GEMINI_GENERATION_TIMEOUT_MS": ("generation_timeout_ms", 20000),
            "GEMINI_MAX_OUTPUT_TOKENS": ("max_output_tokens", 1024),
            "CHAT_MAX_BODY_BYTES": ("max_body_bytes", 8192),
            "CHAT_MAX_CONCURRENT": ("max_concurrent", 4),
            "CHAT_RATE_LIMIT_REQUESTS": ("rate_requests", 20),
            "CHAT_RATE_LIMIT_WINDOW_SECONDS": ("rate_window_seconds", 60),
            "CHAT_RATE_LIMIT_MAX_CLIENTS": ("rate_max_clients", 1024),
        }
        for name, (attribute, default) in defaults.items():
            with self.subTest(name=name):
                self.assertEqual(getattr(Settings.from_env(), attribute), default)
                with patch.dict(os.environ, {name: "7"}):
                    self.assertEqual(getattr(Settings.from_env(), attribute), 7)
                for invalid in ("0", "-1", "1.5", "invalid-private-value"):
                    with patch.dict(os.environ, {name: invalid}):
                        with self.assertRaises(ValueError) as error:
                            Settings.from_env()
                        self.assertNotIn(invalid, str(error.exception))


class LoggingTests(ReliabilityTestCase):
    def test_log_is_structured_and_excludes_all_sensitive_inputs(self):
        secret = "SENSITIVE-VISITOR-CONTENT"
        self.models.generate_content.side_effect = RuntimeError("SENSITIVE-PROVIDER-DIAGNOSTIC")
        with patch("src.reliability.logger.info") as info:
            response = self.http.post("/chat", json={"message": secret}, headers={
                "Authorization": "SENSITIVE-AUTHORIZATION",
                "X-Request-ID": "SENSITIVE-FORGED-ID",
            })
        info.assert_called_once()
        payload = json.loads(info.call_args.args[0])
        self.assertEqual(set(payload), {"event", "request_id", "status", "duration_ms", "provider_failure", "phase_timings_ms", "active_phase"})
        self.assertTrue(all(value >= 0 for value in payload["phase_timings_ms"].values()))
        self.assertEqual(payload["status"], 500)
        self.assertEqual(payload["provider_failure"], "unexpected")
        self.assertGreaterEqual(payload["duration_ms"], 0)
        self.assertEqual(payload["request_id"], response.headers["x-request-id"])
        serialized = json.dumps(payload) + response.text
        for sensitive in (secret, "SENSITIVE-PROVIDER-DIAGNOSTIC", "SENSITIVE-AUTHORIZATION", "SENSITIVE-FORGED-ID", "offline-test-key-not-a-secret", "Retrieved portfolio context"):
            self.assertNotIn(sensitive, serialized)

    def test_timeout_category_and_validation_rejection_are_logged(self):
        self.models.generate_content.side_effect = TimeoutError("private")
        with patch("src.reliability.logger.info") as info:
            response = self.post()
        payload = json.loads(info.call_args.args[0])
        self.assertEqual(payload["status"], 504)
        self.assertEqual(payload["provider_failure"], "timeout")
        self.assertEqual(payload["request_id"], response.headers["x-request-id"])
        with patch("src.reliability.logger.info") as info:
            self.http.post("/chat", content=b"{")
        payload = json.loads(info.call_args.args[0])
        self.assertEqual(payload["status"], 422)
        self.assertIsNone(payload["provider_failure"])
