import asyncio
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import json
import os
from threading import BoundedSemaphore, Event
import time
from types import SimpleNamespace
from unittest.mock import patch

import anyio.to_thread

from src.config import Settings
from src.diagnostics import PHASES
from src.provider import ERROR_DETAIL
from src.reliability import CapacityLease
from tests.offline import OfflineTestCase
from tests.test_reliability import ReliabilityTestCase


class DeadlineTests(ReliabilityTestCase):
    def setUp(self):
        super().setUp()
        self.controls.settings = replace(self.controls.settings, chat_deadline_seconds=0.05)
        self.controls.capacity = BoundedSemaphore(1)

    def available(self):
        acquired = self.controls.capacity.acquire(blocking=False)
        if acquired:
            self.controls.capacity.release()
        return acquired

    def wait_until(self, predicate):
        end = time.monotonic() + 2
        while not predicate():
            if time.monotonic() >= end:
                self.fail("Background operation did not finish")
            time.sleep(0.002)

    def blocked_operation(self, operation, failure=False):
        entered, finish, exited = Event(), Event(), Event()
        original = operation.return_value

        def blocked(*args, **kwargs):
            entered.set()
            try:
                if not finish.wait(3):
                    raise AssertionError("Test did not release mock")
                if failure:
                    raise RuntimeError("PRIVATE-LATE-PROVIDER-ERROR")
                return original
            finally:
                exited.set()

        operation.side_effect = blocked
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(self.post)
            try:
                self.assertTrue(entered.wait(2))
                response = future.result(timeout=0.8)
                self.assertEqual(response.status_code, 504)
                self.assertEqual(response.json(), {"detail": ERROR_DETAIL})
                self.assertFalse(exited.is_set(), "504 waited for the blocked worker")
                self.assertFalse(self.available())
                self.assertEqual(self.http.get("/health").status_code, 200)
                self.assertEqual(self.http.get("/ready").status_code, 200)
                self.assertEqual(self.post().status_code, 503)
            finally:
                finish.set()
            self.assertTrue(exited.wait(2))
        self.wait_until(self.available)
        self.wait_until(lambda: not self.controls.tasks)
        return response

    def test_fast_success_preserves_schema(self):
        # Give successful work scheduling headroom on a busy test runner.
        self.controls.settings = replace(self.controls.settings, chat_deadline_seconds=1)
        response = self.post()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"answer": "Offline test answer."})
        self.assertTrue(self.available())
        self.assertFalse(self.controls.tasks)

    def test_slow_embedding_returns_deadline_before_worker_exits(self):
        self.blocked_operation(self.models.embed_content)
        self.models.generate_content.assert_not_called()

    def test_slow_generation_returns_deadline_before_worker_exits(self):
        self.blocked_operation(self.models.generate_content)
        self.models.generate_content.assert_called_once()

    def test_slow_embedding_client_initialization_is_covered(self):
        self.client_factory.return_value = self.provider
        self.blocked_operation(self.client_factory)
        self.models.embed_content.assert_not_called()
        self.models.generate_content.assert_not_called()

    def test_slow_generation_client_initialization_is_covered(self):
        embeddings = self.load("src.embeddings")
        embeddings.get_client()  # Query embedding client is already initialized.
        self.client_factory.reset_mock()
        self.client_factory.return_value = self.provider
        self.blocked_operation(self.client_factory)
        self.models.embed_content.assert_called_once()
        self.models.generate_content.assert_not_called()

    def test_slow_routing_is_covered(self):
        with patch.object(self.api, "is_project_collection_query", return_value=False) as route:
            self.blocked_operation(route)
        self.models.embed_content.assert_not_called()

    def test_slow_retrieval_is_covered(self):
        with patch.object(self.api, "retrieve_relevant_chunks", return_value=[("Evidence", 1.0)]) as retrieve:
            self.blocked_operation(retrieve)
        self.models.generate_content.assert_not_called()

    def test_slow_response_preparation_is_covered(self):
        with patch.object(self.api, "response_text", return_value="Prepared answer") as prepare:
            self.blocked_operation(prepare)

    def test_late_provider_exception_does_not_leak_or_release_twice(self):
        response = self.blocked_operation(self.models.generate_content, failure=True)
        self.assertNotIn("PRIVATE-LATE-PROVIDER-ERROR", response.text)
        self.assertTrue(self.controls.capacity.acquire(blocking=False))
        try:
            self.assertFalse(self.controls.capacity.acquire(blocking=False))
        finally:
            self.controls.capacity.release()

    def test_late_work_does_not_start_additional_provider_phases(self):
        self.blocked_operation(self.models.embed_content)
        self.models.generate_content.assert_not_called()
        self.client_factory.assert_called_once()

    def test_repeated_requests_cannot_create_unbounded_workers(self):
        entered, finish = Event(), Event()

        def blocked(**kwargs):
            entered.set()
            if not finish.wait(3):
                raise AssertionError("Mock was not released")
            return SimpleNamespace(text="late answer")

        self.models.generate_content.side_effect = blocked
        with ThreadPoolExecutor(max_workers=1) as pool:
            first = pool.submit(self.post)
            try:
                self.assertTrue(entered.wait(2))
                self.assertEqual(first.result(timeout=0.8).status_code, 504)
                for _ in range(8):
                    self.assertEqual(self.post().status_code, 503)
                    self.assertLessEqual(len(self.controls.tasks), 1)
                self.models.embed_content.assert_called_once()
                self.models.generate_content.assert_called_once()
                self.assertFalse(self.available())
            finally:
                finish.set()
        self.wait_until(self.available)

    def test_worker_pool_admission_timeout_does_not_start_work_later(self):
        async def acquire_worker_pool():
            limiter = anyio.to_thread.current_default_thread_limiter()
            limiter.total_tokens = 1
            borrower = object()
            await limiter.acquire_on_behalf_of(borrower)
            return limiter, borrower

        limiter, borrower = self.http.portal.call(acquire_worker_pool)
        try:
            with patch("src.reliability.logger.info") as info:
                response = self.post()
            self.assertEqual(response.status_code, 504)
            record = json.loads(info.call_args.args[0])
            self.assertEqual(record["active_phase"], "worker_admission")
            self.assertGreater(record["phase_timings_ms"]["worker_admission"], 0)
            self.assertEqual(self.http.get("/health").status_code, 200)
            self.assertEqual(self.http.get("/ready").status_code, 200)
            self.assert_no_provider_work()
            self.wait_until(self.available)
        finally:
            self.http.portal.call(limiter.release_on_behalf_of, borrower)
            self.http.portal.call(setattr, limiter, "total_tokens", 40)
        self.models.embed_content.assert_not_called()
        self.controls.settings = replace(self.controls.settings, chat_deadline_seconds=1)
        self.assertEqual(self.post().status_code, 200)

    def test_body_upload_wait_is_also_bounded(self):
        async def request():
            async def receive():
                await asyncio.sleep(2)
                return {"type": "http.request", "body": b"{}", "more_body": False}

            sent = []

            async def send(message):
                sent.append(message)

            await asyncio.wait_for(self.api.app({
                "type": "http", "method": "POST", "path": "/chat", "headers": [],
                "client": ("192.0.2.1", 1),
            }, receive, send), timeout=0.8)
            self.assertEqual(sent[0]["status"], 504)

        asyncio.run(request())
        self.assert_no_provider_work()
        self.wait_until(self.available)

    def test_cancellation_during_provider_work_keeps_slot(self):
        entered, finish = Event(), Event()

        def blocked(**kwargs):
            entered.set()
            if not finish.wait(3):
                raise AssertionError("Mock was not released")
            return self.models.generate_content.return_value

        self.models.generate_content.side_effect = blocked

        async def request():
            task = asyncio.create_task(self.raw_request([b'{"message":"Docker?"}']))
            try:
                async def wait_for_worker():
                    while not entered.is_set():
                        await asyncio.sleep(0.001)
                await asyncio.wait_for(wait_for_worker(), timeout=1)
                task.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await task
                self.assertFalse(self.available())
            finally:
                finish.set()
                if not task.done():
                    task.cancel()

        asyncio.run(request())
        self.wait_until(self.available)

    def test_buffered_headers_prevent_a_late_success_response(self):
        original = self.api.app.middleware_stack

        # Wrap only the inner downstream app; preserve normal admission.
        protection = original
        while not hasattr(protection, "controls"):
            protection = protection.app

        async def delayed_response(scope, receive, send):
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await asyncio.sleep(2)
            await send({"type": "http.response.body", "body": b'{"answer":"late"}'})

        with patch.object(protection, "app", delayed_response):
            response = self.post()
        self.assertEqual(response.status_code, 504)
        self.assertEqual(response.json(), {"detail": ERROR_DETAIL})
        self.wait_until(self.available)
        self.assert_no_provider_work()

    def test_failure_before_worker_starts_releases_capacity(self):
        protection = self.api.app.middleware_stack
        while not hasattr(protection, "controls"):
            protection = protection.app

        async def fail_before_worker(scope, receive, send):
            raise RuntimeError("PRIVATE-PRE-WORKER-FAILURE")

        with patch.object(protection, "app", fail_before_worker):
            response = self.post()
        self.assertEqual(response.status_code, 500)
        self.assertEqual(response.json(), {"detail": ERROR_DETAIL})
        self.wait_until(self.available)
        self.assertFalse(self.controls.tasks)
        self.assert_no_provider_work()

    def test_cancellation_resistant_operation_remains_bounded(self):
        protection = self.api.app.middleware_stack
        while not hasattr(protection, "controls"):
            protection = protection.app
        finished = Event()

        async def resist_cancellation(scope, receive, send):
            try:
                await asyncio.sleep(2)
            except asyncio.CancelledError:
                while not finished.is_set():
                    await asyncio.sleep(0.002)
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": b'{"answer":"late"}'})

        with patch.object(protection, "app", resist_cancellation):
            try:
                response = self.post()
                self.assertEqual(response.status_code, 504)
                self.assertEqual(response.json(), {"detail": ERROR_DETAIL})
                self.assertFalse(self.available())
                self.assertEqual(len(self.controls.tasks), 1)
                for _ in range(3):
                    self.assertEqual(self.post().status_code, 503)
                    self.assertEqual(len(self.controls.tasks), 1)
            finally:
                finished.set()
            self.wait_until(lambda: not self.controls.tasks)
        self.wait_until(self.available)
        self.assert_no_provider_work()

    def test_queued_workers_cancel_without_accumulating_provider_work(self):
        async def occupy_pool():
            limiter = anyio.to_thread.current_default_thread_limiter()
            borrower = object()
            limiter.total_tokens = 1
            await limiter.acquire_on_behalf_of(borrower)
            return limiter, borrower

        limiter, borrower = self.http.portal.call(occupy_pool)
        try:
            for _ in range(3):
                self.assertEqual(self.post().status_code, 504)
                self.wait_until(lambda: not self.controls.tasks)
                self.assertTrue(self.available())
                self.assert_no_provider_work()
        finally:
            self.http.portal.call(limiter.release_on_behalf_of, borrower)
            self.http.portal.call(setattr, limiter, "total_tokens", 40)
        self.assert_no_provider_work()

    def test_provider_transport_timeout_keeps_separate_category(self):
        self.controls.settings = replace(self.controls.settings, chat_deadline_seconds=1)
        self.models.generate_content.side_effect = TimeoutError("PRIVATE-TRANSPORT-ERROR")
        with patch("src.reliability.logger.info") as info:
            response = self.post()
        self.assertEqual(response.status_code, 504)
        self.assertEqual(response.json(), {"detail": ERROR_DETAIL})
        self.assertEqual(json.loads(info.call_args.args[0])["provider_failure"], "timeout")
        self.assertTrue(self.available())

    def test_deadline_response_preserves_cors_and_request_id(self):
        entered, finish = Event(), Event()

        def blocked(**kwargs):
            entered.set()
            if not finish.wait(3):
                raise AssertionError("Mock was not released")
            return SimpleNamespace(text="late answer")

        self.models.generate_content.side_effect = blocked
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(self.post, headers={"Origin": "http://localhost:3000"})
            try:
                self.assertTrue(entered.wait(2))
                response = future.result(timeout=0.8)
                self.assertEqual(response.status_code, 504)
                self.assertEqual(response.headers["access-control-allow-origin"], "http://localhost:3000")
                self.assertEqual(len(response.headers["x-request-id"]), 32)
            finally:
                finish.set()
        self.wait_until(self.available)

    def test_phase_logs_are_sanitized_and_no_late_success_is_logged(self):
        with patch("src.reliability.logger.info") as info:
            self.blocked_operation(self.models.generate_content)
            records = [json.loads(call.args[0]) for call in info.call_args_list]
        chat_records = [record for record in records if record.get("provider_failure") == "deadline"]
        self.assertEqual(len(chat_records), 1)
        record = chat_records[0]
        self.assertEqual(record["status"], 504)
        self.assertEqual(record["active_phase"], "generation")
        self.assertEqual(set(record["phase_timings_ms"]), set(PHASES))
        self.assertGreater(record["phase_timings_ms"]["generation"], 0)
        self.assertFalse(any(r["status"] == 200 and r["request_id"] == record["request_id"] for r in records))
        serialized = json.dumps(records)
        for sensitive in ("Docker?", "Offline test answer.", "offline-test-key-not-a-secret",
                          "Retrieved portfolio context", "Authorization"):
            self.assertNotIn(sensitive, serialized)

    def test_fast_phase_timings_have_no_active_phase(self):
        self.controls.settings = replace(self.controls.settings, chat_deadline_seconds=1)
        with patch("src.reliability.logger.info") as info:
            self.assertEqual(self.post().status_code, 200)
        record = json.loads(info.call_args.args[0])
        self.assertIsNone(record["active_phase"])
        self.assertEqual(set(record["phase_timings_ms"]), set(PHASES))
        self.assertTrue(all(0 <= value <= record["duration_ms"] + 1 for value in record["phase_timings_ms"].values()))

    def test_existing_body_and_rate_rejections_precede_provider_work(self):
        self.controls.settings = replace(self.controls.settings, max_body_bytes=1)
        self.assertEqual(self.http.post("/chat", content=b"{}").status_code, 413)
        self.controls.rate_limiter.requests = 1
        response = self.post()
        self.assertEqual(response.status_code, 429)
        self.assertIn("Retry-After", response.headers)
        self.assert_no_provider_work()
        self.assertTrue(self.available())

    def test_lease_requires_both_worker_and_operation_completion(self):
        capacity = BoundedSemaphore(1)
        capacity.acquire()
        lease = CapacityLease(capacity, operation_owned=True)
        self.assertTrue(lease.start())
        lease.release()
        self.assertFalse(capacity.acquire(blocking=False))
        lease.finish_operation()
        lease.release()
        lease.finish_operation()
        self.assertTrue(capacity.acquire(blocking=False))
        self.assertFalse(capacity.acquire(blocking=False))
        capacity.release()


class DeadlineConfigurationTests(OfflineTestCase):
    def test_default_and_fractional_deadline_configuration(self):
        self.assertEqual(Settings.from_env().chat_deadline_seconds, 40)
        for value in ("0.01", "0.05", "40", "120"):
            with patch.dict(os.environ, {"CHAT_DEADLINE_SECONDS": value}):
                self.assertEqual(Settings.from_env().chat_deadline_seconds, float(value))

    def test_invalid_deadline_configuration_does_not_echo_values(self):
        for value in ("0", "-1", "0.001", "121", "nan", "inf", "", "PRIVATE-CONFIG-VALUE"):
            with self.subTest(value=value), patch.dict(os.environ, {"CHAT_DEADLINE_SECONDS": value}):
                with self.assertRaises(ValueError) as failure:
                    Settings.from_env()
                self.assertIn("CHAT_DEADLINE_SECONDS", str(failure.exception))
                self.assertNotIn("PRIVATE-CONFIG-VALUE", str(failure.exception))
