"""Actual SDK serialization with memory-only HTTP; independent client cleanup."""

import asyncio
import json
import traceback
from unittest.mock import Mock, patch

from fastapi.testclient import TestClient
from google import genai
import httpx

from src.provider import ERROR_DETAIL
from tests.offline import OfflineTestCase


SDK_CLIENT = genai.Client


class SDKGenerationLifecycleTests(OfflineTestCase):
    def exercise(self, reason, *, upstream_status=200, expected_status=200):
        api = self.load("src.api")
        requests = []
        private = "PRIVATE-PROVIDER-CONTENT"

        def handle(request):
            requests.append(request)
            if upstream_status != 200:
                return httpx.Response(upstream_status, json={
                    "error": {"code": upstream_status, "message": private},
                })
            candidate = {
                "content": {"role": "model", "parts": [{"text": private}]},
                "finishReason": reason if len(requests) == 1 else "STOP",
            }
            if reason == "CONTINUATION" and len(requests) == 1:
                candidate["continuationToken"] = "b2ZmbGluZQ=="
            return httpx.Response(200, json={"candidates": [candidate]})

        def factory(**kwargs):
            options = kwargs["http_options"]
            self.assertEqual(options.retry_options.attempts, 1)
            if options.timeout == 10000:
                return self.provider  # Query embedding remains a separate operation.
            self.assertEqual(options.timeout, 20000)
            kwargs["http_options"] = options.model_copy(update={
                "client_args": {"transport": httpx.MockTransport(handle)},
            })
            client = SDK_CLIENT(**kwargs)
            self.stack.callback(client.close)
            self.stack.callback(lambda: asyncio.run(client.aio.aclose()))
            return client

        self.client_factory.side_effect = factory
        with patch("src.reliability.logger.info") as info, TestClient(api.app) as client:
            response = client.post("/chat", json={"message": "What is BundesHost?"})
        self.assertEqual(response.status_code, expected_status)
        self.assertEqual(response.json(), {"answer": private} if expected_status == 200 else {
            "detail": ERROR_DETAIL,
        })
        # A continuation response includes a valid token: this assertion fails
        # if the SDK silently follows it, even though HTTP retry attempts is one.
        self.assertEqual(len(requests), 1)
        request = requests[0]
        self.assertEqual(request.url.host, "generativelanguage.googleapis.com")
        self.assertTrue(request.url.path.endswith("/models/gemini-3.8-flash:generateContent"))
        config = json.loads(request.content)["generationConfig"]
        self.assertEqual(config["maxOutputTokens"], 1024)
        # This SDK version retains snake_case inside the nested thinking dict.
        self.assertEqual(config["thinkingConfig"]["thinking_level"], "LOW")
        self.assertEqual(request.extensions["timeout"]["connect"], 20)
        self.assertEqual(request.extensions["timeout"]["read"], 20)
        self.assertEqual(api.settings.chat_deadline_seconds, 40)
        self.models.embed_content.assert_called_once()
        self.assertEqual(self.models.embed_content.call_args.kwargs["config"]["task_type"], "RETRIEVAL_QUERY")
        self.assertEqual(self.models.embed_content.call_args.kwargs["config"]["output_dimensionality"], 3072)
        self.models.generate_content.assert_not_called()  # Actual SDK handled generation.
        info.assert_called_once()
        record = json.loads(info.call_args.args[0])
        self.assertEqual(record["status"], expected_status)
        if upstream_status == 200:
            self.assertEqual(record["generation"]["finish_reason"], reason)
        serialized = json.dumps(record)
        for sensitive in (private, "What is BundesHost?", "Retrieved portfolio context",
                          "offline-test-key-not-a-secret", "continuationToken"):
            self.assertNotIn(sensitive, serialized)
        for guard in self.network_guards:
            guard.assert_not_called()
        return record

    def test_continuation_token_does_not_trigger_second_http_request(self):
        record = self.exercise("CONTINUATION", expected_status=502)
        self.assertEqual(record["provider_failure"], "incomplete_response")

    def test_stop_is_successful_with_one_http_request(self):
        self.exercise("STOP")

    def test_max_tokens_is_rejected_with_one_http_request(self):
        record = self.exercise("MAX_TOKENS", expected_status=502)
        self.assertEqual(record["provider_failure"], "incomplete_response")

    def test_quota_response_is_not_retried(self):
        record = self.exercise(None, upstream_status=429, expected_status=503)
        self.assertEqual(record["provider_failure"], "quota")

    def test_server_error_is_not_retried(self):
        record = self.exercise(None, upstream_status=503, expected_status=502)
        self.assertEqual(record["provider_failure"], "provider_error")


class ProviderShutdownTests(OfflineTestCase):
    def setUp(self):
        super().setUp()
        self.api = self.load("src.api")
        self.embeddings = self.load("src.embeddings")
        self.generation = Mock(spec_set=["close"])
        self.embedding = Mock(spec_set=["close"])
        self.api.client = self.generation
        self.embeddings.client = self.embedding

    def shutdown(self, failed_clients):
        sensitive = "PRIVATE-CLOSE-ERROR-AND-CREDENTIAL"
        for name, client in (("generation", self.generation), ("embedding", self.embedding)):
            if name in failed_clients:
                client.close.side_effect = RuntimeError(sensitive)
        with patch("src.reliability.logger.error") as error_log:
            if failed_clients:
                with self.assertRaises(RuntimeError) as caught:
                    with TestClient(self.api.app):
                        pass
                self.assertEqual(str(caught.exception), "Provider client shutdown failed.")
                formatted = "".join(traceback.format_exception(caught.exception))
                self.assertNotIn(sensitive, formatted)
                self.assertIsNone(caught.exception.__cause__)
                error_log.assert_called_once()
                record = json.loads(error_log.call_args.args[0])
                self.assertEqual(record, {
                    "event": "provider_shutdown", "status": "failed",
                    "failed_clients": failed_clients,
                })
                self.assertNotIn(sensitive, json.dumps(record))
                self.assertNotIn("offline-test-key-not-a-secret", json.dumps(record))
            else:
                with TestClient(self.api.app):
                    pass
                error_log.assert_not_called()
        self.generation.close.assert_called_once_with()
        self.embedding.close.assert_called_once_with()
        self.assertIsNone(self.api.client)
        self.assertIsNone(self.embeddings.client)
        self.assertIsNone(self.api.app.state.rag_index)
        self.client_factory.assert_not_called()
        self.models.embed_content.assert_not_called()
        self.models.generate_content.assert_not_called()
        for guard in self.network_guards:
            guard.assert_not_called()

    def test_both_clients_close_successfully(self):
        self.shutdown([])

    def test_generation_failure_does_not_skip_embedding_cleanup(self):
        self.shutdown(["generation"])

    def test_embedding_failure_does_not_skip_generation_cleanup(self):
        self.shutdown(["embedding"])

    def test_both_failures_are_reported_without_provider_details(self):
        self.shutdown(["generation", "embedding"])

    def test_shutdown_without_initialized_clients_does_not_construct_them(self):
        self.api.client = None
        self.embeddings.client = None
        with TestClient(self.api.app):
            pass
        self.generation.close.assert_not_called()
        self.embedding.close.assert_not_called()
        self.client_factory.assert_not_called()
        self.models.embed_content.assert_not_called()
        self.models.generate_content.assert_not_called()
