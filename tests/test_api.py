from types import SimpleNamespace
from unittest.mock import patch

from fastapi.testclient import TestClient

from tests.offline import OfflineTestCase


class APITestCase(OfflineTestCase):
    def setUp(self):
        super().setUp()
        self.api = self.load("src.api")
        self.http = self.stack.enter_context(TestClient(self.api.app))
        self.models.embed_content.reset_mock()

    def assert_generic_error(self, response):
        self.assertEqual(response.status_code, 500)
        self.assertEqual(response.json(), {
            "detail": "The AI assistant could not generate a response."
        })


class APIValidationTests(APITestCase):
    def test_valid_request_preserves_response_contract(self):
        response = self.http.post("/chat", json={"message": "Has Timothy used Docker?"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"answer": "Offline test answer."})
        self.models.generate_content.assert_called_once()
        self.assertEqual(self.models.embed_content.call_count, 1)

    def test_outer_whitespace_is_trimmed(self):
        self.assertEqual(self.api.ChatRequest(message="  Docker? \n").message, "Docker?")

    def test_maximum_length_message_is_accepted(self):
        response = self.http.post("/chat", json={"message": "a" * 1000})
        self.assertEqual(response.status_code, 200)

    def test_blank_messages_are_rejected_before_provider_calls(self):
        for message in ("", "   ", "\n\t "):
            with self.subTest(message=repr(message)):
                self.assertEqual(self.http.post("/chat", json={"message": message}).status_code, 422)
        self.models.generate_content.assert_not_called()
        self.models.embed_content.assert_not_called()

    def test_oversized_message_is_rejected_before_provider_calls(self):
        response = self.http.post("/chat", json={"message": "a" * 1001})
        self.assertEqual(response.status_code, 422)
        self.models.generate_content.assert_not_called()
        self.models.embed_content.assert_not_called()

    def test_missing_message_is_rejected(self):
        self.assertEqual(self.http.post("/chat", json={}).status_code, 422)
        self.models.generate_content.assert_not_called()
        self.models.embed_content.assert_not_called()

    def test_invalid_field_types_are_rejected(self):
        for value in (None, 7, True, [], {}):
            with self.subTest(value=value):
                self.assertEqual(self.http.post("/chat", json={"message": value}).status_code, 422)
        self.models.generate_content.assert_not_called()
        self.models.embed_content.assert_not_called()

    def test_invalid_body_and_malformed_json_are_rejected(self):
        for payload in ([], "Docker?", None):
            with self.subTest(payload=payload):
                self.assertEqual(self.http.post("/chat", json=payload).status_code, 422)
        response = self.http.post("/chat", content="{", headers={"Content-Type": "application/json"})
        self.assertEqual(response.status_code, 422)
        self.models.generate_content.assert_not_called()
        self.models.embed_content.assert_not_called()

    def test_extra_fields_preserve_current_contract(self):
        # Phase 1 deliberately preserves Pydantic's current extra-field policy.
        response = self.http.post("/chat", json={"message": "Docker?", "extra": "ignored"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"answer": "Offline test answer."})

    def test_health_does_not_call_provider(self):
        response = self.http.get("/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"status": "ok", "service": "AI Portfolio Assistant"})
        self.models.generate_content.assert_not_called()
        self.models.embed_content.assert_not_called()


class APIErrorTests(APITestCase):
    def test_generation_failure_returns_sanitized_error(self):
        self.models.generate_content.side_effect = RuntimeError("private upstream diagnostic")
        response = self.http.post("/chat", json={"message": "Docker?"})
        self.assert_generic_error(response)
        self.assertNotIn("private upstream diagnostic", response.text)

    def test_embedding_failure_returns_sanitized_error(self):
        self.models.embed_content.side_effect = RuntimeError("private embedding diagnostic")
        response = self.http.post("/chat", json={"message": "Docker?"})
        self.assert_generic_error(response)
        self.models.generate_content.assert_not_called()

    def test_provider_timeout_preserves_current_error_contract(self):
        self.models.generate_content.side_effect = TimeoutError("mock timeout")
        self.assert_generic_error(self.http.post("/chat", json={"message": "Docker?"}))

    def test_absent_model_text_returns_error(self):
        self.models.generate_content.return_value = SimpleNamespace(text=None, candidates=[])
        self.assert_generic_error(self.http.post("/chat", json={"message": "Docker?"}))

    def test_safety_blocked_response_returns_error(self):
        self.models.generate_content.return_value = SimpleNamespace(
            text=None, candidates=[],
            prompt_feedback=SimpleNamespace(block_reason="SAFETY"),
        )
        self.assert_generic_error(self.http.post("/chat", json={"message": "Docker?"}))

    def test_collection_route_uses_overviews_without_query_embedding(self):
        with patch.object(self.api, "get_project_overview_chunks", return_value=["Project overview"]):
            response = self.http.post("/chat", json={"message": "List Timothy's projects."})
        self.assertEqual(response.status_code, 200)
        self.models.embed_content.assert_not_called()
        prompt = self.models.generate_content.call_args.kwargs["contents"]
        self.assertIn("Project overview", prompt)


class KnownAPIResponseRegressionTests(APITestCase):
    """No new response schema/status policy: require the existing generic error."""

    def test_empty_string_model_response_is_not_a_successful_answer(self):
        self.models.generate_content.return_value = SimpleNamespace(text="")
        self.assert_generic_error(self.http.post("/chat", json={"message": "Docker?"}))

    def test_whitespace_model_response_is_not_a_successful_answer(self):
        self.models.generate_content.return_value = SimpleNamespace(text=" \n\t ")
        self.assert_generic_error(self.http.post("/chat", json={"message": "Docker?"}))
