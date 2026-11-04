"""Generation completion, configuration and privacy checks; no provider network."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import json
import os
from threading import BoundedSemaphore, Event
import time
from types import SimpleNamespace
from unittest.mock import patch

from fastapi.testclient import TestClient
from google.genai import types

from src.config import Settings
from src.diagnostics import ChatDiagnostics
from src.provider import ERROR_DETAIL, TOKEN_FIELDS, generation_metadata
from tests.offline import OfflineTestCase
from tests.test_reliability import ReliabilityTestCase


def sdk_response(reason="STOP", text="A complete portfolio answer.", usage=None):
    return types.GenerateContentResponse(
        candidates=[types.Candidate(
            content=types.Content(role="model", parts=[types.Part(text=text)]),
            finish_reason=reason,
        )],
        usage_metadata=usage,
    )


class GenerationResponseTests(ReliabilityTestCase):
    def response_and_log(self, provider_response):
        self.models.generate_content.return_value = provider_response
        with patch("src.reliability.logger.info") as info:
            response = self.post()
        info.assert_called_once()
        return response, json.loads(info.call_args.args[0])

    def assert_safe_error(self, response):
        self.assertEqual(response.status_code, 502)
        self.assertEqual(response.json(), {"detail": ERROR_DETAIL})

    def test_stop_preserves_success_schema_and_does_not_retry(self):
        response, record = self.response_and_log(sdk_response())
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"answer": "A complete portfolio answer."})
        self.assertEqual(record["generation"]["finish_reason"], "STOP")
        self.assertEqual(record["request_id"], response.headers["x-request-id"])
        self.models.generate_content.assert_called_once()
        for guard in self.network_guards:
            guard.assert_not_called()

    def test_max_tokens_partial_answer_is_rejected_without_retry(self):
        response, record = self.response_and_log(sdk_response("MAX_TOKENS", "An unfinished"))
        self.assert_safe_error(response)
        self.assertEqual(record["provider_failure"], "incomplete_response")
        self.assertEqual(record["generation"]["finish_reason"], "MAX_TOKENS")
        self.models.generate_content.assert_called_once()

    def test_every_other_sdk_finish_reason_is_rejected(self):
        for reason in types.FinishReason:
            if reason in (types.FinishReason.STOP, types.FinishReason.MAX_TOKENS):
                continue
            with self.subTest(reason=reason.value):
                response, record = self.response_and_log(sdk_response(reason, "Partial text"))
                self.assert_safe_error(response)
                self.assertEqual(record["generation"]["finish_reason"], reason.value)

    def test_empty_and_whitespace_with_stop_are_empty_response_errors(self):
        for text in ("", " \n\t "):
            with self.subTest(text=repr(text)):
                response, record = self.response_and_log(sdk_response(text=text))
                self.assert_safe_error(response)
                self.assertEqual(record["provider_failure"], "empty_response")

    def test_stop_with_absent_text_is_rejected(self):
        response, record = self.response_and_log(SimpleNamespace(
            candidates=[SimpleNamespace(finish_reason="STOP")],
        ))
        self.assert_safe_error(response)
        self.assertEqual(record["provider_failure"], "empty_response")

    def test_missing_and_malformed_candidates_are_safe(self):
        for candidates in (None, [], {}, "private-candidates", 7, [None]):
            with self.subTest(kind=type(candidates).__name__):
                response, record = self.response_and_log(SimpleNamespace(
                    candidates=candidates, text="Partial text",
                ))
                self.assert_safe_error(response)
                self.assertEqual(record["provider_failure"], "invalid_response")

    def test_missing_and_malformed_finish_reasons_are_safe_and_allowlisted(self):
        for reason, expected in (
            (None, "MISSING"), ("private-upstream-reason", "UNKNOWN"),
            ("", "UNKNOWN"), ("stop", "UNKNOWN"), (7, "MALFORMED"),
            (True, "MALFORMED"), ([], "MALFORMED"), ({}, "MALFORMED"),
            (SimpleNamespace(value="STOP"), "MALFORMED"),
        ):
            with self.subTest(kind=type(reason).__name__, expected=expected):
                response, record = self.response_and_log(SimpleNamespace(
                    text="Partial text", candidates=[SimpleNamespace(finish_reason=reason)],
                ))
                self.assert_safe_error(response)
                self.assertEqual(record["generation"]["finish_reason"], expected)
                self.assertNotIn("private-upstream-reason", json.dumps(record))

    def test_multiple_candidates_cannot_hide_a_failed_completion(self):
        response, _ = self.response_and_log(SimpleNamespace(
            text="First answer", candidates=[
                SimpleNamespace(finish_reason="STOP"),
                SimpleNamespace(finish_reason="MAX_TOKENS"),
            ],
        ))
        self.assert_safe_error(response)

    def test_prompt_block_is_rejected_even_with_stop(self):
        response, record = self.response_and_log(SimpleNamespace(
            text="Partial text", candidates=[SimpleNamespace(finish_reason="STOP")],
            prompt_feedback=SimpleNamespace(block_reason="SAFETY"),
        ))
        self.assert_safe_error(response)
        self.assertEqual(record["provider_failure"], "blocked_response")

    def test_optional_token_usage_is_logged_as_unknown_not_zero(self):
        response, record = self.response_and_log(sdk_response())
        self.assertEqual(response.status_code, 200)
        self.assertEqual(record["generation"], {
            "finish_reason": "STOP", **dict.fromkeys(TOKEN_FIELDS),
        })

    def test_sdk_token_usage_is_logged_without_public_metadata(self):
        usage = types.GenerateContentResponseUsageMetadata(
            prompt_token_count=800, candidates_token_count=120,
            thoughts_token_count=300, total_token_count=1220,
        )
        response, record = self.response_and_log(sdk_response(usage=usage))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(set(response.json()), {"answer"})
        self.assertEqual(record["generation"], {
            "finish_reason": "STOP", "prompt_token_count": 800,
            "candidates_token_count": 120, "thoughts_token_count": 300,
            "total_token_count": 1220,
        })

    def test_malformed_usage_values_are_not_coerced_or_logged(self):
        for invalid in (True, -1, "private-token-count", float("nan"),
                        float("inf"), {}, [], 2**100):
            with self.subTest(kind=type(invalid).__name__):
                response, record = self.response_and_log(SimpleNamespace(
                    text="Complete answer.", candidates=[SimpleNamespace(finish_reason="STOP")],
                    usage_metadata=SimpleNamespace(**dict.fromkeys(TOKEN_FIELDS, invalid)),
                ))
                self.assertEqual(response.status_code, 200)
                self.assertTrue(all(record["generation"][key] is None for key in TOKEN_FIELDS))
                self.assertNotIn("private-token-count", json.dumps(record))

    def test_malformed_usage_container_and_zero_counts_are_safe(self):
        for usage in ("private-usage", [], {}, 123):
            metadata = generation_metadata(SimpleNamespace(usage_metadata=usage))
            self.assertTrue(all(metadata[key] is None for key in TOKEN_FIELDS))
        metadata = generation_metadata(SimpleNamespace(
            usage_metadata=SimpleNamespace(**dict.fromkeys(TOKEN_FIELDS, 0)),
        ))
        self.assertTrue(all(metadata[key] == 0 for key in TOKEN_FIELDS))

    def test_logs_exclude_all_generation_content(self):
        secret = "PRIVATE-RESPONSE-AND-THOUGHT-CONTENT"
        response = sdk_response(text=secret)
        response.candidates[0].finish_message = "PRIVATE-FREE-FORM-MESSAGE"
        response.candidates[0].content.parts.insert(0, types.Part(text=secret, thought=True))
        self.models.generate_content.return_value = response
        with patch("src.reliability.logger.info") as info:
            result = self.post(headers={"Authorization": "PRIVATE-AUTHORIZATION"})
        self.assertEqual(result.json(), {"answer": secret})
        serialized = json.dumps([json.loads(call.args[0]) for call in info.call_args_list])
        for private in (secret, "PRIVATE-FREE-FORM-MESSAGE", "PRIVATE-AUTHORIZATION",
                        "Docker?", "offline-test-key-not-a-secret", "Retrieved portfolio context"):
            self.assertNotIn(private, serialized)
        prompt = self.models.generate_content.call_args.kwargs["contents"]
        self.assertNotIn(prompt, serialized)

    def test_late_worker_cannot_log_success_or_generation_metadata(self):
        self.controls.settings = replace(self.controls.settings, chat_deadline_seconds=0.05)
        self.controls.capacity = BoundedSemaphore(1)
        entered, finish = Event(), Event()

        def delayed(**kwargs):
            entered.set()
            if not finish.wait(3):
                raise AssertionError("Test did not release worker")
            return sdk_response()

        self.models.generate_content.side_effect = delayed
        with patch("src.reliability.logger.info") as info:
            with ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(self.post)
                try:
                    self.assertTrue(entered.wait(2))
                    response = future.result(timeout=1)
                    self.assertEqual(response.status_code, 504)
                    self.assertFalse(self.controls.capacity.acquire(blocking=False))
                finally:
                    finish.set()
            end = time.monotonic() + 2
            while True:
                acquired = self.controls.capacity.acquire(blocking=False)
                if acquired:
                    self.controls.capacity.release()
                    break
                if time.monotonic() >= end:
                    self.fail("Worker did not release capacity")
                time.sleep(0.002)
            info.assert_called_once()
            record = json.loads(info.call_args.args[0])
        self.assertEqual(record["status"], 504)
        self.assertEqual(record["provider_failure"], "deadline")
        self.assertNotIn("generation", record)
        self.models.generate_content.assert_called_once()

    def test_stopped_diagnostics_ignore_late_metadata(self):
        diagnostics = ChatDiagnostics(time.monotonic(), 1)
        diagnostics.stop()
        diagnostics.record_generation({"finish_reason": "STOP"})
        self.assertIsNone(diagnostics.generation_snapshot())
        expired = ChatDiagnostics(time.monotonic() - 2, 1)
        expired.record_generation({"finish_reason": "STOP"})
        self.assertIsNone(expired.generation_snapshot())


class GenerationConfigurationTests(OfflineTestCase):
    def test_defaults_are_initial_evaluation_settings(self):
        with patch.dict(os.environ):
            os.environ.pop("GEMINI_MAX_OUTPUT_TOKENS", None)
            os.environ.pop("GEMINI_THINKING_LEVEL", None)
            settings = Settings.from_env()
        self.assertEqual(settings.max_output_tokens, 1024)
        self.assertEqual(settings.thinking_level, "LOW")
        self.assertEqual(settings.generation_timeout_ms, 20000)
        self.assertEqual(settings.chat_deadline_seconds, 40)

    def test_custom_budget_and_thinking_are_sent_in_sdk_supported_format(self):
        with patch.dict(os.environ, {
            "GEMINI_MAX_OUTPUT_TOKENS": "2048", "GEMINI_THINKING_LEVEL": " medium ",
        }):
            api = self.load("src.api")
        with TestClient(api.app) as client:
            self.assertEqual(client.post("/chat", json={"message": "Docker?"}).status_code, 200)
        arguments = self.models.generate_content.call_args.kwargs
        self.assertEqual(arguments["model"], "gemini-3.8-flash")
        config = types.GenerateContentConfig(**arguments["config"])
        self.assertEqual(config.max_output_tokens, 2048)
        self.assertEqual(config.thinking_config.thinking_level, types.ThinkingLevel.MEDIUM)
        self.assertIsNone(config.thinking_config.thinking_budget)
        self.assertIsNone(config.temperature)
        self.models.generate_content.assert_called_once()
        for call in self.client_factory.call_args_list:
            self.assertEqual(call.kwargs["http_options"].retry_options.attempts, 1)

    def test_supported_thinking_levels(self):
        for level in ("LOW", "MEDIUM", "HIGH"):
            with patch.dict(os.environ, {"GEMINI_THINKING_LEVEL": level}):
                self.assertEqual(Settings.from_env().thinking_level, level)

    def test_invalid_thinking_configuration_fails_safely(self):
        for value in ("", "MINIMAL", "OFF", "0", "PRIVATE-INVALID-SETTING"):
            with self.subTest(value=value), patch.dict(os.environ, {"GEMINI_THINKING_LEVEL": value}):
                with self.assertRaises(ValueError) as error:
                    Settings.from_env()
                self.assertNotIn(value or "PRIVATE", str(error.exception))
        self.client_factory.assert_not_called()

    def test_output_budget_boundaries_and_invalid_values(self):
        for value in ("1", "65536"):
            with patch.dict(os.environ, {"GEMINI_MAX_OUTPUT_TOKENS": value}):
                self.assertEqual(Settings.from_env().max_output_tokens, int(value))
        for value in ("0", "-1", "65537", "1.5", "nan", "PRIVATE-INVALID-TOKENS"):
            with self.subTest(value=value), patch.dict(os.environ, {"GEMINI_MAX_OUTPUT_TOKENS": value}):
                with self.assertRaises(ValueError):
                    Settings.from_env()
