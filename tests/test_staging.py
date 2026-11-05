"""Protected staging contracts, entirely offline with fail-closed network guards."""

from dataclasses import replace
from concurrent.futures import ThreadPoolExecutor
import json
import os
import secrets
from threading import BoundedSemaphore
from unittest.mock import patch

from fastapi.testclient import TestClient

from src.config import Settings
from tests.offline import OfflineTestCase
from tests import test_deadline


TOKEN = "offline-staging-token-" + "a" * 32


class StagingTests(OfflineTestCase):
    def setUp(self):
        super().setUp()
        self.stack.enter_context(patch.dict(os.environ, {
            "STAGING_AUTH_ENABLED": "true", "STAGING_AUTH_TOKEN": TOKEN,
            "FRONTEND_ORIGINS": "https://staging.example.test",
        }))
        self.api = self.load("src.api")
        self.controls = self.api.app.state.chat_controls
        self.http = self.stack.enter_context(TestClient(self.api.app))
        self.logs = self.stack.enter_context(patch("src.reliability.logger.info"))

    def post(self, **kwargs):
        kwargs.setdefault("headers", {"Authorization": f"Bearer {TOKEN}"})
        return self.http.post("/chat", json={"message": "Docker?"}, **kwargs)

    def assert_no_provider_work(self):
        self.client_factory.assert_not_called()
        self.models.embed_content.assert_not_called()
        self.models.generate_content.assert_not_called()

    def test_missing_token_is_generic_401_before_provider_admission(self):
        response = self.post(headers={})
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json(), {"detail": "Unauthorized."})
        self.assertEqual(response.headers["WWW-Authenticate"], "Bearer")
        self.assert_no_provider_work()
        self.assertEqual(self.controls.rate_limiter.clients, {})
        self.assertEqual(self.controls.authenticated_budget.clients, {})
        self.assertTrue(self.controls.capacity.acquire(blocking=False))
        self.controls.capacity.release()

    def test_incorrect_token_uses_constant_time_comparison(self):
        with patch("src.reliability.secrets.compare_digest", wraps=secrets.compare_digest) as compare:
            response = self.post(headers={"Authorization": "Bearer " + "b" * len(TOKEN)})
        self.assertEqual(response.status_code, 401)
        compare.assert_called_once()
        self.assert_no_provider_work()

    def test_malformed_authorization_is_rejected(self):
        for value in ("", "Bearer", f"Basic {TOKEN}", f"Bearer  {TOKEN}",
                      f" Bearer {TOKEN}", f"Bearer {TOKEN} ", f"Bearer {TOKEN}, Bearer {TOKEN}",
                      "Bearer short", "Bearer " + "a" * 257):
            with self.subTest(value_length=len(value)):
                self.assertEqual(self.post(headers={"Authorization": value}).status_code, 401)
        self.assert_no_provider_work()

    def test_duplicate_headers_are_rejected_even_when_both_are_correct(self):
        response = self.post(headers=[("Authorization", f"Bearer {TOKEN}"),
                                      ("authorization", f"Bearer {TOKEN}")])
        self.assertEqual(response.status_code, 401)
        self.assert_no_provider_work()

    def test_correct_token_preserves_success_schema(self):
        with patch("src.reliability.secrets.compare_digest", wraps=secrets.compare_digest) as compare:
            response = self.post()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"answer": "Offline test answer."})
        compare.assert_called_once()
        self.models.generate_content.assert_called_once()

    def test_bearer_scheme_is_case_insensitive(self):
        self.assertEqual(self.post(headers={"Authorization": f"bEaReR {TOKEN}"}).status_code, 200)

    def test_trailing_slash_cannot_bypass_authentication(self):
        response = self.http.post("/chat/", json={"message": "Docker?"}, follow_redirects=False)
        self.assertEqual(response.status_code, 401)
        self.assert_no_provider_work()
        response = self.http.post("/chat/", json={"message": "Docker?"},
                                  headers={"Authorization": f"Bearer {TOKEN}"})
        self.assertEqual(response.status_code, 200)

    def test_query_and_body_credentials_are_not_accepted(self):
        response = self.http.post(f"/chat?token={TOKEN}",
                                  json={"message": "Docker?", "token": TOKEN})
        self.assertEqual(response.status_code, 401)
        self.assert_no_provider_work()
        self.assertNotIn(TOKEN, str(self.logs.call_args_list))

    def test_health_and_readiness_are_public_and_do_not_consume_budget(self):
        for path in ("/health", "/ready"):
            self.assertEqual(self.http.get(path).status_code, 200)
        self.assertEqual(self.controls.authenticated_budget.clients, {})
        self.assert_no_provider_work()

    def test_health_names_do_not_exempt_other_methods(self):
        for path in ("/health", "/ready"):
            self.assertEqual(self.http.post(path).status_code, 401)
        self.assert_no_provider_work()

    def test_documentation_routes_are_not_registered(self):
        self.assertIsNone(self.api.app.openapi_url)
        for path in ("/docs", "/redoc", "/openapi.json"):
            response = self.http.get(path, headers={"Authorization": f"Bearer {TOKEN}"})
            self.assertEqual(response.status_code, 404)
            self.assertNotIn("openapi", response.text.lower())
        self.assert_no_provider_work()

    def test_future_endpoint_inherits_authentication_and_budget(self):
        def future():
            self.models.generate_content()
            return {"answer": "future"}
        self.api.app.add_api_route("/future-paid", future, methods=["GET"])
        self.assertEqual(self.http.get("/future-paid").status_code, 401)
        self.assert_no_provider_work()
        response = self.http.get("/future-paid", headers={"Authorization": f"Bearer {TOKEN}"})
        self.assertEqual(response.status_code, 200)
        self.models.generate_content.assert_called_once()
        self.assertEqual(set(self.controls.authenticated_budget.clients), {"authenticated"})

    def test_cors_allows_only_explicit_origin_and_headers(self):
        headers = {"Origin": "https://staging.example.test", "Access-Control-Request-Method": "POST",
                   "Access-Control-Request-Headers": "authorization,content-type"}
        response = self.http.options("/chat", headers=headers)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["access-control-allow-origin"], headers["Origin"])
        self.assertNotIn("access-control-allow-credentials", response.headers)
        headers["Origin"] = "https://attacker.example.test"
        response = self.http.options("/chat", headers=headers)
        self.assertEqual(response.status_code, 400)
        self.assertNotIn("access-control-allow-origin", response.headers)
        headers["Origin"] = "https://staging.example.test"
        headers["Access-Control-Request-Headers"] = "x-unapproved-header"
        self.assertEqual(self.http.options("/chat", headers=headers).status_code, 400)
        self.assert_no_provider_work()

    def test_allowed_origin_does_not_bypass_authentication(self):
        response = self.post(headers={"Origin": "https://staging.example.test"})
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.headers["access-control-allow-origin"], "https://staging.example.test")
        self.assert_no_provider_work()

    def test_budget_is_shared_across_connection_peers(self):
        self.controls.authenticated_budget.requests = 1
        self.assertEqual(self.post().status_code, 200)
        with TestClient(self.api.app, client=("192.0.2.8", 1234)) as other:
            response = other.post("/chat", json={"message": "Docker?"},
                                  headers={"Authorization": f"Bearer {TOKEN}",
                                           "X-Forwarded-For": "198.51.100.8"})
        self.assertEqual(response.status_code, 429)
        self.assertGreaterEqual(int(response.headers["Retry-After"]), 1)
        self.models.generate_content.assert_called_once()
        self.assertEqual(len(self.controls.authenticated_budget.clients), 1)

    def test_budget_reset_and_rounded_retry_after(self):
        budget = self.controls.authenticated_budget
        budget.requests = 1
        now = [100.0]
        budget.clock = lambda: now[0]
        self.assertEqual(self.post().status_code, 200)
        now[0] = 159.8
        self.assertEqual(self.post().headers["Retry-After"], "1")
        self.assertEqual(self.http.get("/health").status_code, 200)
        self.assertEqual(self.http.get("/ready").status_code, 200)
        now[0] = 160.0
        self.assertEqual(self.post().status_code, 200)

    def test_concurrent_budget_checks_cannot_overshoot(self):
        budget = self.controls.authenticated_budget
        budget.requests = 3
        with ThreadPoolExecutor(max_workers=8) as workers:
            results = list(workers.map(lambda _: budget.check("authenticated"), range(30)))
        self.assertEqual(sum(status is None for status, _ in results), 3)
        self.assertEqual(sum(status == 429 for status, _ in results), 27)
        self.assertEqual(len(budget.clients), 1)
        self.assert_no_provider_work()

    def test_authentication_failures_do_not_consume_budget(self):
        self.controls.authenticated_budget.requests = 1
        for _ in range(12):
            self.assertEqual(self.post(headers={}).status_code, 401)
        self.assertEqual(self.post().status_code, 200)

    def test_provider_failure_still_counts_toward_budget(self):
        self.controls.authenticated_budget.requests = 1
        self.models.generate_content.side_effect = RuntimeError("private-provider-error")
        self.assertEqual(self.post().status_code, 500)
        self.assertEqual(self.post().status_code, 429)
        self.models.generate_content.assert_called_once()

    def test_existing_peer_limit_remains_in_force(self):
        self.controls.rate_limiter.requests = 1
        self.assertEqual(self.post().status_code, 200)
        self.assertEqual(self.post().status_code, 429)
        self.models.generate_content.assert_called_once()

    def test_existing_concurrency_rejection_remains_in_force(self):
        self.controls.capacity = BoundedSemaphore(1)
        self.controls.capacity.acquire()
        try:
            self.assertEqual(self.post().status_code, 503)
            self.assert_no_provider_work()
        finally:
            self.controls.capacity.release()

    def test_existing_body_limit_remains_in_force(self):
        self.controls.settings = replace(self.controls.settings, max_body_bytes=8)
        self.assertEqual(self.post().status_code, 413)
        self.assert_no_provider_work()

    available = test_deadline.DeadlineTests.available
    wait_until = test_deadline.DeadlineTests.wait_until

    def test_deadline_keeps_worker_lease_and_releases_it_after_completion(self):
        self.controls.settings = replace(self.controls.settings, chat_deadline_seconds=0.05)
        self.controls.capacity = BoundedSemaphore(1)
        test_deadline.DeadlineTests.blocked_operation(self, self.models.embed_content)
        self.models.generate_content.assert_not_called()

    def test_validation_and_logs_never_echo_inputs_or_credentials(self):
        marker = "PRIVATE-VISITOR-MARKER"
        headers = {"Authorization": f"Bearer {TOKEN}"}
        cases = [
            {"json": {"message": marker, marker: marker}},
            {"json": {"message": {marker: marker}}},
            {"json": {"message": marker * 100}},
            {"content": '{"message":"' + marker, "headers": {**headers, "Content-Type": "application/json"}},
        ]
        for case in cases:
            case.setdefault("headers", headers)
            response = self.http.post("/chat", **case)
            self.assertEqual(response.status_code, 422)
            self.assertIsInstance(response.json()["detail"], list)
            self.assertNotIn(marker, response.text)
            self.assertNotIn(TOKEN, response.text)
        self.assert_no_provider_work()
        self.post()
        self.post(headers={})
        logs = json.dumps([call.args[0] for call in self.logs.call_args_list])
        for sensitive in (TOKEN, marker, "Offline test answer.", "Authorization", "Bearer"):
            self.assertNotIn(sensitive, logs)


class StagingConfigurationTests(OfflineTestCase):
    def test_local_defaults_preserve_unauthenticated_access_and_documentation(self):
        api = self.load("src.api")
        with TestClient(api.app) as http:
            self.assertEqual(http.post("/chat", json={"message": "Docker?"}).status_code, 200)
            for path in ("/docs", "/redoc", "/openapi.json"):
                self.assertEqual(http.get(path).status_code, 200)
        self.assertEqual(api.app.state.chat_controls.authenticated_budget.clients, {})

    def test_missing_token_prevents_application_startup_without_provider_calls(self):
        with patch.dict(os.environ, {"STAGING_AUTH_ENABLED": "true", "STAGING_AUTH_TOKEN": ""}):
            with self.assertRaisesRegex(ValueError, "STAGING_AUTH_TOKEN"):
                self.load("src.api")
        self.client_factory.assert_not_called()

    def test_invalid_tokens_are_rejected_without_echoing_values(self):
        for token in ("short-private-token", "a" * 257, "a" * 42, "a" * 43 + "!", "a" * 43 + " "):
            with patch.dict(os.environ, {"STAGING_AUTH_ENABLED": "true", "STAGING_AUTH_TOKEN": token}):
                with self.assertRaises(ValueError) as caught:
                    Settings.from_env()
                self.assertNotIn(token, str(caught.exception))

    def test_invalid_authentication_switch_is_rejected(self):
        with patch.dict(os.environ, {"STAGING_AUTH_ENABLED": "private-invalid-value"}):
            with self.assertRaises(ValueError) as caught:
                Settings.from_env()
        self.assertNotIn("private-invalid-value", str(caught.exception))

    def test_token_is_excluded_from_settings_representation(self):
        with patch.dict(os.environ, {"STAGING_AUTH_ENABLED": "true", "STAGING_AUTH_TOKEN": TOKEN}):
            self.assertNotIn(TOKEN, repr(Settings.from_env()))

    def test_staging_without_explicit_origins_has_no_cors_allowlist(self):
        os.environ.pop("FRONTEND_ORIGINS", None)
        with patch.dict(os.environ, {"STAGING_AUTH_ENABLED": "true", "STAGING_AUTH_TOKEN": TOKEN}):
            api = self.load("src.api")
        self.assertEqual(api.frontend_origins, [])

    def test_wildcard_and_malformed_origins_are_rejected(self):
        for origin in ("*", "https://*.example.test", "https://example.test/path",
                       "https://user:password@example.test", "https://example.test?secret=yes",
                       "https://example.test#fragment", "not-an-origin", "https://example.test:bad"):
            with patch.dict(os.environ, {"STAGING_AUTH_ENABLED": "true", "STAGING_AUTH_TOKEN": TOKEN,
                                        "FRONTEND_ORIGINS": origin}):
                with self.assertRaises(ValueError) as caught:
                    Settings.from_env()
                self.assertNotIn(origin, str(caught.exception))

    def test_budget_environment_is_configurable(self):
        with patch.dict(os.environ, {"STAGING_BUDGET_REQUESTS": "3", "STAGING_BUDGET_WINDOW_SECONDS": "120"}):
            settings = Settings.from_env()
        self.assertEqual(settings.staging_budget_requests, 3)
        self.assertEqual(settings.staging_budget_window_seconds, 120)

    def test_invalid_budget_configuration_is_rejected(self):
        for name in ("STAGING_BUDGET_REQUESTS", "STAGING_BUDGET_WINDOW_SECONDS"):
            for value in ("0", "-1", "invalid-private-setting"):
                with patch.dict(os.environ, {name: value}):
                    with self.assertRaises(ValueError):
                        Settings.from_env()

    def test_local_validation_errors_are_sanitized_too(self):
        api = self.load("src.api")
        with TestClient(api.app) as http:
            response = http.post("/chat", json={"message": "local-private-input", "private-field": True})
        self.assertEqual(response.status_code, 422)
        self.assertNotIn("local-private-input", response.text)
        self.assertNotIn("private-field", response.text)
