"""Scoped provider mocks and fail-closed network guards for unittest.

Production modules are imported only after the guards are installed. Their
module cache entries and parent-package attributes are restored after each
test so mocked clients cannot escape into other tests in the same process.
"""

from contextlib import ExitStack, redirect_stdout
import importlib
import io
import json
import os
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch


ISOLATED_MODULES = (
    "src.main",
    "src.embeddings",
    "src.retrieval",
    "src.api",
    "src.evaluate_query_router",
    "src.evaluate_retrieval",
    "src.ingest",
)
MISSING = object()


class OfflineTestCase(unittest.TestCase):
    """Every subclass runs with fake credentials, fake clients, and no network."""

    def setUp(self):
        super().setUp()
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.network_guards = []
        for target in (
            "socket.socket.connect",
            "socket.socket.connect_ex",
            "socket.create_connection",
            "socket.getaddrinfo",
            "httpx.HTTPTransport.handle_request",
            "httpx.AsyncHTTPTransport.handle_async_request",
        ):
            guard = self.stack.enter_context(patch(
                target, side_effect=AssertionError("Network disabled by offline tests")
            ))
            self.network_guards.append(guard)

        # Synthetic artifacts live only in temporary directories. Fixture
        # creation never calls ingestion or any embedding provider.
        self.temporary = self.stack.enter_context(TemporaryDirectory())
        self.index_path = Path(self.temporary) / "index" / "portfolio.json"
        self.index_path.parent.mkdir()
        self.usage_path = Path(self.temporary) / "state" / "usage.sqlite3"
        self.usage_path.parent.mkdir()
        from src.usage import UsageLedger
        self.usage_ledger = UsageLedger(self.usage_path)
        self.usage_ledger.initialize()
        self.usage_ledger.set_disabled(False)
        from src.index_store import EMBEDDING_DIMENSIONS, make_payload, source_snapshot
        source = source_snapshot()
        self.vector = [1.0] + [0.0] * (EMBEDDING_DIMENSIONS - 1)
        payload = make_payload(source, [self.vector.copy() for _ in source.chunks])
        self.index_path.write_text(json.dumps(payload), encoding="utf-8")

        self.stack.enter_context(patch.dict(os.environ, {
            "BACKEND_DEPLOYMENT_POLICY": "production",
            "LEGACY_CHAT_ENABLED": "false",
            "GOOGLE_API_KEY": "offline-test-key-not-a-secret",
            "USAGE_LEDGER_PATH": str(self.usage_path),
            "USAGE_DAILY_LIMIT": "100",
            "USAGE_MONTHLY_LIMIT": "1000",
            "USAGE_MAX_CONCURRENT": "2",
            "USAGE_SQLITE_BUSY_MS": "250",
            "STAGING_AUTH_ENABLED": "false",
            "CAPABILITY_AUTH_ENABLED": "false",
            "VERIFIED_SESSION_AUTH_TOKEN": "",
            "SESSION_CHAT_AUTH_TOKEN": "",
            "VERIFIED_SESSION_CREDENTIAL_ID": "verified-session-v1",
            "SESSION_CHAT_CREDENTIAL_ID": "session-chat-v1",
            "BOT_VERIFICATION_ENABLED": "false",
            "BOT_PROVIDER_SECRET": "",
            "BOT_ALLOWED_HOSTNAMES": "",
            "BOT_EXPECTED_ACTION": "portfolio_session",
            "BOT_MAX_AGE_SECONDS": "300",
            "BOT_TIMEOUT_SECONDS": "5",
            "BOT_ATTEMPTS_MINUTE": "10",
            "BOT_ATTEMPTS_DAY": "100",
            "BOT_MAX_CONCURRENT": "2",
            "SESSION_ISSUANCE_ENABLED": "false",
            "SESSION_ADMISSION_ENABLED": "false",
            "SESSION_CHAT_ENABLED": "false",
            "SESSION_CHAT_HTTP_ENABLED": "false",
            "IP_ADMISSION_ENABLED": "false",
            "IP_RATE_HMAC_KEY": "",
            "IP_ADMISSION_MINUTE_LIMIT": "10",
            "IP_ADMISSION_DAY_LIMIT": "60",
            "SESSION_ADMISSION_MINUTE_LIMIT": "3",
            "SESSION_ADMISSION_HOUR_LIMIT": "12",
            "SESSION_LIFETIME_SECONDS": "14400",
            "SESSION_ISSUANCE_MINUTE_LIMIT": "10",
            "SESSION_ISSUANCE_DAY_LIMIT": "100",
            "SESSION_MAX_LIVE": "500",
            "STAGING_AUTH_TOKEN": "",
            "STAGING_BUDGET_REQUESTS": "10",
            "STAGING_BUDGET_WINDOW_SECONDS": "60",
            "FRONTEND_ORIGINS": "http://localhost:3000",
            "GEMINI_EMBEDDING_TIMEOUT_MS": "10000",
            "GEMINI_GENERATION_TIMEOUT_MS": "20000",
            "GEMINI_NETWORK_POLICY": "auto",
            "GEMINI_MAX_OUTPUT_TOKENS": "1024",
            "GEMINI_THINKING_LEVEL": "LOW",
            "CHAT_MAX_BODY_BYTES": "8192",
            "CHAT_MAX_CONCURRENT": "4",
            "CHAT_RATE_LIMIT_REQUESTS": "20",
            "CHAT_RATE_LIMIT_WINDOW_SECONDS": "60",
            "CHAT_RATE_LIMIT_MAX_CLIENTS": "1024",
            "CHAT_DEADLINE_SECONDS": "40",
            "RAG_INDEX_PATH": str(self.index_path),
        }))
        # Never read the developer's .env file during tests.
        self.dotenv = self.stack.enter_context(patch(
            "dotenv.load_dotenv", return_value=False
        ))
        self.models = Mock(spec_set=["embed_content", "generate_content"])
        self.models.embed_content.return_value = SimpleNamespace(
            embeddings=[SimpleNamespace(values=self.vector.copy())]
        )
        self.models.generate_content.return_value = SimpleNamespace(
            text="Offline test answer.",
            candidates=[SimpleNamespace(finish_reason="STOP")],
        )
        self.provider = Mock(spec_set=["models", "close"])
        self.provider.models = self.models
        self.client_factory = self.stack.enter_context(patch(
            "google.genai.Client", return_value=self.provider
        ))

        package = importlib.import_module("src")
        saved_modules = {name: sys.modules.pop(name, MISSING)
                         for name in ISOLATED_MODULES}
        saved_attributes = {}
        for name in ISOLATED_MODULES:
            attribute = name.rsplit(".", 1)[1]
            saved_attributes[attribute] = getattr(package, attribute, MISSING)
            if hasattr(package, attribute):
                delattr(package, attribute)

        def restore_modules():
            for name, module in saved_modules.items():
                sys.modules.pop(name, None)
                if module is not MISSING:
                    sys.modules[name] = module
            for attribute, value in saved_attributes.items():
                if hasattr(package, attribute):
                    delattr(package, attribute)
                if value is not MISSING:
                    setattr(package, attribute, value)

        self.stack.callback(restore_modules)

    def load(self, name):
        # Suppress import-time indexing prints, not test runner output.
        with redirect_stdout(io.StringIO()):
            return importlib.import_module(name)


    def authorize_legacy_staging(self, api, *, token=None, large_budget=True):
        """Explicit authenticated test staging, never a production-policy bypass.

        Old API/RAG tests exercised anonymous /chat. They now opt into its
        deliberate staging contract and send a synthetic bearer. Security tests
        retain explicit negative requests without default client headers.
        """
        from dataclasses import replace
        from src.reliability import RateLimiter
        settings = api.app.state.chat_controls.settings
        token = token or settings.staging_auth_token or 'offline-staging-fixture-' + 'a' * 32
        settings = replace(settings, backend_deployment_policy='staging', legacy_chat_enabled=True,
                           staging_auth_enabled=True, staging_auth_token=token)
        if large_budget:
            settings = replace(settings, staging_budget_requests=10000)
        api.settings = settings
        api.app.state.chat_controls.settings = settings
        api.app.state.chat_controls.authenticated_budget = RateLimiter(settings.staging_budget_requests,
                                                                      settings.staging_budget_window_seconds, 1)
        return {'Authorization': 'Bearer ' + token}
