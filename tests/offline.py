"""Scoped provider mocks and fail-closed network guards for unittest.

Production modules are imported only after the guards are installed. Their
module cache entries and parent-package attributes are restored after each
test so mocked clients cannot escape into other tests in the same process.
"""

from contextlib import ExitStack, redirect_stdout
import importlib
import io
import os
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch


ISOLATED_MODULES = (
    "src.embeddings",
    "src.retrieval",
    "src.api",
    "src.evaluate_query_router",
    "src.evaluate_retrieval",
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

        self.stack.enter_context(patch.dict(os.environ, {
            "GOOGLE_API_KEY": "offline-test-key-not-a-secret",
            "FRONTEND_ORIGINS": "http://localhost:3000",
            "GEMINI_EMBEDDING_TIMEOUT_MS": "10000",
            "GEMINI_GENERATION_TIMEOUT_MS": "20000",
            "GEMINI_MAX_OUTPUT_TOKENS": "512",
            "CHAT_MAX_BODY_BYTES": "8192",
            "CHAT_MAX_CONCURRENT": "4",
            "CHAT_RATE_LIMIT_REQUESTS": "20",
            "CHAT_RATE_LIMIT_WINDOW_SECONDS": "60",
            "CHAT_RATE_LIMIT_MAX_CLIENTS": "1024",
        }))
        # Never read the developer's .env file during tests.
        self.dotenv = self.stack.enter_context(patch(
            "dotenv.load_dotenv", return_value=False
        ))
        self.models = Mock(spec_set=["embed_content", "generate_content"])
        self.models.embed_content.return_value = SimpleNamespace(
            embeddings=[SimpleNamespace(values=[1.0, 0.0])]
        )
        self.models.generate_content.return_value = SimpleNamespace(
            text="Offline test answer."
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
