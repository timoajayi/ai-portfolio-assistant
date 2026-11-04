import asyncio
import errno
import json
import os
import socket
import ssl
from unittest.mock import patch

import httpx
from fastapi.testclient import TestClient
from google import genai

from src.config import Settings
from src.provider import http_options
from tests.offline import OfflineTestCase


# Keep real public constructors so tests can exercise SDK serialization and
# HTTPX routing with in-memory/fake transports, never real network operations.
SDK_CLIENT = genai.Client
HTTP_TRANSPORT_HANDLE = httpx.HTTPTransport.handle_request
STDLIB_CREATE_CONNECTION = socket.create_connection


class TransportPolicyTests(OfflineTestCase):
    def setUp(self):
        super().setUp()
        self.stack.enter_context(patch("src.config.getproxies", return_value={}))

    def test_default_policy_preserves_sdk_transport_selection(self):
        with patch("src.provider.httpx.HTTPTransport") as transport:
            options = http_options(10000)
        transport.assert_not_called()
        self.assertIsNone(options.client_args)
        self.assertIsNone(options.httpx_client)
        self.assertEqual(options.timeout, 10000)
        self.assertEqual(options.retry_options.attempts, 1)
        self.assertEqual(Settings.from_env().gemini_network_policy, "auto")

    def test_ipv4_uses_public_transport_options_and_tls_verification(self):
        with patch("src.provider.httpx.HTTPTransport") as transport:
            options = http_options(10000, network_policy="ipv4")
        transport.assert_called_once_with(
            local_address="0.0.0.0", verify=True, retries=0, trust_env=True
        )
        self.assertIs(options.client_args["transport"], transport.return_value)
        self.assertIsNone(options.httpx_client)  # SDK owns the HTTPX client.
        self.assertIsNone(options.base_url)  # Preserve official SDK URL/SNI.

    def test_both_transport_modes_preserve_provider_timeouts_and_attempts(self):
        for policy in ("auto", "ipv4"):
            for timeout in (10000, 20000):
                with self.subTest(policy=policy, timeout=timeout):
                    options = http_options(timeout, network_policy=policy)
                    try:
                        self.assertEqual(options.timeout, timeout)
                        self.assertEqual(options.retry_options.attempts, 1)
                    finally:
                        if options.client_args:
                            options.client_args["transport"].close()

    def test_environment_selects_policy_without_enabling_it_by_default(self):
        for value, expected in (("auto", "auto"), ("ipv4", "ipv4"), (" IPV4 ", "ipv4")):
            with patch.dict(os.environ, {"GEMINI_NETWORK_POLICY": value}):
                self.assertEqual(Settings.from_env().gemini_network_policy, expected)

    def test_invalid_policy_is_rejected_without_echoing_values(self):
        for value in ("", "ipv6", "PRIVATE-CONFIG-VALUE", "false"):
            with self.subTest(value=value), patch.dict(os.environ, {"GEMINI_NETWORK_POLICY": value}):
                with self.assertRaisesRegex(ValueError, "GEMINI_NETWORK_POLICY") as error:
                    Settings.from_env()
                if value:
                    self.assertNotIn(value, str(error.exception))

    def test_invalid_direct_factory_policy_is_rejected(self):
        for value in (None, True, "unsupported"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                http_options(10000, network_policy=value)

    def test_ipv4_cannot_silently_bypass_a_configured_proxy(self):
        for scheme in ("http", "https", "all"):
            with self.subTest(scheme=scheme), patch("src.config.getproxies", return_value={scheme: "http://PRIVATE-PROXY"}):
                with self.assertRaisesRegex(ValueError, "configured proxies are unsupported") as error:
                    http_options(10000, network_policy="ipv4")
                self.assertNotIn("PRIVATE-PROXY", str(error.exception))
                with patch.dict(os.environ, {"GEMINI_NETWORK_POLICY": "ipv4"}):
                    with self.assertRaises(ValueError):
                        Settings.from_env()

    def test_auto_does_not_override_or_reject_proxy_settings(self):
        with patch("src.config.getproxies", return_value={"https": "http://PRIVATE-PROXY"}) as proxy_lookup:
            options = http_options(10000, network_policy="auto")
        proxy_lookup.assert_not_called()
        self.assertIsNone(options.client_args)

    def test_no_global_socket_or_httpx_defaults_are_modified(self):
        create_connection = socket.create_connection
        getaddrinfo = socket.getaddrinfo
        client_class = httpx.Client
        options = http_options(10000, network_policy="ipv4")
        try:
            self.assertIs(socket.create_connection, create_connection)
            self.assertIs(socket.getaddrinfo, getaddrinfo)
            self.assertIs(httpx.Client, client_class)
            unrelated = httpx.Client(transport=httpx.MockTransport(lambda req: httpx.Response(200)))
            with unrelated:
                self.assertEqual(unrelated.get("https://offline.invalid/").status_code, 200)
        finally:
            options.client_args["transport"].close()

    def test_ssl_certificate_environment_remains_under_httpx_control(self):
        with patch.dict(os.environ, {"SSL_CERT_FILE": "/offline/ca.pem"}):
            with patch("src.provider.httpx.HTTPTransport") as transport:
                options = http_options(10000, network_policy="ipv4")
        self.assertTrue(transport.call_args.kwargs["verify"])
        self.assertTrue(transport.call_args.kwargs["trust_env"])

    def test_ipv6_candidates_are_skipped_before_connect_and_sni_is_preserved(self):
        connections, bindings, tls_calls = [], [], []
        dns = [
            (socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("2001:db8::1", 443, 0, 0)),
            (socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("2001:db8::2", 443, 0, 0)),
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("192.0.2.1", 443)),
        ]

        class FakeSocket:
            def __init__(self, family, *args):
                self.family = family
                self.response = b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}'
            def settimeout(self, value):
                pass
            def bind(self, address):
                bindings.append((self.family, address))
                if self.family == socket.AF_INET6:
                    raise OSError(errno.EAFNOSUPPORT, "Offline incompatible source address")
            def connect(self, address):
                connections.append((self.family, address))
                if self.family != socket.AF_INET:
                    raise AssertionError("IPv6 must not reach a connection attempt")
            def setsockopt(self, *args):
                pass
            def send(self, data):
                return len(data)
            def recv(self, size):
                result, self.response = self.response[:size], self.response[size:]
                return result
            def close(self):
                pass

        def tls_wrap(context, sock, server_hostname=None, **kwargs):
            self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
            self.assertTrue(context.check_hostname)
            tls_calls.append(server_hostname)
            return sock

        options = http_options(10000, network_policy="ipv4")
        # All patches are test-only and restored; no real socket is created.
        with patch.object(httpx.HTTPTransport, "handle_request", HTTP_TRANSPORT_HANDLE), \
             patch("socket.getaddrinfo", return_value=dns) as resolver, \
             patch("socket.socket", side_effect=FakeSocket), \
             patch("socket.create_connection", STDLIB_CREATE_CONNECTION), \
             patch.object(ssl.SSLContext, "wrap_socket", autospec=True, side_effect=tls_wrap):
            with httpx.Client(**options.client_args, timeout=1) as client:
                response = client.get("https://generativelanguage.googleapis.com/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(resolver.call_args.args[:2], ("generativelanguage.googleapis.com", 443))
        self.assertEqual([family for family, _ in connections], [socket.AF_INET])
        self.assertEqual(tls_calls, ["generativelanguage.googleapis.com"])
        self.assertTrue(all(address == ("0.0.0.0", 0) for _, address in bindings))

    def test_policy_is_shared_by_document_query_and_generation_and_owned_clients_close(self):
        captures, transports, clients = [], [], []

        def handle(request):
            body = json.loads(request.content)
            if request.url.path.endswith(":batchEmbedContents"):
                item = body["requests"][0]
                task = item["taskType"]
                response = {"embeddings": [{"values": self.vector.copy()}]}
            else:
                task = "generation"
                response = {"candidates": [{"content": {"role": "model", "parts": [{"text": "Offline transport answer."}]}, "finishReason": "STOP"}]}
            captures.append({"host": request.url.host, "task": task, "timeouts": request.extensions["timeout"]})
            return httpx.Response(200, json=response)

        class RecordingTransport(httpx.MockTransport):
            closed = False
            def close(self):
                self.closed = True
                super().close()

        def transport_factory(**kwargs):
            self.assertEqual(kwargs, {"local_address": "0.0.0.0", "verify": True, "retries": 0, "trust_env": True})
            transport = RecordingTransport(handle)
            transports.append(transport)
            return transport

        def sdk_factory(**kwargs):
            self.assertEqual(kwargs["http_options"].retry_options.attempts, 1)
            client = SDK_CLIENT(**kwargs)
            clients.append(client)
            return client

        try:
            with patch.dict(os.environ, {"GEMINI_NETWORK_POLICY": "ipv4"}), \
                 patch("src.provider.httpx.HTTPTransport", side_effect=transport_factory), \
                 patch("google.genai.Client", side_effect=sdk_factory):
                api = self.load("src.api")
                embeddings = self.load("src.embeddings")
                self.assertEqual(embeddings.create_embedding("Synthetic document"), self.vector)
                with TestClient(api.app) as client:
                    response = client.post("/chat", json={"message": "Docker?"})
                    self.assertEqual(response.status_code, 200)
                    self.assertEqual(response.json(), {"answer": "Offline transport answer."})
                self.assertEqual(len(transports), 2)
                self.assertTrue(all(transport.closed for transport in transports))
            self.assertEqual([item["task"] for item in captures], ["RETRIEVAL_DOCUMENT", "RETRIEVAL_QUERY", "generation"])
            self.assertTrue(all(item["host"] == "generativelanguage.googleapis.com" for item in captures))
            self.assertEqual([item["timeouts"]["connect"] for item in captures], [10, 10, 20])
            for guard in self.network_guards:
                guard.assert_not_called()
        finally:
            for client in clients:
                client.close()
                asyncio.run(client.aio.aclose())
