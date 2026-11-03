import socket

import httpx

from tests.offline import OfflineTestCase


class OfflineIsolationTests(OfflineTestCase):
    def test_socket_connections_and_dns_are_blocked(self):
        # These addresses are never resolved or contacted.
        with self.assertRaisesRegex(AssertionError, "Network disabled"):
            socket.create_connection(("offline.invalid", 443))
        with self.assertRaisesRegex(AssertionError, "Network disabled"):
            socket.getaddrinfo("offline.invalid", 443)
        with socket.socket() as connection:
            with self.assertRaisesRegex(AssertionError, "Network disabled"):
                connection.connect(("127.0.0.1", 443))
            with self.assertRaisesRegex(AssertionError, "Network disabled"):
                connection.connect_ex(("127.0.0.1", 443))

    def test_http_transport_is_blocked(self):
        with httpx.Client() as client:
            with self.assertRaisesRegex(AssertionError, "Network disabled"):
                client.get("https://offline.invalid")

    def test_import_time_embeddings_use_only_fake_client(self):
        retrieval = self.load("src.retrieval")
        self.client_factory.assert_called_once()
        options = self.client_factory.call_args.kwargs
        self.assertEqual(options["api_key"], "offline-test-key-not-a-secret")
        self.assertEqual(options["http_options"].timeout, 10000)
        self.assertEqual(options["http_options"].retry_options.attempts, 1)
        self.assertEqual(self.models.embed_content.call_count, len(retrieval.PORTFOLIO_INDEX))
        self.assertGreater(len(retrieval.PORTFOLIO_INDEX), 0)
        for guard in self.network_guards:
            guard.assert_not_called()

    def test_api_and_embedding_clients_are_mocked_before_import(self):
        api = self.load("src.api")
        embeddings = self.load("src.embeddings")
        self.assertIs(api.client, self.provider)
        self.assertIs(embeddings.client, self.provider)
        self.assertEqual(self.client_factory.call_count, 2)
        self.assertEqual(api.api_key, "offline-test-key-not-a-secret")
        self.assertEqual(embeddings.api_key, "offline-test-key-not-a-secret")
        self.dotenv.assert_called()
        for guard in self.network_guards:
            guard.assert_not_called()
