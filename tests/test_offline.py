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

    def test_importing_retrieval_does_not_embed_or_load_documents(self):
        retrieval = self.load("src.retrieval")
        self.client_factory.assert_not_called()
        self.models.embed_content.assert_not_called()
        self.models.generate_content.assert_not_called()
        self.assertEqual(retrieval.PORTFOLIO_INDEX, [])
        for guard in self.network_guards:
            guard.assert_not_called()

    def test_api_and_embedding_clients_are_mocked_before_import(self):
        api = self.load("src.api")
        embeddings = self.load("src.embeddings")
        self.client_factory.assert_not_called()
        self.models.embed_content.assert_not_called()
        self.models.generate_content.assert_not_called()
        self.assertIs(api.get_generation_client(), self.provider)
        self.assertIs(embeddings.get_client(), self.provider)
        self.assertEqual(self.client_factory.call_count, 2)
        self.assertEqual(api.api_key, "offline-test-key-not-a-secret")
        self.assertEqual(embeddings.api_key, "offline-test-key-not-a-secret")
        self.dotenv.assert_called()
        for guard in self.network_guards:
            guard.assert_not_called()
