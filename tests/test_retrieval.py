import math
from unittest.mock import patch

from tests.offline import OfflineTestCase


class RetrievalTests(OfflineTestCase):
    def setUp(self):
        super().setUp()
        self.retrieval = self.load("src.retrieval")

    def test_zero_magnitude_embeddings(self):
        for first, second in (([0, 0], [1, 2]), ([1, 2], [0, 0]), ([0, 0], [0, 0])):
            with self.subTest(first=first, second=second):
                self.assertEqual(self.retrieval.cosine_similarity(first, second), 0.0)

    def test_cosine_identical_orthogonal_and_opposite_vectors(self):
        for second, expected in (([1, 0], 1.0), ([0, 1], 0.0), ([-1, 0], -1.0)):
            with self.subTest(second=second):
                self.assertAlmostEqual(self.retrieval.cosine_similarity([1, 0], second), expected)

    def test_bm25_synthetic_corpus(self):
        index = self.retrieval.build_bm25_index(["docker docker", "python api", "docker python"])
        self.assertEqual(index["document_count"], 3)
        self.assertEqual(index["average_document_length"], 2)
        self.assertEqual(index["document_frequencies"]["docker"], 2)
        scores = [self.retrieval.bm25_score("docker", i, index) for i in range(3)]
        self.assertGreater(scores[0], scores[2])
        self.assertGreater(scores[2], scores[1])
        self.assertEqual(scores[1], 0)
        self.assertAlmostEqual(scores[2], math.log(1 + 1.5 / 2.5))

    def test_bm25_unknown_and_empty_queries_score_zero(self):
        index = self.retrieval.build_bm25_index(["docker python"])
        for query in ("unseen", ""):
            with self.subTest(query=query):
                self.assertEqual(self.retrieval.bm25_score(query, 0, index), 0)

    def test_top_k_and_hybrid_ranking(self):
        chunks = ["docker", "python", "api"]
        index = list(zip(chunks, ([1., 0.], [0., 1.], [-1., 0.])))
        with patch.object(self.retrieval, "PORTFOLIO_INDEX", index), patch.object(
            self.retrieval, "BM25_INDEX", self.retrieval.build_bm25_index(chunks)
        ), patch.object(self.retrieval, "create_embedding", return_value=[1., 0.]) as embed:
            for top_k in (0, 1, 2, 3, 10):
                with self.subTest(top_k=top_k):
                    results = self.retrieval.retrieve_relevant_chunks("docker", top_k)
                    self.assertEqual([chunk for chunk, _ in results], chunks[:top_k])
                    scores = [score for _, score in results]
                    self.assertEqual(scores, sorted(scores, reverse=True))
            embed.assert_called_with("docker", task_type="RETRIEVAL_QUERY")

    def test_index_creation_uses_mocked_document_embeddings(self):
        # This utility test intentionally uses tiny synthetic vectors, without
        # serializing them as a production index with fixed dimensions.
        from types import SimpleNamespace
        self.models.embed_content.return_value = SimpleNamespace(
            embeddings=[SimpleNamespace(values=[1.0, 0.0])]
        )
        with patch.object(self.retrieval, "chunk_portfolio_by_section", return_value=["one", "two"]):
            self.models.embed_content.reset_mock()
            index = self.retrieval.build_portfolio_index()
        self.assertEqual(index, [("one", [1., 0.]), ("two", [1., 0.])])
        self.assertEqual(self.models.embed_content.call_count, 2)
        for call in self.models.embed_content.call_args_list:
            self.assertEqual(call.kwargs["config"]["task_type"], "RETRIEVAL_DOCUMENT")


class KnownRetrievalRegressionTests(OfflineTestCase):
    def setUp(self):
        super().setUp()
        self.retrieval = self.load("src.retrieval")

    def test_empty_bm25_corpus_is_a_valid_empty_index(self):
        index = self.retrieval.build_bm25_index([])
        self.assertEqual(index["document_count"], 0)
        self.assertEqual(index["average_document_length"], 0)

    def test_empty_retrieval_corpus_returns_no_evidence(self):
        with patch.object(self.retrieval, "PORTFOLIO_INDEX", []):
            self.assertEqual(self.retrieval.retrieve_relevant_chunks("docker"), [])

    def test_mismatched_embedding_dimensions_are_rejected(self):
        with self.assertRaises(ValueError):
            self.retrieval.cosine_similarity([1., 0.], [1.])

    def test_negative_top_k_is_rejected(self):
        with self.assertRaises(ValueError):
            self.retrieval.retrieve_relevant_chunks("docker", top_k=-1)
