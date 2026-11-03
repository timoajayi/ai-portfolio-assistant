from contextlib import redirect_stdout
import io
from pathlib import Path
import runpy
from unittest.mock import patch

from tests.offline import OfflineTestCase


ROOT = Path(__file__).resolve().parents[1]


class EvaluationExitCodeTests(OfflineTestCase):
    def run_cli(self, filename):
        # Execute the actual __main__ block inside the network-guarded process.
        # This avoids launching an unguarded child interpreter.
        with redirect_stdout(io.StringIO()), self.assertRaises(SystemExit) as exit_info:
            runpy.run_path(str(ROOT / "src" / filename), run_name="__main__")
        return exit_info.exception.code

    def test_router_success_returns_and_exits_zero(self):
        module = self.load("src.evaluate_query_router")
        with redirect_stdout(io.StringIO()):
            self.assertEqual(module.evaluate_query_router(), 0)
        self.assertEqual(self.run_cli("evaluate_query_router.py"), 0)

    def test_router_failure_returns_and_exits_nonzero(self):
        module = self.load("src.evaluate_query_router")
        with patch.object(module, "is_project_collection_query", return_value=False):
            with redirect_stdout(io.StringIO()):
                self.assertEqual(module.evaluate_query_router(), 1)
        with patch("src.query_router.is_project_collection_query", return_value=False):
            self.assertEqual(self.run_cli("evaluate_query_router.py"), 1)

    def test_retrieval_success_returns_and_exits_zero(self):
        module = self.load("src.evaluate_retrieval")
        # Test evaluator bookkeeping, not synthetic semantic quality.
        expected = {case["question"]: case["expected"][0] for case in module.TEST_CASES}

        def matching_results(question, top_k=3):
            return [("### " + expected[question] + "\nEvidence.", 0.9)]

        with patch.object(module, "retrieve_relevant_chunks", side_effect=matching_results):
            with redirect_stdout(io.StringIO()):
                self.assertEqual(module.evaluate_retrieval(), 0)
        with patch("src.retrieval.retrieve_relevant_chunks", side_effect=matching_results):
            self.assertEqual(self.run_cli("evaluate_retrieval.py"), 0)

    def test_retrieval_failure_returns_and_exits_nonzero(self):
        module = self.load("src.evaluate_retrieval")
        with patch.object(module, "retrieve_relevant_chunks", return_value=[]):
            with redirect_stdout(io.StringIO()):
                self.assertEqual(module.evaluate_retrieval(), 1)
        with patch("src.retrieval.retrieve_relevant_chunks", return_value=[]):
            self.assertEqual(self.run_cli("evaluate_retrieval.py"), 1)

    def test_one_router_failure_is_enough_for_nonzero(self):
        module = self.load("src.evaluate_query_router")
        answers = [case["expected"] for case in module.TEST_CASES]
        answers[-1] = not answers[-1]
        with patch.object(module, "is_project_collection_query", side_effect=answers):
            with redirect_stdout(io.StringIO()):
                self.assertEqual(module.evaluate_query_router(), 1)

    def test_one_retrieval_failure_is_enough_for_nonzero(self):
        module = self.load("src.evaluate_retrieval")
        answers = [[("### " + case["expected"][0], 0.9)] for case in module.TEST_CASES]
        answers[-1] = []
        with patch.object(module, "retrieve_relevant_chunks", side_effect=answers):
            with redirect_stdout(io.StringIO()):
                self.assertEqual(module.evaluate_retrieval(), 1)
