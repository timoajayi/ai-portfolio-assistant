from src.query_expansion import expand_query
from src.query_router import is_project_collection_query
from tests.offline import OfflineTestCase


class QueryRoutingTests(OfflineTestCase):
    def test_general_project_lists(self):
        for question in (
            "What AI projects has Timothy worked on?",
            "Tell me about Timothy's projects.",
            "Which projects has Timothy built?",
            "List Timothy's AI projects.",
            "Tell me about his projects",
            "  WHAT AI PROJECTS HAS TIMOTHY BUILT?  ",
        ):
            with self.subTest(question=question):
                self.assertTrue(is_project_collection_query(question))

    def test_project_specific_questions_use_focused_retrieval(self):
        for question in (
            "What did Timothy contribute to BundesHost?",
            "Tell me about Customer Churn Prediction.",
            "Which machine learning project did Timothy build independently to predict customer churn?",
        ):
            with self.subTest(question=question):
                self.assertFalse(is_project_collection_query(question))

    def test_skill_questions_use_focused_retrieval(self):
        for question in ("Has Timothy used Docker?", "Has Timothy worked with RAG?"):
            with self.subTest(question=question):
                self.assertFalse(is_project_collection_query(question))

    def test_unrelated_questions_are_not_project_collections(self):
        for question in ("What is storage?", "What is the weather?", "", "Hello!"):
            with self.subTest(question=question):
                self.assertFalse(is_project_collection_query(question))


class KnownRoutingRegressionTests(OfflineTestCase):
    """Intended behavior; genuine failures until the next production phase.

    Technology-filtered questions must use focused retrieval because the
    existing collection route supplies overviews without technology evidence.
    """

    def test_mlflow_filtered_projects_use_focused_retrieval(self):
        self.assertFalse(is_project_collection_query("Which projects use MLflow?"))

    def test_docker_filtered_projects_use_focused_retrieval(self):
        self.assertFalse(is_project_collection_query("What projects use Docker?"))

    def test_show_me_all_projects_uses_collection(self):
        self.assertTrue(is_project_collection_query("Show me all projects"))

    def test_curly_apostrophe_uses_collection(self):
        self.assertTrue(is_project_collection_query("List Timothy’s projects."))

    def test_summarize_portfolio_projects_uses_collection(self):
        self.assertTrue(is_project_collection_query("Summarize his portfolio projects"))


class QueryExpansionTests(OfflineTestCase):
    def test_supported_terms_expand(self):
        cases = {
            "Has Timothy used RAG?": "retrieval-augmented generation",
            "Has he used an LLM?": "large language model",
            "What about experiment tracking?": "MLflow model tracking",
            "What did he build independently?": "solo project individual project",
        }
        for question, expansion in cases.items():
            with self.subTest(question=question):
                self.assertEqual(expand_query(question), question + " " + expansion)

    def test_unmapped_question_is_unchanged(self):
        question = "What languages does Timothy speak?"
        self.assertEqual(expand_query(question), question)

    def test_empty_question_is_unchanged(self):
        self.assertEqual(expand_query(""), "")


class KnownExpansionRegressionTests(OfflineTestCase):
    def test_storage_does_not_trigger_rag_expansion(self):
        question = "What is storage?"
        self.assertEqual(expand_query(question), question)
