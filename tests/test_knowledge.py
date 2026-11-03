from pathlib import Path
import re
from tempfile import TemporaryDirectory
from unittest.mock import patch

from src import chunking, knowledge
from tests.offline import OfflineTestCase


class KnowledgeLoadingTests(OfflineTestCase):
    def test_valid_utf8_file(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "portfolio.md"
            text = "# Portfolio\n\n## Languages\nDeutsch — B1\n"
            path.write_text(text, encoding="utf-8")
            with patch.object(knowledge, "PORTFOLIO_PATH", path):
                self.assertEqual(knowledge.load_portfolio_knowledge(), text)

    def test_missing_file(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "missing.md"
            with patch.object(knowledge, "PORTFOLIO_PATH", path):
                with self.assertRaisesRegex(FileNotFoundError, "Portfolio knowledge file not found"):
                    knowledge.load_portfolio_knowledge()

    def test_empty_file_loads_empty_text(self):
        # Loading is a raw I/O operation; empty input must chunk to no evidence.
        with TemporaryDirectory() as directory:
            path = Path(directory) / "portfolio.md"
            path.write_text("", encoding="utf-8")
            with patch.object(knowledge, "PORTFOLIO_PATH", path):
                self.assertEqual(knowledge.load_portfolio_knowledge(), "")
                self.assertEqual(chunking.chunk_portfolio_by_section(), [])


class ChunkingTests(OfflineTestCase):
    def test_empty_and_whitespace_content_produces_no_chunks(self):
        for content in ("", " \n\t "):
            with self.subTest(content=repr(content)):
                with patch.object(chunking, "load_portfolio_knowledge", return_value=content):
                    self.assertEqual(chunking.chunk_portfolio_by_section(), [])

    def test_title_and_assistant_guidelines_are_excluded(self):
        text = "# Timothy Ajayi\n\n## Profile\nA profile.\n\n## Assistant Guidelines\nDo not invent facts."
        with patch.object(chunking, "load_portfolio_knowledge", return_value=text):
            self.assertEqual(chunking.chunk_portfolio_by_section(), ["## Profile\nA profile."])

    def test_current_project_coverage(self):
        text = knowledge.load_portfolio_knowledge()
        projects = set(re.findall(r"^### (.+)$", text.split("## Projects\n", 1)[1].split("\n## ", 1)[0], re.MULTILINE))
        chunks = chunking.chunk_portfolio_by_section()
        self.assertEqual(len(projects), 6)
        for title in projects:
            with self.subTest(project=title):
                self.assertTrue(any(c.splitlines()[0].startswith("### " + title) for c in chunks))
        overviews = chunking.get_project_overview_chunks()
        overview_titles = [c.splitlines()[0].removeprefix("### ").split(" — ", 1)[0]
                           for c in overviews]
        self.assertCountEqual(overview_titles, projects)

    def test_current_chunks_have_content_and_no_guidelines(self):
        for chunk in chunking.chunk_portfolio_by_section():
            with self.subTest(heading=chunk.splitlines()[0]):
                self.assertTrue(chunk.partition("\n")[2].strip())
                self.assertNotIn("Assistant Guidelines", chunk)

    def test_short_generic_project_is_preserved(self):
        section = "### Small Project\n\nA short description."
        self.assertEqual(chunking.split_large_project(section), [section])

    def test_empty_project_section(self):
        self.assertEqual(chunking.split_large_project(""), [])


class KnownChunkingRegressionTests(OfflineTestCase):
    def test_short_bundeshost_section_preserves_available_content(self):
        chunks = chunking.split_large_project(
            "### BundesHost Tourism Forecasting\n\nA short summary."
        )
        self.assertTrue(chunks)
        self.assertIn("A short summary.", "\n".join(chunks))
        for chunk in chunks:
            self.assertTrue(chunk.partition("\n")[2].strip())

    def test_short_churn_section_does_not_create_empty_evidence(self):
        chunks = chunking.split_large_project(
            "### Customer Churn Prediction\n\nA short summary."
        )
        self.assertTrue(chunks)
        self.assertIn("A short summary.", "\n".join(chunks))
        for chunk in chunks:
            self.assertTrue(chunk.partition("\n")[2].strip(), chunk.splitlines()[0])

    def test_new_project_is_included_in_collection_coverage(self):
        text = "# Timothy Ajayi\n\n## Projects\n\n### New Project\n\nA new project."
        with patch.object(chunking, "load_portfolio_knowledge", return_value=text):
            self.assertEqual(chunking.get_project_overview_chunks(),
                             ["### New Project\n\nA new project."])
