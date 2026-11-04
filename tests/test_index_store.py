from contextlib import redirect_stdout
from dataclasses import replace
import hashlib
import io
import json
import os
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from src import index_store, knowledge
from src.config import REPOSITORY_ROOT, Settings
from tests.offline import OfflineTestCase


class IndexTestCase(OfflineTestCase):
    def payload(self):
        return json.loads(self.index_path.read_text(encoding="utf-8"))

    def write_payload(self, payload):
        self.index_path.write_text(json.dumps(payload), encoding="utf-8")

    def assert_invalid(self, payload):
        self.write_payload(payload)
        with self.assertRaises(index_store.IndexValidationError):
            index_store.load_index(self.index_path)
        self.models.embed_content.assert_not_called()
        self.models.generate_content.assert_not_called()


class PersistentIndexTests(IndexTestCase):
    def test_successful_loading_matches_all_current_chunks(self):
        document = index_store.load_index(self.index_path)
        source = index_store.source_snapshot()
        self.assertEqual([chunk.text for chunk in document.chunks], list(source.chunks))
        self.assertEqual(document.source_sha256, source.sha256)
        self.assertEqual(document.overviews, source.overviews)
        self.assertTrue(all(len(c.embedding) == 3072 for c in document.chunks))
        self.models.embed_content.assert_not_called()

    def test_schema_and_model_identity(self):
        payload = self.payload()
        self.assertEqual(payload["schema_version"], 1)
        self.assertEqual(payload["chunking_version"], 1)
        self.assertEqual(payload["embedding_model"], "gemini-embedding-001")
        self.assertEqual(payload["embedding_dimensions"], 3072)
        self.assertEqual(set(payload), {"schema_version", "chunking_version", "embedding_model",
                                       "embedding_dimensions", "source_sha256", "chunks"})

    def test_source_hash_uses_exact_content_bytes(self):
        self.assertEqual(self.payload()["source_sha256"],
                         hashlib.sha256(knowledge.PORTFOLIO_PATH.read_bytes()).hexdigest())

    def test_chunk_ids_are_deterministic_and_content_sensitive(self):
        source = index_store.source_snapshot()
        first = index_store.make_payload(source, [self.vector] * len(source.chunks))
        second = index_store.make_payload(source, [self.vector] * len(source.chunks))
        self.assertEqual([c["id"] for c in first["chunks"]], [c["id"] for c in second["chunks"]])
        self.assertNotEqual(index_store.chunk_id("example"), index_store.chunk_id("example changed"))

    def test_missing_index(self):
        self.index_path.unlink()
        with self.assertRaisesRegex(index_store.IndexValidationError, "missing_index"):
            index_store.load_index(self.index_path)

    def test_corrupt_json_and_invalid_utf8(self):
        for content in (b"{", b"not json", b"\xff\xfe"):
            with self.subTest(content=repr(content)):
                self.index_path.write_bytes(content)
                with self.assertRaises(index_store.IndexValidationError):
                    index_store.load_index(self.index_path)

    def test_wrong_schema_and_chunking_versions(self):
        for key in ("schema_version", "chunking_version"):
            for value in (999, True, "1", None):
                with self.subTest(key=key, value=value):
                    payload = self.payload()
                    payload[key] = value
                    self.assert_invalid(payload)
                    # Restore only the tested field before the next case.
                    payload[key] = 1
                    self.write_payload(payload)

    def test_wrong_embedding_model(self):
        payload = self.payload()
        payload["embedding_model"] = "unapproved-model"
        self.assert_invalid(payload)

    def test_stale_content_hash(self):
        payload = self.payload()
        payload["source_sha256"] = "0" * 64
        self.assert_invalid(payload)

    def test_changed_knowledge_invalidates_index(self):
        source_path = Path(self.temporary) / "changed.md"
        source_path.write_text(knowledge.load_portfolio_knowledge() + "\n", encoding="utf-8")
        with patch.object(knowledge, "PORTFOLIO_PATH", source_path):
            with self.assertRaisesRegex(index_store.IndexValidationError, "stale_source"):
                index_store.load_index(self.index_path)

    def test_wrong_declared_embedding_dimensions(self):
        payload = self.payload()
        payload["embedding_dimensions"] = 768
        self.assert_invalid(payload)

    def test_wrong_vector_dimensions(self):
        payload = self.payload()
        payload["chunks"][0]["embedding"] = [1.0, 0.0]
        self.assert_invalid(payload)

    def test_nan_and_infinity_are_rejected(self):
        original = self.payload()
        for value in (float("nan"), float("inf"), float("-inf")):
            with self.subTest(value=str(value)):
                original["chunks"][0]["embedding"][0] = value
                self.assert_invalid(original)

    def test_nonfinite_values_are_rejected_before_serializing(self):
        payload = self.payload()
        payload["chunks"][0]["embedding"][0] = float("nan")
        with self.assertRaisesRegex(index_store.IndexValidationError, "invalid_vector"):
            index_store.validate_payload(payload)

    def test_numeric_overflow_and_non_numeric_or_boolean_vectors(self):
        original = self.payload()
        for value in (1e309, True, "0.5", None, 10 ** 400):
            with self.subTest(kind=type(value).__name__):
                original["chunks"][0]["embedding"][0] = value
                self.assert_invalid(original)

    def test_zero_vectors_are_rejected(self):
        payload = self.payload()
        payload["chunks"][0]["embedding"] = [0.0] * 3072
        self.assert_invalid(payload)

    def test_duplicate_chunk_ids(self):
        payload = self.payload()
        payload["chunks"][1]["id"] = payload["chunks"][0]["id"]
        self.assert_invalid(payload)

    def test_empty_chunks_and_heading_only_chunks(self):
        original = self.payload()
        for text in ("", " \n ", "### Title\n\n"):
            with self.subTest(text=repr(text)):
                original["chunks"][0]["text"] = text
                self.assert_invalid(original)

    def test_missing_chunk_and_wrong_chunk_id(self):
        original = self.payload()
        removed = original["chunks"].pop()
        self.assert_invalid(original)
        original["chunks"].append(removed)
        original["chunks"][0]["id"] = "wrong"
        self.assert_invalid(original)

    def test_altered_text_heading_and_order_are_rejected(self):
        original = self.payload()
        for key in ("text", "heading"):
            payload = json.loads(json.dumps(original))
            payload["chunks"][0][key] += " altered"
            self.assert_invalid(payload)
        original["chunks"].reverse()
        self.assert_invalid(original)

    def test_wrong_container_types_and_unknown_fields(self):
        original = self.payload()
        for payload in ([], None, {}, {**original, "unrecognized": True}, {**original, "chunks": {}}):
            with self.subTest(kind=type(payload).__name__):
                self.assert_invalid(payload)

    def test_duplicate_json_keys_are_rejected(self):
        self.index_path.write_text('{"schema_version":1,"schema_version":1}', encoding="utf-8")
        with self.assertRaisesRegex(index_store.IndexValidationError, "duplicate_json_key"):
            index_store.load_index(self.index_path)

    def test_empty_or_missing_knowledge_is_rejected(self):
        source_path = Path(self.temporary) / "empty.md"
        source_path.write_text("", encoding="utf-8")
        with patch.object(knowledge, "PORTFOLIO_PATH", source_path):
            with self.assertRaisesRegex(index_store.IndexValidationError, "empty_source"):
                index_store.load_index(self.index_path)
            source_path.unlink()
            with self.assertRaisesRegex(index_store.IndexValidationError, "source_unavailable"):
                index_store.load_index(self.index_path)

    def test_index_size_is_bounded(self):
        with patch.object(index_store, "MAX_INDEX_BYTES", 10):
            with self.assertRaisesRegex(index_store.IndexValidationError, "index_too_large"):
                index_store.load_index(self.index_path)


class IngestionTests(IndexTestCase):
    def test_invalid_empty_chunk_source_is_rejected_before_paid_work(self):
        module = self.load("src.ingest")
        source_path = Path(self.temporary) / "heading-only.md"
        source_path.write_text("# Timothy Ajayi\n\n## Profile\n", encoding="utf-8")
        before = self.index_path.read_bytes()
        with patch.object(knowledge, "PORTFOLIO_PATH", source_path):
            with self.assertRaisesRegex(index_store.IndexValidationError, "empty_chunk"):
                module.ingest(self.index_path)
        self.assertEqual(self.index_path.read_bytes(), before)
        self.models.embed_content.assert_not_called()

    def test_duplicate_source_chunks_are_rejected_before_paid_work(self):
        module = self.load("src.ingest")
        source_path = Path(self.temporary) / "duplicate.md"
        source_path.write_text("# Timothy Ajayi\n\n## Profile\nText.\n\n## Profile\nText.", encoding="utf-8")
        before = self.index_path.read_bytes()
        with patch.object(knowledge, "PORTFOLIO_PATH", source_path):
            with self.assertRaisesRegex(index_store.IndexValidationError, "duplicate_or_invalid_chunk_id"):
                module.ingest(self.index_path)
        self.assertEqual(self.index_path.read_bytes(), before)
        self.models.embed_content.assert_not_called()

    def test_mocked_ingestion_writes_validated_document_embeddings(self):
        module = self.load("src.ingest")
        self.assertEqual(module.ingest(self.index_path), 18)
        self.assertEqual(len(index_store.load_index(self.index_path).chunks), 18)
        self.assertEqual(self.models.embed_content.call_count, 18)
        self.models.generate_content.assert_not_called()
        for call in self.models.embed_content.call_args_list:
            self.assertEqual(call.kwargs["model"], "gemini-embedding-001")
            self.assertEqual(call.kwargs["config"]["task_type"], "RETRIEVAL_DOCUMENT")
            self.assertEqual(call.kwargs["config"]["output_dimensionality"], 3072)

    def test_generation_failure_preserves_previous_valid_index(self):
        module = self.load("src.ingest")
        before = self.index_path.read_bytes()
        self.models.embed_content.side_effect = RuntimeError("private provider failure")
        with self.assertRaises(RuntimeError):
            module.ingest(self.index_path)
        self.assertEqual(self.index_path.read_bytes(), before)
        index_store.load_index(self.index_path)

    def test_validation_failure_preserves_previous_valid_index(self):
        module = self.load("src.ingest")
        before = self.index_path.read_bytes()
        self.models.embed_content.return_value.embeddings[0].values = [float("nan")] * 3072
        with self.assertRaises(index_store.IndexValidationError):
            module.ingest(self.index_path)
        self.assertEqual(self.index_path.read_bytes(), before)
        index_store.load_index(self.index_path)

    def test_partial_generation_failure_preserves_previous_valid_index(self):
        module = self.load("src.ingest")
        before = self.index_path.read_bytes()
        self.models.embed_content.side_effect = [self.models.embed_content.return_value, RuntimeError("private")]
        with self.assertRaises(RuntimeError):
            module.ingest(self.index_path)
        self.assertEqual(self.index_path.read_bytes(), before)

    def test_atomic_replace_uses_complete_file_in_same_directory(self):
        payload = self.payload()
        payload["chunks"][0]["embedding"][1] = 0.1
        old = self.index_path.read_bytes()
        real_replace = os.replace

        def replace_file(source, destination):
            self.assertEqual(Path(source).parent, self.index_path.parent)
            self.assertEqual(Path(destination), self.index_path)
            self.assertEqual(self.index_path.read_bytes(), old)
            document = index_store.load_index(Path(source))
            self.assertEqual(document.chunks[0].embedding[1], 0.1)
            real_replace(source, destination)

        with patch("src.index_store.os.replace", side_effect=replace_file) as replace_mock:
            index_store.write_index_atomic(self.index_path, payload)
        replace_mock.assert_called_once()
        self.assertEqual(index_store.load_index(self.index_path).chunks[0].embedding[1], 0.1)
        self.assertEqual(list(self.index_path.parent.glob("*.tmp")), [])

    def test_atomic_replacement_failure_preserves_previous_index_and_cleans_temp(self):
        before = self.index_path.read_bytes()
        with patch("src.index_store.os.replace", side_effect=OSError("private path")):
            with self.assertRaises(OSError):
                index_store.write_index_atomic(self.index_path, self.payload())
        self.assertEqual(self.index_path.read_bytes(), before)
        self.assertEqual(list(self.index_path.parent.glob("*.tmp")), [])

    def test_fsync_failure_preserves_previous_index_and_cleans_temp(self):
        before = self.index_path.read_bytes()
        with patch("src.index_store.os.fsync", side_effect=OSError("private")):
            with self.assertRaises(OSError):
                index_store.write_index_atomic(self.index_path, self.payload())
        self.assertEqual(self.index_path.read_bytes(), before)
        self.assertEqual(list(self.index_path.parent.glob("*.tmp")), [])

    def test_changed_source_before_publication_prevents_replacement(self):
        before = self.index_path.read_bytes()
        payload = self.payload()
        with patch("src.index_store.source_snapshot", return_value=replace(index_store.source_snapshot(), sha256="0" * 64)):
            with self.assertRaisesRegex(index_store.IndexValidationError, "stale_source"):
                index_store.write_index_atomic(self.index_path, payload)
        self.assertEqual(self.index_path.read_bytes(), before)

    def test_cli_failure_is_nonzero_and_does_not_print_provider_details(self):
        module = self.load("src.ingest")
        with patch.object(module, "ingest", side_effect=RuntimeError("SECRET-PROVIDER-DETAIL")):
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(module.main(), 1)
        self.assertNotIn("SECRET-PROVIDER-DETAIL", output.getvalue())
        self.assertIn("previous index retained", output.getvalue())

    def test_cli_success_summary_is_concise_without_running_ingestion(self):
        module = self.load("src.ingest")
        with patch.object(module, "ingest", return_value=18):
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(module.main(), 0)
        self.assertEqual(output.getvalue(), "Validated and saved document index: 18 chunks.\n")


class RuntimeIndexTests(IndexTestCase):
    def test_retrieval_import_does_not_read_index_or_call_provider(self):
        self.index_path.unlink()
        with patch("src.index_store.load_index", side_effect=AssertionError("Import attempted index I/O")):
            retrieval = self.load("src.retrieval")
        self.assertEqual(retrieval.PORTFOLIO_INDEX, [])
        self.client_factory.assert_not_called()
        self.models.embed_content.assert_not_called()
        self.models.generate_content.assert_not_called()

    def test_api_import_does_not_read_index_or_call_provider(self):
        self.index_path.unlink()
        with patch("src.index_store.load_index", side_effect=AssertionError("Import attempted index I/O")):
            api = self.load("src.api")
        self.assertIsNone(api.app.state.rag_index)
        self.client_factory.assert_not_called()
        self.models.embed_content.assert_not_called()
        self.models.generate_content.assert_not_called()

    def test_startup_loads_index_without_embeddings_and_ready_is_success(self):
        api = self.load("src.api")
        with TestClient(api.app) as client:
            response = client.get("/ready")
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json(), {"status": "ready"})
            self.assertEqual(client.get("/health").json(), {"status": "ok", "service": "AI Portfolio Assistant"})
            self.assertEqual(len(api.app.state.rag_index.portfolio), 18)
            self.client_factory.assert_not_called()
            self.models.embed_content.assert_not_called()
            self.models.generate_content.assert_not_called()
        self.assertIsNone(api.app.state.rag_index)

    def test_missing_index_fails_startup_without_regeneration(self):
        api = self.load("src.api")
        self.index_path.unlink()
        with self.assertRaisesRegex(RuntimeError, "RAG index unavailable") as failure:
            with TestClient(api.app):
                self.fail("Invalid startup must not serve requests")
        self.assertNotIn(str(self.index_path), str(failure.exception))
        self.assertFalse(self.index_path.exists())
        self.assertIsNone(api.app.state.rag_index)
        self.models.embed_content.assert_not_called()

    def test_startup_diagnostic_is_structured_and_excludes_internal_path(self):
        api = self.load("src.api")
        self.index_path.unlink()
        with self.assertLogs("portfolio.api", level="ERROR") as records:
            with self.assertRaises(RuntimeError):
                with TestClient(api.app):
                    self.fail("Missing artifact must fail startup")
        record = json.loads(records.records[0].getMessage())
        self.assertEqual(record, {"event": "rag_index_startup", "status": "failed", "category": "missing_index"})
        self.assertNotIn(str(self.index_path), records.output[0])

    def test_corrupt_and_stale_indexes_fail_startup(self):
        api = self.load("src.api")
        for content in ("{", self.index_path.read_text().replace('"source_sha256": "', '"source_sha256": "stale-')):
            with self.subTest(content_length=len(content)):
                self.index_path.write_text(content)
                with self.assertRaisesRegex(RuntimeError, "RAG index unavailable"):
                    with TestClient(api.app):
                        self.fail("Invalid startup must not serve requests")
                self.assertIsNone(api.app.state.rag_index)
        self.models.embed_content.assert_not_called()

    def test_before_startup_readiness_and_chat_fail_safely(self):
        api = self.load("src.api")
        # Intentionally omit the TestClient lifespan context to test no startup.
        client = TestClient(api.app)
        self.addCleanup(client.close)
        self.assertEqual(client.get("/ready").status_code, 503)
        self.assertEqual(client.get("/ready").json(), {"status": "not_ready"})
        self.assertEqual(client.get("/health").status_code, 200)
        response = client.post("/chat", json={"message": "List Timothy's projects."})
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.json(), {"detail": "The AI assistant could not generate a response."})
        self.models.embed_content.assert_not_called()
        self.models.generate_content.assert_not_called()

    def test_only_focused_chat_creates_query_embedding(self):
        api = self.load("src.api")
        with TestClient(api.app) as client:
            client.get("/health")
            client.get("/ready")
            self.models.embed_content.assert_not_called()
            self.assertEqual(client.post("/chat", json={"message": "Docker?"}).status_code, 200)
            self.models.embed_content.assert_called_once()
            self.assertEqual(self.models.embed_content.call_args.kwargs["config"]["task_type"], "RETRIEVAL_QUERY")

    def test_collection_chat_uses_validated_snapshot_if_disk_source_changes(self):
        api = self.load("src.api")
        with TestClient(api.app) as client:
            with patch.object(knowledge, "PORTFOLIO_PATH", Path(self.temporary) / "missing.md"):
                response = client.post("/chat", json={"message": "List Timothy's projects."})
            self.assertEqual(response.status_code, 200)
        self.models.embed_content.assert_not_called()
        self.assertIn("BundesHost", self.models.generate_content.call_args.kwargs["contents"])

    def test_runtime_ranking_matches_standalone_hybrid_ranking(self):
        retrieval = self.load("src.retrieval")
        runtime = retrieval.load_portfolio_index(self.index_path)
        self.models.embed_content.assert_not_called()
        retrieval.initialize_index(self.index_path)
        for question in ("Docker", "languages", "MLflow", "independently"):
            with self.subTest(question=question):
                self.assertEqual(retrieval.retrieve_relevant_chunks(question),
                                 retrieval.retrieve_relevant_chunks(question, index=runtime))

    def test_relative_index_path_resolves_from_repository_not_cwd(self):
        with patch.dict(os.environ, {"RAG_INDEX_PATH": "artifacts/custom.json"}):
            self.assertEqual(Settings.from_env().index_path, REPOSITORY_ROOT / "artifacts/custom.json")
        self.assertEqual(Settings.from_env().index_path, self.index_path)

    def test_empty_index_path_is_rejected_without_echoing_values(self):
        with patch.dict(os.environ, {"RAG_INDEX_PATH": " "}):
            with self.assertRaisesRegex(ValueError, "RAG_INDEX_PATH must not be empty"):
                Settings.from_env()
