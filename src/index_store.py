"""Strict, versioned JSON artifacts; this module never imports a provider client."""

from dataclasses import dataclass
import hashlib
import json
import math
import os
from pathlib import Path
import tempfile

from src import knowledge
from src.chunking import chunk_portfolio_by_section, get_project_overview_chunks


SCHEMA_VERSION = 1
CHUNKING_VERSION = 1
EMBEDDING_MODEL = "gemini-embedding-001"
EMBEDDING_DIMENSIONS = 3072
MAX_INDEX_BYTES = 16 * 1024 * 1024


class IndexValidationError(ValueError):
    """A stable diagnostic code, without source text, paths, or provider details."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class SourceSnapshot:
    sha256: str
    text: str
    chunks: tuple[str, ...]
    overviews: tuple[str, ...]


@dataclass(frozen=True)
class IndexedChunk:
    id: str
    heading: str
    text: str
    embedding: tuple[float, ...]


@dataclass(frozen=True)
class DocumentIndex:
    source_sha256: str
    source_text: str
    chunks: tuple[IndexedChunk, ...]
    overviews: tuple[str, ...]


def source_snapshot() -> SourceSnapshot:
    try:
        content = knowledge.PORTFOLIO_PATH.read_bytes()
        # Match Path.read_text's universal newline behavior while hashing bytes.
        text = content.decode("utf-8").replace("\r\n", "\n").replace("\r", "\n")
        chunks = tuple(chunk_portfolio_by_section(text))
        overviews = tuple(get_project_overview_chunks(text))
    except (OSError, UnicodeError, IndexError):
        raise IndexValidationError("source_unavailable") from None
    if not chunks:
        raise IndexValidationError("empty_source")
    if any(not chunk.partition("\n")[2].strip() for chunk in chunks):
        raise IndexValidationError("empty_chunk")
    if len({chunk_id(chunk) for chunk in chunks}) != len(chunks):
        raise IndexValidationError("duplicate_or_invalid_chunk_id")
    return SourceSnapshot(hashlib.sha256(content).hexdigest(), text, chunks, overviews)


def chunk_id(text: str) -> str:
    return hashlib.sha256(f"chunk-v{CHUNKING_VERSION}\0{text}".encode("utf-8")).hexdigest()


def make_payload(source: SourceSnapshot, vectors: list[list[float]]) -> dict:
    if len(vectors) != len(source.chunks):
        raise IndexValidationError("chunk_count")
    return {
        "schema_version": SCHEMA_VERSION,
        "embedding_model": EMBEDDING_MODEL,
        "embedding_dimensions": EMBEDDING_DIMENSIONS,
        "source_sha256": source.sha256,
        "chunking_version": CHUNKING_VERSION,
        "chunks": [
            {"id": chunk_id(text), "heading": text.split("\n", 1)[0],
             "text": text, "embedding": vector}
            for text, vector in zip(source.chunks, vectors)
        ],
    }


def validate_payload(payload, source: SourceSnapshot | None = None) -> DocumentIndex:
    source = source if source is not None else source_snapshot()
    keys = {"schema_version", "embedding_model", "embedding_dimensions",
            "source_sha256", "chunking_version", "chunks"}
    if not isinstance(payload, dict) or set(payload) != keys:
        raise IndexValidationError("schema")
    for key, expected in (("schema_version", SCHEMA_VERSION), ("chunking_version", CHUNKING_VERSION)):
        if type(payload[key]) is not int or payload[key] != expected:
            raise IndexValidationError(key)
    if payload["embedding_model"] != EMBEDDING_MODEL:
        raise IndexValidationError("embedding_model")
    if type(payload["embedding_dimensions"]) is not int or payload["embedding_dimensions"] != EMBEDDING_DIMENSIONS:
        raise IndexValidationError("embedding_dimensions")
    if payload["source_sha256"] != source.sha256:
        raise IndexValidationError("stale_source")
    records = payload["chunks"]
    if not isinstance(records, list) or len(records) != len(source.chunks) or not records:
        raise IndexValidationError("chunk_count")
    seen = set()
    validated = []
    for record, expected_text in zip(records, source.chunks):
        if not isinstance(record, dict) or set(record) != {"id", "heading", "text", "embedding"}:
            raise IndexValidationError("chunk_schema")
        text = record["text"]
        if not isinstance(text, str) or not text.strip() or not text.partition("\n")[2].strip():
            raise IndexValidationError("empty_chunk")
        identifier = record["id"]
        if not isinstance(identifier, str) or identifier in seen:
            raise IndexValidationError("duplicate_or_invalid_chunk_id")
        seen.add(identifier)
        if (text != expected_text or identifier != chunk_id(expected_text)
                or record["heading"] != expected_text.split("\n", 1)[0]):
            raise IndexValidationError("chunk_mismatch")
        vector = record["embedding"]
        if not isinstance(vector, list) or len(vector) != EMBEDDING_DIMENSIONS:
            raise IndexValidationError("vector_dimensions")
        try:
            valid = all(type(value) in (int, float) and math.isfinite(value) for value in vector)
        except OverflowError:
            valid = False
        if not valid or not any(vector):
            raise IndexValidationError("invalid_vector")
        validated.append(IndexedChunk(identifier, record["heading"], text, tuple(vector)))
    return DocumentIndex(source.sha256, source.text, tuple(validated), source.overviews)


def _reject_constant(value):
    raise IndexValidationError("nonfinite_json")


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise IndexValidationError("duplicate_json_key")
        result[key] = value
    return result


def load_index(path: Path) -> DocumentIndex:
    try:
        with Path(path).open("rb") as handle:
            raw = handle.read(MAX_INDEX_BYTES + 1)
        if len(raw) > MAX_INDEX_BYTES:
            raise IndexValidationError("index_too_large")
        payload = json.loads(raw, parse_constant=_reject_constant, object_pairs_hook=_unique_object)
    except FileNotFoundError:
        raise IndexValidationError("missing_index") from None
    except IndexValidationError:
        raise
    except (OSError, UnicodeError, ValueError, RecursionError):
        raise IndexValidationError("invalid_json_or_unreadable_index") from None
    return validate_payload(payload)


def write_index_atomic(path: Path, payload: dict) -> None:
    # Validate against current knowledge before touching an existing artifact.
    validate_payload(payload)
    encoded = json.dumps(payload, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode("utf-8")
    if len(encoded) > MAX_INDEX_BYTES:
        raise IndexValidationError("index_too_large")
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="wb", dir=path.parent,
                                         prefix=f".{path.name}.", suffix=".tmp", delete=False) as handle:
            temporary = Path(handle.name)
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
