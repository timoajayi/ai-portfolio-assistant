"""Explicit ingestion. Running this command intentionally calls the embedding API."""

from dotenv import load_dotenv

from src.config import Settings
from src.index_store import make_payload, source_snapshot, write_index_atomic


def ingest(path=None) -> int:
    source = source_snapshot()
    # Keep provider/credential setup inside main's sanitized failure boundary.
    from src.retrieval import build_portfolio_index
    from src.embeddings import close_client

    try:
        entries = build_portfolio_index(list(source.chunks))
    finally:
        close_client()
    payload = make_payload(source, [vector for _, vector in entries])
    write_index_atomic(path if path is not None else Settings.from_env().index_path, payload)
    return len(entries)


def main() -> int:
    load_dotenv()
    try:
        count = ingest()
    except Exception:
        # Provider exceptions can contain request details. Never print them.
        print("Index ingestion failed. Check source, configuration, credentials, and provider access; previous index retained.")
        return 1
    print(f"Validated and saved document index: {count} chunks.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
