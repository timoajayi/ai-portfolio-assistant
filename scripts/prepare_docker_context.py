"""Snapshot an explicit release allowlist; never import Gemini or run ingestion."""

import argparse
import hashlib
from pathlib import Path
import shutil
import sys


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.index_store import load_index


RUNTIME_FILES = (
    "src/__init__.py", "src/api.py", "src/chunking.py", "src/config.py",
    "src/diagnostics.py", "src/embeddings.py", "src/index_store.py",
    "src/knowledge.py", "src/provider.py", "src/query_expansion.py",
    "src/query_router.py", "src/reliability.py", "src/retrieval.py",
)
IMAGE_FILES = (
    "pyproject.toml", "uv.lock", *RUNTIME_FILES,
    "data/portfolio.md", "data/index/portfolio.json",
)
CONTEXT_FILES = ("Dockerfile", ".dockerignore", *IMAGE_FILES)


def prepare_context(destination: Path, *, root: Path = ROOT) -> int:
    root = root.resolve()
    destination = destination.resolve()
    if destination == root or root in destination.parents:
        raise ValueError("Release context must be outside the repository.")
    if destination.exists():
        raise ValueError("Release context destination must not exist.")

    snapshot = {}
    for name in CONTEXT_FILES:
        path = root / name
        # Never follow allowlisted files or directories into unrelated content.
        if any(parent.is_symlink() for parent in (path, *path.parents) if parent != root and root in parent.parents):
            raise ValueError("Release inputs must not be symbolic links.")
        snapshot[name] = path.read_bytes()
    document = load_index(root / "data/index/portfolio.json")
    if (hashlib.sha256(snapshot["data/portfolio.md"]).hexdigest() != document.source_sha256
            or snapshot["data/index/portfolio.json"] != (root / "data/index/portfolio.json").read_bytes()):
        raise ValueError("Release knowledge/index snapshot changed or does not match.")

    destination.mkdir(mode=0o700)
    try:
        for name, content in snapshot.items():
            target = destination / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)
            target.chmod(0o444)
        manifest = "".join(
            f"{hashlib.sha256(snapshot[name]).hexdigest()}  {name}\n"
            for name in sorted(IMAGE_FILES)
        )
        (destination / "release.sha256").write_text(manifest, encoding="utf-8")
        (destination / "release.sha256").chmod(0o444)
    except Exception:
        # This directory was created by this invocation, never an existing one.
        shutil.rmtree(destination)
        raise
    return len(document.chunks)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination", type=Path, help="New directory outside the repository")
    args = parser.parse_args()
    try:
        chunks = prepare_context(args.destination)
    except Exception:
        print("Release preparation failed. Check destination, required files, and matching validated index.", file=sys.stderr)
        return 1
    print(f"Prepared Docker context: {chunks} validated chunks; {len(CONTEXT_FILES) + 1} allowlisted files.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
