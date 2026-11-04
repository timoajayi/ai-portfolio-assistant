# syntax=docker/dockerfile:1.7
# Version tags plus immutable multi-platform registry digests.
FROM ghcr.io/astral-sh/uv:0.10.2@sha256:94a23af2d50e97b87b522d3cea24aaf8a1faedec1344c952767434f69585cbf9 AS uv
FROM python:3.11.18-slim-bookworm@sha256:94a8fee35252d06ab75856f15f12c7bae67b10e8a6da93c7fded82b2610926cd AS python-base

FROM python-base AS dependencies
COPY --from=uv /uv /usr/local/bin/uv
WORKDIR /app
ENV UV_PYTHON_DOWNLOADS=never UV_LINK_MODE=copy UV_NO_PROGRESS=1
COPY pyproject.toml uv.lock ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --no-install-project --no-editable --no-build \
    --python /usr/local/bin/python

FROM python-base AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/app/.venv/bin:$PATH" \
    PORT=8080 \
    RAG_INDEX_PATH=/app/data/index/portfolio.json
WORKDIR /app
RUN groupadd --gid 10001 app && \
    useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin app
COPY --from=dependencies /app/.venv /app/.venv
COPY --chmod=0444 pyproject.toml uv.lock release.sha256 ./
# Explicit runtime modules; ingestion, evaluators, and the interactive CLI are absent.
COPY --chmod=0444 src/__init__.py src/api.py src/chunking.py src/config.py \
    src/diagnostics.py src/embeddings.py src/index_store.py src/knowledge.py \
    src/provider.py src/query_expansion.py src/query_router.py src/reliability.py \
    src/retrieval.py ./src/
COPY --chmod=0444 data/portfolio.md ./data/portfolio.md
COPY --chmod=0444 data/index/portfolio.json ./data/index/portfolio.json
# Validate release bytes and source/index compatibility without a network or API key.
RUN --network=none chmod 0555 /app/src /app/data /app/data/index && \
    sha256sum --check release.sha256 && \
    /app/.venv/bin/python -B -c "from pathlib import Path; from src.index_store import load_index; index = load_index(Path('data/index/portfolio.json')); print('Validated packaged index:', len(index.chunks), 'chunks')"
USER 10001:10001
EXPOSE 8080
STOPSIGNAL SIGTERM
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD ["/app/.venv/bin/python", "-B", "-c", "import http.client, os; c = http.client.HTTPConnection('127.0.0.1', int(os.environ.get('PORT', '8080')), timeout=2); c.request('GET', '/ready'); r = c.getresponse(); status = r.status; r.read(); c.close(); raise SystemExit(0 if status == 200 else 1)"]
CMD ["/bin/sh", "-c", "exec uvicorn src.api:app --host 0.0.0.0 --port \"${PORT:-8080}\" --workers 1 --no-proxy-headers"]
