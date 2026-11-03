# Offline regression tests

Run from the repository root using the existing environment:

```sh
.venv/bin/python -m unittest discover -s tests -v
```

With that environment activated, the equivalent command is:

```sh
python -m unittest discover -s tests -v
```

No installation or API key is required beyond the project's already installed
dependencies. The test runner is Python's built-in `unittest`; API tests use
the existing FastAPI/Starlette TestClient and httpx dependencies.

## Phase 1 baseline

Against unchanged production code, 63 tests run: **48 pass, 12 fail assertions,
and 3 error on known production exceptions**. There are no skipped or
`expectedFailure` tests. Discovery deliberately exits nonzero until the defects
are fixed. Do not weaken these assertions to make the baseline green.

Classes named `Known…RegressionTests` assert intended behavior. All other
classes cover currently passing behavior, evaluator exit codes, or test-harness
isolation. Subtests exercise additional inputs without increasing the reported
test-method count.

| Regression group | Tests | Intended behavior |
| --- | ---: | --- |
| Routing | 5 | MLflow/Docker filters use focused retrieval; “Show me all projects”, curly apostrophes, and “Summarize his portfolio projects” use collection retrieval |
| Expansion | 1 | “What is storage?” remains unchanged |
| Chunking | 3 | Short BundesHost sections do not crash; short churn sections produce no empty evidence; new projects appear in collection coverage |
| Retrieval | 4 | Empty BM25/retrieval corpora are handled; mismatched dimensions and negative top_k raise ValueError |
| API response validation | 2 | Empty and whitespace-only model text produce the existing generic error rather than a successful blank answer |

The three production exceptions are `IndexError` for shortened BundesHost,
`ZeroDivisionError` for empty BM25, and `ValueError` from `max()` for empty
retrieval. These are regression errors, not test-harness or dependency failures.

The technology-routing assertion targets the current two-route design: project
overviews omit technology evidence. A future architecture may add filtered
collection retrieval, in which case update this decision with evidence-coverage
tests rather than restoring the existing unfiltered route.

## Offline guarantees

`offline.py` provides a per-test `OfflineTestCase` fixture that:

- Blocks socket connections, DNS, and synchronous/asynchronous httpx network
  transports. TestClient still uses its in-process ASGI transport.
- Patches `google.genai.Client` **before** importing embeddings, retrieval,
  API, or evaluation modules. Import-time embeddings use synthetic vectors.
- Supplies a clearly fake API key and patches dotenv loading, so the local
  `.env` is never read. No secret values are logged.
- Restores patches, imported module cache entries, and package attributes after
  each test, including failures.

`test_offline.py` checks the network guards and that both production clients
are mocked. Intentional guard probes raise before making a connection.

## Evaluation scripts

Both evaluation functions now return 0 when every case passes and 1 when any
case fails. Their command-line entry points propagate that status through
`SystemExit`. Tests cover all-pass, all-fail, and one-failure results, and
execute the actual command-line blocks with `runpy` under the offline guards.

The original retrieval evaluator remains a **live-provider tool** when invoked
directly. Do not run `python -m src.evaluate_retrieval` for offline validation.
Its mocked tests check evaluator bookkeeping, not real retrieval accuracy.

## Limits and deferred checks

All requested unit and mocked API tests can run now; none require an
architectural change to execute. The regression tests will need production
fixes in a later phase to pass.

Synthetic vectors establish arithmetic, BM25, ordering, and top_k behavior;
they do not establish semantic retrieval quality, real Recall@3, grounding,
provider availability, safety-filter behavior, or production latency/cost.
Blocked responses are modeled using absent text and safety metadata rather
than invoking Google's safety systems.

Timeout tests inject a timeout exception and verify the existing error
contract; they do not establish that a real timeout/deadline is configured.
Importing a usable app without index-building side effects remains deferred
to the architecture phase and is currently accommodated with pre-import mocks.

The installed Starlette TestClient emits an httpx deprecation warning. Tests
run successfully with the current dependencies; no dependency was installed or
upgraded to silence it.

Next: fix the routing and word-boundary expansion regressions first, then
chunking/index input validation and blank provider responses, keeping the same
offline suite and API schema throughout.
