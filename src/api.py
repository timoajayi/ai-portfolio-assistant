import os
import json
from contextlib import asynccontextmanager
from threading import Lock

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from google import genai
from pydantic import BaseModel, ConfigDict, Field, field_validator

from src.chunking import get_project_overview_chunks
from src.query_router import is_project_collection_query
from src.retrieval import retrieve_relevant_chunks, load_portfolio_index
from src.index_store import IndexValidationError
from src.embeddings import close_client as close_embedding_client
from src.diagnostics import phase
from src.config import Settings, configured_frontend_origins
from src.provider import ERROR_DETAIL, classify_failure, generation_metadata, http_options, response_text
from src.reliability import ChatControls, ChatProtectionMiddleware, logger


# Load environment variables from .env
load_dotenv()

api_key = os.getenv("GOOGLE_API_KEY")

if not api_key:
    raise ValueError("GOOGLE_API_KEY was not found in the .env file.")


# Create Gemini client
settings = Settings.from_env()
frontend_origins = configured_frontend_origins(settings.staging_auth_enabled)
client = None
_client_lock = Lock()


def get_generation_client():
    global client
    with phase("generation_client_initialization"), _client_lock:
        if client is None:
            client = genai.Client(
                api_key=api_key, http_options=http_options(
                    settings.generation_timeout_ms, network_policy=settings.gemini_network_policy
                )
            )
        return client


@asynccontextmanager
async def lifespan(app):
    app.state.rag_index = None
    try:
        app.state.rag_index = load_portfolio_index(settings.index_path)
    except IndexValidationError as error:
        logger.error(json.dumps({"event": "rag_index_startup", "status": "failed", "category": error.code}))
        raise RuntimeError(
            "RAG index unavailable or invalid; run python -m src.ingest before startup."
        ) from None
    try:
        yield
    finally:
        app.state.rag_index = None
        global client
        failed_clients = []
        try:
            with _client_lock:
                if client is not None:
                    try:
                        client.close()
                    finally:
                        client = None
        except Exception:
            failed_clients.append("generation")
        try:
            close_embedding_client()
        except Exception:
            failed_clients.append("embedding")
        if failed_clients:
            # Never propagate provider exception messages or exception chains.
            logger.error(json.dumps({
                "event": "provider_shutdown", "status": "failed",
                "failed_clients": failed_clients,
            }))
            raise RuntimeError("Provider client shutdown failed.") from None


# Create FastAPI application; no index or document embedding work on import.
app = FastAPI(
    title="AI Portfolio Assistant API",
    version="0.1.0",
    lifespan=lifespan,
    docs_url=None if settings.staging_auth_enabled else "/docs",
    redoc_url=None if settings.staging_auth_enabled else "/redoc",
    openapi_url=None if settings.staging_auth_enabled else "/openapi.json",
)

app.state.rag_index = None
app.state.chat_controls = ChatControls(settings)
app.add_middleware(ChatProtectionMiddleware, controls=app.state.chat_controls)


# Allow the portfolio frontend to communicate with the API
app.add_middleware(
    CORSMiddleware,
    allow_origins=frontend_origins,
    allow_credentials=not settings.staging_auth_enabled,
    allow_methods=["GET", "POST"] if settings.staging_auth_enabled else ["*"],
    allow_headers=["Authorization", "Content-Type"] if settings.staging_auth_enabled else ["*"],
    expose_headers=["X-Request-ID", "Retry-After"],
)


@app.exception_handler(RequestValidationError)
async def safe_validation_error(http_request: Request, error: RequestValidationError):
    # Never serialize Pydantic input/ctx/msg or attacker-selected field names.
    messages = {
        "missing": "Required field is missing.",
        "extra_forbidden": "Unexpected fields are not allowed.",
        "string_type": "Message must be a string.",
        "string_too_short": "Message must not be empty.",
        "string_too_long": "Message must contain at most 1000 characters.",
        "value_error": "Message must not be blank.",
        "json_invalid": "Invalid JSON body.",
    }
    details = []
    for item in error.errors()[:20]:
        kind = item.get("type")
        location = item.get("loc", ())
        details.append({
            "loc": ["body", "message"] if location[:2] == ("body", "message") else ["body"],
            "msg": messages.get(kind, "Invalid request body."),
            "type": kind if kind in messages else "request_validation_error",
        })
    return JSONResponse({"detail": details}, status_code=422)


# Define the structure of a chat request
class ChatRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    message: str = Field(
        ...,
        min_length=1,
        max_length=1000,
    )

    @field_validator("message")
    @classmethod
    def validate_message(cls, value: str) -> str:
        value = value.strip()

        if not value:
            raise ValueError("Message cannot be empty.")

        return value


# Define the structure of a chat response
class ChatResponse(BaseModel):
    answer: str


@app.get("/health")
async def health_check():
    return {
        "status": "ok",
        "service": "AI Portfolio Assistant",
    }


@app.post("/chat", response_model=ChatResponse)
def chat(request: ChatRequest, http_request: Request) -> ChatResponse:
    lease = http_request.state.chat_capacity
    if not lease.start():
        raise HTTPException(status_code=503, detail=ERROR_DETAIL)
    try:
        http_request.state.chat_diagnostics.worker_started()
        runtime_index = http_request.app.state.rag_index
        if runtime_index is None:
            raise HTTPException(status_code=503, detail=ERROR_DETAIL)

        # Broad project questions need coverage across the portfolio.
        with phase("query_routing"):
            collection = is_project_collection_query(request.message)
        with phase("hybrid_retrieval"):
            if collection:
                context_chunks = get_project_overview_chunks(runtime_index.document.source_text)
            else:
                retrieved_chunks = retrieve_relevant_chunks(
                    request.message,
                    top_k=3,
                    index=runtime_index,
                )
                context_chunks = [chunk for chunk, _score in retrieved_chunks]

        retrieved_context = "\n\n---\n\n".join(
            context_chunks
        )

        prompt = f"""
You are the AI portfolio assistant for Timothy Ajayi.

Answer questions about Timothy using only the retrieved portfolio context below.

Rules:
- Do not invent projects, experience, skills, employers, qualifications, or results.
- Clearly distinguish completed projects from projects that are still in development.
- If the answer is not supported by the retrieved context, say that the information is not currently available in Timothy's portfolio.
- Keep answers concise and useful for recruiters, hiring managers, and technical visitors.

Retrieved portfolio context:

{retrieved_context}

Visitor question:

{request.message}
"""

        with phase("generation"):
            response = get_generation_client().models.generate_content(
                model="gemini-3.8-flash",
                contents=prompt,
                config={
                    "automatic_continuation": False,
                    "max_output_tokens": settings.max_output_tokens,
                    "thinking_config": {"thinking_level": settings.thinking_level},
                },
            )

        with phase("response_preparation"):
            http_request.state.chat_diagnostics.record_generation(generation_metadata(response))
            return ChatResponse(answer=response_text(response))

    except HTTPException:
        raise

    except Exception as error:
        status, category, headers = classify_failure(error)
        http_request.state.provider_failure = category
        raise HTTPException(
            status_code=status,
            detail=ERROR_DETAIL,
            headers=headers,
        ) from error
    finally:
        lease.release()


@app.get("/ready")
async def readiness(http_request: Request):
    ready = http_request.app.state.rag_index is not None
    return JSONResponse({"status": "ready" if ready else "not_ready"}, status_code=200 if ready else 503)
