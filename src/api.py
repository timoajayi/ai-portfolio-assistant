import os

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from google import genai
from pydantic import BaseModel, ConfigDict, Field, field_validator

from src.chunking import get_project_overview_chunks
from src.query_router import is_project_collection_query
from src.retrieval import retrieve_relevant_chunks
from src.config import Settings
from src.provider import ERROR_DETAIL, classify_failure, http_options, response_text
from src.reliability import ChatControls, ChatProtectionMiddleware


# Load environment variables from .env
load_dotenv()

api_key = os.getenv("GOOGLE_API_KEY")

frontend_origins = [
    origin.strip()
    for origin in os.getenv(
        "FRONTEND_ORIGINS",
        "http://localhost:3000,http://127.0.0.1:3000",
    ).split(",")
    if origin.strip()
]

if not api_key:
    raise ValueError("GOOGLE_API_KEY was not found in the .env file.")


# Create Gemini client
settings = Settings.from_env()
client = genai.Client(
    api_key=api_key, http_options=http_options(settings.generation_timeout_ms)
)


# Create FastAPI application
app = FastAPI(
    title="AI Portfolio Assistant API",
    version="0.1.0",
)

app.state.chat_controls = ChatControls(settings)
app.add_middleware(ChatProtectionMiddleware, controls=app.state.chat_controls)


# Allow the portfolio frontend to communicate with the API
app.add_middleware(
    CORSMiddleware,
    allow_origins=frontend_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["X-Request-ID", "Retry-After"],
)


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
def health_check():
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
        # Broad project questions need coverage across the portfolio.
        if is_project_collection_query(request.message):
            context_chunks = get_project_overview_chunks()

        # Focused questions use hybrid semantic + BM25 retrieval.
        else:
            retrieved_chunks = retrieve_relevant_chunks(
                request.message,
                top_k=3,
            )

            context_chunks = [
                chunk
                for chunk, _score in retrieved_chunks
            ]

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

        response = client.models.generate_content(
            model="gemini-3.8-flash",
            contents=prompt,
            config={"max_output_tokens": settings.max_output_tokens},
        )

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
