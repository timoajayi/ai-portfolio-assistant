import os
from threading import Lock

from dotenv import load_dotenv
from google import genai

from src.chunking import chunk_portfolio_by_section
from src.config import Settings
from src.provider import http_options
from src.index_store import EMBEDDING_MODEL, EMBEDDING_DIMENSIONS
from src.diagnostics import phase


load_dotenv()

api_key = os.getenv("GOOGLE_API_KEY")

settings = Settings.from_env()
client = None
_client_lock = Lock()


def get_client():
    global client
    with phase("embedding_client_initialization"), _client_lock:
        if client is None:
            if not api_key:
                raise ValueError("GOOGLE_API_KEY is required for embedding requests.")
            client = genai.Client(
                api_key=api_key, http_options=http_options(
                    settings.embedding_timeout_ms, network_policy=settings.gemini_network_policy
                )
            )
        return client


def close_client():
    global client
    with _client_lock:
        if client is not None:
            try:
                client.close()
            finally:
                client = None


def create_embedding(
    text: str,
    task_type: str = "RETRIEVAL_DOCUMENT",
) -> list[float]:
    with phase("embedding"):
        response = get_client().models.embed_content(
            model=EMBEDDING_MODEL,
            contents=text,
            config={
                "task_type": task_type,
                "output_dimensionality": EMBEDDING_DIMENSIONS,
            },
        )

    return response.embeddings[0].values


if __name__ == "__main__":
    chunks = chunk_portfolio_by_section()

    first_chunk = chunks[0]

    embedding = create_embedding(first_chunk)

    print("TEXT:")
    print(first_chunk)

    print("\nEMBEDDING PREVIEW:")
    print(embedding[:10])

    print(f"\nEMBEDDING DIMENSIONS: {len(embedding)}")
