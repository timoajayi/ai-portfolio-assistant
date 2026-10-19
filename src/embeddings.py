import os

from dotenv import load_dotenv
from google import genai

from src.chunking import chunk_portfolio_by_section


load_dotenv()

api_key = os.getenv("GOOGLE_API_KEY")

if not api_key:
    raise ValueError("GOOGLE_API_KEY was not found in the .env file.")

client = genai.Client(api_key=api_key)


def create_embedding(
    text: str,
    task_type: str = "RETRIEVAL_DOCUMENT",
) -> list[float]:
    response = client.models.embed_content(
        model="gemini-embedding-001",
        contents=text,
        config={
            "task_type": task_type,
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