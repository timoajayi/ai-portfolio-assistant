import os

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from google import genai
from pydantic import BaseModel

from src.retrieval import retrieve_relevant_chunks


# Load environment variables from .env
load_dotenv()

api_key = os.getenv("GOOGLE_API_KEY")

if not api_key:
    raise ValueError("GOOGLE_API_KEY was not found in the .env file.")


# Create Gemini client
client = genai.Client(api_key=api_key)


# Create FastAPI application
app = FastAPI(
    title="AI Portfolio Assistant API",
    version="0.1.0",
)


# Define the structure of a chat request
class ChatRequest(BaseModel):
    message: str


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
def chat(request: ChatRequest) -> ChatResponse:
    try:
        retrieved_chunks = retrieve_relevant_chunks(
            request.message,
            top_k=3,
        )

        retrieved_context = "\n\n---\n\n".join(
            chunk
            for chunk, _score in retrieved_chunks
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
        )

        return ChatResponse(
            answer=response.text
        )

    except HTTPException:
        raise

    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail="The AI assistant could not generate a response.",
        ) from error
