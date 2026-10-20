# AI Portfolio Assistant

A retrieval-augmented AI assistant that answers questions about my projects, technical skills, engineering experience, and current work using information grounded in my portfolio knowledge base.

The project combines **hybrid retrieval, query routing, Google Gemini, and FastAPI** to provide concise, portfolio-specific answers while reducing unsupported responses.

It is designed to power the conversational AI experience integrated into my AI Engineer portfolio website.

---

## Overview

A traditional portfolio requires visitors to manually browse project pages, skills, and experience sections.

The AI Portfolio Assistant provides a conversational interface instead. A recruiter, hiring manager, or technical visitor can ask questions such as:

- What AI projects has Timothy built?
- Has Timothy worked with RAG?
- What experience does Timothy have with Docker?
- What did Timothy contribute to the BundesHost project?
- What is Timothy currently working on?

Rather than relying only on the language model's general knowledge, the assistant retrieves relevant information from a dedicated portfolio knowledge base and uses that context to generate the response.

---

## Key Features

- Portfolio-specific Retrieval-Augmented Generation (RAG)
- Google Gemini embeddings and response generation
- Hybrid semantic and BM25 lexical retrieval
- Deterministic query expansion
- Intent-aware routing for broad project queries
- Structured portfolio knowledge base
- Grounded response generation
- FastAPI REST API
- Input validation and CORS configuration
- Retrieval and query-routing evaluation suites
- Integration with a Next.js portfolio frontend

---

## Architecture

```text
Portfolio Visitor
       |
       v
Next.js Portfolio
       |
       | POST /chat
       v
FastAPI Backend
       |
       v
Query Router
       |
       +-------------------------------+
       |                               |
       | Focused Question              | Project Collection Question
       v                               v
Hybrid Retrieval                Project Overview Retrieval
       |                               |
       | Semantic Search               | One overview per project
       | + BM25                        |
       | + Query Expansion             |
       +---------------+---------------+
                       |
                       v
               Retrieved Context
                       |
                       v
                 Google Gemini
                       |
                       v
                Grounded Response
                       |
                       v
                Portfolio Visitor
```

The system uses two retrieval paths.

For focused questions, such as:

> Has Timothy used Docker?

the assistant performs hybrid semantic and lexical retrieval to identify the most relevant portfolio chunks.

For collection-style questions, such as:

> What AI projects has Timothy worked on?

the query router switches to project-overview retrieval so that the response receives coverage across the complete project portfolio rather than only the most semantically similar chunks.

---

## Retrieval Pipeline

### 1. Knowledge Base

Portfolio information is stored in:

```text
data/portfolio.md
```

The knowledge base contains structured information about:

- professional profile
- technical skills
- AI and machine-learning projects
- project contributions
- professional background
- current technical focus
- languages

### 2. Chunking

`src/chunking.py` converts the portfolio knowledge base into retrieval chunks.

Larger projects are separated into focused sections such as overview, contributions, infrastructure, and application details.

The current knowledge base produces **18 retrieval chunks**.

### 3. Semantic Retrieval

`src/embeddings.py` uses Google's embedding model to create vector representations of portfolio chunks and visitor questions.

The current embedding model is:

```text
gemini-embedding-001
```

Document chunks and user queries use their corresponding retrieval task types.

### 4. BM25 Lexical Retrieval

Semantic similarity is combined with BM25 lexical retrieval.

This helps the system retrieve information containing important technical terms such as:

- MLflow
- Docker
- RAG
- FastAPI
- project names

The hybrid retrieval score currently combines:

```text
85% semantic similarity
15% normalized lexical relevance
```

### 5. Query Expansion

`src/query_expansion.py` provides deterministic expansion for selected technical terms and phrases.

Examples include mappings between:

```text
RAG -> retrieval-augmented generation
experiment tracking -> MLflow / model tracking
independently -> solo project / individual project
```

This improves retrieval without requiring an additional language-model request.

### 6. Query Routing

Not every question should use the same retrieval strategy.

`src/query_router.py` identifies broad questions asking about the project portfolio as a collection.

Focused questions use:

```text
Hybrid semantic + BM25 retrieval
        |
        v
Top 3 relevant chunks
```

Broad project questions use:

```text
Project collection route
        |
        v
One representative overview per project
```

This prevents broad questions from returning only the projects that happen to have the highest semantic similarity.

---

## Grounded Generation

After retrieval, the selected portfolio context is provided to Google Gemini.

The generation prompt instructs the model to:

- answer using only retrieved portfolio information
- avoid inventing projects, skills, employers, qualifications, or results
- distinguish completed projects from projects still in development
- state when requested information is unavailable
- keep answers concise and useful for recruiters and technical visitors

This makes retrieval the source of portfolio facts while the language model handles natural-language response generation.

---

## API

The assistant is exposed through a FastAPI backend.

### Health Check

```http
GET /health
```

Example response:

```json
{
  "status": "ok",
  "service": "AI Portfolio Assistant"
}
```

### Chat

```http
POST /chat
```

Example request:

```json
{
  "message": "Has Timothy used Docker?"
}
```

Example response structure:

```json
{
  "answer": "..."
}
```

Messages are validated before processing and are limited to 1,000 characters.

---

## Evaluation

The project includes dedicated evaluation scripts for both focused retrieval and query routing.

### Retrieval Evaluation

Run:

```bash
uv run python -m src.evaluate_retrieval
```

Current result:

```text
Passed: 8/8
Recall@3: 100.00%
```

This means the expected information appears within the top three retrieved chunks for all eight questions in the **current evaluation suite**.

It should not be interpreted as a claim that the retriever is universally 100% accurate.

### Query Router Evaluation

Run:

```bash
uv run python -m src.evaluate_query_router
```

Current result:

```text
Passed: 8/8
Accuracy: 100.00%
```

The current eight-test suite covers both broad project-collection questions and focused technical/project questions.

---

## Project Structure

```text
ai-portfolio-assistant/
|
├── data/
│   └── portfolio.md
|
├── src/
│   ├── __init__.py
│   ├── api.py
│   ├── chunking.py
│   ├── embeddings.py
│   ├── evaluate_query_router.py
│   ├── evaluate_retrieval.py
│   ├── knowledge.py
│   ├── main.py
│   ├── query_expansion.py
│   ├── query_router.py
│   └── retrieval.py
|
├── .gitignore
├── pyproject.toml
├── uv.lock
└── README.md
```

---

## Tech Stack

**Language**
- Python

**AI / Retrieval**
- Google Gemini
- Gemini Embeddings
- Retrieval-Augmented Generation (RAG)
- BM25
- Cosine Similarity
- Query Expansion
- Query Routing

**Backend**
- FastAPI
- Uvicorn
- Pydantic

**Development**
- uv
- python-dotenv
- Git
- GitHub

**Frontend Integration**
- Next.js
- React
- TypeScript

---

## Local Development

### 1. Clone the repository

```bash
git clone git@github.com:timoajayi/ai-portfolio-assistant.git
cd ai-portfolio-assistant
```

### 2. Install dependencies

Using `uv`:

```bash
uv sync
```

### 3. Configure environment variables

Create a `.env` file in the project root.

```env
GOOGLE_API_KEY=your_google_api_key
FRONTEND_ORIGINS=http://localhost:3000,http://127.0.0.1:3000
```

Do not commit `.env` or API keys to Git.

### 4. Start the API

```bash
uv run uvicorn src.api:app --reload
```

The API will be available at:

```text
http://127.0.0.1:8000
```

FastAPI documentation:

```text
http://127.0.0.1:8000/docs
```

Health check:

```text
http://127.0.0.1:8000/health
```

---

## Frontend Integration

The assistant is integrated into a separate Next.js AI Engineer portfolio.

The frontend sends questions to:

```http
POST /chat
```

The portfolio keeps the backend URL in:

```env
NEXT_PUBLIC_AI_ASSISTANT_API_URL=http://127.0.0.1:8000
```

The Google API key remains exclusively on the backend and is never exposed through the browser.

---

## Current Status

The core system is functional locally.

Completed:

- portfolio knowledge base
- document chunking
- Gemini embeddings
- semantic retrieval
- BM25 lexical retrieval
- hybrid ranking
- deterministic query expansion
- project collection query routing
- grounded Gemini response generation
- FastAPI API
- input validation
- configurable CORS
- retrieval evaluation
- query-router evaluation
- Next.js portfolio integration
- conversational frontend interface

Deployment remains to be completed.

---

## Related Project

The frontend portfolio is maintained separately:

**AI Engineer Portfolio Website**  
https://github.com/timoajayi/ai-engineer-portfolio

---

## Author

**Timothy Ajayi**

AI Engineer focused on machine learning, LLM applications, RAG, agentic AI, backend systems, and MLOps.