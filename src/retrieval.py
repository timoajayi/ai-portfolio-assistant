import math
import re

from src.chunking import chunk_portfolio_by_section
from src.embeddings import create_embedding
from src.query_expansion import expand_query


def cosine_similarity(
    vector_a: list[float],
    vector_b: list[float],
) -> float:
    dot_product = sum(
        a * b for a, b in zip(vector_a, vector_b)
    )

    magnitude_a = sum(a * a for a in vector_a) ** 0.5
    magnitude_b = sum(b * b for b in vector_b) ** 0.5

    if magnitude_a == 0 or magnitude_b == 0:
        return 0.0

    return dot_product / (magnitude_a * magnitude_b)


def tokenize(text: str) -> list[str]:
    return re.findall(r"\b\w+\b", text.lower())


def build_bm25_index(chunks: list[str]) -> dict:
    tokenized_chunks = [
        tokenize(chunk)
        for chunk in chunks
    ]

    document_frequencies = {}

    for tokens in tokenized_chunks:
        unique_tokens = set(tokens)

        for token in unique_tokens:
            document_frequencies[token] = (
                document_frequencies.get(token, 0) + 1
            )

    average_document_length = (
        sum(len(tokens) for tokens in tokenized_chunks)
        / len(tokenized_chunks)
    )

    return {
        "tokenized_chunks": tokenized_chunks,
        "document_frequencies": document_frequencies,
        "average_document_length": average_document_length,
        "document_count": len(tokenized_chunks),
    }


def bm25_score(
    question: str,
    chunk_index: int,
    bm25_index: dict,
    k1: float = 1.5,
    b: float = 0.75,
) -> float:
    query_tokens = tokenize(question)

    document_tokens = (
        bm25_index["tokenized_chunks"][chunk_index]
    )

    document_frequencies = (
        bm25_index["document_frequencies"]
    )

    average_document_length = (
        bm25_index["average_document_length"]
    )

    document_count = (
        bm25_index["document_count"]
    )

    document_length = len(document_tokens)

    score = 0.0

    for token in set(query_tokens):
        term_frequency = document_tokens.count(token)

        if term_frequency == 0:
            continue

        document_frequency = document_frequencies.get(
            token,
            0,
        )

        inverse_document_frequency = math.log(
            1
            + (
                document_count
                - document_frequency
                + 0.5
            )
            / (
                document_frequency
                + 0.5
            )
        )

        numerator = (
            term_frequency
            * (k1 + 1)
        )

        denominator = (
            term_frequency
            + k1
            * (
                1
                - b
                + b
                * (
                    document_length
                    / average_document_length
                )
            )
        )

        score += (
            inverse_document_frequency
            * numerator
            / denominator
        )

    return score


def build_portfolio_index() -> list[tuple[str, list[float]]]:
    chunks = chunk_portfolio_by_section()

    portfolio_index = []

    for chunk in chunks:
        embedding = create_embedding(chunk)

        portfolio_index.append(
            (chunk, embedding)
        )

    return portfolio_index


print("Building portfolio embedding index...")

PORTFOLIO_INDEX = build_portfolio_index()

PORTFOLIO_CHUNKS = [
    chunk
    for chunk, _embedding in PORTFOLIO_INDEX
]

BM25_INDEX = build_bm25_index(
    PORTFOLIO_CHUNKS
)

print(
    f"Portfolio index ready with "
    f"{len(PORTFOLIO_INDEX)} chunks."
)


def retrieve_relevant_chunks(
    question: str,
    top_k: int = 3,
) -> list[tuple[str, float]]:
    expanded_question = expand_query(question)

    question_embedding = create_embedding(
        expanded_question,
        task_type="RETRIEVAL_QUERY",
    )

    raw_results = []

    for index, (
        chunk,
        chunk_embedding,
    ) in enumerate(PORTFOLIO_INDEX):

        semantic_score = cosine_similarity(
            question_embedding,
            chunk_embedding,
        )

        lexical_score = bm25_score(
            expanded_question,
            index,
            BM25_INDEX,
        )

        raw_results.append(
            (
                chunk,
                semantic_score,
                lexical_score,
            )
        )

    max_bm25 = max(
        lexical_score
        for _, _, lexical_score in raw_results
    )

    scored_chunks = []

    for (
        chunk,
        semantic_score,
        lexical_score,
    ) in raw_results:

        normalized_lexical_score = (
            lexical_score / max_bm25
            if max_bm25 > 0
            else 0.0
        )

        final_score = (
            0.85 * semantic_score
            + 0.15 * normalized_lexical_score
        )

        scored_chunks.append(
            (chunk, final_score)
        )

    scored_chunks.sort(
        key=lambda item: item[1],
        reverse=True,
    )

    return scored_chunks[:top_k]


def debug_retrieval(
    question: str,
) -> None:
    expanded_question = expand_query(question)

    print(
        f"\nORIGINAL QUESTION:\n{question}"
    )

    print(
        f"\nEXPANDED QUESTION:\n"
        f"{expanded_question}"
    )

    question_embedding = create_embedding(
        expanded_question,
        task_type="RETRIEVAL_QUERY",
    )

    raw_results = []

    for index, (
        chunk,
        chunk_embedding,
    ) in enumerate(PORTFOLIO_INDEX):

        semantic_score = cosine_similarity(
            question_embedding,
            chunk_embedding,
        )

        lexical_score = bm25_score(
            expanded_question,
            index,
            BM25_INDEX,
        )

        raw_results.append(
            (
                chunk,
                semantic_score,
                lexical_score,
            )
        )

    max_bm25 = max(
        lexical_score
        for _, _, lexical_score in raw_results
    )

    debug_results = []

    for (
        chunk,
        semantic_score,
        lexical_score,
    ) in raw_results:

        normalized_lexical_score = (
            lexical_score / max_bm25
            if max_bm25 > 0
            else 0.0
        )

        final_score = (
            0.85 * semantic_score
            + 0.15 * normalized_lexical_score
        )

        heading = chunk.split("\n", 1)[0]

        debug_results.append(
            (
                heading,
                semantic_score,
                lexical_score,
                normalized_lexical_score,
                final_score,
            )
        )

    debug_results.sort(
        key=lambda item: item[4],
        reverse=True,
    )

    print("\nALL RETRIEVAL SCORES:\n")

    for (
        heading,
        semantic_score,
        lexical_score,
        normalized_lexical_score,
        final_score,
    ) in debug_results:

        print(heading)
        print(
            f"  Semantic:       "
            f"{semantic_score:.4f}"
        )
        print(
            f"  BM25:           "
            f"{lexical_score:.4f}"
        )
        print(
            f"  BM25 normalized:"
            f" {normalized_lexical_score:.4f}"
        )
        print(
            f"  Final:          "
            f"{final_score:.4f}"
        )
        print()


if __name__ == "__main__":
    test_question = (
        "Which project did Timothy build independently?"
    )

    debug_retrieval(test_question)