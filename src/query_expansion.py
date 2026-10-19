QUERY_EXPANSIONS = {
    "independently": [
        "solo project",
        "individual project",
    ],
    "experiment tracking": [
        "MLflow",
        "model tracking",
    ],
    "rag": [
        "retrieval-augmented generation",
    ],
    "llm": [
        "large language model",
    ],
}


def expand_query(question: str) -> str:
    expanded_terms = []
    question_lower = question.lower()

    for term, expansions in QUERY_EXPANSIONS.items():
        if term in question_lower:
            expanded_terms.extend(expansions)

    if not expanded_terms:
        return question

    return question + " " + " ".join(expanded_terms)


if __name__ == "__main__":
    test_question = "Which project did Timothy build independently?"

    print("ORIGINAL:")
    print(test_question)

    print("\nEXPANDED:")
    print(expand_query(test_question))