from src.retrieval import retrieve_relevant_chunks


TEST_CASES = [
    {
        "question": "What forecasting project did Timothy work on?",
        "expected": ["BundesHost Tourism Forecasting"],
    },
    {
        "question": "Has Timothy worked with experiment tracking?",
        "expected": ["BundesHost Tourism Forecasting"],
    },
    {
        "question": "What did Timothy personally contribute to BundesHost?",
        "expected": ["BundesHost Tourism Forecasting"],
    },
    {
        "question": "Which project did Timothy build independently?",
        "expected": ["Customer Churn Prediction"],
    },
    {
        "question": "What languages does Timothy speak?",
        "expected": ["Languages"],
    },
    {
        "question": "Has Timothy worked with RAG?",
        "expected": [
            "Generative AI",
            "Professional Profile",
            "Current Focus",
            "AI Portfolio Assistant",
        ],
    },
    {
        "question": "Has Timothy used Docker?",
        "expected": [
            "MLOps and Infrastructure",
            "BundesHost Tourism Forecasting",
        ],
    },
    {
        "question": "What is Timothy currently focusing on?",
        "expected": ["Current Focus"],
    },
]


def evaluate_retrieval(top_k: int = 3) -> None:
    passed = 0

    for index, test_case in enumerate(TEST_CASES, start=1):
        question = test_case["question"]
        expected_chunks = test_case["expected"]

        results = retrieve_relevant_chunks(
            question,
            top_k=top_k,
        )

        print("=" * 70)
        print(f"TEST {index}")
        print(f"Question: {question}")
        print(f"Expected: {', '.join(expected_chunks)}")
        print()

        found = False

        for rank, (chunk, score) in enumerate(results, start=1):
            heading = chunk.split("\n", 1)[0]

            print(
                f"{rank}. {heading} "
                f"(similarity: {score:.4f})"
            )

            if any(
                    expected.lower() in heading.lower()
                    for expected in expected_chunks
            ):
                found = True

        if found:
            passed += 1
            print("\nPASS")
        else:
            print("\nFAIL")

        print()

    total = len(TEST_CASES)

    print("=" * 70)
    print("RETRIEVAL EVALUATION")
    print(f"Passed: {passed}/{total}")
    print(f"Recall@{top_k}: {passed / total:.2%}")


if __name__ == "__main__":
    evaluate_retrieval()