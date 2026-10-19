from src.query_router import is_project_collection_query


TEST_CASES = [
    {
        "question": "What AI projects has Timothy worked on?",
        "expected": True,
    },
    {
        "question": "Tell me about Timothy's projects.",
        "expected": True,
    },
    {
        "question": "Which projects has Timothy built?",
        "expected": True,
    },
    {
        "question": "List Timothy's AI projects.",
        "expected": True,
    },
    {
        "question": "What did Timothy contribute to BundesHost?",
        "expected": False,
    },
    {
        "question": "Has Timothy used Docker?",
        "expected": False,
    },
    {
        "question": "Has Timothy worked with RAG?",
        "expected": False,
    },
    {
        "question": "Which machine learning project did Timothy build independently to predict customer churn?",
        "expected": False,
    },
]


def evaluate_query_router() -> None:
    passed = 0

    for index, test_case in enumerate(TEST_CASES, start=1):
        question = test_case["question"]
        expected = test_case["expected"]

        actual = is_project_collection_query(question)
        success = actual == expected

        if success:
            passed += 1

        print("=" * 70)
        print(f"TEST {index}")
        print(f"Question: {question}")
        print(f"Expected collection route: {expected}")
        print(f"Actual collection route:   {actual}")
        print()
        print("PASS" if success else "FAIL")
        print()

    total = len(TEST_CASES)

    print("=" * 70)
    print("QUERY ROUTER EVALUATION")
    print(f"Passed: {passed}/{total}")
    print(f"Accuracy: {(passed / total) * 100:.2f}%")


if __name__ == "__main__":
    evaluate_query_router()
