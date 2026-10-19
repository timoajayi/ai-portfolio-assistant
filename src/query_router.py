import re


def is_project_collection_query(question: str) -> bool:
    """
    Detect broad questions asking about Timothy's projects as a collection.

    These questions need coverage across the project portfolio rather
    than similarity-based retrieval of only the top few chunks.
    """

    normalized_question = question.lower().strip()

    collection_patterns = [
        r"\bwhat (?:ai )?projects\b",
        r"\bwhich (?:ai )?projects\b",
        r"\btell me about (?:timothy'?s |his )?(?:ai )?projects\b",
        r"\blist (?:timothy'?s |his )?(?:ai )?projects\b",
        r"\bprojects (?:has|did) timothy (?:worked|work|built|build|developed|develop)\b",
        r"\bprojects (?:has|did) he (?:worked|work|built|build|developed|develop)\b",
    ]

    return any(
        re.search(pattern, normalized_question)
        for pattern in collection_patterns
    )