from pathlib import Path


PORTFOLIO_PATH = (
    Path(__file__).resolve().parent.parent
    / "data"
    / "portfolio.md"
)


def load_portfolio_knowledge() -> str:
    if not PORTFOLIO_PATH.exists():
        raise FileNotFoundError(
            f"Portfolio knowledge file not found: {PORTFOLIO_PATH}"
        )

    return PORTFOLIO_PATH.read_text(encoding="utf-8")