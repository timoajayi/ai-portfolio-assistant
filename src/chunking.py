from src.knowledge import load_portfolio_knowledge


def split_large_project(project_section: str) -> list[str]:
    """
    Split large project sections into smaller retrieval chunks while
    preserving the project name in every chunk.
    """

    lines = project_section.splitlines()

    if not lines:
        return []

    project_title = lines[0].replace("### ", "").strip()
    content = "\n".join(lines[1:]).strip()

    # Customer Churn has several distinct retrieval topics
    if project_title == "Customer Churn Prediction":
        paragraphs = [
            paragraph.strip()
            for paragraph in content.split("\n\n")
            if paragraph.strip()
        ]

        overview = "\n\n".join(paragraphs[:3])
        modeling = "\n\n".join(paragraphs[3:7])
        application = "\n\n".join(paragraphs[7:])

        return [
            (
                f"### {project_title} — Overview\n\n"
                f"{overview}"
            ),
            (
                f"### {project_title} — Modeling\n\n"
                f"{modeling}"
            ),
            (
                f"### {project_title} — Application\n\n"
                f"{application}"
            ),
        ]

    # BundesHost also contains several distinct retrieval topics
    if project_title == "BundesHost Tourism Forecasting":
        paragraphs = [
            paragraph.strip()
            for paragraph in content.split("\n\n")
            if paragraph.strip()
        ]

        overview = "\n\n".join(paragraphs[:3])
        infrastructure = paragraphs[3]

        contributions = "\n\n".join(paragraphs[4:])

        return [
            (
                f"### {project_title} — Overview\n\n"
                f"{overview}"
            ),
            (
                f"### {project_title} — Infrastructure\n\n"
                f"{infrastructure}"
            ),
            (
                f"### {project_title} — Timothy's Contributions\n\n"
                f"{contributions}"
            ),
        ]

    # Smaller projects remain as a single chunk
    return [project_section]


def chunk_portfolio_by_section() -> list[str]:
    portfolio_text = load_portfolio_knowledge()

    main_sections = portfolio_text.split("\n## ")

    chunks = []

    for index, section in enumerate(main_sections):
        section = section.strip()

        if not section:
            continue

        # Skip standalone document title
        if section == "# Timothy Ajayi":
            continue

        # Instructions belong in the prompt layer, not retrieval
        if section.startswith("Assistant Guidelines"):
            continue

        if index > 0:
            section = "## " + section

        # Split projects individually
        if section.startswith("## Projects"):
            project_sections = section.split("\n### ")

            for project_index, project_section in enumerate(project_sections):
                project_section = project_section.strip()

                if not project_section:
                    continue

                # Skip standalone Projects heading
                if project_index == 0:
                    continue

                project_chunk = "### " + project_section

                chunks.extend(
                    split_large_project(project_chunk)
                )

        # Split Technical Skills by category
        elif section.startswith("## Technical Skills"):
            skill_sections = section.split("\n### ")

            for skill_index, skill_section in enumerate(skill_sections):
                skill_section = skill_section.strip()

                if not skill_section:
                    continue

                # Skip standalone Technical Skills heading
                if skill_index == 0:
                    continue

                skill_chunk = "### " + skill_section
                chunks.append(skill_chunk)

        else:
            chunks.append(section)

    return chunks


if __name__ == "__main__":
    portfolio_chunks = chunk_portfolio_by_section()

    print(f"Created {len(portfolio_chunks)} chunks.\n")

    for index, chunk in enumerate(portfolio_chunks, start=1):
        print(f"--- CHUNK {index} ---")
        print(chunk)
        print()