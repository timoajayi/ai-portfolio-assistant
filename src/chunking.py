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

    if not content:
        return []

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
            f"### {project_title} — {label}\n\n{body}"
            for label, body in (
                ("Overview", overview),
                ("Modeling", modeling),
                ("Application", application),
            )
            if body.strip()
        ]

    # BundesHost also contains several distinct retrieval topics
    if project_title == "BundesHost Tourism Forecasting":
        paragraphs = [
            paragraph.strip()
            for paragraph in content.split("\n\n")
            if paragraph.strip()
        ]

        overview = "\n\n".join(paragraphs[:3])
        infrastructure = "\n\n".join(paragraphs[3:4])

        contributions = "\n\n".join(paragraphs[4:])

        return [
            f"### {project_title} — {label}\n\n{body}"
            for label, body in (
                ("Overview", overview),
                ("Infrastructure", infrastructure),
                ("Timothy's Contributions", contributions),
            )
            if body.strip()
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

def get_project_overview_chunks() -> list[str]:
    """
    Return one representative chunk for each portfolio project.

    Large projects may have several retrieval chunks, so only their
    overview chunk is included. Smaller projects already exist as a
    single project chunk.
    """

    project_chunks = []

    # Discover projects from their section rather than a fixed title allowlist.
    for section in load_portfolio_knowledge().split("\n## ")[1:]:
        if section.split("\n", 1)[0].strip() != "Projects":
            continue

        for project_section in section.split("\n### ")[1:]:
            chunks = split_large_project("### " + project_section.strip())
            if chunks:
                project_chunks.append(chunks[0])

    return project_chunks

if __name__ == "__main__":
    portfolio_chunks = chunk_portfolio_by_section()

    print(f"Created {len(portfolio_chunks)} chunks.\n")

    for index, chunk in enumerate(portfolio_chunks, start=1):
        print(f"--- CHUNK {index} ---")
        print(chunk)
        print()
