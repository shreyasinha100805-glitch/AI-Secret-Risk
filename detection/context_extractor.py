
COMMENT_PREFIXES = ("#", "//", "/*", "*", "--")


def extract_candidate_context(code, start, end):
    """
    Extract the candidate's assignment line and its
    immediately preceding comments.

    Prevents comments belonging to nearby assignments
    from affecting candidate classification.
    """

    if not code:
        return ""

    start = max(0, min(start, len(code)))
    end = max(start, min(end, len(code)))

    lines = code.splitlines()

    if not lines:
        return ""

    candidate_line = code[:start].count("\n")

    if candidate_line >= len(lines):
        candidate_line = len(lines) - 1

    preceding_comments = []

    index = candidate_line - 1
    blank_lines_seen = 0

    while index >= 0:

        current_line = lines[index]
        stripped = current_line.strip()

        if not stripped:

            if blank_lines_seen >= 1:
                break

            blank_lines_seen += 1
            index -= 1
            continue

        if stripped.startswith(COMMENT_PREFIXES):

            preceding_comments.insert(0, current_line)

            blank_lines_seen = 0
            index -= 1
            continue

        break

    return "\n".join(
        preceding_comments + [lines[candidate_line]]
    )


def extract_line_context(
    code,
    start,
    end,
    lines_before=4,
    lines_after=4
):
    """Extract wider context when required."""

    if not code:
        return ""

    start = max(0, start)
    end = min(len(code), end)

    lines = code.splitlines()

    if not lines:
        return ""

    candidate_line = code[:start].count("\n")

    first_line = max(
        0,
        candidate_line - lines_before
    )

    last_line = min(
        len(lines),
        candidate_line + lines_after + 1
    )

    return "\n".join(
        lines[first_line:last_line]
    )
