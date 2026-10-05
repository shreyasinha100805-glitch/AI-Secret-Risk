def extract_line_context(
    code,
    start,
    end,
    lines_before=4,
    lines_after=4
):
    """
    Extract source-code context around a detected candidate.

    start/end are character positions in the original source code.
    """

    if not code:
        return ""

    # Safety
    start = max(0, start)
    end = min(len(code), end)

    # Find the line containing the candidate
    line_start = code.rfind("\n", 0, start) + 1

    line_end = code.find("\n", end)

    if line_end == -1:
        line_end = len(code)

    # Split source into lines
    lines = code.splitlines()

    # Determine candidate line number
    candidate_line = code[:line_start].count("\n")

    first_line = max(0, candidate_line - lines_before)
    last_line = min(
        len(lines),
        candidate_line + lines_after + 1
    )

    context_lines = lines[first_line:last_line]

    return "\n".join(context_lines)