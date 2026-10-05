import re

from detection.entropy_detector import calculate_entropy
from detection.context_detector import classify_context


# ---------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------

PATTERNS = {

    "api_key": re.compile(
        r"\b(?:API_KEY|api_key|apikey)\s*=\s*['\"]([^'\"]+)['\"]",
        re.IGNORECASE
    ),

    "password": re.compile(
        r"\b(?:PASSWORD|password|passwd|pwd)\s*=\s*['\"]([^'\"]+)['\"]",
        re.IGNORECASE
    ),

    "token": re.compile(
        r"\b(?:TOKEN|token|access_token|auth_token)\s*=\s*['\"]([^'\"]+)['\"]",
        re.IGNORECASE
    )
}


# ---------------------------------------------------------
# Extract candidates
# ---------------------------------------------------------

def extract_candidates(code):

    candidates = []

    if not code:
        return candidates

    # Keep track of values already detected by regex
    detected_values = set()

    # -----------------------------------------------------
    # STEP 1: Regex detection
    # -----------------------------------------------------

    for detected_type, pattern in PATTERNS.items():

        for match in pattern.finditer(code):

            value = match.group(1).strip()

            if not value:
                continue

            # Avoid duplicate regex results
            if value in detected_values:
                continue

            detected_values.add(value)

            candidate = {
                "value": value,
                "type": detected_type,
                "method": "regex",
                "entropy": None,
                "start": match.start(1),
                "end": match.end(1)
            }

            # Context
            context = code[
                max(0, match.start() - 300):
                min(len(code), match.end() + 300)
            ]

            candidate["context_result"] = classify_context(
                candidate,
                context
            )

            candidates.append(candidate)

    # -----------------------------------------------------
    # STEP 2: Entropy detection
    # -----------------------------------------------------

    # Extract quoted strings
    string_pattern = re.compile(
        r"""['"]([^'"]{8,})['"]"""
    )

    for match in string_pattern.finditer(code):

        value = match.group(1).strip()

        if not value:
            continue

        # -----------------------------------------------
        # IMPORTANT:
        # Do not add a value already found by regex.
        # -----------------------------------------------

        if value in detected_values:
            continue

        entropy = calculate_entropy(value)

        # Entropy threshold
        if entropy < 3.5:
            continue

        detected_values.add(value)

        candidate = {
            "value": value,
            "type": "unknown",
            "method": "entropy",
            "entropy": round(entropy, 2),
            "start": match.start(1),
            "end": match.end(1)
        }

        context = code[
            max(0, match.start() - 300):
            min(len(code), match.end() + 300)
        ]

        candidate["context_result"] = classify_context(
            candidate,
            context
        )

        candidates.append(candidate)

    return candidates