import re

from detection.entropy_detector import calculate_entropy
from detection.context_detector import classify_context


# ---------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------

PATTERNS = {

    "api_key": re.compile(
        r"\b(?:API_KEY|api_key|apikey|api[_-]?key)\s*=\s*['\"]([^'\"]+)['\"]",
        re.IGNORECASE
    ),

    "password": re.compile(
        r"\b(?:PASSWORD|password|passwd|pwd|"
        r"database_password|db_password|database_pass|db_pass)\s*="
        r"\s*['\"]([^'\"]+)['\"]",
        re.IGNORECASE
    ),

    "token": re.compile(
        r"\b(?:TOKEN|token|access_token|auth_token|"
        r"refresh_token|bearer_token|id_token)\s*="
        r"\s*['\"]([^'\"]+)['\"]",
        re.IGNORECASE
    ),

    "secret": re.compile(
        r"\b(?:SECRET|secret|secret_key|"
        r"client_secret|app_secret)\s*="
        r"\s*['\"]([^'\"]+)['\"]",
        re.IGNORECASE
    ),

    "credential": re.compile(
        r"\b(?:CREDENTIAL|credential|credentials)\s*="
        r"\s*['\"]([^'\"]+)['\"]",
        re.IGNORECASE
    ),

    "authorization": re.compile(
        r"\b(?:AUTHORIZATION|authorization)\s*="
        r"\s*['\"]([^'\"]+)['\"]",
        re.IGNORECASE
    ),
}


# ---------------------------------------------------------
# Extract candidates
# ---------------------------------------------------------

def extract_candidates(code):

    candidates = []

    if not code:
        return candidates

    # Keep track of values already detected
    detected_values = set()

    # -----------------------------------------------------
    # STEP 1: Regex detection
    # -----------------------------------------------------

    for detected_type, pattern in PATTERNS.items():

        for match in pattern.finditer(code):

            value = match.group(1).strip()

            if not value:
                continue

            # Avoid duplicate results
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

            # Extract surrounding context
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

        # Do not duplicate regex candidates
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

        # Extract surrounding context
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