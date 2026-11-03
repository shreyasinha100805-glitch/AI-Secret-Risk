
import re

from detection.entropy_detector import calculate_entropy
from detection.context_detector import classify_context
from detection.context_extractor import extract_candidate_context


# =========================================================
# REGEX PATTERNS
# =========================================================

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


# =========================================================
# EXTRACT CANDIDATES
# =========================================================

def extract_candidates(code):

    candidates = []

    if not code:
        return candidates

    detected_values = set()

    # -----------------------------------------------------
    # STEP 1: REGEX DETECTION
    # -----------------------------------------------------

    for detected_type, pattern in PATTERNS.items():

        for match in pattern.finditer(code):

            value = match.group(1).strip()

            if not value:
                continue

            # Avoid duplicate candidates
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

            # Extract candidate-specific context
            context = extract_candidate_context(
                code,
                match.start(1),
                match.end(1)
            )

            # Classify the candidate using context
            candidate["context_result"] = classify_context(
                candidate,
                context
            )

            candidates.append(candidate)

    # -----------------------------------------------------
    # STEP 2: ENTROPY DETECTION
    # -----------------------------------------------------

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

        # Calculate Shannon entropy
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

        # Extract candidate-specific context
        context = extract_candidate_context(
            code,
            match.start(1),
            match.end(1)
        )

        # Classify using context detector
        candidate["context_result"] = classify_context(
            candidate,
            context
        )

        candidates.append(candidate)

    # IMPORTANT: Return is inside the function,
    # outside both detection loops.

    return candidates


# =========================================================
# TEST THE CANDIDATE EXTRACTOR
# =========================================================

if __name__ == "__main__":

    sample_code = """
api_key = "A8fK92LmX71QpR5Z"

# Placeholder example
API_KEY = "YOUR_API_KEY_HERE"

message = "Hello World"
"""

    results = extract_candidates(sample_code)

    print("=" * 60)
    print("CANDIDATE EXTRACTION TEST")
    print("=" * 60)

    for candidate in results:

        print("\nDetected candidate:")
        print("Type:", candidate["type"])
        print("Method:", candidate["method"])
        print(
            "Classification:",
            candidate["context_result"]["classification"]
        )
