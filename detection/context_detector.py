import re


# ---------------------------------------------------------
# Placeholder patterns
# ---------------------------------------------------------

PLACEHOLDER_PATTERNS = [
    r"your[_\- ]?api[_\- ]?key",
    r"your[_\- ]?token",
    r"your[_\- ]?password",
    r"your[_\- ]?secret",
    r"api[_\- ]?key[_\- ]?here",
    r"token[_\- ]?here",
    r"password[_\- ]?here",
    r"secret[_\- ]?here",
    r"<[^>]+>",
    r"\bexample\b",
    r"\bsample\b",
    r"\bplaceholder\b",
    r"\btest[_\- ]?(key|token|password|secret)\b",
]


# ---------------------------------------------------------
# Common/default credential values
# ---------------------------------------------------------

COMMON_CREDENTIAL_VALUES = {
    "password",
    "password123",
    "123456",
    "12345678",
    "123456789",
    "admin123",
    "admin1234",
    "qwerty",
    "qwerty123",
    "welcome",
    "welcome123",
    "letmein",
    "letmein123",
    "changeme",
    "change_me",
    "default",
    "defaultpassword",
    "default_password",
    "testpassword",
    "test_password",
    "test123",
    "secret",
    "secret123",
    "yourpassword",
    "your_password",
    "yourpassword123",
}


# ---------------------------------------------------------
# Obvious non-secret values
# ---------------------------------------------------------

NON_SECRET_VALUES = {
    "hello",
    "hello world",
    "test",
    "testing",
    "admin",
    "username",
    "user",
    "null",
    "none",
    "true",
    "false",
    "abc",
    "abc123",
}


# ---------------------------------------------------------
# Context classifier
# ---------------------------------------------------------

def classify_context(candidate, context):

    if not isinstance(candidate, dict):
        return None

    value = str(candidate.get("value", "")).strip()

    detected_type = str(
        candidate.get("type", "unknown")
    ).lower()

    if not value:
        return None

    # -----------------------------------------------------
    # Clean candidate value
    # -----------------------------------------------------

    clean_value = value

    # Remove common assignment syntax
    if "=" in clean_value:
        clean_value = clean_value.split(
            "=",
            1
        )[1].strip()

    # Remove quotes and backticks
    clean_value = clean_value.strip(
        "\"'` "
    )

    value_lower = clean_value.lower()

    context_lower = str(
        context
    ).lower()

    # -----------------------------------------------------
    # 1. Placeholder detection
    # -----------------------------------------------------

    for pattern in PLACEHOLDER_PATTERNS:

        if re.search(
            pattern,
            clean_value,
            re.IGNORECASE
        ):

            return {
                "classification": "PLACEHOLDER",
                "reason": (
                    "The candidate appears to be an "
                    "example, template, or placeholder value."
                ),
                "confidence": 0.98
            }

    # -----------------------------------------------------
    # 2. Common/default credential detection
    # -----------------------------------------------------
    #
    # Important:
    # Values such as password123 are commonly used in
    # demonstrations, test cases, tutorials, and mock
    # authentication examples.
    #
    # This check MUST happen before the general
    # authentication-context check.
    # -----------------------------------------------------

    if value_lower in COMMON_CREDENTIAL_VALUES:

        return {
            "classification": "PLACEHOLDER",
            "reason": (
                "The candidate is a common/default credential "
                "value and is likely to be an example, test, "
                "or placeholder credential."
            ),
            "confidence": 0.98
        }

    # -----------------------------------------------------
    # 3. Common non-secret values
    # -----------------------------------------------------

    if value_lower in NON_SECRET_VALUES:

        return {
            "classification": "NOT_SECRET",
            "reason": (
                "The candidate contains a common non-sensitive "
                "value rather than a credential."
            ),
            "confidence": 0.98
        }

    # -----------------------------------------------------
    # 4. Environment variable references
    # -----------------------------------------------------

    if (
        "os.getenv" in context_lower
        or "os.environ" in context_lower
        or "getenv(" in context_lower
    ):

        return {
            "classification": "NOT_SECRET",
            "reason": (
                "The code references an environment variable "
                "instead of embedding the secret directly."
            ),
            "confidence": 0.95
        }

    # -----------------------------------------------------
    # 5. Obvious authentication context
    # -----------------------------------------------------

    authentication_words = [
        "api_key",
        "apikey",
        "password",
        "token",
        "secret",
        "authorization",
        "credential",
        "bearer",
        "auth",
        "login",
    ]

    authentication_context = any(
        word in context_lower
        for word in authentication_words
    )

    # -----------------------------------------------------
    # 6. Known secret types
    # -----------------------------------------------------

    if detected_type in {
        "api_key",
        "password",
        "token",
        "secret"
    }:

        if authentication_context:

            return {
                "classification": "REAL_SECRET",
                "reason": (
                    "The candidate is associated with an "
                    "authentication or credential-related "
                    "context."
                ),
                "confidence": 0.90
            }

    # -----------------------------------------------------
    # 7. Strong random-looking value
    # -----------------------------------------------------

    if len(clean_value) >= 16:

        has_upper = bool(
            re.search(
                r"[A-Z]",
                clean_value
            )
        )

        has_lower = bool(
            re.search(
                r"[a-z]",
                clean_value
            )
        )

        has_digit = bool(
            re.search(
                r"\d",
                clean_value
            )
        )

        has_special = bool(
            re.search(
                r"[^A-Za-z0-9]",
                clean_value
            )
        )

        complexity = sum([
            has_upper,
            has_lower,
            has_digit,
            has_special
        ])

        if complexity >= 2:

            return {
                "classification": "REAL_SECRET",
                "reason": (
                    "The candidate has characteristics of "
                    "a credential-like secret."
                ),
                "confidence": 0.80
            }

    # -----------------------------------------------------
    # 8. Unknown
    # -----------------------------------------------------

    return {
        "classification": "UNKNOWN",
        "reason": (
            "The available context is insufficient to "
            "determine whether the candidate is a secret."
        ),
        "confidence": 0.50
    }