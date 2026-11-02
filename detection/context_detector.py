import re


# =========================================================
# PLACEHOLDER VALUE PATTERNS
# =========================================================

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

    r"\bplaceholder\b",
]


# =========================================================
# PLACEHOLDER CONTEXT WORDS
# =========================================================

PLACEHOLDER_CONTEXT_WORDS = [
    "example",
    "sample",
    "demo",
    "demonstration",
    "dummy",
    "fake",
    "mock",
    "placeholder",
    "testing",
]


# =========================================================
# COMMON / DEFAULT CREDENTIAL VALUES
# =========================================================

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


# =========================================================
# COMMON NON-SECRET VALUES
# =========================================================

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


# =========================================================
# VARIABLE NAMES THAT STRONGLY INDICATE PLACEHOLDERS
# =========================================================

PLACEHOLDER_VARIABLE_WORDS = {
    "example",
    "sample",
    "demo",
    "demonstration",
    "dummy",
    "fake",
    "mock",
    "placeholder",
    "test",
    "testing",
}


# =========================================================
# VARIABLE NAMES THAT STRONGLY INDICATE NON-SECRETS
# =========================================================

NON_SECRET_VARIABLE_NAMES = {
    "data",
    "value",
    "values",
    "random_value",
    "user_id",
    "id",
    "identifier",
    "session_id",
    "request_id",
    "transaction_id",
    "record_id",
    "trace_id",
    "message",
    "text",
    "content",
    "name",
    "description",
}


# =========================================================
# CREDENTIAL VARIABLE PATTERNS
# =========================================================

CREDENTIAL_VARIABLE_PATTERNS = [
    r"api[_\-]?key",
    r"apikey",

    r"password",
    r"passwd",
    r"pwd",

    r"database[_\-]?password",
    r"db[_\-]?password",
    r"database[_\-]?pass",
    r"db[_\-]?pass",

    r"token",
    r"access[_\-]?token",
    r"auth[_\-]?token",
    r"refresh[_\-]?token",
    r"bearer[_\-]?token",
    r"id[_\-]?token",

    r"secret",
    r"secret[_\-]?key",
    r"client[_\-]?secret",
    r"app[_\-]?secret",

    r"credential",
    r"credentials",

    r"authorization",
    r"private[_\-]?key",
]


# =========================================================
# EXTRACT VARIABLE NAME FROM SOURCE CODE
# =========================================================

def extract_variable_name(context, value):
    """
    Try to identify the variable assigned to the candidate.

    Example:

        api_key = "ABC123"
        test_token = "XYZ123"

    returns:

        api_key
        test_token
    """

    if not context or not value:
        return ""

    escaped_value = re.escape(value)

    # Normal assignment:
    # variable = "value"
    assignment_patterns = [
        rf'\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*["\']{escaped_value}["\']',

        # Bearer token:
        # authorization = "Bearer ABC123"
        rf'\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*["\']Bearer\s+{escaped_value}["\']',

        # Optional type annotation:
        # token: str = "ABC123"
        rf'\b([A-Za-z_][A-Za-z0-9_]*)\s*:\s*[A-Za-z_][A-Za-z0-9_\[\], ]*\s*=\s*["\']{escaped_value}["\']',
    ]

    for pattern in assignment_patterns:

        match = re.search(
            pattern,
            context,
            re.IGNORECASE
        )

        if match:
            return match.group(1).lower()

    return ""


# =========================================================
# SPLIT VARIABLE NAME INTO WORDS
# =========================================================

def variable_words(variable_name):
    """
    Convert names such as:

        test_token
        database_password
        example-key

    into individual words.
    """

    if not variable_name:
        return []

    name = variable_name.lower().replace("-", "_")

    words = [
        word
        for word in name.split("_")
        if word
    ]

    return words


# =========================================================
# CHECK PLACEHOLDER VARIABLE
# =========================================================

def is_placeholder_variable(variable_name):

    words = variable_words(variable_name)

    if not words:
        return False

    return any(
        word in PLACEHOLDER_VARIABLE_WORDS
        for word in words
    )


# =========================================================
# CHECK NON-SECRET VARIABLE
# =========================================================

def is_non_secret_variable(variable_name):

    if not variable_name:
        return False

    if variable_name in NON_SECRET_VARIABLE_NAMES:
        return True

    words = variable_words(variable_name)

    # Generic identifier variables
    identifier_words = {
        "id",
        "identifier",
    }

    if any(word in identifier_words for word in words):
        return True

    return False


# =========================================================
# CHECK CREDENTIAL VARIABLE
# =========================================================

def is_credential_variable(variable_name):

    if not variable_name:
        return False

    name = variable_name.lower()

    return any(
        re.search(
            rf"\b{pattern}\b",
            name,
            re.IGNORECASE
        )
        for pattern in CREDENTIAL_VARIABLE_PATTERNS
    )


# =========================================================
# CLASSIFY SOURCE CODE CONTEXT
# =========================================================

def classify_context(candidate, context):

    if not isinstance(candidate, dict):
        return None

    value = str(
        candidate.get("value", "")
    ).strip()

    detected_type = str(
        candidate.get("type", "unknown")
    ).lower()

    if not value:
        return None

    # -----------------------------------------------------
    # Clean candidate
    # -----------------------------------------------------

    clean_value = value

    if "=" in clean_value:
        clean_value = clean_value.split(
            "=",
            1
        )[1].strip()

    clean_value = clean_value.strip(
        "\"'` "
    )

    value_lower = clean_value.lower()
    context_text = str(context)
    context_lower = context_text.lower()

    # -----------------------------------------------------
    # Extract variable name
    # -----------------------------------------------------

    variable_name = extract_variable_name(
        context_text,
        clean_value
    )

    # -----------------------------------------------------
    # 1. Explicit placeholder VALUE
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
                    "The candidate matches a known "
                    "placeholder or template pattern."
                ),
                "confidence": 0.98
            }

    # -----------------------------------------------------
    # 2. PLACEHOLDER VARIABLE NAME
    #
    # Important:
    # This happens BEFORE authentication detection.
    #
    # Examples:
    #
    # example_key
    # test_token
    # sample_secret
    #
    # should NOT become REAL_SECRET only because
    # key/token/secret appears in the variable name.
    # -----------------------------------------------------

    if is_placeholder_variable(variable_name):

        return {
            "classification": "PLACEHOLDER",
            "reason": (
                f"The variable name '{variable_name}' "
                "indicates that the value is intended "
                "for testing, demonstration, or example use."
            ),
            "confidence": 0.98
        }

    # -----------------------------------------------------
    # 3. NON-SECRET VARIABLE NAME
    # -----------------------------------------------------

    if is_non_secret_variable(variable_name):

        return {
            "classification": "NOT_SECRET",
            "reason": (
                f"The variable name '{variable_name}' "
                "indicates a general data or identifier "
                "rather than a credential."
            ),
            "confidence": 0.95
        }

    # -----------------------------------------------------
    # 4. Placeholder context
    #
    # Keep this after variable-name checks so a word like
    # "test" in unrelated nearby code does not dominate
    # the variable-name semantics.
    # -----------------------------------------------------

    placeholder_context = any(
        re.search(
            rf"\b{re.escape(word)}\b",
            context_lower
        )
        for word in PLACEHOLDER_CONTEXT_WORDS
    )

    if placeholder_context:

        # Stronger condition:
        # Do not automatically call a credential a placeholder
        # just because "test" appears somewhere nearby.
        #
        # Require either:
        # - the variable itself contains placeholder semantics
        # - OR the surrounding context has explicit example/demo
        #   language.

        explicit_example_words = {
            "example",
            "sample",
            "demo",
            "demonstration",
            "dummy",
            "fake",
            "mock",
            "placeholder",
        }

        explicit_example_context = any(
            re.search(
                rf"\b{re.escape(word)}\b",
                context_lower
            )
            for word in explicit_example_words
        )

        if explicit_example_context:

            return {
                "classification": "PLACEHOLDER",
                "reason": (
                    "The surrounding source code indicates "
                    "that the candidate is being used as an "
                    "example, demonstration, sample, or "
                    "placeholder."
                ),
                "confidence": 0.95
            }

    # -----------------------------------------------------
    # 5. Common/default credentials
    # -----------------------------------------------------

    if value_lower in COMMON_CREDENTIAL_VALUES:

        return {
            "classification": "PLACEHOLDER",
            "reason": (
                "The candidate is a common or default "
                "credential value and is likely to be "
                "used for testing or demonstration."
            ),
            "confidence": 0.98
        }

    # -----------------------------------------------------
    # 6. Obvious non-secret values
    # -----------------------------------------------------

    if value_lower in NON_SECRET_VALUES:

        return {
            "classification": "NOT_SECRET",
            "reason": (
                "The candidate is a common non-sensitive value."
            ),
            "confidence": 0.98
        }

    # -----------------------------------------------------
    # 7. Environment variables
    # -----------------------------------------------------

    environment_reference = (
        "os.getenv" in context_lower
        or "os.environ" in context_lower
        or "getenv(" in context_lower
    )

    if environment_reference:

        return {
            "classification": "NOT_SECRET",
            "reason": (
                "The source code obtains the value from "
                "an environment variable rather than "
                "hardcoding the actual secret."
            ),
            "confidence": 0.95
        }

    # -----------------------------------------------------
    # 8. Explicit credential variable
    # -----------------------------------------------------

    if is_credential_variable(variable_name):

        return {
            "classification": "REAL_SECRET",
            "reason": (
                f"The variable name '{variable_name}' "
                "indicates a credential or "
                "authentication-related value."
            ),
            "confidence": 0.90
        }

    # -----------------------------------------------------
    # 9. Known credential type + authentication context
    # -----------------------------------------------------

    authentication_words = [
        "api_key",
        "apikey",
        "password",
        "passwd",
        "token",
        "secret",
        "authorization",
        "credential",
        "bearer",
        "auth",
        "login",
        "private_key",
        "database_password",
        "db_password",
    ]

    authentication_context = any(
        word in context_lower
        for word in authentication_words
    )

    known_secret_types = {
        "api_key",
        "password",
        "token",
        "secret",
        "credential",
        "authorization",
    }

    if detected_type in known_secret_types:

        if authentication_context:

            return {
                "classification": "REAL_SECRET",
                "reason": (
                    "The candidate is associated with "
                    "an authentication or credential-related "
                    "context."
                ),
                "confidence": 0.90
            }

    # -----------------------------------------------------
    # 10. Generic authentication context
    # -----------------------------------------------------

    if authentication_context:

        return {
            "classification": "REAL_SECRET",
            "reason": (
                "The surrounding source code indicates "
                "that the candidate is used in an "
                "authentication or credential-related context."
            ),
            "confidence": 0.85
        }

    # -----------------------------------------------------
    # 11. High entropy / random-looking value
    #
    # Do NOT call it REAL_SECRET just because it looks random.
    # Send UNKNOWN to the LLM.
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
                "classification": "UNKNOWN",
                "reason": (
                    "The candidate has high-entropy "
                    "characteristics, but the available "
                    "context does not clearly establish "
                    "whether it is a real secret."
                ),
                "confidence": 0.50
            }

    # -----------------------------------------------------
    # 12. UNKNOWN
    # -----------------------------------------------------

    return {
        "classification": "UNKNOWN",
        "reason": (
            "The available source-code context is "
            "insufficient to determine whether the "
            "candidate is a secret."
        ),
        "confidence": 0.50
    }