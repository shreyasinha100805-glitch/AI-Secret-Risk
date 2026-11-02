def create_secret_classification_prompt(
    candidate,
    context,
    detected_type=None
):
    """
    Create a classification prompt for the LLM.

    Supports both:
        create_secret_classification_prompt(candidate, context)
    and:
        create_secret_classification_prompt(candidate, context, detected_type)
    """

    # Candidate may be a dictionary or a plain string
    if isinstance(candidate, dict):

        value = candidate.get("value", "")

        if detected_type is None:
            detected_type = candidate.get(
                "type",
                "unknown"
            )

    else:

        value = str(candidate)

    if detected_type is None:
        detected_type = "unknown"

    prompt = f"""
You are a source-code security classifier.

Your task is to classify ONLY the candidate value.

CANDIDATE:
{value}

DETECTED TYPE:
{detected_type}

SOURCE CODE CONTEXT:
{context}

IMPORTANT RULES:

1. Focus ONLY on the candidate.

2. Use the surrounding source-code context to understand
   what the candidate represents.

3. Do NOT assume that every random-looking string is a secret.

4. A demonstration value, example value, sample value,
   test value, dummy value, or placeholder is NOT a real secret.

5. If the context clearly indicates that the value is being
   used for testing, demonstration, documentation, examples,
   samples, or placeholders, classify it as PLACEHOLDER.

6. If the candidate is obtained from an environment variable,
   such as:
       os.getenv(...)
       os.environ[...]
   classify it as NOT_SECRET because the actual secret is not
   hardcoded in the source code.

7. A hardcoded API key, password, authentication token,
   database credential, private key, or other credential
   should be classified as REAL_SECRET when the context
   supports that interpretation.

8. Do NOT classify a candidate as REAL_SECRET only because
   it looks random or has high entropy.

9. Ordinary identifiers, IDs, messages, usernames, names,
   test data, and normal strings are NOT_SECRET.

10. Never reproduce the candidate value in the explanation.

CLASSIFICATION OPTIONS:

REAL_SECRET
PLACEHOLDER
NOT_SECRET
UNKNOWN

SECRET TYPES:

API_KEY
PASSWORD
TOKEN
PRIVATE_KEY
DATABASE_CREDENTIAL
GENERIC_SECRET
OTHER

Return EXACTLY this format:

CLASSIFICATION: REAL_SECRET
TYPE: API_KEY
CONFIDENCE: 0.00
REASON: Short explanation.

OR:

CLASSIFICATION: PLACEHOLDER
TYPE: OTHER
CONFIDENCE: 0.00
REASON: Short explanation.

OR:

CLASSIFICATION: NOT_SECRET
TYPE: OTHER
CONFIDENCE: 0.00
REASON: Short explanation.

OR:

CLASSIFICATION: UNKNOWN
TYPE: OTHER
CONFIDENCE: 0.00
REASON: Short explanation.
"""

    return prompt