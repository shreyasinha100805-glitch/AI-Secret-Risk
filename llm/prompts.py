def create_secret_classification_prompt(
    candidate,
    detected_type,
    context
):
    """
    Create the prompt used by the LLM for secret classification.
    """

    return f"""
You are an expert cybersecurity researcher specializing
in source-code secret detection.

Analyze ONE suspicious candidate from source code.

==================================================
CANDIDATE
==================================================

{candidate}

==================================================
DETECTOR TYPE
==================================================

{detected_type}

==================================================
SOURCE CODE CONTEXT
==================================================

{context}

==================================================
TASK
==================================================

Determine whether the candidate is a real credential
or a false positive.

REAL_SECRET means:
- A credential intended for authentication or authorization.
- An API key used by an application.
- A password used for authentication.
- An access token used for authentication.
- A private cryptographic key.
- Another value that clearly functions as a secret.

FALSE_POSITIVE means:
- Example value.
- Dummy value.
- Test credential.
- Mock credential.
- Documentation placeholder.
- Tutorial example.
- Random identifier that is not used as a credential.
- Public/non-sensitive configuration value.

IMPORTANT RULES:

1. A random-looking string alone does NOT prove that it is
   a real secret.

2. Use the surrounding source-code context.

3. If the code clearly indicates that the value is only for
   testing, documentation, demonstration, or mocking,
   classify it as FALSE_POSITIVE.

4. Do not assume a value is a secret simply because the
   detector identified it.

5. Choose only ONE secret type.

6. Confidence must be between 0.0 and 1.0.

7. Do not invent information that is not present in the
   candidate or source-code context.

==================================================
ALLOWED CLASSIFICATIONS
==================================================

REAL_SECRET
FALSE_POSITIVE

==================================================
ALLOWED TYPES
==================================================

API_KEY
PASSWORD
TOKEN
PRIVATE_KEY
OTHER
NONE

==================================================
OUTPUT FORMAT
==================================================

Return EXACTLY four lines:

CLASSIFICATION: REAL_SECRET
TYPE: API_KEY
CONFIDENCE: 0.85
REASON: The candidate is used as an authentication credential.

Replace the example values with your actual analysis.

Do not add headings.
Do not use Markdown.
Do not provide multiple classifications.
Do not provide multiple types.
"""