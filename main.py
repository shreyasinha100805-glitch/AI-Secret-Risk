from detection.candidate_extractor import extract_candidates
from detection.context_extractor import extract_line_context
from llm.classifier import SecretClassifier


def scan_source_code(code):

    print("\n" + "=" * 60)
    print("AI SECRET DETECTION SYSTEM")
    print("=" * 60)

    # ==========================================
    # STEP 1: Candidate Detection
    # ==========================================

    candidates = extract_candidates(code)

    print(f"\nCandidates detected: {len(candidates)}")

    if not candidates:
        print("\nNo suspicious candidates found.")
        return

    # ==========================================
    # STEP 2: Load LLM once
    # ==========================================

    classifier = SecretClassifier()

    # ==========================================
    # STEP 3: Analyze candidates
    # ==========================================

    for number, candidate in enumerate(candidates, start=1):

        print("\n" + "-" * 60)
        print(f"CANDIDATE {number}")
        print("-" * 60)

        # ------------------------------------------
        # Candidate information
        # ------------------------------------------

        value = candidate.get("value", "")
        method = candidate.get("method", "unknown")
        detected_type = candidate.get("type", "unknown")
        entropy = candidate.get("entropy")

        print("Detected Value:", value)
        print("Detection Method:", method)
        print("Detected Type:", detected_type)
        print("Entropy:", entropy)

        # ------------------------------------------
        # Get source position
        # ------------------------------------------

        start = candidate.get("start", 0)
        end = candidate.get("end", start)

        # ------------------------------------------
        # Extract context
        # ------------------------------------------

        context = extract_line_context(
            code,
            start,
            end,
            lines_before=4,
            lines_after=4
        )

        print("\nContext:")
        print(context)

        # ------------------------------------------
        # LLM Classification
        # ------------------------------------------

        try:

            result = classifier.classify(
                candidate,
                context
            )

        except Exception as error:

            print("\nLLM ERROR:")
            print(error)
            continue

        # ------------------------------------------
        # Display result
        # ------------------------------------------

        print("\nLLM RESULT:")

        print(
            "Classification:",
            result.get("classification", "UNKNOWN")
        )

        print(
            "Type:",
            result.get("type", "UNKNOWN")
        )

        print(
            "Confidence:",
            result.get("confidence", 0.0)
        )

        print(
            "Reason:",
            result.get("reason", "")
        )


# ==================================================
# TEST CODE
# ==================================================

if __name__ == "__main__":

    sample_code = '''
import os

API_KEY = "sk_test_123456789012345678"

password = "mySecretPassword123"

token = "x7F9kP2mL8Q4wZ6rT1"

session_id = "x7F9kP2mL8Q4wZ6rT1"

message = "hello world"

client = APIClient(
    api_key=API_KEY
)

response = client.get_data()
'''

    scan_source_code(sample_code)