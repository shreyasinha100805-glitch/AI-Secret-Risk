from detection.candidate_extractor import extract_candidates
from detection.context_extractor import extract_line_context


# ==================================================
# CONFIGURATION
# ==================================================

# True = use LLM only when Context Detector says UNKNOWN
USE_LLM_FOR_UNKNOWN = True


# ==================================================
# MAIN SCANNER
# ==================================================

def scan_source_code(code):

    print("\n" + "=" * 60, flush=True)
    print("AI SECRET DETECTION SYSTEM", flush=True)
    print("=" * 60, flush=True)

    # ==========================================
    # STEP 1: Candidate Detection
    # ==========================================

    candidates = extract_candidates(code)

    print(
        f"\nCandidates detected: {len(candidates)}",
        flush=True
    )

    if not candidates:
        print("\nNo suspicious candidates found.", flush=True)
        return

    # ==========================================
    # LLM is NOT loaded here
    # ==========================================

    classifier = None

    # ==========================================
    # STEP 2: Analyze Candidates
    # ==========================================

    for number, candidate in enumerate(candidates, start=1):

        print("\n" + "-" * 60, flush=True)
        print(f"CANDIDATE {number}", flush=True)
        print("-" * 60, flush=True)

        # ------------------------------------------
        # Candidate information
        # ------------------------------------------

        value = candidate.get("value", "")
        method = candidate.get("method", "unknown")
        detected_type = candidate.get("type", "unknown")
        entropy = candidate.get("entropy")

        print("Detected Value:", value, flush=True)
        print("Detection Method:", method, flush=True)
        print("Detected Type:", detected_type, flush=True)
        print("Entropy:", entropy, flush=True)

        # ------------------------------------------
        # Source position
        # ------------------------------------------

        start = candidate.get("start", 0)
        end = candidate.get("end", start)

        # ------------------------------------------
        # Context Extraction
        # ------------------------------------------

        context = extract_line_context(
            code,
            start,
            end,
            lines_before=4,
            lines_after=4
        )

        print("\nContext:", flush=True)
        print(context, flush=True)

        # ==========================================
        # STEP 3: Context Detector Result
        # ==========================================

        context_result = candidate.get("context_result")

        if context_result:

            context_classification = context_result.get(
                "classification",
                "UNKNOWN"
            )

            context_confidence = context_result.get(
                "confidence",
                0.0
            )

            context_reason = context_result.get(
                "reason",
                ""
            )

        else:

            context_classification = "UNKNOWN"
            context_confidence = 0.0
            context_reason = ""

        print("\nCONTEXT DETECTOR RESULT:", flush=True)
        print(
            "Classification:",
            context_classification,
            flush=True
        )
        print(
            "Confidence:",
            context_confidence,
            flush=True
        )
        print(
            "Reason:",
            context_reason,
            flush=True
        )

        # ==========================================
        # STEP 4: Decide Whether LLM is Needed
        # ==========================================

        if context_classification != "UNKNOWN":

            # Context detector already made a decision.
            result = {
                "classification": context_classification,
                "type": detected_type,
                "confidence": context_confidence,
                "reason": context_reason
            }

            print(
                "\nLLM STATUS: Not required",
                flush=True
            )

        elif not USE_LLM_FOR_UNKNOWN:

            result = {
                "classification": "UNKNOWN",
                "type": detected_type,
                "confidence": 0.50,
                "reason": "Context detector could not determine the classification."
            }

            print(
                "\nLLM STATUS: Disabled",
                flush=True
            )

        else:

            # ==========================================
            # STEP 5: Load LLM ONLY WHEN REQUIRED
            # ==========================================

            if classifier is None:

                print(
                    "\nLoading LLM for UNKNOWN candidate...",
                    flush=True
                )

                try:

                    from llm.classifier import SecretClassifier

                    classifier = SecretClassifier()

                    print(
                        "LLM loaded successfully.",
                        flush=True
                    )

                except Exception as error:

                    print(
                        "\nLLM LOAD ERROR:",
                        flush=True
                    )

                    print(
                        error,
                        flush=True
                    )

                    result = {
                        "classification": "UNKNOWN",
                        "type": detected_type,
                        "confidence": 0.0,
                        "reason": "LLM could not be loaded."
                    }

                    classifier = None

                    continue

            # ==========================================
            # LLM Classification
            # ==========================================

            try:

                result = classifier.classify(
                    candidate,
                    context
                )

            except Exception as error:

                print(
                    "\nLLM ERROR:",
                    flush=True
                )

                print(
                    error,
                    flush=True
                )

                result = {
                    "classification": "UNKNOWN",
                    "type": detected_type,
                    "confidence": 0.0,
                    "reason": str(error)
                }

        # ==========================================
        # STEP 6: Final Result
        # ==========================================

        print("\n" + "=" * 60, flush=True)
        print("FINAL RESULT", flush=True)
        print("=" * 60, flush=True)

        print(
            "Classification:",
            result.get("classification", "UNKNOWN"),
            flush=True
        )

        print(
            "Type:",
            result.get("type", detected_type),
            flush=True
        )

        print(
            "Confidence:",
            result.get("confidence", 0.0),
            flush=True
        )

        print(
            "Reason:",
            result.get("reason", ""),
            flush=True
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

data = "aB7xP91LmQ2zK84R"

client = APIClient(
    api_key=API_KEY
)

response = client.get_data()
'''

    scan_source_code(sample_code)