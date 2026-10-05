import csv
import sys
import os

# ============================================================
# PROJECT ROOT
# ============================================================

PROJECT_ROOT = os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))
)

sys.path.append(PROJECT_ROOT)


# ============================================================
# IMPORT PROJECT MODULES
# ============================================================

from detection.candidate_extractor import extract_candidates
from detection.context_detector import classify_context
from llm.classifier import SecretClassifier


# ============================================================
# FIND MATCHING CANDIDATE
# ============================================================

def find_matching_candidate(code, expected_type):
    """
    Extract candidates from the source code and return the
    candidate matching the expected secret type.

    If no exact type match is found, return the first candidate.
    """

    candidates = extract_candidates(code)

    if not candidates:
        return None

    expected_type = expected_type.lower().strip()

    # --------------------------------------------------------
    # Try exact type match
    # --------------------------------------------------------

    for candidate in candidates:

        candidate_type = str(
            candidate.get("type", "")
        ).lower().strip()

        if candidate_type == expected_type:
            return candidate

    # --------------------------------------------------------
    # No exact match
    # --------------------------------------------------------

    return candidates[0]


# ============================================================
# MAIN EVALUATION
# ============================================================

def main():

    print("=" * 60)
    print("AI SECRET RISK MODEL EVALUATION")
    print("=" * 60)

    # --------------------------------------------------------
    # Load LLM
    # --------------------------------------------------------

    classifier = SecretClassifier()

    # --------------------------------------------------------
    # Test dataset
    # --------------------------------------------------------

    test_file = os.path.join(
        PROJECT_ROOT,
        "dataset",
        "test_cases.csv"
    )

    total = 0
    correct = 0

    print("\nLoading test dataset...\n")

    # ========================================================
    # READ CSV
    # ========================================================

    with open(
        test_file,
        "r",
        encoding="utf-8"
    ) as file:

        reader = csv.DictReader(file)

        for row in reader:

            total += 1

            code = row["code"]
            expected = row["label"].strip()
            expected_type = row["type"].strip()

            print("\n" + "-" * 60)
            print(f"TEST CASE: {total}")
            print("-" * 60)

            print("\nCode:")
            print(code)

            # =================================================
            # STEP 1: EXTRACT CANDIDATE
            # =================================================

            candidate = find_matching_candidate(
                code,
                expected_type
            )

            # -------------------------------------------------
            # No candidate found
            # -------------------------------------------------

            if candidate is None:

                print("\nNo candidate detected.")

                predicted = "NOT_SECRET"
                predicted_type = "OTHER"
                confidence = 0.90
                reason = (
                    "No suspicious secret candidate was detected "
                    "in the source code."
                )

            else:

                # =================================================
                # STEP 2: DISPLAY CANDIDATE
                # =================================================

                print("\nDetected Candidate:")
                print(
                    candidate.get(
                        "value",
                        ""
                    )
                )

                print(
                    "Detected Type:",
                    candidate.get(
                        "type",
                        "unknown"
                    )
                )

                print(
                    "Detection Method:",
                    candidate.get(
                        "method",
                        "unknown"
                    )
                )

                print(
                    "Entropy:",
                    candidate.get(
                        "entropy",
                        None
                    )
                )

                # =================================================
                # STEP 3: CONTEXT DETECTION
                # =================================================

                try:

                    context_result = classify_context(
                        candidate,
                        code
                    )

                except TypeError:

                    # Compatibility with versions where
                    # classify_context expects different arguments.

                    context_result = classify_context(
                        candidate.get("value", ""),
                        code
                    )

                print("\nContext Detector Result:")
                print(context_result)

                # =================================================
                # STEP 4: ATTACH CONTEXT RESULT
                # =================================================

                if context_result is not None:

                    candidate["context_result"] = (
                        context_result
                    )

                # =================================================
                # STEP 5: LLM CLASSIFICATION
                # =================================================

                result = classifier.classify(
                    candidate=candidate,
                    context=code
                )

                # =================================================
                # STEP 6: GET RESULT
                # =================================================

                predicted = result.get(
                    "classification",
                    "UNKNOWN"
                )

                predicted_type = result.get(
                    "type",
                    "UNKNOWN"
                )

                confidence = result.get(
                    "confidence",
                    None
                )

                reason = result.get(
                    "reason",
                    ""
                )

            # =================================================
            # DISPLAY RESULTS
            # =================================================

            print("\nExpected:")
            print(expected)

            print("Predicted:")
            print(predicted)

            print("Expected Type:")
            print(expected_type)

            print("Predicted Type:")
            print(predicted_type)

            print("Confidence:")
            print(confidence)

            print("Reason:")
            print(reason)

            # =================================================
            # COMPARE
            # =================================================

            if predicted.upper() == expected.upper():

                correct += 1

                print("\nResult: CORRECT")

            else:

                print("\nResult: WRONG")

                print("\n❌ WRONG PREDICTION")

                print(
                    "Code:",
                    code
                )

                print(
                    "Expected:",
                    expected
                )

                print(
                    "Predicted:",
                    predicted
                )

                print(
                    "Expected Type:",
                    expected_type
                )

                print(
                    "Predicted Type:",
                    predicted_type
                )

    # ========================================================
    # FINAL RESULTS
    # ========================================================

    if total > 0:

        accuracy = correct / total

    else:

        accuracy = 0

    print("\n" + "=" * 60)
    print("FINAL RESULTS")
    print("=" * 60)

    print(
        "Total test cases :",
        total
    )

    print(
        "Correct          :",
        correct
    )

    print(
        "Wrong            :",
        total - correct
    )

    print(
        "Accuracy         :",
        round(
            accuracy * 100,
            2
        ),
        "%"
    )

    print("=" * 60)


# ============================================================
# RUN
# ============================================================

if __name__ == "__main__":

    main()