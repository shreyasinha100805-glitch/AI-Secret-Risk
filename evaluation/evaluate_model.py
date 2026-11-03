
"""
AI-Secret-Risk Model Evaluation

CSV format:
    code,label,type

Predictions are generated from source code only.
Expected labels and types are used only for evaluation.
"""

import csv
import re
import sys
from pathlib import Path


# =========================================================
# PROJECT PATHS AND IMPORTS
# =========================================================

PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from detection.candidate_extractor import extract_candidates
from detection.context_detector import (
    classify_context,
    extract_variable_name
)

from evaluation.metrics import (
    calculate_metrics,
    print_metrics
)


DATASET_PATH = PROJECT_ROOT / "dataset" / "test_cases.csv"


# =========================================================
# VALID CLASSIFICATIONS
# =========================================================

VALID_CLASSIFICATIONS = {
    "REAL_SECRET",
    "PLACEHOLDER",
    "NOT_SECRET",
    "UNKNOWN",
}


# =========================================================
# SECRET TYPE NORMALIZATION
# =========================================================

TYPE_ALIASES = {
    "APIKEY": "API_KEY",
    "API-KEY": "API_KEY",
    "SECRET": "GENERIC_SECRET",
    "CREDENTIAL": "GENERIC_SECRET",
    "CREDENTIALS": "GENERIC_SECRET",
    "AUTHORIZATION": "TOKEN",
    "NONE": "OTHER",
}


VALID_TYPES = {
    "API_KEY",
    "PASSWORD",
    "TOKEN",
    "PRIVATE_KEY",
    "GENERIC_SECRET",
    "OTHER",
    "UNKNOWN",
}


# =========================================================
# NORMALIZATION FUNCTIONS
# =========================================================

def normalize_classification(value):

    classification = str(
        value or "UNKNOWN"
    ).strip().upper()

    if classification == "FALSE_POSITIVE":
        classification = "NOT_SECRET"

    if classification not in VALID_CLASSIFICATIONS:
        return "UNKNOWN"

    return classification


def normalize_type(value):

    secret_type = str(
        value or "UNKNOWN"
    ).strip().upper()

    secret_type = TYPE_ALIASES.get(
        secret_type,
        secret_type
    )

    if secret_type not in VALID_TYPES:
        return "UNKNOWN"

    return secret_type


# =========================================================
# REDACT CANDIDATE VALUES
# =========================================================

def redact_value(value):
    """
    Avoid printing complete candidate values
    in evaluation logs.
    """

    if not value:
        return "<empty>"

    return f"<redacted; length={len(str(value))}>"


# =========================================================
# SECRET TYPE INFERENCE
# =========================================================

def infer_secret_type(
    candidate,
    source_code,
    llm_type="UNKNOWN"
):
    """
    Predict the secret type using detected candidate
    information and source-code variable names.

    IMPORTANT:
    Expected CSV type is never used here.
    """

    detected_type = str(
        candidate.get("type", "unknown")
    ).strip().lower()

    detected_type_map = {

        "api_key": "API_KEY",

        "password": "PASSWORD",

        "token": "TOKEN",

        "private_key": "PRIVATE_KEY",

        "secret": "GENERIC_SECRET",

        "credential": "GENERIC_SECRET",

        "authorization": "TOKEN",
    }

    if detected_type in detected_type_map:

        return detected_type_map[detected_type]

    candidate_value = str(
        candidate.get("value", "")
    )

    variable_name = extract_variable_name(
        source_code,
        candidate_value
    ).lower()

    normalized_name = variable_name.replace(
        "-",
        "_"
    )

    # More specific patterns first.

    if re.search(
        r"(^|_)(private[_]?key)(_|$)",
        normalized_name
    ):
        return "PRIVATE_KEY"

    if re.search(
        r"(^|_)(api[_]?key|apikey|key)(_|$)",
        normalized_name
    ):
        return "API_KEY"

    if re.search(
        r"(^|_)(password|passwd|pwd)(_|$)",
        normalized_name
    ):
        return "PASSWORD"

    if re.search(
        r"(^|_)(token)(_|$)",
        normalized_name
    ):
        return "TOKEN"

    if re.search(
        r"(^|_)(secret|credential|credentials)(_|$)",
        normalized_name
    ):
        return "GENERIC_SECRET"

    if re.search(
        r"(^|_)(authorization|bearer)(_|$)",
        normalized_name
    ):
        return "TOKEN"

    non_secret_names = {
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
        "username",
    }

    if normalized_name in non_secret_names:
        return "OTHER"

    # Use the LLM type only when source-code
    # information does not reveal the type.

    llm_normalized = normalize_type(llm_type)

    if llm_normalized != "UNKNOWN":
        return llm_normalized

    return "UNKNOWN"


# =========================================================
# CLASSIFY INDIVIDUAL CANDIDATE
# =========================================================

def classify_candidate(
    candidate,
    source_code,
    classifier_holder
):
    """
    First use the context detector.
    Use the LLM only when classification is UNKNOWN.
    """

    context_result = candidate.get(
        "context_result"
    )

    if not isinstance(context_result, dict):

        context_result = classify_context(
            candidate,
            source_code
        )

        candidate["context_result"] = context_result

    context_classification = normalize_classification(
        context_result.get("classification")
        if context_result
        else "UNKNOWN"
    )

    # -----------------------------------------------------
    # RULE-BASED CLASSIFICATION
    # -----------------------------------------------------

    if context_classification != "UNKNOWN":

        result = {
            "classification": context_classification,
            "type": candidate.get("type", "UNKNOWN"),
            "confidence": context_result.get("confidence"),
            "reason": context_result.get("reason", ""),
        }

    # -----------------------------------------------------
    # LLM FALLBACK
    # -----------------------------------------------------

    else:

        # Load the model only once.
        if classifier_holder[0] is None:

            from llm.classifier import SecretClassifier

            classifier_holder[0] = SecretClassifier()

        result = classifier_holder[0].classify(
            candidate=candidate,
            context=source_code
        )

    # -----------------------------------------------------
    # FINAL PREDICTION
    # -----------------------------------------------------

    prediction = {

        "classification": normalize_classification(
            result.get(
                "classification",
                "UNKNOWN"
            )
        ),

        "confidence": result.get("confidence"),

        "reason": result.get("reason", ""),

        "type": infer_secret_type(
            candidate,
            source_code,
            result.get("type", "UNKNOWN")
        ),

        "candidate": candidate,
    }

    return prediction


# =========================================================
# PREDICT COMPLETE SOURCE-CODE SAMPLE
# =========================================================

def predict_sample(
    source_code,
    classifier_holder
):
    """
    Predict a sample without accessing its
    expected classification or type.
    """

    candidates = extract_candidates(
        source_code
    )

    # No suspicious candidates detected.

    if not candidates:

        return {
            "classification": "NOT_SECRET",
            "type": "OTHER",
            "confidence": 1.0,
            "reason": (
                "No candidate was detected by "
                "the configured detectors."
            ),
            "candidate_count": 0,
            "candidate_predictions": [],
            "type_is_unambiguous": True,
        }

    # Classify all detected candidates.

    candidate_predictions = [

        classify_candidate(
            candidate,
            source_code,
            classifier_holder
        )

        for candidate in candidates
    ]

    # -----------------------------------------------------
    # SAMPLE-LEVEL CLASSIFICATION PRIORITY
    # -----------------------------------------------------

    priority = {

        "NOT_SECRET": 0,

        "UNKNOWN": 1,

        "PLACEHOLDER": 2,

        "REAL_SECRET": 3,
    }

    selected = max(
        candidate_predictions,
        key=lambda item: priority[
            item["classification"]
        ]
    )

    return {

        "classification": selected["classification"],

        "type": selected["type"],

        "confidence": selected["confidence"],

        "reason": selected["reason"],

        "candidate_count": len(candidates),

        "candidate_predictions": candidate_predictions,

        "type_is_unambiguous": len(candidates) == 1,
    }


# =========================================================
# LOAD DATASET
# =========================================================

def load_dataset(dataset_path):

    if not dataset_path.exists():

        raise FileNotFoundError(
            f"Dataset not found: {dataset_path}"
        )

    with dataset_path.open(
        "r",
        encoding="utf-8-sig",
        newline=""
    ) as file:

        reader = csv.DictReader(file)

        required_columns = {
            "code",
            "label",
            "type",
        }

        actual_columns = set(
            reader.fieldnames or []
        )

        missing = required_columns - actual_columns

        if missing:

            raise ValueError(
                "CSV is missing required columns: "
                + ", ".join(sorted(missing))
            )

        rows = []

        for line_number, row in enumerate(
            reader,
            start=2
        ):

            code = (
                row.get("code") or ""
            ).strip()

            label = normalize_classification(
                row.get("label")
            )

            secret_type = normalize_type(
                row.get("type")
            )

            if not code:

                raise ValueError(
                    f"Empty code in CSV row {line_number}"
                )

            if not (row.get("label") or "").strip():

                raise ValueError(
                    f"Missing label in CSV row {line_number}"
                )

            if not (row.get("type") or "").strip():

                raise ValueError(
                    f"Missing type in CSV row {line_number}"
                )

            rows.append({

                "code": code,

                "label": label,

                "type": secret_type,

                "line_number": line_number,
            })

    if not rows:

        raise ValueError(
            "The test dataset contains no records."
        )

    return rows


# =========================================================
# MAIN EVALUATION FUNCTION
# =========================================================

def main():

    print("=" * 72)

    print("AI-SECRET-RISK: MODEL EVALUATION")

    print("=" * 72)

    print(f"Dataset: {DATASET_PATH}")

    rows = load_dataset(DATASET_PATH)

    print(
        f"Loaded {len(rows)} test samples.\n"
    )

    # Shared holder to initialize LLM only once.

    classifier_holder = [None]

    classification_true = []

    classification_predicted = []

    type_true = []

    type_predicted = []

    type_skipped = 0

    # -----------------------------------------------------
    # PROCESS EACH TEST SAMPLE
    # -----------------------------------------------------

    for index, row in enumerate(
        rows,
        start=1
    ):

        prediction = predict_sample(
            row["code"],
            classifier_holder
        )

        expected_class = row["label"]

        predicted_class = prediction[
            "classification"
        ]

        # Classification evaluation.

        classification_true.append(
            expected_class
        )

        classification_predicted.append(
            predicted_class
        )

        # Type evaluation.

        # Multiple candidates in a single sample make
        # type evaluation ambiguous with this CSV format.

        if prediction["type_is_unambiguous"]:

            type_true.append(
                row["type"]
            )

            type_predicted.append(
                normalize_type(
                    prediction["type"]
                )
            )

        else:

            type_skipped += 1

        status = (
            "CORRECT"
            if expected_class == predicted_class
            else "WRONG"
        )

        print(f"[{index:02d}] {status}")

        print(
            f"     Expected classification : {expected_class}"
        )

        print(
            f"     Predicted classification: {predicted_class}"
        )

        print(
            f"     Expected secret type    : {row['type']}"
        )

        if prediction["type_is_unambiguous"]:

            print(
                "     Predicted secret type   : "
                f"{normalize_type(prediction['type'])}"
            )

        else:

            print(
                "     Predicted secret type   : "
                "skipped (multiple candidates)"
            )

        print(
            f"     Candidates detected    : "
            f"{prediction['candidate_count']}"
        )

        print(
            f"     Confidence              : "
            f"{prediction['confidence']}"
        )

        print(
            f"     Reason                  : "
            f"{prediction['reason']}"
        )

        # Print only redacted candidate values.

        for candidate_prediction in prediction[
            "candidate_predictions"
        ]:

            candidate = candidate_prediction[
                "candidate"
            ]

            print(
                "     Candidate               : "
                f"{redact_value(candidate.get('value', ''))}"
                f" | method={candidate.get('method', 'unknown')}"
                f" | predicted={candidate_prediction['classification']}"
            )

        print()

    # -----------------------------------------------------
    # CLASSIFICATION METRICS
    # -----------------------------------------------------

    classification_metrics = calculate_metrics(
        classification_true,
        classification_predicted
    )

    print_metrics(
        "CLASSIFICATION METRICS",
        classification_metrics
    )

    # -----------------------------------------------------
    # SECRET TYPE METRICS
    # -----------------------------------------------------

    type_metrics = calculate_metrics(
        type_true,
        type_predicted
    )

    print_metrics(
        "SECRET-TYPE METRICS",
        type_metrics
    )

    # -----------------------------------------------------
    # FINAL SUMMARY
    # -----------------------------------------------------

    print("\n" + "=" * 72)

    print("EVALUATION SUMMARY")

    print("=" * 72)

    classification_correct = sum(
        actual == predicted
        for actual, predicted in zip(
            classification_true,
            classification_predicted
        )
    )

    print(
        f"Classification accuracy: "
        f"{classification_metrics['accuracy'] * 100:.2f}% "
        f"({classification_correct}/{len(classification_true)})"
    )

    if type_true:

        type_correct = sum(
            actual == predicted
            for actual, predicted in zip(
                type_true,
                type_predicted
            )
        )

        print(
            f"Secret-type accuracy   : "
            f"{type_correct / len(type_true) * 100:.2f}% "
            f"({type_correct}/{len(type_true)})"
        )

    else:

        print(
            "Secret-type accuracy   : not available"
        )

    print(
        "Rows excluded from type accuracy due to "
        f"multiple candidates: {type_skipped}"
    )

    print(
        "Expected labels/types are used only "
        "after prediction, for scoring."
    )

    print("=" * 72)


# =========================================================
# PROGRAM ENTRY POINT
# =========================================================

if __name__ == "__main__":

    try:

        main()

    except (
        FileNotFoundError,
        ValueError,
        KeyError
    ) as error:

        print(
            f"Evaluation error: {error}"
        )

        raise SystemExit(1)
