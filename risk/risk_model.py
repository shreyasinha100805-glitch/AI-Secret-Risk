
"""Heuristic risk scoring for detected source-code candidates."""

from typing import Any, Dict, Optional
import math
import re

from risk.severity import get_severity


# Initial configurable secret-type risk scores.
TYPE_RISK_SCORES = {
    "PRIVATE_KEY": 100.0,
    "DATABASE_CREDENTIAL": 95.0,
    "API_KEY": 90.0,
    "PASSWORD": 85.0,
    "TOKEN": 80.0,
    "GENERIC_SECRET": 70.0,
    "UNKNOWN": 50.0,
    "OTHER": 0.0,
}

TYPE_ALIASES = {
    "APIKEY": "API_KEY",
    "API-KEY": "API_KEY",
    "SECRET": "GENERIC_SECRET",
    "CREDENTIAL": "GENERIC_SECRET",
    "CREDENTIALS": "GENERIC_SECRET",
    "AUTHORIZATION": "TOKEN",
    "BEARER": "TOKEN",
    "DB_PASSWORD": "PASSWORD",
    "DATABASE_PASSWORD": "PASSWORD",
    "PRIVATEKEY": "PRIVATE_KEY",
    "NONE": "UNKNOWN",
}

# Weighted risk-scoring formula.
WEIGHTS = {
    "secret_type": 0.60,
    "confidence": 0.25,
    "entropy": 0.15,
}


def _normalise_classification(value: Any) -> str:
    result = str(value or "UNKNOWN").strip().upper()

    if result == "FALSE_POSITIVE":
        return "NOT_SECRET"

    valid = {
        "REAL_SECRET",
        "PLACEHOLDER",
        "NOT_SECRET",
        "UNKNOWN"
    }

    return result if result in valid else "UNKNOWN"


def _normalise_type(value: Any) -> str:
    result = str(value or "UNKNOWN").strip().upper()
    result = TYPE_ALIASES.get(result, result)

    return (
        result
        if result in TYPE_RISK_SCORES
        else "UNKNOWN"
    )


def _safe_confidence(value: Any) -> float:
    """Normalize confidence to the range 0 to 1."""

    try:
        confidence = float(value)
    except (TypeError, ValueError):
        return 0.50

    if confidence > 1.0:
        confidence /= 100.0

    return max(0.0, min(1.0, confidence))


def _infer_type(
    candidate: Dict[str, Any],
    result: Dict[str, Any],
    context: str
) -> str:
    """Infer canonical secret type from available information."""

    result_type = _normalise_type(
        result.get("type")
    )

    if result_type != "UNKNOWN":
        return result_type

    candidate_type = _normalise_type(
        candidate.get("type")
    )

    if candidate_type != "UNKNOWN":
        return candidate_type

    # Infer from the variable name for entropy candidates.
    value = str(candidate.get("value", "")).strip()

    if value and context:

        escaped = re.escape(value)

        patterns = [
            rf"\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*['\"]{escaped}['\"]",

            rf"\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*['\"]Bearer\s+{escaped}['\"]",
        ]

        variable_name = ""

        for pattern in patterns:

            match = re.search(
                pattern,
                context,
                re.IGNORECASE
            )

            if match:
                variable_name = match.group(1).lower()
                break

        name = variable_name.replace("-", "_")

        if re.search(r"(^|_)private_?key($|_)", name):
            return "PRIVATE_KEY"

        if re.search(r"(^|_)(api_?key|apikey|key)($|_)", name):
            return "API_KEY"

        if re.search(
            r"(^|_)(database_?password|db_?password|password|passwd|pwd)($|_)",
            name
        ):
            return "PASSWORD"

        if re.search(
            r"(^|_)(token|access_token|auth_token|refresh_token|id_token)($|_)",
            name
        ):
            return "TOKEN"

        if re.search(
            r"(^|_)(secret|credential|credentials)($|_)",
            name
        ):
            return "GENERIC_SECRET"

        if re.search(
            r"(^|_)(authorization|bearer)($|_)",
            name
        ):
            return "TOKEN"

        non_secret_names = {
            "data", "value", "values",
            "random_value", "user_id",
            "id", "identifier", "session_id",
            "request_id", "transaction_id",
            "record_id", "trace_id",
            "message", "text", "content",
            "name", "description", "username"
        }

        if name in non_secret_names:
            return "OTHER"

    return "UNKNOWN"


def _calculate_shannon_entropy(value: str) -> float:
    """Calculate Shannon entropy of a string."""

    if not value:
        return 0.0

    length = len(value)
    frequencies = {}

    for character in value:
        frequencies[character] = (
            frequencies.get(character, 0) + 1
        )

    entropy = 0.0

    for count in frequencies.values():

        probability = count / length

        entropy -= (
            probability * math.log2(probability)
        )

    return entropy


def _entropy_value(candidate: Dict[str, Any]) -> float:
    """Use stored entropy or calculate it when unavailable."""

    raw_entropy = candidate.get("entropy")

    try:

        if raw_entropy is not None:
            entropy = float(raw_entropy)

        else:
            entropy = _calculate_shannon_entropy(
                str(candidate.get("value", ""))
            )

    except (TypeError, ValueError):

        entropy = 0.0

    return max(0.0, entropy)


def calculate_risk_score(
    candidate: Dict[str, Any],
    classification_result: Optional[Dict[str, Any]] = None,
    context: str = "",
) -> Dict[str, Any]:
    """
    Calculate a risk score between 0 and 100.

    PLACEHOLDER and NOT_SECRET are excluded.
    UNKNOWN requires manual review.
    """

    if not isinstance(candidate, dict):
        raise TypeError("candidate must be a dictionary")

    result = (
        classification_result
        or candidate.get("context_result")
        or {}
    )

    if not isinstance(result, dict):
        result = {}

    classification = _normalise_classification(
        result.get("classification")
    )

    secret_type = _infer_type(
        candidate,
        result,
        context
    )

    confidence = _safe_confidence(
        result.get("confidence")
    )

    entropy = _entropy_value(candidate)

    # Normalize entropy to a 0-100 heuristic scale.
    entropy_score = min(
        100.0,
        (entropy / 5.0) * 100.0
    )

    type_score = TYPE_RISK_SCORES[secret_type]

    confidence_score = confidence * 100.0

    # Exclude non-secret candidates.
    if classification in {"PLACEHOLDER", "NOT_SECRET"}:

        return {
            "classification": classification,
            "secret_type": secret_type,
            "risk_score": 0.0,
            "severity": "NOT_APPLICABLE",
            "status": "EXCLUDED",

            "risk_factors": {
                "secret_type_score": round(type_score, 2),
                "confidence_score": round(confidence_score, 2),
                "entropy_score": round(entropy_score, 2),
                "entropy_bits_per_character": round(entropy, 3),
            },

            "reason": (
                "The candidate is classified as a placeholder "
                "or non-secret, so confirmed-secret risk scoring "
                "is not applied."
            )
        }

    # Weighted risk calculation.
    score = (
        WEIGHTS["secret_type"] * type_score
        + WEIGHTS["confidence"] * confidence_score
        + WEIGHTS["entropy"] * entropy_score
    )

    score = round(
        max(0.0, min(100.0, score)),
        2
    )

    severity = get_severity(score)

    if classification == "UNKNOWN":

        status = "REVIEW_REQUIRED"

        reason = (
            "Preliminary risk score only: classification is "
            "UNKNOWN. A human reviewer should verify the "
            "candidate before treating it as a confirmed secret."
        )

    else:

        status = "ASSESSED"

        reason = (
            "Risk score combines secret-type risk (60%), "
            "classification confidence (25%), and normalized "
            "Shannon entropy (15%)."
        )

    return {
        "classification": classification,
        "secret_type": secret_type,
        "risk_score": score,
        "severity": severity,
        "status": status,

        "risk_factors": {
            "secret_type_score": round(type_score, 2),
            "confidence_score": round(confidence_score, 2),
            "entropy_score": round(entropy_score, 2),
            "entropy_bits_per_character": round(entropy, 3),
            "weights": WEIGHTS.copy(),
        },

        "reason": reason
    }


def assess_risk(
    candidate: Dict[str, Any],
    classification_result: Optional[Dict[str, Any]] = None,
    context: str = ""
) -> Dict[str, Any]:

    return calculate_risk_score(
        candidate,
        classification_result,
        context
    )
