
"""Severity classification for risk scores."""

SEVERITY_THRESHOLDS = {
    "LOW": (0.0, 29.999),
    "MEDIUM": (30.0, 49.999),
    "HIGH": (50.0, 79.999),
    "CRITICAL": (80.0, 100.0),
}


def get_severity(score: float) -> str:
    """Convert a risk score into a severity level."""

    try:
        numeric_score = float(score)

    except (TypeError, ValueError) as exc:

        raise ValueError(
            "Risk score must be a number between 0 and 100."
        ) from exc

    if not 0.0 <= numeric_score <= 100.0:

        raise ValueError(
            "Risk score must be between 0 and 100."
        )

    for severity, (lower, upper) in SEVERITY_THRESHOLDS.items():
        if lower <= numeric_score <= upper:
            return severity

    raise ValueError("Risk score is out of bounds.")
    if numeric_score < 80.0:
        return "HIGH"

    return "CRITICAL"


def get_severity_label(score: float) -> str:
    """Backward-compatible severity function."""

    return get_severity(score)
