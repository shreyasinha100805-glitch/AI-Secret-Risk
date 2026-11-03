"""AI-Secret-Risk command-line scanner.

Pipeline:
    source code -> regex/entropy candidates -> context rules -> LLM fallback
    -> risk score -> severity summary

Candidate values are redacted from terminal output.
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Dict, List, Optional

from detection.candidate_extractor import extract_candidates
from detection.context_extractor import extract_line_context
from risk.risk_model import calculate_risk_score


VALID_CLASSIFICATIONS = {
    "REAL_SECRET",
    "PLACEHOLDER",
    "NOT_SECRET",
    "UNKNOWN",
}


def normalize_classification(value: Any) -> str:
    """Normalize model output to a supported classification."""
    classification = str(value or "UNKNOWN").strip().upper()
    if classification == "FALSE_POSITIVE":
        classification = "NOT_SECRET"
    return (
        classification
        if classification in VALID_CLASSIFICATIONS
        else "UNKNOWN"
    )


def redact_text(text: Any, secret_values: List[str]) -> str:
    """Remove detected candidate values from text before printing."""
    safe_text = str(text or "")
    for secret in sorted(
        (str(value) for value in secret_values if value),
        key=len,
        reverse=True,
    ):
        safe_text = safe_text.replace(secret, "<REDACTED>")
    return safe_text


def _load_classifier():
    """Load the LLM classifier lazily, only if UNKNOWN needs it."""
    from llm.classifier import SecretClassifier

    return SecretClassifier()


def _print_risk_result(risk_result: Dict[str, Any]) -> None:
    print("\nRISK ASSESSMENT:", flush=True)
    print(f"Risk Score: {risk_result.get('risk_score', 0)}/100", flush=True)
    print(f"Severity: {risk_result.get('severity', 'UNKNOWN')}", flush=True)
    print(f"Assessment Status: {risk_result.get('status', 'UNKNOWN')}", flush=True)
    print(f"Risk Type: {risk_result.get('secret_type', 'UNKNOWN')}", flush=True)
    print(f"Risk Explanation: {risk_result.get('reason', '')}", flush=True)

    print("Risk Factors:", flush=True)
    for factor, value in risk_result.get("risk_factors", {}).items():
        print(f"  {factor}: {value}", flush=True)


def scan_source_code(
    code: str,
    source_name: str = "<memory>",
    use_llm: bool = True,
) -> List[Dict[str, Any]]:
    """Detect, classify, and risk-score candidates in source code."""
    if not isinstance(code, str):
        raise TypeError("code must be a string")

    print("\n" + "=" * 68, flush=True)
    print("AI SECRET DETECTION AND RISK ASSESSMENT", flush=True)
    print(f"Source: {source_name}", flush=True)
    print("=" * 68, flush=True)

    candidates = extract_candidates(code)
    print(f"\nCandidates detected: {len(candidates)}", flush=True)

    if not candidates:
        print("\nNo suspicious candidates found.", flush=True)
        print("No risk assessment was required.", flush=True)
        return []

    # Redact all candidates from the printed source context and explanations.
    candidate_values = [
        str(candidate.get("value", "")) for candidate in candidates
    ]

    classifier: Optional[Any] = None
    classifier_load_attempted = False
    final_results: List[Dict[str, Any]] = []

    for number, candidate in enumerate(candidates, start=1):
        value = str(candidate.get("value", ""))
        method = candidate.get("method", "unknown")
        detected_type = candidate.get("type", "unknown")
        entropy = candidate.get("entropy")

        print("\n" + "-" * 68, flush=True)
        print(f"CANDIDATE {number}", flush=True)
        print("-" * 68, flush=True)
        print(f"Detected Value: <redacted; length={len(value)}>", flush=True)
        print(f"Detection Method: {method}", flush=True)
        print(f"Detected Type: {detected_type}", flush=True)
        print(f"Entropy: {entropy}", flush=True)

        start = int(candidate.get("start", 0) or 0)
        end = int(candidate.get("end", start) or start)
        context = extract_line_context(
            code,
            start,
            end,
            lines_before=4,
            lines_after=4,
        )

        print("\nContext (candidate values redacted):", flush=True)
        print(redact_text(context, candidate_values), flush=True)

        # candidate_extractor normally attaches context_result. Recompute it
        # if it is absent or malformed so this scanner remains defensive.
        context_result = candidate.get("context_result")
        if not isinstance(context_result, dict):
            try:
                from detection.context_detector import classify_context
                context_result = classify_context(candidate, context) or {}
            except Exception as error:
                context_result = {
                    "classification": "UNKNOWN",
                    "confidence": 0.0,
                    "reason": f"Context analysis failed: {type(error).__name__}",
                }

        context_classification = normalize_classification(
            context_result.get("classification")
        )
        context_confidence = context_result.get("confidence", 0.0)
        context_reason = redact_text(
            context_result.get("reason", ""), candidate_values
        )

        print("\nCONTEXT DETECTOR RESULT:", flush=True)
        print(f"Classification: {context_classification}", flush=True)
        print(f"Confidence: {context_confidence}", flush=True)
        print(f"Reason: {context_reason}", flush=True)

        # Use deterministic context rules when they return a final class.
        if context_classification != "UNKNOWN":
            result = {
                "classification": context_classification,
                "type": detected_type,
                "confidence": context_confidence,
                "reason": context_reason,
            }
            print("\nLLM STATUS: Not required", flush=True)

        elif not use_llm:
            result = {
                "classification": "UNKNOWN",
                "type": detected_type,
                "confidence": 0.50,
                "reason": "LLM fallback is disabled; manual review is required.",
            }
            print("\nLLM STATUS: Disabled", flush=True)

        else:
            # Attempt loading once. If loading fails, do not repeatedly retry
            # for every remaining UNKNOWN candidate in this scan.
            if not classifier_load_attempted:
                classifier_load_attempted = True
                print("\nLoading LLM for UNKNOWN candidate...", flush=True)
                try:
                    classifier = _load_classifier()
                    print("LLM loaded successfully.", flush=True)
                except Exception as error:
                    classifier = None
                    print(
                        f"LLM LOAD ERROR: {type(error).__name__}: {error}",
                        flush=True,
                    )

            if classifier is None:
                result = {
                    "classification": "UNKNOWN",
                    "type": detected_type,
                    "confidence": 0.0,
                    "reason": "LLM unavailable; manual review is required.",
                }
            else:
                try:
                    llm_result = classifier.classify(candidate, context)
                    if not isinstance(llm_result, dict):
                        raise TypeError("LLM classifier returned a non-dictionary result")
                    result = llm_result
                except Exception as error:
                    result = {
                        "classification": "UNKNOWN",
                        "type": detected_type,
                        "confidence": 0.0,
                        "reason": f"LLM classification failed: {type(error).__name__}",
                    }
                    print(
                        f"LLM ERROR: {type(error).__name__}: {error}",
                        flush=True,
                    )

        # Normalize the LLM/rule result before scoring.
        result = dict(result)
        result["classification"] = normalize_classification(
            result.get("classification")
        )
        result.setdefault("type", detected_type)
        result.setdefault("confidence", 0.0)
        result["reason"] = redact_text(
            result.get("reason", ""), candidate_values
        )

        print("\nFINAL CLASSIFICATION:", flush=True)
        print(f"Classification: {result['classification']}", flush=True)
        print(f"Type: {result['type']}", flush=True)
        print(f"Confidence: {result['confidence']}", flush=True)
        print(f"Reason: {result['reason']}", flush=True)

        # Risk scoring is performed only after the final classification.
        risk_result = calculate_risk_score(
            candidate=candidate,
            classification_result=result,
            context=context,
        )
        _print_risk_result(risk_result)

        final_results.append({
            "candidate_number": number,
            "classification": result["classification"],
            "type": risk_result.get(
                "secret_type", result.get("type", detected_type)
            ),
            "confidence": result.get("confidence", 0.0),
            "reason": result["reason"],
            "risk": risk_result,
        })

    # Final scan summary.
    print("\n" + "=" * 68, flush=True)
    print("SCAN SUMMARY", flush=True)
    print("=" * 68, flush=True)

    severity_counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "NOT_APPLICABLE": 0,
    }
    review_required_count = 0

    for item in final_results:
        risk = item["risk"]
        severity = str(risk.get("severity", "UNKNOWN"))
        status = str(risk.get("status", "UNKNOWN"))

        if severity in severity_counts:
            severity_counts[severity] += 1
        if status == "REVIEW_REQUIRED":
            review_required_count += 1

        print(
            f"Candidate {item['candidate_number']}: "
            f"{item['classification']} | "
            f"Risk={risk.get('risk_score', 0):.2f} | "
            f"Severity={severity} | Status={status}",
            flush=True,
        )

    print("\nSeverity counts:", flush=True)
    for severity, count in severity_counts.items():
        print(f"  {severity}: {count}", flush=True)
    print(
        f"  Candidates requiring manual review: {review_required_count}",
        flush=True,
    )

    return final_results


def scan_file(file_path: Path, use_llm: bool = True) -> List[Dict[str, Any]]:
    """Read and scan a source-code file."""
    path = file_path.expanduser().resolve()

    if not path.exists():
        raise FileNotFoundError(f"Source file not found: {path}")
    if not path.is_file():
        raise ValueError(f"Path is not a file: {path}")

    # Replace undecodable bytes rather than crashing on an unusual encoding.
    code = path.read_text(encoding="utf-8", errors="replace")
    return scan_source_code(code, source_name=str(path), use_llm=use_llm)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Detect source-code secrets and calculate heuristic risk scores."
    )
    parser.add_argument(
        "source_file",
        nargs="?",
        help="Path to a source-code file to scan. If omitted, a synthetic demo is used.",
    )
    parser.add_argument(
        "--no-llm",
        action="store_true",
        help="Disable LLM fallback for UNKNOWN candidates.",
    )
    args = parser.parse_args()

    try:
        if args.source_file:
            scan_file(Path(args.source_file), use_llm=not args.no_llm)
        else:
            # Synthetic demonstration only; never use a real credential here.
            sample_code = '''\
API_KEY = "SYNTHETIC_API_KEY_EXAMPLE_1234567890"
'''
            scan_source_code(
                sample_code,
                source_name="synthetic demonstration",
                use_llm=not args.no_llm,
            )
    except (OSError, ValueError, TypeError) as error:
        print(f"Scan failed: {type(error).__name__}: {error}")
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
