from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

LABELS = ["Recursive", "Authoritative-only", "Refused", "Inconclusive"]

CAUSES = [
    "rate_limit",
    "packet_loss",
    "timeout_too_short",
    "log_delay",
    "rule_gap",
    "config_error_in_lab",
    "other",
]


@dataclass
class Mismatch:
    """A single ground-truth vs predicted mismatch with a root cause."""

    target_id: str
    truth: str
    predicted: str
    cause: str
    explanation: str


@dataclass
class ComparisonResult:
    """Outcome of comparing predictions to ground truth."""

    confusion_matrix: dict[str, dict[str, int]] = field(
        default_factory=lambda: {t: {p: 0 for p in LABELS} for t in LABELS}
    )
    accuracy: float = 0.0
    precision: dict[str, float] = field(default_factory=dict)
    recall: dict[str, float] = field(default_factory=dict)
    mismatches: list[Mismatch] = field(default_factory=list)
    total: int = 0
    correct: int = 0


def compare(
    predictions: dict[str, str],
    ground_truth: dict[str, str],
    causes: Optional[dict[str, tuple[str, str]]] = None,
) -> ComparisonResult:
    """Compare predicted labels against ground truth.

    Args:
        predictions: target_id -> predicted label.
        ground_truth: target_id -> expected label.
        causes: optional target_id -> (cause_category, explanation) for
            documenting every mismatch.

    Returns:
        A ComparisonResult with matrix, metrics, and mismatches.
    """
    result = ComparisonResult()
    result.total = len(ground_truth)

    for target_id, truth in ground_truth.items():
        predicted = predictions.get(target_id, "Inconclusive")
        if truth not in LABELS:
            truth = "Inconclusive"
        if predicted not in LABELS:
            predicted = "Inconclusive"
        result.confusion_matrix[truth][predicted] += 1
        if truth == predicted:
            result.correct += 1
        else:
            cause = "other"
            explanation = ""
            if causes and target_id in causes:
                cause, explanation = causes[target_id]
            result.mismatches.append(
                Mismatch(
                    target_id=target_id,
                    truth=truth,
                    predicted=predicted,
                    cause=cause,
                    explanation=explanation,
                )
            )

    result.accuracy = result.correct / result.total if result.total else 0.0

    for label in LABELS:
        tp = result.confusion_matrix[label][label]
        fp = sum(result.confusion_matrix[t][label] for t in LABELS if t != label)
        fn = sum(result.confusion_matrix[label][p] for p in LABELS if p != label)
        result.precision[label] = tp / (tp + fp) if (tp + fp) else 0.0
        result.recall[label] = tp / (tp + fn) if (tp + fn) else 0.0

    return result


LAB_CAUSES = {
    "t15": (
        "rate_limit",
        "The intentionally rate-limited target dropped queries before the "
        "configured timeout elapsed.",
    ),
    "t18": (
        "timeout_too_short",
        "The high-latency target adds a 1.5-second response delay; a timeout "
        "can exceed the configured probe deadline when upstream resolution is slow.",
    ),
    "t19": (
        "packet_loss",
        "Simulated packet loss intermittently drops probe or response "
        "packets, producing spurious timeouts for an otherwise open resolver.",
    ),
}
