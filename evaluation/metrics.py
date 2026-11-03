
"""
AI-Secret-Risk Evaluation Metrics

Calculates:
1. Accuracy
2. Precision
3. Recall
4. F1-score
5. Weighted F1-score
6. Per-class performance
7. Confusion matrix

Uses Python standard library only.
"""

# =========================================================
# HELPER FUNCTION
# =========================================================

def safe_divide(numerator, denominator):

    if denominator == 0:
        return 0.0

    return numerator / denominator


# =========================================================
# CALCULATE CLASSIFICATION METRICS
# =========================================================

def calculate_metrics(
    y_true,
    y_pred
):
    """
    Calculate accuracy, precision, recall,
    F1-score and confusion matrix.

    Parameters:
        y_true: Actual classifications
        y_pred: Predicted classifications

    Returns:
        Dictionary containing evaluation metrics.
    """

    if len(y_true) != len(y_pred):

        raise ValueError(
            "y_true and y_pred must have the same length"
        )

    if not y_true:

        return {
            "count": 0,
            "accuracy": 0.0,
            "macro_precision": 0.0,
            "macro_recall": 0.0,
            "macro_f1": 0.0,
            "weighted_f1": 0.0,
            "labels": [],
            "per_class": {},
            "confusion_matrix": {},
        }

    # Include both actual and predicted labels.
    # This ensures unexpected predictions are counted.

    labels = sorted(
        set(y_true) | set(y_pred)
    )

    # -----------------------------------------------------
    # CONFUSION MATRIX
    # -----------------------------------------------------

    confusion = {

        actual: {
            predicted: 0
            for predicted in labels
        }

        for actual in labels
    }

    correct = 0

    for actual, predicted in zip(
        y_true,
        y_pred
    ):

        confusion[actual][predicted] += 1

        if actual == predicted:
            correct += 1

    # -----------------------------------------------------
    # PER-CLASS METRICS
    # -----------------------------------------------------

    per_class = {}

    precision_values = []

    recall_values = []

    f1_values = []

    weighted_f1_sum = 0.0

    for label in labels:

        true_positive = confusion[label][label]

        false_positive = sum(
            confusion[actual][label]
            for actual in labels
            if actual != label
        )

        false_negative = sum(
            confusion[label][predicted]
            for predicted in labels
            if predicted != label
        )

        support = sum(
            confusion[label].values()
        )

        # Precision

        precision = safe_divide(
            true_positive,
            true_positive + false_positive
        )

        # Recall

        recall = safe_divide(
            true_positive,
            true_positive + false_negative
        )

        # F1-score

        f1 = safe_divide(
            2 * precision * recall,
            precision + recall
        )

        per_class[label] = {

            "precision": precision,

            "recall": recall,

            "f1": f1,

            "support": support,
        }

        precision_values.append(precision)

        recall_values.append(recall)

        f1_values.append(f1)

        weighted_f1_sum += (
            f1 * support
        )

    # -----------------------------------------------------
    # OVERALL METRICS
    # -----------------------------------------------------

    class_count = len(labels)

    accuracy = correct / len(y_true)

    macro_precision = (
        sum(precision_values) / class_count
    )

    macro_recall = (
        sum(recall_values) / class_count
    )

    macro_f1 = (
        sum(f1_values) / class_count
    )

    weighted_f1 = (
        weighted_f1_sum / len(y_true)
    )

    return {

        "count": len(y_true),

        "accuracy": accuracy,

        "macro_precision": macro_precision,

        "macro_recall": macro_recall,

        "macro_f1": macro_f1,

        "weighted_f1": weighted_f1,

        "labels": labels,

        "per_class": per_class,

        "confusion_matrix": confusion,
    }


# =========================================================
# PRINT EVALUATION REPORT
# =========================================================

def print_metrics(
    title,
    metrics
):
    """
    Display classification metrics
    and confusion matrix.
    """

    print("\n" + "=" * 72)

    print(title)

    print("=" * 72)

    if metrics["count"] == 0:

        print(
            "No records were available for evaluation."
        )

        return

    # -----------------------------------------------------
    # OVERALL RESULTS
    # -----------------------------------------------------

    print(
        f"Samples          : {metrics['count']}"
    )

    print(
        f"Accuracy         : {metrics['accuracy'] * 100:.2f}%"
    )

    print(
        f"Macro precision  : {metrics['macro_precision']:.4f}"
    )

    print(
        f"Macro recall     : {metrics['macro_recall']:.4f}"
    )

    print(
        f"Macro F1-score   : {metrics['macro_f1']:.4f}"
    )

    print(
        f"Weighted F1-score: {metrics['weighted_f1']:.4f}"
    )

    # -----------------------------------------------------
    # PER-CLASS REPORT
    # -----------------------------------------------------

    print("\nPer-class report:")

    print(
        f"{'Class':<22} "
        f"{'Precision':>10} "
        f"{'Recall':>10} "
        f"{'F1':>10} "
        f"{'Support':>10}"
    )

    print("-" * 66)

    for label in metrics["labels"]:

        values = metrics["per_class"][label]

        print(

            f"{label:<22} "

            f"{values['precision']:>10.3f} "

            f"{values['recall']:>10.3f} "

            f"{values['f1']:>10.3f} "

            f"{values['support']:>10d}"
        )

    # -----------------------------------------------------
    # CONFUSION MATRIX
    # -----------------------------------------------------

    print(
        "\nConfusion matrix "
        "(rows = expected, columns = predicted):"
    )

    labels = metrics["labels"]

    column_width = max(
        12,
        max(len(label) for label in labels) + 2
    )

    header = "".ljust(column_width)

    header += "".join(
        label.rjust(column_width)
        for label in labels
    )

    print(header)

    for actual in labels:

        row = actual.ljust(column_width)

        row += "".join(

            str(
                metrics["confusion_matrix"][actual][predicted]
            ).rjust(column_width)

            for predicted in labels
        )

        print(row)
