import math
import re


def calculate_entropy(value):
    """
    Calculate Shannon entropy of a string.
    """

    if not value:
        return 0.0

    frequency = {}

    for character in value:
        frequency[character] = frequency.get(character, 0) + 1

    entropy = 0.0
    length = len(value)

    for count in frequency.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return round(entropy, 2)


def detect_high_entropy(code, threshold=3.5):
    """
    Detect high-entropy strings in source code.

    Returns a list of candidate dictionaries.
    """

    candidates = []

    # Find quoted strings
    pattern = r"""["']([^"']+)["']"""

    matches = re.finditer(pattern, code)

    for match in matches:

        value = match.group(1)

        # Ignore very short strings
        if len(value) < 8:
            continue

        entropy = calculate_entropy(value)

        if entropy >= threshold:

            candidates.append({
                "value": value,
                "type": "unknown",
                "method": "entropy",
                "entropy": entropy
            })

    return candidates


if __name__ == "__main__":

    test_values = [
        "hello",
        "password123",
        "A8f92KxP7qL1zM4n",
        "x7F9kP2mL8Q4wZ6rT1"
    ]

    print("=" * 60)
    print("ENTROPY DETECTOR TEST")
    print("=" * 60)

    for value in test_values:

        entropy = calculate_entropy(value)

        print("\nValue:", value)
        print("Entropy:", entropy)
        print("High Entropy:", entropy >= 3.5)