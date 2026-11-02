from llm.classifier import SecretClassifier


# ==========================================
# Load LLM
# ==========================================

classifier = SecretClassifier()


# ==========================================
# Test Cases
# ==========================================

test_cases = [

    {
        "name": "REAL SECRET",
        "candidate": {
            "value": "sk_live_ABC123456789",
            "type": "api_key",
            "method": "manual"
        },
        "context": """
client = APIClient(
    api_key = "sk_live_ABC123456789"
)

response = client.get_data()
"""
    },

    {
        "name": "PLACEHOLDER",
        "candidate": {
            "value": "blue_sky_2026",
            "type": "unknown",
            "method": "manual"
        },
        "context": """
def create_demo():

    message = "blue_sky_2026"

    print("This is only a demonstration value.")
    print("It is used for testing the application.")
"""
    },

    {
        "name": "NOT SECRET",
        "candidate": {
            "value": "hello_world",
            "type": "unknown",
            "method": "manual"
        },
        "context": """
def show_message():

    message = "hello_world"

    print(message)
"""
    }
]


# ==========================================
# Run Tests
# ==========================================

print("\n" + "=" * 60)
print("LLM SECRET CLASSIFICATION TEST")
print("=" * 60)


for number, test in enumerate(test_cases, start=1):

    print("\n" + "-" * 60)
    print(f"TEST {number}: {test['name']}")
    print("-" * 60)

    candidate = test["candidate"]
    context = test["context"]

    print("\nCandidate:")
    print(candidate["value"])

    print("\nCalling LLM...")

    try:

        result = classifier.classify(
            candidate,
            context
        )

        print("\nRESULT")
        print("-" * 40)

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

    except Exception as error:

        print("\nERROR:")
        print(error)


print("\n" + "=" * 60)
print("LLM TEST COMPLETE")
print("=" * 60)