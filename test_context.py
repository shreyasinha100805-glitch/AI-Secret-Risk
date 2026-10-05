from detection.context_detector import classify_context


def test_context(candidate, context):

    result = classify_context(candidate, context)

    print("=" * 60)
    print("CANDIDATE")
    print("=" * 60)

    print("Value:", candidate["value"])
    print("Type:", candidate["type"])
    print("Method:", candidate["method"])
    print("Entropy:", candidate["entropy"])

    print("\nCONTEXT")
    print("-" * 60)
    print(context)

    print("\nRESULT")
    print("-" * 60)
    print(result)

    print("=" * 60)


# ---------------------------------------------------------
# TEST 1: REAL SECRET
# ---------------------------------------------------------

candidate1 = {
    "value": "sk_live_abc123456789",
    "type": "api_key",
    "method": "regex",
    "entropy": None
}

context1 = """
API_KEY = "sk_live_abc123456789"

client = APIClient(
    api_key=API_KEY
)

response = client.get_data()
"""

test_context(candidate1, context1)


# ---------------------------------------------------------
# TEST 2: PLACEHOLDER
# ---------------------------------------------------------

candidate2 = {
    "value": "YOUR_API_KEY_HERE",
    "type": "api_key",
    "method": "regex",
    "entropy": None
}

context2 = """
API_KEY = "YOUR_API_KEY_HERE"

# Replace this value with your actual API key.
"""

test_context(candidate2, context2)


# ---------------------------------------------------------
# TEST 3: NORMAL VALUE
# ---------------------------------------------------------

candidate3 = {
    "value": "hello world",
    "type": "unknown",
    "method": "regex",
    "entropy": None
}

context3 = """
message = "hello world"

print(message)
"""

test_context(candidate3, context3)


# ---------------------------------------------------------
# TEST 4: PASSWORD
# ---------------------------------------------------------

candidate4 = {
    "value": "MyRealPassword@123",
    "type": "password",
    "method": "regex",
    "entropy": None
}

context4 = """
password = "MyRealPassword@123"

login(username, password)
"""

test_context(candidate4, context4)