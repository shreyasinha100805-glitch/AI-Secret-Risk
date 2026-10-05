import re

PATTERNS = {
    "api_key": r'(?i)(api[_-]?key|apikey)\s*[:=]\s*["\'][A-Za-z0-9_\-]{16,}["\']',
    "password": r'(?i)(password|passwd|pwd)\s*[:=]\s*["\'][^"\']{6,}["\']',
    "token": r'(?i)(token|access[_-]?token)\s*[:=]\s*["\'][A-Za-z0-9_\-]{16,}["\']',
    "private_key": r'-----BEGIN [A-Z ]*PRIVATE KEY-----'
}


def detect_candidates(code):
    findings = []

    for secret_type, pattern in PATTERNS.items():
        matches = re.finditer(pattern, code)

        for match in matches:
            findings.append({
                "type": secret_type,
                "value": match.group(),
                "start": match.start(),
                "end": match.end()
            })

    return findings


if __name__ == "__main__":

    sample_code = '''
API_KEY = "sk_test_123456789012345678"
password = "mySecretPassword123"
'''

    results = detect_candidates(sample_code)

    for result in results:
        print(result)