from detection.candidate_extractor import extract_candidates

code = 'API_KEY = "YOUR_API_KEY_HERE"'

results = extract_candidates(code)

print("=" * 60)
print("CANDIDATE EXTRACTION TEST")
print("=" * 60)

for result in results:
    print(result)
