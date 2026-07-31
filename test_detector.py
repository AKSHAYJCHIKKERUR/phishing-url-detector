"""
Test set: known phishing-style URLs vs legitimate URLs.
Run this to see how accurately the detector classifies each one.

Note: These "phishing" URLs are constructed examples showing common
red-flag patterns (IP addresses, lookalike domains, shorteners) -
not real live malicious links.
"""

from phishing_detector import analyze_url, verdict

# Label: True = phishing, False = legitimate
TEST_CASES = [
    ("http://192.168.10.5/login-verify", True),
    ("http://paypa1-secure-login.com", True),
    ("https://bit.ly/3xample", True),
    ("http://www.faceb00k-security.com", True),
    ("http://apple-id-verify-account.com", True),
    ("http://account-update-secure-bank.com", True),
    ("http://102.33.12.44/wp-login", True),
    ("http://amaz0n-support-team.com", True),
    ("https://www.google.com", False),
    ("https://www.wikipedia.org", False),
    ("https://github.com", False),
    ("https://www.microsoft.com", False),
    ("https://www.amazon.com", False),
    ("https://www.python.org", False),
    ("https://www.linkedin.com", False),
    ("https://www.netflix.com", False),
]

def run_tests():
    correct = 0
    print(f"{'URL':<45} {'Actual':<12} {'Predicted':<25} {'Score'}")
    print("-" * 100)

    for url, is_phishing in TEST_CASES:
        result = analyze_url(url)
        predicted_label = result["score"] >= 30  # our threshold for "flagged"
        is_correct = predicted_label == is_phishing
        correct += is_correct

        actual_str = "Phishing" if is_phishing else "Legit"
        predicted_str = verdict(result["score"])
        mark = "✓" if is_correct else "✗"

        print(f"{url:<45} {actual_str:<12} {predicted_str:<25} {result['score']:<5} {mark}")

    accuracy = (correct / len(TEST_CASES)) * 100
    print("-" * 100)
    print(f"\nAccuracy: {correct}/{len(TEST_CASES)} = {accuracy:.1f}%")


if __name__ == "__main__":
    run_tests()
