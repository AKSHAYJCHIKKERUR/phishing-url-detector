"""
Phishing URL & Email Detector
------------------------------
A rule-based tool that analyzes a URL or email text and scores how
likely it is to be a phishing attempt, based on common red flags used
in real-world phishing attacks.

This is a RULE-BASED system (not machine learning). Real products
(like enterprise email security tools) combine rules like these with
ML models and live threat intelligence feeds. This project focuses on
understanding the SIGNALS that indicate phishing.
"""

import re
from urllib.parse import urlparse

import threat_intel

# Common suspicious keywords found in phishing emails/messages
SUSPICIOUS_KEYWORDS = [
    "verify your account", "urgent", "act now", "click here immediately",
    "suspended", "confirm your identity", "update your payment",
    "you have won", "limited time", "click below", "restricted access",
    "unusual activity", "security alert", "your account will be closed",
]

# Known safe/trusted domains often impersonated by phishers
COMMONLY_IMPERSONATED = [
    "paypal.com", "google.com", "microsoft.com", "apple.com",
    "amazon.com", "facebook.com", "bankofamerica.com", "netflix.com",
]

# Common URL shortener services (often used to hide the real destination)
URL_SHORTENERS = ["bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd"]


def is_ip_address(hostname: str) -> bool:
    """Check if the hostname is a raw IP address instead of a domain name."""
    pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
    return bool(re.match(pattern, hostname or ""))


def looks_like_impersonation(hostname: str) -> str | None:
    """
    Check if hostname is a lookalike of a commonly impersonated domain.
    Example: 'paypa1.com' or 'paypal-secure.com' instead of 'paypal.com'.
    """
    if not hostname:
        return None

    # Strip a leading "www." so "www.google.com" is treated as "google.com"
    clean_hostname = hostname[4:] if hostname.startswith("www.") else hostname

    for real_domain in COMMONLY_IMPERSONATED:
        brand = real_domain.split(".")[0]  # e.g. "paypal"
        if brand in clean_hostname and clean_hostname != real_domain:
            return real_domain
    return None


def analyze_url(url: str) -> dict:
    """Analyze a single URL and return a risk score + reasons."""
    reasons = []
    score = 0

    parsed = urlparse(url if "://" in url else "http://" + url)
    hostname = parsed.hostname or ""

    # Rule 1: No HTTPS
    if parsed.scheme != "https":
        score += 15
        reasons.append("URL does not use HTTPS")

    # Rule 2: IP address instead of domain name
    if is_ip_address(hostname):
        score += 25
        reasons.append("Uses a raw IP address instead of a domain name")

    # Rule 3: URL shortener
    if any(shortener in hostname for shortener in URL_SHORTENERS):
        score += 20
        reasons.append("Uses a URL shortener (hides real destination)")

    # Rule 4: Excessive hyphens (common in fake domains like paypal-secure-login.com)
    if hostname.count("-") >= 2:
        score += 15
        reasons.append("Domain contains multiple hyphens (common trick)")

    # Rule 5: Very long URL (phishers often pad URLs to hide the real domain)
    if len(url) > 75:
        score += 10
        reasons.append("Unusually long URL")

    # Rule 6: Lookalike domain impersonating a trusted brand
    impersonated = looks_like_impersonation(hostname)
    if impersonated:
        score += 30
        reasons.append(f"Looks like it's impersonating '{impersonated}'")

    # Rule 7: '@' symbol in URL (browsers ignore everything before @ when loading)
    if "@" in url:
        score += 20
        reasons.append("Contains '@' symbol (can hide the real destination)")

    # Rule 8: Live threat intelligence check - is this domain CONFIRMED
    # malicious by security researchers? (real-time feed, not just a guess)
    intel_result = threat_intel.check_domain(hostname)
    if intel_result["checked"] and intel_result["is_known_malicious"]:
        score = 100  # override - confirmed malicious is maximum risk
        reasons.append(
            "⚠ CONFIRMED malicious domain (matched live threat intelligence feed)"
        )

    return {
        "url": url,
        "score": min(score, 100),
        "reasons": reasons,
    }


def analyze_email_text(text: str) -> dict:
    """Analyze email/message body text for phishing language patterns."""
    reasons = []
    score = 0
    text_lower = text.lower()

    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in text_lower:
            score += 10
            reasons.append(f"Contains suspicious phrase: '{keyword}'")

    # Extract any URLs found in the text and analyze them too
    urls_found = re.findall(r"https?://\S+|www\.\S+", text)
    url_results = [analyze_url(u) for u in urls_found]

    for result in url_results:
        score += result["score"] * 0.5  # weight URL risk into overall score

    return {
        "text_score": min(score, 100),
        "keyword_reasons": reasons,
        "url_analysis": url_results,
    }


def verdict(score: int) -> str:
    """Convert numeric score into a human-readable risk level."""
    if score >= 60:
        return "HIGH RISK - Likely Phishing"
    elif score >= 30:
        return "MEDIUM RISK - Suspicious, review carefully"
    else:
        return "LOW RISK - Looks safe (but stay cautious)"


def print_report(label: str, score: int, reasons: list):
    print(f"\n{'=' * 50}")
    print(f"Analyzing: {label}")
    print(f"{'=' * 50}")
    print(f"Risk Score: {score}/100")
    print(f"Verdict: {verdict(score)}")
    if reasons:
        print("\nReasons flagged:")
        for r in reasons:
            print(f"  - {r}")
    else:
        print("\nNo red flags detected.")
    print(f"{'=' * 50}\n")


if __name__ == "__main__":
    print("PHISHING URL & EMAIL DETECTOR")
    print("Type a URL or paste email text to analyze. Type 'quit' to exit.\n")

    while True:
        user_input = input("Enter URL or email text: ").strip()
        if user_input.lower() == "quit":
            break
        if not user_input:
            continue

        # Simple heuristic: if it has no spaces, treat as a single URL
        if " " not in user_input:
            result = analyze_url(user_input)
            print_report(result["url"], result["score"], result["reasons"])
        else:
            result = analyze_email_text(user_input)
            all_reasons = result["keyword_reasons"] + [
                reason
                for u in result["url_analysis"]
                for reason in u["reasons"]
            ]
            print_report("Email text", int(result["text_score"]), all_reasons)
